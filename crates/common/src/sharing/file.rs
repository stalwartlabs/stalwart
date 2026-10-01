/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{GroupwareResources, auth::AccessToken};
use ahash::AHashMap;
use store::roaring::RoaringBitmap;
use types::acl::Acl;
use utils::map::bitmap::Bitmap;

const MAX_ANCESTOR_WALK: usize = 256;

#[derive(Debug, Default)]
pub struct FileNodeAccess {
    pub readable: RoaringBitmap,
    pub discoverable: RoaringBitmap,
    grants: AHashMap<u32, Bitmap<Acl>>,
}

impl FileNodeAccess {
    #[inline(always)]
    pub fn acl(&self, document_id: u32) -> Bitmap<Acl> {
        self.grants.get(&document_id).copied().unwrap_or_default()
    }

    #[inline(always)]
    pub fn has_acl(&self, document_id: u32, acl: Acl) -> bool {
        self.grants
            .get(&document_id)
            .is_some_and(|grants| grants.contains(acl))
    }

    pub fn with_acl(&self, acl: Acl) -> RoaringBitmap {
        self.grants
            .iter()
            .filter(|(_, grants)| grants.contains(acl))
            .map(|(document_id, _)| *document_id)
            .collect()
    }
}

impl GroupwareResources {
    pub fn file_acl(&self, access_token: &AccessToken, document_id: u32) -> Bitmap<Acl> {
        let mut grants = Bitmap::new();
        let mut resolved: Vec<u32> = Vec::new();
        let mut current = self.resources.find_any(document_id);
        for _ in 0..MAX_ANCESTOR_WALK {
            let Some(resource) = current else {
                break;
            };
            let known = resolved.len();
            for acl in resource.acls() {
                if access_token.is_member(acl.account_id)
                    && !resolved.iter().take(known).any(|id| *id == acl.account_id)
                {
                    grants.union(&acl.grants);
                    if !resolved.contains(&acl.account_id) {
                        resolved.push(acl.account_id);
                    }
                }
            }
            current = resource
                .parent_id()
                .and_then(|parent_id| self.resources.find_any(parent_id));
        }
        grants
    }

    pub fn file_discoverable(&self, access_token: &AccessToken, document_id: u32) -> bool {
        is_readable(&self.file_acl(access_token, document_id))
            || self
                .file_access(access_token)
                .discoverable
                .contains(document_id)
    }

    pub fn file_access(&self, access_token: &AccessToken) -> FileNodeAccess {
        let mut direct: AHashMap<u32, DirectGrants> = AHashMap::new();
        for resource in self.resources_with_acls() {
            for acl in resource.acls() {
                if access_token.is_member(acl.account_id) {
                    direct
                        .entry(acl.account_id)
                        .or_default()
                        .entry(resource.document_id())
                        .or_default()
                        .union(&acl.grants);
                }
            }
        }
        if direct.is_empty() {
            return FileNodeAccess::default();
        }

        let mut grants = if self.paths.len() == self.resources.len() {
            self.inherit_from_paths(&direct)
        } else {
            self.inherit_from_parents(&direct)
        };
        grants.retain(|_, found| !found.is_empty());

        let readable = grants
            .iter()
            .filter(|(_, found)| is_readable(found))
            .map(|(document_id, _)| *document_id)
            .collect::<RoaringBitmap>();
        let mut discoverable = readable.clone();
        for document_id in &readable {
            let mut current = self
                .resources
                .find_any(document_id)
                .and_then(|node| node.parent_id());
            for _ in 0..MAX_ANCESTOR_WALK {
                let Some(parent_id) = current else {
                    break;
                };
                if !discoverable.insert(parent_id) {
                    break;
                }
                current = self
                    .resources
                    .find_any(parent_id)
                    .and_then(|node| node.parent_id());
            }
        }
        FileNodeAccess {
            readable,
            discoverable,
            grants,
        }
    }

    fn inherit_from_paths(&self, direct: &AHashMap<u32, DirectGrants>) -> DirectGrants {
        let mut grants = DirectGrants::new();
        let mut inherited = DirectGrants::new();
        let mut roots = Vec::new();
        let mut members = RoaringBitmap::new();
        for entries in direct.values() {
            roots.clear();
            roots.extend(entries.iter().filter_map(|(document_id, acl)| {
                self.any_resource_path_by_id(*document_id)
                    .map(|root| (root, *acl))
            }));
            roots.sort_unstable_by(|(a, _), (b, _)| a.path().cmp(b.path()));
            inherited.clear();
            for (root, acl) in &roots {
                members.clear();
                members.insert(root.document_id());
                inherited.insert(root.document_id(), *acl);
                for (_, path) in self.paths.range(format!("{}/", root.path())) {
                    if members.contains(path.parent_id) {
                        members.insert(path.document_id);
                        inherited.insert(path.document_id, *acl);
                    }
                }
            }
            if grants.is_empty() {
                std::mem::swap(&mut grants, &mut inherited);
            } else {
                for (document_id, acl) in &inherited {
                    grants.entry(*document_id).or_default().union(acl);
                }
            }
        }
        grants
    }

    fn inherit_from_parents(&self, direct: &AHashMap<u32, DirectGrants>) -> DirectGrants {
        let mut grants = DirectGrants::new();
        let mut chain = Vec::with_capacity(16);
        for entries in direct.values() {
            let mut inherited = DirectGrants::new();
            let mut unshared = RoaringBitmap::new();
            for resource in self.resources.iter() {
                let mut current = Some(resource.document_id());
                let mut result = None;
                chain.clear();
                while let Some(document_id) = current {
                    if let Some(found) = entries
                        .get(&document_id)
                        .or_else(|| inherited.get(&document_id))
                    {
                        result = Some(*found);
                        break;
                    } else if unshared.contains(document_id) || chain.len() >= MAX_ANCESTOR_WALK {
                        break;
                    }
                    chain.push(document_id);
                    current = self
                        .resources
                        .find_any(document_id)
                        .and_then(|node| node.parent_id());
                }
                match result {
                    Some(found) => inherited.extend(chain.drain(..).map(|id| (id, found))),
                    None => unshared.extend(chain.drain(..)),
                }
            }
            for (document_id, found) in entries.iter().chain(inherited.iter()) {
                grants.entry(*document_id).or_default().union(found);
            }
        }
        grants
    }
}

type DirectGrants = AHashMap<u32, Bitmap<Acl>>;

fn is_readable(acl: &Bitmap<Acl>) -> bool {
    acl.contains(Acl::Read) || acl.contains(Acl::ReadItems)
}

#[cfg(test)]
mod tests {
    use crate::{
        ArenaRef, DavPath, FileFlags, GroupwareResource, GroupwareResourceMetadata,
        GroupwareResources, NO_ID, PathIndex, ResourceStore, UpdateLock,
        auth::{AccessToken, AccessTokenInner},
        storage::dav::{CONTAINER_FLAG, FILE_KIND_DIRECTORY, FILE_KIND_FILE, ResourceChunkBuilder},
    };
    use std::sync::Arc;
    use types::{
        acl::{Acl, AclGrant},
        media_type::MediaTypeId,
    };
    use utils::map::bitmap::Bitmap;

    const SHAREE: u32 = 7;
    const GROUP: u32 = 9;

    fn node(
        builder: &mut ResourceChunkBuilder,
        document_id: u32,
        parent_id: Option<u32>,
        is_directory: bool,
        grants: &[(u32, &[Acl])],
    ) {
        named_node(
            builder,
            &format!("n{document_id}"),
            document_id,
            parent_id,
            is_directory,
            grants,
        );
    }

    fn named_node(
        builder: &mut ResourceChunkBuilder,
        name: &str,
        document_id: u32,
        parent_id: Option<u32>,
        is_directory: bool,
        grants: &[(u32, &[Acl])],
    ) {
        let (name, _, _) = builder.push_file_name(name, None);
        let acls = builder.push_acls(
            &grants
                .iter()
                .map(|(account_id, grants)| AclGrant {
                    account_id: *account_id,
                    grants: Bitmap::from_iter(grants.iter().copied()),
                })
                .collect::<Vec<_>>(),
        );
        builder.records.push(GroupwareResource {
            document_id,
            data: GroupwareResourceMetadata::File {
                name,
                size: if is_directory { NO_ID } else { 1 },
                parent_id: parent_id.unwrap_or(NO_ID),
                acls,
                etag: 0,
                modified: 0,
                created_delta: 0,
                flags: FileFlags::new(
                    if is_directory {
                        FILE_KIND_DIRECTORY
                    } else {
                        FILE_KIND_FILE
                    },
                    false,
                    0,
                    MediaTypeId::NONE,
                    0,
                ),
            },
        });
    }

    fn resources(builder: ResourceChunkBuilder) -> GroupwareResources {
        let mut resources = GroupwareResources {
            base_path: String::new(),
            paths: Arc::new(PathIndex::default()),
            resources: ResourceStore::from_sorted(vec![builder], Vec::new(), true),
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };
        let mut entries = Vec::with_capacity(resources.resources.len());
        for resource in resources.resources.iter() {
            let mut segments = Vec::new();
            let mut current = Some(resource);
            while let Some(node) = current {
                segments.push(node.container_name().unwrap_or_default());
                current = node
                    .parent_id()
                    .and_then(|parent_id| resources.resources.find_any(parent_id));
            }
            segments.reverse();
            entries.push((
                segments.join("/"),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: resource.parent_id().unwrap_or(NO_ID),
                    hierarchy_seq: if resource.is_container() {
                        CONTAINER_FLAG
                    } else {
                        0
                    },
                    document_id: resource.document_id(),
                },
            ));
        }
        resources.paths = Arc::new(PathIndex::pack(entries));
        resources
    }

    fn without_paths(resources: &GroupwareResources) -> GroupwareResources {
        let mut resources = resources.clone();
        resources.paths = Arc::new(PathIndex::default());
        resources
    }

    fn tree() -> GroupwareResources {
        let mut builder = ResourceChunkBuilder::with_capacity(8);
        node(&mut builder, 0, None, true, &[]);
        node(&mut builder, 1, Some(0), true, &[]);
        node(
            &mut builder,
            2,
            Some(1),
            true,
            &[
                (SHAREE, &[Acl::Read, Acl::ReadItems]),
                (GROUP, &[Acl::AddItems]),
            ],
        );
        node(&mut builder, 3, Some(2), true, &[]);
        node(&mut builder, 4, Some(3), false, &[]);
        node(
            &mut builder,
            5,
            Some(2),
            true,
            &[(SHAREE, &[Acl::Modify]), (GROUP, &[])],
        );
        node(&mut builder, 6, Some(5), false, &[]);
        node(&mut builder, 7, Some(0), false, &[(GROUP, &[Acl::Read])]);
        resources(builder)
    }

    fn assert_same_access(
        resources: &GroupwareResources,
        token: &AccessToken,
        document_ids: std::ops::Range<u32>,
    ) {
        let reference = without_paths(resources);
        assert_ne!(reference.paths.len(), reference.resources.len());
        let expected = reference.file_access(token);
        let access = resources.file_access(token);
        assert_eq!(access.readable, expected.readable);
        assert_eq!(access.discoverable, expected.discoverable);
        for document_id in document_ids {
            assert_eq!(
                access.acl(document_id),
                expected.acl(document_id),
                "{document_id}"
            );
            assert_eq!(
                resources.file_acl(token, document_id),
                access.acl(document_id),
                "{document_id}"
            );
            assert_eq!(
                resources.file_discoverable(token, document_id),
                access.discoverable.contains(document_id),
                "{document_id}"
            );
        }
    }

    #[test]
    fn rights_are_inherited_and_overridden() {
        let tree = tree();
        assert_eq!(tree.paths.len(), tree.resources.len());
        for resources in [tree.clone(), without_paths(&tree)] {
            let token = AccessToken::from_id_maybe_invalid(SHAREE);
            let access = resources.file_access(&token);

            assert_eq!(access.readable.iter().collect::<Vec<_>>(), vec![2, 3, 4]);
            assert_eq!(
                access.discoverable.iter().collect::<Vec<_>>(),
                vec![0, 1, 2, 3, 4]
            );
            assert!(access.has_acl(4, Acl::Read));
            assert!(access.has_acl(6, Acl::Modify));
            assert!(!access.has_acl(6, Acl::Read));
            assert!(access.acl(7).is_empty());
            assert!(access.acl(1).is_empty());

            for document_id in 0..8 {
                assert_eq!(
                    resources.file_acl(&token, document_id),
                    access.acl(document_id),
                    "{document_id}"
                );
            }

            let mut member = AccessTokenInner::from_id(SHAREE);
            member.member_of.push(GROUP);
            let member = AccessToken::new_maybe_invalid(Arc::new(member));
            let access = resources.file_access(&member);
            assert_eq!(access.readable.iter().collect::<Vec<_>>(), vec![2, 3, 4, 7]);
            assert!(access.has_acl(3, Acl::Read) && access.has_acl(3, Acl::AddItems));
            assert!(access.has_acl(6, Acl::Modify) && !access.has_acl(6, Acl::AddItems));
            for document_id in 0..8 {
                assert_eq!(
                    resources.file_acl(&member, document_id),
                    access.acl(document_id),
                    "{document_id}"
                );
            }

            let stranger = AccessToken::from_id_maybe_invalid(SHAREE + 1);
            let access = resources.file_access(&stranger);
            assert!(access.readable.is_empty() && access.discoverable.is_empty());
        }

        let mut member = AccessTokenInner::from_id(SHAREE);
        member.member_of.push(GROUP);
        let member = AccessToken::new_maybe_invalid(Arc::new(member));
        assert_same_access(&tree, &member, 0..8);
    }

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: u32) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % u64::from(bound.max(1))) as u32
        }
    }

    #[test]
    fn inheritance_from_paths_matches_parent_walk() {
        const RIGHTS: [Acl; 6] = [
            Acl::Read,
            Acl::ReadItems,
            Acl::Modify,
            Acl::AddItems,
            Acl::RemoveItems,
            Acl::Share,
        ];
        let principals = [SHAREE, GROUP, GROUP + 1, GROUP + 2];
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);

        for _ in 0..300 {
            let count = 1 + rng.below(150);
            let parents = (0..count)
                .map(|document_id| {
                    (document_id > 0 && rng.below(10) != 0).then(|| rng.below(document_id))
                })
                .collect::<Vec<_>>();
            let mut builder = ResourceChunkBuilder::with_capacity(count as usize);
            for (document_id, parent_id) in (0..count).zip(parents.iter()) {
                let is_directory = parents.contains(&Some(document_id)) || rng.below(3) == 0;
                let grant_count = if rng.below(4) == 0 {
                    1 + rng.below(3)
                } else {
                    0
                };
                let grants = (0..grant_count)
                    .map(|_| {
                        let rights = RIGHTS
                            .iter()
                            .copied()
                            .filter(|_| rng.below(3) == 0)
                            .collect::<Vec<_>>();
                        (principals[rng.below(4) as usize], rights)
                    })
                    .collect::<Vec<_>>();
                let grants = grants
                    .iter()
                    .map(|(account_id, rights)| (*account_id, rights.as_slice()))
                    .collect::<Vec<_>>();
                node(&mut builder, document_id, *parent_id, is_directory, &grants);
            }
            let resources = resources(builder);
            assert_eq!(resources.paths.len(), resources.resources.len());

            let mut member = AccessTokenInner::from_id(SHAREE);
            for group in &principals[1..] {
                if rng.below(2) == 0 {
                    member.member_of.push(*group);
                }
            }
            let token = AccessToken::new_maybe_invalid(Arc::new(member));
            assert_same_access(&resources, &token, 0..count + 1);
        }
    }

    #[test]
    fn colliding_paths_fall_back_to_parent_walk() {
        let mut builder = ResourceChunkBuilder::with_capacity(5);
        named_node(
            &mut builder,
            "root",
            0,
            None,
            true,
            &[(SHAREE, &[Acl::Read])],
        );
        named_node(&mut builder, "dup", 1, Some(0), true, &[]);
        named_node(&mut builder, "dup", 2, Some(0), true, &[]);
        named_node(&mut builder, "leaf", 3, Some(2), false, &[]);
        named_node(&mut builder, "other", 4, None, false, &[]);
        let resources = resources(builder);
        assert!(resources.paths.len() < resources.resources.len());

        let token = AccessToken::from_id_maybe_invalid(SHAREE);
        let access = resources.file_access(&token);
        assert_eq!(access.readable.iter().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
        assert!(resources.file_discoverable(&token, 3));
        assert!(!resources.file_discoverable(&token, 4));
    }
}
