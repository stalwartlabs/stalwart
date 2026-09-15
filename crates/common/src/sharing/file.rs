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

    pub fn file_access(&self, access_token: &AccessToken) -> FileNodeAccess {
        let mut direct: AHashMap<u32, AHashMap<u32, Bitmap<Acl>>> = AHashMap::new();
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

        let mut grants: AHashMap<u32, Bitmap<Acl>> = AHashMap::new();
        let mut chain = Vec::with_capacity(16);
        for entries in direct.values() {
            let mut inherited: AHashMap<u32, Bitmap<Acl>> = AHashMap::new();
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
        grants.retain(|_, found| !found.is_empty());

        let read = Bitmap::from_iter([Acl::Read, Acl::ReadItems]);
        let readable = grants
            .iter()
            .filter(|(_, found)| {
                let mut found = **found;
                found.intersection(&read);
                !found.is_empty()
            })
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
}

#[cfg(test)]
mod tests {
    use crate::{
        FileFlags, GroupwareResource, GroupwareResourceMetadata, GroupwareResources, NO_ID,
        PathIndex, ResourceStore, UpdateLock,
        auth::{AccessToken, AccessTokenInner},
        storage::dav::{FILE_KIND_DIRECTORY, FILE_KIND_FILE, ResourceChunkBuilder},
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
        let (name, _, _) = builder.push_file_name(&format!("n{document_id}"), None);
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
        GroupwareResources {
            base_path: String::new(),
            paths: Arc::new(PathIndex::pack(Vec::new())),
            resources: ResourceStore::from_sorted(vec![builder], Vec::new(), true),
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        }
    }

    #[test]
    fn rights_are_inherited_and_overridden() {
        let resources = tree();
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
}
