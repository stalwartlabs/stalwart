/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavResourcePath, GroupwareResourceRef, GroupwareResources, auth::AccessToken,
    storage::dav::CachedUid,
};
use store::roaring::RoaringBitmap;
use types::acl::{Acl, AclGrant};
use utils::map::bitmap::Bitmap;

fn grant_matches(
    access_token: &AccessToken,
    acl: &AclGrant,
    check_acls: &Bitmap<Acl>,
    match_any: bool,
) -> bool {
    if !access_token.is_member(acl.account_id) {
        return false;
    }
    let mut grants = acl.grants;
    grants.intersection(check_acls);
    grants == *check_acls || (match_any && !grants.is_empty())
}

impl GroupwareResources {
    pub fn shared_containers(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let check_acls = Bitmap::<Acl>::from_iter(check_acls);
        let mut document_ids = RoaringBitmap::new();

        for resource in self.resources_with_acls() {
            if resource
                .acls()
                .iter()
                .any(|acl| grant_matches(access_token, acl, &check_acls, match_any))
            {
                document_ids.insert(resource.document_id());
            }
        }

        document_ids
    }

    pub fn is_shared_item(
        &self,
        item: &GroupwareResourceRef<'_>,
        access_token: &AccessToken,
        check_acls: &Bitmap<Acl>,
        match_any: bool,
    ) -> bool {
        item.child_names().iter().any(|name| {
            self.resources
                .find(name.parent_id, true)
                .is_some_and(|container| {
                    container
                        .acls()
                        .iter()
                        .any(|acl| grant_matches(access_token, acl, check_acls, match_any))
                })
        })
    }

    pub fn shared_items(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let mut document_ids = RoaringBitmap::new();
        for container_id in &self.shared_containers(access_token, check_acls, match_any) {
            document_ids.extend(self.children_ids(container_id));
        }
        document_ids
    }

    pub fn has_access_to_container(
        &self,
        access_token: &AccessToken,
        document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> bool {
        let mut grants = self.container_acl(access_token, document_id);
        grants.intersection(&check_acls.into());
        !grants.is_empty()
    }

    pub fn container_acl(&self, access_token: &AccessToken, document_id: u32) -> Bitmap<Acl> {
        let mut account_acls = Bitmap::<Acl>::new();

        if let Some(resource) = self.resources.find_any(document_id) {
            for acl in resource.acls() {
                if access_token.is_member(acl.account_id) {
                    account_acls.union(&acl.grants);
                }
            }
        }

        account_acls
    }

    pub fn uid_matches(&self, uid: &str) -> RoaringBitmap {
        let uid = uid.cached_uid();
        self.resources
            .iter_run(false)
            .filter(|resource| resource.has_cached_uid(uid.as_bytes()))
            .map(|resource| resource.document_id())
            .collect()
    }

    pub fn children_with_uid(
        &self,
        container_id: u32,
        uid: &str,
    ) -> impl Iterator<Item = DavResourcePath<'_>> {
        let uid = uid.cached_uid();
        self.children(container_id)
            .filter(move |path| path.resource.has_cached_uid(uid.as_bytes()))
    }

    pub fn event_ids_with_flags(&self, mask: u16) -> RoaringBitmap {
        let [document_ids] = self.event_ids_with_flag_masks([mask]);
        document_ids
    }

    pub fn event_ids_with_flag_masks<const N: usize>(&self, masks: [u16; N]) -> [RoaringBitmap; N] {
        let mut document_ids = std::array::from_fn(|_| RoaringBitmap::new());
        for resource in self.resources.iter_run(false) {
            if let Some(flags) = resource.event_flags() {
                let document_id = resource.document_id();
                for (mask, document_ids) in masks.iter().zip(document_ids.iter_mut()) {
                    if flags & *mask != 0 {
                        document_ids.insert(document_id);
                    }
                }
            }
        }
        document_ids
    }

    pub fn document_ids(&self, is_container: bool) -> impl Iterator<Item = u32> {
        self.resources
            .iter_run(is_container)
            .filter_map(move |resource| {
                if resource.is_container() == is_container {
                    Some(resource.document_id())
                } else {
                    None
                }
            })
    }

    pub fn has_container_id(&self, id: &u32) -> bool {
        self.resources.find(*id, true).is_some()
    }

    pub fn has_item_id(&self, id: &u32) -> bool {
        self.resources.find(*id, false).is_some()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ArenaRef, DavName, DavPath, GroupwareResource, GroupwareResourceMetadata,
        GroupwareResources, NO_ID, PathIndex, ResourceStore, UpdateLock,
        auth::{AccessToken, AccessTokenInner},
        storage::dav::{CONTAINER_FLAG, CachedUid, MAX_CACHED_UID_LEN, ResourceChunkBuilder},
    };
    use std::{borrow::Cow, sync::Arc};
    use store::roaring::RoaringBitmap;
    use types::{
        acl::{Acl, AclGrant},
        metadata::MetadataKinds,
    };
    use utils::map::bitmap::Bitmap;

    type EventSpec<'x> = (u32, &'x str, &'x [(u32, &'x str)]);

    fn calendar_resources(
        calendars: &[(u32, &str, Vec<AclGrant>)],
        events: &[EventSpec<'_>],
    ) -> GroupwareResources {
        let mut containers = ResourceChunkBuilder::with_capacity(calendars.len());
        let mut entries = Vec::new();
        for (document_id, name, grants) in calendars {
            let name_ref = containers.push_str(name);
            let acls = containers.push_acls(grants);
            let preferences = containers.push_prefs(&[]);
            containers.records.push(GroupwareResource {
                document_id: *document_id,
                data: GroupwareResourceMetadata::Calendar {
                    name: name_ref,
                    acls,
                    preferences,
                    etag: 0,
                    metadata: MetadataKinds::NONE,
                },
            });
            entries.push((
                name.to_string(),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: NO_ID,
                    hierarchy_seq: 1 | CONTAINER_FLAG,
                    document_id: *document_id,
                },
            ));
        }

        let mut items = ResourceChunkBuilder::with_capacity(events.len());
        for (document_id, uid, links) in events {
            let names = items.push_names(
                &links
                    .iter()
                    .map(|(parent_id, name)| DavName {
                        name: name.to_string(),
                        parent_id: *parent_id,
                    })
                    .collect::<Vec<_>>(),
            );
            let uid = items.push_uid(&uid.cached_uid(), names);
            items.records.push(GroupwareResource {
                document_id: *document_id,
                data: GroupwareResourceMetadata::CalendarEvent {
                    names,
                    start: 0,
                    duration: 0,
                    created_at: 0,
                    modified_at: 0,
                    uid,
                    etag: 0,
                    flags: 0,
                },
            });
            for (parent_id, name) in links.iter() {
                let (_, parent, _) = calendars
                    .iter()
                    .find(|(id, _, _)| id == parent_id)
                    .expect("parent calendar");
                entries.push((
                    format!("{parent}/{name}"),
                    DavPath {
                        path: ArenaRef::default(),
                        parent_id: *parent_id,
                        hierarchy_seq: 0,
                        document_id: *document_id,
                    },
                ));
            }
        }

        GroupwareResources {
            base_path: "/dav/cal/owner/".to_string(),
            paths: Arc::new(PathIndex::pack(entries)),
            resources: ResourceStore::from_sorted(vec![containers], vec![items], false),
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        }
    }

    fn uid_hits(resources: &GroupwareResources, container_id: u32, uid: &str) -> Vec<u32> {
        let mut ids = resources
            .children_with_uid(container_id, uid)
            .map(|path| path.document_id())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn children_with_uid_is_scoped_to_the_container() {
        let resources = calendar_resources(
            &[(0, "home", Vec::new()), (1, "work", Vec::new())],
            &[
                (0, "a", &[(0, "a.ics")]),
                (1, "a", &[(1, "a.ics")]),
                (2, "b", &[(0, "b.ics")]),
                (3, "a", &[(0, "c.ics"), (1, "c.ics")]),
                (4, "b.ics", &[(1, "d.ics")]),
            ],
        );

        assert_eq!(uid_hits(&resources, 0, "a"), [0, 3]);
        assert_eq!(uid_hits(&resources, 1, "a"), [1, 3]);
        assert_eq!(uid_hits(&resources, 0, "b"), [2]);
        assert_eq!(uid_hits(&resources, 1, "b"), Vec::<u32>::new());
        assert_eq!(uid_hits(&resources, 1, "b.ics"), [4]);
        assert_eq!(uid_hits(&resources, 0, "missing"), Vec::<u32>::new());
        assert_eq!(uid_hits(&resources, 9, "a"), Vec::<u32>::new());
        assert_eq!(uid_hits(&resources, 0, ""), Vec::<u32>::new());

        assert_eq!(
            resources.uid_matches("a"),
            RoaringBitmap::from_iter([0, 1, 3])
        );
        assert_eq!(resources.uid_matches("b"), RoaringBitmap::from_iter([2]));
        assert_eq!(
            resources.document_ids(true).collect::<Vec<_>>(),
            [0, 1],
            "container run"
        );
        assert_eq!(
            resources.document_ids(false).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4],
            "item run"
        );
        assert_eq!(
            resources
                .containers()
                .map(|container| container.document_id())
                .collect::<Vec<_>>(),
            [0, 1]
        );
    }

    #[test]
    fn cached_uids_are_verbatim_or_hashed() {
        const HASH_SUFFIX_LEN: usize = 33;
        let short = "a".repeat(10);
        let exact = "x".repeat(MAX_CACHED_UID_LEN);
        let exact_multibyte = format!("{}\u{e9}", "z".repeat(MAX_CACHED_UID_LEN - 2));
        let over = "x".repeat(MAX_CACHED_UID_LEN + 1);
        let multibyte = format!("{}\u{e9}{}", "z".repeat(221), "z".repeat(40));
        let with_nul = "a\0b";

        for uid in [short.as_str(), exact.as_str(), exact_multibyte.as_str()] {
            assert!(matches!(uid.cached_uid(), Cow::Borrowed(cached) if cached == uid));
            assert!(!uid.is_hashed_uid());
        }

        for uid in [over.as_str(), multibyte.as_str(), with_nul] {
            let cached = uid.cached_uid();
            assert!(cached.len() <= MAX_CACHED_UID_LEN, "{uid:?}");
            assert!(cached.is_hashed_uid(), "{uid:?}");
            assert_ne!(cached, uid);
            assert_eq!(cached, uid.cached_uid());
            assert!(cached.contains('\0'));
            assert!(cached.rsplit_once('\0').is_some_and(|(_, hex)| {
                hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            }));
        }

        assert_eq!(over.cached_uid().len(), MAX_CACHED_UID_LEN);
        assert!(
            over.cached_uid()
                .starts_with(&"x".repeat(MAX_CACHED_UID_LEN - HASH_SUFFIX_LEN))
        );
        assert_eq!(multibyte.cached_uid().len(), 221 + HASH_SUFFIX_LEN);
        assert!(multibyte.cached_uid().starts_with(&"z".repeat(221)));
        assert_eq!(
            with_nul.cached_uid().len(),
            with_nul.len() + HASH_SUFFIX_LEN
        );
        assert!(with_nul.cached_uid().starts_with(with_nul));

        let long = "x".repeat(300);
        let sibling = format!("{}y", "x".repeat(299));
        assert_eq!(
            long.get(..MAX_CACHED_UID_LEN),
            sibling.get(..MAX_CACHED_UID_LEN)
        );
        assert_ne!(long.cached_uid(), sibling.cached_uid());
    }

    #[test]
    fn long_uids_sharing_a_prefix_are_distinct() {
        let long = "x".repeat(300);
        let sibling = format!("{}y", "x".repeat(299));
        let exact = "x".repeat(MAX_CACHED_UID_LEN);
        let with_nul = "a\0b";
        let resources = calendar_resources(
            &[(0, "home", Vec::new())],
            &[
                (0, long.as_str(), &[(0, "long.ics")]),
                (1, sibling.as_str(), &[(0, "sibling.ics")]),
                (2, exact.as_str(), &[(0, "exact.ics")]),
                (3, with_nul, &[(0, "nul.ics")]),
            ],
        );

        assert_eq!(uid_hits(&resources, 0, &long), [0]);
        assert_eq!(uid_hits(&resources, 0, &sibling), [1]);
        assert_eq!(uid_hits(&resources, 0, &exact), [2]);
        assert_eq!(uid_hits(&resources, 0, with_nul), [3]);
        assert_eq!(uid_hits(&resources, 0, &"x".repeat(301)), Vec::<u32>::new());
        assert_eq!(uid_hits(&resources, 0, "a"), Vec::<u32>::new());
        assert_eq!(resources.uid_matches(&long), RoaringBitmap::from_iter([0]));
        assert_eq!(resources.uid_matches(&exact), RoaringBitmap::from_iter([2]));

        for (document_id, uid) in [
            (0, long.as_str()),
            (1, sibling.as_str()),
            (2, exact.as_str()),
            (3, with_nul),
        ] {
            let resource = resources
                .resources
                .find(document_id, false)
                .expect("stored event");
            let stored = resource.uid().expect("cached uid");
            assert_eq!(stored, uid.cached_uid());
            assert!(resource.has_cached_uid(stored.as_bytes()));
            assert_eq!(stored.is_hashed_uid(), document_id != 2);
        }
    }

    #[test]
    fn shared_items_matches_a_full_path_scan() {
        const ACCESSOR: u32 = 2;
        let grant = || {
            vec![AclGrant {
                account_id: ACCESSOR,
                grants: Bitmap::from_iter([Acl::ReadItems]),
            }]
        };
        let resources = calendar_resources(
            &[
                (0, "a", grant()),
                (1, "a-private", Vec::new()),
                (2, "b", grant()),
                (3, "c", Vec::new()),
                (
                    4,
                    "d",
                    vec![AclGrant {
                        account_id: ACCESSOR,
                        grants: Bitmap::from_iter([Acl::ReadItems, Acl::SchedulingReadFreeBusy]),
                    }],
                ),
                (
                    5,
                    "e",
                    vec![
                        AclGrant {
                            account_id: ACCESSOR,
                            grants: Bitmap::from_iter([Acl::ReadItems]),
                        },
                        AclGrant {
                            account_id: ACCESSOR,
                            grants: Bitmap::from_iter([Acl::SchedulingReadFreeBusy]),
                        },
                    ],
                ),
            ],
            &[
                (0, "u0", &[(0, "x.ics")]),
                (1, "u1", &[(1, "x.ics")]),
                (2, "u2", &[(1, "y.ics"), (2, "y.ics")]),
                (3, "u3", &[(3, "z.ics")]),
                (4, "u4", &[(2, "w.ics")]),
                (5, "u5", &[(0, "v.ics"), (3, "v.ics")]),
                (6, "u6", &[(4, "t.ics")]),
                (7, "u7", &[(5, "t.ics")]),
            ],
        );
        let access_token = AccessToken::from_id_maybe_invalid(ACCESSOR);

        let shared_containers = resources.shared_containers(&access_token, [Acl::ReadItems], true);
        let expected = resources
            .paths
            .iter()
            .filter(|(_, path)| {
                path.parent_id != NO_ID && shared_containers.contains(path.parent_id)
            })
            .map(|(_, path)| path.document_id)
            .collect::<RoaringBitmap>();

        assert_eq!(shared_containers, RoaringBitmap::from_iter([0, 2, 4, 5]));
        assert_eq!(expected, RoaringBitmap::from_iter([0, 2, 4, 5, 6, 7]));
        assert_eq!(
            resources.shared_items(
                &access_token,
                [Acl::ReadItems, Acl::SchedulingReadFreeBusy],
                false
            ),
            RoaringBitmap::from_iter([6])
        );
        assert_eq!(
            resources.shared_items(&access_token, [Acl::ReadItems], true),
            expected
        );
        assert!(
            resources
                .shared_items(
                    &AccessToken::from_id_maybe_invalid(9),
                    [Acl::ReadItems],
                    true
                )
                .is_empty()
        );

        for (check_acls, match_any) in [
            (vec![Acl::ReadItems], false),
            (vec![Acl::ReadItems, Acl::SchedulingReadFreeBusy], false),
            (vec![Acl::ReadItems, Acl::SchedulingReadFreeBusy], true),
            (vec![Acl::ModifyItems], true),
        ] {
            for token in [
                AccessToken::from_id_maybe_invalid(ACCESSOR),
                AccessToken::from_id_maybe_invalid(9),
            ] {
                let expected = resources.shared_items(&token, check_acls.clone(), match_any);
                let bitmap = Bitmap::from_iter(check_acls.iter().copied());
                for item in resources.resources.iter_run(false) {
                    assert_eq!(
                        resources.is_shared_item(&item, &token, &bitmap, match_any),
                        expected.contains(item.document_id()),
                        "{check_acls:?} {match_any} item {}",
                        item.document_id()
                    );
                }
            }
        }
    }

    // Calendars and events have independent id spaces that both start at zero, so an
    // event can carry the same numeric id as a shared calendar it does not belong to.
    #[test]
    fn shared_items_ignores_colliding_document_ids() {
        const SHARER: u32 = 1;
        const ACCESSOR: u32 = 2;

        let mut containers = ResourceChunkBuilder::with_capacity(2);
        let mut entries: Vec<(String, DavPath)> = Vec::new();

        for (document_id, name, is_shared) in [(0u32, "shared", true), (1u32, "private", false)] {
            let name_ref = containers.push_str(name);
            let grants = if is_shared {
                vec![AclGrant {
                    account_id: ACCESSOR,
                    grants: Bitmap::from_iter([Acl::ReadItems]),
                }]
            } else {
                Vec::new()
            };
            let acls = containers.push_acls(&grants);
            let preferences = containers.push_prefs(&[]);
            containers.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::Calendar {
                    name: name_ref,
                    acls,
                    preferences,
                    etag: 0,
                    metadata: MetadataKinds::NONE,
                },
            });
            entries.push((
                name.to_string(),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: NO_ID,
                    hierarchy_seq: 1 | CONTAINER_FLAG,
                    document_id,
                },
            ));
        }

        // The single event lives in the private calendar but its own id is 0, which
        // collides with the shared calendar's id
        let mut items = ResourceChunkBuilder::with_capacity(1);
        let names = items.push_names(&[DavName {
            name: "event.ics".to_string(),
            parent_id: 1,
        }]);
        let uid = items.push_str("uid-1");
        items.records.push(GroupwareResource {
            document_id: 0,
            data: GroupwareResourceMetadata::CalendarEvent {
                names,
                start: 0,
                duration: 0,
                created_at: 0,
                modified_at: 0,
                uid,
                etag: 0,
                flags: 0,
            },
        });
        entries.push((
            "private/event.ics".to_string(),
            DavPath {
                path: ArenaRef::default(),
                parent_id: 1,
                hierarchy_seq: 0,
                document_id: 0,
            },
        ));

        let resources = GroupwareResources {
            base_path: "/dav/cal/sharer/".to_string(),
            paths: Arc::new(PathIndex::pack(entries)),
            resources: ResourceStore::from_sorted(vec![containers], vec![items], false),
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };

        let access_token = AccessToken::from_id_maybe_invalid(ACCESSOR);
        assert_ne!(ACCESSOR, SHARER);

        let shared_containers = resources.shared_containers(&access_token, [Acl::ReadItems], true);
        assert!(
            shared_containers.contains(0),
            "the shared calendar should be visible"
        );

        let shared_items = resources.shared_items(&access_token, [Acl::ReadItems], true);
        assert!(
            shared_items.is_empty(),
            "an event in an unshared calendar was admitted by numeric id collision: {shared_items:?}"
        );
    }

    #[test]
    fn container_access_unites_matching_grants() {
        const GROUP: u32 = 7;
        const MEMBER: u32 = 8;
        const OUTSIDER: u32 = 9;

        let mut containers = ResourceChunkBuilder::with_capacity(1);
        let name = containers.push_str("team");
        let acls = containers.push_acls(&[
            AclGrant {
                account_id: GROUP,
                grants: Bitmap::from_iter([Acl::Read, Acl::SchedulingReadFreeBusy]),
            },
            AclGrant {
                account_id: MEMBER,
                grants: Bitmap::from_iter([Acl::Read, Acl::ReadItems, Acl::ModifyItems]),
            },
        ]);
        let preferences = containers.push_prefs(&[]);
        containers.records.push(GroupwareResource {
            document_id: 0,
            data: GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag: 0,
                metadata: MetadataKinds::NONE,
            },
        });
        let resources = GroupwareResources {
            base_path: "/dav/cal/sharer/".to_string(),
            paths: Arc::new(PathIndex::pack(vec![(
                "team".to_string(),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: NO_ID,
                    hierarchy_seq: 1 | CONTAINER_FLAG,
                    document_id: 0,
                },
            )])),
            resources: ResourceStore::from_sorted(vec![containers], vec![], false),
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        };

        let member = AccessToken::new_maybe_invalid(Arc::new(AccessTokenInner {
            account_id: MEMBER,
            member_of: [GROUP].into_iter().collect(),
            ..Default::default()
        }));
        assert!(resources.has_access_to_container(&member, 0, Acl::ModifyItems));
        assert!(resources.has_access_to_container(&member, 0, Acl::SchedulingReadFreeBusy));

        let outsider = AccessToken::from_id_maybe_invalid(OUTSIDER);
        assert!(!resources.has_access_to_container(&outsider, 0, Acl::Read));
    }
}
