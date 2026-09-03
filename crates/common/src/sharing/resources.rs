/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavResources, NO_ID, auth::AccessToken};
use store::roaring::RoaringBitmap;
use types::acl::Acl;
use utils::map::bitmap::Bitmap;

impl DavResources {
    pub fn shared_containers(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let check_acls = Bitmap::<Acl>::from_iter(check_acls);
        let mut document_ids = RoaringBitmap::new();

        for resource in self.resources_with_acls() {
            {
                for acl in resource.acls() {
                    if access_token.is_member(acl.account_id) {
                        let mut grants = acl.grants;
                        grants.intersection(&check_acls);
                        if grants == check_acls || (match_any && !grants.is_empty()) {
                            document_ids.insert(resource.document_id());
                        }
                    }
                }
            }
        }

        document_ids
    }

    pub fn shared_items(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let shared_containers = self.shared_containers(access_token, check_acls, match_any);

        if !shared_containers.is_empty() {
            let mut document_ids = RoaringBitmap::new();

            for (_, path) in self.paths.iter() {
                if path.parent_id != NO_ID && shared_containers.contains(path.parent_id) {
                    document_ids.insert(path.document_id);
                }
            }

            document_ids
        } else {
            shared_containers
        }
    }

    pub fn shared_documents(
        &self,
        access_token: &AccessToken,
        check_acls: impl IntoIterator<Item = Acl>,
        match_any: bool,
    ) -> RoaringBitmap {
        let shared_containers = self.shared_containers(access_token, check_acls, match_any);
        let mut document_ids = shared_containers.clone();

        if !shared_containers.is_empty() {
            for (_, path) in self.paths.iter() {
                if path.parent_id != NO_ID && shared_containers.contains(path.parent_id) {
                    document_ids.insert(path.document_id);
                }
            }
        }

        document_ids
    }

    pub fn has_access_to_container(
        &self,
        access_token: &AccessToken,
        document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> bool {
        let check_acls = check_acls.into();

        if let Some(resource) = self.resources.find_any(document_id) {
            for acl in resource.acls() {
                if access_token.is_member(acl.account_id) {
                    let mut grants = acl.grants;
                    grants.intersection(&check_acls);
                    return !grants.is_empty();
                }
            }
        }

        false
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
        self.resources
            .iter()
            .filter(|&resource| resource.uid() == Some(uid))
            .map(|resource| resource.document_id())
            .collect()
    }

    pub fn document_ids(&self, is_container: bool) -> impl Iterator<Item = u32> {
        self.resources.iter().filter_map(move |resource| {
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
        ArenaRef, DavName, DavPath, DavResource, DavResourceMetadata, DavResources, NO_ID,
        PathIndex, ResourceStore, UpdateLock,
        auth::AccessToken,
        storage::dav::{CONTAINER_FLAG, ResourceChunkBuilder},
    };
    use std::sync::Arc;
    use types::acl::{Acl, AclGrant};
    use utils::map::bitmap::Bitmap;

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
            containers.records.push(DavResource {
                document_id,
                data: DavResourceMetadata::Calendar {
                    name: name_ref,
                    acls,
                    preferences,
                    etag: 0,
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
        items.records.push(DavResource {
            document_id: 0,
            data: DavResourceMetadata::CalendarEvent {
                names,
                start: 0,
                duration: 0,
                created_at: 0,
                modified_at: 0,
                uid,
                etag: 0,
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

        let resources = DavResources {
            base_path: "/dav/cal/sharer/".to_string(),
            paths: Arc::new(PathIndex::pack(entries)),
            resources: ResourceStore::from_sorted(vec![containers], vec![items], false),
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
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
}
