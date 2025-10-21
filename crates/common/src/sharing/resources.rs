/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavResources, auth::AccessToken};
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

        for resource in &self.resources {
            if let Some(acls) = resource.acls() {
                for acl in acls {
                    if access_token.is_member(acl.account_id) {
                        let mut grants = acl.grants;
                        grants.intersection(&check_acls);
                        if grants == check_acls || (match_any && !grants.is_empty()) {
                            document_ids.insert(resource.document_id);
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

            for path in &self.paths {
                if let Some(parent_id) = path.parent_id
                    && shared_containers.contains(parent_id)
                {
                    document_ids.insert(self.resources[path.resource_idx].document_id);
                }
            }

            document_ids
        } else {
            shared_containers
        }
    }

    pub fn has_access_to_container(
        &self,
        access_token: &AccessToken,
        document_id: u32,
        check_acls: impl Into<Bitmap<Acl>>,
    ) -> bool {
        let check_acls = check_acls.into();

        for resource in &self.resources {
            if resource.document_id == document_id
                && let Some(acls) = resource.acls()
            {
                for acl in acls {
                    if access_token.is_member(acl.account_id) {
                        let mut grants = acl.grants;
                        grants.intersection(&check_acls);
                        return !grants.is_empty();
                    }
                }
                break;
            }
        }

        false
    }

    pub fn container_acl(&self, access_token: &AccessToken, document_id: u32) -> Bitmap<Acl> {
        let mut account_acls = Bitmap::<Acl>::new();

        for resource in &self.resources {
            if resource.document_id == document_id
                && let Some(acls) = resource.acls()
            {
                for acl in acls {
                    if access_token.is_member(acl.account_id) {
                        account_acls.union(&acl.grants);
                    }
                }
                break;
            }
        }

        account_acls
    }

    pub fn document_ids(&self, is_container: bool) -> impl Iterator<Item = u32> {
        self.resources.iter().filter_map(move |resource| {
            if resource.is_container() == is_container {
                Some(resource.document_id)
            } else {
                None
            }
        })
    }

    pub fn has_container_id(&self, id: &u32) -> bool {
        self.resources
            .iter()
            .any(|r| r.document_id == *id && r.is_container())
    }

    pub fn has_item_id(&self, id: &u32) -> bool {
        self.resources
            .iter()
            .any(|r| r.document_id == *id && !r.is_container())
    }
}
