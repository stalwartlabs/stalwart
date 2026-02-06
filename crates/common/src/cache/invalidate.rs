/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    ipc::{BroadcastEvent, CacheInvalidation},
};

impl Server {
    pub async fn invalidate_caches(&self, changes: Vec<CacheInvalidation>, broadcast: bool) {
        let cache = &self.inner.cache;

        for change in &changes {
            match change {
                CacheInvalidation::AccessToken(id) => {
                    cache.access_tokens.remove(id);
                }
                CacheInvalidation::DavResources(id) => {
                    cache.files.remove(id);
                    cache.contacts.remove(id);
                    cache.events.remove(id);
                    cache.scheduling.remove(id);
                }
                CacheInvalidation::Domain(id) => {
                    cache.domains.remove(id);
                }
                CacheInvalidation::Account(id) => {
                    cache.accounts.remove(id);
                }
                CacheInvalidation::Group(id) => {
                    cache.accounts.remove(id);
                }
                CacheInvalidation::Tenant(id) => {
                    cache.tenants.remove(id);
                }
                CacheInvalidation::Role(id) => {
                    cache.roles.remove(id);
                }
                CacheInvalidation::List(id) => {
                    cache.lists.remove(id);
                }
                CacheInvalidation::PushServers(_) => {}
            }
        }

        // Broadcast cache invalidation to other servers
        if broadcast {
            self.cluster_broadcast(BroadcastEvent::CacheInvalidation(changes))
                .await;
        }
    }
}
