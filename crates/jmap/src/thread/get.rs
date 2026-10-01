/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::{Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, email::MessageAccess, mailbox::MailboxCacheAccess};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, all_ids},
    object::thread::{Thread, ThreadProperty, ThreadValue},
    request::MaybeInvalid,
};
use jmap_tools::Map;
use std::future::Future;
use store::ahash::AHashMap;
use trc::AddContext;
use types::{acl::Acl, collection::SyncCollection, id::Id};

pub trait ThreadGet: Sync + Send {
    fn thread_get(
        &self,
        request: GetRequest<Thread>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Thread>>> + Send;
}

impl ThreadGet for Server {
    async fn thread_get(
        &self,
        mut request: GetRequest<Thread>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Thread>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let access = if access_token.is_shared(account_id) {
            MessageAccess::Mailboxes(cache.shared_mailboxes(access_token, Acl::ReadItems))
        } else {
            MessageAccess::All
        };

        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let mut thread_map: AHashMap<u32, Vec<u32>>;
        let ids = if let Some(ids) = ids {
            thread_map = ids
                .iter()
                .map(|id| (id.document_id(), Vec::new()))
                .collect();
            if !access.is_empty() {
                for item in cache.emails.iter() {
                    if let Some(document_ids) = thread_map.get_mut(&item.thread_id())
                        && access.allows(item)
                    {
                        document_ids.push(item.document_id());
                    }
                }
            }
            ids
        } else {
            thread_map = AHashMap::with_capacity(32);
            for item in cache.emails.iter().filter(|item| access.allows(*item)) {
                thread_map
                    .entry(item.thread_id())
                    .or_default()
                    .push(item.document_id());
            }
            all_ids(
                thread_map.keys().copied().map(Into::into),
                self.core.jmap.get_max_objects,
            )?
        };
        let add_email_ids = request.properties.is_none_or(|p| {
            p.unwrap()
                .contains(&MaybeInvalid::Value(ThreadProperty::EmailIds))
        });
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::Thread)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        for id in ids {
            let thread_id = id.document_id();
            if let Some(document_ids) = thread_map
                .remove(&thread_id)
                .filter(|document_ids| !document_ids.is_empty())
            {
                let mut thread: Map<'_, ThreadProperty, ThreadValue> =
                    Map::with_capacity(2).with_key_value(ThreadProperty::Id, id);
                if add_email_ids {
                    thread.insert_unchecked(
                        ThreadProperty::EmailIds,
                        document_ids
                            .into_iter()
                            .map(|document_id| Id::from_parts(thread_id, document_id))
                            .collect::<Vec<_>>(),
                    );
                }
                response.list.push(thread.into());
            } else {
                response.push_not_found(id);
            }
        }

        Ok(response)
    }
}
