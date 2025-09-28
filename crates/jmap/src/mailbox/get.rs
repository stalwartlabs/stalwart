/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::mailbox::{Mailbox, MailboxProperty, MailboxValue},
};
use jmap_tools::{Map, Value};
use std::future::Future;
use store::ahash::AHashSet;
use types::{acl::Acl, keyword::Keyword, special_use::SpecialUse};

use crate::api::acl::JmapRights;

pub trait MailboxGet: Sync + Send {
    fn mailbox_get(
        &self,
        request: GetRequest<Mailbox>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Mailbox>>> + Send;
}

impl MailboxGet for Server {
    async fn mailbox_get(
        &self,
        mut request: GetRequest<Mailbox>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Mailbox>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            MailboxProperty::Id,
            MailboxProperty::Name,
            MailboxProperty::ParentId,
            MailboxProperty::Role,
            MailboxProperty::SortOrder,
            MailboxProperty::IsSubscribed,
            MailboxProperty::TotalEmails,
            MailboxProperty::UnreadEmails,
            MailboxProperty::TotalThreads,
            MailboxProperty::UnreadThreads,
            MailboxProperty::MyRights,
        ]);
        let account_id = request.account_id.document_id();
        let cache = self.get_cached_messages(account_id).await?;
        let shared_ids = if access_token.is_shared(account_id) {
            cache.shared_mailboxes(access_token, Acl::Read).into()
        } else {
            None
        };
        let ids = if let Some(ids) = ids {
            ids
        } else {
            cache
                .mailboxes
                .index
                .keys()
                .filter(|id| shared_ids.as_ref().is_none_or(|ids| ids.contains(**id)))
                .copied()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: Some(cache.mailboxes.change_id.into()),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the mailbox object
            let document_id = id.document_id();
            let cached_mailbox = if let Some(mailbox) =
                cache.mailbox_by_id(&document_id).filter(|_| {
                    shared_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(document_id))
                }) {
                mailbox
            } else {
                response.not_found.push(id);
                continue;
            };

            let mut mailbox = Map::with_capacity(properties.len());

            for property in &properties {
                let value = match property {
                    MailboxProperty::Id => Value::Element(MailboxValue::Id(id)),
                    MailboxProperty::Name => Value::Str(cached_mailbox.name.to_string().into()),
                    MailboxProperty::Role => match cached_mailbox.role {
                        SpecialUse::None => Value::Null,
                        role => Value::Element(MailboxValue::Role(role)),
                    },
                    MailboxProperty::SortOrder => {
                        Value::Number(cached_mailbox.sort_order().unwrap_or_default().into())
                    }
                    MailboxProperty::ParentId => {
                        if let Some(parent_id) = cached_mailbox.parent_id() {
                            Value::Element(MailboxValue::Id(parent_id.into()))
                        } else {
                            Value::Null
                        }
                    }
                    MailboxProperty::TotalEmails => {
                        Value::Number(cache.in_mailbox(document_id).count().into())
                    }
                    MailboxProperty::UnreadEmails => Value::Number(
                        cache
                            .in_mailbox_without_keyword(document_id, &Keyword::Seen)
                            .count()
                            .into(),
                    ),
                    MailboxProperty::TotalThreads => Value::Number(
                        cache
                            .in_mailbox(document_id)
                            .map(|m| m.thread_id)
                            .collect::<AHashSet<_>>()
                            .len()
                            .into(),
                    ),
                    MailboxProperty::UnreadThreads => Value::Number(
                        cache
                            .in_mailbox_without_keyword(document_id, &Keyword::Seen)
                            .map(|m| m.thread_id)
                            .collect::<AHashSet<_>>()
                            .len()
                            .into(),
                    ),
                    MailboxProperty::MyRights => {
                        if access_token.is_shared(account_id) {
                            JmapRights::rights::<Mailbox>(
                                cached_mailbox.acls.as_slice().effective_acl(access_token),
                            )
                        } else {
                            JmapRights::all_rights::<Mailbox>()
                        }
                    }
                    MailboxProperty::IsSubscribed => Value::Bool(
                        cached_mailbox
                            .subscribers
                            .contains(&access_token.primary_id()),
                    ),
                    MailboxProperty::ShareWith => JmapRights::share_with::<Mailbox>(
                        account_id,
                        access_token,
                        &cached_mailbox.acls,
                    ),
                    _ => Value::Null,
                };

                mailbox.insert_unchecked(property.clone(), value);
            }

            // Add result to response
            response.list.push(mailbox.into());
        }
        Ok(response)
    }
}
