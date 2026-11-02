/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::get::ChangesLookup;
use crate::{
    api::{auth::JmapAuthorization, request::resolve_account_id},
    calendar_event::query::CalendarEventQuery,
    calendar_event_notification::query::CalendarEventNotificationQuery,
    contact::query::ContactCardQuery,
    email::query::EmailQuery,
    file::query::FileNodeQuery,
    mailbox::query::MailboxQuery,
    share_notification::query::ShareNotificationQuery,
    submission::query::EmailSubmissionQuery,
};
use common::{Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, email::MessageAccess, mailbox::MailboxCacheAccess};
use jmap_proto::{
    method::{
        changes::{ChangesRequest, ChangesResponse},
        query_changes::{AddedItem, QueryChangesRequest, QueryChangesResponse},
    },
    object::{JmapObject, NullObject},
    request::{QueryChangesRequestMethod, capability::CapabilityIds, method::MethodObject},
};
use std::future::Future;
use store::{
    ahash::AHashSet,
    roaring::{RoaringBitmap, RoaringTreemap},
};
use trc::AddContext;
use types::{acl::Acl, id::Id};

pub trait QueryChanges: Sync + Send {
    fn query_changes(
        &self,
        request: QueryChangesRequestMethod,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<QueryChangesResponse>> + Send;
}

impl QueryChanges for Server {
    async fn query_changes(
        &self,
        request: QueryChangesRequestMethod,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<QueryChangesResponse> {
        let mut response;
        let mut is_mutable = true;
        let results;
        let mut changes;
        let has_changes;
        let up_to_id;

        match request {
            QueryChangesRequestMethod::Email(mut request) => {
                // Query changes
                resolve_account_id(&mut request.account_id, MethodObject::Email, access_token)?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::Email,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                let collapse_threads = request.arguments.collapse_threads.unwrap_or(false);
                is_mutable = collapse_threads
                    || request.filter.iter().any(|f| !f.is_immutable())
                    || request
                        .sort
                        .as_ref()
                        .is_some_and(|sort| sort.iter().any(|s| !s.is_immutable()));
                let account_id = request.account_id.document_id();

                results = self
                    .email_query((*request).into(), access_token, using)
                    .await?;

                if collapse_threads && has_changes {
                    let mut touched_threads = RoaringBitmap::new();
                    let mut changed_ids = RoaringTreemap::new();
                    for id in changes.created.iter().chain(changes.updated.iter()) {
                        touched_threads.insert(id.prefix_id());
                        changed_ids.insert(id.id());
                    }
                    touched_threads.extend(changes.destroyed.iter().map(|id| id.prefix_id()));
                    let cache = self
                        .get_cached_messages(account_id)
                        .await
                        .caused_by(trc::location!())?;
                    let access = if access_token.is_shared(account_id) {
                        MessageAccess::Mailboxes(
                            cache.shared_mailboxes(access_token, Acl::ReadItems),
                        )
                    } else {
                        MessageAccess::All
                    };
                    changes.updated.extend(
                        cache
                            .emails
                            .iter()
                            .filter(|message| {
                                touched_threads.contains(message.thread_id())
                                    && access.allows(*message)
                            })
                            .map(|message| {
                                Id::from_parts(message.thread_id(), message.document_id())
                            })
                            .filter(|id| !changed_ids.contains(id.id())),
                    );
                }
            }
            QueryChangesRequestMethod::Mailbox(mut request) => {
                // Query changes
                resolve_account_id(&mut request.account_id, MethodObject::Mailbox, access_token)?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::Mailbox,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                results = self
                    .mailbox_query((*request).into(), access_token, using)
                    .await?;
            }
            QueryChangesRequestMethod::EmailSubmission(mut request) => {
                // Query changes
                resolve_account_id(
                    &mut request.account_id,
                    MethodObject::EmailSubmission,
                    access_token,
                )?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::EmailSubmission,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                results = self.email_submission_query((*request).into()).await?;
            }
            QueryChangesRequestMethod::ContactCard(mut request) => {
                // Query changes
                resolve_account_id(
                    &mut request.account_id,
                    MethodObject::ContactCard,
                    access_token,
                )?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::ContactCard,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                results = self
                    .contact_card_query((*request).into(), access_token, using)
                    .await?;
            }
            QueryChangesRequestMethod::FileNode(mut request) => {
                // Query changes
                resolve_account_id(
                    &mut request.account_id,
                    MethodObject::FileNode,
                    access_token,
                )?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::FileNode,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                results = self
                    .file_node_query((*request).into(), access_token, using)
                    .await?;
            }
            QueryChangesRequestMethod::CalendarEvent(mut request) => {
                if request.arguments.expand_recurrences.unwrap_or(false) {
                    return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
                }

                // Query changes
                resolve_account_id(
                    &mut request.account_id,
                    MethodObject::CalendarEvent,
                    access_token,
                )?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::CalendarEvent,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                results = self
                    .calendar_event_query((*request).into(), access_token, using)
                    .await?;
            }
            QueryChangesRequestMethod::CalendarEventNotification(mut request) => {
                // Query changes
                resolve_account_id(
                    &mut request.account_id,
                    MethodObject::CalendarEventNotification,
                    access_token,
                )?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::CalendarEventNotification,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                results = self
                    .calendar_event_notification_query((*request).into(), access_token)
                    .await?;
            }
            QueryChangesRequestMethod::ShareNotification(mut request) => {
                // Query changes
                resolve_account_id(
                    &mut request.account_id,
                    MethodObject::ShareNotification,
                    access_token,
                )?;
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::ShareNotification,
                        access_token,
                        using,
                    )
                    .await?
                    .response;
                let calculate_total = request.calculate_total.unwrap_or(false);
                has_changes = changes.has_changes();
                response = build_query_changes_response(&request, &changes);

                if !has_changes && !calculate_total {
                    return Ok(response);
                }

                up_to_id = request.up_to_id;
                results = self.share_notification_query((*request).into()).await?;
            }
            QueryChangesRequestMethod::Principal(_) => {
                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
            QueryChangesRequestMethod::Quota(mut request) => {
                resolve_account_id(&mut request.account_id, MethodObject::Quota, access_token)?;
                access_token.assert_is_member(request.account_id)?;
                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
        }

        if has_changes {
            if is_mutable {
                let changed = changes
                    .created
                    .iter()
                    .chain(changes.updated.iter())
                    .copied()
                    .collect::<AHashSet<Id>>();
                for (index, id) in results.ids.into_iter().enumerate() {
                    if changed.contains(&id) {
                        response.added.push(AddedItem::new(id, index));
                    }
                }

                response.removed = changes.updated;
            } else {
                let created = changes.created.iter().copied().collect::<AHashSet<Id>>();
                for (index, id) in results.ids.into_iter().enumerate() {
                    if created.contains(&id) {
                        response.added.push(AddedItem::new(id, index));
                    }
                    if matches!(up_to_id, Some(up_to_id) if up_to_id == id) {
                        break;
                    }
                }
            }

            if !changes.destroyed.is_empty() {
                response.removed.extend(changes.destroyed);
            }
        }
        response.total = results.total;

        Ok(response)
    }
}

fn build_changes_request<T: JmapObject>(req: &QueryChangesRequest<T>) -> ChangesRequest {
    ChangesRequest {
        account_id: req.account_id,
        since_state: req.since_query_state.clone(),
        max_changes: req.max_changes,
        ignore_metadata_only_changes: Some(false),
    }
}

fn build_query_changes_response<T: JmapObject>(
    req: &QueryChangesRequest<T>,
    changes: &ChangesResponse<NullObject>,
) -> QueryChangesResponse {
    QueryChangesResponse {
        account_id: req.account_id,
        old_query_state: changes.old_state.clone(),
        new_query_state: changes.new_state.clone(),
        total: None,
        removed: vec![],
        added: vec![],
    }
}
