/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::get::ChangesLookup;
use crate::{
    api::request::set_account_id_if_missing, calendar_event::query::CalendarEventQuery,
    calendar_event_notification::query::CalendarEventNotificationQuery,
    contact::query::ContactCardQuery, email::query::EmailQuery, file::query::FileNodeQuery,
    mailbox::query::MailboxQuery, share_notification::query::ShareNotificationQuery,
    sieve::query::SieveScriptQuery, submission::query::EmailSubmissionQuery,
};
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::{
        changes::{ChangesRequest, ChangesResponse},
        query_changes::{AddedItem, QueryChangesRequest, QueryChangesResponse},
    },
    object::{JmapObject, NullObject},
    request::{QueryChangesRequestMethod, method::MethodObject},
};
use std::future::Future;

pub trait QueryChanges: Sync + Send {
    fn query_changes(
        &self,
        request: QueryChangesRequestMethod,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryChangesResponse>> + Send;
}

impl QueryChanges for Server {
    async fn query_changes(
        &self,
        request: QueryChangesRequestMethod,
        access_token: &AccessToken,
    ) -> trc::Result<QueryChangesResponse> {
        let mut response;
        let mut is_mutable = true;
        let results;
        let changes;
        let has_changes;
        let up_to_id;

        match request {
            QueryChangesRequestMethod::Email(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::Email,
                        access_token,
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
                is_mutable = request.filter.iter().any(|f| !f.is_immutable())
                    || request
                        .sort
                        .as_ref()
                        .is_some_and(|sort| sort.iter().any(|s| !s.is_immutable()));

                results = self.email_query(request.into(), access_token).await?;
            }
            QueryChangesRequestMethod::Mailbox(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::Mailbox,
                        access_token,
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
                results = self.mailbox_query(request.into(), access_token).await?;
            }
            QueryChangesRequestMethod::EmailSubmission(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::EmailSubmission,
                        access_token,
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
                results = self.email_submission_query(request.into()).await?;
            }
            QueryChangesRequestMethod::Sieve(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::SieveScript,
                        access_token,
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
                results = self.sieve_script_query(request.into()).await?;
            }
            QueryChangesRequestMethod::ContactCard(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::ContactCard,
                        access_token,
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
                    .contact_card_query(request.into(), access_token)
                    .await?;
            }
            QueryChangesRequestMethod::FileNode(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::FileNode,
                        access_token,
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
                results = self.file_node_query(request.into(), access_token).await?;
            }
            QueryChangesRequestMethod::CalendarEvent(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::CalendarEvent,
                        access_token,
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
                    .calendar_event_query(request.into(), access_token)
                    .await?;
            }
            QueryChangesRequestMethod::CalendarEventNotification(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::CalendarEventNotification,
                        access_token,
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
                    .calendar_event_notification_query(request.into(), access_token)
                    .await?;
            }
            QueryChangesRequestMethod::ShareNotification(mut request) => {
                // Query changes
                set_account_id_if_missing(&mut request.account_id, access_token);
                changes = self
                    .changes(
                        build_changes_request(&request),
                        MethodObject::ShareNotification,
                        access_token,
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
                results = self.share_notification_query(request.into()).await?;
            }
            QueryChangesRequestMethod::Principal(_) => {
                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
            QueryChangesRequestMethod::Quota(_) => {
                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
        }

        if has_changes {
            if is_mutable {
                for (index, id) in results.ids.into_iter().enumerate() {
                    if changes.created.contains(&id) || changes.updated.contains(&id) {
                        response.added.push(AddedItem::new(id, index));
                    }
                }

                response.removed = changes.updated;
            } else {
                for (index, id) in results.ids.into_iter().enumerate() {
                    if changes.created.contains(&id) {
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
