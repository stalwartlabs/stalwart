/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::auth::JmapAuthorization;
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::changes::{ChangesRequest, ChangesResponse},
    object::{JmapObject, NullObject, mailbox::MailboxProperty},
    request::method::MethodObject,
    response::{ChangesResponseMethod, ResponseMethod},
    types::state::State,
};
use std::future::Future;
use store::query::log::{Change, Query};
use types::collection::{Collection, SyncCollection};

pub trait ChangesLookup: Sync + Send {
    fn changes(
        &self,
        request: ChangesRequest,
        object: MethodObject,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<IntermediateChangesResponse>> + Send;
}

pub struct IntermediateChangesResponse {
    pub response: ChangesResponse<NullObject>,
    pub object: MethodObject,
    pub only_container_changes: bool,
}

impl ChangesLookup for Server {
    async fn changes(
        &self,
        request: ChangesRequest,
        object: MethodObject,
        access_token: &AccessToken,
    ) -> trc::Result<IntermediateChangesResponse> {
        // Map collection and validate ACLs
        let (collection, is_container) = match object {
            MethodObject::Email => {
                access_token.assert_has_access(request.account_id, Collection::Email)?;
                (SyncCollection::Email, false)
            }
            MethodObject::Mailbox => {
                access_token.assert_has_access(request.account_id, Collection::Mailbox)?;

                (SyncCollection::Email, true)
            }
            MethodObject::Thread => {
                access_token.assert_has_access(request.account_id, Collection::Email)?;

                (SyncCollection::Thread, true)
            }
            MethodObject::Identity => {
                access_token.assert_is_member(request.account_id)?;

                (SyncCollection::Identity, false)
            }
            MethodObject::EmailSubmission => {
                access_token.assert_is_member(request.account_id)?;

                (SyncCollection::EmailSubmission, false)
            }
            MethodObject::AddressBook => {
                access_token.assert_has_access(request.account_id, Collection::AddressBook)?;

                (SyncCollection::AddressBook, true)
            }
            MethodObject::ContactCard => {
                access_token.assert_has_access(request.account_id, Collection::ContactCard)?;

                (SyncCollection::AddressBook, false)
            }
            MethodObject::FileNode => {
                access_token.assert_has_access(request.account_id, Collection::FileNode)?;

                (SyncCollection::FileNode, false)
            }
            MethodObject::Calendar => {
                access_token.assert_has_access(request.account_id, Collection::Calendar)?;

                (SyncCollection::Calendar, true)
            }
            MethodObject::CalendarEvent => {
                access_token.assert_has_access(request.account_id, Collection::CalendarEvent)?;

                (SyncCollection::Calendar, false)
            }
            MethodObject::CalendarEventNotification => {
                access_token.assert_is_member(request.account_id)?;

                (SyncCollection::CalendarEventNotification, false)
            }
            MethodObject::ShareNotification => {
                access_token.assert_is_member(request.account_id)?;

                (SyncCollection::ShareNotification, false)
            }
            _ => {
                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
        };
        let max_changes = std::cmp::min(
            request
                .max_changes
                .filter(|n| *n != 0)
                .unwrap_or(usize::MAX),
            self.core.jmap.changes_max_results.unwrap_or(usize::MAX),
        );
        let mut response: ChangesResponse<NullObject> = ChangesResponse {
            account_id: request.account_id,
            old_state: request.since_state.clone(),
            new_state: State::Initial,
            has_more_changes: false,
            created: vec![],
            updated: vec![],
            destroyed: vec![],
            updated_properties: None,
        };
        let account_id = request.account_id.document_id();

        let (items_sent, changelog) = match &request.since_state {
            State::Initial => {
                let changelog = self
                    .store()
                    .changes(account_id, collection.into(), Query::All)
                    .await?;
                if changelog.changes.is_empty() && changelog.from_change_id == 0 {
                    return Ok(IntermediateChangesResponse {
                        response,
                        object,
                        only_container_changes: false,
                    });
                }

                (0, changelog)
            }
            State::Exact(change_id) => (
                0,
                self.store()
                    .changes(account_id, collection.into(), Query::Since(*change_id))
                    .await?,
            ),
            State::Intermediate(intermediate_state) => {
                let changelog = self
                    .store()
                    .changes(
                        account_id,
                        collection.into(),
                        Query::RangeInclusive(intermediate_state.from_id, intermediate_state.to_id),
                    )
                    .await?;
                if (is_container
                    && intermediate_state.items_sent >= changelog.total_container_changes())
                    || (!is_container
                        && intermediate_state.items_sent >= changelog.total_item_changes())
                {
                    (
                        0,
                        self.store()
                            .changes(
                                account_id,
                                collection.into(),
                                Query::Since(intermediate_state.to_id),
                            )
                            .await?,
                    )
                } else {
                    (intermediate_state.items_sent, changelog)
                }
            }
        };

        if changelog.is_truncated && request.since_state != State::Initial {
            return Err(trc::JmapEvent::CannotCalculateChanges
                .into_err()
                .details("Changelog has been truncated"));
        }

        let mut changes = changelog
            .changes
            .into_iter()
            .filter(|change| {
                (is_container && change.is_container_change())
                    || (!is_container && change.is_item_change())
            })
            .skip(items_sent)
            .peekable();

        let mut items_changed = false;
        for change in (&mut changes).take(max_changes) {
            match change {
                Change::InsertContainer(item) | Change::InsertItem(item) => {
                    response.created.push(item.into());
                }
                Change::UpdateContainer(item) | Change::UpdateItem(item) => {
                    response.updated.push(item.into());
                    items_changed = true;
                }
                Change::DeleteContainer(item) | Change::DeleteItem(item) => {
                    response.destroyed.push(item.into());
                }
                Change::UpdateContainerProperty(item) => {
                    response.updated.push(item.into());
                }
            };
        }

        let change_id = (if is_container {
            changelog.container_change_id
        } else {
            changelog.item_change_id
        })
        .unwrap_or(changelog.to_change_id);

        response.has_more_changes = changes.peek().is_some();
        response.new_state = if response.has_more_changes {
            State::new_intermediate(
                changelog.from_change_id,
                change_id,
                items_sent + max_changes,
            )
        } else {
            State::new_exact(change_id)
        };

        Ok(IntermediateChangesResponse {
            only_container_changes: is_container && !response.updated.is_empty() && !items_changed,
            response,
            object,
        })
    }
}

impl IntermediateChangesResponse {
    pub fn into_method_response(self) -> ResponseMethod<'static> {
        ResponseMethod::Changes(match self.object {
            MethodObject::Email => ChangesResponseMethod::Email(transmute_response(self.response)),
            MethodObject::Mailbox => {
                let mut response = transmute_response(self.response);
                if self.only_container_changes {
                    response.updated_properties = vec![
                        MailboxProperty::TotalEmails.into(),
                        MailboxProperty::UnreadEmails.into(),
                        MailboxProperty::TotalThreads.into(),
                        MailboxProperty::UnreadThreads.into(),
                    ]
                    .into();
                }
                ChangesResponseMethod::Mailbox(response)
            }
            MethodObject::Thread => {
                ChangesResponseMethod::Thread(transmute_response(self.response))
            }
            MethodObject::Identity => {
                ChangesResponseMethod::Identity(transmute_response(self.response))
            }
            MethodObject::EmailSubmission => {
                ChangesResponseMethod::EmailSubmission(transmute_response(self.response))
            }
            MethodObject::AddressBook => {
                ChangesResponseMethod::AddressBook(transmute_response(self.response))
            }
            MethodObject::ContactCard => {
                ChangesResponseMethod::ContactCard(transmute_response(self.response))
            }
            MethodObject::FileNode => {
                ChangesResponseMethod::FileNode(transmute_response(self.response))
            }
            MethodObject::Calendar => {
                ChangesResponseMethod::Calendar(transmute_response(self.response))
            }
            MethodObject::CalendarEvent => {
                ChangesResponseMethod::CalendarEvent(transmute_response(self.response))
            }
            MethodObject::CalendarEventNotification => {
                ChangesResponseMethod::CalendarEventNotification(transmute_response(self.response))
            }
            MethodObject::ShareNotification => {
                ChangesResponseMethod::ShareNotification(transmute_response(self.response))
            }
            MethodObject::ParticipantIdentity
            | MethodObject::Core
            | MethodObject::Blob
            | MethodObject::PushSubscription
            | MethodObject::SearchSnippet
            | MethodObject::VacationResponse
            | MethodObject::SieveScript
            | MethodObject::Principal
            | MethodObject::Quota => unreachable!(),
        })
    }
}

fn transmute_response<T: JmapObject>(response: ChangesResponse<NullObject>) -> ChangesResponse<T> {
    ChangesResponse {
        account_id: response.account_id,
        old_state: response.old_state,
        new_state: response.new_state,
        has_more_changes: response.has_more_changes,
        created: response.created,
        updated: response.updated,
        destroyed: response.destroyed,
        updated_properties: None,
    }
}
