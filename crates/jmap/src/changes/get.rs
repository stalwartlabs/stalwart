/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::auth::JmapAuthorization, changes::state::JmapCacheState,
    participant_identity::changes::ParticipantIdentityChanges,
};
use common::{Server, auth::AccessToken};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use groupware::{
    cache::GroupwareCache,
    calendar::{EVENT_SECRET, notification::CalendarNotificationViewers},
};
use jmap_proto::{
    method::changes::{ChangesRequest, ChangesResponse},
    object::{JmapObject, NullObject, mailbox::MailboxProperty},
    request::method::MethodObject,
    response::{ChangesResponseMethod, ResponseMethod},
    types::state::State,
};
use std::future::Future;
use store::{
    query::log::{Change, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum HiddenChanges {
    Drop,
    ReportAsDestroyed,
}

impl HiddenChanges {
    fn for_object(object: MethodObject) -> Self {
        match object {
            MethodObject::CalendarEvent
            | MethodObject::Calendar
            | MethodObject::AddressBook
            | MethodObject::ContactCard
            | MethodObject::FileNode
            | MethodObject::Mailbox
            | MethodObject::CalendarEventNotification => HiddenChanges::ReportAsDestroyed,
            _ => HiddenChanges::Drop,
        }
    }

    fn rewrite(self, change: Change, id: u64) -> Option<Change> {
        match self {
            HiddenChanges::Drop => None,
            HiddenChanges::ReportAsDestroyed => match change {
                Change::DeleteItem(_) | Change::DeleteContainer(_) => Some(change),
                Change::UpdateItem(_) => Some(Change::DeleteItem(id)),
                Change::UpdateContainer(_) => Some(Change::DeleteContainer(id)),
                Change::InsertItem(_)
                | Change::InsertContainer(_)
                | Change::UpdateContainerProperty(_) => None,
            },
        }
    }
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
                access_token.assert_has_access(request.account_id, Collection::CalendarEvent)?;

                (SyncCollection::CalendarEventNotification, false)
            }
            MethodObject::ShareNotification => {
                access_token.assert_is_member(request.account_id)?;

                (SyncCollection::ShareNotification, false)
            }
            MethodObject::ParticipantIdentity => {
                access_token.assert_is_member(request.account_id)?;

                return self.participant_identity_changes(request).await;
            }
            _ => {
                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
        };
        let max_changes = match request.max_changes {
            Some(0) => {
                return Err(trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details("maxChanges must be greater than 0."));
            }
            Some(max_changes) => max_changes.min(self.core.jmap.changes_max_results),
            None => self.core.jmap.changes_max_results,
        };
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
            State::Exact(change_id) => {
                let last_state = match collection {
                    SyncCollection::Calendar
                    | SyncCollection::AddressBook
                    | SyncCollection::FileNode => self
                        .fetch_groupware_resources(
                            access_token.account_id(),
                            account_id,
                            collection,
                        )
                        .await
                        .caused_by(trc::location!())?
                        .get_state(is_container)
                        .into(),
                    SyncCollection::Email => self
                        .get_cached_messages(account_id)
                        .await?
                        .get_state(is_container)
                        .into(),
                    _ => None,
                };

                if let Some(last_state) = last_state {
                    response.new_state = last_state;

                    if response.new_state == State::Exact(*change_id) {
                        return Ok(IntermediateChangesResponse {
                            response,
                            object,
                            only_container_changes: false,
                        });
                    }
                }

                (
                    0,
                    self.store()
                        .changes(account_id, collection.into(), Query::Since(*change_id))
                        .await?,
                )
            }
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

        if (changelog.is_truncated || changelog.from_change_id == 0)
            && request.since_state != State::Initial
        {
            return Err(trc::JmapEvent::CannotCalculateChanges.into_err().details(
                if changelog.is_truncated {
                    "Change log is truncated"
                } else {
                    "Since state is invalid"
                },
            ));
        }

        let allowed_ids: Option<RoaringBitmap> = if object
            == MethodObject::CalendarEventNotification
        {
            let cache = self
                .fetch_groupware_resources(
                    access_token.account_id(),
                    account_id,
                    SyncCollection::CalendarEventNotification,
                )
                .await
                .caused_by(trc::location!())?;
            Some(
                self.notification_viewer(access_token, account_id)
                    .await
                    .caused_by(trc::location!())?
                    .visible_notifications(&cache),
            )
        } else if access_token.is_member(account_id) {
            None
        } else {
            Some(match object {
                MethodObject::Email => self
                    .get_cached_messages(account_id)
                    .await?
                    .shared_messages(access_token, Acl::ReadItems),
                MethodObject::Mailbox => self
                    .get_cached_messages(account_id)
                    .await?
                    .shared_mailboxes(access_token, Acl::Read),
                MethodObject::Thread => {
                    let cache = self.get_cached_messages(account_id).await?;
                    let shared = cache.shared_messages(access_token, Acl::ReadItems);
                    let mut threads = RoaringBitmap::new();
                    for item in cache.emails.iter() {
                        if shared.contains(item.document_id()) {
                            threads.insert(item.thread_id());
                        }
                    }
                    threads
                }
                MethodObject::AddressBook => self
                    .fetch_groupware_resources(
                        access_token.account_id(),
                        account_id,
                        SyncCollection::AddressBook,
                    )
                    .await?
                    .shared_containers(access_token, [Acl::Read, Acl::ReadItems], true),
                MethodObject::ContactCard => self
                    .fetch_groupware_resources(
                        access_token.account_id(),
                        account_id,
                        SyncCollection::AddressBook,
                    )
                    .await?
                    .shared_items(access_token, [Acl::ReadItems], true),
                MethodObject::Calendar => self
                    .fetch_groupware_resources(
                        access_token.account_id(),
                        account_id,
                        SyncCollection::Calendar,
                    )
                    .await?
                    .shared_containers(access_token, [Acl::Read, Acl::ReadItems], true),
                MethodObject::CalendarEvent => {
                    let cache = self
                        .fetch_groupware_resources(
                            access_token.account_id(),
                            account_id,
                            SyncCollection::Calendar,
                        )
                        .await?;
                    let mut shared_ids = cache.shared_items(access_token, [Acl::ReadItems], true);
                    shared_ids -= cache.event_ids_with_flags(EVENT_SECRET);
                    shared_ids
                }
                MethodObject::FileNode => {
                    self.fetch_groupware_resources(
                        access_token.account_id(),
                        account_id,
                        SyncCollection::FileNode,
                    )
                    .await?
                    .file_access(access_token)
                    .discoverable
                }
                _ => RoaringBitmap::new(),
            })
        };

        let hidden_changes = HiddenChanges::for_object(object);
        let mut changes = changelog
            .changes
            .into_iter()
            .filter(|change| {
                (is_container && change.is_container_change())
                    || (!is_container && change.is_item_change())
            })
            .filter_map(|change| {
                let Some(allowed) = allowed_ids.as_ref() else {
                    return Some(change);
                };
                let id = if is_container {
                    change.container_id()
                } else {
                    change.item_id()
                }?;

                if allowed.contains(id as u32) {
                    Some(change)
                } else {
                    hidden_changes.rewrite(change, id)
                }
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
        if response.has_more_changes {
            response.new_state = State::new_intermediate(
                changelog.from_change_id,
                change_id,
                items_sent + max_changes,
            );
        } else if response.new_state == State::Initial {
            response.new_state = State::new_exact(change_id)
        }

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
            MethodObject::ParticipantIdentity => {
                ChangesResponseMethod::ParticipantIdentity(transmute_response(self.response))
            }
            MethodObject::Core
            | MethodObject::Blob
            | MethodObject::PushSubscription
            | MethodObject::SearchSnippet
            | MethodObject::VacationResponse
            | MethodObject::SieveScript
            | MethodObject::Principal
            | MethodObject::Quota
            | MethodObject::Registry(_) => unreachable!(),
        })
    }
}

fn transmute_response<T: JmapObject>(
    response: ChangesResponse<NullObject>,
) -> Box<ChangesResponse<T>> {
    Box::new(ChangesResponse {
        account_id: response.account_id,
        old_state: response.old_state,
        new_state: response.new_state,
        has_more_changes: response.has_more_changes,
        created: response.created,
        updated: response.updated,
        destroyed: response.destroyed,
        updated_properties: None,
    })
}
