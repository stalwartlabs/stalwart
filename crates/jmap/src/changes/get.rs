/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::auth::JmapAuthorization,
    changes::{
        page::{
            LogRead, MetadataChanges, PartialProperties, UpdatedProperties, ViewerChange,
            ViewerChanges, fill_page,
        },
        state::{JmapCacheState, max_state},
    },
    participant_identity::changes::ParticipantIdentityChanges,
};
use calcard::{jscalendar::JSCalendarProperty, jscontact::JSContactProperty};
use common::{Server, auth::AccessToken, storage::metadata::MetadataViewer};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use groupware::{
    cache::GroupwareCache,
    calendar::{EVENT_SECRET, notification::CalendarNotificationViewers},
};
use jmap_proto::{
    method::{
        PropertyWrapper,
        changes::{ChangesRequest, ChangesResponse},
    },
    object::{
        JmapObject, NullObject, addressbook::AddressBookProperty, calendar::CalendarProperty,
        email::EmailProperty, file_node::FileNodeProperty, mailbox::MailboxProperty,
    },
    request::{capability::CapabilityIds, method::MethodObject},
    response::{ChangesResponseMethod, ResponseMethod},
    types::state::State,
};
use jmap_tools::Property;
use std::future::Future;
use store::{
    query::log::{Change, Query},
    roaring::RoaringBitmap,
    write::LogCollection,
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    id::Id,
    type_state::DataType,
};

pub trait ChangesLookup: Sync + Send {
    fn changes(
        &self,
        request: ChangesRequest,
        object: MethodObject,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<IntermediateChangesResponse>> + Send;
}

pub struct IntermediateChangesResponse {
    pub response: ChangesResponse<NullObject>,
    pub object: MethodObject,
    pub updated_properties: Option<UpdatedProperties>,
}

#[derive(Clone, Copy)]
struct ChangesScope {
    account_id: u32,
    collection: SyncCollection,
    viewer: Option<MetadataViewer>,
    read_private: bool,
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
                | Change::UpdateContainerPartial(..)
                | Change::UpdateItemMetadata(_) => None,
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
        using: CapabilityIds,
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

        let metadata_type = metadata_type(object);
        let metadata = match metadata_type {
            Some((data_type, _)) if self.jmap_metadata_aware(access_token, using, data_type) => {
                if request.ignore_metadata_only_changes == Some(true) {
                    MetadataChanges::Ignored
                } else {
                    MetadataChanges::Reported
                }
            }
            _ => MetadataChanges::Unsupported,
        };
        let viewer = metadata_type
            .and_then(|(data_type, _)| self.jmap_metadata_viewer(access_token, using, data_type));
        let viewer_change_id = match (viewer, metadata_type) {
            (Some(viewer), Some((_, metadata_collection))) => {
                self.metadata_viewer_state(viewer, account_id, metadata_collection)
                    .await
                    .caused_by(trc::location!())?
                    .change_id
            }
            _ => 0,
        };
        let scope = ChangesScope {
            account_id,
            collection,
            viewer,
            read_private: viewer.is_some() && metadata == MetadataChanges::Reported,
        };

        let (items_sent, log, covers_latest) = match &request.since_state {
            State::Initial => {
                let log = read_changes(
                    self,
                    scope,
                    Query::All,
                    true,
                    scope.read_private && viewer_change_id > 0,
                )
                .await?;
                if log.is_empty() {
                    response.new_state = max_state(State::Initial, viewer_change_id);
                    return Ok(IntermediateChangesResponse {
                        response,
                        object,
                        updated_properties: None,
                    });
                }

                (0, log, true)
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

                let mut read_shared = true;
                if let Some(last_state) = last_state {
                    let shared_change_id = match last_state {
                        State::Exact(shared_change_id) => shared_change_id,
                        _ => 0,
                    };
                    response.new_state = max_state(last_state, viewer_change_id);

                    if response.new_state == State::Exact(*change_id) {
                        return Ok(IntermediateChangesResponse {
                            response,
                            object,
                            updated_properties: None,
                        });
                    }

                    read_shared = viewer.is_none()
                        || *change_id < shared_change_id
                        || *change_id > viewer_change_id;
                }

                (
                    0,
                    read_changes(
                        self,
                        scope,
                        Query::Since(*change_id),
                        read_shared,
                        scope.read_private && viewer_change_id > *change_id,
                    )
                    .await?,
                    true,
                )
            }
            State::Intermediate(intermediate_state) => {
                let log = read_changes(
                    self,
                    scope,
                    Query::RangeInclusive(intermediate_state.from_id, intermediate_state.to_id),
                    true,
                    scope.read_private && viewer_change_id >= intermediate_state.from_id,
                )
                .await?;
                let total = log.total(is_container);
                if intermediate_state.items_sent >= total {
                    (
                        0,
                        read_changes(
                            self,
                            scope,
                            Query::Since(intermediate_state.to_id),
                            true,
                            scope.read_private && viewer_change_id >= intermediate_state.to_id,
                        )
                        .await?,
                        true,
                    )
                } else {
                    (intermediate_state.items_sent, log, false)
                }
            }
        };

        if request.since_state != State::Initial {
            if log.is_truncated() {
                return Err(trc::JmapEvent::CannotCalculateChanges
                    .into_err()
                    .details("Change log is truncated"));
            } else if !log.is_valid_since() {
                return Err(trc::JmapEvent::CannotCalculateChanges
                    .into_err()
                    .details("Since state is invalid"));
            }
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
        let visible = |change: ViewerChange| {
            let Some(allowed) = allowed_ids.as_ref() else {
                return Some(change);
            };
            let inner = change.change();
            let id = if is_container {
                inner.container_id()
            } else {
                inner.item_id()
            }?;

            if allowed.contains(id as u32) {
                Some(change)
            } else {
                hidden_changes.rewrite(inner, id).map(ViewerChange::Shared)
            }
        };
        let partial = if object == MethodObject::Mailbox {
            PartialProperties::Counts
        } else {
            PartialProperties::Unknown
        };

        let first_change_id = log.first_change_id();
        let last_change_id = log.last_change_id(is_container);
        let private_change_id = log.private_change_id(is_container);
        let page = match log.into_changes(is_container) {
            ViewerChanges::Shared(changes) => fill_page(
                changes
                    .into_iter()
                    .filter(|change| {
                        (is_container && change.is_container_change())
                            || (!is_container && change.is_item_change())
                    })
                    .map(ViewerChange::Shared)
                    .filter_map(visible),
                items_sent,
                max_changes,
                metadata,
                partial,
                &mut response,
            ),
            ViewerChanges::Merged(changes) => fill_page(
                changes.into_iter().filter_map(visible),
                items_sent,
                max_changes,
                metadata,
                partial,
                &mut response,
            ),
        };

        response.has_more_changes = page.has_more;
        if page.has_more {
            response.new_state =
                State::new_intermediate(first_change_id, last_change_id, items_sent + max_changes);
        } else if response.new_state == State::Initial {
            response.new_state = State::new_exact(if covers_latest {
                last_change_id.max(viewer_change_id)
            } else {
                last_change_id
            });
        } else {
            response.new_state = max_state(response.new_state, private_change_id);
        }

        Ok(IntermediateChangesResponse {
            response,
            object,
            updated_properties: page.updated_properties,
        })
    }
}

async fn read_changes(
    server: &Server,
    scope: ChangesScope,
    query: Query,
    read_shared: bool,
    read_private: bool,
) -> trc::Result<LogRead> {
    let store = server.store();
    let shared = if read_shared {
        Some(
            store
                .changes(scope.account_id, scope.collection.into(), query)
                .await?,
        )
    } else {
        None
    };
    let private = match scope.viewer {
        Some(viewer) if read_private => Some(
            store
                .changes(
                    scope.account_id,
                    LogCollection::Private {
                        collection: scope.collection,
                        viewer: viewer.account_id(),
                    },
                    query,
                )
                .await?,
        ),
        _ => None,
    };
    Ok(LogRead { shared, private })
}

fn metadata_type(object: MethodObject) -> Option<(DataType, Collection)> {
    match object {
        MethodObject::Email => Some((DataType::Email, Collection::Email)),
        MethodObject::Mailbox => Some((DataType::Mailbox, Collection::Mailbox)),
        MethodObject::Calendar => Some((DataType::Calendar, Collection::Calendar)),
        MethodObject::CalendarEvent => Some((DataType::CalendarEvent, Collection::CalendarEvent)),
        MethodObject::AddressBook => Some((DataType::AddressBook, Collection::AddressBook)),
        MethodObject::ContactCard => Some((DataType::ContactCard, Collection::ContactCard)),
        MethodObject::FileNode => Some((DataType::FileNode, Collection::FileNode)),
        _ => None,
    }
}

impl IntermediateChangesResponse {
    pub fn into_method_response(self) -> ResponseMethod<'static> {
        let properties = self.updated_properties;
        let response = self.response;
        ResponseMethod::Changes(match self.object {
            MethodObject::Email => ChangesResponseMethod::Email(transmute_response(
                response,
                updated_properties(
                    properties,
                    EmailProperty::Metadata,
                    EmailProperty::PrivateMetadata,
                    &[],
                ),
            )),
            MethodObject::Mailbox => ChangesResponseMethod::Mailbox(transmute_response(
                response,
                updated_properties(
                    properties,
                    MailboxProperty::Metadata,
                    MailboxProperty::PrivateMetadata,
                    &[
                        MailboxProperty::TotalEmails,
                        MailboxProperty::UnreadEmails,
                        MailboxProperty::TotalThreads,
                        MailboxProperty::UnreadThreads,
                    ],
                ),
            )),
            MethodObject::Thread => {
                ChangesResponseMethod::Thread(transmute_response(response, None))
            }
            MethodObject::Identity => {
                ChangesResponseMethod::Identity(transmute_response(response, None))
            }
            MethodObject::EmailSubmission => {
                ChangesResponseMethod::EmailSubmission(transmute_response(response, None))
            }
            MethodObject::AddressBook => ChangesResponseMethod::AddressBook(transmute_response(
                response,
                updated_properties(
                    properties,
                    AddressBookProperty::Metadata,
                    AddressBookProperty::PrivateMetadata,
                    &[],
                ),
            )),
            MethodObject::ContactCard => ChangesResponseMethod::ContactCard(transmute_response(
                response,
                updated_properties(
                    properties,
                    JSContactProperty::<Id>::Metadata,
                    JSContactProperty::<Id>::PrivateMetadata,
                    &[],
                ),
            )),
            MethodObject::FileNode => ChangesResponseMethod::FileNode(transmute_response(
                response,
                updated_properties(
                    properties,
                    FileNodeProperty::Metadata,
                    FileNodeProperty::PrivateMetadata,
                    &[],
                ),
            )),
            MethodObject::Calendar => ChangesResponseMethod::Calendar(transmute_response(
                response,
                updated_properties(
                    properties,
                    CalendarProperty::Metadata,
                    CalendarProperty::PrivateMetadata,
                    &[],
                ),
            )),
            MethodObject::CalendarEvent => {
                ChangesResponseMethod::CalendarEvent(transmute_response(
                    response,
                    updated_properties(
                        properties,
                        JSCalendarProperty::<Id>::Metadata,
                        JSCalendarProperty::<Id>::PrivateMetadata,
                        &[],
                    ),
                ))
            }
            MethodObject::CalendarEventNotification => {
                ChangesResponseMethod::CalendarEventNotification(transmute_response(response, None))
            }
            MethodObject::ShareNotification => {
                ChangesResponseMethod::ShareNotification(transmute_response(response, None))
            }
            MethodObject::ParticipantIdentity => {
                ChangesResponseMethod::ParticipantIdentity(transmute_response(response, None))
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

fn updated_properties<P: Property + Clone>(
    properties: Option<UpdatedProperties>,
    metadata: P,
    private_metadata: P,
    counts: &[P],
) -> Option<Vec<PropertyWrapper<P>>> {
    let properties = properties?;
    let mut names = Vec::with_capacity(counts.len() + 2);
    if properties.has_counts() {
        names.extend(counts.iter().cloned().map(PropertyWrapper::from));
    }
    if properties.has_metadata() {
        names.push(metadata.into());
    }
    if properties.has_private_metadata() {
        names.push(private_metadata.into());
    }
    Some(names)
}

fn transmute_response<T: JmapObject>(
    response: ChangesResponse<NullObject>,
    updated_properties: Option<Vec<PropertyWrapper<T::Property>>>,
) -> Box<ChangesResponse<T>> {
    Box::new(ChangesResponse {
        account_id: response.account_id,
        old_state: response.old_state,
        new_state: response.new_state,
        has_more_changes: response.has_more_changes,
        created: response.created,
        updated: response.updated,
        destroyed: response.destroyed,
        updated_properties,
    })
}
