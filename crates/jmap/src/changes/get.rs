/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::{
        auth::JmapAuthorization,
        metadata::{MetadataType, ObjectMetadata},
    },
    changes::{
        page::{
            Coverage, LogRead, MetadataChanges, PageChange, PartialProperties, UpdatedProperties,
            ViewerChange, ViewerChanges, fill_page, private_query,
        },
        state::{JmapCacheState, max_state},
    },
    participant_identity::changes::ParticipantIdentityChanges,
};
use calcard::{jscalendar::JSCalendarProperty, jscontact::JSContactProperty};
use common::{
    GroupwareResources, MessageStoreCache, Server, auth::AccessToken,
    storage::metadata::MetadataViewer,
};
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
use std::{future::Future, sync::Arc};
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

enum Snapshot {
    Messages(Arc<MessageStoreCache>),
    Resources(Arc<GroupwareResources>),
}

impl Snapshot {
    fn state(&self, is_container: bool) -> State {
        match self {
            Snapshot::Messages(cache) => cache.get_state(is_container),
            Snapshot::Resources(cache) => cache.get_state(is_container),
        }
    }

    fn contains(&self, object: MethodObject, is_container: bool, document_id: u32) -> bool {
        match (self, object) {
            (Snapshot::Messages(cache), MethodObject::Mailbox) => {
                cache.mailbox_by_id(&document_id).is_some()
            }
            (Snapshot::Messages(cache), _) => cache.email_by_id(&document_id).is_some(),
            (Snapshot::Resources(cache), MethodObject::FileNode) => {
                cache.has_item_id(&document_id) || cache.has_container_id(&document_id)
            }
            (Snapshot::Resources(cache), _) if is_container => cache.has_container_id(&document_id),
            (Snapshot::Resources(cache), _) => cache.has_item_id(&document_id),
        }
    }
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

        let object_metadata = metadata_type(object)
            .map(|metadata_type| ObjectMetadata::new(self, access_token, using, metadata_type));
        let metadata = match &object_metadata {
            Some(object_metadata) if object_metadata.support().is_some() => {
                if request.ignore_metadata_only_changes == Some(true) {
                    MetadataChanges::Ignored
                } else {
                    MetadataChanges::Reported
                }
            }
            _ => MetadataChanges::Unsupported,
        };
        let viewer = object_metadata.as_ref().and_then(ObjectMetadata::viewer);
        let viewer_change_id = match (viewer, &object_metadata) {
            (Some(viewer), Some(object_metadata)) => {
                self.metadata_viewer_state(viewer, account_id, object_metadata.collection())
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

        let mut snapshot = None;
        let (items_sent, log, coverage) = match &request.since_state {
            State::Initial => {
                let log = read_changes(
                    self,
                    scope,
                    Query::All,
                    true,
                    scope.read_private && viewer_change_id > 0,
                    viewer_change_id,
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

                (0, log, Coverage::Latest { viewer_change_id })
            }
            State::Exact(change_id) => {
                snapshot = match collection {
                    SyncCollection::Calendar
                    | SyncCollection::AddressBook
                    | SyncCollection::FileNode => Some(Snapshot::Resources(
                        self.fetch_groupware_resources(
                            access_token.account_id(),
                            account_id,
                            collection,
                        )
                        .await
                        .caused_by(trc::location!())?,
                    )),
                    SyncCollection::Email => Some(Snapshot::Messages(
                        self.get_cached_messages(account_id).await?,
                    )),
                    _ => None,
                };

                let mut read_shared = true;
                let mut shared_change_id = 0;
                if let Some(last_state) = snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.state(is_container))
                {
                    if let State::Exact(shared) = last_state {
                        shared_change_id = shared;
                    }
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
                        viewer_change_id.max(shared_change_id),
                    )
                    .await?,
                    Coverage::Latest { viewer_change_id },
                )
            }
            State::Intermediate(intermediate_state) => {
                let log = read_changes(
                    self,
                    scope,
                    Query::RangeInclusive(intermediate_state.from_id, intermediate_state.to_id),
                    true,
                    scope.read_private && viewer_change_id >= intermediate_state.from_id,
                    viewer_change_id,
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
                            viewer_change_id,
                        )
                        .await?,
                        Coverage::Latest { viewer_change_id },
                    )
                } else {
                    (intermediate_state.items_sent, log, Coverage::Range)
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
        let visible = |change: Change| {
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
        };
        let partial = if object == MethodObject::Mailbox {
            PartialProperties::Counts
        } else {
            PartialProperties::Unknown
        };

        let exists = |change: &ViewerChange| match (change, &snapshot) {
            (ViewerChange::Private(change), Some(snapshot)) => {
                let id = if is_container {
                    change.container_id()
                } else {
                    change.item_id()
                };
                id.is_some_and(|id| snapshot.contains(object, is_container, id as u32))
            }
            _ => true,
        };

        let bounds = log.bounds(is_container);
        let page = match log.into_changes(is_container) {
            ViewerChanges::Shared(changes) => fill_page(
                changes
                    .into_iter()
                    .filter(|change| {
                        (is_container && change.is_container_change())
                            || (!is_container && change.is_item_change())
                    })
                    .filter_map(visible),
                items_sent,
                max_changes,
                metadata,
                partial,
                &mut response,
            ),
            ViewerChanges::Merged(changes) => fill_page(
                changes.into_iter().filter(exists).filter_map(|change| {
                    let inner = change.change();
                    visible(inner).map(|visible| {
                        if visible == inner {
                            change
                        } else {
                            ViewerChange::Shared(visible)
                        }
                    })
                }),
                items_sent,
                max_changes,
                metadata,
                partial,
                &mut response,
            ),
        };

        response.has_more_changes = page.has_more;
        response.new_state = bounds.new_state(
            response.new_state,
            page.has_more.then_some(items_sent + max_changes),
            coverage,
        );

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
    known_change_id: u64,
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
    let private = match scope.viewer.filter(|_| read_private).and_then(|viewer| {
        private_query(query, shared.as_ref(), known_change_id).map(|query| (viewer, query))
    }) {
        Some((viewer, query)) => Some(
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
        None => None,
    };
    Ok(LogRead { shared, private })
}

fn metadata_type(object: MethodObject) -> Option<MetadataType> {
    match object {
        MethodObject::Email => Some(MetadataType::Email),
        MethodObject::Mailbox => Some(MetadataType::Mailbox),
        MethodObject::Calendar => Some(MetadataType::Calendar),
        MethodObject::CalendarEvent => Some(MetadataType::CalendarEvent),
        MethodObject::AddressBook => Some(MetadataType::AddressBook),
        MethodObject::ContactCard => Some(MetadataType::ContactCard),
        MethodObject::FileNode => Some(MetadataType::FileNode),
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
