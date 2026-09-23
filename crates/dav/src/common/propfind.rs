/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedResource, DavCollection, DavQuery, DavQueryFilter, SyncType,
    acl::{DavAclHandler, Privileges},
    lock::{LockData, build_lock_key},
    uri::{UriResource, Urn},
};
use crate::{
    DavError, DavErrorCondition,
    calendar::{
        CALENDAR_CONTAINER_PROPS, CALENDAR_ITEM_PROPS, CalendarEventView,
        query::{CalendarQueryHandler, try_parse_tz},
    },
    card::{
        CARD_CONTAINER_PROPS, CARD_ITEM_PROPS,
        query::{serialize_vcard_with_props, vcard_query},
    },
    common::{DavQueryResource, acl::current_user_privilege_set, uri::DavUriResource},
    file::{FILE_CONTAINER_PROPS, FILE_ITEM_PROPS, is_symlink},
    principal::{
        CurrentUserPrincipal,
        propfind::{PrincipalPropFind, build_home_set},
    },
};
use calcard::{common::timezone::Tz, icalendar::ICalendarComponentType};
use common::{
    DavResourcePath, GroupwareResources, Server,
    auth::{AccessToken, AccountCache},
    sharing::file::FileNodeAccess,
    storage::dav::canonical_dav_resource_uri,
};
use dav_proto::{
    Depth, RequestHeaders,
    parser::header::dav_base_uri,
    requests::NsDeadProperty,
    schema::{
        Collation, Namespace,
        property::{
            ActiveLock, CalDavProperty, CardDavProperty, Comp, DavProperty, DavValue,
            PrincipalProperty, Privilege, ReportSet, ResourceType, Rfc1123DateTime,
            SupportedCollation, SupportedLock, WebDavProperty,
        },
        request::{DavDeadProperty, DavPropertyValue, PropFind},
        response::{
            AclRestrictions, BaseCondition, Href, List, MultiStatus, PropStat, Response,
            SupportedPrivilege,
        },
    },
};
use groupware::calendar::{SCHEDULE_INBOX_ID, SupportedComponent};
use groupware::{
    DavCalendarResource, DavResourceName,
    cache::GroupwareCache,
    calendar::{
        ArchivedTimezone, CalendarEvent, EVENT_HAS_ALARMS, EVENT_HAS_DEAD_PROPERTIES,
        EVENT_PRIVATE, EVENT_SECRET, alerts::DefaultAlertsResolver, privacy::EventPrivacy,
    },
    contact::{CARD_HAS_DEAD_PROPERTIES, ContactCard},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::{enums::Permission, prelude::ObjectType};
use std::{borrow::Cow, sync::Arc};
use store::{
    ahash::AHashMap,
    query::log::{Change, Query},
    roaring::RoaringBitmap,
};
use store::{
    registry::RegistryQuery,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    dead_property::DeadProperty,
    field::{CalendarEventField, CalendarNotificationField, ContactField, Field},
};
use utils::map::bitmap::Bitmap;

pub(crate) trait PropFindRequestHandler: Sync + Send {
    fn handle_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropFind,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn handle_dav_query(
        &self,
        access_token: &AccessToken,
        query: DavQuery<'_>,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn dav_quota(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<PropFindAccountQuota>> + Send;
}

pub(crate) struct PropFindData {
    pub accounts: AHashMap<u32, PropFindAccountData>,
}

fn content_field(collection: Collection) -> Option<Field> {
    match collection {
        Collection::CalendarEvent => Some(CalendarEventField::Content.field()),
        Collection::CalendarEventNotification => Some(CalendarNotificationField::Content.field()),
        Collection::ContactCard => Some(ContactField::Content.field()),
        _ => None,
    }
}

struct ContentDemand {
    dead_properties: bool,
    event_content_length: bool,
    is_owner: bool,
}

impl ContentDemand {
    fn view_flags(&self) -> u16 {
        if self.is_owner {
            EVENT_HAS_ALARMS
        } else {
            EVENT_HAS_ALARMS | EVENT_PRIVATE | EVENT_SECRET
        }
    }

    fn is_met_by(
        &self,
        archive: &Archive<ArchiveBytes>,
        collection: Collection,
    ) -> trc::Result<bool> {
        match collection {
            Collection::CalendarEvent => {
                let flags = archive.unarchive::<CalendarEvent>()?.flags.to_native();
                Ok(
                    (self.dead_properties && flags & EVENT_HAS_DEAD_PROPERTIES != 0)
                        || (self.event_content_length && flags & self.view_flags() != 0),
                )
            }
            Collection::ContactCard => Ok(self.dead_properties
                && archive.unarchive::<ContactCard>()?.flags.to_native()
                    & CARD_HAS_DEAD_PROPERTIES
                    != 0),
            _ => Ok(false),
        }
    }
}

#[derive(Default)]
pub(crate) struct PropFindAccountData {
    pub resources: Option<Arc<GroupwareResources>>,
    pub quota: Option<PropFindAccountQuota>,
    pub owner: Option<Href>,
    pub locks: Option<Archive<ArchiveBytes>>,
    pub locks_not_found: bool,
    pub file_access: Option<FileNodeAccess>,
}

#[derive(Clone, Default)]
pub(crate) struct PropFindAccountQuota {
    pub used: u64,
    pub available: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct PropFindItem {
    pub name: String,
    pub account_id: u32,
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub is_container: bool,
    pub is_discover_only: bool,
}

impl PropFindRequestHandler for Server {
    async fn handle_propfind_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropFind,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self.validate_uri(access_token, headers.uri).await?;

        // Reject Infinity depth for certain queries
        let return_children = match headers.depth {
            Depth::One | Depth::None => true,
            Depth::Zero => false,
            Depth::Infinity => match resource.collection {
                Collection::Principal => true,
                Collection::Calendar | Collection::AddressBook
                    if resource.account_id.is_some() && resource.resource.is_some() =>
                {
                    true
                }
                Collection::CalendarEventNotification if resource.account_id.is_some() => true,
                _ => {
                    return Err(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::PropFindFiniteDepth,
                    )
                    .into());
                }
            },
        };

        // List shared resources
        if let Some(account_id) = resource.account_id {
            match resource.collection {
                Collection::FileNode
                | Collection::Calendar
                | Collection::AddressBook
                | Collection::CalendarEventNotification => {
                    // Validate permissions
                    access_token.enforce_permission(match resource.collection {
                        Collection::FileNode => Permission::DavFilePropFind,
                        Collection::Calendar
                        | Collection::CalendarEvent
                        | Collection::CalendarEventNotification => Permission::DavCalPropFind,
                        Collection::AddressBook | Collection::ContactCard => {
                            Permission::DavCardPropFind
                        }
                        _ => unreachable!(),
                    })?;

                    self.handle_dav_query(
                        access_token,
                        DavQuery::propfind(
                            UriResource::new_owned(
                                resource.collection,
                                account_id,
                                resource.resource,
                            ),
                            request,
                            headers,
                        ),
                    )
                    .await
                }
                Collection::Principal => {
                    let mut response = MultiStatus::new(Vec::with_capacity(16));

                    if resource.resource.is_some() {
                        response.add_response(Response::new_status(
                            [headers.uri.to_string()],
                            StatusCode::NOT_FOUND,
                        ));
                    } else if access_token.has_account_access(account_id)
                        || (self.core.groupware.allow_directory_query
                            && access_token.has_permission(Permission::DavPrincipalList))
                        || access_token.has_permission(Permission::SysAccountQuery)
                    {
                        self.prepare_principal_propfind_response(
                            access_token,
                            Collection::Principal,
                            [account_id].into_iter(),
                            &request,
                            &mut response,
                        )
                        .await?;
                    } else {
                        response.add_response(Response::new_status(
                            [headers.uri.to_string()],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                        .with_xml_body(response.to_string()))
                }
                _ => unreachable!(),
            }
        } else {
            let mut response = MultiStatus::new(Vec::with_capacity(16));

            // Add container info
            if !headers.depth_no_root {
                add_base_collection_response(
                    self,
                    &request,
                    resource.collection,
                    access_token,
                    &mut response,
                )
                .await?;
            }

            if return_children {
                let ids = if !matches!(resource.collection, Collection::Principal) {
                    // Validate permissions
                    access_token.enforce_permission(match resource.collection {
                        Collection::FileNode => Permission::DavFilePropFind,
                        Collection::Calendar
                        | Collection::CalendarEvent
                        | Collection::CalendarEventNotification => Permission::DavCalPropFind,
                        Collection::AddressBook | Collection::ContactCard => {
                            Permission::DavCardPropFind
                        }
                        _ => unreachable!(),
                    })?;
                    RoaringBitmap::from_iter(
                        access_token.all_ids_by_collection(resource.collection),
                    )
                } else if (self.core.groupware.allow_directory_query
                    && access_token.has_permission(Permission::DavPrincipalList))
                    || access_token.has_permission(Permission::SysAccountQuery)
                {
                    // Return all principals
                    self.registry()
                        .query::<RoaringBitmap>(
                            RegistryQuery::new(ObjectType::Account)
                                .with_tenant(access_token.tenant_id()),
                        )
                        .await
                        .caused_by(trc::location!())?
                } else {
                    RoaringBitmap::from_iter(access_token.all_ids())
                };

                self.prepare_principal_propfind_response(
                    access_token,
                    resource.collection,
                    ids.into_iter(),
                    &request,
                    &mut response,
                )
                .await?;
            }

            Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
        }
    }

    async fn handle_dav_query(
        &self,
        access_token: &AccessToken,
        mut query: DavQuery<'_>,
    ) -> crate::Result<HttpResponse> {
        let mut response = MultiStatus::new(Vec::with_capacity(16));
        let mut data = PropFindData::new();
        let collection_container;
        let collection_children;
        let sync_collection;
        let mut query_filter = None;
        let mut limit = std::cmp::min(
            query.limit.unwrap_or(u32::MAX) as usize,
            self.core.groupware.max_results,
        );
        let mut is_sync_limited = false;
        let mut is_propfind = false;
        let mut ical_instances_limit = self.core.groupware.max_ical_instances;

        let paths = match std::mem::take(&mut query.resource) {
            DavQueryResource::Uri(resource) => {
                collection_container = resource.collection;
                collection_children = collection_container.child_collection().unwrap();
                sync_collection = SyncCollection::from(collection_container);
                is_propfind = true;

                get(
                    self,
                    access_token,
                    collection_container,
                    collection_children,
                    sync_collection,
                    &query,
                    &mut data,
                    &mut response,
                    resource,
                    limit,
                    &mut is_sync_limited,
                )
                .await?
            }
            DavQueryResource::Multiget {
                hrefs,
                parent_collection,
            } => {
                collection_container = parent_collection;
                collection_children = collection_container.child_collection().unwrap();
                sync_collection = SyncCollection::from(collection_container);

                multiget(
                    self,
                    access_token,
                    collection_container,
                    collection_children,
                    sync_collection,
                    &mut data,
                    &mut response,
                    hrefs,
                )
                .await?
            }
            DavQueryResource::Query {
                filter,
                parent_collection,
                items,
            } => {
                query_filter = Some(filter);
                collection_container = parent_collection;
                collection_children = collection_container.child_collection().unwrap();
                sync_collection = SyncCollection::from(collection_container);

                items
            }
            DavQueryResource::None => unreachable!(),
        };
        response.set_namespace(collection_container.namespace());

        let mut skip_not_found = query.expand;
        let properties = match &query.propfind {
            PropFind::PropName => {
                let (container_props, children_props) = match collection_container {
                    Collection::FileNode => {
                        (FILE_CONTAINER_PROPS.as_slice(), FILE_ITEM_PROPS.as_slice())
                    }
                    Collection::Calendar | Collection::CalendarEventNotification => (
                        CALENDAR_CONTAINER_PROPS.as_slice(),
                        CALENDAR_ITEM_PROPS.as_slice(),
                    ),
                    Collection::AddressBook => {
                        (CARD_CONTAINER_PROPS.as_slice(), CARD_ITEM_PROPS.as_slice())
                    }
                    _ => unreachable!(),
                };

                for property in container_props.iter().chain(children_props) {
                    response.set_namespace(property.namespace());
                }

                for item in paths {
                    let props = if item.is_container {
                        container_props
                            .iter()
                            .cloned()
                            .map(DavPropertyValue::empty)
                            .collect::<Vec<_>>()
                    } else {
                        children_props
                            .iter()
                            .cloned()
                            .map(DavPropertyValue::empty)
                            .collect::<Vec<_>>()
                    };

                    response.add_response(Response::new_propstat(
                        item.name,
                        vec![PropStat::new_list(props)],
                    ));
                }

                return Ok(
                    HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string())
                );
            }
            PropFind::AllProp(items) => {
                skip_not_found = true;
                let mut result = Vec::with_capacity(items.len() + DavProperty::ALL_PROPS.len());
                result.extend(DavProperty::ALL_PROPS);
                result.extend(items.iter().filter(|field| !field.is_all_prop()).cloned());
                result
            }
            PropFind::Prop(items) => items.clone(),
        };

        for property in &properties {
            response.set_namespace(property.namespace());
        }

        let is_scheduling = collection_container == Collection::CalendarEventNotification;
        let account_info = self
            .account(access_token.account_id())
            .await
            .caused_by(trc::location!())?;

        let needs_content = query_filter.is_some()
            || properties.iter().any(|property| {
                matches!(
                    property,
                    DavProperty::CardDav(CardDavProperty::AddressData { .. })
                        | DavProperty::CalDav(CalDavProperty::CalendarData(_))
                )
            });
        let needs_dead_properties = skip_not_found
            || properties
                .iter()
                .any(|property| matches!(property, DavProperty::DeadProperty(_)));
        let needs_content_length = collection_children == Collection::CalendarEvent
            && properties.iter().any(|property| {
                matches!(
                    property,
                    DavProperty::WebDav(WebDavProperty::GetContentLength)
                )
            });

        let mut paths = paths;
        if query_filter.is_none() && paths.len() > limit {
            paths.truncate(limit);
        }

        let mut groups: AHashMap<(u32, Collection), RoaringBitmap> = AHashMap::with_capacity(4);
        for item in &paths {
            if is_scheduling && item.is_container {
                continue;
            }
            let collection = if item.is_container {
                collection_container
            } else {
                collection_children
            };
            groups
                .entry((item.account_id, collection))
                .or_default()
                .insert(item.document_id);
        }

        let content_field = content_field(collection_children);
        let track_carriers = content_field.is_some()
            && (needs_dead_properties || needs_content_length)
            && !needs_content;

        let mut metadata: AHashMap<(u32, u8, u32), Archive<ArchiveBytes>> =
            AHashMap::with_capacity(paths.len());
        let mut carriers: AHashMap<(u32, Collection), RoaringBitmap> = AHashMap::new();
        for ((account_id, collection), documents) in &groups {
            let (account_id, collection) = (*account_id, *collection);
            let content_demand = ContentDemand {
                dead_properties: needs_dead_properties,
                event_content_length: needs_content_length,
                is_owner: access_token.is_member(account_id),
            };
            let mut group_carriers = RoaringBitmap::new();
            self.archives(
                account_id,
                collection,
                Field::ARCHIVE,
                documents,
                |document_id, archive| {
                    if track_carriers
                        && collection == collection_children
                        && content_demand
                            .is_met_by(&archive, collection)
                            .caused_by(trc::location!())?
                    {
                        group_carriers.insert(document_id);
                    }
                    metadata.insert((account_id, collection.into(), document_id), archive);
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

            if !group_carriers.is_empty() {
                carriers.insert((account_id, collection), group_carriers);
            }
        }

        let mut contents: AHashMap<(u32, u8, u32), Archive<ArchiveBytes>> = AHashMap::new();
        if let Some(content_field) = content_field
            && (needs_content || needs_dead_properties || needs_content_length)
        {
            for ((account_id, collection), documents) in &groups {
                let (account_id, collection) = (*account_id, *collection);
                if collection != collection_children {
                    continue;
                }

                let documents = if needs_content {
                    documents
                } else if let Some(carriers) = carriers.get(&(account_id, collection)) {
                    carriers
                } else {
                    continue;
                };

                if documents.is_empty() {
                    continue;
                }

                self.archives(
                    account_id,
                    collection,
                    content_field,
                    documents,
                    |document_id, archive| {
                        contents.insert((account_id, collection.into(), document_id), archive);
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
            }
        }

        let needs_event_view = collection_children == Collection::CalendarEvent
            && (needs_content || needs_content_length);
        let mut default_alerts = DefaultAlertsResolver::default();

        'outer: for item in paths {
            let account_id = item.account_id;
            let personal_id = access_token.personal_id(account_id, collection_container);
            let document_id = item.document_id;
            let collection = if item.is_container {
                collection_container
            } else {
                collection_children
            };

            // Unarchive resource
            let archive = if is_scheduling && item.is_container {
                ArchivedResource::CalendarEventNotificationCollection(
                    item.document_id == SCHEDULE_INBOX_ID,
                )
            } else if let Some(archive_) =
                metadata.get(&(account_id, collection.into(), document_id))
            {
                let mut archive = ArchivedResource::from_archive(
                    archive_,
                    contents.get(&(account_id, collection.into(), document_id)),
                    collection,
                )
                .caused_by(trc::location!())?;

                if needs_event_view
                    && let ArchivedResource::CalendarEvent(event, Some(content)) = &mut archive
                    && let Some((view, merged_overrides)) = self
                        .calendar_event_view(
                            access_token,
                            account_id,
                            event.inner,
                            content.stored(),
                            &mut default_alerts,
                        )
                        .await?
                {
                    content.attach_view(view, merged_overrides);
                }

                archive
            } else {
                response.add_response(Response::new_status([item.name], StatusCode::NOT_FOUND));
                continue;
            };

            // Filter
            let mut calendar_filter = None;
            if let Some(query_filter) = &query_filter {
                match (query_filter, &archive) {
                    (
                        DavQueryFilter::Addressbook(filter),
                        ArchivedResource::ContactCard(_, Some(content)),
                    ) if !vcard_query(&content.card, filter) => {
                        continue;
                    }
                    (
                        DavQueryFilter::Calendar {
                            filter,
                            timezone,
                            max_time_range,
                        },
                        ArchivedResource::CalendarEvent(event, Some(content)),
                    ) => {
                        let default_tz = if let Some(tz) = try_parse_tz(timezone) {
                            tz
                        } else if let Some(calendar_id) = item.parent_id {
                            data.resources(self, access_token, account_id, SyncCollection::Calendar)
                                .await
                                .caused_by(trc::location!())?
                                .calendar_default_tz(calendar_id, account_id)
                                .unwrap_or(Tz::UTC)
                        } else {
                            Tz::UTC
                        };
                        let mut query_handler = CalendarQueryHandler::for_content(
                            event.inner,
                            content,
                            *max_time_range,
                            default_tz,
                        );
                        if !query_handler.filter_content(content, filter) {
                            continue;
                        }
                        calendar_filter = Some(query_handler);
                    }
                    _ => (),
                }
            }

            // Fill properties
            let is_private_view = matches!(
                &archive,
                ArchivedResource::CalendarEvent(event, _)
                    if !access_token.is_member(account_id)
                        && !EventPrivacy::from_flags(event.inner.flags.to_native()).is_public()
            );
            let dead_properties = archive.dead_properties().filter(|_| !is_private_view);
            let mut fields = Vec::with_capacity(properties.len());
            let mut fields_not_found = Vec::new();
            for property in &properties {
                if item.is_discover_only {
                    match property {
                        DavProperty::WebDav(
                            WebDavProperty::ResourceType | WebDavProperty::DisplayName,
                        ) => {}
                        DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                Vec::<Privilege>::new(),
                            ));
                            continue;
                        }
                        _ => {
                            if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                            continue;
                        }
                    }
                }
                match property {
                    DavProperty::WebDav(dav_property) => match dav_property {
                        WebDavProperty::CreationDate => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Timestamp(archive.created()),
                            ));
                        }
                        WebDavProperty::DisplayName => {
                            if let Some(name) = archive
                                .display_name(personal_id)
                                .filter(|_| !is_private_view)
                            {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::String(name.to_string()),
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetContentLanguage => {
                            if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetContentLength => {
                            if let Some(value) = archive.content_length() {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::Uint64(value as u64),
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetContentType => {
                            if let Some(value) = archive.content_type() {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::String(value.to_string()),
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetETag => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::String(archive.etag()),
                            ));
                        }
                        WebDavProperty::GetCTag => {
                            if item.is_container {
                                let ctag = data
                                    .resources(self, access_token, account_id, sync_collection)
                                    .await
                                    .caused_by(trc::location!())?
                                    .highest_change_id;

                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::String(format!("\"{ctag}\"")),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::GetLastModified => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Rfc1123Date(Rfc1123DateTime::new(archive.modified())),
                            ));
                        }
                        WebDavProperty::ResourceType => {
                            if let Some(resource_type) = archive.resource_type() {
                                fields.push(DavPropertyValue::new(property.clone(), resource_type));
                            } else {
                                fields.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::LockDiscovery => {
                            if let Some(locks) = data
                                .locks(self, account_id, collection_container, &item)
                                .await
                                .caused_by(trc::location!())?
                            {
                                fields.push(DavPropertyValue::new(property.clone(), locks));
                            } else {
                                fields.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::SupportedLock => {
                            if !is_scheduling {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    SupportedLock::default(),
                                ));
                            } else {
                                fields.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::SupportedReportSet => {
                            if let Some(report_set) = archive.supported_report_set() {
                                fields.push(DavPropertyValue::new(property.clone(), report_set));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::SyncToken => {
                            let sync_token = data
                                .resources(self, access_token, account_id, sync_collection)
                                .await
                                .caused_by(trc::location!())?
                                .sync_token();

                            fields.push(DavPropertyValue::new(property.clone(), sync_token));
                        }
                        WebDavProperty::CurrentUserPrincipal => {
                            if !query.expand {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![account_info.current_user_principal()],
                                ));
                            } else {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    self.expand_principal(
                                        access_token,
                                        access_token.account_id(),
                                        &query.propfind,
                                    )
                                    .await?
                                    .map(|r| DavValue::Response(Box::new(r)))
                                    .unwrap_or(DavValue::Null),
                                ));
                            }
                        }
                        WebDavProperty::QuotaAvailableBytes => {
                            let available = if item.is_container {
                                data.quota(self, account_id)
                                    .await
                                    .caused_by(trc::location!())?
                                    .available
                            } else {
                                None
                            };

                            if let Some(available) = available {
                                fields.push(DavPropertyValue::new(property.clone(), available));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::QuotaUsedBytes => {
                            if item.is_container {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    data.quota(self, account_id)
                                        .await
                                        .caused_by(trc::location!())?
                                        .used,
                                ));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::Owner => {
                            if !query.expand {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![
                                        data.owner(self, &account_info, account_id)
                                            .await
                                            .caused_by(trc::location!())?,
                                    ],
                                ));
                            } else {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    self.expand_principal(
                                        access_token,
                                        account_id,
                                        &query.propfind,
                                    )
                                    .await?
                                    .map(|r| DavValue::Response(Box::new(r)))
                                    .unwrap_or(DavValue::Null),
                                ));
                            }
                        }
                        WebDavProperty::Group => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        WebDavProperty::SupportedPrivilegeSet => {
                            if !is_scheduling {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![SupportedPrivilege::all_privileges(
                                        collection_container == Collection::Calendar,
                                    )],
                                ));
                            } else {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![SupportedPrivilege::all_scheduling_privileges(matches!(
                                        archive,
                                        ArchivedResource::CalendarEventNotification(..)
                                            | ArchivedResource::CalendarEventNotificationCollection(
                                                true
                                            )
                                    ))],
                                ));
                            }
                        }
                        WebDavProperty::CurrentUserPrivilegeSet => {
                            let privileges = if is_scheduling {
                                Privilege::scheduling(
                                    matches!(
                                        archive,
                                        ArchivedResource::CalendarEventNotification(..)
                                            | ArchivedResource::CalendarEventNotificationCollection(
                                                true
                                            )
                                    ),
                                    access_token.is_member(account_id),
                                )
                            } else if access_token.is_member(account_id) {
                                Privilege::all(matches!(
                                    collection,
                                    Collection::Calendar | Collection::CalendarEvent
                                ))
                            } else if matches!(archive, ArchivedResource::FileNode(_)) {
                                let acl = match data
                                    .accounts
                                    .get(&account_id)
                                    .and_then(|account| account.file_access.as_ref())
                                {
                                    Some(access) => access.acl(item.document_id),
                                    None => data
                                        .resources(self, access_token, account_id, sync_collection)
                                        .await
                                        .caused_by(trc::location!())?
                                        .file_acl(access_token, item.document_id),
                                };
                                current_user_privilege_set(acl)
                            } else if let Some(acls) = archive.acls() {
                                access_token.current_privilege_set(
                                    account_id,
                                    acls,
                                    collection_container == Collection::Calendar,
                                )
                            } else if let Some(parent_id) = item.parent_id {
                                current_user_privilege_set(
                                    data.resources(self, access_token, account_id, sync_collection)
                                        .await
                                        .caused_by(trc::location!())?
                                        .container_acl(access_token, parent_id),
                                )
                            } else {
                                vec![]
                            };

                            if !privileges.is_empty() {
                                fields.push(DavPropertyValue::new(property.clone(), privileges));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::Acl => {
                            if let Some(acls) = archive.acls() {
                                let aces = self
                                    .resolve_ace(
                                        access_token,
                                        account_id,
                                        acls,
                                        query.expand.then_some(&query.propfind),
                                    )
                                    .await?;

                                fields.push(DavPropertyValue::new(property.clone(), aces));
                            } else if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        WebDavProperty::AclRestrictions => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                AclRestrictions::default()
                                    .with_no_invert()
                                    .with_grant_only(),
                            ));
                        }
                        WebDavProperty::InheritedAclSet => {
                            fields.push(DavPropertyValue::empty(property.clone()));
                        }
                        WebDavProperty::PrincipalCollectionSet => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                vec![Href(
                                    DavResourceName::Principal.collection_path().to_string(),
                                )],
                            ));
                        }
                    },
                    DavProperty::DeadProperty(tag) => {
                        if let Some(value) =
                            dead_properties.and_then(|props| props.find_tag(&tag.name))
                        {
                            fields.push(DavPropertyValue::new(property.clone(), value));
                        } else {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    }
                    DavProperty::CardDav(card_property) => match (card_property, &archive) {
                        (
                            CardDavProperty::AddressbookDescription,
                            ArchivedResource::AddressBook(book),
                        ) => {
                            if let Some(desc) =
                                book.inner.preferences(personal_id).description.as_deref()
                            {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    desc.to_string(),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        (
                            CardDavProperty::SupportedAddressData,
                            ArchivedResource::AddressBook(_),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::SupportedAddressData,
                            ));
                        }
                        (
                            CardDavProperty::SupportedCollationSet,
                            ArchivedResource::AddressBook(_),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Collations(List(vec![
                                    SupportedCollation {
                                        collation: Collation::AsciiCasemap,
                                        namespace: Namespace::CardDav,
                                    },
                                    SupportedCollation {
                                        collation: Collation::UnicodeCasemap,
                                        namespace: Namespace::CardDav,
                                    },
                                ])),
                            ));
                        }
                        (CardDavProperty::MaxResourceSize, ArchivedResource::AddressBook(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_vcard_size as u64,
                            ));
                        }
                        (
                            CardDavProperty::AddressData {
                                properties,
                                version,
                            },
                            ArchivedResource::ContactCard(_, Some(content)),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::CData(serialize_vcard_with_props(
                                    &content.card,
                                    properties,
                                    (*version)
                                        .or(query.vcard_version)
                                        .unwrap_or(self.core.groupware.vcard_version),
                                )),
                            ));
                        }
                        _ => {
                            if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                    },
                    DavProperty::CalDav(cal_property) => match (cal_property, &archive) {
                        (
                            CalDavProperty::CalendarDescription,
                            ArchivedResource::Calendar(calendar),
                        ) => {
                            if let Some(desc) = calendar
                                .inner
                                .preferences(personal_id)
                                .and_then(|preferences| preferences.description.as_deref())
                            {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    desc.to_string(),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        (
                            CalDavProperty::CalendarTimezone,
                            ArchivedResource::Calendar(calendar),
                        ) => {
                            if let Some(ArchivedTimezone::Custom(tz)) = calendar
                                .inner
                                .preferences(personal_id)
                                .map(|preferences| &preferences.time_zone)
                            {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::CData(tz.to_string()),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        (CalDavProperty::TimezoneId, ArchivedResource::Calendar(calendar)) => {
                            if let Some(ArchivedTimezone::IANA(tz)) = calendar
                                .inner
                                .preferences(personal_id)
                                .map(|preferences| &preferences.time_zone)
                            {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    Tz::from_id(tz.to_native()).unwrap_or(Tz::UTC).to_string(),
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                        (
                            CalDavProperty::SupportedCalendarComponentSet,
                            ArchivedResource::Calendar(calendar),
                        ) => {
                            let supported_components =
                                calendar.inner.supported_components.to_native();
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                if supported_components != 0 {
                                    DavValue::Components(List(
                                        Bitmap::<SupportedComponent>::from(supported_components)
                                            .into_iter()
                                            .map(ICalendarComponentType::from)
                                            .map(Comp)
                                            .collect(),
                                    ))
                                } else {
                                    DavValue::all_calendar_components()
                                },
                            ));
                        }
                        (CalDavProperty::SupportedCalendarData, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::SupportedCalendarData,
                            ));
                        }
                        (CalDavProperty::SupportedCollationSet, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::Collations(List(vec![
                                    SupportedCollation {
                                        collation: Collation::AsciiCasemap,
                                        namespace: Namespace::CalDav,
                                    },
                                    SupportedCollation {
                                        collation: Collation::UnicodeCasemap,
                                        namespace: Namespace::CalDav,
                                    },
                                ])),
                            ));
                        }
                        (CalDavProperty::MaxResourceSize, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_ical_size as u64,
                            ));
                        }
                        (CalDavProperty::MinDateTime, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::String("0001-01-01T00:00:00Z".to_string()),
                            ));
                        }
                        (CalDavProperty::MaxDateTime, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::String("9999-12-31T23:59:59Z".to_string()),
                            ));
                        }
                        (CalDavProperty::MaxInstances, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_ical_instances as u64,
                            ));
                        }
                        (
                            CalDavProperty::MaxAttendeesPerInstance,
                            ArchivedResource::Calendar(_),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.core.groupware.max_ical_attendees_per_instance as u64,
                            ));
                        }
                        (
                            CalDavProperty::CalendarData(data),
                            ArchivedResource::CalendarEvent(event, Some(content)),
                        ) => {
                            if calendar_filter.is_some() || !data.properties.is_empty() {
                                if let Some(ical) = calendar_filter
                                    .get_or_insert_with(|| {
                                        CalendarQueryHandler::for_content(
                                            event.inner,
                                            content,
                                            None,
                                            Tz::UTC,
                                        )
                                    })
                                    .serialize_content(
                                        content,
                                        event.inner.size.to_native(),
                                        data,
                                        &mut ical_instances_limit,
                                    )
                                {
                                    fields.push(DavPropertyValue::new(
                                        property.clone(),
                                        DavValue::CData(ical),
                                    ));
                                } else {
                                    limit = 0;
                                    break 'outer;
                                }
                            } else {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::CData(content.to_ical_string()),
                                ));
                            }
                        }
                        (
                            CalDavProperty::CalendarData(_),
                            ArchivedResource::CalendarEventNotification(_, Some(content)),
                        ) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::CData(
                                    content
                                        .calendar_data()
                                        .map(|ical| ical.to_string())
                                        .unwrap_or_default(),
                                ),
                            ));
                        }
                        (
                            CalDavProperty::ScheduleTag,
                            ArchivedResource::CalendarEvent(event, _),
                        ) if event.inner.schedule_tag.is_some() => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::String(format!(
                                    "\"{}\"",
                                    event.inner.schedule_tag.as_ref().unwrap()
                                )),
                            ));
                        }
                        (CalDavProperty::ScheduleCalendarTransp, ArchivedResource::Calendar(_)) => {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                DavValue::DeadProperty(DeadProperty::single_with_ns(
                                    Namespace::CalDav,
                                    "opaque",
                                )),
                            ));
                        }
                        (
                            CalDavProperty::ScheduleDefaultCalendarURL,
                            ArchivedResource::CalendarEventNotificationCollection(true),
                        ) => {
                            if let Some(default_cal) = &self.core.groupware.default_calendar_name {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    vec![Href(format!(
                                        "{}/{}/{default_cal}/",
                                        DavResourceName::Cal.base_path(),
                                        item.name.split('/').nth(3).unwrap_or_default()
                                    ))],
                                ));
                            } else {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }

                        _ => {
                            if !skip_not_found {
                                fields_not_found.push(DavPropertyValue::empty(property.clone()));
                            }
                        }
                    },

                    property => {
                        if !skip_not_found {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    }
                }
            }

            // Add dead properties
            if skip_not_found
                && !item.is_discover_only
                && let Some(dead_properties) =
                    dead_properties.filter(|dead_properties| !dead_properties.0.is_empty())
            {
                dead_properties.to_dav_values(&mut fields);
            }

            // Add response
            let mut prop_stat = Vec::with_capacity(2);
            if !fields.is_empty() {
                prop_stat.push(PropStat::new_list(fields));
            }
            if !fields_not_found.is_empty() && !query.is_minimal() {
                prop_stat
                    .push(PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND));
            }
            if prop_stat.is_empty() {
                prop_stat.push(PropStat::new_list(vec![]));
            }
            response.add_response(Response::new_propstat(item.name, prop_stat));

            limit -= 1;
            if limit == 0 {
                break;
            }
        }

        if limit == 0 || is_sync_limited {
            response.add_response(
                Response::new_status([query.uri], StatusCode::INSUFFICIENT_STORAGE)
                    .with_error(BaseCondition::NumberOfMatchesWithinLimit)
                    .with_response_description(if ical_instances_limit > 0 {
                        format!(
                            "The number of matches exceeds the limit of {}",
                            query
                                .limit
                                .unwrap_or(self.core.groupware.max_results as u32)
                        )
                    } else {
                        format!(
                            "The number of recurrence instances exceeds the limit of {}",
                            query
                                .limit
                                .unwrap_or(self.core.groupware.max_ical_instances as u32)
                        )
                    }),
            );
        }

        if !is_propfind || !response.response.0.is_empty() || !query.sync_type.is_none() {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(response.to_string()))
        } else {
            Ok(HttpResponse::new(StatusCode::NOT_FOUND))
        }
    }

    async fn dav_quota(&self, account_id: u32) -> trc::Result<PropFindAccountQuota> {
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let used = self
            .get_used_quota_account(account_id)
            .await
            .caused_by(trc::location!())?
            .max(0) as u64;
        let mut available =
            (account.quota_disk > 0).then(|| account.quota_disk.saturating_sub(used));

        if let Some(tenant_id) = account.id_tenant {
            let tenant = self.tenant(tenant_id).await.caused_by(trc::location!())?;

            if tenant.quota_disk > 0 {
                let tenant_used = self
                    .get_used_quota_tenant(tenant_id)
                    .await
                    .caused_by(trc::location!())?
                    .max(0) as u64;
                let tenant_available = tenant.quota_disk.saturating_sub(tenant_used);

                available = Some(available.map_or(tenant_available, |available| {
                    available.min(tenant_available)
                }));
            }
        }

        Ok(PropFindAccountQuota { used, available })
    }
}
#[allow(clippy::too_many_arguments)]
async fn get(
    server: &Server,
    access_token: &AccessToken,
    collection_container: Collection,
    collection_children: Collection,
    sync_collection: SyncCollection,
    query: &DavQuery<'_>,
    data: &mut PropFindData,
    response: &mut MultiStatus,
    resource: UriResource<u32, Option<&str>>,
    limit: usize,
    is_sync_limited: &mut bool,
) -> crate::Result<Vec<PropFindItem>> {
    let container_has_children = collection_children != collection_container;
    response.set_namespace(collection_container.namespace());

    let account_id = resource.account_id;
    let resources = data
        .resources(server, access_token, account_id, sync_collection)
        .await
        .caused_by(trc::location!())?;

    // Obtain document ids
    let is_file = sync_collection == SyncCollection::FileNode;
    let mut file_readable = None;
    let mut display_containers = if is_file && !access_token.is_member(account_id) {
        let access = resources.file_access(access_token);
        file_readable = Some(access.readable.clone());
        let discoverable = access.discoverable.clone();
        data.accounts.entry(account_id).or_default().file_access = Some(access);
        Some(discoverable)
    } else if !access_token.is_member(account_id) {
        resources
            .shared_containers(
                access_token,
                [if container_has_children {
                    Acl::ReadItems
                } else {
                    Acl::Read
                }],
                true,
            )
            .into()
    } else {
        None
    };
    let visible_containers = display_containers
        .as_ref()
        .filter(|_| matches!(query.sync_type, SyncType::From { .. }))
        .cloned();
    let mut display_children = display_containers
        .as_ref()
        .filter(|_| container_has_children)
        .map(|containers| {
            let mut children =
                RoaringBitmap::from_iter(resources.resources.iter().filter_map(|r| {
                    if r.child_names()
                        .iter()
                        .any(|n| containers.contains(n.parent_id))
                    {
                        Some(r.document_id())
                    } else {
                        None
                    }
                }));
            if sync_collection == SyncCollection::Calendar {
                children -= resources.event_ids_with_flags(EVENT_SECRET);
            }
            children
        });

    // Filter by changelog
    let is_sync = match query.sync_type {
        SyncType::From { id, seq } => {
            let changes = server
                .store()
                .changes(account_id, sync_collection.into(), Query::Since(id))
                .await
                .caused_by(trc::location!())?;
            let mut vanished: Vec<String> = Vec::new();

            // Merge changes
            let mut total_changes = 0;
            let mut maybe_has_vanished = false;
            let mut hidden_hrefs: Vec<String> = Vec::new();
            if container_has_children {
                let mut container_changes = RoaringBitmap::new();
                let mut item_changes = RoaringBitmap::new();
                let mut item_updates = RoaringBitmap::new();
                let track_hidden_items = display_children.is_some();

                for change in changes.changes {
                    match change {
                        Change::InsertItem(id) => {
                            item_changes.insert(id as u32);
                        }
                        Change::UpdateItem(id) => {
                            maybe_has_vanished = true;
                            item_changes.insert(id as u32);
                            if track_hidden_items {
                                item_updates.insert(id as u32);
                            }
                        }
                        Change::InsertContainer(id) => {
                            container_changes.insert(id as u32);
                        }
                        Change::UpdateContainer(id) => {
                            maybe_has_vanished = true;
                            container_changes.insert(id as u32);
                        }
                        Change::DeleteContainer(_) | Change::DeleteItem(_) => {
                            maybe_has_vanished = true;
                        }
                        Change::UpdateContainerProperty(_) => (),
                    }
                }

                if let (Some(children), Some(containers)) = (&display_children, &display_containers)
                {
                    item_updates -= children;
                    hidden_hrefs.extend(item_updates.iter().filter_map(|document_id| {
                        let parent_id = resources
                            .item_by_id(document_id)?
                            .child_names()
                            .iter()
                            .map(|name| name.parent_id)
                            .find(|parent_id| containers.contains(*parent_id))?;
                        resources.format_resource_path_by_parent(document_id, parent_id)
                    }));
                }

                for (document_ids, changes) in [
                    (&mut display_containers, container_changes),
                    (&mut display_children, item_changes),
                ] {
                    if let Some(document_ids) = document_ids {
                        *document_ids &= changes;
                        total_changes += document_ids.len() as usize;
                    } else {
                        total_changes += changes.len() as usize;
                        *document_ids = Some(changes);
                    }
                }
            } else {
                let mut updates = RoaringBitmap::new();
                let track_hidden_items = is_file && display_containers.is_some();
                let changes = RoaringBitmap::from_iter(changes.changes.iter().filter_map(
                    |change| match change {
                        Change::InsertItem(id) | Change::InsertContainer(id) => Some(*id as u32),
                        Change::UpdateItem(id) | Change::UpdateContainer(id) => {
                            maybe_has_vanished = true;
                            if track_hidden_items {
                                updates.insert(*id as u32);
                            }
                            Some(*id as u32)
                        }
                        Change::DeleteContainer(_) | Change::DeleteItem(_) => {
                            maybe_has_vanished = true;
                            None
                        }
                        _ => None,
                    },
                ));

                if let Some(discoverable) = &display_containers {
                    updates -= discoverable;
                    hidden_hrefs.extend(updates.iter().filter_map(|document_id| {
                        let resource = resources.any_resource_path_by_id(document_id)?;
                        match resource.parent_id() {
                            Some(parent_id) if !discoverable.contains(parent_id) => None,
                            _ => Some(resources.format_resource(resource)),
                        }
                    }));
                }

                if let Some(document_ids) = &mut display_containers {
                    *document_ids &= changes;
                    total_changes += document_ids.len() as usize;
                } else {
                    total_changes += changes.len() as usize;
                    display_containers = Some(changes);
                }
            }

            if maybe_has_vanished
                && let Some(vanished_collection) = sync_collection.vanished_collection()
            {
                vanished = server
                    .store()
                    .vanished(account_id, vanished_collection.into(), Query::Since(id))
                    .await
                    .caused_by(trc::location!())?;
            }
            vanished.append(&mut hidden_hrefs);
            if !vanished.is_empty() {
                let scope = resource.resource.map_or_else(
                    || resources.base_path.clone(),
                    |path| resources.format_collection(path),
                );
                vanished.retain(|href| {
                    href.starts_with(scope.as_str())
                        && visible_containers.as_ref().is_none_or(|containers| {
                            let Some(path) = href.strip_prefix(resources.base_path.as_str()) else {
                                return false;
                            };
                            match path.trim_end_matches('/').rsplit_once('/') {
                                Some((parent, _)) => {
                                    resources.by_path(parent).is_some_and(|parent| {
                                        containers.contains(parent.document_id())
                                    })
                                }
                                None => true,
                            }
                        })
                });
                total_changes += vanished.len();
            }

            // Truncate changes
            if total_changes > limit {
                let mut offset = limit * seq as usize;
                let mut total_changes = 0;

                // Add vanished items to response
                for item in vanished {
                    if offset > 0 {
                        offset -= 1;
                    } else if total_changes < limit {
                        response.add_response(Response::new_status([item], StatusCode::NOT_FOUND));
                        total_changes += 1;
                    } else {
                        *is_sync_limited = true;
                    }
                }

                // Add items to document set
                for document_ids in [&mut display_containers, &mut display_children]
                    .into_iter()
                    .flatten()
                {
                    let mut new_document_ids = RoaringBitmap::new();
                    for id in document_ids.iter() {
                        if offset > 0 {
                            offset -= 1;
                        } else if total_changes < limit {
                            new_document_ids.insert(id);
                            total_changes += 1;
                        } else {
                            *is_sync_limited = true;
                        }
                    }
                    *document_ids = new_document_ids;
                }

                if *is_sync_limited {
                    response.set_sync_token(Urn::Sync { id, seq: seq + 1 }.to_string());
                }
            } else {
                // Add vanished items to response
                for item in vanished {
                    response.add_response(Response::new_status([item], StatusCode::NOT_FOUND));
                }
            }

            if !*is_sync_limited {
                response.set_sync_token(resources.sync_token());
            }

            true
        }
        SyncType::Initial => {
            response.set_sync_token(resources.sync_token());
            false
        }
        SyncType::None => false,
    };

    let mut results = Vec::new();
    if let Some(resource) = resource.resource {
        results = resources
            .subtree_with_depth(resource, query.depth)
            .filter(|item| {
                display_containers.as_ref().is_none_or(|containers| {
                    if container_has_children {
                        if item.is_container() {
                            containers.contains(item.document_id())
                        } else {
                            display_children
                                .as_ref()
                                .is_some_and(|children| children.contains(item.document_id()))
                        }
                    } else {
                        containers.contains(item.document_id())
                    }
                }) && (!query.depth_no_root || item.path() != resource)
                    && (!is_file || !is_symlink(item))
            })
            .map(|item| {
                let is_discover_only = is_discover_only(file_readable.as_ref(), &item);
                let href = if is_file && item.path() == resource {
                    requested_href(query.uri, item.is_container())
                } else {
                    resources.format_resource(item)
                };
                PropFindItem::new(href, account_id, item).with_discover_only(is_discover_only)
            })
            .collect::<Vec<_>>();
    } else {
        if !query.depth_no_root && query.sync_type.is_none_or_initial() {
            server
                .prepare_principal_propfind_response(
                    access_token,
                    collection_container,
                    [account_id].into_iter(),
                    &query.propfind,
                    response,
                )
                .await?;
        }

        if query.depth != 0 {
            results = resources
                .tree_with_depth(query.depth - 1)
                .filter(|item| {
                    display_containers.as_ref().is_none_or(|containers| {
                        if container_has_children {
                            if item.is_container() {
                                containers.contains(item.document_id())
                            } else {
                                display_children
                                    .as_ref()
                                    .is_some_and(|children| children.contains(item.document_id()))
                            }
                        } else {
                            containers.contains(item.document_id())
                        }
                    }) && (!is_file || !is_symlink(item))
                })
                .map(|item| {
                    let is_discover_only = is_discover_only(file_readable.as_ref(), &item);
                    PropFindItem::new(resources.format_resource(item), account_id, item)
                        .with_discover_only(is_discover_only)
                })
                .collect::<Vec<_>>();

            // Assisted discovery:
            // If 'bob' has access to 'jane' and `bill` calendars, a query to '/dav/cal/bob' will return:
            //    - /dav/cal/bob/default
            //    - /dav/cal/jane/default
            //    - /dav/cal/bill/default
            // This is invalid but it's the only workaround for clients which do not support multiple home-sets
            if server.core.groupware.assisted_discovery
                && !is_sync
                && account_id == access_token.account_id()
                && matches!(
                    sync_collection,
                    SyncCollection::Calendar | SyncCollection::AddressBook
                )
            {
                for shared_account_id in access_token.all_ids_by_collection(collection_container) {
                    if shared_account_id == access_token.account_id() {
                        continue;
                    }
                    let shared_resources = data
                        .resources(server, access_token, shared_account_id, sync_collection)
                        .await
                        .caused_by(trc::location!())?;
                    let shared_containers =
                        (!access_token.is_member(shared_account_id)).then(|| {
                            shared_resources.shared_containers(
                                access_token,
                                [if container_has_children {
                                    Acl::ReadItems
                                } else {
                                    Acl::Read
                                }],
                                true,
                            )
                        });
                    if shared_containers
                        .as_ref()
                        .is_none_or(|containers| !containers.is_empty())
                    {
                        results.extend(
                            shared_resources
                                .tree_with_depth(query.depth - 1)
                                .filter(|item| {
                                    item.is_container()
                                        && shared_containers.as_ref().is_none_or(|containers| {
                                            containers.contains(item.document_id())
                                        })
                                })
                                .map(|item| {
                                    PropFindItem::new(
                                        shared_resources.format_resource(item),
                                        shared_account_id,
                                        item,
                                    )
                                }),
                        );
                    }
                }
            }
        }
    }

    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn multiget(
    server: &Server,
    access_token: &AccessToken,
    collection_container: Collection,
    collection_children: Collection,
    sync_collection: SyncCollection,
    data: &mut PropFindData,
    response: &mut MultiStatus,
    hrefs: Vec<String>,
) -> crate::Result<Vec<PropFindItem>> {
    let mut paths = Vec::with_capacity(hrefs.len() * 2);
    let mut shared_folders_by_account: AHashMap<u32, Arc<RoaringBitmap>> =
        AHashMap::with_capacity(3);

    for item in hrefs {
        let resource = match server
            .validate_uri(access_token, &item)
            .await
            .and_then(|r| r.into_owned_uri())
        {
            Ok(resource) => resource,
            Err(DavError::Code(code)) => {
                response.add_response(Response::new_status([item], code));
                continue;
            }
            Err(err) => {
                return Err(err);
            }
        };

        let account_id = resource.account_id;
        let resources = data
            .resources(server, access_token, account_id, sync_collection)
            .await
            .caused_by(trc::location!())?;

        let document_ids = if !access_token.is_member(account_id) {
            if let Some(document_ids) = shared_folders_by_account.get(&account_id) {
                document_ids.clone().into()
            } else {
                let document_ids = Arc::new(resources.shared_containers(
                    access_token,
                    [if collection_children == collection_container {
                        Acl::ReadItems
                    } else {
                        Acl::Read
                    }],
                    true,
                ));
                shared_folders_by_account.insert(account_id, document_ids.clone());
                document_ids.into()
            }
        } else {
            None
        };

        if let Some(resource) = resource
            .resource
            .and_then(|name| resources.by_path(name))
            .filter(|resource| {
                access_token.is_member(account_id)
                    || resource
                        .resource
                        .event_flags()
                        .is_none_or(|flags| flags & EVENT_SECRET == 0)
            })
        {
            if !resource.is_container() {
                if document_ids
                    .as_ref()
                    .is_none_or(|docs| docs.contains(resource.parent_id().unwrap()))
                {
                    paths.push(PropFindItem::new(
                        resources.format_resource(resource),
                        account_id,
                        resource,
                    ));
                } else {
                    response.add_response(
                        Response::new_status([item], StatusCode::FORBIDDEN)
                            .with_response_description(
                                "Not enough permissions to access this shared resource",
                            ),
                    );
                }
            } else {
                response.add_response(
                    Response::new_status([item], StatusCode::FORBIDDEN)
                        .with_response_description("Multiget not allowed for collections"),
                );
            }
        } else {
            response.add_response(Response::new_status([item], StatusCode::NOT_FOUND));
        }
    }

    Ok(paths)
}

pub(crate) fn requested_href(uri: &str, is_container: bool) -> String {
    if is_container && !uri.ends_with('/') {
        format!("{uri}/")
    } else {
        uri.to_string()
    }
}

fn is_discover_only(readable: Option<&RoaringBitmap>, item: &DavResourcePath<'_>) -> bool {
    readable.is_some_and(|readable| !readable.contains(item.document_id()))
}

impl PropFindItem {
    pub fn new(name: String, account_id: u32, resource: DavResourcePath<'_>) -> Self {
        Self {
            name,
            account_id,
            document_id: resource.document_id(),
            parent_id: resource.parent_id(),
            is_container: resource.is_container(),
            is_discover_only: false,
        }
    }

    pub fn with_discover_only(mut self, is_discover_only: bool) -> Self {
        self.is_discover_only = is_discover_only;
        self
    }
}

impl PropFindData {
    pub fn new() -> Self {
        Self {
            accounts: AHashMap::with_capacity(2),
        }
    }

    pub async fn quota(
        &mut self,
        server: &Server,
        account_id: u32,
    ) -> trc::Result<PropFindAccountQuota> {
        let data = self.accounts.entry(account_id).or_default();

        if data.quota.is_none() {
            data.quota = server.dav_quota(account_id).await?.into();
        }

        Ok(data.quota.clone().unwrap())
    }

    pub async fn owner(
        &mut self,
        server: &Server,
        account_info: &AccountCache,
        account_id: u32,
    ) -> trc::Result<Href> {
        let data = self.accounts.entry(account_id).or_default();

        if data.owner.is_none() {
            data.owner = server
                .owner_href(account_info, account_id)
                .await
                .caused_by(trc::location!())?
                .into();
        }

        Ok(data.owner.clone().unwrap())
    }

    pub async fn resources(
        &mut self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        sync_collection: SyncCollection,
    ) -> trc::Result<Arc<GroupwareResources>> {
        let data = self.accounts.entry(account_id).or_default();

        if data.resources.is_none() {
            let resources = server
                .fetch_groupware_resources(access_token.account_id(), account_id, sync_collection)
                .await
                .caused_by(trc::location!())?;
            data.resources = resources.into();
        }

        Ok(data.resources.clone().unwrap())
    }

    pub async fn locks(
        &mut self,
        server: &Server,
        account_id: u32,
        collection_container: Collection,
        item: &PropFindItem,
    ) -> trc::Result<Option<Vec<ActiveLock>>> {
        let data = self.accounts.entry(account_id).or_default();

        if data.locks.is_none() && !data.locks_not_found {
            data.locks = server
                .in_memory_store()
                .key_get::<Archive<ArchiveBytes>>(
                    build_lock_key(account_id, collection_container).as_slice(),
                )
                .await
                .caused_by(trc::location!())?;
            if data.locks.is_none() {
                data.locks_not_found = true;
            }
        }

        let Some(lock_data) = &data.locks else {
            return Ok(None);
        };
        let base_uri = dav_base_uri(&item.name).unwrap_or_default();
        let name = if collection_container == Collection::FileNode {
            canonical_dav_resource_uri(&item.name).unwrap_or(Cow::Borrowed(item.name.as_str()))
        } else {
            Cow::Borrowed(item.name.as_str())
        };
        let Some(path) = name
            .strip_prefix(base_uri)
            .and_then(|path| path.strip_prefix('/'))
            .map(|path| path.trim_end_matches('/'))
        else {
            return Ok(None);
        };
        lock_data.unarchive::<LockData>().map(|locks| {
            locks
                .find_locks(path, false)
                .iter()
                .map(|(path, lock)| lock.to_active_lock(format!("{base_uri}/{path}")))
                .collect::<Vec<_>>()
                .into()
        })
    }
}

pub(crate) trait SyncTokenUrn {
    fn sync_token(&self) -> String;
}

impl SyncTokenUrn for GroupwareResources {
    fn sync_token(&self) -> String {
        Urn::Sync {
            id: self.highest_change_id,
            seq: 0,
        }
        .to_string()
    }
}

async fn add_base_collection_response(
    server: &Server,
    request: &PropFind,
    collection: Collection,
    access_token: &AccessToken,
    response: &mut MultiStatus,
) -> trc::Result<()> {
    let properties = match request {
        PropFind::PropName => {
            response.add_response(Response::new_propstat(
                DavResourceName::from(collection).collection_path(),
                vec![PropStat::new_list(vec![
                    DavPropertyValue::empty(DavProperty::WebDav(WebDavProperty::ResourceType)),
                    DavPropertyValue::empty(DavProperty::WebDav(
                        WebDavProperty::CurrentUserPrincipal,
                    )),
                    DavPropertyValue::empty(DavProperty::WebDav(
                        WebDavProperty::SupportedReportSet,
                    )),
                ])],
            ));
            return Ok(());
        }
        PropFind::AllProp(_) => [
            DavProperty::WebDav(WebDavProperty::ResourceType),
            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
            DavProperty::WebDav(WebDavProperty::SupportedReportSet),
        ]
        .as_slice(),
        PropFind::Prop(items) => items,
    };

    let mut fields = Vec::with_capacity(properties.len());
    let mut fields_not_found = Vec::new();
    let account_info = server
        .account(access_token.account_id())
        .await
        .caused_by(trc::location!())?;

    for prop in properties {
        response.set_namespace(prop.namespace());
        match &prop {
            DavProperty::WebDav(WebDavProperty::ResourceType) => {
                fields.push(DavPropertyValue::new(
                    prop.clone(),
                    vec![ResourceType::Collection],
                ));
            }
            DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal) => {
                fields.push(DavPropertyValue::new(
                    prop.clone(),
                    vec![account_info.current_user_principal()],
                ));
            }
            DavProperty::Principal(PrincipalProperty::CalendarHomeSet) => {
                let hrefs = build_home_set(
                    server,
                    access_token,
                    account_info.name(),
                    access_token.account_id(),
                    true,
                )
                .await
                .caused_by(trc::location!())?;

                fields.push(DavPropertyValue::new(prop.clone(), hrefs));
            }
            DavProperty::Principal(PrincipalProperty::AddressbookHomeSet) => {
                let hrefs = build_home_set(
                    server,
                    access_token,
                    account_info.name(),
                    access_token.account_id(),
                    false,
                )
                .await
                .caused_by(trc::location!())?;

                fields.push(DavPropertyValue::new(prop.clone(), hrefs));
            }
            DavProperty::WebDav(WebDavProperty::SupportedReportSet) => {
                let reports = match collection {
                    Collection::Principal => ReportSet::principal(),
                    Collection::Calendar | Collection::CalendarEvent => ReportSet::calendar(),
                    Collection::AddressBook | Collection::ContactCard => ReportSet::addressbook(),
                    _ => ReportSet::file(),
                };

                fields.push(DavPropertyValue::new(prop.clone(), reports));
                response.set_namespace(collection.namespace());
            }
            _ => {
                fields_not_found.push(DavPropertyValue::empty(prop.clone()));
            }
        }
    }

    let mut prop_stat = Vec::with_capacity(2);

    if !fields.is_empty() {
        prop_stat.push(PropStat::new_list(fields));
    }

    if !fields_not_found.is_empty() {
        prop_stat.push(PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND));
    }

    response.add_response(Response::new_propstat(
        DavResourceName::from(collection).collection_path(),
        prop_stat,
    ));

    Ok(())
}
