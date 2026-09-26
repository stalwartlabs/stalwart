/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod data;
mod get;
mod item;
mod load;

pub(crate) use data::{PropFindAccountQuota, PropFindData, SyncTokenUrn};
pub(crate) use get::requested_href;

use super::{
    ArchivedResource, DavCollection, DavQuery, DavQueryFilter, DavQueryResource,
    uri::{DavUriResource, UriResource},
};
use crate::{
    DavErrorCondition,
    calendar::{
        CALENDAR_CONTAINER_PROPS, CALENDAR_ITEM_PROPS, CalendarEventView,
        query::CalendarQueryHandler,
    },
    card::{CARD_CONTAINER_PROPS, CARD_ITEM_PROPS, filter::CardFilterMatch},
    file::{FILE_CONTAINER_PROPS, FILE_ITEM_PROPS},
    principal::{
        CurrentUserPrincipal,
        propfind::{PrincipalPropFind, build_home_set},
    },
};
use calcard::common::timezone::Tz;
use common::{
    DavResourcePath, Server,
    auth::{AccessToken, AccountCache},
};
use dav_proto::{
    Depth, RequestHeaders,
    schema::{
        property::{DavProperty, PrincipalProperty, ReportSet, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropFind},
        response::{BaseCondition, MultiStatus, PropStat, Response},
    },
};
use get::{get, multiget};
use groupware::{
    DavCalendarResource, DavResourceName,
    calendar::{SCHEDULE_INBOX_ID, alerts::DefaultAlertsResolver},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use item::PropFindItemBuilder;
use load::{ArchiveLoader, PROPFIND_BATCH_SIZE};
use registry::schema::{enums::Permission, prelude::ObjectType};
use store::{registry::RegistryQuery, roaring::RoaringBitmap};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

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

#[derive(Debug)]
pub(crate) struct PropFindItem {
    pub name: String,
    pub account_id: u32,
    pub document_id: u32,
    pub parent_id: Option<u32>,
    pub is_container: bool,
    pub is_discover_only: bool,
}

pub(crate) struct PropFindState {
    pub data: PropFindData,
    pub response: MultiStatus,
    pub ical_instances_limit: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct PropFindContext<'x> {
    pub access_token: &'x AccessToken,
    pub query: &'x DavQuery<'x>,
    pub properties: &'x [DavProperty],
    pub account_info: &'x AccountCache,
    pub collection_container: Collection,
    pub collection_children: Collection,
    pub sync_collection: SyncCollection,
    pub is_scheduling: bool,
    pub skip_not_found: bool,
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
        let limit = std::cmp::min(
            query.limit.unwrap_or(u32::MAX) as usize,
            self.core.groupware.max_results,
        );
        let mut is_sync_limited = false;
        let mut is_propfind = false;

        let mut paths = match std::mem::take(&mut query.resource) {
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
        let (properties, property_names) = match &query.propfind {
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

                if query_filter.is_none() {
                    for item in paths {
                        response.add_response(
                            item.into_property_names(container_props, children_props),
                        );
                    }

                    return Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                        .with_xml_body(response.to_string()));
                }

                (Vec::new(), Some((container_props, children_props)))
            }
            PropFind::AllProp(items) => {
                skip_not_found = true;
                let mut result = Vec::with_capacity(items.len() + DavProperty::ALL_PROPS.len());
                result.extend(DavProperty::ALL_PROPS);
                result.extend(items.iter().filter(|field| !field.is_all_prop()).cloned());
                (result, None)
            }
            PropFind::Prop(items) => (items.clone(), None),
        };

        for property in &properties {
            response.set_namespace(property.namespace());
        }

        let account_info = self
            .account(access_token.account_id())
            .await
            .caused_by(trc::location!())?;
        let ctx = PropFindContext {
            access_token,
            query: &query,
            properties: &properties,
            account_info: &account_info,
            collection_container,
            collection_children,
            sync_collection,
            is_scheduling: collection_container == Collection::CalendarEventNotification,
            skip_not_found,
        };
        let loader = ArchiveLoader::new(&ctx, query_filter.is_some());
        let needs_event_view = loader.needs_event_view();

        let mut is_truncated = query_filter.is_none() && paths.len() > limit;
        if is_truncated {
            paths.truncate(limit);
        }
        if paths.len() > PROPFIND_BATCH_SIZE {
            paths.sort_unstable_by_key(PropFindItem::storage_order);
        }

        let mut remaining = limit;
        let mut state = PropFindState {
            data,
            response,
            ical_instances_limit: self.core.groupware.max_ical_instances,
        };
        let mut instances_exceeded = false;
        let mut default_alerts = DefaultAlertsResolver::default();
        let mut paths = paths.into_iter();

        'outer: loop {
            let batch = paths.by_ref().take(PROPFIND_BATCH_SIZE).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            let archives = loader
                .load(self, access_token, &batch)
                .await
                .caused_by(trc::location!())?;

            for item in batch {
                let account_id = item.account_id;
                let collection = loader.collection_of(&item);

                // Unarchive resource
                let mut archive = if ctx.is_scheduling && item.is_container {
                    ArchivedResource::CalendarEventNotificationCollection(
                        item.document_id == SCHEDULE_INBOX_ID,
                    )
                } else if let Some(archive) = archives
                    .resource(collection, &item)
                    .caused_by(trc::location!())?
                {
                    archive
                } else {
                    state
                        .response
                        .add_response(Response::new_status([item.name], StatusCode::NOT_FOUND));
                    continue;
                };
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

                // Filter
                let mut calendar_filter = None;
                if let Some(query_filter) = &query_filter {
                    match (query_filter, &archive) {
                        (
                            DavQueryFilter::Addressbook(filter),
                            ArchivedResource::ContactCard(_, Some(content)),
                        ) => {
                            if !filter.matches(&content.card) {
                                continue;
                            }
                        }
                        (
                            DavQueryFilter::Calendar(filter),
                            ArchivedResource::CalendarEvent(event, Some(content)),
                        ) => {
                            let default_tz = match (filter.timezone, item.parent_id) {
                                (Some(tz), _) => tz,
                                (None, Some(calendar_id)) => state
                                    .data
                                    .resources(self, access_token, account_id, sync_collection)
                                    .await
                                    .caused_by(trc::location!())?
                                    .calendar_default_tz(calendar_id, account_id)
                                    .unwrap_or(Tz::UTC),
                                (None, None) => Tz::UTC,
                            };
                            let query_handler = CalendarQueryHandler::for_content(
                                event.inner,
                                content,
                                filter.expansion,
                                default_tz,
                            );
                            if filter.filter.as_ref().is_some_and(|filter| {
                                !query_handler.matches_content(content, filter)
                            }) {
                                continue;
                            }
                            calendar_filter = Some(query_handler);
                        }
                        (
                            DavQueryFilter::Calendar(filter),
                            ArchivedResource::CalendarEventNotification(_, Some(content)),
                        ) => {
                            if !filter
                                .matches_scheduling_message(
                                    content,
                                    filter.timezone.unwrap_or(Tz::UTC),
                                    self.core.groupware.max_ical_instances,
                                )
                                .caused_by(trc::location!())?
                            {
                                continue;
                            }
                        }
                        _ => continue,
                    }
                }

                if remaining == 0 {
                    is_truncated = true;
                    break 'outer;
                }
                remaining -= 1;

                if let Some((container_props, children_props)) = property_names {
                    state
                        .response
                        .add_response(item.into_property_names(container_props, children_props));
                } else if !self
                    .add_propfind_item(&ctx, &mut state, item, &archive, calendar_filter)
                    .await?
                {
                    instances_exceeded = true;
                    break 'outer;
                }
            }
        }

        let mut response = state.response;
        if is_truncated || instances_exceeded || is_sync_limited {
            response.add_response(
                Response::new_status([query.uri], StatusCode::INSUFFICIENT_STORAGE)
                    .with_error(BaseCondition::NumberOfMatchesWithinLimit)
                    .with_response_description(if instances_exceeded {
                        format!(
                            "The number of recurrence instances exceeds the limit of {}",
                            self.core.groupware.max_ical_instances
                        )
                    } else {
                        format!("The number of matches exceeds the limit of {limit}")
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

    fn storage_order(&self) -> (u32, bool, u32) {
        (self.account_id, !self.is_container, self.document_id)
    }

    fn into_property_names(
        self,
        container_props: &[DavProperty],
        children_props: &[DavProperty],
    ) -> Response {
        let props = if self.is_container {
            container_props
        } else {
            children_props
        };

        Response::new_propstat(
            self.name,
            vec![PropStat::new_list(
                props.iter().cloned().map(DavPropertyValue::empty).collect(),
            )],
        )
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
