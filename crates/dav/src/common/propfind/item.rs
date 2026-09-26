/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PropFindContext, PropFindItem, PropFindState, data::SyncTokenUrn};
use crate::{
    calendar::{
        filter::FilterTimeRanges,
        query::{CalendarDataRange, CalendarQueryHandler},
    },
    card::query::serialize_vcard_with_props,
    common::{
        ArchivedResource,
        acl::{DavAclHandler, Privileges, current_user_privilege_set},
    },
    principal::{CurrentUserPrincipal, propfind::PrincipalPropFind},
};
use calcard::{common::timezone::Tz, icalendar::ICalendarComponentType};
use common::Server;
use dav_proto::{
    requests::NsDeadProperty,
    schema::{
        Collation, Namespace,
        property::{
            CalDavProperty, CardDavProperty, Comp, DavProperty, DavValue, Privilege,
            Rfc1123DateTime, SupportedCollation, SupportedLock, WebDavProperty,
        },
        request::{DavDeadProperty, DavPropertyValue},
        response::{AclRestrictions, Href, List, PropStat, Response, SupportedPrivilege},
    },
};
use groupware::{
    DavCalendarResource, DavResourceName,
    calendar::{ArchivedTimezone, SupportedComponent, privacy::EventPrivacy},
};
use hyper::StatusCode;
use trc::AddContext;
use types::{collection::Collection, dead_property::DeadProperty};
use utils::map::bitmap::Bitmap;

pub(super) trait PropFindItemBuilder: Sync + Send {
    fn add_propfind_item(
        &self,
        ctx: &PropFindContext<'_>,
        state: &mut PropFindState,
        item: PropFindItem,
        archive: &ArchivedResource<'_>,
        calendar_filter: Option<CalendarQueryHandler>,
    ) -> impl Future<Output = crate::Result<bool>> + Send;
}

impl PropFindItemBuilder for Server {
    async fn add_propfind_item(
        &self,
        ctx: &PropFindContext<'_>,
        state: &mut PropFindState,
        item: PropFindItem,
        archive: &ArchivedResource<'_>,
        mut calendar_filter: Option<CalendarQueryHandler>,
    ) -> crate::Result<bool> {
        let PropFindState {
            data,
            response,
            ical_instances_limit,
        } = state;
        let PropFindContext {
            access_token,
            query,
            properties,
            account_info,
            collection_container,
            collection_children,
            sync_collection,
            is_scheduling,
            skip_not_found,
        } = *ctx;
        let account_id = item.account_id;
        let personal_id = access_token.personal_id(account_id, collection_container);
        let collection = if item.is_container {
            collection_container
        } else {
            collection_children
        };

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
        for property in properties {
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
                                    data.owner(self, account_info, account_id)
                                        .await
                                        .caused_by(trc::location!())?,
                                ],
                            ));
                        } else {
                            fields.push(DavPropertyValue::new(
                                property.clone(),
                                self.expand_principal(access_token, account_id, &query.propfind)
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
                    if let Some(value) = dead_properties.and_then(|props| props.find_tag(&tag.name))
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
                            fields.push(DavPropertyValue::new(property.clone(), desc.to_string()));
                        } else {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    }
                    (CardDavProperty::SupportedAddressData, ArchivedResource::AddressBook(_)) => {
                        fields.push(DavPropertyValue::new(
                            property.clone(),
                            DavValue::SupportedAddressData,
                        ));
                    }
                    (CardDavProperty::SupportedCollationSet, ArchivedResource::AddressBook(_)) => {
                        fields.push(DavPropertyValue::new(
                            property.clone(),
                            DavValue::Collations(List(vec![
                                SupportedCollation {
                                    collation: Collation::AsciiCasemap,
                                    namespace: Namespace::CardDav,
                                },
                                SupportedCollation {
                                    collation: Collation::Octet,
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
                    (CalDavProperty::CalendarDescription, ArchivedResource::Calendar(calendar)) => {
                        if let Some(desc) = calendar
                            .inner
                            .preferences(personal_id)
                            .and_then(|preferences| preferences.description.as_deref())
                        {
                            fields.push(DavPropertyValue::new(property.clone(), desc.to_string()));
                        } else {
                            fields_not_found.push(DavPropertyValue::empty(property.clone()));
                        }
                    }
                    (CalDavProperty::CalendarTimezone, ArchivedResource::Calendar(calendar)) => {
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
                        let supported_components = calendar.inner.supported_components.to_native();
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
                                    collation: Collation::Octet,
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
                    (CalDavProperty::MaxAttendeesPerInstance, ArchivedResource::Calendar(_)) => {
                        fields.push(DavPropertyValue::new(
                            property.clone(),
                            self.core.groupware.max_ical_attendees_per_instance as u64,
                        ));
                    }
                    (
                        CalDavProperty::CalendarData(calendar_data),
                        ArchivedResource::CalendarEvent(event, Some(content)),
                    ) => {
                        let data_range = calendar_data.calendar_data_range();
                        if calendar_filter.is_none()
                            && (data_range.is_some() || !calendar_data.properties.is_empty())
                        {
                            let default_tz = match (data_range, item.parent_id) {
                                (Some(_), Some(calendar_id)) => data
                                    .resources(self, access_token, account_id, sync_collection)
                                    .await
                                    .caused_by(trc::location!())?
                                    .calendar_default_tz(calendar_id, account_id)
                                    .unwrap_or(Tz::UTC),
                                _ => Tz::UTC,
                            };
                            calendar_filter = Some(CalendarQueryHandler::for_content(
                                event.inner,
                                content,
                                FilterTimeRanges {
                                    range: data_range,
                                    has_alarms: false,
                                },
                                default_tz,
                            ));
                        }
                        if let Some(handler) = &calendar_filter {
                            if let Some(ical) = handler.serialize_content(
                                content,
                                event.inner.size.to_native(),
                                calendar_data,
                                ical_instances_limit,
                            ) {
                                fields.push(DavPropertyValue::new(
                                    property.clone(),
                                    DavValue::CData(ical),
                                ));
                            } else {
                                return Ok(false);
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
                    (CalDavProperty::ScheduleTag, ArchivedResource::CalendarEvent(event, _))
                        if event.inner.schedule_tag.is_some() =>
                    {
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
            prop_stat.push(PropStat::new_list(fields_not_found).with_status(StatusCode::NOT_FOUND));
        }
        if prop_stat.is_empty() {
            prop_stat.push(PropStat::new_list(vec![]));
        }
        response.add_response(Response::new_propstat(item.name, prop_stat));

        Ok(true)
    }
}
