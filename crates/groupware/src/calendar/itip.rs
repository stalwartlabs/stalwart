/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    RFC_3986,
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, CalendarEventData, CalendarEventNotification, ChangedBy,
        EVENT_NOTIFICATION_IS_CHANGE,
    },
    scheduling::{
        ItipError, ItipMessage,
        inbound::{
            MergeResult, itip_import_message, itip_merge_changes, itip_method, itip_process_message,
        },
        snapshot::itip_snapshot,
    },
};
use calcard::{
    common::{IanaString, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponentType, ICalendarEntry, ICalendarMethod, ICalendarParameter,
        ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationStatus,
        ICalendarProperty, ICalendarValue,
    },
};
use common::{
    DavName, Server,
    auth::{AccessToken, ResourceToken, oauth::GrantType},
    config::groupware::CalendarTemplateVariable,
    i18n,
};
use store::{
    ValueKey, rand,
    write::{AlignedBytes, Archive, BatchBuilder, now},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarEventField, ContactField},
};
use utils::{template::Variables, url_params::UrlParams};

pub enum ItipIngestError {
    Message(ItipError),
    Internal(trc::Error),
}

#[derive(Default)]
pub struct ItipRsvpUrl(String);

pub trait ItipIngest: Sync + Send {
    fn itip_ingest(
        &self,
        access_token: &AccessToken,
        resource_token: &ResourceToken,
        sender: &str,
        recipient: &str,
        itip_message: &str,
    ) -> impl Future<Output = Result<Option<ItipMessage<ICalendar>>, ItipIngestError>> + Send;

    fn http_rsvp_url(
        &self,
        account_id: u32,
        document_id: u32,
        attendee: &str,
    ) -> impl Future<Output = Option<ItipRsvpUrl>> + Send;

    fn http_rsvp_handle(
        &self,
        query: &str,
        language: &str,
    ) -> impl Future<Output = trc::Result<String>> + Send;
}

impl ItipIngest for Server {
    async fn itip_ingest(
        &self,
        access_token: &AccessToken,
        resource_token: &ResourceToken,
        sender: &str,
        recipient: &str,
        itip_message: &str,
    ) -> Result<Option<ItipMessage<ICalendar>>, ItipIngestError> {
        // Parse and validate the iTIP message
        let mut itip = ICalendar::parse(itip_message)
            .map_err(|_| ItipIngestError::Message(ItipError::ICalendarParseError))
            .and_then(|ical| {
                if ical.components.len() > 1
                    && ical.components[0].component_type == ICalendarComponentType::VCalendar
                {
                    Ok(ical)
                } else {
                    Err(ItipIngestError::Message(ItipError::ICalendarParseError))
                }
            })?;

        // Microsoft Exchange does not include the organizer in REPLY, assume it is the recipient.
        // This will be validated against the stored event anyway.
        if itip.components[0]
            .property(&ICalendarProperty::Method)
            .and_then(|v| v.values.first())
            .is_some_and(|v| {
                matches!(
                    v,
                    ICalendarValue::Method(ICalendarMethod::Reply | ICalendarMethod::Request)
                )
            })
        {
            for comp in &mut itip.components {
                if comp.component_type.is_scheduling_object() {
                    let mut has_organizer = false;
                    let mut has_attendee = false;

                    for entry in &comp.entries {
                        match entry.name {
                            ICalendarProperty::Organizer => has_organizer = true,
                            ICalendarProperty::Attendee => has_attendee = true,
                            _ => {}
                        }
                    }

                    if has_attendee && !has_organizer {
                        comp.entries.push(ICalendarEntry {
                            name: ICalendarProperty::Organizer,
                            params: vec![],
                            values: vec![ICalendarValue::Text(format!("mailto:{recipient}"))],
                        });
                    }
                }
            }
        }

        let itip_snapshots = itip_snapshot(&itip, access_token.emails.as_slice(), false)?;
        if !itip_snapshots.sender_is_organizer_or_attendee(sender) {
            return Err(ItipIngestError::Message(
                ItipError::SenderIsNotOrganizerNorAttendee,
            ));
        }

        // Obtain changedBy
        let changed_by = if let Some(id) = self.email_to_id(self.directory(), sender, 0).await? {
            ChangedBy::PrincipalId(id)
        } else {
            ChangedBy::CalendarAddress(sender.into())
        };

        // Find event by UID
        let account_id = access_token.primary_id;
        let document_id = self
            .document_ids_matching(
                account_id,
                Collection::CalendarEvent,
                CalendarEventField::Uid,
                itip_snapshots.uid.as_bytes(),
            )
            .await
            .caused_by(trc::location!())?
            .iter()
            .next();

        if let Some(document_id) = document_id {
            if let Some(archive) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let event_ = archive
                    .to_unarchived::<CalendarEvent>()
                    .caused_by(trc::location!())?;
                let mut event = event_
                    .deserialize::<CalendarEvent>()
                    .caused_by(trc::location!())?;

                // Process the iTIP message
                let snapshots =
                    itip_snapshot(&event.data.event, access_token.emails.as_slice(), false)?;
                let is_organizer_update = !itip_snapshots.organizer.email.is_local;
                match itip_process_message(
                    &event.data.event,
                    snapshots,
                    &itip,
                    itip_snapshots,
                    sender.to_string(),
                )? {
                    MergeResult::Actions(changes) => {
                        // Merge changes
                        itip_merge_changes(&mut event.data.event, changes);

                        // Calculate the new ical size
                        event.size = event.data.event.to_string().len() as u32;
                        if event.size > self.core.groupware.max_ical_size as u32 {
                            return Err(ItipIngestError::Message(ItipError::EventTooLarge));
                        }

                        // Validate quota
                        let extra_bytes = (event.size as u64)
                            .saturating_sub(event_.inner.size.to_native() as u64);
                        if extra_bytes > 0
                            && self
                                .has_available_quota(resource_token, extra_bytes)
                                .await
                                .is_err()
                        {
                            return Err(ItipIngestError::Message(ItipError::QuotaExceeded));
                        }

                        // Build event
                        let now = now() as i64;
                        let prev_email_alarm = event_.inner.data.next_alarm(now, Tz::Floating);
                        let mut next_email_alarm = None;
                        event.data = CalendarEventData::new(
                            event.data.event,
                            Tz::Floating,
                            self.core.groupware.max_ical_instances,
                            &mut next_email_alarm,
                        );
                        if is_organizer_update {
                            if let Some(schedule_tag) = &mut event.schedule_tag {
                                *schedule_tag += 1;
                            } else {
                                event.schedule_tag = Some(1);
                            }
                        }

                        // Build event for schedule inbox
                        let itip_document_id = self
                            .store()
                            .assign_document_ids(
                                account_id,
                                Collection::CalendarEventNotification,
                                1,
                            )
                            .await
                            .caused_by(trc::location!())?;
                        let itip_message = CalendarEventNotification {
                            event: itip,
                            changed_by,
                            event_id: Some(document_id),
                            flags: EVENT_NOTIFICATION_IS_CHANGE,
                            size: itip_message.len() as u32,
                            ..Default::default()
                        };

                        // Prepare write batch
                        let mut batch = BatchBuilder::new();
                        event
                            .update(access_token, event_, account_id, document_id, &mut batch)
                            .caused_by(trc::location!())?;
                        if prev_email_alarm != next_email_alarm {
                            if let Some(prev_alarm) = prev_email_alarm {
                                prev_alarm.delete_task(&mut batch);
                            }
                            if let Some(next_alarm) = next_email_alarm {
                                next_alarm.write_task(&mut batch);
                            }
                        }
                        itip_message
                            .insert(access_token, account_id, itip_document_id, &mut batch)
                            .caused_by(trc::location!())?;
                        self.commit_batch(batch).await.caused_by(trc::location!())?;

                        Ok(None)
                    }
                    MergeResult::Message(itip_message) => Ok(Some(itip_message)),
                    MergeResult::None => Ok(None),
                }
            } else {
                Err(ItipIngestError::Message(ItipError::EventNotFound))
            }
        } else {
            // Verify that auto-adding invitations is allowed
            if !self.core.groupware.itip_auto_add
                && !matches!(changed_by, ChangedBy::PrincipalId(_))
                && !self
                    .document_exists(
                        account_id,
                        Collection::ContactCard,
                        ContactField::Email,
                        sender.as_bytes(),
                    )
                    .await
                    .caused_by(trc::location!())?
            {
                return Err(ItipIngestError::Message(ItipError::AutoAddDisabled));
            } else if itip_method(&itip)? != &ICalendarMethod::Request {
                return Err(ItipIngestError::Message(ItipError::EventNotFound));
            }

            // Import the iTIP message
            let mut ical = itip.clone();
            itip_import_message(&mut ical)?;

            // Validate quota
            if self
                .has_available_quota(resource_token, itip_message.len() as u64)
                .await
                .is_err()
            {
                return Err(ItipIngestError::Message(ItipError::QuotaExceeded));
            }

            // Obtain parent calendar
            let Some(parent_id) = self
                .get_or_create_default_calendar(access_token, account_id)
                .await
                .caused_by(trc::location!())?
            else {
                return Err(ItipIngestError::Message(ItipError::NoDefaultCalendar));
            };

            // Build event
            let mut next_email_alarm = None;
            let now = now() as i64;
            let event = CalendarEvent {
                names: vec![DavName {
                    name: format!("{}_{}.ics", now, rand::random::<u64>()),
                    parent_id,
                }],
                data: CalendarEventData::new(
                    ical,
                    Tz::Floating,
                    self.core.groupware.max_ical_instances,
                    &mut next_email_alarm,
                ),
                size: itip_message.len() as u32,
                schedule_tag: Some(1),
                ..Default::default()
            };

            // Obtain document ids
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::CalendarEvent, 1)
                .await
                .caused_by(trc::location!())?;
            let itip_document_id = self
                .store()
                .assign_document_ids(account_id, Collection::CalendarEventNotification, 1)
                .await
                .caused_by(trc::location!())?;
            let itip_message = CalendarEventNotification {
                event: itip,
                event_id: Some(document_id),
                changed_by,
                size: itip_message.len() as u32,
                ..Default::default()
            };

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            event
                .insert(
                    access_token,
                    account_id,
                    document_id,
                    next_email_alarm,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            itip_message
                .insert(access_token, account_id, itip_document_id, &mut batch)
                .caused_by(trc::location!())?;
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(None)
        }
    }

    async fn http_rsvp_url(
        &self,
        account_id: u32,
        document_id: u32,
        attendee: &str,
    ) -> Option<ItipRsvpUrl> {
        if let Some(base_url) = &self.core.groupware.itip_http_rsvp_url {
            match self
                .encode_access_token(
                    GrantType::Rsvp,
                    account_id,
                    &format!("{attendee};{document_id}"),
                    self.core.groupware.itip_http_rsvp_expiration,
                )
                .await
            {
                Ok(access_token) => Some(ItipRsvpUrl(format!(
                    "{base_url}?i={}",
                    percent_encoding::percent_encode(access_token.as_bytes(), RFC_3986)
                ))),
                Err(err) => {
                    trc::error!(err.caused_by(trc::location!()));
                    None
                }
            }
        } else {
            None
        }
    }

    async fn http_rsvp_handle(&self, query: &str, language: &str) -> trc::Result<String> {
        let response = if let Some(rsvp) = decode_rsvp_response(self, query).await {
            if let Some(archive) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    rsvp.account_id,
                    Collection::CalendarEvent,
                    rsvp.document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let event = archive
                    .to_unarchived::<CalendarEvent>()
                    .caused_by(trc::location!())?;
                let mut new_event = event
                    .deserialize::<CalendarEvent>()
                    .caused_by(trc::location!())?;
                let mut did_change = false;
                let mut summary = None;
                let mut description = None;
                let mut found_participant = false;

                for component in &mut new_event.data.event.components {
                    if component.component_type.is_scheduling_object() {
                        'outer: for entry in &mut component.entries {
                            if entry.name == ICalendarProperty::Attendee
                                && entry
                                    .calendar_address()
                                    .is_some_and(|v| v.eq_ignore_ascii_case(&rsvp.attendee))
                            {
                                let mut add_partstat = true;
                                for param in &mut entry.params {
                                    if let (
                                        ICalendarParameterName::Partstat,
                                        ICalendarParameterValue::Partstat(partstat),
                                    ) = (&param.name, &mut param.value)
                                    {
                                        if partstat != &rsvp.partstat {
                                            *partstat = rsvp.partstat.clone();
                                            add_partstat = false;
                                        } else {
                                            continue 'outer;
                                        }
                                    }
                                }

                                if add_partstat {
                                    entry
                                        .params
                                        .push(ICalendarParameter::partstat(rsvp.partstat.clone()));
                                }
                                found_participant = true;
                                did_change = true;
                            } else if summary.is_none() && entry.name == ICalendarProperty::Summary
                            {
                                summary = entry
                                    .values
                                    .first()
                                    .and_then(|v| v.as_text())
                                    .map(|s| s.to_string());
                            } else if description.is_none()
                                && entry.name == ICalendarProperty::Description
                            {
                                description = entry
                                    .values
                                    .first()
                                    .and_then(|v| v.as_text())
                                    .map(|s| s.to_string());
                            }
                        }
                    }
                }

                if did_change {
                    // Prepare write batch
                    let access_token = self
                        .get_access_token(rsvp.account_id)
                        .await
                        .caused_by(trc::location!())?;
                    let mut batch = BatchBuilder::new();
                    new_event
                        .update(
                            &access_token,
                            event,
                            rsvp.account_id,
                            rsvp.document_id,
                            &mut batch,
                        )
                        .caused_by(trc::location!())?;

                    self.commit_batch(batch).await.caused_by(trc::location!())?;
                }

                if found_participant {
                    Response::Success {
                        summary,
                        description,
                    }
                } else {
                    Response::NoLongerParticipant
                }
            } else {
                Response::EventNotFound
            }
        } else {
            Response::ParseError
        };

        Ok(render_response(self, response, language))
    }
}

struct RsvpResponse {
    account_id: u32,
    document_id: u32,
    attendee: String,
    partstat: ICalendarParticipationStatus,
}

async fn decode_rsvp_response(server: &Server, query: &str) -> Option<RsvpResponse> {
    let params = UrlParams::new(query.into());
    let token = params.get("i")?;
    let method = params.get("m").and_then(|m| {
        hashify::tiny_map_ignore_case!(m.as_bytes(),
            "ACCEPTED" => ICalendarParticipationStatus::Accepted,
            "DECLINED" => ICalendarParticipationStatus::Declined,
            "TENTATIVE" => ICalendarParticipationStatus::Tentative,
            "COMPLETED" => ICalendarParticipationStatus::Completed,
            "IN-PROCESS" => ICalendarParticipationStatus::InProcess,
        )
    })?;
    let token = server
        .validate_access_token(GrantType::Rsvp.into(), token)
        .await
        .ok()?;
    let (attendee, document_id) =
        token
            .client_id
            .rsplit_once(';')
            .and_then(|(attendee, doc_id)| {
                doc_id
                    .parse::<u32>()
                    .ok()
                    .map(|doc_id| (attendee.to_string(), doc_id))
            })?;

    RsvpResponse {
        account_id: token.account_id,
        document_id,
        attendee,
        partstat: method,
    }
    .into()
}

enum Response {
    Success {
        summary: Option<String>,
        description: Option<String>,
    },
    EventNotFound,
    ParseError,
    NoLongerParticipant,
}

fn render_response(server: &Server, response: Response, language: &str) -> String {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let template = server
        .core
        .enterprise
        .as_ref()
        .and_then(|e| e.template_scheduling_web.as_ref())
        .unwrap_or(&server.core.groupware.itip_template);
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    let template = &server.core.groupware.itip_template;
    let locale = i18n::locale_or_default(language);

    let mut variables = Variables::new();

    match response {
        Response::Success {
            summary,
            description,
        } => {
            variables.insert_single(
                CalendarTemplateVariable::PageTitle,
                locale.calendar_rsvp_recorded.to_string(),
            );
            variables.insert_single(
                CalendarTemplateVariable::Header,
                locale.calendar_rsvp_recorded.to_string(),
            );
            variables.insert_block(
                CalendarTemplateVariable::EventDetails,
                [
                    summary.map(|summary| {
                        [
                            (
                                CalendarTemplateVariable::Key,
                                locale.calendar_summary.to_string(),
                            ),
                            (CalendarTemplateVariable::Value, summary),
                        ]
                    }),
                    description.map(|description| {
                        [
                            (
                                CalendarTemplateVariable::Key,
                                locale.calendar_description.to_string(),
                            ),
                            (CalendarTemplateVariable::Value, description),
                        ]
                    }),
                ]
                .into_iter()
                .flatten(),
            );

            variables.insert_single(CalendarTemplateVariable::Color, "info".to_string());
        }
        Response::EventNotFound => {
            variables.insert_single(
                CalendarTemplateVariable::PageTitle,
                locale.calendar_rsvp_failed.to_string(),
            );
            variables.insert_single(
                CalendarTemplateVariable::Header,
                locale.calendar_event_not_found.to_string(),
            );
            variables.insert_single(CalendarTemplateVariable::Color, "danger".to_string());
        }
        Response::ParseError => {
            variables.insert_single(
                CalendarTemplateVariable::PageTitle,
                locale.calendar_rsvp_failed.to_string(),
            );
            variables.insert_single(
                CalendarTemplateVariable::Header,
                locale.calendar_invalid_rsvp.to_string(),
            );
            variables.insert_single(CalendarTemplateVariable::Color, "danger".to_string());
        }
        Response::NoLongerParticipant => {
            variables.insert_single(
                CalendarTemplateVariable::PageTitle,
                locale.calendar_rsvp_failed.to_string(),
            );
            variables.insert_single(
                CalendarTemplateVariable::Header,
                locale.calendar_not_participant.to_string(),
            );
            variables.insert_single(CalendarTemplateVariable::Color, "warning".to_string());
        }
    }
    variables.insert_single(CalendarTemplateVariable::LogoCid, "/logo.svg".to_string());

    template.eval(&variables)
}

impl ItipRsvpUrl {
    pub fn url(&self, partstat: &ICalendarParticipationStatus) -> String {
        format!("{}&m={}", self.0, partstat.as_str())
    }
}

impl From<ItipError> for ItipIngestError {
    fn from(err: ItipError) -> Self {
        ItipIngestError::Message(err)
    }
}

impl From<trc::Error> for ItipIngestError {
    fn from(err: trc::Error) -> Self {
        ItipIngestError::Internal(err)
    }
}
