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
        EVENT_HIDE_ATTENDEES, EVENT_NOTIFICATION_IS_CHANGE,
    },
    scheduling::{
        InstanceId, ItipError, ItipMessage, ItipSnapshots,
        format::{TextFormatter, hyperlink},
        ical_size,
        inbound::{
            MergeAction, MergeResult, itip_import_message, itip_merge_changes, itip_method,
            itip_process_message,
        },
        itip::itip_build_envelope,
        snapshot::itip_snapshot,
    },
};
use calcard::{
    common::{IanaString, PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParameter, ICalendarParameterName, ICalendarParameterValue,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarValue,
    },
};
use common::{
    DavName, Server,
    auth::{AccessToken, AccountInfo, oauth::GrantType},
    i18n,
};
use registry::schema::enums::Permission;
use std::net::IpAddr;
use store::{
    ValueKey, rand,
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarEventField, ContactField},
};
const MAX_RSVP_COMMENT_LEN: usize = 512;

pub enum ItipIngestError {
    Message(ItipError),
    Internal(trc::Error),
}

#[derive(Default)]
pub struct ItipRsvpUrl(String);

pub trait ItipIngest: Sync + Send {
    fn itip_ingest(
        &self,
        account_info: &AccountInfo,
        sender: &str,
        recipient: &str,
        itip_message: &str,
    ) -> impl Future<Output = Result<Option<ItipMessage<ICalendar>>, ItipIngestError>> + Send;

    fn http_rsvp_url(
        &self,
        account_id: u32,
        account_name: &str,
        document_id: u32,
        attendee: &str,
    ) -> impl Future<Output = Option<ItipRsvpUrl>> + Send;

    fn http_rsvp_handle(
        &self,
        request: RsvpRequest,
        language: &str,
        remote_ip: IpAddr,
    ) -> impl Future<Output = trc::Result<RsvpResponse>> + Send;
}

impl ItipIngest for Server {
    async fn itip_ingest(
        &self,
        account_info: &AccountInfo,
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

        let itip_snapshots = itip_snapshot(&itip, account_info.addresses(), false)?;
        if !itip_snapshots.sender_is_organizer_or_attendee(sender) {
            return Err(ItipIngestError::Message(
                ItipError::SenderIsNotOrganizerNorAttendee,
            ));
        }

        // Obtain changedBy
        let changed_by = if let Some(id) = self.account_id_from_email(sender, true).await? {
            ChangedBy::PrincipalId(id)
        } else {
            ChangedBy::CalendarAddress(sender.into())
        };

        // Find event by UID
        let account_id = account_info.account_id();
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
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
                let event = event_
                    .deserialize::<CalendarEvent>()
                    .caused_by(trc::location!())?;

                // Process the iTIP message
                let snapshots = itip_snapshot(&event.data.event, account_info.addresses(), false)?;
                let is_organizer_update = !itip_snapshots.organizer.email.is_local;
                match itip_process_message(
                    &event.data.event,
                    snapshots,
                    &itip,
                    itip_snapshots,
                    sender.to_string(),
                )? {
                    MergeResult::Actions(changes) => {
                        commit_itip_merge(
                            self,
                            account_info,
                            account_id,
                            document_id,
                            &archive,
                            event,
                            changes,
                            itip,
                            itip_message.len(),
                            changed_by,
                            is_organizer_update,
                        )
                        .await?;

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
                .has_available_quota(
                    self.account(account_id).await?.as_ref(),
                    itip_message.len() as u64,
                )
                .await
                .is_err()
            {
                return Err(ItipIngestError::Message(ItipError::QuotaExceeded));
            }

            // Obtain parent calendar
            let Some(parent_id) = self
                .get_or_create_default_calendar(account_id, account_id)
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

            let itip_message = CalendarEventNotification {
                event: itip,
                event_id: None,
                changed_by,
                size: itip_message.len() as u32,
                ..Default::default()
            };

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let document_id = batch.reserve_document_id(account_id, Collection::CalendarEvent);
            let itip_document_id =
                batch.reserve_document_id(account_id, Collection::CalendarEventNotification);
            event
                .insert(
                    account_info.account_tenant_ids(),
                    account_id,
                    document_id,
                    None,
                    next_email_alarm,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            itip_message
                .insert(
                    account_info.account_tenant_ids(),
                    account_id,
                    itip_document_id,
                    Some(document_id),
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(None)
        }
    }

    async fn http_rsvp_url(
        &self,
        account_id: u32,
        account_name: &str,
        document_id: u32,
        attendee: &str,
    ) -> Option<ItipRsvpUrl> {
        if let Some(base_url) = &self.core.groupware.itip_http_rsvp_url {
            match self
                .encode_access_token(
                    GrantType::Rsvp,
                    account_id,
                    account_name,
                    self.core.groupware.itip_http_rsvp_expiration,
                    Some(&format!("{attendee};{document_id}")),
                    None,
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

    async fn http_rsvp_handle(
        &self,
        request: RsvpRequest,
        language: &str,
        remote_ip: IpAddr,
    ) -> trc::Result<RsvpResponse> {
        let rsvp = match decode_rsvp_token(self, &request.token).await {
            Ok(rsvp) => rsvp,
            Err(reason) => return Ok(RsvpResponse::error(reason, language)),
        };

        let part_stat = match request.part_stat() {
            Ok(part_stat) => part_stat,
            Err(reason) => return Ok(RsvpResponse::error(reason, language)),
        };

        let Some(archive) = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                rsvp.account_id,
                Collection::CalendarEvent,
                rsvp.document_id,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(RsvpResponse::error(RsvpError::EventNotFound, language));
        };

        let organizer_info = self
            .account_info(rsvp.account_id)
            .await
            .caused_by(trc::location!())?;

        // Without a participation status this is a request for the invitation details
        let Some(part_stat) = part_stat else {
            let event = archive
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            return Ok(build_rsvp_invitation(
                &event.data.event,
                &rsvp.attendee,
                organizer_info.addresses(),
                event.flags & EVENT_HIDE_ATTENDEES != 0,
                language,
            ));
        };
        let comment = request.sanitized_comment();

        // Locate the attendee within the organizer's copy of the event
        let event = archive
            .deserialize::<CalendarEvent>()
            .caused_by(trc::location!())?;
        let Ok(snapshots) = itip_snapshot(&event.data.event, organizer_info.addresses(), false)
        else {
            return Ok(RsvpResponse::error(RsvpError::NotParticipant, language));
        };
        let mut is_participant = false;
        let mut instances = Vec::with_capacity(snapshots.components.len());
        for (instance_id, instance) in &snapshots.components {
            let Some(attendee) = instance
                .attendees
                .iter()
                .find(|attendee| attendee.email.email.eq_ignore_ascii_case(&rsvp.attendee))
            else {
                continue;
            };
            is_participant = true;

            if attendee.part_stat != Some(&part_stat) {
                instances.push(instance_id);
            }
        }

        if !is_participant {
            return Ok(RsvpResponse::error(RsvpError::NotParticipant, language));
        }

        // A response identical to the stored one is a no-op, so no reply is sent
        if instances.is_empty() {
            return Ok(RsvpResponse::recorded(&part_stat));
        }
        instances.sort_unstable();

        // Deliver the reply to the organizer without going through the mail queue
        let reply = build_rsvp_reply(
            &snapshots,
            &instances,
            &rsvp.attendee,
            &part_stat,
            comment.as_deref(),
        );
        let reply_size = ical_size(&reply);
        let attendee_copy = http_rsvp_attendee_copy(self, &rsvp, snapshots.uid, remote_ip).await?;
        let changed_by = if let Some(account_id) = self
            .account_id_from_email(&rsvp.attendee, true)
            .await
            .caused_by(trc::location!())?
        {
            ChangedBy::PrincipalId(account_id)
        } else {
            ChangedBy::CalendarAddress(rsvp.attendee.as_str().into())
        };

        let merge =
            itip_snapshot(&reply, organizer_info.addresses(), false).and_then(|reply_snapshots| {
                itip_process_message(
                    &event.data.event,
                    snapshots,
                    &reply,
                    reply_snapshots,
                    rsvp.attendee.clone(),
                )
            });
        let changes = match merge {
            Ok(MergeResult::Actions(changes)) => changes,
            Ok(MergeResult::Message(_) | MergeResult::None) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = rsvp.account_id,
                    DocumentId = rsvp.document_id,
                    From = rsvp.attendee.clone(),
                    Details = "RSVP reply did not apply to any instance",
                );

                return Ok(RsvpResponse::error(RsvpError::ServerError, language));
            }
            Err(err) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = rsvp.account_id,
                    DocumentId = rsvp.document_id,
                    From = rsvp.attendee.clone(),
                    Details = err.to_string(),
                );

                return Ok(RsvpResponse::error(RsvpError::ServerError, language));
            }
        };

        match commit_itip_merge(
            self,
            &organizer_info,
            rsvp.account_id,
            rsvp.document_id,
            &archive,
            event,
            changes,
            reply,
            reply_size,
            changed_by,
            false,
        )
        .await
        {
            Ok(()) => {}
            Err(ItipIngestError::Message(err)) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = rsvp.account_id,
                    DocumentId = rsvp.document_id,
                    From = rsvp.attendee.clone(),
                    Details = err.to_string(),
                );

                return Ok(RsvpResponse::error(RsvpError::ServerError, language));
            }
            Err(ItipIngestError::Internal(err)) => {
                return Err(err.caused_by(trc::location!()));
            }
        }

        // Only once the organizer holds the reply is the attendee's own copy brought in line
        if let Some(target) = attendee_copy {
            http_rsvp_sync_attendee_copy(self, target, &rsvp.attendee, &part_stat).await?;
        }

        Ok(RsvpResponse::recorded(&part_stat))
    }
}

async fn http_rsvp_sync_attendee_copy(
    server: &Server,
    target: RsvpTarget,
    attendee: &str,
    part_stat: &ICalendarParticipationStatus,
) -> trc::Result<()> {
    let event = target
        .archive
        .to_unarchived::<CalendarEvent>()
        .caused_by(trc::location!())?;
    let mut new_event = event
        .deserialize::<CalendarEvent>()
        .caused_by(trc::location!())?;
    let mut did_change = false;

    for component in &mut new_event.data.event.components {
        if !component.component_type.is_scheduling_object() {
            continue;
        }

        for entry in &mut component.entries {
            if entry.name != ICalendarProperty::Attendee
                || !entry
                    .calendar_address()
                    .is_some_and(|v| v.eq_ignore_ascii_case(attendee))
            {
                continue;
            }

            let mut has_partstat = false;
            for param in &mut entry.params {
                if let (
                    ICalendarParameterName::Partstat,
                    ICalendarParameterValue::Partstat(current),
                ) = (&param.name, &mut param.value)
                {
                    has_partstat = true;
                    if current != part_stat {
                        *current = part_stat.clone();
                        did_change = true;
                    }
                }
            }

            if !has_partstat {
                entry
                    .params
                    .push(ICalendarParameter::partstat(part_stat.clone()));
                did_change = true;
            }
        }
    }

    if did_change {
        let attendee_info = server
            .account_info(target.account_id)
            .await
            .caused_by(trc::location!())?;
        new_event.size = ical_size(&new_event.data.event) as u32;

        let mut batch = BatchBuilder::new();
        new_event
            .update(
                attendee_info.account_tenant_ids(),
                event,
                target.account_id,
                target.document_id,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}

struct RsvpTarget {
    account_id: u32,
    document_id: u32,
    archive: Archive<ArchiveBytes>,
}

async fn http_rsvp_attendee_copy(
    server: &Server,
    rsvp: &RsvpToken,
    uid: &str,
    remote_ip: IpAddr,
) -> trc::Result<Option<RsvpTarget>> {
    if !server.core.groupware.itip_enabled {
        return Ok(None);
    }

    let Some(account_id) = server
        .account_id_from_email(&rsvp.attendee, true)
        .await
        .caused_by(trc::location!())?
        .filter(|account_id| *account_id != rsvp.account_id)
    else {
        return Ok(None);
    };

    let can_send = match server.access_token(account_id).await {
        Ok(access_token) => AccessToken::new(access_token, remote_ip).is_ok_and(|access_token| {
            access_token.has_permission(Permission::CalendarSchedulingSend)
        }),
        Err(err) => {
            trc::error!(
                err.account_id(account_id)
                    .caused_by(trc::location!())
                    .details("Failed to obtain access token for RSVP attendee")
            );
            false
        }
    };
    if !can_send {
        return Ok(None);
    }

    let Some(document_id) = server
        .document_ids_matching(
            account_id,
            Collection::CalendarEvent,
            CalendarEventField::Uid,
            uid.as_bytes(),
        )
        .await
        .caused_by(trc::location!())?
        .iter()
        .next()
    else {
        return Ok(None);
    };

    Ok(server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::CalendarEvent,
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
        .map(|archive| RsvpTarget {
            account_id,
            document_id,
            archive,
        }))
}

struct RsvpToken {
    account_id: u32,
    document_id: u32,
    attendee: String,
}

async fn decode_rsvp_token(server: &Server, token: &str) -> Result<RsvpToken, RsvpError> {
    if token.is_empty() {
        return Err(RsvpError::InvalidLink);
    }

    let token = server
        .validate_access_token(GrantType::Rsvp.into(), token)
        .await
        .map_err(|err| {
            if err.matches(trc::EventType::Auth(trc::AuthEvent::TokenExpired)) {
                RsvpError::Expired
            } else {
                RsvpError::InvalidLink
            }
        })?;

    token
        .claims
        .as_deref()
        .and_then(|claims| claims.rsplit_once(';'))
        .and_then(|(attendee, document_id)| {
            document_id
                .parse::<u32>()
                .ok()
                .map(|document_id| RsvpToken {
                    account_id: token.account_id,
                    document_id,
                    attendee: attendee.to_string(),
                })
        })
        .ok_or(RsvpError::InvalidLink)
}

#[allow(clippy::too_many_arguments)]
async fn commit_itip_merge(
    server: &Server,
    account_info: &AccountInfo,
    account_id: u32,
    document_id: u32,
    archive: &Archive<ArchiveBytes>,
    mut event: CalendarEvent,
    changes: Vec<MergeAction>,
    itip: ICalendar,
    itip_size: usize,
    changed_by: ChangedBy,
    is_organizer_update: bool,
) -> Result<(), ItipIngestError> {
    let event_ = archive
        .to_unarchived::<CalendarEvent>()
        .caused_by(trc::location!())?;

    // Merge changes
    itip_merge_changes(&mut event.data.event, changes);

    // Calculate the new ical size
    event.size = ical_size(&event.data.event) as u32;
    if event.size > server.core.groupware.max_ical_size as u32 {
        return Err(ItipIngestError::Message(ItipError::EventTooLarge));
    }

    // Validate quota
    let extra_bytes = (event.size as u64).saturating_sub(event_.inner.size.to_native() as u64);
    if extra_bytes > 0
        && server
            .has_available_quota(server.account(account_id).await?.as_ref(), extra_bytes)
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
        server.core.groupware.max_ical_instances,
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
    let itip_message = CalendarEventNotification {
        event: itip,
        changed_by,
        event_id: Some(document_id),
        flags: EVENT_NOTIFICATION_IS_CHANGE,
        size: itip_size as u32,
        ..Default::default()
    };

    // Prepare write batch
    let mut batch = BatchBuilder::new();
    let itip_document_id =
        batch.reserve_document_id(account_id, Collection::CalendarEventNotification);
    event
        .update(
            account_info.account_tenant_ids(),
            event_,
            account_id,
            document_id,
            None,
            &mut batch,
        )
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
        .insert(
            account_info.account_tenant_ids(),
            account_id,
            itip_document_id,
            None,
            &mut batch,
        )
        .caused_by(trc::location!())?;
    server
        .commit_batch(batch)
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

fn build_rsvp_reply(
    snapshots: &ItipSnapshots<'_>,
    instances: &[&InstanceId],
    attendee: &str,
    part_stat: &ICalendarParticipationStatus,
    comment: Option<&str>,
) -> ICalendar {
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: Vec::with_capacity(instances.len() + 1),
    };
    message
        .components
        .push(itip_build_envelope(ICalendarMethod::Reply));

    for instance_id in instances {
        let Some(instance) = snapshots.components.get(*instance_id) else {
            continue;
        };
        let mut reply = ICalendarComponent {
            component_type: instance.comp.component_type.clone(),
            entries: Vec::with_capacity(8),
            component_ids: vec![],
        };

        reply.add_property(
            ICalendarProperty::Organizer,
            ICalendarValue::Text(snapshots.organizer.email.to_string()),
        );
        reply.add_property_with_params(
            ICalendarProperty::Attendee,
            [ICalendarParameter::partstat(part_stat.clone())],
            ICalendarValue::Text(format!("mailto:{attendee}")),
        );
        reply.add_uid(snapshots.uid);
        reply.add_dtstamp(dt_stamp.clone());
        reply.add_sequence(instance.sequence.unwrap_or_default());

        if !matches!(instance_id, InstanceId::Main)
            && let Some(recurrence_id) = instance
                .comp
                .entries
                .iter()
                .find(|entry| entry.name == ICalendarProperty::RecurrenceId)
        {
            reply.entries.push(recurrence_id.clone());
        }

        if let Some(comment) = comment {
            reply.add_property(
                ICalendarProperty::Comment,
                ICalendarValue::Text(comment.to_string()),
            );
        }

        reply.entries.push(ICalendarEntry {
            name: ICalendarProperty::RequestStatus,
            params: vec![],
            values: vec![
                ICalendarValue::Text("2.0".to_string()),
                ICalendarValue::Text("Success".to_string()),
            ],
        });

        let comp_id = message.components.len() as u32;
        message.components[0].component_ids.push(comp_id);
        message.components.push(reply);
    }

    message
}

fn build_rsvp_invitation(
    ical: &ICalendar,
    attendee: &str,
    account_emails: &[String],
    hide_attendees: bool,
    language: &str,
) -> RsvpResponse {
    let Ok(snapshots) = itip_snapshot(ical, account_emails, false) else {
        return RsvpResponse::error(RsvpError::NotParticipant, language);
    };
    let instance = snapshots.main_instance_or_default();
    let Some(participant) = instance
        .attendees
        .iter()
        .find(|candidate| candidate.email.email.eq_ignore_ascii_case(attendee))
    else {
        return RsvpResponse::error(RsvpError::NotParticipant, language);
    };

    let formatter = match TextFormatter::new(language) {
        Ok(formatter) => formatter,
        Err(err) => {
            trc::error!(err.caused_by(trc::location!()));
            return RsvpResponse::error(RsvpError::ServerError, language);
        }
    };
    let locale = formatter.locale;
    let mut invitation = RsvpInvitation {
        kind: if instance.comp.entries.iter().any(|entry| {
            entry.name == ICalendarProperty::Status
                && entry
                    .values
                    .first()
                    .and_then(|value| value.as_text())
                    .is_some_and(|value| value.eq_ignore_ascii_case("CANCELLED"))
        }) {
            "cancel"
        } else if instance.sequence.is_some_and(|sequence| sequence > 0) {
            "update"
        } else {
            "invite"
        },
        partstat: participant
            .part_stat
            .map_or(ICalendarParticipationStatus::NeedsAction.as_str(), |v| {
                v.as_str()
            }),
        labels: RsvpLabels::new(locale),
        attendee: RsvpParticipant {
            name: participant.name.map(|name| name.to_string()),
            email: participant.email.email.clone(),
            partstat: None,
            is_organizer: false,
        },
        ..Default::default()
    };

    for field in instance.build_summary(None, &[]) {
        let value = formatter.field_to_string(&field.value, locale.calendar_date_template_long);
        if value.is_empty() {
            continue;
        }

        match field.name {
            ICalendarProperty::Summary => invitation.summary = Some(value),
            ICalendarProperty::Description => invitation.description = Some(value),
            ICalendarProperty::Location => invitation.location = Some(value),
            ICalendarProperty::Rrule => invitation.recurrence = Some(value),
            ICalendarProperty::Dtstart if invitation.when.is_none() => {
                invitation.when = Some(value)
            }
            ICalendarProperty::Conference if invitation.conference.is_none() => {
                invitation.conference = Some(RsvpConference {
                    url: hyperlink(&value).map(|url| url.to_string()),
                    value,
                });
            }
            _ => {}
        }
    }

    // hideAttendees limits the list to the owners and the requesting participant
    let mut attendees = Vec::with_capacity(if hide_attendees {
        2
    } else {
        instance.attendees.len() + 1
    });
    attendees.push(RsvpParticipant {
        name: snapshots.organizer.name.map(|name| name.to_string()),
        email: snapshots.organizer.email.email.clone(),
        partstat: None,
        is_organizer: true,
    });
    attendees.extend(
        instance
            .attendees
            .iter()
            .filter(|candidate| {
                !candidate
                    .email
                    .email
                    .eq_ignore_ascii_case(&snapshots.organizer.email.email)
                    && (!hide_attendees || candidate.email.email.eq_ignore_ascii_case(attendee))
            })
            .map(|candidate| RsvpParticipant {
                name: candidate.name.map(|name| name.to_string()),
                email: candidate.email.email.clone(),
                partstat: Some(candidate.part_stat.map_or(
                    ICalendarParticipationStatus::NeedsAction.as_str(),
                    |part_stat| part_stat.as_str(),
                )),
                is_organizer: false,
            }),
    );

    // Attendees are held in a hash set, so they are sorted to keep the response stable
    attendees[1..].sort_unstable_by(|a, b| a.email.cmp(&b.email));
    invitation.attendees = attendees;

    RsvpResponse::Invitation(Box::new(invitation))
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RsvpRequest {
    pub token: String,
    #[serde(default)]
    pub partstat: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RsvpResponse {
    Invitation(Box<RsvpInvitation>),
    Recorded {
        partstat: &'static str,
    },
    Error {
        reason: RsvpError,
        title: &'static str,
        message: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RsvpError {
    InvalidLink,
    InvalidPartStat,
    Expired,
    EventNotFound,
    NotParticipant,
    ServerError,
}

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RsvpInvitation {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conference: Option<RsvpConference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence: Option<String>,
    pub attendee: RsvpParticipant,
    pub attendees: Vec<RsvpParticipant>,
    pub partstat: &'static str,
    pub labels: RsvpLabels,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RsvpConference {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RsvpParticipant {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partstat: Option<&'static str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_organizer: bool,
}

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RsvpLabels {
    pub invitation: &'static str,
    pub updated_invitation: &'static str,
    pub cancelled: &'static str,
    pub description: &'static str,
    pub attendees: &'static str,
    pub organizer: &'static str,
    pub location: &'static str,
    pub conference: &'static str,
    pub when: &'static str,
    pub you: &'static str,
    pub yes: &'static str,
    pub maybe: &'static str,
    pub no: &'static str,
    pub reply_as: &'static str,
    pub note: &'static str,
    pub note_hint: &'static str,
    pub send: &'static str,
    pub update: &'static str,
    pub change: &'static str,
    pub recorded: &'static str,
    pub notified: &'static str,
    pub accepted: &'static str,
    pub tentative: &'static str,
    pub declined: &'static str,
    pub show_more: &'static str,
    pub show_less: &'static str,
    pub failed: &'static str,
    pub error: &'static str,
}

impl RsvpLabels {
    fn new(locale: &'static i18n::Locale) -> Self {
        Self {
            invitation: locale.calendar_invitation,
            updated_invitation: locale.calendar_updated_invitation,
            cancelled: locale.calendar_cancelled,
            description: locale.calendar_description,
            attendees: locale.calendar_attendees,
            organizer: locale.calendar_organizer,
            location: locale.calendar_location,
            conference: locale.calendar_conference,
            when: locale.calendar_when,
            you: locale.calendar_rsvp_you,
            yes: locale.calendar_yes,
            maybe: locale.calendar_maybe,
            no: locale.calendar_no,
            reply_as: locale.calendar_rsvp_reply_as,
            note: locale.calendar_rsvp_comment,
            note_hint: locale.calendar_rsvp_comment_hint,
            send: locale.calendar_rsvp_send,
            update: locale.calendar_rsvp_update,
            change: locale.calendar_rsvp_change,
            recorded: locale.calendar_rsvp_recorded,
            notified: locale.calendar_rsvp_notified,
            accepted: locale.calendar_accepted,
            tentative: locale.calendar_tentative,
            declined: locale.calendar_declined,
            show_more: locale.calendar_show_more,
            show_less: locale.calendar_show_less,
            failed: locale.calendar_rsvp_failed,
            error: locale.calendar_rsvp_error,
        }
    }
}

impl RsvpResponse {
    fn error(reason: RsvpError, language: &str) -> Self {
        let locale = i18n::locale_or_default(language);

        RsvpResponse::Error {
            reason,
            title: locale.calendar_rsvp_failed,
            message: match reason {
                RsvpError::InvalidLink | RsvpError::InvalidPartStat => locale.calendar_invalid_rsvp,
                RsvpError::Expired => locale.calendar_rsvp_expired,
                RsvpError::EventNotFound => locale.calendar_event_not_found,
                RsvpError::NotParticipant => locale.calendar_not_participant,
                RsvpError::ServerError => locale.calendar_rsvp_error,
            },
        }
    }

    fn recorded(part_stat: &ICalendarParticipationStatus) -> Self {
        RsvpResponse::Recorded {
            partstat: part_stat.as_str(),
        }
    }
}

impl RsvpRequest {
    fn part_stat(&self) -> Result<Option<ICalendarParticipationStatus>, RsvpError> {
        match self.partstat.as_deref() {
            Some(partstat) => hashify::tiny_map_ignore_case!(partstat.as_bytes(),
                "ACCEPTED" => ICalendarParticipationStatus::Accepted,
                "DECLINED" => ICalendarParticipationStatus::Declined,
                "TENTATIVE" => ICalendarParticipationStatus::Tentative,
                "COMPLETED" => ICalendarParticipationStatus::Completed,
                "IN-PROCESS" => ICalendarParticipationStatus::InProcess,
            )
            .map(Some)
            .ok_or(RsvpError::InvalidPartStat),
            None => Ok(None),
        }
    }

    fn sanitized_comment(&self) -> Option<String> {
        self.comment
            .as_deref()
            .map(|comment| comment.trim())
            .filter(|comment| !comment.is_empty())
            .map(|comment| {
                comment
                    .chars()
                    .filter(|ch| !ch.is_control() || *ch == '\n')
                    .take(MAX_RSVP_COMMENT_LEN)
                    .collect()
            })
    }
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
