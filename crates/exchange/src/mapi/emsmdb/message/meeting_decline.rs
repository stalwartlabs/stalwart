/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::save::meeting_message;
use crate::{
    groupware_write::{
        MeetingError, MeetingReply, MeetingResponse, UnchangedReply, respond_to_meeting, uid_events,
    },
    identity::DirectoryRef,
    mapi::emsmdb::resolve::bag_principal,
};
use common::{Server, auth::AccessToken};
use exchange_proto::{
    convert::{
        ical::{MeetingMessage, ParticipationError, RecurrenceId, meeting_instance, meeting_uid},
        model::{MessageContent, PropBag},
    },
    mapi::prop::{OwnedPropValue, PropKeyRef, PropTag, PropType, tags},
};
use groupware::{
    cache::GroupwareCache,
    calendar::write::{EventWriteError, EventWriter, ItipMode},
};
use trc::AddContext;
use types::collection::SyncCollection;

const ADDRESS_TYPE_SMTP: &str = "SMTP";

#[derive(Debug)]
enum Representing {
    Mailbox,
    Principal(DirectoryRef),
    Smtp(String),
    Unknown,
}

#[derive(Debug)]
pub(super) struct DeclinedMeeting {
    uid: String,
    instance: Option<RecurrenceId>,
    representing: Representing,
}

impl Representing {
    fn of(props: &PropBag) -> Self {
        if let Some(principal) = bag_principal(
            props,
            tags::SENT_REPRESENTING_ADDRESS_TYPE,
            tags::SENT_REPRESENTING_EMAIL_ADDRESS,
            tags::SENT_REPRESENTING_ENTRY_ID,
        ) {
            return Representing::Principal(principal);
        }
        let unicode = |tag: PropTag| match props.get(PropKeyRef::Tag(tag.id()), PropType::Unicode) {
            Some(OwnedPropValue::Unicode(value)) => Some(&value[..]),
            _ => None,
        };
        let smtp = unicode(tags::SENT_REPRESENTING_SMTP_ADDRESS).or_else(|| {
            unicode(tags::SENT_REPRESENTING_ADDRESS_TYPE)
                .filter(|kind| kind.eq_ignore_ascii_case(ADDRESS_TYPE_SMTP))
                .and_then(|_| unicode(tags::SENT_REPRESENTING_EMAIL_ADDRESS))
        });
        if let Some(smtp) = smtp {
            Representing::Smtp(smtp.to_owned())
        } else if [
            tags::SENT_REPRESENTING_ENTRY_ID,
            tags::SENT_REPRESENTING_EMAIL_ADDRESS,
        ]
        .into_iter()
        .any(|tag| props.get_any(PropKeyRef::Tag(tag.id())).is_some())
        {
            Representing::Unknown
        } else {
            Representing::Mailbox
        }
    }
}

impl DeclinedMeeting {
    pub(super) fn of(content: &MessageContent) -> Option<Self> {
        if meeting_message(content)? != MeetingMessage::Declined {
            return None;
        }
        Some(DeclinedMeeting {
            uid: meeting_uid(&content.props)?.into_owned(),
            instance: meeting_instance(&content.props).ok()?,
            representing: Representing::of(&content.props),
        })
    }

    pub(super) async fn apply(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<()> {
        match self.representing {
            Representing::Mailbox | Representing::Smtp(_) => {}
            Representing::Principal(DirectoryRef::Account(id)) if id == account_id => {}
            Representing::Principal(_) | Representing::Unknown => return Ok(()),
        }
        let resources = server
            .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let mut candidates = uid_events(&resources, &self.uid).peekable();
        if candidates.peek().is_none() {
            return Ok(());
        }
        let account_info = server
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        if let Representing::Smtp(smtp) = &self.representing
            && !account_info
                .addresses()
                .iter()
                .any(|address| address.eq_ignore_ascii_case(smtp))
        {
            return Ok(());
        }
        let writer = EventWriter {
            server,
            access_token,
            account_id,
            resources: &resources,
            account_info: &account_info,
        };
        for (calendar_id, document_id) in candidates {
            let response = MeetingResponse {
                calendar_id,
                document_id,
                instance: self.instance,
                reply: MeetingReply::Decline,
                itip: ItipMode::Suppress,
                unchanged: UnchangedReply::Ignore,
            };
            match respond_to_meeting(&writer, response)
                .await
                .caused_by(trc::location!())?
            {
                Err(
                    MeetingError::Participation(
                        ParticipationError::Organizer | ParticipationError::NotAttendee,
                    )
                    | MeetingError::Write(EventWriteError::NotFound),
                ) => {}
                Ok(_) => return Ok(()),
                Err(err) => {
                    trc::event!(
                        Calendar(trc::CalendarEvent::ItipMessageError),
                        AccountId = account_id,
                        DocumentId = document_id,
                        Details = "MAPI declined meeting not applied to the calendar",
                        Reason = format!("{err:?}"),
                    );
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}
