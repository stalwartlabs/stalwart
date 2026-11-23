/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::icalendar::ICalendar;
use exchange_proto::convert::ical::clear_event_draft;
use groupware::calendar::{
    ArchivedCalendarEvent,
    privacy::{EventViewer, ICalendarPrivacy},
    write::{
        EventWrite, EventWriteError, EventWriteResult, EventWriter, ItipMode, StoredEvent,
        UidChange,
    },
};
use store::write::{Archive, serialize::rkyv_deserialize};
use trc::AddContext;

pub struct EventEdit<'x> {
    writer: &'x EventWriter<'x>,
    stored: StoredEvent,
}

impl<'x> EventEdit<'x> {
    pub async fn open(
        writer: &'x EventWriter<'x>,
        calendar_id: u32,
        document_id: u32,
    ) -> EventWriteResult<Self> {
        let stored = writer
            .prepare_update(calendar_id, document_id, &ICalendar::default())
            .await?;
        Ok(EventEdit { writer, stored })
    }

    pub fn event(&self) -> trc::Result<Archive<&ArchivedCalendarEvent>> {
        self.stored.event()
    }

    pub fn to_ical(&self) -> trc::Result<ICalendar> {
        self.stored
            .content()
            .and_then(|content| rkyv_deserialize::<_, ICalendar>(&content.inner.data.event))
            .caused_by(trc::location!())
    }

    pub async fn commit(self, ical: ICalendar, itip: ItipMode) -> EventWriteResult<EventWrite> {
        self.commit_with(ical, itip, UidChange::Refuse).await
    }

    pub async fn commit_with(
        self,
        mut ical: ICalendar,
        itip: ItipMode,
        uid_change: UidChange,
    ) -> EventWriteResult<EventWrite> {
        if itip.sends() {
            clear_event_draft(&mut ical);
        }
        let viewer = EventViewer::of(self.writer.access_token, self.writer.account_id);
        if !ical.privacy().may_be_set_by(viewer) {
            return Err(EventWriteError::Forbidden);
        }
        self.writer
            .update_with(self.stored, ical, None, itip, uid_change)
            .await
    }
}
