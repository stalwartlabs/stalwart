/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{LOAD_CONCURRENCY, email::LoadedMail};
use crate::{
    cache::ExchangeCacheFetch,
    eas::convert::{
        email::ParsedMeeting,
        flag::{
            MEETING_TYPE_KEY, MailRow, StoredFlags, decode, decode_i32, encode_key, set_or_remove,
        },
    },
    store::{
        QuotaOwner,
        account::ExchangeAccountStore,
        object::{ExchangeObject, ExchangeObjectStore, ObjectVersion, OwnerStamp},
    },
};
use calcard::icalendar::{ArchivedICalendar, ArchivedICalendarValue, ICalendarProperty};
use common::{Server, auth::AccessToken, cache::exchange::ExchangeAccountCache};
use exchange_proto::{
    common::time::{FileTime, UtcSeconds},
    convert::ical::{
        MeetingRole,
        eas::{MeetingHistory, MeetingRevision, meeting_version},
        event_meeting_role,
    },
    eas::tokens::ProtocolVersion,
    mapi::prop::{
        OwnedPropValue, PropKeyRef, PropValue,
        sets::{PSETID_APPOINTMENT, PSETID_MEETING},
    },
};
use futures::{StreamExt, TryStreamExt, future::try_join_all, stream, try_join};
use groupware::{cache::GroupwareCache, calendar::CalendarEventContent};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};

const OWNER_CRITICAL_CHANGE_KEY: PropKeyRef<'static> = PropKeyRef::Lid {
    set: PSETID_MEETING,
    lid: 0x001A,
};
const APPOINTMENT_SEQUENCE_KEY: PropKeyRef<'static> = PropKeyRef::Lid {
    set: PSETID_APPOINTMENT,
    lid: 0x8201,
};
const MTG_REQUEST: i32 = 0x0000_0001;
const MTG_FULL: i32 = 0x0001_0000;
const MTG_INFO: i32 = 0x0002_0000;
const MTG_OUT_OF_DATE: i32 = 0x0008_0000;
const MAX_DECIDE_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeetingType {
    Initial,
    Updated,
    Outdated,
}

impl MeetingType {
    const fn mapi(self) -> i32 {
        match self {
            MeetingType::Initial => MTG_REQUEST,
            MeetingType::Updated => MTG_FULL,
            MeetingType::Outdated => MTG_OUT_OF_DATE,
        }
    }

    const fn history(self) -> MeetingHistory {
        match self {
            MeetingType::Initial => MeetingHistory::Initial,
            MeetingType::Updated => MeetingHistory::Updated,
            MeetingType::Outdated => MeetingHistory::Outdated,
        }
    }

    const fn stored_history(value: i32) -> MeetingHistory {
        if value & MTG_OUT_OF_DATE != 0 {
            MeetingHistory::Outdated
        } else if value & MTG_FULL != 0 {
            MeetingHistory::Updated
        } else if value & MTG_INFO != 0 {
            MeetingHistory::Informational
        } else if value & MTG_REQUEST != 0 {
            MeetingHistory::Initial
        } else {
            MeetingHistory::Current
        }
    }

    fn decide(
        revision: MeetingRevision,
        mark: Option<MeetingRevision>,
        stored_sequence: i32,
    ) -> Self {
        match mark {
            _ if stored_sequence > revision.sequence => MeetingType::Outdated,
            Some(mark) if revision < mark => MeetingType::Outdated,
            Some(_) => MeetingType::Updated,
            None if revision.sequence > 0 => MeetingType::Updated,
            None => MeetingType::Initial,
        }
    }
}

struct MeetingKeys {
    meeting_type: Vec<u8>,
    critical_change: Vec<u8>,
    sequence: Vec<u8>,
}

impl MeetingKeys {
    fn new() -> Self {
        MeetingKeys {
            meeting_type: encode_key(MEETING_TYPE_KEY),
            critical_change: encode_key(OWNER_CRITICAL_CHANGE_KEY),
            sequence: encode_key(APPOINTMENT_SEQUENCE_KEY),
        }
    }

    fn stored_type(&self, object: &ExchangeObject) -> Option<i32> {
        object.property(&self.meeting_type).and_then(decode_i32)
    }

    fn set_type(&self, object: &mut ExchangeObject, meeting_type: MeetingType) -> bool {
        set_or_remove(
            object,
            &self.meeting_type,
            Some(OwnedPropValue::I32(meeting_type.mapi())),
        )
    }

    fn revision(&self, object: &ExchangeObject) -> Option<MeetingRevision> {
        let sequence = object.property(&self.sequence).and_then(decode_i32)?;
        let PropValue::Time(stamp) = object.property(&self.critical_change).and_then(decode)?
        else {
            return None;
        };
        Some(MeetingRevision {
            sequence,
            stamp: stamp.to_utc().0.0,
        })
    }

    fn set_revision(&self, object: &mut ExchangeObject, revision: MeetingRevision) -> bool {
        let sequence = set_or_remove(
            object,
            &self.sequence,
            Some(OwnedPropValue::I32(revision.sequence)),
        );
        let stamp = set_or_remove(
            object,
            &self.critical_change,
            Some(OwnedPropValue::Time(FileTime::from_utc(
                UtcSeconds(revision.stamp),
                0,
            ))),
        );
        sequence || stamp
    }
}

struct Pending<'m> {
    document_id: u32,
    received_at: u64,
    meeting: &'m mut ParsedMeeting,
}

struct Candidate<'m> {
    event_id: u32,
    revision: MeetingRevision,
    pending: Pending<'m>,
}

impl Candidate<'_> {
    fn same_document(left: &Self, right: &Self) -> bool {
        left.pending.document_id == right.pending.document_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowLookup {
    Cached,
    Store,
}

struct Decider<'a> {
    server: &'a Server,
    exchange: &'a ExchangeAccountCache,
    keys: MeetingKeys,
    account_id: u32,
    owner: QuotaOwner,
    max_size: usize,
}

pub fn resolve_meetings<'m>(
    server: &'m Server,
    access_token: &'m AccessToken,
    account_id: u32,
    version: ProtocolVersion,
    exchange: &'m ExchangeAccountCache,
    stored: &'m StoredFlags,
    mails: impl Iterator<Item = &'m mut LoadedMail>,
) -> impl Future<Output = trc::Result<Vec<String>>> + Send + 'm {
    let meetings: Vec<Pending<'m>> = mails
        .filter_map(|mail| {
            let document_id = mail.document_id;
            let received_at = mail.received_at;
            mail.meeting.as_deref_mut().map(|meeting| Pending {
                document_id,
                received_at,
                meeting,
            })
        })
        .collect();
    async move {
        if meetings.is_empty() {
            return Ok(Vec::new());
        }
        let owner = server.account_info(account_id).await?.addresses;
        if version < ProtocolVersion::V141 {
            return Ok(owner);
        }
        let mut undecided = Vec::new();
        for pending in meetings {
            if !pending.meeting.part.is_request()
                || matches!(
                    event_meeting_role(&pending.meeting.ical, &owner),
                    MeetingRole::Organizer
                )
            {
                continue;
            }
            match stored
                .get(pending.document_id)
                .and_then(|mail| mail.meeting_type)
            {
                Some(value) => pending.meeting.history = MeetingType::stored_history(value),
                None => undecided.push(pending),
            }
        }
        if undecided.is_empty() {
            return Ok(owner);
        }
        let decider = Decider {
            server,
            exchange,
            keys: MeetingKeys::new(),
            account_id,
            owner: server
                .exchange_quota_owner(access_token, account_id)
                .await?,
            max_size: server.core.exchange.max_object_size,
        };
        decider.decide(undecided).await?;
        Ok(owner)
    }
}

impl Decider<'_> {
    async fn decide(&self, undecided: Vec<Pending<'_>>) -> trc::Result<()> {
        let resources = self
            .server
            .fetch_groupware_resources(self.account_id, self.account_id, SyncCollection::Calendar)
            .await?;
        let mut candidates: Vec<Candidate<'_>> = undecided
            .into_iter()
            .filter_map(|pending| {
                let version = meeting_version(&pending.meeting.ical)?;
                let event_id = resources.uid_matches(version.uid).min()?;
                let revision = version.revision;
                Some(Candidate {
                    event_id,
                    revision,
                    pending,
                })
            })
            .collect();
        candidates.sort_unstable_by_key(|candidate| {
            (
                candidate.event_id,
                candidate.pending.received_at,
                candidate.pending.document_id,
            )
        });
        let events: Vec<_> = candidates
            .chunk_by_mut(|left, right| left.event_id == right.event_id)
            .map(|group| self.decide_event(group))
            .collect();
        stream::iter(events)
            .buffer_unordered(LOAD_CONCURRENCY)
            .try_collect::<()>()
            .await
    }

    async fn decide_event(&self, group: &mut [Candidate<'_>]) -> trc::Result<()> {
        let Some(event_id) = group.first().map(|candidate| candidate.event_id) else {
            return Ok(());
        };
        let stored_sequence = self.stored_sequence(event_id).await?;
        let mut lookup = RowLookup::Cached;
        for _ in 0..MAX_DECIDE_ATTEMPTS {
            let (mut event, mut rows) = try_join!(
                self.load_row(Collection::CalendarEvent, event_id, lookup),
                try_join_all(
                    group
                        .chunk_by(Candidate::same_document)
                        .filter_map(<[_]>::first)
                        .map(|candidate| self.load_row(
                            Collection::Email,
                            candidate.pending.document_id,
                            lookup
                        ))
                ),
            )?;
            let mut mark = self.keys.revision(&event.next);
            let mut batch = BatchBuilder::new();
            let mut writes = false;
            for (copies, row) in group
                .chunk_by_mut(Candidate::same_document)
                .zip(rows.iter_mut())
            {
                let Some((revision, document_id)) = copies
                    .first()
                    .map(|candidate| (candidate.revision, candidate.pending.document_id))
                else {
                    continue;
                };
                let (history, decided) = match self.keys.stored_type(&row.next) {
                    Some(value) => (MeetingType::stored_history(value), true),
                    None => {
                        let meeting_type = MeetingType::decide(revision, mark, stored_sequence);
                        let written = self.keys.set_type(&mut row.next, meeting_type)
                            && !row.next.exceeds(self.max_size);
                        if written {
                            row.write_as(
                                self.owner,
                                document_id,
                                OwnerStamp::Logged,
                                ObjectVersion::Kept,
                                self.max_size,
                            )
                            .build(&mut batch)?;
                            writes = true;
                        }
                        (meeting_type.history(), written)
                    }
                };
                for candidate in copies.iter_mut() {
                    candidate.pending.meeting.history = history;
                }
                if decided {
                    mark = Some(mark.map_or(revision, |mark| mark.max(revision)));
                }
            }
            if let Some(mark) = mark
                && self.keys.set_revision(&mut event.next, mark)
            {
                if event.next.exceeds(self.max_size) {
                    return Ok(());
                }
                event
                    .write_as(
                        self.owner,
                        event_id,
                        OwnerStamp::Logged,
                        ObjectVersion::Kept,
                        self.max_size,
                    )
                    .build(&mut batch)?;
                writes = true;
            }
            if !writes {
                return Ok(());
            }
            match self.server.commit_batch(batch).await {
                Ok(_) => {
                    self.server.mark_exchange_stale(self.account_id);
                    return Ok(());
                }
                Err(err) if err.is_assertion_failure() => {
                    self.server.mark_exchange_stale(self.account_id);
                    lookup = RowLookup::Store;
                }
                Err(err) => {
                    trc::error!(err.caused_by(trc::location!()));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    async fn load_row(
        &self,
        collection: Collection,
        document_id: u32,
        lookup: RowLookup,
    ) -> trc::Result<MailRow> {
        let previous =
            if lookup == RowLookup::Store || self.exchange.has_object(collection, document_id) {
                self.server
                    .exchange_object(self.account_id, collection, document_id)
                    .await?
            } else {
                None
            };
        MailRow::from_previous(previous, collection)
    }

    async fn stored_sequence(&self, event_id: u32) -> trc::Result<i32> {
        let Some(content) = self
            .server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                self.account_id,
                Collection::CalendarEvent,
                event_id,
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(0);
        };
        Ok(series_sequence(
            &content
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?
                .data
                .event,
        ))
    }
}

fn series_sequence(event: &ArchivedICalendar) -> i32 {
    event
        .components
        .iter()
        .find(|component| {
            component.component_type.is_scheduling_object() && !component.is_recurrence_override()
        })
        .and_then(|component| component.property(&ICalendarProperty::Sequence))
        .and_then(|entry| entry.values.first())
        .and_then(ArchivedICalendarValue::as_integer)
        .map_or(0, |sequence| {
            i32::try_from(sequence.max(0)).unwrap_or(i32::MAX)
        })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/sync/meetings/tests.rs"]
mod tests;
