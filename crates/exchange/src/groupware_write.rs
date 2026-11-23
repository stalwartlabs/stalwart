/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod card;
mod event;
mod event_edit;
mod meeting;

pub use card::{
    WriteFailure, assert_card_room, card_failure, card_name, card_size, new_card, new_uid,
    store_failure,
};
pub use event::{
    assert_event_room, event_failure, event_name, ical_size, new_event, new_todo, set_event_uid,
};
pub use event_edit::EventEdit;
pub use meeting::{
    MeetingError, MeetingOutcome, MeetingReply, MeetingResponse, UnchangedReply,
    respond_to_meeting, uid_events,
};
