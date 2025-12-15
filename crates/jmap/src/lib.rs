/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

pub mod addressbook;
pub mod api;
pub mod blob;
pub mod calendar;
pub mod calendar_event;
pub mod calendar_event_notification;
pub mod changes;
pub mod contact;
pub mod email;
pub mod file;
pub mod identity;
pub mod mailbox;
pub mod participant_identity;
pub mod principal;
pub mod push;
pub mod quota;
pub mod share_notification;
pub mod sieve;
pub mod submission;
pub mod thread;
pub mod vacation;
pub mod websocket;
