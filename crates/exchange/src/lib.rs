/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod autodiscover;
pub mod cache;
pub mod contact_group;
pub mod eas;
pub mod ews;
pub mod folders;
pub mod groupware_move;
pub mod groupware_write;
pub mod identity;
pub mod junk;
pub mod mail;
pub mod mail_copy;
pub mod mapi;
pub mod oab;
pub mod push;
pub mod receipt;
pub mod request;
pub mod rules;
pub mod session;
pub mod store;
pub mod submit;
pub mod vacation;

pub use request::ExchangeRequestHandler;
pub use store::cleanup::ExchangeCleanup;
