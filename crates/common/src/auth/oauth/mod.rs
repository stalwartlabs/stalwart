/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod client_id;
pub mod config;
pub mod crypto;
pub mod introspect;
pub mod oidc;
pub mod registration;
pub mod token;

pub const DEVICE_CODE_LEN: usize = 40;
pub const USER_CODE_LEN: usize = 8;
pub const RANDOM_CODE_LEN: usize = 32;
pub const CLIENT_ID_MAX_LEN: usize = 2048;

pub const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No 0, O, I, 1

pub const SCOPE_OPENID: &str = "openid";
pub const SCOPE_OFFLINE_ACCESS: &str = "offline_access";
pub const SCOPE_MAIL: &str = "urn:ietf:params:oauth:scope:mail";
pub const SCOPE_CONTACTS: &str = "urn:ietf:params:oauth:scope:contacts";
pub const SCOPE_CALENDARS: &str = "urn:ietf:params:oauth:scope:calendars";

pub const SUPPORTED_SCOPES: &[&str] = &[
    SCOPE_OPENID,
    SCOPE_OFFLINE_ACCESS,
    SCOPE_MAIL,
    SCOPE_CONTACTS,
    SCOPE_CALENDARS,
];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GrantType {
    AccessToken,
    RefreshToken,
    LiveTracing,
    LiveMetrics,
    LiveDelivery,
    Rsvp,
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantType::AccessToken => "access_token",
            GrantType::RefreshToken => "refresh_token",
            GrantType::LiveTracing => "live_tracing",
            GrantType::LiveMetrics => "live_metrics",
            GrantType::LiveDelivery => "live_delivery",
            GrantType::Rsvp => "rsvp",
        }
    }

    pub fn id(&self) -> u8 {
        match self {
            GrantType::AccessToken => 0,
            GrantType::RefreshToken => 1,
            GrantType::LiveTracing => 2,
            GrantType::LiveMetrics => 3,
            GrantType::LiveDelivery => 4,
            GrantType::Rsvp => 5,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(GrantType::AccessToken),
            1 => Some(GrantType::RefreshToken),
            2 => Some(GrantType::LiveTracing),
            3 => Some(GrantType::LiveMetrics),
            4 => Some(GrantType::LiveDelivery),
            5 => Some(GrantType::Rsvp),
            _ => None,
        }
    }
}
