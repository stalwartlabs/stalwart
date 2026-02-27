/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, str::FromStr};
use utils::{sanitize_domain, sanitize_email, sanitize_email_local};

#[derive(Debug, Clone)]
pub enum StringValidator {
    Email,
    EmailLocalPart,
    Domain,
    Hostname,
    RemoveSpaces,
    Lowercase,
    Uppercase,
    Trim,
    SecretHash,
}

pub enum StringValidatorResult {
    Valid,
    Replace(String),
    Invalid(&'static str),
}

impl StringValidator {
    pub fn validate(&self, value: &str) -> StringValidatorResult {
        match self {
            Self::Email => sanitize_email(value)
                .map(StringValidatorResult::Replace)
                .unwrap_or(StringValidatorResult::Invalid("Invalid email address")),
            Self::EmailLocalPart => sanitize_email_local(value)
                .map(StringValidatorResult::Replace)
                .unwrap_or(StringValidatorResult::Invalid("Invalid email local part")),
            Self::Domain => sanitize_domain(value)
                .map(StringValidatorResult::Replace)
                .unwrap_or(StringValidatorResult::Invalid("Invalid domain name")),
            Self::Hostname => IpAddr::from_str(value)
                .ok()
                .map(|_| StringValidatorResult::Valid)
                .or_else(|| sanitize_domain(value).map(StringValidatorResult::Replace))
                .unwrap_or(StringValidatorResult::Invalid(
                    "Invalid hostname or IP address",
                )),
            Self::RemoveSpaces => {
                if value.chars().any(|c| c.is_whitespace()) {
                    StringValidatorResult::Replace(
                        value.chars().filter(|c| !c.is_whitespace()).collect(),
                    )
                } else {
                    StringValidatorResult::Valid
                }
            }
            Self::Lowercase => StringValidatorResult::Replace(value.to_lowercase()),
            Self::Uppercase => StringValidatorResult::Replace(value.to_uppercase()),
            Self::Trim => {
                let trimmed = value.trim();
                if trimmed.len() != value.len() {
                    if !trimmed.is_empty() {
                        StringValidatorResult::Replace(trimmed.to_string())
                    } else {
                        StringValidatorResult::Invalid("String cannot be empty")
                    }
                } else {
                    StringValidatorResult::Valid
                }
            }
            Self::SecretHash => {
                if !value.is_empty() && value.len() <= 128 {
                    StringValidatorResult::Valid
                } else {
                    StringValidatorResult::Invalid("Secret cannot be empty")
                }
            }
        }
    }
}
