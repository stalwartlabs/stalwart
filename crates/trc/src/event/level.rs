/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Level;
use std::{cmp::Ordering, fmt::Display, str::FromStr};

impl PartialOrd for Level {
    #[inline(always)]
    fn partial_cmp(&self, other: &Level) -> Option<Ordering> {
        Some(self.cmp(other))
    }

    #[inline(always)]
    fn lt(&self, other: &Level) -> bool {
        (*other as usize) < (*self as usize)
    }

    #[inline(always)]
    fn le(&self, other: &Level) -> bool {
        (*other as usize) <= (*self as usize)
    }

    #[inline(always)]
    fn gt(&self, other: &Level) -> bool {
        (*other as usize) > (*self as usize)
    }

    #[inline(always)]
    fn ge(&self, other: &Level) -> bool {
        (*other as usize) >= (*self as usize)
    }
}

impl Ord for Level {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        (*other as usize).cmp(&(*self as usize))
    }
}

impl FromStr for Level {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "disable" => Ok(Self::Disable),
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(s.to_string()),
        }
    }
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disable => "DISABLE",
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    pub fn is_contained(&self, other: Self) -> bool {
        *self >= other && other != Level::Disable && *self != Level::Disable
    }
}

impl Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}
