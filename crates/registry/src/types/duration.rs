/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, str::FromStr};
use crate::pickle::{Pickle, PickledStream};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Duration(pub std::time::Duration);

impl Duration {
    pub fn from_millis(millis: u64) -> Self {
        Duration(std::time::Duration::from_millis(millis))
    }

    pub fn into_inner(self) -> std::time::Duration {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.as_millis() > 0
    }
}

impl Default for Duration {
    fn default() -> Self {
        Duration(std::time::Duration::from_millis(0))
    }
}

impl Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_millis())
    }
}

impl serde::Serialize for Duration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <u64>::deserialize(deserializer)
            .map(std::time::Duration::from_millis)
            .map(Duration)
            .map_err(|_| serde::de::Error::custom("invalid Duration"))
    }
}

impl AsRef<std::time::Duration> for Duration {
    fn as_ref(&self) -> &std::time::Duration {
        &self.0
    }
}

impl PartialOrd for Duration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Duration {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl FromStr for Duration {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut digits = String::new();
        let mut multiplier = String::new();

        for ch in value.chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
            } else if !ch.is_ascii_whitespace() {
                multiplier.push(ch.to_ascii_lowercase());
            }
        }

        let multiplier = match multiplier.as_str() {
            "d" => 24 * 60 * 60 * 1000,
            "h" => 60 * 60 * 1000,
            "m" => 60 * 1000,
            "s" => 1000,
            "ms" | "" => 1,
            _ => return Err(format!("Invalid duration value {:?}.", value)),
        };

        digits
            .parse::<u64>()
            .ok()
            .map(|num| std::time::Duration::from_millis(num * multiplier))
            .map(Duration)
            .ok_or_else(|| format!("Invalid duration value {:?}.", value))
    }
}

impl Pickle for Duration {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.0.as_millis() as u64).to_le_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(data.read_bytes(8)?);
        Some(Duration(std::time::Duration::from_millis(
            u64::from_le_bytes(arr),
        )))
    }
}
