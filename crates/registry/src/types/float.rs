/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{IntoValue, JmapValue, JsonPointerPatch, PatchResult, RegistryJsonPatch},
    pickle::{Pickle, PickledStream},
    types::error::PatchError,
};
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct Float(f64);

impl Eq for Float {}

impl PartialOrd for Float {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Float {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap_or_else(|| {
            if self.0.is_nan() && other.0.is_nan() {
                std::cmp::Ordering::Equal
            } else if self.0.is_nan() {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        })
    }
}

impl Float {
    pub fn new(value: f64) -> Self {
        Float(value)
    }

    pub fn into_inner(self) -> f64 {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        !self.0.is_nan() && self.0.is_finite()
    }
}

impl FromStr for Float {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<f64>().map(Float).map_err(|err| err.to_string())
    }
}

impl Display for Float {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl serde::Serialize for Float {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Float {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        f64::deserialize(deserializer)
            .map(Float::new)
            .map_err(|_| serde::de::Error::custom("invalid Float"))
    }
}

impl AsRef<f64> for Float {
    fn as_ref(&self) -> &f64 {
        &self.0
    }
}

impl Default for Float {
    fn default() -> Self {
        Float(f64::NAN)
    }
}

impl From<f64> for Float {
    fn from(value: f64) -> Self {
        Float(value)
    }
}

impl Pickle for Float {
    fn pickle(&self, out: &mut Vec<u8>) {
        self.0.to_bits().pickle(out);
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        u64::unpickle(data).map(|bits| Float(f64::from_bits(bits)))
    }
}

impl RegistryJsonPatch for Float {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Some(new_value) = value.as_f64().filter(|v| v.is_finite() && !v.is_nan()) {
            *self = Float(new_value);
            pointer.assert_eof()
        } else {
            Err(PatchError::new(
                pointer,
                "Invalid value for float property (expected finite number)",
            ))
        }
    }
}

impl IntoValue for Float {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Number(self.0.into())
    }
}
