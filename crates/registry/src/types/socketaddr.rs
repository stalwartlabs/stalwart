/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, str::FromStr};

use crate::{
    jmap::{IntoValue, JmapValue, JsonPointerPatch, RegistryJsonPatch},
    pickle::{Pickle, PickledStream},
    types::error::PatchError,
};

#[derive(Debug, Clone, PartialEq)]
pub struct SocketAddr(pub std::net::SocketAddr);

impl SocketAddr {
    pub fn into_inner(self) -> std::net::SocketAddr {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        !self.0.ip().is_unspecified()
    }
}

impl FromStr for SocketAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<std::net::SocketAddr>()
            .map(SocketAddr)
            .map_err(|err| err.to_string())
    }
}

impl Display for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl serde::Serialize for SocketAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SocketAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        SocketAddr::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid SocketAddr"))
    }
}

impl Default for SocketAddr {
    fn default() -> Self {
        SocketAddr(std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

impl AsRef<std::net::SocketAddr> for SocketAddr {
    fn as_ref(&self) -> &std::net::SocketAddr {
        &self.0
    }
}

impl Pickle for SocketAddr {
    fn pickle(&self, out: &mut Vec<u8>) {
        self.0.ip().pickle(out);
        self.0.port().pickle(out);
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let ip = std::net::IpAddr::unpickle(data)?;
        let port = u16::unpickle(data)?;
        Some(SocketAddr(std::net::SocketAddr::new(ip, port)))
    }
}

impl RegistryJsonPatch for SocketAddr {
    fn patch(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'_>,
    ) -> Result<(), PatchError> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = SocketAddr::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(())
                } else {
                    Err(PatchError::new(
                        pointer,
                        "Failed to parse SocketAddr from string",
                    ))
                }
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for SocketAddr, expected a string value",
            )),
        }
    }
}

impl IntoValue for SocketAddr {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.to_string().into())
    }
}
