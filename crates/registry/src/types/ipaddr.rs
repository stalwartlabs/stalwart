/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{
        IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, PatchResult, RegistryJsonPatch,
    },
    pickle::{Pickle, PickledStream},
    types::error::PatchError,
};
use std::{fmt::Display, net::Ipv4Addr, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct IpAddr(pub std::net::IpAddr);

impl IpAddr {
    pub fn into_inner(self) -> std::net::IpAddr {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        !matches!(
            self.0,
            std::net::IpAddr::V4(addr) if addr == Ipv4Addr::UNSPECIFIED
        )
    }
}

impl FromStr for IpAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<std::net::IpAddr>()
            .map(IpAddr)
            .map_err(|err| err.to_string())
    }
}

impl Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl serde::Serialize for IpAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for IpAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        IpAddr::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid IpAddr"))
    }
}

impl AsRef<std::net::IpAddr> for IpAddr {
    fn as_ref(&self) -> &std::net::IpAddr {
        &self.0
    }
}

impl Default for IpAddr {
    fn default() -> Self {
        IpAddr(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }
}

impl Pickle for std::net::IpAddr {
    fn pickle(&self, out: &mut Vec<u8>) {
        match self {
            std::net::IpAddr::V4(addr) => {
                out.push(4);
                out.extend_from_slice(&addr.octets());
            }
            std::net::IpAddr::V6(addr) => {
                out.push(6);
                out.extend_from_slice(&addr.octets());
            }
        }
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let kind = data.read()?;
        match kind {
            4 => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(data.read_bytes(4)?);
                Some(std::net::IpAddr::V4(Ipv4Addr::from(arr)))
            }
            6 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(data.read_bytes(16)?);
                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr)))
            }
            _ => None,
        }
    }
}

impl Pickle for IpAddr {
    fn pickle(&self, out: &mut Vec<u8>) {
        self.0.pickle(out);
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        std::net::IpAddr::unpickle(data).map(IpAddr)
    }
}

impl RegistryJsonPatch for IpAddr {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = IpAddr::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(MaybeUnpatched::Patched)
                } else {
                    Err(PatchError::new(
                        pointer,
                        "Failed to parse IpAddr from string",
                    ))
                }
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for IpAddr, expected a string value",
            )),
        }
    }
}

impl IntoValue for IpAddr {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Str(self.to_string().into())
    }
}
