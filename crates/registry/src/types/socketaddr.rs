/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, str::FromStr};

use crate::pickle::{Pickle, PickledStream};

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
        out.extend_from_slice(&self.0.port().to_le_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let ip = std::net::IpAddr::unpickle(data)?;
        let mut port_bytes = [0u8; 2];
        port_bytes.copy_from_slice(data.read_bytes(2)?);
        let port = u16::from_le_bytes(port_bytes);
        Some(SocketAddr(std::net::SocketAddr::new(ip, port)))
    }
}
