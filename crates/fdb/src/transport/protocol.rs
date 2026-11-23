/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::frame::FrameError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolVersion(u64);

impl ProtocolVersion {
    const VERSION_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
    const OBJECT_SERIALIZER_FLAG: u64 = 0x1000_0000_0000_0000;

    pub const fn new(version: u64) -> Self {
        Self(version & Self::VERSION_MASK)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    const fn wire(self) -> u64 {
        self.0 | Self::OBJECT_SERIALIZER_FLAG
    }
}

pub(crate) const CONNECT_PACKET_LEN: usize = 44;
const CONNECT_PACKET_BODY_LEN: u32 = 40;
const CONNECT_PACKET_MIN_BODY_LEN: u32 = 10;
const CONNECT_PACKET_MIN_PREFIX: usize = 14;

pub(crate) fn connect_packet(version: ProtocolVersion) -> [u8; CONNECT_PACKET_LEN] {
    let mut packet = [0u8; CONNECT_PACKET_LEN];
    packet[0..4].copy_from_slice(&CONNECT_PACKET_BODY_LEN.to_le_bytes());
    packet[4..12].copy_from_slice(&version.wire().to_le_bytes());
    packet
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerHello {
    pub(crate) version: ProtocolVersion,
    pub(crate) compatible: bool,
    pub(crate) consumed: usize,
}

pub(crate) fn parse_connect_packet(
    buf: &[u8],
    local: ProtocolVersion,
) -> Result<Option<PeerHello>, FrameError> {
    if buf.len() < CONNECT_PACKET_MIN_PREFIX {
        return Ok(None);
    }
    let Some((len, body)) = buf.split_first_chunk::<4>() else {
        return Ok(None);
    };
    let len = u32::from_le_bytes(*len);
    if !(CONNECT_PACKET_MIN_BODY_LEN..=CONNECT_PACKET_BODY_LEN).contains(&len) {
        return Err(FrameError::ConnectPacket);
    }
    let body_len = len as usize;
    let Some(body) = body.get(..body_len) else {
        return Ok(None);
    };
    let Some(raw) = body.first_chunk::<8>() else {
        return Err(FrameError::ConnectPacket);
    };
    let raw = u64::from_le_bytes(*raw);
    let version = ProtocolVersion::new(raw);
    Ok(Some(PeerHello {
        version,
        compatible: raw & ProtocolVersion::OBJECT_SERIALIZER_FLAG != 0 && version == local,
        consumed: body_len + 4,
    }))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/protocol/tests.rs"]
mod tests;
