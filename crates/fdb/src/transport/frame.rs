/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::error::TransportError;
use crate::codec::Uid;
use bytes::{Buf, Bytes, BytesMut};
use xxhash_rust::xxh3::xxh3_64;

pub(crate) const PACKET_LIMIT: usize = 100 << 20;
const LEN_WIDTH: usize = 4;
const CHECKSUM_WIDTH: usize = 8;
const MAX_HEADER: [u8; LEN_WIDTH + CHECKSUM_WIDTH] = [0; LEN_WIDTH + CHECKSUM_WIDTH];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameError {
    TooLarge,
    TooSmall,
    Checksum,
    ConnectPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    Checksum,
    Tls,
}

impl Framing {
    pub(crate) const fn for_address(tls: bool) -> Self {
        if tls { Self::Tls } else { Self::Checksum }
    }

    pub(crate) const fn header_len(self) -> usize {
        match self {
            Self::Checksum => LEN_WIDTH + CHECKSUM_WIDTH,
            Self::Tls => LEN_WIDTH,
        }
    }
}

pub(crate) struct FrameGuard<'a> {
    buf: &'a mut Vec<u8>,
    start: usize,
    framing: Framing,
    finished: bool,
}

impl<'a> FrameGuard<'a> {
    pub(crate) fn begin(buf: &'a mut Vec<u8>, framing: Framing, dest: Uid) -> Self {
        let start = buf.len();
        buf.extend_from_slice(&MAX_HEADER[..framing.header_len()]);
        buf.extend_from_slice(&dest.to_le_bytes());
        Self {
            buf,
            start,
            framing,
            finished: false,
        }
    }

    pub(crate) fn buf(&mut self) -> &mut Vec<u8> {
        self.buf
    }

    pub(crate) fn finish(mut self) -> Result<usize, TransportError> {
        let header_len = self.framing.header_len();
        let Some((header, payload)) = self
            .buf
            .get_mut(self.start..)
            .and_then(|frame| frame.split_at_mut_checked(header_len))
        else {
            return Err(TransportError::PacketTooLarge);
        };
        let len = payload.len();
        if len > PACKET_LIMIT {
            return Err(TransportError::PacketTooLarge);
        }
        if len <= Uid::LEN {
            return Err(TransportError::EmptyMessage);
        }
        let len_bytes = (len as u32).to_le_bytes();
        match self.framing {
            Framing::Checksum => {
                let checksum = xxh3_64(payload).to_le_bytes();
                let (len_field, checksum_field) = header.split_at_mut(LEN_WIDTH);
                len_field.copy_from_slice(&len_bytes);
                checksum_field.copy_from_slice(&checksum);
            }
            Framing::Tls => header.copy_from_slice(&len_bytes),
        }
        self.finished = true;
        Ok(self.start + header_len + Uid::LEN)
    }
}

impl Drop for FrameGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.buf.truncate(self.start);
        }
    }
}

pub(crate) struct Frame {
    pub(crate) token: Uid,
    pub(crate) message: Bytes,
}

struct Header {
    payload_len: usize,
    checksum: Option<u64>,
}

fn parse_header(buf: &[u8], framing: Framing) -> Result<Option<Header>, FrameError> {
    let Some((len, rest)) = buf.split_first_chunk::<LEN_WIDTH>() else {
        return Ok(None);
    };
    let payload_len = u32::from_le_bytes(*len) as usize;
    if payload_len > PACKET_LIMIT {
        return Err(FrameError::TooLarge);
    }
    let checksum = match framing {
        Framing::Checksum => match rest.first_chunk::<CHECKSUM_WIDTH>() {
            Some(checksum) => Some(u64::from_le_bytes(*checksum)),
            None => return Ok(None),
        },
        Framing::Tls => None,
    };
    if payload_len < Uid::LEN {
        return Err(FrameError::TooSmall);
    }
    Ok(Some(Header {
        payload_len,
        checksum,
    }))
}

pub(crate) fn next_frame(
    buf: &mut BytesMut,
    framing: Framing,
) -> Result<Option<Frame>, FrameError> {
    let Some(header) = parse_header(buf, framing)? else {
        return Ok(None);
    };
    let header_len = framing.header_len();
    let Some(payload) = buf.get(header_len..header_len + header.payload_len) else {
        return Ok(None);
    };
    if let Some(expected) = header.checksum
        && xxh3_64(payload) != expected
    {
        return Err(FrameError::Checksum);
    }
    let Some(token) = payload.first_chunk::<{ Uid::LEN }>() else {
        return Err(FrameError::TooSmall);
    };
    let token = Uid::from_le_bytes(*token);
    buf.advance(header_len + Uid::LEN);
    let message = buf.split_to(header.payload_len - Uid::LEN).freeze();
    Ok(Some(Frame { token, message }))
}

pub(crate) fn pending_frame_len(buf: &[u8], framing: Framing) -> Option<usize> {
    parse_header(buf, framing)
        .ok()
        .flatten()
        .map(|header| framing.header_len() + header.payload_len)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/frame/tests.rs"]
mod tests;
