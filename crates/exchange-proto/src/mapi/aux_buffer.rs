/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use super::{
    error::BodyError,
    rpc_ext::{self, RpcHeaderExt},
};

pub const AUX_HEADER_LEN: usize = 4;
pub const AUX_VERSION_1: u8 = 0x01;
pub const AUX_VERSION_2: u8 = 0x02;
pub const AUX_MAX_ACTUAL: u16 = 0x8000;

pub mod block_type {
    pub const CLIENT_CONTROL: u8 = 0x0A;
    pub const EXORGINFO: u8 = 0x17;
    pub const SERVER_CAPABILITIES: u8 = 0x46;
    pub const ENDPOINT_CAPABILITIES: u8 = 0x48;
}

pub mod client_control {
    pub const ENABLE_PERF_SENDTOSERVER: u32 = 0x01;
    pub const ENABLE_COMPRESSION: u32 = 0x04;
    pub const ENABLE_HTTP_TUNNELING: u32 = 0x08;
    pub const ENABLE_PERF_SENDGCDATA: u32 = 0x10;
    pub const DEFAULT_EXPIRY_MS: u32 = 604_800_000;
}

pub const ENDPOINT_CAPABILITIES_SINGLE_ENDPOINT: u32 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuxIn<'a>(&'a [u8]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxBlock<'a> {
    pub version: u8,
    pub block_type: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct AuxBlocks<'a> {
    rest: &'a [u8],
    offset: usize,
}

impl<'a> AuxIn<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        AuxIn(bytes)
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn validate(&self, scratch: &mut Vec<u8>) -> Result<(), BodyError> {
        self.blocks(scratch)?
            .try_for_each(|block| block.map(|_| ()))
    }

    pub fn blocks<'s>(&self, scratch: &'s mut Vec<u8>) -> Result<AuxBlocks<'s>, BodyError>
    where
        'a: 's,
    {
        let rest = if self.0.is_empty() {
            self.0
        } else {
            rpc_ext::decode_single_buffer(self.0, scratch, AUX_MAX_ACTUAL)?
        };
        Ok(AuxBlocks { rest, offset: 0 })
    }
}

impl<'a> Iterator for AuxBlocks<'a> {
    type Item = Result<AuxBlock<'a>, BodyError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let block =
            self.rest
                .first_chunk::<AUX_HEADER_LEN>()
                .and_then(|&[s0, s1, version, block_type]| {
                    let size = usize::from(u16::from_le_bytes([s0, s1]));
                    let (block, rest) = self.rest.split_at_checked(size)?;
                    let payload = block.get(AUX_HEADER_LEN..)?;
                    Some((
                        AuxBlock {
                            version,
                            block_type,
                            payload,
                        },
                        rest,
                        size,
                    ))
                });
        match block {
            Some((block, rest, size)) => {
                self.rest = rest;
                self.offset = self.offset.saturating_add(size);
                Some(Ok(block))
            }
            None => {
                self.rest = &[];
                Some(Err(BodyError::BadAuxBlock {
                    offset: u32::try_from(self.offset).unwrap_or(u32::MAX),
                }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuxOut {
    bytes: SmallVec<[u8; 36]>,
}

impl AuxOut {
    pub fn empty() -> Self {
        AuxOut::default()
    }

    pub fn connect_default() -> Self {
        const BLOCKS: [(u8, &[u32]); 3] = [
            (block_type::EXORGINFO, &[0]),
            (
                block_type::CLIENT_CONTROL,
                &[
                    client_control::ENABLE_COMPRESSION | client_control::ENABLE_HTTP_TUNNELING,
                    client_control::DEFAULT_EXPIRY_MS,
                ],
            ),
            (
                block_type::ENDPOINT_CAPABILITIES,
                &[ENDPOINT_CAPABILITIES_SINGLE_ENDPOINT],
            ),
        ];
        let size: u16 = BLOCKS
            .iter()
            .map(|(_, fields)| block_size(fields))
            .fold(0, u16::saturating_add);
        let mut bytes = SmallVec::new();
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&RpcHeaderExt::LAST.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        for (block_type, fields) in BLOCKS {
            bytes.extend_from_slice(&block_size(fields).to_le_bytes());
            bytes.push(AUX_VERSION_1);
            bytes.push(block_type);
            for field in fields {
                bytes.extend_from_slice(&field.to_le_bytes());
            }
        }
        AuxOut { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len_u32(&self) -> u32 {
        u32::try_from(self.bytes.len()).unwrap_or(0)
    }
}

fn block_size(fields: &[u32]) -> u16 {
    u16::try_from(
        fields
            .len()
            .saturating_mul(4)
            .saturating_add(AUX_HEADER_LEN),
    )
    .unwrap_or(u16::MAX)
}

const _: () = assert!(RpcHeaderExt::LEN + 8 + 12 + 8 <= 36);

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/aux_buffer/tests.rs"]
mod tests;
