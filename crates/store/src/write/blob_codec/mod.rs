/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod key;

use crate::{
    U32_LEN,
    write::compress::{compress, decompress_into},
};
use key::{KEY_ID_LEN, SALT_LEN, TAG_LEN};
use registry::schema::enums::CompressionAlgo;
use std::sync::Arc;

pub use key::{BLOB_KEY_LEN, BlobKey, BlobKeyError, BlobKeyring};

pub(crate) const PLAIN_MARKER: u8 = 0x00;
const MAGIC: u8 = 0xa0;
const MAGIC_MASK: u8 = 0xe0;
const ENCRYPTED: u8 = 0x10;
const COMPRESSION_MASK: u8 = 0x0f;
const COMPRESSION_NONE: u8 = 0x00;
const COMPRESSION_LZ4: u8 = 0x01;
const COMPRESSION_ZSTD: u8 = 0x02;
const ENCRYPTED_TRAILER_LEN: usize = TAG_LEN + SALT_LEN + KEY_ID_LEN + 1;
const MAX_BLOB_SIZE: usize = u32::MAX as usize;

#[derive(Clone, Default)]
pub enum BlobEncryption {
    #[default]
    None,
    Key(Arc<BlobKey>),
    Unavailable(u32),
}

#[derive(Clone)]
pub struct BlobOpts {
    pub compression: CompressionAlgo,
    pub encryption: BlobEncryption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobFormat {
    pub compression: CompressionAlgo,
    pub key_id: Option<u32>,
}

impl BlobOpts {
    pub const PLAIN: BlobOpts = BlobOpts {
        compression: CompressionAlgo::None,
        encryption: BlobEncryption::None,
    };

    pub fn new(compression: CompressionAlgo, encryption: BlobEncryption) -> Self {
        BlobOpts {
            compression,
            encryption,
        }
    }

    pub fn compressed(compression: CompressionAlgo) -> Self {
        BlobOpts {
            compression,
            encryption: BlobEncryption::None,
        }
    }

    pub fn encode(&self, storage_key: &[u8], data: &[u8]) -> trc::Result<Vec<u8>> {
        let key = match &self.encryption {
            BlobEncryption::None => None,
            BlobEncryption::Key(key) => Some(key.as_ref()),
            BlobEncryption::Unavailable(id) => {
                return Err(BlobKeyring::unavailable_key(*id, storage_key));
            }
        };
        let trailer_len = if key.is_some() {
            ENCRYPTED_TRAILER_LEN
        } else {
            1
        };
        let (mut buf, compression) = self.compress_payload(data, trailer_len);

        match key {
            Some(key) => key.seal(&mut buf, storage_key, MAGIC | ENCRYPTED | compression)?,
            None if compression == COMPRESSION_NONE => buf.push(PLAIN_MARKER),
            None => buf.push(MAGIC | compression),
        }

        Ok(buf)
    }

    fn compress_payload(&self, data: &[u8], trailer_len: usize) -> (Vec<u8>, u8) {
        match self.compression {
            CompressionAlgo::Lz4 => {
                let max_len = lz4_flex::block::get_maximum_output_size(data.len()) + U32_LEN;
                let mut buf = vec![0u8; max_len];
                buf.reserve_exact(trailer_len);
                let (prefix, body) = buf.split_at_mut(U32_LEN);
                if let Ok(len) = u32::try_from(data.len())
                    && let Ok(compressed_len) = lz4_flex::compress_into(data, body)
                    && compressed_len + U32_LEN < data.len()
                {
                    prefix.copy_from_slice(&len.to_le_bytes());
                    buf.truncate(compressed_len + U32_LEN);
                    return (buf, COMPRESSION_LZ4);
                }
            }
            CompressionAlgo::Zstd => {
                if let Ok(buf) = compress(None, data, trailer_len)
                    && buf.len() < data.len()
                {
                    return (buf, COMPRESSION_ZSTD);
                }
            }
            CompressionAlgo::None => {}
        }

        let mut buf = Vec::with_capacity(data.len() + trailer_len);
        buf.extend_from_slice(data);
        (buf, COMPRESSION_NONE)
    }
}

impl BlobFormat {
    pub fn of(data: &[u8]) -> Option<BlobFormat> {
        let (&flags, rest) = data.split_last()?;
        if flags == PLAIN_MARKER {
            return Some(BlobFormat {
                compression: CompressionAlgo::None,
                key_id: None,
            });
        }
        let compression = BlobFormat::compression_bits(flags)?;
        let key_id = if flags & ENCRYPTED != 0 {
            let (_, [a, b, c, d]) = rest.split_last_chunk::<KEY_ID_LEN>()?;
            Some(u32::from_le_bytes([*a, *b, *c, *d]))
        } else {
            None
        };
        Some(BlobFormat {
            compression: match compression {
                COMPRESSION_LZ4 => CompressionAlgo::Lz4,
                COMPRESSION_ZSTD => CompressionAlgo::Zstd,
                _ => CompressionAlgo::None,
            },
            key_id,
        })
    }

    fn compression_bits(flags: u8) -> Option<u8> {
        let compression = flags & COMPRESSION_MASK;
        (flags & MAGIC_MASK == MAGIC && compression <= COMPRESSION_ZSTD).then_some(compression)
    }
}

impl BlobKeyring {
    pub fn decode(&self, storage_key: &[u8], mut data: Vec<u8>) -> trc::Result<Vec<u8>> {
        let Some(&flags) = data.last() else {
            return Ok(data);
        };
        if flags == PLAIN_MARKER {
            data.pop();
            return Ok(data);
        }
        let Some(compression) = BlobFormat::compression_bits(flags) else {
            trc::event!(Store(trc::StoreEvent::BlobMissingMarker), Key = storage_key);
            return Ok(data);
        };

        if flags & ENCRYPTED != 0 {
            self.decrypt(storage_key, &mut data, flags)?;
        } else {
            data.pop();
        }

        match compression {
            COMPRESSION_LZ4 => lz4_flex::decompress_size_prepended(&data)
                .map_err(|err| BlobKeyring::decompress_error(storage_key, err)),
            COMPRESSION_ZSTD => {
                let mut out = Vec::new();
                decompress_into(&data, &mut out, MAX_BLOB_SIZE)
                    .map(|_| out)
                    .map_err(|err| BlobKeyring::decompress_error(storage_key, err))
            }
            _ => Ok(data),
        }
    }

    fn decrypt(&self, storage_key: &[u8], data: &mut Vec<u8>, flags: u8) -> trc::Result<()> {
        let body_len = data
            .len()
            .checked_sub(ENCRYPTED_TRAILER_LEN)
            .ok_or_else(|| BlobKeyring::truncated(storage_key))?;
        let (body, trailer) = data.split_at_mut(body_len);
        let (tag, trailer) = trailer
            .split_first_chunk::<TAG_LEN>()
            .ok_or_else(|| BlobKeyring::truncated(storage_key))?;
        let (salt, trailer) = trailer
            .split_first_chunk::<SALT_LEN>()
            .ok_or_else(|| BlobKeyring::truncated(storage_key))?;
        let Some(([a, b, c, d], _)) = trailer.split_first_chunk::<KEY_ID_LEN>() else {
            return Err(BlobKeyring::truncated(storage_key));
        };
        let key_id = u32::from_le_bytes([*a, *b, *c, *d]);
        let key = self
            .get(key_id)
            .ok_or_else(|| BlobKeyring::unavailable_key(key_id, storage_key))?;
        key.open(body, tag, salt, storage_key, flags)?;
        data.truncate(body_len);
        Ok(())
    }

    #[cold]
    fn unavailable_key(key_id: u32, storage_key: &[u8]) -> trc::Error {
        trc::StoreEvent::DecryptError
            .into_err()
            .ctx(trc::Key::Id, key_id)
            .ctx(trc::Key::Key, storage_key)
            .details("Encryption key not available")
    }

    #[cold]
    fn truncated(storage_key: &[u8]) -> trc::Error {
        trc::StoreEvent::DecryptError
            .into_err()
            .ctx(trc::Key::Key, storage_key)
            .details("Truncated encrypted blob")
    }

    #[cold]
    fn decompress_error(storage_key: &[u8], err: impl std::fmt::Display) -> trc::Error {
        trc::StoreEvent::DecompressError
            .reason(err)
            .ctx(trc::Key::Key, storage_key)
            .caused_by(trc::location!())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/write/blob_codec/tests.rs"]
mod tests;
