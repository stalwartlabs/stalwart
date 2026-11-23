/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Archive, ArchiveBytes, ArchiveVersion, Archiver,
    compress::{
        ArchiveCompression, Compression, MAX_ARCHIVE_SIZE, compress, compress_watermark,
        decompress, decompress_into,
    },
};
use crate::{Deserialize, Serialize, SerializeInfallible, U32_LEN, U64_LEN, Value};
use compact_str::format_compact;
use roaring::{RoaringBitmap, RoaringTreemap};

const MAGIC_MARKER: u8 = 1 << 7;
const VERSIONED: u8 = 1 << 6;
const HASHED: u8 = 1 << 5;
const LZ4_COMPRESSED: u8 = 1 << 4;
const ZSTD_COMPRESSED: u8 = 1 << 3;

const SERIALIZE_CAPACITY: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Plain,
    Zstd,
    Lz4,
}

fn split_hash(encoding: Encoding, contents: &[u8]) -> Option<(&[u8], u32)> {
    match encoding {
        Encoding::Zstd => contents
            .get(contents.len().checked_sub(U32_LEN)?..)?
            .try_into()
            .ok()
            .map(|hash| (contents, u32::from_be_bytes(hash))),
        Encoding::Plain | Encoding::Lz4 => contents
            .split_at_checked(contents.len().checked_sub(U32_LEN)?)
            .and_then(|(contents, archive_hash)| {
                let hash = xxhash_rust::xxh3::xxh3_64(contents) as u32;
                (hash.to_be_bytes().as_slice() == archive_hash).then_some((contents, hash))
            }),
    }
}

fn validate_marker_and_contents(bytes: &[u8]) -> Option<(Encoding, &[u8], ArchiveVersion)> {
    let (marker, contents) = bytes
        .split_last()
        .filter(|(marker, _)| (**marker & MAGIC_MARKER) != 0)?;
    let encoding = if marker & ZSTD_COMPRESSED != 0 {
        Encoding::Zstd
    } else if marker & LZ4_COMPRESSED != 0 {
        Encoding::Lz4
    } else {
        Encoding::Plain
    };

    if marker & VERSIONED != 0 {
        let (contents, change_id) = contents
            .split_at_checked(contents.len().checked_sub(U64_LEN)?)
            .and_then(|(contents, change_id)| {
                change_id
                    .try_into()
                    .ok()
                    .map(|change_id| (contents, u64::from_be_bytes(change_id)))
            })?;
        split_hash(encoding, contents).map(|(contents, hash)| {
            (
                encoding,
                contents,
                ArchiveVersion::Versioned { change_id, hash },
            )
        })
    } else if marker & HASHED != 0 {
        split_hash(encoding, contents)
            .map(|(contents, hash)| (encoding, contents, ArchiveVersion::Hashed { hash }))
    } else {
        Some((encoding, contents, ArchiveVersion::Unversioned))
    }
}

impl Deserialize for Archive<ArchiveBytes> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let (encoding, contents, version) =
            validate_marker_and_contents(bytes).ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
            })?;

        match encoding {
            Encoding::Plain => Ok(Archive {
                version,
                inner: contents.to_vec(),
            }),
            Encoding::Zstd => zstd_inflate(contents).map(|inner| Archive { version, inner }),
            Encoding::Lz4 => lz4_deflate(contents).map(|inner| Archive { version, inner }),
        }
    }

    fn deserialize_owned(mut bytes: Vec<u8>) -> trc::Result<Self> {
        let (encoding, contents, version) =
            validate_marker_and_contents(&bytes).ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes.as_slice())
                    .caused_by(trc::location!())
            })?;

        match encoding {
            Encoding::Plain => {
                let contents_len = contents.len();
                bytes.truncate(contents_len);
                Ok(Archive {
                    version,
                    inner: bytes,
                })
            }
            Encoding::Zstd => zstd_inflate(contents).map(|inner| Archive { version, inner }),
            Encoding::Lz4 => lz4_deflate(contents).map(|inner| Archive { version, inner }),
        }
    }
}

impl Archive<ArchiveBytes> {
    pub fn deserialize_with_prefix(prefix: &[u8], bytes: &[u8]) -> trc::Result<Self> {
        let (encoding, contents, version) =
            validate_marker_and_contents(bytes).ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
            })?;

        let inner = match encoding {
            Encoding::Plain => [prefix, contents].concat(),
            Encoding::Zstd => [prefix, zstd_inflate(contents)?.as_slice()].concat(),
            Encoding::Lz4 => [prefix, lz4_deflate(contents)?.as_slice()].concat(),
        };

        Ok(Archive { version, inner })
    }
}

impl Archive<ArchiveBytes> {
    pub fn serialize_raw(mut contents: Vec<u8>, compress_watermark: usize) -> trc::Result<Vec<u8>> {
        let flags = MAGIC_MARKER | HASHED;
        if contents.len() >= compress_watermark {
            let mut compressed = compress(None, &contents, 1).map_err(|err| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .reason(err)
            })?;
            if compressed.len() < contents.len() {
                compressed.push(flags | ZSTD_COMPRESSED);
                return Ok(compressed);
            }
        }

        let hash = xxhash_rust::xxh3::xxh3_64(&contents) as u32;
        contents.reserve_exact(U32_LEN + 1);
        contents.extend_from_slice(&hash.to_be_bytes());
        contents.push(flags);
        Ok(contents)
    }

    pub fn deserialize_raw<'x>(bytes: &'x [u8], scratch: &'x mut Vec<u8>) -> trc::Result<&'x [u8]> {
        let (encoding, contents, version) =
            validate_marker_and_contents(bytes).ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Archive integrity compromised")
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
            })?;
        if version == ArchiveVersion::Unversioned {
            return Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details("Raw archive carries no integrity hash")
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!()));
        }

        match encoding {
            Encoding::Plain => Ok(contents),
            Encoding::Zstd => {
                decompress_into(contents, scratch, MAX_ARCHIVE_SIZE).map_err(|err| {
                    trc::StoreEvent::DecompressError
                        .ctx(trc::Key::Value, contents)
                        .caused_by(trc::location!())
                        .reason(err)
                })?;
                Ok(scratch.as_slice())
            }
            Encoding::Lz4 => {
                *scratch = lz4_deflate(contents)?;
                Ok(scratch.as_slice())
            }
        }
    }
}

#[inline]
fn zstd_inflate(archive: &[u8]) -> trc::Result<ArchiveBytes> {
    decompress(archive).map_err(|err| {
        trc::StoreEvent::DecompressError
            .ctx(trc::Key::Value, archive)
            .caused_by(trc::location!())
            .reason(err)
    })
}

#[inline]
fn lz4_deflate(archive: &[u8]) -> trc::Result<ArchiveBytes> {
    lz4_flex::block::decompress_size_prepended(archive).map_err(|err| {
        trc::StoreEvent::DecompressError
            .ctx(trc::Key::Value, archive)
            .caused_by(trc::location!())
            .reason(err)
    })
}

impl<T> Serialize for Archiver<T>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                Vec<u8>,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let version_offset = ((self.flags & VERSIONED != 0) as usize) * U64_LEN;
        let trailer_len = U32_LEN + version_offset + 1;
        let bytes = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(
            &self.inner,
            Vec::with_capacity(
                (std::mem::size_of::<T::Archived>() + trailer_len).max(SERIALIZE_CAPACITY),
            ),
        )
        .map_err(|err| {
            trc::StoreEvent::DeserializeError
                .caused_by(trc::location!())
                .reason(err)
        })?;

        if let Compression::Zstd(dictionary) = self.compression
            && bytes.len() >= compress_watermark(dictionary)
        {
            let mut compressed =
                compress(dictionary, &bytes, version_offset + 1).map_err(|err| {
                    trc::StoreEvent::UnexpectedError
                        .caused_by(trc::location!())
                        .reason(err)
                })?;

            if compressed.len() < bytes.len() {
                if version_offset != 0 {
                    compressed.extend_from_slice(0u64.to_be_bytes().as_slice());
                }
                compressed.push(self.flags | ZSTD_COMPRESSED);
                return Ok(compressed);
            }
        }

        let mut bytes = bytes;
        bytes.reserve_exact(trailer_len);
        if self.flags & HASHED != 0 {
            let hash = (xxhash_rust::xxh3::xxh3_64(&bytes) as u32).to_be_bytes();
            bytes.extend_from_slice(&hash);
        }
        if version_offset != 0 {
            bytes.extend_from_slice(0u64.to_be_bytes().as_slice());
        }
        bytes.push(self.flags);

        Ok(bytes)
    }
}

impl Archive<ArchiveBytes> {
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    pub fn unarchive<T>(&self) -> trc::Result<&<T as rkyv::Archive>::Archived>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        const { assert!(std::mem::align_of::<T::Archived>() == 1) };

        let bytes = self.as_bytes();
        if self.version != ArchiveVersion::Unversioned {
            if bytes.len() >= std::mem::size_of::<T::Archived>() {
                // SAFETY: Trusted input with integrity hash
                Ok(unsafe { rkyv::access_unchecked::<T::Archived>(bytes) })
            } else {
                Err(trc::StoreEvent::DataCorruption
                    .into_err()
                    .details(format_compact!(
                        "Archive size mismatch, expected {} bytes but got {} bytes.",
                        std::mem::size_of::<T::Archived>(),
                        bytes.len()
                    ))
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!()))
            }
        } else {
            rkyv::access::<T::Archived, rkyv::rancor::Error>(bytes).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(trc::Key::Value, self.as_bytes())
                    .details("Archive access failed")
                    .caused_by(trc::location!())
                    .reason(err)
            })
        }
    }

    pub fn unarchive_untrusted<T>(&self) -> trc::Result<&<T as rkyv::Archive>::Archived>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        const { assert!(std::mem::align_of::<T::Archived>() == 1) };

        let bytes = self.as_bytes();
        if bytes.len() >= std::mem::size_of::<T::Archived>() {
            rkyv::access::<T::Archived, rkyv::rancor::Error>(bytes).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(trc::Key::Value, self.as_bytes())
                    .details("Archive access failed")
                    .caused_by(trc::location!())
                    .reason(err)
            })
        } else {
            Err(trc::StoreEvent::DataCorruption
                .into_err()
                .details(format_compact!(
                    "Archive size mismatch, expected {} bytes but got {} bytes.",
                    std::mem::size_of::<T::Archived>(),
                    bytes.len()
                ))
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!()))
        }
    }

    pub fn deserialize<T>(&self) -> trc::Result<T>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.unarchive::<T>().and_then(|input| {
            rkyv::deserialize(input).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(trc::Key::Value, self.as_bytes())
                    .caused_by(trc::location!())
                    .reason(err)
            })
        })
    }

    pub fn deserialize_untrusted<T>(&self) -> trc::Result<T>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.unarchive_untrusted::<T>().and_then(|input| {
            rkyv::deserialize(input).map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .ctx(trc::Key::Value, self.as_bytes())
                    .caused_by(trc::location!())
                    .reason(err)
            })
        })
    }

    pub fn to_unarchived<T>(&self) -> trc::Result<Archive<&<T as rkyv::Archive>::Archived>>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.unarchive::<T>().map(|inner| Archive {
            version: self.version,
            inner,
        })
    }

    pub fn into_deserialized<T>(&self) -> trc::Result<Archive<T>>
    where
        T: rkyv::Archive,
        T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
                rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
            > + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        self.deserialize::<T>().map(|inner| Archive {
            version: self.version,
            inner,
        })
    }

    pub fn extract_hash(bytes: &[u8]) -> Option<u32> {
        let marker = *bytes.last()?;
        if marker & VERSIONED != 0 {
            bytes
                .get(bytes.len() - U32_LEN - U64_LEN - 1..bytes.len() - U64_LEN - 1)
                .and_then(|slice| slice.try_into().ok().map(u32::from_be_bytes))
        } else if marker & HASHED != 0 {
            bytes
                .get(bytes.len() - U32_LEN - 1..bytes.len() - 1)
                .and_then(|slice| slice.try_into().ok().map(u32::from_be_bytes))
        } else {
            None
        }
    }

    fn hash_offset(bytes: &[u8]) -> Option<usize> {
        let marker = *bytes.last()?;
        if marker & VERSIONED != 0 {
            bytes.len().checked_sub(U32_LEN + U64_LEN + 1)
        } else if marker & HASHED != 0 {
            bytes.len().checked_sub(U32_LEN + 1)
        } else {
            None
        }
    }

    #[cfg(feature = "exchange")]
    pub fn restamp_change_id(bytes: &mut [u8], change_id: u64) -> bool {
        match bytes.split_last_mut() {
            Some((marker, contents))
                if *marker & (MAGIC_MARKER | VERSIONED) == MAGIC_MARKER | VERSIONED =>
            {
                match contents.last_chunk_mut::<U64_LEN>() {
                    Some(stamp) => {
                        *stamp = change_id.to_be_bytes();
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        }
    }

    pub fn restamp_hash(bytes: &mut [u8]) {
        debug_assert!(
            bytes
                .last()
                .is_none_or(|marker| marker & (ZSTD_COMPRESSED | LZ4_COMPRESSED) == 0),
            "a compressed archive cannot be rehashed"
        );

        if let Some(offset) = Self::hash_offset(bytes) {
            let hash = (xxhash_rust::xxh3::xxh3_64(&bytes[..offset]) as u32).to_be_bytes();
            bytes[offset..offset + U32_LEN].copy_from_slice(&hash);
        }
    }
}

impl<T> Archiver<T>
where
    T: ArchiveCompression
        + rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                Vec<u8>,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    pub fn new(inner: T) -> Self {
        Self::with_compression(inner, T::COMPRESSION)
    }
}

impl<T> Archiver<T>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                Vec<u8>,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    pub fn with_compression(inner: T, compression: Compression) -> Self {
        Self {
            inner,
            flags: MAGIC_MARKER | HASHED,
            compression,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn with_version(self) -> Self {
        Self {
            inner: self.inner,
            flags: self.flags | VERSIONED,
            compression: self.compression,
        }
    }

    pub fn untrusted(self) -> Self {
        Self {
            inner: self.inner,
            flags: MAGIC_MARKER,
            compression: self.compression,
        }
    }

    pub fn serialize_versioned(self) -> trc::Result<(u64, Vec<u8>)> {
        self.with_version()
            .serialize()
            .map(|bytes| ((bytes.len() - U64_LEN - 1) as u64, bytes))
    }

    pub fn serialize_patchable(self) -> trc::Result<(u32, Vec<u8>)> {
        let flags = self.flags;

        Self {
            inner: self.inner,
            flags,
            compression: Compression::None,
        }
        .serialize()
        .map(|bytes| {
            let payload_len = bytes.len()
                - 1
                - ((flags & HASHED != 0) as usize) * U32_LEN
                - ((flags & VERSIONED != 0) as usize) * U64_LEN;

            (payload_len as u32, bytes)
        })
    }
}

impl<T> Archive<&T>
where
    T: rkyv::Portable
        + for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + Sync
        + Send,
{
    pub fn to_deserialized<V>(&self) -> trc::Result<Archive<V>>
    where
        T: rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        rkyv::deserialize::<V, rkyv::rancor::Error>(self.inner)
            .map_err(|err| {
                trc::StoreEvent::DeserializeError
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .map(|inner| Archive {
                version: self.version,
                inner,
            })
    }

    pub fn deserialize<V>(&self) -> trc::Result<V>
    where
        T: rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
    {
        rkyv::deserialize::<V, rkyv::rancor::Error>(self.inner).map_err(|err| {
            trc::StoreEvent::DeserializeError
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

#[inline]
pub fn rkyv_deserialize<T, V>(input: &T) -> trc::Result<V>
where
    T: rkyv::Portable
        + for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + Sync
        + Send
        + rkyv::Deserialize<V, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    rkyv::deserialize::<V, rkyv::rancor::Error>(input).map_err(|err| {
        trc::StoreEvent::DeserializeError
            .caused_by(trc::location!())
            .reason(err)
    })
}

pub fn rkyv_unarchive<T>(input: &[u8]) -> trc::Result<&<T as rkyv::Archive>::Archived>
where
    T: rkyv::Archive,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    const { assert!(std::mem::align_of::<T::Archived>() == 1) };

    rkyv::access::<T::Archived, rkyv::rancor::Error>(input).map_err(|err| {
        trc::StoreEvent::DataCorruption
            .caused_by(trc::location!())
            .ctx(trc::Key::Value, input)
            .reason(err)
    })
}

pub struct RawValue(pub Vec<u8>);

impl Deserialize for RawValue {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(RawValue(bytes.to_vec()))
    }
}

impl SerializeInfallible for u32 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for u64 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for i64 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for u16 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for f64 {
    fn serialize(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl SerializeInfallible for &str {
    fn serialize(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Deserialize for String {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    fn deserialize_owned(bytes: Vec<u8>) -> trc::Result<Self> {
        Ok(String::from_utf8(bytes)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()))
    }
}

impl Deserialize for u64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl Deserialize for i64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(i64::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl Deserialize for u32 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl<T> From<Value<'static>> for Archive<T> {
    fn from(_: Value<'static>) -> Self {
        unimplemented!()
    }
}

impl Default for Archive<ArchiveBytes> {
    fn default() -> Self {
        Archive {
            version: ArchiveVersion::Unversioned,
            inner: Vec::new(),
        }
    }
}

impl Serialize for RoaringBitmap {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.serialized_size());
        self.serialize_into(&mut bytes)
            .map_err(|err| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .map(|_| bytes)
    }
}

impl Deserialize for RoaringBitmap {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        RoaringBitmap::deserialize_from(bytes).map_err(|err| {
            trc::StoreEvent::DeserializeError
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

impl Serialize for RoaringTreemap {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.serialized_size());
        self.serialize_into(&mut bytes)
            .map_err(|err| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .map(|_| bytes)
    }
}

impl Deserialize for RoaringTreemap {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        RoaringTreemap::deserialize_from(bytes).map_err(|err| {
            trc::StoreEvent::DeserializeError
                .caused_by(trc::location!())
                .reason(err)
        })
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/write/serialize/tests.rs"]
mod tests;
