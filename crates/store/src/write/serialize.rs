/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Archive, ArchiveBytes, ArchiveVersion, Archiver,
    compress::{ArchiveCompression, Compression, compress, compress_watermark, decompress},
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write::{
        Compression, Dictionary,
        assert::{AssertValue, ToAssertValue},
        compress::{COMPRESS_WATERMARK, COMPRESS_WATERMARK_DICTIONARY},
    };

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, PartialEq, Eq)]
    struct Compressible {
        headers: String,
        parts: Vec<u32>,
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, PartialEq, Eq)]
    struct Tiny {
        value: u32,
    }

    impl ArchiveCompression for Compressible {
        const COMPRESSION: Compression = Compression::Zstd(Some(Dictionary::Email));
    }

    impl ArchiveCompression for Tiny {
        const COMPRESSION: Compression = Compression::None;
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, PartialEq, Eq)]
    struct Undictionaried {
        headers: String,
    }

    impl ArchiveCompression for Undictionaried {
        const COMPRESSION: Compression = Compression::Zstd(None);
    }

    fn sample(repeats: usize) -> Compressible {
        Compressible {
            headers: "Content-Type: text/plain; charset=utf-8\r\nSubject: hello\r\n"
                .repeat(repeats),
            parts: (0..repeats as u32).collect(),
        }
    }

    #[test]
    fn compressed_round_trip() {
        let value = sample(64);
        let bytes = Archiver::new(value).serialize().expect("serialize");

        assert_ne!(bytes[bytes.len() - 1] & ZSTD_COMPRESSED, 0);
        assert_ne!(bytes[bytes.len() - 1] & HASHED, 0);

        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes).expect("read");
        assert_eq!(
            archive.deserialize::<Compressible>().expect("unarchive"),
            sample(64)
        );

        let hash = Archive::<ArchiveBytes>::extract_hash(&bytes).expect("hash");
        assert_eq!(archive.version, ArchiveVersion::Hashed { hash });
        assert!(archive.to_assert_value().matches(&bytes));
    }

    #[test]
    fn compression_shrinks_the_value() {
        let value = sample(64);
        let compressed = Archiver::new(value).serialize().expect("serialize");
        let plain = Archiver::with_compression(sample(64), Compression::None)
            .serialize()
            .expect("serialize");

        assert!(
            compressed.len() * 3 < plain.len(),
            "{} vs {}",
            compressed.len(),
            plain.len()
        );
    }

    #[test]
    fn values_below_the_watermark_are_stored_verbatim() {
        let bytes = Archiver::new(Undictionaried {
            headers: "x".repeat(16),
        })
        .serialize()
        .expect("serialize");

        assert!(bytes.len() < COMPRESS_WATERMARK);
        assert_eq!(bytes[bytes.len() - 1] & ZSTD_COMPRESSED, 0);

        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes).expect("read");
        assert_eq!(
            archive
                .deserialize::<Undictionaried>()
                .expect("unarchive")
                .headers,
            "x".repeat(16)
        );
        assert!(archive.to_assert_value().matches(&bytes));
    }

    #[test]
    fn the_watermark_depends_on_the_dictionary() {
        let headers = "Content-Type: text/plain; charset=utf-8\r\nSubject: hello\r\n".repeat(2);
        assert!((COMPRESS_WATERMARK_DICTIONARY..COMPRESS_WATERMARK).contains(&headers.len()));

        let without = Archiver::new(Undictionaried {
            headers: headers.clone(),
        })
        .serialize()
        .expect("serialize");
        let with = Archiver::new(Compressible {
            headers,
            parts: Vec::new(),
        })
        .serialize()
        .expect("serialize");

        assert_eq!(without[without.len() - 1] & ZSTD_COMPRESSED, 0);
        assert_ne!(with[with.len() - 1] & ZSTD_COMPRESSED, 0);
        assert!(with.len() < without.len());

        for bytes in [without, with] {
            let archive =
                <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes).expect("read");
            assert!(archive.to_assert_value().matches(&bytes));
        }
    }

    #[test]
    fn uncompressed_types_are_never_compressed() {
        let bytes = Archiver::new(Tiny { value: 42 })
            .serialize()
            .expect("serialize");

        assert_eq!(bytes[bytes.len() - 1] & ZSTD_COMPRESSED, 0);
        assert_eq!(
            <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes)
                .expect("read")
                .deserialize::<Tiny>()
                .expect("unarchive"),
            Tiny { value: 42 }
        );
    }

    #[test]
    fn versioned_round_trip() {
        let (offset, mut bytes) = Archiver::new(sample(64))
            .serialize_versioned()
            .expect("serialize");
        let offset = offset as usize;
        bytes[offset..offset + U64_LEN].copy_from_slice(&1234u64.to_be_bytes());

        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes).expect("read");
        let hash = Archive::<ArchiveBytes>::extract_hash(&bytes).expect("hash");
        assert_eq!(
            archive.version,
            ArchiveVersion::Versioned {
                change_id: 1234,
                hash
            }
        );
        assert_eq!(
            archive.deserialize::<Compressible>().expect("unarchive"),
            sample(64)
        );
        assert!(archive.to_assert_value().matches(&bytes));
    }

    #[test]
    fn owned_and_borrowed_reads_agree() {
        for value in [sample(1), sample(64)] {
            let expected = value.headers.clone();
            let bytes = Archiver::new(value).serialize().expect("serialize");

            let borrowed =
                <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes).expect("read");
            let owned = <Archive<ArchiveBytes> as Deserialize>::deserialize_owned(bytes.clone())
                .expect("read owned");

            assert_eq!(borrowed.inner, owned.inner);
            assert_eq!(borrowed.version, owned.version);
            assert_eq!(
                borrowed.deserialize::<Compressible>().expect("a").headers,
                expected
            );
        }
    }

    #[test]
    fn corruption_is_rejected() {
        let bytes = Archiver::new(sample(64)).serialize().expect("serialize");
        let body_len = bytes.len() - 1;

        let mut detected = 0;
        let mut total = 0;
        for byte in 0..body_len {
            for bit in 0..8 {
                let mut corrupted = bytes.clone();
                corrupted[byte] ^= 1 << bit;
                total += 1;
                match <Archive<ArchiveBytes> as Deserialize>::deserialize(&corrupted) {
                    Err(_) => detected += 1,
                    Ok(archive) => {
                        if archive.inner
                            != <Archive<ArchiveBytes> as Deserialize>::deserialize(&bytes)
                                .unwrap()
                                .inner
                        {
                            panic!("byte {byte} bit {bit} decoded to different contents");
                        }
                    }
                }
            }
        }
        assert!(
            detected * 100 / total >= 99,
            "only {detected} of {total} corruptions rejected"
        );
    }

    #[test]
    fn legacy_lz4_archives_are_still_readable() {
        let value = sample(64);
        let body = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&value, Vec::new())
            .expect("rkyv");

        let mut stored = lz4_flex::block::compress_prepend_size(&body);
        let hash = (xxhash_rust::xxh3::xxh3_64(&stored) as u32).to_be_bytes();
        stored.extend_from_slice(&hash);
        stored.push(MAGIC_MARKER | HASHED | LZ4_COMPRESSED);

        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(&stored).expect("read");
        assert_eq!(
            archive.deserialize::<Compressible>().expect("unarchive"),
            value
        );
        assert!(archive.to_assert_value().matches(&stored));
    }

    #[test]
    fn assert_value_detects_a_changed_archive() {
        let old = Archiver::new(sample(64)).serialize().expect("serialize");
        let new = Archiver::new(sample(65)).serialize().expect("serialize");

        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(&old).expect("read");
        assert!(archive.to_assert_value().matches(&old));
        assert!(!archive.to_assert_value().matches(&new));
        assert!(!AssertValue::None.matches(&old));
    }
}
