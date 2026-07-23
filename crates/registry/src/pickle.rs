/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::types::EnumImpl;
use std::{borrow::Cow, collections::HashMap};
use utils::{
    codec::leb128::{Leb128_, Leb128Reader, Leb128Writer},
    map::vec_map::VecMap,
};

const COMPRESS_MARKER: u8 = 1 << 7;
const COMPRESS_WATERMARK: usize = 8192;

pub trait Pickle: Sized {
    fn pickle(&self, out: &mut Vec<u8>);
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self>;
}

pub struct PickledStream<'x> {
    data: Cow<'x, [u8]>,
    pos: usize,
    version: u8,
}

pub(crate) fn maybe_compress_pickle(input: Vec<u8>) -> Vec<u8> {
    let input_len = input.len() - 1; // Exclude the version byte
    if input_len > COMPRESS_WATERMARK {
        let (version, input) = input.split_first().unwrap();
        let mut bytes: Vec<u8> = vec![
            version | COMPRESS_MARKER;
            lz4_flex::block::get_maximum_output_size(input_len)
                + 1
                + std::mem::size_of::<u32>()
        ];

        // Compress the data
        let compressed_len =
            lz4_flex::compress_into(input, &mut bytes[std::mem::size_of::<u32>() + 1..]).unwrap();
        if compressed_len < input_len {
            // Prepend the length of the uncompressed data
            bytes[1..(std::mem::size_of::<u32>() + 1)]
                .copy_from_slice(&(input_len as u32).to_le_bytes());

            // Truncate to the actual size
            bytes.truncate(compressed_len + std::mem::size_of::<u32>() + 1);
            return bytes;
        }
    }
    input
}

impl<'x> PickledStream<'x> {
    pub fn new(data: &'x [u8]) -> Option<Self> {
        let (marker, data) = data.split_first()?;
        let version = marker & !COMPRESS_MARKER;
        if marker & COMPRESS_MARKER != 0 {
            lz4_flex::block::decompress_size_prepended(data)
                .ok()
                .map(|data| PickledStream {
                    data: Cow::Owned(data),
                    pos: 0,
                    version,
                })
        } else {
            PickledStream {
                data: Cow::Borrowed(data),
                pos: 0,
                version,
            }
            .into()
        }
    }

    pub fn read(&mut self) -> Option<u8> {
        self.data.get(self.pos).copied().inspect(|_| self.pos += 1)
    }

    pub fn read_leb128<T: Leb128_>(&mut self) -> Option<T> {
        self.data
            .get(self.pos..)
            .and_then(|bytes| bytes.read_leb128())
            .map(|(value, read_bytes)| {
                self.pos += read_bytes;
                value
            })
    }

    #[inline(always)]
    pub fn read_bytes(&mut self, len: usize) -> Option<&'_ [u8]> {
        self.data.get(self.pos..self.pos + len).inspect(|_| {
            self.pos += len;
        })
    }

    #[inline(always)]
    pub fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    #[inline(always)]
    pub fn bytes(&self) -> &'_ [u8] {
        self.data.as_ref()
    }

    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.version
    }
}

impl Pickle for u16 {
    fn pickle(&self, out: &mut Vec<u8>) {
        let _ = out.write_leb128(*self);
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        stream.read_leb128()
    }
}

impl Pickle for u64 {
    fn pickle(&self, out: &mut Vec<u8>) {
        let _ = out.write_leb128(*self);
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        stream.read_leb128()
    }
}

impl Pickle for u32 {
    fn pickle(&self, out: &mut Vec<u8>) {
        let _ = out.write_leb128(*self);
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        stream.read_leb128()
    }
}

impl Pickle for i64 {
    fn pickle(&self, out: &mut Vec<u8>) {
        let _ = out.write_leb128(*self as u64);
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        stream.read_leb128::<u64>().map(|v| v as i64)
    }
}

impl Pickle for bool {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.push(if *self { 1 } else { 0 });
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        match stream.read()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

impl Pickle for String {
    fn pickle(&self, out: &mut Vec<u8>) {
        (self.len() as u32).pickle(out);
        out.extend_from_slice(self.as_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        u32::unpickle(stream)
            .and_then(|len| stream.read_bytes(len as usize))
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
    }
}

impl<T: EnumImpl> Pickle for T {
    fn pickle(&self, out: &mut Vec<u8>) {
        self.to_id().pickle(out);
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        u16::unpickle(stream).and_then(Self::from_id)
    }
}

impl<T> Pickle for Option<T>
where
    T: Pickle,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        match self {
            Some(value) => {
                out.push(1);
                value.pickle(out);
            }
            None => {
                out.push(0);
            }
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        match stream.read()? {
            0 => Some(None),
            1 => T::unpickle(stream).map(Some),
            _ => None,
        }
    }
}

impl<K, V, S> Pickle for HashMap<K, V, S>
where
    K: Pickle + std::hash::Hash + Eq,
    V: Pickle,
    S: std::hash::BuildHasher + Default,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        (self.len() as u32).pickle(out);
        for (key, value) in self {
            key.pickle(out);
            value.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = u32::unpickle(stream)? as usize;
        let mut map = HashMap::with_capacity_and_hasher(len, S::default());
        for _ in 0..len {
            let key = K::unpickle(stream)?;
            let value = V::unpickle(stream)?;
            map.insert(key, value);
        }
        Some(map)
    }
}

impl<K, V> Pickle for VecMap<K, V>
where
    K: Pickle + std::hash::Hash + Eq,
    V: Pickle,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        (self.len() as u32).pickle(out);
        for (key, value) in self {
            key.pickle(out);
            value.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = u32::unpickle(stream)? as usize;
        let mut map = VecMap::with_capacity(len);
        for _ in 0..len {
            let key = K::unpickle(stream)?;
            let value = V::unpickle(stream)?;
            map.append(key, value);
        }
        Some(map)
    }
}

impl Pickle for trc::Key {
    fn pickle(&self, out: &mut Vec<u8>) {
        self.to_id().pickle(out);
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        u16::unpickle(stream).and_then(Self::from_id)
    }
}

