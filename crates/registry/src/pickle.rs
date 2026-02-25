/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::{
    codec::leb128::{Leb128_, Leb128Reader, Leb128Writer},
    map::vec_map::VecMap,
};

use crate::types::EnumImpl;
use std::collections::HashMap;

pub trait Pickle: Sized {
    fn pickle(&self, out: &mut Vec<u8>);
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self>;
    fn to_pickled_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        self.pickle(&mut out);
        out
    }
}

pub struct PickledStream<'x> {
    data: &'x [u8],
    pos: usize,
}

impl<'x> PickledStream<'x> {
    pub fn new(data: &'x [u8]) -> Self {
        PickledStream { data, pos: 0 }
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

    pub fn read_bytes(&mut self, len: usize) -> Option<&'x [u8]> {
        self.data.get(self.pos..self.pos + len).inspect(|_| {
            self.pos += len;
        })
    }

    pub fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn bytes(&self) -> &'x [u8] {
        self.data
    }

    pub fn assert_version(&mut self, expected: u8) -> Option<u8> {
        self.read().filter(|&version| version == expected)
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

impl Pickle for f64 {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; std::mem::size_of::<f64>()];
        arr.copy_from_slice(stream.read_bytes(std::mem::size_of::<f64>())?);
        Some(f64::from_be_bytes(arr))
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

impl<T> Pickle for Vec<T>
where
    T: Pickle,
{
    fn pickle(&self, out: &mut Vec<u8>) {
        (self.len() as u32).pickle(out);
        for item in self {
            item.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let len = u32::unpickle(stream)? as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::unpickle(stream)?);
        }
        Some(vec)
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
