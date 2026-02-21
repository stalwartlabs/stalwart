/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::map::vec_map::VecMap;

use crate::types::EnumImpl;
use std::collections::HashMap;

pub trait Pickle: Sized {
    fn pickle(&self, out: &mut Vec<u8>);
    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self>;
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
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    pub fn read_bytes(&mut self, len: usize) -> Option<&'x [u8]> {
        let bytes = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(bytes)
    }

    pub fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn bytes(&self) -> &'x [u8] {
        self.data
    }
}

impl Pickle for u16 {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; std::mem::size_of::<u16>()];
        arr.copy_from_slice(stream.read_bytes(std::mem::size_of::<u16>())?);
        Some(u16::from_be_bytes(arr))
    }
}

impl Pickle for u64 {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; std::mem::size_of::<u64>()];
        arr.copy_from_slice(stream.read_bytes(std::mem::size_of::<u64>())?);
        Some(u64::from_be_bytes(arr))
    }
}

impl Pickle for u32 {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; std::mem::size_of::<u32>()];
        arr.copy_from_slice(stream.read_bytes(std::mem::size_of::<u32>())?);
        Some(u32::from_be_bytes(arr))
    }
}

impl Pickle for i64 {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; std::mem::size_of::<i64>()];
        arr.copy_from_slice(stream.read_bytes(std::mem::size_of::<i64>())?);
        Some(i64::from_be_bytes(arr))
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
        out.extend_from_slice(&(self.len() as u32).to_be_bytes());
        out.extend_from_slice(self.as_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut len_arr = [0u8; std::mem::size_of::<u32>()];
        len_arr.copy_from_slice(stream.read_bytes(std::mem::size_of::<u32>())?);
        let bytes = stream.read_bytes(u32::from_be_bytes(len_arr) as usize)?;
        String::from_utf8(bytes.to_vec()).ok()
    }
}

impl<T: EnumImpl> Pickle for T {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_id().to_be_bytes());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut id_arr = [0u8; std::mem::size_of::<u16>()];
        id_arr.copy_from_slice(stream.read_bytes(std::mem::size_of::<u16>())?);
        Self::from_id(u16::from_be_bytes(id_arr))
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
        out.extend_from_slice(&(self.len() as u32).to_be_bytes());
        for item in self {
            item.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut len_arr = [0u8; 4];
        len_arr.copy_from_slice(stream.read_bytes(4)?);
        let len = u32::from_be_bytes(len_arr) as usize;
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
        out.extend_from_slice(&(self.len() as u32).to_be_bytes());
        for (key, value) in self {
            key.pickle(out);
            value.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut len_arr = [0u8; 4];
        len_arr.copy_from_slice(stream.read_bytes(4)?);
        let len = u32::from_be_bytes(len_arr) as usize;
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
        out.extend_from_slice(&(self.len() as u32).to_be_bytes());
        for (key, value) in self {
            key.pickle(out);
            value.pickle(out);
        }
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        let mut len_arr = [0u8; 4];
        len_arr.copy_from_slice(stream.read_bytes(4)?);
        let len = u32::from_be_bytes(len_arr) as usize;
        let mut map = VecMap::with_capacity(len);
        for _ in 0..len {
            let key = K::unpickle(stream)?;
            let value = V::unpickle(stream)?;
            map.append(key, value);
        }
        Some(map)
    }
}
