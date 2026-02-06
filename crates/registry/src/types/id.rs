/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    pickle::{Pickle, PickledStream},
    schema::prelude::Object,
    types::EnumType,
};
use std::str::FromStr;
use utils::codec::base32_custom::{BASE32_ALPHABET, BASE32_INVERSE};

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct Id {
    object: Object,
    id: u64,
}

impl Id {
    pub fn new(object: Object, id: impl Into<u64>) -> Self {
        Self {
            object,
            id: id.into(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn object(&self) -> Object {
        self.object
    }

    pub fn is_valid(&self) -> bool {
        self.id != u64::MAX
    }

    pub fn as_string(&self) -> String {
        let mut out = String::with_capacity(14);
        encode(self.object.to_id() as u64, &mut out);
        out.push(':');
        encode(self.id, &mut out);
        out
    }
}

impl Object {
    pub fn id(&self, id: u64) -> Id {
        Id::new(*self, id)
    }

    pub fn singleton(&self) -> Id {
        Id::new(*self, 20080258862541u64)
    }
}

impl FromStr for Id {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some((obj_str, id_str)) => {
                let object_id = decode(obj_str).ok_or(())?;
                let object = Object::from_id(object_id as u16).ok_or(())?;
                let id = decode(id_str).ok_or(())?;
                Ok(Id::new(object, id))
            }
            None => Err(()),
        }
    }
}

fn decode(s: &str) -> Option<u64> {
    let mut n = 0u64;

    for &ch in s.as_bytes() {
        let i = BASE32_INVERSE[ch as usize];
        if i != u8::MAX {
            n = (n << 5) | i as u64;
        } else {
            return None;
        }
    }

    Some(n)
}

// From https://github.com/archer884/crockford by J/A <archer884@gmail.com>
// License: MIT/Apache 2.0
fn encode(n: u64, out: &mut String) {
    match n {
        0 => out.push('a'),
        mut n => {
            // Used for the initial shift.
            const QUAD_SHIFT: usize = 60;
            const QUAD_RESET: usize = 4;

            // Used for all subsequent shifts.
            const FIVE_SHIFT: usize = 59;
            const FIVE_RESET: usize = 5;

            // After we clear the four most significant bits, the four least significant bits will be
            // replaced with 0001. We can then know to stop once the four most significant bits are,
            // likewise, 0001.
            const STOP_BIT: u64 = 1 << QUAD_SHIFT;

            // Start by getting the most significant four bits. We get four here because these would be
            // leftovers when starting from the least significant bits. In either case, tag the four least
            // significant bits with our stop bit.
            match (n >> QUAD_SHIFT) as usize {
                // Eat leading zero-bits. This should not be done if the first four bits were non-zero.
                // Additionally, we *must* do this in increments of five bits.
                0 => {
                    n <<= QUAD_RESET;
                    n |= 1;
                    n <<= n.leading_zeros() / 5 * 5;
                }

                // Write value of first four bytes.
                i => {
                    n <<= QUAD_RESET;
                    n |= 1;
                    out.push(char::from(BASE32_ALPHABET[i]));
                }
            }

            // From now until we reach the stop bit, take the five most significant bits and then shift
            // left by five bits.
            while n != STOP_BIT {
                out.push(char::from(BASE32_ALPHABET[(n >> FIVE_SHIFT) as usize]));
                n <<= FIVE_RESET;
            }
        }
    }
}

impl Default for Id {
    fn default() -> Self {
        Id::new(Object::Account, u64::MAX)
    }
}

impl serde::Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Id::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Registry ID"))
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

impl Pickle for Id {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.object.to_id().to_le_bytes());
        out.extend_from_slice(&self.id.to_le_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; 2];
        arr.copy_from_slice(data.read_bytes(2)?);
        let object = Object::from_id(u16::from_le_bytes(arr))?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(data.read_bytes(8)?);
        let id = u64::from_le_bytes(arr);

        Some(Id { object, id })
    }
}
