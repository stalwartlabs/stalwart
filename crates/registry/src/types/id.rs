/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    pickle::{Pickle, PickledStream},
    schema::prelude::Object,
};
use std::str::FromStr;
use utils::codec::base32_custom::{BASE32_ALPHABET, BASE32_INVERSE};

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
#[repr(transparent)]
pub struct Id(u64);

impl Id {
    pub fn new(object: Object, id: u64) -> Self {
        Id(id & (u64::MAX >> 16) | ((object as u64) << 48))
    }

    pub fn id(&self) -> u64 {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0 != u64::MAX
    }

    // From https://github.com/archer884/crockford by J/A <archer884@gmail.com>
    // License: MIT/Apache 2.0
    pub fn as_string(&self) -> String {
        match self.0 {
            0 => "a".to_string(),
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

                let mut buf = String::with_capacity(7);

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
                        buf.push(char::from(BASE32_ALPHABET[i]));
                    }
                }

                // From now until we reach the stop bit, take the five most significant bits and then shift
                // left by five bits.
                while n != STOP_BIT {
                    buf.push(char::from(BASE32_ALPHABET[(n >> FIVE_SHIFT) as usize]));
                    n <<= FIVE_RESET;
                }

                buf
            }
        }
    }
}

impl Object {
    pub fn id(&self, id: u64) -> Id {
        Id::new(*self, id)
    }

    pub fn singleton(&self) -> Id {
        Id::new(*self, u64::MAX)
    }
}

impl FromStr for Id {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut id = 0;

        for &ch in s.as_bytes() {
            let i = BASE32_INVERSE[ch as usize];
            if i != u8::MAX {
                id = (id << 5) | i as u64;
            } else {
                return Err(());
            }
        }

        Ok(Id(id))
    }
}

impl Default for Id {
    fn default() -> Self {
        Id(u64::MAX)
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
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(data.read_bytes(8)?);
        Some(Id(u64::from_le_bytes(arr)))
    }
}
