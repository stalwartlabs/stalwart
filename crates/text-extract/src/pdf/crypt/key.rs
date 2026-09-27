/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) const MAX_KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FileKey {
    bytes: [u8; MAX_KEY_LEN],
    len: usize,
}

impl FileKey {
    pub(crate) fn from_slice(key: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; MAX_KEY_LEN];
        bytes.get_mut(..key.len())?.copy_from_slice(key);
        Some(FileKey {
            bytes,
            len: key.len(),
        })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&self.bytes)
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn zero_extend(&mut self, len: usize) {
        if (self.len..=MAX_KEY_LEN).contains(&len) {
            self.len = len;
        }
    }

    pub(crate) fn xor(&self, value: u8) -> Self {
        let mut derived = *self;
        for byte in derived.bytes.iter_mut().take(self.len) {
            *byte ^= value;
        }
        derived
    }
}
