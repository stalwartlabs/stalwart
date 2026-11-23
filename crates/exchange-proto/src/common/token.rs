/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use arrayvec::ArrayString;

pub const TOKEN_MAX: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TokenBuf(ArrayString<TOKEN_MAX>);

impl TokenBuf {
    pub const fn new() -> Self {
        TokenBuf(ArrayString::new_const())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn try_push_ascii(&mut self, bytes: &[u8]) -> bool {
        if !bytes.is_ascii() {
            return false;
        }
        match std::str::from_utf8(bytes) {
            Ok(text) => self.0.try_push_str(text).is_ok(),
            Err(_) => false,
        }
    }
}

impl AsRef<str> for TokenBuf {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
