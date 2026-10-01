/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::{memchr, memmem::Finder};

#[derive(Debug, Clone)]
pub struct ConstNeedle {
    needle: Box<str>,
    finder: Finder<'static>,
    byte: Option<u8>,
}

impl ConstNeedle {
    pub fn new(needle: &str) -> Self {
        let byte = match needle.as_bytes() {
            [byte] => Some(*byte),
            _ => None,
        };
        Self {
            needle: needle.into(),
            finder: Finder::new(needle.as_bytes()).into_owned(),
            byte,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.needle
    }

    pub fn contains(&self, haystack: &str) -> bool {
        match self.byte {
            Some(byte) => memchr(byte, haystack.as_bytes()).is_some(),
            None => self.finder.find(haystack.as_bytes()).is_some(),
        }
    }

    pub fn starts_with(&self, haystack: &str) -> bool {
        haystack.starts_with(self.as_str())
    }

    pub fn ends_with(&self, haystack: &str) -> bool {
        haystack.ends_with(self.as_str())
    }
}
