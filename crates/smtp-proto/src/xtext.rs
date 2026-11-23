/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{self, Display, Write};

pub struct XText<'x>(pub &'x str);

impl XText<'_> {
    pub fn is_printable(&self) -> bool {
        self.0.bytes().all(|ch| matches!(ch, b'\t' | b' '..=b'~'))
    }
}

impl Display for XText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in self.0.bytes() {
            if matches!(ch, b'!'..=b'*' | b','..=b'<' | b'>'..=b'~') {
                f.write_char(char::from(ch))?;
            } else {
                write!(f, "+{ch:02X}")?;
            }
        }
        Ok(())
    }
}
