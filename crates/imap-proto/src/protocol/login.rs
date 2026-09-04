/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use compact_str::CompactString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub username: CompactString,
    pub password: CompactString,
}
