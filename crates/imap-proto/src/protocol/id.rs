/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use compact_str::CompactString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub client: ClientId,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClientId {
    #[default]
    Unknown,
    MicrosoftOffice365,
}

impl ClientId {
    pub fn allows_uid_only(self) -> bool {
        !matches!(self, ClientId::MicrosoftOffice365)
    }
}
