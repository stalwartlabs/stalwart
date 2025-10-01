/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Semver(u64);

impl Semver {
    pub fn current() -> Self {
        env!("CARGO_PKG_VERSION").try_into().unwrap()
    }

    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        let mut version: u64 = 0;
        version |= (major as u64) << 32;
        version |= (minor as u64) << 16;
        version |= patch as u64;
        Semver(version)
    }

    pub fn unpack(&self) -> (u16, u16, u16) {
        let version = self.0;
        let major = ((version >> 32) & 0xFFFF) as u16;
        let minor = ((version >> 16) & 0xFFFF) as u16;
        let patch = (version & 0xFFFF) as u16;
        (major, minor, patch)
    }

    pub fn major(&self) -> u16 {
        (self.0 >> 32) as u16
    }

    pub fn minor(&self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub fn patch(&self) -> u16 {
        self.0 as u16
    }

    pub fn is_valid(&self) -> bool {
        self.0 > 0
    }
}

impl AsRef<u64> for Semver {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl From<u64> for Semver {
    fn from(value: u64) -> Self {
        Semver(value)
    }
}

impl TryFrom<&str> for Semver {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(3, '.');
        let major = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let minor = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let patch = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        Ok(Semver::new(major, minor, patch))
    }
}

impl Display for Semver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.unpack();
        write!(f, "{major}.{minor}.{patch}")
    }
}
