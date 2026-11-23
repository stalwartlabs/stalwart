/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub use crate::ews::schema::ExchangeVersion;
use crate::xml::XmlWriter;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedVersion<'a> {
    pub raw: Cow<'a, str>,
    pub known: Option<ExchangeVersion>,
}

impl<'a> RequestedVersion<'a> {
    pub fn new(raw: impl Into<Cow<'a, str>>) -> Self {
        let raw = raw.into();
        let known = ExchangeVersion::parse(raw.trim_ascii().as_bytes());
        RequestedVersion { raw, known }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerVersionInfo {
    pub major: u16,
    pub minor: u16,
    pub major_build: u16,
    pub minor_build: u16,
    pub version: ExchangeVersion,
}

impl ServerVersionInfo {
    pub const DEFAULT: Self = Self::for_version(ExchangeVersion::Exchange2016);

    pub const fn for_version(version: ExchangeVersion) -> Self {
        let (major, minor, major_build, minor_build) = match version {
            ExchangeVersion::Exchange2007 => (8, 0, 685, 24),
            ExchangeVersion::Exchange2007Sp1 => (8, 1, 240, 6),
            ExchangeVersion::Exchange2009 | ExchangeVersion::Exchange2010 => (14, 0, 639, 21),
            ExchangeVersion::Exchange2010Sp1 => (14, 1, 218, 15),
            ExchangeVersion::Exchange2010Sp2 => (14, 2, 247, 5),
            ExchangeVersion::Exchange2012 | ExchangeVersion::Exchange2013 => (15, 0, 516, 32),
            ExchangeVersion::Exchange2013Sp1 => (15, 0, 847, 32),
            ExchangeVersion::Exchange2015 | ExchangeVersion::Exchange2016 => (15, 1, 225, 42),
            ExchangeVersion::V2015_10_05
            | ExchangeVersion::V2016_01_06
            | ExchangeVersion::V2016_04_13
            | ExchangeVersion::V2016_07_13
            | ExchangeVersion::V2016_10_10
            | ExchangeVersion::V2017_01_07
            | ExchangeVersion::V2017_04_14
            | ExchangeVersion::V2017_07_11 => (15, 0, 847, 32),
        };
        ServerVersionInfo {
            major,
            minor,
            major_build,
            minor_build,
            version,
        }
    }

    pub fn clamped(self, requested: Option<ExchangeVersion>) -> Self {
        match requested {
            Some(requested) if requested < self.version => ServerVersionInfo {
                version: requested,
                ..self
            },
            _ => self,
        }
    }

    pub fn write_attrs(&self, w: &mut XmlWriter<'_>) {
        w.attr_u64("MajorVersion", u64::from(self.major))
            .attr_u64("MinorVersion", u64::from(self.minor))
            .attr_u64("MajorBuildNumber", u64::from(self.major_build))
            .attr_u64("MinorBuildNumber", u64::from(self.minor_build))
            .attr("Version", self.version.as_str());
    }
}

impl Default for ServerVersionInfo {
    fn default() -> Self {
        Self::DEFAULT
    }
}
