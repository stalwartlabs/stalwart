/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::{
    parser::{ParseErrorKind, Parser, Result},
    schema::DateTimePrecision,
    types::{timezone::TimeZoneDefinition, value::EwsValue},
    version::RequestedVersion,
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SoapHeader<'a> {
    pub server_version: Option<RequestedVersion<'a>>,
    pub impersonation: Option<ConnectingSid<'a>>,
    pub time_zone: Option<TimeZoneDefinition<'a>>,
    pub date_time_precision: Option<DateTimePrecision>,
    pub mailbox_culture: Option<Cow<'a, str>>,
    pub has_management_role: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectingSid<'a> {
    PrincipalName(Cow<'a, str>),
    Sid(Cow<'a, str>),
    PrimarySmtpAddress(Cow<'a, str>),
    SmtpAddress(Cow<'a, str>),
}

impl<'a> SoapHeader<'a> {
    pub fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let mut header = SoapHeader::default();
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "RequestServerVersion" => {
                    p.expect_types(&child)?;
                    let raw = p.attr_required(&child.attrs, "Version")?;
                    header.server_version = Some(RequestedVersion::new(raw));
                    p.skip_rest()?;
                },
                "ExchangeImpersonation" => {
                    p.expect_types(&child)?;
                    header.impersonation = Some(ConnectingSid::parse_wrapper(p)?);
                },
                "TimeZoneContext" => {
                    p.expect_types(&child)?;
                    while let Some(inner) = p.child()? {
                        if inner.local == "TimeZoneDefinition" {
                            p.expect_types(&inner)?;
                            header.time_zone = Some(TimeZoneDefinition::parse(p, &inner.attrs)?);
                        } else {
                            p.skip()?;
                        }
                    }
                },
                "DateTimePrecision" => {
                    p.expect_types(&child)?;
                    header.date_time_precision = Some(<DateTimePrecision as EwsValue>::parse(p, &child.attrs)?);
                },
                "MailboxCulture" => {
                    p.expect_types(&child)?;
                    header.mailbox_culture = Some(p.text()?);
                },
                "ManagementRole" => {
                    p.expect_types(&child)?;
                    header.has_management_role = true;
                    p.skip()?;
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(header)
    }
}

#[derive(Clone, Copy)]
enum SidKind {
    PrincipalName,
    Sid,
    PrimarySmtpAddress,
    SmtpAddress,
}

impl<'a> ConnectingSid<'a> {
    fn parse_wrapper(p: &mut Parser<'a>) -> Result<Self> {
        let mut found = None;
        while let Some(child) = p.child()? {
            if child.local == "ConnectingSID" {
                p.expect_types(&child)?;
                found = Some(Self::parse(p)?);
            } else {
                p.skip()?;
            }
        }
        found.ok_or_else(|| p.error(ParseErrorKind::MissingElement("ConnectingSID")))
    }

    fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let mut found = None;
        while let Some(child) = p.child()? {
            let kind = hashify::map!(child.local.as_bytes(), SidKind,
                "PrincipalName" => SidKind::PrincipalName,
                "SID" => SidKind::Sid,
                "PrimarySmtpAddress" => SidKind::PrimarySmtpAddress,
                "SmtpAddress" => SidKind::SmtpAddress,
            )
            .copied();
            match kind {
                Some(_) if found.is_some() => {
                    return Err(p.error(ParseErrorKind::InvalidValue("ConnectingSID")));
                }
                Some(kind) => {
                    p.expect_types(&child)?;
                    let value = p.text()?;
                    found = Some(match kind {
                        SidKind::PrincipalName => ConnectingSid::PrincipalName(value),
                        SidKind::Sid => ConnectingSid::Sid(value),
                        SidKind::PrimarySmtpAddress => ConnectingSid::PrimarySmtpAddress(value),
                        SidKind::SmtpAddress => ConnectingSid::SmtpAddress(value),
                    });
                }
                None => p.skip()?,
            }
        }
        found.ok_or_else(|| p.error(ParseErrorKind::MissingElement("ConnectingSID")))
    }
}
