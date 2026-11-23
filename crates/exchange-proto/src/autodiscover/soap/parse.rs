/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    RequestedSetting, SoapAdEnvelope, SoapAdRequest, SoapInvalid, SoapOperation, SoapParseError,
    SoapParseErrorKind,
};
use crate::{
    autodiscover::{AdLimits, pox::trim_cow, settings::UserSettingName},
    ews::version::ExchangeVersion,
    xml::{Ns, Token, Tokenizer, XmlErrorKind, tokenizer::NoName},
};
use smallvec::SmallVec;
use std::borrow::Cow;

pub fn parse_soap_request<'a>(
    body: &'a [u8],
    limits: &AdLimits,
) -> Result<SoapAdEnvelope<'a>, SoapParseError> {
    let mut p = SoapParser {
        tok: Tokenizer::new(body, &limits.xml),
        limits,
    };
    let mut requested_version = None;
    let mut parsed = None;

    match p.tok.next_token::<NoName>()? {
        Token::Unknown {
            ns: Ns::Soap11 | Ns::Soap12,
            local: "Envelope",
            ..
        } => {}
        Token::Eof => return Err(p.error(SoapParseErrorKind::MissingBody)),
        _ => return Err(p.error(SoapParseErrorKind::NotEnvelope)),
    }

    while let Some((ns, local)) = p.next_child()? {
        match (ns, local) {
            (Ns::Soap11 | Ns::Soap12, "Header") if parsed.is_none() => {
                while let Some((ns, local)) = p.next_child()? {
                    if ns == Ns::AdSoap
                        && local == "RequestedServerVersion"
                        && requested_version.is_none()
                    {
                        requested_version = Some(trim_cow(p.tok.text()?));
                    } else {
                        p.tok.skip_element()?;
                    }
                }
            }
            (Ns::Soap11 | Ns::Soap12, "Body") if parsed.is_none() => {
                parsed = Some(p.parse_body()?);
            }
            _ => p.tok.skip_element()?,
        }
    }
    p.expect_eof()?;

    let (request, request_version) =
        parsed.ok_or_else(|| p.error(SoapParseErrorKind::MissingBody))?;
    Ok(SoapAdEnvelope {
        requested_version,
        request_version,
        request,
    })
}

struct SoapParser<'a, 'l> {
    tok: Tokenizer<'a>,
    limits: &'l AdLimits,
}

impl<'a> SoapParser<'a, '_> {
    fn error(&self, kind: SoapParseErrorKind) -> SoapParseError {
        SoapParseError::new(kind, self.tok.offset())
    }

    fn invalid(&self, op: SoapOperation, reason: SoapInvalid) -> SoapParseError {
        self.error(SoapParseErrorKind::Invalid(op, reason))
    }

    fn next_child(&mut self) -> Result<Option<(Ns, &'a str)>, SoapParseError> {
        loop {
            match self.tok.next_token::<NoName>()? {
                Token::Unknown { ns, local, .. } => return Ok(Some((ns, local))),
                Token::Start { .. } => self.tok.skip_element()?,
                Token::Text => {}
                Token::End => return Ok(None),
                Token::Eof => return Err(self.tok.error(XmlErrorKind::UnexpectedEof).into()),
            }
        }
    }

    fn next_ad_child(&mut self) -> Result<Option<&'a str>, SoapParseError> {
        while let Some((ns, local)) = self.next_child()? {
            if ns == Ns::AdSoap {
                return Ok(Some(local));
            }
            self.tok.skip_element()?;
        }
        Ok(None)
    }

    fn expect_eof(&mut self) -> Result<(), SoapParseError> {
        loop {
            match self.tok.next_token::<NoName>()? {
                Token::Eof => return Ok(()),
                Token::Text => {}
                _ => return Err(self.tok.error(XmlErrorKind::UnexpectedElement).into()),
            }
        }
    }

    fn parse_body(
        &mut self,
    ) -> Result<(SoapAdRequest<'a>, Option<ExchangeVersion>), SoapParseError> {
        let Some((ns, local)) = self.next_child()? else {
            return Err(self.error(SoapParseErrorKind::MissingBody));
        };
        let op = SoapOperation::from_request_root(local.as_bytes())
            .filter(|_| ns == Ns::AdSoap)
            .ok_or_else(|| self.error(SoapParseErrorKind::UnknownOperation))?;

        let mut result = None;
        while let Some(local) = self.next_ad_child()? {
            if local == "Request" && result.is_none() {
                result = Some(self.parse_request(op)?);
            } else {
                self.tok.skip_element()?;
            }
        }
        while self.next_child()?.is_some() {
            self.tok.skip_element()?;
        }
        result.ok_or_else(|| self.invalid(op, SoapInvalid::MissingRequest))
    }

    fn parse_request(
        &mut self,
        op: SoapOperation,
    ) -> Result<(SoapAdRequest<'a>, Option<ExchangeVersion>), SoapParseError> {
        let mut targets: Option<SmallVec<[Cow<'a, str>; 1]>> = None;
        let mut settings: Option<Vec<RequestedSetting<'a>>> = None;
        let mut domain = None;
        let mut version = None;

        while let Some(local) = self.next_ad_child()? {
            match (op, local) {
                (SoapOperation::GetUserSettings, "Users") if targets.is_none() => {
                    targets = Some(self.parse_users(op)?);
                }
                (
                    SoapOperation::GetDomainSettings
                    | SoapOperation::GetOrganizationRelationshipSettings,
                    "Domains",
                ) if targets.is_none() => {
                    targets = Some(self.parse_list(op, "Domain")?);
                }
                (
                    SoapOperation::GetUserSettings | SoapOperation::GetDomainSettings,
                    "RequestedSettings",
                ) if settings.is_none() => {
                    settings = Some(self.parse_settings(op)?);
                }
                (
                    SoapOperation::GetUserSettings | SoapOperation::GetDomainSettings,
                    "RequestedVersion",
                ) if version.is_none() => {
                    version = Some(ExchangeVersion::parse(self.tok.text()?.trim().as_bytes()));
                }
                (SoapOperation::GetFederationInformation, "Domain") if domain.is_none() => {
                    domain = Some(trim_cow(self.tok.text()?));
                }
                _ => self.tok.skip_element()?,
            }
        }

        let version = version.flatten();
        let request = match op {
            SoapOperation::GetUserSettings => SoapAdRequest::GetUserSettings {
                users: targets
                    .filter(|users| !users.is_empty())
                    .ok_or_else(|| self.invalid(op, SoapInvalid::MissingUsers))?,
                settings: settings.ok_or_else(|| self.invalid(op, SoapInvalid::MissingSettings))?,
            },
            SoapOperation::GetDomainSettings => SoapAdRequest::GetDomainSettings {
                domains: targets
                    .filter(|domains| !domains.is_empty())
                    .ok_or_else(|| self.invalid(op, SoapInvalid::MissingDomain))?,
                settings: settings.ok_or_else(|| self.invalid(op, SoapInvalid::MissingSettings))?,
            },
            SoapOperation::GetFederationInformation => SoapAdRequest::GetFederationInformation {
                domain: domain
                    .filter(|domain| !domain.is_empty())
                    .ok_or_else(|| self.invalid(op, SoapInvalid::MissingDomain))?,
            },
            SoapOperation::GetOrganizationRelationshipSettings => {
                SoapAdRequest::GetOrganizationRelationshipSettings
            }
        };
        Ok((request, version))
    }

    fn parse_users(
        &mut self,
        op: SoapOperation,
    ) -> Result<SmallVec<[Cow<'a, str>; 1]>, SoapParseError> {
        let mut users = SmallVec::new();
        while let Some(local) = self.next_ad_child()? {
            if local != "User" {
                self.tok.skip_element()?;
                continue;
            }
            if users.len() >= usize::from(self.limits.max_users) {
                return Err(self.invalid(op, SoapInvalid::TooManyItems));
            }
            let mut mailbox = None;
            while let Some(local) = self.next_ad_child()? {
                if local == "Mailbox" && mailbox.is_none() {
                    mailbox = Some(trim_cow(self.tok.text()?));
                } else {
                    self.tok.skip_element()?;
                }
            }
            users.push(mailbox.ok_or_else(|| self.invalid(op, SoapInvalid::MissingMailbox))?);
        }
        Ok(users)
    }

    fn parse_list(
        &mut self,
        op: SoapOperation,
        item: &str,
    ) -> Result<SmallVec<[Cow<'a, str>; 1]>, SoapParseError> {
        let mut items = SmallVec::new();
        while let Some(local) = self.next_ad_child()? {
            if local != item {
                self.tok.skip_element()?;
                continue;
            }
            if items.len() >= usize::from(self.limits.max_users) {
                return Err(self.invalid(op, SoapInvalid::TooManyItems));
            }
            items.push(trim_cow(self.tok.text()?));
        }
        Ok(items)
    }

    fn parse_settings(
        &mut self,
        op: SoapOperation,
    ) -> Result<Vec<RequestedSetting<'a>>, SoapParseError> {
        let mut settings = Vec::new();
        while let Some(local) = self.next_ad_child()? {
            if local != "Setting" {
                self.tok.skip_element()?;
                continue;
            }
            if settings.len() >= usize::from(self.limits.max_settings) {
                return Err(self.invalid(op, SoapInvalid::TooManySettings));
            }
            let name = trim_cow(self.tok.text()?);
            settings.push(match UserSettingName::parse(name.as_bytes()) {
                Some(known) => RequestedSetting::Known(known),
                None => RequestedSetting::Unknown(name),
            });
        }
        Ok(settings)
    }
}
