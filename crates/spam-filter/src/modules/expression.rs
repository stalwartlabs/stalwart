/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::mailstore::spamfilter::*,
    expr::{StringCow, Variable, functions::ResolveVariable},
};
use compact_str::{CompactString, ToCompactString, format_compact};
use mail_parser::{Header, HeaderValue};
use nlp::tokenizers::types::TokenType;
use registry::schema::enums::ExpressionVariable;

use crate::{Recipient, SpamFilterContext, TextPart, analysis::url::UrlParts};

pub(crate) struct SpamFilterResolver<'x, T: ResolveVariable> {
    pub ctx: &'x SpamFilterContext<'x>,
    pub item: &'x T,
    pub location: Location,
}

impl<'x, T: ResolveVariable> SpamFilterResolver<'x, T> {
    pub fn new(ctx: &'x SpamFilterContext<'x>, item: &'x T, location: Location) -> Self {
        Self {
            ctx,
            item,
            location,
        }
    }
}

impl<T: ResolveVariable> ResolveVariable for SpamFilterResolver<'_, T> {
    fn resolve_variable(&self, variable: ExpressionVariable) -> Variable<'_> {
        match variable {
            ExpressionVariable::RemoteIp => self.ctx.input.remote_ip.to_compact_string().into(),
            ExpressionVariable::RemoteIpPtr => self
                .ctx
                .output
                .iprev_ptr
                .as_deref()
                .unwrap_or_default()
                .into(),
            ExpressionVariable::HeloDomain => self.ctx.output.ehlo_host.fqdn.as_str().into(),
            ExpressionVariable::AuthenticatedAs => {
                self.ctx.input.authenticated_as.unwrap_or_default().into()
            }
            ExpressionVariable::Asn => self.ctx.input.asn.unwrap_or_default().into(),
            ExpressionVariable::Country => self.ctx.input.country.unwrap_or_default().into(),
            ExpressionVariable::IsTls => self.ctx.input.is_tls.into(),
            ExpressionVariable::EnvFrom => self.ctx.output.env_from_addr.address.as_str().into(),
            ExpressionVariable::EnvFromLocal => {
                self.ctx.output.env_from_addr.local_part.as_str().into()
            }
            ExpressionVariable::EnvFromDomain => self
                .ctx
                .output
                .env_from_addr
                .domain_part
                .fqdn
                .as_str()
                .into(),
            ExpressionVariable::EnvTo => self
                .ctx
                .output
                .env_to_addr
                .iter()
                .map(|e| Variable::from(e.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::From => self.ctx.output.from.email.address.as_str().into(),
            ExpressionVariable::FromName => self
                .ctx
                .output
                .from
                .name
                .as_deref()
                .unwrap_or_default()
                .into(),
            ExpressionVariable::FromLocal => self.ctx.output.from.email.local_part.as_str().into(),
            ExpressionVariable::FromDomain => {
                self.ctx.output.from.email.domain_part.fqdn.as_str().into()
            }
            ExpressionVariable::ReplyTo => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .map(|r| r.email.address.as_str())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::ReplyToName => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .and_then(|r| r.name.as_deref())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::ReplyToLocal => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .map(|r| r.email.local_part.as_str())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::ReplyToDomain => self
                .ctx
                .output
                .reply_to
                .as_ref()
                .map(|r| r.email.domain_part.fqdn.as_str())
                .unwrap_or_default()
                .into(),
            ExpressionVariable::To => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::from(r.email.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::ToName => self
                .ctx
                .output
                .recipients_to
                .iter()
                .filter_map(|r| Variable::from(r.name.as_deref()?).into())
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::ToLocal => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::from(r.email.local_part.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::ToDomain => self
                .ctx
                .output
                .recipients_to
                .iter()
                .map(|r| Variable::from(r.email.domain_part.fqdn.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::Cc => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::from(r.email.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::CcName => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .filter_map(|r| Variable::from(r.name.as_deref()?).into())
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::CcLocal => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::from(r.email.local_part.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::CcDomain => self
                .ctx
                .output
                .recipients_cc
                .iter()
                .map(|r| Variable::from(r.email.domain_part.fqdn.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::Bcc => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::from(r.email.address.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::BccName => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .filter_map(|r| Variable::from(r.name.as_deref()?).into())
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::BccLocal => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::from(r.email.local_part.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::BccDomain => self
                .ctx
                .output
                .recipients_bcc
                .iter()
                .map(|r| Variable::from(r.email.domain_part.fqdn.as_str()))
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::Body | ExpressionVariable::BodyText => {
                self.ctx.text_body().unwrap_or_default().into()
            }
            ExpressionVariable::BodyHtml => self
                .ctx
                .input
                .message
                .html_body
                .first()
                .and_then(|idx| self.ctx.output.text_parts.get(*idx as usize))
                .map(|part| {
                    if let TextPart::Html { text_body, .. } = part {
                        text_body.as_str()
                    } else {
                        ""
                    }
                })
                .unwrap_or_default()
                .into(),
            ExpressionVariable::BodyRaw => Variable::from(CompactString::from_utf8_lossy(
                self.ctx.input.message.raw_message(),
            )),
            ExpressionVariable::Subject => self.ctx.output.subject_lc.as_str().into(),
            ExpressionVariable::SubjectThread => self.ctx.output.subject_thread_lc.as_str().into(),
            ExpressionVariable::Location => self.location.as_str().into(),
            ExpressionVariable::SubjectWords => self
                .ctx
                .output
                .subject_tokens
                .iter()
                .filter_map(|w| match w {
                    TokenType::Alphabetic(w)
                    | TokenType::Alphanumeric(w)
                    | TokenType::Integer(w)
                    | TokenType::Float(w) => Some(Variable::from(w.as_ref())),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .into(),
            ExpressionVariable::BodyWords => self
                .ctx
                .input
                .message
                .html_body
                .first()
                .and_then(|idx| self.ctx.output.text_parts.get(*idx as usize))
                .map(|part| match part {
                    TextPart::Plain { tokens, .. } | TextPart::Html { tokens, .. } => tokens
                        .iter()
                        .filter_map(|w| match w {
                            TokenType::Alphabetic(w)
                            | TokenType::Alphanumeric(w)
                            | TokenType::Integer(w)
                            | TokenType::Float(w) => Some(Variable::from(w.as_ref())),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    TextPart::None => vec![],
                })
                .unwrap_or_default()
                .into(),
            variable => self.item.resolve_variable(variable),
        }
    }

    fn resolve_global(&self, variable: &str) -> Variable<'_> {
        Variable::Integer(self.ctx.result.tags.contains(variable).into())
    }
}

pub(crate) struct EmailHeader<'x> {
    pub header: &'x Header<'x>,
    pub raw: &'x str,
}

impl ResolveVariable for EmailHeader<'_> {
    fn resolve_variable(&self, variable: ExpressionVariable) -> Variable<'_> {
        match variable {
            ExpressionVariable::Name => self.header.name().into(),
            ExpressionVariable::NameLower => {
                CompactString::from_str_to_lowercase(self.header.name()).into()
            }
            ExpressionVariable::Value
            | ExpressionVariable::ValueLower
            | ExpressionVariable::Attributes => match &self.header.value {
                HeaderValue::Text(text) => {
                    if variable == ExpressionVariable::ValueLower {
                        CompactString::from_str_to_lowercase(text).into()
                    } else {
                        text.as_ref().into()
                    }
                }
                HeaderValue::TextList(list) => Variable::Array(
                    list.iter()
                        .map(|text| {
                            Variable::String(if variable == ExpressionVariable::ValueLower {
                                StringCow::Owned(CompactString::from_str_to_lowercase(text))
                            } else {
                                StringCow::Borrowed(text.as_ref())
                            })
                        })
                        .collect(),
                ),
                HeaderValue::Address(address) => {
                    Variable::Array(if matches!(variable, ExpressionVariable::ValueLower) {
                        address
                            .iter()
                            .filter_map(|a| {
                                a.address.as_ref().map(|text| {
                                    Variable::String(
                                        if variable == ExpressionVariable::ValueLower {
                                            StringCow::Owned(CompactString::from_str_to_lowercase(
                                                text,
                                            ))
                                        } else {
                                            StringCow::Borrowed(text.as_ref())
                                        },
                                    )
                                })
                            })
                            .collect()
                    } else {
                        address
                            .iter()
                            .filter_map(|a| {
                                a.name.as_ref().map(|text| {
                                    Variable::String(
                                        if variable == ExpressionVariable::ValueLower {
                                            StringCow::Owned(CompactString::from_str_to_lowercase(
                                                text,
                                            ))
                                        } else {
                                            StringCow::Borrowed(text.as_ref())
                                        },
                                    )
                                })
                            })
                            .collect()
                    })
                }
                HeaderValue::DateTime(date_time) => {
                    CompactString::new(date_time.to_rfc3339()).into()
                }
                HeaderValue::ContentType(ct) => {
                    if variable != ExpressionVariable::Attributes {
                        if let Some(st) = ct.subtype() {
                            format_compact!("{}/{}", ct.ctype(), st).into()
                        } else {
                            ct.ctype().into()
                        }
                    } else {
                        Variable::Array(
                            ct.attributes()
                                .map(|attr| {
                                    attr.iter()
                                        .map(|attr| {
                                            Variable::from(format_compact!(
                                                "{}={}", attr.name, attr.value
                                            ))
                                        })
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default(),
                        )
                    }
                }
                HeaderValue::Received(_) => {
                    if variable == ExpressionVariable::ValueLower {
                        CompactString::from_str_to_lowercase(self.raw.trim()).into()
                    } else {
                        self.raw.trim().into()
                    }
                }
                HeaderValue::Empty => "".into(),
            },
            ExpressionVariable::Raw => self.raw.into(),
            ExpressionVariable::RawLower => CompactString::from_str_to_lowercase(self.raw).into(),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl ResolveVariable for Recipient {
    fn resolve_variable(&self, variable: ExpressionVariable) -> Variable<'_> {
        match variable {
            ExpressionVariable::Email | ExpressionVariable::Value => {
                Variable::from(self.email.address.as_str())
            }
            ExpressionVariable::Name => Variable::from(self.name.as_deref().unwrap_or_default()),
            ExpressionVariable::Local => Variable::from(self.email.local_part.as_str()),
            ExpressionVariable::Domain => Variable::from(self.email.domain_part.fqdn.as_str()),
            ExpressionVariable::Sld => Variable::from(self.email.domain_part.sld_or_default()),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl ResolveVariable for UrlParts<'_> {
    fn resolve_variable(&self, variable: ExpressionVariable) -> Variable<'_> {
        match variable {
            ExpressionVariable::Url | ExpressionVariable::Value => {
                Variable::from(self.url.as_str())
            }
            ExpressionVariable::PathQuery => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.path_and_query().map(|p| p.as_str()))
                    .unwrap_or_default(),
            ),
            ExpressionVariable::UrlPath => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.parts.path())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Query => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.query())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Scheme => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.scheme_str())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Authority => Variable::from(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.authority().map(|a| a.as_str()))
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Host => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.fqdn.as_str())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Sld => Variable::from(
                self.url_parsed
                    .as_ref()
                    .map(|p| p.host.sld_or_default())
                    .unwrap_or_default(),
            ),
            ExpressionVariable::Port => Variable::Integer(
                self.url_parsed
                    .as_ref()
                    .and_then(|p| p.parts.port_u16())
                    .unwrap_or(0) as _,
            ),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub struct StringResolver<'x>(pub &'x str);

impl ResolveVariable for StringResolver<'_> {
    fn resolve_variable(&self, _: ExpressionVariable) -> Variable<'_> {
        Variable::from(self.0)
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

pub struct StringListResolver<'x>(pub &'x [String]);

impl ResolveVariable for StringListResolver<'_> {
    fn resolve_variable(&self, _: ExpressionVariable) -> Variable<'_> {
        Variable::Array(self.0.iter().map(|v| Variable::from(v.as_str())).collect())
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}
