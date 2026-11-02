/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    der::{DerError, oid, reader::Reader, tag},
    x509::cert::{Certificate, name_attributes},
};

pub(crate) const GN_OTHER_NAME: u8 = tag::context_constructed(0);
pub(crate) const GN_RFC822: u8 = tag::context(1);
pub(crate) const GN_DNS: u8 = tag::context(2);
pub(crate) const GN_DIRECTORY: u8 = tag::context_constructed(4);
pub(crate) const GN_URI: u8 = tag::context(6);
pub(crate) const GN_IP: u8 = tag::context(7);
const PERMITTED: u8 = tag::context_constructed(0);
const EXCLUDED: u8 = tag::context_constructed(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Email,
    Dns,
    Directory,
    Ip,
    Other(u8),
}

impl Form {
    fn of(tag: u8) -> Self {
        match tag {
            GN_RFC822 => Form::Email,
            GN_DNS => Form::Dns,
            GN_DIRECTORY => Form::Directory,
            GN_IP => Form::Ip,
            other => Form::Other(other & !tag::CONSTRUCTED),
        }
    }
}

#[derive(Clone, Copy)]
struct Name<'x> {
    form: Form,
    value: &'x [u8],
}

pub(crate) fn uris(general_names: &[u8]) -> impl Iterator<Item = &str> {
    Reader::new(general_names)
        .map_while(Result::ok)
        .filter(|name| name.tag == GN_URI)
        .filter_map(|name| std::str::from_utf8(name.content).ok())
}

pub(crate) fn smtp_utf8_mailbox(other_name: &[u8]) -> Option<&[u8]> {
    let mut other = Reader::new(other_name);
    if other.read_content(tag::OID).ok()? != oid::SMTP_UTF8_MAILBOX {
        return None;
    }
    let value = other.read_tag(tag::context_constructed(0)).ok()?;
    value.reader().read_content(tag::UTF8_STRING).ok()
}

pub(crate) fn general_names(content: &[u8]) -> Result<&[u8], DerError> {
    for name in Reader::new(content) {
        let name = name?;
        if name.tag == GN_OTHER_NAME
            && Reader::new(name.content).read_content(tag::OID)? == oid::SMTP_UTF8_MAILBOX
            && smtp_utf8_mailbox(name.content).is_none()
        {
            return Err(DerError::InvalidValue);
        }
    }
    Ok(content)
}

fn cert_names<'x>(cert: &Certificate<'x>) -> impl Iterator<Item = Name<'x>> {
    let subject = Reader::new(cert.subject)
        .read_tag(tag::SEQUENCE)
        .ok()
        .filter(|dn| !dn.content.is_empty())
        .map(|dn| Name {
            form: Form::Directory,
            value: dn.content,
        });
    let san = cert
        .extensions
        .san
        .into_iter()
        .flat_map(|san| Reader::new(san).map_while(Result::ok))
        .map(|name| match name.tag {
            GN_OTHER_NAME => match smtp_utf8_mailbox(name.content) {
                Some(mailbox) => Name {
                    form: Form::Email,
                    value: mailbox,
                },
                None => Name {
                    form: Form::Other(name.tag & !tag::CONSTRUCTED),
                    value: name.content,
                },
            },
            other => Name {
                form: Form::of(other),
                value: name.content,
            },
        });
    let emails = name_attributes(cert.subject)
        .filter(|(id, _)| *id == oid::EMAIL_ADDRESS)
        .map(|(_, value)| Name {
            form: Form::Email,
            value,
        });
    subject.into_iter().chain(san).chain(emails)
}

fn ends_with_ignore_case(value: &[u8], suffix: &[u8]) -> bool {
    value
        .len()
        .checked_sub(suffix.len())
        .and_then(|start| value.get(start..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn domain_matches(domain: &[u8], constraint: &[u8]) -> bool {
    match constraint.strip_prefix(b".") {
        Some(_) => domain.len() > constraint.len() && ends_with_ignore_case(domain, constraint),
        None => {
            domain.eq_ignore_ascii_case(constraint)
                || (ends_with_ignore_case(domain, constraint)
                    && domain
                        .len()
                        .checked_sub(constraint.len() + 1)
                        .and_then(|dot| domain.get(dot))
                        == Some(&b'.'))
        }
    }
}

fn email_matches(address: &[u8], constraint: &[u8]) -> bool {
    if memchr::memchr(b'@', constraint).is_some() {
        return address.eq_ignore_ascii_case(constraint);
    }
    let mut parts = address.rsplitn(2, |b| *b == b'@');
    let (Some(domain), Some(_)) = (parts.next(), parts.next()) else {
        return false;
    };
    match constraint.strip_prefix(b".") {
        Some(_) => domain.len() > constraint.len() && ends_with_ignore_case(domain, constraint),
        None => domain.eq_ignore_ascii_case(constraint),
    }
}

fn dns_matches(name: &[u8], constraint: &[u8]) -> bool {
    let constraint = constraint.strip_prefix(b".").unwrap_or(constraint);
    constraint.is_empty() || domain_matches(name, constraint)
}

fn directory_matches(subject: &[u8], constraint: &[u8]) -> bool {
    let mut subject = Reader::new(subject);
    for rdn in Reader::new(constraint) {
        match (rdn, subject.read()) {
            (Ok(expected), Ok(actual)) if expected.raw == actual.raw => {}
            _ => return false,
        }
    }
    true
}

fn ip_matches(address: &[u8], constraint: &[u8]) -> bool {
    if constraint.len() != address.len() * 2 {
        return false;
    }
    let (network, mask) = constraint.split_at(address.len());
    address
        .iter()
        .zip(network)
        .zip(mask)
        .all(|((a, n), m)| a & m == n & m)
}

fn matches(name: Name<'_>, base: &[u8]) -> bool {
    match name.form {
        Form::Email => email_matches(name.value, base),
        Form::Dns => dns_matches(name.value, base),
        Form::Directory => directory_matches(name.value, base),
        Form::Ip => ip_matches(name.value, base),
        Form::Other(_) => false,
    }
}

fn subtree_bases(subtrees: Option<&[u8]>) -> impl Iterator<Item = Result<(Form, &[u8]), DerError>> {
    subtrees.into_iter().flat_map(Reader::new).map(|subtree| {
        let subtree = subtree?.expect(tag::SEQUENCE)?;
        let base = subtree.reader().read()?;
        let content = if base.tag == GN_DIRECTORY {
            base.reader().read_tag(tag::SEQUENCE)?.content
        } else {
            base.content
        };
        Ok((Form::of(base.tag), content))
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NameConstraints<'x> {
    permitted: Option<&'x [u8]>,
    excluded: Option<&'x [u8]>,
}

impl<'x> NameConstraints<'x> {
    pub(crate) fn parse(content: &'x [u8]) -> Result<Self, DerError> {
        let mut reader = Reader::new(content);
        let permitted = reader.read_optional(PERMITTED)?.map(|t| t.content);
        let excluded = reader.read_optional(EXCLUDED)?.map(|t| t.content);
        reader.finish()?;
        let constraints = NameConstraints {
            permitted,
            excluded,
        };
        for base in subtree_bases(permitted).chain(subtree_bases(excluded)) {
            base?;
        }
        Ok(constraints)
    }

    pub(crate) fn permits(&self, cert: &Certificate<'_>) -> bool {
        cert_names(cert).all(|name| self.permits_name(name))
    }

    fn permits_name(&self, name: Name<'_>) -> bool {
        let same_form = |subtrees| {
            subtree_bases(subtrees)
                .filter_map(Result::ok)
                .filter(move |(form, _)| *form == name.form)
        };
        if same_form(self.excluded).any(|(form, base)| match form {
            Form::Other(_) => true,
            _ => matches(name, base),
        }) {
            return false;
        }
        let mut permitted = same_form(self.permitted).peekable();
        permitted.peek().is_none()
            || permitted.any(|(form, base)| !matches!(form, Form::Other(_)) && matches(name, base))
    }
}
