/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Children, CommandError, Counter, MAX_VALIDATE_CERTIFICATES, read_bool, read_bytes};
use crate::common::base64::Base64Text;
use crate::eas::status::ValidateCertStatus;
use crate::eas::tokens::tag::validate_cert as vc;
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::wbxml::{Decoder, Encoder};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidateCertRequest<'a> {
    pub certificate_chain: Vec<Base64Text<'a>>,
    pub certificates: Vec<Base64Text<'a>>,
    pub check_crl: bool,
}

impl<'a> ValidateCertRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = ValidateCertRequest::default();
        let mut counter = Counter::new(MAX_VALIDATE_CERTIFICATES);
        let mut children = Children::root(dec, vc::VALIDATE_CERT)?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                vc::CERTIFICATE_CHAIN => {
                    parse_certificates(dec, &mut request.certificate_chain, &mut counter)?
                }
                vc::CERTIFICATES => {
                    parse_certificates(dec, &mut request.certificates, &mut counter)?
                }
                vc::CHECK_CRL => request.check_crl = read_bool(dec, tag)?,
                _ => {}
            }
        }
        Ok(request)
    }
}

fn parse_certificates<'a>(
    dec: &mut Decoder<'a>,
    list: &mut Vec<Base64Text<'a>>,
    counter: &mut Counter,
) -> Result<(), CommandError> {
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        if tag == vc::CERTIFICATE {
            counter.bump(tag)?;
            list.push(Base64Text(read_bytes(dec, tag)?));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateCertResponse {
    pub status: ValidateCertStatus,
    pub certificates: Vec<ValidateCertStatus>,
}

impl ValidateCertResponse {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(vc::VALIDATE_CERT)
            .text_u64(vc::STATUS, u64::from(self.status.0));
        for status in &self.certificates {
            encode_status(enc, vc::CERTIFICATE, *status);
        }
        enc.end();
    }
}

fn encode_status(enc: &mut Encoder, tag: Tag, status: ValidateCertStatus) {
    enc.start(tag)
        .text_u64(vc::STATUS, u64::from(status.0))
        .end();
}
