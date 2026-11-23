/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{
    Children, CommandError, Counter, MAX_RESOLVE_RECIPIENTS, read_date, read_id, read_u8, read_u32,
    required,
};
use crate::eas::status::{PictureStatus, ResolveRecipientsStatus};
use crate::eas::tokens::ProtocolVersion;
use crate::eas::tokens::tag::resolve_recipients as rr;
use crate::eas::types::EasDateTime;
use crate::eas::wbxml::{Decoder, Encoder};

pub const MAX_RECIPIENT_LEN: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PictureOptions {
    pub max_size: Option<u32>,
    pub max_pictures: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvailabilityWindow {
    pub start_time: EasDateTime,
    pub end_time: Option<EasDateTime>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolveRecipientsOptions {
    pub certificate_retrieval: Option<u8>,
    pub max_certificates: Option<u32>,
    pub max_ambiguous_recipients: Option<u32>,
    pub availability: Option<AvailabilityWindow>,
    pub picture: Option<PictureOptions>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolveRecipientsRequest<'a> {
    pub to: Vec<Cow<'a, str>>,
    pub options: ResolveRecipientsOptions,
}

impl<'a> ResolveRecipientsRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = ResolveRecipientsRequest::default();
        let mut counter = Counter::new(MAX_RESOLVE_RECIPIENTS);
        let mut children = Children::root(dec, rr::RESOLVE_RECIPIENTS)?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                rr::TO => {
                    counter.bump(tag)?;
                    request.to.push(read_id(dec, tag, MAX_RECIPIENT_LEN)?);
                }
                rr::OPTIONS => request.options = ResolveRecipientsOptions::parse(dec)?,
                _ => {}
            }
        }
        if request.to.is_empty() {
            return Err(CommandError::Missing { tag: rr::TO });
        }
        Ok(request)
    }
}

impl ResolveRecipientsOptions {
    fn parse(dec: &mut Decoder<'_>) -> Result<Self, CommandError> {
        let mut options = ResolveRecipientsOptions::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                rr::CERTIFICATE_RETRIEVAL => {
                    options.certificate_retrieval = Some(read_u8(dec, tag)?)
                }
                rr::MAX_CERTIFICATES => options.max_certificates = Some(read_u32(dec, tag)?),
                rr::MAX_AMBIGUOUS_RECIPIENTS => {
                    options.max_ambiguous_recipients = Some(read_u32(dec, tag)?)
                }
                rr::AVAILABILITY => {
                    let mut start_time = None;
                    let mut end_time = None;
                    let mut window = Children::of(dec);
                    while let Some(tag) = window.next(dec)? {
                        match tag {
                            rr::START_TIME => start_time = Some(read_date(dec, tag)?),
                            rr::END_TIME => end_time = Some(read_date(dec, tag)?),
                            _ => {}
                        }
                    }
                    options.availability = Some(AvailabilityWindow {
                        start_time: required(start_time, rr::START_TIME)?,
                        end_time,
                    });
                }
                rr::PICTURE => {
                    let mut picture = PictureOptions::default();
                    let mut fields = Children::of(dec);
                    while let Some(tag) = fields.next(dec)? {
                        match tag {
                            rr::MAX_SIZE => picture.max_size = Some(read_u32(dec, tag)?),
                            rr::MAX_PICTURES => picture.max_pictures = Some(read_u32(dec, tag)?),
                            _ => {}
                        }
                    }
                    options.picture = Some(picture);
                }
                _ => {}
            }
        }
        Ok(options)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientAvailability<'x> {
    pub status: ResolveRecipientsStatus,
    pub merged_free_busy: Option<&'x str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientCertificates<'x> {
    pub status: ResolveRecipientsStatus,
    pub certificate_count: Option<u32>,
    pub recipient_count: Option<u32>,
    pub certificates: Vec<&'x [u8]>,
    pub mini_certificate: Option<&'x [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientPicture<'x> {
    pub status: PictureStatus,
    pub data: Option<&'x [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient<'x> {
    pub recipient_type: u8,
    pub display_name: &'x str,
    pub email_address: &'x str,
    pub availability: Option<RecipientAvailability<'x>>,
    pub certificates: Option<RecipientCertificates<'x>>,
    pub pictures: Vec<RecipientPicture<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientResponse<'x> {
    pub to: &'x str,
    pub status: ResolveRecipientsStatus,
    pub recipient_count: Option<u32>,
    pub recipients: Vec<Recipient<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRecipientsResponse<'x> {
    pub status: ResolveRecipientsStatus,
    pub responses: Vec<RecipientResponse<'x>>,
}

impl ResolveRecipientsResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(rr::RESOLVE_RECIPIENTS)
            .text_u64(rr::STATUS, u64::from(self.status.0));
        for response in &self.responses {
            enc.start(rr::RESPONSE)
                .text_str(rr::TO, response.to)
                .text_u64(rr::STATUS, u64::from(response.status.0));
            if let Some(count) = response.recipient_count {
                enc.text_u64(rr::RECIPIENT_COUNT, u64::from(count));
            }
            for recipient in &response.recipients {
                recipient.encode(enc);
            }
            enc.end();
        }
        enc.end();
    }
}

impl Recipient<'_> {
    fn encode(&self, enc: &mut Encoder) {
        enc.start(rr::RECIPIENT)
            .text_u64(rr::TYPE, u64::from(self.recipient_type))
            .text_str(rr::DISPLAY_NAME, self.display_name)
            .text_str(rr::EMAIL_ADDRESS, self.email_address);
        if let Some(availability) = &self.availability
            && enc.allows(rr::AVAILABILITY)
        {
            enc.start(rr::AVAILABILITY)
                .text_u64(rr::STATUS, u64::from(availability.status.0));
            if let Some(merged) = availability.merged_free_busy {
                enc.text_str(rr::MERGED_FREE_BUSY, merged);
            }
            enc.end();
        }
        if let Some(certificates) = &self.certificates {
            enc.start(rr::CERTIFICATES)
                .text_u64(rr::STATUS, u64::from(certificates.status.0));
            if let Some(count) = certificates.certificate_count {
                enc.text_u64(rr::CERTIFICATE_COUNT, u64::from(count));
            }
            if let Some(count) = certificates.recipient_count {
                enc.text_u64(rr::RECIPIENT_COUNT, u64::from(count));
            }
            for certificate in &certificates.certificates {
                enc.text_base64(rr::CERTIFICATE, certificate);
            }
            if let Some(mini) = certificates.mini_certificate {
                enc.text_base64(rr::MINI_CERTIFICATE, mini);
            }
            enc.end();
        }
        if enc.allows(rr::PICTURE) {
            for picture in &self.pictures {
                enc.start(rr::PICTURE)
                    .text_u64(rr::STATUS, u64::from(picture.status.0));
                if let Some(data) = picture.data {
                    enc.opaque(rr::DATA, data);
                }
                enc.end();
            }
        }
        enc.end();
    }
}
