/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::appdata::{List, OrEmpty, Value, eas_struct};
use super::settings::{DeviceInformation, DeviceInformationSet};
use super::{Children, CommandError, read_str, read_u8, read_u32, required};
use crate::eas::status::{PolicyStatus, ProvisionStatus, SettingsStatus};
use crate::eas::tokens::ProtocolVersion;
use crate::eas::tokens::tag::{provision as pv, settings as st};
use crate::eas::wbxml::{Decoder, Encoder};

pub const POLICY_TYPE_WBXML: &str = "MS-EAS-Provisioning-WBXML";

pub type ApplicationNames<'a> = List<Cow<'a, str>, { pv::APPLICATION_NAME.raw() }>;
pub type ApplicationHashes<'a> = List<Cow<'a, str>, { pv::HASH.raw() }>;

eas_struct!(PolicyDoc<'a> {
    device_password_enabled: bool = pv::DEVICE_PASSWORD_ENABLED,
    alphanumeric_device_password_required: bool = pv::ALPHANUMERIC_DEVICE_PASSWORD_REQUIRED,
    password_recovery_enabled: bool = pv::PASSWORD_RECOVERY_ENABLED,
    require_storage_card_encryption: bool = pv::REQUIRE_STORAGE_CARD_ENCRYPTION,
    attachments_enabled: bool = pv::ATTACHMENTS_ENABLED,
    min_device_password_length: OrEmpty<u8> = pv::MIN_DEVICE_PASSWORD_LENGTH,
    max_inactivity_time_device_lock: OrEmpty<u32> = pv::MAX_INACTIVITY_TIME_DEVICE_LOCK,
    max_device_password_failed_attempts: OrEmpty<u8> = pv::MAX_DEVICE_PASSWORD_FAILED_ATTEMPTS,
    max_attachment_size: OrEmpty<u32> = pv::MAX_ATTACHMENT_SIZE,
    allow_simple_device_password: bool = pv::ALLOW_SIMPLE_DEVICE_PASSWORD,
    device_password_expiration: OrEmpty<u32> = pv::DEVICE_PASSWORD_EXPIRATION,
    device_password_history: u32 = pv::DEVICE_PASSWORD_HISTORY,
    allow_storage_card: bool = pv::ALLOW_STORAGE_CARD,
    allow_camera: bool = pv::ALLOW_CAMERA,
    require_device_encryption: bool = pv::REQUIRE_DEVICE_ENCRYPTION,
    allow_unsigned_applications: bool = pv::ALLOW_UNSIGNED_APPLICATIONS,
    allow_unsigned_installation_packages: bool = pv::ALLOW_UNSIGNED_INSTALLATION_PACKAGES,
    min_device_password_complex_characters: u8 = pv::MIN_DEVICE_PASSWORD_COMPLEX_CHARACTERS,
    allow_wi_fi: bool = pv::ALLOW_WI_FI,
    allow_text_messaging: bool = pv::ALLOW_TEXT_MESSAGING,
    allow_popimap_email: bool = pv::ALLOW_POPIMAP_EMAIL,
    allow_bluetooth: u8 = pv::ALLOW_BLUETOOTH,
    allow_ir_da: bool = pv::ALLOW_IR_DA,
    require_manual_sync_when_roaming: bool = pv::REQUIRE_MANUAL_SYNC_WHEN_ROAMING,
    allow_desktop_sync: bool = pv::ALLOW_DESKTOP_SYNC,
    max_calendar_age_filter: u32 = pv::MAX_CALENDAR_AGE_FILTER,
    allow_html_email: bool = pv::ALLOW_HTML_EMAIL,
    max_email_age_filter: u32 = pv::MAX_EMAIL_AGE_FILTER,
    max_email_body_truncation_size: i32 = pv::MAX_EMAIL_BODY_TRUNCATION_SIZE,
    max_email_html_body_truncation_size: i32 = pv::MAX_EMAIL_HTML_BODY_TRUNCATION_SIZE,
    require_signed_smime_messages: bool = pv::REQUIRE_SIGNED_SMIME_MESSAGES,
    require_encrypted_smime_messages: bool = pv::REQUIRE_ENCRYPTED_SMIME_MESSAGES,
    require_signed_smime_algorithm: i32 = pv::REQUIRE_SIGNED_SMIME_ALGORITHM,
    require_encryption_smime_algorithm: i32 = pv::REQUIRE_ENCRYPTION_SMIME_ALGORITHM,
    allow_smime_encryption_algorithm_negotiation: i32 = pv::ALLOW_SMIME_ENCRYPTION_ALGORITHM_NEGOTIATION,
    allow_smime_soft_certs: bool = pv::ALLOW_SMIME_SOFT_CERTS,
    allow_browser: bool = pv::ALLOW_BROWSER,
    allow_consumer_email: bool = pv::ALLOW_CONSUMER_EMAIL,
    allow_remote_desktop: bool = pv::ALLOW_REMOTE_DESKTOP,
    allow_internet_sharing: bool = pv::ALLOW_INTERNET_SHARING,
    unapproved_in_rom_application_list: ApplicationNames<'a> = pv::UNAPPROVED_IN_ROM_APPLICATION_LIST,
    approved_application_list: ApplicationHashes<'a> = pv::APPROVED_APPLICATION_LIST,
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest<'a> {
    pub policy_type: Cow<'a, str>,
    pub policy_key: Option<u32>,
    pub status: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProvisionRequest<'a> {
    pub device_information: Option<DeviceInformationSet<'a>>,
    pub policy: Option<PolicyRequest<'a>>,
    pub remote_wipe: Option<u8>,
    pub account_only_remote_wipe: Option<u8>,
}

impl<'a> ProvisionRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = ProvisionRequest::default();
        let mut children = Children::root(dec, pv::PROVISION)?;
        while let Some(tag) = children.next(dec)? {
            match tag {
                st::DEVICE_INFORMATION => {
                    request.device_information = DeviceInformation::decode(dec)
                        .map_err(|err| CommandError::value(err, tag))?
                        .set
                }
                pv::POLICIES => {
                    let mut policies = Children::of(dec);
                    while let Some(tag) = policies.next(dec)? {
                        if tag == pv::POLICY {
                            request.policy = Some(PolicyRequest::parse(dec)?);
                        }
                    }
                }
                pv::REMOTE_WIPE => request.remote_wipe = Some(read_wipe_status(dec)?),
                pv::ACCOUNT_ONLY_REMOTE_WIPE => {
                    request.account_only_remote_wipe = Some(read_wipe_status(dec)?)
                }
                pv::POLICY => return Err(CommandError::NotSupported { tag }),
                _ => {}
            }
        }
        Ok(request)
    }
}

fn read_wipe_status(dec: &mut Decoder<'_>) -> Result<u8, CommandError> {
    let mut status = None;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        if tag == pv::STATUS {
            status = Some(read_u8(dec, tag)?);
        }
    }
    required(status, pv::STATUS)
}

impl<'a> PolicyRequest<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut policy_type = None;
        let mut policy_key = None;
        let mut status = None;
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                pv::POLICY_TYPE => policy_type = Some(read_str(dec, tag)?),
                pv::POLICY_KEY => policy_key = Some(read_u32(dec, tag)?),
                pv::STATUS => status = Some(read_u8(dec, tag)?),
                _ => {}
            }
        }
        Ok(PolicyRequest {
            policy_type: required(policy_type, pv::POLICY_TYPE)?,
            policy_key,
            status,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyResponse<'x> {
    pub policy_type: &'x str,
    pub status: PolicyStatus,
    pub policy_key: Option<u32>,
    pub document: Option<PolicyDoc<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionResponse<'x> {
    pub device_information: Option<SettingsStatus>,
    pub status: ProvisionStatus,
    pub policy: Option<PolicyResponse<'x>>,
    pub remote_wipe: bool,
    pub account_only_remote_wipe: bool,
}

impl ProvisionResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(pv::PROVISION);
        if let Some(status) = self.device_information {
            enc.start(st::DEVICE_INFORMATION)
                .text_u64(st::STATUS, u64::from(status.0))
                .end();
        }
        enc.text_u64(pv::STATUS, u64::from(self.status.0));
        if let Some(policy) = &self.policy {
            enc.start(pv::POLICIES)
                .start(pv::POLICY)
                .text_str(pv::POLICY_TYPE, policy.policy_type)
                .text_u64(pv::STATUS, u64::from(policy.status.0));
            if let Some(policy_key) = policy.policy_key {
                enc.text_u64(pv::POLICY_KEY, u64::from(policy_key));
            }
            if let Some(document) = &policy.document {
                enc.start(pv::DATA);
                document.encode(enc, pv::EAS_PROVISION_DOC);
                enc.end();
            }
            enc.end().end();
        }
        if self.remote_wipe {
            enc.empty(pv::REMOTE_WIPE);
        }
        if self.account_only_remote_wipe && enc.allows(pv::ACCOUNT_ONLY_REMOTE_WIPE) {
            enc.empty(pv::ACCOUNT_ONLY_REMOTE_WIPE);
        }
        enc.end();
    }
}
