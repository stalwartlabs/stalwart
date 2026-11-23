/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use smallvec::SmallVec;

use super::appdata::rights::RightsManagementTemplate;
use super::appdata::{Empty, List, MAX_LIST_ITEMS, Value, eas_struct};
use super::{Children, CommandError, read_str};
use crate::eas::status::SettingsStatus;
use crate::eas::tokens::tag::{rights_management as rm, settings as st};
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::types::EasDateTime;
use crate::eas::wbxml::{DecodeError, Decoder, Encoder};

pub const MAX_SETTINGS_ACTIONS: usize = 16;
pub const MAX_OOF_MESSAGES: usize = 3;
pub const MAX_PASSWORD_LEN: usize = 255;

pub type Accounts<'a> = List<Account<'a>, { st::ACCOUNT.raw() }>;
pub type RightsManagementTemplates<'a> =
    List<RightsManagementTemplate<'a>, { rm::RIGHTS_MANAGEMENT_TEMPLATE.raw() }>;

eas_struct!(DeviceInformationSet<'a> {
    model: Cow<'a, str> = st::MODEL,
    imei: Cow<'a, str> = st::IMEI,
    friendly_name: Cow<'a, str> = st::FRIENDLY_NAME,
    os: Cow<'a, str> = st::OS,
    os_language: Cow<'a, str> = st::OS_LANGUAGE,
    phone_number: Cow<'a, str> = st::PHONE_NUMBER,
    user_agent: Cow<'a, str> = st::USER_AGENT,
    enable_outbound_sms: u8 = st::ENABLE_OUTBOUND_SMS,
    mobile_operator: Cow<'a, str> = st::MOBILE_OPERATOR,
});

eas_struct!(DeviceInformation<'a> {
    set: DeviceInformationSet<'a> = st::SET,
});

eas_struct!(OofMessage<'a> {
    applies_to_internal: Empty = st::APPLIES_TO_INTERNAL,
    applies_to_external_known: Empty = st::APPLIES_TO_EXTERNAL_KNOWN,
    applies_to_external_unknown: Empty = st::APPLIES_TO_EXTERNAL_UNKNOWN,
    enabled: Cow<'a, str> = st::ENABLED,
    reply_message: Cow<'a, str> = st::REPLY_MESSAGE,
    body_type: Cow<'a, str> = st::BODY_TYPE,
});

eas_struct!(Account<'a> {
    account_id: Cow<'a, str> = st::ACCOUNT_ID,
    account_name: Cow<'a, str> = st::ACCOUNT_NAME,
    user_display_name: Cow<'a, str> = st::USER_DISPLAY_NAME,
    send_disabled: bool = st::SEND_DISABLED,
    email_addresses: EmailAddresses<'a> = st::EMAIL_ADDRESSES,
});

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OofSettings<'a> {
    pub state: Option<u8>,
    pub start_time: Option<EasDateTime>,
    pub end_time: Option<EasDateTime>,
    pub messages: SmallVec<[OofMessage<'a>; 3]>,
}

impl<'a> Value<'a> for OofSettings<'a> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        let mut oof = OofSettings::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                st::OOF_STATE => oof.state = Some(u8::decode(dec)?),
                st::START_TIME => oof.start_time = Some(EasDateTime::decode(dec)?),
                st::END_TIME => oof.end_time = Some(EasDateTime::decode(dec)?),
                st::OOF_MESSAGE => {
                    if oof.messages.len() >= MAX_OOF_MESSAGES {
                        return Err(DecodeError::InvalidValue {
                            offset: dec.offset(),
                        });
                    }
                    oof.messages.push(OofMessage::decode(dec)?);
                }
                _ => {}
            }
        }
        Ok(oof)
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.start(tag);
        if let Some(state) = self.state {
            state.encode(enc, st::OOF_STATE);
        }
        if let Some(start_time) = &self.start_time {
            start_time.encode(enc, st::START_TIME);
        }
        if let Some(end_time) = &self.end_time {
            end_time.encode(enc, st::END_TIME);
        }
        for message in &self.messages {
            message.encode(enc, st::OOF_MESSAGE);
        }
        enc.end();
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmailAddresses<'a> {
    pub smtp_addresses: Vec<Cow<'a, str>>,
    pub primary_smtp_address: Option<Cow<'a, str>>,
}

impl<'a> Value<'a> for EmailAddresses<'a> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        let mut addresses = EmailAddresses::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                st::SMTP_ADDRESS => {
                    if addresses.smtp_addresses.len() >= MAX_LIST_ITEMS {
                        return Err(DecodeError::InvalidValue {
                            offset: dec.offset(),
                        });
                    }
                    addresses.smtp_addresses.push(dec.str()?);
                }
                st::PRIMARY_SMTP_ADDRESS => addresses.primary_smtp_address = Some(dec.str()?),
                _ => {}
            }
        }
        Ok(addresses)
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.start(tag);
        for address in &self.smtp_addresses {
            enc.text_str(st::SMTP_ADDRESS, address);
        }
        if let Some(primary) = &self.primary_smtp_address
            && enc.allows(st::PRIMARY_SMTP_ADDRESS)
        {
            enc.text_str(st::PRIMARY_SMTP_ADDRESS, primary);
        }
        enc.end();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SettingsAction<'a> {
    OofGet { body_type: Cow<'a, str> },
    OofSet(OofSettings<'a>),
    DevicePasswordSet { password: Cow<'a, str> },
    DevicePasswordTooLong,
    DeviceInformationSet(DeviceInformationSet<'a>),
    UserInformationGet,
    RightsManagementInformationGet,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettingsRequest<'a> {
    pub actions: Vec<SettingsAction<'a>>,
}

impl<'a> SettingsRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = SettingsRequest::default();
        let mut children = Children::root(dec, st::SETTINGS)?;
        while let Some(tag) = children.next(dec)? {
            let action = match tag {
                st::OOF => parse_oof(dec)?,
                st::DEVICE_PASSWORD => parse_device_password(dec)?,
                st::DEVICE_INFORMATION => {
                    let info = DeviceInformation::decode(dec)
                        .map_err(|err| CommandError::value(err, tag))?;
                    info.set.map(SettingsAction::DeviceInformationSet)
                }
                st::USER_INFORMATION => {
                    expect_get(dec)?.then_some(SettingsAction::UserInformationGet)
                }
                st::RIGHTS_MANAGEMENT_INFORMATION => {
                    expect_get(dec)?.then_some(SettingsAction::RightsManagementInformationGet)
                }
                _ => continue,
            };
            let action = action.ok_or(CommandError::Missing { tag })?;
            if request.actions.len() >= MAX_SETTINGS_ACTIONS {
                return Err(CommandError::TooMany {
                    tag,
                    limit: MAX_SETTINGS_ACTIONS as u32,
                });
            }
            request.actions.push(action);
        }
        Ok(request)
    }
}

fn expect_get(dec: &mut Decoder<'_>) -> Result<bool, CommandError> {
    let mut found = false;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        found |= tag == st::GET;
    }
    Ok(found)
}

fn parse_oof<'a>(dec: &mut Decoder<'a>) -> Result<Option<SettingsAction<'a>>, CommandError> {
    let mut action = None;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        match tag {
            st::GET => {
                let mut body_type = None;
                let mut get = Children::of(dec);
                while let Some(tag) = get.next(dec)? {
                    if tag == st::BODY_TYPE {
                        body_type = Some(read_str(dec, tag)?);
                    }
                }
                action = Some(SettingsAction::OofGet {
                    body_type: body_type.ok_or(CommandError::Missing { tag: st::BODY_TYPE })?,
                });
            }
            st::SET => {
                action = Some(SettingsAction::OofSet(
                    OofSettings::decode(dec).map_err(|err| CommandError::value(err, tag))?,
                ))
            }
            _ => {}
        }
    }
    Ok(action)
}

fn parse_device_password<'a>(
    dec: &mut Decoder<'a>,
) -> Result<Option<SettingsAction<'a>>, CommandError> {
    let mut action = None;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        if tag != st::SET {
            continue;
        }
        let mut set = Children::of(dec);
        while let Some(tag) = set.next(dec)? {
            if tag == st::PASSWORD {
                let password = read_str(dec, tag)?;
                action = Some(if password.len() > MAX_PASSWORD_LEN {
                    SettingsAction::DevicePasswordTooLong
                } else {
                    SettingsAction::DevicePasswordSet { password }
                });
            }
        }
    }
    Ok(action)
}

#[derive(Debug, Clone, PartialEq)]
pub enum SettingsResult<'x> {
    Oof {
        status: SettingsStatus,
        get: Option<Box<OofSettings<'x>>>,
    },
    DeviceInformation {
        status: SettingsStatus,
    },
    DevicePassword {
        status: SettingsStatus,
    },
    UserInformation {
        status: SettingsStatus,
        email_addresses: Option<EmailAddresses<'x>>,
        accounts: Option<Accounts<'x>>,
    },
    RightsManagementInformation {
        status: SettingsStatus,
        templates: Option<RightsManagementTemplates<'x>>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettingsResponse<'x> {
    pub status: SettingsStatus,
    pub results: Vec<SettingsResult<'x>>,
}

impl SettingsResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(st::SETTINGS)
            .text_u64(st::STATUS, u64::from(self.status.0));
        for result in &self.results {
            result.encode(enc);
        }
        enc.end();
    }
}

impl SettingsResult<'_> {
    fn encode(&self, enc: &mut Encoder) {
        match self {
            SettingsResult::Oof { status, get } => {
                enc.start(st::OOF).text_u64(st::STATUS, u64::from(status.0));
                if let Some(get) = get {
                    get.encode(enc, st::GET);
                }
                enc.end();
            }
            SettingsResult::DeviceInformation { status } => {
                encode_status(enc, st::DEVICE_INFORMATION, *status)
            }
            SettingsResult::DevicePassword { status } => {
                encode_status(enc, st::DEVICE_PASSWORD, *status)
            }
            SettingsResult::UserInformation {
                status,
                email_addresses,
                accounts,
            } => {
                enc.start(st::USER_INFORMATION)
                    .text_u64(st::STATUS, u64::from(status.0));
                if email_addresses.is_some() || accounts.is_some() {
                    enc.start(st::GET);
                    if let Some(email_addresses) = email_addresses {
                        email_addresses.encode(enc, st::EMAIL_ADDRESSES);
                    }
                    if let Some(accounts) = accounts
                        && enc.allows(st::ACCOUNTS)
                    {
                        accounts.encode(enc, st::ACCOUNTS);
                    }
                    enc.end();
                }
                enc.end();
            }
            SettingsResult::RightsManagementInformation { status, templates } => {
                if !enc.allows(st::RIGHTS_MANAGEMENT_INFORMATION) {
                    return;
                }
                enc.start(st::RIGHTS_MANAGEMENT_INFORMATION)
                    .text_u64(st::STATUS, u64::from(status.0));
                enc.start(st::GET);
                match templates {
                    Some(templates) => templates.encode(enc, rm::RIGHTS_MANAGEMENT_TEMPLATES),
                    None => {
                        enc.empty(rm::RIGHTS_MANAGEMENT_TEMPLATES);
                    }
                }
                enc.end().end();
            }
        }
    }
}

fn encode_status(enc: &mut Encoder, tag: Tag, status: SettingsStatus) {
    enc.start(tag)
        .text_u64(st::STATUS, u64::from(status.0))
        .end();
}
