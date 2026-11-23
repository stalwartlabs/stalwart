/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::request::{
    deserialize::{CowStr, DeserializeArguments, deserialize_request},
    reference::MaybeIdReference,
};
use jmap_tools::{Key, Property};
use serde::{Deserialize, Deserializer, Serialize, ser::SerializeMap};
use std::borrow::Cow;
use types::id::Id;
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionMode {
    Manual,
    Automatic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendingMode {
    Manual,
    Automatic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispositionType {
    Deleted,
    Dispatched,
    Displayed,
    Processed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disposition {
    pub action_mode: ActionMode,
    pub sending_mode: SendingMode,
    pub disposition_type: DispositionType,
}

#[derive(Debug, Clone, Default)]
pub struct Mdn {
    pub for_email_id: Option<MaybeIdReference<Id>>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub include_original_message: bool,
    pub reporting_ua: Option<String>,
    pub disposition: Option<Disposition>,
    pub mdn_gateway: Option<String>,
    pub original_recipient: Option<String>,
    pub final_recipient: Option<String>,
    pub original_message_id: Option<String>,
    pub error: Option<Vec<String>>,
    pub extension_fields: Option<VecMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MdnProperty {
    ForEmailId,
    Subject,
    TextBody,
    IncludeOriginalMessage,
    ReportingUa,
    Disposition,
    MdnGateway,
    OriginalRecipient,
    FinalRecipient,
    OriginalMessageId,
    Error,
    ExtensionFields,
}

#[derive(Default)]
struct DispositionArguments {
    action_mode: Option<ActionMode>,
    sending_mode: Option<SendingMode>,
    disposition_type: Option<DispositionType>,
}

impl ActionMode {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), ActionMode,
            "manual-action" => ActionMode::Manual,
            "automatic-action" => ActionMode::Automatic,
        )
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ActionMode::Manual => "manual-action",
            ActionMode::Automatic => "automatic-action",
        }
    }
}

impl SendingMode {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), SendingMode,
            "mdn-sent-manually" => SendingMode::Manual,
            "mdn-sent-automatically" => SendingMode::Automatic,
        )
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SendingMode::Manual => "mdn-sent-manually",
            SendingMode::Automatic => "mdn-sent-automatically",
        }
    }

    pub fn as_field(&self) -> &'static str {
        match self {
            SendingMode::Manual => "MDN-sent-manually",
            SendingMode::Automatic => "MDN-sent-automatically",
        }
    }
}

impl DispositionType {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map_ignore_case!(value.as_bytes(), DispositionType,
            "deleted" => DispositionType::Deleted,
            "dispatched" => DispositionType::Dispatched,
            "displayed" => DispositionType::Displayed,
            "processed" => DispositionType::Processed,
        )
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DispositionType::Deleted => "deleted",
            DispositionType::Dispatched => "dispatched",
            DispositionType::Displayed => "displayed",
            DispositionType::Processed => "processed",
        }
    }
}

impl Disposition {
    pub fn manual(disposition_type: DispositionType) -> Self {
        Disposition {
            action_mode: ActionMode::Manual,
            sending_mode: SendingMode::Manual,
            disposition_type,
        }
    }

    pub fn is_automatic(&self) -> bool {
        self.sending_mode == SendingMode::Automatic
    }
}

impl MdnProperty {
    pub fn as_str(&self) -> &'static str {
        match self {
            MdnProperty::ForEmailId => "forEmailId",
            MdnProperty::Subject => "subject",
            MdnProperty::TextBody => "textBody",
            MdnProperty::IncludeOriginalMessage => "includeOriginalMessage",
            MdnProperty::ReportingUa => "reportingUA",
            MdnProperty::Disposition => "disposition",
            MdnProperty::MdnGateway => "mdnGateway",
            MdnProperty::OriginalRecipient => "originalRecipient",
            MdnProperty::FinalRecipient => "finalRecipient",
            MdnProperty::OriginalMessageId => "originalMessageId",
            MdnProperty::Error => "error",
            MdnProperty::ExtensionFields => "extensionFields",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        hashify::map!(value.as_bytes(), MdnProperty,
            "forEmailId" => MdnProperty::ForEmailId,
            "subject" => MdnProperty::Subject,
            "textBody" => MdnProperty::TextBody,
            "includeOriginalMessage" => MdnProperty::IncludeOriginalMessage,
            "reportingUA" => MdnProperty::ReportingUa,
            "disposition" => MdnProperty::Disposition,
            "mdnGateway" => MdnProperty::MdnGateway,
            "originalRecipient" => MdnProperty::OriginalRecipient,
            "finalRecipient" => MdnProperty::FinalRecipient,
            "originalMessageId" => MdnProperty::OriginalMessageId,
            "error" => MdnProperty::Error,
            "extensionFields" => MdnProperty::ExtensionFields,
        )
        .cloned()
    }
}

impl Property for MdnProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        MdnProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        Cow::Borrowed(self.as_str())
    }
}

impl<'de> DeserializeArguments<'de> for Mdn {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"forEmailId" => {
                self.for_email_id = map.next_value()?;
            },
            b"subject" => {
                self.subject = map.next_value()?;
            },
            b"textBody" => {
                self.text_body = map.next_value()?;
            },
            b"includeOriginalMessage" => {
                self.include_original_message = map.next_value::<Option<bool>>()?.unwrap_or_default();
            },
            b"reportingUA" => {
                self.reporting_ua = map.next_value()?;
            },
            b"disposition" => {
                self.disposition = map.next_value::<Option<DispositionArguments>>()?.and_then(DispositionArguments::into_disposition);
            },
            b"mdnGateway" => {
                self.mdn_gateway = map.next_value()?;
            },
            b"originalRecipient" => {
                self.original_recipient = map.next_value()?;
            },
            b"finalRecipient" => {
                self.final_recipient = map.next_value()?;
            },
            b"originalMessageId" => {
                self.original_message_id = map.next_value()?;
            },
            b"error" => {
                self.error = map.next_value()?;
            },
            b"extensionFields" => {
                self.extension_fields = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for Mdn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl DispositionArguments {
    fn into_disposition(self) -> Option<Disposition> {
        Some(Disposition {
            action_mode: self.action_mode?,
            sending_mode: self.sending_mode?,
            disposition_type: self.disposition_type?,
        })
    }
}

impl<'de> DeserializeArguments<'de> for DispositionArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"actionMode" => {
                self.action_mode = ActionMode::parse(&map.next_value::<CowStr<'de>>()?.0);
            },
            b"sendingMode" => {
                self.sending_mode = SendingMode::parse(&map.next_value::<CowStr<'de>>()?.0);
            },
            b"type" => {
                self.disposition_type = DispositionType::parse(&map.next_value::<CowStr<'de>>()?.0);
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for DispositionArguments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl Serialize for Disposition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("actionMode", self.action_mode.as_str())?;
        map.serialize_entry("sendingMode", self.sending_mode.as_str())?;
        map.serialize_entry("type", self.disposition_type.as_str())?;
        map.end()
    }
}

impl Serialize for Mdn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        if let Some(value) = &self.for_email_id {
            map.serialize_entry(MdnProperty::ForEmailId.as_str(), value)?;
        }
        if let Some(value) = &self.subject {
            map.serialize_entry(MdnProperty::Subject.as_str(), value)?;
        }
        if let Some(value) = &self.text_body {
            map.serialize_entry(MdnProperty::TextBody.as_str(), value)?;
        }
        if self.include_original_message {
            map.serialize_entry(MdnProperty::IncludeOriginalMessage.as_str(), &true)?;
        }
        if let Some(value) = &self.reporting_ua {
            map.serialize_entry(MdnProperty::ReportingUa.as_str(), value)?;
        }
        if let Some(value) = &self.disposition {
            map.serialize_entry(MdnProperty::Disposition.as_str(), value)?;
        }
        if let Some(value) = &self.mdn_gateway {
            map.serialize_entry(MdnProperty::MdnGateway.as_str(), value)?;
        }
        if let Some(value) = &self.original_recipient {
            map.serialize_entry(MdnProperty::OriginalRecipient.as_str(), value)?;
        }
        if let Some(value) = &self.final_recipient {
            map.serialize_entry(MdnProperty::FinalRecipient.as_str(), value)?;
        }
        if let Some(value) = &self.original_message_id {
            map.serialize_entry(MdnProperty::OriginalMessageId.as_str(), value)?;
        }
        if let Some(value) = &self.error {
            map.serialize_entry(MdnProperty::Error.as_str(), value)?;
        }
        if let Some(value) = &self.extension_fields {
            map.serialize_entry(MdnProperty::ExtensionFields.as_str(), value)?;
        }
        map.end()
    }
}
