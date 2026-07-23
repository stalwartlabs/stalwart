/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

use crate::schema::prelude::*;

impl EnumImpl for AccountType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"User" => AccountType::User,
            b"Group" => AccountType::Group,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AccountType::User => "User",
            AccountType::Group => "Group",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AccountType::User),
            1 => Some(AccountType::Group),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for AccountType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AccountType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for AcmeChallengeType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"TlsAlpn01" => AcmeChallengeType::TlsAlpn01,
            b"DnsPersist01" => AcmeChallengeType::DnsPersist01,
            b"Dns01" => AcmeChallengeType::Dns01,
            b"Http01" => AcmeChallengeType::Http01,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AcmeChallengeType::TlsAlpn01 => "TlsAlpn01",
            AcmeChallengeType::DnsPersist01 => "DnsPersist01",
            AcmeChallengeType::Dns01 => "Dns01",
            AcmeChallengeType::Http01 => "Http01",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AcmeChallengeType::TlsAlpn01),
            1 => Some(AcmeChallengeType::DnsPersist01),
            2 => Some(AcmeChallengeType::Dns01),
            3 => Some(AcmeChallengeType::Http01),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for AcmeChallengeType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AcmeChallengeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for AcmeRenewBefore {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"R12" => AcmeRenewBefore::R12,
            b"R23" => AcmeRenewBefore::R23,
            b"R34" => AcmeRenewBefore::R34,
            b"R45" => AcmeRenewBefore::R45,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AcmeRenewBefore::R12 => "R12",
            AcmeRenewBefore::R23 => "R23",
            AcmeRenewBefore::R34 => "R34",
            AcmeRenewBefore::R45 => "R45",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AcmeRenewBefore::R12),
            1 => Some(AcmeRenewBefore::R23),
            2 => Some(AcmeRenewBefore::R34),
            3 => Some(AcmeRenewBefore::R45),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for AcmeRenewBefore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AcmeRenewBefore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ActionType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"ReloadSettings" => ActionType::ReloadSettings,
            b"ReloadTlsCertificates" => ActionType::ReloadTlsCertificates,
            b"ReloadLookupStores" => ActionType::ReloadLookupStores,
            b"ReloadBlockedIps" => ActionType::ReloadBlockedIps,
            b"UpdateApps" => ActionType::UpdateApps,
            b"TroubleshootDmarc" => ActionType::TroubleshootDmarc,
            b"ClassifySpam" => ActionType::ClassifySpam,
            b"InvalidateCaches" => ActionType::InvalidateCaches,
            b"InvalidateNegativeCaches" => ActionType::InvalidateNegativeCaches,
            b"PauseMtaQueue" => ActionType::PauseMtaQueue,
            b"ResumeMtaQueue" => ActionType::ResumeMtaQueue,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ActionType::ReloadSettings => "ReloadSettings",
            ActionType::ReloadTlsCertificates => "ReloadTlsCertificates",
            ActionType::ReloadLookupStores => "ReloadLookupStores",
            ActionType::ReloadBlockedIps => "ReloadBlockedIps",
            ActionType::UpdateApps => "UpdateApps",
            ActionType::TroubleshootDmarc => "TroubleshootDmarc",
            ActionType::ClassifySpam => "ClassifySpam",
            ActionType::InvalidateCaches => "InvalidateCaches",
            ActionType::InvalidateNegativeCaches => "InvalidateNegativeCaches",
            ActionType::PauseMtaQueue => "PauseMtaQueue",
            ActionType::ResumeMtaQueue => "ResumeMtaQueue",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ActionType::ReloadSettings),
            1 => Some(ActionType::ReloadTlsCertificates),
            2 => Some(ActionType::ReloadLookupStores),
            3 => Some(ActionType::ReloadBlockedIps),
            4 => Some(ActionType::UpdateApps),
            5 => Some(ActionType::TroubleshootDmarc),
            6 => Some(ActionType::ClassifySpam),
            7 => Some(ActionType::InvalidateCaches),
            8 => Some(ActionType::InvalidateNegativeCaches),
            9 => Some(ActionType::PauseMtaQueue),
            10 => Some(ActionType::ResumeMtaQueue),
            _ => None,
        }
    }

    const COUNT: usize = 11;
}

impl serde::Serialize for ActionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ActionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for AiModelType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Chat" => AiModelType::Chat,
            b"Text" => AiModelType::Text,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AiModelType::Chat => "Chat",
            AiModelType::Text => "Text",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AiModelType::Chat),
            1 => Some(AiModelType::Text),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for AiModelType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AiModelType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for AlertEmailType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => AlertEmailType::Disabled,
            b"Enabled" => AlertEmailType::Enabled,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AlertEmailType::Disabled => "Disabled",
            AlertEmailType::Enabled => "Enabled",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AlertEmailType::Disabled),
            1 => Some(AlertEmailType::Enabled),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for AlertEmailType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AlertEmailType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for AlertEventType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => AlertEventType::Disabled,
            b"Enabled" => AlertEventType::Enabled,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AlertEventType::Disabled => "Disabled",
            AlertEventType::Enabled => "Enabled",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AlertEventType::Disabled),
            1 => Some(AlertEventType::Enabled),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for AlertEventType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AlertEventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ArchivedItemStatus {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"archived" => ArchivedItemStatus::Archived,
            b"requestRestore" => ArchivedItemStatus::RequestRestore,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ArchivedItemStatus::Archived => "archived",
            ArchivedItemStatus::RequestRestore => "requestRestore",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ArchivedItemStatus::Archived),
            1 => Some(ArchivedItemStatus::RequestRestore),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for ArchivedItemStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ArchivedItemStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ArchivedItemType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Email" => ArchivedItemType::Email,
            b"FileNode" => ArchivedItemType::FileNode,
            b"CalendarEvent" => ArchivedItemType::CalendarEvent,
            b"ContactCard" => ArchivedItemType::ContactCard,
            b"SieveScript" => ArchivedItemType::SieveScript,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ArchivedItemType::Email => "Email",
            ArchivedItemType::FileNode => "FileNode",
            ArchivedItemType::CalendarEvent => "CalendarEvent",
            ArchivedItemType::ContactCard => "ContactCard",
            ArchivedItemType::SieveScript => "SieveScript",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ArchivedItemType::Email),
            1 => Some(ArchivedItemType::FileNode),
            2 => Some(ArchivedItemType::CalendarEvent),
            3 => Some(ArchivedItemType::ContactCard),
            4 => Some(ArchivedItemType::SieveScript),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for ArchivedItemType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ArchivedItemType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ArfAuthFailureType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"adsp" => ArfAuthFailureType::Adsp,
            b"bodyHash" => ArfAuthFailureType::BodyHash,
            b"revoked" => ArfAuthFailureType::Revoked,
            b"signature" => ArfAuthFailureType::Signature,
            b"spf" => ArfAuthFailureType::Spf,
            b"dmarc" => ArfAuthFailureType::Dmarc,
            b"unspecified" => ArfAuthFailureType::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ArfAuthFailureType::Adsp => "adsp",
            ArfAuthFailureType::BodyHash => "bodyHash",
            ArfAuthFailureType::Revoked => "revoked",
            ArfAuthFailureType::Signature => "signature",
            ArfAuthFailureType::Spf => "spf",
            ArfAuthFailureType::Dmarc => "dmarc",
            ArfAuthFailureType::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ArfAuthFailureType::Adsp),
            1 => Some(ArfAuthFailureType::BodyHash),
            2 => Some(ArfAuthFailureType::Revoked),
            3 => Some(ArfAuthFailureType::Signature),
            4 => Some(ArfAuthFailureType::Spf),
            5 => Some(ArfAuthFailureType::Dmarc),
            6 => Some(ArfAuthFailureType::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for ArfAuthFailureType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ArfAuthFailureType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ArfDeliveryResult {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"delivered" => ArfDeliveryResult::Delivered,
            b"spam" => ArfDeliveryResult::Spam,
            b"policy" => ArfDeliveryResult::Policy,
            b"reject" => ArfDeliveryResult::Reject,
            b"other" => ArfDeliveryResult::Other,
            b"unspecified" => ArfDeliveryResult::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ArfDeliveryResult::Delivered => "delivered",
            ArfDeliveryResult::Spam => "spam",
            ArfDeliveryResult::Policy => "policy",
            ArfDeliveryResult::Reject => "reject",
            ArfDeliveryResult::Other => "other",
            ArfDeliveryResult::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ArfDeliveryResult::Delivered),
            1 => Some(ArfDeliveryResult::Spam),
            2 => Some(ArfDeliveryResult::Policy),
            3 => Some(ArfDeliveryResult::Reject),
            4 => Some(ArfDeliveryResult::Other),
            5 => Some(ArfDeliveryResult::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for ArfDeliveryResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ArfDeliveryResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ArfFeedbackType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"abuse" => ArfFeedbackType::Abuse,
            b"authFailure" => ArfFeedbackType::AuthFailure,
            b"fraud" => ArfFeedbackType::Fraud,
            b"notSpam" => ArfFeedbackType::NotSpam,
            b"virus" => ArfFeedbackType::Virus,
            b"other" => ArfFeedbackType::Other,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ArfFeedbackType::Abuse => "abuse",
            ArfFeedbackType::AuthFailure => "authFailure",
            ArfFeedbackType::Fraud => "fraud",
            ArfFeedbackType::NotSpam => "notSpam",
            ArfFeedbackType::Virus => "virus",
            ArfFeedbackType::Other => "other",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ArfFeedbackType::Abuse),
            1 => Some(ArfFeedbackType::AuthFailure),
            2 => Some(ArfFeedbackType::Fraud),
            3 => Some(ArfFeedbackType::NotSpam),
            4 => Some(ArfFeedbackType::Virus),
            5 => Some(ArfFeedbackType::Other),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for ArfFeedbackType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ArfFeedbackType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ArfIdentityAlignment {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"none" => ArfIdentityAlignment::None,
            b"spf" => ArfIdentityAlignment::Spf,
            b"dkim" => ArfIdentityAlignment::Dkim,
            b"dkimSpf" => ArfIdentityAlignment::DkimSpf,
            b"unspecified" => ArfIdentityAlignment::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ArfIdentityAlignment::None => "none",
            ArfIdentityAlignment::Spf => "spf",
            ArfIdentityAlignment::Dkim => "dkim",
            ArfIdentityAlignment::DkimSpf => "dkimSpf",
            ArfIdentityAlignment::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ArfIdentityAlignment::None),
            1 => Some(ArfIdentityAlignment::Spf),
            2 => Some(ArfIdentityAlignment::Dkim),
            3 => Some(ArfIdentityAlignment::DkimSpf),
            4 => Some(ArfIdentityAlignment::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for ArfIdentityAlignment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ArfIdentityAlignment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for AsnType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => AsnType::Disabled,
            b"Resource" => AsnType::Resource,
            b"Dns" => AsnType::Dns,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AsnType::Disabled => "Disabled",
            AsnType::Resource => "Resource",
            AsnType::Dns => "Dns",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AsnType::Disabled),
            1 => Some(AsnType::Resource),
            2 => Some(AsnType::Dns),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for AsnType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AsnType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for AzureEnvironment {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"public" => AzureEnvironment::Public,
            b"china" => AzureEnvironment::China,
            b"us-government" => AzureEnvironment::UsGovernment,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            AzureEnvironment::Public => "public",
            AzureEnvironment::China => "china",
            AzureEnvironment::UsGovernment => "us-government",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(AzureEnvironment::Public),
            1 => Some(AzureEnvironment::China),
            2 => Some(AzureEnvironment::UsGovernment),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for AzureEnvironment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AzureEnvironment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for BlobStoreBaseType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"S3" => BlobStoreBaseType::S3,
            b"Azure" => BlobStoreBaseType::Azure,
            b"FileSystem" => BlobStoreBaseType::FileSystem,
            b"FoundationDb" => BlobStoreBaseType::FoundationDb,
            b"PostgreSql" => BlobStoreBaseType::PostgreSql,
            b"MySql" => BlobStoreBaseType::MySql,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            BlobStoreBaseType::S3 => "S3",
            BlobStoreBaseType::Azure => "Azure",
            BlobStoreBaseType::FileSystem => "FileSystem",
            BlobStoreBaseType::FoundationDb => "FoundationDb",
            BlobStoreBaseType::PostgreSql => "PostgreSql",
            BlobStoreBaseType::MySql => "MySql",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(BlobStoreBaseType::S3),
            1 => Some(BlobStoreBaseType::Azure),
            2 => Some(BlobStoreBaseType::FileSystem),
            3 => Some(BlobStoreBaseType::FoundationDb),
            4 => Some(BlobStoreBaseType::PostgreSql),
            5 => Some(BlobStoreBaseType::MySql),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for BlobStoreBaseType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for BlobStoreBaseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for BlobStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Default" => BlobStoreType::Default,
            b"Sharded" => BlobStoreType::Sharded,
            b"S3" => BlobStoreType::S3,
            b"Azure" => BlobStoreType::Azure,
            b"FileSystem" => BlobStoreType::FileSystem,
            b"FoundationDb" => BlobStoreType::FoundationDb,
            b"PostgreSql" => BlobStoreType::PostgreSql,
            b"MySql" => BlobStoreType::MySql,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            BlobStoreType::Default => "Default",
            BlobStoreType::Sharded => "Sharded",
            BlobStoreType::S3 => "S3",
            BlobStoreType::Azure => "Azure",
            BlobStoreType::FileSystem => "FileSystem",
            BlobStoreType::FoundationDb => "FoundationDb",
            BlobStoreType::PostgreSql => "PostgreSql",
            BlobStoreType::MySql => "MySql",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(BlobStoreType::Default),
            1 => Some(BlobStoreType::Sharded),
            2 => Some(BlobStoreType::S3),
            3 => Some(BlobStoreType::Azure),
            4 => Some(BlobStoreType::FileSystem),
            5 => Some(BlobStoreType::FoundationDb),
            6 => Some(BlobStoreType::PostgreSql),
            7 => Some(BlobStoreType::MySql),
            _ => None,
        }
    }

    const COUNT: usize = 8;
}

impl serde::Serialize for BlobStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for BlobStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for BlockReason {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"rcptToFailure" => BlockReason::RcptToFailure,
            b"authFailure" => BlockReason::AuthFailure,
            b"loitering" => BlockReason::Loitering,
            b"portScanning" => BlockReason::PortScanning,
            b"manual" => BlockReason::Manual,
            b"other" => BlockReason::Other,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            BlockReason::RcptToFailure => "rcptToFailure",
            BlockReason::AuthFailure => "authFailure",
            BlockReason::Loitering => "loitering",
            BlockReason::PortScanning => "portScanning",
            BlockReason::Manual => "manual",
            BlockReason::Other => "other",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(BlockReason::RcptToFailure),
            1 => Some(BlockReason::AuthFailure),
            2 => Some(BlockReason::Loitering),
            3 => Some(BlockReason::PortScanning),
            4 => Some(BlockReason::Manual),
            5 => Some(BlockReason::Other),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for BlockReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for BlockReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for CertificateManagementType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Manual" => CertificateManagementType::Manual,
            b"Automatic" => CertificateManagementType::Automatic,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CertificateManagementType::Manual => "Manual",
            CertificateManagementType::Automatic => "Automatic",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(CertificateManagementType::Manual),
            1 => Some(CertificateManagementType::Automatic),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for CertificateManagementType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CertificateManagementType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ClusterListenerGroupType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"EnableAll" => ClusterListenerGroupType::EnableAll,
            b"DisableAll" => ClusterListenerGroupType::DisableAll,
            b"EnableSome" => ClusterListenerGroupType::EnableSome,
            b"DisableSome" => ClusterListenerGroupType::DisableSome,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ClusterListenerGroupType::EnableAll => "EnableAll",
            ClusterListenerGroupType::DisableAll => "DisableAll",
            ClusterListenerGroupType::EnableSome => "EnableSome",
            ClusterListenerGroupType::DisableSome => "DisableSome",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ClusterListenerGroupType::EnableAll),
            1 => Some(ClusterListenerGroupType::DisableAll),
            2 => Some(ClusterListenerGroupType::EnableSome),
            3 => Some(ClusterListenerGroupType::DisableSome),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for ClusterListenerGroupType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ClusterListenerGroupType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ClusterNodeStatus {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"active" => ClusterNodeStatus::Active,
            b"stale" => ClusterNodeStatus::Stale,
            b"inactive" => ClusterNodeStatus::Inactive,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ClusterNodeStatus::Active => "active",
            ClusterNodeStatus::Stale => "stale",
            ClusterNodeStatus::Inactive => "inactive",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ClusterNodeStatus::Active),
            1 => Some(ClusterNodeStatus::Stale),
            2 => Some(ClusterNodeStatus::Inactive),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for ClusterNodeStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ClusterNodeStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ClusterTaskGroupType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"EnableAll" => ClusterTaskGroupType::EnableAll,
            b"DisableAll" => ClusterTaskGroupType::DisableAll,
            b"EnableSome" => ClusterTaskGroupType::EnableSome,
            b"DisableSome" => ClusterTaskGroupType::DisableSome,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ClusterTaskGroupType::EnableAll => "EnableAll",
            ClusterTaskGroupType::DisableAll => "DisableAll",
            ClusterTaskGroupType::EnableSome => "EnableSome",
            ClusterTaskGroupType::DisableSome => "DisableSome",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ClusterTaskGroupType::EnableAll),
            1 => Some(ClusterTaskGroupType::DisableAll),
            2 => Some(ClusterTaskGroupType::EnableSome),
            3 => Some(ClusterTaskGroupType::DisableSome),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for ClusterTaskGroupType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ClusterTaskGroupType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ClusterTaskType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"storeMaintenance" => ClusterTaskType::StoreMaintenance,
            b"accountMaintenance" => ClusterTaskType::AccountMaintenance,
            b"metricsCalculate" => ClusterTaskType::MetricsCalculate,
            b"metricsPush" => ClusterTaskType::MetricsPush,
            b"pushNotifications" => ClusterTaskType::PushNotifications,
            b"searchIndexing" => ClusterTaskType::SearchIndexing,
            b"spamClassifierTraining" => ClusterTaskType::SpamClassifierTraining,
            b"outboundMta" => ClusterTaskType::OutboundMta,
            b"taskQueueProcessing" => ClusterTaskType::TaskQueueProcessing,
            b"taskScheduler" => ClusterTaskType::TaskScheduler,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ClusterTaskType::StoreMaintenance => "storeMaintenance",
            ClusterTaskType::AccountMaintenance => "accountMaintenance",
            ClusterTaskType::MetricsCalculate => "metricsCalculate",
            ClusterTaskType::MetricsPush => "metricsPush",
            ClusterTaskType::PushNotifications => "pushNotifications",
            ClusterTaskType::SearchIndexing => "searchIndexing",
            ClusterTaskType::SpamClassifierTraining => "spamClassifierTraining",
            ClusterTaskType::OutboundMta => "outboundMta",
            ClusterTaskType::TaskQueueProcessing => "taskQueueProcessing",
            ClusterTaskType::TaskScheduler => "taskScheduler",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ClusterTaskType::StoreMaintenance),
            1 => Some(ClusterTaskType::AccountMaintenance),
            2 => Some(ClusterTaskType::MetricsCalculate),
            3 => Some(ClusterTaskType::MetricsPush),
            4 => Some(ClusterTaskType::PushNotifications),
            5 => Some(ClusterTaskType::SearchIndexing),
            6 => Some(ClusterTaskType::SpamClassifierTraining),
            7 => Some(ClusterTaskType::OutboundMta),
            8 => Some(ClusterTaskType::TaskQueueProcessing),
            9 => Some(ClusterTaskType::TaskScheduler),
            _ => None,
        }
    }

    const COUNT: usize = 10;
}

impl serde::Serialize for ClusterTaskType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ClusterTaskType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for CompressionAlgo {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"lz4" => CompressionAlgo::Lz4,
            b"none" => CompressionAlgo::None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CompressionAlgo::Lz4 => "lz4",
            CompressionAlgo::None => "none",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(CompressionAlgo::Lz4),
            1 => Some(CompressionAlgo::None),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for CompressionAlgo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CompressionAlgo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for CoordinatorType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => CoordinatorType::Disabled,
            b"Default" => CoordinatorType::Default,
            b"Kafka" => CoordinatorType::Kafka,
            b"Nats" => CoordinatorType::Nats,
            b"Zenoh" => CoordinatorType::Zenoh,
            b"Redis" => CoordinatorType::Redis,
            b"RedisCluster" => CoordinatorType::RedisCluster,
            b"RedisSentinel" => CoordinatorType::RedisSentinel,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CoordinatorType::Disabled => "Disabled",
            CoordinatorType::Default => "Default",
            CoordinatorType::Kafka => "Kafka",
            CoordinatorType::Nats => "Nats",
            CoordinatorType::Zenoh => "Zenoh",
            CoordinatorType::Redis => "Redis",
            CoordinatorType::RedisCluster => "RedisCluster",
            CoordinatorType::RedisSentinel => "RedisSentinel",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(CoordinatorType::Disabled),
            1 => Some(CoordinatorType::Default),
            2 => Some(CoordinatorType::Kafka),
            3 => Some(CoordinatorType::Nats),
            4 => Some(CoordinatorType::Zenoh),
            5 => Some(CoordinatorType::Redis),
            6 => Some(CoordinatorType::RedisCluster),
            7 => Some(CoordinatorType::RedisSentinel),
            _ => None,
        }
    }

    const COUNT: usize = 8;
}

impl serde::Serialize for CoordinatorType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CoordinatorType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for CredentialPermissionsType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Inherit" => CredentialPermissionsType::Inherit,
            b"Disable" => CredentialPermissionsType::Disable,
            b"Replace" => CredentialPermissionsType::Replace,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CredentialPermissionsType::Inherit => "Inherit",
            CredentialPermissionsType::Disable => "Disable",
            CredentialPermissionsType::Replace => "Replace",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(CredentialPermissionsType::Inherit),
            1 => Some(CredentialPermissionsType::Disable),
            2 => Some(CredentialPermissionsType::Replace),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for CredentialPermissionsType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CredentialPermissionsType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for CredentialType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Password" => CredentialType::Password,
            b"AppPassword" => CredentialType::AppPassword,
            b"ApiKey" => CredentialType::ApiKey,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CredentialType::Password => "Password",
            CredentialType::AppPassword => "AppPassword",
            CredentialType::ApiKey => "ApiKey",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(CredentialType::Password),
            1 => Some(CredentialType::AppPassword),
            2 => Some(CredentialType::ApiKey),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for CredentialType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CredentialType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for CronType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Daily" => CronType::Daily,
            b"Weekly" => CronType::Weekly,
            b"Hourly" => CronType::Hourly,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CronType::Daily => "Daily",
            CronType::Weekly => "Weekly",
            CronType::Hourly => "Hourly",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(CronType::Daily),
            1 => Some(CronType::Weekly),
            2 => Some(CronType::Hourly),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for CronType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for CronType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DataStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"RocksDb" => DataStoreType::RocksDb,
            b"Sqlite" => DataStoreType::Sqlite,
            b"FoundationDb" => DataStoreType::FoundationDb,
            b"PostgreSql" => DataStoreType::PostgreSql,
            b"MySql" => DataStoreType::MySql,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DataStoreType::RocksDb => "RocksDb",
            DataStoreType::Sqlite => "Sqlite",
            DataStoreType::FoundationDb => "FoundationDb",
            DataStoreType::PostgreSql => "PostgreSql",
            DataStoreType::MySql => "MySql",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DataStoreType::RocksDb),
            1 => Some(DataStoreType::Sqlite),
            2 => Some(DataStoreType::FoundationDb),
            3 => Some(DataStoreType::PostgreSql),
            4 => Some(DataStoreType::MySql),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for DataStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DataStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DeliveryErrorType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"dnsError" => DeliveryErrorType::DnsError,
            b"unexpectedResponse" => DeliveryErrorType::UnexpectedResponse,
            b"connectionError" => DeliveryErrorType::ConnectionError,
            b"tlsError" => DeliveryErrorType::TlsError,
            b"daneError" => DeliveryErrorType::DaneError,
            b"mtaStsError" => DeliveryErrorType::MtaStsError,
            b"rateLimited" => DeliveryErrorType::RateLimited,
            b"concurrencyLimited" => DeliveryErrorType::ConcurrencyLimited,
            b"io" => DeliveryErrorType::Io,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DeliveryErrorType::DnsError => "dnsError",
            DeliveryErrorType::UnexpectedResponse => "unexpectedResponse",
            DeliveryErrorType::ConnectionError => "connectionError",
            DeliveryErrorType::TlsError => "tlsError",
            DeliveryErrorType::DaneError => "daneError",
            DeliveryErrorType::MtaStsError => "mtaStsError",
            DeliveryErrorType::RateLimited => "rateLimited",
            DeliveryErrorType::ConcurrencyLimited => "concurrencyLimited",
            DeliveryErrorType::Io => "io",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DeliveryErrorType::DnsError),
            1 => Some(DeliveryErrorType::UnexpectedResponse),
            2 => Some(DeliveryErrorType::ConnectionError),
            3 => Some(DeliveryErrorType::TlsError),
            4 => Some(DeliveryErrorType::DaneError),
            5 => Some(DeliveryErrorType::MtaStsError),
            6 => Some(DeliveryErrorType::RateLimited),
            7 => Some(DeliveryErrorType::ConcurrencyLimited),
            8 => Some(DeliveryErrorType::Io),
            _ => None,
        }
    }

    const COUNT: usize = 9;
}

impl serde::Serialize for DeliveryErrorType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DeliveryErrorType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DirectoryBootstrapType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Internal" => DirectoryBootstrapType::Internal,
            b"Ldap" => DirectoryBootstrapType::Ldap,
            b"Sql" => DirectoryBootstrapType::Sql,
            b"Oidc" => DirectoryBootstrapType::Oidc,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DirectoryBootstrapType::Internal => "Internal",
            DirectoryBootstrapType::Ldap => "Ldap",
            DirectoryBootstrapType::Sql => "Sql",
            DirectoryBootstrapType::Oidc => "Oidc",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DirectoryBootstrapType::Internal),
            1 => Some(DirectoryBootstrapType::Ldap),
            2 => Some(DirectoryBootstrapType::Sql),
            3 => Some(DirectoryBootstrapType::Oidc),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for DirectoryBootstrapType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DirectoryBootstrapType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DirectoryType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Ldap" => DirectoryType::Ldap,
            b"Sql" => DirectoryType::Sql,
            b"Oidc" => DirectoryType::Oidc,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DirectoryType::Ldap => "Ldap",
            DirectoryType::Sql => "Sql",
            DirectoryType::Oidc => "Oidc",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DirectoryType::Ldap),
            1 => Some(DirectoryType::Sql),
            2 => Some(DirectoryType::Oidc),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for DirectoryType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DirectoryType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for Dkim2Flag {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"donotmodify" => Dkim2Flag::Donotmodify,
            b"donotexplode" => Dkim2Flag::Donotexplode,
            b"feedback" => Dkim2Flag::Feedback,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Dkim2Flag::Donotmodify => "donotmodify",
            Dkim2Flag::Donotexplode => "donotexplode",
            Dkim2Flag::Feedback => "feedback",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(Dkim2Flag::Donotmodify),
            1 => Some(Dkim2Flag::Donotexplode),
            2 => Some(Dkim2Flag::Feedback),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for Dkim2Flag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Dkim2Flag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DkimAuthResult {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"none" => DkimAuthResult::None,
            b"pass" => DkimAuthResult::Pass,
            b"fail" => DkimAuthResult::Fail,
            b"policy" => DkimAuthResult::Policy,
            b"neutral" => DkimAuthResult::Neutral,
            b"tempError" => DkimAuthResult::TempError,
            b"permError" => DkimAuthResult::PermError,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DkimAuthResult::None => "none",
            DkimAuthResult::Pass => "pass",
            DkimAuthResult::Fail => "fail",
            DkimAuthResult::Policy => "policy",
            DkimAuthResult::Neutral => "neutral",
            DkimAuthResult::TempError => "tempError",
            DkimAuthResult::PermError => "permError",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DkimAuthResult::None),
            1 => Some(DkimAuthResult::Pass),
            2 => Some(DkimAuthResult::Fail),
            3 => Some(DkimAuthResult::Policy),
            4 => Some(DkimAuthResult::Neutral),
            5 => Some(DkimAuthResult::TempError),
            6 => Some(DkimAuthResult::PermError),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for DkimAuthResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DkimAuthResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DkimCanonicalization {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"relaxed/relaxed" => DkimCanonicalization::RelaxedRelaxed,
            b"simple/simple" => DkimCanonicalization::SimpleSimple,
            b"relaxed/simple" => DkimCanonicalization::RelaxedSimple,
            b"simple/relaxed" => DkimCanonicalization::SimpleRelaxed,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DkimCanonicalization::RelaxedRelaxed => "relaxed/relaxed",
            DkimCanonicalization::SimpleSimple => "simple/simple",
            DkimCanonicalization::RelaxedSimple => "relaxed/simple",
            DkimCanonicalization::SimpleRelaxed => "simple/relaxed",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DkimCanonicalization::RelaxedRelaxed),
            1 => Some(DkimCanonicalization::SimpleSimple),
            2 => Some(DkimCanonicalization::RelaxedSimple),
            3 => Some(DkimCanonicalization::SimpleRelaxed),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for DkimCanonicalization {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DkimCanonicalization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DkimHash {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"sha256" => DkimHash::Sha256,
            b"sha1" => DkimHash::Sha1,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DkimHash::Sha256 => "sha256",
            DkimHash::Sha1 => "sha1",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DkimHash::Sha256),
            1 => Some(DkimHash::Sha1),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for DkimHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DkimHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DkimManagementType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Automatic" => DkimManagementType::Automatic,
            b"Manual" => DkimManagementType::Manual,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DkimManagementType::Automatic => "Automatic",
            DkimManagementType::Manual => "Manual",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DkimManagementType::Automatic),
            1 => Some(DkimManagementType::Manual),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for DkimManagementType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DkimManagementType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DkimRotationStage {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"active" => DkimRotationStage::Active,
            b"pending" => DkimRotationStage::Pending,
            b"retiring" => DkimRotationStage::Retiring,
            b"retired" => DkimRotationStage::Retired,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DkimRotationStage::Active => "active",
            DkimRotationStage::Pending => "pending",
            DkimRotationStage::Retiring => "retiring",
            DkimRotationStage::Retired => "retired",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DkimRotationStage::Active),
            1 => Some(DkimRotationStage::Pending),
            2 => Some(DkimRotationStage::Retiring),
            3 => Some(DkimRotationStage::Retired),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for DkimRotationStage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DkimRotationStage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DkimSignatureType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Dkim1Ed25519Sha256" => DkimSignatureType::Dkim1Ed25519Sha256,
            b"Dkim1RsaSha256" => DkimSignatureType::Dkim1RsaSha256,
            b"Dkim2Ed25519Sha256" => DkimSignatureType::Dkim2Ed25519Sha256,
            b"Dkim2RsaSha256" => DkimSignatureType::Dkim2RsaSha256,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DkimSignatureType::Dkim1Ed25519Sha256 => "Dkim1Ed25519Sha256",
            DkimSignatureType::Dkim1RsaSha256 => "Dkim1RsaSha256",
            DkimSignatureType::Dkim2Ed25519Sha256 => "Dkim2Ed25519Sha256",
            DkimSignatureType::Dkim2RsaSha256 => "Dkim2RsaSha256",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DkimSignatureType::Dkim1Ed25519Sha256),
            1 => Some(DkimSignatureType::Dkim1RsaSha256),
            2 => Some(DkimSignatureType::Dkim2Ed25519Sha256),
            3 => Some(DkimSignatureType::Dkim2RsaSha256),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for DkimSignatureType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DkimSignatureType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DmarcActionDisposition {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"none" => DmarcActionDisposition::None,
            b"pass" => DmarcActionDisposition::Pass,
            b"quarantine" => DmarcActionDisposition::Quarantine,
            b"reject" => DmarcActionDisposition::Reject,
            b"unspecified" => DmarcActionDisposition::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DmarcActionDisposition::None => "none",
            DmarcActionDisposition::Pass => "pass",
            DmarcActionDisposition::Quarantine => "quarantine",
            DmarcActionDisposition::Reject => "reject",
            DmarcActionDisposition::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DmarcActionDisposition::None),
            1 => Some(DmarcActionDisposition::Pass),
            2 => Some(DmarcActionDisposition::Quarantine),
            3 => Some(DmarcActionDisposition::Reject),
            4 => Some(DmarcActionDisposition::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for DmarcActionDisposition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DmarcActionDisposition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DmarcAlignment {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"relaxed" => DmarcAlignment::Relaxed,
            b"strict" => DmarcAlignment::Strict,
            b"unspecified" => DmarcAlignment::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DmarcAlignment::Relaxed => "relaxed",
            DmarcAlignment::Strict => "strict",
            DmarcAlignment::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DmarcAlignment::Relaxed),
            1 => Some(DmarcAlignment::Strict),
            2 => Some(DmarcAlignment::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for DmarcAlignment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DmarcAlignment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DmarcDiscovery {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"psl" => DmarcDiscovery::Psl,
            b"treewalk" => DmarcDiscovery::Treewalk,
            b"unspecified" => DmarcDiscovery::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DmarcDiscovery::Psl => "psl",
            DmarcDiscovery::Treewalk => "treewalk",
            DmarcDiscovery::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DmarcDiscovery::Psl),
            1 => Some(DmarcDiscovery::Treewalk),
            2 => Some(DmarcDiscovery::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for DmarcDiscovery {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DmarcDiscovery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DmarcDisposition {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"none" => DmarcDisposition::None,
            b"quarantine" => DmarcDisposition::Quarantine,
            b"reject" => DmarcDisposition::Reject,
            b"unspecified" => DmarcDisposition::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DmarcDisposition::None => "none",
            DmarcDisposition::Quarantine => "quarantine",
            DmarcDisposition::Reject => "reject",
            DmarcDisposition::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DmarcDisposition::None),
            1 => Some(DmarcDisposition::Quarantine),
            2 => Some(DmarcDisposition::Reject),
            3 => Some(DmarcDisposition::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for DmarcDisposition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DmarcDisposition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DmarcPolicyOverride {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Forwarded" => DmarcPolicyOverride::Forwarded,
            b"SampledOut" => DmarcPolicyOverride::SampledOut,
            b"TrustedForwarder" => DmarcPolicyOverride::TrustedForwarder,
            b"MailingList" => DmarcPolicyOverride::MailingList,
            b"LocalPolicy" => DmarcPolicyOverride::LocalPolicy,
            b"Other" => DmarcPolicyOverride::Other,
            b"PolicyTestMode" => DmarcPolicyOverride::PolicyTestMode,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DmarcPolicyOverride::Forwarded => "Forwarded",
            DmarcPolicyOverride::SampledOut => "SampledOut",
            DmarcPolicyOverride::TrustedForwarder => "TrustedForwarder",
            DmarcPolicyOverride::MailingList => "MailingList",
            DmarcPolicyOverride::LocalPolicy => "LocalPolicy",
            DmarcPolicyOverride::Other => "Other",
            DmarcPolicyOverride::PolicyTestMode => "PolicyTestMode",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DmarcPolicyOverride::Forwarded),
            1 => Some(DmarcPolicyOverride::SampledOut),
            2 => Some(DmarcPolicyOverride::TrustedForwarder),
            3 => Some(DmarcPolicyOverride::MailingList),
            4 => Some(DmarcPolicyOverride::LocalPolicy),
            5 => Some(DmarcPolicyOverride::Other),
            6 => Some(DmarcPolicyOverride::PolicyTestMode),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for DmarcPolicyOverride {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DmarcPolicyOverride {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DmarcResult {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"pass" => DmarcResult::Pass,
            b"fail" => DmarcResult::Fail,
            b"unspecified" => DmarcResult::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DmarcResult::Pass => "pass",
            DmarcResult::Fail => "fail",
            DmarcResult::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DmarcResult::Pass),
            1 => Some(DmarcResult::Fail),
            2 => Some(DmarcResult::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for DmarcResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DmarcResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DmarcTroubleshootAuthResultType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Pass" => DmarcTroubleshootAuthResultType::Pass,
            b"Fail" => DmarcTroubleshootAuthResultType::Fail,
            b"SoftFail" => DmarcTroubleshootAuthResultType::SoftFail,
            b"TempError" => DmarcTroubleshootAuthResultType::TempError,
            b"PermError" => DmarcTroubleshootAuthResultType::PermError,
            b"Neutral" => DmarcTroubleshootAuthResultType::Neutral,
            b"None" => DmarcTroubleshootAuthResultType::None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DmarcTroubleshootAuthResultType::Pass => "Pass",
            DmarcTroubleshootAuthResultType::Fail => "Fail",
            DmarcTroubleshootAuthResultType::SoftFail => "SoftFail",
            DmarcTroubleshootAuthResultType::TempError => "TempError",
            DmarcTroubleshootAuthResultType::PermError => "PermError",
            DmarcTroubleshootAuthResultType::Neutral => "Neutral",
            DmarcTroubleshootAuthResultType::None => "None",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DmarcTroubleshootAuthResultType::Pass),
            1 => Some(DmarcTroubleshootAuthResultType::Fail),
            2 => Some(DmarcTroubleshootAuthResultType::SoftFail),
            3 => Some(DmarcTroubleshootAuthResultType::TempError),
            4 => Some(DmarcTroubleshootAuthResultType::PermError),
            5 => Some(DmarcTroubleshootAuthResultType::Neutral),
            6 => Some(DmarcTroubleshootAuthResultType::None),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for DmarcTroubleshootAuthResultType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DmarcTroubleshootAuthResultType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DnsManagementType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Manual" => DnsManagementType::Manual,
            b"Automatic" => DnsManagementType::Automatic,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DnsManagementType::Manual => "Manual",
            DnsManagementType::Automatic => "Automatic",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DnsManagementType::Manual),
            1 => Some(DnsManagementType::Automatic),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for DnsManagementType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DnsManagementType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DnsPublishStatus {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"synced" => DnsPublishStatus::Synced,
            b"pending" => DnsPublishStatus::Pending,
            b"failed" => DnsPublishStatus::Failed,
            b"unknown" => DnsPublishStatus::Unknown,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DnsPublishStatus::Synced => "synced",
            DnsPublishStatus::Pending => "pending",
            DnsPublishStatus::Failed => "failed",
            DnsPublishStatus::Unknown => "unknown",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DnsPublishStatus::Synced),
            1 => Some(DnsPublishStatus::Pending),
            2 => Some(DnsPublishStatus::Failed),
            3 => Some(DnsPublishStatus::Unknown),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for DnsPublishStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DnsPublishStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DnsRecordType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"dkim" => DnsRecordType::Dkim,
            b"tlsa" => DnsRecordType::Tlsa,
            b"spf" => DnsRecordType::Spf,
            b"mx" => DnsRecordType::Mx,
            b"dmarc" => DnsRecordType::Dmarc,
            b"srv" => DnsRecordType::Srv,
            b"mtaSts" => DnsRecordType::MtaSts,
            b"tlsRpt" => DnsRecordType::TlsRpt,
            b"caa" => DnsRecordType::Caa,
            b"autoConfig" => DnsRecordType::AutoConfig,
            b"autoConfigLegacy" => DnsRecordType::AutoConfigLegacy,
            b"autoDiscover" => DnsRecordType::AutoDiscover,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DnsRecordType::Dkim => "dkim",
            DnsRecordType::Tlsa => "tlsa",
            DnsRecordType::Spf => "spf",
            DnsRecordType::Mx => "mx",
            DnsRecordType::Dmarc => "dmarc",
            DnsRecordType::Srv => "srv",
            DnsRecordType::MtaSts => "mtaSts",
            DnsRecordType::TlsRpt => "tlsRpt",
            DnsRecordType::Caa => "caa",
            DnsRecordType::AutoConfig => "autoConfig",
            DnsRecordType::AutoConfigLegacy => "autoConfigLegacy",
            DnsRecordType::AutoDiscover => "autoDiscover",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DnsRecordType::Dkim),
            1 => Some(DnsRecordType::Tlsa),
            2 => Some(DnsRecordType::Spf),
            3 => Some(DnsRecordType::Mx),
            4 => Some(DnsRecordType::Dmarc),
            5 => Some(DnsRecordType::Srv),
            6 => Some(DnsRecordType::MtaSts),
            7 => Some(DnsRecordType::TlsRpt),
            8 => Some(DnsRecordType::Caa),
            9 => Some(DnsRecordType::AutoConfig),
            10 => Some(DnsRecordType::AutoConfigLegacy),
            11 => Some(DnsRecordType::AutoDiscover),
            _ => None,
        }
    }

    const COUNT: usize = 12;
}

impl serde::Serialize for DnsRecordType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DnsRecordType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DnsResolverProtocol {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"tls" => DnsResolverProtocol::Tls,
            b"udp" => DnsResolverProtocol::Udp,
            b"tcp" => DnsResolverProtocol::Tcp,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DnsResolverProtocol::Tls => "tls",
            DnsResolverProtocol::Udp => "udp",
            DnsResolverProtocol::Tcp => "tcp",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DnsResolverProtocol::Tls),
            1 => Some(DnsResolverProtocol::Udp),
            2 => Some(DnsResolverProtocol::Tcp),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for DnsResolverProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DnsResolverProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DnsResolverType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"System" => DnsResolverType::System,
            b"Custom" => DnsResolverType::Custom,
            b"Cloudflare" => DnsResolverType::Cloudflare,
            b"Quad9" => DnsResolverType::Quad9,
            b"Google" => DnsResolverType::Google,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            DnsResolverType::System => "System",
            DnsResolverType::Custom => "Custom",
            DnsResolverType::Cloudflare => "Cloudflare",
            DnsResolverType::Quad9 => "Quad9",
            DnsResolverType::Google => "Google",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DnsResolverType::System),
            1 => Some(DnsResolverType::Custom),
            2 => Some(DnsResolverType::Cloudflare),
            3 => Some(DnsResolverType::Quad9),
            4 => Some(DnsResolverType::Google),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for DnsResolverType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DnsResolverType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DnsServerBootstrapType {
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            DnsServerBootstrapType,
            b"Manual" => DnsServerBootstrapType::Manual,
            b"Tsig" => DnsServerBootstrapType::Tsig,
            b"Deprecated1" => DnsServerBootstrapType::Deprecated1,
            b"Cloudflare" => DnsServerBootstrapType::Cloudflare,
            b"DigitalOcean" => DnsServerBootstrapType::DigitalOcean,
            b"DeSEC" => DnsServerBootstrapType::DeSEC,
            b"Ovh" => DnsServerBootstrapType::Ovh,
            b"Bunny" => DnsServerBootstrapType::Bunny,
            b"Porkbun" => DnsServerBootstrapType::Porkbun,
            b"Dnsimple" => DnsServerBootstrapType::Dnsimple,
            b"Spaceship" => DnsServerBootstrapType::Spaceship,
            b"Route53" => DnsServerBootstrapType::Route53,
            b"GoogleCloudDns" => DnsServerBootstrapType::GoogleCloudDns,
            b"Alidns" => DnsServerBootstrapType::Alidns,
            b"ArvanCloud" => DnsServerBootstrapType::ArvanCloud,
            b"Autodns" => DnsServerBootstrapType::Autodns,
            b"AzureDns" => DnsServerBootstrapType::AzureDns,
            b"BaiduCloud" => DnsServerBootstrapType::BaiduCloud,
            b"BluecatV2" => DnsServerBootstrapType::BluecatV2,
            b"ClouDns" => DnsServerBootstrapType::ClouDns,
            b"Constellix" => DnsServerBootstrapType::Constellix,
            b"Cpanel" => DnsServerBootstrapType::Cpanel,
            b"Ddnss" => DnsServerBootstrapType::Ddnss,
            b"DnsMadeEasy" => DnsServerBootstrapType::DnsMadeEasy,
            b"Domeneshop" => DnsServerBootstrapType::Domeneshop,
            b"Dreamhost" => DnsServerBootstrapType::Dreamhost,
            b"DuckDns" => DnsServerBootstrapType::DuckDns,
            b"Dynu" => DnsServerBootstrapType::Dynu,
            b"EasyDns" => DnsServerBootstrapType::EasyDns,
            b"EdgeDns" => DnsServerBootstrapType::EdgeDns,
            b"Exoscale" => DnsServerBootstrapType::Exoscale,
            b"FreeMyIp" => DnsServerBootstrapType::FreeMyIp,
            b"GandiV5" => DnsServerBootstrapType::GandiV5,
            b"Gcore" => DnsServerBootstrapType::Gcore,
            b"Glesys" => DnsServerBootstrapType::Glesys,
            b"Godaddy" => DnsServerBootstrapType::Godaddy,
            b"Hetzner" => DnsServerBootstrapType::Hetzner,
            b"HostingDe" => DnsServerBootstrapType::HostingDe,
            b"Hostinger" => DnsServerBootstrapType::Hostinger,
            b"HuaweiCloud" => DnsServerBootstrapType::HuaweiCloud,
            b"Hurricane" => DnsServerBootstrapType::Hurricane,
            b"IbmCloud" => DnsServerBootstrapType::IbmCloud,
            b"Infoblox" => DnsServerBootstrapType::Infoblox,
            b"Infomaniak" => DnsServerBootstrapType::Infomaniak,
            b"Inwx" => DnsServerBootstrapType::Inwx,
            b"Ionos" => DnsServerBootstrapType::Ionos,
            b"Ipv64" => DnsServerBootstrapType::Ipv64,
            b"Joker" => DnsServerBootstrapType::Joker,
            b"Lightsail" => DnsServerBootstrapType::Lightsail,
            b"Linode" => DnsServerBootstrapType::Linode,
            b"LuaDns" => DnsServerBootstrapType::LuaDns,
            b"MythicBeasts" => DnsServerBootstrapType::MythicBeasts,
            b"Namecheap" => DnsServerBootstrapType::Namecheap,
            b"NameDotCom" => DnsServerBootstrapType::NameDotCom,
            b"NameSilo" => DnsServerBootstrapType::NameSilo,
            b"Netcup" => DnsServerBootstrapType::Netcup,
            b"Netlify" => DnsServerBootstrapType::Netlify,
            b"Nifcloud" => DnsServerBootstrapType::Nifcloud,
            b"Ns1" => DnsServerBootstrapType::Ns1,
            b"OracleCloud" => DnsServerBootstrapType::OracleCloud,
            b"Plesk" => DnsServerBootstrapType::Plesk,
            b"Safedns" => DnsServerBootstrapType::Safedns,
            b"Scaleway" => DnsServerBootstrapType::Scaleway,
            b"TencentCloud" => DnsServerBootstrapType::TencentCloud,
            b"Transip" => DnsServerBootstrapType::Transip,
            b"UltraDns" => DnsServerBootstrapType::UltraDns,
            b"Vercel" => DnsServerBootstrapType::Vercel,
            b"Volcengine" => DnsServerBootstrapType::Volcengine,
            b"Vultr" => DnsServerBootstrapType::Vultr,
            b"WebSupport" => DnsServerBootstrapType::WebSupport,
            b"YandexCloud" => DnsServerBootstrapType::YandexCloud,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            DnsServerBootstrapType::Manual => "Manual",
            DnsServerBootstrapType::Tsig => "Tsig",
            DnsServerBootstrapType::Deprecated1 => "Deprecated1",
            DnsServerBootstrapType::Cloudflare => "Cloudflare",
            DnsServerBootstrapType::DigitalOcean => "DigitalOcean",
            DnsServerBootstrapType::DeSEC => "DeSEC",
            DnsServerBootstrapType::Ovh => "Ovh",
            DnsServerBootstrapType::Bunny => "Bunny",
            DnsServerBootstrapType::Porkbun => "Porkbun",
            DnsServerBootstrapType::Dnsimple => "Dnsimple",
            DnsServerBootstrapType::Spaceship => "Spaceship",
            DnsServerBootstrapType::Route53 => "Route53",
            DnsServerBootstrapType::GoogleCloudDns => "GoogleCloudDns",
            DnsServerBootstrapType::Alidns => "Alidns",
            DnsServerBootstrapType::ArvanCloud => "ArvanCloud",
            DnsServerBootstrapType::Autodns => "Autodns",
            DnsServerBootstrapType::AzureDns => "AzureDns",
            DnsServerBootstrapType::BaiduCloud => "BaiduCloud",
            DnsServerBootstrapType::BluecatV2 => "BluecatV2",
            DnsServerBootstrapType::ClouDns => "ClouDns",
            DnsServerBootstrapType::Constellix => "Constellix",
            DnsServerBootstrapType::Cpanel => "Cpanel",
            DnsServerBootstrapType::Ddnss => "Ddnss",
            DnsServerBootstrapType::DnsMadeEasy => "DnsMadeEasy",
            DnsServerBootstrapType::Domeneshop => "Domeneshop",
            DnsServerBootstrapType::Dreamhost => "Dreamhost",
            DnsServerBootstrapType::DuckDns => "DuckDns",
            DnsServerBootstrapType::Dynu => "Dynu",
            DnsServerBootstrapType::EasyDns => "EasyDns",
            DnsServerBootstrapType::EdgeDns => "EdgeDns",
            DnsServerBootstrapType::Exoscale => "Exoscale",
            DnsServerBootstrapType::FreeMyIp => "FreeMyIp",
            DnsServerBootstrapType::GandiV5 => "GandiV5",
            DnsServerBootstrapType::Gcore => "Gcore",
            DnsServerBootstrapType::Glesys => "Glesys",
            DnsServerBootstrapType::Godaddy => "Godaddy",
            DnsServerBootstrapType::Hetzner => "Hetzner",
            DnsServerBootstrapType::HostingDe => "HostingDe",
            DnsServerBootstrapType::Hostinger => "Hostinger",
            DnsServerBootstrapType::HuaweiCloud => "HuaweiCloud",
            DnsServerBootstrapType::Hurricane => "Hurricane",
            DnsServerBootstrapType::IbmCloud => "IbmCloud",
            DnsServerBootstrapType::Infoblox => "Infoblox",
            DnsServerBootstrapType::Infomaniak => "Infomaniak",
            DnsServerBootstrapType::Inwx => "Inwx",
            DnsServerBootstrapType::Ionos => "Ionos",
            DnsServerBootstrapType::Ipv64 => "Ipv64",
            DnsServerBootstrapType::Joker => "Joker",
            DnsServerBootstrapType::Lightsail => "Lightsail",
            DnsServerBootstrapType::Linode => "Linode",
            DnsServerBootstrapType::LuaDns => "LuaDns",
            DnsServerBootstrapType::MythicBeasts => "MythicBeasts",
            DnsServerBootstrapType::Namecheap => "Namecheap",
            DnsServerBootstrapType::NameDotCom => "NameDotCom",
            DnsServerBootstrapType::NameSilo => "NameSilo",
            DnsServerBootstrapType::Netcup => "Netcup",
            DnsServerBootstrapType::Netlify => "Netlify",
            DnsServerBootstrapType::Nifcloud => "Nifcloud",
            DnsServerBootstrapType::Ns1 => "Ns1",
            DnsServerBootstrapType::OracleCloud => "OracleCloud",
            DnsServerBootstrapType::Plesk => "Plesk",
            DnsServerBootstrapType::Safedns => "Safedns",
            DnsServerBootstrapType::Scaleway => "Scaleway",
            DnsServerBootstrapType::TencentCloud => "TencentCloud",
            DnsServerBootstrapType::Transip => "Transip",
            DnsServerBootstrapType::UltraDns => "UltraDns",
            DnsServerBootstrapType::Vercel => "Vercel",
            DnsServerBootstrapType::Volcengine => "Volcengine",
            DnsServerBootstrapType::Vultr => "Vultr",
            DnsServerBootstrapType::WebSupport => "WebSupport",
            DnsServerBootstrapType::YandexCloud => "YandexCloud",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DnsServerBootstrapType::Manual),
            1 => Some(DnsServerBootstrapType::Tsig),
            2 => Some(DnsServerBootstrapType::Deprecated1),
            3 => Some(DnsServerBootstrapType::Cloudflare),
            4 => Some(DnsServerBootstrapType::DigitalOcean),
            5 => Some(DnsServerBootstrapType::DeSEC),
            6 => Some(DnsServerBootstrapType::Ovh),
            7 => Some(DnsServerBootstrapType::Bunny),
            8 => Some(DnsServerBootstrapType::Porkbun),
            9 => Some(DnsServerBootstrapType::Dnsimple),
            10 => Some(DnsServerBootstrapType::Spaceship),
            11 => Some(DnsServerBootstrapType::Route53),
            12 => Some(DnsServerBootstrapType::GoogleCloudDns),
            13 => Some(DnsServerBootstrapType::Alidns),
            14 => Some(DnsServerBootstrapType::ArvanCloud),
            15 => Some(DnsServerBootstrapType::Autodns),
            16 => Some(DnsServerBootstrapType::AzureDns),
            17 => Some(DnsServerBootstrapType::BaiduCloud),
            18 => Some(DnsServerBootstrapType::BluecatV2),
            19 => Some(DnsServerBootstrapType::ClouDns),
            20 => Some(DnsServerBootstrapType::Constellix),
            21 => Some(DnsServerBootstrapType::Cpanel),
            22 => Some(DnsServerBootstrapType::Ddnss),
            23 => Some(DnsServerBootstrapType::DnsMadeEasy),
            24 => Some(DnsServerBootstrapType::Domeneshop),
            25 => Some(DnsServerBootstrapType::Dreamhost),
            26 => Some(DnsServerBootstrapType::DuckDns),
            27 => Some(DnsServerBootstrapType::Dynu),
            28 => Some(DnsServerBootstrapType::EasyDns),
            29 => Some(DnsServerBootstrapType::EdgeDns),
            30 => Some(DnsServerBootstrapType::Exoscale),
            31 => Some(DnsServerBootstrapType::FreeMyIp),
            32 => Some(DnsServerBootstrapType::GandiV5),
            33 => Some(DnsServerBootstrapType::Gcore),
            34 => Some(DnsServerBootstrapType::Glesys),
            35 => Some(DnsServerBootstrapType::Godaddy),
            36 => Some(DnsServerBootstrapType::Hetzner),
            37 => Some(DnsServerBootstrapType::HostingDe),
            38 => Some(DnsServerBootstrapType::Hostinger),
            39 => Some(DnsServerBootstrapType::HuaweiCloud),
            40 => Some(DnsServerBootstrapType::Hurricane),
            41 => Some(DnsServerBootstrapType::IbmCloud),
            42 => Some(DnsServerBootstrapType::Infoblox),
            43 => Some(DnsServerBootstrapType::Infomaniak),
            44 => Some(DnsServerBootstrapType::Inwx),
            45 => Some(DnsServerBootstrapType::Ionos),
            46 => Some(DnsServerBootstrapType::Ipv64),
            47 => Some(DnsServerBootstrapType::Joker),
            48 => Some(DnsServerBootstrapType::Lightsail),
            49 => Some(DnsServerBootstrapType::Linode),
            50 => Some(DnsServerBootstrapType::LuaDns),
            51 => Some(DnsServerBootstrapType::MythicBeasts),
            52 => Some(DnsServerBootstrapType::Namecheap),
            53 => Some(DnsServerBootstrapType::NameDotCom),
            54 => Some(DnsServerBootstrapType::NameSilo),
            55 => Some(DnsServerBootstrapType::Netcup),
            56 => Some(DnsServerBootstrapType::Netlify),
            57 => Some(DnsServerBootstrapType::Nifcloud),
            58 => Some(DnsServerBootstrapType::Ns1),
            59 => Some(DnsServerBootstrapType::OracleCloud),
            60 => Some(DnsServerBootstrapType::Plesk),
            61 => Some(DnsServerBootstrapType::Safedns),
            62 => Some(DnsServerBootstrapType::Scaleway),
            63 => Some(DnsServerBootstrapType::TencentCloud),
            64 => Some(DnsServerBootstrapType::Transip),
            65 => Some(DnsServerBootstrapType::UltraDns),
            66 => Some(DnsServerBootstrapType::Vercel),
            67 => Some(DnsServerBootstrapType::Volcengine),
            68 => Some(DnsServerBootstrapType::Vultr),
            69 => Some(DnsServerBootstrapType::WebSupport),
            70 => Some(DnsServerBootstrapType::YandexCloud),
            _ => None,
        }
    }

    const COUNT: usize = 71;
}

impl serde::Serialize for DnsServerBootstrapType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DnsServerBootstrapType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for DnsServerType {
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            DnsServerType,
            b"Tsig" => DnsServerType::Tsig,
            b"Deprecated1" => DnsServerType::Deprecated1,
            b"Cloudflare" => DnsServerType::Cloudflare,
            b"DigitalOcean" => DnsServerType::DigitalOcean,
            b"DeSEC" => DnsServerType::DeSEC,
            b"Ovh" => DnsServerType::Ovh,
            b"Bunny" => DnsServerType::Bunny,
            b"Porkbun" => DnsServerType::Porkbun,
            b"Dnsimple" => DnsServerType::Dnsimple,
            b"Spaceship" => DnsServerType::Spaceship,
            b"Route53" => DnsServerType::Route53,
            b"GoogleCloudDns" => DnsServerType::GoogleCloudDns,
            b"Alidns" => DnsServerType::Alidns,
            b"ArvanCloud" => DnsServerType::ArvanCloud,
            b"Autodns" => DnsServerType::Autodns,
            b"AzureDns" => DnsServerType::AzureDns,
            b"BaiduCloud" => DnsServerType::BaiduCloud,
            b"BluecatV2" => DnsServerType::BluecatV2,
            b"ClouDns" => DnsServerType::ClouDns,
            b"Constellix" => DnsServerType::Constellix,
            b"Cpanel" => DnsServerType::Cpanel,
            b"Ddnss" => DnsServerType::Ddnss,
            b"DnsMadeEasy" => DnsServerType::DnsMadeEasy,
            b"Domeneshop" => DnsServerType::Domeneshop,
            b"Dreamhost" => DnsServerType::Dreamhost,
            b"DuckDns" => DnsServerType::DuckDns,
            b"Dynu" => DnsServerType::Dynu,
            b"EasyDns" => DnsServerType::EasyDns,
            b"EdgeDns" => DnsServerType::EdgeDns,
            b"Exoscale" => DnsServerType::Exoscale,
            b"FreeMyIp" => DnsServerType::FreeMyIp,
            b"GandiV5" => DnsServerType::GandiV5,
            b"Gcore" => DnsServerType::Gcore,
            b"Glesys" => DnsServerType::Glesys,
            b"Godaddy" => DnsServerType::Godaddy,
            b"Hetzner" => DnsServerType::Hetzner,
            b"HostingDe" => DnsServerType::HostingDe,
            b"Hostinger" => DnsServerType::Hostinger,
            b"HuaweiCloud" => DnsServerType::HuaweiCloud,
            b"Hurricane" => DnsServerType::Hurricane,
            b"IbmCloud" => DnsServerType::IbmCloud,
            b"Infoblox" => DnsServerType::Infoblox,
            b"Infomaniak" => DnsServerType::Infomaniak,
            b"Inwx" => DnsServerType::Inwx,
            b"Ionos" => DnsServerType::Ionos,
            b"Ipv64" => DnsServerType::Ipv64,
            b"Joker" => DnsServerType::Joker,
            b"Lightsail" => DnsServerType::Lightsail,
            b"Linode" => DnsServerType::Linode,
            b"LuaDns" => DnsServerType::LuaDns,
            b"MythicBeasts" => DnsServerType::MythicBeasts,
            b"Namecheap" => DnsServerType::Namecheap,
            b"NameDotCom" => DnsServerType::NameDotCom,
            b"NameSilo" => DnsServerType::NameSilo,
            b"Netcup" => DnsServerType::Netcup,
            b"Netlify" => DnsServerType::Netlify,
            b"Nifcloud" => DnsServerType::Nifcloud,
            b"Ns1" => DnsServerType::Ns1,
            b"OracleCloud" => DnsServerType::OracleCloud,
            b"Plesk" => DnsServerType::Plesk,
            b"Safedns" => DnsServerType::Safedns,
            b"Scaleway" => DnsServerType::Scaleway,
            b"TencentCloud" => DnsServerType::TencentCloud,
            b"Transip" => DnsServerType::Transip,
            b"UltraDns" => DnsServerType::UltraDns,
            b"Vercel" => DnsServerType::Vercel,
            b"Volcengine" => DnsServerType::Volcengine,
            b"Vultr" => DnsServerType::Vultr,
            b"WebSupport" => DnsServerType::WebSupport,
            b"YandexCloud" => DnsServerType::YandexCloud,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            DnsServerType::Tsig => "Tsig",
            DnsServerType::Deprecated1 => "Deprecated1",
            DnsServerType::Cloudflare => "Cloudflare",
            DnsServerType::DigitalOcean => "DigitalOcean",
            DnsServerType::DeSEC => "DeSEC",
            DnsServerType::Ovh => "Ovh",
            DnsServerType::Bunny => "Bunny",
            DnsServerType::Porkbun => "Porkbun",
            DnsServerType::Dnsimple => "Dnsimple",
            DnsServerType::Spaceship => "Spaceship",
            DnsServerType::Route53 => "Route53",
            DnsServerType::GoogleCloudDns => "GoogleCloudDns",
            DnsServerType::Alidns => "Alidns",
            DnsServerType::ArvanCloud => "ArvanCloud",
            DnsServerType::Autodns => "Autodns",
            DnsServerType::AzureDns => "AzureDns",
            DnsServerType::BaiduCloud => "BaiduCloud",
            DnsServerType::BluecatV2 => "BluecatV2",
            DnsServerType::ClouDns => "ClouDns",
            DnsServerType::Constellix => "Constellix",
            DnsServerType::Cpanel => "Cpanel",
            DnsServerType::Ddnss => "Ddnss",
            DnsServerType::DnsMadeEasy => "DnsMadeEasy",
            DnsServerType::Domeneshop => "Domeneshop",
            DnsServerType::Dreamhost => "Dreamhost",
            DnsServerType::DuckDns => "DuckDns",
            DnsServerType::Dynu => "Dynu",
            DnsServerType::EasyDns => "EasyDns",
            DnsServerType::EdgeDns => "EdgeDns",
            DnsServerType::Exoscale => "Exoscale",
            DnsServerType::FreeMyIp => "FreeMyIp",
            DnsServerType::GandiV5 => "GandiV5",
            DnsServerType::Gcore => "Gcore",
            DnsServerType::Glesys => "Glesys",
            DnsServerType::Godaddy => "Godaddy",
            DnsServerType::Hetzner => "Hetzner",
            DnsServerType::HostingDe => "HostingDe",
            DnsServerType::Hostinger => "Hostinger",
            DnsServerType::HuaweiCloud => "HuaweiCloud",
            DnsServerType::Hurricane => "Hurricane",
            DnsServerType::IbmCloud => "IbmCloud",
            DnsServerType::Infoblox => "Infoblox",
            DnsServerType::Infomaniak => "Infomaniak",
            DnsServerType::Inwx => "Inwx",
            DnsServerType::Ionos => "Ionos",
            DnsServerType::Ipv64 => "Ipv64",
            DnsServerType::Joker => "Joker",
            DnsServerType::Lightsail => "Lightsail",
            DnsServerType::Linode => "Linode",
            DnsServerType::LuaDns => "LuaDns",
            DnsServerType::MythicBeasts => "MythicBeasts",
            DnsServerType::Namecheap => "Namecheap",
            DnsServerType::NameDotCom => "NameDotCom",
            DnsServerType::NameSilo => "NameSilo",
            DnsServerType::Netcup => "Netcup",
            DnsServerType::Netlify => "Netlify",
            DnsServerType::Nifcloud => "Nifcloud",
            DnsServerType::Ns1 => "Ns1",
            DnsServerType::OracleCloud => "OracleCloud",
            DnsServerType::Plesk => "Plesk",
            DnsServerType::Safedns => "Safedns",
            DnsServerType::Scaleway => "Scaleway",
            DnsServerType::TencentCloud => "TencentCloud",
            DnsServerType::Transip => "Transip",
            DnsServerType::UltraDns => "UltraDns",
            DnsServerType::Vercel => "Vercel",
            DnsServerType::Volcengine => "Volcengine",
            DnsServerType::Vultr => "Vultr",
            DnsServerType::WebSupport => "WebSupport",
            DnsServerType::YandexCloud => "YandexCloud",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(DnsServerType::Tsig),
            1 => Some(DnsServerType::Deprecated1),
            2 => Some(DnsServerType::Cloudflare),
            3 => Some(DnsServerType::DigitalOcean),
            4 => Some(DnsServerType::DeSEC),
            5 => Some(DnsServerType::Ovh),
            6 => Some(DnsServerType::Bunny),
            7 => Some(DnsServerType::Porkbun),
            8 => Some(DnsServerType::Dnsimple),
            9 => Some(DnsServerType::Spaceship),
            10 => Some(DnsServerType::Route53),
            11 => Some(DnsServerType::GoogleCloudDns),
            12 => Some(DnsServerType::Alidns),
            13 => Some(DnsServerType::ArvanCloud),
            14 => Some(DnsServerType::Autodns),
            15 => Some(DnsServerType::AzureDns),
            16 => Some(DnsServerType::BaiduCloud),
            17 => Some(DnsServerType::BluecatV2),
            18 => Some(DnsServerType::ClouDns),
            19 => Some(DnsServerType::Constellix),
            20 => Some(DnsServerType::Cpanel),
            21 => Some(DnsServerType::Ddnss),
            22 => Some(DnsServerType::DnsMadeEasy),
            23 => Some(DnsServerType::Domeneshop),
            24 => Some(DnsServerType::Dreamhost),
            25 => Some(DnsServerType::DuckDns),
            26 => Some(DnsServerType::Dynu),
            27 => Some(DnsServerType::EasyDns),
            28 => Some(DnsServerType::EdgeDns),
            29 => Some(DnsServerType::Exoscale),
            30 => Some(DnsServerType::FreeMyIp),
            31 => Some(DnsServerType::GandiV5),
            32 => Some(DnsServerType::Gcore),
            33 => Some(DnsServerType::Glesys),
            34 => Some(DnsServerType::Godaddy),
            35 => Some(DnsServerType::Hetzner),
            36 => Some(DnsServerType::HostingDe),
            37 => Some(DnsServerType::Hostinger),
            38 => Some(DnsServerType::HuaweiCloud),
            39 => Some(DnsServerType::Hurricane),
            40 => Some(DnsServerType::IbmCloud),
            41 => Some(DnsServerType::Infoblox),
            42 => Some(DnsServerType::Infomaniak),
            43 => Some(DnsServerType::Inwx),
            44 => Some(DnsServerType::Ionos),
            45 => Some(DnsServerType::Ipv64),
            46 => Some(DnsServerType::Joker),
            47 => Some(DnsServerType::Lightsail),
            48 => Some(DnsServerType::Linode),
            49 => Some(DnsServerType::LuaDns),
            50 => Some(DnsServerType::MythicBeasts),
            51 => Some(DnsServerType::Namecheap),
            52 => Some(DnsServerType::NameDotCom),
            53 => Some(DnsServerType::NameSilo),
            54 => Some(DnsServerType::Netcup),
            55 => Some(DnsServerType::Netlify),
            56 => Some(DnsServerType::Nifcloud),
            57 => Some(DnsServerType::Ns1),
            58 => Some(DnsServerType::OracleCloud),
            59 => Some(DnsServerType::Plesk),
            60 => Some(DnsServerType::Safedns),
            61 => Some(DnsServerType::Scaleway),
            62 => Some(DnsServerType::TencentCloud),
            63 => Some(DnsServerType::Transip),
            64 => Some(DnsServerType::UltraDns),
            65 => Some(DnsServerType::Vercel),
            66 => Some(DnsServerType::Volcengine),
            67 => Some(DnsServerType::Vultr),
            68 => Some(DnsServerType::WebSupport),
            69 => Some(DnsServerType::YandexCloud),
            _ => None,
        }
    }

    const COUNT: usize = 70;
}

impl serde::Serialize for DnsServerType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DnsServerType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for EncryptionAtRestType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => EncryptionAtRestType::Disabled,
            b"Aes128" => EncryptionAtRestType::Aes128,
            b"Aes256" => EncryptionAtRestType::Aes256,
            b"Aes256Gcm" => EncryptionAtRestType::Aes256Gcm,
            b"ChaCha20Poly1305" => EncryptionAtRestType::ChaCha20Poly1305,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            EncryptionAtRestType::Disabled => "Disabled",
            EncryptionAtRestType::Aes128 => "Aes128",
            EncryptionAtRestType::Aes256 => "Aes256",
            EncryptionAtRestType::Aes256Gcm => "Aes256Gcm",
            EncryptionAtRestType::ChaCha20Poly1305 => "ChaCha20Poly1305",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(EncryptionAtRestType::Disabled),
            1 => Some(EncryptionAtRestType::Aes128),
            2 => Some(EncryptionAtRestType::Aes256),
            3 => Some(EncryptionAtRestType::Aes256Gcm),
            4 => Some(EncryptionAtRestType::ChaCha20Poly1305),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for EncryptionAtRestType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EncryptionAtRestType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for EventPolicy {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"include" => EventPolicy::Include,
            b"exclude" => EventPolicy::Exclude,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            EventPolicy::Include => "include",
            EventPolicy::Exclude => "exclude",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(EventPolicy::Include),
            1 => Some(EventPolicy::Exclude),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for EventPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EventPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ExpressionConstant {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"relaxed" => ExpressionConstant::Relaxed,
            b"strict" => ExpressionConstant::Strict,
            b"disable" => ExpressionConstant::Disable,
            b"optional" => ExpressionConstant::Optional,
            b"require" => ExpressionConstant::Require,
            b"ipv4_only" => ExpressionConstant::Ipv4Only,
            b"ipv6_only" => ExpressionConstant::Ipv6Only,
            b"ipv6_then_ipv4" => ExpressionConstant::Ipv6ThenIpv4,
            b"ipv4_then_ipv6" => ExpressionConstant::Ipv4ThenIpv6,
            b"hourly" => ExpressionConstant::Hourly,
            b"daily" => ExpressionConstant::Daily,
            b"weekly" => ExpressionConstant::Weekly,
            b"login" => ExpressionConstant::Login,
            b"plain" => ExpressionConstant::Plain,
            b"xoauth2" => ExpressionConstant::Xoauth2,
            b"oauthbearer" => ExpressionConstant::Oauthbearer,
            b"mixer" => ExpressionConstant::Mixer,
            b"stanag4406" => ExpressionConstant::Stanag4406,
            b"nsep" => ExpressionConstant::Nsep,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ExpressionConstant::Relaxed => "relaxed",
            ExpressionConstant::Strict => "strict",
            ExpressionConstant::Disable => "disable",
            ExpressionConstant::Optional => "optional",
            ExpressionConstant::Require => "require",
            ExpressionConstant::Ipv4Only => "ipv4_only",
            ExpressionConstant::Ipv6Only => "ipv6_only",
            ExpressionConstant::Ipv6ThenIpv4 => "ipv6_then_ipv4",
            ExpressionConstant::Ipv4ThenIpv6 => "ipv4_then_ipv6",
            ExpressionConstant::Hourly => "hourly",
            ExpressionConstant::Daily => "daily",
            ExpressionConstant::Weekly => "weekly",
            ExpressionConstant::Login => "login",
            ExpressionConstant::Plain => "plain",
            ExpressionConstant::Xoauth2 => "xoauth2",
            ExpressionConstant::Oauthbearer => "oauthbearer",
            ExpressionConstant::Mixer => "mixer",
            ExpressionConstant::Stanag4406 => "stanag4406",
            ExpressionConstant::Nsep => "nsep",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ExpressionConstant::Relaxed),
            1 => Some(ExpressionConstant::Strict),
            2 => Some(ExpressionConstant::Disable),
            3 => Some(ExpressionConstant::Optional),
            4 => Some(ExpressionConstant::Require),
            5 => Some(ExpressionConstant::Ipv4Only),
            6 => Some(ExpressionConstant::Ipv6Only),
            7 => Some(ExpressionConstant::Ipv6ThenIpv4),
            8 => Some(ExpressionConstant::Ipv4ThenIpv6),
            9 => Some(ExpressionConstant::Hourly),
            10 => Some(ExpressionConstant::Daily),
            11 => Some(ExpressionConstant::Weekly),
            12 => Some(ExpressionConstant::Login),
            13 => Some(ExpressionConstant::Plain),
            14 => Some(ExpressionConstant::Xoauth2),
            15 => Some(ExpressionConstant::Oauthbearer),
            16 => Some(ExpressionConstant::Mixer),
            17 => Some(ExpressionConstant::Stanag4406),
            18 => Some(ExpressionConstant::Nsep),
            _ => None,
        }
    }

    const COUNT: usize = 19;
}

impl serde::Serialize for ExpressionConstant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ExpressionConstant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ExpressionVariable {
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            ExpressionVariable,
            b"asn" => ExpressionVariable::Asn,
            b"attributes" => ExpressionVariable::Attributes,
            b"authenticated_as" => ExpressionVariable::AuthenticatedAs,
            b"authority" => ExpressionVariable::Authority,
            b"bcc" => ExpressionVariable::Bcc,
            b"bcc.domain" => ExpressionVariable::BccDomain,
            b"bcc.local" => ExpressionVariable::BccLocal,
            b"bcc.name" => ExpressionVariable::BccName,
            b"body" => ExpressionVariable::Body,
            b"body.html" => ExpressionVariable::BodyHtml,
            b"body.raw" => ExpressionVariable::BodyRaw,
            b"body.text" => ExpressionVariable::BodyText,
            b"body.words" => ExpressionVariable::BodyWords,
            b"cc" => ExpressionVariable::Cc,
            b"cc.domain" => ExpressionVariable::CcDomain,
            b"cc.local" => ExpressionVariable::CcLocal,
            b"cc.name" => ExpressionVariable::CcName,
            b"country" => ExpressionVariable::Country,
            b"domain" => ExpressionVariable::Domain,
            b"email" => ExpressionVariable::Email,
            b"email_lower" => ExpressionVariable::EmailLower,
            b"env_from" => ExpressionVariable::EnvFrom,
            b"env_from.domain" => ExpressionVariable::EnvFromDomain,
            b"env_from.local" => ExpressionVariable::EnvFromLocal,
            b"env_to" => ExpressionVariable::EnvTo,
            b"expires_in" => ExpressionVariable::ExpiresIn,
            b"from" => ExpressionVariable::From,
            b"from.domain" => ExpressionVariable::FromDomain,
            b"from.local" => ExpressionVariable::FromLocal,
            b"from.name" => ExpressionVariable::FromName,
            b"headers" => ExpressionVariable::Headers,
            b"helo_domain" => ExpressionVariable::HeloDomain,
            b"host" => ExpressionVariable::Host,
            b"ip" => ExpressionVariable::Ip,
            b"ip_reverse" => ExpressionVariable::IpReverse,
            b"is_tls" => ExpressionVariable::IsTls,
            b"is_v4" => ExpressionVariable::IsV4,
            b"is_v6" => ExpressionVariable::IsV6,
            b"last_error" => ExpressionVariable::LastError,
            b"last_status" => ExpressionVariable::LastStatus,
            b"listener" => ExpressionVariable::Listener,
            b"local" => ExpressionVariable::Local,
            b"local_ip" => ExpressionVariable::LocalIp,
            b"local_port" => ExpressionVariable::LocalPort,
            b"location" => ExpressionVariable::Location,
            b"method" => ExpressionVariable::Method,
            b"mx" => ExpressionVariable::Mx,
            b"name" => ExpressionVariable::Name,
            b"name_lower" => ExpressionVariable::NameLower,
            b"notify_num" => ExpressionVariable::NotifyNum,
            b"octets" => ExpressionVariable::Octets,
            b"path" => ExpressionVariable::Path,
            b"path_query" => ExpressionVariable::PathQuery,
            b"port" => ExpressionVariable::Port,
            b"priority" => ExpressionVariable::Priority,
            b"protocol" => ExpressionVariable::Protocol,
            b"query" => ExpressionVariable::Query,
            b"queue_age" => ExpressionVariable::QueueAge,
            b"queue_name" => ExpressionVariable::QueueName,
            b"raw" => ExpressionVariable::Raw,
            b"raw_lower" => ExpressionVariable::RawLower,
            b"rcpt" => ExpressionVariable::Rcpt,
            b"rcpt_domain" => ExpressionVariable::RcptDomain,
            b"received_from_ip" => ExpressionVariable::ReceivedFromIp,
            b"received_via_port" => ExpressionVariable::ReceivedViaPort,
            b"recipients" => ExpressionVariable::Recipients,
            b"remote_ip" => ExpressionVariable::RemoteIp,
            b"remote_ip.ptr" => ExpressionVariable::RemoteIpPtr,
            b"remote_port" => ExpressionVariable::RemotePort,
            b"reply_to" => ExpressionVariable::ReplyTo,
            b"reply_to.domain" => ExpressionVariable::ReplyToDomain,
            b"reply_to.local" => ExpressionVariable::ReplyToLocal,
            b"reply_to.name" => ExpressionVariable::ReplyToName,
            b"retry_num" => ExpressionVariable::RetryNum,
            b"reverse_ip" => ExpressionVariable::ReverseIp,
            b"scheme" => ExpressionVariable::Scheme,
            b"sender" => ExpressionVariable::Sender,
            b"sender_domain" => ExpressionVariable::SenderDomain,
            b"size" => ExpressionVariable::Size,
            b"sld" => ExpressionVariable::Sld,
            b"source" => ExpressionVariable::Source,
            b"subject" => ExpressionVariable::Subject,
            b"subject.thread" => ExpressionVariable::SubjectThread,
            b"subject.words" => ExpressionVariable::SubjectWords,
            b"to" => ExpressionVariable::To,
            b"to.domain" => ExpressionVariable::ToDomain,
            b"to.local" => ExpressionVariable::ToLocal,
            b"to.name" => ExpressionVariable::ToName,
            b"url" => ExpressionVariable::Url,
            b"value" => ExpressionVariable::Value,
            b"value_lower" => ExpressionVariable::ValueLower,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            ExpressionVariable::Asn => "asn",
            ExpressionVariable::Attributes => "attributes",
            ExpressionVariable::AuthenticatedAs => "authenticated_as",
            ExpressionVariable::Authority => "authority",
            ExpressionVariable::Bcc => "bcc",
            ExpressionVariable::BccDomain => "bcc.domain",
            ExpressionVariable::BccLocal => "bcc.local",
            ExpressionVariable::BccName => "bcc.name",
            ExpressionVariable::Body => "body",
            ExpressionVariable::BodyHtml => "body.html",
            ExpressionVariable::BodyRaw => "body.raw",
            ExpressionVariable::BodyText => "body.text",
            ExpressionVariable::BodyWords => "body.words",
            ExpressionVariable::Cc => "cc",
            ExpressionVariable::CcDomain => "cc.domain",
            ExpressionVariable::CcLocal => "cc.local",
            ExpressionVariable::CcName => "cc.name",
            ExpressionVariable::Country => "country",
            ExpressionVariable::Domain => "domain",
            ExpressionVariable::Email => "email",
            ExpressionVariable::EmailLower => "email_lower",
            ExpressionVariable::EnvFrom => "env_from",
            ExpressionVariable::EnvFromDomain => "env_from.domain",
            ExpressionVariable::EnvFromLocal => "env_from.local",
            ExpressionVariable::EnvTo => "env_to",
            ExpressionVariable::ExpiresIn => "expires_in",
            ExpressionVariable::From => "from",
            ExpressionVariable::FromDomain => "from.domain",
            ExpressionVariable::FromLocal => "from.local",
            ExpressionVariable::FromName => "from.name",
            ExpressionVariable::Headers => "headers",
            ExpressionVariable::HeloDomain => "helo_domain",
            ExpressionVariable::Host => "host",
            ExpressionVariable::Ip => "ip",
            ExpressionVariable::IpReverse => "ip_reverse",
            ExpressionVariable::IsTls => "is_tls",
            ExpressionVariable::IsV4 => "is_v4",
            ExpressionVariable::IsV6 => "is_v6",
            ExpressionVariable::LastError => "last_error",
            ExpressionVariable::LastStatus => "last_status",
            ExpressionVariable::Listener => "listener",
            ExpressionVariable::Local => "local",
            ExpressionVariable::LocalIp => "local_ip",
            ExpressionVariable::LocalPort => "local_port",
            ExpressionVariable::Location => "location",
            ExpressionVariable::Method => "method",
            ExpressionVariable::Mx => "mx",
            ExpressionVariable::Name => "name",
            ExpressionVariable::NameLower => "name_lower",
            ExpressionVariable::NotifyNum => "notify_num",
            ExpressionVariable::Octets => "octets",
            ExpressionVariable::Path => "path",
            ExpressionVariable::PathQuery => "path_query",
            ExpressionVariable::Port => "port",
            ExpressionVariable::Priority => "priority",
            ExpressionVariable::Protocol => "protocol",
            ExpressionVariable::Query => "query",
            ExpressionVariable::QueueAge => "queue_age",
            ExpressionVariable::QueueName => "queue_name",
            ExpressionVariable::Raw => "raw",
            ExpressionVariable::RawLower => "raw_lower",
            ExpressionVariable::Rcpt => "rcpt",
            ExpressionVariable::RcptDomain => "rcpt_domain",
            ExpressionVariable::ReceivedFromIp => "received_from_ip",
            ExpressionVariable::ReceivedViaPort => "received_via_port",
            ExpressionVariable::Recipients => "recipients",
            ExpressionVariable::RemoteIp => "remote_ip",
            ExpressionVariable::RemoteIpPtr => "remote_ip.ptr",
            ExpressionVariable::RemotePort => "remote_port",
            ExpressionVariable::ReplyTo => "reply_to",
            ExpressionVariable::ReplyToDomain => "reply_to.domain",
            ExpressionVariable::ReplyToLocal => "reply_to.local",
            ExpressionVariable::ReplyToName => "reply_to.name",
            ExpressionVariable::RetryNum => "retry_num",
            ExpressionVariable::ReverseIp => "reverse_ip",
            ExpressionVariable::Scheme => "scheme",
            ExpressionVariable::Sender => "sender",
            ExpressionVariable::SenderDomain => "sender_domain",
            ExpressionVariable::Size => "size",
            ExpressionVariable::Sld => "sld",
            ExpressionVariable::Source => "source",
            ExpressionVariable::Subject => "subject",
            ExpressionVariable::SubjectThread => "subject.thread",
            ExpressionVariable::SubjectWords => "subject.words",
            ExpressionVariable::To => "to",
            ExpressionVariable::ToDomain => "to.domain",
            ExpressionVariable::ToLocal => "to.local",
            ExpressionVariable::ToName => "to.name",
            ExpressionVariable::Url => "url",
            ExpressionVariable::Value => "value",
            ExpressionVariable::ValueLower => "value_lower",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ExpressionVariable::Asn),
            1 => Some(ExpressionVariable::Attributes),
            2 => Some(ExpressionVariable::AuthenticatedAs),
            3 => Some(ExpressionVariable::Authority),
            4 => Some(ExpressionVariable::Bcc),
            5 => Some(ExpressionVariable::BccDomain),
            6 => Some(ExpressionVariable::BccLocal),
            7 => Some(ExpressionVariable::BccName),
            8 => Some(ExpressionVariable::Body),
            9 => Some(ExpressionVariable::BodyHtml),
            10 => Some(ExpressionVariable::BodyRaw),
            11 => Some(ExpressionVariable::BodyText),
            12 => Some(ExpressionVariable::BodyWords),
            13 => Some(ExpressionVariable::Cc),
            14 => Some(ExpressionVariable::CcDomain),
            15 => Some(ExpressionVariable::CcLocal),
            16 => Some(ExpressionVariable::CcName),
            17 => Some(ExpressionVariable::Country),
            18 => Some(ExpressionVariable::Domain),
            19 => Some(ExpressionVariable::Email),
            20 => Some(ExpressionVariable::EmailLower),
            21 => Some(ExpressionVariable::EnvFrom),
            22 => Some(ExpressionVariable::EnvFromDomain),
            23 => Some(ExpressionVariable::EnvFromLocal),
            24 => Some(ExpressionVariable::EnvTo),
            25 => Some(ExpressionVariable::ExpiresIn),
            26 => Some(ExpressionVariable::From),
            27 => Some(ExpressionVariable::FromDomain),
            28 => Some(ExpressionVariable::FromLocal),
            29 => Some(ExpressionVariable::FromName),
            30 => Some(ExpressionVariable::Headers),
            31 => Some(ExpressionVariable::HeloDomain),
            32 => Some(ExpressionVariable::Host),
            33 => Some(ExpressionVariable::Ip),
            34 => Some(ExpressionVariable::IpReverse),
            35 => Some(ExpressionVariable::IsTls),
            36 => Some(ExpressionVariable::IsV4),
            37 => Some(ExpressionVariable::IsV6),
            38 => Some(ExpressionVariable::LastError),
            39 => Some(ExpressionVariable::LastStatus),
            40 => Some(ExpressionVariable::Listener),
            41 => Some(ExpressionVariable::Local),
            42 => Some(ExpressionVariable::LocalIp),
            43 => Some(ExpressionVariable::LocalPort),
            44 => Some(ExpressionVariable::Location),
            45 => Some(ExpressionVariable::Method),
            46 => Some(ExpressionVariable::Mx),
            47 => Some(ExpressionVariable::Name),
            48 => Some(ExpressionVariable::NameLower),
            49 => Some(ExpressionVariable::NotifyNum),
            50 => Some(ExpressionVariable::Octets),
            51 => Some(ExpressionVariable::Path),
            52 => Some(ExpressionVariable::PathQuery),
            53 => Some(ExpressionVariable::Port),
            54 => Some(ExpressionVariable::Priority),
            55 => Some(ExpressionVariable::Protocol),
            56 => Some(ExpressionVariable::Query),
            57 => Some(ExpressionVariable::QueueAge),
            58 => Some(ExpressionVariable::QueueName),
            59 => Some(ExpressionVariable::Raw),
            60 => Some(ExpressionVariable::RawLower),
            61 => Some(ExpressionVariable::Rcpt),
            62 => Some(ExpressionVariable::RcptDomain),
            63 => Some(ExpressionVariable::ReceivedFromIp),
            64 => Some(ExpressionVariable::ReceivedViaPort),
            65 => Some(ExpressionVariable::Recipients),
            66 => Some(ExpressionVariable::RemoteIp),
            67 => Some(ExpressionVariable::RemoteIpPtr),
            68 => Some(ExpressionVariable::RemotePort),
            69 => Some(ExpressionVariable::ReplyTo),
            70 => Some(ExpressionVariable::ReplyToDomain),
            71 => Some(ExpressionVariable::ReplyToLocal),
            72 => Some(ExpressionVariable::ReplyToName),
            73 => Some(ExpressionVariable::RetryNum),
            74 => Some(ExpressionVariable::ReverseIp),
            75 => Some(ExpressionVariable::Scheme),
            76 => Some(ExpressionVariable::Sender),
            77 => Some(ExpressionVariable::SenderDomain),
            78 => Some(ExpressionVariable::Size),
            79 => Some(ExpressionVariable::Sld),
            80 => Some(ExpressionVariable::Source),
            81 => Some(ExpressionVariable::Subject),
            82 => Some(ExpressionVariable::SubjectThread),
            83 => Some(ExpressionVariable::SubjectWords),
            84 => Some(ExpressionVariable::To),
            85 => Some(ExpressionVariable::ToDomain),
            86 => Some(ExpressionVariable::ToLocal),
            87 => Some(ExpressionVariable::ToName),
            88 => Some(ExpressionVariable::Url),
            89 => Some(ExpressionVariable::Value),
            90 => Some(ExpressionVariable::ValueLower),
            _ => None,
        }
    }

    const COUNT: usize = 91;
}

impl serde::Serialize for ExpressionVariable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ExpressionVariable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for FailureReportingOption {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"all" => FailureReportingOption::All,
            b"any" => FailureReportingOption::Any,
            b"dkimFailure" => FailureReportingOption::DkimFailure,
            b"spfFailure" => FailureReportingOption::SpfFailure,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            FailureReportingOption::All => "all",
            FailureReportingOption::Any => "any",
            FailureReportingOption::DkimFailure => "dkimFailure",
            FailureReportingOption::SpfFailure => "spfFailure",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(FailureReportingOption::All),
            1 => Some(FailureReportingOption::Any),
            2 => Some(FailureReportingOption::DkimFailure),
            3 => Some(FailureReportingOption::SpfFailure),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for FailureReportingOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for FailureReportingOption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for HttpAuthType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Unauthenticated" => HttpAuthType::Unauthenticated,
            b"Basic" => HttpAuthType::Basic,
            b"Bearer" => HttpAuthType::Bearer,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            HttpAuthType::Unauthenticated => "Unauthenticated",
            HttpAuthType::Basic => "Basic",
            HttpAuthType::Bearer => "Bearer",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(HttpAuthType::Unauthenticated),
            1 => Some(HttpAuthType::Basic),
            2 => Some(HttpAuthType::Bearer),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for HttpAuthType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for HttpAuthType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for HttpLookupFormatType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Csv" => HttpLookupFormatType::Csv,
            b"List" => HttpLookupFormatType::List,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            HttpLookupFormatType::Csv => "Csv",
            HttpLookupFormatType::List => "List",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(HttpLookupFormatType::Csv),
            1 => Some(HttpLookupFormatType::List),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for HttpLookupFormatType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for HttpLookupFormatType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for InMemoryStoreBaseType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Redis" => InMemoryStoreBaseType::Redis,
            b"RedisCluster" => InMemoryStoreBaseType::RedisCluster,
            b"RedisSentinel" => InMemoryStoreBaseType::RedisSentinel,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            InMemoryStoreBaseType::Redis => "Redis",
            InMemoryStoreBaseType::RedisCluster => "RedisCluster",
            InMemoryStoreBaseType::RedisSentinel => "RedisSentinel",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(InMemoryStoreBaseType::Redis),
            1 => Some(InMemoryStoreBaseType::RedisCluster),
            2 => Some(InMemoryStoreBaseType::RedisSentinel),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for InMemoryStoreBaseType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for InMemoryStoreBaseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for InMemoryStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Default" => InMemoryStoreType::Default,
            b"Sharded" => InMemoryStoreType::Sharded,
            b"Redis" => InMemoryStoreType::Redis,
            b"RedisCluster" => InMemoryStoreType::RedisCluster,
            b"RedisSentinel" => InMemoryStoreType::RedisSentinel,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            InMemoryStoreType::Default => "Default",
            InMemoryStoreType::Sharded => "Sharded",
            InMemoryStoreType::Redis => "Redis",
            InMemoryStoreType::RedisCluster => "RedisCluster",
            InMemoryStoreType::RedisSentinel => "RedisSentinel",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(InMemoryStoreType::Default),
            1 => Some(InMemoryStoreType::Sharded),
            2 => Some(InMemoryStoreType::Redis),
            3 => Some(InMemoryStoreType::RedisCluster),
            4 => Some(InMemoryStoreType::RedisSentinel),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for InMemoryStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for InMemoryStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for IndexDocumentType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"email" => IndexDocumentType::Email,
            b"calendar" => IndexDocumentType::Calendar,
            b"contacts" => IndexDocumentType::Contacts,
            b"file" => IndexDocumentType::File,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            IndexDocumentType::Email => "email",
            IndexDocumentType::Calendar => "calendar",
            IndexDocumentType::Contacts => "contacts",
            IndexDocumentType::File => "file",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(IndexDocumentType::Email),
            1 => Some(IndexDocumentType::Calendar),
            2 => Some(IndexDocumentType::Contacts),
            3 => Some(IndexDocumentType::File),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for IndexDocumentType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for IndexDocumentType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for IpProtocol {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"udp" => IpProtocol::Udp,
            b"tcp" => IpProtocol::Tcp,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            IpProtocol::Udp => "udp",
            IpProtocol::Tcp => "tcp",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(IpProtocol::Udp),
            1 => Some(IpProtocol::Tcp),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for IpProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for IpProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for JokerAuthType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"ApiKey" => JokerAuthType::ApiKey,
            b"UsernamePassword" => JokerAuthType::UsernamePassword,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            JokerAuthType::ApiKey => "ApiKey",
            JokerAuthType::UsernamePassword => "UsernamePassword",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(JokerAuthType::ApiKey),
            1 => Some(JokerAuthType::UsernamePassword),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for JokerAuthType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for JokerAuthType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for JwtSignatureAlgorithm {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"es256" => JwtSignatureAlgorithm::Es256,
            b"es384" => JwtSignatureAlgorithm::Es384,
            b"ps256" => JwtSignatureAlgorithm::Ps256,
            b"ps384" => JwtSignatureAlgorithm::Ps384,
            b"ps512" => JwtSignatureAlgorithm::Ps512,
            b"rs256" => JwtSignatureAlgorithm::Rs256,
            b"rs384" => JwtSignatureAlgorithm::Rs384,
            b"rs512" => JwtSignatureAlgorithm::Rs512,
            b"hs256" => JwtSignatureAlgorithm::Hs256,
            b"hs384" => JwtSignatureAlgorithm::Hs384,
            b"hs512" => JwtSignatureAlgorithm::Hs512,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            JwtSignatureAlgorithm::Es256 => "es256",
            JwtSignatureAlgorithm::Es384 => "es384",
            JwtSignatureAlgorithm::Ps256 => "ps256",
            JwtSignatureAlgorithm::Ps384 => "ps384",
            JwtSignatureAlgorithm::Ps512 => "ps512",
            JwtSignatureAlgorithm::Rs256 => "rs256",
            JwtSignatureAlgorithm::Rs384 => "rs384",
            JwtSignatureAlgorithm::Rs512 => "rs512",
            JwtSignatureAlgorithm::Hs256 => "hs256",
            JwtSignatureAlgorithm::Hs384 => "hs384",
            JwtSignatureAlgorithm::Hs512 => "hs512",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(JwtSignatureAlgorithm::Es256),
            1 => Some(JwtSignatureAlgorithm::Es384),
            2 => Some(JwtSignatureAlgorithm::Ps256),
            3 => Some(JwtSignatureAlgorithm::Ps384),
            4 => Some(JwtSignatureAlgorithm::Ps512),
            5 => Some(JwtSignatureAlgorithm::Rs256),
            6 => Some(JwtSignatureAlgorithm::Rs384),
            7 => Some(JwtSignatureAlgorithm::Rs512),
            8 => Some(JwtSignatureAlgorithm::Hs256),
            9 => Some(JwtSignatureAlgorithm::Hs384),
            10 => Some(JwtSignatureAlgorithm::Hs512),
            _ => None,
        }
    }

    const COUNT: usize = 11;
}

impl serde::Serialize for JwtSignatureAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for JwtSignatureAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for Locale {
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            Locale,
            b"POSIX" => Locale::POSIX,
            b"aa_DJ" => Locale::AaDJ,
            b"aa_ER" => Locale::AaER,
            b"aa_ER@saaho" => Locale::AaERSaaho,
            b"aa_ET" => Locale::AaET,
            b"af_ZA" => Locale::AfZA,
            b"agr_PE" => Locale::AgrPE,
            b"ak_GH" => Locale::AkGH,
            b"am_ET" => Locale::AmET,
            b"an_ES" => Locale::AnES,
            b"anp_IN" => Locale::AnpIN,
            b"ar_AE" => Locale::ArAE,
            b"ar_BH" => Locale::ArBH,
            b"ar_DZ" => Locale::ArDZ,
            b"ar_EG" => Locale::ArEG,
            b"ar_IN" => Locale::ArIN,
            b"ar_IQ" => Locale::ArIQ,
            b"ar_JO" => Locale::ArJO,
            b"ar_KW" => Locale::ArKW,
            b"ar_LB" => Locale::ArLB,
            b"ar_LY" => Locale::ArLY,
            b"ar_MA" => Locale::ArMA,
            b"ar_OM" => Locale::ArOM,
            b"ar_QA" => Locale::ArQA,
            b"ar_SA" => Locale::ArSA,
            b"ar_SD" => Locale::ArSD,
            b"ar_SS" => Locale::ArSS,
            b"ar_SY" => Locale::ArSY,
            b"ar_TN" => Locale::ArTN,
            b"ar_YE" => Locale::ArYE,
            b"as_IN" => Locale::AsIN,
            b"ast_ES" => Locale::AstES,
            b"ayc_PE" => Locale::AycPE,
            b"az_AZ" => Locale::AzAZ,
            b"az_IR" => Locale::AzIR,
            b"be_BY" => Locale::BeBY,
            b"be_BY@latin" => Locale::BeBYLatin,
            b"bem_ZM" => Locale::BemZM,
            b"ber_DZ" => Locale::BerDZ,
            b"ber_MA" => Locale::BerMA,
            b"bg_BG" => Locale::BgBG,
            b"bhb_IN" => Locale::BhbIN,
            b"bho_IN" => Locale::BhoIN,
            b"bho_NP" => Locale::BhoNP,
            b"bi_VU" => Locale::BiVU,
            b"bn_BD" => Locale::BnBD,
            b"bn_IN" => Locale::BnIN,
            b"bo_CN" => Locale::BoCN,
            b"bo_IN" => Locale::BoIN,
            b"br_FR" => Locale::BrFR,
            b"br_FR@euro" => Locale::BrFREuro,
            b"brx_IN" => Locale::BrxIN,
            b"bs_BA" => Locale::BsBA,
            b"byn_ER" => Locale::BynER,
            b"ca_AD" => Locale::CaAD,
            b"ca_ES" => Locale::CaES,
            b"ca_ES@euro" => Locale::CaESEuro,
            b"ca_ES@valencia" => Locale::CaESValencia,
            b"ca_FR" => Locale::CaFR,
            b"ca_IT" => Locale::CaIT,
            b"ce_RU" => Locale::CeRU,
            b"chr_US" => Locale::ChrUS,
            b"cmn_TW" => Locale::CmnTW,
            b"crh_UA" => Locale::CrhUA,
            b"cs_CZ" => Locale::CsCZ,
            b"csb_PL" => Locale::CsbPL,
            b"cv_RU" => Locale::CvRU,
            b"cy_GB" => Locale::CyGB,
            b"da_DK" => Locale::DaDK,
            b"de_AT" => Locale::DeAT,
            b"de_AT@euro" => Locale::DeATEuro,
            b"de_BE" => Locale::DeBE,
            b"de_BE@euro" => Locale::DeBEEuro,
            b"de_CH" => Locale::DeCH,
            b"de_DE" => Locale::DeDE,
            b"de_DE@euro" => Locale::DeDEEuro,
            b"de_IT" => Locale::DeIT,
            b"de_LI" => Locale::DeLI,
            b"de_LU" => Locale::DeLU,
            b"de_LU@euro" => Locale::DeLUEuro,
            b"doi_IN" => Locale::DoiIN,
            b"dsb_DE" => Locale::DsbDE,
            b"dv_MV" => Locale::DvMV,
            b"dz_BT" => Locale::DzBT,
            b"el_CY" => Locale::ElCY,
            b"el_GR" => Locale::ElGR,
            b"el_GR@euro" => Locale::ElGREuro,
            b"en_AG" => Locale::EnAG,
            b"en_AU" => Locale::EnAU,
            b"en_BW" => Locale::EnBW,
            b"en_CA" => Locale::EnCA,
            b"en_DK" => Locale::EnDK,
            b"en_GB" => Locale::EnGB,
            b"en_HK" => Locale::EnHK,
            b"en_IE" => Locale::EnIE,
            b"en_IE@euro" => Locale::EnIEEuro,
            b"en_IL" => Locale::EnIL,
            b"en_IN" => Locale::EnIN,
            b"en_NG" => Locale::EnNG,
            b"en_NZ" => Locale::EnNZ,
            b"en_PH" => Locale::EnPH,
            b"en_SC" => Locale::EnSC,
            b"en_SG" => Locale::EnSG,
            b"en_US" => Locale::EnUS,
            b"en_ZA" => Locale::EnZA,
            b"en_ZM" => Locale::EnZM,
            b"en_ZW" => Locale::EnZW,
            b"eo" => Locale::Eo,
            b"es_AR" => Locale::EsAR,
            b"es_BO" => Locale::EsBO,
            b"es_CL" => Locale::EsCL,
            b"es_CO" => Locale::EsCO,
            b"es_CR" => Locale::EsCR,
            b"es_CU" => Locale::EsCU,
            b"es_DO" => Locale::EsDO,
            b"es_EC" => Locale::EsEC,
            b"es_ES" => Locale::EsES,
            b"es_ES@euro" => Locale::EsESEuro,
            b"es_GT" => Locale::EsGT,
            b"es_HN" => Locale::EsHN,
            b"es_MX" => Locale::EsMX,
            b"es_NI" => Locale::EsNI,
            b"es_PA" => Locale::EsPA,
            b"es_PE" => Locale::EsPE,
            b"es_PR" => Locale::EsPR,
            b"es_PY" => Locale::EsPY,
            b"es_SV" => Locale::EsSV,
            b"es_US" => Locale::EsUS,
            b"es_UY" => Locale::EsUY,
            b"es_VE" => Locale::EsVE,
            b"et_EE" => Locale::EtEE,
            b"eu_ES" => Locale::EuES,
            b"eu_ES@euro" => Locale::EuESEuro,
            b"fa_IR" => Locale::FaIR,
            b"ff_SN" => Locale::FfSN,
            b"fi_FI" => Locale::FiFI,
            b"fi_FI@euro" => Locale::FiFIEuro,
            b"fil_PH" => Locale::FilPH,
            b"fo_FO" => Locale::FoFO,
            b"fr_BE" => Locale::FrBE,
            b"fr_BE@euro" => Locale::FrBEEuro,
            b"fr_CA" => Locale::FrCA,
            b"fr_CH" => Locale::FrCH,
            b"fr_FR" => Locale::FrFR,
            b"fr_FR@euro" => Locale::FrFREuro,
            b"fr_LU" => Locale::FrLU,
            b"fr_LU@euro" => Locale::FrLUEuro,
            b"fur_IT" => Locale::FurIT,
            b"fy_DE" => Locale::FyDE,
            b"fy_NL" => Locale::FyNL,
            b"ga_IE" => Locale::GaIE,
            b"ga_IE@euro" => Locale::GaIEEuro,
            b"gd_GB" => Locale::GdGB,
            b"gez_ER" => Locale::GezER,
            b"gez_ER@abegede" => Locale::GezERAbegede,
            b"gez_ET" => Locale::GezET,
            b"gez_ET@abegede" => Locale::GezETAbegede,
            b"gl_ES" => Locale::GlES,
            b"gl_ES@euro" => Locale::GlESEuro,
            b"gu_IN" => Locale::GuIN,
            b"gv_GB" => Locale::GvGB,
            b"ha_NG" => Locale::HaNG,
            b"hak_TW" => Locale::HakTW,
            b"he_IL" => Locale::HeIL,
            b"hi_IN" => Locale::HiIN,
            b"hif_FJ" => Locale::HifFJ,
            b"hne_IN" => Locale::HneIN,
            b"hr_HR" => Locale::HrHR,
            b"hsb_DE" => Locale::HsbDE,
            b"ht_HT" => Locale::HtHT,
            b"hu_HU" => Locale::HuHU,
            b"hy_AM" => Locale::HyAM,
            b"ia_FR" => Locale::IaFR,
            b"id_ID" => Locale::IdID,
            b"ig_NG" => Locale::IgNG,
            b"ik_CA" => Locale::IkCA,
            b"is_IS" => Locale::IsIS,
            b"it_CH" => Locale::ItCH,
            b"it_IT" => Locale::ItIT,
            b"it_IT@euro" => Locale::ItITEuro,
            b"iu_CA" => Locale::IuCA,
            b"ja_JP" => Locale::JaJP,
            b"ka_GE" => Locale::KaGE,
            b"kab_DZ" => Locale::KabDZ,
            b"kk_KZ" => Locale::KkKZ,
            b"kl_GL" => Locale::KlGL,
            b"km_KH" => Locale::KmKH,
            b"kn_IN" => Locale::KnIN,
            b"ko_KR" => Locale::KoKR,
            b"kok_IN" => Locale::KokIN,
            b"ks_IN" => Locale::KsIN,
            b"ks_IN@devanagari" => Locale::KsINDevanagari,
            b"ku_TR" => Locale::KuTR,
            b"kw_GB" => Locale::KwGB,
            b"ky_KG" => Locale::KyKG,
            b"lb_LU" => Locale::LbLU,
            b"lg_UG" => Locale::LgUG,
            b"li_BE" => Locale::LiBE,
            b"li_NL" => Locale::LiNL,
            b"lij_IT" => Locale::LijIT,
            b"ln_CD" => Locale::LnCD,
            b"lo_LA" => Locale::LoLA,
            b"lt_LT" => Locale::LtLT,
            b"lv_LV" => Locale::LvLV,
            b"lzh_TW" => Locale::LzhTW,
            b"mag_IN" => Locale::MagIN,
            b"mai_IN" => Locale::MaiIN,
            b"mai_NP" => Locale::MaiNP,
            b"mfe_MU" => Locale::MfeMU,
            b"mg_MG" => Locale::MgMG,
            b"mhr_RU" => Locale::MhrRU,
            b"mi_NZ" => Locale::MiNZ,
            b"miq_NI" => Locale::MiqNI,
            b"mjw_IN" => Locale::MjwIN,
            b"mk_MK" => Locale::MkMK,
            b"ml_IN" => Locale::MlIN,
            b"mn_MN" => Locale::MnMN,
            b"mni_IN" => Locale::MniIN,
            b"mnw_MM" => Locale::MnwMM,
            b"mr_IN" => Locale::MrIN,
            b"ms_MY" => Locale::MsMY,
            b"mt_MT" => Locale::MtMT,
            b"my_MM" => Locale::MyMM,
            b"nan_TW" => Locale::NanTW,
            b"nan_TW@latin" => Locale::NanTWLatin,
            b"nb_NO" => Locale::NbNO,
            b"nds_DE" => Locale::NdsDE,
            b"nds_NL" => Locale::NdsNL,
            b"ne_NP" => Locale::NeNP,
            b"nhn_MX" => Locale::NhnMX,
            b"niu_NU" => Locale::NiuNU,
            b"niu_NZ" => Locale::NiuNZ,
            b"nl_AW" => Locale::NlAW,
            b"nl_BE" => Locale::NlBE,
            b"nl_BE@euro" => Locale::NlBEEuro,
            b"nl_NL" => Locale::NlNL,
            b"nl_NL@euro" => Locale::NlNLEuro,
            b"nn_NO" => Locale::NnNO,
            b"nr_ZA" => Locale::NrZA,
            b"nso_ZA" => Locale::NsoZA,
            b"oc_FR" => Locale::OcFR,
            b"om_ET" => Locale::OmET,
            b"om_KE" => Locale::OmKE,
            b"or_IN" => Locale::OrIN,
            b"os_RU" => Locale::OsRU,
            b"pa_IN" => Locale::PaIN,
            b"pa_PK" => Locale::PaPK,
            b"pap_AW" => Locale::PapAW,
            b"pap_CW" => Locale::PapCW,
            b"pl_PL" => Locale::PlPL,
            b"ps_AF" => Locale::PsAF,
            b"pt_BR" => Locale::PtBR,
            b"pt_PT" => Locale::PtPT,
            b"pt_PT@euro" => Locale::PtPTEuro,
            b"quz_PE" => Locale::QuzPE,
            b"raj_IN" => Locale::RajIN,
            b"ro_RO" => Locale::RoRO,
            b"ru_RU" => Locale::RuRU,
            b"ru_UA" => Locale::RuUA,
            b"rw_RW" => Locale::RwRW,
            b"sa_IN" => Locale::SaIN,
            b"sah_RU" => Locale::SahRU,
            b"sat_IN" => Locale::SatIN,
            b"sc_IT" => Locale::ScIT,
            b"sd_IN" => Locale::SdIN,
            b"sd_IN@devanagari" => Locale::SdINDevanagari,
            b"se_NO" => Locale::SeNO,
            b"sgs_LT" => Locale::SgsLT,
            b"shn_MM" => Locale::ShnMM,
            b"shs_CA" => Locale::ShsCA,
            b"si_LK" => Locale::SiLK,
            b"sid_ET" => Locale::SidET,
            b"sk_SK" => Locale::SkSK,
            b"sl_SI" => Locale::SlSI,
            b"sm_WS" => Locale::SmWS,
            b"so_DJ" => Locale::SoDJ,
            b"so_ET" => Locale::SoET,
            b"so_KE" => Locale::SoKE,
            b"so_SO" => Locale::SoSO,
            b"sq_AL" => Locale::SqAL,
            b"sq_MK" => Locale::SqMK,
            b"sr_ME" => Locale::SrME,
            b"sr_RS" => Locale::SrRS,
            b"sr_RS@latin" => Locale::SrRSLatin,
            b"ss_ZA" => Locale::SsZA,
            b"st_ZA" => Locale::StZA,
            b"sv_FI" => Locale::SvFI,
            b"sv_FI@euro" => Locale::SvFIEuro,
            b"sv_SE" => Locale::SvSE,
            b"sw_KE" => Locale::SwKE,
            b"sw_TZ" => Locale::SwTZ,
            b"szl_PL" => Locale::SzlPL,
            b"ta_IN" => Locale::TaIN,
            b"ta_LK" => Locale::TaLK,
            b"tcy_IN" => Locale::TcyIN,
            b"te_IN" => Locale::TeIN,
            b"tg_TJ" => Locale::TgTJ,
            b"th_TH" => Locale::ThTH,
            b"the_NP" => Locale::TheNP,
            b"ti_ER" => Locale::TiER,
            b"ti_ET" => Locale::TiET,
            b"tig_ER" => Locale::TigER,
            b"tk_TM" => Locale::TkTM,
            b"tl_PH" => Locale::TlPH,
            b"tn_ZA" => Locale::TnZA,
            b"to_TO" => Locale::ToTO,
            b"tpi_PG" => Locale::TpiPG,
            b"tr_CY" => Locale::TrCY,
            b"tr_TR" => Locale::TrTR,
            b"ts_ZA" => Locale::TsZA,
            b"tt_RU" => Locale::TtRU,
            b"tt_RU@iqtelif" => Locale::TtRUIqtelif,
            b"ug_CN" => Locale::UgCN,
            b"uk_UA" => Locale::UkUA,
            b"unm_US" => Locale::UnmUS,
            b"ur_IN" => Locale::UrIN,
            b"ur_PK" => Locale::UrPK,
            b"uz_UZ" => Locale::UzUZ,
            b"uz_UZ@cyrillic" => Locale::UzUZCyrillic,
            b"ve_ZA" => Locale::VeZA,
            b"vi_VN" => Locale::ViVN,
            b"wa_BE" => Locale::WaBE,
            b"wa_BE@euro" => Locale::WaBEEuro,
            b"wae_CH" => Locale::WaeCH,
            b"wal_ET" => Locale::WalET,
            b"wo_SN" => Locale::WoSN,
            b"xh_ZA" => Locale::XhZA,
            b"yi_US" => Locale::YiUS,
            b"yo_NG" => Locale::YoNG,
            b"yue_HK" => Locale::YueHK,
            b"yuw_PG" => Locale::YuwPG,
            b"zh_CN" => Locale::ZhCN,
            b"zh_HK" => Locale::ZhHK,
            b"zh_SG" => Locale::ZhSG,
            b"zh_TW" => Locale::ZhTW,
            b"zu_ZA" => Locale::ZuZA,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            Locale::POSIX => "POSIX",
            Locale::AaDJ => "aa_DJ",
            Locale::AaER => "aa_ER",
            Locale::AaERSaaho => "aa_ER@saaho",
            Locale::AaET => "aa_ET",
            Locale::AfZA => "af_ZA",
            Locale::AgrPE => "agr_PE",
            Locale::AkGH => "ak_GH",
            Locale::AmET => "am_ET",
            Locale::AnES => "an_ES",
            Locale::AnpIN => "anp_IN",
            Locale::ArAE => "ar_AE",
            Locale::ArBH => "ar_BH",
            Locale::ArDZ => "ar_DZ",
            Locale::ArEG => "ar_EG",
            Locale::ArIN => "ar_IN",
            Locale::ArIQ => "ar_IQ",
            Locale::ArJO => "ar_JO",
            Locale::ArKW => "ar_KW",
            Locale::ArLB => "ar_LB",
            Locale::ArLY => "ar_LY",
            Locale::ArMA => "ar_MA",
            Locale::ArOM => "ar_OM",
            Locale::ArQA => "ar_QA",
            Locale::ArSA => "ar_SA",
            Locale::ArSD => "ar_SD",
            Locale::ArSS => "ar_SS",
            Locale::ArSY => "ar_SY",
            Locale::ArTN => "ar_TN",
            Locale::ArYE => "ar_YE",
            Locale::AsIN => "as_IN",
            Locale::AstES => "ast_ES",
            Locale::AycPE => "ayc_PE",
            Locale::AzAZ => "az_AZ",
            Locale::AzIR => "az_IR",
            Locale::BeBY => "be_BY",
            Locale::BeBYLatin => "be_BY@latin",
            Locale::BemZM => "bem_ZM",
            Locale::BerDZ => "ber_DZ",
            Locale::BerMA => "ber_MA",
            Locale::BgBG => "bg_BG",
            Locale::BhbIN => "bhb_IN",
            Locale::BhoIN => "bho_IN",
            Locale::BhoNP => "bho_NP",
            Locale::BiVU => "bi_VU",
            Locale::BnBD => "bn_BD",
            Locale::BnIN => "bn_IN",
            Locale::BoCN => "bo_CN",
            Locale::BoIN => "bo_IN",
            Locale::BrFR => "br_FR",
            Locale::BrFREuro => "br_FR@euro",
            Locale::BrxIN => "brx_IN",
            Locale::BsBA => "bs_BA",
            Locale::BynER => "byn_ER",
            Locale::CaAD => "ca_AD",
            Locale::CaES => "ca_ES",
            Locale::CaESEuro => "ca_ES@euro",
            Locale::CaESValencia => "ca_ES@valencia",
            Locale::CaFR => "ca_FR",
            Locale::CaIT => "ca_IT",
            Locale::CeRU => "ce_RU",
            Locale::ChrUS => "chr_US",
            Locale::CmnTW => "cmn_TW",
            Locale::CrhUA => "crh_UA",
            Locale::CsCZ => "cs_CZ",
            Locale::CsbPL => "csb_PL",
            Locale::CvRU => "cv_RU",
            Locale::CyGB => "cy_GB",
            Locale::DaDK => "da_DK",
            Locale::DeAT => "de_AT",
            Locale::DeATEuro => "de_AT@euro",
            Locale::DeBE => "de_BE",
            Locale::DeBEEuro => "de_BE@euro",
            Locale::DeCH => "de_CH",
            Locale::DeDE => "de_DE",
            Locale::DeDEEuro => "de_DE@euro",
            Locale::DeIT => "de_IT",
            Locale::DeLI => "de_LI",
            Locale::DeLU => "de_LU",
            Locale::DeLUEuro => "de_LU@euro",
            Locale::DoiIN => "doi_IN",
            Locale::DsbDE => "dsb_DE",
            Locale::DvMV => "dv_MV",
            Locale::DzBT => "dz_BT",
            Locale::ElCY => "el_CY",
            Locale::ElGR => "el_GR",
            Locale::ElGREuro => "el_GR@euro",
            Locale::EnAG => "en_AG",
            Locale::EnAU => "en_AU",
            Locale::EnBW => "en_BW",
            Locale::EnCA => "en_CA",
            Locale::EnDK => "en_DK",
            Locale::EnGB => "en_GB",
            Locale::EnHK => "en_HK",
            Locale::EnIE => "en_IE",
            Locale::EnIEEuro => "en_IE@euro",
            Locale::EnIL => "en_IL",
            Locale::EnIN => "en_IN",
            Locale::EnNG => "en_NG",
            Locale::EnNZ => "en_NZ",
            Locale::EnPH => "en_PH",
            Locale::EnSC => "en_SC",
            Locale::EnSG => "en_SG",
            Locale::EnUS => "en_US",
            Locale::EnZA => "en_ZA",
            Locale::EnZM => "en_ZM",
            Locale::EnZW => "en_ZW",
            Locale::Eo => "eo",
            Locale::EsAR => "es_AR",
            Locale::EsBO => "es_BO",
            Locale::EsCL => "es_CL",
            Locale::EsCO => "es_CO",
            Locale::EsCR => "es_CR",
            Locale::EsCU => "es_CU",
            Locale::EsDO => "es_DO",
            Locale::EsEC => "es_EC",
            Locale::EsES => "es_ES",
            Locale::EsESEuro => "es_ES@euro",
            Locale::EsGT => "es_GT",
            Locale::EsHN => "es_HN",
            Locale::EsMX => "es_MX",
            Locale::EsNI => "es_NI",
            Locale::EsPA => "es_PA",
            Locale::EsPE => "es_PE",
            Locale::EsPR => "es_PR",
            Locale::EsPY => "es_PY",
            Locale::EsSV => "es_SV",
            Locale::EsUS => "es_US",
            Locale::EsUY => "es_UY",
            Locale::EsVE => "es_VE",
            Locale::EtEE => "et_EE",
            Locale::EuES => "eu_ES",
            Locale::EuESEuro => "eu_ES@euro",
            Locale::FaIR => "fa_IR",
            Locale::FfSN => "ff_SN",
            Locale::FiFI => "fi_FI",
            Locale::FiFIEuro => "fi_FI@euro",
            Locale::FilPH => "fil_PH",
            Locale::FoFO => "fo_FO",
            Locale::FrBE => "fr_BE",
            Locale::FrBEEuro => "fr_BE@euro",
            Locale::FrCA => "fr_CA",
            Locale::FrCH => "fr_CH",
            Locale::FrFR => "fr_FR",
            Locale::FrFREuro => "fr_FR@euro",
            Locale::FrLU => "fr_LU",
            Locale::FrLUEuro => "fr_LU@euro",
            Locale::FurIT => "fur_IT",
            Locale::FyDE => "fy_DE",
            Locale::FyNL => "fy_NL",
            Locale::GaIE => "ga_IE",
            Locale::GaIEEuro => "ga_IE@euro",
            Locale::GdGB => "gd_GB",
            Locale::GezER => "gez_ER",
            Locale::GezERAbegede => "gez_ER@abegede",
            Locale::GezET => "gez_ET",
            Locale::GezETAbegede => "gez_ET@abegede",
            Locale::GlES => "gl_ES",
            Locale::GlESEuro => "gl_ES@euro",
            Locale::GuIN => "gu_IN",
            Locale::GvGB => "gv_GB",
            Locale::HaNG => "ha_NG",
            Locale::HakTW => "hak_TW",
            Locale::HeIL => "he_IL",
            Locale::HiIN => "hi_IN",
            Locale::HifFJ => "hif_FJ",
            Locale::HneIN => "hne_IN",
            Locale::HrHR => "hr_HR",
            Locale::HsbDE => "hsb_DE",
            Locale::HtHT => "ht_HT",
            Locale::HuHU => "hu_HU",
            Locale::HyAM => "hy_AM",
            Locale::IaFR => "ia_FR",
            Locale::IdID => "id_ID",
            Locale::IgNG => "ig_NG",
            Locale::IkCA => "ik_CA",
            Locale::IsIS => "is_IS",
            Locale::ItCH => "it_CH",
            Locale::ItIT => "it_IT",
            Locale::ItITEuro => "it_IT@euro",
            Locale::IuCA => "iu_CA",
            Locale::JaJP => "ja_JP",
            Locale::KaGE => "ka_GE",
            Locale::KabDZ => "kab_DZ",
            Locale::KkKZ => "kk_KZ",
            Locale::KlGL => "kl_GL",
            Locale::KmKH => "km_KH",
            Locale::KnIN => "kn_IN",
            Locale::KoKR => "ko_KR",
            Locale::KokIN => "kok_IN",
            Locale::KsIN => "ks_IN",
            Locale::KsINDevanagari => "ks_IN@devanagari",
            Locale::KuTR => "ku_TR",
            Locale::KwGB => "kw_GB",
            Locale::KyKG => "ky_KG",
            Locale::LbLU => "lb_LU",
            Locale::LgUG => "lg_UG",
            Locale::LiBE => "li_BE",
            Locale::LiNL => "li_NL",
            Locale::LijIT => "lij_IT",
            Locale::LnCD => "ln_CD",
            Locale::LoLA => "lo_LA",
            Locale::LtLT => "lt_LT",
            Locale::LvLV => "lv_LV",
            Locale::LzhTW => "lzh_TW",
            Locale::MagIN => "mag_IN",
            Locale::MaiIN => "mai_IN",
            Locale::MaiNP => "mai_NP",
            Locale::MfeMU => "mfe_MU",
            Locale::MgMG => "mg_MG",
            Locale::MhrRU => "mhr_RU",
            Locale::MiNZ => "mi_NZ",
            Locale::MiqNI => "miq_NI",
            Locale::MjwIN => "mjw_IN",
            Locale::MkMK => "mk_MK",
            Locale::MlIN => "ml_IN",
            Locale::MnMN => "mn_MN",
            Locale::MniIN => "mni_IN",
            Locale::MnwMM => "mnw_MM",
            Locale::MrIN => "mr_IN",
            Locale::MsMY => "ms_MY",
            Locale::MtMT => "mt_MT",
            Locale::MyMM => "my_MM",
            Locale::NanTW => "nan_TW",
            Locale::NanTWLatin => "nan_TW@latin",
            Locale::NbNO => "nb_NO",
            Locale::NdsDE => "nds_DE",
            Locale::NdsNL => "nds_NL",
            Locale::NeNP => "ne_NP",
            Locale::NhnMX => "nhn_MX",
            Locale::NiuNU => "niu_NU",
            Locale::NiuNZ => "niu_NZ",
            Locale::NlAW => "nl_AW",
            Locale::NlBE => "nl_BE",
            Locale::NlBEEuro => "nl_BE@euro",
            Locale::NlNL => "nl_NL",
            Locale::NlNLEuro => "nl_NL@euro",
            Locale::NnNO => "nn_NO",
            Locale::NrZA => "nr_ZA",
            Locale::NsoZA => "nso_ZA",
            Locale::OcFR => "oc_FR",
            Locale::OmET => "om_ET",
            Locale::OmKE => "om_KE",
            Locale::OrIN => "or_IN",
            Locale::OsRU => "os_RU",
            Locale::PaIN => "pa_IN",
            Locale::PaPK => "pa_PK",
            Locale::PapAW => "pap_AW",
            Locale::PapCW => "pap_CW",
            Locale::PlPL => "pl_PL",
            Locale::PsAF => "ps_AF",
            Locale::PtBR => "pt_BR",
            Locale::PtPT => "pt_PT",
            Locale::PtPTEuro => "pt_PT@euro",
            Locale::QuzPE => "quz_PE",
            Locale::RajIN => "raj_IN",
            Locale::RoRO => "ro_RO",
            Locale::RuRU => "ru_RU",
            Locale::RuUA => "ru_UA",
            Locale::RwRW => "rw_RW",
            Locale::SaIN => "sa_IN",
            Locale::SahRU => "sah_RU",
            Locale::SatIN => "sat_IN",
            Locale::ScIT => "sc_IT",
            Locale::SdIN => "sd_IN",
            Locale::SdINDevanagari => "sd_IN@devanagari",
            Locale::SeNO => "se_NO",
            Locale::SgsLT => "sgs_LT",
            Locale::ShnMM => "shn_MM",
            Locale::ShsCA => "shs_CA",
            Locale::SiLK => "si_LK",
            Locale::SidET => "sid_ET",
            Locale::SkSK => "sk_SK",
            Locale::SlSI => "sl_SI",
            Locale::SmWS => "sm_WS",
            Locale::SoDJ => "so_DJ",
            Locale::SoET => "so_ET",
            Locale::SoKE => "so_KE",
            Locale::SoSO => "so_SO",
            Locale::SqAL => "sq_AL",
            Locale::SqMK => "sq_MK",
            Locale::SrME => "sr_ME",
            Locale::SrRS => "sr_RS",
            Locale::SrRSLatin => "sr_RS@latin",
            Locale::SsZA => "ss_ZA",
            Locale::StZA => "st_ZA",
            Locale::SvFI => "sv_FI",
            Locale::SvFIEuro => "sv_FI@euro",
            Locale::SvSE => "sv_SE",
            Locale::SwKE => "sw_KE",
            Locale::SwTZ => "sw_TZ",
            Locale::SzlPL => "szl_PL",
            Locale::TaIN => "ta_IN",
            Locale::TaLK => "ta_LK",
            Locale::TcyIN => "tcy_IN",
            Locale::TeIN => "te_IN",
            Locale::TgTJ => "tg_TJ",
            Locale::ThTH => "th_TH",
            Locale::TheNP => "the_NP",
            Locale::TiER => "ti_ER",
            Locale::TiET => "ti_ET",
            Locale::TigER => "tig_ER",
            Locale::TkTM => "tk_TM",
            Locale::TlPH => "tl_PH",
            Locale::TnZA => "tn_ZA",
            Locale::ToTO => "to_TO",
            Locale::TpiPG => "tpi_PG",
            Locale::TrCY => "tr_CY",
            Locale::TrTR => "tr_TR",
            Locale::TsZA => "ts_ZA",
            Locale::TtRU => "tt_RU",
            Locale::TtRUIqtelif => "tt_RU@iqtelif",
            Locale::UgCN => "ug_CN",
            Locale::UkUA => "uk_UA",
            Locale::UnmUS => "unm_US",
            Locale::UrIN => "ur_IN",
            Locale::UrPK => "ur_PK",
            Locale::UzUZ => "uz_UZ",
            Locale::UzUZCyrillic => "uz_UZ@cyrillic",
            Locale::VeZA => "ve_ZA",
            Locale::ViVN => "vi_VN",
            Locale::WaBE => "wa_BE",
            Locale::WaBEEuro => "wa_BE@euro",
            Locale::WaeCH => "wae_CH",
            Locale::WalET => "wal_ET",
            Locale::WoSN => "wo_SN",
            Locale::XhZA => "xh_ZA",
            Locale::YiUS => "yi_US",
            Locale::YoNG => "yo_NG",
            Locale::YueHK => "yue_HK",
            Locale::YuwPG => "yuw_PG",
            Locale::ZhCN => "zh_CN",
            Locale::ZhHK => "zh_HK",
            Locale::ZhSG => "zh_SG",
            Locale::ZhTW => "zh_TW",
            Locale::ZuZA => "zu_ZA",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(Locale::POSIX),
            1 => Some(Locale::AaDJ),
            2 => Some(Locale::AaER),
            3 => Some(Locale::AaERSaaho),
            4 => Some(Locale::AaET),
            5 => Some(Locale::AfZA),
            6 => Some(Locale::AgrPE),
            7 => Some(Locale::AkGH),
            8 => Some(Locale::AmET),
            9 => Some(Locale::AnES),
            10 => Some(Locale::AnpIN),
            11 => Some(Locale::ArAE),
            12 => Some(Locale::ArBH),
            13 => Some(Locale::ArDZ),
            14 => Some(Locale::ArEG),
            15 => Some(Locale::ArIN),
            16 => Some(Locale::ArIQ),
            17 => Some(Locale::ArJO),
            18 => Some(Locale::ArKW),
            19 => Some(Locale::ArLB),
            20 => Some(Locale::ArLY),
            21 => Some(Locale::ArMA),
            22 => Some(Locale::ArOM),
            23 => Some(Locale::ArQA),
            24 => Some(Locale::ArSA),
            25 => Some(Locale::ArSD),
            26 => Some(Locale::ArSS),
            27 => Some(Locale::ArSY),
            28 => Some(Locale::ArTN),
            29 => Some(Locale::ArYE),
            30 => Some(Locale::AsIN),
            31 => Some(Locale::AstES),
            32 => Some(Locale::AycPE),
            33 => Some(Locale::AzAZ),
            34 => Some(Locale::AzIR),
            35 => Some(Locale::BeBY),
            36 => Some(Locale::BeBYLatin),
            37 => Some(Locale::BemZM),
            38 => Some(Locale::BerDZ),
            39 => Some(Locale::BerMA),
            40 => Some(Locale::BgBG),
            41 => Some(Locale::BhbIN),
            42 => Some(Locale::BhoIN),
            43 => Some(Locale::BhoNP),
            44 => Some(Locale::BiVU),
            45 => Some(Locale::BnBD),
            46 => Some(Locale::BnIN),
            47 => Some(Locale::BoCN),
            48 => Some(Locale::BoIN),
            49 => Some(Locale::BrFR),
            50 => Some(Locale::BrFREuro),
            51 => Some(Locale::BrxIN),
            52 => Some(Locale::BsBA),
            53 => Some(Locale::BynER),
            54 => Some(Locale::CaAD),
            55 => Some(Locale::CaES),
            56 => Some(Locale::CaESEuro),
            57 => Some(Locale::CaESValencia),
            58 => Some(Locale::CaFR),
            59 => Some(Locale::CaIT),
            60 => Some(Locale::CeRU),
            61 => Some(Locale::ChrUS),
            62 => Some(Locale::CmnTW),
            63 => Some(Locale::CrhUA),
            64 => Some(Locale::CsCZ),
            65 => Some(Locale::CsbPL),
            66 => Some(Locale::CvRU),
            67 => Some(Locale::CyGB),
            68 => Some(Locale::DaDK),
            69 => Some(Locale::DeAT),
            70 => Some(Locale::DeATEuro),
            71 => Some(Locale::DeBE),
            72 => Some(Locale::DeBEEuro),
            73 => Some(Locale::DeCH),
            74 => Some(Locale::DeDE),
            75 => Some(Locale::DeDEEuro),
            76 => Some(Locale::DeIT),
            77 => Some(Locale::DeLI),
            78 => Some(Locale::DeLU),
            79 => Some(Locale::DeLUEuro),
            80 => Some(Locale::DoiIN),
            81 => Some(Locale::DsbDE),
            82 => Some(Locale::DvMV),
            83 => Some(Locale::DzBT),
            84 => Some(Locale::ElCY),
            85 => Some(Locale::ElGR),
            86 => Some(Locale::ElGREuro),
            87 => Some(Locale::EnAG),
            88 => Some(Locale::EnAU),
            89 => Some(Locale::EnBW),
            90 => Some(Locale::EnCA),
            91 => Some(Locale::EnDK),
            92 => Some(Locale::EnGB),
            93 => Some(Locale::EnHK),
            94 => Some(Locale::EnIE),
            95 => Some(Locale::EnIEEuro),
            96 => Some(Locale::EnIL),
            97 => Some(Locale::EnIN),
            98 => Some(Locale::EnNG),
            99 => Some(Locale::EnNZ),
            100 => Some(Locale::EnPH),
            101 => Some(Locale::EnSC),
            102 => Some(Locale::EnSG),
            103 => Some(Locale::EnUS),
            104 => Some(Locale::EnZA),
            105 => Some(Locale::EnZM),
            106 => Some(Locale::EnZW),
            107 => Some(Locale::Eo),
            108 => Some(Locale::EsAR),
            109 => Some(Locale::EsBO),
            110 => Some(Locale::EsCL),
            111 => Some(Locale::EsCO),
            112 => Some(Locale::EsCR),
            113 => Some(Locale::EsCU),
            114 => Some(Locale::EsDO),
            115 => Some(Locale::EsEC),
            116 => Some(Locale::EsES),
            117 => Some(Locale::EsESEuro),
            118 => Some(Locale::EsGT),
            119 => Some(Locale::EsHN),
            120 => Some(Locale::EsMX),
            121 => Some(Locale::EsNI),
            122 => Some(Locale::EsPA),
            123 => Some(Locale::EsPE),
            124 => Some(Locale::EsPR),
            125 => Some(Locale::EsPY),
            126 => Some(Locale::EsSV),
            127 => Some(Locale::EsUS),
            128 => Some(Locale::EsUY),
            129 => Some(Locale::EsVE),
            130 => Some(Locale::EtEE),
            131 => Some(Locale::EuES),
            132 => Some(Locale::EuESEuro),
            133 => Some(Locale::FaIR),
            134 => Some(Locale::FfSN),
            135 => Some(Locale::FiFI),
            136 => Some(Locale::FiFIEuro),
            137 => Some(Locale::FilPH),
            138 => Some(Locale::FoFO),
            139 => Some(Locale::FrBE),
            140 => Some(Locale::FrBEEuro),
            141 => Some(Locale::FrCA),
            142 => Some(Locale::FrCH),
            143 => Some(Locale::FrFR),
            144 => Some(Locale::FrFREuro),
            145 => Some(Locale::FrLU),
            146 => Some(Locale::FrLUEuro),
            147 => Some(Locale::FurIT),
            148 => Some(Locale::FyDE),
            149 => Some(Locale::FyNL),
            150 => Some(Locale::GaIE),
            151 => Some(Locale::GaIEEuro),
            152 => Some(Locale::GdGB),
            153 => Some(Locale::GezER),
            154 => Some(Locale::GezERAbegede),
            155 => Some(Locale::GezET),
            156 => Some(Locale::GezETAbegede),
            157 => Some(Locale::GlES),
            158 => Some(Locale::GlESEuro),
            159 => Some(Locale::GuIN),
            160 => Some(Locale::GvGB),
            161 => Some(Locale::HaNG),
            162 => Some(Locale::HakTW),
            163 => Some(Locale::HeIL),
            164 => Some(Locale::HiIN),
            165 => Some(Locale::HifFJ),
            166 => Some(Locale::HneIN),
            167 => Some(Locale::HrHR),
            168 => Some(Locale::HsbDE),
            169 => Some(Locale::HtHT),
            170 => Some(Locale::HuHU),
            171 => Some(Locale::HyAM),
            172 => Some(Locale::IaFR),
            173 => Some(Locale::IdID),
            174 => Some(Locale::IgNG),
            175 => Some(Locale::IkCA),
            176 => Some(Locale::IsIS),
            177 => Some(Locale::ItCH),
            178 => Some(Locale::ItIT),
            179 => Some(Locale::ItITEuro),
            180 => Some(Locale::IuCA),
            181 => Some(Locale::JaJP),
            182 => Some(Locale::KaGE),
            183 => Some(Locale::KabDZ),
            184 => Some(Locale::KkKZ),
            185 => Some(Locale::KlGL),
            186 => Some(Locale::KmKH),
            187 => Some(Locale::KnIN),
            188 => Some(Locale::KoKR),
            189 => Some(Locale::KokIN),
            190 => Some(Locale::KsIN),
            191 => Some(Locale::KsINDevanagari),
            192 => Some(Locale::KuTR),
            193 => Some(Locale::KwGB),
            194 => Some(Locale::KyKG),
            195 => Some(Locale::LbLU),
            196 => Some(Locale::LgUG),
            197 => Some(Locale::LiBE),
            198 => Some(Locale::LiNL),
            199 => Some(Locale::LijIT),
            200 => Some(Locale::LnCD),
            201 => Some(Locale::LoLA),
            202 => Some(Locale::LtLT),
            203 => Some(Locale::LvLV),
            204 => Some(Locale::LzhTW),
            205 => Some(Locale::MagIN),
            206 => Some(Locale::MaiIN),
            207 => Some(Locale::MaiNP),
            208 => Some(Locale::MfeMU),
            209 => Some(Locale::MgMG),
            210 => Some(Locale::MhrRU),
            211 => Some(Locale::MiNZ),
            212 => Some(Locale::MiqNI),
            213 => Some(Locale::MjwIN),
            214 => Some(Locale::MkMK),
            215 => Some(Locale::MlIN),
            216 => Some(Locale::MnMN),
            217 => Some(Locale::MniIN),
            218 => Some(Locale::MnwMM),
            219 => Some(Locale::MrIN),
            220 => Some(Locale::MsMY),
            221 => Some(Locale::MtMT),
            222 => Some(Locale::MyMM),
            223 => Some(Locale::NanTW),
            224 => Some(Locale::NanTWLatin),
            225 => Some(Locale::NbNO),
            226 => Some(Locale::NdsDE),
            227 => Some(Locale::NdsNL),
            228 => Some(Locale::NeNP),
            229 => Some(Locale::NhnMX),
            230 => Some(Locale::NiuNU),
            231 => Some(Locale::NiuNZ),
            232 => Some(Locale::NlAW),
            233 => Some(Locale::NlBE),
            234 => Some(Locale::NlBEEuro),
            235 => Some(Locale::NlNL),
            236 => Some(Locale::NlNLEuro),
            237 => Some(Locale::NnNO),
            238 => Some(Locale::NrZA),
            239 => Some(Locale::NsoZA),
            240 => Some(Locale::OcFR),
            241 => Some(Locale::OmET),
            242 => Some(Locale::OmKE),
            243 => Some(Locale::OrIN),
            244 => Some(Locale::OsRU),
            245 => Some(Locale::PaIN),
            246 => Some(Locale::PaPK),
            247 => Some(Locale::PapAW),
            248 => Some(Locale::PapCW),
            249 => Some(Locale::PlPL),
            250 => Some(Locale::PsAF),
            251 => Some(Locale::PtBR),
            252 => Some(Locale::PtPT),
            253 => Some(Locale::PtPTEuro),
            254 => Some(Locale::QuzPE),
            255 => Some(Locale::RajIN),
            256 => Some(Locale::RoRO),
            257 => Some(Locale::RuRU),
            258 => Some(Locale::RuUA),
            259 => Some(Locale::RwRW),
            260 => Some(Locale::SaIN),
            261 => Some(Locale::SahRU),
            262 => Some(Locale::SatIN),
            263 => Some(Locale::ScIT),
            264 => Some(Locale::SdIN),
            265 => Some(Locale::SdINDevanagari),
            266 => Some(Locale::SeNO),
            267 => Some(Locale::SgsLT),
            268 => Some(Locale::ShnMM),
            269 => Some(Locale::ShsCA),
            270 => Some(Locale::SiLK),
            271 => Some(Locale::SidET),
            272 => Some(Locale::SkSK),
            273 => Some(Locale::SlSI),
            274 => Some(Locale::SmWS),
            275 => Some(Locale::SoDJ),
            276 => Some(Locale::SoET),
            277 => Some(Locale::SoKE),
            278 => Some(Locale::SoSO),
            279 => Some(Locale::SqAL),
            280 => Some(Locale::SqMK),
            281 => Some(Locale::SrME),
            282 => Some(Locale::SrRS),
            283 => Some(Locale::SrRSLatin),
            284 => Some(Locale::SsZA),
            285 => Some(Locale::StZA),
            286 => Some(Locale::SvFI),
            287 => Some(Locale::SvFIEuro),
            288 => Some(Locale::SvSE),
            289 => Some(Locale::SwKE),
            290 => Some(Locale::SwTZ),
            291 => Some(Locale::SzlPL),
            292 => Some(Locale::TaIN),
            293 => Some(Locale::TaLK),
            294 => Some(Locale::TcyIN),
            295 => Some(Locale::TeIN),
            296 => Some(Locale::TgTJ),
            297 => Some(Locale::ThTH),
            298 => Some(Locale::TheNP),
            299 => Some(Locale::TiER),
            300 => Some(Locale::TiET),
            301 => Some(Locale::TigER),
            302 => Some(Locale::TkTM),
            303 => Some(Locale::TlPH),
            304 => Some(Locale::TnZA),
            305 => Some(Locale::ToTO),
            306 => Some(Locale::TpiPG),
            307 => Some(Locale::TrCY),
            308 => Some(Locale::TrTR),
            309 => Some(Locale::TsZA),
            310 => Some(Locale::TtRU),
            311 => Some(Locale::TtRUIqtelif),
            312 => Some(Locale::UgCN),
            313 => Some(Locale::UkUA),
            314 => Some(Locale::UnmUS),
            315 => Some(Locale::UrIN),
            316 => Some(Locale::UrPK),
            317 => Some(Locale::UzUZ),
            318 => Some(Locale::UzUZCyrillic),
            319 => Some(Locale::VeZA),
            320 => Some(Locale::ViVN),
            321 => Some(Locale::WaBE),
            322 => Some(Locale::WaBEEuro),
            323 => Some(Locale::WaeCH),
            324 => Some(Locale::WalET),
            325 => Some(Locale::WoSN),
            326 => Some(Locale::XhZA),
            327 => Some(Locale::YiUS),
            328 => Some(Locale::YoNG),
            329 => Some(Locale::YueHK),
            330 => Some(Locale::YuwPG),
            331 => Some(Locale::ZhCN),
            332 => Some(Locale::ZhHK),
            333 => Some(Locale::ZhSG),
            334 => Some(Locale::ZhTW),
            335 => Some(Locale::ZuZA),
            _ => None,
        }
    }

    const COUNT: usize = 336;
}

impl serde::Serialize for Locale {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Locale {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for LogRotateFrequency {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"daily" => LogRotateFrequency::Daily,
            b"hourly" => LogRotateFrequency::Hourly,
            b"minutely" => LogRotateFrequency::Minutely,
            b"never" => LogRotateFrequency::Never,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            LogRotateFrequency::Daily => "daily",
            LogRotateFrequency::Hourly => "hourly",
            LogRotateFrequency::Minutely => "minutely",
            LogRotateFrequency::Never => "never",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(LogRotateFrequency::Daily),
            1 => Some(LogRotateFrequency::Hourly),
            2 => Some(LogRotateFrequency::Minutely),
            3 => Some(LogRotateFrequency::Never),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for LogRotateFrequency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for LogRotateFrequency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for LookupStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"PostgreSql" => LookupStoreType::PostgreSql,
            b"MySql" => LookupStoreType::MySql,
            b"Sqlite" => LookupStoreType::Sqlite,
            b"Sharded" => LookupStoreType::Sharded,
            b"Redis" => LookupStoreType::Redis,
            b"RedisCluster" => LookupStoreType::RedisCluster,
            b"RedisSentinel" => LookupStoreType::RedisSentinel,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            LookupStoreType::PostgreSql => "PostgreSql",
            LookupStoreType::MySql => "MySql",
            LookupStoreType::Sqlite => "Sqlite",
            LookupStoreType::Sharded => "Sharded",
            LookupStoreType::Redis => "Redis",
            LookupStoreType::RedisCluster => "RedisCluster",
            LookupStoreType::RedisSentinel => "RedisSentinel",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(LookupStoreType::PostgreSql),
            1 => Some(LookupStoreType::MySql),
            2 => Some(LookupStoreType::Sqlite),
            3 => Some(LookupStoreType::Sharded),
            4 => Some(LookupStoreType::Redis),
            5 => Some(LookupStoreType::RedisCluster),
            6 => Some(LookupStoreType::RedisSentinel),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for LookupStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for LookupStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MessageFlag {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"authenticated" => MessageFlag::Authenticated,
            b"unauthenticated" => MessageFlag::Unauthenticated,
            b"unauthenticatedDmarc" => MessageFlag::UnauthenticatedDmarc,
            b"dsn" => MessageFlag::Dsn,
            b"report" => MessageFlag::Report,
            b"autogenerated" => MessageFlag::Autogenerated,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MessageFlag::Authenticated => "authenticated",
            MessageFlag::Unauthenticated => "unauthenticated",
            MessageFlag::UnauthenticatedDmarc => "unauthenticatedDmarc",
            MessageFlag::Dsn => "dsn",
            MessageFlag::Report => "report",
            MessageFlag::Autogenerated => "autogenerated",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MessageFlag::Authenticated),
            1 => Some(MessageFlag::Unauthenticated),
            2 => Some(MessageFlag::UnauthenticatedDmarc),
            3 => Some(MessageFlag::Dsn),
            4 => Some(MessageFlag::Report),
            5 => Some(MessageFlag::Autogenerated),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for MessageFlag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MessageFlag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MetricType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Counter" => MetricType::Counter,
            b"Gauge" => MetricType::Gauge,
            b"Histogram" => MetricType::Histogram,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MetricType::Counter => "Counter",
            MetricType::Gauge => "Gauge",
            MetricType::Histogram => "Histogram",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MetricType::Counter),
            1 => Some(MetricType::Gauge),
            2 => Some(MetricType::Histogram),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for MetricType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MetricType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MetricsOtelType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => MetricsOtelType::Disabled,
            b"Http" => MetricsOtelType::Http,
            b"Grpc" => MetricsOtelType::Grpc,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MetricsOtelType::Disabled => "Disabled",
            MetricsOtelType::Http => "Http",
            MetricsOtelType::Grpc => "Grpc",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MetricsOtelType::Disabled),
            1 => Some(MetricsOtelType::Http),
            2 => Some(MetricsOtelType::Grpc),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for MetricsOtelType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MetricsOtelType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MetricsPrometheusType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => MetricsPrometheusType::Disabled,
            b"Enabled" => MetricsPrometheusType::Enabled,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MetricsPrometheusType::Disabled => "Disabled",
            MetricsPrometheusType::Enabled => "Enabled",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MetricsPrometheusType::Disabled),
            1 => Some(MetricsPrometheusType::Enabled),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for MetricsPrometheusType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MetricsPrometheusType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MetricsStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => MetricsStoreType::Disabled,
            b"Default" => MetricsStoreType::Default,
            b"FoundationDb" => MetricsStoreType::FoundationDb,
            b"PostgreSql" => MetricsStoreType::PostgreSql,
            b"MySql" => MetricsStoreType::MySql,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MetricsStoreType::Disabled => "Disabled",
            MetricsStoreType::Default => "Default",
            MetricsStoreType::FoundationDb => "FoundationDb",
            MetricsStoreType::PostgreSql => "PostgreSql",
            MetricsStoreType::MySql => "MySql",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MetricsStoreType::Disabled),
            1 => Some(MetricsStoreType::Default),
            2 => Some(MetricsStoreType::FoundationDb),
            3 => Some(MetricsStoreType::PostgreSql),
            4 => Some(MetricsStoreType::MySql),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for MetricsStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MetricsStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MilterVersion {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"v2" => MilterVersion::V2,
            b"v6" => MilterVersion::V6,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MilterVersion::V2 => "v2",
            MilterVersion::V6 => "v6",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MilterVersion::V2),
            1 => Some(MilterVersion::V6),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for MilterVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MilterVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ModelSize {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"16" => ModelSize::V16,
            b"17" => ModelSize::V17,
            b"18" => ModelSize::V18,
            b"19" => ModelSize::V19,
            b"20" => ModelSize::V20,
            b"21" => ModelSize::V21,
            b"22" => ModelSize::V22,
            b"23" => ModelSize::V23,
            b"24" => ModelSize::V24,
            b"25" => ModelSize::V25,
            b"26" => ModelSize::V26,
            b"27" => ModelSize::V27,
            b"28" => ModelSize::V28,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ModelSize::V16 => "16",
            ModelSize::V17 => "17",
            ModelSize::V18 => "18",
            ModelSize::V19 => "19",
            ModelSize::V20 => "20",
            ModelSize::V21 => "21",
            ModelSize::V22 => "22",
            ModelSize::V23 => "23",
            ModelSize::V24 => "24",
            ModelSize::V25 => "25",
            ModelSize::V26 => "26",
            ModelSize::V27 => "27",
            ModelSize::V28 => "28",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ModelSize::V16),
            1 => Some(ModelSize::V17),
            2 => Some(ModelSize::V18),
            3 => Some(ModelSize::V19),
            4 => Some(ModelSize::V20),
            5 => Some(ModelSize::V21),
            6 => Some(ModelSize::V22),
            7 => Some(ModelSize::V23),
            8 => Some(ModelSize::V24),
            9 => Some(ModelSize::V25),
            10 => Some(ModelSize::V26),
            11 => Some(ModelSize::V27),
            12 => Some(ModelSize::V28),
            _ => None,
        }
    }

    const COUNT: usize = 13;
}

impl serde::Serialize for ModelSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ModelSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaDeliveryExpirationType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Ttl" => MtaDeliveryExpirationType::Ttl,
            b"Attempts" => MtaDeliveryExpirationType::Attempts,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaDeliveryExpirationType::Ttl => "Ttl",
            MtaDeliveryExpirationType::Attempts => "Attempts",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaDeliveryExpirationType::Ttl),
            1 => Some(MtaDeliveryExpirationType::Attempts),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for MtaDeliveryExpirationType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaDeliveryExpirationType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaDeliveryScheduleIntervalsOrDefaultType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Default" => MtaDeliveryScheduleIntervalsOrDefaultType::Default,
            b"Custom" => MtaDeliveryScheduleIntervalsOrDefaultType::Custom,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaDeliveryScheduleIntervalsOrDefaultType::Default => "Default",
            MtaDeliveryScheduleIntervalsOrDefaultType::Custom => "Custom",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaDeliveryScheduleIntervalsOrDefaultType::Default),
            1 => Some(MtaDeliveryScheduleIntervalsOrDefaultType::Custom),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for MtaDeliveryScheduleIntervalsOrDefaultType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaDeliveryScheduleIntervalsOrDefaultType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaInboundThrottleKey {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"listener" => MtaInboundThrottleKey::Listener,
            b"remoteIp" => MtaInboundThrottleKey::RemoteIp,
            b"localIp" => MtaInboundThrottleKey::LocalIp,
            b"authenticatedAs" => MtaInboundThrottleKey::AuthenticatedAs,
            b"heloDomain" => MtaInboundThrottleKey::HeloDomain,
            b"sender" => MtaInboundThrottleKey::Sender,
            b"senderDomain" => MtaInboundThrottleKey::SenderDomain,
            b"rcpt" => MtaInboundThrottleKey::Rcpt,
            b"rcptDomain" => MtaInboundThrottleKey::RcptDomain,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaInboundThrottleKey::Listener => "listener",
            MtaInboundThrottleKey::RemoteIp => "remoteIp",
            MtaInboundThrottleKey::LocalIp => "localIp",
            MtaInboundThrottleKey::AuthenticatedAs => "authenticatedAs",
            MtaInboundThrottleKey::HeloDomain => "heloDomain",
            MtaInboundThrottleKey::Sender => "sender",
            MtaInboundThrottleKey::SenderDomain => "senderDomain",
            MtaInboundThrottleKey::Rcpt => "rcpt",
            MtaInboundThrottleKey::RcptDomain => "rcptDomain",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaInboundThrottleKey::Listener),
            1 => Some(MtaInboundThrottleKey::RemoteIp),
            2 => Some(MtaInboundThrottleKey::LocalIp),
            3 => Some(MtaInboundThrottleKey::AuthenticatedAs),
            4 => Some(MtaInboundThrottleKey::HeloDomain),
            5 => Some(MtaInboundThrottleKey::Sender),
            6 => Some(MtaInboundThrottleKey::SenderDomain),
            7 => Some(MtaInboundThrottleKey::Rcpt),
            8 => Some(MtaInboundThrottleKey::RcptDomain),
            _ => None,
        }
    }

    const COUNT: usize = 9;
}

impl serde::Serialize for MtaInboundThrottleKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaInboundThrottleKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaIpStrategy {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"v4ThenV6" => MtaIpStrategy::V4ThenV6,
            b"v6ThenV4" => MtaIpStrategy::V6ThenV4,
            b"v4Only" => MtaIpStrategy::V4Only,
            b"v6Only" => MtaIpStrategy::V6Only,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaIpStrategy::V4ThenV6 => "v4ThenV6",
            MtaIpStrategy::V6ThenV4 => "v6ThenV4",
            MtaIpStrategy::V4Only => "v4Only",
            MtaIpStrategy::V6Only => "v6Only",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaIpStrategy::V4ThenV6),
            1 => Some(MtaIpStrategy::V6ThenV4),
            2 => Some(MtaIpStrategy::V4Only),
            3 => Some(MtaIpStrategy::V6Only),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for MtaIpStrategy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaIpStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaOutboundThrottleKey {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"mx" => MtaOutboundThrottleKey::Mx,
            b"remoteIp" => MtaOutboundThrottleKey::RemoteIp,
            b"localIp" => MtaOutboundThrottleKey::LocalIp,
            b"sender" => MtaOutboundThrottleKey::Sender,
            b"senderDomain" => MtaOutboundThrottleKey::SenderDomain,
            b"rcptDomain" => MtaOutboundThrottleKey::RcptDomain,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaOutboundThrottleKey::Mx => "mx",
            MtaOutboundThrottleKey::RemoteIp => "remoteIp",
            MtaOutboundThrottleKey::LocalIp => "localIp",
            MtaOutboundThrottleKey::Sender => "sender",
            MtaOutboundThrottleKey::SenderDomain => "senderDomain",
            MtaOutboundThrottleKey::RcptDomain => "rcptDomain",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaOutboundThrottleKey::Mx),
            1 => Some(MtaOutboundThrottleKey::RemoteIp),
            2 => Some(MtaOutboundThrottleKey::LocalIp),
            3 => Some(MtaOutboundThrottleKey::Sender),
            4 => Some(MtaOutboundThrottleKey::SenderDomain),
            5 => Some(MtaOutboundThrottleKey::RcptDomain),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for MtaOutboundThrottleKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaOutboundThrottleKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaProtocol {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"smtp" => MtaProtocol::Smtp,
            b"lmtp" => MtaProtocol::Lmtp,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaProtocol::Smtp => "smtp",
            MtaProtocol::Lmtp => "lmtp",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaProtocol::Smtp),
            1 => Some(MtaProtocol::Lmtp),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for MtaProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaQueueQuotaKey {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"sender" => MtaQueueQuotaKey::Sender,
            b"senderDomain" => MtaQueueQuotaKey::SenderDomain,
            b"rcpt" => MtaQueueQuotaKey::Rcpt,
            b"rcptDomain" => MtaQueueQuotaKey::RcptDomain,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaQueueQuotaKey::Sender => "sender",
            MtaQueueQuotaKey::SenderDomain => "senderDomain",
            MtaQueueQuotaKey::Rcpt => "rcpt",
            MtaQueueQuotaKey::RcptDomain => "rcptDomain",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaQueueQuotaKey::Sender),
            1 => Some(MtaQueueQuotaKey::SenderDomain),
            2 => Some(MtaQueueQuotaKey::Rcpt),
            3 => Some(MtaQueueQuotaKey::RcptDomain),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for MtaQueueQuotaKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaQueueQuotaKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaRequiredOrOptional {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"optional" => MtaRequiredOrOptional::Optional,
            b"require" => MtaRequiredOrOptional::Require,
            b"disable" => MtaRequiredOrOptional::Disable,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaRequiredOrOptional::Optional => "optional",
            MtaRequiredOrOptional::Require => "require",
            MtaRequiredOrOptional::Disable => "disable",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaRequiredOrOptional::Optional),
            1 => Some(MtaRequiredOrOptional::Require),
            2 => Some(MtaRequiredOrOptional::Disable),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for MtaRequiredOrOptional {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaRequiredOrOptional {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaRouteType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Mx" => MtaRouteType::Mx,
            b"Relay" => MtaRouteType::Relay,
            b"Local" => MtaRouteType::Local,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaRouteType::Mx => "Mx",
            MtaRouteType::Relay => "Relay",
            MtaRouteType::Local => "Local",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaRouteType::Mx),
            1 => Some(MtaRouteType::Relay),
            2 => Some(MtaRouteType::Local),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for MtaRouteType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaRouteType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for MtaStage {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"connect" => MtaStage::Connect,
            b"ehlo" => MtaStage::Ehlo,
            b"auth" => MtaStage::Auth,
            b"mail" => MtaStage::Mail,
            b"rcpt" => MtaStage::Rcpt,
            b"data" => MtaStage::Data,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            MtaStage::Connect => "connect",
            MtaStage::Ehlo => "ehlo",
            MtaStage::Auth => "auth",
            MtaStage::Mail => "mail",
            MtaStage::Rcpt => "rcpt",
            MtaStage::Data => "data",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(MtaStage::Connect),
            1 => Some(MtaStage::Ehlo),
            2 => Some(MtaStage::Auth),
            3 => Some(MtaStage::Mail),
            4 => Some(MtaStage::Rcpt),
            5 => Some(MtaStage::Data),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for MtaStage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MtaStage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for NetworkListenerProtocol {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"smtp" => NetworkListenerProtocol::Smtp,
            b"lmtp" => NetworkListenerProtocol::Lmtp,
            b"http" => NetworkListenerProtocol::Http,
            b"imap" => NetworkListenerProtocol::Imap,
            b"pop3" => NetworkListenerProtocol::Pop3,
            b"manageSieve" => NetworkListenerProtocol::ManageSieve,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            NetworkListenerProtocol::Smtp => "smtp",
            NetworkListenerProtocol::Lmtp => "lmtp",
            NetworkListenerProtocol::Http => "http",
            NetworkListenerProtocol::Imap => "imap",
            NetworkListenerProtocol::Pop3 => "pop3",
            NetworkListenerProtocol::ManageSieve => "manageSieve",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(NetworkListenerProtocol::Smtp),
            1 => Some(NetworkListenerProtocol::Lmtp),
            2 => Some(NetworkListenerProtocol::Http),
            3 => Some(NetworkListenerProtocol::Imap),
            4 => Some(NetworkListenerProtocol::Pop3),
            5 => Some(NetworkListenerProtocol::ManageSieve),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for NetworkListenerProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for NetworkListenerProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for OvhEndpoint {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"ovh-eu" => OvhEndpoint::OvhEu,
            b"ovh-ca" => OvhEndpoint::OvhCa,
            b"kimsufi-eu" => OvhEndpoint::KimsufiEu,
            b"kimsufi-ca" => OvhEndpoint::KimsufiCa,
            b"soyoustart-eu" => OvhEndpoint::SoyoustartEu,
            b"soyoustart-ca" => OvhEndpoint::SoyoustartCa,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            OvhEndpoint::OvhEu => "ovh-eu",
            OvhEndpoint::OvhCa => "ovh-ca",
            OvhEndpoint::KimsufiEu => "kimsufi-eu",
            OvhEndpoint::KimsufiCa => "kimsufi-ca",
            OvhEndpoint::SoyoustartEu => "soyoustart-eu",
            OvhEndpoint::SoyoustartCa => "soyoustart-ca",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(OvhEndpoint::OvhEu),
            1 => Some(OvhEndpoint::OvhCa),
            2 => Some(OvhEndpoint::KimsufiEu),
            3 => Some(OvhEndpoint::KimsufiCa),
            4 => Some(OvhEndpoint::SoyoustartEu),
            5 => Some(OvhEndpoint::SoyoustartCa),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for OvhEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for OvhEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for PasswordHashAlgorithm {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"argon2id" => PasswordHashAlgorithm::Argon2id,
            b"bcrypt" => PasswordHashAlgorithm::Bcrypt,
            b"scrypt" => PasswordHashAlgorithm::Scrypt,
            b"pbkdf2" => PasswordHashAlgorithm::Pbkdf2,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            PasswordHashAlgorithm::Argon2id => "argon2id",
            PasswordHashAlgorithm::Bcrypt => "bcrypt",
            PasswordHashAlgorithm::Scrypt => "scrypt",
            PasswordHashAlgorithm::Pbkdf2 => "pbkdf2",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(PasswordHashAlgorithm::Argon2id),
            1 => Some(PasswordHashAlgorithm::Bcrypt),
            2 => Some(PasswordHashAlgorithm::Scrypt),
            3 => Some(PasswordHashAlgorithm::Pbkdf2),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for PasswordHashAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PasswordHashAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for PasswordStrength {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"zero" => PasswordStrength::Zero,
            b"one" => PasswordStrength::One,
            b"two" => PasswordStrength::Two,
            b"three" => PasswordStrength::Three,
            b"four" => PasswordStrength::Four,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            PasswordStrength::Zero => "zero",
            PasswordStrength::One => "one",
            PasswordStrength::Two => "two",
            PasswordStrength::Three => "three",
            PasswordStrength::Four => "four",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(PasswordStrength::Zero),
            1 => Some(PasswordStrength::One),
            2 => Some(PasswordStrength::Two),
            3 => Some(PasswordStrength::Three),
            4 => Some(PasswordStrength::Four),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for PasswordStrength {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PasswordStrength {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for Permission {
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            Permission,
            b"authenticate" => Permission::Authenticate,
            b"authenticateWithAlias" => Permission::AuthenticateWithAlias,
            b"interactAi" => Permission::InteractAi,
            b"impersonate" => Permission::Impersonate,
            b"unlimitedRequests" => Permission::UnlimitedRequests,
            b"unlimitedUploads" => Permission::UnlimitedUploads,
            b"fetchAnyBlob" => Permission::FetchAnyBlob,
            b"emailSend" => Permission::EmailSend,
            b"emailReceive" => Permission::EmailReceive,
            b"calendarAlarmsSend" => Permission::CalendarAlarmsSend,
            b"calendarSchedulingSend" => Permission::CalendarSchedulingSend,
            b"calendarSchedulingReceive" => Permission::CalendarSchedulingReceive,
            b"jmapPushSubscriptionGet" => Permission::JmapPushSubscriptionGet,
            b"jmapPushSubscriptionCreate" => Permission::JmapPushSubscriptionCreate,
            b"jmapPushSubscriptionUpdate" => Permission::JmapPushSubscriptionUpdate,
            b"jmapPushSubscriptionDestroy" => Permission::JmapPushSubscriptionDestroy,
            b"jmapMailboxGet" => Permission::JmapMailboxGet,
            b"jmapMailboxChanges" => Permission::JmapMailboxChanges,
            b"jmapMailboxQuery" => Permission::JmapMailboxQuery,
            b"jmapMailboxQueryChanges" => Permission::JmapMailboxQueryChanges,
            b"jmapMailboxCreate" => Permission::JmapMailboxCreate,
            b"jmapMailboxUpdate" => Permission::JmapMailboxUpdate,
            b"jmapMailboxDestroy" => Permission::JmapMailboxDestroy,
            b"jmapThreadGet" => Permission::JmapThreadGet,
            b"jmapThreadChanges" => Permission::JmapThreadChanges,
            b"jmapEmailGet" => Permission::JmapEmailGet,
            b"jmapEmailChanges" => Permission::JmapEmailChanges,
            b"jmapEmailQuery" => Permission::JmapEmailQuery,
            b"jmapEmailQueryChanges" => Permission::JmapEmailQueryChanges,
            b"jmapEmailCreate" => Permission::JmapEmailCreate,
            b"jmapEmailUpdate" => Permission::JmapEmailUpdate,
            b"jmapEmailDestroy" => Permission::JmapEmailDestroy,
            b"jmapEmailCopy" => Permission::JmapEmailCopy,
            b"jmapEmailImport" => Permission::JmapEmailImport,
            b"jmapEmailParse" => Permission::JmapEmailParse,
            b"jmapSearchSnippetGet" => Permission::JmapSearchSnippetGet,
            b"jmapIdentityGet" => Permission::JmapIdentityGet,
            b"jmapIdentityChanges" => Permission::JmapIdentityChanges,
            b"jmapIdentityCreate" => Permission::JmapIdentityCreate,
            b"jmapIdentityUpdate" => Permission::JmapIdentityUpdate,
            b"jmapIdentityDestroy" => Permission::JmapIdentityDestroy,
            b"jmapEmailSubmissionGet" => Permission::JmapEmailSubmissionGet,
            b"jmapEmailSubmissionChanges" => Permission::JmapEmailSubmissionChanges,
            b"jmapEmailSubmissionQuery" => Permission::JmapEmailSubmissionQuery,
            b"jmapEmailSubmissionQueryChanges" => Permission::JmapEmailSubmissionQueryChanges,
            b"jmapEmailSubmissionCreate" => Permission::JmapEmailSubmissionCreate,
            b"jmapEmailSubmissionUpdate" => Permission::JmapEmailSubmissionUpdate,
            b"jmapEmailSubmissionDestroy" => Permission::JmapEmailSubmissionDestroy,
            b"jmapVacationResponseGet" => Permission::JmapVacationResponseGet,
            b"jmapVacationResponseCreate" => Permission::JmapVacationResponseCreate,
            b"jmapVacationResponseUpdate" => Permission::JmapVacationResponseUpdate,
            b"jmapVacationResponseDestroy" => Permission::JmapVacationResponseDestroy,
            b"jmapSieveScriptGet" => Permission::JmapSieveScriptGet,
            b"jmapSieveScriptQuery" => Permission::JmapSieveScriptQuery,
            b"jmapSieveScriptValidate" => Permission::JmapSieveScriptValidate,
            b"jmapSieveScriptCreate" => Permission::JmapSieveScriptCreate,
            b"jmapSieveScriptUpdate" => Permission::JmapSieveScriptUpdate,
            b"jmapSieveScriptDestroy" => Permission::JmapSieveScriptDestroy,
            b"jmapPrincipalGet" => Permission::JmapPrincipalGet,
            b"jmapPrincipalQuery" => Permission::JmapPrincipalQuery,
            b"jmapPrincipalChanges" => Permission::JmapPrincipalChanges,
            b"jmapPrincipalQueryChanges" => Permission::JmapPrincipalQueryChanges,
            b"jmapPrincipalGetAvailability" => Permission::JmapPrincipalGetAvailability,
            b"jmapPrincipalCreate" => Permission::JmapPrincipalCreate,
            b"jmapPrincipalUpdate" => Permission::JmapPrincipalUpdate,
            b"jmapPrincipalDestroy" => Permission::JmapPrincipalDestroy,
            b"jmapQuotaGet" => Permission::JmapQuotaGet,
            b"jmapQuotaChanges" => Permission::JmapQuotaChanges,
            b"jmapQuotaQuery" => Permission::JmapQuotaQuery,
            b"jmapQuotaQueryChanges" => Permission::JmapQuotaQueryChanges,
            b"jmapBlobGet" => Permission::JmapBlobGet,
            b"jmapBlobCopy" => Permission::JmapBlobCopy,
            b"jmapBlobLookup" => Permission::JmapBlobLookup,
            b"jmapBlobUpload" => Permission::JmapBlobUpload,
            b"jmapAddressBookGet" => Permission::JmapAddressBookGet,
            b"jmapAddressBookChanges" => Permission::JmapAddressBookChanges,
            b"jmapAddressBookCreate" => Permission::JmapAddressBookCreate,
            b"jmapAddressBookUpdate" => Permission::JmapAddressBookUpdate,
            b"jmapAddressBookDestroy" => Permission::JmapAddressBookDestroy,
            b"jmapContactCardGet" => Permission::JmapContactCardGet,
            b"jmapContactCardChanges" => Permission::JmapContactCardChanges,
            b"jmapContactCardQuery" => Permission::JmapContactCardQuery,
            b"jmapContactCardQueryChanges" => Permission::JmapContactCardQueryChanges,
            b"jmapContactCardCreate" => Permission::JmapContactCardCreate,
            b"jmapContactCardUpdate" => Permission::JmapContactCardUpdate,
            b"jmapContactCardDestroy" => Permission::JmapContactCardDestroy,
            b"jmapContactCardCopy" => Permission::JmapContactCardCopy,
            b"jmapContactCardParse" => Permission::JmapContactCardParse,
            b"jmapFileNodeGet" => Permission::JmapFileNodeGet,
            b"jmapFileNodeChanges" => Permission::JmapFileNodeChanges,
            b"jmapFileNodeQuery" => Permission::JmapFileNodeQuery,
            b"jmapFileNodeQueryChanges" => Permission::JmapFileNodeQueryChanges,
            b"jmapFileNodeCreate" => Permission::JmapFileNodeCreate,
            b"jmapFileNodeUpdate" => Permission::JmapFileNodeUpdate,
            b"jmapFileNodeDestroy" => Permission::JmapFileNodeDestroy,
            b"jmapFileNodeCopy" => Permission::JmapFileNodeCopy,
            b"jmapShareNotificationGet" => Permission::JmapShareNotificationGet,
            b"jmapShareNotificationChanges" => Permission::JmapShareNotificationChanges,
            b"jmapShareNotificationQuery" => Permission::JmapShareNotificationQuery,
            b"jmapShareNotificationQueryChanges" => Permission::JmapShareNotificationQueryChanges,
            b"jmapShareNotificationCreate" => Permission::JmapShareNotificationCreate,
            b"jmapShareNotificationUpdate" => Permission::JmapShareNotificationUpdate,
            b"jmapShareNotificationDestroy" => Permission::JmapShareNotificationDestroy,
            b"jmapCalendarGet" => Permission::JmapCalendarGet,
            b"jmapCalendarChanges" => Permission::JmapCalendarChanges,
            b"jmapCalendarCreate" => Permission::JmapCalendarCreate,
            b"jmapCalendarUpdate" => Permission::JmapCalendarUpdate,
            b"jmapCalendarDestroy" => Permission::JmapCalendarDestroy,
            b"jmapCalendarEventGet" => Permission::JmapCalendarEventGet,
            b"jmapCalendarEventChanges" => Permission::JmapCalendarEventChanges,
            b"jmapCalendarEventQuery" => Permission::JmapCalendarEventQuery,
            b"jmapCalendarEventQueryChanges" => Permission::JmapCalendarEventQueryChanges,
            b"jmapCalendarEventCreate" => Permission::JmapCalendarEventCreate,
            b"jmapCalendarEventUpdate" => Permission::JmapCalendarEventUpdate,
            b"jmapCalendarEventDestroy" => Permission::JmapCalendarEventDestroy,
            b"jmapCalendarEventCopy" => Permission::JmapCalendarEventCopy,
            b"jmapCalendarEventParse" => Permission::JmapCalendarEventParse,
            b"jmapCalendarEventNotificationGet" => Permission::JmapCalendarEventNotificationGet,
            b"jmapCalendarEventNotificationChanges" => Permission::JmapCalendarEventNotificationChanges,
            b"jmapCalendarEventNotificationQuery" => Permission::JmapCalendarEventNotificationQuery,
            b"jmapCalendarEventNotificationQueryChanges" => Permission::JmapCalendarEventNotificationQueryChanges,
            b"jmapCalendarEventNotificationCreate" => Permission::JmapCalendarEventNotificationCreate,
            b"jmapCalendarEventNotificationUpdate" => Permission::JmapCalendarEventNotificationUpdate,
            b"jmapCalendarEventNotificationDestroy" => Permission::JmapCalendarEventNotificationDestroy,
            b"jmapParticipantIdentityGet" => Permission::JmapParticipantIdentityGet,
            b"jmapParticipantIdentityChanges" => Permission::JmapParticipantIdentityChanges,
            b"jmapParticipantIdentityCreate" => Permission::JmapParticipantIdentityCreate,
            b"jmapParticipantIdentityUpdate" => Permission::JmapParticipantIdentityUpdate,
            b"jmapParticipantIdentityDestroy" => Permission::JmapParticipantIdentityDestroy,
            b"jmapCoreEcho" => Permission::JmapCoreEcho,
            b"imapAuthenticate" => Permission::ImapAuthenticate,
            b"imapAclGet" => Permission::ImapAclGet,
            b"imapAclSet" => Permission::ImapAclSet,
            b"imapMyRights" => Permission::ImapMyRights,
            b"imapListRights" => Permission::ImapListRights,
            b"imapAppend" => Permission::ImapAppend,
            b"imapCapability" => Permission::ImapCapability,
            b"imapId" => Permission::ImapId,
            b"imapCopy" => Permission::ImapCopy,
            b"imapMove" => Permission::ImapMove,
            b"imapCreate" => Permission::ImapCreate,
            b"imapDelete" => Permission::ImapDelete,
            b"imapEnable" => Permission::ImapEnable,
            b"imapExpunge" => Permission::ImapExpunge,
            b"imapFetch" => Permission::ImapFetch,
            b"imapIdle" => Permission::ImapIdle,
            b"imapList" => Permission::ImapList,
            b"imapLsub" => Permission::ImapLsub,
            b"imapNamespace" => Permission::ImapNamespace,
            b"imapRename" => Permission::ImapRename,
            b"imapSearch" => Permission::ImapSearch,
            b"imapSort" => Permission::ImapSort,
            b"imapSelect" => Permission::ImapSelect,
            b"imapExamine" => Permission::ImapExamine,
            b"imapStatus" => Permission::ImapStatus,
            b"imapStore" => Permission::ImapStore,
            b"imapSubscribe" => Permission::ImapSubscribe,
            b"imapThread" => Permission::ImapThread,
            b"pop3Authenticate" => Permission::Pop3Authenticate,
            b"pop3List" => Permission::Pop3List,
            b"pop3Uidl" => Permission::Pop3Uidl,
            b"pop3Stat" => Permission::Pop3Stat,
            b"pop3Retr" => Permission::Pop3Retr,
            b"pop3Dele" => Permission::Pop3Dele,
            b"sieveAuthenticate" => Permission::SieveAuthenticate,
            b"sieveListScripts" => Permission::SieveListScripts,
            b"sieveSetActive" => Permission::SieveSetActive,
            b"sieveGetScript" => Permission::SieveGetScript,
            b"sievePutScript" => Permission::SievePutScript,
            b"sieveDeleteScript" => Permission::SieveDeleteScript,
            b"sieveRenameScript" => Permission::SieveRenameScript,
            b"sieveCheckScript" => Permission::SieveCheckScript,
            b"sieveHaveSpace" => Permission::SieveHaveSpace,
            b"davSyncCollection" => Permission::DavSyncCollection,
            b"davExpandProperty" => Permission::DavExpandProperty,
            b"davPrincipalAcl" => Permission::DavPrincipalAcl,
            b"davPrincipalList" => Permission::DavPrincipalList,
            b"davPrincipalMatch" => Permission::DavPrincipalMatch,
            b"davPrincipalSearch" => Permission::DavPrincipalSearch,
            b"davPrincipalSearchPropSet" => Permission::DavPrincipalSearchPropSet,
            b"davFilePropFind" => Permission::DavFilePropFind,
            b"davFilePropPatch" => Permission::DavFilePropPatch,
            b"davFileGet" => Permission::DavFileGet,
            b"davFileMkCol" => Permission::DavFileMkCol,
            b"davFileDelete" => Permission::DavFileDelete,
            b"davFilePut" => Permission::DavFilePut,
            b"davFileCopy" => Permission::DavFileCopy,
            b"davFileMove" => Permission::DavFileMove,
            b"davFileLock" => Permission::DavFileLock,
            b"davFileAcl" => Permission::DavFileAcl,
            b"davCardPropFind" => Permission::DavCardPropFind,
            b"davCardPropPatch" => Permission::DavCardPropPatch,
            b"davCardGet" => Permission::DavCardGet,
            b"davCardMkCol" => Permission::DavCardMkCol,
            b"davCardDelete" => Permission::DavCardDelete,
            b"davCardPut" => Permission::DavCardPut,
            b"davCardCopy" => Permission::DavCardCopy,
            b"davCardMove" => Permission::DavCardMove,
            b"davCardLock" => Permission::DavCardLock,
            b"davCardAcl" => Permission::DavCardAcl,
            b"davCardQuery" => Permission::DavCardQuery,
            b"davCardMultiGet" => Permission::DavCardMultiGet,
            b"davCalPropFind" => Permission::DavCalPropFind,
            b"davCalPropPatch" => Permission::DavCalPropPatch,
            b"davCalGet" => Permission::DavCalGet,
            b"davCalMkCol" => Permission::DavCalMkCol,
            b"davCalDelete" => Permission::DavCalDelete,
            b"davCalPut" => Permission::DavCalPut,
            b"davCalCopy" => Permission::DavCalCopy,
            b"davCalMove" => Permission::DavCalMove,
            b"davCalLock" => Permission::DavCalLock,
            b"davCalAcl" => Permission::DavCalAcl,
            b"davCalQuery" => Permission::DavCalQuery,
            b"davCalMultiGet" => Permission::DavCalMultiGet,
            b"davCalFreeBusyQuery" => Permission::DavCalFreeBusyQuery,
            b"oAuthClientRegistration" => Permission::OAuthClientRegistration,
            b"oAuthClientOverride" => Permission::OAuthClientOverride,
            b"liveTracing" => Permission::LiveTracing,
            b"liveMetrics" => Permission::LiveMetrics,
            b"liveDeliveryTest" => Permission::LiveDeliveryTest,
            b"sysAccountGet" => Permission::SysAccountGet,
            b"sysAccountCreate" => Permission::SysAccountCreate,
            b"sysAccountUpdate" => Permission::SysAccountUpdate,
            b"sysAccountDestroy" => Permission::SysAccountDestroy,
            b"sysAccountQuery" => Permission::SysAccountQuery,
            b"sysAccountPasswordGet" => Permission::SysAccountPasswordGet,
            b"sysAccountPasswordUpdate" => Permission::SysAccountPasswordUpdate,
            b"sysAccountSettingsGet" => Permission::SysAccountSettingsGet,
            b"sysAccountSettingsUpdate" => Permission::SysAccountSettingsUpdate,
            b"sysAcmeProviderGet" => Permission::SysAcmeProviderGet,
            b"sysAcmeProviderCreate" => Permission::SysAcmeProviderCreate,
            b"sysAcmeProviderUpdate" => Permission::SysAcmeProviderUpdate,
            b"sysAcmeProviderDestroy" => Permission::SysAcmeProviderDestroy,
            b"sysAcmeProviderQuery" => Permission::SysAcmeProviderQuery,
            b"actionReloadSettings" => Permission::ActionReloadSettings,
            b"actionReloadTlsCertificates" => Permission::ActionReloadTlsCertificates,
            b"actionReloadLookupStores" => Permission::ActionReloadLookupStores,
            b"actionReloadBlockedIps" => Permission::ActionReloadBlockedIps,
            b"actionUpdateApps" => Permission::ActionUpdateApps,
            b"actionTroubleshootDmarc" => Permission::ActionTroubleshootDmarc,
            b"actionClassifySpam" => Permission::ActionClassifySpam,
            b"actionInvalidateCaches" => Permission::ActionInvalidateCaches,
            b"actionInvalidateNegativeCaches" => Permission::ActionInvalidateNegativeCaches,
            b"actionPauseMtaQueue" => Permission::ActionPauseMtaQueue,
            b"actionResumeMtaQueue" => Permission::ActionResumeMtaQueue,
            b"sysActionGet" => Permission::SysActionGet,
            b"sysActionCreate" => Permission::SysActionCreate,
            b"sysActionUpdate" => Permission::SysActionUpdate,
            b"sysActionDestroy" => Permission::SysActionDestroy,
            b"sysActionQuery" => Permission::SysActionQuery,
            b"sysAddressBookGet" => Permission::SysAddressBookGet,
            b"sysAddressBookUpdate" => Permission::SysAddressBookUpdate,
            b"sysAiModelGet" => Permission::SysAiModelGet,
            b"sysAiModelCreate" => Permission::SysAiModelCreate,
            b"sysAiModelUpdate" => Permission::SysAiModelUpdate,
            b"sysAiModelDestroy" => Permission::SysAiModelDestroy,
            b"sysAiModelQuery" => Permission::SysAiModelQuery,
            b"sysAlertGet" => Permission::SysAlertGet,
            b"sysAlertCreate" => Permission::SysAlertCreate,
            b"sysAlertUpdate" => Permission::SysAlertUpdate,
            b"sysAlertDestroy" => Permission::SysAlertDestroy,
            b"sysAlertQuery" => Permission::SysAlertQuery,
            b"sysAllowedIpGet" => Permission::SysAllowedIpGet,
            b"sysAllowedIpCreate" => Permission::SysAllowedIpCreate,
            b"sysAllowedIpUpdate" => Permission::SysAllowedIpUpdate,
            b"sysAllowedIpDestroy" => Permission::SysAllowedIpDestroy,
            b"sysAllowedIpQuery" => Permission::SysAllowedIpQuery,
            b"sysApiKeyGet" => Permission::SysApiKeyGet,
            b"sysApiKeyCreate" => Permission::SysApiKeyCreate,
            b"sysApiKeyUpdate" => Permission::SysApiKeyUpdate,
            b"sysApiKeyDestroy" => Permission::SysApiKeyDestroy,
            b"sysApiKeyQuery" => Permission::SysApiKeyQuery,
            b"sysAppPasswordGet" => Permission::SysAppPasswordGet,
            b"sysAppPasswordCreate" => Permission::SysAppPasswordCreate,
            b"sysAppPasswordUpdate" => Permission::SysAppPasswordUpdate,
            b"sysAppPasswordDestroy" => Permission::SysAppPasswordDestroy,
            b"sysAppPasswordQuery" => Permission::SysAppPasswordQuery,
            b"sysApplicationGet" => Permission::SysApplicationGet,
            b"sysApplicationCreate" => Permission::SysApplicationCreate,
            b"sysApplicationUpdate" => Permission::SysApplicationUpdate,
            b"sysApplicationDestroy" => Permission::SysApplicationDestroy,
            b"sysApplicationQuery" => Permission::SysApplicationQuery,
            b"sysArchivedItemGet" => Permission::SysArchivedItemGet,
            b"sysArchivedItemCreate" => Permission::SysArchivedItemCreate,
            b"sysArchivedItemUpdate" => Permission::SysArchivedItemUpdate,
            b"sysArchivedItemDestroy" => Permission::SysArchivedItemDestroy,
            b"sysArchivedItemQuery" => Permission::SysArchivedItemQuery,
            b"sysArfExternalReportGet" => Permission::SysArfExternalReportGet,
            b"sysArfExternalReportCreate" => Permission::SysArfExternalReportCreate,
            b"sysArfExternalReportUpdate" => Permission::SysArfExternalReportUpdate,
            b"sysArfExternalReportDestroy" => Permission::SysArfExternalReportDestroy,
            b"sysArfExternalReportQuery" => Permission::SysArfExternalReportQuery,
            b"sysAsnGet" => Permission::SysAsnGet,
            b"sysAsnUpdate" => Permission::SysAsnUpdate,
            b"sysAuthenticationGet" => Permission::SysAuthenticationGet,
            b"sysAuthenticationUpdate" => Permission::SysAuthenticationUpdate,
            b"sysBlobStoreGet" => Permission::SysBlobStoreGet,
            b"sysBlobStoreUpdate" => Permission::SysBlobStoreUpdate,
            b"sysBlockedIpGet" => Permission::SysBlockedIpGet,
            b"sysBlockedIpCreate" => Permission::SysBlockedIpCreate,
            b"sysBlockedIpUpdate" => Permission::SysBlockedIpUpdate,
            b"sysBlockedIpDestroy" => Permission::SysBlockedIpDestroy,
            b"sysBlockedIpQuery" => Permission::SysBlockedIpQuery,
            b"sysBootstrapGet" => Permission::SysBootstrapGet,
            b"sysBootstrapUpdate" => Permission::SysBootstrapUpdate,
            b"sysCacheGet" => Permission::SysCacheGet,
            b"sysCacheUpdate" => Permission::SysCacheUpdate,
            b"sysCalendarGet" => Permission::SysCalendarGet,
            b"sysCalendarUpdate" => Permission::SysCalendarUpdate,
            b"sysCalendarAlarmGet" => Permission::SysCalendarAlarmGet,
            b"sysCalendarAlarmUpdate" => Permission::SysCalendarAlarmUpdate,
            b"sysCalendarSchedulingGet" => Permission::SysCalendarSchedulingGet,
            b"sysCalendarSchedulingUpdate" => Permission::SysCalendarSchedulingUpdate,
            b"sysCertificateGet" => Permission::SysCertificateGet,
            b"sysCertificateCreate" => Permission::SysCertificateCreate,
            b"sysCertificateUpdate" => Permission::SysCertificateUpdate,
            b"sysCertificateDestroy" => Permission::SysCertificateDestroy,
            b"sysCertificateQuery" => Permission::SysCertificateQuery,
            b"sysClusterNodeGet" => Permission::SysClusterNodeGet,
            b"sysClusterNodeCreate" => Permission::SysClusterNodeCreate,
            b"sysClusterNodeUpdate" => Permission::SysClusterNodeUpdate,
            b"sysClusterNodeDestroy" => Permission::SysClusterNodeDestroy,
            b"sysClusterNodeQuery" => Permission::SysClusterNodeQuery,
            b"sysClusterRoleGet" => Permission::SysClusterRoleGet,
            b"sysClusterRoleCreate" => Permission::SysClusterRoleCreate,
            b"sysClusterRoleUpdate" => Permission::SysClusterRoleUpdate,
            b"sysClusterRoleDestroy" => Permission::SysClusterRoleDestroy,
            b"sysClusterRoleQuery" => Permission::SysClusterRoleQuery,
            b"sysCoordinatorGet" => Permission::SysCoordinatorGet,
            b"sysCoordinatorUpdate" => Permission::SysCoordinatorUpdate,
            b"sysDataRetentionGet" => Permission::SysDataRetentionGet,
            b"sysDataRetentionUpdate" => Permission::SysDataRetentionUpdate,
            b"sysDataStoreGet" => Permission::SysDataStoreGet,
            b"sysDataStoreUpdate" => Permission::SysDataStoreUpdate,
            b"sysDirectoryGet" => Permission::SysDirectoryGet,
            b"sysDirectoryCreate" => Permission::SysDirectoryCreate,
            b"sysDirectoryUpdate" => Permission::SysDirectoryUpdate,
            b"sysDirectoryDestroy" => Permission::SysDirectoryDestroy,
            b"sysDirectoryQuery" => Permission::SysDirectoryQuery,
            b"sysDkimReportSettingsGet" => Permission::SysDkimReportSettingsGet,
            b"sysDkimReportSettingsUpdate" => Permission::SysDkimReportSettingsUpdate,
            b"sysDkimSignatureGet" => Permission::SysDkimSignatureGet,
            b"sysDkimSignatureCreate" => Permission::SysDkimSignatureCreate,
            b"sysDkimSignatureUpdate" => Permission::SysDkimSignatureUpdate,
            b"sysDkimSignatureDestroy" => Permission::SysDkimSignatureDestroy,
            b"sysDkimSignatureQuery" => Permission::SysDkimSignatureQuery,
            b"sysDmarcExternalReportGet" => Permission::SysDmarcExternalReportGet,
            b"sysDmarcExternalReportCreate" => Permission::SysDmarcExternalReportCreate,
            b"sysDmarcExternalReportUpdate" => Permission::SysDmarcExternalReportUpdate,
            b"sysDmarcExternalReportDestroy" => Permission::SysDmarcExternalReportDestroy,
            b"sysDmarcExternalReportQuery" => Permission::SysDmarcExternalReportQuery,
            b"sysDmarcInternalReportGet" => Permission::SysDmarcInternalReportGet,
            b"sysDmarcInternalReportCreate" => Permission::SysDmarcInternalReportCreate,
            b"sysDmarcInternalReportUpdate" => Permission::SysDmarcInternalReportUpdate,
            b"sysDmarcInternalReportDestroy" => Permission::SysDmarcInternalReportDestroy,
            b"sysDmarcInternalReportQuery" => Permission::SysDmarcInternalReportQuery,
            b"sysDmarcReportSettingsGet" => Permission::SysDmarcReportSettingsGet,
            b"sysDmarcReportSettingsUpdate" => Permission::SysDmarcReportSettingsUpdate,
            b"sysDnsResolverGet" => Permission::SysDnsResolverGet,
            b"sysDnsResolverUpdate" => Permission::SysDnsResolverUpdate,
            b"sysDnsServerGet" => Permission::SysDnsServerGet,
            b"sysDnsServerCreate" => Permission::SysDnsServerCreate,
            b"sysDnsServerUpdate" => Permission::SysDnsServerUpdate,
            b"sysDnsServerDestroy" => Permission::SysDnsServerDestroy,
            b"sysDnsServerQuery" => Permission::SysDnsServerQuery,
            b"sysDomainGet" => Permission::SysDomainGet,
            b"sysDomainCreate" => Permission::SysDomainCreate,
            b"sysDomainUpdate" => Permission::SysDomainUpdate,
            b"sysDomainDestroy" => Permission::SysDomainDestroy,
            b"sysDomainQuery" => Permission::SysDomainQuery,
            b"sysDsnReportSettingsGet" => Permission::SysDsnReportSettingsGet,
            b"sysDsnReportSettingsUpdate" => Permission::SysDsnReportSettingsUpdate,
            b"sysEmailGet" => Permission::SysEmailGet,
            b"sysEmailUpdate" => Permission::SysEmailUpdate,
            b"sysEnterpriseGet" => Permission::SysEnterpriseGet,
            b"sysEnterpriseUpdate" => Permission::SysEnterpriseUpdate,
            b"sysEventTracingLevelGet" => Permission::SysEventTracingLevelGet,
            b"sysEventTracingLevelCreate" => Permission::SysEventTracingLevelCreate,
            b"sysEventTracingLevelUpdate" => Permission::SysEventTracingLevelUpdate,
            b"sysEventTracingLevelDestroy" => Permission::SysEventTracingLevelDestroy,
            b"sysEventTracingLevelQuery" => Permission::SysEventTracingLevelQuery,
            b"sysFileStorageGet" => Permission::SysFileStorageGet,
            b"sysFileStorageUpdate" => Permission::SysFileStorageUpdate,
            b"sysHttpGet" => Permission::SysHttpGet,
            b"sysHttpUpdate" => Permission::SysHttpUpdate,
            b"sysHttpFormGet" => Permission::SysHttpFormGet,
            b"sysHttpFormUpdate" => Permission::SysHttpFormUpdate,
            b"sysHttpLookupGet" => Permission::SysHttpLookupGet,
            b"sysHttpLookupCreate" => Permission::SysHttpLookupCreate,
            b"sysHttpLookupUpdate" => Permission::SysHttpLookupUpdate,
            b"sysHttpLookupDestroy" => Permission::SysHttpLookupDestroy,
            b"sysHttpLookupQuery" => Permission::SysHttpLookupQuery,
            b"sysImapGet" => Permission::SysImapGet,
            b"sysImapUpdate" => Permission::SysImapUpdate,
            b"sysInMemoryStoreGet" => Permission::SysInMemoryStoreGet,
            b"sysInMemoryStoreUpdate" => Permission::SysInMemoryStoreUpdate,
            b"sysJmapGet" => Permission::SysJmapGet,
            b"sysJmapUpdate" => Permission::SysJmapUpdate,
            b"sysLogGet" => Permission::SysLogGet,
            b"sysLogCreate" => Permission::SysLogCreate,
            b"sysLogUpdate" => Permission::SysLogUpdate,
            b"sysLogDestroy" => Permission::SysLogDestroy,
            b"sysLogQuery" => Permission::SysLogQuery,
            b"sysMailingListGet" => Permission::SysMailingListGet,
            b"sysMailingListCreate" => Permission::SysMailingListCreate,
            b"sysMailingListUpdate" => Permission::SysMailingListUpdate,
            b"sysMailingListDestroy" => Permission::SysMailingListDestroy,
            b"sysMailingListQuery" => Permission::SysMailingListQuery,
            b"sysMaskedEmailGet" => Permission::SysMaskedEmailGet,
            b"sysMaskedEmailCreate" => Permission::SysMaskedEmailCreate,
            b"sysMaskedEmailUpdate" => Permission::SysMaskedEmailUpdate,
            b"sysMaskedEmailDestroy" => Permission::SysMaskedEmailDestroy,
            b"sysMaskedEmailQuery" => Permission::SysMaskedEmailQuery,
            b"sysMemoryLookupKeyGet" => Permission::SysMemoryLookupKeyGet,
            b"sysMemoryLookupKeyCreate" => Permission::SysMemoryLookupKeyCreate,
            b"sysMemoryLookupKeyUpdate" => Permission::SysMemoryLookupKeyUpdate,
            b"sysMemoryLookupKeyDestroy" => Permission::SysMemoryLookupKeyDestroy,
            b"sysMemoryLookupKeyQuery" => Permission::SysMemoryLookupKeyQuery,
            b"sysMemoryLookupKeyValueGet" => Permission::SysMemoryLookupKeyValueGet,
            b"sysMemoryLookupKeyValueCreate" => Permission::SysMemoryLookupKeyValueCreate,
            b"sysMemoryLookupKeyValueUpdate" => Permission::SysMemoryLookupKeyValueUpdate,
            b"sysMemoryLookupKeyValueDestroy" => Permission::SysMemoryLookupKeyValueDestroy,
            b"sysMemoryLookupKeyValueQuery" => Permission::SysMemoryLookupKeyValueQuery,
            b"sysMetricGet" => Permission::SysMetricGet,
            b"sysMetricCreate" => Permission::SysMetricCreate,
            b"sysMetricUpdate" => Permission::SysMetricUpdate,
            b"sysMetricDestroy" => Permission::SysMetricDestroy,
            b"sysMetricQuery" => Permission::SysMetricQuery,
            b"sysMetricsGet" => Permission::SysMetricsGet,
            b"sysMetricsUpdate" => Permission::SysMetricsUpdate,
            b"sysMetricsStoreGet" => Permission::SysMetricsStoreGet,
            b"sysMetricsStoreUpdate" => Permission::SysMetricsStoreUpdate,
            b"sysMtaConnectionStrategyGet" => Permission::SysMtaConnectionStrategyGet,
            b"sysMtaConnectionStrategyCreate" => Permission::SysMtaConnectionStrategyCreate,
            b"sysMtaConnectionStrategyUpdate" => Permission::SysMtaConnectionStrategyUpdate,
            b"sysMtaConnectionStrategyDestroy" => Permission::SysMtaConnectionStrategyDestroy,
            b"sysMtaConnectionStrategyQuery" => Permission::SysMtaConnectionStrategyQuery,
            b"sysMtaDeliveryScheduleGet" => Permission::SysMtaDeliveryScheduleGet,
            b"sysMtaDeliveryScheduleCreate" => Permission::SysMtaDeliveryScheduleCreate,
            b"sysMtaDeliveryScheduleUpdate" => Permission::SysMtaDeliveryScheduleUpdate,
            b"sysMtaDeliveryScheduleDestroy" => Permission::SysMtaDeliveryScheduleDestroy,
            b"sysMtaDeliveryScheduleQuery" => Permission::SysMtaDeliveryScheduleQuery,
            b"sysMtaExtensionsGet" => Permission::SysMtaExtensionsGet,
            b"sysMtaExtensionsUpdate" => Permission::SysMtaExtensionsUpdate,
            b"sysMtaHookGet" => Permission::SysMtaHookGet,
            b"sysMtaHookCreate" => Permission::SysMtaHookCreate,
            b"sysMtaHookUpdate" => Permission::SysMtaHookUpdate,
            b"sysMtaHookDestroy" => Permission::SysMtaHookDestroy,
            b"sysMtaHookQuery" => Permission::SysMtaHookQuery,
            b"sysMtaInboundSessionGet" => Permission::SysMtaInboundSessionGet,
            b"sysMtaInboundSessionUpdate" => Permission::SysMtaInboundSessionUpdate,
            b"sysMtaInboundThrottleGet" => Permission::SysMtaInboundThrottleGet,
            b"sysMtaInboundThrottleCreate" => Permission::SysMtaInboundThrottleCreate,
            b"sysMtaInboundThrottleUpdate" => Permission::SysMtaInboundThrottleUpdate,
            b"sysMtaInboundThrottleDestroy" => Permission::SysMtaInboundThrottleDestroy,
            b"sysMtaInboundThrottleQuery" => Permission::SysMtaInboundThrottleQuery,
            b"sysMtaMilterGet" => Permission::SysMtaMilterGet,
            b"sysMtaMilterCreate" => Permission::SysMtaMilterCreate,
            b"sysMtaMilterUpdate" => Permission::SysMtaMilterUpdate,
            b"sysMtaMilterDestroy" => Permission::SysMtaMilterDestroy,
            b"sysMtaMilterQuery" => Permission::SysMtaMilterQuery,
            b"sysMtaOutboundStrategyGet" => Permission::SysMtaOutboundStrategyGet,
            b"sysMtaOutboundStrategyUpdate" => Permission::SysMtaOutboundStrategyUpdate,
            b"sysMtaOutboundThrottleGet" => Permission::SysMtaOutboundThrottleGet,
            b"sysMtaOutboundThrottleCreate" => Permission::SysMtaOutboundThrottleCreate,
            b"sysMtaOutboundThrottleUpdate" => Permission::SysMtaOutboundThrottleUpdate,
            b"sysMtaOutboundThrottleDestroy" => Permission::SysMtaOutboundThrottleDestroy,
            b"sysMtaOutboundThrottleQuery" => Permission::SysMtaOutboundThrottleQuery,
            b"sysMtaQueueQuotaGet" => Permission::SysMtaQueueQuotaGet,
            b"sysMtaQueueQuotaCreate" => Permission::SysMtaQueueQuotaCreate,
            b"sysMtaQueueQuotaUpdate" => Permission::SysMtaQueueQuotaUpdate,
            b"sysMtaQueueQuotaDestroy" => Permission::SysMtaQueueQuotaDestroy,
            b"sysMtaQueueQuotaQuery" => Permission::SysMtaQueueQuotaQuery,
            b"sysMtaRouteGet" => Permission::SysMtaRouteGet,
            b"sysMtaRouteCreate" => Permission::SysMtaRouteCreate,
            b"sysMtaRouteUpdate" => Permission::SysMtaRouteUpdate,
            b"sysMtaRouteDestroy" => Permission::SysMtaRouteDestroy,
            b"sysMtaRouteQuery" => Permission::SysMtaRouteQuery,
            b"sysMtaStageAuthGet" => Permission::SysMtaStageAuthGet,
            b"sysMtaStageAuthUpdate" => Permission::SysMtaStageAuthUpdate,
            b"sysMtaStageConnectGet" => Permission::SysMtaStageConnectGet,
            b"sysMtaStageConnectUpdate" => Permission::SysMtaStageConnectUpdate,
            b"sysMtaStageDataGet" => Permission::SysMtaStageDataGet,
            b"sysMtaStageDataUpdate" => Permission::SysMtaStageDataUpdate,
            b"sysMtaStageEhloGet" => Permission::SysMtaStageEhloGet,
            b"sysMtaStageEhloUpdate" => Permission::SysMtaStageEhloUpdate,
            b"sysMtaStageMailGet" => Permission::SysMtaStageMailGet,
            b"sysMtaStageMailUpdate" => Permission::SysMtaStageMailUpdate,
            b"sysMtaStageRcptGet" => Permission::SysMtaStageRcptGet,
            b"sysMtaStageRcptUpdate" => Permission::SysMtaStageRcptUpdate,
            b"sysMtaStsGet" => Permission::SysMtaStsGet,
            b"sysMtaStsUpdate" => Permission::SysMtaStsUpdate,
            b"sysMtaTlsStrategyGet" => Permission::SysMtaTlsStrategyGet,
            b"sysMtaTlsStrategyCreate" => Permission::SysMtaTlsStrategyCreate,
            b"sysMtaTlsStrategyUpdate" => Permission::SysMtaTlsStrategyUpdate,
            b"sysMtaTlsStrategyDestroy" => Permission::SysMtaTlsStrategyDestroy,
            b"sysMtaTlsStrategyQuery" => Permission::SysMtaTlsStrategyQuery,
            b"sysMtaVirtualQueueGet" => Permission::SysMtaVirtualQueueGet,
            b"sysMtaVirtualQueueCreate" => Permission::SysMtaVirtualQueueCreate,
            b"sysMtaVirtualQueueUpdate" => Permission::SysMtaVirtualQueueUpdate,
            b"sysMtaVirtualQueueDestroy" => Permission::SysMtaVirtualQueueDestroy,
            b"sysMtaVirtualQueueQuery" => Permission::SysMtaVirtualQueueQuery,
            b"sysNetworkListenerGet" => Permission::SysNetworkListenerGet,
            b"sysNetworkListenerCreate" => Permission::SysNetworkListenerCreate,
            b"sysNetworkListenerUpdate" => Permission::SysNetworkListenerUpdate,
            b"sysNetworkListenerDestroy" => Permission::SysNetworkListenerDestroy,
            b"sysNetworkListenerQuery" => Permission::SysNetworkListenerQuery,
            b"sysOAuthClientGet" => Permission::SysOAuthClientGet,
            b"sysOAuthClientCreate" => Permission::SysOAuthClientCreate,
            b"sysOAuthClientUpdate" => Permission::SysOAuthClientUpdate,
            b"sysOAuthClientDestroy" => Permission::SysOAuthClientDestroy,
            b"sysOAuthClientQuery" => Permission::SysOAuthClientQuery,
            b"sysOidcProviderGet" => Permission::SysOidcProviderGet,
            b"sysOidcProviderUpdate" => Permission::SysOidcProviderUpdate,
            b"sysPublicKeyGet" => Permission::SysPublicKeyGet,
            b"sysPublicKeyCreate" => Permission::SysPublicKeyCreate,
            b"sysPublicKeyUpdate" => Permission::SysPublicKeyUpdate,
            b"sysPublicKeyDestroy" => Permission::SysPublicKeyDestroy,
            b"sysPublicKeyQuery" => Permission::SysPublicKeyQuery,
            b"sysQueuedMessageGet" => Permission::SysQueuedMessageGet,
            b"sysQueuedMessageCreate" => Permission::SysQueuedMessageCreate,
            b"sysQueuedMessageUpdate" => Permission::SysQueuedMessageUpdate,
            b"sysQueuedMessageDestroy" => Permission::SysQueuedMessageDestroy,
            b"sysQueuedMessageQuery" => Permission::SysQueuedMessageQuery,
            b"sysReportSettingsGet" => Permission::SysReportSettingsGet,
            b"sysReportSettingsUpdate" => Permission::SysReportSettingsUpdate,
            b"sysRoleGet" => Permission::SysRoleGet,
            b"sysRoleCreate" => Permission::SysRoleCreate,
            b"sysRoleUpdate" => Permission::SysRoleUpdate,
            b"sysRoleDestroy" => Permission::SysRoleDestroy,
            b"sysRoleQuery" => Permission::SysRoleQuery,
            b"sysSearchGet" => Permission::SysSearchGet,
            b"sysSearchUpdate" => Permission::SysSearchUpdate,
            b"sysSearchStoreGet" => Permission::SysSearchStoreGet,
            b"sysSearchStoreUpdate" => Permission::SysSearchStoreUpdate,
            b"sysSecurityGet" => Permission::SysSecurityGet,
            b"sysSecurityUpdate" => Permission::SysSecurityUpdate,
            b"sysSenderAuthGet" => Permission::SysSenderAuthGet,
            b"sysSenderAuthUpdate" => Permission::SysSenderAuthUpdate,
            b"sysSharingGet" => Permission::SysSharingGet,
            b"sysSharingUpdate" => Permission::SysSharingUpdate,
            b"sysSieveSystemInterpreterGet" => Permission::SysSieveSystemInterpreterGet,
            b"sysSieveSystemInterpreterUpdate" => Permission::SysSieveSystemInterpreterUpdate,
            b"sysSieveSystemScriptGet" => Permission::SysSieveSystemScriptGet,
            b"sysSieveSystemScriptCreate" => Permission::SysSieveSystemScriptCreate,
            b"sysSieveSystemScriptUpdate" => Permission::SysSieveSystemScriptUpdate,
            b"sysSieveSystemScriptDestroy" => Permission::SysSieveSystemScriptDestroy,
            b"sysSieveSystemScriptQuery" => Permission::SysSieveSystemScriptQuery,
            b"sysSieveUserInterpreterGet" => Permission::SysSieveUserInterpreterGet,
            b"sysSieveUserInterpreterUpdate" => Permission::SysSieveUserInterpreterUpdate,
            b"sysSieveUserScriptGet" => Permission::SysSieveUserScriptGet,
            b"sysSieveUserScriptCreate" => Permission::SysSieveUserScriptCreate,
            b"sysSieveUserScriptUpdate" => Permission::SysSieveUserScriptUpdate,
            b"sysSieveUserScriptDestroy" => Permission::SysSieveUserScriptDestroy,
            b"sysSieveUserScriptQuery" => Permission::SysSieveUserScriptQuery,
            b"sysSpamClassifierGet" => Permission::SysSpamClassifierGet,
            b"sysSpamClassifierUpdate" => Permission::SysSpamClassifierUpdate,
            b"sysSpamDnsblServerGet" => Permission::SysSpamDnsblServerGet,
            b"sysSpamDnsblServerCreate" => Permission::SysSpamDnsblServerCreate,
            b"sysSpamDnsblServerUpdate" => Permission::SysSpamDnsblServerUpdate,
            b"sysSpamDnsblServerDestroy" => Permission::SysSpamDnsblServerDestroy,
            b"sysSpamDnsblServerQuery" => Permission::SysSpamDnsblServerQuery,
            b"sysSpamDnsblSettingsGet" => Permission::SysSpamDnsblSettingsGet,
            b"sysSpamDnsblSettingsUpdate" => Permission::SysSpamDnsblSettingsUpdate,
            b"sysSpamFileExtensionGet" => Permission::SysSpamFileExtensionGet,
            b"sysSpamFileExtensionCreate" => Permission::SysSpamFileExtensionCreate,
            b"sysSpamFileExtensionUpdate" => Permission::SysSpamFileExtensionUpdate,
            b"sysSpamFileExtensionDestroy" => Permission::SysSpamFileExtensionDestroy,
            b"sysSpamFileExtensionQuery" => Permission::SysSpamFileExtensionQuery,
            b"sysSpamLlmGet" => Permission::SysSpamLlmGet,
            b"sysSpamLlmUpdate" => Permission::SysSpamLlmUpdate,
            b"sysSpamPyzorGet" => Permission::SysSpamPyzorGet,
            b"sysSpamPyzorUpdate" => Permission::SysSpamPyzorUpdate,
            b"sysSpamRuleGet" => Permission::SysSpamRuleGet,
            b"sysSpamRuleCreate" => Permission::SysSpamRuleCreate,
            b"sysSpamRuleUpdate" => Permission::SysSpamRuleUpdate,
            b"sysSpamRuleDestroy" => Permission::SysSpamRuleDestroy,
            b"sysSpamRuleQuery" => Permission::SysSpamRuleQuery,
            b"sysSpamSettingsGet" => Permission::SysSpamSettingsGet,
            b"sysSpamSettingsUpdate" => Permission::SysSpamSettingsUpdate,
            b"sysSpamTagGet" => Permission::SysSpamTagGet,
            b"sysSpamTagCreate" => Permission::SysSpamTagCreate,
            b"sysSpamTagUpdate" => Permission::SysSpamTagUpdate,
            b"sysSpamTagDestroy" => Permission::SysSpamTagDestroy,
            b"sysSpamTagQuery" => Permission::SysSpamTagQuery,
            b"sysSpamTrainingSampleGet" => Permission::SysSpamTrainingSampleGet,
            b"sysSpamTrainingSampleCreate" => Permission::SysSpamTrainingSampleCreate,
            b"sysSpamTrainingSampleUpdate" => Permission::SysSpamTrainingSampleUpdate,
            b"sysSpamTrainingSampleDestroy" => Permission::SysSpamTrainingSampleDestroy,
            b"sysSpamTrainingSampleQuery" => Permission::SysSpamTrainingSampleQuery,
            b"sysSpfReportSettingsGet" => Permission::SysSpfReportSettingsGet,
            b"sysSpfReportSettingsUpdate" => Permission::SysSpfReportSettingsUpdate,
            b"sysStoreLookupGet" => Permission::SysStoreLookupGet,
            b"sysStoreLookupCreate" => Permission::SysStoreLookupCreate,
            b"sysStoreLookupUpdate" => Permission::SysStoreLookupUpdate,
            b"sysStoreLookupDestroy" => Permission::SysStoreLookupDestroy,
            b"sysStoreLookupQuery" => Permission::SysStoreLookupQuery,
            b"sysSystemSettingsGet" => Permission::SysSystemSettingsGet,
            b"sysSystemSettingsUpdate" => Permission::SysSystemSettingsUpdate,
            b"taskIndexDocument" => Permission::TaskIndexDocument,
            b"taskUnindexDocument" => Permission::TaskUnindexDocument,
            b"taskIndexTrace" => Permission::TaskIndexTrace,
            b"taskCalendarAlarmEmail" => Permission::TaskCalendarAlarmEmail,
            b"taskCalendarAlarmNotification" => Permission::TaskCalendarAlarmNotification,
            b"taskCalendarItipMessage" => Permission::TaskCalendarItipMessage,
            b"taskMergeThreads" => Permission::TaskMergeThreads,
            b"taskDmarcReport" => Permission::TaskDmarcReport,
            b"taskTlsReport" => Permission::TaskTlsReport,
            b"taskRestoreArchivedItem" => Permission::TaskRestoreArchivedItem,
            b"taskDestroyAccount" => Permission::TaskDestroyAccount,
            b"taskAccountMaintenance" => Permission::TaskAccountMaintenance,
            b"taskTenantMaintenance" => Permission::TaskTenantMaintenance,
            b"taskStoreMaintenance" => Permission::TaskStoreMaintenance,
            b"taskSpamFilterMaintenance" => Permission::TaskSpamFilterMaintenance,
            b"taskAcmeRenewal" => Permission::TaskAcmeRenewal,
            b"taskDkimManagement" => Permission::TaskDkimManagement,
            b"taskDnsManagement" => Permission::TaskDnsManagement,
            b"sysTaskGet" => Permission::SysTaskGet,
            b"sysTaskCreate" => Permission::SysTaskCreate,
            b"sysTaskUpdate" => Permission::SysTaskUpdate,
            b"sysTaskDestroy" => Permission::SysTaskDestroy,
            b"sysTaskQuery" => Permission::SysTaskQuery,
            b"sysTaskManagerGet" => Permission::SysTaskManagerGet,
            b"sysTaskManagerUpdate" => Permission::SysTaskManagerUpdate,
            b"sysTenantGet" => Permission::SysTenantGet,
            b"sysTenantCreate" => Permission::SysTenantCreate,
            b"sysTenantUpdate" => Permission::SysTenantUpdate,
            b"sysTenantDestroy" => Permission::SysTenantDestroy,
            b"sysTenantQuery" => Permission::SysTenantQuery,
            b"sysTlsExternalReportGet" => Permission::SysTlsExternalReportGet,
            b"sysTlsExternalReportCreate" => Permission::SysTlsExternalReportCreate,
            b"sysTlsExternalReportUpdate" => Permission::SysTlsExternalReportUpdate,
            b"sysTlsExternalReportDestroy" => Permission::SysTlsExternalReportDestroy,
            b"sysTlsExternalReportQuery" => Permission::SysTlsExternalReportQuery,
            b"sysTlsInternalReportGet" => Permission::SysTlsInternalReportGet,
            b"sysTlsInternalReportCreate" => Permission::SysTlsInternalReportCreate,
            b"sysTlsInternalReportUpdate" => Permission::SysTlsInternalReportUpdate,
            b"sysTlsInternalReportDestroy" => Permission::SysTlsInternalReportDestroy,
            b"sysTlsInternalReportQuery" => Permission::SysTlsInternalReportQuery,
            b"sysTlsReportSettingsGet" => Permission::SysTlsReportSettingsGet,
            b"sysTlsReportSettingsUpdate" => Permission::SysTlsReportSettingsUpdate,
            b"sysTraceGet" => Permission::SysTraceGet,
            b"sysTraceCreate" => Permission::SysTraceCreate,
            b"sysTraceUpdate" => Permission::SysTraceUpdate,
            b"sysTraceDestroy" => Permission::SysTraceDestroy,
            b"sysTraceQuery" => Permission::SysTraceQuery,
            b"sysTracerGet" => Permission::SysTracerGet,
            b"sysTracerCreate" => Permission::SysTracerCreate,
            b"sysTracerUpdate" => Permission::SysTracerUpdate,
            b"sysTracerDestroy" => Permission::SysTracerDestroy,
            b"sysTracerQuery" => Permission::SysTracerQuery,
            b"sysTracingStoreGet" => Permission::SysTracingStoreGet,
            b"sysTracingStoreUpdate" => Permission::SysTracingStoreUpdate,
            b"sysWebDavGet" => Permission::SysWebDavGet,
            b"sysWebDavUpdate" => Permission::SysWebDavUpdate,
            b"sysWebHookGet" => Permission::SysWebHookGet,
            b"sysWebHookCreate" => Permission::SysWebHookCreate,
            b"sysWebHookUpdate" => Permission::SysWebHookUpdate,
            b"sysWebHookDestroy" => Permission::SysWebHookDestroy,
            b"sysWebHookQuery" => Permission::SysWebHookQuery,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            Permission::Authenticate => "authenticate",
            Permission::AuthenticateWithAlias => "authenticateWithAlias",
            Permission::InteractAi => "interactAi",
            Permission::Impersonate => "impersonate",
            Permission::UnlimitedRequests => "unlimitedRequests",
            Permission::UnlimitedUploads => "unlimitedUploads",
            Permission::FetchAnyBlob => "fetchAnyBlob",
            Permission::EmailSend => "emailSend",
            Permission::EmailReceive => "emailReceive",
            Permission::CalendarAlarmsSend => "calendarAlarmsSend",
            Permission::CalendarSchedulingSend => "calendarSchedulingSend",
            Permission::CalendarSchedulingReceive => "calendarSchedulingReceive",
            Permission::JmapPushSubscriptionGet => "jmapPushSubscriptionGet",
            Permission::JmapPushSubscriptionCreate => "jmapPushSubscriptionCreate",
            Permission::JmapPushSubscriptionUpdate => "jmapPushSubscriptionUpdate",
            Permission::JmapPushSubscriptionDestroy => "jmapPushSubscriptionDestroy",
            Permission::JmapMailboxGet => "jmapMailboxGet",
            Permission::JmapMailboxChanges => "jmapMailboxChanges",
            Permission::JmapMailboxQuery => "jmapMailboxQuery",
            Permission::JmapMailboxQueryChanges => "jmapMailboxQueryChanges",
            Permission::JmapMailboxCreate => "jmapMailboxCreate",
            Permission::JmapMailboxUpdate => "jmapMailboxUpdate",
            Permission::JmapMailboxDestroy => "jmapMailboxDestroy",
            Permission::JmapThreadGet => "jmapThreadGet",
            Permission::JmapThreadChanges => "jmapThreadChanges",
            Permission::JmapEmailGet => "jmapEmailGet",
            Permission::JmapEmailChanges => "jmapEmailChanges",
            Permission::JmapEmailQuery => "jmapEmailQuery",
            Permission::JmapEmailQueryChanges => "jmapEmailQueryChanges",
            Permission::JmapEmailCreate => "jmapEmailCreate",
            Permission::JmapEmailUpdate => "jmapEmailUpdate",
            Permission::JmapEmailDestroy => "jmapEmailDestroy",
            Permission::JmapEmailCopy => "jmapEmailCopy",
            Permission::JmapEmailImport => "jmapEmailImport",
            Permission::JmapEmailParse => "jmapEmailParse",
            Permission::JmapSearchSnippetGet => "jmapSearchSnippetGet",
            Permission::JmapIdentityGet => "jmapIdentityGet",
            Permission::JmapIdentityChanges => "jmapIdentityChanges",
            Permission::JmapIdentityCreate => "jmapIdentityCreate",
            Permission::JmapIdentityUpdate => "jmapIdentityUpdate",
            Permission::JmapIdentityDestroy => "jmapIdentityDestroy",
            Permission::JmapEmailSubmissionGet => "jmapEmailSubmissionGet",
            Permission::JmapEmailSubmissionChanges => "jmapEmailSubmissionChanges",
            Permission::JmapEmailSubmissionQuery => "jmapEmailSubmissionQuery",
            Permission::JmapEmailSubmissionQueryChanges => "jmapEmailSubmissionQueryChanges",
            Permission::JmapEmailSubmissionCreate => "jmapEmailSubmissionCreate",
            Permission::JmapEmailSubmissionUpdate => "jmapEmailSubmissionUpdate",
            Permission::JmapEmailSubmissionDestroy => "jmapEmailSubmissionDestroy",
            Permission::JmapVacationResponseGet => "jmapVacationResponseGet",
            Permission::JmapVacationResponseCreate => "jmapVacationResponseCreate",
            Permission::JmapVacationResponseUpdate => "jmapVacationResponseUpdate",
            Permission::JmapVacationResponseDestroy => "jmapVacationResponseDestroy",
            Permission::JmapSieveScriptGet => "jmapSieveScriptGet",
            Permission::JmapSieveScriptQuery => "jmapSieveScriptQuery",
            Permission::JmapSieveScriptValidate => "jmapSieveScriptValidate",
            Permission::JmapSieveScriptCreate => "jmapSieveScriptCreate",
            Permission::JmapSieveScriptUpdate => "jmapSieveScriptUpdate",
            Permission::JmapSieveScriptDestroy => "jmapSieveScriptDestroy",
            Permission::JmapPrincipalGet => "jmapPrincipalGet",
            Permission::JmapPrincipalQuery => "jmapPrincipalQuery",
            Permission::JmapPrincipalChanges => "jmapPrincipalChanges",
            Permission::JmapPrincipalQueryChanges => "jmapPrincipalQueryChanges",
            Permission::JmapPrincipalGetAvailability => "jmapPrincipalGetAvailability",
            Permission::JmapPrincipalCreate => "jmapPrincipalCreate",
            Permission::JmapPrincipalUpdate => "jmapPrincipalUpdate",
            Permission::JmapPrincipalDestroy => "jmapPrincipalDestroy",
            Permission::JmapQuotaGet => "jmapQuotaGet",
            Permission::JmapQuotaChanges => "jmapQuotaChanges",
            Permission::JmapQuotaQuery => "jmapQuotaQuery",
            Permission::JmapQuotaQueryChanges => "jmapQuotaQueryChanges",
            Permission::JmapBlobGet => "jmapBlobGet",
            Permission::JmapBlobCopy => "jmapBlobCopy",
            Permission::JmapBlobLookup => "jmapBlobLookup",
            Permission::JmapBlobUpload => "jmapBlobUpload",
            Permission::JmapAddressBookGet => "jmapAddressBookGet",
            Permission::JmapAddressBookChanges => "jmapAddressBookChanges",
            Permission::JmapAddressBookCreate => "jmapAddressBookCreate",
            Permission::JmapAddressBookUpdate => "jmapAddressBookUpdate",
            Permission::JmapAddressBookDestroy => "jmapAddressBookDestroy",
            Permission::JmapContactCardGet => "jmapContactCardGet",
            Permission::JmapContactCardChanges => "jmapContactCardChanges",
            Permission::JmapContactCardQuery => "jmapContactCardQuery",
            Permission::JmapContactCardQueryChanges => "jmapContactCardQueryChanges",
            Permission::JmapContactCardCreate => "jmapContactCardCreate",
            Permission::JmapContactCardUpdate => "jmapContactCardUpdate",
            Permission::JmapContactCardDestroy => "jmapContactCardDestroy",
            Permission::JmapContactCardCopy => "jmapContactCardCopy",
            Permission::JmapContactCardParse => "jmapContactCardParse",
            Permission::JmapFileNodeGet => "jmapFileNodeGet",
            Permission::JmapFileNodeChanges => "jmapFileNodeChanges",
            Permission::JmapFileNodeQuery => "jmapFileNodeQuery",
            Permission::JmapFileNodeQueryChanges => "jmapFileNodeQueryChanges",
            Permission::JmapFileNodeCreate => "jmapFileNodeCreate",
            Permission::JmapFileNodeUpdate => "jmapFileNodeUpdate",
            Permission::JmapFileNodeDestroy => "jmapFileNodeDestroy",
            Permission::JmapFileNodeCopy => "jmapFileNodeCopy",
            Permission::JmapShareNotificationGet => "jmapShareNotificationGet",
            Permission::JmapShareNotificationChanges => "jmapShareNotificationChanges",
            Permission::JmapShareNotificationQuery => "jmapShareNotificationQuery",
            Permission::JmapShareNotificationQueryChanges => "jmapShareNotificationQueryChanges",
            Permission::JmapShareNotificationCreate => "jmapShareNotificationCreate",
            Permission::JmapShareNotificationUpdate => "jmapShareNotificationUpdate",
            Permission::JmapShareNotificationDestroy => "jmapShareNotificationDestroy",
            Permission::JmapCalendarGet => "jmapCalendarGet",
            Permission::JmapCalendarChanges => "jmapCalendarChanges",
            Permission::JmapCalendarCreate => "jmapCalendarCreate",
            Permission::JmapCalendarUpdate => "jmapCalendarUpdate",
            Permission::JmapCalendarDestroy => "jmapCalendarDestroy",
            Permission::JmapCalendarEventGet => "jmapCalendarEventGet",
            Permission::JmapCalendarEventChanges => "jmapCalendarEventChanges",
            Permission::JmapCalendarEventQuery => "jmapCalendarEventQuery",
            Permission::JmapCalendarEventQueryChanges => "jmapCalendarEventQueryChanges",
            Permission::JmapCalendarEventCreate => "jmapCalendarEventCreate",
            Permission::JmapCalendarEventUpdate => "jmapCalendarEventUpdate",
            Permission::JmapCalendarEventDestroy => "jmapCalendarEventDestroy",
            Permission::JmapCalendarEventCopy => "jmapCalendarEventCopy",
            Permission::JmapCalendarEventParse => "jmapCalendarEventParse",
            Permission::JmapCalendarEventNotificationGet => "jmapCalendarEventNotificationGet",
            Permission::JmapCalendarEventNotificationChanges => {
                "jmapCalendarEventNotificationChanges"
            }
            Permission::JmapCalendarEventNotificationQuery => "jmapCalendarEventNotificationQuery",
            Permission::JmapCalendarEventNotificationQueryChanges => {
                "jmapCalendarEventNotificationQueryChanges"
            }
            Permission::JmapCalendarEventNotificationCreate => {
                "jmapCalendarEventNotificationCreate"
            }
            Permission::JmapCalendarEventNotificationUpdate => {
                "jmapCalendarEventNotificationUpdate"
            }
            Permission::JmapCalendarEventNotificationDestroy => {
                "jmapCalendarEventNotificationDestroy"
            }
            Permission::JmapParticipantIdentityGet => "jmapParticipantIdentityGet",
            Permission::JmapParticipantIdentityChanges => "jmapParticipantIdentityChanges",
            Permission::JmapParticipantIdentityCreate => "jmapParticipantIdentityCreate",
            Permission::JmapParticipantIdentityUpdate => "jmapParticipantIdentityUpdate",
            Permission::JmapParticipantIdentityDestroy => "jmapParticipantIdentityDestroy",
            Permission::JmapCoreEcho => "jmapCoreEcho",
            Permission::ImapAuthenticate => "imapAuthenticate",
            Permission::ImapAclGet => "imapAclGet",
            Permission::ImapAclSet => "imapAclSet",
            Permission::ImapMyRights => "imapMyRights",
            Permission::ImapListRights => "imapListRights",
            Permission::ImapAppend => "imapAppend",
            Permission::ImapCapability => "imapCapability",
            Permission::ImapId => "imapId",
            Permission::ImapCopy => "imapCopy",
            Permission::ImapMove => "imapMove",
            Permission::ImapCreate => "imapCreate",
            Permission::ImapDelete => "imapDelete",
            Permission::ImapEnable => "imapEnable",
            Permission::ImapExpunge => "imapExpunge",
            Permission::ImapFetch => "imapFetch",
            Permission::ImapIdle => "imapIdle",
            Permission::ImapList => "imapList",
            Permission::ImapLsub => "imapLsub",
            Permission::ImapNamespace => "imapNamespace",
            Permission::ImapRename => "imapRename",
            Permission::ImapSearch => "imapSearch",
            Permission::ImapSort => "imapSort",
            Permission::ImapSelect => "imapSelect",
            Permission::ImapExamine => "imapExamine",
            Permission::ImapStatus => "imapStatus",
            Permission::ImapStore => "imapStore",
            Permission::ImapSubscribe => "imapSubscribe",
            Permission::ImapThread => "imapThread",
            Permission::Pop3Authenticate => "pop3Authenticate",
            Permission::Pop3List => "pop3List",
            Permission::Pop3Uidl => "pop3Uidl",
            Permission::Pop3Stat => "pop3Stat",
            Permission::Pop3Retr => "pop3Retr",
            Permission::Pop3Dele => "pop3Dele",
            Permission::SieveAuthenticate => "sieveAuthenticate",
            Permission::SieveListScripts => "sieveListScripts",
            Permission::SieveSetActive => "sieveSetActive",
            Permission::SieveGetScript => "sieveGetScript",
            Permission::SievePutScript => "sievePutScript",
            Permission::SieveDeleteScript => "sieveDeleteScript",
            Permission::SieveRenameScript => "sieveRenameScript",
            Permission::SieveCheckScript => "sieveCheckScript",
            Permission::SieveHaveSpace => "sieveHaveSpace",
            Permission::DavSyncCollection => "davSyncCollection",
            Permission::DavExpandProperty => "davExpandProperty",
            Permission::DavPrincipalAcl => "davPrincipalAcl",
            Permission::DavPrincipalList => "davPrincipalList",
            Permission::DavPrincipalMatch => "davPrincipalMatch",
            Permission::DavPrincipalSearch => "davPrincipalSearch",
            Permission::DavPrincipalSearchPropSet => "davPrincipalSearchPropSet",
            Permission::DavFilePropFind => "davFilePropFind",
            Permission::DavFilePropPatch => "davFilePropPatch",
            Permission::DavFileGet => "davFileGet",
            Permission::DavFileMkCol => "davFileMkCol",
            Permission::DavFileDelete => "davFileDelete",
            Permission::DavFilePut => "davFilePut",
            Permission::DavFileCopy => "davFileCopy",
            Permission::DavFileMove => "davFileMove",
            Permission::DavFileLock => "davFileLock",
            Permission::DavFileAcl => "davFileAcl",
            Permission::DavCardPropFind => "davCardPropFind",
            Permission::DavCardPropPatch => "davCardPropPatch",
            Permission::DavCardGet => "davCardGet",
            Permission::DavCardMkCol => "davCardMkCol",
            Permission::DavCardDelete => "davCardDelete",
            Permission::DavCardPut => "davCardPut",
            Permission::DavCardCopy => "davCardCopy",
            Permission::DavCardMove => "davCardMove",
            Permission::DavCardLock => "davCardLock",
            Permission::DavCardAcl => "davCardAcl",
            Permission::DavCardQuery => "davCardQuery",
            Permission::DavCardMultiGet => "davCardMultiGet",
            Permission::DavCalPropFind => "davCalPropFind",
            Permission::DavCalPropPatch => "davCalPropPatch",
            Permission::DavCalGet => "davCalGet",
            Permission::DavCalMkCol => "davCalMkCol",
            Permission::DavCalDelete => "davCalDelete",
            Permission::DavCalPut => "davCalPut",
            Permission::DavCalCopy => "davCalCopy",
            Permission::DavCalMove => "davCalMove",
            Permission::DavCalLock => "davCalLock",
            Permission::DavCalAcl => "davCalAcl",
            Permission::DavCalQuery => "davCalQuery",
            Permission::DavCalMultiGet => "davCalMultiGet",
            Permission::DavCalFreeBusyQuery => "davCalFreeBusyQuery",
            Permission::OAuthClientRegistration => "oAuthClientRegistration",
            Permission::OAuthClientOverride => "oAuthClientOverride",
            Permission::LiveTracing => "liveTracing",
            Permission::LiveMetrics => "liveMetrics",
            Permission::LiveDeliveryTest => "liveDeliveryTest",
            Permission::SysAccountGet => "sysAccountGet",
            Permission::SysAccountCreate => "sysAccountCreate",
            Permission::SysAccountUpdate => "sysAccountUpdate",
            Permission::SysAccountDestroy => "sysAccountDestroy",
            Permission::SysAccountQuery => "sysAccountQuery",
            Permission::SysAccountPasswordGet => "sysAccountPasswordGet",
            Permission::SysAccountPasswordUpdate => "sysAccountPasswordUpdate",
            Permission::SysAccountSettingsGet => "sysAccountSettingsGet",
            Permission::SysAccountSettingsUpdate => "sysAccountSettingsUpdate",
            Permission::SysAcmeProviderGet => "sysAcmeProviderGet",
            Permission::SysAcmeProviderCreate => "sysAcmeProviderCreate",
            Permission::SysAcmeProviderUpdate => "sysAcmeProviderUpdate",
            Permission::SysAcmeProviderDestroy => "sysAcmeProviderDestroy",
            Permission::SysAcmeProviderQuery => "sysAcmeProviderQuery",
            Permission::ActionReloadSettings => "actionReloadSettings",
            Permission::ActionReloadTlsCertificates => "actionReloadTlsCertificates",
            Permission::ActionReloadLookupStores => "actionReloadLookupStores",
            Permission::ActionReloadBlockedIps => "actionReloadBlockedIps",
            Permission::ActionUpdateApps => "actionUpdateApps",
            Permission::ActionTroubleshootDmarc => "actionTroubleshootDmarc",
            Permission::ActionClassifySpam => "actionClassifySpam",
            Permission::ActionInvalidateCaches => "actionInvalidateCaches",
            Permission::ActionInvalidateNegativeCaches => "actionInvalidateNegativeCaches",
            Permission::ActionPauseMtaQueue => "actionPauseMtaQueue",
            Permission::ActionResumeMtaQueue => "actionResumeMtaQueue",
            Permission::SysActionGet => "sysActionGet",
            Permission::SysActionCreate => "sysActionCreate",
            Permission::SysActionUpdate => "sysActionUpdate",
            Permission::SysActionDestroy => "sysActionDestroy",
            Permission::SysActionQuery => "sysActionQuery",
            Permission::SysAddressBookGet => "sysAddressBookGet",
            Permission::SysAddressBookUpdate => "sysAddressBookUpdate",
            Permission::SysAiModelGet => "sysAiModelGet",
            Permission::SysAiModelCreate => "sysAiModelCreate",
            Permission::SysAiModelUpdate => "sysAiModelUpdate",
            Permission::SysAiModelDestroy => "sysAiModelDestroy",
            Permission::SysAiModelQuery => "sysAiModelQuery",
            Permission::SysAlertGet => "sysAlertGet",
            Permission::SysAlertCreate => "sysAlertCreate",
            Permission::SysAlertUpdate => "sysAlertUpdate",
            Permission::SysAlertDestroy => "sysAlertDestroy",
            Permission::SysAlertQuery => "sysAlertQuery",
            Permission::SysAllowedIpGet => "sysAllowedIpGet",
            Permission::SysAllowedIpCreate => "sysAllowedIpCreate",
            Permission::SysAllowedIpUpdate => "sysAllowedIpUpdate",
            Permission::SysAllowedIpDestroy => "sysAllowedIpDestroy",
            Permission::SysAllowedIpQuery => "sysAllowedIpQuery",
            Permission::SysApiKeyGet => "sysApiKeyGet",
            Permission::SysApiKeyCreate => "sysApiKeyCreate",
            Permission::SysApiKeyUpdate => "sysApiKeyUpdate",
            Permission::SysApiKeyDestroy => "sysApiKeyDestroy",
            Permission::SysApiKeyQuery => "sysApiKeyQuery",
            Permission::SysAppPasswordGet => "sysAppPasswordGet",
            Permission::SysAppPasswordCreate => "sysAppPasswordCreate",
            Permission::SysAppPasswordUpdate => "sysAppPasswordUpdate",
            Permission::SysAppPasswordDestroy => "sysAppPasswordDestroy",
            Permission::SysAppPasswordQuery => "sysAppPasswordQuery",
            Permission::SysApplicationGet => "sysApplicationGet",
            Permission::SysApplicationCreate => "sysApplicationCreate",
            Permission::SysApplicationUpdate => "sysApplicationUpdate",
            Permission::SysApplicationDestroy => "sysApplicationDestroy",
            Permission::SysApplicationQuery => "sysApplicationQuery",
            Permission::SysArchivedItemGet => "sysArchivedItemGet",
            Permission::SysArchivedItemCreate => "sysArchivedItemCreate",
            Permission::SysArchivedItemUpdate => "sysArchivedItemUpdate",
            Permission::SysArchivedItemDestroy => "sysArchivedItemDestroy",
            Permission::SysArchivedItemQuery => "sysArchivedItemQuery",
            Permission::SysArfExternalReportGet => "sysArfExternalReportGet",
            Permission::SysArfExternalReportCreate => "sysArfExternalReportCreate",
            Permission::SysArfExternalReportUpdate => "sysArfExternalReportUpdate",
            Permission::SysArfExternalReportDestroy => "sysArfExternalReportDestroy",
            Permission::SysArfExternalReportQuery => "sysArfExternalReportQuery",
            Permission::SysAsnGet => "sysAsnGet",
            Permission::SysAsnUpdate => "sysAsnUpdate",
            Permission::SysAuthenticationGet => "sysAuthenticationGet",
            Permission::SysAuthenticationUpdate => "sysAuthenticationUpdate",
            Permission::SysBlobStoreGet => "sysBlobStoreGet",
            Permission::SysBlobStoreUpdate => "sysBlobStoreUpdate",
            Permission::SysBlockedIpGet => "sysBlockedIpGet",
            Permission::SysBlockedIpCreate => "sysBlockedIpCreate",
            Permission::SysBlockedIpUpdate => "sysBlockedIpUpdate",
            Permission::SysBlockedIpDestroy => "sysBlockedIpDestroy",
            Permission::SysBlockedIpQuery => "sysBlockedIpQuery",
            Permission::SysBootstrapGet => "sysBootstrapGet",
            Permission::SysBootstrapUpdate => "sysBootstrapUpdate",
            Permission::SysCacheGet => "sysCacheGet",
            Permission::SysCacheUpdate => "sysCacheUpdate",
            Permission::SysCalendarGet => "sysCalendarGet",
            Permission::SysCalendarUpdate => "sysCalendarUpdate",
            Permission::SysCalendarAlarmGet => "sysCalendarAlarmGet",
            Permission::SysCalendarAlarmUpdate => "sysCalendarAlarmUpdate",
            Permission::SysCalendarSchedulingGet => "sysCalendarSchedulingGet",
            Permission::SysCalendarSchedulingUpdate => "sysCalendarSchedulingUpdate",
            Permission::SysCertificateGet => "sysCertificateGet",
            Permission::SysCertificateCreate => "sysCertificateCreate",
            Permission::SysCertificateUpdate => "sysCertificateUpdate",
            Permission::SysCertificateDestroy => "sysCertificateDestroy",
            Permission::SysCertificateQuery => "sysCertificateQuery",
            Permission::SysClusterNodeGet => "sysClusterNodeGet",
            Permission::SysClusterNodeCreate => "sysClusterNodeCreate",
            Permission::SysClusterNodeUpdate => "sysClusterNodeUpdate",
            Permission::SysClusterNodeDestroy => "sysClusterNodeDestroy",
            Permission::SysClusterNodeQuery => "sysClusterNodeQuery",
            Permission::SysClusterRoleGet => "sysClusterRoleGet",
            Permission::SysClusterRoleCreate => "sysClusterRoleCreate",
            Permission::SysClusterRoleUpdate => "sysClusterRoleUpdate",
            Permission::SysClusterRoleDestroy => "sysClusterRoleDestroy",
            Permission::SysClusterRoleQuery => "sysClusterRoleQuery",
            Permission::SysCoordinatorGet => "sysCoordinatorGet",
            Permission::SysCoordinatorUpdate => "sysCoordinatorUpdate",
            Permission::SysDataRetentionGet => "sysDataRetentionGet",
            Permission::SysDataRetentionUpdate => "sysDataRetentionUpdate",
            Permission::SysDataStoreGet => "sysDataStoreGet",
            Permission::SysDataStoreUpdate => "sysDataStoreUpdate",
            Permission::SysDirectoryGet => "sysDirectoryGet",
            Permission::SysDirectoryCreate => "sysDirectoryCreate",
            Permission::SysDirectoryUpdate => "sysDirectoryUpdate",
            Permission::SysDirectoryDestroy => "sysDirectoryDestroy",
            Permission::SysDirectoryQuery => "sysDirectoryQuery",
            Permission::SysDkimReportSettingsGet => "sysDkimReportSettingsGet",
            Permission::SysDkimReportSettingsUpdate => "sysDkimReportSettingsUpdate",
            Permission::SysDkimSignatureGet => "sysDkimSignatureGet",
            Permission::SysDkimSignatureCreate => "sysDkimSignatureCreate",
            Permission::SysDkimSignatureUpdate => "sysDkimSignatureUpdate",
            Permission::SysDkimSignatureDestroy => "sysDkimSignatureDestroy",
            Permission::SysDkimSignatureQuery => "sysDkimSignatureQuery",
            Permission::SysDmarcExternalReportGet => "sysDmarcExternalReportGet",
            Permission::SysDmarcExternalReportCreate => "sysDmarcExternalReportCreate",
            Permission::SysDmarcExternalReportUpdate => "sysDmarcExternalReportUpdate",
            Permission::SysDmarcExternalReportDestroy => "sysDmarcExternalReportDestroy",
            Permission::SysDmarcExternalReportQuery => "sysDmarcExternalReportQuery",
            Permission::SysDmarcInternalReportGet => "sysDmarcInternalReportGet",
            Permission::SysDmarcInternalReportCreate => "sysDmarcInternalReportCreate",
            Permission::SysDmarcInternalReportUpdate => "sysDmarcInternalReportUpdate",
            Permission::SysDmarcInternalReportDestroy => "sysDmarcInternalReportDestroy",
            Permission::SysDmarcInternalReportQuery => "sysDmarcInternalReportQuery",
            Permission::SysDmarcReportSettingsGet => "sysDmarcReportSettingsGet",
            Permission::SysDmarcReportSettingsUpdate => "sysDmarcReportSettingsUpdate",
            Permission::SysDnsResolverGet => "sysDnsResolverGet",
            Permission::SysDnsResolverUpdate => "sysDnsResolverUpdate",
            Permission::SysDnsServerGet => "sysDnsServerGet",
            Permission::SysDnsServerCreate => "sysDnsServerCreate",
            Permission::SysDnsServerUpdate => "sysDnsServerUpdate",
            Permission::SysDnsServerDestroy => "sysDnsServerDestroy",
            Permission::SysDnsServerQuery => "sysDnsServerQuery",
            Permission::SysDomainGet => "sysDomainGet",
            Permission::SysDomainCreate => "sysDomainCreate",
            Permission::SysDomainUpdate => "sysDomainUpdate",
            Permission::SysDomainDestroy => "sysDomainDestroy",
            Permission::SysDomainQuery => "sysDomainQuery",
            Permission::SysDsnReportSettingsGet => "sysDsnReportSettingsGet",
            Permission::SysDsnReportSettingsUpdate => "sysDsnReportSettingsUpdate",
            Permission::SysEmailGet => "sysEmailGet",
            Permission::SysEmailUpdate => "sysEmailUpdate",
            Permission::SysEnterpriseGet => "sysEnterpriseGet",
            Permission::SysEnterpriseUpdate => "sysEnterpriseUpdate",
            Permission::SysEventTracingLevelGet => "sysEventTracingLevelGet",
            Permission::SysEventTracingLevelCreate => "sysEventTracingLevelCreate",
            Permission::SysEventTracingLevelUpdate => "sysEventTracingLevelUpdate",
            Permission::SysEventTracingLevelDestroy => "sysEventTracingLevelDestroy",
            Permission::SysEventTracingLevelQuery => "sysEventTracingLevelQuery",
            Permission::SysFileStorageGet => "sysFileStorageGet",
            Permission::SysFileStorageUpdate => "sysFileStorageUpdate",
            Permission::SysHttpGet => "sysHttpGet",
            Permission::SysHttpUpdate => "sysHttpUpdate",
            Permission::SysHttpFormGet => "sysHttpFormGet",
            Permission::SysHttpFormUpdate => "sysHttpFormUpdate",
            Permission::SysHttpLookupGet => "sysHttpLookupGet",
            Permission::SysHttpLookupCreate => "sysHttpLookupCreate",
            Permission::SysHttpLookupUpdate => "sysHttpLookupUpdate",
            Permission::SysHttpLookupDestroy => "sysHttpLookupDestroy",
            Permission::SysHttpLookupQuery => "sysHttpLookupQuery",
            Permission::SysImapGet => "sysImapGet",
            Permission::SysImapUpdate => "sysImapUpdate",
            Permission::SysInMemoryStoreGet => "sysInMemoryStoreGet",
            Permission::SysInMemoryStoreUpdate => "sysInMemoryStoreUpdate",
            Permission::SysJmapGet => "sysJmapGet",
            Permission::SysJmapUpdate => "sysJmapUpdate",
            Permission::SysLogGet => "sysLogGet",
            Permission::SysLogCreate => "sysLogCreate",
            Permission::SysLogUpdate => "sysLogUpdate",
            Permission::SysLogDestroy => "sysLogDestroy",
            Permission::SysLogQuery => "sysLogQuery",
            Permission::SysMailingListGet => "sysMailingListGet",
            Permission::SysMailingListCreate => "sysMailingListCreate",
            Permission::SysMailingListUpdate => "sysMailingListUpdate",
            Permission::SysMailingListDestroy => "sysMailingListDestroy",
            Permission::SysMailingListQuery => "sysMailingListQuery",
            Permission::SysMaskedEmailGet => "sysMaskedEmailGet",
            Permission::SysMaskedEmailCreate => "sysMaskedEmailCreate",
            Permission::SysMaskedEmailUpdate => "sysMaskedEmailUpdate",
            Permission::SysMaskedEmailDestroy => "sysMaskedEmailDestroy",
            Permission::SysMaskedEmailQuery => "sysMaskedEmailQuery",
            Permission::SysMemoryLookupKeyGet => "sysMemoryLookupKeyGet",
            Permission::SysMemoryLookupKeyCreate => "sysMemoryLookupKeyCreate",
            Permission::SysMemoryLookupKeyUpdate => "sysMemoryLookupKeyUpdate",
            Permission::SysMemoryLookupKeyDestroy => "sysMemoryLookupKeyDestroy",
            Permission::SysMemoryLookupKeyQuery => "sysMemoryLookupKeyQuery",
            Permission::SysMemoryLookupKeyValueGet => "sysMemoryLookupKeyValueGet",
            Permission::SysMemoryLookupKeyValueCreate => "sysMemoryLookupKeyValueCreate",
            Permission::SysMemoryLookupKeyValueUpdate => "sysMemoryLookupKeyValueUpdate",
            Permission::SysMemoryLookupKeyValueDestroy => "sysMemoryLookupKeyValueDestroy",
            Permission::SysMemoryLookupKeyValueQuery => "sysMemoryLookupKeyValueQuery",
            Permission::SysMetricGet => "sysMetricGet",
            Permission::SysMetricCreate => "sysMetricCreate",
            Permission::SysMetricUpdate => "sysMetricUpdate",
            Permission::SysMetricDestroy => "sysMetricDestroy",
            Permission::SysMetricQuery => "sysMetricQuery",
            Permission::SysMetricsGet => "sysMetricsGet",
            Permission::SysMetricsUpdate => "sysMetricsUpdate",
            Permission::SysMetricsStoreGet => "sysMetricsStoreGet",
            Permission::SysMetricsStoreUpdate => "sysMetricsStoreUpdate",
            Permission::SysMtaConnectionStrategyGet => "sysMtaConnectionStrategyGet",
            Permission::SysMtaConnectionStrategyCreate => "sysMtaConnectionStrategyCreate",
            Permission::SysMtaConnectionStrategyUpdate => "sysMtaConnectionStrategyUpdate",
            Permission::SysMtaConnectionStrategyDestroy => "sysMtaConnectionStrategyDestroy",
            Permission::SysMtaConnectionStrategyQuery => "sysMtaConnectionStrategyQuery",
            Permission::SysMtaDeliveryScheduleGet => "sysMtaDeliveryScheduleGet",
            Permission::SysMtaDeliveryScheduleCreate => "sysMtaDeliveryScheduleCreate",
            Permission::SysMtaDeliveryScheduleUpdate => "sysMtaDeliveryScheduleUpdate",
            Permission::SysMtaDeliveryScheduleDestroy => "sysMtaDeliveryScheduleDestroy",
            Permission::SysMtaDeliveryScheduleQuery => "sysMtaDeliveryScheduleQuery",
            Permission::SysMtaExtensionsGet => "sysMtaExtensionsGet",
            Permission::SysMtaExtensionsUpdate => "sysMtaExtensionsUpdate",
            Permission::SysMtaHookGet => "sysMtaHookGet",
            Permission::SysMtaHookCreate => "sysMtaHookCreate",
            Permission::SysMtaHookUpdate => "sysMtaHookUpdate",
            Permission::SysMtaHookDestroy => "sysMtaHookDestroy",
            Permission::SysMtaHookQuery => "sysMtaHookQuery",
            Permission::SysMtaInboundSessionGet => "sysMtaInboundSessionGet",
            Permission::SysMtaInboundSessionUpdate => "sysMtaInboundSessionUpdate",
            Permission::SysMtaInboundThrottleGet => "sysMtaInboundThrottleGet",
            Permission::SysMtaInboundThrottleCreate => "sysMtaInboundThrottleCreate",
            Permission::SysMtaInboundThrottleUpdate => "sysMtaInboundThrottleUpdate",
            Permission::SysMtaInboundThrottleDestroy => "sysMtaInboundThrottleDestroy",
            Permission::SysMtaInboundThrottleQuery => "sysMtaInboundThrottleQuery",
            Permission::SysMtaMilterGet => "sysMtaMilterGet",
            Permission::SysMtaMilterCreate => "sysMtaMilterCreate",
            Permission::SysMtaMilterUpdate => "sysMtaMilterUpdate",
            Permission::SysMtaMilterDestroy => "sysMtaMilterDestroy",
            Permission::SysMtaMilterQuery => "sysMtaMilterQuery",
            Permission::SysMtaOutboundStrategyGet => "sysMtaOutboundStrategyGet",
            Permission::SysMtaOutboundStrategyUpdate => "sysMtaOutboundStrategyUpdate",
            Permission::SysMtaOutboundThrottleGet => "sysMtaOutboundThrottleGet",
            Permission::SysMtaOutboundThrottleCreate => "sysMtaOutboundThrottleCreate",
            Permission::SysMtaOutboundThrottleUpdate => "sysMtaOutboundThrottleUpdate",
            Permission::SysMtaOutboundThrottleDestroy => "sysMtaOutboundThrottleDestroy",
            Permission::SysMtaOutboundThrottleQuery => "sysMtaOutboundThrottleQuery",
            Permission::SysMtaQueueQuotaGet => "sysMtaQueueQuotaGet",
            Permission::SysMtaQueueQuotaCreate => "sysMtaQueueQuotaCreate",
            Permission::SysMtaQueueQuotaUpdate => "sysMtaQueueQuotaUpdate",
            Permission::SysMtaQueueQuotaDestroy => "sysMtaQueueQuotaDestroy",
            Permission::SysMtaQueueQuotaQuery => "sysMtaQueueQuotaQuery",
            Permission::SysMtaRouteGet => "sysMtaRouteGet",
            Permission::SysMtaRouteCreate => "sysMtaRouteCreate",
            Permission::SysMtaRouteUpdate => "sysMtaRouteUpdate",
            Permission::SysMtaRouteDestroy => "sysMtaRouteDestroy",
            Permission::SysMtaRouteQuery => "sysMtaRouteQuery",
            Permission::SysMtaStageAuthGet => "sysMtaStageAuthGet",
            Permission::SysMtaStageAuthUpdate => "sysMtaStageAuthUpdate",
            Permission::SysMtaStageConnectGet => "sysMtaStageConnectGet",
            Permission::SysMtaStageConnectUpdate => "sysMtaStageConnectUpdate",
            Permission::SysMtaStageDataGet => "sysMtaStageDataGet",
            Permission::SysMtaStageDataUpdate => "sysMtaStageDataUpdate",
            Permission::SysMtaStageEhloGet => "sysMtaStageEhloGet",
            Permission::SysMtaStageEhloUpdate => "sysMtaStageEhloUpdate",
            Permission::SysMtaStageMailGet => "sysMtaStageMailGet",
            Permission::SysMtaStageMailUpdate => "sysMtaStageMailUpdate",
            Permission::SysMtaStageRcptGet => "sysMtaStageRcptGet",
            Permission::SysMtaStageRcptUpdate => "sysMtaStageRcptUpdate",
            Permission::SysMtaStsGet => "sysMtaStsGet",
            Permission::SysMtaStsUpdate => "sysMtaStsUpdate",
            Permission::SysMtaTlsStrategyGet => "sysMtaTlsStrategyGet",
            Permission::SysMtaTlsStrategyCreate => "sysMtaTlsStrategyCreate",
            Permission::SysMtaTlsStrategyUpdate => "sysMtaTlsStrategyUpdate",
            Permission::SysMtaTlsStrategyDestroy => "sysMtaTlsStrategyDestroy",
            Permission::SysMtaTlsStrategyQuery => "sysMtaTlsStrategyQuery",
            Permission::SysMtaVirtualQueueGet => "sysMtaVirtualQueueGet",
            Permission::SysMtaVirtualQueueCreate => "sysMtaVirtualQueueCreate",
            Permission::SysMtaVirtualQueueUpdate => "sysMtaVirtualQueueUpdate",
            Permission::SysMtaVirtualQueueDestroy => "sysMtaVirtualQueueDestroy",
            Permission::SysMtaVirtualQueueQuery => "sysMtaVirtualQueueQuery",
            Permission::SysNetworkListenerGet => "sysNetworkListenerGet",
            Permission::SysNetworkListenerCreate => "sysNetworkListenerCreate",
            Permission::SysNetworkListenerUpdate => "sysNetworkListenerUpdate",
            Permission::SysNetworkListenerDestroy => "sysNetworkListenerDestroy",
            Permission::SysNetworkListenerQuery => "sysNetworkListenerQuery",
            Permission::SysOAuthClientGet => "sysOAuthClientGet",
            Permission::SysOAuthClientCreate => "sysOAuthClientCreate",
            Permission::SysOAuthClientUpdate => "sysOAuthClientUpdate",
            Permission::SysOAuthClientDestroy => "sysOAuthClientDestroy",
            Permission::SysOAuthClientQuery => "sysOAuthClientQuery",
            Permission::SysOidcProviderGet => "sysOidcProviderGet",
            Permission::SysOidcProviderUpdate => "sysOidcProviderUpdate",
            Permission::SysPublicKeyGet => "sysPublicKeyGet",
            Permission::SysPublicKeyCreate => "sysPublicKeyCreate",
            Permission::SysPublicKeyUpdate => "sysPublicKeyUpdate",
            Permission::SysPublicKeyDestroy => "sysPublicKeyDestroy",
            Permission::SysPublicKeyQuery => "sysPublicKeyQuery",
            Permission::SysQueuedMessageGet => "sysQueuedMessageGet",
            Permission::SysQueuedMessageCreate => "sysQueuedMessageCreate",
            Permission::SysQueuedMessageUpdate => "sysQueuedMessageUpdate",
            Permission::SysQueuedMessageDestroy => "sysQueuedMessageDestroy",
            Permission::SysQueuedMessageQuery => "sysQueuedMessageQuery",
            Permission::SysReportSettingsGet => "sysReportSettingsGet",
            Permission::SysReportSettingsUpdate => "sysReportSettingsUpdate",
            Permission::SysRoleGet => "sysRoleGet",
            Permission::SysRoleCreate => "sysRoleCreate",
            Permission::SysRoleUpdate => "sysRoleUpdate",
            Permission::SysRoleDestroy => "sysRoleDestroy",
            Permission::SysRoleQuery => "sysRoleQuery",
            Permission::SysSearchGet => "sysSearchGet",
            Permission::SysSearchUpdate => "sysSearchUpdate",
            Permission::SysSearchStoreGet => "sysSearchStoreGet",
            Permission::SysSearchStoreUpdate => "sysSearchStoreUpdate",
            Permission::SysSecurityGet => "sysSecurityGet",
            Permission::SysSecurityUpdate => "sysSecurityUpdate",
            Permission::SysSenderAuthGet => "sysSenderAuthGet",
            Permission::SysSenderAuthUpdate => "sysSenderAuthUpdate",
            Permission::SysSharingGet => "sysSharingGet",
            Permission::SysSharingUpdate => "sysSharingUpdate",
            Permission::SysSieveSystemInterpreterGet => "sysSieveSystemInterpreterGet",
            Permission::SysSieveSystemInterpreterUpdate => "sysSieveSystemInterpreterUpdate",
            Permission::SysSieveSystemScriptGet => "sysSieveSystemScriptGet",
            Permission::SysSieveSystemScriptCreate => "sysSieveSystemScriptCreate",
            Permission::SysSieveSystemScriptUpdate => "sysSieveSystemScriptUpdate",
            Permission::SysSieveSystemScriptDestroy => "sysSieveSystemScriptDestroy",
            Permission::SysSieveSystemScriptQuery => "sysSieveSystemScriptQuery",
            Permission::SysSieveUserInterpreterGet => "sysSieveUserInterpreterGet",
            Permission::SysSieveUserInterpreterUpdate => "sysSieveUserInterpreterUpdate",
            Permission::SysSieveUserScriptGet => "sysSieveUserScriptGet",
            Permission::SysSieveUserScriptCreate => "sysSieveUserScriptCreate",
            Permission::SysSieveUserScriptUpdate => "sysSieveUserScriptUpdate",
            Permission::SysSieveUserScriptDestroy => "sysSieveUserScriptDestroy",
            Permission::SysSieveUserScriptQuery => "sysSieveUserScriptQuery",
            Permission::SysSpamClassifierGet => "sysSpamClassifierGet",
            Permission::SysSpamClassifierUpdate => "sysSpamClassifierUpdate",
            Permission::SysSpamDnsblServerGet => "sysSpamDnsblServerGet",
            Permission::SysSpamDnsblServerCreate => "sysSpamDnsblServerCreate",
            Permission::SysSpamDnsblServerUpdate => "sysSpamDnsblServerUpdate",
            Permission::SysSpamDnsblServerDestroy => "sysSpamDnsblServerDestroy",
            Permission::SysSpamDnsblServerQuery => "sysSpamDnsblServerQuery",
            Permission::SysSpamDnsblSettingsGet => "sysSpamDnsblSettingsGet",
            Permission::SysSpamDnsblSettingsUpdate => "sysSpamDnsblSettingsUpdate",
            Permission::SysSpamFileExtensionGet => "sysSpamFileExtensionGet",
            Permission::SysSpamFileExtensionCreate => "sysSpamFileExtensionCreate",
            Permission::SysSpamFileExtensionUpdate => "sysSpamFileExtensionUpdate",
            Permission::SysSpamFileExtensionDestroy => "sysSpamFileExtensionDestroy",
            Permission::SysSpamFileExtensionQuery => "sysSpamFileExtensionQuery",
            Permission::SysSpamLlmGet => "sysSpamLlmGet",
            Permission::SysSpamLlmUpdate => "sysSpamLlmUpdate",
            Permission::SysSpamPyzorGet => "sysSpamPyzorGet",
            Permission::SysSpamPyzorUpdate => "sysSpamPyzorUpdate",
            Permission::SysSpamRuleGet => "sysSpamRuleGet",
            Permission::SysSpamRuleCreate => "sysSpamRuleCreate",
            Permission::SysSpamRuleUpdate => "sysSpamRuleUpdate",
            Permission::SysSpamRuleDestroy => "sysSpamRuleDestroy",
            Permission::SysSpamRuleQuery => "sysSpamRuleQuery",
            Permission::SysSpamSettingsGet => "sysSpamSettingsGet",
            Permission::SysSpamSettingsUpdate => "sysSpamSettingsUpdate",
            Permission::SysSpamTagGet => "sysSpamTagGet",
            Permission::SysSpamTagCreate => "sysSpamTagCreate",
            Permission::SysSpamTagUpdate => "sysSpamTagUpdate",
            Permission::SysSpamTagDestroy => "sysSpamTagDestroy",
            Permission::SysSpamTagQuery => "sysSpamTagQuery",
            Permission::SysSpamTrainingSampleGet => "sysSpamTrainingSampleGet",
            Permission::SysSpamTrainingSampleCreate => "sysSpamTrainingSampleCreate",
            Permission::SysSpamTrainingSampleUpdate => "sysSpamTrainingSampleUpdate",
            Permission::SysSpamTrainingSampleDestroy => "sysSpamTrainingSampleDestroy",
            Permission::SysSpamTrainingSampleQuery => "sysSpamTrainingSampleQuery",
            Permission::SysSpfReportSettingsGet => "sysSpfReportSettingsGet",
            Permission::SysSpfReportSettingsUpdate => "sysSpfReportSettingsUpdate",
            Permission::SysStoreLookupGet => "sysStoreLookupGet",
            Permission::SysStoreLookupCreate => "sysStoreLookupCreate",
            Permission::SysStoreLookupUpdate => "sysStoreLookupUpdate",
            Permission::SysStoreLookupDestroy => "sysStoreLookupDestroy",
            Permission::SysStoreLookupQuery => "sysStoreLookupQuery",
            Permission::SysSystemSettingsGet => "sysSystemSettingsGet",
            Permission::SysSystemSettingsUpdate => "sysSystemSettingsUpdate",
            Permission::TaskIndexDocument => "taskIndexDocument",
            Permission::TaskUnindexDocument => "taskUnindexDocument",
            Permission::TaskIndexTrace => "taskIndexTrace",
            Permission::TaskCalendarAlarmEmail => "taskCalendarAlarmEmail",
            Permission::TaskCalendarAlarmNotification => "taskCalendarAlarmNotification",
            Permission::TaskCalendarItipMessage => "taskCalendarItipMessage",
            Permission::TaskMergeThreads => "taskMergeThreads",
            Permission::TaskDmarcReport => "taskDmarcReport",
            Permission::TaskTlsReport => "taskTlsReport",
            Permission::TaskRestoreArchivedItem => "taskRestoreArchivedItem",
            Permission::TaskDestroyAccount => "taskDestroyAccount",
            Permission::TaskAccountMaintenance => "taskAccountMaintenance",
            Permission::TaskTenantMaintenance => "taskTenantMaintenance",
            Permission::TaskStoreMaintenance => "taskStoreMaintenance",
            Permission::TaskSpamFilterMaintenance => "taskSpamFilterMaintenance",
            Permission::TaskAcmeRenewal => "taskAcmeRenewal",
            Permission::TaskDkimManagement => "taskDkimManagement",
            Permission::TaskDnsManagement => "taskDnsManagement",
            Permission::SysTaskGet => "sysTaskGet",
            Permission::SysTaskCreate => "sysTaskCreate",
            Permission::SysTaskUpdate => "sysTaskUpdate",
            Permission::SysTaskDestroy => "sysTaskDestroy",
            Permission::SysTaskQuery => "sysTaskQuery",
            Permission::SysTaskManagerGet => "sysTaskManagerGet",
            Permission::SysTaskManagerUpdate => "sysTaskManagerUpdate",
            Permission::SysTenantGet => "sysTenantGet",
            Permission::SysTenantCreate => "sysTenantCreate",
            Permission::SysTenantUpdate => "sysTenantUpdate",
            Permission::SysTenantDestroy => "sysTenantDestroy",
            Permission::SysTenantQuery => "sysTenantQuery",
            Permission::SysTlsExternalReportGet => "sysTlsExternalReportGet",
            Permission::SysTlsExternalReportCreate => "sysTlsExternalReportCreate",
            Permission::SysTlsExternalReportUpdate => "sysTlsExternalReportUpdate",
            Permission::SysTlsExternalReportDestroy => "sysTlsExternalReportDestroy",
            Permission::SysTlsExternalReportQuery => "sysTlsExternalReportQuery",
            Permission::SysTlsInternalReportGet => "sysTlsInternalReportGet",
            Permission::SysTlsInternalReportCreate => "sysTlsInternalReportCreate",
            Permission::SysTlsInternalReportUpdate => "sysTlsInternalReportUpdate",
            Permission::SysTlsInternalReportDestroy => "sysTlsInternalReportDestroy",
            Permission::SysTlsInternalReportQuery => "sysTlsInternalReportQuery",
            Permission::SysTlsReportSettingsGet => "sysTlsReportSettingsGet",
            Permission::SysTlsReportSettingsUpdate => "sysTlsReportSettingsUpdate",
            Permission::SysTraceGet => "sysTraceGet",
            Permission::SysTraceCreate => "sysTraceCreate",
            Permission::SysTraceUpdate => "sysTraceUpdate",
            Permission::SysTraceDestroy => "sysTraceDestroy",
            Permission::SysTraceQuery => "sysTraceQuery",
            Permission::SysTracerGet => "sysTracerGet",
            Permission::SysTracerCreate => "sysTracerCreate",
            Permission::SysTracerUpdate => "sysTracerUpdate",
            Permission::SysTracerDestroy => "sysTracerDestroy",
            Permission::SysTracerQuery => "sysTracerQuery",
            Permission::SysTracingStoreGet => "sysTracingStoreGet",
            Permission::SysTracingStoreUpdate => "sysTracingStoreUpdate",
            Permission::SysWebDavGet => "sysWebDavGet",
            Permission::SysWebDavUpdate => "sysWebDavUpdate",
            Permission::SysWebHookGet => "sysWebHookGet",
            Permission::SysWebHookCreate => "sysWebHookCreate",
            Permission::SysWebHookUpdate => "sysWebHookUpdate",
            Permission::SysWebHookDestroy => "sysWebHookDestroy",
            Permission::SysWebHookQuery => "sysWebHookQuery",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(Permission::Authenticate),
            1 => Some(Permission::AuthenticateWithAlias),
            2 => Some(Permission::InteractAi),
            3 => Some(Permission::Impersonate),
            4 => Some(Permission::UnlimitedRequests),
            5 => Some(Permission::UnlimitedUploads),
            6 => Some(Permission::FetchAnyBlob),
            7 => Some(Permission::EmailSend),
            8 => Some(Permission::EmailReceive),
            9 => Some(Permission::CalendarAlarmsSend),
            10 => Some(Permission::CalendarSchedulingSend),
            11 => Some(Permission::CalendarSchedulingReceive),
            12 => Some(Permission::JmapPushSubscriptionGet),
            13 => Some(Permission::JmapPushSubscriptionCreate),
            14 => Some(Permission::JmapPushSubscriptionUpdate),
            15 => Some(Permission::JmapPushSubscriptionDestroy),
            16 => Some(Permission::JmapMailboxGet),
            17 => Some(Permission::JmapMailboxChanges),
            18 => Some(Permission::JmapMailboxQuery),
            19 => Some(Permission::JmapMailboxQueryChanges),
            20 => Some(Permission::JmapMailboxCreate),
            21 => Some(Permission::JmapMailboxUpdate),
            22 => Some(Permission::JmapMailboxDestroy),
            23 => Some(Permission::JmapThreadGet),
            24 => Some(Permission::JmapThreadChanges),
            25 => Some(Permission::JmapEmailGet),
            26 => Some(Permission::JmapEmailChanges),
            27 => Some(Permission::JmapEmailQuery),
            28 => Some(Permission::JmapEmailQueryChanges),
            29 => Some(Permission::JmapEmailCreate),
            30 => Some(Permission::JmapEmailUpdate),
            31 => Some(Permission::JmapEmailDestroy),
            32 => Some(Permission::JmapEmailCopy),
            33 => Some(Permission::JmapEmailImport),
            34 => Some(Permission::JmapEmailParse),
            35 => Some(Permission::JmapSearchSnippetGet),
            36 => Some(Permission::JmapIdentityGet),
            37 => Some(Permission::JmapIdentityChanges),
            38 => Some(Permission::JmapIdentityCreate),
            39 => Some(Permission::JmapIdentityUpdate),
            40 => Some(Permission::JmapIdentityDestroy),
            41 => Some(Permission::JmapEmailSubmissionGet),
            42 => Some(Permission::JmapEmailSubmissionChanges),
            43 => Some(Permission::JmapEmailSubmissionQuery),
            44 => Some(Permission::JmapEmailSubmissionQueryChanges),
            45 => Some(Permission::JmapEmailSubmissionCreate),
            46 => Some(Permission::JmapEmailSubmissionUpdate),
            47 => Some(Permission::JmapEmailSubmissionDestroy),
            48 => Some(Permission::JmapVacationResponseGet),
            49 => Some(Permission::JmapVacationResponseCreate),
            50 => Some(Permission::JmapVacationResponseUpdate),
            51 => Some(Permission::JmapVacationResponseDestroy),
            52 => Some(Permission::JmapSieveScriptGet),
            53 => Some(Permission::JmapSieveScriptQuery),
            54 => Some(Permission::JmapSieveScriptValidate),
            55 => Some(Permission::JmapSieveScriptCreate),
            56 => Some(Permission::JmapSieveScriptUpdate),
            57 => Some(Permission::JmapSieveScriptDestroy),
            58 => Some(Permission::JmapPrincipalGet),
            59 => Some(Permission::JmapPrincipalQuery),
            60 => Some(Permission::JmapPrincipalChanges),
            61 => Some(Permission::JmapPrincipalQueryChanges),
            62 => Some(Permission::JmapPrincipalGetAvailability),
            63 => Some(Permission::JmapPrincipalCreate),
            64 => Some(Permission::JmapPrincipalUpdate),
            65 => Some(Permission::JmapPrincipalDestroy),
            66 => Some(Permission::JmapQuotaGet),
            67 => Some(Permission::JmapQuotaChanges),
            68 => Some(Permission::JmapQuotaQuery),
            69 => Some(Permission::JmapQuotaQueryChanges),
            70 => Some(Permission::JmapBlobGet),
            71 => Some(Permission::JmapBlobCopy),
            72 => Some(Permission::JmapBlobLookup),
            73 => Some(Permission::JmapBlobUpload),
            74 => Some(Permission::JmapAddressBookGet),
            75 => Some(Permission::JmapAddressBookChanges),
            76 => Some(Permission::JmapAddressBookCreate),
            77 => Some(Permission::JmapAddressBookUpdate),
            78 => Some(Permission::JmapAddressBookDestroy),
            79 => Some(Permission::JmapContactCardGet),
            80 => Some(Permission::JmapContactCardChanges),
            81 => Some(Permission::JmapContactCardQuery),
            82 => Some(Permission::JmapContactCardQueryChanges),
            83 => Some(Permission::JmapContactCardCreate),
            84 => Some(Permission::JmapContactCardUpdate),
            85 => Some(Permission::JmapContactCardDestroy),
            86 => Some(Permission::JmapContactCardCopy),
            87 => Some(Permission::JmapContactCardParse),
            88 => Some(Permission::JmapFileNodeGet),
            89 => Some(Permission::JmapFileNodeChanges),
            90 => Some(Permission::JmapFileNodeQuery),
            91 => Some(Permission::JmapFileNodeQueryChanges),
            92 => Some(Permission::JmapFileNodeCreate),
            93 => Some(Permission::JmapFileNodeUpdate),
            94 => Some(Permission::JmapFileNodeDestroy),
            659 => Some(Permission::JmapFileNodeCopy),
            95 => Some(Permission::JmapShareNotificationGet),
            96 => Some(Permission::JmapShareNotificationChanges),
            97 => Some(Permission::JmapShareNotificationQuery),
            98 => Some(Permission::JmapShareNotificationQueryChanges),
            99 => Some(Permission::JmapShareNotificationCreate),
            100 => Some(Permission::JmapShareNotificationUpdate),
            101 => Some(Permission::JmapShareNotificationDestroy),
            102 => Some(Permission::JmapCalendarGet),
            103 => Some(Permission::JmapCalendarChanges),
            104 => Some(Permission::JmapCalendarCreate),
            105 => Some(Permission::JmapCalendarUpdate),
            106 => Some(Permission::JmapCalendarDestroy),
            107 => Some(Permission::JmapCalendarEventGet),
            108 => Some(Permission::JmapCalendarEventChanges),
            109 => Some(Permission::JmapCalendarEventQuery),
            110 => Some(Permission::JmapCalendarEventQueryChanges),
            111 => Some(Permission::JmapCalendarEventCreate),
            112 => Some(Permission::JmapCalendarEventUpdate),
            113 => Some(Permission::JmapCalendarEventDestroy),
            114 => Some(Permission::JmapCalendarEventCopy),
            115 => Some(Permission::JmapCalendarEventParse),
            116 => Some(Permission::JmapCalendarEventNotificationGet),
            117 => Some(Permission::JmapCalendarEventNotificationChanges),
            118 => Some(Permission::JmapCalendarEventNotificationQuery),
            119 => Some(Permission::JmapCalendarEventNotificationQueryChanges),
            120 => Some(Permission::JmapCalendarEventNotificationCreate),
            121 => Some(Permission::JmapCalendarEventNotificationUpdate),
            122 => Some(Permission::JmapCalendarEventNotificationDestroy),
            123 => Some(Permission::JmapParticipantIdentityGet),
            124 => Some(Permission::JmapParticipantIdentityChanges),
            125 => Some(Permission::JmapParticipantIdentityCreate),
            126 => Some(Permission::JmapParticipantIdentityUpdate),
            127 => Some(Permission::JmapParticipantIdentityDestroy),
            128 => Some(Permission::JmapCoreEcho),
            129 => Some(Permission::ImapAuthenticate),
            130 => Some(Permission::ImapAclGet),
            131 => Some(Permission::ImapAclSet),
            132 => Some(Permission::ImapMyRights),
            133 => Some(Permission::ImapListRights),
            134 => Some(Permission::ImapAppend),
            135 => Some(Permission::ImapCapability),
            136 => Some(Permission::ImapId),
            137 => Some(Permission::ImapCopy),
            138 => Some(Permission::ImapMove),
            139 => Some(Permission::ImapCreate),
            140 => Some(Permission::ImapDelete),
            141 => Some(Permission::ImapEnable),
            142 => Some(Permission::ImapExpunge),
            143 => Some(Permission::ImapFetch),
            144 => Some(Permission::ImapIdle),
            145 => Some(Permission::ImapList),
            146 => Some(Permission::ImapLsub),
            147 => Some(Permission::ImapNamespace),
            148 => Some(Permission::ImapRename),
            149 => Some(Permission::ImapSearch),
            150 => Some(Permission::ImapSort),
            151 => Some(Permission::ImapSelect),
            152 => Some(Permission::ImapExamine),
            153 => Some(Permission::ImapStatus),
            154 => Some(Permission::ImapStore),
            155 => Some(Permission::ImapSubscribe),
            156 => Some(Permission::ImapThread),
            157 => Some(Permission::Pop3Authenticate),
            158 => Some(Permission::Pop3List),
            159 => Some(Permission::Pop3Uidl),
            160 => Some(Permission::Pop3Stat),
            161 => Some(Permission::Pop3Retr),
            162 => Some(Permission::Pop3Dele),
            163 => Some(Permission::SieveAuthenticate),
            164 => Some(Permission::SieveListScripts),
            165 => Some(Permission::SieveSetActive),
            166 => Some(Permission::SieveGetScript),
            167 => Some(Permission::SievePutScript),
            168 => Some(Permission::SieveDeleteScript),
            169 => Some(Permission::SieveRenameScript),
            170 => Some(Permission::SieveCheckScript),
            171 => Some(Permission::SieveHaveSpace),
            172 => Some(Permission::DavSyncCollection),
            173 => Some(Permission::DavExpandProperty),
            174 => Some(Permission::DavPrincipalAcl),
            175 => Some(Permission::DavPrincipalList),
            176 => Some(Permission::DavPrincipalMatch),
            177 => Some(Permission::DavPrincipalSearch),
            178 => Some(Permission::DavPrincipalSearchPropSet),
            179 => Some(Permission::DavFilePropFind),
            180 => Some(Permission::DavFilePropPatch),
            181 => Some(Permission::DavFileGet),
            182 => Some(Permission::DavFileMkCol),
            183 => Some(Permission::DavFileDelete),
            184 => Some(Permission::DavFilePut),
            185 => Some(Permission::DavFileCopy),
            186 => Some(Permission::DavFileMove),
            187 => Some(Permission::DavFileLock),
            188 => Some(Permission::DavFileAcl),
            189 => Some(Permission::DavCardPropFind),
            190 => Some(Permission::DavCardPropPatch),
            191 => Some(Permission::DavCardGet),
            192 => Some(Permission::DavCardMkCol),
            193 => Some(Permission::DavCardDelete),
            194 => Some(Permission::DavCardPut),
            195 => Some(Permission::DavCardCopy),
            196 => Some(Permission::DavCardMove),
            197 => Some(Permission::DavCardLock),
            198 => Some(Permission::DavCardAcl),
            199 => Some(Permission::DavCardQuery),
            200 => Some(Permission::DavCardMultiGet),
            201 => Some(Permission::DavCalPropFind),
            202 => Some(Permission::DavCalPropPatch),
            203 => Some(Permission::DavCalGet),
            204 => Some(Permission::DavCalMkCol),
            205 => Some(Permission::DavCalDelete),
            206 => Some(Permission::DavCalPut),
            207 => Some(Permission::DavCalCopy),
            208 => Some(Permission::DavCalMove),
            209 => Some(Permission::DavCalLock),
            210 => Some(Permission::DavCalAcl),
            211 => Some(Permission::DavCalQuery),
            212 => Some(Permission::DavCalMultiGet),
            213 => Some(Permission::DavCalFreeBusyQuery),
            214 => Some(Permission::OAuthClientRegistration),
            215 => Some(Permission::OAuthClientOverride),
            216 => Some(Permission::LiveTracing),
            217 => Some(Permission::LiveMetrics),
            218 => Some(Permission::LiveDeliveryTest),
            219 => Some(Permission::SysAccountGet),
            220 => Some(Permission::SysAccountCreate),
            221 => Some(Permission::SysAccountUpdate),
            222 => Some(Permission::SysAccountDestroy),
            223 => Some(Permission::SysAccountQuery),
            224 => Some(Permission::SysAccountPasswordGet),
            225 => Some(Permission::SysAccountPasswordUpdate),
            226 => Some(Permission::SysAccountSettingsGet),
            227 => Some(Permission::SysAccountSettingsUpdate),
            228 => Some(Permission::SysAcmeProviderGet),
            229 => Some(Permission::SysAcmeProviderCreate),
            230 => Some(Permission::SysAcmeProviderUpdate),
            231 => Some(Permission::SysAcmeProviderDestroy),
            232 => Some(Permission::SysAcmeProviderQuery),
            233 => Some(Permission::ActionReloadSettings),
            234 => Some(Permission::ActionReloadTlsCertificates),
            235 => Some(Permission::ActionReloadLookupStores),
            236 => Some(Permission::ActionReloadBlockedIps),
            237 => Some(Permission::ActionUpdateApps),
            238 => Some(Permission::ActionTroubleshootDmarc),
            239 => Some(Permission::ActionClassifySpam),
            240 => Some(Permission::ActionInvalidateCaches),
            241 => Some(Permission::ActionInvalidateNegativeCaches),
            242 => Some(Permission::ActionPauseMtaQueue),
            243 => Some(Permission::ActionResumeMtaQueue),
            244 => Some(Permission::SysActionGet),
            245 => Some(Permission::SysActionCreate),
            246 => Some(Permission::SysActionUpdate),
            247 => Some(Permission::SysActionDestroy),
            248 => Some(Permission::SysActionQuery),
            249 => Some(Permission::SysAddressBookGet),
            250 => Some(Permission::SysAddressBookUpdate),
            251 => Some(Permission::SysAiModelGet),
            252 => Some(Permission::SysAiModelCreate),
            253 => Some(Permission::SysAiModelUpdate),
            254 => Some(Permission::SysAiModelDestroy),
            255 => Some(Permission::SysAiModelQuery),
            256 => Some(Permission::SysAlertGet),
            257 => Some(Permission::SysAlertCreate),
            258 => Some(Permission::SysAlertUpdate),
            259 => Some(Permission::SysAlertDestroy),
            260 => Some(Permission::SysAlertQuery),
            261 => Some(Permission::SysAllowedIpGet),
            262 => Some(Permission::SysAllowedIpCreate),
            263 => Some(Permission::SysAllowedIpUpdate),
            264 => Some(Permission::SysAllowedIpDestroy),
            265 => Some(Permission::SysAllowedIpQuery),
            266 => Some(Permission::SysApiKeyGet),
            267 => Some(Permission::SysApiKeyCreate),
            268 => Some(Permission::SysApiKeyUpdate),
            269 => Some(Permission::SysApiKeyDestroy),
            270 => Some(Permission::SysApiKeyQuery),
            271 => Some(Permission::SysAppPasswordGet),
            272 => Some(Permission::SysAppPasswordCreate),
            273 => Some(Permission::SysAppPasswordUpdate),
            274 => Some(Permission::SysAppPasswordDestroy),
            275 => Some(Permission::SysAppPasswordQuery),
            276 => Some(Permission::SysApplicationGet),
            277 => Some(Permission::SysApplicationCreate),
            278 => Some(Permission::SysApplicationUpdate),
            279 => Some(Permission::SysApplicationDestroy),
            280 => Some(Permission::SysApplicationQuery),
            281 => Some(Permission::SysArchivedItemGet),
            282 => Some(Permission::SysArchivedItemCreate),
            283 => Some(Permission::SysArchivedItemUpdate),
            284 => Some(Permission::SysArchivedItemDestroy),
            285 => Some(Permission::SysArchivedItemQuery),
            286 => Some(Permission::SysArfExternalReportGet),
            287 => Some(Permission::SysArfExternalReportCreate),
            288 => Some(Permission::SysArfExternalReportUpdate),
            289 => Some(Permission::SysArfExternalReportDestroy),
            290 => Some(Permission::SysArfExternalReportQuery),
            291 => Some(Permission::SysAsnGet),
            292 => Some(Permission::SysAsnUpdate),
            293 => Some(Permission::SysAuthenticationGet),
            294 => Some(Permission::SysAuthenticationUpdate),
            295 => Some(Permission::SysBlobStoreGet),
            296 => Some(Permission::SysBlobStoreUpdate),
            297 => Some(Permission::SysBlockedIpGet),
            298 => Some(Permission::SysBlockedIpCreate),
            299 => Some(Permission::SysBlockedIpUpdate),
            300 => Some(Permission::SysBlockedIpDestroy),
            301 => Some(Permission::SysBlockedIpQuery),
            302 => Some(Permission::SysBootstrapGet),
            303 => Some(Permission::SysBootstrapUpdate),
            304 => Some(Permission::SysCacheGet),
            305 => Some(Permission::SysCacheUpdate),
            306 => Some(Permission::SysCalendarGet),
            307 => Some(Permission::SysCalendarUpdate),
            308 => Some(Permission::SysCalendarAlarmGet),
            309 => Some(Permission::SysCalendarAlarmUpdate),
            310 => Some(Permission::SysCalendarSchedulingGet),
            311 => Some(Permission::SysCalendarSchedulingUpdate),
            312 => Some(Permission::SysCertificateGet),
            313 => Some(Permission::SysCertificateCreate),
            314 => Some(Permission::SysCertificateUpdate),
            315 => Some(Permission::SysCertificateDestroy),
            316 => Some(Permission::SysCertificateQuery),
            317 => Some(Permission::SysClusterNodeGet),
            318 => Some(Permission::SysClusterNodeCreate),
            319 => Some(Permission::SysClusterNodeUpdate),
            320 => Some(Permission::SysClusterNodeDestroy),
            321 => Some(Permission::SysClusterNodeQuery),
            322 => Some(Permission::SysClusterRoleGet),
            323 => Some(Permission::SysClusterRoleCreate),
            324 => Some(Permission::SysClusterRoleUpdate),
            325 => Some(Permission::SysClusterRoleDestroy),
            326 => Some(Permission::SysClusterRoleQuery),
            327 => Some(Permission::SysCoordinatorGet),
            328 => Some(Permission::SysCoordinatorUpdate),
            329 => Some(Permission::SysDataRetentionGet),
            330 => Some(Permission::SysDataRetentionUpdate),
            331 => Some(Permission::SysDataStoreGet),
            332 => Some(Permission::SysDataStoreUpdate),
            333 => Some(Permission::SysDirectoryGet),
            334 => Some(Permission::SysDirectoryCreate),
            335 => Some(Permission::SysDirectoryUpdate),
            336 => Some(Permission::SysDirectoryDestroy),
            337 => Some(Permission::SysDirectoryQuery),
            338 => Some(Permission::SysDkimReportSettingsGet),
            339 => Some(Permission::SysDkimReportSettingsUpdate),
            340 => Some(Permission::SysDkimSignatureGet),
            341 => Some(Permission::SysDkimSignatureCreate),
            342 => Some(Permission::SysDkimSignatureUpdate),
            343 => Some(Permission::SysDkimSignatureDestroy),
            344 => Some(Permission::SysDkimSignatureQuery),
            345 => Some(Permission::SysDmarcExternalReportGet),
            346 => Some(Permission::SysDmarcExternalReportCreate),
            347 => Some(Permission::SysDmarcExternalReportUpdate),
            348 => Some(Permission::SysDmarcExternalReportDestroy),
            349 => Some(Permission::SysDmarcExternalReportQuery),
            350 => Some(Permission::SysDmarcInternalReportGet),
            351 => Some(Permission::SysDmarcInternalReportCreate),
            352 => Some(Permission::SysDmarcInternalReportUpdate),
            353 => Some(Permission::SysDmarcInternalReportDestroy),
            354 => Some(Permission::SysDmarcInternalReportQuery),
            355 => Some(Permission::SysDmarcReportSettingsGet),
            356 => Some(Permission::SysDmarcReportSettingsUpdate),
            357 => Some(Permission::SysDnsResolverGet),
            358 => Some(Permission::SysDnsResolverUpdate),
            359 => Some(Permission::SysDnsServerGet),
            360 => Some(Permission::SysDnsServerCreate),
            361 => Some(Permission::SysDnsServerUpdate),
            362 => Some(Permission::SysDnsServerDestroy),
            363 => Some(Permission::SysDnsServerQuery),
            364 => Some(Permission::SysDomainGet),
            365 => Some(Permission::SysDomainCreate),
            366 => Some(Permission::SysDomainUpdate),
            367 => Some(Permission::SysDomainDestroy),
            368 => Some(Permission::SysDomainQuery),
            369 => Some(Permission::SysDsnReportSettingsGet),
            370 => Some(Permission::SysDsnReportSettingsUpdate),
            371 => Some(Permission::SysEmailGet),
            372 => Some(Permission::SysEmailUpdate),
            373 => Some(Permission::SysEnterpriseGet),
            374 => Some(Permission::SysEnterpriseUpdate),
            375 => Some(Permission::SysEventTracingLevelGet),
            376 => Some(Permission::SysEventTracingLevelCreate),
            377 => Some(Permission::SysEventTracingLevelUpdate),
            378 => Some(Permission::SysEventTracingLevelDestroy),
            379 => Some(Permission::SysEventTracingLevelQuery),
            380 => Some(Permission::SysFileStorageGet),
            381 => Some(Permission::SysFileStorageUpdate),
            382 => Some(Permission::SysHttpGet),
            383 => Some(Permission::SysHttpUpdate),
            384 => Some(Permission::SysHttpFormGet),
            385 => Some(Permission::SysHttpFormUpdate),
            386 => Some(Permission::SysHttpLookupGet),
            387 => Some(Permission::SysHttpLookupCreate),
            388 => Some(Permission::SysHttpLookupUpdate),
            389 => Some(Permission::SysHttpLookupDestroy),
            390 => Some(Permission::SysHttpLookupQuery),
            391 => Some(Permission::SysImapGet),
            392 => Some(Permission::SysImapUpdate),
            393 => Some(Permission::SysInMemoryStoreGet),
            394 => Some(Permission::SysInMemoryStoreUpdate),
            395 => Some(Permission::SysJmapGet),
            396 => Some(Permission::SysJmapUpdate),
            397 => Some(Permission::SysLogGet),
            398 => Some(Permission::SysLogCreate),
            399 => Some(Permission::SysLogUpdate),
            400 => Some(Permission::SysLogDestroy),
            401 => Some(Permission::SysLogQuery),
            402 => Some(Permission::SysMailingListGet),
            403 => Some(Permission::SysMailingListCreate),
            404 => Some(Permission::SysMailingListUpdate),
            405 => Some(Permission::SysMailingListDestroy),
            406 => Some(Permission::SysMailingListQuery),
            407 => Some(Permission::SysMaskedEmailGet),
            408 => Some(Permission::SysMaskedEmailCreate),
            409 => Some(Permission::SysMaskedEmailUpdate),
            410 => Some(Permission::SysMaskedEmailDestroy),
            411 => Some(Permission::SysMaskedEmailQuery),
            412 => Some(Permission::SysMemoryLookupKeyGet),
            413 => Some(Permission::SysMemoryLookupKeyCreate),
            414 => Some(Permission::SysMemoryLookupKeyUpdate),
            415 => Some(Permission::SysMemoryLookupKeyDestroy),
            416 => Some(Permission::SysMemoryLookupKeyQuery),
            417 => Some(Permission::SysMemoryLookupKeyValueGet),
            418 => Some(Permission::SysMemoryLookupKeyValueCreate),
            419 => Some(Permission::SysMemoryLookupKeyValueUpdate),
            420 => Some(Permission::SysMemoryLookupKeyValueDestroy),
            421 => Some(Permission::SysMemoryLookupKeyValueQuery),
            422 => Some(Permission::SysMetricGet),
            423 => Some(Permission::SysMetricCreate),
            424 => Some(Permission::SysMetricUpdate),
            425 => Some(Permission::SysMetricDestroy),
            426 => Some(Permission::SysMetricQuery),
            427 => Some(Permission::SysMetricsGet),
            428 => Some(Permission::SysMetricsUpdate),
            429 => Some(Permission::SysMetricsStoreGet),
            430 => Some(Permission::SysMetricsStoreUpdate),
            431 => Some(Permission::SysMtaConnectionStrategyGet),
            432 => Some(Permission::SysMtaConnectionStrategyCreate),
            433 => Some(Permission::SysMtaConnectionStrategyUpdate),
            434 => Some(Permission::SysMtaConnectionStrategyDestroy),
            435 => Some(Permission::SysMtaConnectionStrategyQuery),
            436 => Some(Permission::SysMtaDeliveryScheduleGet),
            437 => Some(Permission::SysMtaDeliveryScheduleCreate),
            438 => Some(Permission::SysMtaDeliveryScheduleUpdate),
            439 => Some(Permission::SysMtaDeliveryScheduleDestroy),
            440 => Some(Permission::SysMtaDeliveryScheduleQuery),
            441 => Some(Permission::SysMtaExtensionsGet),
            442 => Some(Permission::SysMtaExtensionsUpdate),
            443 => Some(Permission::SysMtaHookGet),
            444 => Some(Permission::SysMtaHookCreate),
            445 => Some(Permission::SysMtaHookUpdate),
            446 => Some(Permission::SysMtaHookDestroy),
            447 => Some(Permission::SysMtaHookQuery),
            448 => Some(Permission::SysMtaInboundSessionGet),
            449 => Some(Permission::SysMtaInboundSessionUpdate),
            450 => Some(Permission::SysMtaInboundThrottleGet),
            451 => Some(Permission::SysMtaInboundThrottleCreate),
            452 => Some(Permission::SysMtaInboundThrottleUpdate),
            453 => Some(Permission::SysMtaInboundThrottleDestroy),
            454 => Some(Permission::SysMtaInboundThrottleQuery),
            455 => Some(Permission::SysMtaMilterGet),
            456 => Some(Permission::SysMtaMilterCreate),
            457 => Some(Permission::SysMtaMilterUpdate),
            458 => Some(Permission::SysMtaMilterDestroy),
            459 => Some(Permission::SysMtaMilterQuery),
            460 => Some(Permission::SysMtaOutboundStrategyGet),
            461 => Some(Permission::SysMtaOutboundStrategyUpdate),
            462 => Some(Permission::SysMtaOutboundThrottleGet),
            463 => Some(Permission::SysMtaOutboundThrottleCreate),
            464 => Some(Permission::SysMtaOutboundThrottleUpdate),
            465 => Some(Permission::SysMtaOutboundThrottleDestroy),
            466 => Some(Permission::SysMtaOutboundThrottleQuery),
            467 => Some(Permission::SysMtaQueueQuotaGet),
            468 => Some(Permission::SysMtaQueueQuotaCreate),
            469 => Some(Permission::SysMtaQueueQuotaUpdate),
            470 => Some(Permission::SysMtaQueueQuotaDestroy),
            471 => Some(Permission::SysMtaQueueQuotaQuery),
            472 => Some(Permission::SysMtaRouteGet),
            473 => Some(Permission::SysMtaRouteCreate),
            474 => Some(Permission::SysMtaRouteUpdate),
            475 => Some(Permission::SysMtaRouteDestroy),
            476 => Some(Permission::SysMtaRouteQuery),
            477 => Some(Permission::SysMtaStageAuthGet),
            478 => Some(Permission::SysMtaStageAuthUpdate),
            479 => Some(Permission::SysMtaStageConnectGet),
            480 => Some(Permission::SysMtaStageConnectUpdate),
            481 => Some(Permission::SysMtaStageDataGet),
            482 => Some(Permission::SysMtaStageDataUpdate),
            483 => Some(Permission::SysMtaStageEhloGet),
            484 => Some(Permission::SysMtaStageEhloUpdate),
            485 => Some(Permission::SysMtaStageMailGet),
            486 => Some(Permission::SysMtaStageMailUpdate),
            487 => Some(Permission::SysMtaStageRcptGet),
            488 => Some(Permission::SysMtaStageRcptUpdate),
            489 => Some(Permission::SysMtaStsGet),
            490 => Some(Permission::SysMtaStsUpdate),
            491 => Some(Permission::SysMtaTlsStrategyGet),
            492 => Some(Permission::SysMtaTlsStrategyCreate),
            493 => Some(Permission::SysMtaTlsStrategyUpdate),
            494 => Some(Permission::SysMtaTlsStrategyDestroy),
            495 => Some(Permission::SysMtaTlsStrategyQuery),
            496 => Some(Permission::SysMtaVirtualQueueGet),
            497 => Some(Permission::SysMtaVirtualQueueCreate),
            498 => Some(Permission::SysMtaVirtualQueueUpdate),
            499 => Some(Permission::SysMtaVirtualQueueDestroy),
            500 => Some(Permission::SysMtaVirtualQueueQuery),
            501 => Some(Permission::SysNetworkListenerGet),
            502 => Some(Permission::SysNetworkListenerCreate),
            503 => Some(Permission::SysNetworkListenerUpdate),
            504 => Some(Permission::SysNetworkListenerDestroy),
            505 => Some(Permission::SysNetworkListenerQuery),
            506 => Some(Permission::SysOAuthClientGet),
            507 => Some(Permission::SysOAuthClientCreate),
            508 => Some(Permission::SysOAuthClientUpdate),
            509 => Some(Permission::SysOAuthClientDestroy),
            510 => Some(Permission::SysOAuthClientQuery),
            511 => Some(Permission::SysOidcProviderGet),
            512 => Some(Permission::SysOidcProviderUpdate),
            513 => Some(Permission::SysPublicKeyGet),
            514 => Some(Permission::SysPublicKeyCreate),
            515 => Some(Permission::SysPublicKeyUpdate),
            516 => Some(Permission::SysPublicKeyDestroy),
            517 => Some(Permission::SysPublicKeyQuery),
            518 => Some(Permission::SysQueuedMessageGet),
            519 => Some(Permission::SysQueuedMessageCreate),
            520 => Some(Permission::SysQueuedMessageUpdate),
            521 => Some(Permission::SysQueuedMessageDestroy),
            522 => Some(Permission::SysQueuedMessageQuery),
            523 => Some(Permission::SysReportSettingsGet),
            524 => Some(Permission::SysReportSettingsUpdate),
            525 => Some(Permission::SysRoleGet),
            526 => Some(Permission::SysRoleCreate),
            527 => Some(Permission::SysRoleUpdate),
            528 => Some(Permission::SysRoleDestroy),
            529 => Some(Permission::SysRoleQuery),
            530 => Some(Permission::SysSearchGet),
            531 => Some(Permission::SysSearchUpdate),
            532 => Some(Permission::SysSearchStoreGet),
            533 => Some(Permission::SysSearchStoreUpdate),
            534 => Some(Permission::SysSecurityGet),
            535 => Some(Permission::SysSecurityUpdate),
            536 => Some(Permission::SysSenderAuthGet),
            537 => Some(Permission::SysSenderAuthUpdate),
            538 => Some(Permission::SysSharingGet),
            539 => Some(Permission::SysSharingUpdate),
            540 => Some(Permission::SysSieveSystemInterpreterGet),
            541 => Some(Permission::SysSieveSystemInterpreterUpdate),
            542 => Some(Permission::SysSieveSystemScriptGet),
            543 => Some(Permission::SysSieveSystemScriptCreate),
            544 => Some(Permission::SysSieveSystemScriptUpdate),
            545 => Some(Permission::SysSieveSystemScriptDestroy),
            546 => Some(Permission::SysSieveSystemScriptQuery),
            547 => Some(Permission::SysSieveUserInterpreterGet),
            548 => Some(Permission::SysSieveUserInterpreterUpdate),
            549 => Some(Permission::SysSieveUserScriptGet),
            550 => Some(Permission::SysSieveUserScriptCreate),
            551 => Some(Permission::SysSieveUserScriptUpdate),
            552 => Some(Permission::SysSieveUserScriptDestroy),
            553 => Some(Permission::SysSieveUserScriptQuery),
            554 => Some(Permission::SysSpamClassifierGet),
            555 => Some(Permission::SysSpamClassifierUpdate),
            556 => Some(Permission::SysSpamDnsblServerGet),
            557 => Some(Permission::SysSpamDnsblServerCreate),
            558 => Some(Permission::SysSpamDnsblServerUpdate),
            559 => Some(Permission::SysSpamDnsblServerDestroy),
            560 => Some(Permission::SysSpamDnsblServerQuery),
            561 => Some(Permission::SysSpamDnsblSettingsGet),
            562 => Some(Permission::SysSpamDnsblSettingsUpdate),
            563 => Some(Permission::SysSpamFileExtensionGet),
            564 => Some(Permission::SysSpamFileExtensionCreate),
            565 => Some(Permission::SysSpamFileExtensionUpdate),
            566 => Some(Permission::SysSpamFileExtensionDestroy),
            567 => Some(Permission::SysSpamFileExtensionQuery),
            568 => Some(Permission::SysSpamLlmGet),
            569 => Some(Permission::SysSpamLlmUpdate),
            570 => Some(Permission::SysSpamPyzorGet),
            571 => Some(Permission::SysSpamPyzorUpdate),
            572 => Some(Permission::SysSpamRuleGet),
            573 => Some(Permission::SysSpamRuleCreate),
            574 => Some(Permission::SysSpamRuleUpdate),
            575 => Some(Permission::SysSpamRuleDestroy),
            576 => Some(Permission::SysSpamRuleQuery),
            577 => Some(Permission::SysSpamSettingsGet),
            578 => Some(Permission::SysSpamSettingsUpdate),
            579 => Some(Permission::SysSpamTagGet),
            580 => Some(Permission::SysSpamTagCreate),
            581 => Some(Permission::SysSpamTagUpdate),
            582 => Some(Permission::SysSpamTagDestroy),
            583 => Some(Permission::SysSpamTagQuery),
            584 => Some(Permission::SysSpamTrainingSampleGet),
            585 => Some(Permission::SysSpamTrainingSampleCreate),
            586 => Some(Permission::SysSpamTrainingSampleUpdate),
            587 => Some(Permission::SysSpamTrainingSampleDestroy),
            588 => Some(Permission::SysSpamTrainingSampleQuery),
            589 => Some(Permission::SysSpfReportSettingsGet),
            590 => Some(Permission::SysSpfReportSettingsUpdate),
            591 => Some(Permission::SysStoreLookupGet),
            592 => Some(Permission::SysStoreLookupCreate),
            593 => Some(Permission::SysStoreLookupUpdate),
            594 => Some(Permission::SysStoreLookupDestroy),
            595 => Some(Permission::SysStoreLookupQuery),
            596 => Some(Permission::SysSystemSettingsGet),
            597 => Some(Permission::SysSystemSettingsUpdate),
            598 => Some(Permission::TaskIndexDocument),
            599 => Some(Permission::TaskUnindexDocument),
            600 => Some(Permission::TaskIndexTrace),
            601 => Some(Permission::TaskCalendarAlarmEmail),
            602 => Some(Permission::TaskCalendarAlarmNotification),
            603 => Some(Permission::TaskCalendarItipMessage),
            604 => Some(Permission::TaskMergeThreads),
            605 => Some(Permission::TaskDmarcReport),
            606 => Some(Permission::TaskTlsReport),
            607 => Some(Permission::TaskRestoreArchivedItem),
            608 => Some(Permission::TaskDestroyAccount),
            609 => Some(Permission::TaskAccountMaintenance),
            610 => Some(Permission::TaskTenantMaintenance),
            611 => Some(Permission::TaskStoreMaintenance),
            612 => Some(Permission::TaskSpamFilterMaintenance),
            613 => Some(Permission::TaskAcmeRenewal),
            614 => Some(Permission::TaskDkimManagement),
            615 => Some(Permission::TaskDnsManagement),
            616 => Some(Permission::SysTaskGet),
            617 => Some(Permission::SysTaskCreate),
            618 => Some(Permission::SysTaskUpdate),
            619 => Some(Permission::SysTaskDestroy),
            620 => Some(Permission::SysTaskQuery),
            621 => Some(Permission::SysTaskManagerGet),
            622 => Some(Permission::SysTaskManagerUpdate),
            623 => Some(Permission::SysTenantGet),
            624 => Some(Permission::SysTenantCreate),
            625 => Some(Permission::SysTenantUpdate),
            626 => Some(Permission::SysTenantDestroy),
            627 => Some(Permission::SysTenantQuery),
            628 => Some(Permission::SysTlsExternalReportGet),
            629 => Some(Permission::SysTlsExternalReportCreate),
            630 => Some(Permission::SysTlsExternalReportUpdate),
            631 => Some(Permission::SysTlsExternalReportDestroy),
            632 => Some(Permission::SysTlsExternalReportQuery),
            633 => Some(Permission::SysTlsInternalReportGet),
            634 => Some(Permission::SysTlsInternalReportCreate),
            635 => Some(Permission::SysTlsInternalReportUpdate),
            636 => Some(Permission::SysTlsInternalReportDestroy),
            637 => Some(Permission::SysTlsInternalReportQuery),
            638 => Some(Permission::SysTlsReportSettingsGet),
            639 => Some(Permission::SysTlsReportSettingsUpdate),
            640 => Some(Permission::SysTraceGet),
            641 => Some(Permission::SysTraceCreate),
            642 => Some(Permission::SysTraceUpdate),
            643 => Some(Permission::SysTraceDestroy),
            644 => Some(Permission::SysTraceQuery),
            645 => Some(Permission::SysTracerGet),
            646 => Some(Permission::SysTracerCreate),
            647 => Some(Permission::SysTracerUpdate),
            648 => Some(Permission::SysTracerDestroy),
            649 => Some(Permission::SysTracerQuery),
            650 => Some(Permission::SysTracingStoreGet),
            651 => Some(Permission::SysTracingStoreUpdate),
            652 => Some(Permission::SysWebDavGet),
            653 => Some(Permission::SysWebDavUpdate),
            654 => Some(Permission::SysWebHookGet),
            655 => Some(Permission::SysWebHookCreate),
            656 => Some(Permission::SysWebHookUpdate),
            657 => Some(Permission::SysWebHookDestroy),
            658 => Some(Permission::SysWebHookQuery),
            _ => None,
        }
    }

    const COUNT: usize = 660;
}

impl serde::Serialize for Permission {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Permission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for PermissionsType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Inherit" => PermissionsType::Inherit,
            b"Merge" => PermissionsType::Merge,
            b"Replace" => PermissionsType::Replace,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            PermissionsType::Inherit => "Inherit",
            PermissionsType::Merge => "Merge",
            PermissionsType::Replace => "Replace",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(PermissionsType::Inherit),
            1 => Some(PermissionsType::Merge),
            2 => Some(PermissionsType::Replace),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for PermissionsType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PermissionsType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for PolicyEnforcement {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"enforce" => PolicyEnforcement::Enforce,
            b"testing" => PolicyEnforcement::Testing,
            b"disable" => PolicyEnforcement::Disable,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            PolicyEnforcement::Enforce => "enforce",
            PolicyEnforcement::Testing => "testing",
            PolicyEnforcement::Disable => "disable",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(PolicyEnforcement::Enforce),
            1 => Some(PolicyEnforcement::Testing),
            2 => Some(PolicyEnforcement::Disable),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for PolicyEnforcement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PolicyEnforcement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for PostgreSqlRecyclingMethod {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"fast" => PostgreSqlRecyclingMethod::Fast,
            b"verified" => PostgreSqlRecyclingMethod::Verified,
            b"clean" => PostgreSqlRecyclingMethod::Clean,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            PostgreSqlRecyclingMethod::Fast => "fast",
            PostgreSqlRecyclingMethod::Verified => "verified",
            PostgreSqlRecyclingMethod::Clean => "clean",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(PostgreSqlRecyclingMethod::Fast),
            1 => Some(PostgreSqlRecyclingMethod::Verified),
            2 => Some(PostgreSqlRecyclingMethod::Clean),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for PostgreSqlRecyclingMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PostgreSqlRecyclingMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ProviderInfo {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"providerName" => ProviderInfo::ProviderName,
            b"providerShortName" => ProviderInfo::ProviderShortName,
            b"userDocumentation" => ProviderInfo::UserDocumentation,
            b"developerDocumentation" => ProviderInfo::DeveloperDocumentation,
            b"contactUri" => ProviderInfo::ContactUri,
            b"logoUrl" => ProviderInfo::LogoUrl,
            b"logoWidth" => ProviderInfo::LogoWidth,
            b"logoHeight" => ProviderInfo::LogoHeight,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ProviderInfo::ProviderName => "providerName",
            ProviderInfo::ProviderShortName => "providerShortName",
            ProviderInfo::UserDocumentation => "userDocumentation",
            ProviderInfo::DeveloperDocumentation => "developerDocumentation",
            ProviderInfo::ContactUri => "contactUri",
            ProviderInfo::LogoUrl => "logoUrl",
            ProviderInfo::LogoWidth => "logoWidth",
            ProviderInfo::LogoHeight => "logoHeight",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ProviderInfo::ProviderName),
            1 => Some(ProviderInfo::ProviderShortName),
            2 => Some(ProviderInfo::UserDocumentation),
            3 => Some(ProviderInfo::DeveloperDocumentation),
            4 => Some(ProviderInfo::ContactUri),
            5 => Some(ProviderInfo::LogoUrl),
            6 => Some(ProviderInfo::LogoWidth),
            7 => Some(ProviderInfo::LogoHeight),
            _ => None,
        }
    }

    const COUNT: usize = 8;
}

impl serde::Serialize for ProviderInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ProviderInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for PublicTextType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Text" => PublicTextType::Text,
            b"EnvironmentVariable" => PublicTextType::EnvironmentVariable,
            b"File" => PublicTextType::File,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            PublicTextType::Text => "Text",
            PublicTextType::EnvironmentVariable => "EnvironmentVariable",
            PublicTextType::File => "File",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(PublicTextType::Text),
            1 => Some(PublicTextType::EnvironmentVariable),
            2 => Some(PublicTextType::File),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for PublicTextType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PublicTextType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for QueueExpiryType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Ttl" => QueueExpiryType::Ttl,
            b"Attempts" => QueueExpiryType::Attempts,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            QueueExpiryType::Ttl => "Ttl",
            QueueExpiryType::Attempts => "Attempts",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(QueueExpiryType::Ttl),
            1 => Some(QueueExpiryType::Attempts),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for QueueExpiryType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for QueueExpiryType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for RecipientFlag {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"dsnSent" => RecipientFlag::DsnSent,
            b"spamPayload" => RecipientFlag::SpamPayload,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            RecipientFlag::DsnSent => "dsnSent",
            RecipientFlag::SpamPayload => "spamPayload",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(RecipientFlag::DsnSent),
            1 => Some(RecipientFlag::SpamPayload),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for RecipientFlag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RecipientFlag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for RecipientStatusType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Scheduled" => RecipientStatusType::Scheduled,
            b"Completed" => RecipientStatusType::Completed,
            b"TemporaryFailure" => RecipientStatusType::TemporaryFailure,
            b"PermanentFailure" => RecipientStatusType::PermanentFailure,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            RecipientStatusType::Scheduled => "Scheduled",
            RecipientStatusType::Completed => "Completed",
            RecipientStatusType::TemporaryFailure => "TemporaryFailure",
            RecipientStatusType::PermanentFailure => "PermanentFailure",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(RecipientStatusType::Scheduled),
            1 => Some(RecipientStatusType::Completed),
            2 => Some(RecipientStatusType::TemporaryFailure),
            3 => Some(RecipientStatusType::PermanentFailure),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for RecipientStatusType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RecipientStatusType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for RedisProtocol {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"resp2" => RedisProtocol::Resp2,
            b"resp3" => RedisProtocol::Resp3,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            RedisProtocol::Resp2 => "resp2",
            RedisProtocol::Resp3 => "resp3",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(RedisProtocol::Resp2),
            1 => Some(RedisProtocol::Resp3),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for RedisProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RedisProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for RolesType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Default" => RolesType::Default,
            b"Custom" => RolesType::Custom,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            RolesType::Default => "Default",
            RolesType::Custom => "Custom",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(RolesType::Default),
            1 => Some(RolesType::Custom),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for RolesType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RolesType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for S3StoreRegionType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"UsEast1" => S3StoreRegionType::UsEast1,
            b"UsEast2" => S3StoreRegionType::UsEast2,
            b"UsWest1" => S3StoreRegionType::UsWest1,
            b"UsWest2" => S3StoreRegionType::UsWest2,
            b"CaCentral1" => S3StoreRegionType::CaCentral1,
            b"AfSouth1" => S3StoreRegionType::AfSouth1,
            b"ApEast1" => S3StoreRegionType::ApEast1,
            b"ApSouth1" => S3StoreRegionType::ApSouth1,
            b"ApNortheast1" => S3StoreRegionType::ApNortheast1,
            b"ApNortheast2" => S3StoreRegionType::ApNortheast2,
            b"ApNortheast3" => S3StoreRegionType::ApNortheast3,
            b"ApSoutheast1" => S3StoreRegionType::ApSoutheast1,
            b"ApSoutheast2" => S3StoreRegionType::ApSoutheast2,
            b"CnNorth1" => S3StoreRegionType::CnNorth1,
            b"CnNorthwest1" => S3StoreRegionType::CnNorthwest1,
            b"EuNorth1" => S3StoreRegionType::EuNorth1,
            b"EuCentral1" => S3StoreRegionType::EuCentral1,
            b"EuCentral2" => S3StoreRegionType::EuCentral2,
            b"EuWest1" => S3StoreRegionType::EuWest1,
            b"EuWest2" => S3StoreRegionType::EuWest2,
            b"EuWest3" => S3StoreRegionType::EuWest3,
            b"IlCentral1" => S3StoreRegionType::IlCentral1,
            b"MeSouth1" => S3StoreRegionType::MeSouth1,
            b"SaEast1" => S3StoreRegionType::SaEast1,
            b"DoNyc3" => S3StoreRegionType::DoNyc3,
            b"DoAms3" => S3StoreRegionType::DoAms3,
            b"DoSgp1" => S3StoreRegionType::DoSgp1,
            b"DoFra1" => S3StoreRegionType::DoFra1,
            b"Yandex" => S3StoreRegionType::Yandex,
            b"WaUsEast1" => S3StoreRegionType::WaUsEast1,
            b"WaUsEast2" => S3StoreRegionType::WaUsEast2,
            b"WaUsCentral1" => S3StoreRegionType::WaUsCentral1,
            b"WaUsWest1" => S3StoreRegionType::WaUsWest1,
            b"WaCaCentral1" => S3StoreRegionType::WaCaCentral1,
            b"WaEuCentral1" => S3StoreRegionType::WaEuCentral1,
            b"WaEuCentral2" => S3StoreRegionType::WaEuCentral2,
            b"WaEuWest1" => S3StoreRegionType::WaEuWest1,
            b"WaEuWest2" => S3StoreRegionType::WaEuWest2,
            b"WaApNortheast1" => S3StoreRegionType::WaApNortheast1,
            b"WaApNortheast2" => S3StoreRegionType::WaApNortheast2,
            b"WaApSoutheast1" => S3StoreRegionType::WaApSoutheast1,
            b"WaApSoutheast2" => S3StoreRegionType::WaApSoutheast2,
            b"Custom" => S3StoreRegionType::Custom,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            S3StoreRegionType::UsEast1 => "UsEast1",
            S3StoreRegionType::UsEast2 => "UsEast2",
            S3StoreRegionType::UsWest1 => "UsWest1",
            S3StoreRegionType::UsWest2 => "UsWest2",
            S3StoreRegionType::CaCentral1 => "CaCentral1",
            S3StoreRegionType::AfSouth1 => "AfSouth1",
            S3StoreRegionType::ApEast1 => "ApEast1",
            S3StoreRegionType::ApSouth1 => "ApSouth1",
            S3StoreRegionType::ApNortheast1 => "ApNortheast1",
            S3StoreRegionType::ApNortheast2 => "ApNortheast2",
            S3StoreRegionType::ApNortheast3 => "ApNortheast3",
            S3StoreRegionType::ApSoutheast1 => "ApSoutheast1",
            S3StoreRegionType::ApSoutheast2 => "ApSoutheast2",
            S3StoreRegionType::CnNorth1 => "CnNorth1",
            S3StoreRegionType::CnNorthwest1 => "CnNorthwest1",
            S3StoreRegionType::EuNorth1 => "EuNorth1",
            S3StoreRegionType::EuCentral1 => "EuCentral1",
            S3StoreRegionType::EuCentral2 => "EuCentral2",
            S3StoreRegionType::EuWest1 => "EuWest1",
            S3StoreRegionType::EuWest2 => "EuWest2",
            S3StoreRegionType::EuWest3 => "EuWest3",
            S3StoreRegionType::IlCentral1 => "IlCentral1",
            S3StoreRegionType::MeSouth1 => "MeSouth1",
            S3StoreRegionType::SaEast1 => "SaEast1",
            S3StoreRegionType::DoNyc3 => "DoNyc3",
            S3StoreRegionType::DoAms3 => "DoAms3",
            S3StoreRegionType::DoSgp1 => "DoSgp1",
            S3StoreRegionType::DoFra1 => "DoFra1",
            S3StoreRegionType::Yandex => "Yandex",
            S3StoreRegionType::WaUsEast1 => "WaUsEast1",
            S3StoreRegionType::WaUsEast2 => "WaUsEast2",
            S3StoreRegionType::WaUsCentral1 => "WaUsCentral1",
            S3StoreRegionType::WaUsWest1 => "WaUsWest1",
            S3StoreRegionType::WaCaCentral1 => "WaCaCentral1",
            S3StoreRegionType::WaEuCentral1 => "WaEuCentral1",
            S3StoreRegionType::WaEuCentral2 => "WaEuCentral2",
            S3StoreRegionType::WaEuWest1 => "WaEuWest1",
            S3StoreRegionType::WaEuWest2 => "WaEuWest2",
            S3StoreRegionType::WaApNortheast1 => "WaApNortheast1",
            S3StoreRegionType::WaApNortheast2 => "WaApNortheast2",
            S3StoreRegionType::WaApSoutheast1 => "WaApSoutheast1",
            S3StoreRegionType::WaApSoutheast2 => "WaApSoutheast2",
            S3StoreRegionType::Custom => "Custom",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(S3StoreRegionType::UsEast1),
            1 => Some(S3StoreRegionType::UsEast2),
            2 => Some(S3StoreRegionType::UsWest1),
            3 => Some(S3StoreRegionType::UsWest2),
            4 => Some(S3StoreRegionType::CaCentral1),
            5 => Some(S3StoreRegionType::AfSouth1),
            6 => Some(S3StoreRegionType::ApEast1),
            7 => Some(S3StoreRegionType::ApSouth1),
            8 => Some(S3StoreRegionType::ApNortheast1),
            9 => Some(S3StoreRegionType::ApNortheast2),
            10 => Some(S3StoreRegionType::ApNortheast3),
            11 => Some(S3StoreRegionType::ApSoutheast1),
            12 => Some(S3StoreRegionType::ApSoutheast2),
            13 => Some(S3StoreRegionType::CnNorth1),
            14 => Some(S3StoreRegionType::CnNorthwest1),
            15 => Some(S3StoreRegionType::EuNorth1),
            16 => Some(S3StoreRegionType::EuCentral1),
            17 => Some(S3StoreRegionType::EuCentral2),
            18 => Some(S3StoreRegionType::EuWest1),
            19 => Some(S3StoreRegionType::EuWest2),
            20 => Some(S3StoreRegionType::EuWest3),
            21 => Some(S3StoreRegionType::IlCentral1),
            22 => Some(S3StoreRegionType::MeSouth1),
            23 => Some(S3StoreRegionType::SaEast1),
            24 => Some(S3StoreRegionType::DoNyc3),
            25 => Some(S3StoreRegionType::DoAms3),
            26 => Some(S3StoreRegionType::DoSgp1),
            27 => Some(S3StoreRegionType::DoFra1),
            28 => Some(S3StoreRegionType::Yandex),
            29 => Some(S3StoreRegionType::WaUsEast1),
            30 => Some(S3StoreRegionType::WaUsEast2),
            31 => Some(S3StoreRegionType::WaUsCentral1),
            32 => Some(S3StoreRegionType::WaUsWest1),
            33 => Some(S3StoreRegionType::WaCaCentral1),
            34 => Some(S3StoreRegionType::WaEuCentral1),
            35 => Some(S3StoreRegionType::WaEuCentral2),
            36 => Some(S3StoreRegionType::WaEuWest1),
            37 => Some(S3StoreRegionType::WaEuWest2),
            38 => Some(S3StoreRegionType::WaApNortheast1),
            39 => Some(S3StoreRegionType::WaApNortheast2),
            40 => Some(S3StoreRegionType::WaApSoutheast1),
            41 => Some(S3StoreRegionType::WaApSoutheast2),
            42 => Some(S3StoreRegionType::Custom),
            _ => None,
        }
    }

    const COUNT: usize = 43;
}

impl serde::Serialize for S3StoreRegionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for S3StoreRegionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SearchCalendarField {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"title" => SearchCalendarField::Title,
            b"description" => SearchCalendarField::Description,
            b"location" => SearchCalendarField::Location,
            b"owner" => SearchCalendarField::Owner,
            b"attendee" => SearchCalendarField::Attendee,
            b"start" => SearchCalendarField::Start,
            b"uid" => SearchCalendarField::Uid,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SearchCalendarField::Title => "title",
            SearchCalendarField::Description => "description",
            SearchCalendarField::Location => "location",
            SearchCalendarField::Owner => "owner",
            SearchCalendarField::Attendee => "attendee",
            SearchCalendarField::Start => "start",
            SearchCalendarField::Uid => "uid",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SearchCalendarField::Title),
            1 => Some(SearchCalendarField::Description),
            2 => Some(SearchCalendarField::Location),
            3 => Some(SearchCalendarField::Owner),
            4 => Some(SearchCalendarField::Attendee),
            5 => Some(SearchCalendarField::Start),
            6 => Some(SearchCalendarField::Uid),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for SearchCalendarField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SearchCalendarField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SearchContactField {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"member" => SearchContactField::Member,
            b"kind" => SearchContactField::Kind,
            b"name" => SearchContactField::Name,
            b"nickname" => SearchContactField::Nickname,
            b"organization" => SearchContactField::Organization,
            b"email" => SearchContactField::Email,
            b"phone" => SearchContactField::Phone,
            b"onlineService" => SearchContactField::OnlineService,
            b"address" => SearchContactField::Address,
            b"note" => SearchContactField::Note,
            b"uid" => SearchContactField::Uid,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SearchContactField::Member => "member",
            SearchContactField::Kind => "kind",
            SearchContactField::Name => "name",
            SearchContactField::Nickname => "nickname",
            SearchContactField::Organization => "organization",
            SearchContactField::Email => "email",
            SearchContactField::Phone => "phone",
            SearchContactField::OnlineService => "onlineService",
            SearchContactField::Address => "address",
            SearchContactField::Note => "note",
            SearchContactField::Uid => "uid",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SearchContactField::Member),
            1 => Some(SearchContactField::Kind),
            2 => Some(SearchContactField::Name),
            3 => Some(SearchContactField::Nickname),
            4 => Some(SearchContactField::Organization),
            5 => Some(SearchContactField::Email),
            6 => Some(SearchContactField::Phone),
            7 => Some(SearchContactField::OnlineService),
            8 => Some(SearchContactField::Address),
            9 => Some(SearchContactField::Note),
            10 => Some(SearchContactField::Uid),
            _ => None,
        }
    }

    const COUNT: usize = 11;
}

impl serde::Serialize for SearchContactField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SearchContactField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SearchEmailField {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"from" => SearchEmailField::From,
            b"to" => SearchEmailField::To,
            b"cc" => SearchEmailField::Cc,
            b"bcc" => SearchEmailField::Bcc,
            b"subject" => SearchEmailField::Subject,
            b"body" => SearchEmailField::Body,
            b"attachment" => SearchEmailField::Attachment,
            b"receivedAt" => SearchEmailField::ReceivedAt,
            b"sentAt" => SearchEmailField::SentAt,
            b"size" => SearchEmailField::Size,
            b"hasAttachment" => SearchEmailField::HasAttachment,
            b"headers" => SearchEmailField::Headers,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SearchEmailField::From => "from",
            SearchEmailField::To => "to",
            SearchEmailField::Cc => "cc",
            SearchEmailField::Bcc => "bcc",
            SearchEmailField::Subject => "subject",
            SearchEmailField::Body => "body",
            SearchEmailField::Attachment => "attachment",
            SearchEmailField::ReceivedAt => "receivedAt",
            SearchEmailField::SentAt => "sentAt",
            SearchEmailField::Size => "size",
            SearchEmailField::HasAttachment => "hasAttachment",
            SearchEmailField::Headers => "headers",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SearchEmailField::From),
            1 => Some(SearchEmailField::To),
            2 => Some(SearchEmailField::Cc),
            3 => Some(SearchEmailField::Bcc),
            4 => Some(SearchEmailField::Subject),
            5 => Some(SearchEmailField::Body),
            6 => Some(SearchEmailField::Attachment),
            7 => Some(SearchEmailField::ReceivedAt),
            8 => Some(SearchEmailField::SentAt),
            9 => Some(SearchEmailField::Size),
            10 => Some(SearchEmailField::HasAttachment),
            11 => Some(SearchEmailField::Headers),
            _ => None,
        }
    }

    const COUNT: usize = 12;
}

impl serde::Serialize for SearchEmailField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SearchEmailField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SearchFileField {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"name" => SearchFileField::Name,
            b"content" => SearchFileField::Content,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SearchFileField::Name => "name",
            SearchFileField::Content => "content",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SearchFileField::Name),
            1 => Some(SearchFileField::Content),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for SearchFileField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SearchFileField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SearchStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Default" => SearchStoreType::Default,
            b"ElasticSearch" => SearchStoreType::ElasticSearch,
            b"Meilisearch" => SearchStoreType::Meilisearch,
            b"FoundationDb" => SearchStoreType::FoundationDb,
            b"PostgreSql" => SearchStoreType::PostgreSql,
            b"MySql" => SearchStoreType::MySql,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SearchStoreType::Default => "Default",
            SearchStoreType::ElasticSearch => "ElasticSearch",
            SearchStoreType::Meilisearch => "Meilisearch",
            SearchStoreType::FoundationDb => "FoundationDb",
            SearchStoreType::PostgreSql => "PostgreSql",
            SearchStoreType::MySql => "MySql",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SearchStoreType::Default),
            1 => Some(SearchStoreType::ElasticSearch),
            2 => Some(SearchStoreType::Meilisearch),
            3 => Some(SearchStoreType::FoundationDb),
            4 => Some(SearchStoreType::PostgreSql),
            5 => Some(SearchStoreType::MySql),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for SearchStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SearchStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SearchTracingField {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"eventType" => SearchTracingField::EventType,
            b"queueId" => SearchTracingField::QueueId,
            b"keywords" => SearchTracingField::Keywords,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SearchTracingField::EventType => "eventType",
            SearchTracingField::QueueId => "queueId",
            SearchTracingField::Keywords => "keywords",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SearchTracingField::EventType),
            1 => Some(SearchTracingField::QueueId),
            2 => Some(SearchTracingField::Keywords),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SearchTracingField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SearchTracingField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SecretKeyOptionalType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"None" => SecretKeyOptionalType::None,
            b"Value" => SecretKeyOptionalType::Value,
            b"EnvironmentVariable" => SecretKeyOptionalType::EnvironmentVariable,
            b"File" => SecretKeyOptionalType::File,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SecretKeyOptionalType::None => "None",
            SecretKeyOptionalType::Value => "Value",
            SecretKeyOptionalType::EnvironmentVariable => "EnvironmentVariable",
            SecretKeyOptionalType::File => "File",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SecretKeyOptionalType::None),
            1 => Some(SecretKeyOptionalType::Value),
            2 => Some(SecretKeyOptionalType::EnvironmentVariable),
            3 => Some(SecretKeyOptionalType::File),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for SecretKeyOptionalType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SecretKeyOptionalType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SecretKeyType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Value" => SecretKeyType::Value,
            b"EnvironmentVariable" => SecretKeyType::EnvironmentVariable,
            b"File" => SecretKeyType::File,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SecretKeyType::Value => "Value",
            SecretKeyType::EnvironmentVariable => "EnvironmentVariable",
            SecretKeyType::File => "File",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SecretKeyType::Value),
            1 => Some(SecretKeyType::EnvironmentVariable),
            2 => Some(SecretKeyType::File),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SecretKeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SecretKeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SecretTextOptionalType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"None" => SecretTextOptionalType::None,
            b"Text" => SecretTextOptionalType::Text,
            b"EnvironmentVariable" => SecretTextOptionalType::EnvironmentVariable,
            b"File" => SecretTextOptionalType::File,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SecretTextOptionalType::None => "None",
            SecretTextOptionalType::Text => "Text",
            SecretTextOptionalType::EnvironmentVariable => "EnvironmentVariable",
            SecretTextOptionalType::File => "File",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SecretTextOptionalType::None),
            1 => Some(SecretTextOptionalType::Text),
            2 => Some(SecretTextOptionalType::EnvironmentVariable),
            3 => Some(SecretTextOptionalType::File),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for SecretTextOptionalType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SecretTextOptionalType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SecretTextType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Text" => SecretTextType::Text,
            b"EnvironmentVariable" => SecretTextType::EnvironmentVariable,
            b"File" => SecretTextType::File,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SecretTextType::Text => "Text",
            SecretTextType::EnvironmentVariable => "EnvironmentVariable",
            SecretTextType::File => "File",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SecretTextType::Text),
            1 => Some(SecretTextType::EnvironmentVariable),
            2 => Some(SecretTextType::File),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SecretTextType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SecretTextType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for ServiceProtocol {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"jmap" => ServiceProtocol::Jmap,
            b"imap" => ServiceProtocol::Imap,
            b"pop3" => ServiceProtocol::Pop3,
            b"smtp" => ServiceProtocol::Smtp,
            b"caldav" => ServiceProtocol::Caldav,
            b"carddav" => ServiceProtocol::Carddav,
            b"webdav" => ServiceProtocol::Webdav,
            b"managesieve" => ServiceProtocol::Managesieve,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            ServiceProtocol::Jmap => "jmap",
            ServiceProtocol::Imap => "imap",
            ServiceProtocol::Pop3 => "pop3",
            ServiceProtocol::Smtp => "smtp",
            ServiceProtocol::Caldav => "caldav",
            ServiceProtocol::Carddav => "carddav",
            ServiceProtocol::Webdav => "webdav",
            ServiceProtocol::Managesieve => "managesieve",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ServiceProtocol::Jmap),
            1 => Some(ServiceProtocol::Imap),
            2 => Some(ServiceProtocol::Pop3),
            3 => Some(ServiceProtocol::Smtp),
            4 => Some(ServiceProtocol::Caldav),
            5 => Some(ServiceProtocol::Carddav),
            6 => Some(ServiceProtocol::Webdav),
            7 => Some(ServiceProtocol::Managesieve),
            _ => None,
        }
    }

    const COUNT: usize = 8;
}

impl serde::Serialize for ServiceProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ServiceProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SieveCapability {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"envelope" => SieveCapability::Envelope,
            b"envelope-dsn" => SieveCapability::EnvelopeDsn,
            b"envelope-deliverby" => SieveCapability::EnvelopeDeliverby,
            b"fileinto" => SieveCapability::Fileinto,
            b"encoded-character" => SieveCapability::EncodedCharacter,
            b"comparator-elbonia" => SieveCapability::ComparatorElbonia,
            b"comparator-i;octet" => SieveCapability::ComparatorIOctet,
            b"comparator-i;ascii-casemap" => SieveCapability::ComparatorIAsciiCasemap,
            b"comparator-i;ascii-numeric" => SieveCapability::ComparatorIAsciiNumeric,
            b"body" => SieveCapability::Body,
            b"convert" => SieveCapability::Convert,
            b"copy" => SieveCapability::Copy,
            b"relational" => SieveCapability::Relational,
            b"date" => SieveCapability::Date,
            b"index" => SieveCapability::Index,
            b"duplicate" => SieveCapability::Duplicate,
            b"variables" => SieveCapability::Variables,
            b"editheader" => SieveCapability::Editheader,
            b"foreverypart" => SieveCapability::Foreverypart,
            b"mime" => SieveCapability::Mime,
            b"replace" => SieveCapability::Replace,
            b"enclose" => SieveCapability::Enclose,
            b"extracttext" => SieveCapability::Extracttext,
            b"enotify" => SieveCapability::Enotify,
            b"redirect-dsn" => SieveCapability::RedirectDsn,
            b"redirect-deliverby" => SieveCapability::RedirectDeliverby,
            b"environment" => SieveCapability::Environment,
            b"reject" => SieveCapability::Reject,
            b"ereject" => SieveCapability::Ereject,
            b"extlists" => SieveCapability::Extlists,
            b"subaddress" => SieveCapability::Subaddress,
            b"vacation" => SieveCapability::Vacation,
            b"vacation-seconds" => SieveCapability::VacationSeconds,
            b"fcc" => SieveCapability::Fcc,
            b"mailbox" => SieveCapability::Mailbox,
            b"mailboxid" => SieveCapability::Mailboxid,
            b"mboxmetadata" => SieveCapability::Mboxmetadata,
            b"servermetadata" => SieveCapability::Servermetadata,
            b"special-use" => SieveCapability::SpecialUse,
            b"imap4flags" => SieveCapability::Imap4flags,
            b"ihave" => SieveCapability::Ihave,
            b"imapsieve" => SieveCapability::Imapsieve,
            b"include" => SieveCapability::Include,
            b"regex" => SieveCapability::Regex,
            b"spamtest" => SieveCapability::Spamtest,
            b"spamtestplus" => SieveCapability::Spamtestplus,
            b"virustest" => SieveCapability::Virustest,
            b"vnd.stalwart.while" => SieveCapability::VndStalwartWhile,
            b"vnd.stalwart.expressions" => SieveCapability::VndStalwartExpressions,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SieveCapability::Envelope => "envelope",
            SieveCapability::EnvelopeDsn => "envelope-dsn",
            SieveCapability::EnvelopeDeliverby => "envelope-deliverby",
            SieveCapability::Fileinto => "fileinto",
            SieveCapability::EncodedCharacter => "encoded-character",
            SieveCapability::ComparatorElbonia => "comparator-elbonia",
            SieveCapability::ComparatorIOctet => "comparator-i;octet",
            SieveCapability::ComparatorIAsciiCasemap => "comparator-i;ascii-casemap",
            SieveCapability::ComparatorIAsciiNumeric => "comparator-i;ascii-numeric",
            SieveCapability::Body => "body",
            SieveCapability::Convert => "convert",
            SieveCapability::Copy => "copy",
            SieveCapability::Relational => "relational",
            SieveCapability::Date => "date",
            SieveCapability::Index => "index",
            SieveCapability::Duplicate => "duplicate",
            SieveCapability::Variables => "variables",
            SieveCapability::Editheader => "editheader",
            SieveCapability::Foreverypart => "foreverypart",
            SieveCapability::Mime => "mime",
            SieveCapability::Replace => "replace",
            SieveCapability::Enclose => "enclose",
            SieveCapability::Extracttext => "extracttext",
            SieveCapability::Enotify => "enotify",
            SieveCapability::RedirectDsn => "redirect-dsn",
            SieveCapability::RedirectDeliverby => "redirect-deliverby",
            SieveCapability::Environment => "environment",
            SieveCapability::Reject => "reject",
            SieveCapability::Ereject => "ereject",
            SieveCapability::Extlists => "extlists",
            SieveCapability::Subaddress => "subaddress",
            SieveCapability::Vacation => "vacation",
            SieveCapability::VacationSeconds => "vacation-seconds",
            SieveCapability::Fcc => "fcc",
            SieveCapability::Mailbox => "mailbox",
            SieveCapability::Mailboxid => "mailboxid",
            SieveCapability::Mboxmetadata => "mboxmetadata",
            SieveCapability::Servermetadata => "servermetadata",
            SieveCapability::SpecialUse => "special-use",
            SieveCapability::Imap4flags => "imap4flags",
            SieveCapability::Ihave => "ihave",
            SieveCapability::Imapsieve => "imapsieve",
            SieveCapability::Include => "include",
            SieveCapability::Regex => "regex",
            SieveCapability::Spamtest => "spamtest",
            SieveCapability::Spamtestplus => "spamtestplus",
            SieveCapability::Virustest => "virustest",
            SieveCapability::VndStalwartWhile => "vnd.stalwart.while",
            SieveCapability::VndStalwartExpressions => "vnd.stalwart.expressions",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SieveCapability::Envelope),
            1 => Some(SieveCapability::EnvelopeDsn),
            2 => Some(SieveCapability::EnvelopeDeliverby),
            3 => Some(SieveCapability::Fileinto),
            4 => Some(SieveCapability::EncodedCharacter),
            5 => Some(SieveCapability::ComparatorElbonia),
            6 => Some(SieveCapability::ComparatorIOctet),
            7 => Some(SieveCapability::ComparatorIAsciiCasemap),
            8 => Some(SieveCapability::ComparatorIAsciiNumeric),
            9 => Some(SieveCapability::Body),
            10 => Some(SieveCapability::Convert),
            11 => Some(SieveCapability::Copy),
            12 => Some(SieveCapability::Relational),
            13 => Some(SieveCapability::Date),
            14 => Some(SieveCapability::Index),
            15 => Some(SieveCapability::Duplicate),
            16 => Some(SieveCapability::Variables),
            17 => Some(SieveCapability::Editheader),
            18 => Some(SieveCapability::Foreverypart),
            19 => Some(SieveCapability::Mime),
            20 => Some(SieveCapability::Replace),
            21 => Some(SieveCapability::Enclose),
            22 => Some(SieveCapability::Extracttext),
            23 => Some(SieveCapability::Enotify),
            24 => Some(SieveCapability::RedirectDsn),
            25 => Some(SieveCapability::RedirectDeliverby),
            26 => Some(SieveCapability::Environment),
            27 => Some(SieveCapability::Reject),
            28 => Some(SieveCapability::Ereject),
            29 => Some(SieveCapability::Extlists),
            30 => Some(SieveCapability::Subaddress),
            31 => Some(SieveCapability::Vacation),
            32 => Some(SieveCapability::VacationSeconds),
            33 => Some(SieveCapability::Fcc),
            34 => Some(SieveCapability::Mailbox),
            35 => Some(SieveCapability::Mailboxid),
            36 => Some(SieveCapability::Mboxmetadata),
            37 => Some(SieveCapability::Servermetadata),
            38 => Some(SieveCapability::SpecialUse),
            39 => Some(SieveCapability::Imap4flags),
            40 => Some(SieveCapability::Ihave),
            41 => Some(SieveCapability::Imapsieve),
            42 => Some(SieveCapability::Include),
            43 => Some(SieveCapability::Regex),
            44 => Some(SieveCapability::Spamtest),
            45 => Some(SieveCapability::Spamtestplus),
            46 => Some(SieveCapability::Virustest),
            47 => Some(SieveCapability::VndStalwartWhile),
            48 => Some(SieveCapability::VndStalwartExpressions),
            _ => None,
        }
    }

    const COUNT: usize = 49;
}

impl serde::Serialize for SieveCapability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SieveCapability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for Sig0Algorithm {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"ecdsa-p256-sha256" => Sig0Algorithm::EcdsaP256Sha256,
            b"ecdsa-p384-sha384" => Sig0Algorithm::EcdsaP384Sha384,
            b"ed25519" => Sig0Algorithm::Ed25519,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Sig0Algorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Sig0Algorithm::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            Sig0Algorithm::Ed25519 => "ed25519",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(Sig0Algorithm::EcdsaP256Sha256),
            1 => Some(Sig0Algorithm::EcdsaP384Sha384),
            2 => Some(Sig0Algorithm::Ed25519),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for Sig0Algorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Sig0Algorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamClassifierModelType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"FtrlFh" => SpamClassifierModelType::FtrlFh,
            b"FtrlCcfh" => SpamClassifierModelType::FtrlCcfh,
            b"Disabled" => SpamClassifierModelType::Disabled,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamClassifierModelType::FtrlFh => "FtrlFh",
            SpamClassifierModelType::FtrlCcfh => "FtrlCcfh",
            SpamClassifierModelType::Disabled => "Disabled",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamClassifierModelType::FtrlFh),
            1 => Some(SpamClassifierModelType::FtrlCcfh),
            2 => Some(SpamClassifierModelType::Disabled),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SpamClassifierModelType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamClassifierModelType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamClassifyParameters {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"bit7" => SpamClassifyParameters::Bit7,
            b"bit8Mime - 8-bit MIME message content" => SpamClassifyParameters::Bit8Mime8BitMIMEMessageContent,
            b"binaryMime" => SpamClassifyParameters::BinaryMime,
            b"smtpUtf8" => SpamClassifyParameters::SmtpUtf8,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamClassifyParameters::Bit7 => "bit7",
            SpamClassifyParameters::Bit8Mime8BitMIMEMessageContent => {
                "bit8Mime - 8-bit MIME message content"
            }
            SpamClassifyParameters::BinaryMime => "binaryMime",
            SpamClassifyParameters::SmtpUtf8 => "smtpUtf8",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamClassifyParameters::Bit7),
            1 => Some(SpamClassifyParameters::Bit8Mime8BitMIMEMessageContent),
            2 => Some(SpamClassifyParameters::BinaryMime),
            3 => Some(SpamClassifyParameters::SmtpUtf8),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for SpamClassifyParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamClassifyParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamClassifyResult {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"spam" => SpamClassifyResult::Spam,
            b"ham" => SpamClassifyResult::Ham,
            b"reject" => SpamClassifyResult::Reject,
            b"discard" => SpamClassifyResult::Discard,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamClassifyResult::Spam => "spam",
            SpamClassifyResult::Ham => "ham",
            SpamClassifyResult::Reject => "reject",
            SpamClassifyResult::Discard => "discard",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamClassifyResult::Spam),
            1 => Some(SpamClassifyResult::Ham),
            2 => Some(SpamClassifyResult::Reject),
            3 => Some(SpamClassifyResult::Discard),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for SpamClassifyResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamClassifyResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamClassifyTagDisposition {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"score" => SpamClassifyTagDisposition::Score,
            b"reject" => SpamClassifyTagDisposition::Reject,
            b"discard" => SpamClassifyTagDisposition::Discard,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamClassifyTagDisposition::Score => "score",
            SpamClassifyTagDisposition::Reject => "reject",
            SpamClassifyTagDisposition::Discard => "discard",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamClassifyTagDisposition::Score),
            1 => Some(SpamClassifyTagDisposition::Reject),
            2 => Some(SpamClassifyTagDisposition::Discard),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SpamClassifyTagDisposition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamClassifyTagDisposition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamDnsblServerType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Any" => SpamDnsblServerType::Any,
            b"Url" => SpamDnsblServerType::Url,
            b"Domain" => SpamDnsblServerType::Domain,
            b"Email" => SpamDnsblServerType::Email,
            b"Ip" => SpamDnsblServerType::Ip,
            b"Header" => SpamDnsblServerType::Header,
            b"Body" => SpamDnsblServerType::Body,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamDnsblServerType::Any => "Any",
            SpamDnsblServerType::Url => "Url",
            SpamDnsblServerType::Domain => "Domain",
            SpamDnsblServerType::Email => "Email",
            SpamDnsblServerType::Ip => "Ip",
            SpamDnsblServerType::Header => "Header",
            SpamDnsblServerType::Body => "Body",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamDnsblServerType::Any),
            1 => Some(SpamDnsblServerType::Url),
            2 => Some(SpamDnsblServerType::Domain),
            3 => Some(SpamDnsblServerType::Email),
            4 => Some(SpamDnsblServerType::Ip),
            5 => Some(SpamDnsblServerType::Header),
            6 => Some(SpamDnsblServerType::Body),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for SpamDnsblServerType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamDnsblServerType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamLlmType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disable" => SpamLlmType::Disable,
            b"Enable" => SpamLlmType::Enable,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamLlmType::Disable => "Disable",
            SpamLlmType::Enable => "Enable",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamLlmType::Disable),
            1 => Some(SpamLlmType::Enable),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for SpamLlmType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamLlmType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamRuleType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Any" => SpamRuleType::Any,
            b"Url" => SpamRuleType::Url,
            b"Domain" => SpamRuleType::Domain,
            b"Email" => SpamRuleType::Email,
            b"Ip" => SpamRuleType::Ip,
            b"Header" => SpamRuleType::Header,
            b"Body" => SpamRuleType::Body,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamRuleType::Any => "Any",
            SpamRuleType::Url => "Url",
            SpamRuleType::Domain => "Domain",
            SpamRuleType::Email => "Email",
            SpamRuleType::Ip => "Ip",
            SpamRuleType::Header => "Header",
            SpamRuleType::Body => "Body",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamRuleType::Any),
            1 => Some(SpamRuleType::Url),
            2 => Some(SpamRuleType::Domain),
            3 => Some(SpamRuleType::Email),
            4 => Some(SpamRuleType::Ip),
            5 => Some(SpamRuleType::Header),
            6 => Some(SpamRuleType::Body),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for SpamRuleType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamRuleType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpamTagType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Score" => SpamTagType::Score,
            b"Discard" => SpamTagType::Discard,
            b"Reject" => SpamTagType::Reject,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpamTagType::Score => "Score",
            SpamTagType::Discard => "Discard",
            SpamTagType::Reject => "Reject",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpamTagType::Score),
            1 => Some(SpamTagType::Discard),
            2 => Some(SpamTagType::Reject),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SpamTagType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpamTagType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpecialUse {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"inbox" => SpecialUse::Inbox,
            b"trash" => SpecialUse::Trash,
            b"junk" => SpecialUse::Junk,
            b"drafts" => SpecialUse::Drafts,
            b"archive" => SpecialUse::Archive,
            b"sent" => SpecialUse::Sent,
            b"shared" => SpecialUse::Shared,
            b"important" => SpecialUse::Important,
            b"memos" => SpecialUse::Memos,
            b"scheduled" => SpecialUse::Scheduled,
            b"snoozed" => SpecialUse::Snoozed,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpecialUse::Inbox => "inbox",
            SpecialUse::Trash => "trash",
            SpecialUse::Junk => "junk",
            SpecialUse::Drafts => "drafts",
            SpecialUse::Archive => "archive",
            SpecialUse::Sent => "sent",
            SpecialUse::Shared => "shared",
            SpecialUse::Important => "important",
            SpecialUse::Memos => "memos",
            SpecialUse::Scheduled => "scheduled",
            SpecialUse::Snoozed => "snoozed",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpecialUse::Inbox),
            1 => Some(SpecialUse::Trash),
            2 => Some(SpecialUse::Junk),
            3 => Some(SpecialUse::Drafts),
            4 => Some(SpecialUse::Archive),
            5 => Some(SpecialUse::Sent),
            6 => Some(SpecialUse::Shared),
            7 => Some(SpecialUse::Important),
            8 => Some(SpecialUse::Memos),
            9 => Some(SpecialUse::Scheduled),
            10 => Some(SpecialUse::Snoozed),
            _ => None,
        }
    }

    const COUNT: usize = 11;
}

impl serde::Serialize for SpecialUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpecialUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpfAuthResult {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"none" => SpfAuthResult::None,
            b"neutral" => SpfAuthResult::Neutral,
            b"pass" => SpfAuthResult::Pass,
            b"fail" => SpfAuthResult::Fail,
            b"softFail" => SpfAuthResult::SoftFail,
            b"tempError" => SpfAuthResult::TempError,
            b"permError" => SpfAuthResult::PermError,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpfAuthResult::None => "none",
            SpfAuthResult::Neutral => "neutral",
            SpfAuthResult::Pass => "pass",
            SpfAuthResult::Fail => "fail",
            SpfAuthResult::SoftFail => "softFail",
            SpfAuthResult::TempError => "tempError",
            SpfAuthResult::PermError => "permError",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpfAuthResult::None),
            1 => Some(SpfAuthResult::Neutral),
            2 => Some(SpfAuthResult::Pass),
            3 => Some(SpfAuthResult::Fail),
            4 => Some(SpfAuthResult::SoftFail),
            5 => Some(SpfAuthResult::TempError),
            6 => Some(SpfAuthResult::PermError),
            _ => None,
        }
    }

    const COUNT: usize = 7;
}

impl serde::Serialize for SpfAuthResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpfAuthResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SpfDomainScope {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"helo" => SpfDomainScope::Helo,
            b"mailFrom" => SpfDomainScope::MailFrom,
            b"unspecified" => SpfDomainScope::Unspecified,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SpfDomainScope::Helo => "helo",
            SpfDomainScope::MailFrom => "mailFrom",
            SpfDomainScope::Unspecified => "unspecified",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SpfDomainScope::Helo),
            1 => Some(SpfDomainScope::MailFrom),
            2 => Some(SpfDomainScope::Unspecified),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SpfDomainScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SpfDomainScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SqlAuthStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Default" => SqlAuthStoreType::Default,
            b"PostgreSql" => SqlAuthStoreType::PostgreSql,
            b"MySql" => SqlAuthStoreType::MySql,
            b"Sqlite" => SqlAuthStoreType::Sqlite,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SqlAuthStoreType::Default => "Default",
            SqlAuthStoreType::PostgreSql => "PostgreSql",
            SqlAuthStoreType::MySql => "MySql",
            SqlAuthStoreType::Sqlite => "Sqlite",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SqlAuthStoreType::Default),
            1 => Some(SqlAuthStoreType::PostgreSql),
            2 => Some(SqlAuthStoreType::MySql),
            3 => Some(SqlAuthStoreType::Sqlite),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for SqlAuthStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SqlAuthStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for StorageQuota {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"maxEmails" => StorageQuota::MaxEmails,
            b"maxMailboxes" => StorageQuota::MaxMailboxes,
            b"maxEmailSubmissions" => StorageQuota::MaxEmailSubmissions,
            b"maxEmailIdentities" => StorageQuota::MaxEmailIdentities,
            b"maxParticipantIdentities" => StorageQuota::MaxParticipantIdentities,
            b"maxSieveScripts" => StorageQuota::MaxSieveScripts,
            b"maxPushSubscriptions" => StorageQuota::MaxPushSubscriptions,
            b"maxCalendars" => StorageQuota::MaxCalendars,
            b"maxCalendarEvents" => StorageQuota::MaxCalendarEvents,
            b"maxCalendarEventNotifications" => StorageQuota::MaxCalendarEventNotifications,
            b"maxAddressBooks" => StorageQuota::MaxAddressBooks,
            b"maxContactCards" => StorageQuota::MaxContactCards,
            b"maxFiles" => StorageQuota::MaxFiles,
            b"maxFolders" => StorageQuota::MaxFolders,
            b"maxMaskedAddresses" => StorageQuota::MaxMaskedAddresses,
            b"maxAppPasswords" => StorageQuota::MaxAppPasswords,
            b"maxApiKeys" => StorageQuota::MaxApiKeys,
            b"maxPublicKeys" => StorageQuota::MaxPublicKeys,
            b"maxDiskQuota" => StorageQuota::MaxDiskQuota,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            StorageQuota::MaxEmails => "maxEmails",
            StorageQuota::MaxMailboxes => "maxMailboxes",
            StorageQuota::MaxEmailSubmissions => "maxEmailSubmissions",
            StorageQuota::MaxEmailIdentities => "maxEmailIdentities",
            StorageQuota::MaxParticipantIdentities => "maxParticipantIdentities",
            StorageQuota::MaxSieveScripts => "maxSieveScripts",
            StorageQuota::MaxPushSubscriptions => "maxPushSubscriptions",
            StorageQuota::MaxCalendars => "maxCalendars",
            StorageQuota::MaxCalendarEvents => "maxCalendarEvents",
            StorageQuota::MaxCalendarEventNotifications => "maxCalendarEventNotifications",
            StorageQuota::MaxAddressBooks => "maxAddressBooks",
            StorageQuota::MaxContactCards => "maxContactCards",
            StorageQuota::MaxFiles => "maxFiles",
            StorageQuota::MaxFolders => "maxFolders",
            StorageQuota::MaxMaskedAddresses => "maxMaskedAddresses",
            StorageQuota::MaxAppPasswords => "maxAppPasswords",
            StorageQuota::MaxApiKeys => "maxApiKeys",
            StorageQuota::MaxPublicKeys => "maxPublicKeys",
            StorageQuota::MaxDiskQuota => "maxDiskQuota",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(StorageQuota::MaxEmails),
            1 => Some(StorageQuota::MaxMailboxes),
            2 => Some(StorageQuota::MaxEmailSubmissions),
            3 => Some(StorageQuota::MaxEmailIdentities),
            4 => Some(StorageQuota::MaxParticipantIdentities),
            5 => Some(StorageQuota::MaxSieveScripts),
            6 => Some(StorageQuota::MaxPushSubscriptions),
            7 => Some(StorageQuota::MaxCalendars),
            8 => Some(StorageQuota::MaxCalendarEvents),
            9 => Some(StorageQuota::MaxCalendarEventNotifications),
            10 => Some(StorageQuota::MaxAddressBooks),
            11 => Some(StorageQuota::MaxContactCards),
            12 => Some(StorageQuota::MaxFiles),
            13 => Some(StorageQuota::MaxFolders),
            14 => Some(StorageQuota::MaxMaskedAddresses),
            15 => Some(StorageQuota::MaxAppPasswords),
            16 => Some(StorageQuota::MaxApiKeys),
            17 => Some(StorageQuota::MaxPublicKeys),
            18 => Some(StorageQuota::MaxDiskQuota),
            _ => None,
        }
    }

    const COUNT: usize = 19;
}

impl serde::Serialize for StorageQuota {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for StorageQuota {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for SubAddressingType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Enabled" => SubAddressingType::Enabled,
            b"Custom" => SubAddressingType::Custom,
            b"Disabled" => SubAddressingType::Disabled,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            SubAddressingType::Enabled => "Enabled",
            SubAddressingType::Custom => "Custom",
            SubAddressingType::Disabled => "Disabled",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(SubAddressingType::Enabled),
            1 => Some(SubAddressingType::Custom),
            2 => Some(SubAddressingType::Disabled),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for SubAddressingType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SubAddressingType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TaskAccountMaintenanceType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"purge" => TaskAccountMaintenanceType::Purge,
            b"reindex" => TaskAccountMaintenanceType::Reindex,
            b"recalculateImapUid" => TaskAccountMaintenanceType::RecalculateImapUid,
            b"recalculateQuota" => TaskAccountMaintenanceType::RecalculateQuota,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskAccountMaintenanceType::Purge => "purge",
            TaskAccountMaintenanceType::Reindex => "reindex",
            TaskAccountMaintenanceType::RecalculateImapUid => "recalculateImapUid",
            TaskAccountMaintenanceType::RecalculateQuota => "recalculateQuota",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TaskAccountMaintenanceType::Purge),
            1 => Some(TaskAccountMaintenanceType::Reindex),
            2 => Some(TaskAccountMaintenanceType::RecalculateImapUid),
            3 => Some(TaskAccountMaintenanceType::RecalculateQuota),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for TaskAccountMaintenanceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskAccountMaintenanceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TaskRetryStrategyType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"ExponentialBackoff" => TaskRetryStrategyType::ExponentialBackoff,
            b"FixedDelay" => TaskRetryStrategyType::FixedDelay,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskRetryStrategyType::ExponentialBackoff => "ExponentialBackoff",
            TaskRetryStrategyType::FixedDelay => "FixedDelay",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TaskRetryStrategyType::ExponentialBackoff),
            1 => Some(TaskRetryStrategyType::FixedDelay),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for TaskRetryStrategyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskRetryStrategyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TaskSpamFilterMaintenanceType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"train" => TaskSpamFilterMaintenanceType::Train,
            b"retrain" => TaskSpamFilterMaintenanceType::Retrain,
            b"abort" => TaskSpamFilterMaintenanceType::Abort,
            b"reset" => TaskSpamFilterMaintenanceType::Reset,
            b"updateRules" => TaskSpamFilterMaintenanceType::UpdateRules,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskSpamFilterMaintenanceType::Train => "train",
            TaskSpamFilterMaintenanceType::Retrain => "retrain",
            TaskSpamFilterMaintenanceType::Abort => "abort",
            TaskSpamFilterMaintenanceType::Reset => "reset",
            TaskSpamFilterMaintenanceType::UpdateRules => "updateRules",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TaskSpamFilterMaintenanceType::Train),
            1 => Some(TaskSpamFilterMaintenanceType::Retrain),
            2 => Some(TaskSpamFilterMaintenanceType::Abort),
            3 => Some(TaskSpamFilterMaintenanceType::Reset),
            4 => Some(TaskSpamFilterMaintenanceType::UpdateRules),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for TaskSpamFilterMaintenanceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskSpamFilterMaintenanceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TaskStatusType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Pending" => TaskStatusType::Pending,
            b"Retry" => TaskStatusType::Retry,
            b"Failed" => TaskStatusType::Failed,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskStatusType::Pending => "Pending",
            TaskStatusType::Retry => "Retry",
            TaskStatusType::Failed => "Failed",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TaskStatusType::Pending),
            1 => Some(TaskStatusType::Retry),
            2 => Some(TaskStatusType::Failed),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for TaskStatusType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskStatusType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TaskStoreMaintenanceType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"reindexAccounts" => TaskStoreMaintenanceType::ReindexAccounts,
            b"reindexTelemetry" => TaskStoreMaintenanceType::ReindexTelemetry,
            b"purgeAccounts" => TaskStoreMaintenanceType::PurgeAccounts,
            b"purgeData" => TaskStoreMaintenanceType::PurgeData,
            b"purgeBlob" => TaskStoreMaintenanceType::PurgeBlob,
            b"resetRateLimiters" => TaskStoreMaintenanceType::ResetRateLimiters,
            b"resetUserQuotas" => TaskStoreMaintenanceType::ResetUserQuotas,
            b"resetTenantQuotas" => TaskStoreMaintenanceType::ResetTenantQuotas,
            b"resetBlobQuotas" => TaskStoreMaintenanceType::ResetBlobQuotas,
            b"removeAuthTokens" => TaskStoreMaintenanceType::RemoveAuthTokens,
            b"removeLockQueueMessage" => TaskStoreMaintenanceType::RemoveLockQueueMessage,
            b"removeLockTask" => TaskStoreMaintenanceType::RemoveLockTask,
            b"removeLockDav" => TaskStoreMaintenanceType::RemoveLockDav,
            b"removeSieveId" => TaskStoreMaintenanceType::RemoveSieveId,
            b"removeGreylist" => TaskStoreMaintenanceType::RemoveGreylist,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskStoreMaintenanceType::ReindexAccounts => "reindexAccounts",
            TaskStoreMaintenanceType::ReindexTelemetry => "reindexTelemetry",
            TaskStoreMaintenanceType::PurgeAccounts => "purgeAccounts",
            TaskStoreMaintenanceType::PurgeData => "purgeData",
            TaskStoreMaintenanceType::PurgeBlob => "purgeBlob",
            TaskStoreMaintenanceType::ResetRateLimiters => "resetRateLimiters",
            TaskStoreMaintenanceType::ResetUserQuotas => "resetUserQuotas",
            TaskStoreMaintenanceType::ResetTenantQuotas => "resetTenantQuotas",
            TaskStoreMaintenanceType::ResetBlobQuotas => "resetBlobQuotas",
            TaskStoreMaintenanceType::RemoveAuthTokens => "removeAuthTokens",
            TaskStoreMaintenanceType::RemoveLockQueueMessage => "removeLockQueueMessage",
            TaskStoreMaintenanceType::RemoveLockTask => "removeLockTask",
            TaskStoreMaintenanceType::RemoveLockDav => "removeLockDav",
            TaskStoreMaintenanceType::RemoveSieveId => "removeSieveId",
            TaskStoreMaintenanceType::RemoveGreylist => "removeGreylist",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TaskStoreMaintenanceType::ReindexAccounts),
            1 => Some(TaskStoreMaintenanceType::ReindexTelemetry),
            2 => Some(TaskStoreMaintenanceType::PurgeAccounts),
            3 => Some(TaskStoreMaintenanceType::PurgeData),
            4 => Some(TaskStoreMaintenanceType::PurgeBlob),
            5 => Some(TaskStoreMaintenanceType::ResetRateLimiters),
            6 => Some(TaskStoreMaintenanceType::ResetUserQuotas),
            7 => Some(TaskStoreMaintenanceType::ResetTenantQuotas),
            8 => Some(TaskStoreMaintenanceType::ResetBlobQuotas),
            9 => Some(TaskStoreMaintenanceType::RemoveAuthTokens),
            10 => Some(TaskStoreMaintenanceType::RemoveLockQueueMessage),
            11 => Some(TaskStoreMaintenanceType::RemoveLockTask),
            12 => Some(TaskStoreMaintenanceType::RemoveLockDav),
            13 => Some(TaskStoreMaintenanceType::RemoveSieveId),
            14 => Some(TaskStoreMaintenanceType::RemoveGreylist),
            _ => None,
        }
    }

    const COUNT: usize = 15;
}

impl serde::Serialize for TaskStoreMaintenanceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskStoreMaintenanceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TaskTenantMaintenanceType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"recalculateQuota" => TaskTenantMaintenanceType::RecalculateQuota,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskTenantMaintenanceType::RecalculateQuota => "recalculateQuota",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TaskTenantMaintenanceType::RecalculateQuota),
            _ => None,
        }
    }

    const COUNT: usize = 1;
}

impl serde::Serialize for TaskTenantMaintenanceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskTenantMaintenanceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TaskType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"IndexDocument" => TaskType::IndexDocument,
            b"UnindexDocument" => TaskType::UnindexDocument,
            b"IndexTrace" => TaskType::IndexTrace,
            b"CalendarAlarmEmail" => TaskType::CalendarAlarmEmail,
            b"CalendarAlarmNotification" => TaskType::CalendarAlarmNotification,
            b"CalendarItipMessage" => TaskType::CalendarItipMessage,
            b"MergeThreads" => TaskType::MergeThreads,
            b"DmarcReport" => TaskType::DmarcReport,
            b"TlsReport" => TaskType::TlsReport,
            b"RestoreArchivedItem" => TaskType::RestoreArchivedItem,
            b"DestroyAccount" => TaskType::DestroyAccount,
            b"AccountMaintenance" => TaskType::AccountMaintenance,
            b"TenantMaintenance" => TaskType::TenantMaintenance,
            b"StoreMaintenance" => TaskType::StoreMaintenance,
            b"SpamFilterMaintenance" => TaskType::SpamFilterMaintenance,
            b"AcmeRenewal" => TaskType::AcmeRenewal,
            b"DkimManagement" => TaskType::DkimManagement,
            b"DnsManagement" => TaskType::DnsManagement,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TaskType::IndexDocument => "IndexDocument",
            TaskType::UnindexDocument => "UnindexDocument",
            TaskType::IndexTrace => "IndexTrace",
            TaskType::CalendarAlarmEmail => "CalendarAlarmEmail",
            TaskType::CalendarAlarmNotification => "CalendarAlarmNotification",
            TaskType::CalendarItipMessage => "CalendarItipMessage",
            TaskType::MergeThreads => "MergeThreads",
            TaskType::DmarcReport => "DmarcReport",
            TaskType::TlsReport => "TlsReport",
            TaskType::RestoreArchivedItem => "RestoreArchivedItem",
            TaskType::DestroyAccount => "DestroyAccount",
            TaskType::AccountMaintenance => "AccountMaintenance",
            TaskType::TenantMaintenance => "TenantMaintenance",
            TaskType::StoreMaintenance => "StoreMaintenance",
            TaskType::SpamFilterMaintenance => "SpamFilterMaintenance",
            TaskType::AcmeRenewal => "AcmeRenewal",
            TaskType::DkimManagement => "DkimManagement",
            TaskType::DnsManagement => "DnsManagement",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TaskType::IndexDocument),
            1 => Some(TaskType::UnindexDocument),
            2 => Some(TaskType::IndexTrace),
            3 => Some(TaskType::CalendarAlarmEmail),
            4 => Some(TaskType::CalendarAlarmNotification),
            5 => Some(TaskType::CalendarItipMessage),
            6 => Some(TaskType::MergeThreads),
            7 => Some(TaskType::DmarcReport),
            8 => Some(TaskType::TlsReport),
            9 => Some(TaskType::RestoreArchivedItem),
            10 => Some(TaskType::DestroyAccount),
            11 => Some(TaskType::AccountMaintenance),
            12 => Some(TaskType::TenantMaintenance),
            13 => Some(TaskType::StoreMaintenance),
            14 => Some(TaskType::SpamFilterMaintenance),
            15 => Some(TaskType::AcmeRenewal),
            16 => Some(TaskType::DkimManagement),
            17 => Some(TaskType::DnsManagement),
            _ => None,
        }
    }

    const COUNT: usize = 18;
}

impl serde::Serialize for TaskType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TaskType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TenantStorageQuota {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"maxAccounts" => TenantStorageQuota::MaxAccounts,
            b"maxGroups" => TenantStorageQuota::MaxGroups,
            b"maxDomains" => TenantStorageQuota::MaxDomains,
            b"maxMailingLists" => TenantStorageQuota::MaxMailingLists,
            b"maxRoles" => TenantStorageQuota::MaxRoles,
            b"maxOauthClients" => TenantStorageQuota::MaxOauthClients,
            b"maxDkimKeys" => TenantStorageQuota::MaxDkimKeys,
            b"maxDnsServers" => TenantStorageQuota::MaxDnsServers,
            b"maxDirectories" => TenantStorageQuota::MaxDirectories,
            b"maxAcmeProviders" => TenantStorageQuota::MaxAcmeProviders,
            b"maxDiskQuota" => TenantStorageQuota::MaxDiskQuota,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TenantStorageQuota::MaxAccounts => "maxAccounts",
            TenantStorageQuota::MaxGroups => "maxGroups",
            TenantStorageQuota::MaxDomains => "maxDomains",
            TenantStorageQuota::MaxMailingLists => "maxMailingLists",
            TenantStorageQuota::MaxRoles => "maxRoles",
            TenantStorageQuota::MaxOauthClients => "maxOauthClients",
            TenantStorageQuota::MaxDkimKeys => "maxDkimKeys",
            TenantStorageQuota::MaxDnsServers => "maxDnsServers",
            TenantStorageQuota::MaxDirectories => "maxDirectories",
            TenantStorageQuota::MaxAcmeProviders => "maxAcmeProviders",
            TenantStorageQuota::MaxDiskQuota => "maxDiskQuota",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TenantStorageQuota::MaxAccounts),
            1 => Some(TenantStorageQuota::MaxGroups),
            2 => Some(TenantStorageQuota::MaxDomains),
            3 => Some(TenantStorageQuota::MaxMailingLists),
            4 => Some(TenantStorageQuota::MaxRoles),
            5 => Some(TenantStorageQuota::MaxOauthClients),
            6 => Some(TenantStorageQuota::MaxDkimKeys),
            7 => Some(TenantStorageQuota::MaxDnsServers),
            8 => Some(TenantStorageQuota::MaxDirectories),
            9 => Some(TenantStorageQuota::MaxAcmeProviders),
            10 => Some(TenantStorageQuota::MaxDiskQuota),
            _ => None,
        }
    }

    const COUNT: usize = 11;
}

impl serde::Serialize for TenantStorageQuota {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TenantStorageQuota {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TimeZone {
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            TimeZone,
            b"Africa/Abidjan" => TimeZone::AfricaAbidjan,
            b"Africa/Accra" => TimeZone::AfricaAccra,
            b"Africa/Addis_Ababa" => TimeZone::AfricaAddisAbaba,
            b"Africa/Algiers" => TimeZone::AfricaAlgiers,
            b"Africa/Asmara" => TimeZone::AfricaAsmara,
            b"Africa/Asmera" => TimeZone::AfricaAsmera,
            b"Africa/Bamako" => TimeZone::AfricaBamako,
            b"Africa/Bangui" => TimeZone::AfricaBangui,
            b"Africa/Banjul" => TimeZone::AfricaBanjul,
            b"Africa/Bissau" => TimeZone::AfricaBissau,
            b"Africa/Blantyre" => TimeZone::AfricaBlantyre,
            b"Africa/Brazzaville" => TimeZone::AfricaBrazzaville,
            b"Africa/Bujumbura" => TimeZone::AfricaBujumbura,
            b"Africa/Cairo" => TimeZone::AfricaCairo,
            b"Africa/Casablanca" => TimeZone::AfricaCasablanca,
            b"Africa/Ceuta" => TimeZone::AfricaCeuta,
            b"Africa/Conakry" => TimeZone::AfricaConakry,
            b"Africa/Dakar" => TimeZone::AfricaDakar,
            b"Africa/Dar_es_Salaam" => TimeZone::AfricaDarEsSalaam,
            b"Africa/Djibouti" => TimeZone::AfricaDjibouti,
            b"Africa/Douala" => TimeZone::AfricaDouala,
            b"Africa/El_Aaiun" => TimeZone::AfricaElAaiun,
            b"Africa/Freetown" => TimeZone::AfricaFreetown,
            b"Africa/Gaborone" => TimeZone::AfricaGaborone,
            b"Africa/Harare" => TimeZone::AfricaHarare,
            b"Africa/Johannesburg" => TimeZone::AfricaJohannesburg,
            b"Africa/Juba" => TimeZone::AfricaJuba,
            b"Africa/Kampala" => TimeZone::AfricaKampala,
            b"Africa/Khartoum" => TimeZone::AfricaKhartoum,
            b"Africa/Kigali" => TimeZone::AfricaKigali,
            b"Africa/Kinshasa" => TimeZone::AfricaKinshasa,
            b"Africa/Lagos" => TimeZone::AfricaLagos,
            b"Africa/Libreville" => TimeZone::AfricaLibreville,
            b"Africa/Lome" => TimeZone::AfricaLome,
            b"Africa/Luanda" => TimeZone::AfricaLuanda,
            b"Africa/Lubumbashi" => TimeZone::AfricaLubumbashi,
            b"Africa/Lusaka" => TimeZone::AfricaLusaka,
            b"Africa/Malabo" => TimeZone::AfricaMalabo,
            b"Africa/Maputo" => TimeZone::AfricaMaputo,
            b"Africa/Maseru" => TimeZone::AfricaMaseru,
            b"Africa/Mbabane" => TimeZone::AfricaMbabane,
            b"Africa/Mogadishu" => TimeZone::AfricaMogadishu,
            b"Africa/Monrovia" => TimeZone::AfricaMonrovia,
            b"Africa/Nairobi" => TimeZone::AfricaNairobi,
            b"Africa/Ndjamena" => TimeZone::AfricaNdjamena,
            b"Africa/Niamey" => TimeZone::AfricaNiamey,
            b"Africa/Nouakchott" => TimeZone::AfricaNouakchott,
            b"Africa/Ouagadougou" => TimeZone::AfricaOuagadougou,
            b"Africa/Porto-Novo" => TimeZone::AfricaPortoNovo,
            b"Africa/Sao_Tome" => TimeZone::AfricaSaoTome,
            b"Africa/Timbuktu" => TimeZone::AfricaTimbuktu,
            b"Africa/Tripoli" => TimeZone::AfricaTripoli,
            b"Africa/Tunis" => TimeZone::AfricaTunis,
            b"Africa/Windhoek" => TimeZone::AfricaWindhoek,
            b"America/Adak" => TimeZone::AmericaAdak,
            b"America/Anchorage" => TimeZone::AmericaAnchorage,
            b"America/Anguilla" => TimeZone::AmericaAnguilla,
            b"America/Antigua" => TimeZone::AmericaAntigua,
            b"America/Araguaina" => TimeZone::AmericaAraguaina,
            b"America/Argentina/Buenos_Aires" => TimeZone::AmericaArgentinaBuenosAires,
            b"America/Argentina/Catamarca" => TimeZone::AmericaArgentinaCatamarca,
            b"America/Argentina/ComodRivadavia" => TimeZone::AmericaArgentinaComodRivadavia,
            b"America/Argentina/Cordoba" => TimeZone::AmericaArgentinaCordoba,
            b"America/Argentina/Jujuy" => TimeZone::AmericaArgentinaJujuy,
            b"America/Argentina/La_Rioja" => TimeZone::AmericaArgentinaLaRioja,
            b"America/Argentina/Mendoza" => TimeZone::AmericaArgentinaMendoza,
            b"America/Argentina/Rio_Gallegos" => TimeZone::AmericaArgentinaRioGallegos,
            b"America/Argentina/Salta" => TimeZone::AmericaArgentinaSalta,
            b"America/Argentina/San_Juan" => TimeZone::AmericaArgentinaSanJuan,
            b"America/Argentina/San_Luis" => TimeZone::AmericaArgentinaSanLuis,
            b"America/Argentina/Tucuman" => TimeZone::AmericaArgentinaTucuman,
            b"America/Argentina/Ushuaia" => TimeZone::AmericaArgentinaUshuaia,
            b"America/Aruba" => TimeZone::AmericaAruba,
            b"America/Asuncion" => TimeZone::AmericaAsuncion,
            b"America/Atikokan" => TimeZone::AmericaAtikokan,
            b"America/Atka" => TimeZone::AmericaAtka,
            b"America/Bahia" => TimeZone::AmericaBahia,
            b"America/Bahia_Banderas" => TimeZone::AmericaBahiaBanderas,
            b"America/Barbados" => TimeZone::AmericaBarbados,
            b"America/Belem" => TimeZone::AmericaBelem,
            b"America/Belize" => TimeZone::AmericaBelize,
            b"America/Blanc-Sablon" => TimeZone::AmericaBlancSablon,
            b"America/Boa_Vista" => TimeZone::AmericaBoaVista,
            b"America/Bogota" => TimeZone::AmericaBogota,
            b"America/Boise" => TimeZone::AmericaBoise,
            b"America/Buenos_Aires" => TimeZone::AmericaBuenosAires,
            b"America/Cambridge_Bay" => TimeZone::AmericaCambridgeBay,
            b"America/Campo_Grande" => TimeZone::AmericaCampoGrande,
            b"America/Cancun" => TimeZone::AmericaCancun,
            b"America/Caracas" => TimeZone::AmericaCaracas,
            b"America/Catamarca" => TimeZone::AmericaCatamarca,
            b"America/Cayenne" => TimeZone::AmericaCayenne,
            b"America/Cayman" => TimeZone::AmericaCayman,
            b"America/Chicago" => TimeZone::AmericaChicago,
            b"America/Chihuahua" => TimeZone::AmericaChihuahua,
            b"America/Ciudad_Juarez" => TimeZone::AmericaCiudadJuarez,
            b"America/Coral_Harbour" => TimeZone::AmericaCoralHarbour,
            b"America/Cordoba" => TimeZone::AmericaCordoba,
            b"America/Costa_Rica" => TimeZone::AmericaCostaRica,
            b"America/Coyhaique" => TimeZone::AmericaCoyhaique,
            b"America/Creston" => TimeZone::AmericaCreston,
            b"America/Cuiaba" => TimeZone::AmericaCuiaba,
            b"America/Curacao" => TimeZone::AmericaCuracao,
            b"America/Danmarkshavn" => TimeZone::AmericaDanmarkshavn,
            b"America/Dawson" => TimeZone::AmericaDawson,
            b"America/Dawson_Creek" => TimeZone::AmericaDawsonCreek,
            b"America/Denver" => TimeZone::AmericaDenver,
            b"America/Detroit" => TimeZone::AmericaDetroit,
            b"America/Dominica" => TimeZone::AmericaDominica,
            b"America/Edmonton" => TimeZone::AmericaEdmonton,
            b"America/Eirunepe" => TimeZone::AmericaEirunepe,
            b"America/El_Salvador" => TimeZone::AmericaElSalvador,
            b"America/Ensenada" => TimeZone::AmericaEnsenada,
            b"America/Fort_Nelson" => TimeZone::AmericaFortNelson,
            b"America/Fort_Wayne" => TimeZone::AmericaFortWayne,
            b"America/Fortaleza" => TimeZone::AmericaFortaleza,
            b"America/Glace_Bay" => TimeZone::AmericaGlaceBay,
            b"America/Godthab" => TimeZone::AmericaGodthab,
            b"America/Goose_Bay" => TimeZone::AmericaGooseBay,
            b"America/Grand_Turk" => TimeZone::AmericaGrandTurk,
            b"America/Grenada" => TimeZone::AmericaGrenada,
            b"America/Guadeloupe" => TimeZone::AmericaGuadeloupe,
            b"America/Guatemala" => TimeZone::AmericaGuatemala,
            b"America/Guayaquil" => TimeZone::AmericaGuayaquil,
            b"America/Guyana" => TimeZone::AmericaGuyana,
            b"America/Halifax" => TimeZone::AmericaHalifax,
            b"America/Havana" => TimeZone::AmericaHavana,
            b"America/Hermosillo" => TimeZone::AmericaHermosillo,
            b"America/Indiana/Indianapolis" => TimeZone::AmericaIndianaIndianapolis,
            b"America/Indiana/Knox" => TimeZone::AmericaIndianaKnox,
            b"America/Indiana/Marengo" => TimeZone::AmericaIndianaMarengo,
            b"America/Indiana/Petersburg" => TimeZone::AmericaIndianaPetersburg,
            b"America/Indiana/Tell_City" => TimeZone::AmericaIndianaTellCity,
            b"America/Indiana/Vevay" => TimeZone::AmericaIndianaVevay,
            b"America/Indiana/Vincennes" => TimeZone::AmericaIndianaVincennes,
            b"America/Indiana/Winamac" => TimeZone::AmericaIndianaWinamac,
            b"America/Indianapolis" => TimeZone::AmericaIndianapolis,
            b"America/Inuvik" => TimeZone::AmericaInuvik,
            b"America/Iqaluit" => TimeZone::AmericaIqaluit,
            b"America/Jamaica" => TimeZone::AmericaJamaica,
            b"America/Jujuy" => TimeZone::AmericaJujuy,
            b"America/Juneau" => TimeZone::AmericaJuneau,
            b"America/Kentucky/Louisville" => TimeZone::AmericaKentuckyLouisville,
            b"America/Kentucky/Monticello" => TimeZone::AmericaKentuckyMonticello,
            b"America/Knox_IN" => TimeZone::AmericaKnoxIN,
            b"America/Kralendijk" => TimeZone::AmericaKralendijk,
            b"America/La_Paz" => TimeZone::AmericaLaPaz,
            b"America/Lima" => TimeZone::AmericaLima,
            b"America/Los_Angeles" => TimeZone::AmericaLosAngeles,
            b"America/Louisville" => TimeZone::AmericaLouisville,
            b"America/Lower_Princes" => TimeZone::AmericaLowerPrinces,
            b"America/Maceio" => TimeZone::AmericaMaceio,
            b"America/Managua" => TimeZone::AmericaManagua,
            b"America/Manaus" => TimeZone::AmericaManaus,
            b"America/Marigot" => TimeZone::AmericaMarigot,
            b"America/Martinique" => TimeZone::AmericaMartinique,
            b"America/Matamoros" => TimeZone::AmericaMatamoros,
            b"America/Mazatlan" => TimeZone::AmericaMazatlan,
            b"America/Mendoza" => TimeZone::AmericaMendoza,
            b"America/Menominee" => TimeZone::AmericaMenominee,
            b"America/Merida" => TimeZone::AmericaMerida,
            b"America/Metlakatla" => TimeZone::AmericaMetlakatla,
            b"America/Mexico_City" => TimeZone::AmericaMexicoCity,
            b"America/Miquelon" => TimeZone::AmericaMiquelon,
            b"America/Moncton" => TimeZone::AmericaMoncton,
            b"America/Monterrey" => TimeZone::AmericaMonterrey,
            b"America/Montevideo" => TimeZone::AmericaMontevideo,
            b"America/Montreal" => TimeZone::AmericaMontreal,
            b"America/Montserrat" => TimeZone::AmericaMontserrat,
            b"America/Nassau" => TimeZone::AmericaNassau,
            b"America/New_York" => TimeZone::AmericaNewYork,
            b"America/Nipigon" => TimeZone::AmericaNipigon,
            b"America/Nome" => TimeZone::AmericaNome,
            b"America/Noronha" => TimeZone::AmericaNoronha,
            b"America/North_Dakota/Beulah" => TimeZone::AmericaNorthDakotaBeulah,
            b"America/North_Dakota/Center" => TimeZone::AmericaNorthDakotaCenter,
            b"America/North_Dakota/New_Salem" => TimeZone::AmericaNorthDakotaNewSalem,
            b"America/Nuuk" => TimeZone::AmericaNuuk,
            b"America/Ojinaga" => TimeZone::AmericaOjinaga,
            b"America/Panama" => TimeZone::AmericaPanama,
            b"America/Pangnirtung" => TimeZone::AmericaPangnirtung,
            b"America/Paramaribo" => TimeZone::AmericaParamaribo,
            b"America/Phoenix" => TimeZone::AmericaPhoenix,
            b"America/Port-au-Prince" => TimeZone::AmericaPortAuPrince,
            b"America/Port_of_Spain" => TimeZone::AmericaPortOfSpain,
            b"America/Porto_Acre" => TimeZone::AmericaPortoAcre,
            b"America/Porto_Velho" => TimeZone::AmericaPortoVelho,
            b"America/Puerto_Rico" => TimeZone::AmericaPuertoRico,
            b"America/Punta_Arenas" => TimeZone::AmericaPuntaArenas,
            b"America/Rainy_River" => TimeZone::AmericaRainyRiver,
            b"America/Rankin_Inlet" => TimeZone::AmericaRankinInlet,
            b"America/Recife" => TimeZone::AmericaRecife,
            b"America/Regina" => TimeZone::AmericaRegina,
            b"America/Resolute" => TimeZone::AmericaResolute,
            b"America/Rio_Branco" => TimeZone::AmericaRioBranco,
            b"America/Rosario" => TimeZone::AmericaRosario,
            b"America/Santa_Isabel" => TimeZone::AmericaSantaIsabel,
            b"America/Santarem" => TimeZone::AmericaSantarem,
            b"America/Santiago" => TimeZone::AmericaSantiago,
            b"America/Santo_Domingo" => TimeZone::AmericaSantoDomingo,
            b"America/Sao_Paulo" => TimeZone::AmericaSaoPaulo,
            b"America/Scoresbysund" => TimeZone::AmericaScoresbysund,
            b"America/Shiprock" => TimeZone::AmericaShiprock,
            b"America/Sitka" => TimeZone::AmericaSitka,
            b"America/St_Barthelemy" => TimeZone::AmericaStBarthelemy,
            b"America/St_Johns" => TimeZone::AmericaStJohns,
            b"America/St_Kitts" => TimeZone::AmericaStKitts,
            b"America/St_Lucia" => TimeZone::AmericaStLucia,
            b"America/St_Thomas" => TimeZone::AmericaStThomas,
            b"America/St_Vincent" => TimeZone::AmericaStVincent,
            b"America/Swift_Current" => TimeZone::AmericaSwiftCurrent,
            b"America/Tegucigalpa" => TimeZone::AmericaTegucigalpa,
            b"America/Thule" => TimeZone::AmericaThule,
            b"America/Thunder_Bay" => TimeZone::AmericaThunderBay,
            b"America/Tijuana" => TimeZone::AmericaTijuana,
            b"America/Toronto" => TimeZone::AmericaToronto,
            b"America/Tortola" => TimeZone::AmericaTortola,
            b"America/Vancouver" => TimeZone::AmericaVancouver,
            b"America/Virgin" => TimeZone::AmericaVirgin,
            b"America/Whitehorse" => TimeZone::AmericaWhitehorse,
            b"America/Winnipeg" => TimeZone::AmericaWinnipeg,
            b"America/Yakutat" => TimeZone::AmericaYakutat,
            b"America/Yellowknife" => TimeZone::AmericaYellowknife,
            b"Antarctica/Casey" => TimeZone::AntarcticaCasey,
            b"Antarctica/Davis" => TimeZone::AntarcticaDavis,
            b"Antarctica/DumontDUrville" => TimeZone::AntarcticaDumontDUrville,
            b"Antarctica/Macquarie" => TimeZone::AntarcticaMacquarie,
            b"Antarctica/Mawson" => TimeZone::AntarcticaMawson,
            b"Antarctica/McMurdo" => TimeZone::AntarcticaMcMurdo,
            b"Antarctica/Palmer" => TimeZone::AntarcticaPalmer,
            b"Antarctica/Rothera" => TimeZone::AntarcticaRothera,
            b"Antarctica/South_Pole" => TimeZone::AntarcticaSouthPole,
            b"Antarctica/Syowa" => TimeZone::AntarcticaSyowa,
            b"Antarctica/Troll" => TimeZone::AntarcticaTroll,
            b"Antarctica/Vostok" => TimeZone::AntarcticaVostok,
            b"Arctic/Longyearbyen" => TimeZone::ArcticLongyearbyen,
            b"Asia/Aden" => TimeZone::AsiaAden,
            b"Asia/Almaty" => TimeZone::AsiaAlmaty,
            b"Asia/Amman" => TimeZone::AsiaAmman,
            b"Asia/Anadyr" => TimeZone::AsiaAnadyr,
            b"Asia/Aqtau" => TimeZone::AsiaAqtau,
            b"Asia/Aqtobe" => TimeZone::AsiaAqtobe,
            b"Asia/Ashgabat" => TimeZone::AsiaAshgabat,
            b"Asia/Ashkhabad" => TimeZone::AsiaAshkhabad,
            b"Asia/Atyrau" => TimeZone::AsiaAtyrau,
            b"Asia/Baghdad" => TimeZone::AsiaBaghdad,
            b"Asia/Bahrain" => TimeZone::AsiaBahrain,
            b"Asia/Baku" => TimeZone::AsiaBaku,
            b"Asia/Bangkok" => TimeZone::AsiaBangkok,
            b"Asia/Barnaul" => TimeZone::AsiaBarnaul,
            b"Asia/Beirut" => TimeZone::AsiaBeirut,
            b"Asia/Bishkek" => TimeZone::AsiaBishkek,
            b"Asia/Brunei" => TimeZone::AsiaBrunei,
            b"Asia/Calcutta" => TimeZone::AsiaCalcutta,
            b"Asia/Chita" => TimeZone::AsiaChita,
            b"Asia/Choibalsan" => TimeZone::AsiaChoibalsan,
            b"Asia/Chongqing" => TimeZone::AsiaChongqing,
            b"Asia/Chungking" => TimeZone::AsiaChungking,
            b"Asia/Colombo" => TimeZone::AsiaColombo,
            b"Asia/Dacca" => TimeZone::AsiaDacca,
            b"Asia/Damascus" => TimeZone::AsiaDamascus,
            b"Asia/Dhaka" => TimeZone::AsiaDhaka,
            b"Asia/Dili" => TimeZone::AsiaDili,
            b"Asia/Dubai" => TimeZone::AsiaDubai,
            b"Asia/Dushanbe" => TimeZone::AsiaDushanbe,
            b"Asia/Famagusta" => TimeZone::AsiaFamagusta,
            b"Asia/Gaza" => TimeZone::AsiaGaza,
            b"Asia/Harbin" => TimeZone::AsiaHarbin,
            b"Asia/Hebron" => TimeZone::AsiaHebron,
            b"Asia/Ho_Chi_Minh" => TimeZone::AsiaHoChiMinh,
            b"Asia/Hong_Kong" => TimeZone::AsiaHongKong,
            b"Asia/Hovd" => TimeZone::AsiaHovd,
            b"Asia/Irkutsk" => TimeZone::AsiaIrkutsk,
            b"Asia/Istanbul" => TimeZone::AsiaIstanbul,
            b"Asia/Jakarta" => TimeZone::AsiaJakarta,
            b"Asia/Jayapura" => TimeZone::AsiaJayapura,
            b"Asia/Jerusalem" => TimeZone::AsiaJerusalem,
            b"Asia/Kabul" => TimeZone::AsiaKabul,
            b"Asia/Kamchatka" => TimeZone::AsiaKamchatka,
            b"Asia/Karachi" => TimeZone::AsiaKarachi,
            b"Asia/Kashgar" => TimeZone::AsiaKashgar,
            b"Asia/Kathmandu" => TimeZone::AsiaKathmandu,
            b"Asia/Katmandu" => TimeZone::AsiaKatmandu,
            b"Asia/Khandyga" => TimeZone::AsiaKhandyga,
            b"Asia/Kolkata" => TimeZone::AsiaKolkata,
            b"Asia/Krasnoyarsk" => TimeZone::AsiaKrasnoyarsk,
            b"Asia/Kuala_Lumpur" => TimeZone::AsiaKualaLumpur,
            b"Asia/Kuching" => TimeZone::AsiaKuching,
            b"Asia/Kuwait" => TimeZone::AsiaKuwait,
            b"Asia/Macao" => TimeZone::AsiaMacao,
            b"Asia/Macau" => TimeZone::AsiaMacau,
            b"Asia/Magadan" => TimeZone::AsiaMagadan,
            b"Asia/Makassar" => TimeZone::AsiaMakassar,
            b"Asia/Manila" => TimeZone::AsiaManila,
            b"Asia/Muscat" => TimeZone::AsiaMuscat,
            b"Asia/Nicosia" => TimeZone::AsiaNicosia,
            b"Asia/Novokuznetsk" => TimeZone::AsiaNovokuznetsk,
            b"Asia/Novosibirsk" => TimeZone::AsiaNovosibirsk,
            b"Asia/Omsk" => TimeZone::AsiaOmsk,
            b"Asia/Oral" => TimeZone::AsiaOral,
            b"Asia/Phnom_Penh" => TimeZone::AsiaPhnomPenh,
            b"Asia/Pontianak" => TimeZone::AsiaPontianak,
            b"Asia/Pyongyang" => TimeZone::AsiaPyongyang,
            b"Asia/Qatar" => TimeZone::AsiaQatar,
            b"Asia/Qostanay" => TimeZone::AsiaQostanay,
            b"Asia/Qyzylorda" => TimeZone::AsiaQyzylorda,
            b"Asia/Rangoon" => TimeZone::AsiaRangoon,
            b"Asia/Riyadh" => TimeZone::AsiaRiyadh,
            b"Asia/Saigon" => TimeZone::AsiaSaigon,
            b"Asia/Sakhalin" => TimeZone::AsiaSakhalin,
            b"Asia/Samarkand" => TimeZone::AsiaSamarkand,
            b"Asia/Seoul" => TimeZone::AsiaSeoul,
            b"Asia/Shanghai" => TimeZone::AsiaShanghai,
            b"Asia/Singapore" => TimeZone::AsiaSingapore,
            b"Asia/Srednekolymsk" => TimeZone::AsiaSrednekolymsk,
            b"Asia/Taipei" => TimeZone::AsiaTaipei,
            b"Asia/Tashkent" => TimeZone::AsiaTashkent,
            b"Asia/Tbilisi" => TimeZone::AsiaTbilisi,
            b"Asia/Tehran" => TimeZone::AsiaTehran,
            b"Asia/Tel_Aviv" => TimeZone::AsiaTelAviv,
            b"Asia/Thimbu" => TimeZone::AsiaThimbu,
            b"Asia/Thimphu" => TimeZone::AsiaThimphu,
            b"Asia/Tokyo" => TimeZone::AsiaTokyo,
            b"Asia/Tomsk" => TimeZone::AsiaTomsk,
            b"Asia/Ujung_Pandang" => TimeZone::AsiaUjungPandang,
            b"Asia/Ulaanbaatar" => TimeZone::AsiaUlaanbaatar,
            b"Asia/Ulan_Bator" => TimeZone::AsiaUlanBator,
            b"Asia/Urumqi" => TimeZone::AsiaUrumqi,
            b"Asia/Ust-Nera" => TimeZone::AsiaUstNera,
            b"Asia/Vientiane" => TimeZone::AsiaVientiane,
            b"Asia/Vladivostok" => TimeZone::AsiaVladivostok,
            b"Asia/Yakutsk" => TimeZone::AsiaYakutsk,
            b"Asia/Yangon" => TimeZone::AsiaYangon,
            b"Asia/Yekaterinburg" => TimeZone::AsiaYekaterinburg,
            b"Asia/Yerevan" => TimeZone::AsiaYerevan,
            b"Atlantic/Azores" => TimeZone::AtlanticAzores,
            b"Atlantic/Bermuda" => TimeZone::AtlanticBermuda,
            b"Atlantic/Canary" => TimeZone::AtlanticCanary,
            b"Atlantic/Cape_Verde" => TimeZone::AtlanticCapeVerde,
            b"Atlantic/Faeroe" => TimeZone::AtlanticFaeroe,
            b"Atlantic/Faroe" => TimeZone::AtlanticFaroe,
            b"Atlantic/Jan_Mayen" => TimeZone::AtlanticJanMayen,
            b"Atlantic/Madeira" => TimeZone::AtlanticMadeira,
            b"Atlantic/Reykjavik" => TimeZone::AtlanticReykjavik,
            b"Atlantic/South_Georgia" => TimeZone::AtlanticSouthGeorgia,
            b"Atlantic/St_Helena" => TimeZone::AtlanticStHelena,
            b"Atlantic/Stanley" => TimeZone::AtlanticStanley,
            b"Australia/ACT" => TimeZone::AustraliaACT,
            b"Australia/Adelaide" => TimeZone::AustraliaAdelaide,
            b"Australia/Brisbane" => TimeZone::AustraliaBrisbane,
            b"Australia/Broken_Hill" => TimeZone::AustraliaBrokenHill,
            b"Australia/Canberra" => TimeZone::AustraliaCanberra,
            b"Australia/Currie" => TimeZone::AustraliaCurrie,
            b"Australia/Darwin" => TimeZone::AustraliaDarwin,
            b"Australia/Eucla" => TimeZone::AustraliaEucla,
            b"Australia/Hobart" => TimeZone::AustraliaHobart,
            b"Australia/LHI" => TimeZone::AustraliaLHI,
            b"Australia/Lindeman" => TimeZone::AustraliaLindeman,
            b"Australia/Lord_Howe" => TimeZone::AustraliaLordHowe,
            b"Australia/Melbourne" => TimeZone::AustraliaMelbourne,
            b"Australia/NSW" => TimeZone::AustraliaNSW,
            b"Australia/North" => TimeZone::AustraliaNorth,
            b"Australia/Perth" => TimeZone::AustraliaPerth,
            b"Australia/Queensland" => TimeZone::AustraliaQueensland,
            b"Australia/South" => TimeZone::AustraliaSouth,
            b"Australia/Sydney" => TimeZone::AustraliaSydney,
            b"Australia/Tasmania" => TimeZone::AustraliaTasmania,
            b"Australia/Victoria" => TimeZone::AustraliaVictoria,
            b"Australia/West" => TimeZone::AustraliaWest,
            b"Australia/Yancowinna" => TimeZone::AustraliaYancowinna,
            b"Brazil/Acre" => TimeZone::BrazilAcre,
            b"Brazil/DeNoronha" => TimeZone::BrazilDeNoronha,
            b"Brazil/East" => TimeZone::BrazilEast,
            b"Brazil/West" => TimeZone::BrazilWest,
            b"CET" => TimeZone::CET,
            b"CST6CDT" => TimeZone::CST6CDT,
            b"Canada/Atlantic" => TimeZone::CanadaAtlantic,
            b"Canada/Central" => TimeZone::CanadaCentral,
            b"Canada/Eastern" => TimeZone::CanadaEastern,
            b"Canada/Mountain" => TimeZone::CanadaMountain,
            b"Canada/Newfoundland" => TimeZone::CanadaNewfoundland,
            b"Canada/Pacific" => TimeZone::CanadaPacific,
            b"Canada/Saskatchewan" => TimeZone::CanadaSaskatchewan,
            b"Canada/Yukon" => TimeZone::CanadaYukon,
            b"Chile/Continental" => TimeZone::ChileContinental,
            b"Chile/EasterIsland" => TimeZone::ChileEasterIsland,
            b"Cuba" => TimeZone::Cuba,
            b"EET" => TimeZone::EET,
            b"EST" => TimeZone::EST,
            b"EST5EDT" => TimeZone::EST5EDT,
            b"Egypt" => TimeZone::Egypt,
            b"Eire" => TimeZone::Eire,
            b"Etc/GMT" => TimeZone::EtcGMT,
            b"Etc/GMT+0" => TimeZone::EtcGMTPlus0,
            b"Etc/GMT+1" => TimeZone::EtcGMTPlus1,
            b"Etc/GMT+10" => TimeZone::EtcGMTPlus10,
            b"Etc/GMT+11" => TimeZone::EtcGMTPlus11,
            b"Etc/GMT+12" => TimeZone::EtcGMTPlus12,
            b"Etc/GMT+2" => TimeZone::EtcGMTPlus2,
            b"Etc/GMT+3" => TimeZone::EtcGMTPlus3,
            b"Etc/GMT+4" => TimeZone::EtcGMTPlus4,
            b"Etc/GMT+5" => TimeZone::EtcGMTPlus5,
            b"Etc/GMT+6" => TimeZone::EtcGMTPlus6,
            b"Etc/GMT+7" => TimeZone::EtcGMTPlus7,
            b"Etc/GMT+8" => TimeZone::EtcGMTPlus8,
            b"Etc/GMT+9" => TimeZone::EtcGMTPlus9,
            b"Etc/GMT-0" => TimeZone::EtcGMTMinus0,
            b"Etc/GMT-1" => TimeZone::EtcGMTMinus1,
            b"Etc/GMT-10" => TimeZone::EtcGMTMinus10,
            b"Etc/GMT-11" => TimeZone::EtcGMTMinus11,
            b"Etc/GMT-12" => TimeZone::EtcGMTMinus12,
            b"Etc/GMT-13" => TimeZone::EtcGMTMinus13,
            b"Etc/GMT-14" => TimeZone::EtcGMTMinus14,
            b"Etc/GMT-2" => TimeZone::EtcGMTMinus2,
            b"Etc/GMT-3" => TimeZone::EtcGMTMinus3,
            b"Etc/GMT-4" => TimeZone::EtcGMTMinus4,
            b"Etc/GMT-5" => TimeZone::EtcGMTMinus5,
            b"Etc/GMT-6" => TimeZone::EtcGMTMinus6,
            b"Etc/GMT-7" => TimeZone::EtcGMTMinus7,
            b"Etc/GMT-8" => TimeZone::EtcGMTMinus8,
            b"Etc/GMT-9" => TimeZone::EtcGMTMinus9,
            b"Etc/GMT0" => TimeZone::EtcGMT0,
            b"Etc/Greenwich" => TimeZone::EtcGreenwich,
            b"Etc/UCT" => TimeZone::EtcUCT,
            b"Etc/UTC" => TimeZone::EtcUTC,
            b"Etc/Universal" => TimeZone::EtcUniversal,
            b"Etc/Zulu" => TimeZone::EtcZulu,
            b"Europe/Amsterdam" => TimeZone::EuropeAmsterdam,
            b"Europe/Andorra" => TimeZone::EuropeAndorra,
            b"Europe/Astrakhan" => TimeZone::EuropeAstrakhan,
            b"Europe/Athens" => TimeZone::EuropeAthens,
            b"Europe/Belfast" => TimeZone::EuropeBelfast,
            b"Europe/Belgrade" => TimeZone::EuropeBelgrade,
            b"Europe/Berlin" => TimeZone::EuropeBerlin,
            b"Europe/Bratislava" => TimeZone::EuropeBratislava,
            b"Europe/Brussels" => TimeZone::EuropeBrussels,
            b"Europe/Bucharest" => TimeZone::EuropeBucharest,
            b"Europe/Budapest" => TimeZone::EuropeBudapest,
            b"Europe/Busingen" => TimeZone::EuropeBusingen,
            b"Europe/Chisinau" => TimeZone::EuropeChisinau,
            b"Europe/Copenhagen" => TimeZone::EuropeCopenhagen,
            b"Europe/Dublin" => TimeZone::EuropeDublin,
            b"Europe/Gibraltar" => TimeZone::EuropeGibraltar,
            b"Europe/Guernsey" => TimeZone::EuropeGuernsey,
            b"Europe/Helsinki" => TimeZone::EuropeHelsinki,
            b"Europe/Isle_of_Man" => TimeZone::EuropeIsleOfMan,
            b"Europe/Istanbul" => TimeZone::EuropeIstanbul,
            b"Europe/Jersey" => TimeZone::EuropeJersey,
            b"Europe/Kaliningrad" => TimeZone::EuropeKaliningrad,
            b"Europe/Kiev" => TimeZone::EuropeKiev,
            b"Europe/Kirov" => TimeZone::EuropeKirov,
            b"Europe/Kyiv" => TimeZone::EuropeKyiv,
            b"Europe/Lisbon" => TimeZone::EuropeLisbon,
            b"Europe/Ljubljana" => TimeZone::EuropeLjubljana,
            b"Europe/London" => TimeZone::EuropeLondon,
            b"Europe/Luxembourg" => TimeZone::EuropeLuxembourg,
            b"Europe/Madrid" => TimeZone::EuropeMadrid,
            b"Europe/Malta" => TimeZone::EuropeMalta,
            b"Europe/Mariehamn" => TimeZone::EuropeMariehamn,
            b"Europe/Minsk" => TimeZone::EuropeMinsk,
            b"Europe/Monaco" => TimeZone::EuropeMonaco,
            b"Europe/Moscow" => TimeZone::EuropeMoscow,
            b"Europe/Nicosia" => TimeZone::EuropeNicosia,
            b"Europe/Oslo" => TimeZone::EuropeOslo,
            b"Europe/Paris" => TimeZone::EuropeParis,
            b"Europe/Podgorica" => TimeZone::EuropePodgorica,
            b"Europe/Prague" => TimeZone::EuropePrague,
            b"Europe/Riga" => TimeZone::EuropeRiga,
            b"Europe/Rome" => TimeZone::EuropeRome,
            b"Europe/Samara" => TimeZone::EuropeSamara,
            b"Europe/San_Marino" => TimeZone::EuropeSanMarino,
            b"Europe/Sarajevo" => TimeZone::EuropeSarajevo,
            b"Europe/Saratov" => TimeZone::EuropeSaratov,
            b"Europe/Simferopol" => TimeZone::EuropeSimferopol,
            b"Europe/Skopje" => TimeZone::EuropeSkopje,
            b"Europe/Sofia" => TimeZone::EuropeSofia,
            b"Europe/Stockholm" => TimeZone::EuropeStockholm,
            b"Europe/Tallinn" => TimeZone::EuropeTallinn,
            b"Europe/Tirane" => TimeZone::EuropeTirane,
            b"Europe/Tiraspol" => TimeZone::EuropeTiraspol,
            b"Europe/Ulyanovsk" => TimeZone::EuropeUlyanovsk,
            b"Europe/Uzhgorod" => TimeZone::EuropeUzhgorod,
            b"Europe/Vaduz" => TimeZone::EuropeVaduz,
            b"Europe/Vatican" => TimeZone::EuropeVatican,
            b"Europe/Vienna" => TimeZone::EuropeVienna,
            b"Europe/Vilnius" => TimeZone::EuropeVilnius,
            b"Europe/Volgograd" => TimeZone::EuropeVolgograd,
            b"Europe/Warsaw" => TimeZone::EuropeWarsaw,
            b"Europe/Zagreb" => TimeZone::EuropeZagreb,
            b"Europe/Zaporozhye" => TimeZone::EuropeZaporozhye,
            b"Europe/Zurich" => TimeZone::EuropeZurich,
            b"Factory" => TimeZone::Factory,
            b"GB" => TimeZone::GB,
            b"GB-Eire" => TimeZone::GBEire,
            b"GMT" => TimeZone::GMT,
            b"GMT+0" => TimeZone::GMTPlus0,
            b"GMT-0" => TimeZone::GMTMinus0,
            b"GMT0" => TimeZone::GMT0,
            b"Greenwich" => TimeZone::Greenwich,
            b"HST" => TimeZone::HST,
            b"Hongkong" => TimeZone::Hongkong,
            b"Iceland" => TimeZone::Iceland,
            b"Indian/Antananarivo" => TimeZone::IndianAntananarivo,
            b"Indian/Chagos" => TimeZone::IndianChagos,
            b"Indian/Christmas" => TimeZone::IndianChristmas,
            b"Indian/Cocos" => TimeZone::IndianCocos,
            b"Indian/Comoro" => TimeZone::IndianComoro,
            b"Indian/Kerguelen" => TimeZone::IndianKerguelen,
            b"Indian/Mahe" => TimeZone::IndianMahe,
            b"Indian/Maldives" => TimeZone::IndianMaldives,
            b"Indian/Mauritius" => TimeZone::IndianMauritius,
            b"Indian/Mayotte" => TimeZone::IndianMayotte,
            b"Indian/Reunion" => TimeZone::IndianReunion,
            b"Iran" => TimeZone::Iran,
            b"Israel" => TimeZone::Israel,
            b"Jamaica" => TimeZone::Jamaica,
            b"Japan" => TimeZone::Japan,
            b"Kwajalein" => TimeZone::Kwajalein,
            b"Libya" => TimeZone::Libya,
            b"MET" => TimeZone::MET,
            b"MST" => TimeZone::MST,
            b"MST7MDT" => TimeZone::MST7MDT,
            b"Mexico/BajaNorte" => TimeZone::MexicoBajaNorte,
            b"Mexico/BajaSur" => TimeZone::MexicoBajaSur,
            b"Mexico/General" => TimeZone::MexicoGeneral,
            b"NZ" => TimeZone::NZ,
            b"NZ-CHAT" => TimeZone::NZCHAT,
            b"Navajo" => TimeZone::Navajo,
            b"PRC" => TimeZone::PRC,
            b"PST8PDT" => TimeZone::PST8PDT,
            b"Pacific/Apia" => TimeZone::PacificApia,
            b"Pacific/Auckland" => TimeZone::PacificAuckland,
            b"Pacific/Bougainville" => TimeZone::PacificBougainville,
            b"Pacific/Chatham" => TimeZone::PacificChatham,
            b"Pacific/Chuuk" => TimeZone::PacificChuuk,
            b"Pacific/Easter" => TimeZone::PacificEaster,
            b"Pacific/Efate" => TimeZone::PacificEfate,
            b"Pacific/Enderbury" => TimeZone::PacificEnderbury,
            b"Pacific/Fakaofo" => TimeZone::PacificFakaofo,
            b"Pacific/Fiji" => TimeZone::PacificFiji,
            b"Pacific/Funafuti" => TimeZone::PacificFunafuti,
            b"Pacific/Galapagos" => TimeZone::PacificGalapagos,
            b"Pacific/Gambier" => TimeZone::PacificGambier,
            b"Pacific/Guadalcanal" => TimeZone::PacificGuadalcanal,
            b"Pacific/Guam" => TimeZone::PacificGuam,
            b"Pacific/Honolulu" => TimeZone::PacificHonolulu,
            b"Pacific/Johnston" => TimeZone::PacificJohnston,
            b"Pacific/Kanton" => TimeZone::PacificKanton,
            b"Pacific/Kiritimati" => TimeZone::PacificKiritimati,
            b"Pacific/Kosrae" => TimeZone::PacificKosrae,
            b"Pacific/Kwajalein" => TimeZone::PacificKwajalein,
            b"Pacific/Majuro" => TimeZone::PacificMajuro,
            b"Pacific/Marquesas" => TimeZone::PacificMarquesas,
            b"Pacific/Midway" => TimeZone::PacificMidway,
            b"Pacific/Nauru" => TimeZone::PacificNauru,
            b"Pacific/Niue" => TimeZone::PacificNiue,
            b"Pacific/Norfolk" => TimeZone::PacificNorfolk,
            b"Pacific/Noumea" => TimeZone::PacificNoumea,
            b"Pacific/Pago_Pago" => TimeZone::PacificPagoPago,
            b"Pacific/Palau" => TimeZone::PacificPalau,
            b"Pacific/Pitcairn" => TimeZone::PacificPitcairn,
            b"Pacific/Pohnpei" => TimeZone::PacificPohnpei,
            b"Pacific/Ponape" => TimeZone::PacificPonape,
            b"Pacific/Port_Moresby" => TimeZone::PacificPortMoresby,
            b"Pacific/Rarotonga" => TimeZone::PacificRarotonga,
            b"Pacific/Saipan" => TimeZone::PacificSaipan,
            b"Pacific/Samoa" => TimeZone::PacificSamoa,
            b"Pacific/Tahiti" => TimeZone::PacificTahiti,
            b"Pacific/Tarawa" => TimeZone::PacificTarawa,
            b"Pacific/Tongatapu" => TimeZone::PacificTongatapu,
            b"Pacific/Truk" => TimeZone::PacificTruk,
            b"Pacific/Wake" => TimeZone::PacificWake,
            b"Pacific/Wallis" => TimeZone::PacificWallis,
            b"Pacific/Yap" => TimeZone::PacificYap,
            b"Poland" => TimeZone::Poland,
            b"Portugal" => TimeZone::Portugal,
            b"ROC" => TimeZone::ROC,
            b"ROK" => TimeZone::ROK,
            b"Singapore" => TimeZone::Singapore,
            b"Turkey" => TimeZone::Turkey,
            b"UCT" => TimeZone::UCT,
            b"US/Alaska" => TimeZone::USAlaska,
            b"US/Aleutian" => TimeZone::USAleutian,
            b"US/Arizona" => TimeZone::USArizona,
            b"US/Central" => TimeZone::USCentral,
            b"US/East-Indiana" => TimeZone::USEastIndiana,
            b"US/Eastern" => TimeZone::USEastern,
            b"US/Hawaii" => TimeZone::USHawaii,
            b"US/Indiana-Starke" => TimeZone::USIndianaStarke,
            b"US/Michigan" => TimeZone::USMichigan,
            b"US/Mountain" => TimeZone::USMountain,
            b"US/Pacific" => TimeZone::USPacific,
            b"US/Samoa" => TimeZone::USSamoa,
            b"UTC" => TimeZone::UTC,
            b"Universal" => TimeZone::Universal,
            b"W-SU" => TimeZone::WSU,
            b"WET" => TimeZone::WET,
            b"Zulu" => TimeZone::Zulu,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            TimeZone::AfricaAbidjan => "Africa/Abidjan",
            TimeZone::AfricaAccra => "Africa/Accra",
            TimeZone::AfricaAddisAbaba => "Africa/Addis_Ababa",
            TimeZone::AfricaAlgiers => "Africa/Algiers",
            TimeZone::AfricaAsmara => "Africa/Asmara",
            TimeZone::AfricaAsmera => "Africa/Asmera",
            TimeZone::AfricaBamako => "Africa/Bamako",
            TimeZone::AfricaBangui => "Africa/Bangui",
            TimeZone::AfricaBanjul => "Africa/Banjul",
            TimeZone::AfricaBissau => "Africa/Bissau",
            TimeZone::AfricaBlantyre => "Africa/Blantyre",
            TimeZone::AfricaBrazzaville => "Africa/Brazzaville",
            TimeZone::AfricaBujumbura => "Africa/Bujumbura",
            TimeZone::AfricaCairo => "Africa/Cairo",
            TimeZone::AfricaCasablanca => "Africa/Casablanca",
            TimeZone::AfricaCeuta => "Africa/Ceuta",
            TimeZone::AfricaConakry => "Africa/Conakry",
            TimeZone::AfricaDakar => "Africa/Dakar",
            TimeZone::AfricaDarEsSalaam => "Africa/Dar_es_Salaam",
            TimeZone::AfricaDjibouti => "Africa/Djibouti",
            TimeZone::AfricaDouala => "Africa/Douala",
            TimeZone::AfricaElAaiun => "Africa/El_Aaiun",
            TimeZone::AfricaFreetown => "Africa/Freetown",
            TimeZone::AfricaGaborone => "Africa/Gaborone",
            TimeZone::AfricaHarare => "Africa/Harare",
            TimeZone::AfricaJohannesburg => "Africa/Johannesburg",
            TimeZone::AfricaJuba => "Africa/Juba",
            TimeZone::AfricaKampala => "Africa/Kampala",
            TimeZone::AfricaKhartoum => "Africa/Khartoum",
            TimeZone::AfricaKigali => "Africa/Kigali",
            TimeZone::AfricaKinshasa => "Africa/Kinshasa",
            TimeZone::AfricaLagos => "Africa/Lagos",
            TimeZone::AfricaLibreville => "Africa/Libreville",
            TimeZone::AfricaLome => "Africa/Lome",
            TimeZone::AfricaLuanda => "Africa/Luanda",
            TimeZone::AfricaLubumbashi => "Africa/Lubumbashi",
            TimeZone::AfricaLusaka => "Africa/Lusaka",
            TimeZone::AfricaMalabo => "Africa/Malabo",
            TimeZone::AfricaMaputo => "Africa/Maputo",
            TimeZone::AfricaMaseru => "Africa/Maseru",
            TimeZone::AfricaMbabane => "Africa/Mbabane",
            TimeZone::AfricaMogadishu => "Africa/Mogadishu",
            TimeZone::AfricaMonrovia => "Africa/Monrovia",
            TimeZone::AfricaNairobi => "Africa/Nairobi",
            TimeZone::AfricaNdjamena => "Africa/Ndjamena",
            TimeZone::AfricaNiamey => "Africa/Niamey",
            TimeZone::AfricaNouakchott => "Africa/Nouakchott",
            TimeZone::AfricaOuagadougou => "Africa/Ouagadougou",
            TimeZone::AfricaPortoNovo => "Africa/Porto-Novo",
            TimeZone::AfricaSaoTome => "Africa/Sao_Tome",
            TimeZone::AfricaTimbuktu => "Africa/Timbuktu",
            TimeZone::AfricaTripoli => "Africa/Tripoli",
            TimeZone::AfricaTunis => "Africa/Tunis",
            TimeZone::AfricaWindhoek => "Africa/Windhoek",
            TimeZone::AmericaAdak => "America/Adak",
            TimeZone::AmericaAnchorage => "America/Anchorage",
            TimeZone::AmericaAnguilla => "America/Anguilla",
            TimeZone::AmericaAntigua => "America/Antigua",
            TimeZone::AmericaAraguaina => "America/Araguaina",
            TimeZone::AmericaArgentinaBuenosAires => "America/Argentina/Buenos_Aires",
            TimeZone::AmericaArgentinaCatamarca => "America/Argentina/Catamarca",
            TimeZone::AmericaArgentinaComodRivadavia => "America/Argentina/ComodRivadavia",
            TimeZone::AmericaArgentinaCordoba => "America/Argentina/Cordoba",
            TimeZone::AmericaArgentinaJujuy => "America/Argentina/Jujuy",
            TimeZone::AmericaArgentinaLaRioja => "America/Argentina/La_Rioja",
            TimeZone::AmericaArgentinaMendoza => "America/Argentina/Mendoza",
            TimeZone::AmericaArgentinaRioGallegos => "America/Argentina/Rio_Gallegos",
            TimeZone::AmericaArgentinaSalta => "America/Argentina/Salta",
            TimeZone::AmericaArgentinaSanJuan => "America/Argentina/San_Juan",
            TimeZone::AmericaArgentinaSanLuis => "America/Argentina/San_Luis",
            TimeZone::AmericaArgentinaTucuman => "America/Argentina/Tucuman",
            TimeZone::AmericaArgentinaUshuaia => "America/Argentina/Ushuaia",
            TimeZone::AmericaAruba => "America/Aruba",
            TimeZone::AmericaAsuncion => "America/Asuncion",
            TimeZone::AmericaAtikokan => "America/Atikokan",
            TimeZone::AmericaAtka => "America/Atka",
            TimeZone::AmericaBahia => "America/Bahia",
            TimeZone::AmericaBahiaBanderas => "America/Bahia_Banderas",
            TimeZone::AmericaBarbados => "America/Barbados",
            TimeZone::AmericaBelem => "America/Belem",
            TimeZone::AmericaBelize => "America/Belize",
            TimeZone::AmericaBlancSablon => "America/Blanc-Sablon",
            TimeZone::AmericaBoaVista => "America/Boa_Vista",
            TimeZone::AmericaBogota => "America/Bogota",
            TimeZone::AmericaBoise => "America/Boise",
            TimeZone::AmericaBuenosAires => "America/Buenos_Aires",
            TimeZone::AmericaCambridgeBay => "America/Cambridge_Bay",
            TimeZone::AmericaCampoGrande => "America/Campo_Grande",
            TimeZone::AmericaCancun => "America/Cancun",
            TimeZone::AmericaCaracas => "America/Caracas",
            TimeZone::AmericaCatamarca => "America/Catamarca",
            TimeZone::AmericaCayenne => "America/Cayenne",
            TimeZone::AmericaCayman => "America/Cayman",
            TimeZone::AmericaChicago => "America/Chicago",
            TimeZone::AmericaChihuahua => "America/Chihuahua",
            TimeZone::AmericaCiudadJuarez => "America/Ciudad_Juarez",
            TimeZone::AmericaCoralHarbour => "America/Coral_Harbour",
            TimeZone::AmericaCordoba => "America/Cordoba",
            TimeZone::AmericaCostaRica => "America/Costa_Rica",
            TimeZone::AmericaCoyhaique => "America/Coyhaique",
            TimeZone::AmericaCreston => "America/Creston",
            TimeZone::AmericaCuiaba => "America/Cuiaba",
            TimeZone::AmericaCuracao => "America/Curacao",
            TimeZone::AmericaDanmarkshavn => "America/Danmarkshavn",
            TimeZone::AmericaDawson => "America/Dawson",
            TimeZone::AmericaDawsonCreek => "America/Dawson_Creek",
            TimeZone::AmericaDenver => "America/Denver",
            TimeZone::AmericaDetroit => "America/Detroit",
            TimeZone::AmericaDominica => "America/Dominica",
            TimeZone::AmericaEdmonton => "America/Edmonton",
            TimeZone::AmericaEirunepe => "America/Eirunepe",
            TimeZone::AmericaElSalvador => "America/El_Salvador",
            TimeZone::AmericaEnsenada => "America/Ensenada",
            TimeZone::AmericaFortNelson => "America/Fort_Nelson",
            TimeZone::AmericaFortWayne => "America/Fort_Wayne",
            TimeZone::AmericaFortaleza => "America/Fortaleza",
            TimeZone::AmericaGlaceBay => "America/Glace_Bay",
            TimeZone::AmericaGodthab => "America/Godthab",
            TimeZone::AmericaGooseBay => "America/Goose_Bay",
            TimeZone::AmericaGrandTurk => "America/Grand_Turk",
            TimeZone::AmericaGrenada => "America/Grenada",
            TimeZone::AmericaGuadeloupe => "America/Guadeloupe",
            TimeZone::AmericaGuatemala => "America/Guatemala",
            TimeZone::AmericaGuayaquil => "America/Guayaquil",
            TimeZone::AmericaGuyana => "America/Guyana",
            TimeZone::AmericaHalifax => "America/Halifax",
            TimeZone::AmericaHavana => "America/Havana",
            TimeZone::AmericaHermosillo => "America/Hermosillo",
            TimeZone::AmericaIndianaIndianapolis => "America/Indiana/Indianapolis",
            TimeZone::AmericaIndianaKnox => "America/Indiana/Knox",
            TimeZone::AmericaIndianaMarengo => "America/Indiana/Marengo",
            TimeZone::AmericaIndianaPetersburg => "America/Indiana/Petersburg",
            TimeZone::AmericaIndianaTellCity => "America/Indiana/Tell_City",
            TimeZone::AmericaIndianaVevay => "America/Indiana/Vevay",
            TimeZone::AmericaIndianaVincennes => "America/Indiana/Vincennes",
            TimeZone::AmericaIndianaWinamac => "America/Indiana/Winamac",
            TimeZone::AmericaIndianapolis => "America/Indianapolis",
            TimeZone::AmericaInuvik => "America/Inuvik",
            TimeZone::AmericaIqaluit => "America/Iqaluit",
            TimeZone::AmericaJamaica => "America/Jamaica",
            TimeZone::AmericaJujuy => "America/Jujuy",
            TimeZone::AmericaJuneau => "America/Juneau",
            TimeZone::AmericaKentuckyLouisville => "America/Kentucky/Louisville",
            TimeZone::AmericaKentuckyMonticello => "America/Kentucky/Monticello",
            TimeZone::AmericaKnoxIN => "America/Knox_IN",
            TimeZone::AmericaKralendijk => "America/Kralendijk",
            TimeZone::AmericaLaPaz => "America/La_Paz",
            TimeZone::AmericaLima => "America/Lima",
            TimeZone::AmericaLosAngeles => "America/Los_Angeles",
            TimeZone::AmericaLouisville => "America/Louisville",
            TimeZone::AmericaLowerPrinces => "America/Lower_Princes",
            TimeZone::AmericaMaceio => "America/Maceio",
            TimeZone::AmericaManagua => "America/Managua",
            TimeZone::AmericaManaus => "America/Manaus",
            TimeZone::AmericaMarigot => "America/Marigot",
            TimeZone::AmericaMartinique => "America/Martinique",
            TimeZone::AmericaMatamoros => "America/Matamoros",
            TimeZone::AmericaMazatlan => "America/Mazatlan",
            TimeZone::AmericaMendoza => "America/Mendoza",
            TimeZone::AmericaMenominee => "America/Menominee",
            TimeZone::AmericaMerida => "America/Merida",
            TimeZone::AmericaMetlakatla => "America/Metlakatla",
            TimeZone::AmericaMexicoCity => "America/Mexico_City",
            TimeZone::AmericaMiquelon => "America/Miquelon",
            TimeZone::AmericaMoncton => "America/Moncton",
            TimeZone::AmericaMonterrey => "America/Monterrey",
            TimeZone::AmericaMontevideo => "America/Montevideo",
            TimeZone::AmericaMontreal => "America/Montreal",
            TimeZone::AmericaMontserrat => "America/Montserrat",
            TimeZone::AmericaNassau => "America/Nassau",
            TimeZone::AmericaNewYork => "America/New_York",
            TimeZone::AmericaNipigon => "America/Nipigon",
            TimeZone::AmericaNome => "America/Nome",
            TimeZone::AmericaNoronha => "America/Noronha",
            TimeZone::AmericaNorthDakotaBeulah => "America/North_Dakota/Beulah",
            TimeZone::AmericaNorthDakotaCenter => "America/North_Dakota/Center",
            TimeZone::AmericaNorthDakotaNewSalem => "America/North_Dakota/New_Salem",
            TimeZone::AmericaNuuk => "America/Nuuk",
            TimeZone::AmericaOjinaga => "America/Ojinaga",
            TimeZone::AmericaPanama => "America/Panama",
            TimeZone::AmericaPangnirtung => "America/Pangnirtung",
            TimeZone::AmericaParamaribo => "America/Paramaribo",
            TimeZone::AmericaPhoenix => "America/Phoenix",
            TimeZone::AmericaPortAuPrince => "America/Port-au-Prince",
            TimeZone::AmericaPortOfSpain => "America/Port_of_Spain",
            TimeZone::AmericaPortoAcre => "America/Porto_Acre",
            TimeZone::AmericaPortoVelho => "America/Porto_Velho",
            TimeZone::AmericaPuertoRico => "America/Puerto_Rico",
            TimeZone::AmericaPuntaArenas => "America/Punta_Arenas",
            TimeZone::AmericaRainyRiver => "America/Rainy_River",
            TimeZone::AmericaRankinInlet => "America/Rankin_Inlet",
            TimeZone::AmericaRecife => "America/Recife",
            TimeZone::AmericaRegina => "America/Regina",
            TimeZone::AmericaResolute => "America/Resolute",
            TimeZone::AmericaRioBranco => "America/Rio_Branco",
            TimeZone::AmericaRosario => "America/Rosario",
            TimeZone::AmericaSantaIsabel => "America/Santa_Isabel",
            TimeZone::AmericaSantarem => "America/Santarem",
            TimeZone::AmericaSantiago => "America/Santiago",
            TimeZone::AmericaSantoDomingo => "America/Santo_Domingo",
            TimeZone::AmericaSaoPaulo => "America/Sao_Paulo",
            TimeZone::AmericaScoresbysund => "America/Scoresbysund",
            TimeZone::AmericaShiprock => "America/Shiprock",
            TimeZone::AmericaSitka => "America/Sitka",
            TimeZone::AmericaStBarthelemy => "America/St_Barthelemy",
            TimeZone::AmericaStJohns => "America/St_Johns",
            TimeZone::AmericaStKitts => "America/St_Kitts",
            TimeZone::AmericaStLucia => "America/St_Lucia",
            TimeZone::AmericaStThomas => "America/St_Thomas",
            TimeZone::AmericaStVincent => "America/St_Vincent",
            TimeZone::AmericaSwiftCurrent => "America/Swift_Current",
            TimeZone::AmericaTegucigalpa => "America/Tegucigalpa",
            TimeZone::AmericaThule => "America/Thule",
            TimeZone::AmericaThunderBay => "America/Thunder_Bay",
            TimeZone::AmericaTijuana => "America/Tijuana",
            TimeZone::AmericaToronto => "America/Toronto",
            TimeZone::AmericaTortola => "America/Tortola",
            TimeZone::AmericaVancouver => "America/Vancouver",
            TimeZone::AmericaVirgin => "America/Virgin",
            TimeZone::AmericaWhitehorse => "America/Whitehorse",
            TimeZone::AmericaWinnipeg => "America/Winnipeg",
            TimeZone::AmericaYakutat => "America/Yakutat",
            TimeZone::AmericaYellowknife => "America/Yellowknife",
            TimeZone::AntarcticaCasey => "Antarctica/Casey",
            TimeZone::AntarcticaDavis => "Antarctica/Davis",
            TimeZone::AntarcticaDumontDUrville => "Antarctica/DumontDUrville",
            TimeZone::AntarcticaMacquarie => "Antarctica/Macquarie",
            TimeZone::AntarcticaMawson => "Antarctica/Mawson",
            TimeZone::AntarcticaMcMurdo => "Antarctica/McMurdo",
            TimeZone::AntarcticaPalmer => "Antarctica/Palmer",
            TimeZone::AntarcticaRothera => "Antarctica/Rothera",
            TimeZone::AntarcticaSouthPole => "Antarctica/South_Pole",
            TimeZone::AntarcticaSyowa => "Antarctica/Syowa",
            TimeZone::AntarcticaTroll => "Antarctica/Troll",
            TimeZone::AntarcticaVostok => "Antarctica/Vostok",
            TimeZone::ArcticLongyearbyen => "Arctic/Longyearbyen",
            TimeZone::AsiaAden => "Asia/Aden",
            TimeZone::AsiaAlmaty => "Asia/Almaty",
            TimeZone::AsiaAmman => "Asia/Amman",
            TimeZone::AsiaAnadyr => "Asia/Anadyr",
            TimeZone::AsiaAqtau => "Asia/Aqtau",
            TimeZone::AsiaAqtobe => "Asia/Aqtobe",
            TimeZone::AsiaAshgabat => "Asia/Ashgabat",
            TimeZone::AsiaAshkhabad => "Asia/Ashkhabad",
            TimeZone::AsiaAtyrau => "Asia/Atyrau",
            TimeZone::AsiaBaghdad => "Asia/Baghdad",
            TimeZone::AsiaBahrain => "Asia/Bahrain",
            TimeZone::AsiaBaku => "Asia/Baku",
            TimeZone::AsiaBangkok => "Asia/Bangkok",
            TimeZone::AsiaBarnaul => "Asia/Barnaul",
            TimeZone::AsiaBeirut => "Asia/Beirut",
            TimeZone::AsiaBishkek => "Asia/Bishkek",
            TimeZone::AsiaBrunei => "Asia/Brunei",
            TimeZone::AsiaCalcutta => "Asia/Calcutta",
            TimeZone::AsiaChita => "Asia/Chita",
            TimeZone::AsiaChoibalsan => "Asia/Choibalsan",
            TimeZone::AsiaChongqing => "Asia/Chongqing",
            TimeZone::AsiaChungking => "Asia/Chungking",
            TimeZone::AsiaColombo => "Asia/Colombo",
            TimeZone::AsiaDacca => "Asia/Dacca",
            TimeZone::AsiaDamascus => "Asia/Damascus",
            TimeZone::AsiaDhaka => "Asia/Dhaka",
            TimeZone::AsiaDili => "Asia/Dili",
            TimeZone::AsiaDubai => "Asia/Dubai",
            TimeZone::AsiaDushanbe => "Asia/Dushanbe",
            TimeZone::AsiaFamagusta => "Asia/Famagusta",
            TimeZone::AsiaGaza => "Asia/Gaza",
            TimeZone::AsiaHarbin => "Asia/Harbin",
            TimeZone::AsiaHebron => "Asia/Hebron",
            TimeZone::AsiaHoChiMinh => "Asia/Ho_Chi_Minh",
            TimeZone::AsiaHongKong => "Asia/Hong_Kong",
            TimeZone::AsiaHovd => "Asia/Hovd",
            TimeZone::AsiaIrkutsk => "Asia/Irkutsk",
            TimeZone::AsiaIstanbul => "Asia/Istanbul",
            TimeZone::AsiaJakarta => "Asia/Jakarta",
            TimeZone::AsiaJayapura => "Asia/Jayapura",
            TimeZone::AsiaJerusalem => "Asia/Jerusalem",
            TimeZone::AsiaKabul => "Asia/Kabul",
            TimeZone::AsiaKamchatka => "Asia/Kamchatka",
            TimeZone::AsiaKarachi => "Asia/Karachi",
            TimeZone::AsiaKashgar => "Asia/Kashgar",
            TimeZone::AsiaKathmandu => "Asia/Kathmandu",
            TimeZone::AsiaKatmandu => "Asia/Katmandu",
            TimeZone::AsiaKhandyga => "Asia/Khandyga",
            TimeZone::AsiaKolkata => "Asia/Kolkata",
            TimeZone::AsiaKrasnoyarsk => "Asia/Krasnoyarsk",
            TimeZone::AsiaKualaLumpur => "Asia/Kuala_Lumpur",
            TimeZone::AsiaKuching => "Asia/Kuching",
            TimeZone::AsiaKuwait => "Asia/Kuwait",
            TimeZone::AsiaMacao => "Asia/Macao",
            TimeZone::AsiaMacau => "Asia/Macau",
            TimeZone::AsiaMagadan => "Asia/Magadan",
            TimeZone::AsiaMakassar => "Asia/Makassar",
            TimeZone::AsiaManila => "Asia/Manila",
            TimeZone::AsiaMuscat => "Asia/Muscat",
            TimeZone::AsiaNicosia => "Asia/Nicosia",
            TimeZone::AsiaNovokuznetsk => "Asia/Novokuznetsk",
            TimeZone::AsiaNovosibirsk => "Asia/Novosibirsk",
            TimeZone::AsiaOmsk => "Asia/Omsk",
            TimeZone::AsiaOral => "Asia/Oral",
            TimeZone::AsiaPhnomPenh => "Asia/Phnom_Penh",
            TimeZone::AsiaPontianak => "Asia/Pontianak",
            TimeZone::AsiaPyongyang => "Asia/Pyongyang",
            TimeZone::AsiaQatar => "Asia/Qatar",
            TimeZone::AsiaQostanay => "Asia/Qostanay",
            TimeZone::AsiaQyzylorda => "Asia/Qyzylorda",
            TimeZone::AsiaRangoon => "Asia/Rangoon",
            TimeZone::AsiaRiyadh => "Asia/Riyadh",
            TimeZone::AsiaSaigon => "Asia/Saigon",
            TimeZone::AsiaSakhalin => "Asia/Sakhalin",
            TimeZone::AsiaSamarkand => "Asia/Samarkand",
            TimeZone::AsiaSeoul => "Asia/Seoul",
            TimeZone::AsiaShanghai => "Asia/Shanghai",
            TimeZone::AsiaSingapore => "Asia/Singapore",
            TimeZone::AsiaSrednekolymsk => "Asia/Srednekolymsk",
            TimeZone::AsiaTaipei => "Asia/Taipei",
            TimeZone::AsiaTashkent => "Asia/Tashkent",
            TimeZone::AsiaTbilisi => "Asia/Tbilisi",
            TimeZone::AsiaTehran => "Asia/Tehran",
            TimeZone::AsiaTelAviv => "Asia/Tel_Aviv",
            TimeZone::AsiaThimbu => "Asia/Thimbu",
            TimeZone::AsiaThimphu => "Asia/Thimphu",
            TimeZone::AsiaTokyo => "Asia/Tokyo",
            TimeZone::AsiaTomsk => "Asia/Tomsk",
            TimeZone::AsiaUjungPandang => "Asia/Ujung_Pandang",
            TimeZone::AsiaUlaanbaatar => "Asia/Ulaanbaatar",
            TimeZone::AsiaUlanBator => "Asia/Ulan_Bator",
            TimeZone::AsiaUrumqi => "Asia/Urumqi",
            TimeZone::AsiaUstNera => "Asia/Ust-Nera",
            TimeZone::AsiaVientiane => "Asia/Vientiane",
            TimeZone::AsiaVladivostok => "Asia/Vladivostok",
            TimeZone::AsiaYakutsk => "Asia/Yakutsk",
            TimeZone::AsiaYangon => "Asia/Yangon",
            TimeZone::AsiaYekaterinburg => "Asia/Yekaterinburg",
            TimeZone::AsiaYerevan => "Asia/Yerevan",
            TimeZone::AtlanticAzores => "Atlantic/Azores",
            TimeZone::AtlanticBermuda => "Atlantic/Bermuda",
            TimeZone::AtlanticCanary => "Atlantic/Canary",
            TimeZone::AtlanticCapeVerde => "Atlantic/Cape_Verde",
            TimeZone::AtlanticFaeroe => "Atlantic/Faeroe",
            TimeZone::AtlanticFaroe => "Atlantic/Faroe",
            TimeZone::AtlanticJanMayen => "Atlantic/Jan_Mayen",
            TimeZone::AtlanticMadeira => "Atlantic/Madeira",
            TimeZone::AtlanticReykjavik => "Atlantic/Reykjavik",
            TimeZone::AtlanticSouthGeorgia => "Atlantic/South_Georgia",
            TimeZone::AtlanticStHelena => "Atlantic/St_Helena",
            TimeZone::AtlanticStanley => "Atlantic/Stanley",
            TimeZone::AustraliaACT => "Australia/ACT",
            TimeZone::AustraliaAdelaide => "Australia/Adelaide",
            TimeZone::AustraliaBrisbane => "Australia/Brisbane",
            TimeZone::AustraliaBrokenHill => "Australia/Broken_Hill",
            TimeZone::AustraliaCanberra => "Australia/Canberra",
            TimeZone::AustraliaCurrie => "Australia/Currie",
            TimeZone::AustraliaDarwin => "Australia/Darwin",
            TimeZone::AustraliaEucla => "Australia/Eucla",
            TimeZone::AustraliaHobart => "Australia/Hobart",
            TimeZone::AustraliaLHI => "Australia/LHI",
            TimeZone::AustraliaLindeman => "Australia/Lindeman",
            TimeZone::AustraliaLordHowe => "Australia/Lord_Howe",
            TimeZone::AustraliaMelbourne => "Australia/Melbourne",
            TimeZone::AustraliaNSW => "Australia/NSW",
            TimeZone::AustraliaNorth => "Australia/North",
            TimeZone::AustraliaPerth => "Australia/Perth",
            TimeZone::AustraliaQueensland => "Australia/Queensland",
            TimeZone::AustraliaSouth => "Australia/South",
            TimeZone::AustraliaSydney => "Australia/Sydney",
            TimeZone::AustraliaTasmania => "Australia/Tasmania",
            TimeZone::AustraliaVictoria => "Australia/Victoria",
            TimeZone::AustraliaWest => "Australia/West",
            TimeZone::AustraliaYancowinna => "Australia/Yancowinna",
            TimeZone::BrazilAcre => "Brazil/Acre",
            TimeZone::BrazilDeNoronha => "Brazil/DeNoronha",
            TimeZone::BrazilEast => "Brazil/East",
            TimeZone::BrazilWest => "Brazil/West",
            TimeZone::CET => "CET",
            TimeZone::CST6CDT => "CST6CDT",
            TimeZone::CanadaAtlantic => "Canada/Atlantic",
            TimeZone::CanadaCentral => "Canada/Central",
            TimeZone::CanadaEastern => "Canada/Eastern",
            TimeZone::CanadaMountain => "Canada/Mountain",
            TimeZone::CanadaNewfoundland => "Canada/Newfoundland",
            TimeZone::CanadaPacific => "Canada/Pacific",
            TimeZone::CanadaSaskatchewan => "Canada/Saskatchewan",
            TimeZone::CanadaYukon => "Canada/Yukon",
            TimeZone::ChileContinental => "Chile/Continental",
            TimeZone::ChileEasterIsland => "Chile/EasterIsland",
            TimeZone::Cuba => "Cuba",
            TimeZone::EET => "EET",
            TimeZone::EST => "EST",
            TimeZone::EST5EDT => "EST5EDT",
            TimeZone::Egypt => "Egypt",
            TimeZone::Eire => "Eire",
            TimeZone::EtcGMT => "Etc/GMT",
            TimeZone::EtcGMTPlus0 => "Etc/GMT+0",
            TimeZone::EtcGMTPlus1 => "Etc/GMT+1",
            TimeZone::EtcGMTPlus10 => "Etc/GMT+10",
            TimeZone::EtcGMTPlus11 => "Etc/GMT+11",
            TimeZone::EtcGMTPlus12 => "Etc/GMT+12",
            TimeZone::EtcGMTPlus2 => "Etc/GMT+2",
            TimeZone::EtcGMTPlus3 => "Etc/GMT+3",
            TimeZone::EtcGMTPlus4 => "Etc/GMT+4",
            TimeZone::EtcGMTPlus5 => "Etc/GMT+5",
            TimeZone::EtcGMTPlus6 => "Etc/GMT+6",
            TimeZone::EtcGMTPlus7 => "Etc/GMT+7",
            TimeZone::EtcGMTPlus8 => "Etc/GMT+8",
            TimeZone::EtcGMTPlus9 => "Etc/GMT+9",
            TimeZone::EtcGMTMinus0 => "Etc/GMT-0",
            TimeZone::EtcGMTMinus1 => "Etc/GMT-1",
            TimeZone::EtcGMTMinus10 => "Etc/GMT-10",
            TimeZone::EtcGMTMinus11 => "Etc/GMT-11",
            TimeZone::EtcGMTMinus12 => "Etc/GMT-12",
            TimeZone::EtcGMTMinus13 => "Etc/GMT-13",
            TimeZone::EtcGMTMinus14 => "Etc/GMT-14",
            TimeZone::EtcGMTMinus2 => "Etc/GMT-2",
            TimeZone::EtcGMTMinus3 => "Etc/GMT-3",
            TimeZone::EtcGMTMinus4 => "Etc/GMT-4",
            TimeZone::EtcGMTMinus5 => "Etc/GMT-5",
            TimeZone::EtcGMTMinus6 => "Etc/GMT-6",
            TimeZone::EtcGMTMinus7 => "Etc/GMT-7",
            TimeZone::EtcGMTMinus8 => "Etc/GMT-8",
            TimeZone::EtcGMTMinus9 => "Etc/GMT-9",
            TimeZone::EtcGMT0 => "Etc/GMT0",
            TimeZone::EtcGreenwich => "Etc/Greenwich",
            TimeZone::EtcUCT => "Etc/UCT",
            TimeZone::EtcUTC => "Etc/UTC",
            TimeZone::EtcUniversal => "Etc/Universal",
            TimeZone::EtcZulu => "Etc/Zulu",
            TimeZone::EuropeAmsterdam => "Europe/Amsterdam",
            TimeZone::EuropeAndorra => "Europe/Andorra",
            TimeZone::EuropeAstrakhan => "Europe/Astrakhan",
            TimeZone::EuropeAthens => "Europe/Athens",
            TimeZone::EuropeBelfast => "Europe/Belfast",
            TimeZone::EuropeBelgrade => "Europe/Belgrade",
            TimeZone::EuropeBerlin => "Europe/Berlin",
            TimeZone::EuropeBratislava => "Europe/Bratislava",
            TimeZone::EuropeBrussels => "Europe/Brussels",
            TimeZone::EuropeBucharest => "Europe/Bucharest",
            TimeZone::EuropeBudapest => "Europe/Budapest",
            TimeZone::EuropeBusingen => "Europe/Busingen",
            TimeZone::EuropeChisinau => "Europe/Chisinau",
            TimeZone::EuropeCopenhagen => "Europe/Copenhagen",
            TimeZone::EuropeDublin => "Europe/Dublin",
            TimeZone::EuropeGibraltar => "Europe/Gibraltar",
            TimeZone::EuropeGuernsey => "Europe/Guernsey",
            TimeZone::EuropeHelsinki => "Europe/Helsinki",
            TimeZone::EuropeIsleOfMan => "Europe/Isle_of_Man",
            TimeZone::EuropeIstanbul => "Europe/Istanbul",
            TimeZone::EuropeJersey => "Europe/Jersey",
            TimeZone::EuropeKaliningrad => "Europe/Kaliningrad",
            TimeZone::EuropeKiev => "Europe/Kiev",
            TimeZone::EuropeKirov => "Europe/Kirov",
            TimeZone::EuropeKyiv => "Europe/Kyiv",
            TimeZone::EuropeLisbon => "Europe/Lisbon",
            TimeZone::EuropeLjubljana => "Europe/Ljubljana",
            TimeZone::EuropeLondon => "Europe/London",
            TimeZone::EuropeLuxembourg => "Europe/Luxembourg",
            TimeZone::EuropeMadrid => "Europe/Madrid",
            TimeZone::EuropeMalta => "Europe/Malta",
            TimeZone::EuropeMariehamn => "Europe/Mariehamn",
            TimeZone::EuropeMinsk => "Europe/Minsk",
            TimeZone::EuropeMonaco => "Europe/Monaco",
            TimeZone::EuropeMoscow => "Europe/Moscow",
            TimeZone::EuropeNicosia => "Europe/Nicosia",
            TimeZone::EuropeOslo => "Europe/Oslo",
            TimeZone::EuropeParis => "Europe/Paris",
            TimeZone::EuropePodgorica => "Europe/Podgorica",
            TimeZone::EuropePrague => "Europe/Prague",
            TimeZone::EuropeRiga => "Europe/Riga",
            TimeZone::EuropeRome => "Europe/Rome",
            TimeZone::EuropeSamara => "Europe/Samara",
            TimeZone::EuropeSanMarino => "Europe/San_Marino",
            TimeZone::EuropeSarajevo => "Europe/Sarajevo",
            TimeZone::EuropeSaratov => "Europe/Saratov",
            TimeZone::EuropeSimferopol => "Europe/Simferopol",
            TimeZone::EuropeSkopje => "Europe/Skopje",
            TimeZone::EuropeSofia => "Europe/Sofia",
            TimeZone::EuropeStockholm => "Europe/Stockholm",
            TimeZone::EuropeTallinn => "Europe/Tallinn",
            TimeZone::EuropeTirane => "Europe/Tirane",
            TimeZone::EuropeTiraspol => "Europe/Tiraspol",
            TimeZone::EuropeUlyanovsk => "Europe/Ulyanovsk",
            TimeZone::EuropeUzhgorod => "Europe/Uzhgorod",
            TimeZone::EuropeVaduz => "Europe/Vaduz",
            TimeZone::EuropeVatican => "Europe/Vatican",
            TimeZone::EuropeVienna => "Europe/Vienna",
            TimeZone::EuropeVilnius => "Europe/Vilnius",
            TimeZone::EuropeVolgograd => "Europe/Volgograd",
            TimeZone::EuropeWarsaw => "Europe/Warsaw",
            TimeZone::EuropeZagreb => "Europe/Zagreb",
            TimeZone::EuropeZaporozhye => "Europe/Zaporozhye",
            TimeZone::EuropeZurich => "Europe/Zurich",
            TimeZone::Factory => "Factory",
            TimeZone::GB => "GB",
            TimeZone::GBEire => "GB-Eire",
            TimeZone::GMT => "GMT",
            TimeZone::GMTPlus0 => "GMT+0",
            TimeZone::GMTMinus0 => "GMT-0",
            TimeZone::GMT0 => "GMT0",
            TimeZone::Greenwich => "Greenwich",
            TimeZone::HST => "HST",
            TimeZone::Hongkong => "Hongkong",
            TimeZone::Iceland => "Iceland",
            TimeZone::IndianAntananarivo => "Indian/Antananarivo",
            TimeZone::IndianChagos => "Indian/Chagos",
            TimeZone::IndianChristmas => "Indian/Christmas",
            TimeZone::IndianCocos => "Indian/Cocos",
            TimeZone::IndianComoro => "Indian/Comoro",
            TimeZone::IndianKerguelen => "Indian/Kerguelen",
            TimeZone::IndianMahe => "Indian/Mahe",
            TimeZone::IndianMaldives => "Indian/Maldives",
            TimeZone::IndianMauritius => "Indian/Mauritius",
            TimeZone::IndianMayotte => "Indian/Mayotte",
            TimeZone::IndianReunion => "Indian/Reunion",
            TimeZone::Iran => "Iran",
            TimeZone::Israel => "Israel",
            TimeZone::Jamaica => "Jamaica",
            TimeZone::Japan => "Japan",
            TimeZone::Kwajalein => "Kwajalein",
            TimeZone::Libya => "Libya",
            TimeZone::MET => "MET",
            TimeZone::MST => "MST",
            TimeZone::MST7MDT => "MST7MDT",
            TimeZone::MexicoBajaNorte => "Mexico/BajaNorte",
            TimeZone::MexicoBajaSur => "Mexico/BajaSur",
            TimeZone::MexicoGeneral => "Mexico/General",
            TimeZone::NZ => "NZ",
            TimeZone::NZCHAT => "NZ-CHAT",
            TimeZone::Navajo => "Navajo",
            TimeZone::PRC => "PRC",
            TimeZone::PST8PDT => "PST8PDT",
            TimeZone::PacificApia => "Pacific/Apia",
            TimeZone::PacificAuckland => "Pacific/Auckland",
            TimeZone::PacificBougainville => "Pacific/Bougainville",
            TimeZone::PacificChatham => "Pacific/Chatham",
            TimeZone::PacificChuuk => "Pacific/Chuuk",
            TimeZone::PacificEaster => "Pacific/Easter",
            TimeZone::PacificEfate => "Pacific/Efate",
            TimeZone::PacificEnderbury => "Pacific/Enderbury",
            TimeZone::PacificFakaofo => "Pacific/Fakaofo",
            TimeZone::PacificFiji => "Pacific/Fiji",
            TimeZone::PacificFunafuti => "Pacific/Funafuti",
            TimeZone::PacificGalapagos => "Pacific/Galapagos",
            TimeZone::PacificGambier => "Pacific/Gambier",
            TimeZone::PacificGuadalcanal => "Pacific/Guadalcanal",
            TimeZone::PacificGuam => "Pacific/Guam",
            TimeZone::PacificHonolulu => "Pacific/Honolulu",
            TimeZone::PacificJohnston => "Pacific/Johnston",
            TimeZone::PacificKanton => "Pacific/Kanton",
            TimeZone::PacificKiritimati => "Pacific/Kiritimati",
            TimeZone::PacificKosrae => "Pacific/Kosrae",
            TimeZone::PacificKwajalein => "Pacific/Kwajalein",
            TimeZone::PacificMajuro => "Pacific/Majuro",
            TimeZone::PacificMarquesas => "Pacific/Marquesas",
            TimeZone::PacificMidway => "Pacific/Midway",
            TimeZone::PacificNauru => "Pacific/Nauru",
            TimeZone::PacificNiue => "Pacific/Niue",
            TimeZone::PacificNorfolk => "Pacific/Norfolk",
            TimeZone::PacificNoumea => "Pacific/Noumea",
            TimeZone::PacificPagoPago => "Pacific/Pago_Pago",
            TimeZone::PacificPalau => "Pacific/Palau",
            TimeZone::PacificPitcairn => "Pacific/Pitcairn",
            TimeZone::PacificPohnpei => "Pacific/Pohnpei",
            TimeZone::PacificPonape => "Pacific/Ponape",
            TimeZone::PacificPortMoresby => "Pacific/Port_Moresby",
            TimeZone::PacificRarotonga => "Pacific/Rarotonga",
            TimeZone::PacificSaipan => "Pacific/Saipan",
            TimeZone::PacificSamoa => "Pacific/Samoa",
            TimeZone::PacificTahiti => "Pacific/Tahiti",
            TimeZone::PacificTarawa => "Pacific/Tarawa",
            TimeZone::PacificTongatapu => "Pacific/Tongatapu",
            TimeZone::PacificTruk => "Pacific/Truk",
            TimeZone::PacificWake => "Pacific/Wake",
            TimeZone::PacificWallis => "Pacific/Wallis",
            TimeZone::PacificYap => "Pacific/Yap",
            TimeZone::Poland => "Poland",
            TimeZone::Portugal => "Portugal",
            TimeZone::ROC => "ROC",
            TimeZone::ROK => "ROK",
            TimeZone::Singapore => "Singapore",
            TimeZone::Turkey => "Turkey",
            TimeZone::UCT => "UCT",
            TimeZone::USAlaska => "US/Alaska",
            TimeZone::USAleutian => "US/Aleutian",
            TimeZone::USArizona => "US/Arizona",
            TimeZone::USCentral => "US/Central",
            TimeZone::USEastIndiana => "US/East-Indiana",
            TimeZone::USEastern => "US/Eastern",
            TimeZone::USHawaii => "US/Hawaii",
            TimeZone::USIndianaStarke => "US/Indiana-Starke",
            TimeZone::USMichigan => "US/Michigan",
            TimeZone::USMountain => "US/Mountain",
            TimeZone::USPacific => "US/Pacific",
            TimeZone::USSamoa => "US/Samoa",
            TimeZone::UTC => "UTC",
            TimeZone::Universal => "Universal",
            TimeZone::WSU => "W-SU",
            TimeZone::WET => "WET",
            TimeZone::Zulu => "Zulu",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TimeZone::AfricaAbidjan),
            1 => Some(TimeZone::AfricaAccra),
            2 => Some(TimeZone::AfricaAddisAbaba),
            3 => Some(TimeZone::AfricaAlgiers),
            4 => Some(TimeZone::AfricaAsmara),
            5 => Some(TimeZone::AfricaAsmera),
            6 => Some(TimeZone::AfricaBamako),
            7 => Some(TimeZone::AfricaBangui),
            8 => Some(TimeZone::AfricaBanjul),
            9 => Some(TimeZone::AfricaBissau),
            10 => Some(TimeZone::AfricaBlantyre),
            11 => Some(TimeZone::AfricaBrazzaville),
            12 => Some(TimeZone::AfricaBujumbura),
            13 => Some(TimeZone::AfricaCairo),
            14 => Some(TimeZone::AfricaCasablanca),
            15 => Some(TimeZone::AfricaCeuta),
            16 => Some(TimeZone::AfricaConakry),
            17 => Some(TimeZone::AfricaDakar),
            18 => Some(TimeZone::AfricaDarEsSalaam),
            19 => Some(TimeZone::AfricaDjibouti),
            20 => Some(TimeZone::AfricaDouala),
            21 => Some(TimeZone::AfricaElAaiun),
            22 => Some(TimeZone::AfricaFreetown),
            23 => Some(TimeZone::AfricaGaborone),
            24 => Some(TimeZone::AfricaHarare),
            25 => Some(TimeZone::AfricaJohannesburg),
            26 => Some(TimeZone::AfricaJuba),
            27 => Some(TimeZone::AfricaKampala),
            28 => Some(TimeZone::AfricaKhartoum),
            29 => Some(TimeZone::AfricaKigali),
            30 => Some(TimeZone::AfricaKinshasa),
            31 => Some(TimeZone::AfricaLagos),
            32 => Some(TimeZone::AfricaLibreville),
            33 => Some(TimeZone::AfricaLome),
            34 => Some(TimeZone::AfricaLuanda),
            35 => Some(TimeZone::AfricaLubumbashi),
            36 => Some(TimeZone::AfricaLusaka),
            37 => Some(TimeZone::AfricaMalabo),
            38 => Some(TimeZone::AfricaMaputo),
            39 => Some(TimeZone::AfricaMaseru),
            40 => Some(TimeZone::AfricaMbabane),
            41 => Some(TimeZone::AfricaMogadishu),
            42 => Some(TimeZone::AfricaMonrovia),
            43 => Some(TimeZone::AfricaNairobi),
            44 => Some(TimeZone::AfricaNdjamena),
            45 => Some(TimeZone::AfricaNiamey),
            46 => Some(TimeZone::AfricaNouakchott),
            47 => Some(TimeZone::AfricaOuagadougou),
            48 => Some(TimeZone::AfricaPortoNovo),
            49 => Some(TimeZone::AfricaSaoTome),
            50 => Some(TimeZone::AfricaTimbuktu),
            51 => Some(TimeZone::AfricaTripoli),
            52 => Some(TimeZone::AfricaTunis),
            53 => Some(TimeZone::AfricaWindhoek),
            54 => Some(TimeZone::AmericaAdak),
            55 => Some(TimeZone::AmericaAnchorage),
            56 => Some(TimeZone::AmericaAnguilla),
            57 => Some(TimeZone::AmericaAntigua),
            58 => Some(TimeZone::AmericaAraguaina),
            59 => Some(TimeZone::AmericaArgentinaBuenosAires),
            60 => Some(TimeZone::AmericaArgentinaCatamarca),
            61 => Some(TimeZone::AmericaArgentinaComodRivadavia),
            62 => Some(TimeZone::AmericaArgentinaCordoba),
            63 => Some(TimeZone::AmericaArgentinaJujuy),
            64 => Some(TimeZone::AmericaArgentinaLaRioja),
            65 => Some(TimeZone::AmericaArgentinaMendoza),
            66 => Some(TimeZone::AmericaArgentinaRioGallegos),
            67 => Some(TimeZone::AmericaArgentinaSalta),
            68 => Some(TimeZone::AmericaArgentinaSanJuan),
            69 => Some(TimeZone::AmericaArgentinaSanLuis),
            70 => Some(TimeZone::AmericaArgentinaTucuman),
            71 => Some(TimeZone::AmericaArgentinaUshuaia),
            72 => Some(TimeZone::AmericaAruba),
            73 => Some(TimeZone::AmericaAsuncion),
            74 => Some(TimeZone::AmericaAtikokan),
            75 => Some(TimeZone::AmericaAtka),
            76 => Some(TimeZone::AmericaBahia),
            77 => Some(TimeZone::AmericaBahiaBanderas),
            78 => Some(TimeZone::AmericaBarbados),
            79 => Some(TimeZone::AmericaBelem),
            80 => Some(TimeZone::AmericaBelize),
            81 => Some(TimeZone::AmericaBlancSablon),
            82 => Some(TimeZone::AmericaBoaVista),
            83 => Some(TimeZone::AmericaBogota),
            84 => Some(TimeZone::AmericaBoise),
            85 => Some(TimeZone::AmericaBuenosAires),
            86 => Some(TimeZone::AmericaCambridgeBay),
            87 => Some(TimeZone::AmericaCampoGrande),
            88 => Some(TimeZone::AmericaCancun),
            89 => Some(TimeZone::AmericaCaracas),
            90 => Some(TimeZone::AmericaCatamarca),
            91 => Some(TimeZone::AmericaCayenne),
            92 => Some(TimeZone::AmericaCayman),
            93 => Some(TimeZone::AmericaChicago),
            94 => Some(TimeZone::AmericaChihuahua),
            95 => Some(TimeZone::AmericaCiudadJuarez),
            96 => Some(TimeZone::AmericaCoralHarbour),
            97 => Some(TimeZone::AmericaCordoba),
            98 => Some(TimeZone::AmericaCostaRica),
            99 => Some(TimeZone::AmericaCoyhaique),
            100 => Some(TimeZone::AmericaCreston),
            101 => Some(TimeZone::AmericaCuiaba),
            102 => Some(TimeZone::AmericaCuracao),
            103 => Some(TimeZone::AmericaDanmarkshavn),
            104 => Some(TimeZone::AmericaDawson),
            105 => Some(TimeZone::AmericaDawsonCreek),
            106 => Some(TimeZone::AmericaDenver),
            107 => Some(TimeZone::AmericaDetroit),
            108 => Some(TimeZone::AmericaDominica),
            109 => Some(TimeZone::AmericaEdmonton),
            110 => Some(TimeZone::AmericaEirunepe),
            111 => Some(TimeZone::AmericaElSalvador),
            112 => Some(TimeZone::AmericaEnsenada),
            113 => Some(TimeZone::AmericaFortNelson),
            114 => Some(TimeZone::AmericaFortWayne),
            115 => Some(TimeZone::AmericaFortaleza),
            116 => Some(TimeZone::AmericaGlaceBay),
            117 => Some(TimeZone::AmericaGodthab),
            118 => Some(TimeZone::AmericaGooseBay),
            119 => Some(TimeZone::AmericaGrandTurk),
            120 => Some(TimeZone::AmericaGrenada),
            121 => Some(TimeZone::AmericaGuadeloupe),
            122 => Some(TimeZone::AmericaGuatemala),
            123 => Some(TimeZone::AmericaGuayaquil),
            124 => Some(TimeZone::AmericaGuyana),
            125 => Some(TimeZone::AmericaHalifax),
            126 => Some(TimeZone::AmericaHavana),
            127 => Some(TimeZone::AmericaHermosillo),
            128 => Some(TimeZone::AmericaIndianaIndianapolis),
            129 => Some(TimeZone::AmericaIndianaKnox),
            130 => Some(TimeZone::AmericaIndianaMarengo),
            131 => Some(TimeZone::AmericaIndianaPetersburg),
            132 => Some(TimeZone::AmericaIndianaTellCity),
            133 => Some(TimeZone::AmericaIndianaVevay),
            134 => Some(TimeZone::AmericaIndianaVincennes),
            135 => Some(TimeZone::AmericaIndianaWinamac),
            136 => Some(TimeZone::AmericaIndianapolis),
            137 => Some(TimeZone::AmericaInuvik),
            138 => Some(TimeZone::AmericaIqaluit),
            139 => Some(TimeZone::AmericaJamaica),
            140 => Some(TimeZone::AmericaJujuy),
            141 => Some(TimeZone::AmericaJuneau),
            142 => Some(TimeZone::AmericaKentuckyLouisville),
            143 => Some(TimeZone::AmericaKentuckyMonticello),
            144 => Some(TimeZone::AmericaKnoxIN),
            145 => Some(TimeZone::AmericaKralendijk),
            146 => Some(TimeZone::AmericaLaPaz),
            147 => Some(TimeZone::AmericaLima),
            148 => Some(TimeZone::AmericaLosAngeles),
            149 => Some(TimeZone::AmericaLouisville),
            150 => Some(TimeZone::AmericaLowerPrinces),
            151 => Some(TimeZone::AmericaMaceio),
            152 => Some(TimeZone::AmericaManagua),
            153 => Some(TimeZone::AmericaManaus),
            154 => Some(TimeZone::AmericaMarigot),
            155 => Some(TimeZone::AmericaMartinique),
            156 => Some(TimeZone::AmericaMatamoros),
            157 => Some(TimeZone::AmericaMazatlan),
            158 => Some(TimeZone::AmericaMendoza),
            159 => Some(TimeZone::AmericaMenominee),
            160 => Some(TimeZone::AmericaMerida),
            161 => Some(TimeZone::AmericaMetlakatla),
            162 => Some(TimeZone::AmericaMexicoCity),
            163 => Some(TimeZone::AmericaMiquelon),
            164 => Some(TimeZone::AmericaMoncton),
            165 => Some(TimeZone::AmericaMonterrey),
            166 => Some(TimeZone::AmericaMontevideo),
            167 => Some(TimeZone::AmericaMontreal),
            168 => Some(TimeZone::AmericaMontserrat),
            169 => Some(TimeZone::AmericaNassau),
            170 => Some(TimeZone::AmericaNewYork),
            171 => Some(TimeZone::AmericaNipigon),
            172 => Some(TimeZone::AmericaNome),
            173 => Some(TimeZone::AmericaNoronha),
            174 => Some(TimeZone::AmericaNorthDakotaBeulah),
            175 => Some(TimeZone::AmericaNorthDakotaCenter),
            176 => Some(TimeZone::AmericaNorthDakotaNewSalem),
            177 => Some(TimeZone::AmericaNuuk),
            178 => Some(TimeZone::AmericaOjinaga),
            179 => Some(TimeZone::AmericaPanama),
            180 => Some(TimeZone::AmericaPangnirtung),
            181 => Some(TimeZone::AmericaParamaribo),
            182 => Some(TimeZone::AmericaPhoenix),
            183 => Some(TimeZone::AmericaPortAuPrince),
            184 => Some(TimeZone::AmericaPortOfSpain),
            185 => Some(TimeZone::AmericaPortoAcre),
            186 => Some(TimeZone::AmericaPortoVelho),
            187 => Some(TimeZone::AmericaPuertoRico),
            188 => Some(TimeZone::AmericaPuntaArenas),
            189 => Some(TimeZone::AmericaRainyRiver),
            190 => Some(TimeZone::AmericaRankinInlet),
            191 => Some(TimeZone::AmericaRecife),
            192 => Some(TimeZone::AmericaRegina),
            193 => Some(TimeZone::AmericaResolute),
            194 => Some(TimeZone::AmericaRioBranco),
            195 => Some(TimeZone::AmericaRosario),
            196 => Some(TimeZone::AmericaSantaIsabel),
            197 => Some(TimeZone::AmericaSantarem),
            198 => Some(TimeZone::AmericaSantiago),
            199 => Some(TimeZone::AmericaSantoDomingo),
            200 => Some(TimeZone::AmericaSaoPaulo),
            201 => Some(TimeZone::AmericaScoresbysund),
            202 => Some(TimeZone::AmericaShiprock),
            203 => Some(TimeZone::AmericaSitka),
            204 => Some(TimeZone::AmericaStBarthelemy),
            205 => Some(TimeZone::AmericaStJohns),
            206 => Some(TimeZone::AmericaStKitts),
            207 => Some(TimeZone::AmericaStLucia),
            208 => Some(TimeZone::AmericaStThomas),
            209 => Some(TimeZone::AmericaStVincent),
            210 => Some(TimeZone::AmericaSwiftCurrent),
            211 => Some(TimeZone::AmericaTegucigalpa),
            212 => Some(TimeZone::AmericaThule),
            213 => Some(TimeZone::AmericaThunderBay),
            214 => Some(TimeZone::AmericaTijuana),
            215 => Some(TimeZone::AmericaToronto),
            216 => Some(TimeZone::AmericaTortola),
            217 => Some(TimeZone::AmericaVancouver),
            218 => Some(TimeZone::AmericaVirgin),
            219 => Some(TimeZone::AmericaWhitehorse),
            220 => Some(TimeZone::AmericaWinnipeg),
            221 => Some(TimeZone::AmericaYakutat),
            222 => Some(TimeZone::AmericaYellowknife),
            223 => Some(TimeZone::AntarcticaCasey),
            224 => Some(TimeZone::AntarcticaDavis),
            225 => Some(TimeZone::AntarcticaDumontDUrville),
            226 => Some(TimeZone::AntarcticaMacquarie),
            227 => Some(TimeZone::AntarcticaMawson),
            228 => Some(TimeZone::AntarcticaMcMurdo),
            229 => Some(TimeZone::AntarcticaPalmer),
            230 => Some(TimeZone::AntarcticaRothera),
            231 => Some(TimeZone::AntarcticaSouthPole),
            232 => Some(TimeZone::AntarcticaSyowa),
            233 => Some(TimeZone::AntarcticaTroll),
            234 => Some(TimeZone::AntarcticaVostok),
            235 => Some(TimeZone::ArcticLongyearbyen),
            236 => Some(TimeZone::AsiaAden),
            237 => Some(TimeZone::AsiaAlmaty),
            238 => Some(TimeZone::AsiaAmman),
            239 => Some(TimeZone::AsiaAnadyr),
            240 => Some(TimeZone::AsiaAqtau),
            241 => Some(TimeZone::AsiaAqtobe),
            242 => Some(TimeZone::AsiaAshgabat),
            243 => Some(TimeZone::AsiaAshkhabad),
            244 => Some(TimeZone::AsiaAtyrau),
            245 => Some(TimeZone::AsiaBaghdad),
            246 => Some(TimeZone::AsiaBahrain),
            247 => Some(TimeZone::AsiaBaku),
            248 => Some(TimeZone::AsiaBangkok),
            249 => Some(TimeZone::AsiaBarnaul),
            250 => Some(TimeZone::AsiaBeirut),
            251 => Some(TimeZone::AsiaBishkek),
            252 => Some(TimeZone::AsiaBrunei),
            253 => Some(TimeZone::AsiaCalcutta),
            254 => Some(TimeZone::AsiaChita),
            255 => Some(TimeZone::AsiaChoibalsan),
            256 => Some(TimeZone::AsiaChongqing),
            257 => Some(TimeZone::AsiaChungking),
            258 => Some(TimeZone::AsiaColombo),
            259 => Some(TimeZone::AsiaDacca),
            260 => Some(TimeZone::AsiaDamascus),
            261 => Some(TimeZone::AsiaDhaka),
            262 => Some(TimeZone::AsiaDili),
            263 => Some(TimeZone::AsiaDubai),
            264 => Some(TimeZone::AsiaDushanbe),
            265 => Some(TimeZone::AsiaFamagusta),
            266 => Some(TimeZone::AsiaGaza),
            267 => Some(TimeZone::AsiaHarbin),
            268 => Some(TimeZone::AsiaHebron),
            269 => Some(TimeZone::AsiaHoChiMinh),
            270 => Some(TimeZone::AsiaHongKong),
            271 => Some(TimeZone::AsiaHovd),
            272 => Some(TimeZone::AsiaIrkutsk),
            273 => Some(TimeZone::AsiaIstanbul),
            274 => Some(TimeZone::AsiaJakarta),
            275 => Some(TimeZone::AsiaJayapura),
            276 => Some(TimeZone::AsiaJerusalem),
            277 => Some(TimeZone::AsiaKabul),
            278 => Some(TimeZone::AsiaKamchatka),
            279 => Some(TimeZone::AsiaKarachi),
            280 => Some(TimeZone::AsiaKashgar),
            281 => Some(TimeZone::AsiaKathmandu),
            282 => Some(TimeZone::AsiaKatmandu),
            283 => Some(TimeZone::AsiaKhandyga),
            284 => Some(TimeZone::AsiaKolkata),
            285 => Some(TimeZone::AsiaKrasnoyarsk),
            286 => Some(TimeZone::AsiaKualaLumpur),
            287 => Some(TimeZone::AsiaKuching),
            288 => Some(TimeZone::AsiaKuwait),
            289 => Some(TimeZone::AsiaMacao),
            290 => Some(TimeZone::AsiaMacau),
            291 => Some(TimeZone::AsiaMagadan),
            292 => Some(TimeZone::AsiaMakassar),
            293 => Some(TimeZone::AsiaManila),
            294 => Some(TimeZone::AsiaMuscat),
            295 => Some(TimeZone::AsiaNicosia),
            296 => Some(TimeZone::AsiaNovokuznetsk),
            297 => Some(TimeZone::AsiaNovosibirsk),
            298 => Some(TimeZone::AsiaOmsk),
            299 => Some(TimeZone::AsiaOral),
            300 => Some(TimeZone::AsiaPhnomPenh),
            301 => Some(TimeZone::AsiaPontianak),
            302 => Some(TimeZone::AsiaPyongyang),
            303 => Some(TimeZone::AsiaQatar),
            304 => Some(TimeZone::AsiaQostanay),
            305 => Some(TimeZone::AsiaQyzylorda),
            306 => Some(TimeZone::AsiaRangoon),
            307 => Some(TimeZone::AsiaRiyadh),
            308 => Some(TimeZone::AsiaSaigon),
            309 => Some(TimeZone::AsiaSakhalin),
            310 => Some(TimeZone::AsiaSamarkand),
            311 => Some(TimeZone::AsiaSeoul),
            312 => Some(TimeZone::AsiaShanghai),
            313 => Some(TimeZone::AsiaSingapore),
            314 => Some(TimeZone::AsiaSrednekolymsk),
            315 => Some(TimeZone::AsiaTaipei),
            316 => Some(TimeZone::AsiaTashkent),
            317 => Some(TimeZone::AsiaTbilisi),
            318 => Some(TimeZone::AsiaTehran),
            319 => Some(TimeZone::AsiaTelAviv),
            320 => Some(TimeZone::AsiaThimbu),
            321 => Some(TimeZone::AsiaThimphu),
            322 => Some(TimeZone::AsiaTokyo),
            323 => Some(TimeZone::AsiaTomsk),
            324 => Some(TimeZone::AsiaUjungPandang),
            325 => Some(TimeZone::AsiaUlaanbaatar),
            326 => Some(TimeZone::AsiaUlanBator),
            327 => Some(TimeZone::AsiaUrumqi),
            328 => Some(TimeZone::AsiaUstNera),
            329 => Some(TimeZone::AsiaVientiane),
            330 => Some(TimeZone::AsiaVladivostok),
            331 => Some(TimeZone::AsiaYakutsk),
            332 => Some(TimeZone::AsiaYangon),
            333 => Some(TimeZone::AsiaYekaterinburg),
            334 => Some(TimeZone::AsiaYerevan),
            335 => Some(TimeZone::AtlanticAzores),
            336 => Some(TimeZone::AtlanticBermuda),
            337 => Some(TimeZone::AtlanticCanary),
            338 => Some(TimeZone::AtlanticCapeVerde),
            339 => Some(TimeZone::AtlanticFaeroe),
            340 => Some(TimeZone::AtlanticFaroe),
            341 => Some(TimeZone::AtlanticJanMayen),
            342 => Some(TimeZone::AtlanticMadeira),
            343 => Some(TimeZone::AtlanticReykjavik),
            344 => Some(TimeZone::AtlanticSouthGeorgia),
            345 => Some(TimeZone::AtlanticStHelena),
            346 => Some(TimeZone::AtlanticStanley),
            347 => Some(TimeZone::AustraliaACT),
            348 => Some(TimeZone::AustraliaAdelaide),
            349 => Some(TimeZone::AustraliaBrisbane),
            350 => Some(TimeZone::AustraliaBrokenHill),
            351 => Some(TimeZone::AustraliaCanberra),
            352 => Some(TimeZone::AustraliaCurrie),
            353 => Some(TimeZone::AustraliaDarwin),
            354 => Some(TimeZone::AustraliaEucla),
            355 => Some(TimeZone::AustraliaHobart),
            356 => Some(TimeZone::AustraliaLHI),
            357 => Some(TimeZone::AustraliaLindeman),
            358 => Some(TimeZone::AustraliaLordHowe),
            359 => Some(TimeZone::AustraliaMelbourne),
            360 => Some(TimeZone::AustraliaNSW),
            361 => Some(TimeZone::AustraliaNorth),
            362 => Some(TimeZone::AustraliaPerth),
            363 => Some(TimeZone::AustraliaQueensland),
            364 => Some(TimeZone::AustraliaSouth),
            365 => Some(TimeZone::AustraliaSydney),
            366 => Some(TimeZone::AustraliaTasmania),
            367 => Some(TimeZone::AustraliaVictoria),
            368 => Some(TimeZone::AustraliaWest),
            369 => Some(TimeZone::AustraliaYancowinna),
            370 => Some(TimeZone::BrazilAcre),
            371 => Some(TimeZone::BrazilDeNoronha),
            372 => Some(TimeZone::BrazilEast),
            373 => Some(TimeZone::BrazilWest),
            374 => Some(TimeZone::CET),
            375 => Some(TimeZone::CST6CDT),
            376 => Some(TimeZone::CanadaAtlantic),
            377 => Some(TimeZone::CanadaCentral),
            378 => Some(TimeZone::CanadaEastern),
            379 => Some(TimeZone::CanadaMountain),
            380 => Some(TimeZone::CanadaNewfoundland),
            381 => Some(TimeZone::CanadaPacific),
            382 => Some(TimeZone::CanadaSaskatchewan),
            383 => Some(TimeZone::CanadaYukon),
            384 => Some(TimeZone::ChileContinental),
            385 => Some(TimeZone::ChileEasterIsland),
            386 => Some(TimeZone::Cuba),
            387 => Some(TimeZone::EET),
            388 => Some(TimeZone::EST),
            389 => Some(TimeZone::EST5EDT),
            390 => Some(TimeZone::Egypt),
            391 => Some(TimeZone::Eire),
            392 => Some(TimeZone::EtcGMT),
            393 => Some(TimeZone::EtcGMTPlus0),
            394 => Some(TimeZone::EtcGMTPlus1),
            395 => Some(TimeZone::EtcGMTPlus10),
            396 => Some(TimeZone::EtcGMTPlus11),
            397 => Some(TimeZone::EtcGMTPlus12),
            398 => Some(TimeZone::EtcGMTPlus2),
            399 => Some(TimeZone::EtcGMTPlus3),
            400 => Some(TimeZone::EtcGMTPlus4),
            401 => Some(TimeZone::EtcGMTPlus5),
            402 => Some(TimeZone::EtcGMTPlus6),
            403 => Some(TimeZone::EtcGMTPlus7),
            404 => Some(TimeZone::EtcGMTPlus8),
            405 => Some(TimeZone::EtcGMTPlus9),
            406 => Some(TimeZone::EtcGMTMinus0),
            407 => Some(TimeZone::EtcGMTMinus1),
            408 => Some(TimeZone::EtcGMTMinus10),
            409 => Some(TimeZone::EtcGMTMinus11),
            410 => Some(TimeZone::EtcGMTMinus12),
            411 => Some(TimeZone::EtcGMTMinus13),
            412 => Some(TimeZone::EtcGMTMinus14),
            413 => Some(TimeZone::EtcGMTMinus2),
            414 => Some(TimeZone::EtcGMTMinus3),
            415 => Some(TimeZone::EtcGMTMinus4),
            416 => Some(TimeZone::EtcGMTMinus5),
            417 => Some(TimeZone::EtcGMTMinus6),
            418 => Some(TimeZone::EtcGMTMinus7),
            419 => Some(TimeZone::EtcGMTMinus8),
            420 => Some(TimeZone::EtcGMTMinus9),
            421 => Some(TimeZone::EtcGMT0),
            422 => Some(TimeZone::EtcGreenwich),
            423 => Some(TimeZone::EtcUCT),
            424 => Some(TimeZone::EtcUTC),
            425 => Some(TimeZone::EtcUniversal),
            426 => Some(TimeZone::EtcZulu),
            427 => Some(TimeZone::EuropeAmsterdam),
            428 => Some(TimeZone::EuropeAndorra),
            429 => Some(TimeZone::EuropeAstrakhan),
            430 => Some(TimeZone::EuropeAthens),
            431 => Some(TimeZone::EuropeBelfast),
            432 => Some(TimeZone::EuropeBelgrade),
            433 => Some(TimeZone::EuropeBerlin),
            434 => Some(TimeZone::EuropeBratislava),
            435 => Some(TimeZone::EuropeBrussels),
            436 => Some(TimeZone::EuropeBucharest),
            437 => Some(TimeZone::EuropeBudapest),
            438 => Some(TimeZone::EuropeBusingen),
            439 => Some(TimeZone::EuropeChisinau),
            440 => Some(TimeZone::EuropeCopenhagen),
            441 => Some(TimeZone::EuropeDublin),
            442 => Some(TimeZone::EuropeGibraltar),
            443 => Some(TimeZone::EuropeGuernsey),
            444 => Some(TimeZone::EuropeHelsinki),
            445 => Some(TimeZone::EuropeIsleOfMan),
            446 => Some(TimeZone::EuropeIstanbul),
            447 => Some(TimeZone::EuropeJersey),
            448 => Some(TimeZone::EuropeKaliningrad),
            449 => Some(TimeZone::EuropeKiev),
            450 => Some(TimeZone::EuropeKirov),
            451 => Some(TimeZone::EuropeKyiv),
            452 => Some(TimeZone::EuropeLisbon),
            453 => Some(TimeZone::EuropeLjubljana),
            454 => Some(TimeZone::EuropeLondon),
            455 => Some(TimeZone::EuropeLuxembourg),
            456 => Some(TimeZone::EuropeMadrid),
            457 => Some(TimeZone::EuropeMalta),
            458 => Some(TimeZone::EuropeMariehamn),
            459 => Some(TimeZone::EuropeMinsk),
            460 => Some(TimeZone::EuropeMonaco),
            461 => Some(TimeZone::EuropeMoscow),
            462 => Some(TimeZone::EuropeNicosia),
            463 => Some(TimeZone::EuropeOslo),
            464 => Some(TimeZone::EuropeParis),
            465 => Some(TimeZone::EuropePodgorica),
            466 => Some(TimeZone::EuropePrague),
            467 => Some(TimeZone::EuropeRiga),
            468 => Some(TimeZone::EuropeRome),
            469 => Some(TimeZone::EuropeSamara),
            470 => Some(TimeZone::EuropeSanMarino),
            471 => Some(TimeZone::EuropeSarajevo),
            472 => Some(TimeZone::EuropeSaratov),
            473 => Some(TimeZone::EuropeSimferopol),
            474 => Some(TimeZone::EuropeSkopje),
            475 => Some(TimeZone::EuropeSofia),
            476 => Some(TimeZone::EuropeStockholm),
            477 => Some(TimeZone::EuropeTallinn),
            478 => Some(TimeZone::EuropeTirane),
            479 => Some(TimeZone::EuropeTiraspol),
            480 => Some(TimeZone::EuropeUlyanovsk),
            481 => Some(TimeZone::EuropeUzhgorod),
            482 => Some(TimeZone::EuropeVaduz),
            483 => Some(TimeZone::EuropeVatican),
            484 => Some(TimeZone::EuropeVienna),
            485 => Some(TimeZone::EuropeVilnius),
            486 => Some(TimeZone::EuropeVolgograd),
            487 => Some(TimeZone::EuropeWarsaw),
            488 => Some(TimeZone::EuropeZagreb),
            489 => Some(TimeZone::EuropeZaporozhye),
            490 => Some(TimeZone::EuropeZurich),
            491 => Some(TimeZone::Factory),
            492 => Some(TimeZone::GB),
            493 => Some(TimeZone::GBEire),
            494 => Some(TimeZone::GMT),
            495 => Some(TimeZone::GMTPlus0),
            496 => Some(TimeZone::GMTMinus0),
            497 => Some(TimeZone::GMT0),
            498 => Some(TimeZone::Greenwich),
            499 => Some(TimeZone::HST),
            500 => Some(TimeZone::Hongkong),
            501 => Some(TimeZone::Iceland),
            502 => Some(TimeZone::IndianAntananarivo),
            503 => Some(TimeZone::IndianChagos),
            504 => Some(TimeZone::IndianChristmas),
            505 => Some(TimeZone::IndianCocos),
            506 => Some(TimeZone::IndianComoro),
            507 => Some(TimeZone::IndianKerguelen),
            508 => Some(TimeZone::IndianMahe),
            509 => Some(TimeZone::IndianMaldives),
            510 => Some(TimeZone::IndianMauritius),
            511 => Some(TimeZone::IndianMayotte),
            512 => Some(TimeZone::IndianReunion),
            513 => Some(TimeZone::Iran),
            514 => Some(TimeZone::Israel),
            515 => Some(TimeZone::Jamaica),
            516 => Some(TimeZone::Japan),
            517 => Some(TimeZone::Kwajalein),
            518 => Some(TimeZone::Libya),
            519 => Some(TimeZone::MET),
            520 => Some(TimeZone::MST),
            521 => Some(TimeZone::MST7MDT),
            522 => Some(TimeZone::MexicoBajaNorte),
            523 => Some(TimeZone::MexicoBajaSur),
            524 => Some(TimeZone::MexicoGeneral),
            525 => Some(TimeZone::NZ),
            526 => Some(TimeZone::NZCHAT),
            527 => Some(TimeZone::Navajo),
            528 => Some(TimeZone::PRC),
            529 => Some(TimeZone::PST8PDT),
            530 => Some(TimeZone::PacificApia),
            531 => Some(TimeZone::PacificAuckland),
            532 => Some(TimeZone::PacificBougainville),
            533 => Some(TimeZone::PacificChatham),
            534 => Some(TimeZone::PacificChuuk),
            535 => Some(TimeZone::PacificEaster),
            536 => Some(TimeZone::PacificEfate),
            537 => Some(TimeZone::PacificEnderbury),
            538 => Some(TimeZone::PacificFakaofo),
            539 => Some(TimeZone::PacificFiji),
            540 => Some(TimeZone::PacificFunafuti),
            541 => Some(TimeZone::PacificGalapagos),
            542 => Some(TimeZone::PacificGambier),
            543 => Some(TimeZone::PacificGuadalcanal),
            544 => Some(TimeZone::PacificGuam),
            545 => Some(TimeZone::PacificHonolulu),
            546 => Some(TimeZone::PacificJohnston),
            547 => Some(TimeZone::PacificKanton),
            548 => Some(TimeZone::PacificKiritimati),
            549 => Some(TimeZone::PacificKosrae),
            550 => Some(TimeZone::PacificKwajalein),
            551 => Some(TimeZone::PacificMajuro),
            552 => Some(TimeZone::PacificMarquesas),
            553 => Some(TimeZone::PacificMidway),
            554 => Some(TimeZone::PacificNauru),
            555 => Some(TimeZone::PacificNiue),
            556 => Some(TimeZone::PacificNorfolk),
            557 => Some(TimeZone::PacificNoumea),
            558 => Some(TimeZone::PacificPagoPago),
            559 => Some(TimeZone::PacificPalau),
            560 => Some(TimeZone::PacificPitcairn),
            561 => Some(TimeZone::PacificPohnpei),
            562 => Some(TimeZone::PacificPonape),
            563 => Some(TimeZone::PacificPortMoresby),
            564 => Some(TimeZone::PacificRarotonga),
            565 => Some(TimeZone::PacificSaipan),
            566 => Some(TimeZone::PacificSamoa),
            567 => Some(TimeZone::PacificTahiti),
            568 => Some(TimeZone::PacificTarawa),
            569 => Some(TimeZone::PacificTongatapu),
            570 => Some(TimeZone::PacificTruk),
            571 => Some(TimeZone::PacificWake),
            572 => Some(TimeZone::PacificWallis),
            573 => Some(TimeZone::PacificYap),
            574 => Some(TimeZone::Poland),
            575 => Some(TimeZone::Portugal),
            576 => Some(TimeZone::ROC),
            577 => Some(TimeZone::ROK),
            578 => Some(TimeZone::Singapore),
            579 => Some(TimeZone::Turkey),
            580 => Some(TimeZone::UCT),
            581 => Some(TimeZone::USAlaska),
            582 => Some(TimeZone::USAleutian),
            583 => Some(TimeZone::USArizona),
            584 => Some(TimeZone::USCentral),
            585 => Some(TimeZone::USEastIndiana),
            586 => Some(TimeZone::USEastern),
            587 => Some(TimeZone::USHawaii),
            588 => Some(TimeZone::USIndianaStarke),
            589 => Some(TimeZone::USMichigan),
            590 => Some(TimeZone::USMountain),
            591 => Some(TimeZone::USPacific),
            592 => Some(TimeZone::USSamoa),
            593 => Some(TimeZone::UTC),
            594 => Some(TimeZone::Universal),
            595 => Some(TimeZone::WSU),
            596 => Some(TimeZone::WET),
            597 => Some(TimeZone::Zulu),
            _ => None,
        }
    }

    const COUNT: usize = 598;
}

impl serde::Serialize for TimeZone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TimeZone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TlsCipherSuite {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"tls13-aes-256-gcm-sha384" => TlsCipherSuite::Tls13Aes256GcmSha384,
            b"tls13-aes-128-gcm-sha256" => TlsCipherSuite::Tls13Aes128GcmSha256,
            b"tls13-chacha20-poly1305-sha256" => TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
            b"tls-ecdhe-ecdsa-with-aes-256-gcm-sha384" => TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
            b"tls-ecdhe-ecdsa-with-aes-128-gcm-sha256" => TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
            b"tls-ecdhe-ecdsa-with-chacha20-poly1305-sha256" => TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256,
            b"tls-ecdhe-rsa-with-aes-256-gcm-sha384" => TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
            b"tls-ecdhe-rsa-with-aes-128-gcm-sha256" => TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
            b"tls-ecdhe-rsa-with-chacha20-poly1305-sha256" => TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TlsCipherSuite::Tls13Aes256GcmSha384 => "tls13-aes-256-gcm-sha384",
            TlsCipherSuite::Tls13Aes128GcmSha256 => "tls13-aes-128-gcm-sha256",
            TlsCipherSuite::Tls13Chacha20Poly1305Sha256 => "tls13-chacha20-poly1305-sha256",
            TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384 => {
                "tls-ecdhe-ecdsa-with-aes-256-gcm-sha384"
            }
            TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256 => {
                "tls-ecdhe-ecdsa-with-aes-128-gcm-sha256"
            }
            TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
                "tls-ecdhe-ecdsa-with-chacha20-poly1305-sha256"
            }
            TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                "tls-ecdhe-rsa-with-aes-256-gcm-sha384"
            }
            TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256 => {
                "tls-ecdhe-rsa-with-aes-128-gcm-sha256"
            }
            TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
                "tls-ecdhe-rsa-with-chacha20-poly1305-sha256"
            }
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TlsCipherSuite::Tls13Aes256GcmSha384),
            1 => Some(TlsCipherSuite::Tls13Aes128GcmSha256),
            2 => Some(TlsCipherSuite::Tls13Chacha20Poly1305Sha256),
            3 => Some(TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384),
            4 => Some(TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256),
            5 => Some(TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256),
            6 => Some(TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384),
            7 => Some(TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256),
            8 => Some(TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256),
            _ => None,
        }
    }

    const COUNT: usize = 9;
}

impl serde::Serialize for TlsCipherSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TlsCipherSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TlsPolicyType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"tlsa" => TlsPolicyType::Tlsa,
            b"sts" => TlsPolicyType::Sts,
            b"noPolicyFound" => TlsPolicyType::NoPolicyFound,
            b"other" => TlsPolicyType::Other,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TlsPolicyType::Tlsa => "tlsa",
            TlsPolicyType::Sts => "sts",
            TlsPolicyType::NoPolicyFound => "noPolicyFound",
            TlsPolicyType::Other => "other",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TlsPolicyType::Tlsa),
            1 => Some(TlsPolicyType::Sts),
            2 => Some(TlsPolicyType::NoPolicyFound),
            3 => Some(TlsPolicyType::Other),
            _ => None,
        }
    }

    const COUNT: usize = 4;
}

impl serde::Serialize for TlsPolicyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TlsPolicyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TlsResultType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"startTlsNotSupported" => TlsResultType::StartTlsNotSupported,
            b"certificateHostMismatch" => TlsResultType::CertificateHostMismatch,
            b"certificateExpired" => TlsResultType::CertificateExpired,
            b"certificateNotTrusted" => TlsResultType::CertificateNotTrusted,
            b"validationFailure" => TlsResultType::ValidationFailure,
            b"tlsaInvalid" => TlsResultType::TlsaInvalid,
            b"dnssecInvalid" => TlsResultType::DnssecInvalid,
            b"daneRequired" => TlsResultType::DaneRequired,
            b"stsPolicyFetchError" => TlsResultType::StsPolicyFetchError,
            b"stsPolicyInvalid" => TlsResultType::StsPolicyInvalid,
            b"stsWebpkiInvalid" => TlsResultType::StsWebpkiInvalid,
            b"other" => TlsResultType::Other,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TlsResultType::StartTlsNotSupported => "startTlsNotSupported",
            TlsResultType::CertificateHostMismatch => "certificateHostMismatch",
            TlsResultType::CertificateExpired => "certificateExpired",
            TlsResultType::CertificateNotTrusted => "certificateNotTrusted",
            TlsResultType::ValidationFailure => "validationFailure",
            TlsResultType::TlsaInvalid => "tlsaInvalid",
            TlsResultType::DnssecInvalid => "dnssecInvalid",
            TlsResultType::DaneRequired => "daneRequired",
            TlsResultType::StsPolicyFetchError => "stsPolicyFetchError",
            TlsResultType::StsPolicyInvalid => "stsPolicyInvalid",
            TlsResultType::StsWebpkiInvalid => "stsWebpkiInvalid",
            TlsResultType::Other => "other",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TlsResultType::StartTlsNotSupported),
            1 => Some(TlsResultType::CertificateHostMismatch),
            2 => Some(TlsResultType::CertificateExpired),
            3 => Some(TlsResultType::CertificateNotTrusted),
            4 => Some(TlsResultType::ValidationFailure),
            5 => Some(TlsResultType::TlsaInvalid),
            6 => Some(TlsResultType::DnssecInvalid),
            7 => Some(TlsResultType::DaneRequired),
            8 => Some(TlsResultType::StsPolicyFetchError),
            9 => Some(TlsResultType::StsPolicyInvalid),
            10 => Some(TlsResultType::StsWebpkiInvalid),
            11 => Some(TlsResultType::Other),
            _ => None,
        }
    }

    const COUNT: usize = 12;
}

impl serde::Serialize for TlsResultType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TlsResultType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TlsVersion {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"tls12" => TlsVersion::Tls12,
            b"tls13" => TlsVersion::Tls13,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls12 => "tls12",
            TlsVersion::Tls13 => "tls13",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TlsVersion::Tls12),
            1 => Some(TlsVersion::Tls13),
            _ => None,
        }
    }

    const COUNT: usize = 2;
}

impl serde::Serialize for TlsVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TlsVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TraceValueType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"String" => TraceValueType::String,
            b"UnsignedInt" => TraceValueType::UnsignedInt,
            b"Integer" => TraceValueType::Integer,
            b"Boolean" => TraceValueType::Boolean,
            b"Float" => TraceValueType::Float,
            b"UTCDateTime" => TraceValueType::UTCDateTime,
            b"Duration" => TraceValueType::Duration,
            b"IpAddr" => TraceValueType::IpAddr,
            b"List" => TraceValueType::List,
            b"Event" => TraceValueType::Event,
            b"Null" => TraceValueType::Null,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TraceValueType::String => "String",
            TraceValueType::UnsignedInt => "UnsignedInt",
            TraceValueType::Integer => "Integer",
            TraceValueType::Boolean => "Boolean",
            TraceValueType::Float => "Float",
            TraceValueType::UTCDateTime => "UTCDateTime",
            TraceValueType::Duration => "Duration",
            TraceValueType::IpAddr => "IpAddr",
            TraceValueType::List => "List",
            TraceValueType::Event => "Event",
            TraceValueType::Null => "Null",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TraceValueType::String),
            1 => Some(TraceValueType::UnsignedInt),
            2 => Some(TraceValueType::Integer),
            3 => Some(TraceValueType::Boolean),
            4 => Some(TraceValueType::Float),
            5 => Some(TraceValueType::UTCDateTime),
            6 => Some(TraceValueType::Duration),
            7 => Some(TraceValueType::IpAddr),
            8 => Some(TraceValueType::List),
            9 => Some(TraceValueType::Event),
            10 => Some(TraceValueType::Null),
            _ => None,
        }
    }

    const COUNT: usize = 11;
}

impl serde::Serialize for TraceValueType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TraceValueType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TracerType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Log" => TracerType::Log,
            b"Stdout" => TracerType::Stdout,
            b"Journal" => TracerType::Journal,
            b"OtelHttp" => TracerType::OtelHttp,
            b"OtelGrpc" => TracerType::OtelGrpc,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TracerType::Log => "Log",
            TracerType::Stdout => "Stdout",
            TracerType::Journal => "Journal",
            TracerType::OtelHttp => "OtelHttp",
            TracerType::OtelGrpc => "OtelGrpc",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TracerType::Log),
            1 => Some(TracerType::Stdout),
            2 => Some(TracerType::Journal),
            3 => Some(TracerType::OtelHttp),
            4 => Some(TracerType::OtelGrpc),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for TracerType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TracerType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TracingLevel {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"error" => TracingLevel::Error,
            b"warn" => TracingLevel::Warn,
            b"info" => TracingLevel::Info,
            b"debug" => TracingLevel::Debug,
            b"trace" => TracingLevel::Trace,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TracingLevel::Error => "error",
            TracingLevel::Warn => "warn",
            TracingLevel::Info => "info",
            TracingLevel::Debug => "debug",
            TracingLevel::Trace => "trace",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TracingLevel::Error),
            1 => Some(TracingLevel::Warn),
            2 => Some(TracingLevel::Info),
            3 => Some(TracingLevel::Debug),
            4 => Some(TracingLevel::Trace),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for TracingLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TracingLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TracingLevelOpt {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"disable" => TracingLevelOpt::Disable,
            b"error" => TracingLevelOpt::Error,
            b"warn" => TracingLevelOpt::Warn,
            b"info" => TracingLevelOpt::Info,
            b"debug" => TracingLevelOpt::Debug,
            b"trace" => TracingLevelOpt::Trace,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TracingLevelOpt::Disable => "disable",
            TracingLevelOpt::Error => "error",
            TracingLevelOpt::Warn => "warn",
            TracingLevelOpt::Info => "info",
            TracingLevelOpt::Debug => "debug",
            TracingLevelOpt::Trace => "trace",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TracingLevelOpt::Disable),
            1 => Some(TracingLevelOpt::Error),
            2 => Some(TracingLevelOpt::Warn),
            3 => Some(TracingLevelOpt::Info),
            4 => Some(TracingLevelOpt::Debug),
            5 => Some(TracingLevelOpt::Trace),
            _ => None,
        }
    }

    const COUNT: usize = 6;
}

impl serde::Serialize for TracingLevelOpt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TracingLevelOpt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TracingStoreType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"Disabled" => TracingStoreType::Disabled,
            b"Default" => TracingStoreType::Default,
            b"FoundationDb" => TracingStoreType::FoundationDb,
            b"PostgreSql" => TracingStoreType::PostgreSql,
            b"MySql" => TracingStoreType::MySql,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TracingStoreType::Disabled => "Disabled",
            TracingStoreType::Default => "Default",
            TracingStoreType::FoundationDb => "FoundationDb",
            TracingStoreType::PostgreSql => "PostgreSql",
            TracingStoreType::MySql => "MySql",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TracingStoreType::Disabled),
            1 => Some(TracingStoreType::Default),
            2 => Some(TracingStoreType::FoundationDb),
            3 => Some(TracingStoreType::PostgreSql),
            4 => Some(TracingStoreType::MySql),
            _ => None,
        }
    }

    const COUNT: usize = 5;
}

impl serde::Serialize for TracingStoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TracingStoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for TsigAlgorithm {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"hmac-md5" => TsigAlgorithm::HmacMd5,
            b"gss" => TsigAlgorithm::Gss,
            b"hmac-sha1" => TsigAlgorithm::HmacSha1,
            b"hmac-sha224" => TsigAlgorithm::HmacSha224,
            b"hmac-sha256" => TsigAlgorithm::HmacSha256,
            b"hmac-sha256-128" => TsigAlgorithm::HmacSha256128,
            b"hmac-sha384" => TsigAlgorithm::HmacSha384,
            b"hmac-sha384-192" => TsigAlgorithm::HmacSha384192,
            b"hmac-sha512" => TsigAlgorithm::HmacSha512,
            b"hmac-sha512-256" => TsigAlgorithm::HmacSha512256,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TsigAlgorithm::HmacMd5 => "hmac-md5",
            TsigAlgorithm::Gss => "gss",
            TsigAlgorithm::HmacSha1 => "hmac-sha1",
            TsigAlgorithm::HmacSha224 => "hmac-sha224",
            TsigAlgorithm::HmacSha256 => "hmac-sha256",
            TsigAlgorithm::HmacSha256128 => "hmac-sha256-128",
            TsigAlgorithm::HmacSha384 => "hmac-sha384",
            TsigAlgorithm::HmacSha384192 => "hmac-sha384-192",
            TsigAlgorithm::HmacSha512 => "hmac-sha512",
            TsigAlgorithm::HmacSha512256 => "hmac-sha512-256",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(TsigAlgorithm::HmacMd5),
            1 => Some(TsigAlgorithm::Gss),
            2 => Some(TsigAlgorithm::HmacSha1),
            3 => Some(TsigAlgorithm::HmacSha224),
            4 => Some(TsigAlgorithm::HmacSha256),
            5 => Some(TsigAlgorithm::HmacSha256128),
            6 => Some(TsigAlgorithm::HmacSha384),
            7 => Some(TsigAlgorithm::HmacSha384192),
            8 => Some(TsigAlgorithm::HmacSha512),
            9 => Some(TsigAlgorithm::HmacSha512256),
            _ => None,
        }
    }

    const COUNT: usize = 10;
}

impl serde::Serialize for TsigAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for TsigAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for UserRolesType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"User" => UserRolesType::User,
            b"Admin" => UserRolesType::Admin,
            b"Custom" => UserRolesType::Custom,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            UserRolesType::User => "User",
            UserRolesType::Admin => "Admin",
            UserRolesType::Custom => "Custom",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(UserRolesType::User),
            1 => Some(UserRolesType::Admin),
            2 => Some(UserRolesType::Custom),
            _ => None,
        }
    }

    const COUNT: usize = 3;
}

impl serde::Serialize for UserRolesType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for UserRolesType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}
