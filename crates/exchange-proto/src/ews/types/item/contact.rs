/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::Guid,
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{
            ContactSource, ContactUrlKey, EmailAddressKey, FileAsMapping, ImAddressKey,
            MailboxType, MemberStatus, PhoneNumberKey, PhysicalAddressIndex, PhysicalAddressKey,
        },
        types::{
            address::{EmailAddress, Recipients, SingleRecipient},
            value::{
                DateTime, EwsValue, List, ListItem, Strings, T, XBinary, ews_fields, fields_value,
            },
        },
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

fn required_key<'x, K>(
    p: &Parser<'x>,
    attrs: &Attrs<'x>,
    parse: fn(&[u8]) -> Option<K>,
) -> Result<K> {
    p.attr_enum(attrs, "Key", parse)?
        .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("Key")))
}

ews_fields! {
    pub struct CompleteName<'x> {
        title: "Title" => Cow<'x, str>,
        first_name: "FirstName" => Cow<'x, str>,
        middle_name: "MiddleName" => Cow<'x, str>,
        last_name: "LastName" => Cow<'x, str>,
        suffix: "Suffix" => Cow<'x, str>,
        initials: "Initials" => Cow<'x, str>,
        full_name: "FullName" => Cow<'x, str>,
        nickname: "Nickname" => Cow<'x, str>,
        yomi_first_name: "YomiFirstName" => Cow<'x, str>,
        yomi_last_name: "YomiLastName" => Cow<'x, str>,
    }
}

fields_value!(CompleteName<'x>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAddressEntry<'x> {
    pub key: EmailAddressKey,
    pub name: Option<Cow<'x, str>>,
    pub routing_type: Option<Cow<'x, str>>,
    pub mailbox_type: Option<MailboxType>,
    pub address: Cow<'x, str>,
}

impl ListItem for EmailAddressEntry<'_> {
    const ITEM: &'static str = "Entry";
}

impl<'x> EwsValue<'x> for EmailAddressEntry<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        Ok(EmailAddressEntry {
            key: required_key(p, attrs, EmailAddressKey::parse)?,
            name: p.attr(attrs, "Name")?,
            routing_type: p.attr(attrs, "RoutingType")?,
            mailbox_type: p.attr_enum(attrs, "MailboxType", MailboxType::parse)?,
            address: p.text()?,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local)
            .attr("Key", self.key.as_str())
            .attr_opt("Name", self.name.as_deref())
            .attr_opt("RoutingType", self.routing_type.as_deref())
            .attr_opt("MailboxType", self.mailbox_type.map(MailboxType::as_str));
        w.text(&self.address);
        w.end(T, local);
    }
}

macro_rules! keyed_text_entry {
    ($name:ident, $key:ty) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name<'x> {
            pub key: $key,
            pub value: Cow<'x, str>,
        }

        impl ListItem for $name<'_> {
            const ITEM: &'static str = "Entry";
        }

        impl<'x> EwsValue<'x> for $name<'x> {
            fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
                Ok($name {
                    key: required_key(p, attrs, <$key>::parse)?,
                    value: p.text()?,
                })
            }

            fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
                w.start(T, local).attr("Key", self.key.as_str());
                w.text(&self.value);
                w.end(T, local);
            }
        }
    };
}

keyed_text_entry!(PhoneNumberEntry, PhoneNumberKey);
keyed_text_entry!(ImAddressEntry, ImAddressKey);

ews_fields! {
    pub struct PhysicalAddressFields<'x> {
        street: "Street" => Cow<'x, str>,
        city: "City" => Cow<'x, str>,
        state: "State" => Cow<'x, str>,
        country_or_region: "CountryOrRegion" => Cow<'x, str>,
        postal_code: "PostalCode" => Cow<'x, str>,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PhysicalAddressEntry<'x> {
    pub key: PhysicalAddressKey,
    pub fields: PhysicalAddressFields<'x>,
}

impl ListItem for PhysicalAddressEntry<'_> {
    const ITEM: &'static str = "Entry";
}

impl<'x> EwsValue<'x> for PhysicalAddressEntry<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let key = required_key(p, attrs, PhysicalAddressKey::parse)?;
        let mut fields = PhysicalAddressFields::default();
        while let Some(child) = p.child()? {
            if !fields.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        Ok(PhysicalAddressEntry { key, fields })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).attr("Key", self.key.as_str());
        self.fields.write_fields(w);
        w.end(T, local);
    }
}

ews_fields! {
    pub struct ContactUrl<'x> {
        url_type: "Type" => ContactUrlKey,
        name: "Name" => Cow<'x, str>,
        address: "Address" => Cow<'x, str>,
    }
}

fields_value!(ContactUrl<'x>);

impl ListItem for ContactUrl<'_> {
    const ITEM: &'static str = "Url";
}

ews_fields! {
    pub struct ContactFields<'x> {
        file_as: "FileAs" => Cow<'x, str>,
        file_as_mapping: "FileAsMapping" => FileAsMapping,
        display_name: "DisplayName" => Cow<'x, str>,
        given_name: "GivenName" => Cow<'x, str>,
        initials: "Initials" => Cow<'x, str>,
        middle_name: "MiddleName" => Cow<'x, str>,
        nickname: "Nickname" => Cow<'x, str>,
        complete_name: "CompleteName" => CompleteName<'x>,
        company_name: "CompanyName" => Cow<'x, str>,
        email_addresses: "EmailAddresses" => List<EmailAddressEntry<'x>>,
        physical_addresses: "PhysicalAddresses" => List<PhysicalAddressEntry<'x>>,
        phone_numbers: "PhoneNumbers" => List<PhoneNumberEntry<'x>>,
        assistant_name: "AssistantName" => Cow<'x, str>,
        birthday: "Birthday" => DateTime,
        business_home_page: "BusinessHomePage" => Cow<'x, str>,
        children: "Children" => Strings<'x>,
        companies: "Companies" => Strings<'x>,
        contact_source: "ContactSource" => ContactSource,
        department: "Department" => Cow<'x, str>,
        generation: "Generation" => Cow<'x, str>,
        im_addresses: "ImAddresses" => List<ImAddressEntry<'x>>,
        job_title: "JobTitle" => Cow<'x, str>,
        manager: "Manager" => Cow<'x, str>,
        mileage: "Mileage" => Cow<'x, str>,
        office_location: "OfficeLocation" => Cow<'x, str>,
        postal_address_index: "PostalAddressIndex" => PhysicalAddressIndex,
        profession: "Profession" => Cow<'x, str>,
        spouse_name: "SpouseName" => Cow<'x, str>,
        surname: "Surname" => Cow<'x, str>,
        wedding_anniversary: "WeddingAnniversary" => DateTime,
        birthday_local: "BirthdayLocal" => DateTime,
        wedding_anniversary_local: "WeddingAnniversaryLocal" => DateTime,
        has_picture: "HasPicture" => bool,
        phonetic_full_name: "PhoneticFullName" => Cow<'x, str>,
        phonetic_first_name: "PhoneticFirstName" => Cow<'x, str>,
        phonetic_last_name: "PhoneticLastName" => Cow<'x, str>,
        alias: "Alias" => Cow<'x, str>,
        notes: "Notes" => Cow<'x, str>,
        photo: "Photo" => XBinary<'x>,
        user_smime_certificate: "UserSMIMECertificate" => List<XBinary<'x>>,
        ms_exchange_certificate: "MSExchangeCertificate" => List<XBinary<'x>>,
        directory_id: "DirectoryId" => Cow<'x, str>,
        manager_mailbox: "ManagerMailbox" => SingleRecipient<'x>,
        direct_reports: "DirectReports" => Recipients<'x>,
        account_name: "AccountName" => Cow<'x, str>,
        is_auto_update_disabled: "IsAutoUpdateDisabled" => bool,
        is_messenger_enabled: "IsMessengerEnabled" => bool,
        comment: "Comment" => Cow<'x, str>,
        contact_short_id: "ContactShortId" => i32,
        contact_type: "ContactType" => Cow<'x, str>,
        gender: "Gender" => Cow<'x, str>,
        is_hidden: "IsHidden" => bool,
        object_id: "ObjectId" => Cow<'x, str>,
        passport_id: "PassportId" => i64,
        is_private: "IsPrivate" => bool,
        source_id: "SourceId" => Cow<'x, str>,
        trust_level: "TrustLevel" => i32,
        created_by: "CreatedBy" => Cow<'x, str>,
        urls: "Urls" => List<ContactUrl<'x>>,
        cid: "Cid" => i64,
        skype_auth_certificate: "SkypeAuthCertificate" => Cow<'x, str>,
        skype_context: "SkypeContext" => Cow<'x, str>,
        skype_id: "SkypeId" => Cow<'x, str>,
        skype_relationship: "SkypeRelationship" => Cow<'x, str>,
        yomi_nickname: "YomiNickname" => Cow<'x, str>,
        xbox_live_tag: "XboxLiveTag" => Cow<'x, str>,
        invite_free: "InviteFree" => bool,
        hide_presence_and_profile: "HidePresenceAndProfile" => bool,
        is_pending_outbound: "IsPendingOutbound" => bool,
        support_group_feeds: "SupportGroupFeeds" => bool,
        user_tile_hash: "UserTileHash" => Cow<'x, str>,
        unified_inbox: "UnifiedInbox" => bool,
        mris: "Mris" => Strings<'x>,
        wlid: "Wlid" => Cow<'x, str>,
        abch_contact_id: "AbchContactId" => Guid,
        not_in_birthday_calendar: "NotInBirthdayCalendar" => bool,
        shell_contact_type: "ShellContactType" => Cow<'x, str>,
        im_mri: "ImMri" => Cow<'x, str>,
        presence_trust_level: "PresenceTrustLevel" => Cow<'x, str>,
        other_mri: "OtherMri" => Cow<'x, str>,
        profile_last_changed: "ProfileLastChanged" => Cow<'x, str>,
        mobile_im_enabled: "MobileIMEnabled" => bool,
        display_name_prefix: "DisplayNamePrefix" => Cow<'x, str>,
        yomi_given_name: "YomiGivenName" => Cow<'x, str>,
        yomi_surname: "YomiSurname" => Cow<'x, str>,
        personal_notes: "PersonalNotes" => Cow<'x, str>,
        partner_network_profile_photo_url: "PartnerNetworkProfilePhotoUrl" => Cow<'x, str>,
        partner_network_thumbnail_photo_url: "PartnerNetworkThumbnailPhotoUrl" => Cow<'x, str>,
        person_id: "PersonId" => Cow<'x, str>,
        conversation_guid: "ConversationGuid" => Guid,
    }
    skip { "AbchEmailAddresses" }
}

ews_fields! {
    pub struct MemberFields<'x> {
        mailbox: "Mailbox" => EmailAddress<'x>,
        status: "Status" => MemberStatus,
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Member<'x> {
    pub key: Option<Cow<'x, str>>,
    pub fields: MemberFields<'x>,
}

impl ListItem for Member<'_> {
    const ITEM: &'static str = "Member";
}

impl<'x> EwsValue<'x> for Member<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let key = p.attr(attrs, "Key")?;
        let mut fields = MemberFields::default();
        while let Some(child) = p.child()? {
            if !fields.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        Ok(Member { key, fields })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).attr_opt("Key", self.key.as_deref());
        self.fields.write_fields(w);
        w.end(T, local);
    }
}

ews_fields! {
    pub struct DistributionListFields<'x> {
        display_name: "DisplayName" => Cow<'x, str>,
        file_as: "FileAs" => Cow<'x, str>,
        contact_source: "ContactSource" => ContactSource,
        members: "Members" => List<Member<'x>>,
    }
}
