/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::{CalendarScale, elements::Elements};
use jmap_tools::{JsonPointer, Value};
use serde::Serialize;
use std::{
    borrow::Cow,
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
};

pub const JSCONTACT_VERSION: &str = "1.0";

pub mod export;
pub mod import;
pub mod parser;
pub mod types;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[repr(transparent)]
pub struct JSContact<'x, I, B>(pub Value<'x, JSContactProperty<I>, JSContactValue<I, B>>)
where
    I: JSContactId,
    B: JSContactId;

pub trait JSContactId:
    FromStr + Sized + Serialize + Display + Clone + Eq + Hash + Ord + Debug + Default
{
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactValue<I: JSContactId, B: JSContactId> {
    Id(I),
    BlobId(B),
    IdReference(String),
    Timestamp(i64),
    Type(JSContactType),
    GrammaticalGender(JSContactGrammaticalGender),
    Kind(JSContactKind),
    Level(JSContactLevel),
    Relation(JSContactRelation),
    PhoneticSystem(JSContactPhoneticSystem),
    CalendarScale(CalendarScale),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactProperty<I: JSContactId> {
    Type,
    Address,
    AddressBookIds,
    Addresses,
    Anniversaries,
    Author,
    BlobId,
    Calendars,
    CalendarScale,
    Components,
    Contexts,
    ConvertedProperties,
    Coordinates,
    CountryCode,
    Created,
    CryptoKeys,
    Date,
    Day,
    DefaultSeparator,
    Directories,
    Emails,
    Extra,
    Features,
    Full,
    GrammaticalGender,
    Id,
    IsOrdered,
    Keywords,
    Kind,
    Label,
    Language,
    Level,
    Links,
    ListAs,
    Localizations,
    Media,
    MediaType,
    Members,
    Metadata,
    Month,
    Name,
    Nicknames,
    Note,
    Notes,
    Number,
    OnlineServices,
    OrganizationId,
    Organizations,
    Parameters,
    PersonalInfo,
    Phones,
    Phonetic,
    PhoneticScript,
    PhoneticSystem,
    Place,
    Pref,
    PreferredLanguages,
    PrivateMetadata,
    ProdId,
    Pronouns,
    Properties,
    RelatedTo,
    Relation,
    SchedulingAddresses,
    Service,
    SortAs,
    SpeakToAs,
    TimeZone,
    Titles,
    Uid,
    Units,
    Updated,
    Uri,
    User,
    Utc,
    VCard,
    Value,
    Version,
    Year,
    IdValue(I),
    IdReference(String),
    Context(Context),
    Feature(Feature),
    SortAsKind(JSContactKind),
    Pointer(JsonPointer<JSContactProperty<I>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactType {
    Address,
    AddressComponent,
    Anniversary,
    Author,
    Boolean,
    Calendar,
    Card,
    CryptoKey,
    Directory,
    EmailAddress,
    Id,
    Int,
    JCardProp,
    LanguagePref,
    Link,
    Media,
    Name,
    NameComponent,
    Nickname,
    Note,
    Number,
    OnlineService,
    Organization,
    OrgUnit,
    PartialDate,
    PatchObject,
    PersonalInfo,
    Phone,
    Pronouns,
    Relation,
    Resource,
    SchedulingAddress,
    SpeakToAs,
    String,
    Timestamp,
    Title,
    UnsignedInt,
    UTCDateTime,
}

impl FromStr for JSContactType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hashify::map!(s.as_bytes(), JSContactType,
            "Address" => JSContactType::Address,
            "AddressComponent" => JSContactType::AddressComponent,
            "Anniversary" => JSContactType::Anniversary,
            "Author" => JSContactType::Author,
            "Boolean" => JSContactType::Boolean,
            "Calendar" => JSContactType::Calendar,
            "Card" => JSContactType::Card,
            "CryptoKey" => JSContactType::CryptoKey,
            "Directory" => JSContactType::Directory,
            "EmailAddress" => JSContactType::EmailAddress,
            "Id" => JSContactType::Id,
            "Int" => JSContactType::Int,
            "JCardProp" => JSContactType::JCardProp,
            "LanguagePref" => JSContactType::LanguagePref,
            "Link" => JSContactType::Link,
            "Media" => JSContactType::Media,
            "Name" => JSContactType::Name,
            "NameComponent" => JSContactType::NameComponent,
            "Nickname" => JSContactType::Nickname,
            "Note" => JSContactType::Note,
            "Number" => JSContactType::Number,
            "OnlineService" => JSContactType::OnlineService,
            "Organization" => JSContactType::Organization,
            "OrgUnit" => JSContactType::OrgUnit,
            "PartialDate" => JSContactType::PartialDate,
            "PatchObject" => JSContactType::PatchObject,
            "PersonalInfo" => JSContactType::PersonalInfo,
            "Phone" => JSContactType::Phone,
            "Pronouns" => JSContactType::Pronouns,
            "Relation" => JSContactType::Relation,
            "Resource" => JSContactType::Resource,
            "SchedulingAddress" => JSContactType::SchedulingAddress,
            "SpeakToAs" => JSContactType::SpeakToAs,
            "String" => JSContactType::String,
            "Timestamp" => JSContactType::Timestamp,
            "Title" => JSContactType::Title,
            "UnsignedInt" => JSContactType::UnsignedInt,
            "UTCDateTime" => JSContactType::UTCDateTime,
        )
        .copied()
        .ok_or(())
    }
}

impl JSContactType {
    pub fn as_str(&self) -> &'static str {
        match self {
            JSContactType::Address => "Address",
            JSContactType::AddressComponent => "AddressComponent",
            JSContactType::Anniversary => "Anniversary",
            JSContactType::Author => "Author",
            JSContactType::Boolean => "Boolean",
            JSContactType::Calendar => "Calendar",
            JSContactType::Card => "Card",
            JSContactType::CryptoKey => "CryptoKey",
            JSContactType::Directory => "Directory",
            JSContactType::EmailAddress => "EmailAddress",
            JSContactType::Id => "Id",
            JSContactType::Int => "Int",
            JSContactType::JCardProp => "JCardProp",
            JSContactType::LanguagePref => "LanguagePref",
            JSContactType::Link => "Link",
            JSContactType::Media => "Media",
            JSContactType::Name => "Name",
            JSContactType::NameComponent => "NameComponent",
            JSContactType::Nickname => "Nickname",
            JSContactType::Note => "Note",
            JSContactType::Number => "Number",
            JSContactType::OnlineService => "OnlineService",
            JSContactType::Organization => "Organization",
            JSContactType::OrgUnit => "OrgUnit",
            JSContactType::PartialDate => "PartialDate",
            JSContactType::PatchObject => "PatchObject",
            JSContactType::PersonalInfo => "PersonalInfo",
            JSContactType::Phone => "Phone",
            JSContactType::Pronouns => "Pronouns",
            JSContactType::Relation => "Relation",
            JSContactType::Resource => "Resource",
            JSContactType::SchedulingAddress => "SchedulingAddress",
            JSContactType::SpeakToAs => "SpeakToAs",
            JSContactType::String => "String",
            JSContactType::Timestamp => "Timestamp",
            JSContactType::Title => "Title",
            JSContactType::UnsignedInt => "UnsignedInt",
            JSContactType::UTCDateTime => "UTCDateTime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Context {
    Billing,
    Delivery,
    Private,
    Work,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    Fax,
    MainNumber,
    Mobile,
    Pager,
    Text,
    TextPhone,
    Video,
    Voice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactGrammaticalGender {
    Animate,
    Common,
    Feminine,
    Inanimate,
    Masculine,
    Neuter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactKind {
    Apartment,
    Block,
    Building,
    Country,
    Direction,
    District,
    Floor,
    Landmark,
    Locality,
    Name,
    Number,
    Postcode,
    PostOfficeBox,
    Region,
    Room,
    Separator,
    Subdistrict,
    Birth,
    Death,
    Wedding,
    Calendar,
    FreeBusy,
    Application,
    Device,
    Group,
    Individual,
    Location,
    Org,
    Directory,
    Entry,
    Contact,
    Logo,
    Photo,
    Sound,
    Credential,
    Generation,
    Given,
    Given2,
    Surname,
    Surname2,
    Title,
    Expertise,
    Hobby,
    Interest,
    Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactLevel {
    High,
    Low,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactRelation {
    Acquaintance,
    Agent,
    Child,
    Colleague,
    Contact,
    CoResident,
    CoWorker,
    Crush,
    Date,
    Emergency,
    Friend,
    Kin,
    Me,
    Met,
    Muse,
    Neighbor,
    Parent,
    Sibling,
    Spouse,
    Sweetheart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JSContactPhoneticSystem {
    Ipa,
    Jyut,
    Piny,
    Script,
}

#[cfg(all(test, stalwart_tests))]
impl<I, B> std::fmt::Display for JSContact<'_, I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string_pretty(&self.0).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s)
    }
}

impl<T> JSContactId for T where
    T: FromStr + Sized + Serialize + Display + Clone + Eq + Hash + Ord + Debug + Default
{
}

impl<I: JSContactId> From<I> for JSContactProperty<I> {
    fn from(id: I) -> Self {
        JSContactProperty::IdValue(id)
    }
}

impl<I: JSContactId, B: JSContactId> From<I> for JSContactValue<I, B> {
    fn from(id: I) -> Self {
        JSContactValue::Id(id)
    }
}

impl<I: JSContactId, B: JSContactId> JSContact<'_, I, B> {
    pub fn blob_ids(&self) -> impl Iterator<Item = &B> {
        Elements::new(&self.0).filter_map(|element| match element {
            JSContactValue::BlobId(blob_id) => Some(blob_id),
            _ => None,
        })
    }
}

impl<'x, I: JSContactId, B: JSContactId> Default for JSContact<'x, I, B> {
    fn default() -> Self {
        Self(Value::Object(jmap_tools::Map::new()))
    }
}

impl<I: JSContactId> Display for JSContactProperty<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_string().as_ref())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/jscontact/tests.rs"]
mod tests;
