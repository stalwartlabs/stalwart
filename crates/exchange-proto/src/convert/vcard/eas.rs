/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use calcard::{
    common::Data,
    vcard::{VCard, VCardProperty},
};

use super::{
    patch,
    props::{
        ACCOUNT, ASSISTANT, ASSISTANT_TELEPHONE_NUMBER, BIRTHDAY, BODY, BUSINESS_FAX_NUMBER,
        BUSINESS_HOME_PAGE, BUSINESS_TELEPHONE_NUMBER, BUSINESS2_TELEPHONE_NUMBER,
        CALLBACK_TELEPHONE_NUMBER, CAR_TELEPHONE_NUMBER, CHILDRENS_NAMES,
        COMPANY_MAIN_PHONE_NUMBER, COMPANY_NAME, DEPARTMENT_NAME, DISPLAY_NAME,
        DISPLAY_NAME_PREFIX, EMAIL_SLOTS, GENERATION, GIVEN_NAME, HOBBIES, HOME_ADDRESS_CITY,
        HOME_ADDRESS_COUNTRY, HOME_ADDRESS_POSTAL_CODE, HOME_ADDRESS_STATE, HOME_ADDRESS_STREET,
        HOME_FAX_NUMBER, HOME_TELEPHONE_NUMBER, HOME2_TELEPHONE_NUMBER, ISDN_NUMBER,
        LID_FREE_BUSY_LOCATION, LID_INSTANT_MESSAGING_ADDRESS, LID_WORK_ADDRESS_CITY,
        LID_WORK_ADDRESS_COUNTRY, LID_WORK_ADDRESS_POSTAL_CODE, LID_WORK_ADDRESS_STATE,
        LID_WORK_ADDRESS_STREET, MANAGER_NAME, MIDDLE_NAME, MOBILE_TELEPHONE_NUMBER, NICKNAME,
        OTHER_ADDRESS_CITY, OTHER_ADDRESS_COUNTRY, OTHER_ADDRESS_POSTAL_CODE, OTHER_ADDRESS_STATE,
        OTHER_ADDRESS_STREET, OTHER_TELEPHONE_NUMBER, PAGER_TELEPHONE_NUMBER, PERSONAL_HOME_PAGE,
        PRIMARY_FAX_NUMBER, PRIMARY_TELEPHONE_NUMBER, PROFESSION, RADIO_TELEPHONE_NUMBER,
        SPOUSE_NAME, SURNAME, TELEX_NUMBER, TITLE, TTY_TDD_PHONE_NUMBER, WEDDING_ANNIVERSARY,
    },
    related,
    sink::ContactSink,
    to_message,
};
use crate::{
    common::{
        base64::{Base64Text, base64_encode_into},
        time::{FileTime, UtcSeconds},
    },
    convert::{
        ConvertError,
        context::ConvertOptions,
        model::{LossKind, PatchReport, PropBag},
        tags::KEYWORDS_NAME,
    },
    eas::{
        commands::{
            appdata::{Contact, List, OrEmpty},
            sync::Ghosting,
        },
        tokens::tag::{contacts as c, contacts2 as c2},
        types::EasDateTime,
    },
    mapi::prop::{
        OwnedPropValue, PropId, PropKey, PropKeyRef, PropType,
        sets::{PS_PUBLIC_STRINGS, PSETID_ADDRESS},
    },
};

pub const MAX_PICTURE_BYTES: usize = 48 * 1024;
pub const MAX_CHILDREN: usize = 300;

const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EasContact<'c> {
    pub contact: Contact<'c>,
    pub notes: Option<Cow<'c, str>>,
}

#[derive(Debug, Clone, Copy)]
pub struct ContactUpdate<'x> {
    pub contact: &'x Contact<'x>,
    pub notes: Option<&'x str>,
    pub ghosting: Ghosting<'x>,
}

pub fn contact_to_eas<'c>(
    card: &'c VCard,
    opts: &ConvertOptions<'_>,
) -> Result<EasContact<'c>, ConvertError> {
    to_message::build(card, u64::from(opts.max_decoded), EasSink::default()).map(EasSink::finish)
}

pub fn contact_from_eas(
    card: &mut VCard,
    update: &ContactUpdate<'_>,
) -> Result<Option<PatchReport>, ConvertError> {
    let plan = to_message::build(card, u64::MAX, EasSink::default())?.plan(update)?;
    if plan.is_empty() {
        return Ok(None);
    }
    let mut report = patch::contact(card, &plan.props)?;
    if matches!(plan.picture, PictureEdit::Unsupported) {
        report.lossy.insert(LossKind::ContactField);
    }
    plan.apply(card);
    Ok(Some(report))
}

const EMAIL1_ADDRESS: u32 = EMAIL_SLOTS[0].email;
const EMAIL2_ADDRESS: u32 = EMAIL_SLOTS[1].email;
const EMAIL3_ADDRESS: u32 = EMAIL_SLOTS[2].email;

macro_rules! fields {
    (
        tags { $($tag_field:ident = $tag:path => $tag_name:ident @ $tag_eas:path,)* }
        lids { $($lid_field:ident = $lid:path => $lid_name:ident @ $lid_eas:path,)* }
        other_tags { $($other_tag_field:ident = $other_tag:path,)* }
        other_lids { $($other_lid_field:ident = $other_lid:path,)* }
    ) => {
        #[derive(Clone, Copy)]
        enum Field {
            $($tag_field,)*
            $($lid_field,)*
            $($other_tag_field,)*
            $($other_lid_field,)*
        }

        const FIELDS: usize = [
            $(Field::$tag_field,)*
            $(Field::$lid_field,)*
            $(Field::$other_tag_field,)*
            $(Field::$other_lid_field,)*
        ]
        .len();

        impl Field {
            fn of(key: PropKeyRef<'_>) -> Option<Self> {
                match key {
                    PropKeyRef::Tag(id) => match id {
                        $($tag => Some(Field::$tag_field),)*
                        $($other_tag => Some(Field::$other_tag_field),)*
                        _ => None,
                    },
                    PropKeyRef::Lid {
                        set: PSETID_ADDRESS,
                        lid,
                    } => match lid {
                        $($lid => Some(Field::$lid_field),)*
                        $($other_lid => Some(Field::$other_lid_field),)*
                        _ => None,
                    },
                    _ => None,
                }
            }

            fn key(self) -> PropKey {
                match self {
                    $(Field::$tag_field => PropKey::tag($tag),)*
                    $(Field::$other_tag_field => PropKey::tag($other_tag),)*
                    $(Field::$lid_field => PropKey::lid(PSETID_ADDRESS, $lid),)*
                    $(Field::$other_lid_field => PropKey::lid(PSETID_ADDRESS, $other_lid),)*
                }
            }
        }

        impl<'c> EasSink<'c> {
            fn fill(&mut self, contact: &mut Contact<'c>) {
                $(contact.$tag_name = self.take(Field::$tag_field);)*
                $(contact.$lid_name = self.take(Field::$lid_field);)*
            }

            fn diff_fields(&self, contact: &Contact<'_>, ghosting: Ghosting<'_>, props: &mut PropBag) {
                $(self.diff_text(
                    Field::$tag_field,
                    contact.$tag_name.as_deref(),
                    ghosting.ghosts($tag_eas),
                    props,
                );)*
                $(self.diff_text(
                    Field::$lid_field,
                    contact.$lid_name.as_deref().map(|value| Field::$lid_field.incoming(value)),
                    ghosting.ghosts($lid_eas),
                    props,
                );)*
            }
        }
    };
}

fields!(
    tags {
        FirstName = GIVEN_NAME => first_name @ c::FIRST_NAME,
        LastName = SURNAME => last_name @ c::LAST_NAME,
        MiddleName = MIDDLE_NAME => middle_name @ c::MIDDLE_NAME,
        Suffix = GENERATION => suffix @ c::SUFFIX,
        Title = DISPLAY_NAME_PREFIX => title @ c::TITLE,
        JobTitle = TITLE => job_title @ c::JOB_TITLE,
        CompanyName = COMPANY_NAME => company_name @ c::COMPANY_NAME,
        Department = DEPARTMENT_NAME => department @ c::DEPARTMENT,
        AssistantName = ASSISTANT => assistant_name @ c::ASSISTANT_NAME,
        AssistantPhone = ASSISTANT_TELEPHONE_NUMBER => assistant_phone_number @ c::ASSISTANT_PHONE_NUMBER,
        BusinessPhone = BUSINESS_TELEPHONE_NUMBER => business_phone_number @ c::BUSINESS_PHONE_NUMBER,
        Business2Phone = BUSINESS2_TELEPHONE_NUMBER => business2_phone_number @ c::BUSINESS2_PHONE_NUMBER,
        HomePhone = HOME_TELEPHONE_NUMBER => home_phone_number @ c::HOME_PHONE_NUMBER,
        Home2Phone = HOME2_TELEPHONE_NUMBER => home2_phone_number @ c::HOME2_PHONE_NUMBER,
        MobilePhone = MOBILE_TELEPHONE_NUMBER => mobile_phone_number @ c::MOBILE_PHONE_NUMBER,
        CarPhone = CAR_TELEPHONE_NUMBER => car_phone_number @ c::CAR_PHONE_NUMBER,
        RadioPhone = RADIO_TELEPHONE_NUMBER => radio_phone_number @ c::RADIO_PHONE_NUMBER,
        Pager = PAGER_TELEPHONE_NUMBER => pager_number @ c::PAGER_NUMBER,
        BusinessFax = BUSINESS_FAX_NUMBER => business_fax_number @ c::BUSINESS_FAX_NUMBER,
        HomeFax = HOME_FAX_NUMBER => home_fax_number @ c::HOME_FAX_NUMBER,
        CompanyMainPhone = COMPANY_MAIN_PHONE_NUMBER => company_main_phone @ c2::COMPANY_MAIN_PHONE,
        Spouse = SPOUSE_NAME => spouse @ c::SPOUSE,
        ManagerName = MANAGER_NAME => manager_name @ c2::MANAGER_NAME,
        NickName = NICKNAME => nick_name @ c2::NICK_NAME,
        AccountName = ACCOUNT => account_name @ c2::ACCOUNT_NAME,
        FileAs = DISPLAY_NAME => file_as @ c::FILE_AS,
        HomeStreet = HOME_ADDRESS_STREET => home_address_street @ c::HOME_ADDRESS_STREET,
        HomeCity = HOME_ADDRESS_CITY => home_address_city @ c::HOME_ADDRESS_CITY,
        HomeState = HOME_ADDRESS_STATE => home_address_state @ c::HOME_ADDRESS_STATE,
        HomePostalCode = HOME_ADDRESS_POSTAL_CODE => home_address_postal_code @ c::HOME_ADDRESS_POSTAL_CODE,
        HomeCountry = HOME_ADDRESS_COUNTRY => home_address_country @ c::HOME_ADDRESS_COUNTRY,
        OtherStreet = OTHER_ADDRESS_STREET => other_address_street @ c::OTHER_ADDRESS_STREET,
        OtherCity = OTHER_ADDRESS_CITY => other_address_city @ c::OTHER_ADDRESS_CITY,
        OtherState = OTHER_ADDRESS_STATE => other_address_state @ c::OTHER_ADDRESS_STATE,
        OtherPostalCode = OTHER_ADDRESS_POSTAL_CODE => other_address_postal_code @ c::OTHER_ADDRESS_POSTAL_CODE,
        OtherCountry = OTHER_ADDRESS_COUNTRY => other_address_country @ c::OTHER_ADDRESS_COUNTRY,
    }
    lids {
        ImAddress = LID_INSTANT_MESSAGING_ADDRESS => im_address @ c2::IM_ADDRESS,
        Email1 = EMAIL1_ADDRESS => email1_address @ c::EMAIL1_ADDRESS,
        Email2 = EMAIL2_ADDRESS => email2_address @ c::EMAIL2_ADDRESS,
        Email3 = EMAIL3_ADDRESS => email3_address @ c::EMAIL3_ADDRESS,
        BusinessStreet = LID_WORK_ADDRESS_STREET => business_address_street @ c::BUSINESS_ADDRESS_STREET,
        BusinessCity = LID_WORK_ADDRESS_CITY => business_address_city @ c::BUSINESS_ADDRESS_CITY,
        BusinessState = LID_WORK_ADDRESS_STATE => business_address_state @ c::BUSINESS_ADDRESS_STATE,
        BusinessPostalCode = LID_WORK_ADDRESS_POSTAL_CODE => business_address_postal_code @ c::BUSINESS_ADDRESS_POSTAL_CODE,
        BusinessCountry = LID_WORK_ADDRESS_COUNTRY => business_address_country @ c::BUSINESS_ADDRESS_COUNTRY,
    }
    other_tags {
        BusinessHomePage = BUSINESS_HOME_PAGE,
        PersonalHomePage = PERSONAL_HOME_PAGE,
        Notes = BODY,
        IsdnNumber = ISDN_NUMBER,
        PrimaryPhone = PRIMARY_TELEPHONE_NUMBER,
        TtyTddPhone = TTY_TDD_PHONE_NUMBER,
        CallbackPhone = CALLBACK_TELEPHONE_NUMBER,
        OtherPhone = OTHER_TELEPHONE_NUMBER,
        PrimaryFax = PRIMARY_FAX_NUMBER,
        Telex = TELEX_NUMBER,
        Profession = PROFESSION,
        Hobbies = HOBBIES,
    }
    other_lids {
        FreeBusyLocation = LID_FREE_BUSY_LOCATION,
    }
);

impl Field {
    fn incoming(self, value: &str) -> &str {
        match self {
            Field::Email1 | Field::Email2 | Field::Email3 => value
                .rsplit_once('<')
                .and_then(|(_, address)| address.split_once('>'))
                .map_or(value, |(address, _)| address)
                .trim(),
            _ => value,
        }
    }
}

struct EasSink<'c> {
    values: [Option<Cow<'c, str>>; FIELDS],
    birthday: Option<EasDateTime>,
    anniversary: Option<EasDateTime>,
    categories: Option<Vec<Cow<'c, str>>>,
    children: Option<Vec<Cow<'c, str>>>,
    picture: Option<Base64Text<'c>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DateEdit {
    Keep,
    Remove,
}

enum ListEdit {
    Keep,
    Set(Vec<String>),
}

enum PictureEdit {
    Keep,
    Unsupported,
    Remove,
    Set(Box<Data>),
}

struct Plan {
    props: PropBag,
    birthday: DateEdit,
    anniversary: DateEdit,
    children: ListEdit,
    picture: PictureEdit,
}

impl Default for EasSink<'_> {
    fn default() -> Self {
        EasSink {
            values: [const { None }; FIELDS],
            birthday: None,
            anniversary: None,
            categories: None,
            children: None,
            picture: None,
        }
    }
}

impl<'c> EasSink<'c> {
    fn take(&mut self, field: Field) -> Option<Cow<'c, str>> {
        self.values
            .get_mut(field as usize)
            .and_then(Option::take)
            .filter(|value| !value.is_empty())
    }

    fn value(&self, field: Field) -> Option<&str> {
        self.values
            .get(field as usize)
            .and_then(Option::as_deref)
            .filter(|value| !value.is_empty())
    }

    fn finish(mut self) -> EasContact<'c> {
        let mut contact = Contact {
            web_page: self
                .take(Field::BusinessHomePage)
                .or_else(|| self.take(Field::PersonalHomePage)),
            birthday: self.birthday.map(|date| OrEmpty(Some(date))),
            anniversary: self.anniversary.map(|date| OrEmpty(Some(date))),
            categories: self.categories.take().map(List),
            children: self.children.take().map(List),
            picture: self.picture.take(),
            ..Contact::default()
        };
        self.fill(&mut contact);
        EasContact {
            contact,
            notes: self.take(Field::Notes),
        }
    }

    fn plan(&self, update: &ContactUpdate<'_>) -> Result<Plan, ConvertError> {
        let contact = update.contact;
        let ghosting = update.ghosting;
        let mut props = PropBag::new();
        self.diff_fields(contact, ghosting, &mut props);
        self.diff_display_name(contact, &mut props);
        let web_page = match (
            self.value(Field::BusinessHomePage),
            self.value(Field::PersonalHomePage),
        ) {
            (None, Some(_)) => Field::PersonalHomePage,
            _ => Field::BusinessHomePage,
        };
        self.diff_text(
            web_page,
            contact.web_page.as_deref(),
            ghosting.ghosts(c::WEB_PAGE),
            &mut props,
        );
        if let Some(notes) = update.notes {
            self.diff_text(Field::Notes, Some(notes), false, &mut props);
        }
        self.diff_categories(contact, ghosting, &mut props);
        Ok(Plan {
            birthday: diff_date(
                BIRTHDAY,
                self.birthday,
                contact.birthday,
                ghosting.ghosts(c::BIRTHDAY),
                &mut props,
            ),
            anniversary: diff_date(
                WEDDING_ANNIVERSARY,
                self.anniversary,
                contact.anniversary,
                ghosting.ghosts(c::ANNIVERSARY),
                &mut props,
            ),
            children: self.diff_children(contact, ghosting),
            picture: self.diff_picture(contact)?,
            props,
        })
    }

    fn diff_text(&self, field: Field, new: Option<&str>, ghosted: bool, props: &mut PropBag) {
        let old = self.value(field);
        let next = match new {
            Some(new) if !new.is_empty() => {
                if old == Some(new) {
                    return;
                }
                new
            }
            None if ghosted => return,
            _ if old.is_none() => return,
            _ => "",
        };
        props.set(field.key(), OwnedPropValue::Unicode(next.into()));
    }

    fn diff_display_name(&self, contact: &Contact<'_>, props: &mut PropBag) {
        let key = PropKey::tag(DISPLAY_NAME);
        let cleared = match props.get(key.as_ref(), PropType::Unicode) {
            Some(OwnedPropValue::Unicode(value)) => value.is_empty(),
            Some(_) => false,
            None => self.value(Field::FileAs).is_none(),
        };
        if !cleared {
            return;
        }
        match composed_name(contact) {
            Some(name) if self.value(Field::FileAs) != Some(name.as_str()) => {
                props.set(key, OwnedPropValue::Unicode(name.into()));
            }
            _ => {
                props.remove(key.as_ref(), PropType::Unicode);
            }
        }
    }

    fn diff_categories(&self, contact: &Contact<'_>, ghosting: Ghosting<'_>, props: &mut PropBag) {
        let old = self.categories.as_deref().unwrap_or_default();
        let new = match &contact.categories {
            Some(List(new)) => new.as_slice(),
            None if ghosting.ghosts(c::CATEGORIES) => return,
            None => &[],
        };
        if !same_list(old, new) {
            props.set(
                PropKey::name(PS_PUBLIC_STRINGS, KEYWORDS_NAME),
                OwnedPropValue::MvUnicode(
                    new.iter().map(|value| Box::from(value.as_ref())).collect(),
                ),
            );
        }
    }

    fn diff_children(&self, contact: &Contact<'_>, ghosting: Ghosting<'_>) -> ListEdit {
        let old = self.children.as_deref().unwrap_or_default();
        let new = match &contact.children {
            Some(List(new)) => new.as_slice(),
            None if ghosting.ghosts(c::CHILDREN) => return ListEdit::Keep,
            None => &[],
        };
        if same_list(old, new) {
            ListEdit::Keep
        } else {
            ListEdit::Set(
                new.iter()
                    .filter(|child| !child.is_empty())
                    .map(|child| child.to_string())
                    .collect(),
            )
        }
    }

    fn diff_picture(&self, contact: &Contact<'_>) -> Result<PictureEdit, ConvertError> {
        let Some(picture) = &contact.picture else {
            return Ok(PictureEdit::Keep);
        };
        if picture.0.is_empty() {
            return Ok(if self.picture.is_some() {
                PictureEdit::Remove
            } else {
                PictureEdit::Keep
            });
        }
        if self.picture.as_ref() == Some(picture) {
            return Ok(PictureEdit::Keep);
        }
        let mut data = Vec::with_capacity(picture.decoded_len_max().min(MAX_PICTURE_BYTES));
        picture
            .decode_into(&mut data, MAX_PICTURE_BYTES)
            .map_err(|_| ConvertError::TooLarge)?;
        let Some(media) = patch::image_type(&data) else {
            return Ok(PictureEdit::Unsupported);
        };
        Ok(PictureEdit::Set(Box::new(Data {
            content_type: Some(media.to_string()),
            data,
        })))
    }
}

impl Plan {
    fn is_empty(&self) -> bool {
        self.props.is_empty()
            && self.birthday == DateEdit::Keep
            && self.anniversary == DateEdit::Keep
            && matches!(self.children, ListEdit::Keep)
            && matches!(self.picture, PictureEdit::Keep | PictureEdit::Unsupported)
    }

    fn apply(self, card: &mut VCard) {
        if self.birthday == DateEdit::Remove {
            card.entries
                .retain(|entry| entry.name != VCardProperty::Bday);
        }
        if self.anniversary == DateEdit::Remove {
            card.entries.retain(|entry| !is_anniversary(&entry.name));
        }
        if let ListEdit::Set(children) = self.children {
            let mut removed = Vec::new();
            related::rewrite_children(card, children, &mut removed);
            patch::remove_entries(&mut card.entries, removed);
        }
        match self.picture {
            PictureEdit::Keep | PictureEdit::Unsupported => {}
            PictureEdit::Remove => patch::set_photo(card, None),
            PictureEdit::Set(data) => patch::set_photo(card, Some(data)),
        }
    }
}

fn diff_date(
    id: PropId,
    old: Option<EasDateTime>,
    new: Option<OrEmpty<EasDateTime>>,
    ghosted: bool,
    props: &mut PropBag,
) -> DateEdit {
    match new {
        Some(OrEmpty(Some(new))) => {
            let day = nearest_day(new);
            if old.map(nearest_day) != Some(day) {
                props.set(
                    PropKey::tag(id),
                    OwnedPropValue::Time(FileTime::from_utc(
                        UtcSeconds(day.saturating_mul(SECONDS_PER_DAY)),
                        0,
                    )),
                );
            }
            DateEdit::Keep
        }
        Some(OrEmpty(None)) if old.is_some() => DateEdit::Remove,
        Some(OrEmpty(None)) => DateEdit::Keep,
        None if ghosted || old.is_none() => DateEdit::Keep,
        None => DateEdit::Remove,
    }
}

fn nearest_day(time: EasDateTime) -> i64 {
    time.0
        .0
        .saturating_add(SECONDS_PER_DAY / 2)
        .div_euclid(SECONDS_PER_DAY)
}

fn same_list(old: &[Cow<'_, str>], new: &[Cow<'_, str>]) -> bool {
    old.iter()
        .filter(|value| !value.is_empty())
        .eq(new.iter().filter(|value| !value.is_empty()))
}

fn composed_name(contact: &Contact<'_>) -> Option<String> {
    let mut name = String::new();
    for part in [
        &contact.first_name,
        &contact.middle_name,
        &contact.last_name,
    ]
    .into_iter()
    .filter_map(|part| part.as_deref())
    .filter(|part| !part.is_empty())
    {
        if !name.is_empty() {
            name.push(' ');
        }
        name.push_str(part);
    }
    if name.is_empty() {
        name = contact
            .company_name
            .as_deref()
            .filter(|company| !company.is_empty())
            .or_else(|| {
                contact
                    .email1_address
                    .as_deref()
                    .map(|address| Field::Email1.incoming(address))
            })
            .unwrap_or_default()
            .to_string();
    }
    (!name.is_empty()).then_some(name)
}

fn is_anniversary(name: &VCardProperty) -> bool {
    match name {
        VCardProperty::Anniversary => true,
        VCardProperty::Other(name) => {
            hashify::set_ignore_case!(name.as_bytes(), "X-MS-ANNIVERSARY", "X-ANNIVERSARY")
        }
        _ => false,
    }
}

impl<'c> ContactSink<'c> for EasSink<'c> {
    const FULL_MESSAGE: bool = false;
    const BINARY: bool = true;

    fn has(&self, key: PropKeyRef<'_>) -> bool {
        debug_assert!(Field::of(key).is_some());
        Field::of(key)
            .and_then(|field| self.values.get(field as usize))
            .is_some_and(Option::is_some)
    }

    fn text(&mut self, key: PropKeyRef<'static>, value: Cow<'c, str>, _: usize) {
        if let Some(slot) = Field::of(key).and_then(|field| self.values.get_mut(field as usize)) {
            *slot = Some(value);
        }
    }

    fn value(&mut self, key: PropKeyRef<'static>, value: OwnedPropValue, _: usize) {
        let OwnedPropValue::Time(time) = value else {
            return;
        };
        let date = Some(EasDateTime(FileTime::to_utc(time).0, 0));
        match key {
            PropKeyRef::Tag(BIRTHDAY) => self.birthday = date,
            PropKeyRef::Tag(WEDDING_ANNIVERSARY) => self.anniversary = date,
            _ => {}
        }
    }

    fn list(&mut self, key: PropKeyRef<'static>, mut values: Vec<Cow<'c, str>>, _: usize) {
        if key == PropKeyRef::Tag(CHILDRENS_NAMES) && !values.is_empty() {
            values.truncate(MAX_CHILDREN);
            self.children = Some(values);
        }
    }

    fn categories(&mut self, values: Vec<Cow<'c, str>>, _: usize) {
        self.categories = Some(values);
    }

    fn photo(&mut self, _: &'static str, data: &'c [u8]) {
        if data.len() <= MAX_PICTURE_BYTES {
            let mut encoded = Vec::new();
            base64_encode_into(data, &mut encoded);
            self.picture = Some(Base64Text(Cow::Owned(encoded)));
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/vcard/eas/tests.rs"]
mod tests;
