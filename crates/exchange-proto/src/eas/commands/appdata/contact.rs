/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Body, List, OrEmpty, eas_struct};
use crate::common::base64::Base64Text;
use crate::eas::tokens::tag::{airsyncbase as asb, contacts as c, contacts2 as c2};
use crate::eas::types::EasDateTime;

pub type Categories<'a> = List<Cow<'a, str>, { c::CATEGORY.raw() }>;
pub type ChildList<'a> = List<Cow<'a, str>, { c::CHILD.raw() }>;

eas_struct!(Contact<'a> {
    body: Body<'a> = asb::BODY,
    anniversary: OrEmpty<EasDateTime> = c::ANNIVERSARY,
    assistant_name: Cow<'a, str> = c::ASSISTANT_NAME,
    assistant_phone_number: Cow<'a, str> = c::ASSISTANT_PHONE_NUMBER,
    birthday: OrEmpty<EasDateTime> = c::BIRTHDAY,
    business2_phone_number: Cow<'a, str> = c::BUSINESS2_PHONE_NUMBER,
    business_address_city: Cow<'a, str> = c::BUSINESS_ADDRESS_CITY,
    business_address_country: Cow<'a, str> = c::BUSINESS_ADDRESS_COUNTRY,
    business_address_postal_code: Cow<'a, str> = c::BUSINESS_ADDRESS_POSTAL_CODE,
    business_address_state: Cow<'a, str> = c::BUSINESS_ADDRESS_STATE,
    business_address_street: Cow<'a, str> = c::BUSINESS_ADDRESS_STREET,
    business_fax_number: Cow<'a, str> = c::BUSINESS_FAX_NUMBER,
    business_phone_number: Cow<'a, str> = c::BUSINESS_PHONE_NUMBER,
    car_phone_number: Cow<'a, str> = c::CAR_PHONE_NUMBER,
    categories: Categories<'a> = c::CATEGORIES,
    children: ChildList<'a> = c::CHILDREN,
    company_name: Cow<'a, str> = c::COMPANY_NAME,
    department: Cow<'a, str> = c::DEPARTMENT,
    email1_address: Cow<'a, str> = c::EMAIL1_ADDRESS,
    email2_address: Cow<'a, str> = c::EMAIL2_ADDRESS,
    email3_address: Cow<'a, str> = c::EMAIL3_ADDRESS,
    file_as: Cow<'a, str> = c::FILE_AS,
    first_name: Cow<'a, str> = c::FIRST_NAME,
    home2_phone_number: Cow<'a, str> = c::HOME2_PHONE_NUMBER,
    home_address_city: Cow<'a, str> = c::HOME_ADDRESS_CITY,
    home_address_country: Cow<'a, str> = c::HOME_ADDRESS_COUNTRY,
    home_address_postal_code: Cow<'a, str> = c::HOME_ADDRESS_POSTAL_CODE,
    home_address_state: Cow<'a, str> = c::HOME_ADDRESS_STATE,
    home_address_street: Cow<'a, str> = c::HOME_ADDRESS_STREET,
    home_fax_number: Cow<'a, str> = c::HOME_FAX_NUMBER,
    home_phone_number: Cow<'a, str> = c::HOME_PHONE_NUMBER,
    job_title: Cow<'a, str> = c::JOB_TITLE,
    last_name: Cow<'a, str> = c::LAST_NAME,
    middle_name: Cow<'a, str> = c::MIDDLE_NAME,
    mobile_phone_number: Cow<'a, str> = c::MOBILE_PHONE_NUMBER,
    office_location: Cow<'a, str> = c::OFFICE_LOCATION,
    other_address_city: Cow<'a, str> = c::OTHER_ADDRESS_CITY,
    other_address_country: Cow<'a, str> = c::OTHER_ADDRESS_COUNTRY,
    other_address_postal_code: Cow<'a, str> = c::OTHER_ADDRESS_POSTAL_CODE,
    other_address_state: Cow<'a, str> = c::OTHER_ADDRESS_STATE,
    other_address_street: Cow<'a, str> = c::OTHER_ADDRESS_STREET,
    pager_number: Cow<'a, str> = c::PAGER_NUMBER,
    radio_phone_number: Cow<'a, str> = c::RADIO_PHONE_NUMBER,
    spouse: Cow<'a, str> = c::SPOUSE,
    suffix: Cow<'a, str> = c::SUFFIX,
    title: Cow<'a, str> = c::TITLE,
    web_page: Cow<'a, str> = c::WEB_PAGE,
    yomi_company_name: Cow<'a, str> = c::YOMI_COMPANY_NAME,
    yomi_first_name: Cow<'a, str> = c::YOMI_FIRST_NAME,
    yomi_last_name: Cow<'a, str> = c::YOMI_LAST_NAME,
    picture: Base64Text<'a> = c::PICTURE,
    alias: Cow<'a, str> = c::ALIAS,
    weighted_rank: i32 = c::WEIGHTED_RANK,
    customer_id: Cow<'a, str> = c2::CUSTOMER_ID,
    government_id: Cow<'a, str> = c2::GOVERNMENT_ID,
    im_address: Cow<'a, str> = c2::IM_ADDRESS,
    im_address2: Cow<'a, str> = c2::IM_ADDRESS2,
    im_address3: Cow<'a, str> = c2::IM_ADDRESS3,
    manager_name: Cow<'a, str> = c2::MANAGER_NAME,
    company_main_phone: Cow<'a, str> = c2::COMPANY_MAIN_PHONE,
    account_name: Cow<'a, str> = c2::ACCOUNT_NAME,
    nick_name: Cow<'a, str> = c2::NICK_NAME,
    mms: Cow<'a, str> = c2::MMS,
    native_body_type: u8 = asb::NATIVE_BODY_TYPE,
});
