/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::eas_struct;
use crate::eas::tokens::tag::rights_management as rm;
use crate::eas::types::EasDateTime;

eas_struct!(RightsManagementLicense<'a> {
    edit_allowed: bool = rm::EDIT_ALLOWED,
    reply_allowed: bool = rm::REPLY_ALLOWED,
    reply_all_allowed: bool = rm::REPLY_ALL_ALLOWED,
    forward_allowed: bool = rm::FORWARD_ALLOWED,
    modify_recipients_allowed: bool = rm::MODIFY_RECIPIENTS_ALLOWED,
    extract_allowed: bool = rm::EXTRACT_ALLOWED,
    print_allowed: bool = rm::PRINT_ALLOWED,
    export_allowed: bool = rm::EXPORT_ALLOWED,
    programmatic_access_allowed: bool = rm::PROGRAMMATIC_ACCESS_ALLOWED,
    owner: bool = rm::OWNER,
    content_expiry_date: EasDateTime = rm::CONTENT_EXPIRY_DATE,
    template_id: Cow<'a, str> = rm::TEMPLATE_ID,
    template_name: Cow<'a, str> = rm::TEMPLATE_NAME,
    template_description: Cow<'a, str> = rm::TEMPLATE_DESCRIPTION,
    content_owner: Cow<'a, str> = rm::CONTENT_OWNER,
});

eas_struct!(RightsManagementTemplate<'a> {
    template_id: Cow<'a, str> = rm::TEMPLATE_ID,
    template_name: Cow<'a, str> = rm::TEMPLATE_NAME,
    template_description: Cow<'a, str> = rm::TEMPLATE_DESCRIPTION,
});
