/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::types::{config::UserConfiguration, value::M},
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetUserConfigurationMessage<'x> {
    pub configuration: Option<UserConfiguration<'x>>,
}

impl ResponseMessage for GetUserConfigurationMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(configuration) = &self.configuration {
            w.start(M, "UserConfiguration");
            configuration.write_children(w);
            w.end(M, "UserConfiguration");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetAppManifestsBody;

impl ResponseMessage for GetAppManifestsBody {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.empty_leaf(M, "Apps");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetUserRetentionPolicyTagsBody;

impl ResponseMessage for GetUserRetentionPolicyTagsBody {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.empty_leaf(M, "RetentionPolicyTags");
    }
}
