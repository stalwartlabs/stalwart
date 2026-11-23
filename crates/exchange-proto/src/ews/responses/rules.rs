/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::types::{
        generated::RuleOperationError,
        rule::Rule,
        value::{EwsValue, M},
    },
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetInboxRulesBody<'x> {
    pub outlook_rule_blob_exists: Option<bool>,
    pub rules: Vec<Rule<'x>>,
}

impl ResponseMessage for GetInboxRulesBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(exists) = self.outlook_rule_blob_exists {
            w.leaf_bool(M, "OutlookRuleBlobExists", exists);
        }
        w.start(M, "InboxRules");
        for rule in &self.rules {
            rule.write(w, "Rule");
        }
        w.end(M, "InboxRules");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpdateInboxRulesBody<'x> {
    pub errors: Vec<RuleOperationError<'x>>,
}

impl ResponseMessage for UpdateInboxRulesBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if !self.errors.is_empty() {
            w.start(M, "RuleOperationErrors");
            for error in &self.errors {
                error.write(w, "RuleOperationError");
            }
            w.end(M, "RuleOperationErrors");
        }
    }
}
