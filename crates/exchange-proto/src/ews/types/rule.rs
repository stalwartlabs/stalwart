/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    address::EmailAddress,
    ids::{ItemId, TargetFolderId},
    value::{DateTime, EwsValue, Strings, T, ews_fields, ews_struct, fields_value},
};
use crate::{
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        schema::{FlaggedForAction, Importance, Sensitivity},
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Addresses<'x>(pub Vec<EmailAddress<'x>>);

impl<'x> EwsValue<'x> for Addresses<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            if child.local == "Address" {
                p.expect_types(&child)?;
                p.count_id()?;
                list.push(EmailAddress::parse(p, &child.attrs)?);
            } else {
                p.skip()?;
            }
        }
        Ok(Addresses(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for address in &self.0 {
            address.write(w, "Address");
        }
        w.end(T, local);
    }
}

ews_fields! {
    pub struct SizeRange {
        minimum_size: "MinimumSize" => i32,
        maximum_size: "MaximumSize" => i32,
    }
}

fields_value!(SizeRange);

ews_fields! {
    pub struct DateRange {
        start_date_time: "StartDateTime" => DateTime,
        end_date_time: "EndDateTime" => DateTime,
    }
}

fields_value!(DateRange);

ews_fields! {
    pub struct RulePredicates<'x> {
        categories: "Categories" => Strings<'x>,
        contains_body_strings: "ContainsBodyStrings" => Strings<'x>,
        contains_header_strings: "ContainsHeaderStrings" => Strings<'x>,
        contains_recipient_strings: "ContainsRecipientStrings" => Strings<'x>,
        contains_sender_strings: "ContainsSenderStrings" => Strings<'x>,
        contains_subject_or_body_strings: "ContainsSubjectOrBodyStrings" => Strings<'x>,
        contains_subject_strings: "ContainsSubjectStrings" => Strings<'x>,
        flagged_for_action: "FlaggedForAction" => FlaggedForAction,
        from_addresses: "FromAddresses" => Addresses<'x>,
        from_connected_accounts: "FromConnectedAccounts" => Strings<'x>,
        has_attachments: "HasAttachments" => bool,
        importance: "Importance" => Importance,
        is_approval_request: "IsApprovalRequest" => bool,
        is_automatic_forward: "IsAutomaticForward" => bool,
        is_automatic_reply: "IsAutomaticReply" => bool,
        is_encrypted: "IsEncrypted" => bool,
        is_meeting_request: "IsMeetingRequest" => bool,
        is_meeting_response: "IsMeetingResponse" => bool,
        is_ndr: "IsNDR" => bool,
        is_permission_controlled: "IsPermissionControlled" => bool,
        is_read_receipt: "IsReadReceipt" => bool,
        is_signed: "IsSigned" => bool,
        is_voicemail: "IsVoicemail" => bool,
        item_classes: "ItemClasses" => Strings<'x>,
        message_classifications: "MessageClassifications" => Strings<'x>,
        not_sent_to_me: "NotSentToMe" => bool,
        sent_cc_me: "SentCcMe" => bool,
        sent_only_to_me: "SentOnlyToMe" => bool,
        sent_to_addresses: "SentToAddresses" => Addresses<'x>,
        sent_to_me: "SentToMe" => bool,
        sent_to_or_cc_me: "SentToOrCcMe" => bool,
        sensitivity: "Sensitivity" => Sensitivity,
        within_date_range: "WithinDateRange" => DateRange,
        within_size_range: "WithinSizeRange" => SizeRange,
    }
}

fields_value!(RulePredicates<'x>);

ews_fields! {
    pub struct RuleActions<'x> {
        assign_categories: "AssignCategories" => Strings<'x>,
        copy_to_folder: "CopyToFolder" => TargetFolderId<'x>,
        delete: "Delete" => bool,
        forward_as_attachment_to_recipients: "ForwardAsAttachmentToRecipients" => Addresses<'x>,
        forward_to_recipients: "ForwardToRecipients" => Addresses<'x>,
        mark_importance: "MarkImportance" => Importance,
        mark_as_read: "MarkAsRead" => bool,
        move_to_folder: "MoveToFolder" => TargetFolderId<'x>,
        permanent_delete: "PermanentDelete" => bool,
        redirect_to_recipients: "RedirectToRecipients" => Addresses<'x>,
        send_sms_alert_to_recipients: "SendSMSAlertToRecipients" => Addresses<'x>,
        server_reply_with_message: "ServerReplyWithMessage" => ItemId<'x>,
        stop_processing_rules: "StopProcessingRules" => bool,
    }
}

fields_value!(RuleActions<'x>);

ews_struct! {
    pub struct Rule<'x> {
        rule_id: opt "RuleId" => Cow<'x, str>,
        display_name: req "DisplayName" => Cow<'x, str>,
        priority: req "Priority" => i32,
        is_enabled: opt "IsEnabled" => bool,
        is_not_supported: opt "IsNotSupported" => bool,
        is_in_error: opt "IsInError" => bool,
        conditions: opt "Conditions" => RulePredicates<'x>,
        exceptions: opt "Exceptions" => RulePredicates<'x>,
        actions: opt "Actions" => RuleActions<'x>,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleOperation<'a> {
    Create(Rule<'a>),
    Set(Rule<'a>),
    Delete(Cow<'a, str>),
}

#[derive(Clone, Copy)]
enum OperationKind {
    Create,
    Set,
    Delete,
}

impl<'a> RuleOperation<'a> {
    pub fn parse_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(operation) => {
                    p.count_id()?;
                    list.push(operation);
                }
                None => p.skip()?,
            }
        }
        Ok(list)
    }

    fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let Some(kind) = hashify::map!(child.local.as_bytes(), OperationKind,
            "CreateRuleOperation" => OperationKind::Create,
            "SetRuleOperation" => OperationKind::Set,
            "DeleteRuleOperation" => OperationKind::Delete,
        )
        .copied() else {
            return Ok(None);
        };
        p.expect_types(child)?;
        let (element, name) = match kind {
            OperationKind::Delete => ("RuleId", "RuleId"),
            OperationKind::Create | OperationKind::Set => ("Rule", "Rule"),
        };
        let mut found = None;
        while let Some(child) = p.child()? {
            if child.local != element {
                p.skip()?;
                continue;
            }
            p.expect_types(&child)?;
            found = Some(match kind {
                OperationKind::Create => RuleOperation::Create(Rule::parse(p, &child.attrs)?),
                OperationKind::Set => RuleOperation::Set(Rule::parse(p, &child.attrs)?),
                OperationKind::Delete => RuleOperation::Delete(p.text()?),
            });
        }
        found
            .map(Some)
            .ok_or_else(|| p.error(ParseErrorKind::MissingElement(name)))
    }
}
