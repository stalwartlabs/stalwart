/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EwsCaller, EwsContext},
    folder::{FolderSelector, folder_id, resolve_folder},
    item::{EmailIds, find::mailbox_of},
    reply::{RESPONSE_CAPACITY, ews_response},
    service::is_own,
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::{FolderNode, FolderTree},
    mail::{
        category::{AccountCategories, CategoryNames, CategoryUse},
        fetch_raw_message,
    },
    rules::{
        RulesWrite, load_rules,
        map::{can_be_condition, can_be_exception},
        save_rules,
    },
    store::{
        FolderKind, FolderRef,
        account::ExchangeAccountStore,
        folder::{FaiChange, FaiCommit, FaiFolder, FolderStore},
    },
};
use ahash::AHashSet;
use common::{MessageStoreCache, Server, auth::AccessToken, cache::exchange::CategoryTable};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::INBOX_ID,
};
use exchange_proto::{
    common::UtcSeconds,
    ews::{
        Operation, Status,
        requests::rules::{GetInboxRules, UpdateInboxRules},
        responses::{
            ShapeB,
            rules::{GetInboxRulesBody, UpdateInboxRulesBody},
        },
        schema::{
            FlaggedForAction, Importance, ResponseCode, RuleField, RuleValidationErrorCode,
            Sensitivity,
        },
        types::{
            address::EmailAddress,
            generated::{RuleOperationError, RuleValidationError},
            ids::{EwsIdStr, ItemId, TargetFolderId},
            rule::{
                Addresses, DateRange, Rule, RuleActions, RuleOperation, RulePredicates, SizeRange,
            },
            value::{DateTime, List, Strings},
        },
    },
    ids::ews::EwsRuleId,
    rules::{
        Action, AddressField, Level, MAX_STRING_LEN, MAX_VALUES, ManagedRule, MeKind, MessageKind,
        Predicate, RECEIVED_SECONDS, RedirectKind, RuleBody, RuleId, RuleLogic, RuleSet, RuleState,
        SensitivityLevel, ServerReply, TextField, is_valid_address, is_valid_text,
    },
};
use http_proto::HttpResponse;
use mail_parser::{MessageParser, PartKind};
use registry::{schema::prelude::Property, types::error::ValidationError};
use std::{borrow::Cow, mem, sync::Arc};
use store::write::{Archive, ArchiveBytes};
use trc::AddContext;
use types::type_state::DataType;

const OTHER_MAILBOX: &str = "Only the authenticated user's own mailbox can be accessed.";
const SCOPE_DENIED: &str = "The access token does not grant access to the inbox rules.";
const NO_PERMISSION: &str = "The account is not allowed to manage Sieve scripts.";
const BLOB_EXISTS: &str = "Outlook rules exist; set RemoveOutlookRuleBlob to replace them.";
const VALIDATION_FAILED: &str = "One or more rules failed validation.";
const OVER_QUOTA: &str = "The inbox rules exceed the account's Sieve limits.";
const BUSY: &str = "The inbox rules changed while they were being saved; retry the request.";
const RULE_ORGANIZER_CLASS: &str = "IPM.RuleOrganizer";
const SMTP: &str = "SMTP";
const MAX_WRITE_ATTEMPTS: usize = 3;
const MAX_RULES: usize = 256;
const MAX_NAME_LEN: usize = 256;

const MSG_UNSUPPORTED: &str = "The operation on this unsupported rule is not allowed.";
const MSG_INVALID: &str = "The value is not valid.";
const MSG_EMPTY: &str = "The value is empty.";
const MSG_TOO_BIG: &str = "The value is too long.";
const MSG_ADDRESS: &str = "The address is not a valid SMTP address.";
const MSG_FOLDER: &str = "The folder does not exist.";
const MSG_TEMPLATE: &str = "The reply template is not a readable message in this mailbox.";
const MSG_TEMPLATE_SUBJECT: &str = "The reply template subject is too long or has a line break.";
const MSG_RANGE: &str = "The size range is not valid.";
const MSG_NEGATIVE: &str = "The size is less than zero.";
const MSG_DATE_RANGE: &str = "The date range is not valid.";
const MSG_MISSING_ACTION: &str = "The rule has no action.";
const MSG_CREATE_ID: &str = "A rule to create cannot carry a rule id.";
const MSG_NOT_FOUND: &str = "The rule does not exist.";
const MSG_DUPLICATE_PRIORITY: &str = "Two rules in the request have the same priority.";
const MSG_DUPLICATE_RULE: &str = "The request changes the same rule twice.";
const MSG_NO_RULE_ID: &str = "No rule id is left to assign.";
const MSG_REDIRECT_LIMIT: &str = "The rules forward to more recipients than allowed.";

#[derive(Debug, Clone, Copy)]
enum Side {
    Condition,
    Exception,
}

macro_rules! predicate_fields {
    ($($name:ident => $condition:ident, $exception:ident;)+) => {
        #[derive(Debug, Clone, Copy)]
        enum PredicateField {
            $($name),+
        }

        impl PredicateField {
            const fn uri(self, side: Side) -> RuleField {
                match (self, side) {
                    $(
                        (PredicateField::$name, Side::Condition) => RuleField::$condition,
                        (PredicateField::$name, Side::Exception) => RuleField::$exception,
                    )+
                }
            }
        }
    };
}

predicate_fields! {
    Categories => ConditionCategories, ExceptionCategories;
    BodyStrings => ConditionContainsBodyStrings, ExceptionContainsBodyStrings;
    HeaderStrings => ConditionContainsHeaderStrings, ExceptionContainsHeaderStrings;
    RecipientStrings => ConditionContainsRecipientStrings, ExceptionContainsRecipientStrings;
    SenderStrings => ConditionContainsSenderStrings, ExceptionContainsSenderStrings;
    SubjectOrBodyStrings => ConditionContainsSubjectOrBodyStrings, ExceptionContainsSubjectOrBodyStrings;
    SubjectStrings => ConditionContainsSubjectStrings, ExceptionContainsSubjectStrings;
    FlaggedForAction => ConditionFlaggedForAction, ExceptionFlaggedForAction;
    FromAddresses => ConditionFromAddresses, ExceptionFromAddresses;
    FromConnectedAccounts => ConditionFromConnectedAccounts, ExceptionFromConnectedAccounts;
    IsApprovalRequest => ConditionIsApprovalRequest, ExceptionIsApprovalRequest;
    IsPermissionControlled => ConditionIsPermissionControlled, ExceptionIsPermissionControlled;
    ItemClasses => ConditionItemClasses, ExceptionItemClasses;
    MessageClassifications => ConditionMessageClassifications, ExceptionMessageClassifications;
    SentToAddresses => ConditionSentToAddresses, ExceptionSentToAddresses;
    WithinDateRange => ConditionWithinDateRange, ExceptionWithinDateRange;
    WithinSizeRange => ConditionWithinSizeRange, ExceptionWithinSizeRange;
}

#[derive(Debug)]
struct FieldError {
    field: RuleField,
    code: RuleValidationErrorCode,
    message: Cow<'static, str>,
    value: String,
}

impl FieldError {
    fn new(field: RuleField, code: RuleValidationErrorCode, message: &'static str) -> Self {
        FieldError {
            field,
            code,
            message: Cow::Borrowed(message),
            value: String::new(),
        }
    }

    fn with_value(mut self, value: &str) -> Self {
        self.value = value.to_string();
        self
    }

    fn into_validation(self) -> RuleValidationError<'static> {
        RuleValidationError {
            field_uri: self.field,
            error_code: self.code,
            error_message: self.message,
            field_value: Cow::Owned(self.value),
        }
    }
}

struct Prepared {
    name: String,
    priority: i32,
    enabled: bool,
    stop: bool,
    logic: RuleLogic,
}

enum PreparedOp {
    Create(Prepared),
    Set(EwsRuleId, Prepared),
    Delete(EwsRuleId),
}

struct Lookups<'a> {
    server: &'a Server,
    ctx: &'a EwsContext,
    tree: Option<Arc<FolderTree>>,
    mailboxes: Option<Arc<MessageStoreCache>>,
    categories: CategoryNames,
}

pub(crate) async fn get_inbox_rules(
    server: &Server,
    ctx: &EwsContext,
    request: &GetInboxRules<'_>,
) -> trc::Result<HttpResponse> {
    let (status, body) = if !is_own(server, ctx, request.mailbox_smtp_address.as_deref()).await? {
        (
            Status::error(ResponseCode::ErrorAccessDenied, OTHER_MAILBOX),
            None,
        )
    } else if !ctx.account.data_types.contains(DataType::SieveScript) {
        (
            Status::error(ResponseCode::ErrorAccessDenied, SCOPE_DENIED),
            None,
        )
    } else {
        (Status::SUCCESS, Some(read_rules(server, ctx).await?))
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::GetInboxRules,
        status,
        body,
    });
    Ok(ews_response(out))
}

pub(crate) async fn update_inbox_rules(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UpdateInboxRules<'_>,
) -> trc::Result<HttpResponse> {
    let (status, body) = if !is_own(server, ctx, request.mailbox_smtp_address.as_deref()).await? {
        (
            Status::error(ResponseCode::ErrorAccessDenied, OTHER_MAILBOX),
            None,
        )
    } else if !ctx.account.data_types.contains(DataType::SieveScript) {
        (
            Status::error(ResponseCode::ErrorAccessDenied, SCOPE_DENIED),
            None,
        )
    } else {
        update(server, ctx, caller, request).await?
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::UpdateInboxRules,
        status,
        body,
    });
    Ok(ews_response(out))
}

async fn read_rules(server: &Server, ctx: &EwsContext) -> trc::Result<GetInboxRulesBody<'static>> {
    let account_id = ctx.account.account_id;
    let loaded = load_rules(server, account_id).await?;
    let blob_exists = outlook_blob(server, account_id).await?.is_some();
    let tree = if loaded.set.rules.iter().any(has_folder_action) {
        Some(ctx.folder_tree(server).await?)
    } else {
        None
    };
    let exchange = if loaded.set.rules.iter().any(has_categories) {
        Some(server.get_cached_exchange(account_id).await?)
    } else {
        None
    };
    let empty = CategoryTable::default();
    let categories = AccountCategories::from_table(
        exchange
            .as_deref()
            .map_or(&empty, |exchange| &exchange.categories),
    );
    let detached = !loaded.is_active;
    let rules = loaded
        .set
        .rules
        .iter()
        .filter(|rule| !is_delegate(rule))
        .zip(1..)
        .map(|(rule, priority)| {
            rule_view(
                rule,
                priority,
                detached,
                account_id,
                tree.as_deref(),
                categories,
            )
        })
        .collect();
    Ok(GetInboxRulesBody {
        outlook_rule_blob_exists: Some(blob_exists),
        rules,
    })
}

async fn update(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UpdateInboxRules<'_>,
) -> trc::Result<(Status<'static>, Option<UpdateInboxRulesBody<'static>>)> {
    let account_id = ctx.account.account_id;
    let mut lookups = Lookups {
        server,
        ctx,
        tree: None,
        mailboxes: None,
        categories: CategoryNames::default(),
    };
    if request.operations.len() > MAX_RULES {
        return Ok(over_quota());
    }
    let mut prepared = Vec::with_capacity(request.operations.len());
    let mut errors = Vec::new();
    for (index, operation) in (0i32..).zip(&request.operations) {
        match prepare(&mut lookups, operation).await? {
            Ok(op) => prepared.push((index, op)),
            Err(fields) => errors.push(operation_error(index, fields)),
        }
    }
    check_duplicates(&prepared, &mut errors);
    if !errors.is_empty() {
        return Ok(validation_failed(errors));
    }

    let remove_blob = request.remove_outlook_rule_blob.unwrap_or(false);
    for _ in 0..MAX_WRITE_ATTEMPTS {
        let mut loaded = load_rules(server, account_id).await?;
        let blob = outlook_blob(server, account_id).await?;
        if blob.is_some() && !remove_blob {
            return Ok((
                Status::error(ResponseCode::ErrorOutlookRuleBlobExists, BLOB_EXISTS),
                None,
            ));
        }

        let mut set = mem::take(&mut loaded.set);
        let hidden = set
            .rules
            .iter()
            .position(is_delegate)
            .map(|position| set.rules.remove(position));
        let mut errors = Vec::new();
        for (index, op) in &prepared {
            if let Err(field) = apply(&mut set, op) {
                errors.push(operation_error(*index, vec![field]));
            }
        }
        if !errors.is_empty() {
            return Ok(validation_failed(errors));
        }
        if set.rules.len() > MAX_RULES {
            return Ok(over_quota());
        }
        if let Some(hidden) = hidden {
            set.rules.insert(0, hidden);
        }
        set.renumber();

        match save_rules(server, caller.access_token, account_id, loaded, set).await? {
            RulesWrite::Written { .. } => {
                if let Err(err) = lookups.categories.save(server, account_id).await {
                    trc::error!(err.caused_by(trc::location!()));
                }
                if let Some((id, row)) = blob
                    && let Err(err) =
                        delete_blob(server, caller.access_token, account_id, id, &row).await
                {
                    trc::error!(err.caused_by(trc::location!()));
                }
                return Ok((Status::SUCCESS, Some(UpdateInboxRulesBody::default())));
            }
            RulesWrite::Conflict => {}
            RulesWrite::Forbidden => {
                return Ok((
                    Status::error(ResponseCode::ErrorAccessDenied, NO_PERMISSION),
                    None,
                ));
            }
            RulesWrite::Limit(err) => {
                let (index, field) = match limit_property(&err) {
                    Property::Addresses => redirect_field(&prepared),
                    Property::Name => (last_index(&prepared), RuleField::DisplayName),
                    Property::AddKeywords => {
                        (last_index(&prepared), RuleField::ActionAssignCategories)
                    }
                    _ => (last_index(&prepared), RuleField::Actions),
                };
                return Ok(validation_failed(vec![operation_error(
                    index,
                    vec![FieldError {
                        field,
                        code: RuleValidationErrorCode::InvalidValue,
                        message: Cow::Owned(err.to_string()),
                        value: String::new(),
                    }],
                )]));
            }
            RulesWrite::RedirectLimit => {
                let (index, field) = redirect_field(&prepared);
                return Ok(validation_failed(vec![operation_error(
                    index,
                    vec![FieldError::new(
                        field,
                        RuleValidationErrorCode::InvalidValue,
                        MSG_REDIRECT_LIMIT,
                    )],
                )]));
            }
            RulesWrite::ScriptLimit(reason) | RulesWrite::Invalid(reason) => {
                let index = last_index(&prepared);
                return Ok(validation_failed(vec![operation_error(
                    index,
                    vec![FieldError {
                        field: RuleField::Actions,
                        code: RuleValidationErrorCode::UnsupportedRule,
                        message: Cow::Owned(reason),
                        value: String::new(),
                    }],
                )]));
            }
        }
    }
    Ok((Status::error(ResponseCode::ErrorServerBusy, BUSY), None))
}

async fn prepare(
    lookups: &mut Lookups<'_>,
    operation: &RuleOperation<'_>,
) -> trc::Result<Result<PreparedOp, Vec<FieldError>>> {
    Ok(match operation {
        RuleOperation::Create(rule) => {
            if rule.rule_id.is_some() {
                Err(vec![FieldError::new(
                    RuleField::RuleId,
                    RuleValidationErrorCode::CreateWithRuleId,
                    MSG_CREATE_ID,
                )])
            } else {
                prepare_rule(lookups, rule).await?.map(PreparedOp::Create)
            }
        }
        RuleOperation::Set(rule) => match rule.rule_id.as_deref().and_then(EwsRuleId::decode) {
            Some(id) => prepare_rule(lookups, rule)
                .await?
                .map(|prepared| PreparedOp::Set(id, prepared)),
            None => Err(vec![not_found(rule.rule_id.as_deref().unwrap_or_default())]),
        },
        RuleOperation::Delete(id) => match EwsRuleId::decode(id) {
            Some(id) => Ok(PreparedOp::Delete(id)),
            None => Err(vec![not_found(id)]),
        },
    })
}

async fn prepare_rule(
    lookups: &mut Lookups<'_>,
    rule: &Rule<'_>,
) -> trc::Result<Result<Prepared, Vec<FieldError>>> {
    let mut errors = Vec::new();
    let name = rule.display_name.trim();
    if name.is_empty() {
        errors.push(FieldError::new(
            RuleField::DisplayName,
            RuleValidationErrorCode::EmptyValueFound,
            MSG_EMPTY,
        ));
    } else if name.len() > MAX_NAME_LEN || name.contains(['\r', '\n']) {
        errors.push(
            FieldError::new(
                RuleField::DisplayName,
                RuleValidationErrorCode::StringValueTooBig,
                MSG_TOO_BIG,
            )
            .with_value(name),
        );
    }

    let mut logic = RuleLogic::default();
    if let Some(conditions) = &rule.conditions {
        predicates(
            conditions,
            Side::Condition,
            &mut logic.conditions,
            &mut lookups.categories,
            &mut errors,
        );
    }
    if let Some(exceptions) = &rule.exceptions {
        predicates(
            exceptions,
            Side::Exception,
            &mut logic.exceptions,
            &mut lookups.categories,
            &mut errors,
        );
    }
    for predicate in &logic.conditions {
        if !can_be_condition(predicate) {
            errors.push(unmappable(predicate, Side::Condition));
        }
    }
    for predicate in &logic.exceptions {
        if !can_be_exception(predicate) {
            errors.push(unmappable(predicate, Side::Exception));
        }
    }
    let mut stop = false;
    if let Some(actions) = &rule.actions {
        stop = actions.stop_processing_rules == Some(true);
        rule_actions(lookups, actions, &mut logic.actions, &mut errors).await?;
    }
    if logic.actions.is_empty() && !stop && errors.is_empty() {
        errors.push(FieldError::new(
            RuleField::Actions,
            RuleValidationErrorCode::MissingAction,
            MSG_MISSING_ACTION,
        ));
    }
    if errors.is_empty() && !logic.is_valid() {
        errors.push(FieldError::new(
            RuleField::Actions,
            RuleValidationErrorCode::InvalidValue,
            MSG_INVALID,
        ));
    }

    Ok(if errors.is_empty() {
        Ok(Prepared {
            name: name.to_string(),
            priority: rule.priority,
            enabled: rule.is_enabled.unwrap_or(true),
            stop,
            logic,
        })
    } else {
        Err(errors)
    })
}

fn unmappable(predicate: &Predicate, side: Side) -> FieldError {
    let field = match predicate {
        Predicate::Size { .. } => PredicateField::WithinSizeRange,
        _ => PredicateField::WithinDateRange,
    };
    FieldError::new(
        field.uri(side),
        RuleValidationErrorCode::InvalidValue,
        MSG_INVALID,
    )
}

fn predicates(
    source: &RulePredicates<'_>,
    side: Side,
    out: &mut Vec<Predicate>,
    categories: &mut CategoryNames,
    errors: &mut Vec<FieldError>,
) {
    let refused = [
        (
            PredicateField::HeaderStrings,
            source.contains_header_strings.is_some(),
        ),
        (
            PredicateField::FlaggedForAction,
            source
                .flagged_for_action
                .is_some_and(|flag| flag != FlaggedForAction::Any),
        ),
        (
            PredicateField::FromConnectedAccounts,
            source.from_connected_accounts.is_some(),
        ),
        (
            PredicateField::IsApprovalRequest,
            source.is_approval_request == Some(true),
        ),
        (
            PredicateField::IsPermissionControlled,
            source.is_permission_controlled == Some(true),
        ),
        (PredicateField::ItemClasses, source.item_classes.is_some()),
        (
            PredicateField::MessageClassifications,
            source.message_classifications.is_some(),
        ),
    ];
    for (field, present) in refused {
        if present {
            errors.push(FieldError::new(
                field.uri(side),
                RuleValidationErrorCode::UnsupportedRule,
                MSG_UNSUPPORTED,
            ));
        }
    }

    for (field, kind, values) in [
        (
            PredicateField::SubjectStrings,
            TextField::Subject,
            &source.contains_subject_strings,
        ),
        (
            PredicateField::BodyStrings,
            TextField::Body,
            &source.contains_body_strings,
        ),
        (
            PredicateField::SubjectOrBodyStrings,
            TextField::SubjectOrBody,
            &source.contains_subject_or_body_strings,
        ),
        (
            PredicateField::SenderStrings,
            TextField::Sender,
            &source.contains_sender_strings,
        ),
        (
            PredicateField::RecipientStrings,
            TextField::Recipient,
            &source.contains_recipient_strings,
        ),
    ] {
        if let Some(values) = values {
            match strings(&values.0) {
                Ok(values) => out.push(Predicate::Text {
                    field: kind,
                    values,
                }),
                Err((code, message, value)) => {
                    errors.push(FieldError::new(field.uri(side), code, message).with_value(&value))
                }
            }
        }
    }

    for (field, kind, values) in [
        (
            PredicateField::FromAddresses,
            AddressField::From,
            &source.from_addresses,
        ),
        (
            PredicateField::SentToAddresses,
            AddressField::SentTo,
            &source.sent_to_addresses,
        ),
    ] {
        if let Some(values) = values {
            match addresses(&values.0) {
                Ok(values) => out.push(Predicate::Address {
                    field: kind,
                    values,
                }),
                Err(value) => errors.push(
                    FieldError::new(
                        field.uri(side),
                        RuleValidationErrorCode::InvalidAddress,
                        MSG_ADDRESS,
                    )
                    .with_value(value),
                ),
            }
        }
    }

    for (kind, flag) in [
        (MeKind::To, source.sent_to_me),
        (MeKind::Cc, source.sent_cc_me),
        (MeKind::ToOrCc, source.sent_to_or_cc_me),
        (MeKind::NotTo, source.not_sent_to_me),
        (MeKind::OnlyTo, source.sent_only_to_me),
    ] {
        if flag == Some(true) {
            out.push(Predicate::Me(kind));
        }
    }

    if let Some(importance) = source.importance {
        out.push(Predicate::Importance(level(importance)));
    }
    if let Some(sensitivity) = source.sensitivity {
        out.push(Predicate::Sensitivity(match sensitivity {
            Sensitivity::Normal => SensitivityLevel::Normal,
            Sensitivity::Personal => SensitivityLevel::Personal,
            Sensitivity::Private => SensitivityLevel::Private,
            Sensitivity::Confidential => SensitivityLevel::Confidential,
        }));
    }
    if let Some(names) = &source.categories {
        let field = PredicateField::Categories.uri(side);
        match category_keywords(&names.0, CategoryUse::Tested, categories) {
            Ok(keywords) if matches!(side, Side::Exception) && keywords.len() > 1 => {
                errors.push(FieldError::new(
                    field,
                    RuleValidationErrorCode::UnsupportedRule,
                    MSG_UNSUPPORTED,
                ))
            }
            Ok(keywords) => out.extend(
                keywords
                    .into_iter()
                    .map(|keyword| Predicate::Categories(vec![keyword])),
            ),
            Err(error) => errors.push(error.into_field(field)),
        }
    }
    if source.flagged_for_action == Some(FlaggedForAction::Any) {
        out.push(Predicate::Flagged);
    }
    if source.has_attachments == Some(true) {
        out.push(Predicate::HasAttachments);
    }
    for (kind, flag) in [
        (MessageKind::AutomaticForward, source.is_automatic_forward),
        (MessageKind::AutomaticReply, source.is_automatic_reply),
        (MessageKind::Encrypted, source.is_encrypted),
        (MessageKind::MeetingRequest, source.is_meeting_request),
        (MessageKind::MeetingResponse, source.is_meeting_response),
        (MessageKind::NonDeliveryReport, source.is_ndr),
        (MessageKind::ReadReceipt, source.is_read_receipt),
        (MessageKind::Signed, source.is_signed),
        (MessageKind::Voicemail, source.is_voicemail),
    ] {
        if flag == Some(true) {
            out.push(Predicate::MessageType(kind));
        }
    }
    if let Some(range) = &source.within_date_range {
        match date_range(range, side) {
            Ok((after, before)) => {
                out.extend(after.map(Predicate::ReceivedAfter));
                out.extend(before.map(Predicate::ReceivedBefore));
            }
            Err((code, message)) => errors.push(FieldError::new(
                PredicateField::WithinDateRange.uri(side),
                code,
                message,
            )),
        }
    }
    if let Some(range) = &source.within_size_range {
        match size_range(range) {
            Ok(predicate) => out.push(predicate),
            Err((code, message)) => errors.push(FieldError::new(
                PredicateField::WithinSizeRange.uri(side),
                code,
                message,
            )),
        }
    }
}

async fn rule_actions(
    lookups: &mut Lookups<'_>,
    source: &RuleActions<'_>,
    out: &mut Vec<Action>,
    errors: &mut Vec<FieldError>,
) -> trc::Result<()> {
    if source.send_sms_alert_to_recipients.is_some() {
        errors.push(FieldError::new(
            RuleField::ActionSendSMSAlertToRecipients,
            RuleValidationErrorCode::UnsupportedRule,
            MSG_UNSUPPORTED,
        ));
    }
    if let Some(template) = &source.server_reply_with_message {
        match lookups.reply_template(template).await? {
            Ok(reply) => out.push(Action::ServerReply(Box::new(reply))),
            Err(message) => errors.push(FieldError::new(
                RuleField::ActionServerReplyWithMessage,
                RuleValidationErrorCode::InvalidValue,
                message,
            )),
        }
    }

    if let Some(importance) = source.mark_importance {
        out.push(Action::SetImportance(level(importance)));
    }
    if source.mark_as_read == Some(true) {
        out.push(Action::MarkAsRead);
    }
    if let Some(categories) = &source.assign_categories {
        match category_keywords(
            &categories.0,
            CategoryUse::Assigned,
            &mut lookups.categories,
        ) {
            Ok(keywords) => out.push(Action::AssignCategories(keywords)),
            Err(error) => errors.push(error.into_field(RuleField::ActionAssignCategories)),
        }
    }
    for (field, kind, values) in [
        (
            RuleField::ActionForwardToRecipients,
            RedirectKind::Forward,
            &source.forward_to_recipients,
        ),
        (
            RuleField::ActionForwardAsAttachmentToRecipients,
            RedirectKind::ForwardAsAttachment,
            &source.forward_as_attachment_to_recipients,
        ),
        (
            RuleField::ActionRedirectToRecipients,
            RedirectKind::Redirect,
            &source.redirect_to_recipients,
        ),
    ] {
        if let Some(values) = values {
            match addresses(&values.0) {
                Ok(addresses) => out.push(Action::Redirect { kind, addresses }),
                Err(value) => errors.push(
                    FieldError::new(field, RuleValidationErrorCode::InvalidAddress, MSG_ADDRESS)
                        .with_value(value),
                ),
            }
        }
    }
    for (field, target, copy) in [
        (RuleField::ActionCopyToFolder, &source.copy_to_folder, true),
        (RuleField::ActionMoveToFolder, &source.move_to_folder, false),
    ] {
        if let Some(target) = target {
            match lookups.folder(target).await? {
                Some(mailbox_id) => out.push(if copy {
                    Action::Copy { mailbox_id }
                } else {
                    Action::Move { mailbox_id }
                }),
                None => errors.push(FieldError::new(
                    field,
                    RuleValidationErrorCode::FolderDoesNotExist,
                    MSG_FOLDER,
                )),
            }
        }
    }
    if source.delete == Some(true) {
        out.push(Action::Delete);
    }
    if source.permanent_delete == Some(true) {
        out.push(Action::PermanentDelete);
    }
    Ok(())
}

impl Lookups<'_> {
    async fn mailboxes(&mut self) -> trc::Result<&MessageStoreCache> {
        let cache = match self.mailboxes.take() {
            Some(cache) => cache,
            None => self
                .server
                .get_cached_messages(self.ctx.account.account_id)
                .await
                .caused_by(trc::location!())?,
        };
        Ok(&**self.mailboxes.insert(cache))
    }

    async fn reply_template(
        &mut self,
        id: &ItemId<'_>,
    ) -> trc::Result<Result<ServerReply, &'static str>> {
        let (server, ctx) = (self.server, self.ctx);
        let template = id.id.as_str();
        if template.is_empty() || template.len() > MAX_STRING_LEN {
            return Ok(Err(MSG_TEMPLATE));
        }
        let ids = EmailIds::load(server, ctx).await?;
        let Ok(item) = ids.resolve_item_id(ctx, self.mailboxes().await?, id) else {
            return Ok(Err(MSG_TEMPLATE));
        };
        let Some((raw, _reservation)) =
            fetch_raw_message(server, ctx.account.account_id, item.document_id).await?
        else {
            return Ok(Err(MSG_TEMPLATE));
        };
        let Some(message) = MessageParser::new().parse(&raw) else {
            return Ok(Err(MSG_TEMPLATE));
        };
        let subject = message.subject().filter(|subject| !subject.is_empty());
        if subject.is_some_and(|subject| !is_valid_text(subject)) {
            return Ok(Err(MSG_TEMPLATE_SUBJECT));
        }
        let html_body = message
            .html_body()
            .next()
            .filter(|part| matches!(part.kind(), PartKind::Html))
            .and_then(|part| part.text())
            .map(Cow::into_owned);
        Ok(Ok(ServerReply {
            template: template.to_string(),
            subject: subject.map(str::to_string),
            text_body: message
                .body_text(0)
                .map(Cow::into_owned)
                .unwrap_or_default(),
            html_body,
        }))
    }

    async fn folder(&mut self, target: &TargetFolderId<'_>) -> trc::Result<Option<u32>> {
        let tree = match self.tree.take() {
            Some(tree) => tree,
            None => self.ctx.folder_tree(self.server).await?,
        };
        let tree = &*self.tree.insert(tree);
        let Ok(entry) =
            resolve_folder(self.server, self.ctx, tree, FolderSelector::from(target)).await?
        else {
            return Ok(None);
        };
        let Some(mailbox_id) = mailbox_of(entry.node) else {
            return Ok(None);
        };
        Ok(self
            .mailboxes()
            .await?
            .mailbox_by_id(&mailbox_id)
            .map(|_| mailbox_id))
    }
}

fn strings(
    values: &[Cow<'_, str>],
) -> Result<Vec<String>, (RuleValidationErrorCode, &'static str, String)> {
    if values.is_empty() || values.len() > MAX_VALUES {
        return Err((
            RuleValidationErrorCode::EmptyValueFound,
            MSG_EMPTY,
            String::new(),
        ));
    }
    values
        .iter()
        .map(|value| {
            if value.is_empty() {
                Err((
                    RuleValidationErrorCode::EmptyValueFound,
                    MSG_EMPTY,
                    String::new(),
                ))
            } else if value.len() > MAX_STRING_LEN {
                Err((
                    RuleValidationErrorCode::StringValueTooBig,
                    MSG_TOO_BIG,
                    value.to_string(),
                ))
            } else if value.contains(['\r', '\n']) {
                Err((
                    RuleValidationErrorCode::InvalidValue,
                    MSG_INVALID,
                    value.to_string(),
                ))
            } else {
                Ok(value.to_string())
            }
        })
        .collect()
}

fn addresses<'x>(values: &'x [EmailAddress<'_>]) -> Result<Vec<String>, &'x str> {
    if values.is_empty() || values.len() > MAX_VALUES {
        return Err("");
    }
    values
        .iter()
        .map(|address| {
            let text = address.email_address.as_deref().unwrap_or_default();
            let smtp = address
                .routing_type
                .as_deref()
                .is_none_or(|routing| routing.eq_ignore_ascii_case(SMTP));
            if smtp && is_valid_address(text) {
                Ok(text.to_ascii_lowercase())
            } else {
                Err(text)
            }
        })
        .collect()
}

struct CategoryError<'x>(Option<&'x str>);

impl CategoryError<'_> {
    fn into_field(self, field: RuleField) -> FieldError {
        let error = FieldError::new(field, RuleValidationErrorCode::InvalidValue, MSG_INVALID);
        match self.0 {
            Some(name) => error.with_value(name),
            None => error,
        }
    }
}

fn category_keywords<'x>(
    names: &'x [Cow<'_, str>],
    usage: CategoryUse,
    categories: &mut CategoryNames,
) -> Result<Vec<String>, CategoryError<'x>> {
    if names.is_empty() || names.len() > MAX_VALUES {
        return Err(CategoryError(None));
    }
    names
        .iter()
        .map(|name| {
            categories
                .keyword(name, usage)
                .ok_or(CategoryError(Some(name)))
        })
        .collect()
}

const fn level(importance: Importance) -> Level {
    match importance {
        Importance::Low => Level::Low,
        Importance::Normal => Level::Normal,
        Importance::High => Level::High,
    }
}

const fn importance(level: Level) -> Importance {
    match level {
        Level::Low => Importance::Low,
        Level::Normal => Importance::Normal,
        Level::High => Importance::High,
    }
}

type DateBounds = (Option<i64>, Option<i64>);

fn date_range(
    range: &DateRange,
    side: Side,
) -> Result<DateBounds, (RuleValidationErrorCode, &'static str)> {
    let convert = |value: Option<DateTime>| match value {
        Some(value) => value
            .to_utc()
            .map(|seconds| seconds.0)
            .filter(|seconds| RECEIVED_SECONDS.contains(seconds))
            .map(Some)
            .ok_or((RuleValidationErrorCode::InvalidValue, MSG_INVALID)),
        None => Ok(None),
    };
    match (
        convert(range.start_date_time)?,
        convert(range.end_date_time)?,
        side,
    ) {
        (None, None, _) => Err((RuleValidationErrorCode::MissingRangeValue, MSG_DATE_RANGE)),
        (Some(after), Some(before), _) if after > before => {
            Err((RuleValidationErrorCode::InvalidDateRange, MSG_DATE_RANGE))
        }
        (Some(_), Some(_), Side::Exception) => {
            Err((RuleValidationErrorCode::UnsupportedRule, MSG_UNSUPPORTED))
        }
        (after, before, _) => Ok((after, before)),
    }
}

fn size_range(range: &SizeRange) -> Result<Predicate, (RuleValidationErrorCode, &'static str)> {
    let convert = |value: Option<i32>| match value {
        Some(value) => u32::try_from(value)
            .map(Some)
            .map_err(|_| (RuleValidationErrorCode::SizeLessThanZero, MSG_NEGATIVE)),
        None => Ok(None),
    };
    let min_kb = convert(range.minimum_size)?;
    let max_kb = convert(range.maximum_size)?;
    match (min_kb, max_kb) {
        (None, None) => Err((RuleValidationErrorCode::MissingRangeValue, MSG_RANGE)),
        (Some(min), Some(max)) if min > max => {
            Err((RuleValidationErrorCode::InvalidSizeRange, MSG_RANGE))
        }
        _ => Ok(Predicate::Size { min_kb, max_kb }),
    }
}

fn check_duplicates(prepared: &[(i32, PreparedOp)], errors: &mut Vec<RuleOperationError<'static>>) {
    let mut priorities = AHashSet::with_capacity(prepared.len());
    let mut rule_ids = AHashSet::with_capacity(prepared.len());
    for (index, op) in prepared {
        let mut fields = Vec::new();
        if let Some(priority) = op.priority()
            && !priorities.insert(priority)
        {
            fields.push(FieldError::new(
                RuleField::Priority,
                RuleValidationErrorCode::DuplicatedPriority,
                MSG_DUPLICATE_PRIORITY,
            ));
        }
        if let Some(id) = op.rule_id()
            && !rule_ids.insert(id)
        {
            fields.push(
                FieldError::new(
                    RuleField::RuleId,
                    RuleValidationErrorCode::DuplicatedOperationOnTheSameRule,
                    MSG_DUPLICATE_RULE,
                )
                .with_value(&id.encode()),
            );
        }
        if !fields.is_empty() {
            errors.push(operation_error(*index, fields));
        }
    }
}

impl PreparedOp {
    fn priority(&self) -> Option<i32> {
        match self {
            PreparedOp::Create(prepared) | PreparedOp::Set(_, prepared) => Some(prepared.priority),
            PreparedOp::Delete(_) => None,
        }
    }

    fn rule_id(&self) -> Option<EwsRuleId> {
        match self {
            PreparedOp::Set(id, _) | PreparedOp::Delete(id) => Some(*id),
            PreparedOp::Create(_) => None,
        }
    }
}

fn apply(set: &mut RuleSet, op: &PreparedOp) -> Result<(), FieldError> {
    match op {
        PreparedOp::Create(prepared) => {
            let id = set.allocate_id().ok_or_else(|| {
                FieldError::new(
                    RuleField::RuleId,
                    RuleValidationErrorCode::UnexpectedError,
                    MSG_NO_RULE_ID,
                )
            })?;
            let rule = ManagedRule {
                id,
                sequence: 0,
                state: RuleState(0)
                    .with_enabled(prepared.enabled)
                    .with(RuleState::EXIT_LEVEL, prepared.stop),
                name: prepared.name.clone(),
                body: RuleBody::Logic(prepared.logic.clone()),
                mapi: None,
            };
            let position = insert_position(prepared.priority, set.rules.len());
            set.rules.insert(position, rule);
            Ok(())
        }
        PreparedOp::Set(id, prepared) => {
            let position = set
                .position(RuleId(id.0))
                .ok_or_else(|| not_found(&id.encode()))?;
            if !set.rules.get(position).is_some_and(is_supported) {
                return Err(FieldError::new(
                    RuleField::RuleId,
                    RuleValidationErrorCode::UnsupportedRule,
                    MSG_UNSUPPORTED,
                )
                .with_value(&id.encode()));
            }
            let mut rule = set.rules.remove(position);
            rule.name.clone_from(&prepared.name);
            rule.state = rule
                .state
                .with_enabled(prepared.enabled)
                .with(RuleState::EXIT_LEVEL, prepared.stop);
            rule.body = RuleBody::Logic(prepared.logic.clone());
            rule.mapi = None;
            let position = insert_position(prepared.priority, set.rules.len());
            set.rules.insert(position, rule);
            Ok(())
        }
        PreparedOp::Delete(id) => {
            let position = set
                .position(RuleId(id.0))
                .ok_or_else(|| not_found(&id.encode()))?;
            set.remove(position);
            Ok(())
        }
    }
}

fn is_supported(rule: &ManagedRule) -> bool {
    let table = CategoryTable::default();
    let categories = AccountCategories::from_table(&table);
    rule_view(rule, 0, false, 0, None, categories)
        .is_not_supported
        .is_none()
}

fn insert_position(priority: i32, len: usize) -> usize {
    usize::try_from(priority.saturating_sub(1)).map_or(0, |position| position.min(len))
}

fn not_found(value: &str) -> FieldError {
    FieldError::new(
        RuleField::RuleId,
        RuleValidationErrorCode::RuleNotFound,
        MSG_NOT_FOUND,
    )
    .with_value(value)
}

fn operation_error(index: i32, fields: Vec<FieldError>) -> RuleOperationError<'static> {
    RuleOperationError {
        operation_index: index,
        validation_errors: List(
            fields
                .into_iter()
                .map(FieldError::into_validation)
                .collect(),
        ),
    }
}

fn validation_failed(
    errors: Vec<RuleOperationError<'static>>,
) -> (Status<'static>, Option<UpdateInboxRulesBody<'static>>) {
    (
        Status::error(
            ResponseCode::ErrorInboxRulesValidationError,
            VALIDATION_FAILED,
        ),
        Some(UpdateInboxRulesBody { errors }),
    )
}

fn over_quota() -> (Status<'static>, Option<UpdateInboxRulesBody<'static>>) {
    (
        Status::error(ResponseCode::ErrorRulesOverQuota, OVER_QUOTA),
        None,
    )
}

fn last_index(prepared: &[(i32, PreparedOp)]) -> i32 {
    prepared
        .iter()
        .rev()
        .find_map(|(index, op)| op.priority().map(|_| *index))
        .unwrap_or_default()
}

fn limit_property(err: &ValidationError) -> Property {
    match err {
        ValidationError::Invalid { property, .. }
        | ValidationError::Required { property }
        | ValidationError::MaxLength { property, .. }
        | ValidationError::MinLength { property, .. }
        | ValidationError::MaxValue { property, .. }
        | ValidationError::MinValue { property, .. } => *property,
    }
}

fn redirect_field(prepared: &[(i32, PreparedOp)]) -> (i32, RuleField) {
    let (index, kind) = prepared
        .iter()
        .rev()
        .find_map(|(index, op)| match op {
            PreparedOp::Create(prepared) | PreparedOp::Set(_, prepared) => prepared
                .logic
                .actions
                .iter()
                .find_map(|action| match action {
                    Action::Redirect { kind, .. } => Some((*index, *kind)),
                    _ => None,
                }),
            PreparedOp::Delete(_) => None,
        })
        .unwrap_or((0, RedirectKind::Forward));
    let field = match kind {
        RedirectKind::Forward => RuleField::ActionForwardToRecipients,
        RedirectKind::ForwardAsAttachment => RuleField::ActionForwardAsAttachmentToRecipients,
        RedirectKind::Redirect => RuleField::ActionRedirectToRecipients,
    };
    (index, field)
}

fn is_delegate(rule: &ManagedRule) -> bool {
    matches!(rule.body, RuleBody::Delegate(_))
}

fn has_folder_action(rule: &ManagedRule) -> bool {
    matches!(&rule.body, RuleBody::Logic(logic) if logic.actions.iter().any(|action| matches!(action, Action::Move { .. } | Action::Copy { .. })))
}

fn has_categories(rule: &ManagedRule) -> bool {
    let RuleBody::Logic(logic) = &rule.body else {
        return false;
    };
    logic
        .actions
        .iter()
        .any(|action| matches!(action, Action::AssignCategories(_)))
        || logic
            .conditions
            .iter()
            .chain(&logic.exceptions)
            .any(|predicate| matches!(predicate, Predicate::Categories(_)))
}

async fn outlook_blob(
    server: &Server,
    account_id: u32,
) -> trc::Result<Option<(u32, Archive<ArchiveBytes>)>> {
    let folder = inbox_fai();
    let mut found = None;
    server
        .fai_messages(account_id, folder, |id, message| {
            if message
                .message_class
                .as_str()
                .eq_ignore_ascii_case(RULE_ORGANIZER_CLASS)
            {
                found = Some(id);
                Ok(false)
            } else {
                Ok(true)
            }
        })
        .await
        .caused_by(trc::location!())?;
    let Some(id) = found else {
        return Ok(None);
    };
    Ok(server
        .fai_message(account_id, folder, id)
        .await
        .caused_by(trc::location!())?
        .map(|row| (id, row)))
}

async fn delete_blob(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    id: u32,
    row: &Archive<ArchiveBytes>,
) -> trc::Result<()> {
    let owner = server
        .exchange_quota_owner(access_token, account_id)
        .await?;
    match server
        .commit_fai(owner, inbox_fai(), FaiChange::Delete { id, previous: row })
        .await
        .caused_by(trc::location!())?
    {
        FaiCommit::Written { .. } | FaiCommit::Conflict => Ok(()),
    }
}

fn inbox_fai() -> FaiFolder {
    FaiFolder::from(FolderRef {
        kind: FolderKind::Mailbox,
        id: INBOX_ID,
    })
}

fn rule_view(
    rule: &ManagedRule,
    priority: i32,
    detached: bool,
    account_id: u32,
    tree: Option<&FolderTree>,
    categories: AccountCategories<'_>,
) -> Rule<'static> {
    let mut in_error =
        detached && rule.state.is_enabled() && matches!(rule.body, RuleBody::Logic(_));
    let mut view = Rule {
        rule_id: Some(Cow::Owned(EwsRuleId(rule.id.0).encode())),
        display_name: Cow::Owned(rule.name.clone()),
        priority,
        is_enabled: Some(rule.state.is_enabled()),
        is_not_supported: None,
        is_in_error: None,
        conditions: None,
        exceptions: None,
        actions: None,
    };
    let stop = rule.state.has(RuleState::EXIT_LEVEL).then_some(true);
    match &rule.body {
        RuleBody::Logic(logic) => {
            let mut supported = true;
            view.conditions = predicates_view(
                &logic.conditions,
                Side::Condition,
                categories,
                &mut supported,
            );
            view.exceptions = predicates_view(
                &logic.exceptions,
                Side::Exception,
                categories,
                &mut supported,
            );
            let mut actions = RuleActions {
                stop_processing_rules: stop,
                ..Default::default()
            };
            let (mut moved, mut copied) = (false, false);
            for action in &logic.actions {
                match action {
                    Action::Move { mailbox_id, .. } | Action::Copy { mailbox_id, .. } => {
                        let is_move = matches!(action, Action::Move { .. });
                        let seen = if is_move { &mut moved } else { &mut copied };
                        supported &= !mem::replace(seen, true);
                        let node = FolderNode::Stored(FolderRef {
                            kind: FolderKind::Mailbox,
                            id: *mailbox_id,
                        });
                        let Some(entry) = tree.and_then(|tree| tree.get(node)) else {
                            in_error = true;
                            continue;
                        };
                        let target = Some(TargetFolderId::Folder(folder_id(
                            account_id,
                            node,
                            entry.change_id,
                        )));
                        if is_move {
                            actions.move_to_folder = target;
                        } else {
                            actions.copy_to_folder = target;
                        }
                    }
                    Action::Delete => actions.delete = Some(true),
                    Action::PermanentDelete => actions.permanent_delete = Some(true),
                    Action::MarkAsRead => actions.mark_as_read = Some(true),
                    Action::SetImportance(level) => {
                        supported &= actions.mark_importance.is_none();
                        actions.mark_importance = Some(importance(*level))
                    }
                    Action::AssignCategories(keywords) => {
                        supported &= actions.assign_categories.is_none();
                        actions.assign_categories = Some(category_names(keywords, categories))
                    }
                    Action::ServerReply(reply) => {
                        actions.server_reply_with_message = Some(ItemId {
                            id: EwsIdStr::Parsed(Cow::Owned(reply.template.clone())),
                            change_key: None,
                        })
                    }
                    Action::Redirect { kind, addresses } => {
                        let list = Some(address_list(addresses));
                        match kind {
                            RedirectKind::Forward => actions.forward_to_recipients = list,
                            RedirectKind::ForwardAsAttachment => {
                                actions.forward_as_attachment_to_recipients = list
                            }
                            RedirectKind::Redirect => actions.redirect_to_recipients = list,
                        }
                    }
                }
            }
            view.actions = Some(actions);
            if !supported {
                view.is_not_supported = Some(true);
            }
        }
        RuleBody::Delegate(_) | RuleBody::StoredOnly => {
            view.is_not_supported = Some(true);
            view.actions = stop.map(|stop| RuleActions {
                stop_processing_rules: Some(stop),
                ..Default::default()
            });
        }
    }
    if in_error {
        view.is_in_error = Some(true);
    }
    view
}

fn predicates_view(
    predicates: &[Predicate],
    side: Side,
    categories: AccountCategories<'_>,
    supported: &mut bool,
) -> Option<RulePredicates<'static>> {
    if predicates.is_empty() {
        return None;
    }
    let mut view = RulePredicates::default();
    for predicate in predicates {
        match predicate {
            Predicate::Text { field, values } => {
                let slot = match field {
                    TextField::Subject => &mut view.contains_subject_strings,
                    TextField::Body => &mut view.contains_body_strings,
                    TextField::SubjectOrBody => &mut view.contains_subject_or_body_strings,
                    TextField::Sender => &mut view.contains_sender_strings,
                    TextField::Recipient => &mut view.contains_recipient_strings,
                };
                *supported &= slot.is_none();
                *slot = Some(string_list(values));
            }
            Predicate::Address { field, values } => {
                let slot = match field {
                    AddressField::From => &mut view.from_addresses,
                    AddressField::SentTo => &mut view.sent_to_addresses,
                };
                *supported &= slot.is_none();
                *slot = Some(address_list(values));
            }
            Predicate::Me(kind) => match kind {
                MeKind::To => view.sent_to_me = Some(true),
                MeKind::Cc => view.sent_cc_me = Some(true),
                MeKind::ToOrCc => view.sent_to_or_cc_me = Some(true),
                MeKind::NotTo => view.not_sent_to_me = Some(true),
                MeKind::OnlyTo => view.sent_only_to_me = Some(true),
            },
            Predicate::Importance(level) => {
                *supported &= view.importance.is_none();
                view.importance = Some(importance(*level))
            }
            Predicate::Sensitivity(level) => {
                *supported &= view.sensitivity.is_none();
                view.sensitivity = Some(match level {
                    SensitivityLevel::Normal => Sensitivity::Normal,
                    SensitivityLevel::Personal => Sensitivity::Personal,
                    SensitivityLevel::Private => Sensitivity::Private,
                    SensitivityLevel::Confidential => Sensitivity::Confidential,
                })
            }
            Predicate::HasAttachments => view.has_attachments = Some(true),
            Predicate::Flagged => view.flagged_for_action = Some(FlaggedForAction::Any),
            Predicate::Categories(keywords) => {
                let names = view.categories.get_or_insert_default();
                *supported &=
                    keywords.len() == 1 && (matches!(side, Side::Condition) || names.0.is_empty());
                names.0.extend(
                    keywords
                        .iter()
                        .map(|keyword| Cow::Owned(categories.name(keyword).into_owned())),
                );
            }
            Predicate::MessageType(kind) => {
                *match kind {
                    MessageKind::AutomaticForward => &mut view.is_automatic_forward,
                    MessageKind::AutomaticReply => &mut view.is_automatic_reply,
                    MessageKind::Encrypted => &mut view.is_encrypted,
                    MessageKind::MeetingRequest => &mut view.is_meeting_request,
                    MessageKind::MeetingResponse => &mut view.is_meeting_response,
                    MessageKind::NonDeliveryReport => &mut view.is_ndr,
                    MessageKind::ReadReceipt => &mut view.is_read_receipt,
                    MessageKind::Signed => &mut view.is_signed,
                    MessageKind::Voicemail => &mut view.is_voicemail,
                } = Some(true)
            }
            Predicate::ReceivedAfter(_) | Predicate::ReceivedBefore(_) => {
                if view.within_date_range.is_none() {
                    let (after, before) = RuleLogic::received_range(predicates);
                    let at = |seconds: Option<i64>| seconds.map(|at| DateTime::utc(UtcSeconds(at)));
                    view.within_date_range = Some(DateRange {
                        start_date_time: at(after),
                        end_date_time: at(before),
                    });
                }
            }
            Predicate::Size { min_kb, max_kb } => {
                *supported &= view.within_size_range.is_none();
                view.within_size_range = Some(SizeRange {
                    minimum_size: min_kb.map(|min| i32::try_from(min).unwrap_or(i32::MAX)),
                    maximum_size: max_kb.map(|max| i32::try_from(max).unwrap_or(i32::MAX)),
                })
            }
        }
    }
    Some(view)
}

fn category_names(keywords: &[String], categories: AccountCategories<'_>) -> Strings<'static> {
    Strings(
        keywords
            .iter()
            .map(|keyword| Cow::Owned(categories.name(keyword).into_owned()))
            .collect(),
    )
}

fn string_list(values: &[String]) -> Strings<'static> {
    Strings(
        values
            .iter()
            .map(|value| Cow::Owned(value.clone()))
            .collect(),
    )
}

fn address_list(values: &[String]) -> Addresses<'static> {
    Addresses(
        values
            .iter()
            .map(|address| EmailAddress {
                email_address: Some(Cow::Owned(address.clone())),
                routing_type: Some(Cow::Borrowed(SMTP)),
                ..Default::default()
            })
            .collect(),
    )
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/ews/rules/tests.rs"]
mod tests;
