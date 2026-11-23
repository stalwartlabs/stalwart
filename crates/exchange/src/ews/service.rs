/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EwsContext,
    owns_address,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use common::Server;
use exchange_proto::ews::{
    Fault, MessageResult, Operation, Status,
    requests::{
        config::GetAppManifests,
        mailtips::{GetMailTips, GetPasswordExpirationDate, GetServiceConfiguration},
    },
    responses::{
        ShapeB,
        config::{GetAppManifestsBody, GetUserRetentionPolicyTagsBody},
        mailtips::{
            GetMailTipsBody, GetPasswordExpirationDateBody, GetServiceConfigurationBody,
            MailTipsMessage, ServiceConfigurationMessage,
        },
        people::AddEntityFeedbackBody,
    },
    schema::{MailTipType, ResponseCode, ServiceConfigurationName},
    types::{
        address::EmailAddress,
        generated::{MailTips, MailTipsServiceConfiguration},
        mailtip::MailTipSet,
        response_extra::SmtpDomains,
    },
    write_fault,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::borrow::Cow;

const MAX_MAIL_TIPS_RECIPIENTS: i32 = 50;
const LARGE_AUDIENCE_THRESHOLD: i32 = 25;
const LARGE_AUDIENCE_CAP: i32 = 1000;
const OTHER_MAILBOX: &str = "Only the authenticated user's own mailbox can be accessed.";
const ACTING_AS: &str = "The ActingAs parameter does not match the authenticated user.";
const UNSUPPORTED_CONFIGURATION: &str = "The requested configuration is not available.";
const INVALID_API_VERSION: &str = "The apiVersionSupported parameter is invalid. It should be in the form of major version, minor version, separated by '.', for example '2.34'.";
const NO_RBAC_ROLE: &str =
    "The caller has not assigned any of the RBAC roles requested in the management role header.";

pub(crate) async fn get_password_expiration_date(
    server: &Server,
    ctx: &EwsContext,
    request: &GetPasswordExpirationDate<'_>,
) -> trc::Result<HttpResponse> {
    let own = is_own(server, ctx, request.mailbox_smtp_address.as_deref()).await?;
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::GetPasswordExpirationDate,
        status: if own {
            Status::SUCCESS
        } else {
            Status::error(ResponseCode::ErrorAccessDenied, OTHER_MAILBOX)
        },
        body: own.then(GetPasswordExpirationDateBody::never_expires),
    });
    Ok(ews_response(out))
}

pub(crate) fn get_mail_tips<'x>(
    server: &Server,
    ctx: &EwsContext,
    request: &GetMailTips<'x>,
) -> HttpResponse {
    let max_message_size = request
        .mail_tips_requested
        .is_none_or(|requested| {
            requested.contains(MailTipType::All) || requested.contains(MailTipType::MaxMessageSize)
        })
        .then(|| max_message_size(server));
    let body: GetMailTipsBody<'x> = GetMailTipsBody {
        messages: request
            .recipients
            .iter()
            .map(|recipient| MessageResult {
                status: Status::success(),
                body: Some(MailTipsMessage {
                    mail_tips: Some(MailTips {
                        recipient_address: EmailAddress {
                            name: recipient.name.clone(),
                            email_address: recipient.email_address.clone(),
                            routing_type: recipient.routing_type.clone(),
                            ..Default::default()
                        },
                        pending_mail_tips: MailTipSet::default(),
                        out_of_office: None,
                        mailbox_full: None,
                        custom_mail_tip: None,
                        total_member_count: None,
                        external_member_count: None,
                        max_message_size,
                        delivery_restricted: None,
                        is_moderated: None,
                        invalid_recipient: None,
                        scope: None,
                        recipient_suggestions: None,
                        prefer_accessible_content: None,
                    }),
                }),
            })
            .collect(),
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::GetMailTips,
        status: Status::SUCCESS,
        body: Some(body),
    });
    ews_response(out)
}

pub(crate) async fn get_service_configuration(
    server: &Server,
    ctx: &EwsContext,
    request: &GetServiceConfiguration<'_>,
) -> trc::Result<HttpResponse> {
    let acting_as = request
        .acting_as
        .as_ref()
        .and_then(|mailbox| mailbox.email_address.as_deref());
    let own = is_own(server, ctx, acting_as).await?;
    let body = own.then(|| GetServiceConfigurationBody {
        messages: request
            .requested_configuration
            .iter()
            .map(|name| match name {
                ServiceConfigurationName::MailTips => MessageResult {
                    status: Status::SUCCESS,
                    body: Some(ServiceConfigurationMessage {
                        mail_tips: Some(MailTipsServiceConfiguration {
                            mail_tips_enabled: true,
                            max_recipients_per_get_mail_tips_request: MAX_MAIL_TIPS_RECIPIENTS,
                            max_message_size: max_message_size(server),
                            large_audience_threshold: LARGE_AUDIENCE_THRESHOLD,
                            show_external_recipient_count: false,
                            internal_domains: SmtpDomains::default(),
                            policy_tips_enabled: false,
                            large_audience_cap: LARGE_AUDIENCE_CAP,
                        }),
                    }),
                },
                _ => MessageResult {
                    status: Status::error(
                        ResponseCode::ErrorInvalidOperation,
                        UNSUPPORTED_CONFIGURATION,
                    ),
                    body: None,
                },
            })
            .collect(),
    });
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::GetServiceConfiguration,
        status: if own {
            Status::SUCCESS
        } else {
            Status::error(ResponseCode::ErrorInvalidArgument, ACTING_AS)
        },
        body,
    });
    Ok(ews_response(out))
}

pub(crate) fn get_app_manifests(ctx: &EwsContext, request: &GetAppManifests<'_>) -> HttpResponse {
    let valid = request
        .api_version_supported
        .as_deref()
        .is_none_or(is_api_version);
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::GetAppManifests,
        status: if valid {
            Status::SUCCESS
        } else {
            Status::error(ResponseCode::ErrorInvalidRequest, INVALID_API_VERSION)
        },
        body: valid.then_some(GetAppManifestsBody),
    });
    ews_response(out)
}

fn is_api_version(value: &str) -> bool {
    value
        .split_once('.')
        .is_some_and(|(major, minor)| is_version_number(major) && is_version_number(minor))
}

fn is_version_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn rbac_role_required(ctx: &EwsContext) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    write_fault(
        &mut out,
        &ctx.version,
        &Fault {
            code: ResponseCode::ErrorAccessDenied,
            text: Cow::Borrowed(NO_RBAC_ROLE),
            line: None,
            message_xml: None,
        },
    );
    ews_response(out).with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
}

pub(crate) fn get_user_retention_policy_tags(ctx: &EwsContext) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::GetUserRetentionPolicyTags,
        status: Status::SUCCESS,
        body: Some(GetUserRetentionPolicyTagsBody),
    });
    ews_response(out)
}

pub(crate) fn add_entity_feedback(ctx: &EwsContext) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::AddEntityFeedback,
        status: Status::SUCCESS,
        body: Some(AddEntityFeedbackBody::default()),
    });
    ews_response(out)
}

pub(crate) fn get_user_photo() -> HttpResponse {
    HttpResponse::new(StatusCode::NOT_FOUND).with_no_store()
}

pub(super) async fn is_own(
    server: &Server,
    ctx: &EwsContext,
    address: Option<&str>,
) -> trc::Result<bool> {
    match address.map(str::trim).filter(|address| !address.is_empty()) {
        Some(address) => owns_address(server, address, ctx.account.account_id).await,
        None => Ok(true),
    }
}

fn max_message_size(server: &Server) -> i32 {
    i32::try_from(server.core.email.mail_max_size).unwrap_or(i32::MAX)
}
