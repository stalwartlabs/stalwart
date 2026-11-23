/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod folders;
mod rule;

use super::{
    context::{EwsCaller, EwsContext},
    reply::{RESPONSE_CAPACITY, ews_response},
    service::is_own,
};
use crate::rules::{load_rules, sidecar::sidecar_forwards_to};
use common::Server;
use email::sieve::rules::ForwarderId;
use exchange_proto::{
    ews::{
        MessageResult, Operation, Status,
        requests::delegate::{AddDelegate, GetDelegate, RemoveDelegate, UpdateDelegate},
        responses::{
            ShapeD,
            delegate::{DelegateUserMessage, DeliverMeetingRequestsTail},
        },
        schema::{DeliverMeetingRequests, MailboxType, ResponseCode},
        types::{
            address::{EmailAddress, SingleRecipient},
            delegate::DelegateUser,
            folder::UserId,
        },
    },
    rules::{DelegateRule, DeliverMode},
};
use folders::{DelegateFolders, Target, role_of};
use http_proto::HttpResponse;
use rule::{DelegateEdit, DelegateWriter, Planned, Resolved, RuleOutcome};
use smallvec::SmallVec;
use std::borrow::Cow;
use types::type_state::DataType;

pub(crate) use rule::Principal;

const OTHER_MAILBOX: &str = "Only the authenticated user's own mailbox can be accessed.";
const NOT_DELEGATE: &str = "The user is not a delegate for the mailbox.";
const NO_USER: &str = "The delegate does not map to a user in the Active Directory.";
const ALREADY_EXISTS: &str = "The user is already a delegate for the mailbox.";
const CANNOT_ADD_OWNER: &str = "The mailbox owner cannot be added as a delegate.";
const CUSTOM_LEVEL: &str = "Custom folder permission levels cannot be set through delegates.";
const NOTHING_GRANTED: &str =
    "A delegate needs a folder permission level or copies of meeting messages.";
const NO_PERMISSION: &str = "The account is not allowed to manage Sieve scripts.";
const NO_SCOPE: &str = "The access token does not grant access to the inbox rules.";
const REDIRECT_LIMIT: &str = "The number of delegates that receive meeting copies exceeds the redirect limit of this server.";
const RULE_FAILED: &str = "The delegate rule could not be saved.";
const ACL_FAILED: &str = "The folder permissions could not be saved.";
const BUSY: &str = "The delegates changed while they were being saved; retry the request.";
const ROUTING_SMTP: &str = "SMTP";
const MAX_REPRESENTING: usize = 16;
const MAX_DELEGATOR_CANDIDATES: usize = 32;

type DelegateResult = MessageResult<'static, DelegateUserMessage<'static>>;
type DelegateShape = ShapeD<'static, DelegateUserMessage<'static>, DeliverMeetingRequestsTail>;

pub(crate) async fn get_delegate(
    server: &Server,
    ctx: &EwsContext,
    request: &GetDelegate<'_>,
) -> trc::Result<HttpResponse> {
    let body = if is_own(server, ctx, request.mailbox.email_address.as_deref()).await? {
        read_delegates(server, ctx, request).await?
    } else {
        other_mailbox(Operation::GetDelegate)
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&body);
    Ok(ews_response(out))
}

pub(crate) async fn add_delegate(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &AddDelegate<'_>,
) -> trc::Result<HttpResponse> {
    let own = is_own(server, ctx, request.mailbox.email_address.as_deref()).await?;
    let users = request
        .delegate_users
        .iter()
        .map(|user| (&user.user_id, Some(user)));
    respond(
        server,
        ctx,
        caller,
        own,
        DelegateEdit::Add,
        users,
        request.deliver_meeting_requests,
    )
    .await
}

pub(crate) async fn update_delegate(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UpdateDelegate<'_>,
) -> trc::Result<HttpResponse> {
    let own = is_own(server, ctx, request.mailbox.email_address.as_deref()).await?;
    let users = request
        .delegate_users
        .iter()
        .flatten()
        .map(|user| (&user.user_id, Some(user)));
    respond(
        server,
        ctx,
        caller,
        own,
        DelegateEdit::Update,
        users,
        request.deliver_meeting_requests,
    )
    .await
}

pub(crate) async fn remove_delegate(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &RemoveDelegate<'_>,
) -> trc::Result<HttpResponse> {
    let own = is_own(server, ctx, request.mailbox.email_address.as_deref()).await?;
    let users = request.user_ids.iter().map(|user_id| (user_id, None));
    respond(server, ctx, caller, own, DelegateEdit::Remove, users, None).await
}

async fn respond<'u, 'x: 'u>(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    own: bool,
    edit: DelegateEdit,
    users: impl Iterator<Item = (&'u UserId<'x>, Option<&'u DelegateUser<'x>>)>,
    mode: Option<DeliverMeetingRequests>,
) -> trc::Result<HttpResponse> {
    let body = if own {
        let writer = DelegateWriter {
            server,
            caller,
            account_id: ctx.account.account_id,
            sieve_scope: ctx.account.data_types.contains(DataType::SieveScript),
        };
        write_delegates(writer, ctx, edit, users, mode.map(deliver_mode)).await?
    } else {
        other_mailbox(edit.operation())
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&body);
    Ok(ews_response(out))
}

async fn delegator_for(
    server: &Server,
    account_id: u32,
    marker: &str,
    candidates: &[&str],
) -> trc::Result<Delegator> {
    let markers = marker
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<SmallVec<[&str; 4]>>();
    if markers.is_empty() {
        return Ok(Delegator::Refused);
    }
    let secret = server.core.oauth.oauth_key.as_bytes();
    let mut checked = SmallVec::<[u32; 8]>::new();
    let mut outcome = Delegator::Unknown;
    for address in candidates {
        let Some(delegator) = server.account_id_from_email(address, true).await? else {
            continue;
        };
        if delegator == account_id || checked.contains(&delegator) {
            continue;
        }
        checked.push(delegator);
        let forwarder = ForwarderId::new(secret, delegator).to_string();
        if !markers
            .iter()
            .any(|value| value.eq_ignore_ascii_case(&forwarder))
        {
            continue;
        }
        if sidecar_forwards_to(server, delegator, account_id).await? {
            return Principal::load_user(server, delegator)
                .await
                .map(Delegator::Found);
        }
        outcome = Delegator::Refused;
    }
    Ok(outcome)
}

enum Delegator {
    Found(Option<Principal>),
    Refused,
    Unknown,
}

#[derive(Default)]
pub(crate) struct Representing(Vec<(u32, Box<str>, Option<Principal>)>);

impl Representing {
    pub(crate) async fn of<'a>(
        &mut self,
        server: &Server,
        account_id: u32,
        marker: &str,
        candidates: impl Iterator<Item = &'a str>,
    ) -> trc::Result<Option<SingleRecipient<'static>>> {
        Ok(self
            .principal(server, account_id, marker, candidates)
            .await?
            .map(|principal| {
                SingleRecipient(EmailAddress {
                    name: Some(Cow::Owned(principal.name)),
                    email_address: Some(Cow::Owned(principal.address)),
                    routing_type: Some(Cow::Borrowed(ROUTING_SMTP)),
                    mailbox_type: Some(MailboxType::Mailbox),
                    ..Default::default()
                })
            }))
    }

    pub(crate) async fn principal<'a>(
        &mut self,
        server: &Server,
        account_id: u32,
        marker: &str,
        candidates: impl Iterator<Item = &'a str>,
    ) -> trc::Result<Option<Principal>> {
        if let Some((_, _, known)) = self
            .0
            .iter()
            .find(|(id, key, _)| *id == account_id && &**key == marker)
        {
            return Ok(known.clone());
        }
        let candidates = candidates
            .take(MAX_DELEGATOR_CANDIDATES)
            .collect::<Vec<_>>();
        let found = match delegator_for(server, account_id, marker, &candidates).await? {
            Delegator::Found(found) => found,
            Delegator::Refused => None,
            Delegator::Unknown => return Ok(None),
        };
        if self.0.len() < MAX_REPRESENTING {
            self.0.push((account_id, marker.into(), found.clone()));
        }
        Ok(found)
    }

    pub(crate) fn remember_none(&mut self, account_id: u32, marker: &str) {
        if self.0.len() < MAX_REPRESENTING {
            self.0.push((account_id, marker.into(), None));
        }
    }
}

async fn read_delegates(
    server: &Server,
    ctx: &EwsContext,
    request: &GetDelegate<'_>,
) -> trc::Result<DelegateShape> {
    let account_id = ctx.account.account_id;
    let folders = DelegateFolders::load(server, ctx).await?;
    let loaded = if ctx.account.data_types.contains(DataType::SieveScript) {
        Some(load_rules(server, account_id).await?)
    } else {
        None
    };
    let delegate = loaded.as_ref().and_then(|loaded| {
        loaded.set.delegate().map(|(_, rule, delegate)| {
            let runs = loaded.is_active && rule.state.runs();
            (delegate, runs)
        })
    });
    let stored = delegate.map(|(delegate, _)| delegate);
    let members = folders.members(server, account_id, stored).await?;
    let include_permissions = request.include_permissions;
    let receives = |principal_id: u32| {
        delegate.is_some_and(|(delegate, runs)| {
            runs && !delegate.forwards().is_empty() && delegate.has_recipient(principal_id)
        })
    };
    let view = |principal_id: u32, user_id: UserId<'static>| MessageResult {
        status: Status::SUCCESS,
        body: Some(DelegateUserMessage {
            user: Some(DelegateUser {
                user_id,
                delegate_permissions: include_permissions
                    .then(|| folders.permissions(principal_id)),
                receive_copies_of_meeting_messages: Some(receives(principal_id)),
                view_private_items: Some(false),
            }),
        }),
    };
    let mut messages = Vec::new();
    match &request.user_ids {
        Some(user_ids) => {
            messages.reserve(user_ids.len());
            for user_id in user_ids {
                let resolved = rule::resolve(server, user_id, stored).await?;
                messages.push(match resolved.map(Resolved::into_principal) {
                    Some(principal) if members.iter().any(|member| member.id == principal.id) => {
                        view(principal.id, principal.user_id())
                    }
                    Some(_) => error(ResponseCode::ErrorNotDelegate, NOT_DELEGATE),
                    None => error(ResponseCode::ErrorDelegateNoUser, NO_USER),
                });
            }
        }
        None => {
            messages.extend(
                members
                    .iter()
                    .map(|principal| view(principal.id, principal.user_id())),
            );
        }
    }
    Ok(ShapeD {
        op: Operation::GetDelegate,
        status: Status::SUCCESS,
        messages,
        tail: Some(DeliverMeetingRequestsTail(meeting_requests(
            delegate.map_or(DeliverMode::default(), |(delegate, _)| delegate.mode),
        ))),
    })
}

async fn write_delegates<'u, 'x: 'u>(
    writer: DelegateWriter<'_>,
    ctx: &EwsContext,
    edit: DelegateEdit,
    users: impl Iterator<Item = (&'u UserId<'x>, Option<&'u DelegateUser<'x>>)>,
    mode: Option<DeliverMode>,
) -> trc::Result<DelegateShape> {
    let DelegateWriter {
        server, account_id, ..
    } = writer;
    let folders = DelegateFolders::load(server, ctx).await?;
    let loaded = load_rules(server, account_id).await?;
    let current = loaded
        .set
        .delegate()
        .filter(|_| writer.sieve_scope)
        .map(|(_, _, delegate)| delegate.clone());
    let members = folders
        .members(server, account_id, current.as_ref())
        .await?;

    let mut answers: Vec<Result<usize, (ResponseCode, &'static str)>> = Vec::new();
    let mut planned: Vec<Planned> = Vec::new();
    let lookup = match edit {
        DelegateEdit::Add => None,
        DelegateEdit::Update | DelegateEdit::Remove => current.as_ref(),
    };
    for (user_id, user) in users {
        let resolved = match rule::resolve(server, user_id, lookup).await? {
            Some(Resolved::Orphan(_)) if edit != DelegateEdit::Remove => None,
            resolved => resolved.map(Resolved::into_principal),
        };
        let answer = match resolved {
            None => Err((ResponseCode::ErrorDelegateNoUser, NO_USER)),
            Some(principal) if principal.id == account_id => {
                Err((ResponseCode::ErrorDelegateCannotAddOwner, CANNOT_ADD_OWNER))
            }
            Some(principal) => {
                let known = members.iter().any(|member| member.id == principal.id);
                let repeated = planned.iter().any(|plan| plan.principal.id == principal.id);
                match edit {
                    DelegateEdit::Add if known || repeated => {
                        Err((ResponseCode::ErrorDelegateAlreadyExists, ALREADY_EXISTS))
                    }
                    DelegateEdit::Update | DelegateEdit::Remove if !known || repeated => {
                        Err((ResponseCode::ErrorNotDelegate, NOT_DELEGATE))
                    }
                    _ => plan(&folders, current.as_ref(), edit, principal, user),
                }
            }
        };
        answers.push(answer.map(|plan| {
            planned.push(plan);
            planned.len() - 1
        }));
    }

    let outcome = if planned.is_empty() && mode.is_none() {
        RuleOutcome::Saved {
            active: loaded.is_active,
        }
    } else {
        let outcome = rule::apply(writer, &folders, loaded, edit, &mut planned, mode).await?;
        ctx.folders_changed();
        outcome
    };
    let (status, active) = match outcome {
        RuleOutcome::Saved { active } => (Status::SUCCESS, active),
        RuleOutcome::Failed(code, text) if planned.is_empty() => (Status::error(code, text), false),
        RuleOutcome::Failed(..) => (Status::SUCCESS, false),
    };
    let messages = answers
        .into_iter()
        .map(|answer| match answer {
            Ok(index) => match (&outcome, planned.get(index)) {
                (&RuleOutcome::Failed(code, text), _) => error(code, text),
                (_, Some(plan)) if plan.failed => {
                    error(ResponseCode::ErrorDelegateValidationFailed, ACL_FAILED)
                }
                (_, Some(plan)) => success(edit, plan, active),
                (_, None) => error(ResponseCode::ErrorDelegateValidationFailed, RULE_FAILED),
            },
            Err((code, text)) => error(code, text),
        })
        .collect();
    Ok(ShapeD {
        op: edit.operation(),
        status,
        messages,
        tail: None,
    })
}

fn plan(
    folders: &DelegateFolders,
    current: Option<&DelegateRule>,
    edit: DelegateEdit,
    principal: rule::Principal,
    user: Option<&DelegateUser<'_>>,
) -> Result<Planned, (ResponseCode, &'static str)> {
    let mut levels = [None; Target::COUNT];
    if let Some(permissions) = user.and_then(|user| user.delegate_permissions.as_ref()) {
        for (target, level) in Target::ALL.into_iter().zip(&mut levels) {
            if let Some(requested) = target.level(permissions) {
                *level = Some(
                    role_of(requested)
                        .ok_or((ResponseCode::ErrorDelegateValidationFailed, CUSTOM_LEVEL))?,
                );
            }
        }
    }
    let copies = user.and_then(|user| user.receive_copies_of_meeting_messages);
    let plan = Planned {
        principal,
        levels,
        copies,
        failed: false,
        receives: false,
    };
    if edit != DelegateEdit::Remove && !plan.grants_anything(folders, current) {
        return Err((ResponseCode::ErrorDelegateValidationFailed, NOTHING_GRANTED));
    }
    Ok(plan)
}

fn success(edit: DelegateEdit, plan: &Planned, active: bool) -> DelegateResult {
    MessageResult {
        status: Status::SUCCESS,
        body: Some(DelegateUserMessage {
            user: (edit != DelegateEdit::Remove).then(|| DelegateUser {
                user_id: plan.principal.user_id(),
                delegate_permissions: None,
                receive_copies_of_meeting_messages: Some(plan.receives && active),
                view_private_items: Some(false),
            }),
        }),
    }
}

fn error(code: ResponseCode, text: &'static str) -> DelegateResult {
    MessageResult {
        status: Status::error(code, text),
        body: None,
    }
}

fn other_mailbox(op: Operation) -> DelegateShape {
    ShapeD {
        op,
        status: Status::error(ResponseCode::ErrorAccessDenied, OTHER_MAILBOX),
        messages: Vec::new(),
        tail: None,
    }
}

const fn deliver_mode(mode: DeliverMeetingRequests) -> DeliverMode {
    match mode {
        DeliverMeetingRequests::DelegatesOnly => DeliverMode::DelegatesOnly,
        DeliverMeetingRequests::DelegatesAndMe => DeliverMode::DelegatesAndMe,
        DeliverMeetingRequests::DelegatesAndSendInformationToMe => {
            DeliverMode::DelegatesAndSendInformationToMe
        }
        DeliverMeetingRequests::NoForward => DeliverMode::NoForward,
    }
}

const fn meeting_requests(mode: DeliverMode) -> DeliverMeetingRequests {
    match mode {
        DeliverMode::DelegatesOnly => DeliverMeetingRequests::DelegatesOnly,
        DeliverMode::DelegatesAndMe => DeliverMeetingRequests::DelegatesAndMe,
        DeliverMode::DelegatesAndSendInformationToMe => {
            DeliverMeetingRequests::DelegatesAndSendInformationToMe
        }
        DeliverMode::NoForward => DeliverMeetingRequests::NoForward,
    }
}
