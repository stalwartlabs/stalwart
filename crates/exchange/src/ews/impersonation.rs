/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::{AccessToken, authentication::UsernameParts},
};
use compact_str::CompactString;
use exchange_proto::ews::{fault::Fault, header::ConnectingSid, schema::ResponseCode};
use registry::schema::enums::Permission;
use std::borrow::Cow;

const SID_UNSUPPORTED: &str = "Impersonation by security identifier is not supported.";
const NO_MAILBOX: &str = "The impersonated address does not refer to a valid account.";
const IMPERSONATION_DENIED: &str = "The account does not have permission to impersonate.";
const USER_DENIED: &str = "The account does not have permission to impersonate the requested user.";
const IMPERSONATION: &str = "EWS impersonation";

pub(crate) enum Impersonation {
    Own,
    Target(AccessToken),
}

#[derive(Clone, Copy)]
enum Refusal {
    Sid,
    NoMailbox,
    Denied,
    #[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
    UserDenied,
}

struct Request<'x> {
    caller: &'x AccessToken,
    requested: &'x str,
    session_id: u64,
}

pub(crate) async fn impersonate(
    server: &Server,
    caller: &AccessToken,
    target: &ConnectingSid<'_>,
    session_id: u64,
) -> trc::Result<Result<Impersonation, Fault<'static>>> {
    let (requested, account_id) = match target {
        ConnectingSid::PrincipalName(address)
        | ConnectingSid::PrimarySmtpAddress(address)
        | ConnectingSid::SmtpAddress(address) => (
            address.as_ref(),
            server.account_id_from_email(address, false).await?,
        ),
        ConnectingSid::Sid(sid) => (sid.as_ref(), None),
    };
    if account_id.is_some_and(|account_id| caller.is_account_id(account_id)) {
        return Ok(Ok(Impersonation::Own));
    }
    let request = Request {
        caller,
        requested,
        session_id,
    };
    if !caller.has_permission(Permission::Impersonate) {
        return Ok(Err(request.refuse(Refusal::Denied)));
    }
    let account_id = match (account_id, target) {
        (Some(account_id), _) => Some(account_id),
        (None, ConnectingSid::Sid(_)) => return Ok(Err(request.refuse(Refusal::Sid))),
        (None, _) => {
            let parts = UsernameParts::new(requested);
            if parts.is_master() {
                None
            } else {
                server.impersonated_account_id(parts.account()).await?
            }
        }
    };
    let Some(account_id) = account_id else {
        return Ok(Err(request.refuse(Refusal::NoMailbox)));
    };
    let effective = AccessToken::new_maybe_invalid(server.access_token(account_id).await?)
        .with_token_scope(caller.token_scope());
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if caller
        .tenant_id()
        .is_some_and(|tenant_id| effective.tenant_id() != Some(tenant_id))
    {
        return Ok(Err(request.refuse(Refusal::UserDenied)));
    }
    // SPDX-SnippetEnd
    trc::event!(
        Auth(trc::AuthEvent::Success),
        AccountName = CompactString::from(requested),
        AccountId = account_id,
        Id = caller.account_id(),
        SpanId = session_id,
        Details = IMPERSONATION,
    );
    Ok(Ok(Impersonation::Target(effective)))
}

impl Request<'_> {
    fn refuse(&self, refusal: Refusal) -> Fault<'static> {
        let requested = CompactString::from(self.requested);
        let caller = self.caller.account_id();
        let (code, text) = match refusal {
            Refusal::Sid => (ResponseCode::ErrorImpersonationFailed, SID_UNSUPPORTED),
            Refusal::NoMailbox => (ResponseCode::ErrorNonExistentMailbox, NO_MAILBOX),
            Refusal::Denied => (ResponseCode::ErrorImpersonationDenied, IMPERSONATION_DENIED),
            Refusal::UserDenied => (ResponseCode::ErrorImpersonateUserDenied, USER_DENIED),
        };
        match refusal {
            Refusal::Sid | Refusal::NoMailbox => trc::event!(
                Auth(trc::AuthEvent::Failed),
                AccountName = requested,
                AccountId = caller,
                SpanId = self.session_id,
                Details = IMPERSONATION,
            ),
            Refusal::Denied | Refusal::UserDenied => trc::event!(
                Security(trc::SecurityEvent::Unauthorized),
                AccountName = requested,
                AccountId = caller,
                SpanId = self.session_id,
                Details = IMPERSONATION,
            ),
        }
        Fault {
            code,
            text: Cow::Borrowed(text),
            line: None,
            message_xml: None,
        }
    }
}
