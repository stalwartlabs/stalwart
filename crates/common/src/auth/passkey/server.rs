/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    PASSKEY_CHALLENGE_TTL, PasskeyCeremony, PasskeyChallenge, PasskeyError, PasskeyRp,
    assertion::PasskeyAssertion,
};
use crate::{Server, auth::AccessToken};
use registry::schema::{enums::Permission, structs};
use std::net::IpAddr;
use store::dispatch::lookup::KeyValue;

pub enum PasskeySignIn {
    Authenticated(AccessToken),
    UnknownCredential,
}

impl From<PasskeyError> for trc::Error {
    #[cold]
    fn from(err: PasskeyError) -> Self {
        trc::AuthEvent::Failed.into_err().reason(err.as_str())
    }
}

impl Server {
    pub async fn issue_passkey_challenge(
        &self,
        ceremony: PasskeyCeremony,
    ) -> trc::Result<PasskeyChallenge> {
        let challenge = PasskeyChallenge::random();
        self.in_memory_store()
            .key_set(
                KeyValue::new(challenge.store_key(ceremony), vec![1])
                    .expires(PASSKEY_CHALLENGE_TTL),
            )
            .await
            .map(|_| challenge)
    }

    pub async fn consume_passkey_challenge(
        &self,
        challenge: &PasskeyChallenge,
        ceremony: PasskeyCeremony,
    ) -> trc::Result<bool> {
        self.in_memory_store()
            .key_delete(challenge.store_key(ceremony).as_slice())
            .await
    }

    pub async fn authenticate_passkey(
        &self,
        assertion: &PasskeyAssertion,
        rp: &PasskeyRp<'_>,
        remote_ip: IpAddr,
        session_id: u64,
    ) -> trc::Result<PasskeySignIn> {
        match self
            .passkey_access_token(assertion, rp, remote_ip, session_id)
            .await
            .and_then(|token| {
                token
                    .map(|token| token.assert_has_permission(Permission::Authenticate))
                    .transpose()
            }) {
            Ok(Some(token)) => Ok(PasskeySignIn::Authenticated(token)),
            Ok(None) => {
                self.delay_failed_authentication().await;
                if self.has_auth_fail2ban() && self.is_auth_fail2banned(remote_ip, None).await? {
                    Err(trc::SecurityEvent::AuthenticationBan
                        .into_err()
                        .ctx(trc::Key::RemoteIp, remote_ip))
                } else {
                    Ok(PasskeySignIn::UnknownCredential)
                }
            }
            Err(err) => Err(self.reject_authentication(err, remote_ip, None).await),
        }
    }

    async fn passkey_access_token(
        &self,
        assertion: &PasskeyAssertion,
        rp: &PasskeyRp<'_>,
        remote_ip: IpAddr,
        session_id: u64,
    ) -> trc::Result<Option<AccessToken>> {
        let assertion = assertion
            .parse(rp)
            .map_err(|err| trc::Error::from(err).ctx(trc::Key::SpanId, session_id))?;
        let account_id = assertion.user_handle.0;

        if !self
            .consume_passkey_challenge(&assertion.challenge, PasskeyCeremony::SignIn)
            .await?
        {
            return Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountId, account_id)
                .ctx(trc::Key::SpanId, session_id)
                .reason("Passkey challenge expired or already used"));
        }

        let Some(account) = self
            .registry()
            .object::<structs::Account>(account_id.into())
            .await?
            .and_then(|account| account.into_user())
        else {
            trc::event!(
                Auth(trc::AuthEvent::Failed),
                AccountId = account_id,
                SpanId = session_id,
                Reason = "Passkey account not found",
            );
            return Ok(None);
        };

        if self
            .domain_by_id(account.domain_id.document_id())
            .await?
            .is_none_or(|domain| self.get_directory_for_cached_domain(&domain).is_some())
        {
            return Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountName, account.name)
                .ctx(trc::Key::AccountId, account_id)
                .ctx(trc::Key::SpanId, session_id)
                .reason("Passkeys are only accepted for internal directory accounts"));
        }

        let Some(credential) = account
            .passkeys()
            .find(|credential| credential.key_id == assertion.key_id)
        else {
            trc::event!(
                Auth(trc::AuthEvent::Failed),
                AccountName = account.name,
                AccountId = account_id,
                SpanId = session_id,
                Reason = "Passkey credential not found",
            );
            return Ok(None);
        };
        let credential_id = credential.credential_id.document_id();

        if let Err(err) = assertion.verify_signature(credential) {
            return Err(trc::Error::from(err)
                .ctx(trc::Key::AccountName, account.name)
                .ctx(trc::Key::AccountId, account_id)
                .ctx(trc::Key::Id, credential_id)
                .ctx(trc::Key::SpanId, session_id));
        }

        trc::event!(
            Auth(trc::AuthEvent::Success),
            AccountName = account.name,
            AccountId = account_id,
            Id = credential_id,
            SpanId = session_id,
            Details = "Authenticated with passkey",
        );

        self.access_token(account_id)
            .await
            .and_then(|token| AccessToken::new(token, remote_ip))
            .map(Some)
    }
}
