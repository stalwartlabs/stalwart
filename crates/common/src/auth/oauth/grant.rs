/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{scope::OAuthScopes, token::TokenGrant};
use crate::{
    Server,
    auth::{AccessToken, GrantClient, RECOVERY_ADMIN_ID, TokenScope},
    cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
};
use registry::{
    schema::{
        enums::OAuthClientKind,
        prelude::{Object, ObjectInner, ObjectType, Property},
        structs::OAuthGrant,
    },
    types::{datetime::UTCDateTime, id::ObjectId, ipaddr::IpAddr},
};
use std::net::IpAddr as StdIpAddr;
use store::{
    blake3,
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::AddContext;
use types::id::Id;

pub const MAX_OAUTH_GRANTS: usize = 256;
pub const RECOVERY_ADMIN_GRANT_ID: u64 = 1 << 62;
const MAX_WRITE_ATTEMPTS: usize = 3;

pub struct NewOAuthGrant<'x> {
    pub account_id: u32,
    pub client_id: &'x str,
    pub client_name: Option<&'x str>,
    pub client_kind: OAuthClientKind,
    pub scopes: OAuthScopes,
    pub remote_ip: StdIpAddr,
}

pub struct StoredOAuthGrant {
    pub id: u64,
    pub revision: u64,
    pub grant: Box<OAuthGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDeletion {
    Unconditional,
    IfUnchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRotation {
    Issue { next: TokenGrant, rotated_at: u64 },
    Revoked,
    Rejected,
}

impl StoredOAuthGrant {
    pub fn account_id(&self) -> u32 {
        self.grant.account_id.document_id()
    }

    fn object_id(&self) -> ObjectId {
        ObjectId::new(ObjectType::OAuthGrant, Id::new(self.id))
    }

    pub fn is_current(&self, presented: u64) -> bool {
        matches!(
            self.rotation(presented),
            RotationStep::Retry | RotationStep::Rotate { .. }
        )
    }

    fn rotation(&self, presented: u64) -> RotationStep {
        let current = self.grant.generation;
        if presented == current {
            if self.grant.pending {
                RotationStep::Retry
            } else {
                RotationStep::Rotate {
                    stored: current,
                    next: current.saturating_add(1),
                }
            }
        } else if self.grant.pending && presented == current.saturating_add(1) {
            RotationStep::Rotate {
                stored: presented,
                next: presented.saturating_add(1),
            }
        } else if presented < current {
            RotationStep::Replay
        } else {
            RotationStep::Invalid
        }
    }
}

impl TokenScope {
    pub fn from_grant(grant_id: u64, grant: &OAuthGrant) -> Self {
        TokenScope::Grant {
            grant_id,
            scopes: OAuthScopes::from_registry(grant.scopes.iter()),
            client: if grant.client_kind == OAuthClientKind::FirstParty {
                GrantClient::FirstParty
            } else {
                GrantClient::ThirdParty
            },
        }
    }
}

fn client_id_hash(client_id: &str) -> String {
    blake3::hash(client_id.as_bytes()).to_hex().to_string()
}

fn prune_selection(last_used: &[i64], now: i64, idle_timeout: i64) -> Vec<bool> {
    let mut prune = last_used
        .iter()
        .map(|last_used| last_used.saturating_add(idle_timeout) <= now)
        .collect::<Vec<_>>();
    let mut live = last_used
        .iter()
        .zip(&prune)
        .enumerate()
        .filter(|(_, (_, expired))| !**expired)
        .map(|(idx, (last_used, _))| (*last_used, idx))
        .collect::<Vec<_>>();
    if live.len() >= MAX_OAUTH_GRANTS {
        live.sort_unstable();
        let excess = live.len() + 1 - MAX_OAUTH_GRANTS;
        for (_, idx) in live.into_iter().take(excess) {
            prune[idx] = true;
        }
    }
    prune
}

enum RotationStep {
    Retry,
    Rotate { stored: u64, next: u64 },
    Replay,
    Invalid,
}

impl Server {
    pub async fn oauth_grant(&self, grant_id: u64) -> trc::Result<Option<StoredOAuthGrant>> {
        self.registry()
            .get(ObjectId::new(ObjectType::OAuthGrant, Id::new(grant_id)))
            .await
            .caused_by(trc::location!())
            .map(|object| {
                object.and_then(|object| match object.inner {
                    ObjectInner::OAuthGrant(grant) => Some(StoredOAuthGrant {
                        id: grant_id,
                        revision: object.revision,
                        grant,
                    }),
                    _ => None,
                })
            })
    }

    pub async fn oauth_grant_scope(
        &self,
        grant_id: u64,
        account_id: u32,
    ) -> trc::Result<TokenScope> {
        match self.oauth_grant(grant_id).await? {
            Some(stored) if stored.account_id() == account_id => {
                Ok(TokenScope::from_grant(grant_id, &stored.grant))
            }
            None if account_id == RECOVERY_ADMIN_ID && grant_id == RECOVERY_ADMIN_GRANT_ID => {
                Ok(TokenScope::Grant {
                    grant_id,
                    scopes: OAuthScopes::ALL,
                    client: GrantClient::FirstParty,
                })
            }
            _ => Err(trc::AuthEvent::TokenExpired
                .into_err()
                .account_id(account_id)
                .id(grant_id)
                .details("OAuth grant revoked")),
        }
    }

    pub async fn renew_access_token(
        &self,
        access_token: &AccessToken,
        remote_ip: StdIpAddr,
    ) -> trc::Result<AccessToken> {
        let account_id = access_token.account_id();
        let inner = self.access_token(account_id).await?;
        let token_scope = match access_token.token_scope() {
            Some(TokenScope::Grant { grant_id, .. }) => {
                Some(self.oauth_grant_scope(grant_id, account_id).await?)
            }
            token_scope => token_scope,
        };
        AccessToken::renew(inner, access_token.credential_id(), token_scope, remote_ip)
    }

    pub async fn refresh_access_token(
        &self,
        access_token: &AccessToken,
        remote_ip: StdIpAddr,
    ) -> trc::Result<Option<AccessToken>> {
        let inner = self.access_token(access_token.account_id()).await?;
        if access_token.is_built_from(&inner) {
            Ok(None)
        } else {
            AccessToken::renew(
                inner,
                access_token.credential_id(),
                access_token.token_scope(),
                remote_ip,
            )
            .map(Some)
        }
    }

    pub async fn create_oauth_grant(&self, new: NewOAuthGrant<'_>) -> trc::Result<u64> {
        let mut invalidator = CacheInvalidationBuilder::default();
        self.prune_oauth_grants(new.account_id, &mut invalidator)
            .await?;

        let now = UTCDateTime::now();
        let grant = OAuthGrant {
            account_id: Id::from(new.account_id),
            client_id: new.client_id.to_string(),
            client_hash: client_id_hash(new.client_id),
            client_name: new
                .client_name
                .filter(|name| !name.is_empty())
                .map(str::to_string),
            client_kind: new.client_kind,
            scopes: new.scopes.to_registry(),
            remote_ip: Some(IpAddr(new.remote_ip)),
            created_at: now,
            last_used_at: now,
            generation: 0,
            pending: false,
        };
        let object = Object::new(grant.into());

        let result = self
            .registry()
            .write(RegistryWrite::insert(&object))
            .await
            .caused_by(trc::location!())?;
        self.invalidate_caches(invalidator).await?;

        match result {
            RegistryWriteResult::Success(id) => Ok(id.id()),
            failure => Err(trc::AuthEvent::Error
                .into_err()
                .account_id(new.account_id)
                .details("Failed to create OAuth grant")
                .reason(failure)
                .caused_by(trc::location!())),
        }
    }

    async fn prune_oauth_grants(
        &self,
        account_id: u32,
        invalidator: &mut CacheInvalidationBuilder,
    ) -> trc::Result<()> {
        let ids = self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::OAuthGrant).with_account(account_id))
            .await
            .caused_by(trc::location!())?;
        if ids.is_empty() {
            return Ok(());
        }

        let mut grants = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(stored) = self.oauth_grant(id.id()).await? {
                grants.push(stored);
            }
        }

        let last_used = grants
            .iter()
            .map(|stored| stored.grant.last_used_at.timestamp())
            .collect::<Vec<_>>();
        let prune = prune_selection(
            &last_used,
            now() as i64,
            self.core.oauth.oauth_expiry_refresh_token as i64,
        );
        for (stored, prune) in grants.into_iter().zip(prune) {
            if prune {
                self.delete_oauth_grant(stored, GrantDeletion::IfUnchanged, invalidator)
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn has_oauth_grant(
        &self,
        account_id: u32,
        client_id: &str,
        client_kind: OAuthClientKind,
        scopes: OAuthScopes,
    ) -> trc::Result<bool> {
        let idle_since =
            (now() as i64).saturating_sub(self.core.oauth.oauth_expiry_refresh_token as i64);
        for id in self
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::OAuthGrant)
                    .with_account(account_id)
                    .equal(Property::ClientHash, client_id_hash(client_id)),
            )
            .await
            .caused_by(trc::location!())?
        {
            if self.oauth_grant(id.id()).await?.is_some_and(|stored| {
                let grant = &stored.grant;
                grant.client_id == client_id
                    && grant.client_kind == client_kind
                    && grant.last_used_at.timestamp() > idle_since
                    && OAuthScopes::from_registry(grant.scopes.iter()).contains(scopes)
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn revoke_oauth_grants(
        &self,
        account_id: u32,
        invalidator: &mut CacheInvalidationBuilder,
    ) -> trc::Result<()> {
        for id in self
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::OAuthGrant).with_account(account_id))
            .await
            .caused_by(trc::location!())?
        {
            if let Some(stored) = self.oauth_grant(id.id()).await? {
                self.delete_oauth_grant(stored, GrantDeletion::Unconditional, invalidator)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn delete_oauth_grant(
        &self,
        mut stored: StoredOAuthGrant,
        mode: GrantDeletion,
        invalidator: &mut CacheInvalidationBuilder,
    ) -> trc::Result<bool> {
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let account_id = stored.account_id();
            let object_id = stored.object_id();
            let object =
                Object::with_revision(ObjectInner::OAuthGrant(stored.grant), stored.revision);
            match self
                .registry()
                .write(RegistryWrite::delete_object(object_id, &object))
                .await
            {
                Ok(RegistryWriteResult::Success(_)) => {
                    invalidator.invalidate(CacheInvalidation::OAuthGrant {
                        account_id,
                        grant_id: stored.id,
                    });
                    return Ok(true);
                }
                Ok(RegistryWriteResult::NotFound { .. }) => return Ok(false),
                Ok(failure) => {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .id(stored.id)
                        .details("Failed to delete OAuth grant")
                        .reason(failure)
                        .caused_by(trc::location!()));
                }
                Err(err) if err.is_assertion_failure() => {
                    if mode == GrantDeletion::IfUnchanged {
                        return Ok(false);
                    }
                    match self.oauth_grant(stored.id).await? {
                        Some(current) => stored = current,
                        None => return Ok(false),
                    }
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }

        Err(trc::StoreEvent::AssertValueFailed
            .into_err()
            .id(stored.id)
            .details("OAuth grant changed concurrently")
            .caused_by(trc::location!()))
    }

    pub async fn rotate_oauth_grant(
        &self,
        mut stored: StoredOAuthGrant,
        presented_generation: u64,
    ) -> trc::Result<GrantRotation> {
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let (stored_generation, next_generation) = match stored.rotation(presented_generation) {
                RotationStep::Retry => {
                    return Ok(GrantRotation::Issue {
                        next: TokenGrant {
                            id: stored.id,
                            generation: stored.grant.generation.saturating_add(1),
                        },
                        rotated_at: stored.grant.last_used_at.timestamp() as u64,
                    });
                }
                RotationStep::Rotate { stored, next } => (stored, next),
                RotationStep::Replay => {
                    trc::event!(
                        Auth(trc::AuthEvent::Failed),
                        AccountId = stored.account_id(),
                        Id = stored.id,
                        Reason = "Superseded refresh token reused, revoking OAuth grant",
                    );
                    let mut invalidator = CacheInvalidationBuilder::default();
                    self.delete_oauth_grant(stored, GrantDeletion::Unconditional, &mut invalidator)
                        .await?;
                    self.invalidate_caches(invalidator).await?;
                    return Ok(GrantRotation::Revoked);
                }
                RotationStep::Invalid => return Ok(GrantRotation::Rejected),
            };

            let now = UTCDateTime::now();
            let mut updated = stored.grant.clone();
            updated.generation = stored_generation;
            updated.pending = true;
            updated.last_used_at = now;
            if updated.client_hash.is_empty() {
                updated.client_hash = client_id_hash(&updated.client_id);
            }
            let old_object =
                Object::with_revision(ObjectInner::OAuthGrant(stored.grant), stored.revision);
            let new_object = Object::new(ObjectInner::OAuthGrant(updated));

            match self
                .registry()
                .write(RegistryWrite::update(
                    Id::new(stored.id),
                    &new_object,
                    &old_object,
                ))
                .await
            {
                Ok(RegistryWriteResult::Success(_)) => {
                    return Ok(GrantRotation::Issue {
                        next: TokenGrant {
                            id: stored.id,
                            generation: next_generation,
                        },
                        rotated_at: now.timestamp() as u64,
                    });
                }
                Ok(failure) => {
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .id(stored.id)
                        .details("Failed to rotate OAuth grant")
                        .reason(failure)
                        .caused_by(trc::location!()));
                }
                Err(err) if err.is_assertion_failure() => {
                    match self.oauth_grant(stored.id).await? {
                        Some(current) => stored = current,
                        None => return Ok(GrantRotation::Rejected),
                    }
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }

        Err(trc::StoreEvent::AssertValueFailed
            .into_err()
            .id(stored.id)
            .details("OAuth grant changed concurrently")
            .caused_by(trc::location!()))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/grant/tests.rs"]
mod tests;
