/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FORWARDED_BY_HEADER, ForwarderId, MANAGED_SCRIPT_ID, MANAGED_SCRIPT_NAME, ManagedScript,
    RuleError, VacationResponse, is_managed_script,
};
use crate::sieve::{
    ArchivedSieveScript, SieveScript,
    ingest::{SieveScriptIngest, verified_script},
};
use common::{
    Server,
    auth::{AccessToken, AccountInfo},
    ipc::CacheInvalidation,
    storage::index::ObjectIndexBuilder,
};
use groupware::calendar::working_hours::WorkingHoursHandler;
use registry::schema::enums::StorageQuota;
use sieve::{
    Sieve,
    bytecode::view::{Op, Value},
};
use std::{fmt::Display, future::Future};
use store::{
    SerializeInfallible, ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, ValueClass, assert::AssertValue, now},
};
use trc::{AddContext, StoreEvent};
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::{Field, PrincipalField, SieveField},
};

pub struct ManagedScriptState {
    pub script: ManagedScript,
    stored: Stored,
    activity: ManagedActivity,
}

enum Stored {
    Absent,
    Decoded {
        archive: Archive<ArchiveBytes>,
        bytecode: Bytecode,
    },
    Undecodable {
        archive: Archive<ArchiveBytes>,
        reason: trc::Error,
        keep_copy: bool,
    },
}

enum Bytecode {
    Current { source: BlobHash },
    Recompiled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedActivity {
    Inactive { active: Option<u32> },
    Active,
    IncludedBy(u32),
    Unknown,
}

enum Activation {
    Unchanged,
    Activate { observed: Option<u32> },
    Deactivate,
    Included(u32),
}

#[derive(Debug)]
pub enum SaveError {
    Conflict,
    Invalid(RuleError),
}

pub trait ManagedSieveScript: Sync + Send {
    fn managed_script_read(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<ManagedScript>> + Send;

    fn managed_script_load(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<ManagedScriptState>> + Send;

    fn managed_vacation_read(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<VacationResponse>>> + Send;

    fn managed_script_activity(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<ManagedActivity>> + Send;

    fn managed_script_included_by(
        &self,
        account_id: u32,
        document_id: u32,
    ) -> impl Future<Output = trc::Result<bool>> + Send;

    fn managed_script_save(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        state: ManagedScriptState,
    ) -> impl Future<Output = trc::Result<Result<Option<u64>, SaveError>>> + Send;
}

impl ManagedSieveScript for Server {
    async fn managed_script_read(&self, account_id: u32) -> trc::Result<ManagedScript> {
        read_stored(self, account_id)
            .await
            .map(|(script, _)| script)
    }

    async fn managed_script_load(&self, account_id: u32) -> trc::Result<ManagedScriptState> {
        let (mut script, stored) = read_stored(self, account_id).await?;
        let activity = match self.managed_script_activity(account_id).await? {
            ManagedActivity::Active if matches!(stored, Stored::Absent) => {
                ManagedActivity::Inactive {
                    active: Some(MANAGED_SCRIPT_ID),
                }
            }
            activity => activity,
        };
        if activity.is_inactive()
            && let Some(vacation) = &mut script.vacation
        {
            vacation.is_enabled = false;
        }
        Ok(ManagedScriptState {
            script,
            stored,
            activity,
        })
    }

    async fn managed_vacation_read(
        &self,
        account_id: u32,
    ) -> trc::Result<Option<VacationResponse>> {
        let Some(mut vacation) = read_stored(self, account_id).await?.0.vacation else {
            return Ok(None);
        };
        if vacation.is_enabled
            && self
                .managed_script_activity(account_id)
                .await?
                .is_inactive()
        {
            vacation.is_enabled = false;
        }
        Ok(Some(vacation))
    }

    async fn managed_script_activity(&self, account_id: u32) -> trc::Result<ManagedActivity> {
        let active = self.sieve_script_get_active_id_cached(account_id).await?;
        Ok(match active {
            Some(MANAGED_SCRIPT_ID) => ManagedActivity::Active,
            Some(document_id) => match self
                .managed_script_included_by(account_id, document_id)
                .await
            {
                Ok(true) => ManagedActivity::IncludedBy(document_id),
                Ok(false) => ManagedActivity::Inactive { active },
                Err(err) => {
                    trc::error!(
                        err.account_id(account_id)
                            .document_id(document_id)
                            .details("Failed to check whether the active Sieve script includes the managed script")
                            .caused_by(trc::location!())
                    );
                    ManagedActivity::Unknown
                }
            },
            None => ManagedActivity::Inactive { active },
        })
    }

    async fn managed_script_included_by(
        &self,
        account_id: u32,
        document_id: u32,
    ) -> trc::Result<bool> {
        let Some(active) = self
            .sieve_script_load(account_id, document_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(false);
        };
        let mut recompiled = None;
        let sieve = verified_script(self, account_id, &active, &mut recompiled).await?;
        Ok(sieve.ops().any(|op| {
            matches!(
                op,
                Ok((_, Op::Include { global: false, name: Value::Text(name), .. }))
                    if is_managed_script(name)
            )
        }))
    }

    async fn managed_script_save(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        state: ManagedScriptState,
    ) -> trc::Result<Result<Option<u64>, SaveError>> {
        let ManagedScriptState {
            script,
            stored,
            activity,
        } = state;
        let account = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let account_zone = if script.uses_account_zone() {
            self.account_time_zone(account_id)
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };
        let forwarder = self
            .core
            .sieve
            .untrusted_runtime
            .can_edit_header(FORWARDED_BY_HEADER)
            .then(|| ForwarderId::new(self.core.oauth.oauth_key.as_bytes(), account_id));
        let text = script.emit(forwarder, account.addresses(), account_zone);
        let text_hash = BlobHash::generate(text.as_bytes());
        let activation = match (script.runs_anything(), activity) {
            (_, ManagedActivity::IncludedBy(document_id)) => Activation::Included(document_id),
            (true, ManagedActivity::Inactive { active }) => {
                Activation::Activate { observed: active }
            }
            (false, ManagedActivity::Active) => Activation::Deactivate,
            _ => Activation::Unchanged,
        };
        if let Stored::Decoded {
            bytecode: Bytecode::Current { source },
            ..
        } = &stored
            && *source == text_hash
            && matches!(activation, Activation::Unchanged | Activation::Included(_))
        {
            return Ok(Ok(None));
        }
        let compiled = match self.core.sieve.untrusted_compiler.compile(text.as_bytes()) {
            Ok(compiled) => compiled,
            Err(err) => return Ok(Err(SaveError::Invalid(RuleError::Compile(err.to_string())))),
        };
        let instructions = match script.verify(&compiled) {
            Ok(instructions) => instructions,
            Err(err) => return Ok(Err(SaveError::Invalid(err))),
        };
        let cpu_limit = self.core.sieve.untrusted_runtime.cpu_limit();
        if instructions > cpu_limit {
            return Ok(Err(SaveError::Invalid(RuleError::TooManyInstructions {
                instructions,
                limit: cpu_limit,
            })));
        }

        let (current, decode_failure) = match stored {
            Stored::Absent => (None, None),
            Stored::Decoded { archive, .. } => (Some(archive), None),
            Stored::Undecodable {
                archive,
                reason,
                keep_copy,
            } => (Some(archive), Some((reason, keep_copy))),
        };
        let current = current
            .as_ref()
            .map(|archive| archive.to_unarchived::<SieveScript>())
            .transpose()
            .caused_by(trc::location!())?;
        let (blob_hash, blob_hold) = self
            .hold_blob(
                account_id,
                text_hash,
                text.as_bytes(),
                60,
                &self.core.blob.email,
            )
            .await?;

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript);
        let recovered = match (&decode_failure, &current) {
            (Some((_, true)), Some(current)) => {
                keep_recovered_copy(self, &mut batch, access_token, &account, current.inner).await?
            }
            _ => false,
        };

        let changes = SieveScript {
            name: MANAGED_SCRIPT_NAME.to_string(),
            blob_hash,
            size: u32::try_from(text.len()).unwrap_or(u32::MAX),
            _vacation: None,
            script: compiled.to_bytes(),
            metadata_flags: current
                .as_ref()
                .map_or(0, |current| current.inner.metadata_flags),
        };
        batch.with_document(MANAGED_SCRIPT_ID);
        if current.is_none() {
            batch.assert_value(
                ValueClass::Property(Field::ARCHIVE.into()),
                AssertValue::None,
            );
        }
        batch
            .custom(
                ObjectIndexBuilder::new()
                    .with_current_opt(current)
                    .with_changes(changes)
                    .with_changed_by(access_token.changed_by()),
            )
            .caused_by(trc::location!())?;
        blob_hold.release(&mut batch);

        let active_changed = match activation {
            Activation::Activate { observed } => {
                batch
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .assert_value(
                        PrincipalField::ActiveScriptId,
                        observed.map_or(AssertValue::None, AssertValue::U32),
                    )
                    .set(
                        PrincipalField::ActiveScriptId,
                        MANAGED_SCRIPT_ID.serialize(),
                    );
                true
            }
            Activation::Deactivate => {
                batch
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .clear_if_equals(PrincipalField::ActiveScriptId, MANAGED_SCRIPT_ID);
                true
            }
            Activation::Included(document_id) => {
                batch
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .assert_value(PrincipalField::ActiveScriptId, document_id);
                false
            }
            Activation::Unchanged => false,
        };

        match self.commit_batch(batch).await {
            Ok(ids) => {
                if let Some((reason, keep_copy)) = decode_failure {
                    trc::error!(
                        StoreEvent::UnexpectedError
                            .into_err()
                            .account_id(account_id)
                            .reason(reason)
                            .details(match (keep_copy, recovered) {
                                (true, true) => {
                                    "Replaced the undecodable managed Sieve script and kept an inactive copy"
                                }
                                (true, false) => {
                                    "Replaced the undecodable managed Sieve script, no room for a recovered copy"
                                }
                                (false, _) => {
                                    "Replaced the managed Sieve script whose source is missing"
                                }
                            })
                            .caused_by(trc::location!())
                    );
                }
                if active_changed {
                    self.invalidate_caches(CacheInvalidation::ActiveSieveScript(account_id).into())
                        .await
                        .caused_by(trc::location!())?;
                }
                Ok(Ok(Some(
                    ids.last_change_id(account_id, SyncCollection::SieveScript),
                )))
            }
            Err(err) if err.is_assertion_failure() => Ok(Err(SaveError::Conflict)),
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }
}

impl ManagedActivity {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            ManagedActivity::Active | ManagedActivity::IncludedBy(_)
        )
    }

    pub fn is_inactive(self) -> bool {
        matches!(self, ManagedActivity::Inactive { .. })
    }
}

impl ManagedScriptState {
    pub fn is_active(&self) -> bool {
        self.activity.is_active()
    }

    pub fn keep_activation(&mut self) {
        if let ManagedActivity::Inactive { .. } = self.activity {
            self.activity = ManagedActivity::Unknown;
        }
    }
}

async fn keep_recovered_copy(
    server: &Server,
    batch: &mut BatchBuilder,
    access_token: &AccessToken,
    account: &AccountInfo,
    current: &ArchivedSieveScript,
) -> trc::Result<bool> {
    let account_id = account.account_id;
    let script_count = server
        .document_ids(account_id, Collection::SieveScript, SieveField::Name)
        .await
        .caused_by(trc::location!())?
        .len();
    let max_scripts =
        u64::from(server.object_quota(account.object_quotas(), StorageQuota::MaxSieveScripts));
    let name = format!("{MANAGED_SCRIPT_NAME}-recovered-{}", now());
    let is_taken = !server
        .document_ids_matching(
            account_id,
            Collection::SieveScript,
            SieveField::Name,
            name.as_bytes(),
        )
        .await
        .caused_by(trc::location!())?
        .is_empty();
    if script_count >= max_scripts || is_taken {
        return Ok(false);
    }

    let slot = batch.reserve_document_id(account_id, Collection::SieveScript);
    batch
        .create_document(slot)
        .custom(
            ObjectIndexBuilder::<(), _>::new()
                .with_changes(SieveScript {
                    name,
                    blob_hash: BlobHash::from(&current.blob_hash),
                    size: current.size.to_native(),
                    _vacation: None,
                    script: current.script.to_vec(),
                    metadata_flags: 0,
                })
                .with_changed_by(access_token.changed_by()),
        )
        .caused_by(trc::location!())?;
    Ok(true)
}

async fn read_stored(server: &Server, account_id: u32) -> trc::Result<(ManagedScript, Stored)> {
    let Some(archive) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::SieveScript,
            MANAGED_SCRIPT_ID,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok((ManagedScript::default(), Stored::Absent));
    };
    let stored = archive
        .unarchive::<SieveScript>()
        .caused_by(trc::location!())?;
    let decoded = Sieve::from_bytes(stored.script.as_ref())
        .ok()
        .map(|sieve| ManagedScript::decode(&sieve).map_err(undecodable));
    if let Some(decoded) = decoded {
        let bytecode = Bytecode::Current {
            source: BlobHash::from(&stored.blob_hash),
        };
        return Ok(classify(archive, decoded, bytecode));
    }

    let Some(source) = server
        .get_blob(stored.blob_hash.0.as_ref(), 0..usize::MAX)
        .await
        .caused_by(trc::location!())?
    else {
        return Ok((
            ManagedScript::default(),
            Stored::Undecodable {
                archive,
                reason: undecodable("The source of the managed Sieve script is missing"),
                keep_copy: false,
            },
        ));
    };
    let decoded = server
        .core
        .sieve
        .untrusted_compiler
        .compile(&source)
        .map_err(undecodable)
        .and_then(|sieve| ManagedScript::decode(&sieve).map_err(undecodable));
    Ok(classify(archive, decoded, Bytecode::Recompiled))
}

fn classify(
    archive: Archive<ArchiveBytes>,
    decoded: trc::Result<ManagedScript>,
    bytecode: Bytecode,
) -> (ManagedScript, Stored) {
    match decoded {
        Ok(script) => (script, Stored::Decoded { archive, bytecode }),
        Err(reason) => (
            ManagedScript::default(),
            Stored::Undecodable {
                archive,
                reason,
                keep_copy: true,
            },
        ),
    }
}

fn undecodable(err: impl Display) -> trc::Error {
    StoreEvent::UnexpectedError
        .into_err()
        .reason(err)
        .caused_by(trc::location!())
}
