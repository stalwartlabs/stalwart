/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::metadata::{
        ContainerTarget, MetadataAccess, MetadataPatches, MetadataSupport, MetadataType,
        ObjectMetadata, PreloadedContainers, PreparedMetadata, is_empty_update, reject_uncommitted,
    },
    blob::download::BlobDownload,
    changes::state::{MetadataStateManager, StateManager},
};
use common::{
    Server,
    auth::{AccessToken, AccountCache},
    storage::{
        index::ObjectIndexBuilder,
        metadata::{MetadataLog, PrivateMetadataCommit},
    },
};
use email::{
    presence::update_sieve_presence,
    sieve::{
        ArchivedSieveScript, SieveScript, delete::SieveScriptDelete, ingest::SieveScriptIngest,
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::sieve::{Sieve, SieveProperty, SieveValue},
    references::resolve::ResolveCreatedReference,
    request::{MaybeInvalid, capability::CapabilityIds, reference::MaybeIdReference},
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use rand::distr::Alphanumeric;
use registry::schema::enums::StorageQuota;
use sieve::compiler::ErrorType;
use std::future::Future;
use store::{
    ValueKey,
    rand::{RngExt, rng},
    write::{Archive, ArchiveBytes, BatchBuilder, PendingId, Slot},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::{PrincipalField, SieveField},
    id::Id,
    metadata::MetadataKinds,
};

struct PendingSieveScript {
    id: String,
    slot: Slot,
    blob_hash: BlobHash,
    blob_size: usize,
    is_active: bool,
}

pub struct SetContext<'x> {
    account_id: u32,
    access_token: &'x AccessToken,
    account_cache: &'x AccountCache,
    response: SetResponse<Sieve>,
}

pub trait SieveScriptSet: Sync + Send {
    fn sieve_script_set(
        &self,
        request: SetRequest<'_, Sieve>,
        access_token: &AccessToken,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<SetResponse<Sieve>>> + Send;

    #[allow(clippy::type_complexity)]
    fn sieve_set_item<'x>(
        &self,
        changes_: Value<'_, SieveProperty, SieveValue>,
        update: Option<(u32, Archive<&'x ArchivedSieveScript>)>,
        ctx: &SetContext,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<Result<SetItemResponse<'x>, SetError<SieveProperty>>>> + Send;
}

impl SieveScriptSet for Server {
    async fn sieve_script_set(
        &self,
        mut request: SetRequest<'_, Sieve>,
        access_token: &AccessToken,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> trc::Result<SetResponse<Sieve>> {
        let account_id = request.account_id.document_id();
        let sieve_ids = self
            .document_ids(account_id, Collection::SieveScript, SieveField::Name)
            .await?;
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let object_metadata =
            ObjectMetadata::new(self, access_token, using, MetadataType::SieveScript);
        let viewer = object_metadata.viewer();
        let shared_state = self
            .get_state(account_id, SyncCollection::SieveScript)
            .await?;
        let mut ctx = SetContext {
            account_id,
            access_token,
            account_cache: &account,
            response: SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
                .with_state(
                    self.assert_metadata_state(
                        viewer,
                        account_id,
                        Collection::SieveScript,
                        shared_state.clone(),
                        &request.if_in_state,
                    )
                    .await?,
                ),
        };
        let metadata_support = object_metadata.support();
        let containers = object_metadata
            .preload_updates(self, account_id, request.update.as_ref(), |_| {
                Some(MetadataKinds::JMAP)
            })
            .await?;
        let mut commit = PrivateMetadataCommit::default();
        let mut private_batch = BatchBuilder::new();
        let mut private_commit = PrivateMetadataCommit::default();
        let mut will_update_private = Vec::new();
        let will_destroy = ctx.response.collect_will_destroy(request.unwrap_destroy());

        // Validate active script id
        if let Some(MaybeIdReference::Id(id)) = &request.arguments.on_success_activate_script
            && !sieve_ids.contains(id.document_id())
        {
            request.arguments.on_success_activate_script = None;
        }

        // Process creates
        let mut batch = BatchBuilder::new();
        let mut activations: Vec<(PendingId, bool)> = Vec::new();
        let mut activate_script = match &request.arguments.on_success_activate_script {
            Some(MaybeIdReference::Id(id)) => Some(PendingId::Assigned(id.document_id())),
            _ => None,
        };
        let mut pending_creates: Vec<PendingSieveScript> = Vec::new();
        'create: for (id, mut object) in request.unwrap_create() {
            if sieve_ids.len()
                < self.object_quota(account.object_quotas(), StorageQuota::MaxSieveScripts) as u64
            {
                let metadata_patches =
                    match object_metadata.extract(MetadataPatches::for_create(), &mut object) {
                        Ok(patches) => patches,
                        Err(err) => {
                            ctx.response.not_created.append(id, err);
                            continue 'create;
                        }
                    };
                match self
                    .sieve_set_item(object, None, &ctx, session.session_id)
                    .await?
                {
                    Ok(mut result) => {
                        let metadata_writes = match sieve_metadata_writes(
                            self,
                            metadata_patches,
                            &mut result,
                            &ctx,
                            metadata_support,
                            &containers,
                            None,
                        )
                        .await?
                        {
                            Ok(writes) => writes,
                            Err(err) => {
                                ctx.response.not_created.append(id, err);
                                continue 'create;
                            }
                        };
                        // Store blob
                        let sieve = &mut result.builder.changes_mut().unwrap();
                        let (blob_hash, blob_hold) = self
                            .put_temporary_blob(
                                account_id,
                                result.blob_update.as_ref().unwrap(),
                                60,
                            )
                            .await?;
                        sieve.blob_hash = blob_hash;
                        let blob_size = sieve.size as usize;
                        let blob_hash = sieve.blob_hash.clone();

                        // Write record
                        let slot = batch.reserve_document_id(account_id, Collection::SieveScript);
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::SieveScript)
                            .create_document(slot)
                            .custom(
                                result
                                    .builder
                                    .with_changed_by(ctx.access_token.account_tenant_ids()),
                            )
                            .caused_by(trc::location!())?
                            .clear(blob_hold);
                        if let Some(prepared) = metadata_writes {
                            prepared
                                .build(slot, &mut batch, &mut commit)
                                .caused_by(trc::location!())?;
                        }
                        batch.commit_point();

                        // Set isActive if needed
                        if let Some(set_item) = result.set_item {
                            activations.push((PendingId::Slot(slot), set_item));
                        }

                        // Update active script if needed
                        let is_active = if let Some(MaybeIdReference::Reference(id_ref)) =
                            &request.arguments.on_success_activate_script
                            && id_ref == &id
                        {
                            activate_script = Some(PendingId::Slot(slot));
                            true
                        } else {
                            false
                        };

                        pending_creates.push(PendingSieveScript {
                            id,
                            slot,
                            blob_hash,
                            blob_size,
                            is_active,
                        });
                    }
                    Err(err) => {
                        ctx.response.not_created.append(id, err);
                    }
                }
            } else {
                ctx.response.not_created.append(
                    id,
                    SetError::new(SetErrorType::OverQuota).with_description(concat!(
                        "There are too many sieve scripts, ",
                        "please delete some before adding a new one."
                    )),
                );
            }
        }

        // Process updates
        'update: for (id, mut object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    ctx.response
                        .not_updated
                        .append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                ctx.response
                    .not_updated
                    .append(id, SetError::will_destroy());
                continue 'update;
            }
            let metadata_patches =
                match object_metadata.extract(MetadataPatches::for_update(), &mut object) {
                    Ok(patches) => patches,
                    Err(err) => {
                        ctx.response.not_updated.append(id, err);
                        continue 'update;
                    }
                };

            // Obtain sieve script
            let document_id = id.document_id();
            if let Some(sieve_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                ))
                .await?
            {
                let sieve = sieve_
                    .to_unarchived::<SieveScript>()
                    .caused_by(trc::location!())?;
                let is_metadata_only = metadata_patches.is_some()
                    && object
                        .as_object()
                        .is_some_and(|object| is_empty_update::<Sieve>(object, id));

                match self
                    .sieve_set_item(
                        object,
                        (document_id, sieve.clone()).into(),
                        &ctx,
                        session.session_id,
                    )
                    .await?
                {
                    Ok(mut result) => {
                        let metadata_writes = match sieve_metadata_writes(
                            self,
                            metadata_patches,
                            &mut result,
                            &ctx,
                            metadata_support,
                            &containers,
                            Some(document_id),
                        )
                        .await?
                        {
                            Ok(writes) => writes,
                            Err(err) => {
                                ctx.response.not_updated.append(id, err);
                                continue 'update;
                            }
                        };
                        // Prepare write batch
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::SieveScript)
                            .with_document(document_id);

                        let blob_id = if let Some(blob) = result.blob_update.take() {
                            // Store blob
                            let sieve = &mut result.builder.changes_mut().unwrap();
                            let (blob_hash, blob_hold) =
                                self.put_temporary_blob(account_id, &blob, 60).await?;
                            sieve.blob_hash = blob_hash;
                            batch.clear(blob_hold);

                            BlobId {
                                hash: sieve.blob_hash.clone(),
                                class: BlobClass::Linked {
                                    account_id,
                                    collection: Collection::SieveScript.into(),
                                    document_id,
                                },
                                section: BlobSection::new(0, sieve.size as usize, 0).into(),
                            }
                            .into()
                        } else {
                            None
                        };

                        // Set isActive if needed
                        if let Some(set_item) = result.set_item {
                            activations.push((PendingId::Assigned(document_id), set_item));
                        }

                        // Write record
                        let mut is_private_only = false;
                        if !is_metadata_only {
                            batch
                                .custom(
                                    result
                                        .builder
                                        .with_changed_by(ctx.access_token.account_tenant_ids()),
                                )
                                .caused_by(trc::location!())?;
                            if let Some(prepared) = metadata_writes {
                                prepared
                                    .build(document_id, &mut batch, &mut commit)
                                    .caused_by(trc::location!())?;
                            }
                            batch.commit_point();
                        } else if let Some(prepared) = metadata_writes {
                            is_private_only = prepared.is_private_only();
                            let (target, target_commit) = if is_private_only {
                                (&mut private_batch, &mut private_commit)
                            } else {
                                (&mut batch, &mut commit)
                            };
                            if let Some(presence) = prepared
                                .build(document_id, target, target_commit)
                                .caused_by(trc::location!())?
                            {
                                update_sieve_presence(
                                    target,
                                    account_id,
                                    document_id,
                                    &sieve,
                                    presence,
                                )
                                .caused_by(trc::location!())?;
                            }
                            target.commit_point();
                        }

                        // Update blobId property if needed
                        let mut result = Map::with_capacity(1);
                        if let Some(blob_id) = blob_id {
                            result.insert_unchecked(
                                SieveProperty::BlobId,
                                SieveValue::BlobId(blob_id),
                            );
                        }

                        // Add active script property if needed
                        if let Some(MaybeIdReference::Id(id)) =
                            &request.arguments.on_success_activate_script
                            && document_id == id.document_id()
                        {
                            result.insert_unchecked(SieveProperty::IsActive, true);
                        }

                        // Add result
                        let result = if !result.is_empty() {
                            Value::Object(result).into()
                        } else {
                            None
                        };
                        if is_private_only {
                            will_update_private.push((id, result));
                        } else {
                            ctx.response.updated.append(id, result);
                        }
                    }
                    Err(err) => {
                        ctx.response.not_updated.append(id, err);
                        continue 'update;
                    }
                }
            } else {
                ctx.response.not_updated.append(id, SetError::not_found());
            }
        }

        // Process deletions
        let active_script_id = self.sieve_script_get_active_id(account_id).await?;
        for id in will_destroy {
            let document_id = id.document_id();
            if sieve_ids.contains(document_id) {
                if active_script_id != Some(document_id) {
                    if self
                        .sieve_script_delete(account_id, document_id, ctx.access_token, &mut batch)
                        .await?
                    {
                        ctx.response.destroyed.push(id);
                    } else {
                        ctx.response.not_destroyed.append(id, SetError::not_found());
                    }
                } else {
                    ctx.response.not_destroyed.append(
                        id,
                        SetError::new(SetErrorType::ScriptIsActive)
                            .with_description("Deactivate Sieve script before deletion."),
                    );
                }
            } else {
                ctx.response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Non-standard script activation handling
        let mut on_success_deactivate_script = request
            .arguments
            .on_success_deactivate_script
            .unwrap_or(false);
        if activations.len() == 1 {
            let (document_id, set_item) = activations[0];
            let is_active = document_id
                .assigned()
                .is_some_and(|document_id| active_script_id == Some(document_id));
            if set_item {
                if request.arguments.on_success_activate_script.is_none() && !is_active {
                    activate_script = Some(document_id);
                }
            } else if !on_success_deactivate_script && is_active {
                on_success_deactivate_script = true;
            }
        }

        // Activate / deactivate scripts
        if ctx.response.not_created.is_empty()
            && ctx.response.not_updated.is_empty()
            && ctx.response.not_destroyed.is_empty()
            && (activate_script.is_some() || on_success_deactivate_script)
        {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);

            match activate_script {
                Some(document_id) => {
                    batch.set(PrincipalField::ActiveScriptId, document_id);
                }
                None => {
                    batch.clear(PrincipalField::ActiveScriptId);
                }
            }
        }

        // Write changes
        let mut shared_change_id = None;
        if !batch.is_empty() {
            match self.commit_batch(batch).await {
                Ok(assigned_ids) => {
                    self.private_metadata_committed(commit, &assigned_ids).await;
                    shared_change_id =
                        assigned_ids.change_id(account_id, SyncCollection::SieveScript);

                    for create in pending_creates {
                        let document_id = assigned_ids.slot(create.slot);
                        let mut result = Map::with_capacity(1)
                            .with_key_value(SieveProperty::Id, SieveValue::Id(document_id.into()))
                            .with_key_value(
                                SieveProperty::BlobId,
                                SieveValue::BlobId(BlobId {
                                    hash: create.blob_hash,
                                    class: BlobClass::Linked {
                                        account_id,
                                        collection: Collection::SieveScript.into(),
                                        document_id,
                                    },
                                    section: BlobSection::new(0, create.blob_size, 0).into(),
                                }),
                            );
                        if create.is_active {
                            result.insert_unchecked(SieveProperty::IsActive, true);
                        }
                        ctx.response.created.insert(create.id, result.into());
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    reject_uncommitted(
                        &mut ctx.response,
                        pending_creates.into_iter().map(|create| create.id),
                        "Another process modified this script, please try again.",
                    );
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        let mut has_private_changes = false;
        if !private_batch.is_empty() {
            match self.commit_batch(private_batch).await {
                Ok(assigned_ids) => {
                    has_private_changes = true;
                    self.private_metadata_committed(private_commit, &assigned_ids)
                        .await;
                    for (id, result) in will_update_private {
                        ctx.response.updated.append(id, result);
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    for (id, _) in will_update_private {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "Another process modified this script, please try again.",
                            ),
                        );
                    }
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        if shared_change_id.is_some() || has_private_changes {
            ctx.response.new_state = self
                .metadata_state(
                    viewer,
                    account_id,
                    Collection::SieveScript,
                    shared_change_id.map_or(shared_state, State::Exact),
                )
                .await?
                .into();
        }

        Ok(ctx.response)
    }

    #[allow(clippy::blocks_in_conditions)]
    async fn sieve_set_item<'x>(
        &self,
        changes_: Value<'_, SieveProperty, SieveValue>,
        update: Option<(u32, Archive<&'x ArchivedSieveScript>)>,
        ctx: &SetContext<'_>,
        session_id: u64,
    ) -> trc::Result<Result<SetItemResponse<'x>, SetError<SieveProperty>>> {
        // Vacation script cannot be modified
        if update
            .as_ref()
            .is_some_and(|(_, obj)| obj.inner.name.eq_ignore_ascii_case("vacation"))
        {
            return Ok(Err(SetError::forbidden().with_description(concat!(
                "The 'vacation' script cannot be modified, ",
                "use VacationResponse/set instead."
            ))));
        }

        // Parse properties
        let mut set_item = None;
        let mut changes = update
            .as_ref()
            .map(|(_, obj)| obj.deserialize().unwrap_or_default())
            .unwrap_or_default();
        let mut blob_id = None;
        for (property, mut value) in changes_.into_expanded_object() {
            if let Err(err) = ctx.response.resolve_self_references(&mut value, 0, false) {
                return Ok(Err(err));
            };
            match (&property, value) {
                (Key::Property(SieveProperty::Name), Value::Str(value)) => {
                    if value.len() > self.core.email.sieve_max_script_name {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(property.into_owned())
                            .with_description("Script name is too long.")));
                    } else if value.eq_ignore_ascii_case("vacation") {
                        return Ok(Err(SetError::forbidden()
                            .with_property(property.into_owned())
                            .with_description(
                                "The 'vacation' name is reserved, please use a different name.",
                            )));
                    } else if update
                        .as_ref()
                        .is_none_or(|(_, obj)| obj.inner.name != value.as_ref())
                        && let Some(id) = self
                            .document_ids_matching(
                                ctx.account_id,
                                Collection::SieveScript,
                                SieveField::Name,
                                value.as_bytes(),
                            )
                            .await?
                            .min()
                    {
                        return Ok(Err(SetError::already_exists()
                            .with_existing_id(id.into())
                            .with_description(format!(
                                "A sieve script with name '{}' already exists.",
                                value
                            ))));
                    }

                    changes.name = value.into_owned();
                }
                (
                    Key::Property(SieveProperty::BlobId),
                    Value::Element(SieveValue::BlobId(value)),
                ) => {
                    blob_id = value.into();
                    continue;
                }
                (Key::Property(SieveProperty::Name), Value::Null) => {
                    continue;
                }
                (Key::Property(SieveProperty::IsActive), Value::Bool(value)) => {
                    set_item = Some(value);
                    continue;
                }
                (Key::Property(SieveProperty::Id), value) => {
                    if update
                        .as_ref()
                        .map(|(document_id, _)| Id::from(*document_id))
                        .is_none_or(|expected| !crate::matches_id(&value, expected))
                    {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(SieveProperty::Id)
                            .with_description("The id property is immutable.".to_string())));
                    }
                }
                _ => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(property.into_owned())
                        .with_description("Invalid property or value.".to_string())));
                }
            }
        }

        if update.is_none() {
            // Add name if missing
            if changes.name.is_empty() {
                changes.name = rng()
                    .sample_iter(Alphanumeric)
                    .take(15)
                    .map(char::from)
                    .collect::<String>();
            }
        }

        let blob_update = if let Some(blob_id) = blob_id {
            if update.as_ref().is_none_or( |(document_id, _)| {
                !matches!(blob_id.class, BlobClass::Linked { account_id, collection, document_id: d } if account_id == ctx.account_id && collection == u8::from(Collection::SieveScript) && *document_id == d)
            }) {
                // Check access
                if let Some(bytes) = self.blob_download(&blob_id, ctx.access_token).await? {
                    // Check quota
                    match self
                        .has_available_quota(ctx.account_cache, bytes.len() as u64)
                        .await
                    {
                        Ok(_) => (),
                        Err(err) => {
                            if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota))
                                || err.matches(trc::EventType::Limit(trc::LimitEvent::TenantQuota))
                            {
                                trc::error!(err.account_id(ctx.account_id).span_id(session_id));
                                return Ok(Err(SetError::over_quota()));
                            } else {
                                return Err(err);
                            }
                        }
                    }

                    // Compile script
                    match self.core.sieve.untrusted_compiler.compile(&bytes) {
                        Ok(script) => {
                            changes.size = bytes.len() as u32;
                            changes.set_script(&script);
                            bytes.into()
                        }
                        Err(err) => {
                            return Ok(Err(SetError::new(
                                if let ErrorType::ScriptTooLong = &err.error_type() {
                                    SetErrorType::TooLarge
                                } else {
                                    SetErrorType::InvalidScript
                                },
                            )
                            .with_description(err.to_string())));
                        }
                    }
                } else {
                    return Ok(Err(SetError::new(SetErrorType::BlobNotFound)
                        .with_property(SieveProperty::BlobId)
                        .with_description("Blob does not exist.")));
                }
            } else {
                None
            }
        } else if update.is_none() {
            return Ok(Err(SetError::invalid_properties()
                .with_property(SieveProperty::BlobId)
                .with_description("Missing blobId.")));
        } else {
            None
        };

        // Validate
        Ok(Ok(SetItemResponse {
            builder: ObjectIndexBuilder::new()
                .with_changes(changes)
                .with_current_opt(update.map(|(_, current)| current)),
            blob_update,
            set_item,
        }))
    }
}

async fn sieve_metadata_writes(
    server: &Server,
    patches: Option<MetadataPatches>,
    result: &mut SetItemResponse<'_>,
    ctx: &SetContext<'_>,
    support: Option<&MetadataSupport>,
    containers: &PreloadedContainers,
    document_id: Option<u32>,
) -> trc::Result<Result<Option<PreparedMetadata>, SetError<SieveProperty>>> {
    let Some(patches) = patches else {
        return Ok(Ok(None));
    };
    let Some(support) = support else {
        return Ok(Err(patches.unsupported()));
    };
    let access = MetadataAccess {
        may_write_shared: true,
        may_read: true,
    };
    let update = match patches.apply(
        support,
        access,
        document_id.and_then(|document_id| containers.shared.get(document_id)),
        document_id.and_then(|document_id| containers.private.get(document_id)),
    ) {
        Ok(update) => update,
        Err(err) => return Ok(Err(err)),
    };
    if update.is_empty() {
        return Ok(Ok(None));
    }
    let prepared = match update
        .prepare(
            server,
            ContainerTarget {
                owner: ctx.account_cache,
                viewer_id: ctx.access_token.account_id(),
                collection: Collection::SieveScript,
                log: match document_id {
                    Some(_) => MetadataLog::Item { prefix: None },
                    None => MetadataLog::None,
                },
            },
        )
        .await?
    {
        Ok(prepared) => prepared,
        Err(err) => return Ok(Err(err)),
    };
    if let Some((kinds, script)) = prepared.shared_kinds().zip(result.builder.changes_mut()) {
        script.set_metadata_kinds(kinds);
    }
    Ok(Ok(Some(prepared)))
}

pub struct SetItemResponse<'x> {
    builder: ObjectIndexBuilder<Archive<&'x ArchivedSieveScript>, SieveScript>,
    blob_update: Option<Vec<u8>>,
    set_item: Option<bool>,
}
