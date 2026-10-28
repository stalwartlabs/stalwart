/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::{
    EnterpriseRegistry,
    mapping::{
        ObjectResponse, RegistrySetResponse,
        account::account_set,
        action::action_set,
        bootstrap::bootstrap_set,
        cluster::{validate_coordinator, validate_in_memory_store},
        dkim::validate_dkim_signature,
        domain::{validate_dns_server, validate_domain},
        index_queue::index_queue_status_set,
        map_bootstrap_error,
        oauth_client::validate_oauth_client_object,
        principal::{
            AccountUpdate, schedule_account_destruction, validate_account, validate_account_access,
            validate_role,
        },
        public_key::validate_public_key,
        queued_message::queued_message_set,
        report::report_set,
        sieve::validate_sieve_script,
        spam_sample::spam_sample_set,
        task::task_set,
        tls::{validate_acme_directory, validate_acme_provider, validate_certificate},
    },
};
use common::{
    Server,
    auth::AccessToken,
    cache::invalidate::CacheInvalidationBuilder,
    expr::if_block::BootstrapExprExt,
    manager::{app_client::validate_url_prefix, application::WebApplicationManager},
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::registry::Registry,
    references::resolve::ResolveCreatedReference,
    request::{IntoValid, MaybeInvalid},
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::{JmapValue, JsonPointerPatch, MaybeUnpatched, RegistryValue},
    schema::{
        enums::Permission,
        prelude::{OBJ_FILTER_ACCOUNT, OBJ_SINGLETON, Object, ObjectInner, ObjectType, Property},
        structs::{Certificate, DkimSignature, DnsServer, Domain, PublicKey, Role, Task},
    },
    types::id::ObjectId,
};
use services::task_manager::reconcile::schedule_replacing;
use services::task_manager::tasks::rebuild_shares::RevokeAccountGrants;
use std::borrow::Cow;
use store::{
    registry::{
        bootstrap::Bootstrap,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::BatchBuilder,
};
use trc::AddContext;
use types::id::Id;
use utils::{map::vec_map::VecMap, outbound::OutboundPolicy};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::registry::mapping::principal::{tenant_object_quota, validate_tenant_quota};
#[cfg(feature = "enterprise")]
use registry::schema::{
    prelude::OBJ_FILTER_TENANT,
    structs::{Permissions, Tenant},
};
// SPDX-SnippetEnd

pub trait RegistrySet: Sync + Send {
    fn registry_set(
        &self,
        object_type: ObjectType,
        request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<Registry>>> + Send;
}

async fn registry_object_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<SetResponse<Registry>> {
    let server = set.server;
    let access_token = set.access_token;
    let object_type = set.object_type;
    let object_flags = object_type.flags();
    let is_singleton = (object_flags & OBJ_SINGLETON) != 0;
    let has_account_id = (object_flags & OBJ_FILTER_ACCOUNT) != 0;
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let is_tenant_filtered = set.is_tenant_filtered;
    #[cfg(feature = "enterprise")]
    let can_set_tenant = access_token.tenant_id().is_none();
    // SPDX-SnippetEnd
    let can_set_account = access_token.has_permission(Permission::Impersonate);
    let is_account_filtered = set.is_account_filtered;
    // Bundle modifications together
    let mut modifications = Vec::with_capacity(set.create.len() + set.update.len());
    for (id, value) in set.create.drain() {
        if is_singleton
            && let Some(object) = server
                .registry()
                .get(ObjectId::new(object_type, Id::singleton()))
                .await
                .caused_by(trc::location!())?
        {
            modifications.push((
                Modification::Create {
                    client_id: id,
                    object: Some(object),
                },
                value,
                Object::from(set.object_type),
            ));
        } else {
            modifications.push((
                Modification::Create {
                    client_id: id,
                    object: None,
                },
                value,
                Object::from(set.object_type),
            ));
        }
    }
    for (id, value) in set.update.drain(..) {
        if let Some(object) = server
            .registry()
            .get(ObjectId::new(object_type, id))
            .await
            .caused_by(trc::location!())?
        {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            let is_tenant_mismatch = is_tenant_filtered
                && access_token.tenant_id().map(Id::from) != object.inner.member_tenant_id();
            // SPDX-SnippetEnd
            #[cfg(not(feature = "enterprise"))]
            let is_tenant_mismatch = false;
            if is_tenant_mismatch
                || (is_account_filtered
                    && object.inner.account_id() != Some(Id::from(set.account_id)))
            {
                set.response.not_updated.append(id, SetError::not_found());
                continue;
            }

            modifications.push((
                Modification::Update {
                    id,
                    object: object.clone(),
                },
                value,
                object,
            ));
        } else if is_singleton {
            modifications.push((
                Modification::Update {
                    id,
                    object: Object::from(set.object_type),
                },
                value,
                Object::from(set.object_type),
            ));
        } else {
            set.response.not_updated.append(id, SetError::not_found());
        }
    }

    // Process modifications
    let mut cache_invalidator = CacheInvalidationBuilder::default();
    'outer: for (modification, mut value, mut new_object) in modifications {
        // Initial validations
        let is_create = matches!(modification, Modification::Create { .. });
        let mut unpatched_properties = VecMap::new();

        if let Err(err) = set.response.resolve_self_references(&mut value, 0, true) {
            set.failed(modification, err);
            continue 'outer;
        };

        if is_create
            || value
                .as_object()
                .unwrap()
                .get(&Key::Property(Property::Type))
                .and_then(|v| v.as_str())
                .is_some_and(|t| new_object.object_variant().is_some_and(|v| v != t))
        {
            // Patch object
            let ptr = JsonPointer::new(vec![]);
            let patch = JsonPointerPatch::new(&ptr).with_create(true);
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            let patch = patch.with_can_set_tenant(can_set_tenant);
            // SPDX-SnippetEnd
            match new_object.patch(patch.with_can_set_account(can_set_account), value) {
                Ok(MaybeUnpatched::Patched) => {}
                Ok(MaybeUnpatched::Unpatched { property, value }) => {
                    unpatched_properties.append(property, value);
                }
                Ok(MaybeUnpatched::UnpatchedMany { properties }) => {
                    unpatched_properties = properties;
                }
                Err(err) => {
                    set.failed(modification, err.into());
                    continue 'outer;
                }
            }

            // Add tenantId for tenant filtered objects
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            if is_tenant_filtered && let Some(tenant_id) = set.access_token.tenant_id() {
                new_object.inner.set_member_tenant_id(tenant_id.into());
            }
            // SPDX-SnippetEnd

            // Add accountId
            if has_account_id {
                new_object.inner.set_account_id(set.account_id.into());
            }
        } else {
            for (key, value) in value.into_expanded_object() {
                let ptr = match key {
                    Key::Property(Property::Type) => {
                        continue;
                    }
                    Key::Property(prop) => {
                        JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                    }
                    Key::Borrowed(other) => JsonPointer::parse(other),
                    Key::Owned(other) => JsonPointer::parse(&other),
                };

                // Patch object
                let patch = JsonPointerPatch::new(&ptr).with_create(false);
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let patch = patch.with_can_set_tenant(can_set_tenant);
                // SPDX-SnippetEnd
                match new_object.patch(patch.with_can_set_account(can_set_account), value) {
                    Ok(MaybeUnpatched::Patched) => {}
                    Ok(MaybeUnpatched::Unpatched { property, value }) => {
                        unpatched_properties.append(property, value);
                    }
                    Ok(MaybeUnpatched::UnpatchedMany { properties }) => {
                        if unpatched_properties.is_empty() {
                            unpatched_properties = properties;
                        } else {
                            unpatched_properties.extend(properties);
                        }
                    }
                    Err(err) => {
                        set.failed(modification, err.into());
                        continue 'outer;
                    }
                }
            }
        }

        // Validate objects
        let mut tasks = Vec::new();
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let outbound_policy = OutboundPolicy::for_tenant(new_object.inner.member_tenant_id());
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        let outbound_policy = OutboundPolicy::Trusted;
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if outbound_policy == OutboundPolicy::PublicOnly || new_object.inner.account_id().is_some()
        {
            let mut errors = Vec::new();
            new_object.validate_inline_secrets(&mut errors);
            if !errors.is_empty() {
                set.failed(
                    modification,
                    SetError::new(SetErrorType::ValidationFailed).with_validation_errors(errors),
                );
                continue 'outer;
            }
        }
        #[cfg(feature = "enterprise")]
        if let Some(quota) = tenant_object_quota(&new_object.inner)
            && let Some(tenant_id) = new_object.inner.member_tenant_id()
            && match &modification {
                Modification::Create { .. } => true,
                Modification::Update { object, .. } => {
                    object.inner.member_tenant_id() != Some(tenant_id)
                }
            }
            && let Err(err) =
                validate_tenant_quota(server, Some(tenant_id.document_id()), quota).await?
        {
            set.failed(modification, err);
            continue 'outer;
        }
        // SPDX-SnippetEnd
        let result = match &mut new_object.inner {
            ObjectInner::Account(account) => {
                validate_account(server, access_token, account, modification.as_account()).await?
            }
            ObjectInner::Role(role) => {
                validate_role(access_token, role, modification.as_role()).await?
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(masked_email) => {
                crate::registry::mapping::masked_email::validate_masked_email(
                    &set,
                    masked_email,
                    is_create,
                    unpatched_properties,
                )
                .await?
            }
            // SPDX-SnippetEnd
            ObjectInner::PublicKey(key) => {
                validate_public_key(&set, key, modification.as_public_key()).await?
            }
            ObjectInner::DkimSignature(key) => {
                validate_dkim_signature(key, modification.as_dkim_signature()).await?
            }
            ObjectInner::Domain(domain) => {
                validate_domain(
                    &set,
                    domain,
                    modification.as_domain(),
                    outbound_policy,
                    &mut tasks,
                )
                .await?
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(tenant)
                if tenant_grants_impersonate(tenant)
                    && !modification
                        .as_tenant()
                        .is_some_and(tenant_grants_impersonate) =>
            {
                Err(SetError::invalid_properties()
                    .with_property(Property::Permissions)
                    .with_description(
                        "The impersonate permission is reserved for server administrators",
                    ))
            }
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(tenant) => match &tenant.logo {
                Some(logo)
                    if modification
                        .as_tenant()
                        .is_none_or(|old| old.logo.as_ref() != Some(logo)) =>
                {
                    common::enterprise::logo::LogoSource::parse(logo, OutboundPolicy::PublicOnly)
                        .map(|_| ObjectResponse::default())
                        .map_err(|err| {
                            SetError::invalid_properties()
                                .with_property(Property::Logo)
                                .with_description(err.as_str())
                        })
                }
                _ => Ok(ObjectResponse::default()),
            },
            // SPDX-SnippetEnd
            ObjectInner::DnsServer(dns) => {
                validate_dns_server(&set, dns, modification.as_dns_server(), outbound_policy)
                    .await?
            }
            ObjectInner::InMemoryStore(store) => validate_in_memory_store(server, store).await?,
            ObjectInner::Coordinator(coordinator) => {
                validate_coordinator(server, coordinator).await?
            }
            ObjectInner::OAuthClient(client) => {
                validate_oauth_client_object(server, access_token, client).await?
            }
            ObjectInner::Application(app) => app
                .url_prefix
                .iter()
                .find_map(|prefix| validate_url_prefix(prefix).err())
                .map_or_else(
                    || Ok(ObjectResponse::default()),
                    |err| {
                        Err(SetError::invalid_properties()
                            .with_property(Property::UrlPrefix)
                            .with_description(err))
                    },
                ),
            ObjectInner::AcmeProvider(provider) if is_create => {
                validate_acme_provider(provider, unpatched_properties, outbound_policy).await?
            }
            ObjectInner::AcmeProvider(provider) => {
                validate_acme_directory(provider, outbound_policy)
                    .map(|_| ObjectResponse::default())
            }
            ObjectInner::Certificate(cert) => {
                validate_certificate(cert, modification.as_certificate()).await?
            }
            ObjectInner::SieveUserScript(script) => {
                validate_sieve_script(
                    set.server,
                    &script.contents,
                    modification.as_sieve_script(),
                    false,
                )
                .await?
            }
            ObjectInner::SieveSystemScript(script) => {
                validate_sieve_script(
                    set.server,
                    &script.contents,
                    modification.as_sieve_script(),
                    true,
                )
                .await?
            }
            _ => Ok(ObjectResponse::default()),
        };

        let mut response = match result {
            Ok(response) => response,
            Err(err) => {
                set.failed(modification, err);
                continue 'outer;
            }
        };

        // Validate expressions
        if let Some(expressions) = new_object.inner.expression_ctxs() {
            let mut bp = Bootstrap::new_uninitialized(server.registry().clone());

            for expression in expressions {
                bp.compile_expr(ObjectId::new(object_type, 0u64.into()), &expression);
                if !bp.errors.is_empty() {
                    set.failed(
                        modification,
                        map_bootstrap_error(bp.errors)
                            .with_object_id_opt(None)
                            .with_property(expression.property),
                    );
                    continue 'outer;
                }
            }
        }

        // Save object
        let result = match &modification {
            Modification::Create { client_id, object } => {
                if let Some(object) = object {
                    if object.inner != new_object.inner {
                        server
                            .registry()
                            .write(RegistryWrite::update(Id::singleton(), &new_object, object))
                            .await?
                    } else {
                        set.response.created(client_id.to_string(), Id::singleton());
                        continue;
                    }
                } else {
                    server
                        .registry()
                        .write(RegistryWrite::Insert {
                            object: &new_object,
                            id: response.id,
                        })
                        .await?
                }
            }
            Modification::Update { id, object } => {
                if object.inner != new_object.inner {
                    if !(is_singleton && object.revision == 0) {
                        server
                            .registry()
                            .write(RegistryWrite::update(*id, &new_object, object))
                            .await?
                    } else {
                        server
                            .registry()
                            .write(RegistryWrite::insert(&new_object))
                            .await?
                    }
                } else {
                    set.response.updated.append(*id, None);
                    continue;
                }
            }
        };

        let object_id = match (modification, result) {
            (Modification::Update { id, object }, RegistryWriteResult::Success(_)) => {
                cache_invalidator.process_update(id, &object, &new_object);
                if let (ObjectInner::Application(previous), ObjectInner::Application(updated)) =
                    (&object.inner, &new_object.inner)
                    && previous.resource_url != updated.resource_url
                    && let Err(err) = WebApplicationManager::delete_bundle(server, id).await
                {
                    trc::error!(err.details("Failed to delete cached application bundle"));
                }
                set.response.updated.append(
                    id,
                    if !response.object.is_empty() {
                        Some(JmapValue::Object(response.object))
                    } else {
                        None
                    },
                );
                Some(id)
            }
            (Modification::Create { client_id, .. }, RegistryWriteResult::Success(id)) => {
                cache_invalidator.process_create(&new_object);
                response.object.insert(Property::Id, RegistryValue::Id(id));
                set.response
                    .created
                    .insert(client_id, JmapValue::Object(response.object));
                Some(id)
            }
            (Modification::Update { id, .. }, err) => {
                set.response.not_updated.append(id, map_write_error(err));
                None
            }
            (Modification::Create { client_id, .. }, err) => {
                set.response
                    .not_created
                    .append(client_id, map_write_error(err));
                None
            }
        };

        // Dispatch tasks
        if !tasks.is_empty()
            && let Some(object_id) = object_id
        {
            let mut batch = BatchBuilder::new();
            for mut task in tasks.drain(..) {
                match &mut task {
                    Task::AcmeRenewal(task) => task.domain_id = object_id,
                    Task::DkimManagement(task) => task.domain_id = object_id,
                    Task::DnsManagement(task) => task.domain_id = object_id,
                    _ => unreachable!(),
                }
                schedule_replacing(set.server, &mut batch, task).await?;
            }
            set.server.commit_batch(batch).await?;
        }
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    const ACCOUNT_ORPHAN_TYPES: &[ObjectType] = &[
        ObjectType::PublicKey,
        ObjectType::MaskedEmail,
        ObjectType::OAuthGrant,
    ];
    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    const ACCOUNT_ORPHAN_TYPES: &[ObjectType] = &[ObjectType::PublicKey, ObjectType::OAuthGrant];

    // Process destroy
    for id in set.destroy.drain(..) {
        let object_id = ObjectId::new(object_type, id);
        if let Some(object) = server
            .registry()
            .get(object_id)
            .await
            .caused_by(trc::location!())?
            .filter(|object| {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                let is_tenant_mismatch = is_tenant_filtered
                    && access_token.tenant_id().map(Id::from) != object.inner.member_tenant_id();
                // SPDX-SnippetEnd
                #[cfg(not(feature = "enterprise"))]
                let is_tenant_mismatch = false;
                !(is_tenant_mismatch
                    || (is_account_filtered
                        && object.inner.account_id() != Some(Id::from(set.account_id))))
            })
        {
            if let ObjectInner::Account(account) = &object.inner
                && let Err(err) = validate_account_access(server, access_token, account).await?
            {
                set.response.not_destroyed.append(id, err);
                continue;
            }

            match server
                .registry()
                .write(RegistryWrite::Delete {
                    object_id,
                    object: Some(&object),
                    allowed_orphan_types: if object_type == ObjectType::Account {
                        ACCOUNT_ORPHAN_TYPES
                    } else {
                        &[]
                    },
                })
                .await?
            {
                RegistryWriteResult::Success(_) => {
                    if let ObjectInner::Account(account) = &object.inner {
                        for sharee_id in server
                            .revoke_account_grants(id.document_id())
                            .await
                            .caused_by(trc::location!())?
                        {
                            server
                                .invalidate_grantee(&mut cache_invalidator, sharee_id)
                                .await;
                        }

                        schedule_account_destruction(set.server, id, account).await?;
                    }

                    if matches!(object.inner, ObjectInner::Application(_))
                        && let Err(err) = WebApplicationManager::delete_bundle(server, id).await
                    {
                        trc::error!(err.details("Failed to delete cached application bundle"));
                    }

                    cache_invalidator.process_delete(id, &object);
                    set.response.destroyed.push(id);
                }
                err => {
                    set.response.not_destroyed.append(id, map_write_error(err));
                }
            }
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    // Finalize cache invalidation
    server.invalidate_caches(cache_invalidator).await?;

    Ok(set.into_response())
}

#[allow(clippy::large_enum_variant)]
enum Modification {
    Create {
        client_id: String,
        object: Option<Object>,
    },
    Update {
        id: Id,
        object: Object,
    },
}

impl RegistrySet for Server {
    async fn registry_set(
        &self,
        object_type: ObjectType,
        mut request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<SetResponse<Registry>> {
        // Initial assertions
        if self.registry().is_bootstrap_mode() && !matches!(object_type, ObjectType::Bootstrap) {
            return Err(trc::JmapEvent::Forbidden.into_err().details(concat!(
                "The server is in bootstrap mode. Only the 'Bootstrap' object type ",
                "can be modified until the bootstrap process is complete.",
            )));
        }
        self.assert_enterprise_object(object_type)?;

        let object_flags = object_type.flags();
        let is_singleton = (object_flags & OBJ_SINGLETON) != 0;
        let has_account_id = (object_flags & OBJ_FILTER_ACCOUNT) != 0;
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let is_tenant_filtered =
            (object_flags & OBJ_FILTER_TENANT) != 0 && access_token.tenant_id().is_some();
        // SPDX-SnippetEnd
        let can_set_account = access_token.has_permission(Permission::Impersonate);
        let is_account_filtered = has_account_id && !can_set_account;

        // Build response
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;

        // Initial create validation for singletons
        let create = request.unwrap_create();

        // Initial destroy validation for singletons
        let mut destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
        if is_singleton && !destroy.is_empty() {
            response.not_destroyed.extend(
                destroy
                    .drain(..)
                    .map(|id| (MaybeInvalid::Value(id), SetError::singleton())),
            );
        }

        // Update validation for willDestroy
        let update = request
            .unwrap_update()
            .into_valid()
            .filter_map(|(id, value)| {
                if is_singleton {
                    if id.is_singleton() {
                        Some((id, value))
                    } else {
                        response.not_updated.append(id, SetError::not_found());
                        None
                    }
                } else if !destroy.contains(&id) {
                    Some((id, value))
                } else {
                    response.not_updated.append(id, SetError::will_destroy());
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut set = RegistrySetResponse {
            access_token,
            server: self,
            remote_ip: session.remote_ip,
            account_id: request.account_id.document_id(),
            object_type,
            response,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            is_tenant_filtered,
            // SPDX-SnippetEnd
            is_account_filtered,
            create,
            update,
            destroy,
        };
        match object_type {
            ObjectType::AddressBook
            | ObjectType::Asn
            | ObjectType::Authentication
            | ObjectType::BlobStore
            | ObjectType::Cache
            | ObjectType::Calendar
            | ObjectType::CalendarAlarm
            | ObjectType::CalendarScheduling
            | ObjectType::Coordinator
            | ObjectType::DataRetention
            | ObjectType::DataStore
            | ObjectType::DkimReportSettings
            | ObjectType::DmarcReportSettings
            | ObjectType::DnsResolver
            | ObjectType::Email
            | ObjectType::FileStorage
            | ObjectType::Http
            | ObjectType::HttpForm
            | ObjectType::Imap
            | ObjectType::InMemoryStore
            | ObjectType::Jmap
            | ObjectType::SystemSettings
            | ObjectType::Metadata
            | ObjectType::Metrics
            | ObjectType::MtaConnectionStrategy
            | ObjectType::MtaExtensions
            | ObjectType::MtaInboundSession
            | ObjectType::MtaOutboundStrategy
            | ObjectType::MtaOutboundThrottle
            | ObjectType::MtaStageAuth
            | ObjectType::MtaStageConnect
            | ObjectType::MtaStageData
            | ObjectType::MtaStageEhlo
            | ObjectType::MtaStageMail
            | ObjectType::MtaStageRcpt
            | ObjectType::MtaSts
            | ObjectType::OidcProvider
            | ObjectType::ReportSettings
            | ObjectType::Search
            | ObjectType::SearchStore
            | ObjectType::Security
            | ObjectType::SenderAuth
            | ObjectType::Sharing
            | ObjectType::SieveSystemInterpreter
            | ObjectType::SieveUserInterpreter
            | ObjectType::SpamClassifier
            | ObjectType::SpamDnsblSettings
            | ObjectType::SpamPyzor
            | ObjectType::SpamSettings
            | ObjectType::SpfReportSettings
            | ObjectType::TaskManager
            | ObjectType::TlsReportSettings
            | ObjectType::WebDav
            | ObjectType::DsnReportSettings
            | ObjectType::AcmeProvider
            | ObjectType::AllowedIp
            | ObjectType::Application
            | ObjectType::BlockedIp
            | ObjectType::Certificate
            | ObjectType::Directory
            | ObjectType::DnsServer
            | ObjectType::EventTracingLevel
            | ObjectType::HttpLookup
            | ObjectType::MemoryLookupKey
            | ObjectType::MemoryLookupKeyValue
            | ObjectType::MtaVirtualQueue
            | ObjectType::MtaQueueQuota
            | ObjectType::MtaRoute
            | ObjectType::MtaDeliverySchedule
            | ObjectType::MtaInboundThrottle
            | ObjectType::MtaTlsStrategy
            | ObjectType::MtaMilter
            | ObjectType::MtaHook
            | ObjectType::NetworkListener
            | ObjectType::ClusterRole
            | ObjectType::SieveSystemScript
            | ObjectType::SieveUserScript
            | ObjectType::SpamDnsblServer
            | ObjectType::SpamFileExtension
            | ObjectType::SpamRule
            | ObjectType::SpamTag
            | ObjectType::StoreLookup
            | ObjectType::Tracer
            | ObjectType::WebHook
            | ObjectType::PublicKey
            | ObjectType::DkimSignature
            | ObjectType::Account
            | ObjectType::MailingList
            | ObjectType::OAuthClient
            | ObjectType::OAuthGrant
            | ObjectType::Role
            | ObjectType::Domain => registry_object_set(set).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel
            | ObjectType::Alert
            | ObjectType::Enterprise
            | ObjectType::MetricsStore
            | ObjectType::SpamAi
            | ObjectType::TracingStore
            | ObjectType::Tenant
            | ObjectType::MaskedEmail => registry_object_set(set).await,
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport
            | ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::DmarcInternalReport
            | ObjectType::TlsInternalReport => report_set(set).await.map(|set| set.into_response()),

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => super::mapping::archived_item::archived_item_set(set)
                .await
                .map(|set| set.into_response()),
            // SPDX-SnippetEnd
            ObjectType::SpamTrainingSample => {
                spam_sample_set(set).await.map(|set| set.into_response())
            }

            ObjectType::AccountSettings
            | ObjectType::ApiKey
            | ObjectType::AccountPassword
            | ObjectType::AppPassword => account_set(set).await.map(|set| set.into_response()),

            ObjectType::QueuedMessage => {
                queued_message_set(set).await.map(|set| set.into_response())
            }

            ObjectType::IndexQueueStatus => index_queue_status_set(set)
                .await
                .map(|set| set.into_response()),

            ObjectType::Task => task_set(set).await.map(|set| set.into_response()),

            ObjectType::Action => action_set(set).await.map(|set| set.into_response()),

            ObjectType::Bootstrap => Box::pin(bootstrap_set(set))
                .await
                .map(|set| set.into_response()),

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric | ObjectType::Trace => {
                set.fail_all_create("Telemetry objects cannot be created");
                set.fail_all_update("Telemetry objects cannot be modified");
                set.fail_all_destroy("Telemetry objects cannot be deleted");
                Ok(set.into_response())
            }
            // SPDX-SnippetEnd
            ObjectType::Log | ObjectType::ClusterNode => {
                set.fail_all_create("Telemetry objects cannot be created");
                set.fail_all_update("Telemetry objects cannot be modified");
                set.fail_all_destroy("Telemetry objects cannot be deleted");
                Ok(set.into_response())
            }
        }
    }
}

impl RegistrySetResponse<'_> {
    fn failed(&mut self, modification: Modification, error: SetError<Property>) {
        match modification {
            Modification::Create { client_id, .. } => {
                self.response.not_created.append(client_id, error)
            }
            Modification::Update { id, .. } => self.response.not_updated.append(id, error),
        }
    }

    pub fn fail_all(&mut self, error: SetError<Property>) {
        for (client_id, _) in self.create.drain() {
            self.response.not_created.append(client_id, error.clone());
        }
        for (id, _) in self.update.drain(..) {
            self.response.not_updated.append(id, error.clone());
        }
        for id in self.destroy.drain(..) {
            self.response.not_destroyed.append(id, error.clone());
        }
    }

    pub fn fail_all_create(&mut self, error: impl Into<Cow<'static, str>>) {
        let error = error.into();
        for (client_id, _) in self.create.drain() {
            self.response.not_created.append(
                client_id,
                SetError::forbidden().with_description(error.clone()),
            );
        }
    }

    pub fn fail_all_update(&mut self, error: impl Into<Cow<'static, str>>) {
        let error = error.into();
        for (id, _) in self.update.drain(..) {
            self.response
                .not_updated
                .append(id, SetError::forbidden().with_description(error.clone()));
        }
    }

    pub fn fail_all_destroy(&mut self, error: impl Into<Cow<'static, str>>) {
        let error = error.into();
        for id in self.destroy.drain(..) {
            self.response
                .not_destroyed
                .append(id, SetError::forbidden().with_description(error.clone()));
        }
    }

    fn into_response(self) -> SetResponse<Registry> {
        self.response
    }
}

impl Modification {
    fn as_account(&self) -> AccountUpdate<'_> {
        match self {
            Modification::Create { client_id, .. } => AccountUpdate::Create(client_id),
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::Account(account) => AccountUpdate::Update(account),
                _ => unreachable!(),
            },
        }
    }

    fn as_role(&self) -> Option<&Role> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::Role(role) => Some(role),
                _ => None,
            },
        }
    }

    fn as_public_key(&self) -> Option<&PublicKey> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::PublicKey(key) => Some(key),
                _ => None,
            },
        }
    }

    fn as_dkim_signature(&self) -> Option<&DkimSignature> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::DkimSignature(key) => Some(key),
                _ => None,
            },
        }
    }

    fn as_domain(&self) -> Option<&Domain> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::Domain(domain) => Some(domain),
                _ => None,
            },
        }
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    fn as_tenant(&self) -> Option<&Tenant> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::Tenant(tenant) => Some(tenant),
                _ => None,
            },
        }
    }
    // SPDX-SnippetEnd

    fn as_dns_server(&self) -> Option<&DnsServer> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::DnsServer(dns) => Some(dns),
                _ => None,
            },
        }
    }

    fn as_certificate(&self) -> Option<&Certificate> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::Certificate(cert) => Some(cert),
                _ => None,
            },
        }
    }

    fn as_sieve_script(&self) -> Option<&str> {
        match self {
            Modification::Create { .. } => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::SieveUserScript(script) => Some(script.contents.as_str()),
                ObjectInner::SieveSystemScript(script) => Some(script.contents.as_str()),
                _ => None,
            },
        }
    }
}

pub(crate) fn map_write_error(err: RegistryWriteResult) -> SetError<Property> {
    match err {
        RegistryWriteResult::CannotDeleteLinked {
            object_id,
            linked_objects,
        } => SetError::new(SetErrorType::ObjectIsLinked)
            .with_object_id(object_id)
            .with_linked_objects(linked_objects),
        RegistryWriteResult::InvalidSingletonId => SetError::invalid_properties()
            .with_property(Property::Id)
            .with_description("Invalid singleton id"),
        RegistryWriteResult::CannotDeleteSingleton => {
            SetError::forbidden().with_description("Singleton objects cannot be deleted")
        }
        RegistryWriteResult::InvalidForeignKey { object_id } => {
            SetError::new(SetErrorType::InvalidForeignKey).with_object_id(object_id)
        }
        RegistryWriteResult::ForeignKeyOutOfScope { object_id, scope } => {
            SetError::new(SetErrorType::InvalidForeignKey)
                .with_description(format!(
                    "{object_id} is not assigned to the same {scope} as this object."
                ))
                .with_object_id(object_id)
        }
        RegistryWriteResult::PrimaryKeyConflict {
            property,
            existing_id,
        } => SetError::new(SetErrorType::PrimaryKeyViolation)
            .with_property(property)
            .with_object_id(existing_id),
        RegistryWriteResult::ValidationError { errors } => {
            SetError::new(SetErrorType::ValidationFailed).with_validation_errors(errors)
        }
        RegistryWriteResult::NotSupported => SetError::forbidden()
            .with_description("The requested action is not supported by the registry store"),
        RegistryWriteResult::NotFound { .. } => SetError::not_found(),
        RegistryWriteResult::Success(_) => unreachable!(),
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
fn tenant_grants_impersonate(tenant: &Tenant) -> bool {
    match &tenant.permissions {
        Permissions::Merge(list) | Permissions::Replace(list) => {
            list.enabled_permissions.contains(&Permission::Impersonate)
        }
        Permissions::Inherit => false,
    }
}
// SPDX-SnippetEnd
