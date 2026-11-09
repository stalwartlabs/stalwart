/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{outcome::Outcome, tasks::append_error};
use common::{
    Server,
    cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
    network::dkim::{
        generate_dkim_dns_record, generate_dkim_dns_record_name, generate_dkim_private_key,
        generate_dkim_selector,
    },
};
use compact_str::{CompactString, ToCompactString};
use registry::{
    schema::{
        enums::{DkimRotationStage, DkimSignatureType, DnsRecordType},
        prelude::{Object, ObjectType, Property},
        structs::{
            Dkim1Signature, Dkim2Signature, DkimManagement, DkimSignature, DnsManagement, Domain,
            SecretText, SecretTextValue, Task, TaskDomainManagement, TaskStatus,
        },
    },
    types::{datetime::UTCDateTime, id::ObjectId},
};
use store::{
    registry::{
        RegistryObject, RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use trc::{DkimEvent, DnsEvent};
use types::id::Id;

pub(crate) trait DkimManagementTask: Sync + Send {
    fn dkim_management(&self, task: &TaskDomainManagement) -> impl Future<Output = Outcome> + Send;
}

impl DkimManagementTask for Server {
    async fn dkim_management(&self, task: &TaskDomainManagement) -> Outcome {
        let mut do_refresh = false;
        let result = dkim_management(self, task, &mut do_refresh).await;

        if do_refresh
            && let Err(err) = self
                .invalidate_caches(CacheInvalidationBuilder::default().with_invalidation(
                    CacheInvalidation::DkimSignature(task.domain_id.document_id()),
                ))
                .await
        {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to invalidate caches after DKIM management task")
            );
        }

        match result {
            Ok(outcome) => outcome,
            Err(err) => {
                let outcome = Outcome::error(&err);
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to run DKIM management task")
                );
                outcome
            }
        }
    }
}

async fn dkim_management(
    server: &Server,
    task: &TaskDomainManagement,
    do_refresh: &mut bool,
) -> trc::Result<Outcome> {
    let Some(domain) = server.registry().object::<Domain>(task.domain_id).await? else {
        return Ok(Outcome::Obsolete("Domain no longer exists"));
    };
    let DkimManagement::Automatic(dkim) = domain.dkim_management else {
        return Ok(Outcome::Obsolete(
            "Domain no longer uses automatic DKIM management",
        ));
    };
    let configured = dkim.algorithms.into_inner();
    if configured.is_empty() {
        return Ok(Outcome::fatal("No DKIM algorithms configured for domain"));
    }
    let mut create_signatures = configured.clone();
    let mut active_types: Vec<DkimSignatureType> = Vec::with_capacity(configured.len());

    let dns_updater = if domain.dns_management.publishes(DnsRecordType::Dkim)
        && let DnsManagement::Automatic(props) = domain.dns_management
    {
        match server.build_dns_updater(props.dns_server_id).await? {
            Ok(updater) => Some((updater, props.origin.unwrap_or_else(|| domain.name.clone()))),
            Err(err) => {
                return Ok(Outcome::fatal(format!(
                    "Failed to build DNS updater: {err}"
                )));
            }
        }
    } else {
        None
    };

    // Fetch existing DKIM keys
    let mut publish_signatures = Vec::new();
    let mut retire_signatures = Vec::new();
    let mut retiring_signatures = Vec::new();
    let mut delete_signatures = Vec::new();
    let mut schedule_signatures = Vec::new();
    let mut next_transition = None;

    let signature_ids = server
        .registry()
        .query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::DkimSignature)
                .equal(Property::DomainId, task.domain_id.document_id()),
        )
        .await?;

    for id in signature_ids {
        let id = ObjectId::new(ObjectType::DkimSignature, id);
        let Some(key) = server.registry().get(id).await? else {
            continue;
        };
        let key: RegistryObject<DkimSignature> = RegistryObject {
            id,
            revision: key.revision,
            object: key.into(),
        };

        let key_algo = key.object.object_type();
        if let Some(current_stage) = key.object.rotation_due() {
            match current_stage {
                DkimRotationStage::Pending => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    publish_signatures.push(key)
                }
                DkimRotationStage::Active if dns_updater.is_some() => retiring_signatures.push(key),
                DkimRotationStage::Active => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    active_types.push(key_algo);
                }
                DkimRotationStage::Retiring => retire_signatures.push(key),
                DkimRotationStage::Retired => delete_signatures.push(key),
            }
        } else {
            let transition = key.object.next_transition();
            match key.object.stage() {
                DkimRotationStage::Active => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    active_types.push(key_algo);
                    if transition.is_none() && dns_updater.is_some() {
                        schedule_signatures.push(key);
                    }
                }
                DkimRotationStage::Pending => {
                    create_signatures.retain(|algo| algo != &key_algo);
                    if transition.is_none() || dns_updater.is_none() {
                        publish_signatures.push(key);
                        continue;
                    }
                }
                DkimRotationStage::Retiring | DkimRotationStage::Retired => {}
            }

            if let Some(transition) = transition
                && next_transition.is_none_or(|next| transition < next)
            {
                next_transition = Some(transition);
            }
        }
    }

    let now = now();
    let mut temporary_errors = String::new();

    for algorithm in create_signatures {
        #[cfg(stalwart_tests)]
        let secret = {
            if dkim.selector_template.contains("dummy") {
                match algorithm {
                    DkimSignatureType::Dkim1Ed25519Sha256
                    | DkimSignatureType::Dkim2Ed25519Sha256 => {
                        test_support::TEST_ED25519_KEY.to_string()
                    }
                    DkimSignatureType::Dkim1RsaSha256 | DkimSignatureType::Dkim2RsaSha256 => {
                        test_support::TEST_RSA_KEY.to_string()
                    }
                    DkimSignatureType::Dkim2MlDsa44 => {
                        generate_dkim_private_key(algorithm).await.unwrap().unwrap()
                    }
                }
            } else {
                generate_dkim_private_key(algorithm).await.unwrap().unwrap()
            }
        };

        // Generate new key and selector
        #[cfg(not(stalwart_tests))]
        let secret = match generate_dkim_private_key(algorithm).await? {
            Ok(secret) => secret,
            Err(err) => {
                return Ok(Outcome::fatal(err));
            }
        };
        let selector = match generate_dkim_selector(&dkim.selector_template, algorithm) {
            Ok(selector) => selector,
            Err(err) => {
                return Ok(Outcome::fatal(format!(
                    "Failed to generate DKIM selector: {err}"
                )));
            }
        };

        // Build key
        let private_key = SecretText::Text(SecretTextValue { secret });
        let mut signature = match algorithm {
            DkimSignatureType::Dkim1Ed25519Sha256 | DkimSignatureType::Dkim1RsaSha256 => {
                let signature = Dkim1Signature {
                    stage: DkimRotationStage::Active,
                    domain_id: task.domain_id,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    member_tenant_id: domain.member_tenant_id,
                    // SPDX-SnippetEnd
                    selector: selector.clone(),
                    private_key,
                    ..Default::default()
                };
                if algorithm == DkimSignatureType::Dkim1Ed25519Sha256 {
                    DkimSignature::Dkim1Ed25519Sha256(signature)
                } else {
                    DkimSignature::Dkim1RsaSha256(signature)
                }
            }
            DkimSignatureType::Dkim2Ed25519Sha256
            | DkimSignatureType::Dkim2RsaSha256
            | DkimSignatureType::Dkim2MlDsa44 => {
                let signature = Dkim2Signature {
                    stage: DkimRotationStage::Active,
                    domain_id: task.domain_id,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    member_tenant_id: domain.member_tenant_id,
                    // SPDX-SnippetEnd
                    selector: selector.clone(),
                    private_key,
                    ..Default::default()
                };
                match algorithm {
                    DkimSignatureType::Dkim2Ed25519Sha256 => {
                        DkimSignature::Dkim2Ed25519Sha256(signature)
                    }
                    DkimSignatureType::Dkim2MlDsa44 => DkimSignature::Dkim2MlDsa44(signature),
                    _ => DkimSignature::Dkim2RsaSha256(signature),
                }
            }
        };

        // Publish key
        if let Some((updater, origin)) = &dns_updater {
            let record = generate_dkim_dns_record(&signature, &domain.name).await?;
            let dns_update::DnsRecord::TXT(txt_value) = &record.record else {
                return Ok(Outcome::fatal("DKIM record must be a TXT record"));
            };
            let propagation_target = txt_value.clone();
            let published = match updater
                .set_rrset(
                    origin,
                    &record.name,
                    dns_update::DnsRecordType::TXT,
                    vec![record.record.clone()],
                )
                .await
            {
                Ok(_) => {
                    let propagated = updater
                        .check_txt_propagation(&record.name, origin, &propagation_target)
                        .await;
                    if !propagated {
                        append_error(
                            &mut temporary_errors,
                            format_args!(
                                "DKIM record {} did not propagate yet, will retry.",
                                record.name
                            ),
                        );
                    }
                    propagated
                }
                Err(err) => {
                    append_error(
                        &mut temporary_errors,
                        format_args!("Failed to publish DKIM record {}: {err}.", record.name),
                    );
                    false
                }
            };
            let signature_transition = if published {
                trc::event!(
                    Dkim(DkimEvent::SignaturePublished),
                    Name = selector.clone(),
                    Domain = domain.name.clone()
                );

                *do_refresh = true;
                UTCDateTime::from_timestamp((now + dkim.rotate_after.as_secs()) as i64)
            } else {
                // Something went wrong, reschedule.
                signature.set_stage(DkimRotationStage::Pending);
                UTCDateTime::from_timestamp(now as i64)
            };

            if next_transition.is_none_or(|next| signature_transition < next) {
                next_transition = Some(signature_transition);
            }

            signature.set_next_transition(signature_transition);
        }

        // Write key
        let is_active = signature.is_active();
        match server
            .registry()
            .write(RegistryWrite::insert(&signature.into()))
            .await?
        {
            RegistryWriteResult::Success(_) => {
                *do_refresh |= is_active;
                if is_active {
                    active_types.push(algorithm);
                }
                trc::event!(
                    Dkim(DkimEvent::SignatureCreated),
                    Name = selector,
                    Domain = domain.name.clone()
                );
            }
            err => {
                return Ok(Outcome::fatal(format!(
                    "Failed to write DKIM signature: {err}"
                )));
            }
        }
    }

    for signature in schedule_signatures {
        let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
        let signature_transition =
            UTCDateTime::from_timestamp((now + dkim.rotate_after.as_secs()) as i64);

        if next_transition.is_none_or(|next| signature_transition < next) {
            next_transition = Some(signature_transition);
        }

        let mut new_signature = signature.object.clone();
        new_signature.set_next_transition(signature_transition);

        if let SignatureUpdate::Failed(reason) = update_signature(
            server,
            signature,
            new_signature,
            &record,
            &mut temporary_errors,
        )
        .await?
        {
            return Ok(Outcome::Fatal(reason));
        }
    }

    // Publish signatures
    if let Some((updater, origin)) = &dns_updater {
        for signature in publish_signatures {
            let record = match generate_dkim_dns_record(&signature.object, &domain.name).await {
                Ok(record) => record,
                Err(err) => {
                    append_error(
                        &mut temporary_errors,
                        format_args!(
                            "Failed to build DKIM record for selector {}: {err}.",
                            signature.object.selector()
                        ),
                    );
                    continue;
                }
            };
            let dns_update::DnsRecord::TXT(txt_value) = &record.record else {
                return Ok(Outcome::fatal("DKIM record must be a TXT record"));
            };
            let propagation_target = txt_value.clone();
            let publish_result = updater
                .set_rrset(
                    origin,
                    &record.name,
                    dns_update::DnsRecordType::TXT,
                    vec![record.record.clone()],
                )
                .await;
            let propagation_result = match publish_result {
                Ok(_) => Ok(updater
                    .check_txt_propagation(&record.name, origin, &propagation_target)
                    .await),
                Err(err) => Err(err),
            };
            match propagation_result {
                Ok(true) => {
                    let signature_transition =
                        UTCDateTime::from_timestamp((now + dkim.rotate_after.as_secs()) as i64);

                    if next_transition.is_none_or(|next| signature_transition < next) {
                        next_transition = Some(signature_transition);
                    }

                    let signature_type = signature.object.object_type();
                    let mut new_signature = signature.object.clone();

                    new_signature.set_next_transition(signature_transition);
                    new_signature.set_stage(DkimRotationStage::Active);

                    trc::event!(
                        Dkim(DkimEvent::SignaturePublished),
                        Name = CompactString::from(new_signature.selector()),
                        Domain = domain.name.clone()
                    );

                    // Write key
                    match update_signature(
                        server,
                        signature,
                        new_signature,
                        &record.name,
                        &mut temporary_errors,
                    )
                    .await?
                    {
                        SignatureUpdate::Written => active_types.push(signature_type),
                        SignatureUpdate::Conflict => {}
                        SignatureUpdate::Failed(reason) => return Ok(Outcome::Fatal(reason)),
                    }
                    *do_refresh = true;
                }
                Ok(false) => {
                    append_error(
                        &mut temporary_errors,
                        format_args!(
                            "DKIM record {} did not propagate yet, will retry.",
                            record.name
                        ),
                    );
                }
                Err(err) => {
                    append_error(
                        &mut temporary_errors,
                        format_args!("Failed to publish DKIM record {}: {err}.", record.name),
                    );
                }
            }
        }
    } else {
        for signature in publish_signatures {
            let signature_type = signature.object.object_type();
            if active_types.contains(&signature_type) || !configured.contains(&signature_type) {
                continue;
            }

            let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
            let mut new_signature = signature.object.clone();
            new_signature.set_stage(DkimRotationStage::Active);
            match &mut new_signature {
                DkimSignature::Dkim1Ed25519Sha256(sign) | DkimSignature::Dkim1RsaSha256(sign) => {
                    sign.next_transition_at = None
                }
                DkimSignature::Dkim2Ed25519Sha256(sign)
                | DkimSignature::Dkim2RsaSha256(sign)
                | DkimSignature::Dkim2MlDsa44(sign) => sign.next_transition_at = None,
            }

            match update_signature(
                server,
                signature,
                new_signature,
                &record,
                &mut temporary_errors,
            )
            .await?
            {
                SignatureUpdate::Written => {
                    active_types.push(signature_type);
                    *do_refresh = true;
                }
                SignatureUpdate::Conflict => active_types.push(signature_type),
                SignatureUpdate::Failed(reason) => return Ok(Outcome::Fatal(reason)),
            }
        }
    }

    // Retiring signatures
    for signature in retiring_signatures {
        let signature_type = signature.object.object_type();
        if configured.contains(&signature_type) && !active_types.contains(&signature_type) {
            continue;
        }

        let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
        let signature_transition =
            UTCDateTime::from_timestamp((now + dkim.retire_after.as_secs()) as i64);

        if next_transition.is_none_or(|next| signature_transition < next) {
            next_transition = Some(signature_transition);
        }

        let mut new_signature = signature.object.clone();

        new_signature.set_next_transition(signature_transition);
        new_signature.set_stage(DkimRotationStage::Retiring);

        trc::event!(
            Dkim(DkimEvent::SignatureRetiring),
            Name = CompactString::from(new_signature.selector()),
            Domain = domain.name.clone()
        );

        // Write key
        if let SignatureUpdate::Failed(reason) = update_signature(
            server,
            signature,
            new_signature,
            &record,
            &mut temporary_errors,
        )
        .await?
        {
            return Ok(Outcome::Fatal(reason));
        }
        *do_refresh = true;
    }

    // Retire signatures
    if let Some((updater, origin)) = &dns_updater {
        for signature in retire_signatures {
            let record = generate_dkim_dns_record_name(&signature.object, &domain.name);
            match updater
                .set_rrset(origin, &record, dns_update::DnsRecordType::TXT, Vec::new())
                .await
            {
                Ok(_) => {
                    let signature_transition =
                        UTCDateTime::from_timestamp((now + dkim.delete_after.as_secs()) as i64);

                    if next_transition.is_none_or(|next| signature_transition < next) {
                        next_transition = Some(signature_transition);
                    }

                    let mut new_signature = signature.object.clone();

                    new_signature.set_next_transition(signature_transition);
                    new_signature.set_stage(DkimRotationStage::Retired);

                    trc::event!(
                        Dkim(DkimEvent::SignatureRetired),
                        Name = CompactString::from(new_signature.selector()),
                        Domain = domain.name.clone()
                    );

                    // Write key
                    if let SignatureUpdate::Failed(reason) = update_signature(
                        server,
                        signature,
                        new_signature,
                        &record,
                        &mut temporary_errors,
                    )
                    .await?
                    {
                        return Ok(Outcome::Fatal(reason));
                    }

                    *do_refresh = true;
                }
                Err(err) => {
                    append_error(
                        &mut temporary_errors,
                        format_args!("Failed to remove DKIM record {record}: {err}."),
                    );
                }
            }
        }
    }

    // Delete signatures
    for signature in delete_signatures {
        let record = generate_dkim_dns_record_name(&signature.object, &domain.name);

        if let Some((updater, origin)) = &dns_updater
            && let Err(err) = updater
                .set_rrset(origin, &record, dns_update::DnsRecordType::TXT, Vec::new())
                .await
        {
            append_error(
                &mut temporary_errors,
                format_args!("Failed to remove DKIM record {record}: {err}."),
            );
            trc::event!(
                Dns(DnsEvent::RecordDeletionFailed),
                Hostname = record,
                Domain = origin.clone(),
                Type = "TXT",
                Reason = err.to_compact_string(),
            );
            continue;
        }

        trc::event!(
            Dkim(DkimEvent::SignatureDeleted),
            Name = CompactString::from(signature.object.selector()),
            Domain = domain.name.clone()
        );

        match server
            .registry()
            .write(RegistryWrite::delete_object(
                signature.id,
                &Object {
                    inner: signature.object.into(),
                    revision: signature.revision,
                },
            ))
            .await
        {
            Ok(RegistryWriteResult::Success(_)) => {}
            Ok(err) => {
                return Ok(Outcome::fatal(format!(
                    "Failed to delete DKIM signature for record {record}: {err}"
                )));
            }
            Err(err) => {
                if err.is_assertion_failure() {
                    append_error(
                        &mut temporary_errors,
                        format_args!(
                            "Failed to delete DKIM signature for record {record} due to concurrent modification, will retry."
                        ),
                    );
                } else {
                    return Err(err);
                }
            }
        }
    }

    if !temporary_errors.is_empty() {
        Ok(Outcome::transient(temporary_errors))
    } else if let Some(next_transition) = next_transition {
        Ok(Outcome::Done(vec![Task::DkimManagement(
            TaskDomainManagement {
                domain_id: task.domain_id,
                status: TaskStatus::at(next_transition.timestamp()),
            },
        )]))
    } else {
        Ok(Outcome::done())
    }
}

enum SignatureUpdate {
    Written,
    Conflict,
    Failed(String),
}

async fn update_signature(
    server: &Server,
    signature: RegistryObject<DkimSignature>,
    new_signature: DkimSignature,
    name: &str,
    temporary_errors: &mut String,
) -> trc::Result<SignatureUpdate> {
    match server
        .registry()
        .write(RegistryWrite::update(
            signature.id.id(),
            &new_signature.into(),
            &Object {
                inner: signature.object.into(),
                revision: signature.revision,
            },
        ))
        .await
    {
        Ok(RegistryWriteResult::Success(_)) => Ok(SignatureUpdate::Written),
        Ok(err) => Ok(SignatureUpdate::Failed(format!(
            "Failed to write DKIM signature for record {name}: {err}"
        ))),
        Err(err) => {
            if err.is_assertion_failure() {
                append_error(
                    temporary_errors,
                    format_args!(
                        "Failed to write DKIM signature for record {name} due to concurrent modification, will retry."
                    ),
                );
                Ok(SignatureUpdate::Conflict)
            } else {
                Err(err)
            }
        }
    }
}

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/services/src/task_manager/tasks/dkim/test_support.rs"]
mod test_support;
