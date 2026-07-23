/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{
    ObjectResponse, RegistrySetResponse, ValidationResult, principal::validate_tenant_quota,
};
use common::network::{dkim::generate_dkim_selector, dns::update::DnsUpdater};
use jmap_proto::error::set::SetError;
use registry::{
    schema::{
        enums::{AcmeChallengeType, DkimSignatureType, DnsRecordType, TenantStorageQuota},
        prelude::Property,
        structs::{
            AcmeProvider, CertificateManagement, DkimManagement, DkimManagementProperties,
            DnsManagement, DnsServer, Domain, Task, TaskDnsManagement, TaskDomainManagement,
            TaskStatus,
        },
    },
    types::map::Map,
};
use types::id::Id;

pub(crate) async fn validate_domain(
    set: &RegistrySetResponse<'_>,
    domain: &mut Domain,
    old_domain: Option<&Domain>,
    tasks: &mut Vec<Task>,
) -> ValidationResult {
    let response = if old_domain.is_none() {
        match validate_tenant_quota(set, TenantStorageQuota::MaxDomains).await? {
            Ok(response) => response,
            Err(err) => {
                return Ok(Err(err));
            }
        }
    } else {
        ObjectResponse::default()
    };

    // Validate DKIM selector template
    if let DkimManagement::Automatic(DkimManagementProperties {
        selector_template, ..
    }) = &domain.dkim_management
        && old_domain.is_none_or(|old| {
            matches!(
                &old.dkim_management,
                DkimManagement::Automatic(DkimManagementProperties {
                    selector_template: old_selector_template,
                    ..
                }) if old_selector_template != selector_template
            )
        })
        && let Err(err) =
            generate_dkim_selector(selector_template, DkimSignatureType::Dkim1RsaSha256)
    {
        return Ok(Err(SetError::invalid_properties()
            .with_property(Property::SelectorTemplate)
            .with_description(err)));
    }

    // Schedule DNS update task
    let will_trigger_dkim = matches!(domain.dkim_management, DkimManagement::Automatic(_))
        && old_domain
            .is_none_or(|old| !matches!(old.dkim_management, DkimManagement::Automatic(_)));
    let will_trigger_acme = if let DnsManagement::Automatic(details) = &domain.dns_management
        && old_domain.is_none_or(|old| !matches!(old.dns_management, DnsManagement::Automatic(_)))
    {
        let on_success_renew_certificate = old_domain.is_none()
            && matches!(
                domain.certificate_management,
                CertificateManagement::Automatic(_)
            );
        tasks.push(Task::DnsManagement(TaskDnsManagement {
            domain_id: Id::default(),
            update_records: Map::new(
                details
                    .publish_records
                    .iter()
                    .filter(|&&r| r != DnsRecordType::Dkim || !will_trigger_dkim)
                    .copied()
                    .collect(),
            ),
            on_success_renew_certificate,
            status: TaskStatus::now(),
        }));
        on_success_renew_certificate
    } else {
        false
    };

    // Schedule DKIM key rotation task
    if will_trigger_dkim {
        tasks.push(Task::DkimManagement(TaskDomainManagement {
            domain_id: Id::default(),
            status: TaskStatus::now(),
        }));
    }

    // Schedule ACME renewal task if needed
    if !will_trigger_acme
        && let CertificateManagement::Automatic(details) = &domain.certificate_management
        && old_domain.is_none_or(|old| {
            !matches!(
                old.certificate_management,
                CertificateManagement::Automatic(_)
            )
        })
    {
        let Some(provider) = set
            .server
            .registry()
            .object::<AcmeProvider>(details.acme_provider_id)
            .await?
        else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::AcmeProviderId)
                .with_description("ACME provider not found")));
        };

        if matches!(provider.challenge_type, AcmeChallengeType::Dns01)
            && !matches!(domain.dns_management, DnsManagement::Automatic(_))
        {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::AcmeProviderId)
                .with_description(
                    "ACME provider requires automatic DNS management",
                )));
        }

        tasks.push(Task::AcmeRenewal(TaskDomainManagement {
            domain_id: Id::default(),
            status: TaskStatus::now(),
        }));
    }

    Ok(Ok(response))
}

pub(crate) async fn validate_dns_server(
    set: &RegistrySetResponse<'_>,
    dns: &mut DnsServer,
    old_dns: Option<&DnsServer>,
) -> ValidationResult {
    let response = if old_dns.is_none() {
        match validate_tenant_quota(set, TenantStorageQuota::MaxDnsServers).await? {
            Ok(response) => response,
            Err(err) => {
                return Ok(Err(err));
            }
        }
    } else {
        ObjectResponse::default()
    };

    if old_dns.is_none_or(|old_dns| old_dns != dns)
        && let Err(err) = DnsUpdater::build(dns.clone(), set.server.core.clone()).await
    {
        return Ok(Err(SetError::invalid_properties()
            .with_description(format!("Failed to build DNS server: {err}"))));
    }

    Ok(Ok(response))
}
