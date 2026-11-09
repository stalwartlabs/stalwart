/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, RegistrySetResponse, ValidationResult};
use common::network::{
    acme::order::is_within_domain, dkim::generate_dkim_selector, dns::update::DnsUpdater,
};
use jmap_proto::error::set::{SetError, SetErrorType};
use registry::{
    schema::{
        enums::{AcmeChallengeType, DkimSignatureType, DnsRecordType},
        prelude::{ObjectType, Property},
        structs::{
            AcmeProvider, CertificateManagement, CertificateManagementProperties, DkimManagement,
            DkimManagementProperties, DnsManagement, DnsServer, Domain, Task, TaskDnsManagement,
            TaskDomainManagement, TaskStatus,
        },
    },
    types::map::Map,
};
use std::borrow::Cow;
use types::id::Id;
use utils::outbound::{OutboundError, OutboundPolicy};

const MAX_HOSTNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub(crate) async fn validate_domain(
    set: &RegistrySetResponse<'_>,
    domain: &mut Domain,
    old_domain: Option<&Domain>,
    outbound_policy: OutboundPolicy,
    tasks: &mut Vec<Task>,
) -> ValidationResult {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if let Some(logo) = &domain.logo
        && old_domain.is_none_or(|old| old.logo.as_ref() != Some(logo))
        && let Err(err) = common::enterprise::logo::LogoSource::parse(logo, outbound_policy)
    {
        return Ok(Err(SetError::invalid_properties()
            .with_property(Property::Logo)
            .with_description(err.as_str())));
    }
    // SPDX-SnippetEnd

    let response = ObjectResponse::default();

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

    if let CertificateManagement::Automatic(CertificateManagementProperties {
        subject_alternative_names,
        ..
    }) = &domain.certificate_management
    {
        let old_names = old_domain
            .filter(|old| tenant_id(old) == tenant_id(domain))
            .and_then(|old| match &old.certificate_management {
                CertificateManagement::Automatic(props) => Some(&props.subject_alternative_names),
                CertificateManagement::Manual => None,
            });
        if let Some(name) = subject_alternative_names.iter().find(|name| {
            old_names.is_none_or(|old| !old.contains(name)) && !is_issuable_name(name, domain)
        }) {
            let scope = if tenant_id(domain).is_some() {
                "within this domain or its aliases"
            } else {
                "under a public suffix"
            };
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::SubjectAlternativeNames)
                .with_description(format!(
                    "{name:?} is not a valid hostname {scope}; names containing a dot are used as written"
                ))));
        }
    }

    let check_name =
        old_domain.is_none_or(|old| old.name != domain.name && !old.aliases.contains(&domain.name));
    let mut lookups = Vec::with_capacity(usize::from(check_name) + domain.aliases.len() * 2);
    if check_name {
        lookups.push((Property::Aliases, domain.name.as_bytes()));
    }
    for alias in domain.aliases.iter().filter(|alias| {
        *alias != &domain.name
            && old_domain.is_none_or(|old| !old.aliases.contains(*alias) && &old.name != *alias)
    }) {
        lookups.push((Property::Name, alias.as_bytes()));
        lookups.push((Property::Aliases, alias.as_bytes()));
    }
    if !lookups.is_empty()
        && let Some((position, existing)) = set
            .server
            .registry()
            .first_primary_key(ObjectType::Domain.into(), &lookups)
            .await?
    {
        return Ok(Err(SetError::new(SetErrorType::PrimaryKeyViolation)
            .with_property(if check_name && position == 0 {
                Property::Name
            } else {
                Property::Aliases
            })
            .with_object_id(existing)));
    }

    // Schedule DNS update task
    let will_trigger_dkim = matches!(domain.dkim_management, DkimManagement::Automatic(_))
        && old_domain.is_none_or(|old| old.dkim_management != domain.dkim_management);
    let will_schedule_dkim = !will_trigger_dkim
        && matches!(domain.dkim_management, DkimManagement::Automatic(_))
        && publishes_dkim(domain)
        && old_domain.is_some_and(|old| !publishes_dkim(old));
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
        if will_schedule_dkim {
            tasks.push(Task::DnsManagement(TaskDnsManagement {
                domain_id: Id::default(),
                update_records: Map::new(vec![DnsRecordType::Dkim]),
                on_success_renew_certificate: false,
                status: TaskStatus::now(),
            }));
        }
        false
    };

    // Schedule DKIM key rotation task
    if will_trigger_dkim || will_schedule_dkim {
        tasks.push(Task::DkimManagement(TaskDomainManagement {
            domain_id: Id::default(),
            status: TaskStatus::now(),
        }));
    }

    // Schedule ACME renewal task if needed
    if !will_trigger_acme
        && let CertificateManagement::Automatic(details) = &domain.certificate_management
        && old_domain.is_none_or(|old| old.certificate_management != domain.certificate_management)
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

fn is_issuable_name(name: &str, domain: &Domain) -> bool {
    if !name.contains('.') {
        return (name == "*" || is_ldh_label(name))
            && name.len() + 1 + domain.name.len() <= MAX_HOSTNAME_LEN;
    }
    let name = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    };
    let hostname = name.strip_prefix("*.").unwrap_or(&name);
    hostname.len() <= MAX_HOSTNAME_LEN
        && hostname.split('.').all(is_ldh_label)
        && (is_within_domain(hostname, &domain.name, domain.aliases.as_slice())
            || (tenant_id(domain).is_none()
                && psl::domain(hostname.as_bytes()).is_some_and(|d| d.suffix().typ().is_some())))
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
fn tenant_id(domain: &Domain) -> Option<Id> {
    domain.member_tenant_id
}
// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
fn tenant_id(_domain: &Domain) -> Option<Id> {
    None
}

fn is_ldh_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn publishes_dkim(domain: &Domain) -> bool {
    domain.dns_management.publishes(DnsRecordType::Dkim)
}

pub(crate) async fn validate_dns_server(
    set: &RegistrySetResponse<'_>,
    dns: &mut DnsServer,
    old_dns: Option<&DnsServer>,
    outbound_policy: OutboundPolicy,
) -> ValidationResult {
    if outbound_policy == OutboundPolicy::PublicOnly
        && old_dns.is_none_or(|old_dns| old_dns != dns)
        && let Err((property, err)) = validate_dns_server_destination(dns).await
    {
        return Ok(Err(SetError::invalid_properties()
            .with_property(property)
            .with_description(err.as_str())));
    }

    let response = ObjectResponse::default();

    if old_dns.is_none_or(|old_dns| old_dns != dns)
        && let Err(err) = DnsUpdater::build(dns.clone(), set.server.core.clone()).await
    {
        return Ok(Err(SetError::invalid_properties()
            .with_description(format!("Failed to build DNS server: {err}"))));
    }

    Ok(Ok(response))
}

async fn validate_dns_server_destination(dns: &DnsServer) -> Result<(), (Property, OutboundError)> {
    let policy = OutboundPolicy::PublicOnly;
    let check_url = |url: &str| {
        policy
            .parse_url(url)
            .map(|_| ())
            .map_err(|err| (Property::Url, err))
    };
    let check_host = |host: &str| {
        if host.contains("://") {
            policy.parse_url(host)
        } else {
            policy.parse_url(&format!("https://{host}"))
        }
        .map(|_| ())
        .map_err(|err| (Property::Host, err))
    };

    match dns {
        DnsServer::Tsig(server) => policy
            .check_ip(server.host.into_inner())
            .map_err(|err| (Property::Host, err)),
        DnsServer::BluecatV2(server) => check_url(&server.url),
        DnsServer::Cpanel(server) => check_url(&server.url),
        DnsServer::Plesk(server) => check_url(&server.url),
        DnsServer::PowerDns(server) => server
            .url
            .as_deref()
            .ok_or((Property::Url, OutboundError::MissingHost))
            .and_then(check_url),
        DnsServer::UltraDns(server) => server.url.as_deref().map_or(Ok(()), check_url),
        DnsServer::EdgeDns(server) => check_host(&server.host),
        DnsServer::Infoblox(server) => check_host(&server.host),
        DnsServer::Volcengine(server) => {
            if server
                .scheme
                .as_deref()
                .is_some_and(|scheme| !scheme.eq_ignore_ascii_case("https"))
            {
                Err((Property::Scheme, OutboundError::InsecureScheme))
            } else {
                server.host.as_deref().map_or(Ok(()), check_host)
            }
        }
        DnsServer::GoogleCloudDns(server) => {
            let Ok(service_account) = server.service_account_json.secret().await else {
                return Ok(());
            };
            serde_json::from_str::<ServiceAccountTokenUri<'_>>(&service_account)
                .ok()
                .and_then(|account| account.token_uri)
                .map_or(Ok(()), |token_uri| {
                    policy
                        .parse_url(&token_uri)
                        .map(|_| ())
                        .map_err(|err| (Property::ServiceAccountJson, err))
                })
        }
        _ => Ok(()),
    }
}

#[derive(serde::Deserialize)]
struct ServiceAccountTokenUri<'x> {
    #[serde(borrow)]
    token_uri: Option<Cow<'x, str>>,
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/jmap/src/registry/mapping/domain/tests.rs"]
mod tests;
