/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, RegistrySetResponse, ValidationResult};
use common::network::masked::MaskedAddress;
use jmap_proto::error::set::SetError;
use rand::{Rng, distr::Alphanumeric};
use registry::{
    jmap::JmapValue,
    schema::{
        enums::StorageQuota,
        prelude::{ObjectType, Property},
        structs::MaskedEmail,
    },
};
use store::{ahash::AHashSet, registry::RegistryQuery, write::now};
use utils::{DomainPart, map::vec_map::VecMap};

pub(crate) async fn validate_masked_email(
    set: &RegistrySetResponse<'_>,
    addr: &mut MaskedEmail,
    is_create: bool,
    unpatched_properties: VecMap<Property, JmapValue<'_>>,
) -> ValidationResult {
    let mut response = ObjectResponse::default();

    if is_create {
        // Validate quotas
        let num_masked = set
            .server
            .registry()
            .count(RegistryQuery::new(ObjectType::MaskedEmail).with_account(set.account_id))
            .await? as u32;
        let account = set.server.account(set.account_id).await?;
        let masked_quota = set
            .server
            .object_quota(account.object_quotas(), StorageQuota::MaxMaskedAddresses);
        if num_masked >= masked_quota {
            return Ok(Err(SetError::over_quota().with_description(format!(
                "You have exceeded your quota of {} masked addresses.",
                masked_quota
            ))));
        }

        // Validate settings
        let mut requested_domain = None;
        let mut requested_prefix = None;
        for (key, value) in unpatched_properties {
            match (key, value) {
                (Property::EmailPrefix, JmapValue::Str(prefix))
                    if (1..=64).contains(&prefix.len())
                        && prefix
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        && prefix.as_bytes().first().is_some_and(|v| *v != b'_') =>
                {
                    requested_prefix = Some(prefix.to_lowercase());
                }
                (Property::EmailDomain, JmapValue::Str(domain)) if !domain.is_empty() => {
                    let domain = domain.to_lowercase();
                    if set
                        .server
                        .domain(&domain)
                        .await?
                        .filter(|domain| {
                            account
                                .addresses
                                .iter()
                                .all(|addr| addr.domain_id == domain.id)
                        })
                        .is_some()
                    {
                        requested_domain = Some(domain);
                    }
                    if requested_domain.is_none() {
                        return Ok(Err(SetError::forbidden()
                            .with_property(key)
                            .with_description(
                                "The specified domain is not valid for this account.",
                            )));
                    }
                }
                (_, JmapValue::Null) => {}
                _ => {
                    return Ok(Err(SetError::invalid_properties().with_property(key)));
                }
            }
        }

        // If not specified, use the first available domain and a random prefix
        let domain = if let Some(domain) = requested_domain {
            domain
        } else {
            let Some(domain) = account.name.try_domain_part() else {
                return Ok(Err(SetError::forbidden()
                    .with_property(Property::EmailDomain)
                    .with_description(
                        "No valid domain is available for this account.",
                    )));
            };
            domain.to_string()
        };
        let prefix = if let Some(prefix) = requested_prefix {
            prefix
        } else {
            rand::rng()
                .sample_iter(Alphanumeric)
                .take(16)
                .map(|ch| char::from(ch.to_ascii_lowercase()))
                .collect::<String>()
        };

        let address_id = set.server.registry().assign_id();
        addr.email = MaskedAddress::generate(
            address_id,
            addr.expires_at
                .map(|t| (t.timestamp() as u64).saturating_sub(now()))
                .filter(|t| *t > 0)
                .map(|t| t as u32),
            &prefix,
            &domain,
        );

        response.id = Some(address_id.into());
        response
            .object
            .insert_unchecked(Property::Email, addr.email.clone());
    } else {
        for (key, value) in unpatched_properties {
            match (key, value) {
                (Property::Email, JmapValue::Str(email)) if email == addr.email => {}
                _ => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(key)
                        .with_description("Cannot modify read-only property")));
                }
            }
        }
    }

    Ok(Ok(response))
}
