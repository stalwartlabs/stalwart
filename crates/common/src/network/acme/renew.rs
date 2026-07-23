/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    ipc::{BroadcastEvent, RegistryChange},
    network::acme::{
        AcmeDnsParameters, AcmeError, AcmeResult, ParsedCert, directory::AcmeRequestBuilder,
    },
};
use registry::{
    schema::{
        enums::{AcmeChallengeType, AcmeRenewBefore, DnsRecordType},
        prelude::{ObjectType, Property},
        structs::{
            AcmeProvider, Certificate, CertificateManagement, DnsManagement, Domain, PublicText,
            PublicTextValue, SecretText, SecretTextValue, SystemSettings, Task, TaskDnsManagement,
            TaskDomainManagement, TaskStatus,
        },
    },
    types::{datetime::UTCDateTime, id::ObjectId, map::Map},
};
use store::{
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use types::id::Id;

impl Server {
    pub async fn acme_renew(&self, domain_id: Id) -> AcmeResult<Vec<Task>> {
        let Some(domain) = self.registry().object::<Domain>(domain_id).await? else {
            return Err(AcmeError::Invalid(format!(
                "Domain with ID {} not found",
                domain_id
            )));
        };
        let cert = match domain.certificate_management {
            CertificateManagement::Manual => {
                return Err(AcmeError::Invalid(
                    "ACME not configured for domain".to_string(),
                ));
            }
            CertificateManagement::Automatic(props) => props,
        };
        let Some(acme_provider) = self
            .registry()
            .object::<AcmeProvider>(cert.acme_provider_id)
            .await?
        else {
            return Err(AcmeError::Invalid(format!(
                "ACME provider with ID {} not found",
                cert.acme_provider_id
            )));
        };
        let challenge_type = acme_provider.challenge_type;
        let renew_before = acme_provider.renew_before;
        let reuse_key = acme_provider.reuse_key;
        let request = AcmeRequestBuilder::new(acme_provider).await?;
        let domains = request.build_domains(
            self,
            &domain.name,
            &cert.subject_alternative_names.into_inner(),
        );

        if let Some(renew_at) = self
            .acme_certificate_renewal_due(&domains, renew_before, now())
            .await?
        {
            return Err(AcmeError::NotDue(format!(
                "Certificate for domain {} is still valid; renewal is not due until {}",
                domain.name,
                UTCDateTime::from_timestamp(renew_at as i64)
            )));
        }

        let dns_parameters = match &domain.dns_management {
            DnsManagement::Automatic(props) if challenge_type == AcmeChallengeType::Dns01 => {
                match self.build_dns_updater(props.dns_server_id).await? {
                    Ok(updater) => Some(AcmeDnsParameters {
                        updater,
                        origin: props.origin.clone(),
                    }),
                    Err(err) => {
                        return Err(AcmeError::Invalid(format!(
                            "Failed to build DNS updater: {}",
                            err
                        )));
                    }
                }
            }
            _ => None,
        };
        if challenge_type == AcmeChallengeType::Dns01 && dns_parameters.is_none() {
            return Err(AcmeError::Invalid(
                "ACME provider requires DNS challenge but a DNS provider was not configured"
                    .to_string(),
            ));
        }
        let reuse_key_pem = if reuse_key {
            match self.acme_certificate_by_domains(&domains).await? {
                Some(certificate) => certificate
                    .private_key
                    .secret()
                    .await
                    .map(std::borrow::Cow::into_owned)
                    .map_err(|err| {
                        AcmeError::Crypto(format!("Failed to load certificate private key: {err}"))
                    })?
                    .into(),
                None => None,
            }
        } else {
            None
        };
        let pem_cert = request
            .renew(self, domains, reuse_key_pem, dns_parameters)
            .await?;
        let parsed_cert = ParsedCert::parse(&pem_cert.certificate)?;
        let mut new_sans = parsed_cert.sans.clone();
        new_sans.sort();
        let certificate = Certificate {
            private_key: SecretText::Text(SecretTextValue {
                secret: pem_cert.private_key,
            }),
            certificate: PublicText::Text(PublicTextValue {
                value: pem_cert.certificate,
            }),
            issuer: parsed_cert.issuer,
            not_valid_after: UTCDateTime::from_timestamp(parsed_cert.valid_not_after.timestamp()),
            not_valid_before: UTCDateTime::from_timestamp(parsed_cert.valid_not_before.timestamp()),
            subject_alternative_names: Map::new(parsed_cert.sans),
        };
        let now = now();
        let expires_in = (parsed_cert.valid_not_after.timestamp() as u64).saturating_sub(now);
        if expires_in < 3600 {
            return Err(AcmeError::Invalid(format!(
                "Certificate expires in {} seconds, expected at least 3600 seconds",
                expires_in
            )));
        }

        match self
            .registry()
            .write(RegistryWrite::insert(&certificate.into()))
            .await?
        {
            RegistryWriteResult::Success(id) => {
                // Repoint the default certificate to the renewed object when it
                // tracks the same SAN set, so its id does not go stale
                if let Some(old) = self
                    .registry()
                    .get(ObjectType::SystemSettings.singleton())
                    .await?
                {
                    let mut settings = SystemSettings::from(old.clone());
                    if let Some(default_id) = settings.default_certificate_id
                        && let Some(default_cert) =
                            self.registry().object::<Certificate>(default_id).await?
                    {
                        let mut default_sans =
                            default_cert.subject_alternative_names.clone().into_inner();
                        default_sans.sort();
                        if default_sans == new_sans {
                            settings.default_certificate_id = Some(id);
                            if let Err(err) = self
                                .registry()
                                .write(RegistryWrite::update(
                                    Id::singleton(),
                                    &settings.into(),
                                    &old,
                                ))
                                .await
                            {
                                trc::error!(
                                    err.details(
                                        "Failed to update default certificate after ACME renewal."
                                    )
                                    .caused_by(trc::location!())
                                );
                            }
                        }
                    }
                }

                // Reload registry
                let change = RegistryChange::Insert(ObjectId::new(ObjectType::Certificate, id));
                Box::pin(self.reload_registry(change)).await?;
                self.cluster_broadcast(BroadcastEvent::RegistryChange(change))
                    .await;

                let mut tasks = Vec::new();
                let renew_at = Self::acme_renewal_due_at(
                    parsed_cert.valid_not_before.timestamp(),
                    parsed_cert.valid_not_after.timestamp(),
                    renew_before,
                );
                tasks.push(Task::AcmeRenewal(TaskDomainManagement {
                    domain_id,
                    status: TaskStatus::at(renew_at),
                }));

                // Update TLSA records
                if let DnsManagement::Automatic(props) = &domain.dns_management
                    && props.publish_records.contains(&DnsRecordType::Tlsa)
                {
                    tasks.push(Task::DnsManagement(TaskDnsManagement {
                        domain_id,
                        on_success_renew_certificate: false,
                        status: TaskStatus::now(),
                        update_records: Map::new(vec![DnsRecordType::Tlsa]),
                    }));
                }

                Ok(tasks)
            }
            err => Err(AcmeError::Registry(err)),
        }
    }

    async fn acme_certificate_by_domains(
        &self,
        domains: &[String],
    ) -> AcmeResult<Option<Certificate>> {
        let mut wanted = domains.iter().collect::<Vec<_>>();
        wanted.sort();
        let Some(reference) = wanted.first() else {
            return Ok(None);
        };

        let candidate_ids = self
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::Certificate)
                    .text(Property::SubjectAlternativeNames, reference.as_str()),
            )
            .await?;

        for id in candidate_ids {
            let Some(certificate) = self.registry().object::<Certificate>(id).await? else {
                continue;
            };
            let mut sans = certificate
                .subject_alternative_names
                .iter()
                .collect::<Vec<_>>();
            sans.sort();
            if sans == wanted {
                return Ok(Some(certificate));
            }
        }

        Ok(None)
    }

    async fn acme_certificate_renewal_due(
        &self,
        domains: &[String],
        renew_before: AcmeRenewBefore,
        now: u64,
    ) -> AcmeResult<Option<u64>> {
        let now = now as i64;
        let Some(certificate) = self.acme_certificate_by_domains(domains).await? else {
            return Ok(None);
        };

        let not_valid_after = certificate.not_valid_after.timestamp();
        if not_valid_after <= now {
            return Ok(None);
        }
        let not_valid_before = certificate.not_valid_before.timestamp();
        let renew_at = Self::acme_renewal_due_at(not_valid_before, not_valid_after, renew_before);
        Ok(if now < renew_at {
            Some(renew_at as u64)
        } else {
            None
        })
    }

    fn acme_renewal_due_at(
        not_valid_before: i64,
        not_valid_after: i64,
        renew_before: AcmeRenewBefore,
    ) -> i64 {
        let total = not_valid_after.saturating_sub(not_valid_before);
        let (numerator, denominator) = match renew_before {
            AcmeRenewBefore::R12 => (1, 2),
            AcmeRenewBefore::R23 => (2, 3),
            AcmeRenewBefore::R34 => (3, 4),
            AcmeRenewBefore::R45 => (4, 5),
        };
        not_valid_before + total * numerator / denominator
    }
}
