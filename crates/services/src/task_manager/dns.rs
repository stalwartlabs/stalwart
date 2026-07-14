/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use common::Server;
use dns_update::{CAARecord, DnsRecord, DnsRecordType, Error as DnsUpdateError, KeyValue};
use registry::schema::structs::{
    DnsManagement, Domain, Task, TaskDnsManagement, TaskDomainManagement, TaskStatus,
};
use std::fmt::Write;
use store::ahash::AHashMap;
use trc::DnsEvent;

pub(crate) trait DnsManagementTask: Sync + Send {
    fn dns_management(&self, task: &TaskDnsManagement) -> impl Future<Output = TaskResult> + Send;
}

impl DnsManagementTask for Server {
    async fn dns_management(&self, task: &TaskDnsManagement) -> TaskResult {
        match dns_management(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to run DNS management task")
                );
                result
            }
        }
    }
}

async fn dns_management(server: &Server, task: &TaskDnsManagement) -> trc::Result<TaskResult> {
    if task.update_records.is_empty() {
        return Ok(TaskResult::permanent(
            "No DNS records to update".to_string(),
        ));
    }
    let Some(domain) = server.registry().object::<Domain>(task.domain_id).await? else {
        return Ok(TaskResult::permanent("Domain not found".to_string()));
    };
    let DnsManagement::Automatic(props) = &domain.dns_management else {
        return Ok(TaskResult::permanent(
            "Domain is not set to automatic DNS management".to_string(),
        ));
    };
    let dns_updater = match server.build_dns_updater(props.dns_server_id).await? {
        Ok(updater) => updater,
        Err(err) => {
            return Ok(TaskResult::permanent(format!(
                "Failed to build DNS updater: {}",
                err
            )));
        }
    };
    let origin = props.origin.as_deref().unwrap_or(&domain.name);
    let records = server
        .build_dns_records(task.domain_id, &domain, task.update_records.as_slice())
        .await?;

    // Group records by (name, type) so each RRSet is published in one call.
    let mut by_owner: AHashMap<(String, DnsRecordType), Vec<DnsRecord>> = AHashMap::new();
    for record in records {
        by_owner
            .entry((record.name, record.record.as_type()))
            .or_default()
            .push(record.record);
    }

    let mut errors = String::new();
    for ((name, record_type), mut recs) in by_owner {
        let preserve_unrelated = match record_type {
            DnsRecordType::TXT => !is_owned_txt_name(&name),
            DnsRecordType::CAA => true,
            _ => false,
        };
        if preserve_unrelated {
            match dns_updater.list_rrset(origin, &name, record_type).await {
                Ok(existing) => {
                    for existing_rec in existing {
                        if !recs.iter().any(|new| same_rrset_family(new, &existing_rec)) {
                            recs.push(existing_rec);
                        }
                    }
                }
                Err(DnsUpdateError::Unsupported(reason)) => {
                    trc::event!(
                        Dns(DnsEvent::RecordLookupFailed),
                        Hostname = name.clone(),
                        Details = origin.to_string(),
                        Type = record_type.as_str(),
                        Reason = format!(
                            "DNS provider cannot list RRSet, unrelated records at this name may be overwritten: {reason}"
                        ),
                    );
                }
                Err(err) => {
                    trc::event!(
                        Dns(DnsEvent::RecordLookupFailed),
                        Hostname = name.clone(),
                        Details = origin.to_string(),
                        Type = record_type.as_str(),
                        Reason = format!("DNS provider failed to list RRSet: {err}"),
                    );
                }
            }
        }

        if let Err(err) = dns_updater
            .set_rrset(origin, &name, record_type, recs)
            .await
        {
            if !errors.is_empty() {
                errors.push_str("; ");
            }
            let _ = write!(
                &mut errors,
                "Failed to set DNS RRSet for {}/{}: {}",
                name,
                record_type.as_str(),
                err
            );
        }
    }

    if errors.is_empty() {
        if task.on_success_renew_certificate {
            Ok(TaskResult::Success(vec![Task::AcmeRenewal(
                TaskDomainManagement {
                    domain_id: task.domain_id,
                    status: TaskStatus::now(),
                },
            )]))
        } else {
            Ok(TaskResult::Success(vec![]))
        }
    } else {
        Ok(TaskResult::permanent(errors))
    }
}

fn same_rrset_family(a: &DnsRecord, b: &DnsRecord) -> bool {
    match (a, b) {
        (DnsRecord::TXT(_), DnsRecord::TXT(_)) => same_txt_family(a, b),
        (DnsRecord::CAA(_), DnsRecord::CAA(_)) => same_caa_family(a, b),
        _ => false,
    }
}

fn same_txt_family(a: &DnsRecord, b: &DnsRecord) -> bool {
    match (a, b) {
        (DnsRecord::TXT(va), DnsRecord::TXT(vb)) => match (txt_family(va), txt_family(vb)) {
            (Some(fa), Some(fb)) => fa.eq_ignore_ascii_case(fb),
            _ => false,
        },
        _ => false,
    }
}

fn same_caa_family(a: &DnsRecord, b: &DnsRecord) -> bool {
    match (a, b) {
        (DnsRecord::CAA(ca), DnsRecord::CAA(cb)) => match (ca, cb) {
            (CAARecord::Issue { options: oa, .. }, CAARecord::Issue { options: ob, .. })
            | (
                CAARecord::IssueWild { options: oa, .. },
                CAARecord::IssueWild { options: ob, .. },
            ) => match (caa_account_uri(oa), caa_account_uri(ob)) {
                (Some(ua), Some(ub)) => ua.eq_ignore_ascii_case(ub),
                _ => false,
            },
            (CAARecord::Iodef { url: ua, .. }, CAARecord::Iodef { url: ub, .. }) => {
                ua.eq_ignore_ascii_case(ub)
            }
            _ => false,
        },
        _ => false,
    }
}

fn caa_account_uri(options: &[KeyValue]) -> Option<&str> {
    options
        .iter()
        .find(|kv| kv.key.eq_ignore_ascii_case("accounturi"))
        .map(|kv| kv.value.as_str())
}

fn txt_family(value: &str) -> Option<&str> {
    value.trim_start().strip_prefix("v=").map(|rest| {
        rest.split_once([';', ' '])
            .map_or(rest, |(family, _)| family)
    })
}

fn is_owned_txt_name(name: &str) -> bool {
    name.contains("_dmarc.")
        || name.contains("_smtp._tls.")
        || name.contains("_mta-sts.")
        || name.contains("_ua-auto-config.")
        || name.contains("_validation-persist.")
        || name.contains("._domainkey.")
}
