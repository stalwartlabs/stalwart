/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::{
        enums::DmarcActionDisposition,
        prelude::{ObjectType, Property},
        structs::{
            ArfExternalReport, DmarcExternalReport, DmarcInternalReport, Task, TaskDmarcReport,
            TaskStatus, TaskTlsReport, TlsExternalReport, TlsInternalReport,
        },
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId, index::IndexBuilder},
};
use store::{
    SerializeInfallible, U64_LEN,
    registry::ObjectIdVersioned,
    write::{
        BatchBuilder, RegistryClass, TaskQueueClass, ValueClass, assert::AssertValue,
        key::KeySerializer,
    },
};
use types::id::Id;

pub trait InternalReportIndex: ObjectImpl {
    fn deliver_at(&self) -> UTCDateTime;

    fn set_deliver_at(&mut self, at: UTCDateTime);

    fn task(&self, item_id: u64) -> Task;

    fn primary_key(&self) -> ValueClass;

    fn reschedule_ops(
        &mut self,
        batch: &mut BatchBuilder,
        item_id: u64,
        revision: u64,
        at: UTCDateTime,
    ) {
        let current_deliver_at = self.deliver_at();

        if current_deliver_at != at {
            let object = Self::OBJECT;
            let object_id = object.to_id();
            let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });

            self.set_deliver_at(at);

            batch
                .assert_value(key.clone(), AssertValue::Hash(revision))
                .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id: item_id,
                    due: current_deliver_at.timestamp() as u64,
                }))
                .set(
                    ValueClass::TaskQueue(TaskQueueClass::Due {
                        id: item_id,
                        due: at.timestamp() as u64,
                    }),
                    object_id.serialize(),
                )
                .set(key, self.to_pickled_vec());
        }
    }

    fn write_ops(&self, batch: &mut BatchBuilder, item_id: u64, is_set: bool) {
        let object = Self::OBJECT;
        let object_id = object.to_id();
        let pk = self.primary_key();

        if is_set {
            batch
                .assert_value(pk.clone(), ())
                .set(
                    pk,
                    ObjectIdVersioned {
                        object_id: ObjectId::new(object, item_id.into()),
                        version: 0,
                    }
                    .serialize(),
                )
                .schedule_task_with_id(item_id, self.task(item_id));
        } else {
            batch
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id,
                }))
                .clear(pk)
                .clear(ValueClass::TaskQueue(TaskQueueClass::Task { id: item_id }))
                .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                    id: item_id,
                    due: self.deliver_at().timestamp() as u64,
                }));
        }
    }
}

pub trait ExternalReportIndex: ObjectImpl {
    fn text(&self) -> impl Iterator<Item = &str>;

    fn tenant_id(&self) -> Option<Id>;

    fn expires_at(&self) -> u64;

    fn domains(&self) -> impl Iterator<Item = &str>;

    fn success_fail_count(&self) -> (u64, u64);

    fn write_ops(&self, batch: &mut BatchBuilder, item_id: u64, is_set: bool) {
        let object_id = Self::OBJECT.to_id();
        let mut index_builder = IndexBuilder::default();
        for text in self.text() {
            index_builder.text(Property::Text, text);
        }

        if let Some(tenant_id) = self.tenant_id() {
            index_builder.search(Property::MemberTenantId, tenant_id.id());
        }

        let (success_count, fail_count) = self.success_fail_count();
        index_builder.search(Property::TotalSuccessfulSessions, success_count);
        index_builder.search(Property::TotalFailedSessions, fail_count);

        index_builder.search(Property::ExpiresAt, self.expires_at());
        batch.registry_index(object_id, item_id, index_builder.keys.iter(), is_set);

        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
        if is_set {
            batch.set(key, self.to_pickled_vec());
        } else {
            batch.clear(key);
        }
    }
}

impl InternalReportIndex for DmarcInternalReport {
    fn deliver_at(&self) -> UTCDateTime {
        self.deliver_at
    }

    fn set_deliver_at(&mut self, at: UTCDateTime) {
        self.deliver_at = at;
    }

    fn task(&self, item_id: u64) -> Task {
        Task::DmarcReport(TaskDmarcReport {
            report_id: item_id.into(),
            status: TaskStatus::at(self.deliver_at.timestamp()),
        })
    }

    fn primary_key(&self) -> ValueClass {
        ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: ObjectType::DmarcInternalReport.to_id().into(),
            index_id: Property::Domain.to_id(),
            key: KeySerializer::new(self.domain.len() + U64_LEN)
                .write(self.domain.as_str())
                .write(self.policy_identifier)
                .finalize(),
        })
    }
}

impl InternalReportIndex for TlsInternalReport {
    fn deliver_at(&self) -> UTCDateTime {
        self.deliver_at
    }

    fn set_deliver_at(&mut self, at: UTCDateTime) {
        self.deliver_at = at;
    }

    fn task(&self, item_id: u64) -> Task {
        Task::TlsReport(TaskTlsReport {
            report_id: item_id.into(),
            status: TaskStatus::at(self.deliver_at.timestamp()),
        })
    }

    fn primary_key(&self) -> ValueClass {
        ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: ObjectType::TlsInternalReport.to_id().into(),
            index_id: Property::Domain.to_id(),
            key: self.domain.as_bytes().to_vec(),
        })
    }
}

impl ExternalReportIndex for ArfExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .reported_domains
            .iter()
            .filter_map(|s| non_empty(s))
            .chain(
                [report.dkim_domain.as_deref()]
                    .into_iter()
                    .flatten()
                    .filter_map(non_empty),
            )
    }

    fn text(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .reported_domains
            .iter()
            .filter_map(|s| non_empty(s))
            .chain(
                [
                    report.dkim_domain.as_deref(),
                    report.reporting_mta.as_deref(),
                    report.original_mail_from.as_deref(),
                    report.original_rcpt_to.as_deref(),
                ]
                .into_iter()
                .flatten()
                .filter_map(non_empty),
            )
            .chain(non_empty(&self.from))
    }

    fn tenant_id(&self) -> Option<Id> {
        self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }

    fn success_fail_count(&self) -> (u64, u64) {
        (self.report.incidents, 0)
    }
}

impl ExternalReportIndex for DmarcExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        non_empty(&report.policy_domain)
            .into_iter()
            .filter_map(non_empty)
    }

    fn text(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        non_empty(&report.email)
            .into_iter()
            .filter_map(non_empty)
            .chain(non_empty(&report.policy_domain))
            .chain(report.records.iter().flat_map(|r| {
                r.envelope_to
                    .as_deref()
                    .into_iter()
                    .filter_map(non_empty)
                    .chain(non_empty(&r.envelope_from))
                    .chain(non_empty(&r.header_from))
                    .chain(r.dkim_results.iter().filter_map(|d| non_empty(&d.domain)))
                    .chain(r.spf_results.iter().filter_map(|s| non_empty(&s.domain)))
            }))
            .chain(non_empty(&self.from))
    }

    fn tenant_id(&self) -> Option<Id> {
        self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }

    fn success_fail_count(&self) -> (u64, u64) {
        let mut success_count = 0;
        let mut fail_count = 0;

        for record in self.report.records.iter() {
            if record.evaluated_disposition == DmarcActionDisposition::Pass {
                success_count += std::cmp::min(record.count, 1);
            } else {
                fail_count += std::cmp::min(record.count, 1);
            }
        }

        (success_count, fail_count)
    }
}

impl ExternalReportIndex for TlsExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .policies
            .iter()
            .flat_map(|p| non_empty(&p.policy_domain).into_iter())
    }

    fn text(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .policies
            .iter()
            .flat_map(|p| {
                non_empty(&p.policy_domain)
                    .into_iter()
                    .chain(p.mx_hosts.iter().filter_map(|s| non_empty(s)))
                    .chain(p.failure_details.iter().flat_map(|fd| {
                        non_empty_opt(&fd.receiving_mx_hostname)
                            .into_iter()
                            .chain(non_empty_opt(&fd.receiving_mx_helo))
                    }))
            })
            .chain(non_empty(&self.from))
    }

    fn tenant_id(&self) -> Option<Id> {
        self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }

    fn success_fail_count(&self) -> (u64, u64) {
        let mut success_count = 0;
        let mut fail_count = 0;

        for policy in self.report.policies.iter() {
            success_count += std::cmp::min(policy.total_successful_sessions, 1);
            fail_count += std::cmp::min(policy.total_failed_sessions, 1);
        }

        (success_count, fail_count)
    }
}

#[inline(always)]
fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

#[inline(always)]
fn non_empty_opt(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}
