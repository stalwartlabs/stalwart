/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    schema::{
        enums,
        prelude::{Property, UTCDateTime},
        structs,
    },
    types::{index::IndexBuilder, ipaddr::IpAddr},
};
use mail_auth::report::{tlsrpt::*, *};
use std::borrow::Cow;
use types::id::Id;

pub trait ReportIndex {
    fn text(&self) -> impl Iterator<Item = &str>;

    fn tenant_ids(&self) -> &[Id];

    fn expires_at(&self) -> u64;

    fn domains(&self) -> impl Iterator<Item = &str>;

    fn build_search_index<'x>(&'x self, index: &mut IndexBuilder<'x>) {
        for text in self.text() {
            index.text(Property::Domain, text);
        }

        for tenant_id in self.tenant_ids() {
            index.search(Property::MemberTenantId, tenant_id.id());
        }

        index.search(Property::ExpiresAt, self.expires_at());
    }
}

impl ReportIndex for structs::ArfExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .reported_domains
            .iter()
            .filter_map(|s| non_empty(s))
            .chain(
                [
                    report.dkim_domain.as_deref(),
                    report.original_mail_from.as_deref(),
                ]
                .into_iter()
                .flatten()
                .filter_map(non_empty),
            )
            .chain(self.to.iter().filter_map(|s| non_empty(s)))
            .map(|domain| domain.rsplit_once('@').map(|(_, d)| d).unwrap_or(domain))
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

    fn tenant_ids(&self) -> &[Id] {
        &self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }
}

impl ReportIndex for structs::DmarcExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        non_empty(&report.policy_domain)
            .into_iter()
            .filter_map(non_empty)
            .chain(report.records.iter().flat_map(|r| {
                non_empty(&r.envelope_from)
                    .into_iter()
                    .filter_map(non_empty)
                    .chain(non_empty(&r.header_from))
                    .chain(r.dkim_results.iter().filter_map(|d| non_empty(&d.domain)))
                    .chain(r.spf_results.iter().filter_map(|s| non_empty(&s.domain)))
            }))
            .chain(self.to.iter().filter_map(|s| non_empty(s)))
            .map(|domain| domain.rsplit_once('@').map(|(_, d)| d).unwrap_or(domain))
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

    fn tenant_ids(&self) -> &[Id] {
        &self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }
}

impl ReportIndex for structs::TlsExternalReport {
    fn domains(&self) -> impl Iterator<Item = &str> {
        let report = &self.report;

        report
            .policies
            .iter()
            .flat_map(|p| {
                non_empty(&p.policy_domain)
                    .into_iter()
                    .chain(p.mx_hosts.iter().filter_map(|s| non_empty(s)))
            })
            .chain(self.to.iter().filter_map(|s| non_empty(s)))
            .map(|domain| domain.rsplit_once('@').map(|(_, d)| d).unwrap_or(domain))
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

    fn tenant_ids(&self) -> &[Id] {
        &self.member_tenant_id
    }

    fn expires_at(&self) -> u64 {
        self.expires_at.timestamp() as u64
    }
}

impl From<enums::DmarcAlignment> for Alignment {
    fn from(value: enums::DmarcAlignment) -> Self {
        match value {
            enums::DmarcAlignment::Relaxed => Alignment::Relaxed,
            enums::DmarcAlignment::Strict => Alignment::Strict,
            enums::DmarcAlignment::Unspecified => Alignment::Unspecified,
        }
    }
}

impl From<Alignment> for enums::DmarcAlignment {
    fn from(value: Alignment) -> Self {
        match value {
            Alignment::Relaxed => enums::DmarcAlignment::Relaxed,
            Alignment::Strict => enums::DmarcAlignment::Strict,
            Alignment::Unspecified => enums::DmarcAlignment::Unspecified,
        }
    }
}

impl From<enums::DmarcDisposition> for Disposition {
    fn from(value: enums::DmarcDisposition) -> Self {
        match value {
            enums::DmarcDisposition::None => Disposition::None,
            enums::DmarcDisposition::Quarantine => Disposition::Quarantine,
            enums::DmarcDisposition::Reject => Disposition::Reject,
            enums::DmarcDisposition::Unspecified => Disposition::Unspecified,
        }
    }
}

impl From<Disposition> for enums::DmarcDisposition {
    fn from(value: Disposition) -> Self {
        match value {
            Disposition::None => enums::DmarcDisposition::None,
            Disposition::Quarantine => enums::DmarcDisposition::Quarantine,
            Disposition::Reject => enums::DmarcDisposition::Reject,
            Disposition::Unspecified => enums::DmarcDisposition::Unspecified,
        }
    }
}

impl From<enums::DmarcActionDisposition> for ActionDisposition {
    fn from(value: enums::DmarcActionDisposition) -> Self {
        match value {
            enums::DmarcActionDisposition::None => ActionDisposition::None,
            enums::DmarcActionDisposition::Pass => ActionDisposition::Pass,
            enums::DmarcActionDisposition::Quarantine => ActionDisposition::Quarantine,
            enums::DmarcActionDisposition::Reject => ActionDisposition::Reject,
            enums::DmarcActionDisposition::Unspecified => ActionDisposition::Unspecified,
        }
    }
}

impl From<ActionDisposition> for enums::DmarcActionDisposition {
    fn from(value: ActionDisposition) -> Self {
        match value {
            ActionDisposition::None => enums::DmarcActionDisposition::None,
            ActionDisposition::Pass => enums::DmarcActionDisposition::Pass,
            ActionDisposition::Quarantine => enums::DmarcActionDisposition::Quarantine,
            ActionDisposition::Reject => enums::DmarcActionDisposition::Reject,
            ActionDisposition::Unspecified => enums::DmarcActionDisposition::Unspecified,
        }
    }
}

impl From<enums::DmarcResult> for DmarcResult {
    fn from(value: enums::DmarcResult) -> Self {
        match value {
            enums::DmarcResult::Pass => DmarcResult::Pass,
            enums::DmarcResult::Fail => DmarcResult::Fail,
            enums::DmarcResult::Unspecified => DmarcResult::Unspecified,
        }
    }
}

impl From<DmarcResult> for enums::DmarcResult {
    fn from(value: DmarcResult) -> Self {
        match value {
            DmarcResult::Pass => enums::DmarcResult::Pass,
            DmarcResult::Fail => enums::DmarcResult::Fail,
            DmarcResult::Unspecified => enums::DmarcResult::Unspecified,
        }
    }
}

impl From<enums::DmarcPolicyOverride> for PolicyOverride {
    fn from(value: enums::DmarcPolicyOverride) -> Self {
        match value {
            enums::DmarcPolicyOverride::Forwarded => PolicyOverride::Forwarded,
            enums::DmarcPolicyOverride::SampledOut => PolicyOverride::SampledOut,
            enums::DmarcPolicyOverride::TrustedForwarder => PolicyOverride::TrustedForwarder,
            enums::DmarcPolicyOverride::MailingList => PolicyOverride::MailingList,
            enums::DmarcPolicyOverride::LocalPolicy => PolicyOverride::LocalPolicy,
            enums::DmarcPolicyOverride::Other => PolicyOverride::Other,
        }
    }
}

impl From<PolicyOverride> for enums::DmarcPolicyOverride {
    fn from(value: PolicyOverride) -> Self {
        match value {
            PolicyOverride::Forwarded => enums::DmarcPolicyOverride::Forwarded,
            PolicyOverride::SampledOut => enums::DmarcPolicyOverride::SampledOut,
            PolicyOverride::TrustedForwarder => enums::DmarcPolicyOverride::TrustedForwarder,
            PolicyOverride::MailingList => enums::DmarcPolicyOverride::MailingList,
            PolicyOverride::LocalPolicy => enums::DmarcPolicyOverride::LocalPolicy,
            PolicyOverride::Other => enums::DmarcPolicyOverride::Other,
        }
    }
}

impl From<enums::DkimAuthResult> for DkimResult {
    fn from(value: enums::DkimAuthResult) -> Self {
        match value {
            enums::DkimAuthResult::None => DkimResult::None,
            enums::DkimAuthResult::Pass => DkimResult::Pass,
            enums::DkimAuthResult::Fail => DkimResult::Fail,
            enums::DkimAuthResult::Policy => DkimResult::Policy,
            enums::DkimAuthResult::Neutral => DkimResult::Neutral,
            enums::DkimAuthResult::TempError => DkimResult::TempError,
            enums::DkimAuthResult::PermError => DkimResult::PermError,
        }
    }
}

impl From<DkimResult> for enums::DkimAuthResult {
    fn from(value: DkimResult) -> Self {
        match value {
            DkimResult::None => enums::DkimAuthResult::None,
            DkimResult::Pass => enums::DkimAuthResult::Pass,
            DkimResult::Fail => enums::DkimAuthResult::Fail,
            DkimResult::Policy => enums::DkimAuthResult::Policy,
            DkimResult::Neutral => enums::DkimAuthResult::Neutral,
            DkimResult::TempError => enums::DkimAuthResult::TempError,
            DkimResult::PermError => enums::DkimAuthResult::PermError,
        }
    }
}

impl From<enums::SpfAuthResult> for SpfResult {
    fn from(value: enums::SpfAuthResult) -> Self {
        match value {
            enums::SpfAuthResult::None => SpfResult::None,
            enums::SpfAuthResult::Neutral => SpfResult::Neutral,
            enums::SpfAuthResult::Pass => SpfResult::Pass,
            enums::SpfAuthResult::Fail => SpfResult::Fail,
            enums::SpfAuthResult::SoftFail => SpfResult::SoftFail,
            enums::SpfAuthResult::TempError => SpfResult::TempError,
            enums::SpfAuthResult::PermError => SpfResult::PermError,
        }
    }
}

impl From<SpfResult> for enums::SpfAuthResult {
    fn from(value: SpfResult) -> Self {
        match value {
            SpfResult::None => enums::SpfAuthResult::None,
            SpfResult::Neutral => enums::SpfAuthResult::Neutral,
            SpfResult::Pass => enums::SpfAuthResult::Pass,
            SpfResult::Fail => enums::SpfAuthResult::Fail,
            SpfResult::SoftFail => enums::SpfAuthResult::SoftFail,
            SpfResult::TempError => enums::SpfAuthResult::TempError,
            SpfResult::PermError => enums::SpfAuthResult::PermError,
        }
    }
}

impl From<enums::SpfDomainScope> for SPFDomainScope {
    fn from(value: enums::SpfDomainScope) -> Self {
        match value {
            enums::SpfDomainScope::Helo => SPFDomainScope::Helo,
            enums::SpfDomainScope::MailFrom => SPFDomainScope::MailFrom,
            enums::SpfDomainScope::Unspecified => SPFDomainScope::Unspecified,
        }
    }
}

impl From<SPFDomainScope> for enums::SpfDomainScope {
    fn from(value: SPFDomainScope) -> Self {
        match value {
            SPFDomainScope::Helo => enums::SpfDomainScope::Helo,
            SPFDomainScope::MailFrom => enums::SpfDomainScope::MailFrom,
            SPFDomainScope::Unspecified => enums::SpfDomainScope::Unspecified,
        }
    }
}

impl From<structs::DmarcPolicyOverrideReason> for PolicyOverrideReason {
    fn from(value: structs::DmarcPolicyOverrideReason) -> Self {
        PolicyOverrideReason {
            type_: value.class.into(),
            comment: value.comment,
        }
    }
}

impl From<PolicyOverrideReason> for structs::DmarcPolicyOverrideReason {
    fn from(value: PolicyOverrideReason) -> Self {
        structs::DmarcPolicyOverrideReason {
            class: value.type_.into(),
            comment: value.comment,
        }
    }
}

impl From<structs::DmarcDkimResult> for DKIMAuthResult {
    fn from(value: structs::DmarcDkimResult) -> Self {
        DKIMAuthResult {
            domain: value.domain,
            selector: value.selector,
            result: value.result.into(),
            human_result: value.human_result,
        }
    }
}

impl From<DKIMAuthResult> for structs::DmarcDkimResult {
    fn from(value: DKIMAuthResult) -> Self {
        structs::DmarcDkimResult {
            domain: value.domain,
            selector: value.selector,
            result: value.result.into(),
            human_result: value.human_result,
        }
    }
}

impl From<structs::DmarcSpfResult> for SPFAuthResult {
    fn from(value: structs::DmarcSpfResult) -> Self {
        SPFAuthResult {
            domain: value.domain,
            scope: value.scope.into(),
            result: value.result.into(),
            human_result: value.human_result,
        }
    }
}

impl From<SPFAuthResult> for structs::DmarcSpfResult {
    fn from(value: SPFAuthResult) -> Self {
        structs::DmarcSpfResult {
            domain: value.domain,
            scope: value.scope.into(),
            result: value.result.into(),
            human_result: value.human_result,
        }
    }
}

impl From<structs::DmarcExtension> for Extension {
    fn from(value: structs::DmarcExtension) -> Self {
        Extension {
            name: value.name,
            definition: value.definition,
        }
    }
}

impl From<Extension> for structs::DmarcExtension {
    fn from(value: Extension) -> Self {
        structs::DmarcExtension {
            name: value.name,
            definition: value.definition,
        }
    }
}

impl From<structs::DmarcReportRecord> for Record {
    fn from(value: structs::DmarcReportRecord) -> Self {
        Record {
            row: Row {
                source_ip: value.source_ip.map(|ip| ip.into_inner()),
                count: value.count as u32,
                policy_evaluated: PolicyEvaluated {
                    disposition: value.evaluated_disposition.into(),
                    dkim: value.evaluated_dkim.into(),
                    spf: value.evaluated_spf.into(),
                    reason: value
                        .policy_override_reasons
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                },
            },
            identifiers: Identifier {
                envelope_to: value.envelope_to,
                envelope_from: value.envelope_from,
                header_from: value.header_from,
            },
            auth_results: AuthResult {
                dkim: value.dkim_results.into_iter().map(Into::into).collect(),
                spf: value.spf_results.into_iter().map(Into::into).collect(),
            },
            extensions: value.extensions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Record> for structs::DmarcReportRecord {
    fn from(value: Record) -> Self {
        structs::DmarcReportRecord {
            count: value.row.count as u64,
            source_ip: value.row.source_ip.map(IpAddr),
            evaluated_disposition: value.row.policy_evaluated.disposition.into(),
            evaluated_dkim: value.row.policy_evaluated.dkim.into(),
            evaluated_spf: value.row.policy_evaluated.spf.into(),
            policy_override_reasons: value
                .row
                .policy_evaluated
                .reason
                .into_iter()
                .map(Into::into)
                .collect(),
            envelope_to: value.identifiers.envelope_to,
            envelope_from: value.identifiers.envelope_from,
            header_from: value.identifiers.header_from,
            dkim_results: value
                .auth_results
                .dkim
                .into_iter()
                .map(Into::into)
                .collect(),
            spf_results: value.auth_results.spf.into_iter().map(Into::into).collect(),
            extensions: value.extensions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<structs::DmarcReport> for Report {
    fn from(value: structs::DmarcReport) -> Self {
        Report {
            version: value.version as f32,
            report_metadata: ReportMetadata {
                org_name: value.org_name,
                email: value.email,
                extra_contact_info: value.extra_contact_info,
                report_id: value.report_id,
                date_range: mail_auth::report::DateRange {
                    begin: value.date_range_begin.timestamp() as u64,
                    end: value.date_range_end.timestamp() as u64,
                },
                error: value.errors,
            },
            policy_published: PolicyPublished {
                domain: value.policy_domain,
                version_published: value.policy_version.as_deref().and_then(|v| v.parse().ok()),
                adkim: value.policy_adkim.into(),
                aspf: value.policy_aspf.into(),
                p: value.policy_disposition.into(),
                sp: value.policy_subdomain_disposition.into(),
                testing: value.policy_testing_mode,
                fo: failure_reporting_options_to_fo(&value.policy_failure_reporting_options),
            },
            record: value.records.into_iter().map(Into::into).collect(),
            extensions: value.extensions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Report> for structs::DmarcReport {
    fn from(value: Report) -> Self {
        structs::DmarcReport {
            version: value.version as f64,
            date_range_begin: UTCDateTime::from_timestamp(
                value.report_metadata.date_range.begin as i64,
            ),
            date_range_end: UTCDateTime::from_timestamp(
                value.report_metadata.date_range.end as i64,
            ),
            email: value.report_metadata.email,
            errors: value.report_metadata.error,
            extensions: value.extensions.into_iter().map(Into::into).collect(),
            extra_contact_info: value.report_metadata.extra_contact_info,
            org_name: value.report_metadata.org_name,
            policy_adkim: value.policy_published.adkim.into(),
            policy_aspf: value.policy_published.aspf.into(),
            policy_disposition: value.policy_published.p.into(),
            policy_domain: value.policy_published.domain,
            policy_failure_reporting_options: fo_to_failure_reporting_options(
                &value.policy_published.fo,
            ),
            policy_subdomain_disposition: value.policy_published.sp.into(),
            policy_testing_mode: value.policy_published.testing,
            policy_version: value
                .policy_published
                .version_published
                .map(|v| v.to_string()),
            records: value.record.into_iter().map(Into::into).collect(),
            report_id: value.report_metadata.report_id,
        }
    }
}

impl From<enums::ArfAuthFailureType> for AuthFailureType {
    fn from(value: enums::ArfAuthFailureType) -> Self {
        match value {
            enums::ArfAuthFailureType::Adsp => AuthFailureType::Adsp,
            enums::ArfAuthFailureType::BodyHash => AuthFailureType::BodyHash,
            enums::ArfAuthFailureType::Revoked => AuthFailureType::Revoked,
            enums::ArfAuthFailureType::Signature => AuthFailureType::Signature,
            enums::ArfAuthFailureType::Spf => AuthFailureType::Spf,
            enums::ArfAuthFailureType::Dmarc => AuthFailureType::Dmarc,
            enums::ArfAuthFailureType::Unspecified => AuthFailureType::Unspecified,
        }
    }
}

impl From<AuthFailureType> for enums::ArfAuthFailureType {
    fn from(value: AuthFailureType) -> Self {
        match value {
            AuthFailureType::Adsp => enums::ArfAuthFailureType::Adsp,
            AuthFailureType::BodyHash => enums::ArfAuthFailureType::BodyHash,
            AuthFailureType::Revoked => enums::ArfAuthFailureType::Revoked,
            AuthFailureType::Signature => enums::ArfAuthFailureType::Signature,
            AuthFailureType::Spf => enums::ArfAuthFailureType::Spf,
            AuthFailureType::Dmarc => enums::ArfAuthFailureType::Dmarc,
            AuthFailureType::Unspecified => enums::ArfAuthFailureType::Unspecified,
        }
    }
}

impl From<enums::ArfDeliveryResult> for DeliveryResult {
    fn from(value: enums::ArfDeliveryResult) -> Self {
        match value {
            enums::ArfDeliveryResult::Delivered => DeliveryResult::Delivered,
            enums::ArfDeliveryResult::Spam => DeliveryResult::Spam,
            enums::ArfDeliveryResult::Policy => DeliveryResult::Policy,
            enums::ArfDeliveryResult::Reject => DeliveryResult::Reject,
            enums::ArfDeliveryResult::Other => DeliveryResult::Other,
            enums::ArfDeliveryResult::Unspecified => DeliveryResult::Unspecified,
        }
    }
}

impl From<DeliveryResult> for enums::ArfDeliveryResult {
    fn from(value: DeliveryResult) -> Self {
        match value {
            DeliveryResult::Delivered => enums::ArfDeliveryResult::Delivered,
            DeliveryResult::Spam => enums::ArfDeliveryResult::Spam,
            DeliveryResult::Policy => enums::ArfDeliveryResult::Policy,
            DeliveryResult::Reject => enums::ArfDeliveryResult::Reject,
            DeliveryResult::Other => enums::ArfDeliveryResult::Other,
            DeliveryResult::Unspecified => enums::ArfDeliveryResult::Unspecified,
        }
    }
}

impl From<enums::ArfFeedbackType> for FeedbackType {
    fn from(value: enums::ArfFeedbackType) -> Self {
        match value {
            enums::ArfFeedbackType::Abuse => FeedbackType::Abuse,
            enums::ArfFeedbackType::AuthFailure => FeedbackType::AuthFailure,
            enums::ArfFeedbackType::Fraud => FeedbackType::Fraud,
            enums::ArfFeedbackType::NotSpam => FeedbackType::NotSpam,
            enums::ArfFeedbackType::Virus => FeedbackType::Virus,
            enums::ArfFeedbackType::Other => FeedbackType::Other,
        }
    }
}

impl From<FeedbackType> for enums::ArfFeedbackType {
    fn from(value: FeedbackType) -> Self {
        match value {
            FeedbackType::Abuse => enums::ArfFeedbackType::Abuse,
            FeedbackType::AuthFailure => enums::ArfFeedbackType::AuthFailure,
            FeedbackType::Fraud => enums::ArfFeedbackType::Fraud,
            FeedbackType::NotSpam => enums::ArfFeedbackType::NotSpam,
            FeedbackType::Virus => enums::ArfFeedbackType::Virus,
            FeedbackType::Other => enums::ArfFeedbackType::Other,
        }
    }
}

impl From<enums::ArfIdentityAlignment> for IdentityAlignment {
    fn from(value: enums::ArfIdentityAlignment) -> Self {
        match value {
            enums::ArfIdentityAlignment::None => IdentityAlignment::None,
            enums::ArfIdentityAlignment::Spf => IdentityAlignment::Spf,
            enums::ArfIdentityAlignment::Dkim => IdentityAlignment::Dkim,
            enums::ArfIdentityAlignment::DkimSpf => IdentityAlignment::DkimSpf,
            enums::ArfIdentityAlignment::Unspecified => IdentityAlignment::Unspecified,
        }
    }
}

impl From<IdentityAlignment> for enums::ArfIdentityAlignment {
    fn from(value: IdentityAlignment) -> Self {
        match value {
            IdentityAlignment::None => enums::ArfIdentityAlignment::None,
            IdentityAlignment::Spf => enums::ArfIdentityAlignment::Spf,
            IdentityAlignment::Dkim => enums::ArfIdentityAlignment::Dkim,
            IdentityAlignment::DkimSpf => enums::ArfIdentityAlignment::DkimSpf,
            IdentityAlignment::Unspecified => enums::ArfIdentityAlignment::Unspecified,
        }
    }
}

impl From<structs::ArfFeedbackReport> for Feedback<'static> {
    fn from(value: structs::ArfFeedbackReport) -> Self {
        Feedback {
            feedback_type: value.feedback_type.into(),
            arrival_date: value.arrival_date.map(|d| d.timestamp()),
            authentication_results: value
                .authentication_results
                .into_iter()
                .map(Cow::Owned)
                .collect(),
            incidents: value.incidents as u32,
            original_envelope_id: value.original_envelope_id.map(Cow::Owned),
            original_mail_from: value.original_mail_from.map(Cow::Owned),
            original_rcpt_to: value.original_rcpt_to.map(Cow::Owned),
            reported_domain: value.reported_domains.into_iter().map(Cow::Owned).collect(),
            reported_uri: value.reported_uris.into_iter().map(Cow::Owned).collect(),
            reporting_mta: value.reporting_mta.map(Cow::Owned),
            source_ip: value.source_ip.map(|ip| ip.into_inner()),
            user_agent: value.user_agent.map(Cow::Owned),
            version: value.version as u32,
            source_port: value.source_port.unwrap_or(0) as u32,
            auth_failure: value.auth_failure.into(),
            delivery_result: value.delivery_result.into(),
            dkim_adsp_dns: value.dkim_adsp_dns.map(Cow::Owned),
            dkim_canonicalized_body: value.dkim_canonicalized_body.map(Cow::Owned),
            dkim_canonicalized_header: value.dkim_canonicalized_header.map(Cow::Owned),
            dkim_domain: value.dkim_domain.map(Cow::Owned),
            dkim_identity: value.dkim_identity.map(Cow::Owned),
            dkim_selector: value.dkim_selector.map(Cow::Owned),
            dkim_selector_dns: value.dkim_selector_dns.map(Cow::Owned),
            spf_dns: value.spf_dns.map(Cow::Owned),
            identity_alignment: value.identity_alignment.into(),
            message: value.message.map(Cow::Owned),
            headers: value.headers.map(Cow::Owned),
        }
    }
}

impl From<Feedback<'_>> for structs::ArfFeedbackReport {
    fn from(value: Feedback<'_>) -> Self {
        let port = value.source_port;
        structs::ArfFeedbackReport {
            arrival_date: value.arrival_date.map(UTCDateTime::from_timestamp),
            auth_failure: value.auth_failure.into(),
            authentication_results: value
                .authentication_results
                .into_iter()
                .map(|s| s.into_owned())
                .collect(),
            delivery_result: value.delivery_result.into(),
            dkim_adsp_dns: value.dkim_adsp_dns.map(|s| s.into_owned()),
            dkim_canonicalized_body: value.dkim_canonicalized_body.map(|s| s.into_owned()),
            dkim_canonicalized_header: value.dkim_canonicalized_header.map(|s| s.into_owned()),
            dkim_domain: value.dkim_domain.map(|s| s.into_owned()),
            dkim_identity: value.dkim_identity.map(|s| s.into_owned()),
            dkim_selector: value.dkim_selector.map(|s| s.into_owned()),
            dkim_selector_dns: value.dkim_selector_dns.map(|s| s.into_owned()),
            feedback_type: value.feedback_type.into(),
            headers: value.headers.map(|s| s.into_owned()),
            identity_alignment: value.identity_alignment.into(),
            incidents: value.incidents as u64,
            message: value.message.map(|s| s.into_owned()),
            original_envelope_id: value.original_envelope_id.map(|s| s.into_owned()),
            original_mail_from: value.original_mail_from.map(|s| s.into_owned()),
            original_rcpt_to: value.original_rcpt_to.map(|s| s.into_owned()),
            reported_domains: value
                .reported_domain
                .into_iter()
                .map(|s| s.into_owned())
                .collect(),
            reported_uris: value
                .reported_uri
                .into_iter()
                .map(|s| s.into_owned())
                .collect(),
            reporting_mta: value.reporting_mta.map(|s| s.into_owned()),
            source_ip: value.source_ip.map(IpAddr),
            source_port: if port == 0 || port > 65535 {
                None
            } else {
                Some(port as u64)
            },
            spf_dns: value.spf_dns.map(|s| s.into_owned()),
            user_agent: value.user_agent.map(|s| s.into_owned()),
            version: value.version as u64,
        }
    }
}

impl From<enums::TlsPolicyType> for PolicyType {
    fn from(value: enums::TlsPolicyType) -> Self {
        match value {
            enums::TlsPolicyType::Tlsa => PolicyType::Tlsa,
            enums::TlsPolicyType::Sts => PolicyType::Sts,
            enums::TlsPolicyType::NoPolicyFound => PolicyType::NoPolicyFound,
            enums::TlsPolicyType::Other => PolicyType::Other,
        }
    }
}

impl From<PolicyType> for enums::TlsPolicyType {
    fn from(value: PolicyType) -> Self {
        match value {
            PolicyType::Tlsa => enums::TlsPolicyType::Tlsa,
            PolicyType::Sts => enums::TlsPolicyType::Sts,
            PolicyType::NoPolicyFound => enums::TlsPolicyType::NoPolicyFound,
            PolicyType::Other => enums::TlsPolicyType::Other,
        }
    }
}

impl From<enums::TlsResultType> for ResultType {
    fn from(value: enums::TlsResultType) -> Self {
        match value {
            enums::TlsResultType::StartTlsNotSupported => ResultType::StartTlsNotSupported,
            enums::TlsResultType::CertificateHostMismatch => ResultType::CertificateHostMismatch,
            enums::TlsResultType::CertificateExpired => ResultType::CertificateExpired,
            enums::TlsResultType::CertificateNotTrusted => ResultType::CertificateNotTrusted,
            enums::TlsResultType::ValidationFailure => ResultType::ValidationFailure,
            enums::TlsResultType::TlsaInvalid => ResultType::TlsaInvalid,
            enums::TlsResultType::DnssecInvalid => ResultType::DnssecInvalid,
            enums::TlsResultType::DaneRequired => ResultType::DaneRequired,
            enums::TlsResultType::StsPolicyFetchError => ResultType::StsPolicyFetchError,
            enums::TlsResultType::StsPolicyInvalid => ResultType::StsPolicyInvalid,
            enums::TlsResultType::StsWebpkiInvalid => ResultType::StsWebpkiInvalid,
            enums::TlsResultType::Other => ResultType::Other,
        }
    }
}

impl From<ResultType> for enums::TlsResultType {
    fn from(value: ResultType) -> Self {
        match value {
            ResultType::StartTlsNotSupported => enums::TlsResultType::StartTlsNotSupported,
            ResultType::CertificateHostMismatch => enums::TlsResultType::CertificateHostMismatch,
            ResultType::CertificateExpired => enums::TlsResultType::CertificateExpired,
            ResultType::CertificateNotTrusted => enums::TlsResultType::CertificateNotTrusted,
            ResultType::ValidationFailure => enums::TlsResultType::ValidationFailure,
            ResultType::TlsaInvalid => enums::TlsResultType::TlsaInvalid,
            ResultType::DnssecInvalid => enums::TlsResultType::DnssecInvalid,
            ResultType::DaneRequired => enums::TlsResultType::DaneRequired,
            ResultType::StsPolicyFetchError => enums::TlsResultType::StsPolicyFetchError,
            ResultType::StsPolicyInvalid => enums::TlsResultType::StsPolicyInvalid,
            ResultType::StsWebpkiInvalid => enums::TlsResultType::StsWebpkiInvalid,
            ResultType::Other => enums::TlsResultType::Other,
        }
    }
}

impl From<structs::TlsFailureDetails> for FailureDetails {
    fn from(value: structs::TlsFailureDetails) -> Self {
        FailureDetails {
            result_type: value.result_type.into(),
            sending_mta_ip: value.sending_mta_ip.map(|ip| ip.into_inner()),
            receiving_mx_hostname: value.receiving_mx_hostname,
            receiving_mx_helo: value.receiving_mx_helo,
            receiving_ip: value.receiving_ip.map(|ip| ip.into_inner()),
            failed_session_count: value.failed_session_count as u32,
            additional_information: value.additional_information,
            failure_reason_code: value.failure_reason_code,
        }
    }
}

impl From<FailureDetails> for structs::TlsFailureDetails {
    fn from(value: FailureDetails) -> Self {
        structs::TlsFailureDetails {
            result_type: value.result_type.into(),
            sending_mta_ip: value.sending_mta_ip.map(IpAddr),
            receiving_mx_hostname: value.receiving_mx_hostname,
            receiving_mx_helo: value.receiving_mx_helo,
            receiving_ip: value.receiving_ip.map(IpAddr),
            failed_session_count: value.failed_session_count as u64,
            additional_information: value.additional_information,
            failure_reason_code: value.failure_reason_code,
        }
    }
}

impl From<structs::TlsReportPolicy> for Policy {
    fn from(value: structs::TlsReportPolicy) -> Self {
        Policy {
            policy: PolicyDetails {
                policy_type: value.policy_type.into(),
                policy_string: value.policy_strings,
                policy_domain: value.policy_domain,
                mx_host: value.mx_hosts,
            },
            summary: Summary {
                total_success: value.total_successful_sessions as u32,
                total_failure: value.total_failed_sessions as u32,
            },
            failure_details: value.failure_details.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<Policy> for structs::TlsReportPolicy {
    fn from(value: Policy) -> Self {
        structs::TlsReportPolicy {
            policy_type: value.policy.policy_type.into(),
            policy_strings: value.policy.policy_string,
            policy_domain: value.policy.policy_domain,
            mx_hosts: value.policy.mx_host,
            total_successful_sessions: value.summary.total_success as u64,
            total_failed_sessions: value.summary.total_failure as u64,
            failure_details: value.failure_details.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<structs::TlsReport> for TlsReport {
    fn from(value: structs::TlsReport) -> Self {
        TlsReport {
            organization_name: value.organization_name,
            date_range: mail_auth::report::tlsrpt::DateRange::from_timestamps(
                value.date_range_start.timestamp(),
                value.date_range_end.timestamp(),
            ),
            contact_info: value.contact_info,
            report_id: value.report_id,
            policies: value.policies.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<TlsReport> for structs::TlsReport {
    fn from(value: TlsReport) -> Self {
        structs::TlsReport {
            organization_name: value.organization_name,
            date_range_start: UTCDateTime::from_timestamp(
                value.date_range.start_datetime.to_timestamp(),
            ),
            date_range_end: UTCDateTime::from_timestamp(
                value.date_range.end_datetime.to_timestamp(),
            ),
            contact_info: value.contact_info,
            report_id: value.report_id,
            policies: value.policies.into_iter().map(Into::into).collect(),
        }
    }
}

fn failure_reporting_options_to_fo(opts: &[enums::FailureReportingOption]) -> Option<String> {
    let opts_len = opts.len();
    if opts_len > 0 {
        let mut out = String::with_capacity(opts_len * 2);
        for (i, o) in opts.iter().enumerate() {
            if i > 0 {
                out.push(':');
            }
            match o {
                enums::FailureReportingOption::All => out.push('0'),
                enums::FailureReportingOption::Any => out.push('1'),
                enums::FailureReportingOption::DkimFailure => out.push('d'),
                enums::FailureReportingOption::SpfFailure => out.push('s'),
            }
        }
        Some(out)
    } else {
        None
    }
}

fn fo_to_failure_reporting_options(fo: &Option<String>) -> Vec<enums::FailureReportingOption> {
    match fo {
        None => vec![],
        Some(s) if s.is_empty() => vec![],
        Some(s) => s
            .split(':')
            .filter_map(|token| match token.trim() {
                "0" => Some(enums::FailureReportingOption::All),
                "1" => Some(enums::FailureReportingOption::Any),
                "d" => Some(enums::FailureReportingOption::DkimFailure),
                "s" => Some(enums::FailureReportingOption::SpfFailure),
                _ => None,
            })
            .collect(),
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
