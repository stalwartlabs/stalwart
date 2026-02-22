/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::registry::Registry,
};
use registry::schema::prelude::ObjectType;

pub trait RegistrySet: Sync + Send {
    fn registry_set(
        &self,
        object_type: ObjectType,
        request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<Registry>>> + Send;
}

impl RegistrySet for Server {
    async fn registry_set(
        &self,
        object_type: ObjectType,
        mut request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<Registry>> {
        match object_type {
            ObjectType::AcmeProvider => {}
            ObjectType::AddressBook => {}
            ObjectType::AiModel => {}
            ObjectType::Alert => {}
            ObjectType::AllowedIp => {}
            ObjectType::Application => {}
            ObjectType::Asn => {}
            ObjectType::Authentication => {}
            ObjectType::BlobStore => {}
            ObjectType::BlockedIp => {}
            ObjectType::Cache => {}
            ObjectType::Calendar => {}
            ObjectType::CalendarAlarm => {}
            ObjectType::CalendarScheduling => {}
            ObjectType::Certificate => {}
            ObjectType::Coordinator => {}
            ObjectType::DataRetention => {}
            ObjectType::DataStore => {}
            ObjectType::Directory => {}
            ObjectType::DkimReportSettings => {}
            ObjectType::DmarcReportSettings => {}
            ObjectType::DnsResolver => {}
            ObjectType::DnsServer => {}
            ObjectType::Email => {}
            ObjectType::Enterprise => {}
            ObjectType::EventTracingLevel => {}
            ObjectType::FileStorage => {}
            ObjectType::Http => {}
            ObjectType::HttpForm => {}
            ObjectType::HttpLookup => {}
            ObjectType::Imap => {}
            ObjectType::InMemoryStore => {}
            ObjectType::Jmap => {}
            ObjectType::LocalSettings => {}
            ObjectType::MemoryLookupKey => {}
            ObjectType::MemoryLookupKeyValue => {}
            ObjectType::Metrics => {}
            ObjectType::MetricsStore => {}
            ObjectType::MtaConnectionStrategy => {}
            ObjectType::MtaDeliverySchedule => {}
            ObjectType::MtaExtensions => {}
            ObjectType::MtaHook => {}
            ObjectType::MtaInboundSession => {}
            ObjectType::MtaInboundThrottle => {}
            ObjectType::MtaMilter => {}
            ObjectType::MtaOutboundStrategy => {}
            ObjectType::MtaOutboundThrottle => {}
            ObjectType::MtaQueueQuota => {}
            ObjectType::MtaRoute => {}
            ObjectType::MtaStageAuth => {}
            ObjectType::MtaStageConnect => {}
            ObjectType::MtaStageData => {}
            ObjectType::MtaStageEhlo => {}
            ObjectType::MtaStageMail => {}
            ObjectType::MtaStageRcpt => {}
            ObjectType::MtaSts => {}
            ObjectType::MtaTlsStrategy => {}
            ObjectType::MtaVirtualQueue => {}
            ObjectType::NetworkListener => {}
            ObjectType::Node => {}
            ObjectType::NodeRole => {}
            ObjectType::NodeShard => {}
            ObjectType::OidcProvider => {}
            ObjectType::RegistryBundle => {}
            ObjectType::ReportSettings => {}
            ObjectType::Search => {}
            ObjectType::SearchStore => {}
            ObjectType::Security => {}
            ObjectType::SenderAuth => {}
            ObjectType::Sharing => {}
            ObjectType::SieveSystemInterpreter => {}
            ObjectType::SieveSystemScript => {}
            ObjectType::SieveUserInterpreter => {}
            ObjectType::SieveUserScript => {}
            ObjectType::SpamClassifier => {}
            ObjectType::SpamDnsblServer => {}
            ObjectType::SpamDnsblSettings => {}
            ObjectType::SpamFileExtension => {}
            ObjectType::SpamLlm => {}
            ObjectType::SpamPyzor => {}
            ObjectType::SpamRule => {}
            ObjectType::SpamSettings => {}
            ObjectType::SpamTag => {}
            ObjectType::SpfReportSettings => {}
            ObjectType::StoreLookup => {}
            ObjectType::TlsReportSettings => {}
            ObjectType::Tracer => {}
            ObjectType::TracingStore => {}
            ObjectType::WebDav => {}
            ObjectType::WebHook => {}

            // Tenant filtered
            ObjectType::Account => {}
            ObjectType::DsnReportSettings => {}
            ObjectType::MailingList => {}
            ObjectType::OAuthClient => {}
            ObjectType::Role => {}
            ObjectType::Tenant => {}

            // Account filtered
            ObjectType::MaskedEmail => {}
            ObjectType::PublicKey => {}

            // Special
            ObjectType::DkimSignature => {}
            ObjectType::Domain => {}
            ObjectType::Log => {}
            ObjectType::QueuedMessage => {}
            ObjectType::Task => {}

            // Move to registry?
            ObjectType::ArfFeedbackReport => {}
            ObjectType::DmarcReport => {}
            ObjectType::TlsReport => {}
            ObjectType::DeletedItem => {}
            ObjectType::Metric => {}
            ObjectType::Trace => {}
            ObjectType::SpamTrainingSample => {}
        }

        let todo = "read only properties";

        todo!()
    }
}
