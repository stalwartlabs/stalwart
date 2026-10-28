/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

use crate::schema::prelude::*;

impl EnumImpl for ObjectType {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            ObjectType,
            b"Account" => ObjectType::Account,
            b"AccountPassword" => ObjectType::AccountPassword,
            b"AccountSettings" => ObjectType::AccountSettings,
            b"AcmeProvider" => ObjectType::AcmeProvider,
            b"Action" => ObjectType::Action,
            b"AddressBook" => ObjectType::AddressBook,
            b"AiModel" => ObjectType::AiModel,
            b"Alert" => ObjectType::Alert,
            b"AllowedIp" => ObjectType::AllowedIp,
            b"ApiKey" => ObjectType::ApiKey,
            b"AppPassword" => ObjectType::AppPassword,
            b"Application" => ObjectType::Application,
            b"ArchivedItem" => ObjectType::ArchivedItem,
            b"ArfExternalReport" => ObjectType::ArfExternalReport,
            b"Asn" => ObjectType::Asn,
            b"Authentication" => ObjectType::Authentication,
            b"BlobStore" => ObjectType::BlobStore,
            b"BlockedIp" => ObjectType::BlockedIp,
            b"Bootstrap" => ObjectType::Bootstrap,
            b"Cache" => ObjectType::Cache,
            b"Calendar" => ObjectType::Calendar,
            b"CalendarAlarm" => ObjectType::CalendarAlarm,
            b"CalendarScheduling" => ObjectType::CalendarScheduling,
            b"Certificate" => ObjectType::Certificate,
            b"ClusterNode" => ObjectType::ClusterNode,
            b"ClusterRole" => ObjectType::ClusterRole,
            b"Coordinator" => ObjectType::Coordinator,
            b"DataRetention" => ObjectType::DataRetention,
            b"DataStore" => ObjectType::DataStore,
            b"Directory" => ObjectType::Directory,
            b"DkimReportSettings" => ObjectType::DkimReportSettings,
            b"DkimSignature" => ObjectType::DkimSignature,
            b"DmarcExternalReport" => ObjectType::DmarcExternalReport,
            b"DmarcInternalReport" => ObjectType::DmarcInternalReport,
            b"DmarcReportSettings" => ObjectType::DmarcReportSettings,
            b"DnsResolver" => ObjectType::DnsResolver,
            b"DnsServer" => ObjectType::DnsServer,
            b"Domain" => ObjectType::Domain,
            b"DsnReportSettings" => ObjectType::DsnReportSettings,
            b"Email" => ObjectType::Email,
            b"Enterprise" => ObjectType::Enterprise,
            b"EventTracingLevel" => ObjectType::EventTracingLevel,
            b"FileStorage" => ObjectType::FileStorage,
            b"Http" => ObjectType::Http,
            b"HttpForm" => ObjectType::HttpForm,
            b"HttpLookup" => ObjectType::HttpLookup,
            b"Imap" => ObjectType::Imap,
            b"InMemoryStore" => ObjectType::InMemoryStore,
            b"IndexQueueStatus" => ObjectType::IndexQueueStatus,
            b"Jmap" => ObjectType::Jmap,
            b"Log" => ObjectType::Log,
            b"MailingList" => ObjectType::MailingList,
            b"MaskedEmail" => ObjectType::MaskedEmail,
            b"MemoryLookupKey" => ObjectType::MemoryLookupKey,
            b"MemoryLookupKeyValue" => ObjectType::MemoryLookupKeyValue,
            b"Metadata" => ObjectType::Metadata,
            b"Metric" => ObjectType::Metric,
            b"Metrics" => ObjectType::Metrics,
            b"MetricsStore" => ObjectType::MetricsStore,
            b"MtaConnectionStrategy" => ObjectType::MtaConnectionStrategy,
            b"MtaDeliverySchedule" => ObjectType::MtaDeliverySchedule,
            b"MtaExtensions" => ObjectType::MtaExtensions,
            b"MtaHook" => ObjectType::MtaHook,
            b"MtaInboundSession" => ObjectType::MtaInboundSession,
            b"MtaInboundThrottle" => ObjectType::MtaInboundThrottle,
            b"MtaMilter" => ObjectType::MtaMilter,
            b"MtaOutboundStrategy" => ObjectType::MtaOutboundStrategy,
            b"MtaOutboundThrottle" => ObjectType::MtaOutboundThrottle,
            b"MtaQueueQuota" => ObjectType::MtaQueueQuota,
            b"MtaRoute" => ObjectType::MtaRoute,
            b"MtaStageAuth" => ObjectType::MtaStageAuth,
            b"MtaStageConnect" => ObjectType::MtaStageConnect,
            b"MtaStageData" => ObjectType::MtaStageData,
            b"MtaStageEhlo" => ObjectType::MtaStageEhlo,
            b"MtaStageMail" => ObjectType::MtaStageMail,
            b"MtaStageRcpt" => ObjectType::MtaStageRcpt,
            b"MtaSts" => ObjectType::MtaSts,
            b"MtaTlsStrategy" => ObjectType::MtaTlsStrategy,
            b"MtaVirtualQueue" => ObjectType::MtaVirtualQueue,
            b"NetworkListener" => ObjectType::NetworkListener,
            b"OAuthClient" => ObjectType::OAuthClient,
            b"OAuthGrant" => ObjectType::OAuthGrant,
            b"OidcProvider" => ObjectType::OidcProvider,
            b"PublicKey" => ObjectType::PublicKey,
            b"QueuedMessage" => ObjectType::QueuedMessage,
            b"ReportSettings" => ObjectType::ReportSettings,
            b"Role" => ObjectType::Role,
            b"Search" => ObjectType::Search,
            b"SearchStore" => ObjectType::SearchStore,
            b"Security" => ObjectType::Security,
            b"SenderAuth" => ObjectType::SenderAuth,
            b"Sharing" => ObjectType::Sharing,
            b"SieveSystemInterpreter" => ObjectType::SieveSystemInterpreter,
            b"SieveSystemScript" => ObjectType::SieveSystemScript,
            b"SieveUserInterpreter" => ObjectType::SieveUserInterpreter,
            b"SieveUserScript" => ObjectType::SieveUserScript,
            b"SpamAi" => ObjectType::SpamAi,
            b"SpamClassifier" => ObjectType::SpamClassifier,
            b"SpamDnsblServer" => ObjectType::SpamDnsblServer,
            b"SpamDnsblSettings" => ObjectType::SpamDnsblSettings,
            b"SpamFileExtension" => ObjectType::SpamFileExtension,
            b"SpamPyzor" => ObjectType::SpamPyzor,
            b"SpamRule" => ObjectType::SpamRule,
            b"SpamSettings" => ObjectType::SpamSettings,
            b"SpamTag" => ObjectType::SpamTag,
            b"SpamTrainingSample" => ObjectType::SpamTrainingSample,
            b"SpfReportSettings" => ObjectType::SpfReportSettings,
            b"StoreLookup" => ObjectType::StoreLookup,
            b"SystemSettings" => ObjectType::SystemSettings,
            b"Task" => ObjectType::Task,
            b"TaskManager" => ObjectType::TaskManager,
            b"Tenant" => ObjectType::Tenant,
            b"TlsExternalReport" => ObjectType::TlsExternalReport,
            b"TlsInternalReport" => ObjectType::TlsInternalReport,
            b"TlsReportSettings" => ObjectType::TlsReportSettings,
            b"Trace" => ObjectType::Trace,
            b"Tracer" => ObjectType::Tracer,
            b"TracingStore" => ObjectType::TracingStore,
            b"WebDav" => ObjectType::WebDav,
            b"WebHook" => ObjectType::WebHook,
        }
        .copied()
    }

    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            ObjectType,
            b"Account" => ObjectType::Account,
            b"AccountPassword" => ObjectType::AccountPassword,
            b"AccountSettings" => ObjectType::AccountSettings,
            b"AcmeProvider" => ObjectType::AcmeProvider,
            b"Action" => ObjectType::Action,
            b"AddressBook" => ObjectType::AddressBook,
            b"AllowedIp" => ObjectType::AllowedIp,
            b"ApiKey" => ObjectType::ApiKey,
            b"AppPassword" => ObjectType::AppPassword,
            b"Application" => ObjectType::Application,
            b"ArfExternalReport" => ObjectType::ArfExternalReport,
            b"Asn" => ObjectType::Asn,
            b"Authentication" => ObjectType::Authentication,
            b"BlobStore" => ObjectType::BlobStore,
            b"BlockedIp" => ObjectType::BlockedIp,
            b"Bootstrap" => ObjectType::Bootstrap,
            b"Cache" => ObjectType::Cache,
            b"Calendar" => ObjectType::Calendar,
            b"CalendarAlarm" => ObjectType::CalendarAlarm,
            b"CalendarScheduling" => ObjectType::CalendarScheduling,
            b"Certificate" => ObjectType::Certificate,
            b"ClusterNode" => ObjectType::ClusterNode,
            b"ClusterRole" => ObjectType::ClusterRole,
            b"Coordinator" => ObjectType::Coordinator,
            b"DataRetention" => ObjectType::DataRetention,
            b"DataStore" => ObjectType::DataStore,
            b"Directory" => ObjectType::Directory,
            b"DkimReportSettings" => ObjectType::DkimReportSettings,
            b"DkimSignature" => ObjectType::DkimSignature,
            b"DmarcExternalReport" => ObjectType::DmarcExternalReport,
            b"DmarcInternalReport" => ObjectType::DmarcInternalReport,
            b"DmarcReportSettings" => ObjectType::DmarcReportSettings,
            b"DnsResolver" => ObjectType::DnsResolver,
            b"DnsServer" => ObjectType::DnsServer,
            b"Domain" => ObjectType::Domain,
            b"DsnReportSettings" => ObjectType::DsnReportSettings,
            b"Email" => ObjectType::Email,
            b"EventTracingLevel" => ObjectType::EventTracingLevel,
            b"FileStorage" => ObjectType::FileStorage,
            b"Http" => ObjectType::Http,
            b"HttpForm" => ObjectType::HttpForm,
            b"HttpLookup" => ObjectType::HttpLookup,
            b"Imap" => ObjectType::Imap,
            b"InMemoryStore" => ObjectType::InMemoryStore,
            b"IndexQueueStatus" => ObjectType::IndexQueueStatus,
            b"Jmap" => ObjectType::Jmap,
            b"Log" => ObjectType::Log,
            b"MailingList" => ObjectType::MailingList,
            b"MemoryLookupKey" => ObjectType::MemoryLookupKey,
            b"MemoryLookupKeyValue" => ObjectType::MemoryLookupKeyValue,
            b"Metadata" => ObjectType::Metadata,
            b"Metrics" => ObjectType::Metrics,
            b"MtaConnectionStrategy" => ObjectType::MtaConnectionStrategy,
            b"MtaDeliverySchedule" => ObjectType::MtaDeliverySchedule,
            b"MtaExtensions" => ObjectType::MtaExtensions,
            b"MtaHook" => ObjectType::MtaHook,
            b"MtaInboundSession" => ObjectType::MtaInboundSession,
            b"MtaInboundThrottle" => ObjectType::MtaInboundThrottle,
            b"MtaMilter" => ObjectType::MtaMilter,
            b"MtaOutboundStrategy" => ObjectType::MtaOutboundStrategy,
            b"MtaOutboundThrottle" => ObjectType::MtaOutboundThrottle,
            b"MtaQueueQuota" => ObjectType::MtaQueueQuota,
            b"MtaRoute" => ObjectType::MtaRoute,
            b"MtaStageAuth" => ObjectType::MtaStageAuth,
            b"MtaStageConnect" => ObjectType::MtaStageConnect,
            b"MtaStageData" => ObjectType::MtaStageData,
            b"MtaStageEhlo" => ObjectType::MtaStageEhlo,
            b"MtaStageMail" => ObjectType::MtaStageMail,
            b"MtaStageRcpt" => ObjectType::MtaStageRcpt,
            b"MtaSts" => ObjectType::MtaSts,
            b"MtaTlsStrategy" => ObjectType::MtaTlsStrategy,
            b"MtaVirtualQueue" => ObjectType::MtaVirtualQueue,
            b"NetworkListener" => ObjectType::NetworkListener,
            b"OAuthClient" => ObjectType::OAuthClient,
            b"OAuthGrant" => ObjectType::OAuthGrant,
            b"OidcProvider" => ObjectType::OidcProvider,
            b"PublicKey" => ObjectType::PublicKey,
            b"QueuedMessage" => ObjectType::QueuedMessage,
            b"ReportSettings" => ObjectType::ReportSettings,
            b"Role" => ObjectType::Role,
            b"Search" => ObjectType::Search,
            b"SearchStore" => ObjectType::SearchStore,
            b"Security" => ObjectType::Security,
            b"SenderAuth" => ObjectType::SenderAuth,
            b"Sharing" => ObjectType::Sharing,
            b"SieveSystemInterpreter" => ObjectType::SieveSystemInterpreter,
            b"SieveSystemScript" => ObjectType::SieveSystemScript,
            b"SieveUserInterpreter" => ObjectType::SieveUserInterpreter,
            b"SieveUserScript" => ObjectType::SieveUserScript,
            b"SpamClassifier" => ObjectType::SpamClassifier,
            b"SpamDnsblServer" => ObjectType::SpamDnsblServer,
            b"SpamDnsblSettings" => ObjectType::SpamDnsblSettings,
            b"SpamFileExtension" => ObjectType::SpamFileExtension,
            b"SpamPyzor" => ObjectType::SpamPyzor,
            b"SpamRule" => ObjectType::SpamRule,
            b"SpamSettings" => ObjectType::SpamSettings,
            b"SpamTag" => ObjectType::SpamTag,
            b"SpamTrainingSample" => ObjectType::SpamTrainingSample,
            b"SpfReportSettings" => ObjectType::SpfReportSettings,
            b"StoreLookup" => ObjectType::StoreLookup,
            b"SystemSettings" => ObjectType::SystemSettings,
            b"Task" => ObjectType::Task,
            b"TaskManager" => ObjectType::TaskManager,
            b"TlsExternalReport" => ObjectType::TlsExternalReport,
            b"TlsInternalReport" => ObjectType::TlsInternalReport,
            b"TlsReportSettings" => ObjectType::TlsReportSettings,
            b"Tracer" => ObjectType::Tracer,
            b"WebDav" => ObjectType::WebDav,
            b"WebHook" => ObjectType::WebHook,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Account => "Account",
            ObjectType::AccountPassword => "AccountPassword",
            ObjectType::AccountSettings => "AccountSettings",
            ObjectType::AcmeProvider => "AcmeProvider",
            ObjectType::Action => "Action",
            ObjectType::AddressBook => "AddressBook",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => "AiModel",
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => "Alert",
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => "AllowedIp",
            ObjectType::ApiKey => "ApiKey",
            ObjectType::AppPassword => "AppPassword",
            ObjectType::Application => "Application",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => "ArchivedItem",
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => "ArfExternalReport",
            ObjectType::Asn => "Asn",
            ObjectType::Authentication => "Authentication",
            ObjectType::BlobStore => "BlobStore",
            ObjectType::BlockedIp => "BlockedIp",
            ObjectType::Bootstrap => "Bootstrap",
            ObjectType::Cache => "Cache",
            ObjectType::Calendar => "Calendar",
            ObjectType::CalendarAlarm => "CalendarAlarm",
            ObjectType::CalendarScheduling => "CalendarScheduling",
            ObjectType::Certificate => "Certificate",
            ObjectType::ClusterNode => "ClusterNode",
            ObjectType::ClusterRole => "ClusterRole",
            ObjectType::Coordinator => "Coordinator",
            ObjectType::DataRetention => "DataRetention",
            ObjectType::DataStore => "DataStore",
            ObjectType::Directory => "Directory",
            ObjectType::DkimReportSettings => "DkimReportSettings",
            ObjectType::DkimSignature => "DkimSignature",
            ObjectType::DmarcExternalReport => "DmarcExternalReport",
            ObjectType::DmarcInternalReport => "DmarcInternalReport",
            ObjectType::DmarcReportSettings => "DmarcReportSettings",
            ObjectType::DnsResolver => "DnsResolver",
            ObjectType::DnsServer => "DnsServer",
            ObjectType::Domain => "Domain",
            ObjectType::DsnReportSettings => "DsnReportSettings",
            ObjectType::Email => "Email",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => "Enterprise",
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => "EventTracingLevel",
            ObjectType::FileStorage => "FileStorage",
            ObjectType::Http => "Http",
            ObjectType::HttpForm => "HttpForm",
            ObjectType::HttpLookup => "HttpLookup",
            ObjectType::Imap => "Imap",
            ObjectType::InMemoryStore => "InMemoryStore",
            ObjectType::IndexQueueStatus => "IndexQueueStatus",
            ObjectType::Jmap => "Jmap",
            ObjectType::Log => "Log",
            ObjectType::MailingList => "MailingList",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => "MaskedEmail",
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => "MemoryLookupKey",
            ObjectType::MemoryLookupKeyValue => "MemoryLookupKeyValue",
            ObjectType::Metadata => "Metadata",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => "Metric",
            // SPDX-SnippetEnd
            ObjectType::Metrics => "Metrics",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => "MetricsStore",
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => "MtaConnectionStrategy",
            ObjectType::MtaDeliverySchedule => "MtaDeliverySchedule",
            ObjectType::MtaExtensions => "MtaExtensions",
            ObjectType::MtaHook => "MtaHook",
            ObjectType::MtaInboundSession => "MtaInboundSession",
            ObjectType::MtaInboundThrottle => "MtaInboundThrottle",
            ObjectType::MtaMilter => "MtaMilter",
            ObjectType::MtaOutboundStrategy => "MtaOutboundStrategy",
            ObjectType::MtaOutboundThrottle => "MtaOutboundThrottle",
            ObjectType::MtaQueueQuota => "MtaQueueQuota",
            ObjectType::MtaRoute => "MtaRoute",
            ObjectType::MtaStageAuth => "MtaStageAuth",
            ObjectType::MtaStageConnect => "MtaStageConnect",
            ObjectType::MtaStageData => "MtaStageData",
            ObjectType::MtaStageEhlo => "MtaStageEhlo",
            ObjectType::MtaStageMail => "MtaStageMail",
            ObjectType::MtaStageRcpt => "MtaStageRcpt",
            ObjectType::MtaSts => "MtaSts",
            ObjectType::MtaTlsStrategy => "MtaTlsStrategy",
            ObjectType::MtaVirtualQueue => "MtaVirtualQueue",
            ObjectType::NetworkListener => "NetworkListener",
            ObjectType::OAuthClient => "OAuthClient",
            ObjectType::OAuthGrant => "OAuthGrant",
            ObjectType::OidcProvider => "OidcProvider",
            ObjectType::PublicKey => "PublicKey",
            ObjectType::QueuedMessage => "QueuedMessage",
            ObjectType::ReportSettings => "ReportSettings",
            ObjectType::Role => "Role",
            ObjectType::Search => "Search",
            ObjectType::SearchStore => "SearchStore",
            ObjectType::Security => "Security",
            ObjectType::SenderAuth => "SenderAuth",
            ObjectType::Sharing => "Sharing",
            ObjectType::SieveSystemInterpreter => "SieveSystemInterpreter",
            ObjectType::SieveSystemScript => "SieveSystemScript",
            ObjectType::SieveUserInterpreter => "SieveUserInterpreter",
            ObjectType::SieveUserScript => "SieveUserScript",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => "SpamAi",
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => "SpamClassifier",
            ObjectType::SpamDnsblServer => "SpamDnsblServer",
            ObjectType::SpamDnsblSettings => "SpamDnsblSettings",
            ObjectType::SpamFileExtension => "SpamFileExtension",
            ObjectType::SpamPyzor => "SpamPyzor",
            ObjectType::SpamRule => "SpamRule",
            ObjectType::SpamSettings => "SpamSettings",
            ObjectType::SpamTag => "SpamTag",
            ObjectType::SpamTrainingSample => "SpamTrainingSample",
            ObjectType::SpfReportSettings => "SpfReportSettings",
            ObjectType::StoreLookup => "StoreLookup",
            ObjectType::SystemSettings => "SystemSettings",
            ObjectType::Task => "Task",
            ObjectType::TaskManager => "TaskManager",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => "Tenant",
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => "TlsExternalReport",
            ObjectType::TlsInternalReport => "TlsInternalReport",
            ObjectType::TlsReportSettings => "TlsReportSettings",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => "Trace",
            // SPDX-SnippetEnd
            ObjectType::Tracer => "Tracer",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => "TracingStore",
            // SPDX-SnippetEnd
            ObjectType::WebDav => "WebDav",
            ObjectType::WebHook => "WebHook",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(ObjectType::Account),
            1 => Some(ObjectType::AccountPassword),
            2 => Some(ObjectType::AccountSettings),
            3 => Some(ObjectType::AcmeProvider),
            4 => Some(ObjectType::Action),
            5 => Some(ObjectType::AddressBook),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            6 => Some(ObjectType::AiModel),
            #[cfg(feature = "enterprise")]
            7 => Some(ObjectType::Alert),
            // SPDX-SnippetEnd
            8 => Some(ObjectType::AllowedIp),
            9 => Some(ObjectType::ApiKey),
            10 => Some(ObjectType::AppPassword),
            11 => Some(ObjectType::Application),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            12 => Some(ObjectType::ArchivedItem),
            // SPDX-SnippetEnd
            13 => Some(ObjectType::ArfExternalReport),
            14 => Some(ObjectType::Asn),
            15 => Some(ObjectType::Authentication),
            16 => Some(ObjectType::BlobStore),
            17 => Some(ObjectType::BlockedIp),
            18 => Some(ObjectType::Bootstrap),
            19 => Some(ObjectType::Cache),
            20 => Some(ObjectType::Calendar),
            21 => Some(ObjectType::CalendarAlarm),
            22 => Some(ObjectType::CalendarScheduling),
            23 => Some(ObjectType::Certificate),
            24 => Some(ObjectType::ClusterNode),
            25 => Some(ObjectType::ClusterRole),
            26 => Some(ObjectType::Coordinator),
            27 => Some(ObjectType::DataRetention),
            28 => Some(ObjectType::DataStore),
            29 => Some(ObjectType::Directory),
            30 => Some(ObjectType::DkimReportSettings),
            31 => Some(ObjectType::DkimSignature),
            32 => Some(ObjectType::DmarcExternalReport),
            33 => Some(ObjectType::DmarcInternalReport),
            34 => Some(ObjectType::DmarcReportSettings),
            35 => Some(ObjectType::DnsResolver),
            36 => Some(ObjectType::DnsServer),
            37 => Some(ObjectType::Domain),
            38 => Some(ObjectType::DsnReportSettings),
            39 => Some(ObjectType::Email),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            40 => Some(ObjectType::Enterprise),
            // SPDX-SnippetEnd
            41 => Some(ObjectType::EventTracingLevel),
            42 => Some(ObjectType::FileStorage),
            43 => Some(ObjectType::Http),
            44 => Some(ObjectType::HttpForm),
            45 => Some(ObjectType::HttpLookup),
            46 => Some(ObjectType::Imap),
            47 => Some(ObjectType::InMemoryStore),
            48 => Some(ObjectType::IndexQueueStatus),
            49 => Some(ObjectType::Jmap),
            50 => Some(ObjectType::Log),
            51 => Some(ObjectType::MailingList),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            52 => Some(ObjectType::MaskedEmail),
            // SPDX-SnippetEnd
            53 => Some(ObjectType::MemoryLookupKey),
            54 => Some(ObjectType::MemoryLookupKeyValue),
            55 => Some(ObjectType::Metadata),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            56 => Some(ObjectType::Metric),
            // SPDX-SnippetEnd
            57 => Some(ObjectType::Metrics),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            58 => Some(ObjectType::MetricsStore),
            // SPDX-SnippetEnd
            59 => Some(ObjectType::MtaConnectionStrategy),
            60 => Some(ObjectType::MtaDeliverySchedule),
            61 => Some(ObjectType::MtaExtensions),
            62 => Some(ObjectType::MtaHook),
            63 => Some(ObjectType::MtaInboundSession),
            64 => Some(ObjectType::MtaInboundThrottle),
            65 => Some(ObjectType::MtaMilter),
            66 => Some(ObjectType::MtaOutboundStrategy),
            67 => Some(ObjectType::MtaOutboundThrottle),
            68 => Some(ObjectType::MtaQueueQuota),
            69 => Some(ObjectType::MtaRoute),
            70 => Some(ObjectType::MtaStageAuth),
            71 => Some(ObjectType::MtaStageConnect),
            72 => Some(ObjectType::MtaStageData),
            73 => Some(ObjectType::MtaStageEhlo),
            74 => Some(ObjectType::MtaStageMail),
            75 => Some(ObjectType::MtaStageRcpt),
            76 => Some(ObjectType::MtaSts),
            77 => Some(ObjectType::MtaTlsStrategy),
            78 => Some(ObjectType::MtaVirtualQueue),
            79 => Some(ObjectType::NetworkListener),
            80 => Some(ObjectType::OAuthClient),
            81 => Some(ObjectType::OAuthGrant),
            82 => Some(ObjectType::OidcProvider),
            83 => Some(ObjectType::PublicKey),
            84 => Some(ObjectType::QueuedMessage),
            85 => Some(ObjectType::ReportSettings),
            86 => Some(ObjectType::Role),
            87 => Some(ObjectType::Search),
            88 => Some(ObjectType::SearchStore),
            89 => Some(ObjectType::Security),
            90 => Some(ObjectType::SenderAuth),
            91 => Some(ObjectType::Sharing),
            92 => Some(ObjectType::SieveSystemInterpreter),
            93 => Some(ObjectType::SieveSystemScript),
            94 => Some(ObjectType::SieveUserInterpreter),
            95 => Some(ObjectType::SieveUserScript),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            96 => Some(ObjectType::SpamAi),
            // SPDX-SnippetEnd
            97 => Some(ObjectType::SpamClassifier),
            98 => Some(ObjectType::SpamDnsblServer),
            99 => Some(ObjectType::SpamDnsblSettings),
            100 => Some(ObjectType::SpamFileExtension),
            101 => Some(ObjectType::SpamPyzor),
            102 => Some(ObjectType::SpamRule),
            103 => Some(ObjectType::SpamSettings),
            104 => Some(ObjectType::SpamTag),
            105 => Some(ObjectType::SpamTrainingSample),
            106 => Some(ObjectType::SpfReportSettings),
            107 => Some(ObjectType::StoreLookup),
            108 => Some(ObjectType::SystemSettings),
            109 => Some(ObjectType::Task),
            110 => Some(ObjectType::TaskManager),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            111 => Some(ObjectType::Tenant),
            // SPDX-SnippetEnd
            112 => Some(ObjectType::TlsExternalReport),
            113 => Some(ObjectType::TlsInternalReport),
            114 => Some(ObjectType::TlsReportSettings),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            115 => Some(ObjectType::Trace),
            // SPDX-SnippetEnd
            116 => Some(ObjectType::Tracer),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            117 => Some(ObjectType::TracingStore),
            // SPDX-SnippetEnd
            118 => Some(ObjectType::WebDav),
            119 => Some(ObjectType::WebHook),
            _ => None,
        }
    }

    const COUNT: usize = 120;
}

impl serde::Serialize for ObjectType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ObjectType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl EnumImpl for Property {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            Property,
            b"@type" => Property::Type,
            b"abuseBanPeriod" => Property::AbuseBanPeriod,
            b"abuseBanRate" => Property::AbuseBanRate,
            b"acceptedAudiences" => Property::AcceptedAudiences,
            b"accessKeyId" => Property::AccessKeyId,
            b"accessToken" => Property::AccessToken,
            b"accessTokenExpiry" => Property::AccessTokenExpiry,
            b"accessTokens" => Property::AccessTokens,
            b"accountDomainId" => Property::AccountDomainId,
            b"accountHashPrefix" => Property::AccountHashPrefix,
            b"accountId" => Property::AccountId,
            b"accountIdentifier" => Property::AccountIdentifier,
            b"accountKey" => Property::AccountKey,
            b"accountName" => Property::AccountName,
            b"accountSwitchKey" => Property::AccountSwitchKey,
            b"accountType" => Property::AccountType,
            b"accountUri" => Property::AccountUri,
            b"accounts" => Property::Accounts,
            b"acmeProviderId" => Property::AcmeProviderId,
            b"addAuthResultsHeader" => Property::AddAuthResultsHeader,
            b"addDateHeader" => Property::AddDateHeader,
            b"addDeliveredToHeader" => Property::AddDeliveredToHeader,
            b"addHeader" => Property::AddHeader,
            b"addMessageIdHeader" => Property::AddMessageIdHeader,
            b"addReceivedHeader" => Property::AddReceivedHeader,
            b"addReceivedSpfHeader" => Property::AddReceivedSpfHeader,
            b"addReturnPathHeader" => Property::AddReturnPathHeader,
            b"additionalInformation" => Property::AdditionalInformation,
            b"address" => Property::Address,
            b"aggregateContactInfo" => Property::AggregateContactInfo,
            b"aggregateDkimSignDomain" => Property::AggregateDkimSignDomain,
            b"aggregateFromAddress" => Property::AggregateFromAddress,
            b"aggregateFromName" => Property::AggregateFromName,
            b"aggregateOrgName" => Property::AggregateOrgName,
            b"aggregateSendFrequency" => Property::AggregateSendFrequency,
            b"aiFacts" => Property::AiFacts,
            b"aiGate" => Property::AiGate,
            b"aiVerdict" => Property::AiVerdict,
            b"alarmId" => Property::AlarmId,
            b"alertAfter" => Property::AlertAfter,
            b"algorithms" => Property::Algorithms,
            b"aliases" => Property::Aliases,
            b"allowCount" => Property::AllowCount,
            b"allowDirectoryQueries" => Property::AllowDirectoryQueries,
            b"allowExternalRcpts" => Property::AllowExternalRcpts,
            b"allowIdTokenClaims" => Property::AllowIdTokenClaims,
            b"allowInvalidCerts" => Property::AllowInvalidCerts,
            b"allowPlainTextAuth" => Property::AllowPlainTextAuth,
            b"allowRelaying" => Property::AllowRelaying,
            b"allowScimProvisioning" => Property::AllowScimProvisioning,
            b"allowSpamTraining" => Property::AllowSpamTraining,
            b"allowedEndpoints" => Property::AllowedEndpoints,
            b"allowedIps" => Property::AllowedIps,
            b"allowedNotifyUris" => Property::AllowedNotifyUris,
            b"alpha" => Property::Alpha,
            b"anonymousTimeout" => Property::AnonymousTimeout,
            b"ansi" => Property::Ansi,
            b"apiKey" => Property::ApiKey,
            b"apiKeyId" => Property::ApiKeyId,
            b"apiUser" => Property::ApiUser,
            b"applicationKey" => Property::ApplicationKey,
            b"applicationSecret" => Property::ApplicationSecret,
            b"arcResult" => Property::ArcResult,
            b"arcVerify" => Property::ArcVerify,
            b"archiveDeletedAccountsFor" => Property::ArchiveDeletedAccountsFor,
            b"archiveDeletedItemsFor" => Property::ArchiveDeletedItemsFor,
            b"archivedAt" => Property::ArchivedAt,
            b"archivedItemType" => Property::ArchivedItemType,
            b"archivedUntil" => Property::ArchivedUntil,
            b"arrivalDate" => Property::ArrivalDate,
            b"asnUrls" => Property::AsnUrls,
            b"attemptNumber" => Property::AttemptNumber,
            b"attempts" => Property::Attempts,
            b"attrClass" => Property::AttrClass,
            b"attrDescription" => Property::AttrDescription,
            b"attrEmail" => Property::AttrEmail,
            b"attrEmailAlias" => Property::AttrEmailAlias,
            b"attrMemberOf" => Property::AttrMemberOf,
            b"attrSecret" => Property::AttrSecret,
            b"attrSecretChanged" => Property::AttrSecretChanged,
            b"auid" => Property::Auid,
            b"auth" => Property::Auth,
            b"authBanPeriod" => Property::AuthBanPeriod,
            b"authBanRate" => Property::AuthBanRate,
            b"authCodeExpiry" => Property::AuthCodeExpiry,
            b"authFailure" => Property::AuthFailure,
            b"authId" => Property::AuthId,
            b"authSecret" => Property::AuthSecret,
            b"authUsername" => Property::AuthUsername,
            b"authenticatedAs" => Property::AuthenticatedAs,
            b"authenticatedTimeout" => Property::AuthenticatedTimeout,
            b"authenticationResults" => Property::AuthenticationResults,
            b"autoAddInvitations" => Property::AutoAddInvitations,
            b"autoUpdateInterval" => Property::AutoUpdateInterval,
            b"availabilityRateLimit" => Property::AvailabilityRateLimit,
            b"baseDn" => Property::BaseDn,
            b"bearerToken" => Property::BearerToken,
            b"beta" => Property::Beta,
            b"bind" => Property::Bind,
            b"bindAuthentication" => Property::BindAuthentication,
            b"bindDn" => Property::BindDn,
            b"bindSecret" => Property::BindSecret,
            b"blobCleanupSchedule" => Property::BlobCleanupSchedule,
            b"blobId" => Property::BlobId,
            b"blobSize" => Property::BlobSize,
            b"blobStore" => Property::BlobStore,
            b"blockCount" => Property::BlockCount,
            b"body" => Property::Body,
            b"breakerCooldown" => Property::BreakerCooldown,
            b"breakerThreshold" => Property::BreakerThreshold,
            b"bucket" => Property::Bucket,
            b"bucketHigh" => Property::BucketHigh,
            b"bucketMedium" => Property::BucketMedium,
            b"bufferSize" => Property::BufferSize,
            b"buffered" => Property::Buffered,
            b"caaIdentities" => Property::CaaIdentities,
            b"cacheSize" => Property::CacheSize,
            b"canonicalization" => Property::Canonicalization,
            b"catchAllAddress" => Property::CatchAllAddress,
            b"categories" => Property::Categories,
            b"certificate" => Property::Certificate,
            b"certificateManagement" => Property::CertificateManagement,
            b"challengeType" => Property::ChallengeType,
            b"chunkSize" => Property::ChunkSize,
            b"chunking" => Property::Chunking,
            b"claimGroups" => Property::ClaimGroups,
            b"claimName" => Property::ClaimName,
            b"claimUsername" => Property::ClaimUsername,
            b"cleartext" => Property::Cleartext,
            b"clientCapacity" => Property::ClientCapacity,
            b"clientHash" => Property::ClientHash,
            b"clientId" => Property::ClientId,
            b"clientIp" => Property::ClientIp,
            b"clientIpSource" => Property::ClientIpSource,
            b"clientKind" => Property::ClientKind,
            b"clientMetadataDocuments" => Property::ClientMetadataDocuments,
            b"clientName" => Property::ClientName,
            b"clientSecret" => Property::ClientSecret,
            b"clientToken" => Property::ClientToken,
            b"clusterFile" => Property::ClusterFile,
            b"columnClass" => Property::ColumnClass,
            b"columnDescription" => Property::ColumnDescription,
            b"columnEmail" => Property::ColumnEmail,
            b"columnSecret" => Property::ColumnSecret,
            b"commandTimeout" => Property::CommandTimeout,
            b"comment" => Property::Comment,
            b"compartmentOcid" => Property::CompartmentOcid,
            b"compressionAlgorithm" => Property::CompressionAlgorithm,
            b"condition" => Property::Condition,
            b"config" => Property::Config,
            b"configName" => Property::ConfigName,
            b"connectTimeout" => Property::ConnectTimeout,
            b"connection" => Property::Connection,
            b"consumerKey" => Property::ConsumerKey,
            b"contact" => Property::Contact,
            b"contactInfo" => Property::ContactInfo,
            b"contacts" => Property::Contacts,
            b"container" => Property::Container,
            b"contentTypes" => Property::ContentTypes,
            b"contents" => Property::Contents,
            b"context" => Property::Context,
            b"count" => Property::Count,
            b"create" => Property::Create,
            b"createdAt" => Property::CreatedAt,
            b"createdBy" => Property::CreatedBy,
            b"credentialId" => Property::CredentialId,
            b"credentials" => Property::Credentials,
            b"currentSecret" => Property::CurrentSecret,
            b"customRule" => Property::CustomRule,
            b"customerNumber" => Property::CustomerNumber,
            b"dane" => Property::Dane,
            b"dataCleanupSchedule" => Property::DataCleanupSchedule,
            b"dataStore" => Property::DataStore,
            b"dataTimeout" => Property::DataTimeout,
            b"dataTypes" => Property::DataTypes,
            b"database" => Property::Database,
            b"datacenterId" => Property::DatacenterId,
            b"dateRangeEnd" => Property::DateRangeEnd,
            b"dateRangeStart" => Property::DateRangeStart,
            b"day" => Property::Day,
            b"deadline" => Property::Deadline,
            b"defaultAdminRoleIds" => Property::DefaultAdminRoleIds,
            b"defaultCertificateId" => Property::DefaultCertificateId,
            b"defaultDisplayName" => Property::DefaultDisplayName,
            b"defaultDomain" => Property::DefaultDomain,
            b"defaultDomainId" => Property::DefaultDomainId,
            b"defaultExpiryDuplicate" => Property::DefaultExpiryDuplicate,
            b"defaultExpiryVacation" => Property::DefaultExpiryVacation,
            b"defaultFolders" => Property::DefaultFolders,
            b"defaultFromAddress" => Property::DefaultFromAddress,
            b"defaultFromName" => Property::DefaultFromName,
            b"defaultGroupRoleIds" => Property::DefaultGroupRoleIds,
            b"defaultHostname" => Property::DefaultHostname,
            b"defaultHrefName" => Property::DefaultHrefName,
            b"defaultLanguage" => Property::DefaultLanguage,
            b"defaultName" => Property::DefaultName,
            b"defaultReturnPath" => Property::DefaultReturnPath,
            b"defaultSubject" => Property::DefaultSubject,
            b"defaultSubjectPrefix" => Property::DefaultSubjectPrefix,
            b"defaultTenantRoleIds" => Property::DefaultTenantRoleIds,
            b"defaultUserRoleIds" => Property::DefaultUserRoleIds,
            b"definition" => Property::Definition,
            b"delay" => Property::Delay,
            b"deleteAfter" => Property::DeleteAfter,
            b"deleteAfterUse" => Property::DeleteAfterUse,
            b"deliverAt" => Property::DeliverAt,
            b"deliverBy" => Property::DeliverBy,
            b"deliverTo" => Property::DeliverTo,
            b"deliveryResult" => Property::DeliveryResult,
            b"depth" => Property::Depth,
            b"description" => Property::Description,
            b"details" => Property::Details,
            b"directory" => Property::Directory,
            b"directoryId" => Property::DirectoryId,
            b"directoryRecipients" => Property::DirectoryRecipients,
            b"directoryRecipientsTtl" => Property::DirectoryRecipientsTtl,
            b"disableCapabilities" => Property::DisableCapabilities,
            b"disabledPermissions" => Property::DisabledPermissions,
            b"discardAfter" => Property::DiscardAfter,
            b"disposition" => Property::Disposition,
            b"dkim2Pass" => Property::Dkim2Pass,
            b"dkim2Result" => Property::Dkim2Result,
            b"dkimAdspDns" => Property::DkimAdspDns,
            b"dkimCanonicalizedBody" => Property::DkimCanonicalizedBody,
            b"dkimCanonicalizedHeader" => Property::DkimCanonicalizedHeader,
            b"dkimDomain" => Property::DkimDomain,
            b"dkimIdentity" => Property::DkimIdentity,
            b"dkimManagement" => Property::DkimManagement,
            b"dkimPass" => Property::DkimPass,
            b"dkimResults" => Property::DkimResults,
            b"dkimSelector" => Property::DkimSelector,
            b"dkimSelectorDns" => Property::DkimSelectorDns,
            b"dkimSignDomain" => Property::DkimSignDomain,
            b"dkimSignatures" => Property::DkimSignatures,
            b"dkimStrict" => Property::DkimStrict,
            b"dkimVerify" => Property::DkimVerify,
            b"dmarcPass" => Property::DmarcPass,
            b"dmarcPolicy" => Property::DmarcPolicy,
            b"dmarcResult" => Property::DmarcResult,
            b"dmarcVerify" => Property::DmarcVerify,
            b"dnsIpv4" => Property::DnsIpv4,
            b"dnsIpv6" => Property::DnsIpv6,
            b"dnsManagement" => Property::DnsManagement,
            b"dnsMtaSts" => Property::DnsMtaSts,
            b"dnsMx" => Property::DnsMx,
            b"dnsPtr" => Property::DnsPtr,
            b"dnsServer" => Property::DnsServer,
            b"dnsServerId" => Property::DnsServerId,
            b"dnsTlsa" => Property::DnsTlsa,
            b"dnsTxt" => Property::DnsTxt,
            b"dnsView" => Property::DnsView,
            b"dnsZoneFile" => Property::DnsZoneFile,
            b"documentId" => Property::DocumentId,
            b"domain" => Property::Domain,
            b"domainId" => Property::DomainId,
            b"domainLimit" => Property::DomainLimit,
            b"domainNames" => Property::DomainNames,
            b"domainNamesNegative" => Property::DomainNamesNegative,
            b"domains" => Property::Domains,
            b"dsn" => Property::Dsn,
            b"due" => Property::Due,
            b"duration" => Property::Duration,
            b"eabHmacKey" => Property::EabHmacKey,
            b"eabKeyId" => Property::EabKeyId,
            b"ehloDomain" => Property::EhloDomain,
            b"ehloHostname" => Property::EhloHostname,
            b"ehloTimeout" => Property::EhloTimeout,
            b"elapsed" => Property::Elapsed,
            b"else" => Property::Else,
            b"email" => Property::Email,
            b"emailAddress" => Property::EmailAddress,
            b"emailAddresses" => Property::EmailAddresses,
            b"emailAddressesNegative" => Property::EmailAddressesNegative,
            b"emailAlert" => Property::EmailAlert,
            b"emailDomain" => Property::EmailDomain,
            b"emailLimit" => Property::EmailLimit,
            b"emailPrefix" => Property::EmailPrefix,
            b"emailTemplate" => Property::EmailTemplate,
            b"enable" => Property::Enable,
            b"enableAssistedDiscovery" => Property::EnableAssistedDiscovery,
            b"enableEdns" => Property::EnableEdns,
            b"enableHsts" => Property::EnableHsts,
            b"enableLogExporter" => Property::EnableLogExporter,
            b"enableSpamFilter" => Property::EnableSpamFilter,
            b"enableSpanExporter" => Property::EnableSpanExporter,
            b"enabledPermissions" => Property::EnabledPermissions,
            b"encryptAtRest" => Property::EncryptAtRest,
            b"encryptOnAppend" => Property::EncryptOnAppend,
            b"encryptionAtRest" => Property::EncryptionAtRest,
            b"encryptionKey" => Property::EncryptionKey,
            b"envId" => Property::EnvId,
            b"envelopeFrom" => Property::EnvelopeFrom,
            b"envelopeTo" => Property::EnvelopeTo,
            b"environment" => Property::Environment,
            b"errorCommand" => Property::ErrorCommand,
            b"errorMessage" => Property::ErrorMessage,
            b"errorType" => Property::ErrorType,
            b"errors" => Property::Errors,
            b"escalateBelow" => Property::EscalateBelow,
            b"escalateOn" => Property::EscalateOn,
            b"evaluatedDisposition" => Property::EvaluatedDisposition,
            b"evaluatedDkim" => Property::EvaluatedDkim,
            b"evaluatedSpf" => Property::EvaluatedSpf,
            b"event" => Property::Event,
            b"eventAlert" => Property::EventAlert,
            b"eventEnd" => Property::EventEnd,
            b"eventEndTz" => Property::EventEndTz,
            b"eventId" => Property::EventId,
            b"eventMessage" => Property::EventMessage,
            b"eventSourceThrottle" => Property::EventSourceThrottle,
            b"eventStart" => Property::EventStart,
            b"eventStartTz" => Property::EventStartTz,
            b"events" => Property::Events,
            b"eventsPolicy" => Property::EventsPolicy,
            b"expire" => Property::Expire,
            b"expires" => Property::Expires,
            b"expiresAt" => Property::ExpiresAt,
            b"expiresAttempts" => Property::ExpiresAttempts,
            b"expiry" => Property::Expiry,
            b"explanation" => Property::Explanation,
            b"expn" => Property::Expn,
            b"expungeSchedule" => Property::ExpungeSchedule,
            b"expungeSchedulingInboxAfter" => Property::ExpungeSchedulingInboxAfter,
            b"expungeShareNotifyAfter" => Property::ExpungeShareNotifyAfter,
            b"expungeSubmissionsAfter" => Property::ExpungeSubmissionsAfter,
            b"expungeTrashAfter" => Property::ExpungeTrashAfter,
            b"extension" => Property::Extension,
            b"extensions" => Property::Extensions,
            b"externalId" => Property::ExternalId,
            b"extraContactInfo" => Property::ExtraContactInfo,
            b"extraParameters" => Property::ExtraParameters,
            b"factor" => Property::Factor,
            b"failOnTimeout" => Property::FailOnTimeout,
            b"failedAt" => Property::FailedAt,
            b"failedAttemptNumber" => Property::FailedAttemptNumber,
            b"failedSessionCount" => Property::FailedSessionCount,
            b"failureDetails" => Property::FailureDetails,
            b"failureDkimSignDomain" => Property::FailureDkimSignDomain,
            b"failureFromAddress" => Property::FailureFromAddress,
            b"failureFromName" => Property::FailureFromName,
            b"failureReason" => Property::FailureReason,
            b"failureReasonCode" => Property::FailureReasonCode,
            b"failureSendFrequency" => Property::FailureSendFrequency,
            b"failureSubject" => Property::FailureSubject,
            b"featureL2Normalize" => Property::FeatureL2Normalize,
            b"featureLogScale" => Property::FeatureLogScale,
            b"feedbackType" => Property::FeedbackType,
            b"fieldEmail" => Property::FieldEmail,
            b"fieldHoneyPot" => Property::FieldHoneyPot,
            b"fieldName" => Property::FieldName,
            b"fieldSubject" => Property::FieldSubject,
            b"filePath" => Property::FilePath,
            b"files" => Property::Files,
            b"filterLogin" => Property::FilterLogin,
            b"filterMemberOf" => Property::FilterMemberOf,
            b"filterRecipient" => Property::FilterRecipient,
            b"fingerprint" => Property::Fingerprint,
            b"firstFailedAt" => Property::FirstFailedAt,
            b"firstParty" => Property::FirstParty,
            b"flags" => Property::Flags,
            b"flagsAction" => Property::FlagsAction,
            b"flagsProtocol" => Property::FlagsProtocol,
            b"flushChanges" => Property::FlushChanges,
            b"flushInterval" => Property::FlushInterval,
            b"folderId" => Property::FolderId,
            b"forDomain" => Property::ForDomain,
            b"format" => Property::Format,
            b"forwardedHops" => Property::ForwardedHops,
            b"from" => Property::From,
            b"fromAddress" => Property::FromAddress,
            b"fromName" => Property::FromName,
            b"futureRelease" => Property::FutureRelease,
            b"generateDkimKeys" => Property::GenerateDkimKeys,
            b"generation" => Property::Generation,
            b"generator" => Property::Generator,
            b"geoUrls" => Property::GeoUrls,
            b"grantTypes" => Property::GrantTypes,
            b"greetingTimeout" => Property::GreetingTimeout,
            b"greylistFor" => Property::GreylistFor,
            b"groupClass" => Property::GroupClass,
            b"groupId" => Property::GroupId,
            b"groupwareLarge" => Property::GroupwareLarge,
            b"groupwareLargeTtl" => Property::GroupwareLargeTtl,
            b"headerFrom" => Property::HeaderFrom,
            b"headers" => Property::Headers,
            b"holdMetricsFor" => Property::HoldMetricsFor,
            b"holdMtaReportsFor" => Property::HoldMtaReportsFor,
            b"holdSamplesFor" => Property::HoldSamplesFor,
            b"holdTracesFor" => Property::HoldTracesFor,
            b"host" => Property::Host,
            b"hostedZoneId" => Property::HostedZoneId,
            b"hostname" => Property::Hostname,
            b"hosts" => Property::Hosts,
            b"hour" => Property::Hour,
            b"httpAuth" => Property::HttpAuth,
            b"httpHeaders" => Property::HttpHeaders,
            b"httpRsvpEnable" => Property::HttpRsvpEnable,
            b"httpRsvpLinkExpiry" => Property::HttpRsvpLinkExpiry,
            b"httpRsvpTemplate" => Property::HttpRsvpTemplate,
            b"httpRsvpUrl" => Property::HttpRsvpUrl,
            b"httpRua" => Property::HttpRua,
            b"humanResult" => Property::HumanResult,
            b"iCalendarData" => Property::ICalendarData,
            b"id" => Property::Id,
            b"idTokenExpiry" => Property::IdTokenExpiry,
            b"identityAlignment" => Property::IdentityAlignment,
            b"idleTimeout" => Property::IdleTimeout,
            b"if" => Property::If,
            b"imapServerAdmin" => Property::ImapServerAdmin,
            b"imapServerComment" => Property::ImapServerComment,
            b"impersonateServiceAccount" => Property::ImpersonateServiceAccount,
            b"implicitTls" => Property::ImplicitTls,
            b"inMemoryStore" => Property::InMemoryStore,
            b"inboundReportAddresses" => Property::InboundReportAddresses,
            b"inboundReportForwarding" => Property::InboundReportForwarding,
            b"incidents" => Property::Incidents,
            b"includeAttachments" => Property::IncludeAttachments,
            b"includeAuth" => Property::IncludeAuth,
            b"includeLinks" => Property::IncludeLinks,
            b"includeSecrets" => Property::IncludeSecrets,
            b"includeSource" => Property::IncludeSource,
            b"includes" => Property::Includes,
            b"index" => Property::Index,
            b"indexAsn" => Property::IndexAsn,
            b"indexAsnName" => Property::IndexAsnName,
            b"indexBatchSize" => Property::IndexBatchSize,
            b"indexCalendar" => Property::IndexCalendar,
            b"indexCalendarFields" => Property::IndexCalendarFields,
            b"indexContactFields" => Property::IndexContactFields,
            b"indexContacts" => Property::IndexContacts,
            b"indexCountry" => Property::IndexCountry,
            b"indexEmail" => Property::IndexEmail,
            b"indexEmailFields" => Property::IndexEmailFields,
            b"indexFiles" => Property::IndexFiles,
            b"indexKey" => Property::IndexKey,
            b"indexTelemetry" => Property::IndexTelemetry,
            b"indexValue" => Property::IndexValue,
            b"indicatorParameters" => Property::IndicatorParameters,
            b"initialDelay" => Property::InitialDelay,
            b"instanceHashes" => Property::InstanceHashes,
            b"instructions" => Property::Instructions,
            b"interval" => Property::Interval,
            b"intervals" => Property::Intervals,
            b"introspectionAuthMethod" => Property::IntrospectionAuthMethod,
            b"introspectionClientId" => Property::IntrospectionClientId,
            b"introspectionClientSecret" => Property::IntrospectionClientSecret,
            b"ipLimit" => Property::IpLimit,
            b"ipLookupStrategy" => Property::IpLookupStrategy,
            b"ipRevPtr" => Property::IpRevPtr,
            b"ipRevResult" => Property::IpRevResult,
            b"isActive" => Property::IsActive,
            b"isArchive" => Property::IsArchive,
            b"isBad" => Property::IsBad,
            b"isFromOrganizer" => Property::IsFromOrganizer,
            b"isGlobPattern" => Property::IsGlobPattern,
            b"isGzipped" => Property::IsGzipped,
            b"isNz" => Property::IsNz,
            b"isSenderAllowed" => Property::IsSenderAllowed,
            b"isSpam" => Property::IsSpam,
            b"isTls" => Property::IsTls,
            b"issuer" => Property::Issuer,
            b"issuerDomainNames" => Property::IssuerDomainNames,
            b"issuerUrl" => Property::IssuerUrl,
            b"jitter" => Property::Jitter,
            b"keepAlive" => Property::KeepAlive,
            b"key" => Property::Key,
            b"keyName" => Property::KeyName,
            b"keyPrefix" => Property::KeyPrefix,
            b"keyValues" => Property::KeyValues,
            b"l1Ratio" => Property::L1Ratio,
            b"l2Ratio" => Property::L2Ratio,
            b"lastRenewal" => Property::LastRenewal,
            b"lastUsedAt" => Property::LastUsedAt,
            b"learn" => Property::Learn,
            b"learnHamFromCard" => Property::LearnHamFromCard,
            b"learnHamFromReply" => Property::LearnHamFromReply,
            b"learnSpamFromRblHits" => Property::LearnSpamFromRblHits,
            b"learnSpamFromTraps" => Property::LearnSpamFromTraps,
            b"lenientIssuerMatch" => Property::LenientIssuerMatch,
            b"level" => Property::Level,
            b"licenseKey" => Property::LicenseKey,
            b"line" => Property::Line,
            b"listenerIds" => Property::ListenerIds,
            b"listeners" => Property::Listeners,
            b"localIp" => Property::LocalIp,
            b"localIps" => Property::LocalIps,
            b"locale" => Property::Locale,
            b"logo" => Property::Logo,
            b"logprobs" => Property::Logprobs,
            b"loiterBanPeriod" => Property::LoiterBanPeriod,
            b"loiterBanRate" => Property::LoiterBanRate,
            b"lossy" => Property::Lossy,
            b"machineId" => Property::MachineId,
            b"mailExchangers" => Property::MailExchangers,
            b"mailFrom" => Property::MailFrom,
            b"mailFromParameters" => Property::MailFromParameters,
            b"mailFromTimeout" => Property::MailFromTimeout,
            b"mailRua" => Property::MailRua,
            b"mailingLists" => Property::MailingLists,
            b"maintenanceType" => Property::MaintenanceType,
            b"managedZone" => Property::ManagedZone,
            b"match" => Property::Match,
            b"maxAccountSize" => Property::MaxAccountSize,
            b"maxAddressBooks" => Property::MaxAddressBooks,
            b"maxAddressBooksPerCard" => Property::MaxAddressBooksPerCard,
            b"maxAge" => Property::MaxAge,
            b"maxAggregateReportSize" => Property::MaxAggregateReportSize,
            b"maxAllowedPacket" => Property::MaxAllowedPacket,
            b"maxApiKeys" => Property::MaxApiKeys,
            b"maxAppPasswords" => Property::MaxAppPasswords,
            b"maxAttachmentSize" => Property::MaxAttachmentSize,
            b"maxAttachmentText" => Property::MaxAttachmentText,
            b"maxAttachments" => Property::MaxAttachments,
            b"maxAttachmentsSize" => Property::MaxAttachmentsSize,
            b"maxAttempts" => Property::MaxAttempts,
            b"maxAttendees" => Property::MaxAttendees,
            b"maxAuthFailures" => Property::MaxAuthFailures,
            b"maxAvailabilityDuration" => Property::MaxAvailabilityDuration,
            b"maxBodyText" => Property::MaxBodyText,
            b"maxBufferedMemory" => Property::MaxBufferedMemory,
            b"maxCalendars" => Property::MaxCalendars,
            b"maxCalendarsPerEvent" => Property::MaxCalendarsPerEvent,
            b"maxChangesHistory" => Property::MaxChangesHistory,
            b"maxChangesResults" => Property::MaxChangesResults,
            b"maxConcurrentConnections" => Property::MaxConcurrentConnections,
            b"maxConcurrentIndexTasks" => Property::MaxConcurrentIndexTasks,
            b"maxConcurrentRequests" => Property::MaxConcurrentRequests,
            b"maxConcurrentUploads" => Property::MaxConcurrentUploads,
            b"maxConnections" => Property::MaxConnections,
            b"maxContacts" => Property::MaxContacts,
            b"maxCpuCycles" => Property::MaxCpuCycles,
            b"maxDelay" => Property::MaxDelay,
            b"maxDepth" => Property::MaxDepth,
            b"maxDuration" => Property::MaxDuration,
            b"maxEntries" => Property::MaxEntries,
            b"maxEntrySize" => Property::MaxEntrySize,
            b"maxEventNotifications" => Property::MaxEventNotifications,
            b"maxEvents" => Property::MaxEvents,
            b"maxExpandedQueryDuration" => Property::MaxExpandedQueryDuration,
            b"maxExtractArchiveEntries" => Property::MaxExtractArchiveEntries,
            b"maxExtractDecompressedSize" => Property::MaxExtractDecompressedSize,
            b"maxExtractDocumentSize" => Property::MaxExtractDocumentSize,
            b"maxExtractPartSize" => Property::MaxExtractPartSize,
            b"maxExtractParts" => Property::MaxExtractParts,
            b"maxExtractPdfObjects" => Property::MaxExtractPdfObjects,
            b"maxExtractRtfDepth" => Property::MaxExtractRtfDepth,
            b"maxExtractTextSize" => Property::MaxExtractTextSize,
            b"maxFailures" => Property::MaxFailures,
            b"maxFiles" => Property::MaxFiles,
            b"maxFlagLength" => Property::MaxFlagLength,
            b"maxFlagsPerEmail" => Property::MaxFlagsPerEmail,
            b"maxFolders" => Property::MaxFolders,
            b"maxGetResults" => Property::MaxGetResults,
            b"maxHeaderCount" => Property::MaxHeaderCount,
            b"maxHeaderSize" => Property::MaxHeaderSize,
            b"maxICalendarSize" => Property::MaxICalendarSize,
            b"maxIdentities" => Property::MaxIdentities,
            b"maxInboundReportSize" => Property::MaxInboundReportSize,
            b"maxIncludes" => Property::MaxIncludes,
            b"maxInputChars" => Property::MaxInputChars,
            b"maxItipSize" => Property::MaxItipSize,
            b"maxLinks" => Property::MaxLinks,
            b"maxLivePropertySize" => Property::MaxLivePropertySize,
            b"maxLocalVars" => Property::MaxLocalVars,
            b"maxLockTimeout" => Property::MaxLockTimeout,
            b"maxLocks" => Property::MaxLocks,
            b"maxMailboxDepth" => Property::MaxMailboxDepth,
            b"maxMailboxNameLength" => Property::MaxMailboxNameLength,
            b"maxMailboxes" => Property::MaxMailboxes,
            b"maxMailboxesPerEmail" => Property::MaxMailboxesPerEmail,
            b"maxMaskedAddresses" => Property::MaxMaskedAddresses,
            b"maxMatchVars" => Property::MaxMatchVars,
            b"maxMediaSize" => Property::MaxMediaSize,
            b"maxMessageSize" => Property::MaxMessageSize,
            b"maxMessageText" => Property::MaxMessageText,
            b"maxMessages" => Property::MaxMessages,
            b"maxMessagesPerCommand" => Property::MaxMessagesPerCommand,
            b"maxMessagesPerSave" => Property::MaxMessagesPerSave,
            b"maxMethodCalls" => Property::MaxMethodCalls,
            b"maxMultihomed" => Property::MaxMultihomed,
            b"maxMxHosts" => Property::MaxMxHosts,
            b"maxNestedBlocks" => Property::MaxNestedBlocks,
            b"maxNestedForEvery" => Property::MaxNestedForEvery,
            b"maxNestedIncludes" => Property::MaxNestedIncludes,
            b"maxNestedTests" => Property::MaxNestedTests,
            b"maxOutMessages" => Property::MaxOutMessages,
            b"maxOutputTokens" => Property::MaxOutputTokens,
            b"maxParticipantIdentities" => Property::MaxParticipantIdentities,
            b"maxPasswordLength" => Property::MaxPasswordLength,
            b"maxPolls" => Property::MaxPolls,
            b"maxPrivateSize" => Property::MaxPrivateSize,
            b"maxPublicKeys" => Property::MaxPublicKeys,
            b"maxPushAttempts" => Property::MaxPushAttempts,
            b"maxPushSize" => Property::MaxPushSize,
            b"maxQueryResults" => Property::MaxQueryResults,
            b"maxQueryScan" => Property::MaxQueryScan,
            b"maxReceivedHeaders" => Property::MaxReceivedHeaders,
            b"maxRecipients" => Property::MaxRecipients,
            b"maxReconnects" => Property::MaxReconnects,
            b"maxRecurrenceExpansions" => Property::MaxRecurrenceExpansions,
            b"maxRedirectUrls" => Property::MaxRedirectUrls,
            b"maxRedirects" => Property::MaxRedirects,
            b"maxReportSize" => Property::MaxReportSize,
            b"maxRequestSize" => Property::MaxRequestSize,
            b"maxResponseSize" => Property::MaxResponseSize,
            b"maxResults" => Property::MaxResults,
            b"maxRetries" => Property::MaxRetries,
            b"maxRetryWait" => Property::MaxRetryWait,
            b"maxScriptNameLength" => Property::MaxScriptNameLength,
            b"maxScriptSize" => Property::MaxScriptSize,
            b"maxScripts" => Property::MaxScripts,
            b"maxSetObjects" => Property::MaxSetObjects,
            b"maxShares" => Property::MaxShares,
            b"maxSize" => Property::MaxSize,
            b"maxSnippetResults" => Property::MaxSnippetResults,
            b"maxStringLength" => Property::MaxStringLength,
            b"maxSubmissions" => Property::MaxSubmissions,
            b"maxSubscriptions" => Property::MaxSubscriptions,
            b"maxUidBatches" => Property::MaxUidBatches,
            b"maxUploadCount" => Property::MaxUploadCount,
            b"maxUploadSize" => Property::MaxUploadSize,
            b"maxVCardSize" => Property::MaxVCardSize,
            b"maxVarNameLength" => Property::MaxVarNameLength,
            b"maxVarSize" => Property::MaxVarSize,
            b"memberGroupIds" => Property::MemberGroupIds,
            b"memberTenantId" => Property::MemberTenantId,
            b"message" => Property::Message,
            b"messageIdHostname" => Property::MessageIdHostname,
            b"messageIds" => Property::MessageIds,
            b"messageTimeout" => Property::MessageTimeout,
            b"messages" => Property::Messages,
            b"messagesLarge" => Property::MessagesLarge,
            b"messagesLargeTtl" => Property::MessagesLargeTtl,
            b"metric" => Property::Metric,
            b"metrics" => Property::Metrics,
            b"metricsCollectionInterval" => Property::MetricsCollectionInterval,
            b"metricsPolicy" => Property::MetricsPolicy,
            b"minAccountSize" => Property::MinAccountSize,
            b"minHamSamples" => Property::MinHamSamples,
            b"minPasswordLength" => Property::MinPasswordLength,
            b"minPasswordStrength" => Property::MinPasswordStrength,
            b"minProbability" => Property::MinProbability,
            b"minRetryWait" => Property::MinRetryWait,
            b"minSpamSamples" => Property::MinSpamSamples,
            b"minTriggerInterval" => Property::MinTriggerInterval,
            b"minUidBatchSize" => Property::MinUidBatchSize,
            b"minute" => Property::Minute,
            b"mode" => Property::Mode,
            b"model" => Property::Model,
            b"modelId" => Property::ModelId,
            b"mtPriority" => Property::MtPriority,
            b"mtaSts" => Property::MtaSts,
            b"mtaStsTimeout" => Property::MtaStsTimeout,
            b"multiline" => Property::Multiline,
            b"mustMatchSender" => Property::MustMatchSender,
            b"mxHosts" => Property::MxHosts,
            b"name" => Property::Name,
            b"namespace" => Property::Namespace,
            b"negativeTtl" => Property::NegativeTtl,
            b"nextNotify" => Property::NextNotify,
            b"nextRetry" => Property::NextRetry,
            b"nextTransitionAt" => Property::NextTransitionAt,
            b"noCapabilityCheck" => Property::NoCapabilityCheck,
            b"noEcho" => Property::NoEcho,
            b"noSoliciting" => Property::NoSoliciting,
            b"nodeId" => Property::NodeId,
            b"notValidAfter" => Property::NotValidAfter,
            b"notValidBefore" => Property::NotValidBefore,
            b"notify" => Property::Notify,
            b"notifyCount" => Property::NotifyCount,
            b"notifyDue" => Property::NotifyDue,
            b"numFeatures" => Property::NumFeatures,
            b"numReplicas" => Property::NumReplicas,
            b"numShards" => Property::NumShards,
            b"oauthClientId" => Property::OauthClientId,
            b"objectType" => Property::ObjectType,
            b"onSuccessRenewCertificate" => Property::OnSuccessRenewCertificate,
            b"opaqueTokenValidation" => Property::OpaqueTokenValidation,
            b"openTelemetry" => Property::OpenTelemetry,
            b"options" => Property::Options,
            b"orcpt" => Property::Orcpt,
            b"orgName" => Property::OrgName,
            b"organizationName" => Property::OrganizationName,
            b"origin" => Property::Origin,
            b"originalEnvelopeId" => Property::OriginalEnvelopeId,
            b"originalMailFrom" => Property::OriginalMailFrom,
            b"originalRcptTo" => Property::OriginalRcptTo,
            b"otpAuth" => Property::OtpAuth,
            b"otpCode" => Property::OtpCode,
            b"otpUrl" => Property::OtpUrl,
            b"outboundReportDomain" => Property::OutboundReportDomain,
            b"outboundReportSubmitter" => Property::OutboundReportSubmitter,
            b"overrideProxyTrustedNetworks" => Property::OverrideProxyTrustedNetworks,
            b"overrideType" => Property::OverrideType,
            b"ovhEndpoint" => Property::OvhEndpoint,
            b"parameters" => Property::Parameters,
            b"parseLimitContact" => Property::ParseLimitContact,
            b"parseLimitEmail" => Property::ParseLimitEmail,
            b"parseLimitEvent" => Property::ParseLimitEvent,
            b"partition" => Property::Partition,
            b"password" => Property::Password,
            b"passwordDefaultExpiry" => Property::PasswordDefaultExpiry,
            b"passwordHashAlgorithm" => Property::PasswordHashAlgorithm,
            b"path" => Property::Path,
            b"pending" => Property::Pending,
            b"period" => Property::Period,
            b"permissions" => Property::Permissions,
            b"pingInterval" => Property::PingInterval,
            b"pipelining" => Property::Pipelining,
            b"policies" => Property::Policies,
            b"policyAdkim" => Property::PolicyAdkim,
            b"policyAspf" => Property::PolicyAspf,
            b"policyDiscoveryMethod" => Property::PolicyDiscoveryMethod,
            b"policyDisposition" => Property::PolicyDisposition,
            b"policyDomain" => Property::PolicyDomain,
            b"policyFailureReportingOptions" => Property::PolicyFailureReportingOptions,
            b"policyIdentifier" => Property::PolicyIdentifier,
            b"policyIdentifiers" => Property::PolicyIdentifiers,
            b"policyNp" => Property::PolicyNp,
            b"policyOverrideReasons" => Property::PolicyOverrideReasons,
            b"policyStrings" => Property::PolicyStrings,
            b"policySubdomainDisposition" => Property::PolicySubdomainDisposition,
            b"policyTestingMode" => Property::PolicyTestingMode,
            b"policyType" => Property::PolicyType,
            b"policyVersion" => Property::PolicyVersion,
            b"pollInterval" => Property::PollInterval,
            b"poolMaxConnections" => Property::PoolMaxConnections,
            b"poolMinConnections" => Property::PoolMinConnections,
            b"poolRecyclingMethod" => Property::PoolRecyclingMethod,
            b"poolTimeoutCreate" => Property::PoolTimeoutCreate,
            b"poolTimeoutRecycle" => Property::PoolTimeoutRecycle,
            b"poolTimeoutWait" => Property::PoolTimeoutWait,
            b"poolWorkers" => Property::PoolWorkers,
            b"port" => Property::Port,
            b"postLogoutRedirectUris" => Property::PostLogoutRedirectUris,
            b"preferredChain" => Property::PreferredChain,
            b"prefix" => Property::Prefix,
            b"preserveIntermediates" => Property::PreserveIntermediates,
            b"priority" => Property::Priority,
            b"privateKey" => Property::PrivateKey,
            b"privateKeyPassword" => Property::PrivateKeyPassword,
            b"privateKeyPem" => Property::PrivateKeyPem,
            b"privateMetadata" => Property::PrivateMetadata,
            b"privateZone" => Property::PrivateZone,
            b"privateZoneOnly" => Property::PrivateZoneOnly,
            b"profile" => Property::Profile,
            b"projectId" => Property::ProjectId,
            b"prometheus" => Property::Prometheus,
            b"propagationDelay" => Property::PropagationDelay,
            b"propagationTimeout" => Property::PropagationTimeout,
            b"protectedHeaders" => Property::ProtectedHeaders,
            b"protocol" => Property::Protocol,
            b"protocolVersion" => Property::ProtocolVersion,
            b"providerInfo" => Property::ProviderInfo,
            b"proxyTrustedNetworks" => Property::ProxyTrustedNetworks,
            b"publicKey" => Property::PublicKey,
            b"publishRecords" => Property::PublishRecords,
            b"pushAttemptWait" => Property::PushAttemptWait,
            b"pushRequestTimeout" => Property::PushRequestTimeout,
            b"pushRetryWait" => Property::PushRetryWait,
            b"pushShardsTotal" => Property::PushShardsTotal,
            b"pushThrottle" => Property::PushThrottle,
            b"pushVerifyTimeout" => Property::PushVerifyTimeout,
            b"queryEmailAliases" => Property::QueryEmailAliases,
            b"queryLogin" => Property::QueryLogin,
            b"queryMemberOf" => Property::QueryMemberOf,
            b"queryRecipient" => Property::QueryRecipient,
            b"question" => Property::Question,
            b"queueId" => Property::QueueId,
            b"queueName" => Property::QueueName,
            b"queuedDeletions" => Property::QueuedDeletions,
            b"queuedUpdates" => Property::QueuedUpdates,
            b"quotas" => Property::Quotas,
            b"rate" => Property::Rate,
            b"rateLimit" => Property::RateLimit,
            b"rateLimitAnonymous" => Property::RateLimitAnonymous,
            b"rateLimitAuthenticated" => Property::RateLimitAuthenticated,
            b"ratio" => Property::Ratio,
            b"rcptTo" => Property::RcptTo,
            b"rcptToTimeout" => Property::RcptToTimeout,
            b"readBufferCapacity" => Property::ReadBufferCapacity,
            b"readFromReplicas" => Property::ReadFromReplicas,
            b"readReplicas" => Property::ReadReplicas,
            b"reason" => Property::Reason,
            b"reasoning" => Property::Reasoning,
            b"receivedAt" => Property::ReceivedAt,
            b"receivedFromIp" => Property::ReceivedFromIp,
            b"receivedViaPort" => Property::ReceivedViaPort,
            b"receivingIp" => Property::ReceivingIp,
            b"receivingMxHelo" => Property::ReceivingMxHelo,
            b"receivingMxHostname" => Property::ReceivingMxHostname,
            b"recipients" => Property::Recipients,
            b"records" => Property::Records,
            b"recurrenceId" => Property::RecurrenceId,
            b"redirectCacheTtl" => Property::RedirectCacheTtl,
            b"redirectRoot" => Property::RedirectRoot,
            b"redirectTimeout" => Property::RedirectTimeout,
            b"redirectUris" => Property::RedirectUris,
            b"refreshInterval" => Property::RefreshInterval,
            b"refreshTokenExpiry" => Property::RefreshTokenExpiry,
            b"region" => Property::Region,
            b"rejectNonFqdn" => Property::RejectNonFqdn,
            b"remoteIp" => Property::RemoteIp,
            b"renewBefore" => Property::RenewBefore,
            b"report" => Property::Report,
            b"reportAddressUri" => Property::ReportAddressUri,
            b"reportId" => Property::ReportId,
            b"reportedDomains" => Property::ReportedDomains,
            b"reportedUris" => Property::ReportedUris,
            b"reportingMta" => Property::ReportingMta,
            b"requestTimeout" => Property::RequestTimeout,
            b"requestTlsCertificate" => Property::RequestTlsCertificate,
            b"require" => Property::Require,
            b"requireTls" => Property::RequireTls,
            b"reservoirCapacity" => Property::ReservoirCapacity,
            b"resourceAttributes" => Property::ResourceAttributes,
            b"resourceGroup" => Property::ResourceGroup,
            b"resourceUrl" => Property::ResourceUrl,
            b"responseCode" => Property::ResponseCode,
            b"responseEnhanced" => Property::ResponseEnhanced,
            b"responseHeaders" => Property::ResponseHeaders,
            b"responseHostname" => Property::ResponseHostname,
            b"responseMessage" => Property::ResponseMessage,
            b"result" => Property::Result,
            b"resultType" => Property::ResultType,
            b"retention" => Property::Retention,
            b"retireAfter" => Property::RetireAfter,
            b"retry" => Property::Retry,
            b"retryCount" => Property::RetryCount,
            b"retryDue" => Property::RetryDue,
            b"returnPath" => Property::ReturnPath,
            b"reuseKey" => Property::ReuseKey,
            b"reverseIpVerify" => Property::ReverseIpVerify,
            b"rewrite" => Property::Rewrite,
            b"roleIds" => Property::RoleIds,
            b"roles" => Property::Roles,
            b"rotate" => Property::Rotate,
            b"rotateAfter" => Property::RotateAfter,
            b"route" => Property::Route,
            b"rua" => Property::Rua,
            b"sampleRate" => Property::SampleRate,
            b"sandbox" => Property::Sandbox,
            b"sasToken" => Property::SasToken,
            b"saslMechanisms" => Property::SaslMechanisms,
            b"scanBanPaths" => Property::ScanBanPaths,
            b"scanBanPeriod" => Property::ScanBanPeriod,
            b"scanBanRate" => Property::ScanBanRate,
            b"schedule" => Property::Schedule,
            b"scheduling" => Property::Scheduling,
            b"scheme" => Property::Scheme,
            b"scope" => Property::Scope,
            b"scopes" => Property::Scopes,
            b"score" => Property::Score,
            b"scoreDiscard" => Property::ScoreDiscard,
            b"scoreReject" => Property::ScoreReject,
            b"scoreSpam" => Property::ScoreSpam,
            b"script" => Property::Script,
            b"searchStore" => Property::SearchStore,
            b"secret" => Property::Secret,
            b"secretKey" => Property::SecretKey,
            b"selector" => Property::Selector,
            b"selectorTemplate" => Property::SelectorTemplate,
            b"sendFrequency" => Property::SendFrequency,
            b"sendingMtaIp" => Property::SendingMtaIp,
            b"sentinelSecret" => Property::SentinelSecret,
            b"sentinelUsername" => Property::SentinelUsername,
            b"separator" => Property::Separator,
            b"serverId" => Property::ServerId,
            b"servers" => Property::Servers,
            b"serviceAccountJson" => Property::ServiceAccountJson,
            b"serviceName" => Property::ServiceName,
            b"serviceNamespace" => Property::ServiceNamespace,
            b"services" => Property::Services,
            b"sessionTimeout" => Property::SessionTimeout,
            b"sessionToken" => Property::SessionToken,
            b"shardIndex" => Property::ShardIndex,
            b"sharedSecret" => Property::SharedSecret,
            b"signals" => Property::Signals,
            b"signatureAlgorithm" => Property::SignatureAlgorithm,
            b"signatureKey" => Property::SignatureKey,
            b"size" => Property::Size,
            b"skipAudienceValidation" => Property::SkipAudienceValidation,
            b"skipDeploy" => Property::SkipDeploy,
            b"skipFirst" => Property::SkipFirst,
            b"smtpGreeting" => Property::SmtpGreeting,
            b"socketBacklog" => Property::SocketBacklog,
            b"socketNoDelay" => Property::SocketNoDelay,
            b"socketReceiveBufferSize" => Property::SocketReceiveBufferSize,
            b"socketReuseAddress" => Property::SocketReuseAddress,
            b"socketReusePort" => Property::SocketReusePort,
            b"socketSendBufferSize" => Property::SocketSendBufferSize,
            b"socketTosV4" => Property::SocketTosV4,
            b"socketTtl" => Property::SocketTtl,
            b"sourceIp" => Property::SourceIp,
            b"sourcePort" => Property::SourcePort,
            b"spamFilterRulesUrl" => Property::SpamFilterRulesUrl,
            b"spamLookup" => Property::SpamLookup,
            b"spfDns" => Property::SpfDns,
            b"spfEhloDomain" => Property::SpfEhloDomain,
            b"spfEhloResult" => Property::SpfEhloResult,
            b"spfEhloVerify" => Property::SpfEhloVerify,
            b"spfFromVerify" => Property::SpfFromVerify,
            b"spfMailFromDomain" => Property::SpfMailFromDomain,
            b"spfMailFromResult" => Property::SpfMailFromResult,
            b"spfResults" => Property::SpfResults,
            b"stage" => Property::Stage,
            b"stages" => Property::Stages,
            b"startTime" => Property::StartTime,
            b"startTls" => Property::StartTls,
            b"status" => Property::Status,
            b"storageAccount" => Property::StorageAccount,
            b"store" => Property::Store,
            b"stores" => Property::Stores,
            b"strategy" => Property::Strategy,
            b"subAddressing" => Property::SubAddressing,
            b"subAuthId" => Property::SubAuthId,
            b"subject" => Property::Subject,
            b"subjectAlternativeNames" => Property::SubjectAlternativeNames,
            b"subscribe" => Property::Subscribe,
            b"subscriptionCapacity" => Property::SubscriptionCapacity,
            b"subscriptionId" => Property::SubscriptionId,
            b"sum" => Property::Sum,
            b"summary" => Property::Summary,
            b"supportedLanguages" => Property::SupportedLanguages,
            b"swap" => Property::Swap,
            b"tag" => Property::Tag,
            b"tags" => Property::Tags,
            b"targetAccountId" => Property::TargetAccountId,
            b"taskTypes" => Property::TaskTypes,
            b"tasks" => Property::Tasks,
            b"tcpOnError" => Property::TcpOnError,
            b"teamId" => Property::TeamId,
            b"tempFailOnError" => Property::TempFailOnError,
            b"temperature" => Property::Temperature,
            b"template" => Property::Template,
            b"tenancyOcid" => Property::TenancyOcid,
            b"tenantId" => Property::TenantId,
            b"tenants" => Property::Tenants,
            b"text" => Property::Text,
            b"then" => Property::Then,
            b"thirdParty" => Property::ThirdParty,
            b"thirdPartyHash" => Property::ThirdPartyHash,
            b"threadName" => Property::ThreadName,
            b"threadsPerNode" => Property::ThreadsPerNode,
            b"throttle" => Property::Throttle,
            b"tiers" => Property::Tiers,
            b"timeZone" => Property::TimeZone,
            b"timeout" => Property::Timeout,
            b"timestamp" => Property::Timestamp,
            b"title" => Property::Title,
            b"tls" => Property::Tls,
            b"tlsDisableCipherSuites" => Property::TlsDisableCipherSuites,
            b"tlsDisableProtocols" => Property::TlsDisableProtocols,
            b"tlsIgnoreClientOrder" => Property::TlsIgnoreClientOrder,
            b"tlsTimeout" => Property::TlsTimeout,
            b"to" => Property::To,
            b"token" => Property::Token,
            b"tokenFile" => Property::TokenFile,
            b"totalFailedSessions" => Property::TotalFailedSessions,
            b"totalSuccessfulSessions" => Property::TotalSuccessfulSessions,
            b"tracer" => Property::Tracer,
            b"trainInterval" => Property::TrainInterval,
            b"transactionRetryDelay" => Property::TransactionRetryDelay,
            b"transactionRetryLimit" => Property::TransactionRetryLimit,
            b"transactionTimeout" => Property::TransactionTimeout,
            b"transferLimit" => Property::TransferLimit,
            b"trimQuotes" => Property::TrimQuotes,
            b"trustContacts" => Property::TrustContacts,
            b"trustReplies" => Property::TrustReplies,
            b"tsigAlgorithm" => Property::TsigAlgorithm,
            b"ttl" => Property::Ttl,
            b"uncertainBelow" => Property::UncertainBelow,
            b"unpackDirectory" => Property::UnpackDirectory,
            b"unscopedTokens" => Property::UnscopedTokens,
            b"updateRecords" => Property::UpdateRecords,
            b"uploadQuota" => Property::UploadQuota,
            b"uploadTtl" => Property::UploadTtl,
            b"url" => Property::Url,
            b"urlFailover" => Property::UrlFailover,
            b"urlLimit" => Property::UrlLimit,
            b"urlPrefix" => Property::UrlPrefix,
            b"urls" => Property::Urls,
            b"usePermissiveCors" => Property::UsePermissiveCors,
            b"useTls" => Property::UseTls,
            b"usedDiskQuota" => Property::UsedDiskQuota,
            b"userAgent" => Property::UserAgent,
            b"userCodeExpiry" => Property::UserCodeExpiry,
            b"userOcid" => Property::UserOcid,
            b"username" => Property::Username,
            b"usernameDomain" => Property::UsernameDomain,
            b"vCardVersion" => Property::VCardVersion,
            b"validateDomain" => Property::ValidateDomain,
            b"value" => Property::Value,
            b"variableName" => Property::VariableName,
            b"vendorNamespaces" => Property::VendorNamespaces,
            b"verbalHigh" => Property::VerbalHigh,
            b"verbalLow" => Property::VerbalLow,
            b"verbalMedium" => Property::VerbalMedium,
            b"verifyAfterWrite" => Property::VerifyAfterWrite,
            b"version" => Property::Version,
            b"viewName" => Property::ViewName,
            b"vrfy" => Property::Vrfy,
            b"waitOnFail" => Property::WaitOnFail,
            b"wapiVersion" => Property::WapiVersion,
            b"warnings" => Property::Warnings,
            b"webPushContact" => Property::WebPushContact,
            b"webPushKey" => Property::WebPushKey,
            b"webSearch" => Property::WebSearch,
            b"websocketHeartbeat" => Property::WebsocketHeartbeat,
            b"websocketThrottle" => Property::WebsocketThrottle,
            b"websocketTimeout" => Property::WebsocketTimeout,
            b"windowEnd" => Property::WindowEnd,
            b"zone" => Property::Zone,
            b"zoneIpV4" => Property::ZoneIpV4,
            b"zoneIpV6" => Property::ZoneIpV6,
        }
        .copied()
    }

    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            Property,
            b"@type" => Property::Type,
            b"abuseBanPeriod" => Property::AbuseBanPeriod,
            b"abuseBanRate" => Property::AbuseBanRate,
            b"acceptedAudiences" => Property::AcceptedAudiences,
            b"accessKeyId" => Property::AccessKeyId,
            b"accessToken" => Property::AccessToken,
            b"accessTokenExpiry" => Property::AccessTokenExpiry,
            b"accessTokens" => Property::AccessTokens,
            b"accountDomainId" => Property::AccountDomainId,
            b"accountHashPrefix" => Property::AccountHashPrefix,
            b"accountId" => Property::AccountId,
            b"accountIdentifier" => Property::AccountIdentifier,
            b"accountKey" => Property::AccountKey,
            b"accountName" => Property::AccountName,
            b"accountSwitchKey" => Property::AccountSwitchKey,
            b"accountType" => Property::AccountType,
            b"accountUri" => Property::AccountUri,
            b"accounts" => Property::Accounts,
            b"acmeProviderId" => Property::AcmeProviderId,
            b"addAuthResultsHeader" => Property::AddAuthResultsHeader,
            b"addDateHeader" => Property::AddDateHeader,
            b"addDeliveredToHeader" => Property::AddDeliveredToHeader,
            b"addMessageIdHeader" => Property::AddMessageIdHeader,
            b"addReceivedHeader" => Property::AddReceivedHeader,
            b"addReceivedSpfHeader" => Property::AddReceivedSpfHeader,
            b"addReturnPathHeader" => Property::AddReturnPathHeader,
            b"additionalInformation" => Property::AdditionalInformation,
            b"address" => Property::Address,
            b"aggregateContactInfo" => Property::AggregateContactInfo,
            b"aggregateDkimSignDomain" => Property::AggregateDkimSignDomain,
            b"aggregateFromAddress" => Property::AggregateFromAddress,
            b"aggregateFromName" => Property::AggregateFromName,
            b"aggregateOrgName" => Property::AggregateOrgName,
            b"aggregateSendFrequency" => Property::AggregateSendFrequency,
            b"alarmId" => Property::AlarmId,
            b"alertAfter" => Property::AlertAfter,
            b"algorithms" => Property::Algorithms,
            b"aliases" => Property::Aliases,
            b"allowCount" => Property::AllowCount,
            b"allowDirectoryQueries" => Property::AllowDirectoryQueries,
            b"allowExternalRcpts" => Property::AllowExternalRcpts,
            b"allowIdTokenClaims" => Property::AllowIdTokenClaims,
            b"allowInvalidCerts" => Property::AllowInvalidCerts,
            b"allowPlainTextAuth" => Property::AllowPlainTextAuth,
            b"allowRelaying" => Property::AllowRelaying,
            b"allowSpamTraining" => Property::AllowSpamTraining,
            b"allowedEndpoints" => Property::AllowedEndpoints,
            b"allowedIps" => Property::AllowedIps,
            b"allowedNotifyUris" => Property::AllowedNotifyUris,
            b"alpha" => Property::Alpha,
            b"anonymousTimeout" => Property::AnonymousTimeout,
            b"ansi" => Property::Ansi,
            b"apiKey" => Property::ApiKey,
            b"apiKeyId" => Property::ApiKeyId,
            b"apiUser" => Property::ApiUser,
            b"applicationKey" => Property::ApplicationKey,
            b"applicationSecret" => Property::ApplicationSecret,
            b"arcResult" => Property::ArcResult,
            b"arcVerify" => Property::ArcVerify,
            b"arrivalDate" => Property::ArrivalDate,
            b"asnUrls" => Property::AsnUrls,
            b"attemptNumber" => Property::AttemptNumber,
            b"attempts" => Property::Attempts,
            b"attrClass" => Property::AttrClass,
            b"attrDescription" => Property::AttrDescription,
            b"attrEmail" => Property::AttrEmail,
            b"attrEmailAlias" => Property::AttrEmailAlias,
            b"attrMemberOf" => Property::AttrMemberOf,
            b"attrSecret" => Property::AttrSecret,
            b"attrSecretChanged" => Property::AttrSecretChanged,
            b"auid" => Property::Auid,
            b"auth" => Property::Auth,
            b"authBanPeriod" => Property::AuthBanPeriod,
            b"authBanRate" => Property::AuthBanRate,
            b"authCodeExpiry" => Property::AuthCodeExpiry,
            b"authFailure" => Property::AuthFailure,
            b"authId" => Property::AuthId,
            b"authSecret" => Property::AuthSecret,
            b"authUsername" => Property::AuthUsername,
            b"authenticatedAs" => Property::AuthenticatedAs,
            b"authenticatedTimeout" => Property::AuthenticatedTimeout,
            b"authenticationResults" => Property::AuthenticationResults,
            b"autoAddInvitations" => Property::AutoAddInvitations,
            b"autoUpdateInterval" => Property::AutoUpdateInterval,
            b"availabilityRateLimit" => Property::AvailabilityRateLimit,
            b"baseDn" => Property::BaseDn,
            b"bearerToken" => Property::BearerToken,
            b"beta" => Property::Beta,
            b"bind" => Property::Bind,
            b"bindAuthentication" => Property::BindAuthentication,
            b"bindDn" => Property::BindDn,
            b"bindSecret" => Property::BindSecret,
            b"blobCleanupSchedule" => Property::BlobCleanupSchedule,
            b"blobId" => Property::BlobId,
            b"blobSize" => Property::BlobSize,
            b"blobStore" => Property::BlobStore,
            b"blockCount" => Property::BlockCount,
            b"bucket" => Property::Bucket,
            b"bufferSize" => Property::BufferSize,
            b"buffered" => Property::Buffered,
            b"caaIdentities" => Property::CaaIdentities,
            b"cacheSize" => Property::CacheSize,
            b"canonicalization" => Property::Canonicalization,
            b"catchAllAddress" => Property::CatchAllAddress,
            b"certificate" => Property::Certificate,
            b"certificateManagement" => Property::CertificateManagement,
            b"challengeType" => Property::ChallengeType,
            b"chunkSize" => Property::ChunkSize,
            b"chunking" => Property::Chunking,
            b"claimGroups" => Property::ClaimGroups,
            b"claimName" => Property::ClaimName,
            b"claimUsername" => Property::ClaimUsername,
            b"cleartext" => Property::Cleartext,
            b"clientCapacity" => Property::ClientCapacity,
            b"clientHash" => Property::ClientHash,
            b"clientId" => Property::ClientId,
            b"clientIp" => Property::ClientIp,
            b"clientIpSource" => Property::ClientIpSource,
            b"clientKind" => Property::ClientKind,
            b"clientMetadataDocuments" => Property::ClientMetadataDocuments,
            b"clientName" => Property::ClientName,
            b"clientSecret" => Property::ClientSecret,
            b"clientToken" => Property::ClientToken,
            b"clusterFile" => Property::ClusterFile,
            b"columnClass" => Property::ColumnClass,
            b"columnDescription" => Property::ColumnDescription,
            b"columnEmail" => Property::ColumnEmail,
            b"columnSecret" => Property::ColumnSecret,
            b"commandTimeout" => Property::CommandTimeout,
            b"comment" => Property::Comment,
            b"compartmentOcid" => Property::CompartmentOcid,
            b"compressionAlgorithm" => Property::CompressionAlgorithm,
            b"condition" => Property::Condition,
            b"config" => Property::Config,
            b"configName" => Property::ConfigName,
            b"connectTimeout" => Property::ConnectTimeout,
            b"connection" => Property::Connection,
            b"consumerKey" => Property::ConsumerKey,
            b"contact" => Property::Contact,
            b"contactInfo" => Property::ContactInfo,
            b"contacts" => Property::Contacts,
            b"container" => Property::Container,
            b"contentTypes" => Property::ContentTypes,
            b"contents" => Property::Contents,
            b"context" => Property::Context,
            b"count" => Property::Count,
            b"create" => Property::Create,
            b"createdAt" => Property::CreatedAt,
            b"credentialId" => Property::CredentialId,
            b"credentials" => Property::Credentials,
            b"currentSecret" => Property::CurrentSecret,
            b"customRule" => Property::CustomRule,
            b"customerNumber" => Property::CustomerNumber,
            b"dane" => Property::Dane,
            b"dataCleanupSchedule" => Property::DataCleanupSchedule,
            b"dataStore" => Property::DataStore,
            b"dataTimeout" => Property::DataTimeout,
            b"dataTypes" => Property::DataTypes,
            b"database" => Property::Database,
            b"datacenterId" => Property::DatacenterId,
            b"dateRangeEnd" => Property::DateRangeEnd,
            b"dateRangeStart" => Property::DateRangeStart,
            b"day" => Property::Day,
            b"defaultAdminRoleIds" => Property::DefaultAdminRoleIds,
            b"defaultCertificateId" => Property::DefaultCertificateId,
            b"defaultDisplayName" => Property::DefaultDisplayName,
            b"defaultDomain" => Property::DefaultDomain,
            b"defaultDomainId" => Property::DefaultDomainId,
            b"defaultExpiryDuplicate" => Property::DefaultExpiryDuplicate,
            b"defaultExpiryVacation" => Property::DefaultExpiryVacation,
            b"defaultFolders" => Property::DefaultFolders,
            b"defaultFromAddress" => Property::DefaultFromAddress,
            b"defaultFromName" => Property::DefaultFromName,
            b"defaultGroupRoleIds" => Property::DefaultGroupRoleIds,
            b"defaultHostname" => Property::DefaultHostname,
            b"defaultHrefName" => Property::DefaultHrefName,
            b"defaultLanguage" => Property::DefaultLanguage,
            b"defaultName" => Property::DefaultName,
            b"defaultReturnPath" => Property::DefaultReturnPath,
            b"defaultSubject" => Property::DefaultSubject,
            b"defaultSubjectPrefix" => Property::DefaultSubjectPrefix,
            b"defaultUserRoleIds" => Property::DefaultUserRoleIds,
            b"definition" => Property::Definition,
            b"delay" => Property::Delay,
            b"deleteAfter" => Property::DeleteAfter,
            b"deleteAfterUse" => Property::DeleteAfterUse,
            b"deliverAt" => Property::DeliverAt,
            b"deliverBy" => Property::DeliverBy,
            b"deliverTo" => Property::DeliverTo,
            b"deliveryResult" => Property::DeliveryResult,
            b"depth" => Property::Depth,
            b"description" => Property::Description,
            b"details" => Property::Details,
            b"directory" => Property::Directory,
            b"directoryId" => Property::DirectoryId,
            b"directoryRecipients" => Property::DirectoryRecipients,
            b"directoryRecipientsTtl" => Property::DirectoryRecipientsTtl,
            b"disableCapabilities" => Property::DisableCapabilities,
            b"disabledPermissions" => Property::DisabledPermissions,
            b"discardAfter" => Property::DiscardAfter,
            b"disposition" => Property::Disposition,
            b"dkim2Pass" => Property::Dkim2Pass,
            b"dkim2Result" => Property::Dkim2Result,
            b"dkimAdspDns" => Property::DkimAdspDns,
            b"dkimCanonicalizedBody" => Property::DkimCanonicalizedBody,
            b"dkimCanonicalizedHeader" => Property::DkimCanonicalizedHeader,
            b"dkimDomain" => Property::DkimDomain,
            b"dkimIdentity" => Property::DkimIdentity,
            b"dkimManagement" => Property::DkimManagement,
            b"dkimPass" => Property::DkimPass,
            b"dkimResults" => Property::DkimResults,
            b"dkimSelector" => Property::DkimSelector,
            b"dkimSelectorDns" => Property::DkimSelectorDns,
            b"dkimSignDomain" => Property::DkimSignDomain,
            b"dkimSignatures" => Property::DkimSignatures,
            b"dkimStrict" => Property::DkimStrict,
            b"dkimVerify" => Property::DkimVerify,
            b"dmarcPass" => Property::DmarcPass,
            b"dmarcPolicy" => Property::DmarcPolicy,
            b"dmarcResult" => Property::DmarcResult,
            b"dmarcVerify" => Property::DmarcVerify,
            b"dnsIpv4" => Property::DnsIpv4,
            b"dnsIpv6" => Property::DnsIpv6,
            b"dnsManagement" => Property::DnsManagement,
            b"dnsMtaSts" => Property::DnsMtaSts,
            b"dnsMx" => Property::DnsMx,
            b"dnsPtr" => Property::DnsPtr,
            b"dnsServer" => Property::DnsServer,
            b"dnsServerId" => Property::DnsServerId,
            b"dnsTlsa" => Property::DnsTlsa,
            b"dnsTxt" => Property::DnsTxt,
            b"dnsView" => Property::DnsView,
            b"dnsZoneFile" => Property::DnsZoneFile,
            b"documentId" => Property::DocumentId,
            b"domain" => Property::Domain,
            b"domainId" => Property::DomainId,
            b"domainLimit" => Property::DomainLimit,
            b"domainNames" => Property::DomainNames,
            b"domainNamesNegative" => Property::DomainNamesNegative,
            b"domains" => Property::Domains,
            b"dsn" => Property::Dsn,
            b"due" => Property::Due,
            b"duration" => Property::Duration,
            b"eabHmacKey" => Property::EabHmacKey,
            b"eabKeyId" => Property::EabKeyId,
            b"ehloDomain" => Property::EhloDomain,
            b"ehloHostname" => Property::EhloHostname,
            b"ehloTimeout" => Property::EhloTimeout,
            b"elapsed" => Property::Elapsed,
            b"else" => Property::Else,
            b"email" => Property::Email,
            b"emailAddress" => Property::EmailAddress,
            b"emailAddresses" => Property::EmailAddresses,
            b"emailAddressesNegative" => Property::EmailAddressesNegative,
            b"emailLimit" => Property::EmailLimit,
            b"enable" => Property::Enable,
            b"enableAssistedDiscovery" => Property::EnableAssistedDiscovery,
            b"enableEdns" => Property::EnableEdns,
            b"enableHsts" => Property::EnableHsts,
            b"enableLogExporter" => Property::EnableLogExporter,
            b"enableSpamFilter" => Property::EnableSpamFilter,
            b"enableSpanExporter" => Property::EnableSpanExporter,
            b"enabledPermissions" => Property::EnabledPermissions,
            b"encryptAtRest" => Property::EncryptAtRest,
            b"encryptOnAppend" => Property::EncryptOnAppend,
            b"encryptionAtRest" => Property::EncryptionAtRest,
            b"encryptionKey" => Property::EncryptionKey,
            b"envId" => Property::EnvId,
            b"envelopeFrom" => Property::EnvelopeFrom,
            b"envelopeTo" => Property::EnvelopeTo,
            b"environment" => Property::Environment,
            b"errorCommand" => Property::ErrorCommand,
            b"errorMessage" => Property::ErrorMessage,
            b"errorType" => Property::ErrorType,
            b"errors" => Property::Errors,
            b"evaluatedDisposition" => Property::EvaluatedDisposition,
            b"evaluatedDkim" => Property::EvaluatedDkim,
            b"evaluatedSpf" => Property::EvaluatedSpf,
            b"event" => Property::Event,
            b"eventEnd" => Property::EventEnd,
            b"eventEndTz" => Property::EventEndTz,
            b"eventId" => Property::EventId,
            b"eventSourceThrottle" => Property::EventSourceThrottle,
            b"eventStart" => Property::EventStart,
            b"eventStartTz" => Property::EventStartTz,
            b"events" => Property::Events,
            b"eventsPolicy" => Property::EventsPolicy,
            b"expire" => Property::Expire,
            b"expires" => Property::Expires,
            b"expiresAt" => Property::ExpiresAt,
            b"expiresAttempts" => Property::ExpiresAttempts,
            b"expiry" => Property::Expiry,
            b"expn" => Property::Expn,
            b"expungeSchedule" => Property::ExpungeSchedule,
            b"expungeSchedulingInboxAfter" => Property::ExpungeSchedulingInboxAfter,
            b"expungeShareNotifyAfter" => Property::ExpungeShareNotifyAfter,
            b"expungeSubmissionsAfter" => Property::ExpungeSubmissionsAfter,
            b"expungeTrashAfter" => Property::ExpungeTrashAfter,
            b"extension" => Property::Extension,
            b"extensions" => Property::Extensions,
            b"extraContactInfo" => Property::ExtraContactInfo,
            b"factor" => Property::Factor,
            b"failOnTimeout" => Property::FailOnTimeout,
            b"failedAt" => Property::FailedAt,
            b"failedAttemptNumber" => Property::FailedAttemptNumber,
            b"failedSessionCount" => Property::FailedSessionCount,
            b"failureDetails" => Property::FailureDetails,
            b"failureDkimSignDomain" => Property::FailureDkimSignDomain,
            b"failureFromAddress" => Property::FailureFromAddress,
            b"failureFromName" => Property::FailureFromName,
            b"failureReason" => Property::FailureReason,
            b"failureReasonCode" => Property::FailureReasonCode,
            b"failureSendFrequency" => Property::FailureSendFrequency,
            b"failureSubject" => Property::FailureSubject,
            b"featureL2Normalize" => Property::FeatureL2Normalize,
            b"featureLogScale" => Property::FeatureLogScale,
            b"feedbackType" => Property::FeedbackType,
            b"fieldEmail" => Property::FieldEmail,
            b"fieldHoneyPot" => Property::FieldHoneyPot,
            b"fieldName" => Property::FieldName,
            b"fieldSubject" => Property::FieldSubject,
            b"filePath" => Property::FilePath,
            b"files" => Property::Files,
            b"filterLogin" => Property::FilterLogin,
            b"filterMemberOf" => Property::FilterMemberOf,
            b"filterRecipient" => Property::FilterRecipient,
            b"fingerprint" => Property::Fingerprint,
            b"firstFailedAt" => Property::FirstFailedAt,
            b"firstParty" => Property::FirstParty,
            b"flags" => Property::Flags,
            b"flagsAction" => Property::FlagsAction,
            b"flagsProtocol" => Property::FlagsProtocol,
            b"flushChanges" => Property::FlushChanges,
            b"flushInterval" => Property::FlushInterval,
            b"folderId" => Property::FolderId,
            b"format" => Property::Format,
            b"forwardedHops" => Property::ForwardedHops,
            b"from" => Property::From,
            b"fromAddress" => Property::FromAddress,
            b"fromName" => Property::FromName,
            b"futureRelease" => Property::FutureRelease,
            b"generateDkimKeys" => Property::GenerateDkimKeys,
            b"generation" => Property::Generation,
            b"generator" => Property::Generator,
            b"geoUrls" => Property::GeoUrls,
            b"grantTypes" => Property::GrantTypes,
            b"greetingTimeout" => Property::GreetingTimeout,
            b"greylistFor" => Property::GreylistFor,
            b"groupClass" => Property::GroupClass,
            b"groupId" => Property::GroupId,
            b"groupwareLarge" => Property::GroupwareLarge,
            b"groupwareLargeTtl" => Property::GroupwareLargeTtl,
            b"headerFrom" => Property::HeaderFrom,
            b"headers" => Property::Headers,
            b"holdMtaReportsFor" => Property::HoldMtaReportsFor,
            b"holdSamplesFor" => Property::HoldSamplesFor,
            b"host" => Property::Host,
            b"hostedZoneId" => Property::HostedZoneId,
            b"hostname" => Property::Hostname,
            b"hosts" => Property::Hosts,
            b"hour" => Property::Hour,
            b"httpAuth" => Property::HttpAuth,
            b"httpHeaders" => Property::HttpHeaders,
            b"httpRsvpEnable" => Property::HttpRsvpEnable,
            b"httpRsvpLinkExpiry" => Property::HttpRsvpLinkExpiry,
            b"httpRsvpUrl" => Property::HttpRsvpUrl,
            b"httpRua" => Property::HttpRua,
            b"humanResult" => Property::HumanResult,
            b"iCalendarData" => Property::ICalendarData,
            b"id" => Property::Id,
            b"idTokenExpiry" => Property::IdTokenExpiry,
            b"identityAlignment" => Property::IdentityAlignment,
            b"idleTimeout" => Property::IdleTimeout,
            b"if" => Property::If,
            b"imapServerAdmin" => Property::ImapServerAdmin,
            b"imapServerComment" => Property::ImapServerComment,
            b"impersonateServiceAccount" => Property::ImpersonateServiceAccount,
            b"implicitTls" => Property::ImplicitTls,
            b"inMemoryStore" => Property::InMemoryStore,
            b"inboundReportAddresses" => Property::InboundReportAddresses,
            b"inboundReportForwarding" => Property::InboundReportForwarding,
            b"incidents" => Property::Incidents,
            b"includeSecrets" => Property::IncludeSecrets,
            b"includeSource" => Property::IncludeSource,
            b"index" => Property::Index,
            b"indexAsn" => Property::IndexAsn,
            b"indexAsnName" => Property::IndexAsnName,
            b"indexBatchSize" => Property::IndexBatchSize,
            b"indexCalendar" => Property::IndexCalendar,
            b"indexCalendarFields" => Property::IndexCalendarFields,
            b"indexContactFields" => Property::IndexContactFields,
            b"indexContacts" => Property::IndexContacts,
            b"indexCountry" => Property::IndexCountry,
            b"indexEmail" => Property::IndexEmail,
            b"indexEmailFields" => Property::IndexEmailFields,
            b"indexFiles" => Property::IndexFiles,
            b"indexKey" => Property::IndexKey,
            b"indexValue" => Property::IndexValue,
            b"indicatorParameters" => Property::IndicatorParameters,
            b"initialDelay" => Property::InitialDelay,
            b"instanceHashes" => Property::InstanceHashes,
            b"interval" => Property::Interval,
            b"intervals" => Property::Intervals,
            b"introspectionAuthMethod" => Property::IntrospectionAuthMethod,
            b"introspectionClientId" => Property::IntrospectionClientId,
            b"introspectionClientSecret" => Property::IntrospectionClientSecret,
            b"ipLimit" => Property::IpLimit,
            b"ipLookupStrategy" => Property::IpLookupStrategy,
            b"ipRevPtr" => Property::IpRevPtr,
            b"ipRevResult" => Property::IpRevResult,
            b"isActive" => Property::IsActive,
            b"isArchive" => Property::IsArchive,
            b"isBad" => Property::IsBad,
            b"isFromOrganizer" => Property::IsFromOrganizer,
            b"isGlobPattern" => Property::IsGlobPattern,
            b"isGzipped" => Property::IsGzipped,
            b"isNz" => Property::IsNz,
            b"isSenderAllowed" => Property::IsSenderAllowed,
            b"isSpam" => Property::IsSpam,
            b"isTls" => Property::IsTls,
            b"issuer" => Property::Issuer,
            b"issuerDomainNames" => Property::IssuerDomainNames,
            b"issuerUrl" => Property::IssuerUrl,
            b"jitter" => Property::Jitter,
            b"key" => Property::Key,
            b"keyName" => Property::KeyName,
            b"keyPrefix" => Property::KeyPrefix,
            b"l1Ratio" => Property::L1Ratio,
            b"l2Ratio" => Property::L2Ratio,
            b"lastRenewal" => Property::LastRenewal,
            b"lastUsedAt" => Property::LastUsedAt,
            b"learnHamFromCard" => Property::LearnHamFromCard,
            b"learnHamFromReply" => Property::LearnHamFromReply,
            b"learnSpamFromRblHits" => Property::LearnSpamFromRblHits,
            b"learnSpamFromTraps" => Property::LearnSpamFromTraps,
            b"lenientIssuerMatch" => Property::LenientIssuerMatch,
            b"level" => Property::Level,
            b"line" => Property::Line,
            b"listenerIds" => Property::ListenerIds,
            b"listeners" => Property::Listeners,
            b"localIp" => Property::LocalIp,
            b"localIps" => Property::LocalIps,
            b"locale" => Property::Locale,
            b"logo" => Property::Logo,
            b"loiterBanPeriod" => Property::LoiterBanPeriod,
            b"loiterBanRate" => Property::LoiterBanRate,
            b"lossy" => Property::Lossy,
            b"machineId" => Property::MachineId,
            b"mailExchangers" => Property::MailExchangers,
            b"mailFrom" => Property::MailFrom,
            b"mailFromParameters" => Property::MailFromParameters,
            b"mailFromTimeout" => Property::MailFromTimeout,
            b"mailRua" => Property::MailRua,
            b"mailingLists" => Property::MailingLists,
            b"maintenanceType" => Property::MaintenanceType,
            b"managedZone" => Property::ManagedZone,
            b"match" => Property::Match,
            b"maxAccountSize" => Property::MaxAccountSize,
            b"maxAddressBooks" => Property::MaxAddressBooks,
            b"maxAddressBooksPerCard" => Property::MaxAddressBooksPerCard,
            b"maxAge" => Property::MaxAge,
            b"maxAggregateReportSize" => Property::MaxAggregateReportSize,
            b"maxAllowedPacket" => Property::MaxAllowedPacket,
            b"maxApiKeys" => Property::MaxApiKeys,
            b"maxAppPasswords" => Property::MaxAppPasswords,
            b"maxAttachmentSize" => Property::MaxAttachmentSize,
            b"maxAttachmentText" => Property::MaxAttachmentText,
            b"maxAttachmentsSize" => Property::MaxAttachmentsSize,
            b"maxAttempts" => Property::MaxAttempts,
            b"maxAttendees" => Property::MaxAttendees,
            b"maxAuthFailures" => Property::MaxAuthFailures,
            b"maxAvailabilityDuration" => Property::MaxAvailabilityDuration,
            b"maxBodyText" => Property::MaxBodyText,
            b"maxBufferedMemory" => Property::MaxBufferedMemory,
            b"maxCalendars" => Property::MaxCalendars,
            b"maxCalendarsPerEvent" => Property::MaxCalendarsPerEvent,
            b"maxChangesHistory" => Property::MaxChangesHistory,
            b"maxChangesResults" => Property::MaxChangesResults,
            b"maxConcurrentConnections" => Property::MaxConcurrentConnections,
            b"maxConcurrentIndexTasks" => Property::MaxConcurrentIndexTasks,
            b"maxConcurrentRequests" => Property::MaxConcurrentRequests,
            b"maxConcurrentUploads" => Property::MaxConcurrentUploads,
            b"maxConnections" => Property::MaxConnections,
            b"maxContacts" => Property::MaxContacts,
            b"maxCpuCycles" => Property::MaxCpuCycles,
            b"maxDelay" => Property::MaxDelay,
            b"maxDepth" => Property::MaxDepth,
            b"maxDuration" => Property::MaxDuration,
            b"maxEntries" => Property::MaxEntries,
            b"maxEntrySize" => Property::MaxEntrySize,
            b"maxEventNotifications" => Property::MaxEventNotifications,
            b"maxEvents" => Property::MaxEvents,
            b"maxExpandedQueryDuration" => Property::MaxExpandedQueryDuration,
            b"maxExtractArchiveEntries" => Property::MaxExtractArchiveEntries,
            b"maxExtractDecompressedSize" => Property::MaxExtractDecompressedSize,
            b"maxExtractDocumentSize" => Property::MaxExtractDocumentSize,
            b"maxExtractPartSize" => Property::MaxExtractPartSize,
            b"maxExtractParts" => Property::MaxExtractParts,
            b"maxExtractPdfObjects" => Property::MaxExtractPdfObjects,
            b"maxExtractRtfDepth" => Property::MaxExtractRtfDepth,
            b"maxExtractTextSize" => Property::MaxExtractTextSize,
            b"maxFailures" => Property::MaxFailures,
            b"maxFiles" => Property::MaxFiles,
            b"maxFlagLength" => Property::MaxFlagLength,
            b"maxFlagsPerEmail" => Property::MaxFlagsPerEmail,
            b"maxFolders" => Property::MaxFolders,
            b"maxGetResults" => Property::MaxGetResults,
            b"maxHeaderCount" => Property::MaxHeaderCount,
            b"maxHeaderSize" => Property::MaxHeaderSize,
            b"maxICalendarSize" => Property::MaxICalendarSize,
            b"maxIdentities" => Property::MaxIdentities,
            b"maxInboundReportSize" => Property::MaxInboundReportSize,
            b"maxIncludes" => Property::MaxIncludes,
            b"maxItipSize" => Property::MaxItipSize,
            b"maxLivePropertySize" => Property::MaxLivePropertySize,
            b"maxLocalVars" => Property::MaxLocalVars,
            b"maxLockTimeout" => Property::MaxLockTimeout,
            b"maxLocks" => Property::MaxLocks,
            b"maxMailboxDepth" => Property::MaxMailboxDepth,
            b"maxMailboxNameLength" => Property::MaxMailboxNameLength,
            b"maxMailboxes" => Property::MaxMailboxes,
            b"maxMailboxesPerEmail" => Property::MaxMailboxesPerEmail,
            b"maxMatchVars" => Property::MaxMatchVars,
            b"maxMediaSize" => Property::MaxMediaSize,
            b"maxMessageSize" => Property::MaxMessageSize,
            b"maxMessageText" => Property::MaxMessageText,
            b"maxMessages" => Property::MaxMessages,
            b"maxMessagesPerCommand" => Property::MaxMessagesPerCommand,
            b"maxMessagesPerSave" => Property::MaxMessagesPerSave,
            b"maxMethodCalls" => Property::MaxMethodCalls,
            b"maxMultihomed" => Property::MaxMultihomed,
            b"maxMxHosts" => Property::MaxMxHosts,
            b"maxNestedBlocks" => Property::MaxNestedBlocks,
            b"maxNestedForEvery" => Property::MaxNestedForEvery,
            b"maxNestedIncludes" => Property::MaxNestedIncludes,
            b"maxNestedTests" => Property::MaxNestedTests,
            b"maxOutMessages" => Property::MaxOutMessages,
            b"maxParticipantIdentities" => Property::MaxParticipantIdentities,
            b"maxPasswordLength" => Property::MaxPasswordLength,
            b"maxPolls" => Property::MaxPolls,
            b"maxPrivateSize" => Property::MaxPrivateSize,
            b"maxPublicKeys" => Property::MaxPublicKeys,
            b"maxPushAttempts" => Property::MaxPushAttempts,
            b"maxPushSize" => Property::MaxPushSize,
            b"maxQueryResults" => Property::MaxQueryResults,
            b"maxQueryScan" => Property::MaxQueryScan,
            b"maxReceivedHeaders" => Property::MaxReceivedHeaders,
            b"maxRecipients" => Property::MaxRecipients,
            b"maxReconnects" => Property::MaxReconnects,
            b"maxRecurrenceExpansions" => Property::MaxRecurrenceExpansions,
            b"maxRedirectUrls" => Property::MaxRedirectUrls,
            b"maxRedirects" => Property::MaxRedirects,
            b"maxReportSize" => Property::MaxReportSize,
            b"maxRequestSize" => Property::MaxRequestSize,
            b"maxResponseSize" => Property::MaxResponseSize,
            b"maxResults" => Property::MaxResults,
            b"maxRetries" => Property::MaxRetries,
            b"maxRetryWait" => Property::MaxRetryWait,
            b"maxScriptNameLength" => Property::MaxScriptNameLength,
            b"maxScriptSize" => Property::MaxScriptSize,
            b"maxScripts" => Property::MaxScripts,
            b"maxSetObjects" => Property::MaxSetObjects,
            b"maxShares" => Property::MaxShares,
            b"maxSize" => Property::MaxSize,
            b"maxSnippetResults" => Property::MaxSnippetResults,
            b"maxStringLength" => Property::MaxStringLength,
            b"maxSubmissions" => Property::MaxSubmissions,
            b"maxSubscriptions" => Property::MaxSubscriptions,
            b"maxUidBatches" => Property::MaxUidBatches,
            b"maxUploadCount" => Property::MaxUploadCount,
            b"maxUploadSize" => Property::MaxUploadSize,
            b"maxVCardSize" => Property::MaxVCardSize,
            b"maxVarNameLength" => Property::MaxVarNameLength,
            b"maxVarSize" => Property::MaxVarSize,
            b"memberGroupIds" => Property::MemberGroupIds,
            b"message" => Property::Message,
            b"messageIdHostname" => Property::MessageIdHostname,
            b"messageIds" => Property::MessageIds,
            b"messageTimeout" => Property::MessageTimeout,
            b"messages" => Property::Messages,
            b"messagesLarge" => Property::MessagesLarge,
            b"messagesLargeTtl" => Property::MessagesLargeTtl,
            b"metrics" => Property::Metrics,
            b"metricsPolicy" => Property::MetricsPolicy,
            b"minAccountSize" => Property::MinAccountSize,
            b"minHamSamples" => Property::MinHamSamples,
            b"minPasswordLength" => Property::MinPasswordLength,
            b"minPasswordStrength" => Property::MinPasswordStrength,
            b"minRetryWait" => Property::MinRetryWait,
            b"minSpamSamples" => Property::MinSpamSamples,
            b"minTriggerInterval" => Property::MinTriggerInterval,
            b"minUidBatchSize" => Property::MinUidBatchSize,
            b"minute" => Property::Minute,
            b"mode" => Property::Mode,
            b"model" => Property::Model,
            b"mtPriority" => Property::MtPriority,
            b"mtaSts" => Property::MtaSts,
            b"mtaStsTimeout" => Property::MtaStsTimeout,
            b"multiline" => Property::Multiline,
            b"mustMatchSender" => Property::MustMatchSender,
            b"mxHosts" => Property::MxHosts,
            b"name" => Property::Name,
            b"namespace" => Property::Namespace,
            b"negativeTtl" => Property::NegativeTtl,
            b"nextNotify" => Property::NextNotify,
            b"nextRetry" => Property::NextRetry,
            b"nextTransitionAt" => Property::NextTransitionAt,
            b"noCapabilityCheck" => Property::NoCapabilityCheck,
            b"noEcho" => Property::NoEcho,
            b"noSoliciting" => Property::NoSoliciting,
            b"nodeId" => Property::NodeId,
            b"notValidAfter" => Property::NotValidAfter,
            b"notValidBefore" => Property::NotValidBefore,
            b"notify" => Property::Notify,
            b"notifyCount" => Property::NotifyCount,
            b"notifyDue" => Property::NotifyDue,
            b"numFeatures" => Property::NumFeatures,
            b"numReplicas" => Property::NumReplicas,
            b"numShards" => Property::NumShards,
            b"oauthClientId" => Property::OauthClientId,
            b"objectType" => Property::ObjectType,
            b"onSuccessRenewCertificate" => Property::OnSuccessRenewCertificate,
            b"opaqueTokenValidation" => Property::OpaqueTokenValidation,
            b"openTelemetry" => Property::OpenTelemetry,
            b"options" => Property::Options,
            b"orcpt" => Property::Orcpt,
            b"orgName" => Property::OrgName,
            b"organizationName" => Property::OrganizationName,
            b"origin" => Property::Origin,
            b"originalEnvelopeId" => Property::OriginalEnvelopeId,
            b"originalMailFrom" => Property::OriginalMailFrom,
            b"originalRcptTo" => Property::OriginalRcptTo,
            b"otpAuth" => Property::OtpAuth,
            b"otpCode" => Property::OtpCode,
            b"otpUrl" => Property::OtpUrl,
            b"outboundReportDomain" => Property::OutboundReportDomain,
            b"outboundReportSubmitter" => Property::OutboundReportSubmitter,
            b"overrideProxyTrustedNetworks" => Property::OverrideProxyTrustedNetworks,
            b"overrideType" => Property::OverrideType,
            b"ovhEndpoint" => Property::OvhEndpoint,
            b"parameters" => Property::Parameters,
            b"parseLimitContact" => Property::ParseLimitContact,
            b"parseLimitEmail" => Property::ParseLimitEmail,
            b"parseLimitEvent" => Property::ParseLimitEvent,
            b"partition" => Property::Partition,
            b"password" => Property::Password,
            b"passwordDefaultExpiry" => Property::PasswordDefaultExpiry,
            b"passwordHashAlgorithm" => Property::PasswordHashAlgorithm,
            b"path" => Property::Path,
            b"pending" => Property::Pending,
            b"period" => Property::Period,
            b"permissions" => Property::Permissions,
            b"pingInterval" => Property::PingInterval,
            b"pipelining" => Property::Pipelining,
            b"policies" => Property::Policies,
            b"policyAdkim" => Property::PolicyAdkim,
            b"policyAspf" => Property::PolicyAspf,
            b"policyDiscoveryMethod" => Property::PolicyDiscoveryMethod,
            b"policyDisposition" => Property::PolicyDisposition,
            b"policyDomain" => Property::PolicyDomain,
            b"policyFailureReportingOptions" => Property::PolicyFailureReportingOptions,
            b"policyIdentifier" => Property::PolicyIdentifier,
            b"policyIdentifiers" => Property::PolicyIdentifiers,
            b"policyNp" => Property::PolicyNp,
            b"policyOverrideReasons" => Property::PolicyOverrideReasons,
            b"policyStrings" => Property::PolicyStrings,
            b"policySubdomainDisposition" => Property::PolicySubdomainDisposition,
            b"policyTestingMode" => Property::PolicyTestingMode,
            b"policyType" => Property::PolicyType,
            b"policyVersion" => Property::PolicyVersion,
            b"pollInterval" => Property::PollInterval,
            b"poolMaxConnections" => Property::PoolMaxConnections,
            b"poolMinConnections" => Property::PoolMinConnections,
            b"poolRecyclingMethod" => Property::PoolRecyclingMethod,
            b"poolTimeoutCreate" => Property::PoolTimeoutCreate,
            b"poolTimeoutRecycle" => Property::PoolTimeoutRecycle,
            b"poolTimeoutWait" => Property::PoolTimeoutWait,
            b"poolWorkers" => Property::PoolWorkers,
            b"port" => Property::Port,
            b"postLogoutRedirectUris" => Property::PostLogoutRedirectUris,
            b"preferredChain" => Property::PreferredChain,
            b"prefix" => Property::Prefix,
            b"preserveIntermediates" => Property::PreserveIntermediates,
            b"priority" => Property::Priority,
            b"privateKey" => Property::PrivateKey,
            b"privateKeyPassword" => Property::PrivateKeyPassword,
            b"privateKeyPem" => Property::PrivateKeyPem,
            b"privateMetadata" => Property::PrivateMetadata,
            b"privateZone" => Property::PrivateZone,
            b"privateZoneOnly" => Property::PrivateZoneOnly,
            b"profile" => Property::Profile,
            b"projectId" => Property::ProjectId,
            b"prometheus" => Property::Prometheus,
            b"propagationDelay" => Property::PropagationDelay,
            b"propagationTimeout" => Property::PropagationTimeout,
            b"protectedHeaders" => Property::ProtectedHeaders,
            b"protocol" => Property::Protocol,
            b"protocolVersion" => Property::ProtocolVersion,
            b"providerInfo" => Property::ProviderInfo,
            b"proxyTrustedNetworks" => Property::ProxyTrustedNetworks,
            b"publicKey" => Property::PublicKey,
            b"publishRecords" => Property::PublishRecords,
            b"pushAttemptWait" => Property::PushAttemptWait,
            b"pushRequestTimeout" => Property::PushRequestTimeout,
            b"pushRetryWait" => Property::PushRetryWait,
            b"pushShardsTotal" => Property::PushShardsTotal,
            b"pushThrottle" => Property::PushThrottle,
            b"pushVerifyTimeout" => Property::PushVerifyTimeout,
            b"queryEmailAliases" => Property::QueryEmailAliases,
            b"queryLogin" => Property::QueryLogin,
            b"queryMemberOf" => Property::QueryMemberOf,
            b"queryRecipient" => Property::QueryRecipient,
            b"queueId" => Property::QueueId,
            b"queueName" => Property::QueueName,
            b"queuedDeletions" => Property::QueuedDeletions,
            b"queuedUpdates" => Property::QueuedUpdates,
            b"quotas" => Property::Quotas,
            b"rate" => Property::Rate,
            b"rateLimit" => Property::RateLimit,
            b"rateLimitAnonymous" => Property::RateLimitAnonymous,
            b"rateLimitAuthenticated" => Property::RateLimitAuthenticated,
            b"ratio" => Property::Ratio,
            b"rcptTo" => Property::RcptTo,
            b"rcptToTimeout" => Property::RcptToTimeout,
            b"readBufferCapacity" => Property::ReadBufferCapacity,
            b"readFromReplicas" => Property::ReadFromReplicas,
            b"reason" => Property::Reason,
            b"receivedAt" => Property::ReceivedAt,
            b"receivedFromIp" => Property::ReceivedFromIp,
            b"receivedViaPort" => Property::ReceivedViaPort,
            b"receivingIp" => Property::ReceivingIp,
            b"receivingMxHelo" => Property::ReceivingMxHelo,
            b"receivingMxHostname" => Property::ReceivingMxHostname,
            b"recipients" => Property::Recipients,
            b"records" => Property::Records,
            b"recurrenceId" => Property::RecurrenceId,
            b"redirectCacheTtl" => Property::RedirectCacheTtl,
            b"redirectRoot" => Property::RedirectRoot,
            b"redirectTimeout" => Property::RedirectTimeout,
            b"redirectUris" => Property::RedirectUris,
            b"refreshInterval" => Property::RefreshInterval,
            b"refreshTokenExpiry" => Property::RefreshTokenExpiry,
            b"region" => Property::Region,
            b"rejectNonFqdn" => Property::RejectNonFqdn,
            b"remoteIp" => Property::RemoteIp,
            b"renewBefore" => Property::RenewBefore,
            b"report" => Property::Report,
            b"reportAddressUri" => Property::ReportAddressUri,
            b"reportId" => Property::ReportId,
            b"reportedDomains" => Property::ReportedDomains,
            b"reportedUris" => Property::ReportedUris,
            b"reportingMta" => Property::ReportingMta,
            b"requestTimeout" => Property::RequestTimeout,
            b"requestTlsCertificate" => Property::RequestTlsCertificate,
            b"require" => Property::Require,
            b"requireTls" => Property::RequireTls,
            b"reservoirCapacity" => Property::ReservoirCapacity,
            b"resourceAttributes" => Property::ResourceAttributes,
            b"resourceGroup" => Property::ResourceGroup,
            b"resourceUrl" => Property::ResourceUrl,
            b"responseCode" => Property::ResponseCode,
            b"responseEnhanced" => Property::ResponseEnhanced,
            b"responseHeaders" => Property::ResponseHeaders,
            b"responseHostname" => Property::ResponseHostname,
            b"responseMessage" => Property::ResponseMessage,
            b"result" => Property::Result,
            b"resultType" => Property::ResultType,
            b"retention" => Property::Retention,
            b"retireAfter" => Property::RetireAfter,
            b"retry" => Property::Retry,
            b"retryCount" => Property::RetryCount,
            b"retryDue" => Property::RetryDue,
            b"returnPath" => Property::ReturnPath,
            b"reuseKey" => Property::ReuseKey,
            b"reverseIpVerify" => Property::ReverseIpVerify,
            b"rewrite" => Property::Rewrite,
            b"roleIds" => Property::RoleIds,
            b"roles" => Property::Roles,
            b"rotate" => Property::Rotate,
            b"rotateAfter" => Property::RotateAfter,
            b"route" => Property::Route,
            b"rua" => Property::Rua,
            b"sandbox" => Property::Sandbox,
            b"sasToken" => Property::SasToken,
            b"saslMechanisms" => Property::SaslMechanisms,
            b"scanBanPaths" => Property::ScanBanPaths,
            b"scanBanPeriod" => Property::ScanBanPeriod,
            b"scanBanRate" => Property::ScanBanRate,
            b"schedule" => Property::Schedule,
            b"scheduling" => Property::Scheduling,
            b"scheme" => Property::Scheme,
            b"scope" => Property::Scope,
            b"scopes" => Property::Scopes,
            b"score" => Property::Score,
            b"scoreDiscard" => Property::ScoreDiscard,
            b"scoreReject" => Property::ScoreReject,
            b"scoreSpam" => Property::ScoreSpam,
            b"script" => Property::Script,
            b"searchStore" => Property::SearchStore,
            b"secret" => Property::Secret,
            b"secretKey" => Property::SecretKey,
            b"selector" => Property::Selector,
            b"selectorTemplate" => Property::SelectorTemplate,
            b"sendFrequency" => Property::SendFrequency,
            b"sendingMtaIp" => Property::SendingMtaIp,
            b"sentinelSecret" => Property::SentinelSecret,
            b"sentinelUsername" => Property::SentinelUsername,
            b"separator" => Property::Separator,
            b"serverId" => Property::ServerId,
            b"servers" => Property::Servers,
            b"serviceAccountJson" => Property::ServiceAccountJson,
            b"serviceName" => Property::ServiceName,
            b"serviceNamespace" => Property::ServiceNamespace,
            b"services" => Property::Services,
            b"sessionTimeout" => Property::SessionTimeout,
            b"sessionToken" => Property::SessionToken,
            b"shardIndex" => Property::ShardIndex,
            b"sharedSecret" => Property::SharedSecret,
            b"signatureAlgorithm" => Property::SignatureAlgorithm,
            b"signatureKey" => Property::SignatureKey,
            b"size" => Property::Size,
            b"skipAudienceValidation" => Property::SkipAudienceValidation,
            b"skipDeploy" => Property::SkipDeploy,
            b"skipFirst" => Property::SkipFirst,
            b"smtpGreeting" => Property::SmtpGreeting,
            b"socketBacklog" => Property::SocketBacklog,
            b"socketNoDelay" => Property::SocketNoDelay,
            b"socketReceiveBufferSize" => Property::SocketReceiveBufferSize,
            b"socketReuseAddress" => Property::SocketReuseAddress,
            b"socketReusePort" => Property::SocketReusePort,
            b"socketSendBufferSize" => Property::SocketSendBufferSize,
            b"socketTosV4" => Property::SocketTosV4,
            b"socketTtl" => Property::SocketTtl,
            b"sourceIp" => Property::SourceIp,
            b"sourcePort" => Property::SourcePort,
            b"spamFilterRulesUrl" => Property::SpamFilterRulesUrl,
            b"spamLookup" => Property::SpamLookup,
            b"spfDns" => Property::SpfDns,
            b"spfEhloDomain" => Property::SpfEhloDomain,
            b"spfEhloResult" => Property::SpfEhloResult,
            b"spfEhloVerify" => Property::SpfEhloVerify,
            b"spfFromVerify" => Property::SpfFromVerify,
            b"spfMailFromDomain" => Property::SpfMailFromDomain,
            b"spfMailFromResult" => Property::SpfMailFromResult,
            b"spfResults" => Property::SpfResults,
            b"stage" => Property::Stage,
            b"stages" => Property::Stages,
            b"startTls" => Property::StartTls,
            b"status" => Property::Status,
            b"storageAccount" => Property::StorageAccount,
            b"store" => Property::Store,
            b"strategy" => Property::Strategy,
            b"subAddressing" => Property::SubAddressing,
            b"subAuthId" => Property::SubAuthId,
            b"subject" => Property::Subject,
            b"subjectAlternativeNames" => Property::SubjectAlternativeNames,
            b"subscribe" => Property::Subscribe,
            b"subscriptionCapacity" => Property::SubscriptionCapacity,
            b"subscriptionId" => Property::SubscriptionId,
            b"summary" => Property::Summary,
            b"supportedLanguages" => Property::SupportedLanguages,
            b"swap" => Property::Swap,
            b"tag" => Property::Tag,
            b"tags" => Property::Tags,
            b"targetAccountId" => Property::TargetAccountId,
            b"taskTypes" => Property::TaskTypes,
            b"tasks" => Property::Tasks,
            b"tcpOnError" => Property::TcpOnError,
            b"teamId" => Property::TeamId,
            b"tempFailOnError" => Property::TempFailOnError,
            b"tenancyOcid" => Property::TenancyOcid,
            b"tenantId" => Property::TenantId,
            b"text" => Property::Text,
            b"then" => Property::Then,
            b"thirdParty" => Property::ThirdParty,
            b"thirdPartyHash" => Property::ThirdPartyHash,
            b"threadName" => Property::ThreadName,
            b"threadsPerNode" => Property::ThreadsPerNode,
            b"throttle" => Property::Throttle,
            b"timeZone" => Property::TimeZone,
            b"timeout" => Property::Timeout,
            b"timestamp" => Property::Timestamp,
            b"tls" => Property::Tls,
            b"tlsDisableCipherSuites" => Property::TlsDisableCipherSuites,
            b"tlsDisableProtocols" => Property::TlsDisableProtocols,
            b"tlsIgnoreClientOrder" => Property::TlsIgnoreClientOrder,
            b"tlsTimeout" => Property::TlsTimeout,
            b"to" => Property::To,
            b"token" => Property::Token,
            b"tokenFile" => Property::TokenFile,
            b"totalFailedSessions" => Property::TotalFailedSessions,
            b"totalSuccessfulSessions" => Property::TotalSuccessfulSessions,
            b"tracer" => Property::Tracer,
            b"trainInterval" => Property::TrainInterval,
            b"transactionRetryDelay" => Property::TransactionRetryDelay,
            b"transactionRetryLimit" => Property::TransactionRetryLimit,
            b"transactionTimeout" => Property::TransactionTimeout,
            b"transferLimit" => Property::TransferLimit,
            b"trustContacts" => Property::TrustContacts,
            b"trustReplies" => Property::TrustReplies,
            b"tsigAlgorithm" => Property::TsigAlgorithm,
            b"ttl" => Property::Ttl,
            b"unpackDirectory" => Property::UnpackDirectory,
            b"unscopedTokens" => Property::UnscopedTokens,
            b"updateRecords" => Property::UpdateRecords,
            b"uploadQuota" => Property::UploadQuota,
            b"uploadTtl" => Property::UploadTtl,
            b"url" => Property::Url,
            b"urlLimit" => Property::UrlLimit,
            b"urlPrefix" => Property::UrlPrefix,
            b"urls" => Property::Urls,
            b"usePermissiveCors" => Property::UsePermissiveCors,
            b"useTls" => Property::UseTls,
            b"usedDiskQuota" => Property::UsedDiskQuota,
            b"userAgent" => Property::UserAgent,
            b"userCodeExpiry" => Property::UserCodeExpiry,
            b"userOcid" => Property::UserOcid,
            b"username" => Property::Username,
            b"usernameDomain" => Property::UsernameDomain,
            b"vCardVersion" => Property::VCardVersion,
            b"validateDomain" => Property::ValidateDomain,
            b"value" => Property::Value,
            b"variableName" => Property::VariableName,
            b"vendorNamespaces" => Property::VendorNamespaces,
            b"verifyAfterWrite" => Property::VerifyAfterWrite,
            b"version" => Property::Version,
            b"viewName" => Property::ViewName,
            b"vrfy" => Property::Vrfy,
            b"waitOnFail" => Property::WaitOnFail,
            b"wapiVersion" => Property::WapiVersion,
            b"warnings" => Property::Warnings,
            b"webPushContact" => Property::WebPushContact,
            b"webPushKey" => Property::WebPushKey,
            b"websocketHeartbeat" => Property::WebsocketHeartbeat,
            b"websocketThrottle" => Property::WebsocketThrottle,
            b"websocketTimeout" => Property::WebsocketTimeout,
            b"windowEnd" => Property::WindowEnd,
            b"zone" => Property::Zone,
            b"zoneIpV4" => Property::ZoneIpV4,
            b"zoneIpV6" => Property::ZoneIpV6,
        }
        .copied()
    }

    fn as_str(&self) -> &'static str {
        match self {
            Property::Type => "@type",
            Property::AbuseBanPeriod => "abuseBanPeriod",
            Property::AbuseBanRate => "abuseBanRate",
            Property::AcceptedAudiences => "acceptedAudiences",
            Property::AccessKeyId => "accessKeyId",
            Property::AccessToken => "accessToken",
            Property::AccessTokenExpiry => "accessTokenExpiry",
            Property::AccessTokens => "accessTokens",
            Property::AccountDomainId => "accountDomainId",
            Property::AccountHashPrefix => "accountHashPrefix",
            Property::AccountId => "accountId",
            Property::AccountIdentifier => "accountIdentifier",
            Property::AccountKey => "accountKey",
            Property::AccountName => "accountName",
            Property::AccountSwitchKey => "accountSwitchKey",
            Property::AccountType => "accountType",
            Property::AccountUri => "accountUri",
            Property::Accounts => "accounts",
            Property::AcmeProviderId => "acmeProviderId",
            Property::AddAuthResultsHeader => "addAuthResultsHeader",
            Property::AddDateHeader => "addDateHeader",
            Property::AddDeliveredToHeader => "addDeliveredToHeader",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::AddHeader => "addHeader",
            // SPDX-SnippetEnd
            Property::AddMessageIdHeader => "addMessageIdHeader",
            Property::AddReceivedHeader => "addReceivedHeader",
            Property::AddReceivedSpfHeader => "addReceivedSpfHeader",
            Property::AddReturnPathHeader => "addReturnPathHeader",
            Property::AdditionalInformation => "additionalInformation",
            Property::Address => "address",
            Property::AggregateContactInfo => "aggregateContactInfo",
            Property::AggregateDkimSignDomain => "aggregateDkimSignDomain",
            Property::AggregateFromAddress => "aggregateFromAddress",
            Property::AggregateFromName => "aggregateFromName",
            Property::AggregateOrgName => "aggregateOrgName",
            Property::AggregateSendFrequency => "aggregateSendFrequency",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::AiFacts => "aiFacts",
            #[cfg(feature = "enterprise")]
            Property::AiGate => "aiGate",
            #[cfg(feature = "enterprise")]
            Property::AiVerdict => "aiVerdict",
            // SPDX-SnippetEnd
            Property::AlarmId => "alarmId",
            Property::AlertAfter => "alertAfter",
            Property::Algorithms => "algorithms",
            Property::Aliases => "aliases",
            Property::AllowCount => "allowCount",
            Property::AllowDirectoryQueries => "allowDirectoryQueries",
            Property::AllowExternalRcpts => "allowExternalRcpts",
            Property::AllowIdTokenClaims => "allowIdTokenClaims",
            Property::AllowInvalidCerts => "allowInvalidCerts",
            Property::AllowPlainTextAuth => "allowPlainTextAuth",
            Property::AllowRelaying => "allowRelaying",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::AllowScimProvisioning => "allowScimProvisioning",
            // SPDX-SnippetEnd
            Property::AllowSpamTraining => "allowSpamTraining",
            Property::AllowedEndpoints => "allowedEndpoints",
            Property::AllowedIps => "allowedIps",
            Property::AllowedNotifyUris => "allowedNotifyUris",
            Property::Alpha => "alpha",
            Property::AnonymousTimeout => "anonymousTimeout",
            Property::Ansi => "ansi",
            Property::ApiKey => "apiKey",
            Property::ApiKeyId => "apiKeyId",
            Property::ApiUser => "apiUser",
            Property::ApplicationKey => "applicationKey",
            Property::ApplicationSecret => "applicationSecret",
            Property::ArcResult => "arcResult",
            Property::ArcVerify => "arcVerify",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::ArchiveDeletedAccountsFor => "archiveDeletedAccountsFor",
            #[cfg(feature = "enterprise")]
            Property::ArchiveDeletedItemsFor => "archiveDeletedItemsFor",
            #[cfg(feature = "enterprise")]
            Property::ArchivedAt => "archivedAt",
            #[cfg(feature = "enterprise")]
            Property::ArchivedItemType => "archivedItemType",
            #[cfg(feature = "enterprise")]
            Property::ArchivedUntil => "archivedUntil",
            // SPDX-SnippetEnd
            Property::ArrivalDate => "arrivalDate",
            Property::AsnUrls => "asnUrls",
            Property::AttemptNumber => "attemptNumber",
            Property::Attempts => "attempts",
            Property::AttrClass => "attrClass",
            Property::AttrDescription => "attrDescription",
            Property::AttrEmail => "attrEmail",
            Property::AttrEmailAlias => "attrEmailAlias",
            Property::AttrMemberOf => "attrMemberOf",
            Property::AttrSecret => "attrSecret",
            Property::AttrSecretChanged => "attrSecretChanged",
            Property::Auid => "auid",
            Property::Auth => "auth",
            Property::AuthBanPeriod => "authBanPeriod",
            Property::AuthBanRate => "authBanRate",
            Property::AuthCodeExpiry => "authCodeExpiry",
            Property::AuthFailure => "authFailure",
            Property::AuthId => "authId",
            Property::AuthSecret => "authSecret",
            Property::AuthUsername => "authUsername",
            Property::AuthenticatedAs => "authenticatedAs",
            Property::AuthenticatedTimeout => "authenticatedTimeout",
            Property::AuthenticationResults => "authenticationResults",
            Property::AutoAddInvitations => "autoAddInvitations",
            Property::AutoUpdateInterval => "autoUpdateInterval",
            Property::AvailabilityRateLimit => "availabilityRateLimit",
            Property::BaseDn => "baseDn",
            Property::BearerToken => "bearerToken",
            Property::Beta => "beta",
            Property::Bind => "bind",
            Property::BindAuthentication => "bindAuthentication",
            Property::BindDn => "bindDn",
            Property::BindSecret => "bindSecret",
            Property::BlobCleanupSchedule => "blobCleanupSchedule",
            Property::BlobId => "blobId",
            Property::BlobSize => "blobSize",
            Property::BlobStore => "blobStore",
            Property::BlockCount => "blockCount",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Body => "body",
            #[cfg(feature = "enterprise")]
            Property::BreakerCooldown => "breakerCooldown",
            #[cfg(feature = "enterprise")]
            Property::BreakerThreshold => "breakerThreshold",
            // SPDX-SnippetEnd
            Property::Bucket => "bucket",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::BucketHigh => "bucketHigh",
            #[cfg(feature = "enterprise")]
            Property::BucketMedium => "bucketMedium",
            // SPDX-SnippetEnd
            Property::BufferSize => "bufferSize",
            Property::Buffered => "buffered",
            Property::CaaIdentities => "caaIdentities",
            Property::CacheSize => "cacheSize",
            Property::Canonicalization => "canonicalization",
            Property::CatchAllAddress => "catchAllAddress",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Categories => "categories",
            // SPDX-SnippetEnd
            Property::Certificate => "certificate",
            Property::CertificateManagement => "certificateManagement",
            Property::ChallengeType => "challengeType",
            Property::ChunkSize => "chunkSize",
            Property::Chunking => "chunking",
            Property::ClaimGroups => "claimGroups",
            Property::ClaimName => "claimName",
            Property::ClaimUsername => "claimUsername",
            Property::Cleartext => "cleartext",
            Property::ClientCapacity => "clientCapacity",
            Property::ClientHash => "clientHash",
            Property::ClientId => "clientId",
            Property::ClientIp => "clientIp",
            Property::ClientIpSource => "clientIpSource",
            Property::ClientKind => "clientKind",
            Property::ClientMetadataDocuments => "clientMetadataDocuments",
            Property::ClientName => "clientName",
            Property::ClientSecret => "clientSecret",
            Property::ClientToken => "clientToken",
            Property::ClusterFile => "clusterFile",
            Property::ColumnClass => "columnClass",
            Property::ColumnDescription => "columnDescription",
            Property::ColumnEmail => "columnEmail",
            Property::ColumnSecret => "columnSecret",
            Property::CommandTimeout => "commandTimeout",
            Property::Comment => "comment",
            Property::CompartmentOcid => "compartmentOcid",
            Property::CompressionAlgorithm => "compressionAlgorithm",
            Property::Condition => "condition",
            Property::Config => "config",
            Property::ConfigName => "configName",
            Property::ConnectTimeout => "connectTimeout",
            Property::Connection => "connection",
            Property::ConsumerKey => "consumerKey",
            Property::Contact => "contact",
            Property::ContactInfo => "contactInfo",
            Property::Contacts => "contacts",
            Property::Container => "container",
            Property::ContentTypes => "contentTypes",
            Property::Contents => "contents",
            Property::Context => "context",
            Property::Count => "count",
            Property::Create => "create",
            Property::CreatedAt => "createdAt",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::CreatedBy => "createdBy",
            // SPDX-SnippetEnd
            Property::CredentialId => "credentialId",
            Property::Credentials => "credentials",
            Property::CurrentSecret => "currentSecret",
            Property::CustomRule => "customRule",
            Property::CustomerNumber => "customerNumber",
            Property::Dane => "dane",
            Property::DataCleanupSchedule => "dataCleanupSchedule",
            Property::DataStore => "dataStore",
            Property::DataTimeout => "dataTimeout",
            Property::DataTypes => "dataTypes",
            Property::Database => "database",
            Property::DatacenterId => "datacenterId",
            Property::DateRangeEnd => "dateRangeEnd",
            Property::DateRangeStart => "dateRangeStart",
            Property::Day => "day",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Deadline => "deadline",
            // SPDX-SnippetEnd
            Property::DefaultAdminRoleIds => "defaultAdminRoleIds",
            Property::DefaultCertificateId => "defaultCertificateId",
            Property::DefaultDisplayName => "defaultDisplayName",
            Property::DefaultDomain => "defaultDomain",
            Property::DefaultDomainId => "defaultDomainId",
            Property::DefaultExpiryDuplicate => "defaultExpiryDuplicate",
            Property::DefaultExpiryVacation => "defaultExpiryVacation",
            Property::DefaultFolders => "defaultFolders",
            Property::DefaultFromAddress => "defaultFromAddress",
            Property::DefaultFromName => "defaultFromName",
            Property::DefaultGroupRoleIds => "defaultGroupRoleIds",
            Property::DefaultHostname => "defaultHostname",
            Property::DefaultHrefName => "defaultHrefName",
            Property::DefaultLanguage => "defaultLanguage",
            Property::DefaultName => "defaultName",
            Property::DefaultReturnPath => "defaultReturnPath",
            Property::DefaultSubject => "defaultSubject",
            Property::DefaultSubjectPrefix => "defaultSubjectPrefix",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::DefaultTenantRoleIds => "defaultTenantRoleIds",
            // SPDX-SnippetEnd
            Property::DefaultUserRoleIds => "defaultUserRoleIds",
            Property::Definition => "definition",
            Property::Delay => "delay",
            Property::DeleteAfter => "deleteAfter",
            Property::DeleteAfterUse => "deleteAfterUse",
            Property::DeliverAt => "deliverAt",
            Property::DeliverBy => "deliverBy",
            Property::DeliverTo => "deliverTo",
            Property::DeliveryResult => "deliveryResult",
            Property::Depth => "depth",
            Property::Description => "description",
            Property::Details => "details",
            Property::Directory => "directory",
            Property::DirectoryId => "directoryId",
            Property::DirectoryRecipients => "directoryRecipients",
            Property::DirectoryRecipientsTtl => "directoryRecipientsTtl",
            Property::DisableCapabilities => "disableCapabilities",
            Property::DisabledPermissions => "disabledPermissions",
            Property::DiscardAfter => "discardAfter",
            Property::Disposition => "disposition",
            Property::Dkim2Pass => "dkim2Pass",
            Property::Dkim2Result => "dkim2Result",
            Property::DkimAdspDns => "dkimAdspDns",
            Property::DkimCanonicalizedBody => "dkimCanonicalizedBody",
            Property::DkimCanonicalizedHeader => "dkimCanonicalizedHeader",
            Property::DkimDomain => "dkimDomain",
            Property::DkimIdentity => "dkimIdentity",
            Property::DkimManagement => "dkimManagement",
            Property::DkimPass => "dkimPass",
            Property::DkimResults => "dkimResults",
            Property::DkimSelector => "dkimSelector",
            Property::DkimSelectorDns => "dkimSelectorDns",
            Property::DkimSignDomain => "dkimSignDomain",
            Property::DkimSignatures => "dkimSignatures",
            Property::DkimStrict => "dkimStrict",
            Property::DkimVerify => "dkimVerify",
            Property::DmarcPass => "dmarcPass",
            Property::DmarcPolicy => "dmarcPolicy",
            Property::DmarcResult => "dmarcResult",
            Property::DmarcVerify => "dmarcVerify",
            Property::DnsIpv4 => "dnsIpv4",
            Property::DnsIpv6 => "dnsIpv6",
            Property::DnsManagement => "dnsManagement",
            Property::DnsMtaSts => "dnsMtaSts",
            Property::DnsMx => "dnsMx",
            Property::DnsPtr => "dnsPtr",
            Property::DnsServer => "dnsServer",
            Property::DnsServerId => "dnsServerId",
            Property::DnsTlsa => "dnsTlsa",
            Property::DnsTxt => "dnsTxt",
            Property::DnsView => "dnsView",
            Property::DnsZoneFile => "dnsZoneFile",
            Property::DocumentId => "documentId",
            Property::Domain => "domain",
            Property::DomainId => "domainId",
            Property::DomainLimit => "domainLimit",
            Property::DomainNames => "domainNames",
            Property::DomainNamesNegative => "domainNamesNegative",
            Property::Domains => "domains",
            Property::Dsn => "dsn",
            Property::Due => "due",
            Property::Duration => "duration",
            Property::EabHmacKey => "eabHmacKey",
            Property::EabKeyId => "eabKeyId",
            Property::EhloDomain => "ehloDomain",
            Property::EhloHostname => "ehloHostname",
            Property::EhloTimeout => "ehloTimeout",
            Property::Elapsed => "elapsed",
            Property::Else => "else",
            Property::Email => "email",
            Property::EmailAddress => "emailAddress",
            Property::EmailAddresses => "emailAddresses",
            Property::EmailAddressesNegative => "emailAddressesNegative",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::EmailAlert => "emailAlert",
            #[cfg(feature = "enterprise")]
            Property::EmailDomain => "emailDomain",
            // SPDX-SnippetEnd
            Property::EmailLimit => "emailLimit",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::EmailPrefix => "emailPrefix",
            #[cfg(feature = "enterprise")]
            Property::EmailTemplate => "emailTemplate",
            // SPDX-SnippetEnd
            Property::Enable => "enable",
            Property::EnableAssistedDiscovery => "enableAssistedDiscovery",
            Property::EnableEdns => "enableEdns",
            Property::EnableHsts => "enableHsts",
            Property::EnableLogExporter => "enableLogExporter",
            Property::EnableSpamFilter => "enableSpamFilter",
            Property::EnableSpanExporter => "enableSpanExporter",
            Property::EnabledPermissions => "enabledPermissions",
            Property::EncryptAtRest => "encryptAtRest",
            Property::EncryptOnAppend => "encryptOnAppend",
            Property::EncryptionAtRest => "encryptionAtRest",
            Property::EncryptionKey => "encryptionKey",
            Property::EnvId => "envId",
            Property::EnvelopeFrom => "envelopeFrom",
            Property::EnvelopeTo => "envelopeTo",
            Property::Environment => "environment",
            Property::ErrorCommand => "errorCommand",
            Property::ErrorMessage => "errorMessage",
            Property::ErrorType => "errorType",
            Property::Errors => "errors",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::EscalateBelow => "escalateBelow",
            #[cfg(feature = "enterprise")]
            Property::EscalateOn => "escalateOn",
            // SPDX-SnippetEnd
            Property::EvaluatedDisposition => "evaluatedDisposition",
            Property::EvaluatedDkim => "evaluatedDkim",
            Property::EvaluatedSpf => "evaluatedSpf",
            Property::Event => "event",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::EventAlert => "eventAlert",
            // SPDX-SnippetEnd
            Property::EventEnd => "eventEnd",
            Property::EventEndTz => "eventEndTz",
            Property::EventId => "eventId",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::EventMessage => "eventMessage",
            // SPDX-SnippetEnd
            Property::EventSourceThrottle => "eventSourceThrottle",
            Property::EventStart => "eventStart",
            Property::EventStartTz => "eventStartTz",
            Property::Events => "events",
            Property::EventsPolicy => "eventsPolicy",
            Property::Expire => "expire",
            Property::Expires => "expires",
            Property::ExpiresAt => "expiresAt",
            Property::ExpiresAttempts => "expiresAttempts",
            Property::Expiry => "expiry",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Explanation => "explanation",
            // SPDX-SnippetEnd
            Property::Expn => "expn",
            Property::ExpungeSchedule => "expungeSchedule",
            Property::ExpungeSchedulingInboxAfter => "expungeSchedulingInboxAfter",
            Property::ExpungeShareNotifyAfter => "expungeShareNotifyAfter",
            Property::ExpungeSubmissionsAfter => "expungeSubmissionsAfter",
            Property::ExpungeTrashAfter => "expungeTrashAfter",
            Property::Extension => "extension",
            Property::Extensions => "extensions",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::ExternalId => "externalId",
            // SPDX-SnippetEnd
            Property::ExtraContactInfo => "extraContactInfo",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::ExtraParameters => "extraParameters",
            // SPDX-SnippetEnd
            Property::Factor => "factor",
            Property::FailOnTimeout => "failOnTimeout",
            Property::FailedAt => "failedAt",
            Property::FailedAttemptNumber => "failedAttemptNumber",
            Property::FailedSessionCount => "failedSessionCount",
            Property::FailureDetails => "failureDetails",
            Property::FailureDkimSignDomain => "failureDkimSignDomain",
            Property::FailureFromAddress => "failureFromAddress",
            Property::FailureFromName => "failureFromName",
            Property::FailureReason => "failureReason",
            Property::FailureReasonCode => "failureReasonCode",
            Property::FailureSendFrequency => "failureSendFrequency",
            Property::FailureSubject => "failureSubject",
            Property::FeatureL2Normalize => "featureL2Normalize",
            Property::FeatureLogScale => "featureLogScale",
            Property::FeedbackType => "feedbackType",
            Property::FieldEmail => "fieldEmail",
            Property::FieldHoneyPot => "fieldHoneyPot",
            Property::FieldName => "fieldName",
            Property::FieldSubject => "fieldSubject",
            Property::FilePath => "filePath",
            Property::Files => "files",
            Property::FilterLogin => "filterLogin",
            Property::FilterMemberOf => "filterMemberOf",
            Property::FilterRecipient => "filterRecipient",
            Property::Fingerprint => "fingerprint",
            Property::FirstFailedAt => "firstFailedAt",
            Property::FirstParty => "firstParty",
            Property::Flags => "flags",
            Property::FlagsAction => "flagsAction",
            Property::FlagsProtocol => "flagsProtocol",
            Property::FlushChanges => "flushChanges",
            Property::FlushInterval => "flushInterval",
            Property::FolderId => "folderId",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::ForDomain => "forDomain",
            // SPDX-SnippetEnd
            Property::Format => "format",
            Property::ForwardedHops => "forwardedHops",
            Property::From => "from",
            Property::FromAddress => "fromAddress",
            Property::FromName => "fromName",
            Property::FutureRelease => "futureRelease",
            Property::GenerateDkimKeys => "generateDkimKeys",
            Property::Generation => "generation",
            Property::Generator => "generator",
            Property::GeoUrls => "geoUrls",
            Property::GrantTypes => "grantTypes",
            Property::GreetingTimeout => "greetingTimeout",
            Property::GreylistFor => "greylistFor",
            Property::GroupClass => "groupClass",
            Property::GroupId => "groupId",
            Property::GroupwareLarge => "groupwareLarge",
            Property::GroupwareLargeTtl => "groupwareLargeTtl",
            Property::HeaderFrom => "headerFrom",
            Property::Headers => "headers",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::HoldMetricsFor => "holdMetricsFor",
            // SPDX-SnippetEnd
            Property::HoldMtaReportsFor => "holdMtaReportsFor",
            Property::HoldSamplesFor => "holdSamplesFor",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::HoldTracesFor => "holdTracesFor",
            // SPDX-SnippetEnd
            Property::Host => "host",
            Property::HostedZoneId => "hostedZoneId",
            Property::Hostname => "hostname",
            Property::Hosts => "hosts",
            Property::Hour => "hour",
            Property::HttpAuth => "httpAuth",
            Property::HttpHeaders => "httpHeaders",
            Property::HttpRsvpEnable => "httpRsvpEnable",
            Property::HttpRsvpLinkExpiry => "httpRsvpLinkExpiry",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::HttpRsvpTemplate => "httpRsvpTemplate",
            // SPDX-SnippetEnd
            Property::HttpRsvpUrl => "httpRsvpUrl",
            Property::HttpRua => "httpRua",
            Property::HumanResult => "humanResult",
            Property::ICalendarData => "iCalendarData",
            Property::Id => "id",
            Property::IdTokenExpiry => "idTokenExpiry",
            Property::IdentityAlignment => "identityAlignment",
            Property::IdleTimeout => "idleTimeout",
            Property::If => "if",
            Property::ImapServerAdmin => "imapServerAdmin",
            Property::ImapServerComment => "imapServerComment",
            Property::ImpersonateServiceAccount => "impersonateServiceAccount",
            Property::ImplicitTls => "implicitTls",
            Property::InMemoryStore => "inMemoryStore",
            Property::InboundReportAddresses => "inboundReportAddresses",
            Property::InboundReportForwarding => "inboundReportForwarding",
            Property::Incidents => "incidents",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::IncludeAttachments => "includeAttachments",
            #[cfg(feature = "enterprise")]
            Property::IncludeAuth => "includeAuth",
            #[cfg(feature = "enterprise")]
            Property::IncludeLinks => "includeLinks",
            // SPDX-SnippetEnd
            Property::IncludeSecrets => "includeSecrets",
            Property::IncludeSource => "includeSource",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Includes => "includes",
            // SPDX-SnippetEnd
            Property::Index => "index",
            Property::IndexAsn => "indexAsn",
            Property::IndexAsnName => "indexAsnName",
            Property::IndexBatchSize => "indexBatchSize",
            Property::IndexCalendar => "indexCalendar",
            Property::IndexCalendarFields => "indexCalendarFields",
            Property::IndexContactFields => "indexContactFields",
            Property::IndexContacts => "indexContacts",
            Property::IndexCountry => "indexCountry",
            Property::IndexEmail => "indexEmail",
            Property::IndexEmailFields => "indexEmailFields",
            Property::IndexFiles => "indexFiles",
            Property::IndexKey => "indexKey",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::IndexTelemetry => "indexTelemetry",
            // SPDX-SnippetEnd
            Property::IndexValue => "indexValue",
            Property::IndicatorParameters => "indicatorParameters",
            Property::InitialDelay => "initialDelay",
            Property::InstanceHashes => "instanceHashes",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Instructions => "instructions",
            // SPDX-SnippetEnd
            Property::Interval => "interval",
            Property::Intervals => "intervals",
            Property::IntrospectionAuthMethod => "introspectionAuthMethod",
            Property::IntrospectionClientId => "introspectionClientId",
            Property::IntrospectionClientSecret => "introspectionClientSecret",
            Property::IpLimit => "ipLimit",
            Property::IpLookupStrategy => "ipLookupStrategy",
            Property::IpRevPtr => "ipRevPtr",
            Property::IpRevResult => "ipRevResult",
            Property::IsActive => "isActive",
            Property::IsArchive => "isArchive",
            Property::IsBad => "isBad",
            Property::IsFromOrganizer => "isFromOrganizer",
            Property::IsGlobPattern => "isGlobPattern",
            Property::IsGzipped => "isGzipped",
            Property::IsNz => "isNz",
            Property::IsSenderAllowed => "isSenderAllowed",
            Property::IsSpam => "isSpam",
            Property::IsTls => "isTls",
            Property::Issuer => "issuer",
            Property::IssuerDomainNames => "issuerDomainNames",
            Property::IssuerUrl => "issuerUrl",
            Property::Jitter => "jitter",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::KeepAlive => "keepAlive",
            // SPDX-SnippetEnd
            Property::Key => "key",
            Property::KeyName => "keyName",
            Property::KeyPrefix => "keyPrefix",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::KeyValues => "keyValues",
            // SPDX-SnippetEnd
            Property::L1Ratio => "l1Ratio",
            Property::L2Ratio => "l2Ratio",
            Property::LastRenewal => "lastRenewal",
            Property::LastUsedAt => "lastUsedAt",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Learn => "learn",
            // SPDX-SnippetEnd
            Property::LearnHamFromCard => "learnHamFromCard",
            Property::LearnHamFromReply => "learnHamFromReply",
            Property::LearnSpamFromRblHits => "learnSpamFromRblHits",
            Property::LearnSpamFromTraps => "learnSpamFromTraps",
            Property::LenientIssuerMatch => "lenientIssuerMatch",
            Property::Level => "level",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::LicenseKey => "licenseKey",
            // SPDX-SnippetEnd
            Property::Line => "line",
            Property::ListenerIds => "listenerIds",
            Property::Listeners => "listeners",
            Property::LocalIp => "localIp",
            Property::LocalIps => "localIps",
            Property::Locale => "locale",
            Property::Logo => "logo",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Logprobs => "logprobs",
            // SPDX-SnippetEnd
            Property::LoiterBanPeriod => "loiterBanPeriod",
            Property::LoiterBanRate => "loiterBanRate",
            Property::Lossy => "lossy",
            Property::MachineId => "machineId",
            Property::MailExchangers => "mailExchangers",
            Property::MailFrom => "mailFrom",
            Property::MailFromParameters => "mailFromParameters",
            Property::MailFromTimeout => "mailFromTimeout",
            Property::MailRua => "mailRua",
            Property::MailingLists => "mailingLists",
            Property::MaintenanceType => "maintenanceType",
            Property::ManagedZone => "managedZone",
            Property::Match => "match",
            Property::MaxAccountSize => "maxAccountSize",
            Property::MaxAddressBooks => "maxAddressBooks",
            Property::MaxAddressBooksPerCard => "maxAddressBooksPerCard",
            Property::MaxAge => "maxAge",
            Property::MaxAggregateReportSize => "maxAggregateReportSize",
            Property::MaxAllowedPacket => "maxAllowedPacket",
            Property::MaxApiKeys => "maxApiKeys",
            Property::MaxAppPasswords => "maxAppPasswords",
            Property::MaxAttachmentSize => "maxAttachmentSize",
            Property::MaxAttachmentText => "maxAttachmentText",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MaxAttachments => "maxAttachments",
            // SPDX-SnippetEnd
            Property::MaxAttachmentsSize => "maxAttachmentsSize",
            Property::MaxAttempts => "maxAttempts",
            Property::MaxAttendees => "maxAttendees",
            Property::MaxAuthFailures => "maxAuthFailures",
            Property::MaxAvailabilityDuration => "maxAvailabilityDuration",
            Property::MaxBodyText => "maxBodyText",
            Property::MaxBufferedMemory => "maxBufferedMemory",
            Property::MaxCalendars => "maxCalendars",
            Property::MaxCalendarsPerEvent => "maxCalendarsPerEvent",
            Property::MaxChangesHistory => "maxChangesHistory",
            Property::MaxChangesResults => "maxChangesResults",
            Property::MaxConcurrentConnections => "maxConcurrentConnections",
            Property::MaxConcurrentIndexTasks => "maxConcurrentIndexTasks",
            Property::MaxConcurrentRequests => "maxConcurrentRequests",
            Property::MaxConcurrentUploads => "maxConcurrentUploads",
            Property::MaxConnections => "maxConnections",
            Property::MaxContacts => "maxContacts",
            Property::MaxCpuCycles => "maxCpuCycles",
            Property::MaxDelay => "maxDelay",
            Property::MaxDepth => "maxDepth",
            Property::MaxDuration => "maxDuration",
            Property::MaxEntries => "maxEntries",
            Property::MaxEntrySize => "maxEntrySize",
            Property::MaxEventNotifications => "maxEventNotifications",
            Property::MaxEvents => "maxEvents",
            Property::MaxExpandedQueryDuration => "maxExpandedQueryDuration",
            Property::MaxExtractArchiveEntries => "maxExtractArchiveEntries",
            Property::MaxExtractDecompressedSize => "maxExtractDecompressedSize",
            Property::MaxExtractDocumentSize => "maxExtractDocumentSize",
            Property::MaxExtractPartSize => "maxExtractPartSize",
            Property::MaxExtractParts => "maxExtractParts",
            Property::MaxExtractPdfObjects => "maxExtractPdfObjects",
            Property::MaxExtractRtfDepth => "maxExtractRtfDepth",
            Property::MaxExtractTextSize => "maxExtractTextSize",
            Property::MaxFailures => "maxFailures",
            Property::MaxFiles => "maxFiles",
            Property::MaxFlagLength => "maxFlagLength",
            Property::MaxFlagsPerEmail => "maxFlagsPerEmail",
            Property::MaxFolders => "maxFolders",
            Property::MaxGetResults => "maxGetResults",
            Property::MaxHeaderCount => "maxHeaderCount",
            Property::MaxHeaderSize => "maxHeaderSize",
            Property::MaxICalendarSize => "maxICalendarSize",
            Property::MaxIdentities => "maxIdentities",
            Property::MaxInboundReportSize => "maxInboundReportSize",
            Property::MaxIncludes => "maxIncludes",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MaxInputChars => "maxInputChars",
            // SPDX-SnippetEnd
            Property::MaxItipSize => "maxItipSize",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MaxLinks => "maxLinks",
            // SPDX-SnippetEnd
            Property::MaxLivePropertySize => "maxLivePropertySize",
            Property::MaxLocalVars => "maxLocalVars",
            Property::MaxLockTimeout => "maxLockTimeout",
            Property::MaxLocks => "maxLocks",
            Property::MaxMailboxDepth => "maxMailboxDepth",
            Property::MaxMailboxNameLength => "maxMailboxNameLength",
            Property::MaxMailboxes => "maxMailboxes",
            Property::MaxMailboxesPerEmail => "maxMailboxesPerEmail",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MaxMaskedAddresses => "maxMaskedAddresses",
            // SPDX-SnippetEnd
            Property::MaxMatchVars => "maxMatchVars",
            Property::MaxMediaSize => "maxMediaSize",
            Property::MaxMessageSize => "maxMessageSize",
            Property::MaxMessageText => "maxMessageText",
            Property::MaxMessages => "maxMessages",
            Property::MaxMessagesPerCommand => "maxMessagesPerCommand",
            Property::MaxMessagesPerSave => "maxMessagesPerSave",
            Property::MaxMethodCalls => "maxMethodCalls",
            Property::MaxMultihomed => "maxMultihomed",
            Property::MaxMxHosts => "maxMxHosts",
            Property::MaxNestedBlocks => "maxNestedBlocks",
            Property::MaxNestedForEvery => "maxNestedForEvery",
            Property::MaxNestedIncludes => "maxNestedIncludes",
            Property::MaxNestedTests => "maxNestedTests",
            Property::MaxOutMessages => "maxOutMessages",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MaxOutputTokens => "maxOutputTokens",
            // SPDX-SnippetEnd
            Property::MaxParticipantIdentities => "maxParticipantIdentities",
            Property::MaxPasswordLength => "maxPasswordLength",
            Property::MaxPolls => "maxPolls",
            Property::MaxPrivateSize => "maxPrivateSize",
            Property::MaxPublicKeys => "maxPublicKeys",
            Property::MaxPushAttempts => "maxPushAttempts",
            Property::MaxPushSize => "maxPushSize",
            Property::MaxQueryResults => "maxQueryResults",
            Property::MaxQueryScan => "maxQueryScan",
            Property::MaxReceivedHeaders => "maxReceivedHeaders",
            Property::MaxRecipients => "maxRecipients",
            Property::MaxReconnects => "maxReconnects",
            Property::MaxRecurrenceExpansions => "maxRecurrenceExpansions",
            Property::MaxRedirectUrls => "maxRedirectUrls",
            Property::MaxRedirects => "maxRedirects",
            Property::MaxReportSize => "maxReportSize",
            Property::MaxRequestSize => "maxRequestSize",
            Property::MaxResponseSize => "maxResponseSize",
            Property::MaxResults => "maxResults",
            Property::MaxRetries => "maxRetries",
            Property::MaxRetryWait => "maxRetryWait",
            Property::MaxScriptNameLength => "maxScriptNameLength",
            Property::MaxScriptSize => "maxScriptSize",
            Property::MaxScripts => "maxScripts",
            Property::MaxSetObjects => "maxSetObjects",
            Property::MaxShares => "maxShares",
            Property::MaxSize => "maxSize",
            Property::MaxSnippetResults => "maxSnippetResults",
            Property::MaxStringLength => "maxStringLength",
            Property::MaxSubmissions => "maxSubmissions",
            Property::MaxSubscriptions => "maxSubscriptions",
            Property::MaxUidBatches => "maxUidBatches",
            Property::MaxUploadCount => "maxUploadCount",
            Property::MaxUploadSize => "maxUploadSize",
            Property::MaxVCardSize => "maxVCardSize",
            Property::MaxVarNameLength => "maxVarNameLength",
            Property::MaxVarSize => "maxVarSize",
            Property::MemberGroupIds => "memberGroupIds",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MemberTenantId => "memberTenantId",
            // SPDX-SnippetEnd
            Property::Message => "message",
            Property::MessageIdHostname => "messageIdHostname",
            Property::MessageIds => "messageIds",
            Property::MessageTimeout => "messageTimeout",
            Property::Messages => "messages",
            Property::MessagesLarge => "messagesLarge",
            Property::MessagesLargeTtl => "messagesLargeTtl",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Metric => "metric",
            // SPDX-SnippetEnd
            Property::Metrics => "metrics",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MetricsCollectionInterval => "metricsCollectionInterval",
            // SPDX-SnippetEnd
            Property::MetricsPolicy => "metricsPolicy",
            Property::MinAccountSize => "minAccountSize",
            Property::MinHamSamples => "minHamSamples",
            Property::MinPasswordLength => "minPasswordLength",
            Property::MinPasswordStrength => "minPasswordStrength",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::MinProbability => "minProbability",
            // SPDX-SnippetEnd
            Property::MinRetryWait => "minRetryWait",
            Property::MinSpamSamples => "minSpamSamples",
            Property::MinTriggerInterval => "minTriggerInterval",
            Property::MinUidBatchSize => "minUidBatchSize",
            Property::Minute => "minute",
            Property::Mode => "mode",
            Property::Model => "model",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::ModelId => "modelId",
            // SPDX-SnippetEnd
            Property::MtPriority => "mtPriority",
            Property::MtaSts => "mtaSts",
            Property::MtaStsTimeout => "mtaStsTimeout",
            Property::Multiline => "multiline",
            Property::MustMatchSender => "mustMatchSender",
            Property::MxHosts => "mxHosts",
            Property::Name => "name",
            Property::Namespace => "namespace",
            Property::NegativeTtl => "negativeTtl",
            Property::NextNotify => "nextNotify",
            Property::NextRetry => "nextRetry",
            Property::NextTransitionAt => "nextTransitionAt",
            Property::NoCapabilityCheck => "noCapabilityCheck",
            Property::NoEcho => "noEcho",
            Property::NoSoliciting => "noSoliciting",
            Property::NodeId => "nodeId",
            Property::NotValidAfter => "notValidAfter",
            Property::NotValidBefore => "notValidBefore",
            Property::Notify => "notify",
            Property::NotifyCount => "notifyCount",
            Property::NotifyDue => "notifyDue",
            Property::NumFeatures => "numFeatures",
            Property::NumReplicas => "numReplicas",
            Property::NumShards => "numShards",
            Property::OauthClientId => "oauthClientId",
            Property::ObjectType => "objectType",
            Property::OnSuccessRenewCertificate => "onSuccessRenewCertificate",
            Property::OpaqueTokenValidation => "opaqueTokenValidation",
            Property::OpenTelemetry => "openTelemetry",
            Property::Options => "options",
            Property::Orcpt => "orcpt",
            Property::OrgName => "orgName",
            Property::OrganizationName => "organizationName",
            Property::Origin => "origin",
            Property::OriginalEnvelopeId => "originalEnvelopeId",
            Property::OriginalMailFrom => "originalMailFrom",
            Property::OriginalRcptTo => "originalRcptTo",
            Property::OtpAuth => "otpAuth",
            Property::OtpCode => "otpCode",
            Property::OtpUrl => "otpUrl",
            Property::OutboundReportDomain => "outboundReportDomain",
            Property::OutboundReportSubmitter => "outboundReportSubmitter",
            Property::OverrideProxyTrustedNetworks => "overrideProxyTrustedNetworks",
            Property::OverrideType => "overrideType",
            Property::OvhEndpoint => "ovhEndpoint",
            Property::Parameters => "parameters",
            Property::ParseLimitContact => "parseLimitContact",
            Property::ParseLimitEmail => "parseLimitEmail",
            Property::ParseLimitEvent => "parseLimitEvent",
            Property::Partition => "partition",
            Property::Password => "password",
            Property::PasswordDefaultExpiry => "passwordDefaultExpiry",
            Property::PasswordHashAlgorithm => "passwordHashAlgorithm",
            Property::Path => "path",
            Property::Pending => "pending",
            Property::Period => "period",
            Property::Permissions => "permissions",
            Property::PingInterval => "pingInterval",
            Property::Pipelining => "pipelining",
            Property::Policies => "policies",
            Property::PolicyAdkim => "policyAdkim",
            Property::PolicyAspf => "policyAspf",
            Property::PolicyDiscoveryMethod => "policyDiscoveryMethod",
            Property::PolicyDisposition => "policyDisposition",
            Property::PolicyDomain => "policyDomain",
            Property::PolicyFailureReportingOptions => "policyFailureReportingOptions",
            Property::PolicyIdentifier => "policyIdentifier",
            Property::PolicyIdentifiers => "policyIdentifiers",
            Property::PolicyNp => "policyNp",
            Property::PolicyOverrideReasons => "policyOverrideReasons",
            Property::PolicyStrings => "policyStrings",
            Property::PolicySubdomainDisposition => "policySubdomainDisposition",
            Property::PolicyTestingMode => "policyTestingMode",
            Property::PolicyType => "policyType",
            Property::PolicyVersion => "policyVersion",
            Property::PollInterval => "pollInterval",
            Property::PoolMaxConnections => "poolMaxConnections",
            Property::PoolMinConnections => "poolMinConnections",
            Property::PoolRecyclingMethod => "poolRecyclingMethod",
            Property::PoolTimeoutCreate => "poolTimeoutCreate",
            Property::PoolTimeoutRecycle => "poolTimeoutRecycle",
            Property::PoolTimeoutWait => "poolTimeoutWait",
            Property::PoolWorkers => "poolWorkers",
            Property::Port => "port",
            Property::PostLogoutRedirectUris => "postLogoutRedirectUris",
            Property::PreferredChain => "preferredChain",
            Property::Prefix => "prefix",
            Property::PreserveIntermediates => "preserveIntermediates",
            Property::Priority => "priority",
            Property::PrivateKey => "privateKey",
            Property::PrivateKeyPassword => "privateKeyPassword",
            Property::PrivateKeyPem => "privateKeyPem",
            Property::PrivateMetadata => "privateMetadata",
            Property::PrivateZone => "privateZone",
            Property::PrivateZoneOnly => "privateZoneOnly",
            Property::Profile => "profile",
            Property::ProjectId => "projectId",
            Property::Prometheus => "prometheus",
            Property::PropagationDelay => "propagationDelay",
            Property::PropagationTimeout => "propagationTimeout",
            Property::ProtectedHeaders => "protectedHeaders",
            Property::Protocol => "protocol",
            Property::ProtocolVersion => "protocolVersion",
            Property::ProviderInfo => "providerInfo",
            Property::ProxyTrustedNetworks => "proxyTrustedNetworks",
            Property::PublicKey => "publicKey",
            Property::PublishRecords => "publishRecords",
            Property::PushAttemptWait => "pushAttemptWait",
            Property::PushRequestTimeout => "pushRequestTimeout",
            Property::PushRetryWait => "pushRetryWait",
            Property::PushShardsTotal => "pushShardsTotal",
            Property::PushThrottle => "pushThrottle",
            Property::PushVerifyTimeout => "pushVerifyTimeout",
            Property::QueryEmailAliases => "queryEmailAliases",
            Property::QueryLogin => "queryLogin",
            Property::QueryMemberOf => "queryMemberOf",
            Property::QueryRecipient => "queryRecipient",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Question => "question",
            // SPDX-SnippetEnd
            Property::QueueId => "queueId",
            Property::QueueName => "queueName",
            Property::QueuedDeletions => "queuedDeletions",
            Property::QueuedUpdates => "queuedUpdates",
            Property::Quotas => "quotas",
            Property::Rate => "rate",
            Property::RateLimit => "rateLimit",
            Property::RateLimitAnonymous => "rateLimitAnonymous",
            Property::RateLimitAuthenticated => "rateLimitAuthenticated",
            Property::Ratio => "ratio",
            Property::RcptTo => "rcptTo",
            Property::RcptToTimeout => "rcptToTimeout",
            Property::ReadBufferCapacity => "readBufferCapacity",
            Property::ReadFromReplicas => "readFromReplicas",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::ReadReplicas => "readReplicas",
            // SPDX-SnippetEnd
            Property::Reason => "reason",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Reasoning => "reasoning",
            // SPDX-SnippetEnd
            Property::ReceivedAt => "receivedAt",
            Property::ReceivedFromIp => "receivedFromIp",
            Property::ReceivedViaPort => "receivedViaPort",
            Property::ReceivingIp => "receivingIp",
            Property::ReceivingMxHelo => "receivingMxHelo",
            Property::ReceivingMxHostname => "receivingMxHostname",
            Property::Recipients => "recipients",
            Property::Records => "records",
            Property::RecurrenceId => "recurrenceId",
            Property::RedirectCacheTtl => "redirectCacheTtl",
            Property::RedirectRoot => "redirectRoot",
            Property::RedirectTimeout => "redirectTimeout",
            Property::RedirectUris => "redirectUris",
            Property::RefreshInterval => "refreshInterval",
            Property::RefreshTokenExpiry => "refreshTokenExpiry",
            Property::Region => "region",
            Property::RejectNonFqdn => "rejectNonFqdn",
            Property::RemoteIp => "remoteIp",
            Property::RenewBefore => "renewBefore",
            Property::Report => "report",
            Property::ReportAddressUri => "reportAddressUri",
            Property::ReportId => "reportId",
            Property::ReportedDomains => "reportedDomains",
            Property::ReportedUris => "reportedUris",
            Property::ReportingMta => "reportingMta",
            Property::RequestTimeout => "requestTimeout",
            Property::RequestTlsCertificate => "requestTlsCertificate",
            Property::Require => "require",
            Property::RequireTls => "requireTls",
            Property::ReservoirCapacity => "reservoirCapacity",
            Property::ResourceAttributes => "resourceAttributes",
            Property::ResourceGroup => "resourceGroup",
            Property::ResourceUrl => "resourceUrl",
            Property::ResponseCode => "responseCode",
            Property::ResponseEnhanced => "responseEnhanced",
            Property::ResponseHeaders => "responseHeaders",
            Property::ResponseHostname => "responseHostname",
            Property::ResponseMessage => "responseMessage",
            Property::Result => "result",
            Property::ResultType => "resultType",
            Property::Retention => "retention",
            Property::RetireAfter => "retireAfter",
            Property::Retry => "retry",
            Property::RetryCount => "retryCount",
            Property::RetryDue => "retryDue",
            Property::ReturnPath => "returnPath",
            Property::ReuseKey => "reuseKey",
            Property::ReverseIpVerify => "reverseIpVerify",
            Property::Rewrite => "rewrite",
            Property::RoleIds => "roleIds",
            Property::Roles => "roles",
            Property::Rotate => "rotate",
            Property::RotateAfter => "rotateAfter",
            Property::Route => "route",
            Property::Rua => "rua",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::SampleRate => "sampleRate",
            // SPDX-SnippetEnd
            Property::Sandbox => "sandbox",
            Property::SasToken => "sasToken",
            Property::SaslMechanisms => "saslMechanisms",
            Property::ScanBanPaths => "scanBanPaths",
            Property::ScanBanPeriod => "scanBanPeriod",
            Property::ScanBanRate => "scanBanRate",
            Property::Schedule => "schedule",
            Property::Scheduling => "scheduling",
            Property::Scheme => "scheme",
            Property::Scope => "scope",
            Property::Scopes => "scopes",
            Property::Score => "score",
            Property::ScoreDiscard => "scoreDiscard",
            Property::ScoreReject => "scoreReject",
            Property::ScoreSpam => "scoreSpam",
            Property::Script => "script",
            Property::SearchStore => "searchStore",
            Property::Secret => "secret",
            Property::SecretKey => "secretKey",
            Property::Selector => "selector",
            Property::SelectorTemplate => "selectorTemplate",
            Property::SendFrequency => "sendFrequency",
            Property::SendingMtaIp => "sendingMtaIp",
            Property::SentinelSecret => "sentinelSecret",
            Property::SentinelUsername => "sentinelUsername",
            Property::Separator => "separator",
            Property::ServerId => "serverId",
            Property::Servers => "servers",
            Property::ServiceAccountJson => "serviceAccountJson",
            Property::ServiceName => "serviceName",
            Property::ServiceNamespace => "serviceNamespace",
            Property::Services => "services",
            Property::SessionTimeout => "sessionTimeout",
            Property::SessionToken => "sessionToken",
            Property::ShardIndex => "shardIndex",
            Property::SharedSecret => "sharedSecret",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Signals => "signals",
            // SPDX-SnippetEnd
            Property::SignatureAlgorithm => "signatureAlgorithm",
            Property::SignatureKey => "signatureKey",
            Property::Size => "size",
            Property::SkipAudienceValidation => "skipAudienceValidation",
            Property::SkipDeploy => "skipDeploy",
            Property::SkipFirst => "skipFirst",
            Property::SmtpGreeting => "smtpGreeting",
            Property::SocketBacklog => "socketBacklog",
            Property::SocketNoDelay => "socketNoDelay",
            Property::SocketReceiveBufferSize => "socketReceiveBufferSize",
            Property::SocketReuseAddress => "socketReuseAddress",
            Property::SocketReusePort => "socketReusePort",
            Property::SocketSendBufferSize => "socketSendBufferSize",
            Property::SocketTosV4 => "socketTosV4",
            Property::SocketTtl => "socketTtl",
            Property::SourceIp => "sourceIp",
            Property::SourcePort => "sourcePort",
            Property::SpamFilterRulesUrl => "spamFilterRulesUrl",
            Property::SpamLookup => "spamLookup",
            Property::SpfDns => "spfDns",
            Property::SpfEhloDomain => "spfEhloDomain",
            Property::SpfEhloResult => "spfEhloResult",
            Property::SpfEhloVerify => "spfEhloVerify",
            Property::SpfFromVerify => "spfFromVerify",
            Property::SpfMailFromDomain => "spfMailFromDomain",
            Property::SpfMailFromResult => "spfMailFromResult",
            Property::SpfResults => "spfResults",
            Property::Stage => "stage",
            Property::Stages => "stages",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::StartTime => "startTime",
            // SPDX-SnippetEnd
            Property::StartTls => "startTls",
            Property::Status => "status",
            Property::StorageAccount => "storageAccount",
            Property::Store => "store",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Stores => "stores",
            // SPDX-SnippetEnd
            Property::Strategy => "strategy",
            Property::SubAddressing => "subAddressing",
            Property::SubAuthId => "subAuthId",
            Property::Subject => "subject",
            Property::SubjectAlternativeNames => "subjectAlternativeNames",
            Property::Subscribe => "subscribe",
            Property::SubscriptionCapacity => "subscriptionCapacity",
            Property::SubscriptionId => "subscriptionId",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Sum => "sum",
            // SPDX-SnippetEnd
            Property::Summary => "summary",
            Property::SupportedLanguages => "supportedLanguages",
            Property::Swap => "swap",
            Property::Tag => "tag",
            Property::Tags => "tags",
            Property::TargetAccountId => "targetAccountId",
            Property::TaskTypes => "taskTypes",
            Property::Tasks => "tasks",
            Property::TcpOnError => "tcpOnError",
            Property::TeamId => "teamId",
            Property::TempFailOnError => "tempFailOnError",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Temperature => "temperature",
            #[cfg(feature = "enterprise")]
            Property::Template => "template",
            // SPDX-SnippetEnd
            Property::TenancyOcid => "tenancyOcid",
            Property::TenantId => "tenantId",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Tenants => "tenants",
            // SPDX-SnippetEnd
            Property::Text => "text",
            Property::Then => "then",
            Property::ThirdParty => "thirdParty",
            Property::ThirdPartyHash => "thirdPartyHash",
            Property::ThreadName => "threadName",
            Property::ThreadsPerNode => "threadsPerNode",
            Property::Throttle => "throttle",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Tiers => "tiers",
            // SPDX-SnippetEnd
            Property::TimeZone => "timeZone",
            Property::Timeout => "timeout",
            Property::Timestamp => "timestamp",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::Title => "title",
            // SPDX-SnippetEnd
            Property::Tls => "tls",
            Property::TlsDisableCipherSuites => "tlsDisableCipherSuites",
            Property::TlsDisableProtocols => "tlsDisableProtocols",
            Property::TlsIgnoreClientOrder => "tlsIgnoreClientOrder",
            Property::TlsTimeout => "tlsTimeout",
            Property::To => "to",
            Property::Token => "token",
            Property::TokenFile => "tokenFile",
            Property::TotalFailedSessions => "totalFailedSessions",
            Property::TotalSuccessfulSessions => "totalSuccessfulSessions",
            Property::Tracer => "tracer",
            Property::TrainInterval => "trainInterval",
            Property::TransactionRetryDelay => "transactionRetryDelay",
            Property::TransactionRetryLimit => "transactionRetryLimit",
            Property::TransactionTimeout => "transactionTimeout",
            Property::TransferLimit => "transferLimit",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::TrimQuotes => "trimQuotes",
            // SPDX-SnippetEnd
            Property::TrustContacts => "trustContacts",
            Property::TrustReplies => "trustReplies",
            Property::TsigAlgorithm => "tsigAlgorithm",
            Property::Ttl => "ttl",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::UncertainBelow => "uncertainBelow",
            // SPDX-SnippetEnd
            Property::UnpackDirectory => "unpackDirectory",
            Property::UnscopedTokens => "unscopedTokens",
            Property::UpdateRecords => "updateRecords",
            Property::UploadQuota => "uploadQuota",
            Property::UploadTtl => "uploadTtl",
            Property::Url => "url",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::UrlFailover => "urlFailover",
            // SPDX-SnippetEnd
            Property::UrlLimit => "urlLimit",
            Property::UrlPrefix => "urlPrefix",
            Property::Urls => "urls",
            Property::UsePermissiveCors => "usePermissiveCors",
            Property::UseTls => "useTls",
            Property::UsedDiskQuota => "usedDiskQuota",
            Property::UserAgent => "userAgent",
            Property::UserCodeExpiry => "userCodeExpiry",
            Property::UserOcid => "userOcid",
            Property::Username => "username",
            Property::UsernameDomain => "usernameDomain",
            Property::VCardVersion => "vCardVersion",
            Property::ValidateDomain => "validateDomain",
            Property::Value => "value",
            Property::VariableName => "variableName",
            Property::VendorNamespaces => "vendorNamespaces",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::VerbalHigh => "verbalHigh",
            #[cfg(feature = "enterprise")]
            Property::VerbalLow => "verbalLow",
            #[cfg(feature = "enterprise")]
            Property::VerbalMedium => "verbalMedium",
            // SPDX-SnippetEnd
            Property::VerifyAfterWrite => "verifyAfterWrite",
            Property::Version => "version",
            Property::ViewName => "viewName",
            Property::Vrfy => "vrfy",
            Property::WaitOnFail => "waitOnFail",
            Property::WapiVersion => "wapiVersion",
            Property::Warnings => "warnings",
            Property::WebPushContact => "webPushContact",
            Property::WebPushKey => "webPushKey",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Property::WebSearch => "webSearch",
            // SPDX-SnippetEnd
            Property::WebsocketHeartbeat => "websocketHeartbeat",
            Property::WebsocketThrottle => "websocketThrottle",
            Property::WebsocketTimeout => "websocketTimeout",
            Property::WindowEnd => "windowEnd",
            Property::Zone => "zone",
            Property::ZoneIpV4 => "zoneIpV4",
            Property::ZoneIpV6 => "zoneIpV6",
        }
    }

    fn to_id(&self) -> u16 {
        *self as u16
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(Property::Type),
            792 => Some(Property::AbuseBanPeriod),
            791 => Some(Property::AbuseBanRate),
            710 => Some(Property::AcceptedAudiences),
            354 => Some(Property::AccessKeyId),
            378 => Some(Property::AccessToken),
            721 => Some(Property::AccessTokenExpiry),
            159 => Some(Property::AccessTokens),
            951 => Some(Property::AccountDomainId),
            17 => Some(Property::AccountHashPrefix),
            71 => Some(Property::AccountId),
            374 => Some(Property::AccountIdentifier),
            15 => Some(Property::AccountKey),
            950 => Some(Property::AccountName),
            379 => Some(Property::AccountSwitchKey),
            952 => Some(Property::AccountType),
            16 => Some(Property::AccountUri),
            182 => Some(Property::Accounts),
            220 => Some(Property::AcmeProviderId),
            649 => Some(Property::AddAuthResultsHeader),
            650 => Some(Property::AddDateHeader),
            651 => Some(Property::AddDeliveredToHeader),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            852 => Some(Property::AddHeader),
            // SPDX-SnippetEnd
            652 => Some(Property::AddMessageIdHeader),
            653 => Some(Property::AddReceivedHeader),
            654 => Some(Property::AddReceivedSpfHeader),
            655 => Some(Property::AddReturnPathHeader),
            980 => Some(Property::AdditionalInformation),
            58 => Some(Property::Address),
            311 => Some(Property::AggregateContactInfo),
            317 => Some(Property::AggregateDkimSignDomain),
            312 => Some(Property::AggregateFromAddress),
            313 => Some(Property::AggregateFromName),
            315 => Some(Property::AggregateOrgName),
            316 => Some(Property::AggregateSendFrequency),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            888 => Some(Property::AiFacts),
            #[cfg(feature = "enterprise")]
            887 => Some(Property::AiGate),
            #[cfg(feature = "enterprise")]
            889 => Some(Property::AiVerdict),
            // SPDX-SnippetEnd
            938 => Some(Property::AlarmId),
            957 => Some(Property::AlertAfter),
            265 => Some(Property::Algorithms),
            411 => Some(Property::Aliases),
            903 => Some(Property::AllowCount),
            809 => Some(Property::AllowDirectoryQueries),
            203 => Some(Property::AllowExternalRcpts),
            717 => Some(Property::AllowIdTokenClaims),
            41 => Some(Property::AllowInvalidCerts),
            502 => Some(Property::AllowPlainTextAuth),
            419 => Some(Property::AllowRelaying),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            421 => Some(Property::AllowScimProvisioning),
            // SPDX-SnippetEnd
            446 => Some(Property::AllowSpamTraining),
            475 => Some(Property::AllowedEndpoints),
            63 => Some(Property::AllowedIps),
            824 => Some(Property::AllowedNotifyUris),
            464 => Some(Property::Alpha),
            506 => Some(Property::AnonymousTimeout),
            999 => Some(Property::Ansi),
            39 => Some(Property::ApiKey),
            372 => Some(Property::ApiKeyId),
            390 => Some(Property::ApiUser),
            399 => Some(Property::ApplicationKey),
            400 => Some(Property::ApplicationSecret),
            337 => Some(Property::ArcResult),
            804 => Some(Property::ArcVerify),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            241 => Some(Property::ArchiveDeletedAccountsFor),
            #[cfg(feature = "enterprise")]
            240 => Some(Property::ArchiveDeletedItemsFor),
            #[cfg(feature = "enterprise")]
            72 => Some(Property::ArchivedAt),
            #[cfg(feature = "enterprise")]
            961 => Some(Property::ArchivedItemType),
            #[cfg(feature = "enterprise")]
            73 => Some(Property::ArchivedUntil),
            // SPDX-SnippetEnd
            82 => Some(Property::ArrivalDate),
            116 => Some(Property::AsnUrls),
            971 => Some(Property::AttemptNumber),
            348 => Some(Property::Attempts),
            559 => Some(Property::AttrClass),
            560 => Some(Property::AttrDescription),
            561 => Some(Property::AttrEmail),
            562 => Some(Property::AttrEmailAlias),
            563 => Some(Property::AttrMemberOf),
            564 => Some(Property::AttrSecret),
            565 => Some(Property::AttrSecretChanged),
            253 => Some(Property::Auid),
            139 => Some(Property::Auth),
            794 => Some(Property::AuthBanPeriod),
            793 => Some(Property::AuthBanRate),
            719 => Some(Property::AuthCodeExpiry),
            95 => Some(Property::AuthFailure),
            370 => Some(Property::AuthId),
            597 => Some(Property::AuthSecret),
            598 => Some(Property::AuthUsername),
            882 => Some(Property::AuthenticatedAs),
            507 => Some(Property::AuthenticatedTimeout),
            83 => Some(Property::AuthenticationResults),
            209 => Some(Property::AutoAddInvitations),
            66 => Some(Property::AutoUpdateInterval),
            201 => Some(Property::AvailabilityRateLimit),
            552 => Some(Property::BaseDn),
            482 => Some(Property::BearerToken),
            465 => Some(Property::Beta),
            681 => Some(Property::Bind),
            555 => Some(Property::BindAuthentication),
            553 => Some(Property::BindDn),
            554 => Some(Property::BindSecret),
            238 => Some(Property::BlobCleanupSchedule),
            74 => Some(Property::BlobId),
            763 => Some(Property::BlobSize),
            153 => Some(Property::BlobStore),
            901 => Some(Property::BlockCount),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            52 => Some(Property::Body),
            #[cfg(feature = "enterprise")]
            862 => Some(Property::BreakerCooldown),
            #[cfg(feature = "enterprise")]
            861 => Some(Property::BreakerThreshold),
            // SPDX-SnippetEnd
            767 => Some(Property::Bucket),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            845 => Some(Property::BucketHigh),
            #[cfg(feature = "enterprise")]
            846 => Some(Property::BucketMedium),
            // SPDX-SnippetEnd
            764 => Some(Property::BufferSize),
            1004 => Some(Property::Buffered),
            19 => Some(Property::CaaIdentities),
            766 => Some(Property::CacheSize),
            254 => Some(Property::Canonicalization),
            417 => Some(Property::CatchAllAddress),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            843 => Some(Property::Categories),
            // SPDX-SnippetEnd
            214 => Some(Property::Certificate),
            413 => Some(Property::CertificateManagement),
            10 => Some(Property::ChallengeType),
            756 => Some(Property::ChunkSize),
            614 => Some(Property::Chunking),
            709 => Some(Property::ClaimGroups),
            708 => Some(Property::ClaimName),
            706 => Some(Property::ClaimUsername),
            807 => Some(Property::Cleartext),
            677 => Some(Property::ClientCapacity),
            1012 => Some(Property::ClientHash),
            132 => Some(Property::ClientId),
            391 => Some(Property::ClientIp),
            479 => Some(Property::ClientIpSource),
            701 => Some(Property::ClientKind),
            727 => Some(Property::ClientMetadataDocuments),
            700 => Some(Property::ClientName),
            133 => Some(Property::ClientSecret),
            377 => Some(Property::ClientToken),
            458 => Some(Property::ClusterFile),
            921 => Some(Property::ColumnClass),
            922 => Some(Property::ColumnDescription),
            919 => Some(Property::ColumnEmail),
            920 => Some(Property::ColumnSecret),
            631 => Some(Property::CommandTimeout),
            280 => Some(Property::Comment),
            398 => Some(Property::CompartmentOcid),
            431 => Some(Property::CompressionAlgorithm),
            48 => Some(Property::Condition),
            1011 => Some(Property::Config),
            367 => Some(Property::ConfigName),
            602 => Some(Property::ConnectTimeout),
            634 => Some(Property::Connection),
            401 => Some(Property::ConsumerKey),
            11 => Some(Property::Contact),
            986 => Some(Property::ContactInfo),
            160 => Some(Property::Contacts),
            137 => Some(Property::Container),
            900 => Some(Property::ContentTypes),
            79 => Some(Property::Contents),
            364 => Some(Property::Context),
            301 => Some(Property::Count),
            444 => Some(Property::Create),
            60 => Some(Property::CreatedAt),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            575 => Some(Property::CreatedBy),
            // SPDX-SnippetEnd
            730 => Some(Property::CredentialId),
            385 => Some(Property::Credentials),
            4 => Some(Property::CurrentSecret),
            927 => Some(Property::CustomRule),
            392 => Some(Property::CustomerNumber),
            664 => Some(Property::Dane),
            237 => Some(Property::DataCleanupSchedule),
            152 => Some(Property::DataStore),
            603 => Some(Property::DataTimeout),
            582 => Some(Property::DataTypes),
            670 => Some(Property::Database),
            459 => Some(Property::DatacenterId),
            286 => Some(Property::DateRangeEnd),
            285 => Some(Property::DateRangeStart),
            230 => Some(Property::Day),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            860 => Some(Property::Deadline),
            // SPDX-SnippetEnd
            123 => Some(Property::DefaultAdminRoleIds),
            929 => Some(Property::DefaultCertificateId),
            24 => Some(Property::DefaultDisplayName),
            149 => Some(Property::DefaultDomain),
            928 => Some(Property::DefaultDomainId),
            821 => Some(Property::DefaultExpiryDuplicate),
            822 => Some(Property::DefaultExpiryVacation),
            432 => Some(Property::DefaultFolders),
            484 => Some(Property::DefaultFromAddress),
            811 => Some(Property::DefaultFromName),
            121 => Some(Property::DefaultGroupRoleIds),
            148 => Some(Property::DefaultHostname),
            25 => Some(Property::DefaultHrefName),
            770 => Some(Property::DefaultLanguage),
            487 => Some(Property::DefaultName),
            814 => Some(Property::DefaultReturnPath),
            489 => Some(Property::DefaultSubject),
            826 => Some(Property::DefaultSubjectPrefix),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            122 => Some(Property::DefaultTenantRoleIds),
            // SPDX-SnippetEnd
            120 => Some(Property::DefaultUserRoleIds),
            275 => Some(Property::Definition),
            966 => Some(Property::Delay),
            269 => Some(Property::DeleteAfter),
            918 => Some(Property::DeleteAfterUse),
            278 => Some(Property::DeliverAt),
            615 => Some(Property::DeliverBy),
            483 => Some(Property::DeliverTo),
            96 => Some(Property::DeliveryResult),
            457 => Some(Property::Depth),
            6 => Some(Property::Description),
            342 => Some(Property::Details),
            12 => Some(Property::Directory),
            119 => Some(Property::DirectoryId),
            188 => Some(Property::DirectoryRecipients),
            189 => Some(Property::DirectoryRecipientsTtl),
            823 => Some(Property::DisableCapabilities),
            732 => Some(Property::DisabledPermissions),
            1010 => Some(Property::DiscardAfter),
            890 => Some(Property::Disposition),
            336 => Some(Property::Dkim2Pass),
            335 => Some(Property::Dkim2Result),
            97 => Some(Property::DkimAdspDns),
            98 => Some(Property::DkimCanonicalizedBody),
            99 => Some(Property::DkimCanonicalizedHeader),
            100 => Some(Property::DkimDomain),
            101 => Some(Property::DkimIdentity),
            414 => Some(Property::DkimManagement),
            334 => Some(Property::DkimPass),
            309 => Some(Property::DkimResults),
            102 => Some(Property::DkimSelector),
            103 => Some(Property::DkimSelectorDns),
            271 => Some(Property::DkimSignDomain),
            186 => Some(Property::DkimSignatures),
            800 => Some(Property::DkimStrict),
            801 => Some(Property::DkimVerify),
            339 => Some(Property::DmarcPass),
            340 => Some(Property::DmarcPolicy),
            338 => Some(Property::DmarcResult),
            805 => Some(Property::DmarcVerify),
            161 => Some(Property::DnsIpv4),
            162 => Some(Property::DnsIpv6),
            415 => Some(Property::DnsManagement),
            163 => Some(Property::DnsMtaSts),
            164 => Some(Property::DnsMx),
            165 => Some(Property::DnsPtr),
            157 => Some(Property::DnsServer),
            345 => Some(Property::DnsServerId),
            167 => Some(Property::DnsTlsa),
            168 => Some(Property::DnsTxt),
            387 => Some(Property::DnsView),
            416 => Some(Property::DnsZoneFile),
            946 => Some(Property::DocumentId),
            272 => Some(Property::Domain),
            259 => Some(Property::DomainId),
            892 => Some(Property::DomainLimit),
            178 => Some(Property::DomainNames),
            179 => Some(Property::DomainNamesNegative),
            177 => Some(Property::Domains),
            616 => Some(Property::Dsn),
            937 => Some(Property::Due),
            612 => Some(Property::Duration),
            13 => Some(Property::EabHmacKey),
            14 => Some(Property::EabKeyId),
            325 => Some(Property::EhloDomain),
            599 => Some(Property::EhloHostname),
            604 => Some(Property::EhloTimeout),
            341 => Some(Property::Elapsed),
            451 => Some(Property::Else),
            282 => Some(Property::Email),
            469 => Some(Property::EmailAddress),
            180 => Some(Property::EmailAddresses),
            181 => Some(Property::EmailAddressesNegative),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            49 => Some(Property::EmailAlert),
            #[cfg(feature = "enterprise")]
            577 => Some(Property::EmailDomain),
            // SPDX-SnippetEnd
            893 => Some(Property::EmailLimit),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            576 => Some(Property::EmailPrefix),
            #[cfg(feature = "enterprise")]
            212 => Some(Property::EmailTemplate),
            // SPDX-SnippetEnd
            51 => Some(Property::Enable),
            1005 => Some(Property::EnableAssistedDiscovery),
            349 => Some(Property::EnableEdns),
            476 => Some(Property::EnableHsts),
            1001 => Some(Property::EnableLogExporter),
            657 => Some(Property::EnableSpamFilter),
            1002 => Some(Property::EnableSpanExporter),
            731 => Some(Property::EnabledPermissions),
            430 => Some(Property::EncryptAtRest),
            429 => Some(Property::EncryptOnAppend),
            9 => Some(Property::EncryptionAtRest),
            724 => Some(Property::EncryptionKey),
            740 => Some(Property::EnvId),
            307 => Some(Property::EnvelopeFrom),
            306 => Some(Property::EnvelopeTo),
            138 => Some(Property::Environment),
            248 => Some(Property::ErrorCommand),
            247 => Some(Property::ErrorMessage),
            246 => Some(Property::ErrorType),
            287 => Some(Property::Errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            867 => Some(Property::EscalateBelow),
            #[cfg(feature = "enterprise")]
            868 => Some(Property::EscalateOn),
            // SPDX-SnippetEnd
            302 => Some(Property::EvaluatedDisposition),
            303 => Some(Property::EvaluatedDkim),
            304 => Some(Property::EvaluatedSpf),
            448 => Some(Property::Event),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            50 => Some(Property::EventAlert),
            // SPDX-SnippetEnd
            941 => Some(Property::EventEnd),
            943 => Some(Property::EventEndTz),
            939 => Some(Property::EventId),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            57 => Some(Property::EventMessage),
            // SPDX-SnippetEnd
            532 => Some(Property::EventSourceThrottle),
            940 => Some(Property::EventStart),
            942 => Some(Property::EventStartTz),
            169 => Some(Property::Events),
            996 => Some(Property::EventsPolicy),
            255 => Some(Property::Expire),
            745 => Some(Property::Expires),
            61 => Some(Property::ExpiresAt),
            735 => Some(Property::ExpiresAttempts),
            609 => Some(Property::Expiry),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            851 => Some(Property::Explanation),
            // SPDX-SnippetEnd
            617 => Some(Property::Expn),
            236 => Some(Property::ExpungeSchedule),
            235 => Some(Property::ExpungeSchedulingInboxAfter),
            234 => Some(Property::ExpungeShareNotifyAfter),
            233 => Some(Property::ExpungeSubmissionsAfter),
            232 => Some(Property::ExpungeTrashAfter),
            896 => Some(Property::Extension),
            297 => Some(Property::Extensions),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            472 => Some(Property::ExternalId),
            // SPDX-SnippetEnd
            283 => Some(Property::ExtraContactInfo),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            35 => Some(Property::ExtraParameters),
            // SPDX-SnippetEnd
            962 => Some(Property::Factor),
            579 => Some(Property::FailOnTimeout),
            968 => Some(Property::FailedAt),
            969 => Some(Property::FailedAttemptNumber),
            979 => Some(Property::FailedSessionCount),
            992 => Some(Property::FailureDetails),
            321 => Some(Property::FailureDkimSignDomain),
            318 => Some(Property::FailureFromAddress),
            319 => Some(Property::FailureFromName),
            970 => Some(Property::FailureReason),
            981 => Some(Property::FailureReasonCode),
            320 => Some(Property::FailureSendFrequency),
            322 => Some(Property::FailureSubject),
            880 => Some(Property::FeatureL2Normalize),
            881 => Some(Property::FeatureLogScale),
            81 => Some(Property::FeedbackType),
            485 => Some(Property::FieldEmail),
            486 => Some(Property::FieldHoneyPot),
            488 => Some(Property::FieldName),
            490 => Some(Property::FieldSubject),
            790 => Some(Property::FilePath),
            171 => Some(Property::Files),
            556 => Some(Property::FilterLogin),
            558 => Some(Property::FilterMemberOf),
            557 => Some(Property::FilterRecipient),
            395 => Some(Property::Fingerprint),
            972 => Some(Property::FirstFailedAt),
            697 => Some(Property::FirstParty),
            263 => Some(Property::Flags),
            632 => Some(Property::FlagsAction),
            633 => Some(Property::FlagsProtocol),
            144 => Some(Property::FlushChanges),
            145 => Some(Property::FlushInterval),
            410 => Some(Property::FolderId),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            574 => Some(Property::ForDomain),
            // SPDX-SnippetEnd
            493 => Some(Property::Format),
            480 => Some(Property::ForwardedHops),
            76 => Some(Property::From),
            53 => Some(Property::FromAddress),
            54 => Some(Property::FromName),
            618 => Some(Property::FutureRelease),
            151 => Some(Property::GenerateDkimKeys),
            703 => Some(Property::Generation),
            298 => Some(Property::Generator),
            117 => Some(Property::GeoUrls),
            699 => Some(Property::GrantTypes),
            605 => Some(Property::GreetingTimeout),
            905 => Some(Property::GreylistFor),
            566 => Some(Property::GroupClass),
            548 => Some(Property::GroupId),
            175 => Some(Property::GroupwareLarge),
            176 => Some(Property::GroupwareLargeTtl),
            308 => Some(Property::HeaderFrom),
            107 => Some(Property::Headers),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            244 => Some(Property::HoldMetricsFor),
            // SPDX-SnippetEnd
            242 => Some(Property::HoldMtaReportsFor),
            872 => Some(Property::HoldSamplesFor),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            243 => Some(Property::HoldTracesFor),
            // SPDX-SnippetEnd
            376 => Some(Property::Host),
            404 => Some(Property::HostedZoneId),
            223 => Some(Property::Hostname),
            547 => Some(Property::Hosts),
            228 => Some(Property::Hour),
            118 => Some(Property::HttpAuth),
            40 => Some(Property::HttpHeaders),
            206 => Some(Property::HttpRsvpEnable),
            207 => Some(Property::HttpRsvpLinkExpiry),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            213 => Some(Property::HttpRsvpTemplate),
            // SPDX-SnippetEnd
            208 => Some(Property::HttpRsvpUrl),
            984 => Some(Property::HttpRua),
            274 => Some(Property::HumanResult),
            948 => Some(Property::ICalendarData),
            1 => Some(Property::Id),
            723 => Some(Property::IdTokenExpiry),
            105 => Some(Property::IdentityAlignment),
            508 => Some(Property::IdleTimeout),
            452 => Some(Property::If),
            589 => Some(Property::ImapServerAdmin),
            588 => Some(Property::ImapServerComment),
            384 => Some(Property::ImpersonateServiceAccount),
            641 => Some(Property::ImplicitTls),
            155 => Some(Property::InMemoryStore),
            758 => Some(Property::InboundReportAddresses),
            759 => Some(Property::InboundReportForwarding),
            84 => Some(Property::Incidents),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            859 => Some(Property::IncludeAttachments),
            #[cfg(feature = "enterprise")]
            857 => Some(Property::IncludeAuth),
            #[cfg(feature = "enterprise")]
            858 => Some(Property::IncludeLinks),
            // SPDX-SnippetEnd
            935 => Some(Property::IncludeSecrets),
            424 => Some(Property::IncludeSource),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            838 => Some(Property::Includes),
            // SPDX-SnippetEnd
            513 => Some(Property::Index),
            108 => Some(Property::IndexAsn),
            109 => Some(Property::IndexAsnName),
            769 => Some(Property::IndexBatchSize),
            772 => Some(Property::IndexCalendar),
            773 => Some(Property::IndexCalendarFields),
            775 => Some(Property::IndexContactFields),
            774 => Some(Property::IndexContacts),
            110 => Some(Property::IndexCountry),
            776 => Some(Property::IndexEmail),
            777 => Some(Property::IndexEmailFields),
            780 => Some(Property::IndexFiles),
            498 => Some(Property::IndexKey),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            778 => Some(Property::IndexTelemetry),
            // SPDX-SnippetEnd
            499 => Some(Property::IndexValue),
            878 => Some(Property::IndicatorParameters),
            963 => Some(Property::InitialDelay),
            264 => Some(Property::InstanceHashes),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            842 => Some(Property::Instructions),
            // SPDX-SnippetEnd
            596 => Some(Property::Interval),
            613 => Some(Property::Intervals),
            714 => Some(Property::IntrospectionAuthMethod),
            712 => Some(Property::IntrospectionClientId),
            713 => Some(Property::IntrospectionClientSecret),
            894 => Some(Property::IpLimit),
            638 => Some(Property::IpLookupStrategy),
            333 => Some(Property::IpRevPtr),
            332 => Some(Property::IpRevResult),
            820 => Some(Property::IsActive),
            897 => Some(Property::IsArchive),
            898 => Some(Property::IsBad),
            947 => Some(Property::IsFromOrganizer),
            580 => Some(Property::IsGlobPattern),
            494 => Some(Property::IsGzipped),
            899 => Some(Property::IsNz),
            659 => Some(Property::IsSenderAllowed),
            917 => Some(Property::IsSpam),
            883 => Some(Property::IsTls),
            219 => Some(Property::Issuer),
            18 => Some(Property::IssuerDomainNames),
            705 => Some(Property::IssuerUrl),
            965 => Some(Property::Jitter),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            46 => Some(Property::KeepAlive),
            // SPDX-SnippetEnd
            375 => Some(Property::Key),
            406 => Some(Property::KeyName),
            141 => Some(Property::KeyPrefix),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            994 => Some(Property::KeyValues),
            // SPDX-SnippetEnd
            467 => Some(Property::L1Ratio),
            468 => Some(Property::L2Ratio),
            224 => Some(Property::LastRenewal),
            702 => Some(Property::LastUsedAt),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            863 => Some(Property::Learn),
            // SPDX-SnippetEnd
            869 => Some(Property::LearnHamFromCard),
            877 => Some(Property::LearnHamFromReply),
            870 => Some(Property::LearnSpamFromRblHits),
            871 => Some(Property::LearnSpamFromTraps),
            718 => Some(Property::LenientIssuerMatch),
            449 => Some(Property::Level),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            447 => Some(Property::LicenseKey),
            // SPDX-SnippetEnd
            358 => Some(Property::Line),
            221 => Some(Property::ListenerIds),
            226 => Some(Property::Listeners),
            600 => Some(Property::LocalIp),
            601 => Some(Property::LocalIps),
            7 => Some(Property::Locale),
            412 => Some(Property::Logo),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            45 => Some(Property::Logprobs),
            // SPDX-SnippetEnd
            796 => Some(Property::LoiterBanPeriod),
            795 => Some(Property::LoiterBanRate),
            995 => Some(Property::Lossy),
            460 => Some(Property::MachineId),
            932 => Some(Property::MailExchangers),
            326 => Some(Property::MailFrom),
            884 => Some(Property::MailFromParameters),
            606 => Some(Property::MailFromTimeout),
            983 => Some(Property::MailRua),
            185 => Some(Property::MailingLists),
            936 => Some(Property::MaintenanceType),
            382 => Some(Property::ManagedZone),
            450 => Some(Property::Match),
            146 => Some(Property::MaxAccountSize),
            27 => Some(Property::MaxAddressBooks),
            30 => Some(Property::MaxAddressBooksPerCard),
            661 => Some(Property::MaxAge),
            314 => Some(Property::MaxAggregateReportSize),
            671 => Some(Property::MaxAllowedPacket),
            130 => Some(Property::MaxApiKeys),
            129 => Some(Property::MaxAppPasswords),
            425 => Some(Property::MaxAttachmentSize),
            912 => Some(Property::MaxAttachmentText),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            855 => Some(Property::MaxAttachments),
            // SPDX-SnippetEnd
            202 => Some(Property::MaxAttachmentsSize),
            608 => Some(Property::MaxAttempts),
            191 => Some(Property::MaxAttendees),
            503 => Some(Property::MaxAuthFailures),
            200 => Some(Property::MaxAvailabilityDuration),
            911 => Some(Property::MaxBodyText),
            930 => Some(Property::MaxBufferedMemory),
            194 => Some(Property::MaxCalendars),
            198 => Some(Property::MaxCalendarsPerEvent),
            239 => Some(Property::MaxChangesHistory),
            521 => Some(Property::MaxChangesResults),
            504 => Some(Property::MaxConcurrentConnections),
            779 => Some(Property::MaxConcurrentIndexTasks),
            43 => Some(Property::MaxConcurrentRequests),
            527 => Some(Property::MaxConcurrentUploads),
            694 => Some(Property::MaxConnections),
            28 => Some(Property::MaxContacts),
            815 => Some(Property::MaxCpuCycles),
            964 => Some(Property::MaxDelay),
            585 => Some(Property::MaxDepth),
            627 => Some(Property::MaxDuration),
            495 => Some(Property::MaxEntries),
            496 => Some(Property::MaxEntrySize),
            197 => Some(Property::MaxEventNotifications),
            195 => Some(Property::MaxEvents),
            199 => Some(Property::MaxExpandedQueryDuration),
            786 => Some(Property::MaxExtractArchiveEntries),
            783 => Some(Property::MaxExtractDecompressedSize),
            781 => Some(Property::MaxExtractDocumentSize),
            784 => Some(Property::MaxExtractPartSize),
            785 => Some(Property::MaxExtractParts),
            787 => Some(Property::MaxExtractPdfObjects),
            788 => Some(Property::MaxExtractRtfDepth),
            782 => Some(Property::MaxExtractTextSize),
            642 => Some(Property::MaxFailures),
            454 => Some(Property::MaxFiles),
            441 => Some(Property::MaxFlagLength),
            440 => Some(Property::MaxFlagsPerEmail),
            455 => Some(Property::MaxFolders),
            522 => Some(Property::MaxGetResults),
            443 => Some(Property::MaxHeaderCount),
            442 => Some(Property::MaxHeaderSize),
            193 => Some(Property::MaxICalendarSize),
            435 => Some(Property::MaxIdentities),
            762 => Some(Property::MaxInboundReportSize),
            827 => Some(Property::MaxIncludes),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            853 => Some(Property::MaxInputChars),
            // SPDX-SnippetEnd
            210 => Some(Property::MaxItipSize),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            854 => Some(Property::MaxLinks),
            // SPDX-SnippetEnd
            1008 => Some(Property::MaxLivePropertySize),
            828 => Some(Property::MaxLocalVars),
            1006 => Some(Property::MaxLockTimeout),
            1007 => Some(Property::MaxLocks),
            427 => Some(Property::MaxMailboxDepth),
            428 => Some(Property::MaxMailboxNameLength),
            436 => Some(Property::MaxMailboxes),
            439 => Some(Property::MaxMailboxesPerEmail),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            437 => Some(Property::MaxMaskedAddresses),
            // SPDX-SnippetEnd
            829 => Some(Property::MaxMatchVars),
            31 => Some(Property::MaxMediaSize),
            426 => Some(Property::MaxMessageSize),
            913 => Some(Property::MaxMessageText),
            433 => Some(Property::MaxMessages),
            509 => Some(Property::MaxMessagesPerCommand),
            512 => Some(Property::MaxMessagesPerSave),
            524 => Some(Property::MaxMethodCalls),
            639 => Some(Property::MaxMultihomed),
            640 => Some(Property::MaxMxHosts),
            831 => Some(Property::MaxNestedBlocks),
            832 => Some(Property::MaxNestedForEvery),
            816 => Some(Property::MaxNestedIncludes),
            833 => Some(Property::MaxNestedTests),
            817 => Some(Property::MaxOutMessages),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            32 => Some(Property::MaxOutputTokens),
            // SPDX-SnippetEnd
            196 => Some(Property::MaxParticipantIdentities),
            126 => Some(Property::MaxPasswordLength),
            578 => Some(Property::MaxPolls),
            586 => Some(Property::MaxPrivateSize),
            438 => Some(Property::MaxPublicKeys),
            534 => Some(Property::MaxPushAttempts),
            546 => Some(Property::MaxPushSize),
            523 => Some(Property::MaxQueryResults),
            587 => Some(Property::MaxQueryScan),
            656 => Some(Property::MaxReceivedHeaders),
            211 => Some(Property::MaxRecipients),
            674 => Some(Property::MaxReconnects),
            192 => Some(Property::MaxRecurrenceExpansions),
            914 => Some(Property::MaxRedirectUrls),
            818 => Some(Property::MaxRedirects),
            993 => Some(Property::MaxReportSize),
            505 => Some(Property::MaxRequestSize),
            624 => Some(Property::MaxResponseSize),
            1009 => Some(Property::MaxResults),
            140 => Some(Property::MaxRetries),
            750 => Some(Property::MaxRetryWait),
            830 => Some(Property::MaxScriptNameLength),
            834 => Some(Property::MaxScriptSize),
            837 => Some(Property::MaxScripts),
            525 => Some(Property::MaxSetObjects),
            810 => Some(Property::MaxShares),
            115 => Some(Property::MaxSize),
            526 => Some(Property::MaxSnippetResults),
            835 => Some(Property::MaxStringLength),
            434 => Some(Property::MaxSubmissions),
            543 => Some(Property::MaxSubscriptions),
            511 => Some(Property::MaxUidBatches),
            529 => Some(Property::MaxUploadCount),
            528 => Some(Property::MaxUploadSize),
            26 => Some(Property::MaxVCardSize),
            836 => Some(Property::MaxVarNameLength),
            819 => Some(Property::MaxVarSize),
            953 => Some(Property::MemberGroupIds),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            21 => Some(Property::MemberTenantId),
            // SPDX-SnippetEnd
            106 => Some(Property::Message),
            812 => Some(Property::MessageIdHostname),
            959 => Some(Property::MessageIds),
            549 => Some(Property::MessageTimeout),
            172 => Some(Property::Messages),
            173 => Some(Property::MessagesLarge),
            174 => Some(Property::MessagesLargeTtl),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            590 => Some(Property::Metric),
            // SPDX-SnippetEnd
            594 => Some(Property::Metrics),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            245 => Some(Property::MetricsCollectionInterval),
            // SPDX-SnippetEnd
            595 => Some(Property::MetricsPolicy),
            147 => Some(Property::MinAccountSize),
            873 => Some(Property::MinHamSamples),
            125 => Some(Property::MinPasswordLength),
            127 => Some(Property::MinPasswordStrength),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            839 => Some(Property::MinProbability),
            // SPDX-SnippetEnd
            751 => Some(Property::MinRetryWait),
            874 => Some(Property::MinSpamSamples),
            204 => Some(Property::MinTriggerInterval),
            510 => Some(Property::MinUidBatchSize),
            229 => Some(Property::Minute),
            662 => Some(Property::Mode),
            37 => Some(Property::Model),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            866 => Some(Property::ModelId),
            // SPDX-SnippetEnd
            619 => Some(Property::MtPriority),
            665 => Some(Property::MtaSts),
            667 => Some(Property::MtaStsTimeout),
            1000 => Some(Property::Multiline),
            645 => Some(Property::MustMatchSender),
            663 => Some(Property::MxHosts),
            36 => Some(Property::Name),
            492 => Some(Property::Namespace),
            187 => Some(Property::NegativeTtl),
            736 => Some(Property::NextNotify),
            517 => Some(Property::NextRetry),
            261 => Some(Property::NextTransitionAt),
            813 => Some(Property::NoCapabilityCheck),
            680 => Some(Property::NoEcho),
            620 => Some(Property::NoSoliciting),
            222 => Some(Property::NodeId),
            217 => Some(Property::NotValidAfter),
            218 => Some(Property::NotValidBefore),
            610 => Some(Property::Notify),
            743 => Some(Property::NotifyCount),
            744 => Some(Property::NotifyDue),
            466 => Some(Property::NumFeatures),
            422 => Some(Property::NumReplicas),
            423 => Some(Property::NumShards),
            68 => Some(Property::OauthClientId),
            967 => Some(Property::ObjectType),
            955 => Some(Property::OnSuccessRenewCertificate),
            711 => Some(Property::OpaqueTokenValidation),
            592 => Some(Property::OpenTelemetry),
            733 => Some(Property::Options),
            747 => Some(Property::Orcpt),
            281 => Some(Property::OrgName),
            985 => Some(Property::OrganizationName),
            346 => Some(Property::Origin),
            85 => Some(Property::OriginalEnvelopeId),
            86 => Some(Property::OriginalMailFrom),
            87 => Some(Property::OriginalRcptTo),
            5 => Some(Property::OtpAuth),
            728 => Some(Property::OtpCode),
            729 => Some(Property::OtpUrl),
            760 => Some(Property::OutboundReportDomain),
            761 => Some(Property::OutboundReportSubmitter),
            682 => Some(Property::OverrideProxyTrustedNetworks),
            279 => Some(Property::OverrideType),
            402 => Some(Property::OvhEndpoint),
            879 => Some(Property::Parameters),
            519 => Some(Property::ParseLimitContact),
            520 => Some(Property::ParseLimitEmail),
            518 => Some(Property::ParseLimitEvent),
            514 => Some(Property::Partition),
            363 => Some(Property::Password),
            128 => Some(Property::PasswordDefaultExpiry),
            124 => Some(Property::PasswordHashAlgorithm),
            456 => Some(Property::Path),
            704 => Some(Property::Pending),
            748 => Some(Property::Period),
            62 => Some(Property::Permissions),
            676 => Some(Property::PingInterval),
            621 => Some(Property::Pipelining),
            987 => Some(Property::Policies),
            290 => Some(Property::PolicyAdkim),
            291 => Some(Property::PolicyAspf),
            300 => Some(Property::PolicyDiscoveryMethod),
            292 => Some(Property::PolicyDisposition),
            288 => Some(Property::PolicyDomain),
            295 => Some(Property::PolicyFailureReportingOptions),
            277 => Some(Property::PolicyIdentifier),
            982 => Some(Property::PolicyIdentifiers),
            299 => Some(Property::PolicyNp),
            305 => Some(Property::PolicyOverrideReasons),
            989 => Some(Property::PolicyStrings),
            293 => Some(Property::PolicySubdomainDisposition),
            294 => Some(Property::PolicyTestingMode),
            988 => Some(Property::PolicyType),
            289 => Some(Property::PolicyVersion),
            360 => Some(Property::PollInterval),
            567 => Some(Property::PoolMaxConnections),
            672 => Some(Property::PoolMinConnections),
            734 => Some(Property::PoolRecyclingMethod),
            568 => Some(Property::PoolTimeoutCreate),
            569 => Some(Property::PoolTimeoutRecycle),
            570 => Some(Property::PoolTimeoutWait),
            765 => Some(Property::PoolWorkers),
            344 => Some(Property::Port),
            696 => Some(Property::PostLogoutRedirectUris),
            22 => Some(Property::PreferredChain),
            997 => Some(Property::Prefix),
            350 => Some(Property::PreserveIntermediates),
            572 => Some(Property::Priority),
            215 => Some(Property::PrivateKey),
            397 => Some(Property::PrivateKeyPassword),
            396 => Some(Property::PrivateKeyPem),
            584 => Some(Property::PrivateMetadata),
            383 => Some(Property::PrivateZone),
            405 => Some(Property::PrivateZoneOnly),
            47 => Some(Property::Profile),
            381 => Some(Property::ProjectId),
            593 => Some(Property::Prometheus),
            362 => Some(Property::PropagationDelay),
            361 => Some(Property::PropagationTimeout),
            825 => Some(Property::ProtectedHeaders),
            343 => Some(Property::Protocol),
            630 => Some(Property::ProtocolVersion),
            934 => Some(Property::ProviderInfo),
            931 => Some(Property::ProxyTrustedNetworks),
            256 => Some(Property::PublicKey),
            347 => Some(Property::PublishRecords),
            533 => Some(Property::PushAttemptWait),
            537 => Some(Property::PushRequestTimeout),
            535 => Some(Property::PushRetryWait),
            539 => Some(Property::PushShardsTotal),
            536 => Some(Property::PushThrottle),
            538 => Some(Property::PushVerifyTimeout),
            926 => Some(Property::QueryEmailAliases),
            923 => Some(Property::QueryLogin),
            925 => Some(Property::QueryMemberOf),
            924 => Some(Property::QueryRecipient),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            865 => Some(Property::Question),
            // SPDX-SnippetEnd
            611 => Some(Property::QueueId),
            746 => Some(Property::QueueName),
            516 => Some(Property::QueuedDeletions),
            515 => Some(Property::QueuedUpdates),
            470 => Some(Property::Quotas),
            629 => Some(Property::Rate),
            44 => Some(Property::RateLimit),
            474 => Some(Property::RateLimitAnonymous),
            473 => Some(Property::RateLimitAuthenticated),
            902 => Some(Property::Ratio),
            327 => Some(Property::RcptTo),
            607 => Some(Property::RcptToTimeout),
            678 => Some(Property::ReadBufferCapacity),
            752 => Some(Property::ReadFromReplicas),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            673 => Some(Property::ReadReplicas),
            // SPDX-SnippetEnd
            59 => Some(Property::Reason),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            34 => Some(Property::Reasoning),
            // SPDX-SnippetEnd
            77 => Some(Property::ReceivedAt),
            738 => Some(Property::ReceivedFromIp),
            739 => Some(Property::ReceivedViaPort),
            978 => Some(Property::ReceivingIp),
            977 => Some(Property::ReceivingMxHelo),
            976 => Some(Property::ReceivingMxHostname),
            573 => Some(Property::Recipients),
            296 => Some(Property::Records),
            945 => Some(Property::RecurrenceId),
            916 => Some(Property::RedirectCacheTtl),
            481 => Some(Property::RedirectRoot),
            915 => Some(Property::RedirectTimeout),
            695 => Some(Property::RedirectUris),
            114 => Some(Property::RefreshInterval),
            720 => Some(Property::RefreshTokenExpiry),
            356 => Some(Property::Region),
            658 => Some(Property::RejectNonFqdn),
            324 => Some(Property::RemoteIp),
            20 => Some(Property::RenewBefore),
            80 => Some(Property::Report),
            420 => Some(Property::ReportAddressUri),
            284 => Some(Property::ReportId),
            88 => Some(Property::ReportedDomains),
            89 => Some(Property::ReportedUris),
            90 => Some(Property::ReportingMta),
            675 => Some(Property::RequestTimeout),
            150 => Some(Property::RequestTlsCertificate),
            646 => Some(Property::Require),
            622 => Some(Property::RequireTls),
            875 => Some(Property::ReservoirCapacity),
            1014 => Some(Property::ResourceAttributes),
            366 => Some(Property::ResourceGroup),
            64 => Some(Property::ResourceUrl),
            250 => Some(Property::ResponseCode),
            251 => Some(Property::ResponseEnhanced),
            478 => Some(Property::ResponseHeaders),
            249 => Some(Property::ResponseHostname),
            252 => Some(Property::ResponseMessage),
            273 => Some(Property::Result),
            974 => Some(Property::ResultType),
            143 => Some(Property::Retention),
            268 => Some(Property::RetireAfter),
            497 => Some(Property::Retry),
            741 => Some(Property::RetryCount),
            742 => Some(Property::RetryDue),
            737 => Some(Property::ReturnPath),
            23 => Some(Property::ReuseKey),
            806 => Some(Property::ReverseIpVerify),
            660 => Some(Property::Rewrite),
            231 => Some(Property::RoleIds),
            183 => Some(Property::Roles),
            998 => Some(Property::Rotate),
            267 => Some(Property::RotateAfter),
            635 => Some(Property::Route),
            276 => Some(Property::Rua),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            840 => Some(Property::SampleRate),
            // SPDX-SnippetEnd
            389 => Some(Property::Sandbox),
            134 => Some(Property::SasToken),
            644 => Some(Property::SaslMechanisms),
            797 => Some(Property::ScanBanPaths),
            799 => Some(Property::ScanBanPeriod),
            798 => Some(Property::ScanBanRate),
            636 => Some(Property::Schedule),
            170 => Some(Property::Scheduling),
            409 => Some(Property::Scheme),
            323 => Some(Property::Scope),
            698 => Some(Property::Scopes),
            885 => Some(Property::Score),
            906 => Some(Property::ScoreDiscard),
            907 => Some(Property::ScoreReject),
            908 => Some(Property::ScoreSpam),
            648 => Some(Property::Script),
            154 => Some(Property::SearchStore),
            3 => Some(Property::Secret),
            355 => Some(Property::SecretKey),
            260 => Some(Property::Selector),
            266 => Some(Property::SelectorTemplate),
            270 => Some(Property::SendFrequency),
            975 => Some(Property::SendingMtaIp),
            755 => Some(Property::SentinelSecret),
            754 => Some(Property::SentinelUsername),
            111 => Some(Property::Separator),
            403 => Some(Property::ServerId),
            352 => Some(Property::Servers),
            380 => Some(Property::ServiceAccountJson),
            753 => Some(Property::ServiceName),
            1013 => Some(Property::ServiceNamespace),
            933 => Some(Property::Services),
            550 => Some(Property::SessionTimeout),
            357 => Some(Property::SessionToken),
            973 => Some(Property::ShardIndex),
            388 => Some(Property::SharedSecret),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            844 => Some(Property::Signals),
            // SPDX-SnippetEnd
            725 => Some(Property::SignatureAlgorithm),
            726 => Some(Property::SignatureKey),
            78 => Some(Property::Size),
            716 => Some(Property::SkipAudienceValidation),
            369 => Some(Property::SkipDeploy),
            500 => Some(Property::SkipFirst),
            647 => Some(Property::SmtpGreeting),
            683 => Some(Property::SocketBacklog),
            684 => Some(Property::SocketNoDelay),
            685 => Some(Property::SocketReceiveBufferSize),
            686 => Some(Property::SocketReuseAddress),
            687 => Some(Property::SocketReusePort),
            688 => Some(Property::SocketSendBufferSize),
            689 => Some(Property::SocketTosV4),
            690 => Some(Property::SocketTtl),
            91 => Some(Property::SourceIp),
            92 => Some(Property::SourcePort),
            910 => Some(Property::SpamFilterRulesUrl),
            166 => Some(Property::SpamLookup),
            104 => Some(Property::SpfDns),
            328 => Some(Property::SpfEhloDomain),
            329 => Some(Property::SpfEhloResult),
            802 => Some(Property::SpfEhloVerify),
            803 => Some(Property::SpfFromVerify),
            330 => Some(Property::SpfMailFromDomain),
            331 => Some(Property::SpfMailFromResult),
            310 => Some(Property::SpfResults),
            262 => Some(Property::Stage),
            626 => Some(Property::Stages),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            70 => Some(Property::StartTime),
            // SPDX-SnippetEnd
            666 => Some(Property::StartTls),
            75 => Some(Property::Status),
            136 => Some(Property::StorageAccount),
            142 => Some(Property::Store),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            808 => Some(Property::Stores),
            // SPDX-SnippetEnd
            956 => Some(Property::Strategy),
            418 => Some(Property::SubAddressing),
            371 => Some(Property::SubAuthId),
            55 => Some(Property::Subject),
            216 => Some(Property::SubjectAlternativeNames),
            445 => Some(Property::Subscribe),
            679 => Some(Property::SubscriptionCapacity),
            365 => Some(Property::SubscriptionId),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            591 => Some(Property::Sum),
            // SPDX-SnippetEnd
            949 => Some(Property::Summary),
            771 => Some(Property::SupportedLanguages),
            190 => Some(Property::Swap),
            891 => Some(Property::Tag),
            886 => Some(Property::Tags),
            944 => Some(Property::TargetAccountId),
            227 => Some(Property::TaskTypes),
            225 => Some(Property::Tasks),
            351 => Some(Property::TcpOnError),
            408 => Some(Property::TeamId),
            625 => Some(Property::TempFailOnError),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            33 => Some(Property::Temperature),
            #[cfg(feature = "enterprise")]
            205 => Some(Property::Template),
            // SPDX-SnippetEnd
            393 => Some(Property::TenancyOcid),
            131 => Some(Property::TenantId),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            184 => Some(Property::Tenants),
            // SPDX-SnippetEnd
            2 => Some(Property::Text),
            453 => Some(Property::Then),
            257 => Some(Property::ThirdParty),
            258 => Some(Property::ThirdPartyHash),
            958 => Some(Property::ThreadName),
            669 => Some(Property::ThreadsPerNode),
            1003 => Some(Property::Throttle),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            841 => Some(Property::Tiers),
            // SPDX-SnippetEnd
            8 => Some(Property::TimeZone),
            42 => Some(Property::Timeout),
            571 => Some(Property::Timestamp),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            69 => Some(Property::Title),
            // SPDX-SnippetEnd
            637 => Some(Property::Tls),
            691 => Some(Property::TlsDisableCipherSuites),
            692 => Some(Property::TlsDisableProtocols),
            693 => Some(Property::TlsIgnoreClientOrder),
            668 => Some(Property::TlsTimeout),
            56 => Some(Property::To),
            373 => Some(Property::Token),
            135 => Some(Property::TokenFile),
            991 => Some(Property::TotalFailedSessions),
            990 => Some(Property::TotalSuccessfulSessions),
            156 => Some(Property::Tracer),
            876 => Some(Property::TrainInterval),
            461 => Some(Property::TransactionRetryDelay),
            462 => Some(Property::TransactionRetryLimit),
            463 => Some(Property::TransactionTimeout),
            628 => Some(Property::TransferLimit),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            856 => Some(Property::TrimQuotes),
            // SPDX-SnippetEnd
            904 => Some(Property::TrustContacts),
            909 => Some(Property::TrustReplies),
            407 => Some(Property::TsigAlgorithm),
            359 => Some(Property::Ttl),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            847 => Some(Property::UncertainBelow),
            // SPDX-SnippetEnd
            67 => Some(Property::UnpackDirectory),
            715 => Some(Property::UnscopedTokens),
            954 => Some(Property::UpdateRecords),
            530 => Some(Property::UploadQuota),
            531 => Some(Property::UploadTtl),
            38 => Some(Property::Url),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            551 => Some(Property::UrlFailover),
            // SPDX-SnippetEnd
            895 => Some(Property::UrlLimit),
            65 => Some(Property::UrlPrefix),
            749 => Some(Property::Urls),
            477 => Some(Property::UsePermissiveCors),
            353 => Some(Property::UseTls),
            471 => Some(Property::UsedDiskQuota),
            93 => Some(Property::UserAgent),
            722 => Some(Property::UserCodeExpiry),
            394 => Some(Property::UserOcid),
            158 => Some(Property::Username),
            707 => Some(Property::UsernameDomain),
            29 => Some(Property::VCardVersion),
            491 => Some(Property::ValidateDomain),
            581 => Some(Property::Value),
            789 => Some(Property::VariableName),
            583 => Some(Property::VendorNamespaces),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            848 => Some(Property::VerbalHigh),
            #[cfg(feature = "enterprise")]
            850 => Some(Property::VerbalLow),
            #[cfg(feature = "enterprise")]
            849 => Some(Property::VerbalMedium),
            // SPDX-SnippetEnd
            768 => Some(Property::VerifyAfterWrite),
            94 => Some(Property::Version),
            368 => Some(Property::ViewName),
            623 => Some(Property::Vrfy),
            643 => Some(Property::WaitOnFail),
            386 => Some(Property::WapiVersion),
            757 => Some(Property::Warnings),
            545 => Some(Property::WebPushContact),
            544 => Some(Property::WebPushKey),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            864 => Some(Property::WebSearch),
            // SPDX-SnippetEnd
            540 => Some(Property::WebsocketHeartbeat),
            541 => Some(Property::WebsocketThrottle),
            542 => Some(Property::WebsocketTimeout),
            960 => Some(Property::WindowEnd),
            501 => Some(Property::Zone),
            112 => Some(Property::ZoneIpV4),
            113 => Some(Property::ZoneIpV6),
            _ => None,
        }
    }

    const COUNT: usize = 1015;
}

impl serde::Serialize for Property {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Property {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}

impl ObjectType {
    pub fn flags(&self) -> u64 {
        match self {
            ObjectType::Account => Account::FLAGS,
            ObjectType::AccountPassword => AccountPassword::FLAGS,
            ObjectType::AccountSettings => AccountSettings::FLAGS,
            ObjectType::AcmeProvider => AcmeProvider::FLAGS,
            ObjectType::Action => Action::FLAGS,
            ObjectType::AddressBook => AddressBook::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => AiModel::FLAGS,
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => Alert::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => AllowedIp::FLAGS,
            ObjectType::ApiKey => ApiKey::FLAGS,
            ObjectType::AppPassword => AppPassword::FLAGS,
            ObjectType::Application => Application::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => ArchivedItem::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => ArfExternalReport::FLAGS,
            ObjectType::Asn => Asn::FLAGS,
            ObjectType::Authentication => Authentication::FLAGS,
            ObjectType::BlobStore => BlobStore::FLAGS,
            ObjectType::BlockedIp => BlockedIp::FLAGS,
            ObjectType::Bootstrap => Bootstrap::FLAGS,
            ObjectType::Cache => Cache::FLAGS,
            ObjectType::Calendar => Calendar::FLAGS,
            ObjectType::CalendarAlarm => CalendarAlarm::FLAGS,
            ObjectType::CalendarScheduling => CalendarScheduling::FLAGS,
            ObjectType::Certificate => Certificate::FLAGS,
            ObjectType::ClusterNode => ClusterNode::FLAGS,
            ObjectType::ClusterRole => ClusterRole::FLAGS,
            ObjectType::Coordinator => Coordinator::FLAGS,
            ObjectType::DataRetention => DataRetention::FLAGS,
            ObjectType::DataStore => DataStore::FLAGS,
            ObjectType::Directory => Directory::FLAGS,
            ObjectType::DkimReportSettings => DkimReportSettings::FLAGS,
            ObjectType::DkimSignature => DkimSignature::FLAGS,
            ObjectType::DmarcExternalReport => DmarcExternalReport::FLAGS,
            ObjectType::DmarcInternalReport => DmarcInternalReport::FLAGS,
            ObjectType::DmarcReportSettings => DmarcReportSettings::FLAGS,
            ObjectType::DnsResolver => DnsResolver::FLAGS,
            ObjectType::DnsServer => DnsServer::FLAGS,
            ObjectType::Domain => Domain::FLAGS,
            ObjectType::DsnReportSettings => DsnReportSettings::FLAGS,
            ObjectType::Email => Email::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => Enterprise::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => EventTracingLevel::FLAGS,
            ObjectType::FileStorage => FileStorage::FLAGS,
            ObjectType::Http => Http::FLAGS,
            ObjectType::HttpForm => HttpForm::FLAGS,
            ObjectType::HttpLookup => HttpLookup::FLAGS,
            ObjectType::Imap => Imap::FLAGS,
            ObjectType::InMemoryStore => InMemoryStore::FLAGS,
            ObjectType::IndexQueueStatus => IndexQueueStatus::FLAGS,
            ObjectType::Jmap => Jmap::FLAGS,
            ObjectType::Log => Log::FLAGS,
            ObjectType::MailingList => MailingList::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => MaskedEmail::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => MemoryLookupKey::FLAGS,
            ObjectType::MemoryLookupKeyValue => MemoryLookupKeyValue::FLAGS,
            ObjectType::Metadata => Metadata::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => Metric::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::Metrics => Metrics::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => MetricsStore::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => MtaConnectionStrategy::FLAGS,
            ObjectType::MtaDeliverySchedule => MtaDeliverySchedule::FLAGS,
            ObjectType::MtaExtensions => MtaExtensions::FLAGS,
            ObjectType::MtaHook => MtaHook::FLAGS,
            ObjectType::MtaInboundSession => MtaInboundSession::FLAGS,
            ObjectType::MtaInboundThrottle => MtaInboundThrottle::FLAGS,
            ObjectType::MtaMilter => MtaMilter::FLAGS,
            ObjectType::MtaOutboundStrategy => MtaOutboundStrategy::FLAGS,
            ObjectType::MtaOutboundThrottle => MtaOutboundThrottle::FLAGS,
            ObjectType::MtaQueueQuota => MtaQueueQuota::FLAGS,
            ObjectType::MtaRoute => MtaRoute::FLAGS,
            ObjectType::MtaStageAuth => MtaStageAuth::FLAGS,
            ObjectType::MtaStageConnect => MtaStageConnect::FLAGS,
            ObjectType::MtaStageData => MtaStageData::FLAGS,
            ObjectType::MtaStageEhlo => MtaStageEhlo::FLAGS,
            ObjectType::MtaStageMail => MtaStageMail::FLAGS,
            ObjectType::MtaStageRcpt => MtaStageRcpt::FLAGS,
            ObjectType::MtaSts => MtaSts::FLAGS,
            ObjectType::MtaTlsStrategy => MtaTlsStrategy::FLAGS,
            ObjectType::MtaVirtualQueue => MtaVirtualQueue::FLAGS,
            ObjectType::NetworkListener => NetworkListener::FLAGS,
            ObjectType::OAuthClient => OAuthClient::FLAGS,
            ObjectType::OAuthGrant => OAuthGrant::FLAGS,
            ObjectType::OidcProvider => OidcProvider::FLAGS,
            ObjectType::PublicKey => PublicKey::FLAGS,
            ObjectType::QueuedMessage => QueuedMessage::FLAGS,
            ObjectType::ReportSettings => ReportSettings::FLAGS,
            ObjectType::Role => Role::FLAGS,
            ObjectType::Search => Search::FLAGS,
            ObjectType::SearchStore => SearchStore::FLAGS,
            ObjectType::Security => Security::FLAGS,
            ObjectType::SenderAuth => SenderAuth::FLAGS,
            ObjectType::Sharing => Sharing::FLAGS,
            ObjectType::SieveSystemInterpreter => SieveSystemInterpreter::FLAGS,
            ObjectType::SieveSystemScript => SieveSystemScript::FLAGS,
            ObjectType::SieveUserInterpreter => SieveUserInterpreter::FLAGS,
            ObjectType::SieveUserScript => SieveUserScript::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => SpamAi::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => SpamClassifier::FLAGS,
            ObjectType::SpamDnsblServer => SpamDnsblServer::FLAGS,
            ObjectType::SpamDnsblSettings => SpamDnsblSettings::FLAGS,
            ObjectType::SpamFileExtension => SpamFileExtension::FLAGS,
            ObjectType::SpamPyzor => SpamPyzor::FLAGS,
            ObjectType::SpamRule => SpamRule::FLAGS,
            ObjectType::SpamSettings => SpamSettings::FLAGS,
            ObjectType::SpamTag => SpamTag::FLAGS,
            ObjectType::SpamTrainingSample => SpamTrainingSample::FLAGS,
            ObjectType::SpfReportSettings => SpfReportSettings::FLAGS,
            ObjectType::StoreLookup => StoreLookup::FLAGS,
            ObjectType::SystemSettings => SystemSettings::FLAGS,
            ObjectType::Task => Task::FLAGS,
            ObjectType::TaskManager => TaskManager::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => Tenant::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => TlsExternalReport::FLAGS,
            ObjectType::TlsInternalReport => TlsInternalReport::FLAGS,
            ObjectType::TlsReportSettings => TlsReportSettings::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => Trace::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::Tracer => Tracer::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => TracingStore::FLAGS,
            // SPDX-SnippetEnd
            ObjectType::WebDav => WebDav::FLAGS,
            ObjectType::WebHook => WebHook::FLAGS,
        }
    }

    pub fn indexes(&self) -> Vec<IndexSchema> {
        match self {
            ObjectType::Account => vec![
                IndexSchema::new(
                    Property::Text,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Text,
                ),
                IndexSchema::new(
                    Property::Type,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Enum,
                ),
                IndexSchema::new(
                    Property::DomainId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::ExternalId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Keyword,
                ),
                // SPDX-SnippetEnd
                IndexSchema::new(
                    Property::MemberGroupIds,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
                IndexSchema::new(
                    Property::Name,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Keyword,
                ),
            ],
            ObjectType::AcmeProvider => vec![
                IndexSchema::new(
                    Property::Text,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Text,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
            ],
            ObjectType::AllowedIp => vec![IndexSchema::new(
                Property::Address,
                IndexSchemaType::Unique,
                IndexSchemaValueType::IpMask,
            )],
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => vec![IndexSchema::new(
                Property::AccountId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
            // SPDX-SnippetEnd
            ObjectType::BlockedIp => vec![IndexSchema::new(
                Property::Address,
                IndexSchemaType::Unique,
                IndexSchemaValueType::IpMask,
            )],
            ObjectType::Certificate => vec![IndexSchema::new(
                Property::SubjectAlternativeNames,
                IndexSchemaType::Search,
                IndexSchemaValueType::Text,
            )],
            ObjectType::ClusterRole => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::Directory => vec![
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
            ],
            ObjectType::DkimSignature => vec![
                IndexSchema::new(
                    Property::DomainId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
            ],
            ObjectType::DnsServer => vec![
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
            ],
            ObjectType::Domain => vec![
                IndexSchema::new(
                    Property::Text,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Text,
                ),
                IndexSchema::new(
                    Property::Aliases,
                    IndexSchemaType::Unique,
                    IndexSchemaValueType::Keyword,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
                IndexSchema::new(
                    Property::Name,
                    IndexSchemaType::Unique,
                    IndexSchemaValueType::Keyword,
                ),
            ],
            ObjectType::MailingList => vec![
                IndexSchema::new(
                    Property::Text,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Text,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
            ],
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => vec![IndexSchema::new(
                Property::AccountId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => vec![IndexSchema::new(
                Property::Namespace,
                IndexSchemaType::Search,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::MemoryLookupKeyValue => vec![IndexSchema::new(
                Property::Namespace,
                IndexSchemaType::Search,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::MtaConnectionStrategy => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::MtaDeliverySchedule => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::MtaRoute => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::MtaTlsStrategy => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::MtaVirtualQueue => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::NetworkListener => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::OAuthClient => vec![
                IndexSchema::new(
                    Property::Text,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Text,
                ),
                IndexSchema::new(
                    Property::ClientId,
                    IndexSchemaType::Unique,
                    IndexSchemaValueType::Keyword,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
            ],
            ObjectType::OAuthGrant => vec![
                IndexSchema::new(
                    Property::AccountId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                IndexSchema::new(
                    Property::ClientHash,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Keyword,
                ),
            ],
            ObjectType::PublicKey => vec![IndexSchema::new(
                Property::AccountId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
            ObjectType::Role => vec![
                IndexSchema::new(
                    Property::Description,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Text,
                ),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                // SPDX-SnippetEnd
            ],
            ObjectType::SieveSystemScript => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::SieveUserScript => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::SpamDnsblServer => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::SpamFileExtension => vec![IndexSchema::new(
                Property::Extension,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::SpamRule => vec![IndexSchema::new(
                Property::Name,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::SpamTag => vec![IndexSchema::new(
                Property::Tag,
                IndexSchemaType::Unique,
                IndexSchemaValueType::Keyword,
            )],
            ObjectType::SpamTrainingSample => vec![IndexSchema::new(
                Property::AccountId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => vec![IndexSchema::new(
                Property::Text,
                IndexSchemaType::Search,
                IndexSchemaValueType::Text,
            )],
            // SPDX-SnippetEnd
            _ => vec![],
        }
    }

    pub fn get_permission(&self) -> Permission {
        match self {
            ObjectType::Account => Permission::SysAccountGet,
            ObjectType::AccountPassword => Permission::SysAccountPasswordGet,
            ObjectType::AccountSettings => Permission::SysAccountSettingsGet,
            ObjectType::AcmeProvider => Permission::SysAcmeProviderGet,
            ObjectType::Action => unreachable!(),
            ObjectType::AddressBook => Permission::SysAddressBookGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => Permission::SysAiModelGet,
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => Permission::SysAlertGet,
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => Permission::SysAllowedIpGet,
            ObjectType::ApiKey => Permission::SysApiKeyGet,
            ObjectType::AppPassword => Permission::SysAppPasswordGet,
            ObjectType::Application => Permission::SysApplicationGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => Permission::SysArchivedItemGet,
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => Permission::SysArfExternalReportGet,
            ObjectType::Asn => Permission::SysAsnGet,
            ObjectType::Authentication => Permission::SysAuthenticationGet,
            ObjectType::BlobStore => Permission::SysBlobStoreGet,
            ObjectType::BlockedIp => Permission::SysBlockedIpGet,
            ObjectType::Bootstrap => Permission::SysBootstrapGet,
            ObjectType::Cache => Permission::SysCacheGet,
            ObjectType::Calendar => Permission::SysCalendarGet,
            ObjectType::CalendarAlarm => Permission::SysCalendarAlarmGet,
            ObjectType::CalendarScheduling => Permission::SysCalendarSchedulingGet,
            ObjectType::Certificate => Permission::SysCertificateGet,
            ObjectType::ClusterNode => Permission::SysClusterNodeGet,
            ObjectType::ClusterRole => Permission::SysClusterRoleGet,
            ObjectType::Coordinator => Permission::SysCoordinatorGet,
            ObjectType::DataRetention => Permission::SysDataRetentionGet,
            ObjectType::DataStore => Permission::SysDataStoreGet,
            ObjectType::Directory => Permission::SysDirectoryGet,
            ObjectType::DkimReportSettings => Permission::SysDkimReportSettingsGet,
            ObjectType::DkimSignature => Permission::SysDkimSignatureGet,
            ObjectType::DmarcExternalReport => Permission::SysDmarcExternalReportGet,
            ObjectType::DmarcInternalReport => Permission::SysDmarcInternalReportGet,
            ObjectType::DmarcReportSettings => Permission::SysDmarcReportSettingsGet,
            ObjectType::DnsResolver => Permission::SysDnsResolverGet,
            ObjectType::DnsServer => Permission::SysDnsServerGet,
            ObjectType::Domain => Permission::SysDomainGet,
            ObjectType::DsnReportSettings => Permission::SysDsnReportSettingsGet,
            ObjectType::Email => Permission::SysEmailGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => Permission::SysEnterpriseGet,
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => Permission::SysEventTracingLevelGet,
            ObjectType::FileStorage => Permission::SysFileStorageGet,
            ObjectType::Http => Permission::SysHttpGet,
            ObjectType::HttpForm => Permission::SysHttpFormGet,
            ObjectType::HttpLookup => Permission::SysHttpLookupGet,
            ObjectType::Imap => Permission::SysImapGet,
            ObjectType::InMemoryStore => Permission::SysInMemoryStoreGet,
            ObjectType::IndexQueueStatus => Permission::SysIndexQueueStatusGet,
            ObjectType::Jmap => Permission::SysJmapGet,
            ObjectType::Log => Permission::SysLogGet,
            ObjectType::MailingList => Permission::SysMailingListGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => Permission::SysMaskedEmailGet,
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => Permission::SysMemoryLookupKeyGet,
            ObjectType::MemoryLookupKeyValue => Permission::SysMemoryLookupKeyValueGet,
            ObjectType::Metadata => Permission::SysMetadataGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => Permission::SysMetricGet,
            // SPDX-SnippetEnd
            ObjectType::Metrics => Permission::SysMetricsGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => Permission::SysMetricsStoreGet,
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => Permission::SysMtaConnectionStrategyGet,
            ObjectType::MtaDeliverySchedule => Permission::SysMtaDeliveryScheduleGet,
            ObjectType::MtaExtensions => Permission::SysMtaExtensionsGet,
            ObjectType::MtaHook => Permission::SysMtaHookGet,
            ObjectType::MtaInboundSession => Permission::SysMtaInboundSessionGet,
            ObjectType::MtaInboundThrottle => Permission::SysMtaInboundThrottleGet,
            ObjectType::MtaMilter => Permission::SysMtaMilterGet,
            ObjectType::MtaOutboundStrategy => Permission::SysMtaOutboundStrategyGet,
            ObjectType::MtaOutboundThrottle => Permission::SysMtaOutboundThrottleGet,
            ObjectType::MtaQueueQuota => Permission::SysMtaQueueQuotaGet,
            ObjectType::MtaRoute => Permission::SysMtaRouteGet,
            ObjectType::MtaStageAuth => Permission::SysMtaStageAuthGet,
            ObjectType::MtaStageConnect => Permission::SysMtaStageConnectGet,
            ObjectType::MtaStageData => Permission::SysMtaStageDataGet,
            ObjectType::MtaStageEhlo => Permission::SysMtaStageEhloGet,
            ObjectType::MtaStageMail => Permission::SysMtaStageMailGet,
            ObjectType::MtaStageRcpt => Permission::SysMtaStageRcptGet,
            ObjectType::MtaSts => Permission::SysMtaStsGet,
            ObjectType::MtaTlsStrategy => Permission::SysMtaTlsStrategyGet,
            ObjectType::MtaVirtualQueue => Permission::SysMtaVirtualQueueGet,
            ObjectType::NetworkListener => Permission::SysNetworkListenerGet,
            ObjectType::OAuthClient => Permission::SysOAuthClientGet,
            ObjectType::OAuthGrant => Permission::SysOAuthGrantGet,
            ObjectType::OidcProvider => Permission::SysOidcProviderGet,
            ObjectType::PublicKey => Permission::SysPublicKeyGet,
            ObjectType::QueuedMessage => Permission::SysQueuedMessageGet,
            ObjectType::ReportSettings => Permission::SysReportSettingsGet,
            ObjectType::Role => Permission::SysRoleGet,
            ObjectType::Search => Permission::SysSearchGet,
            ObjectType::SearchStore => Permission::SysSearchStoreGet,
            ObjectType::Security => Permission::SysSecurityGet,
            ObjectType::SenderAuth => Permission::SysSenderAuthGet,
            ObjectType::Sharing => Permission::SysSharingGet,
            ObjectType::SieveSystemInterpreter => Permission::SysSieveSystemInterpreterGet,
            ObjectType::SieveSystemScript => Permission::SysSieveSystemScriptGet,
            ObjectType::SieveUserInterpreter => Permission::SysSieveUserInterpreterGet,
            ObjectType::SieveUserScript => Permission::SysSieveUserScriptGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => Permission::SysSpamAiGet,
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => Permission::SysSpamClassifierGet,
            ObjectType::SpamDnsblServer => Permission::SysSpamDnsblServerGet,
            ObjectType::SpamDnsblSettings => Permission::SysSpamDnsblSettingsGet,
            ObjectType::SpamFileExtension => Permission::SysSpamFileExtensionGet,
            ObjectType::SpamPyzor => Permission::SysSpamPyzorGet,
            ObjectType::SpamRule => Permission::SysSpamRuleGet,
            ObjectType::SpamSettings => Permission::SysSpamSettingsGet,
            ObjectType::SpamTag => Permission::SysSpamTagGet,
            ObjectType::SpamTrainingSample => Permission::SysSpamTrainingSampleGet,
            ObjectType::SpfReportSettings => Permission::SysSpfReportSettingsGet,
            ObjectType::StoreLookup => Permission::SysStoreLookupGet,
            ObjectType::SystemSettings => Permission::SysSystemSettingsGet,
            ObjectType::Task => Permission::SysTaskGet,
            ObjectType::TaskManager => Permission::SysTaskManagerGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => Permission::SysTenantGet,
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => Permission::SysTlsExternalReportGet,
            ObjectType::TlsInternalReport => Permission::SysTlsInternalReportGet,
            ObjectType::TlsReportSettings => Permission::SysTlsReportSettingsGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => Permission::SysTraceGet,
            // SPDX-SnippetEnd
            ObjectType::Tracer => Permission::SysTracerGet,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => Permission::SysTracingStoreGet,
            // SPDX-SnippetEnd
            ObjectType::WebDav => Permission::SysWebDavGet,
            ObjectType::WebHook => Permission::SysWebHookGet,
        }
    }

    pub fn query_permission(&self) -> Permission {
        match self {
            ObjectType::Account => Permission::SysAccountQuery,
            ObjectType::AcmeProvider => Permission::SysAcmeProviderQuery,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => Permission::SysAiModelQuery,
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => Permission::SysAlertQuery,
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => Permission::SysAllowedIpQuery,
            ObjectType::ApiKey => Permission::SysApiKeyQuery,
            ObjectType::AppPassword => Permission::SysAppPasswordQuery,
            ObjectType::Application => Permission::SysApplicationQuery,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => Permission::SysArchivedItemQuery,
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => Permission::SysArfExternalReportQuery,
            ObjectType::BlockedIp => Permission::SysBlockedIpQuery,
            ObjectType::Certificate => Permission::SysCertificateQuery,
            ObjectType::ClusterNode => Permission::SysClusterNodeQuery,
            ObjectType::ClusterRole => Permission::SysClusterRoleQuery,
            ObjectType::Directory => Permission::SysDirectoryQuery,
            ObjectType::DkimSignature => Permission::SysDkimSignatureQuery,
            ObjectType::DmarcExternalReport => Permission::SysDmarcExternalReportQuery,
            ObjectType::DmarcInternalReport => Permission::SysDmarcInternalReportQuery,
            ObjectType::DnsServer => Permission::SysDnsServerQuery,
            ObjectType::Domain => Permission::SysDomainQuery,
            ObjectType::EventTracingLevel => Permission::SysEventTracingLevelQuery,
            ObjectType::HttpLookup => Permission::SysHttpLookupQuery,
            ObjectType::IndexQueueStatus => Permission::SysIndexQueueStatusQuery,
            ObjectType::Log => Permission::SysLogQuery,
            ObjectType::MailingList => Permission::SysMailingListQuery,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => Permission::SysMaskedEmailQuery,
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => Permission::SysMemoryLookupKeyQuery,
            ObjectType::MemoryLookupKeyValue => Permission::SysMemoryLookupKeyValueQuery,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => Permission::SysMetricQuery,
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => Permission::SysMtaConnectionStrategyQuery,
            ObjectType::MtaDeliverySchedule => Permission::SysMtaDeliveryScheduleQuery,
            ObjectType::MtaHook => Permission::SysMtaHookQuery,
            ObjectType::MtaInboundThrottle => Permission::SysMtaInboundThrottleQuery,
            ObjectType::MtaMilter => Permission::SysMtaMilterQuery,
            ObjectType::MtaOutboundThrottle => Permission::SysMtaOutboundThrottleQuery,
            ObjectType::MtaQueueQuota => Permission::SysMtaQueueQuotaQuery,
            ObjectType::MtaRoute => Permission::SysMtaRouteQuery,
            ObjectType::MtaTlsStrategy => Permission::SysMtaTlsStrategyQuery,
            ObjectType::MtaVirtualQueue => Permission::SysMtaVirtualQueueQuery,
            ObjectType::NetworkListener => Permission::SysNetworkListenerQuery,
            ObjectType::OAuthClient => Permission::SysOAuthClientQuery,
            ObjectType::OAuthGrant => Permission::SysOAuthGrantQuery,
            ObjectType::PublicKey => Permission::SysPublicKeyQuery,
            ObjectType::QueuedMessage => Permission::SysQueuedMessageQuery,
            ObjectType::Role => Permission::SysRoleQuery,
            ObjectType::SieveSystemScript => Permission::SysSieveSystemScriptQuery,
            ObjectType::SieveUserScript => Permission::SysSieveUserScriptQuery,
            ObjectType::SpamDnsblServer => Permission::SysSpamDnsblServerQuery,
            ObjectType::SpamFileExtension => Permission::SysSpamFileExtensionQuery,
            ObjectType::SpamRule => Permission::SysSpamRuleQuery,
            ObjectType::SpamTag => Permission::SysSpamTagQuery,
            ObjectType::SpamTrainingSample => Permission::SysSpamTrainingSampleQuery,
            ObjectType::StoreLookup => Permission::SysStoreLookupQuery,
            ObjectType::Task => Permission::SysTaskQuery,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => Permission::SysTenantQuery,
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => Permission::SysTlsExternalReportQuery,
            ObjectType::TlsInternalReport => Permission::SysTlsInternalReportQuery,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => Permission::SysTraceQuery,
            // SPDX-SnippetEnd
            ObjectType::Tracer => Permission::SysTracerQuery,
            ObjectType::WebHook => Permission::SysWebHookQuery,
            _ => unreachable!(),
        }
    }

    pub fn create_permission(&self) -> Permission {
        match self {
            ObjectType::Account => Permission::SysAccountCreate,
            ObjectType::AccountPassword => Permission::SysAccountPasswordUpdate,
            ObjectType::AccountSettings => Permission::SysAccountSettingsUpdate,
            ObjectType::AcmeProvider => Permission::SysAcmeProviderCreate,
            ObjectType::Action => Permission::SysActionCreate,
            ObjectType::AddressBook => Permission::SysAddressBookUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => Permission::SysAiModelCreate,
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => Permission::SysAlertCreate,
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => Permission::SysAllowedIpCreate,
            ObjectType::ApiKey => Permission::SysApiKeyCreate,
            ObjectType::AppPassword => Permission::SysAppPasswordCreate,
            ObjectType::Application => Permission::SysApplicationCreate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => unreachable!(),
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => unreachable!(),
            ObjectType::Asn => Permission::SysAsnUpdate,
            ObjectType::Authentication => Permission::SysAuthenticationUpdate,
            ObjectType::BlobStore => Permission::SysBlobStoreUpdate,
            ObjectType::BlockedIp => Permission::SysBlockedIpCreate,
            ObjectType::Bootstrap => Permission::SysBootstrapUpdate,
            ObjectType::Cache => Permission::SysCacheUpdate,
            ObjectType::Calendar => Permission::SysCalendarUpdate,
            ObjectType::CalendarAlarm => Permission::SysCalendarAlarmUpdate,
            ObjectType::CalendarScheduling => Permission::SysCalendarSchedulingUpdate,
            ObjectType::Certificate => Permission::SysCertificateCreate,
            ObjectType::ClusterNode => unreachable!(),
            ObjectType::ClusterRole => Permission::SysClusterRoleCreate,
            ObjectType::Coordinator => Permission::SysCoordinatorUpdate,
            ObjectType::DataRetention => Permission::SysDataRetentionUpdate,
            ObjectType::DataStore => Permission::SysDataStoreUpdate,
            ObjectType::Directory => Permission::SysDirectoryCreate,
            ObjectType::DkimReportSettings => Permission::SysDkimReportSettingsUpdate,
            ObjectType::DkimSignature => Permission::SysDkimSignatureCreate,
            ObjectType::DmarcExternalReport => unreachable!(),
            ObjectType::DmarcInternalReport => unreachable!(),
            ObjectType::DmarcReportSettings => Permission::SysDmarcReportSettingsUpdate,
            ObjectType::DnsResolver => Permission::SysDnsResolverUpdate,
            ObjectType::DnsServer => Permission::SysDnsServerCreate,
            ObjectType::Domain => Permission::SysDomainCreate,
            ObjectType::DsnReportSettings => Permission::SysDsnReportSettingsUpdate,
            ObjectType::Email => Permission::SysEmailUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => Permission::SysEnterpriseUpdate,
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => Permission::SysEventTracingLevelCreate,
            ObjectType::FileStorage => Permission::SysFileStorageUpdate,
            ObjectType::Http => Permission::SysHttpUpdate,
            ObjectType::HttpForm => Permission::SysHttpFormUpdate,
            ObjectType::HttpLookup => Permission::SysHttpLookupCreate,
            ObjectType::Imap => Permission::SysImapUpdate,
            ObjectType::InMemoryStore => Permission::SysInMemoryStoreUpdate,
            ObjectType::IndexQueueStatus => unreachable!(),
            ObjectType::Jmap => Permission::SysJmapUpdate,
            ObjectType::Log => unreachable!(),
            ObjectType::MailingList => Permission::SysMailingListCreate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => Permission::SysMaskedEmailCreate,
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => Permission::SysMemoryLookupKeyCreate,
            ObjectType::MemoryLookupKeyValue => Permission::SysMemoryLookupKeyValueCreate,
            ObjectType::Metadata => Permission::SysMetadataUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => unreachable!(),
            // SPDX-SnippetEnd
            ObjectType::Metrics => Permission::SysMetricsUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => Permission::SysMetricsStoreUpdate,
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => Permission::SysMtaConnectionStrategyCreate,
            ObjectType::MtaDeliverySchedule => Permission::SysMtaDeliveryScheduleCreate,
            ObjectType::MtaExtensions => Permission::SysMtaExtensionsUpdate,
            ObjectType::MtaHook => Permission::SysMtaHookCreate,
            ObjectType::MtaInboundSession => Permission::SysMtaInboundSessionUpdate,
            ObjectType::MtaInboundThrottle => Permission::SysMtaInboundThrottleCreate,
            ObjectType::MtaMilter => Permission::SysMtaMilterCreate,
            ObjectType::MtaOutboundStrategy => Permission::SysMtaOutboundStrategyUpdate,
            ObjectType::MtaOutboundThrottle => Permission::SysMtaOutboundThrottleCreate,
            ObjectType::MtaQueueQuota => Permission::SysMtaQueueQuotaCreate,
            ObjectType::MtaRoute => Permission::SysMtaRouteCreate,
            ObjectType::MtaStageAuth => Permission::SysMtaStageAuthUpdate,
            ObjectType::MtaStageConnect => Permission::SysMtaStageConnectUpdate,
            ObjectType::MtaStageData => Permission::SysMtaStageDataUpdate,
            ObjectType::MtaStageEhlo => Permission::SysMtaStageEhloUpdate,
            ObjectType::MtaStageMail => Permission::SysMtaStageMailUpdate,
            ObjectType::MtaStageRcpt => Permission::SysMtaStageRcptUpdate,
            ObjectType::MtaSts => Permission::SysMtaStsUpdate,
            ObjectType::MtaTlsStrategy => Permission::SysMtaTlsStrategyCreate,
            ObjectType::MtaVirtualQueue => Permission::SysMtaVirtualQueueCreate,
            ObjectType::NetworkListener => Permission::SysNetworkListenerCreate,
            ObjectType::OAuthClient => Permission::SysOAuthClientCreate,
            ObjectType::OAuthGrant => unreachable!(),
            ObjectType::OidcProvider => Permission::SysOidcProviderUpdate,
            ObjectType::PublicKey => Permission::SysPublicKeyCreate,
            ObjectType::QueuedMessage => unreachable!(),
            ObjectType::ReportSettings => Permission::SysReportSettingsUpdate,
            ObjectType::Role => Permission::SysRoleCreate,
            ObjectType::Search => Permission::SysSearchUpdate,
            ObjectType::SearchStore => Permission::SysSearchStoreUpdate,
            ObjectType::Security => Permission::SysSecurityUpdate,
            ObjectType::SenderAuth => Permission::SysSenderAuthUpdate,
            ObjectType::Sharing => Permission::SysSharingUpdate,
            ObjectType::SieveSystemInterpreter => Permission::SysSieveSystemInterpreterUpdate,
            ObjectType::SieveSystemScript => Permission::SysSieveSystemScriptCreate,
            ObjectType::SieveUserInterpreter => Permission::SysSieveUserInterpreterUpdate,
            ObjectType::SieveUserScript => Permission::SysSieveUserScriptCreate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => Permission::SysSpamAiUpdate,
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => Permission::SysSpamClassifierUpdate,
            ObjectType::SpamDnsblServer => Permission::SysSpamDnsblServerCreate,
            ObjectType::SpamDnsblSettings => Permission::SysSpamDnsblSettingsUpdate,
            ObjectType::SpamFileExtension => Permission::SysSpamFileExtensionCreate,
            ObjectType::SpamPyzor => Permission::SysSpamPyzorUpdate,
            ObjectType::SpamRule => Permission::SysSpamRuleCreate,
            ObjectType::SpamSettings => Permission::SysSpamSettingsUpdate,
            ObjectType::SpamTag => Permission::SysSpamTagCreate,
            ObjectType::SpamTrainingSample => Permission::SysSpamTrainingSampleCreate,
            ObjectType::SpfReportSettings => Permission::SysSpfReportSettingsUpdate,
            ObjectType::StoreLookup => Permission::SysStoreLookupCreate,
            ObjectType::SystemSettings => Permission::SysSystemSettingsUpdate,
            ObjectType::Task => Permission::SysTaskCreate,
            ObjectType::TaskManager => Permission::SysTaskManagerUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => Permission::SysTenantCreate,
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => unreachable!(),
            ObjectType::TlsInternalReport => unreachable!(),
            ObjectType::TlsReportSettings => Permission::SysTlsReportSettingsUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => unreachable!(),
            // SPDX-SnippetEnd
            ObjectType::Tracer => Permission::SysTracerCreate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => Permission::SysTracingStoreUpdate,
            // SPDX-SnippetEnd
            ObjectType::WebDav => Permission::SysWebDavUpdate,
            ObjectType::WebHook => Permission::SysWebHookCreate,
        }
    }

    pub fn update_permission(&self) -> Permission {
        match self {
            ObjectType::Account => Permission::SysAccountUpdate,
            ObjectType::AccountPassword => Permission::SysAccountPasswordUpdate,
            ObjectType::AccountSettings => Permission::SysAccountSettingsUpdate,
            ObjectType::AcmeProvider => Permission::SysAcmeProviderUpdate,
            ObjectType::Action => unreachable!(),
            ObjectType::AddressBook => Permission::SysAddressBookUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => Permission::SysAiModelUpdate,
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => Permission::SysAlertUpdate,
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => Permission::SysAllowedIpUpdate,
            ObjectType::ApiKey => Permission::SysApiKeyUpdate,
            ObjectType::AppPassword => Permission::SysAppPasswordUpdate,
            ObjectType::Application => Permission::SysApplicationUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => Permission::SysArchivedItemUpdate,
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => unreachable!(),
            ObjectType::Asn => Permission::SysAsnUpdate,
            ObjectType::Authentication => Permission::SysAuthenticationUpdate,
            ObjectType::BlobStore => Permission::SysBlobStoreUpdate,
            ObjectType::BlockedIp => Permission::SysBlockedIpUpdate,
            ObjectType::Bootstrap => Permission::SysBootstrapUpdate,
            ObjectType::Cache => Permission::SysCacheUpdate,
            ObjectType::Calendar => Permission::SysCalendarUpdate,
            ObjectType::CalendarAlarm => Permission::SysCalendarAlarmUpdate,
            ObjectType::CalendarScheduling => Permission::SysCalendarSchedulingUpdate,
            ObjectType::Certificate => Permission::SysCertificateUpdate,
            ObjectType::ClusterNode => unreachable!(),
            ObjectType::ClusterRole => Permission::SysClusterRoleUpdate,
            ObjectType::Coordinator => Permission::SysCoordinatorUpdate,
            ObjectType::DataRetention => Permission::SysDataRetentionUpdate,
            ObjectType::DataStore => Permission::SysDataStoreUpdate,
            ObjectType::Directory => Permission::SysDirectoryUpdate,
            ObjectType::DkimReportSettings => Permission::SysDkimReportSettingsUpdate,
            ObjectType::DkimSignature => Permission::SysDkimSignatureUpdate,
            ObjectType::DmarcExternalReport => unreachable!(),
            ObjectType::DmarcInternalReport => Permission::SysDmarcInternalReportUpdate,
            ObjectType::DmarcReportSettings => Permission::SysDmarcReportSettingsUpdate,
            ObjectType::DnsResolver => Permission::SysDnsResolverUpdate,
            ObjectType::DnsServer => Permission::SysDnsServerUpdate,
            ObjectType::Domain => Permission::SysDomainUpdate,
            ObjectType::DsnReportSettings => Permission::SysDsnReportSettingsUpdate,
            ObjectType::Email => Permission::SysEmailUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => Permission::SysEnterpriseUpdate,
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => Permission::SysEventTracingLevelUpdate,
            ObjectType::FileStorage => Permission::SysFileStorageUpdate,
            ObjectType::Http => Permission::SysHttpUpdate,
            ObjectType::HttpForm => Permission::SysHttpFormUpdate,
            ObjectType::HttpLookup => Permission::SysHttpLookupUpdate,
            ObjectType::Imap => Permission::SysImapUpdate,
            ObjectType::InMemoryStore => Permission::SysInMemoryStoreUpdate,
            ObjectType::IndexQueueStatus => Permission::SysIndexQueueStatusUpdate,
            ObjectType::Jmap => Permission::SysJmapUpdate,
            ObjectType::Log => unreachable!(),
            ObjectType::MailingList => Permission::SysMailingListUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => Permission::SysMaskedEmailUpdate,
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => Permission::SysMemoryLookupKeyUpdate,
            ObjectType::MemoryLookupKeyValue => Permission::SysMemoryLookupKeyValueUpdate,
            ObjectType::Metadata => Permission::SysMetadataUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => unreachable!(),
            // SPDX-SnippetEnd
            ObjectType::Metrics => Permission::SysMetricsUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => Permission::SysMetricsStoreUpdate,
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => Permission::SysMtaConnectionStrategyUpdate,
            ObjectType::MtaDeliverySchedule => Permission::SysMtaDeliveryScheduleUpdate,
            ObjectType::MtaExtensions => Permission::SysMtaExtensionsUpdate,
            ObjectType::MtaHook => Permission::SysMtaHookUpdate,
            ObjectType::MtaInboundSession => Permission::SysMtaInboundSessionUpdate,
            ObjectType::MtaInboundThrottle => Permission::SysMtaInboundThrottleUpdate,
            ObjectType::MtaMilter => Permission::SysMtaMilterUpdate,
            ObjectType::MtaOutboundStrategy => Permission::SysMtaOutboundStrategyUpdate,
            ObjectType::MtaOutboundThrottle => Permission::SysMtaOutboundThrottleUpdate,
            ObjectType::MtaQueueQuota => Permission::SysMtaQueueQuotaUpdate,
            ObjectType::MtaRoute => Permission::SysMtaRouteUpdate,
            ObjectType::MtaStageAuth => Permission::SysMtaStageAuthUpdate,
            ObjectType::MtaStageConnect => Permission::SysMtaStageConnectUpdate,
            ObjectType::MtaStageData => Permission::SysMtaStageDataUpdate,
            ObjectType::MtaStageEhlo => Permission::SysMtaStageEhloUpdate,
            ObjectType::MtaStageMail => Permission::SysMtaStageMailUpdate,
            ObjectType::MtaStageRcpt => Permission::SysMtaStageRcptUpdate,
            ObjectType::MtaSts => Permission::SysMtaStsUpdate,
            ObjectType::MtaTlsStrategy => Permission::SysMtaTlsStrategyUpdate,
            ObjectType::MtaVirtualQueue => Permission::SysMtaVirtualQueueUpdate,
            ObjectType::NetworkListener => Permission::SysNetworkListenerUpdate,
            ObjectType::OAuthClient => Permission::SysOAuthClientUpdate,
            ObjectType::OAuthGrant => unreachable!(),
            ObjectType::OidcProvider => Permission::SysOidcProviderUpdate,
            ObjectType::PublicKey => Permission::SysPublicKeyUpdate,
            ObjectType::QueuedMessage => Permission::SysQueuedMessageUpdate,
            ObjectType::ReportSettings => Permission::SysReportSettingsUpdate,
            ObjectType::Role => Permission::SysRoleUpdate,
            ObjectType::Search => Permission::SysSearchUpdate,
            ObjectType::SearchStore => Permission::SysSearchStoreUpdate,
            ObjectType::Security => Permission::SysSecurityUpdate,
            ObjectType::SenderAuth => Permission::SysSenderAuthUpdate,
            ObjectType::Sharing => Permission::SysSharingUpdate,
            ObjectType::SieveSystemInterpreter => Permission::SysSieveSystemInterpreterUpdate,
            ObjectType::SieveSystemScript => Permission::SysSieveSystemScriptUpdate,
            ObjectType::SieveUserInterpreter => Permission::SysSieveUserInterpreterUpdate,
            ObjectType::SieveUserScript => Permission::SysSieveUserScriptUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => Permission::SysSpamAiUpdate,
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => Permission::SysSpamClassifierUpdate,
            ObjectType::SpamDnsblServer => Permission::SysSpamDnsblServerUpdate,
            ObjectType::SpamDnsblSettings => Permission::SysSpamDnsblSettingsUpdate,
            ObjectType::SpamFileExtension => Permission::SysSpamFileExtensionUpdate,
            ObjectType::SpamPyzor => Permission::SysSpamPyzorUpdate,
            ObjectType::SpamRule => Permission::SysSpamRuleUpdate,
            ObjectType::SpamSettings => Permission::SysSpamSettingsUpdate,
            ObjectType::SpamTag => Permission::SysSpamTagUpdate,
            ObjectType::SpamTrainingSample => unreachable!(),
            ObjectType::SpfReportSettings => Permission::SysSpfReportSettingsUpdate,
            ObjectType::StoreLookup => Permission::SysStoreLookupUpdate,
            ObjectType::SystemSettings => Permission::SysSystemSettingsUpdate,
            ObjectType::Task => Permission::SysTaskUpdate,
            ObjectType::TaskManager => Permission::SysTaskManagerUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => Permission::SysTenantUpdate,
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => unreachable!(),
            ObjectType::TlsInternalReport => Permission::SysTlsInternalReportUpdate,
            ObjectType::TlsReportSettings => Permission::SysTlsReportSettingsUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => unreachable!(),
            // SPDX-SnippetEnd
            ObjectType::Tracer => Permission::SysTracerUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => Permission::SysTracingStoreUpdate,
            // SPDX-SnippetEnd
            ObjectType::WebDav => Permission::SysWebDavUpdate,
            ObjectType::WebHook => Permission::SysWebHookUpdate,
        }
    }

    pub fn destroy_permission(&self) -> Permission {
        match self {
            ObjectType::Account => Permission::SysAccountDestroy,
            ObjectType::AccountPassword => Permission::SysAccountPasswordUpdate,
            ObjectType::AccountSettings => Permission::SysAccountSettingsUpdate,
            ObjectType::AcmeProvider => Permission::SysAcmeProviderDestroy,
            ObjectType::Action => unreachable!(),
            ObjectType::AddressBook => Permission::SysAddressBookUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => Permission::SysAiModelDestroy,
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => Permission::SysAlertDestroy,
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => Permission::SysAllowedIpDestroy,
            ObjectType::ApiKey => Permission::SysApiKeyDestroy,
            ObjectType::AppPassword => Permission::SysAppPasswordDestroy,
            ObjectType::Application => Permission::SysApplicationDestroy,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => Permission::SysArchivedItemDestroy,
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => Permission::SysArfExternalReportDestroy,
            ObjectType::Asn => Permission::SysAsnUpdate,
            ObjectType::Authentication => Permission::SysAuthenticationUpdate,
            ObjectType::BlobStore => Permission::SysBlobStoreUpdate,
            ObjectType::BlockedIp => Permission::SysBlockedIpDestroy,
            ObjectType::Bootstrap => Permission::SysBootstrapUpdate,
            ObjectType::Cache => Permission::SysCacheUpdate,
            ObjectType::Calendar => Permission::SysCalendarUpdate,
            ObjectType::CalendarAlarm => Permission::SysCalendarAlarmUpdate,
            ObjectType::CalendarScheduling => Permission::SysCalendarSchedulingUpdate,
            ObjectType::Certificate => Permission::SysCertificateDestroy,
            ObjectType::ClusterNode => unreachable!(),
            ObjectType::ClusterRole => Permission::SysClusterRoleDestroy,
            ObjectType::Coordinator => Permission::SysCoordinatorUpdate,
            ObjectType::DataRetention => Permission::SysDataRetentionUpdate,
            ObjectType::DataStore => Permission::SysDataStoreUpdate,
            ObjectType::Directory => Permission::SysDirectoryDestroy,
            ObjectType::DkimReportSettings => Permission::SysDkimReportSettingsUpdate,
            ObjectType::DkimSignature => Permission::SysDkimSignatureDestroy,
            ObjectType::DmarcExternalReport => Permission::SysDmarcExternalReportDestroy,
            ObjectType::DmarcInternalReport => Permission::SysDmarcInternalReportDestroy,
            ObjectType::DmarcReportSettings => Permission::SysDmarcReportSettingsUpdate,
            ObjectType::DnsResolver => Permission::SysDnsResolverUpdate,
            ObjectType::DnsServer => Permission::SysDnsServerDestroy,
            ObjectType::Domain => Permission::SysDomainDestroy,
            ObjectType::DsnReportSettings => Permission::SysDsnReportSettingsUpdate,
            ObjectType::Email => Permission::SysEmailUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => Permission::SysEnterpriseUpdate,
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => Permission::SysEventTracingLevelDestroy,
            ObjectType::FileStorage => Permission::SysFileStorageUpdate,
            ObjectType::Http => Permission::SysHttpUpdate,
            ObjectType::HttpForm => Permission::SysHttpFormUpdate,
            ObjectType::HttpLookup => Permission::SysHttpLookupDestroy,
            ObjectType::Imap => Permission::SysImapUpdate,
            ObjectType::InMemoryStore => Permission::SysInMemoryStoreUpdate,
            ObjectType::IndexQueueStatus => unreachable!(),
            ObjectType::Jmap => Permission::SysJmapUpdate,
            ObjectType::Log => unreachable!(),
            ObjectType::MailingList => Permission::SysMailingListDestroy,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => Permission::SysMaskedEmailDestroy,
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => Permission::SysMemoryLookupKeyDestroy,
            ObjectType::MemoryLookupKeyValue => Permission::SysMemoryLookupKeyValueDestroy,
            ObjectType::Metadata => Permission::SysMetadataUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => unreachable!(),
            // SPDX-SnippetEnd
            ObjectType::Metrics => Permission::SysMetricsUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => Permission::SysMetricsStoreUpdate,
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => Permission::SysMtaConnectionStrategyDestroy,
            ObjectType::MtaDeliverySchedule => Permission::SysMtaDeliveryScheduleDestroy,
            ObjectType::MtaExtensions => Permission::SysMtaExtensionsUpdate,
            ObjectType::MtaHook => Permission::SysMtaHookDestroy,
            ObjectType::MtaInboundSession => Permission::SysMtaInboundSessionUpdate,
            ObjectType::MtaInboundThrottle => Permission::SysMtaInboundThrottleDestroy,
            ObjectType::MtaMilter => Permission::SysMtaMilterDestroy,
            ObjectType::MtaOutboundStrategy => Permission::SysMtaOutboundStrategyUpdate,
            ObjectType::MtaOutboundThrottle => Permission::SysMtaOutboundThrottleDestroy,
            ObjectType::MtaQueueQuota => Permission::SysMtaQueueQuotaDestroy,
            ObjectType::MtaRoute => Permission::SysMtaRouteDestroy,
            ObjectType::MtaStageAuth => Permission::SysMtaStageAuthUpdate,
            ObjectType::MtaStageConnect => Permission::SysMtaStageConnectUpdate,
            ObjectType::MtaStageData => Permission::SysMtaStageDataUpdate,
            ObjectType::MtaStageEhlo => Permission::SysMtaStageEhloUpdate,
            ObjectType::MtaStageMail => Permission::SysMtaStageMailUpdate,
            ObjectType::MtaStageRcpt => Permission::SysMtaStageRcptUpdate,
            ObjectType::MtaSts => Permission::SysMtaStsUpdate,
            ObjectType::MtaTlsStrategy => Permission::SysMtaTlsStrategyDestroy,
            ObjectType::MtaVirtualQueue => Permission::SysMtaVirtualQueueDestroy,
            ObjectType::NetworkListener => Permission::SysNetworkListenerDestroy,
            ObjectType::OAuthClient => Permission::SysOAuthClientDestroy,
            ObjectType::OAuthGrant => Permission::SysOAuthGrantDestroy,
            ObjectType::OidcProvider => Permission::SysOidcProviderUpdate,
            ObjectType::PublicKey => Permission::SysPublicKeyDestroy,
            ObjectType::QueuedMessage => Permission::SysQueuedMessageDestroy,
            ObjectType::ReportSettings => Permission::SysReportSettingsUpdate,
            ObjectType::Role => Permission::SysRoleDestroy,
            ObjectType::Search => Permission::SysSearchUpdate,
            ObjectType::SearchStore => Permission::SysSearchStoreUpdate,
            ObjectType::Security => Permission::SysSecurityUpdate,
            ObjectType::SenderAuth => Permission::SysSenderAuthUpdate,
            ObjectType::Sharing => Permission::SysSharingUpdate,
            ObjectType::SieveSystemInterpreter => Permission::SysSieveSystemInterpreterUpdate,
            ObjectType::SieveSystemScript => Permission::SysSieveSystemScriptDestroy,
            ObjectType::SieveUserInterpreter => Permission::SysSieveUserInterpreterUpdate,
            ObjectType::SieveUserScript => Permission::SysSieveUserScriptDestroy,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => Permission::SysSpamAiUpdate,
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => Permission::SysSpamClassifierUpdate,
            ObjectType::SpamDnsblServer => Permission::SysSpamDnsblServerDestroy,
            ObjectType::SpamDnsblSettings => Permission::SysSpamDnsblSettingsUpdate,
            ObjectType::SpamFileExtension => Permission::SysSpamFileExtensionDestroy,
            ObjectType::SpamPyzor => Permission::SysSpamPyzorUpdate,
            ObjectType::SpamRule => Permission::SysSpamRuleDestroy,
            ObjectType::SpamSettings => Permission::SysSpamSettingsUpdate,
            ObjectType::SpamTag => Permission::SysSpamTagDestroy,
            ObjectType::SpamTrainingSample => Permission::SysSpamTrainingSampleDestroy,
            ObjectType::SpfReportSettings => Permission::SysSpfReportSettingsUpdate,
            ObjectType::StoreLookup => Permission::SysStoreLookupDestroy,
            ObjectType::SystemSettings => Permission::SysSystemSettingsUpdate,
            ObjectType::Task => Permission::SysTaskDestroy,
            ObjectType::TaskManager => Permission::SysTaskManagerUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => Permission::SysTenantDestroy,
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => Permission::SysTlsExternalReportDestroy,
            ObjectType::TlsInternalReport => Permission::SysTlsInternalReportDestroy,
            ObjectType::TlsReportSettings => Permission::SysTlsReportSettingsUpdate,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => unreachable!(),
            // SPDX-SnippetEnd
            ObjectType::Tracer => Permission::SysTracerDestroy,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => Permission::SysTracingStoreUpdate,
            // SPDX-SnippetEnd
            ObjectType::WebDav => Permission::SysWebDavUpdate,
            ObjectType::WebHook => Permission::SysWebHookDestroy,
        }
    }
}

impl ObjectInner {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn member_tenant_id(&self) -> Option<Id> {
        match self {
            ObjectInner::Account(inner) => match inner.as_ref() {
                Account::User(obj) => obj.member_tenant_id,
                Account::Group(obj) => obj.member_tenant_id,
            },
            ObjectInner::AcmeProvider(obj) => obj.member_tenant_id,
            ObjectInner::ArfExternalReport(obj) => obj.member_tenant_id,
            ObjectInner::Directory(inner) => match inner.as_ref() {
                Directory::Ldap(obj) => obj.member_tenant_id,
                Directory::Sql(obj) => obj.member_tenant_id,
                Directory::Oidc(obj) => obj.member_tenant_id,
            },
            ObjectInner::DkimSignature(inner) => match inner.as_ref() {
                DkimSignature::Dkim1Ed25519Sha256(obj) => obj.member_tenant_id,
                DkimSignature::Dkim1RsaSha256(obj) => obj.member_tenant_id,
                DkimSignature::Dkim2Ed25519Sha256(obj) => obj.member_tenant_id,
                DkimSignature::Dkim2RsaSha256(obj) => obj.member_tenant_id,
                DkimSignature::Dkim2MlDsa44Ed25519Sha512(obj) => obj.member_tenant_id,
            },
            ObjectInner::DmarcExternalReport(obj) => obj.member_tenant_id,
            ObjectInner::DnsServer(inner) => match inner.as_ref() {
                DnsServer::Tsig(obj) => obj.member_tenant_id,
                DnsServer::Cloudflare(obj) => obj.member_tenant_id,
                DnsServer::DigitalOcean(obj) => obj.member_tenant_id,
                DnsServer::DeSEC(obj) => obj.member_tenant_id,
                DnsServer::Ovh(obj) => obj.member_tenant_id,
                DnsServer::Bunny(obj) => obj.member_tenant_id,
                DnsServer::Porkbun(obj) => obj.member_tenant_id,
                DnsServer::Dnsimple(obj) => obj.member_tenant_id,
                DnsServer::Spaceship(obj) => obj.member_tenant_id,
                DnsServer::Route53(obj) => obj.member_tenant_id,
                DnsServer::GoogleCloudDns(obj) => obj.member_tenant_id,
                DnsServer::Alidns(obj) => obj.member_tenant_id,
                DnsServer::ArvanCloud(obj) => obj.member_tenant_id,
                DnsServer::Autodns(obj) => obj.member_tenant_id,
                DnsServer::AzureDns(obj) => obj.member_tenant_id,
                DnsServer::BaiduCloud(obj) => obj.member_tenant_id,
                DnsServer::BluecatV2(obj) => obj.member_tenant_id,
                DnsServer::ClouDns(obj) => obj.member_tenant_id,
                DnsServer::Constellix(obj) => obj.member_tenant_id,
                DnsServer::Cpanel(obj) => obj.member_tenant_id,
                DnsServer::Ddnss(obj) => obj.member_tenant_id,
                DnsServer::DnsMadeEasy(obj) => obj.member_tenant_id,
                DnsServer::Domeneshop(obj) => obj.member_tenant_id,
                DnsServer::Dreamhost(obj) => obj.member_tenant_id,
                DnsServer::DuckDns(obj) => obj.member_tenant_id,
                DnsServer::Dynu(obj) => obj.member_tenant_id,
                DnsServer::EasyDns(obj) => obj.member_tenant_id,
                DnsServer::EdgeDns(obj) => obj.member_tenant_id,
                DnsServer::Exoscale(obj) => obj.member_tenant_id,
                DnsServer::FreeMyIp(obj) => obj.member_tenant_id,
                DnsServer::GandiV5(obj) => obj.member_tenant_id,
                DnsServer::Gcore(obj) => obj.member_tenant_id,
                DnsServer::Glesys(obj) => obj.member_tenant_id,
                DnsServer::Godaddy(obj) => obj.member_tenant_id,
                DnsServer::Hetzner(obj) => obj.member_tenant_id,
                DnsServer::HostingDe(obj) => obj.member_tenant_id,
                DnsServer::Hostinger(obj) => obj.member_tenant_id,
                DnsServer::HuaweiCloud(obj) => obj.member_tenant_id,
                DnsServer::Hurricane(obj) => obj.member_tenant_id,
                DnsServer::IbmCloud(obj) => obj.member_tenant_id,
                DnsServer::Infoblox(obj) => obj.member_tenant_id,
                DnsServer::Infomaniak(obj) => obj.member_tenant_id,
                DnsServer::Inwx(obj) => obj.member_tenant_id,
                DnsServer::Ionos(obj) => obj.member_tenant_id,
                DnsServer::Ipv64(obj) => obj.member_tenant_id,
                DnsServer::Joker(obj) => obj.member_tenant_id,
                DnsServer::Lightsail(obj) => obj.member_tenant_id,
                DnsServer::Linode(obj) => obj.member_tenant_id,
                DnsServer::LuaDns(obj) => obj.member_tenant_id,
                DnsServer::MythicBeasts(obj) => obj.member_tenant_id,
                DnsServer::Namecheap(obj) => obj.member_tenant_id,
                DnsServer::NameDotCom(obj) => obj.member_tenant_id,
                DnsServer::NameSilo(obj) => obj.member_tenant_id,
                DnsServer::Netcup(obj) => obj.member_tenant_id,
                DnsServer::Netlify(obj) => obj.member_tenant_id,
                DnsServer::Nifcloud(obj) => obj.member_tenant_id,
                DnsServer::Ns1(obj) => obj.member_tenant_id,
                DnsServer::OracleCloud(obj) => obj.member_tenant_id,
                DnsServer::Plesk(obj) => obj.member_tenant_id,
                DnsServer::Safedns(obj) => obj.member_tenant_id,
                DnsServer::Scaleway(obj) => obj.member_tenant_id,
                DnsServer::TencentCloud(obj) => obj.member_tenant_id,
                DnsServer::Transip(obj) => obj.member_tenant_id,
                DnsServer::UltraDns(obj) => obj.member_tenant_id,
                DnsServer::Vercel(obj) => obj.member_tenant_id,
                DnsServer::Volcengine(obj) => obj.member_tenant_id,
                DnsServer::Vultr(obj) => obj.member_tenant_id,
                DnsServer::WebSupport(obj) => obj.member_tenant_id,
                DnsServer::YandexCloud(obj) => obj.member_tenant_id,
                DnsServer::PowerDns(obj) => obj.member_tenant_id,
            },
            ObjectInner::Domain(obj) => obj.member_tenant_id,
            ObjectInner::MailingList(obj) => obj.member_tenant_id,
            ObjectInner::OAuthClient(obj) => obj.member_tenant_id,
            ObjectInner::Role(obj) => obj.member_tenant_id,
            ObjectInner::TlsExternalReport(obj) => obj.member_tenant_id,
            _ => None,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn set_member_tenant_id(&mut self, id: Id) {
        match self {
            ObjectInner::Account(inner) => match inner.as_mut() {
                Account::User(obj) => obj.member_tenant_id = Some(id),
                Account::Group(obj) => obj.member_tenant_id = Some(id),
            },
            ObjectInner::AcmeProvider(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::ArfExternalReport(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::Directory(inner) => match inner.as_mut() {
                Directory::Ldap(obj) => obj.member_tenant_id = Some(id),
                Directory::Sql(obj) => obj.member_tenant_id = Some(id),
                Directory::Oidc(obj) => obj.member_tenant_id = Some(id),
            },
            ObjectInner::DkimSignature(inner) => match inner.as_mut() {
                DkimSignature::Dkim1Ed25519Sha256(obj) => obj.member_tenant_id = Some(id),
                DkimSignature::Dkim1RsaSha256(obj) => obj.member_tenant_id = Some(id),
                DkimSignature::Dkim2Ed25519Sha256(obj) => obj.member_tenant_id = Some(id),
                DkimSignature::Dkim2RsaSha256(obj) => obj.member_tenant_id = Some(id),
                DkimSignature::Dkim2MlDsa44Ed25519Sha512(obj) => obj.member_tenant_id = Some(id),
            },
            ObjectInner::DmarcExternalReport(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(inner) => match inner.as_mut() {
                DnsServer::Tsig(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Cloudflare(obj) => obj.member_tenant_id = Some(id),
                DnsServer::DigitalOcean(obj) => obj.member_tenant_id = Some(id),
                DnsServer::DeSEC(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Ovh(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Bunny(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Porkbun(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Dnsimple(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Spaceship(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Route53(obj) => obj.member_tenant_id = Some(id),
                DnsServer::GoogleCloudDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Alidns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::ArvanCloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Autodns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::AzureDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::BaiduCloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::BluecatV2(obj) => obj.member_tenant_id = Some(id),
                DnsServer::ClouDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Constellix(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Cpanel(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Ddnss(obj) => obj.member_tenant_id = Some(id),
                DnsServer::DnsMadeEasy(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Domeneshop(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Dreamhost(obj) => obj.member_tenant_id = Some(id),
                DnsServer::DuckDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Dynu(obj) => obj.member_tenant_id = Some(id),
                DnsServer::EasyDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::EdgeDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Exoscale(obj) => obj.member_tenant_id = Some(id),
                DnsServer::FreeMyIp(obj) => obj.member_tenant_id = Some(id),
                DnsServer::GandiV5(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Gcore(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Glesys(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Godaddy(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Hetzner(obj) => obj.member_tenant_id = Some(id),
                DnsServer::HostingDe(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Hostinger(obj) => obj.member_tenant_id = Some(id),
                DnsServer::HuaweiCloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Hurricane(obj) => obj.member_tenant_id = Some(id),
                DnsServer::IbmCloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Infoblox(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Infomaniak(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Inwx(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Ionos(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Ipv64(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Joker(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Lightsail(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Linode(obj) => obj.member_tenant_id = Some(id),
                DnsServer::LuaDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::MythicBeasts(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Namecheap(obj) => obj.member_tenant_id = Some(id),
                DnsServer::NameDotCom(obj) => obj.member_tenant_id = Some(id),
                DnsServer::NameSilo(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Netcup(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Netlify(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Nifcloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Ns1(obj) => obj.member_tenant_id = Some(id),
                DnsServer::OracleCloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Plesk(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Safedns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Scaleway(obj) => obj.member_tenant_id = Some(id),
                DnsServer::TencentCloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Transip(obj) => obj.member_tenant_id = Some(id),
                DnsServer::UltraDns(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Vercel(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Volcengine(obj) => obj.member_tenant_id = Some(id),
                DnsServer::Vultr(obj) => obj.member_tenant_id = Some(id),
                DnsServer::WebSupport(obj) => obj.member_tenant_id = Some(id),
                DnsServer::YandexCloud(obj) => obj.member_tenant_id = Some(id),
                DnsServer::PowerDns(obj) => obj.member_tenant_id = Some(id),
            },
            ObjectInner::Domain(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::MailingList(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::OAuthClient(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::Role(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::TlsExternalReport(obj) => obj.member_tenant_id = Some(id),
            _ => {}
        }
    }

    // SPDX-SnippetEnd
    pub fn account_id(&self) -> Option<Id> {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(inner) => match inner.as_ref() {
                ArchivedItem::Email(obj) => Some(obj.account_id),
                ArchivedItem::FileNode(obj) => Some(obj.account_id),
                ArchivedItem::CalendarEvent(obj) => Some(obj.account_id),
                ArchivedItem::ContactCard(obj) => Some(obj.account_id),
                ArchivedItem::SieveScript(obj) => Some(obj.account_id),
            },
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(obj) => Some(obj.account_id),
            // SPDX-SnippetEnd
            ObjectInner::OAuthGrant(obj) => Some(obj.account_id),
            ObjectInner::PublicKey(obj) => Some(obj.account_id),
            ObjectInner::SpamTrainingSample(obj) => obj.account_id,
            ObjectInner::Task(inner) => match inner.as_ref() {
                Task::CalendarAlarmEmail(obj) => Some(obj.account_id),
                Task::CalendarAlarmNotification(obj) => Some(obj.account_id),
                Task::CalendarItipMessage(obj) => Some(obj.account_id),
                Task::MergeThreads(obj) => Some(obj.account_id),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                Task::RestoreArchivedItem(obj) => Some(obj.account_id),
                // SPDX-SnippetEnd
                Task::DestroyAccount(obj) => Some(obj.account_id),
                Task::AccountMaintenance(obj) => Some(obj.account_id),
                Task::ShareRevokeCleanup(obj) => Some(obj.account_id),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn set_account_id(&mut self, id: Id) {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(inner) => match inner.as_mut() {
                ArchivedItem::Email(obj) => obj.account_id = id,
                ArchivedItem::FileNode(obj) => obj.account_id = id,
                ArchivedItem::CalendarEvent(obj) => obj.account_id = id,
                ArchivedItem::ContactCard(obj) => obj.account_id = id,
                ArchivedItem::SieveScript(obj) => obj.account_id = id,
            },
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(obj) => obj.account_id = id,
            // SPDX-SnippetEnd
            ObjectInner::OAuthGrant(obj) => obj.account_id = id,
            ObjectInner::PublicKey(obj) => obj.account_id = id,
            ObjectInner::SpamTrainingSample(obj) => obj.account_id = Some(id),
            ObjectInner::Task(inner) => match inner.as_mut() {
                Task::CalendarAlarmEmail(obj) => obj.account_id = id,
                Task::CalendarAlarmNotification(obj) => obj.account_id = id,
                Task::CalendarItipMessage(obj) => obj.account_id = id,
                Task::MergeThreads(obj) => obj.account_id = id,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                Task::RestoreArchivedItem(obj) => obj.account_id = id,
                // SPDX-SnippetEnd
                Task::DestroyAccount(obj) => obj.account_id = id,
                Task::AccountMaintenance(obj) => obj.account_id = id,
                Task::ShareRevokeCleanup(obj) => obj.account_id = id,
                _ => {}
            },
            _ => {}
        }
    }

    pub fn to_pickled_vec(&self) -> Vec<u8> {
        match &self {
            ObjectInner::Account(obj) => obj.to_pickled_vec(),
            ObjectInner::AccountPassword(_) => unimplemented!("AccountPassword is not stored"),
            ObjectInner::AccountSettings(_) => unimplemented!("AccountSettings is not stored"),
            ObjectInner::AcmeProvider(obj) => obj.to_pickled_vec(),
            ObjectInner::Action(_) => unimplemented!("Action is not stored"),
            ObjectInner::AddressBook(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(obj) => obj.to_pickled_vec(),
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::AllowedIp(obj) => obj.to_pickled_vec(),
            ObjectInner::ApiKey(_) => unimplemented!("ApiKey is not stored"),
            ObjectInner::AppPassword(_) => unimplemented!("AppPassword is not stored"),
            ObjectInner::Application(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::ArfExternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::Asn(obj) => obj.to_pickled_vec(),
            ObjectInner::Authentication(obj) => obj.to_pickled_vec(),
            ObjectInner::BlobStore(obj) => obj.to_pickled_vec(),
            ObjectInner::BlockedIp(obj) => obj.to_pickled_vec(),
            ObjectInner::Bootstrap(_) => unimplemented!("Bootstrap is not stored"),
            ObjectInner::Cache(obj) => obj.to_pickled_vec(),
            ObjectInner::Calendar(obj) => obj.to_pickled_vec(),
            ObjectInner::CalendarAlarm(obj) => obj.to_pickled_vec(),
            ObjectInner::CalendarScheduling(obj) => obj.to_pickled_vec(),
            ObjectInner::Certificate(obj) => obj.to_pickled_vec(),
            ObjectInner::ClusterNode(_) => unimplemented!("ClusterNode is not stored"),
            ObjectInner::ClusterRole(obj) => obj.to_pickled_vec(),
            ObjectInner::Coordinator(obj) => obj.to_pickled_vec(),
            ObjectInner::DataRetention(obj) => obj.to_pickled_vec(),
            ObjectInner::DataStore(_) => unimplemented!("DataStore is not stored"),
            ObjectInner::Directory(obj) => obj.to_pickled_vec(),
            ObjectInner::DkimReportSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::DkimSignature(obj) => obj.to_pickled_vec(),
            ObjectInner::DmarcExternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::DmarcInternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::DmarcReportSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::DnsResolver(obj) => obj.to_pickled_vec(),
            ObjectInner::DnsServer(obj) => obj.to_pickled_vec(),
            ObjectInner::Domain(obj) => obj.to_pickled_vec(),
            ObjectInner::DsnReportSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::Email(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Enterprise(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::EventTracingLevel(obj) => obj.to_pickled_vec(),
            ObjectInner::FileStorage(obj) => obj.to_pickled_vec(),
            ObjectInner::Http(obj) => obj.to_pickled_vec(),
            ObjectInner::HttpForm(obj) => obj.to_pickled_vec(),
            ObjectInner::HttpLookup(obj) => obj.to_pickled_vec(),
            ObjectInner::Imap(obj) => obj.to_pickled_vec(),
            ObjectInner::InMemoryStore(obj) => obj.to_pickled_vec(),
            ObjectInner::IndexQueueStatus(_) => unimplemented!("IndexQueueStatus is not stored"),
            ObjectInner::Jmap(obj) => obj.to_pickled_vec(),
            ObjectInner::Log(_) => unimplemented!("Log is not stored"),
            ObjectInner::MailingList(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::MemoryLookupKey(obj) => obj.to_pickled_vec(),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.to_pickled_vec(),
            ObjectInner::Metadata(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::Metrics(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::MtaConnectionStrategy(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaDeliverySchedule(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaExtensions(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaHook(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaInboundSession(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaInboundThrottle(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaMilter(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaOutboundStrategy(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaOutboundThrottle(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaQueueQuota(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaRoute(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaStageAuth(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaStageConnect(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaStageData(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaStageEhlo(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaStageMail(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaStageRcpt(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaSts(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaTlsStrategy(obj) => obj.to_pickled_vec(),
            ObjectInner::MtaVirtualQueue(obj) => obj.to_pickled_vec(),
            ObjectInner::NetworkListener(obj) => obj.to_pickled_vec(),
            ObjectInner::OAuthClient(obj) => obj.to_pickled_vec(),
            ObjectInner::OAuthGrant(obj) => obj.to_pickled_vec(),
            ObjectInner::OidcProvider(obj) => obj.to_pickled_vec(),
            ObjectInner::PublicKey(obj) => obj.to_pickled_vec(),
            ObjectInner::QueuedMessage(_) => unimplemented!("QueuedMessage is not stored"),
            ObjectInner::ReportSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::Role(obj) => obj.to_pickled_vec(),
            ObjectInner::Search(obj) => obj.to_pickled_vec(),
            ObjectInner::SearchStore(obj) => obj.to_pickled_vec(),
            ObjectInner::Security(obj) => obj.to_pickled_vec(),
            ObjectInner::SenderAuth(obj) => obj.to_pickled_vec(),
            ObjectInner::Sharing(obj) => obj.to_pickled_vec(),
            ObjectInner::SieveSystemInterpreter(obj) => obj.to_pickled_vec(),
            ObjectInner::SieveSystemScript(obj) => obj.to_pickled_vec(),
            ObjectInner::SieveUserInterpreter(obj) => obj.to_pickled_vec(),
            ObjectInner::SieveUserScript(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::SpamClassifier(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamDnsblServer(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamDnsblSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamFileExtension(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamPyzor(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamRule(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamTag(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamTrainingSample(obj) => obj.to_pickled_vec(),
            ObjectInner::SpfReportSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::StoreLookup(obj) => obj.to_pickled_vec(),
            ObjectInner::SystemSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::Task(obj) => obj.to_pickled_vec(),
            ObjectInner::TaskManager(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::TlsExternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::TlsInternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::TlsReportSettings(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Trace(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::Tracer(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(obj) => obj.to_pickled_vec(),
            // SPDX-SnippetEnd
            ObjectInner::WebDav(obj) => obj.to_pickled_vec(),
            ObjectInner::WebHook(obj) => obj.to_pickled_vec(),
        }
    }

    pub fn unpickle(
        object: ObjectType,
        stream: &mut crate::pickle::PickledStream<'_>,
    ) -> Option<Self> {
        match object {
            ObjectType::Account => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Account(Box::new(obj)))
            }
            ObjectType::AccountPassword => unimplemented!("AccountPassword is not stored"),
            ObjectType::AccountSettings => unimplemented!("AccountSettings is not stored"),
            ObjectType::AcmeProvider => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::AcmeProvider(Box::new(obj)))
            }
            ObjectType::Action => unimplemented!("Action is not stored"),
            ObjectType::AddressBook => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::AddressBook(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::AiModel(Box::new(obj)))
            }
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Alert(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::AllowedIp(Box::new(obj)))
            }
            ObjectType::ApiKey => unimplemented!("ApiKey is not stored"),
            ObjectType::AppPassword => unimplemented!("AppPassword is not stored"),
            ObjectType::Application => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Application(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::ArchivedItem(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::ArfExternalReport(Box::new(obj)))
            }
            ObjectType::Asn => Pickle::unpickle(stream).map(|obj| ObjectInner::Asn(Box::new(obj))),
            ObjectType::Authentication => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Authentication(Box::new(obj)))
            }
            ObjectType::BlobStore => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::BlobStore(Box::new(obj)))
            }
            ObjectType::BlockedIp => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::BlockedIp(Box::new(obj)))
            }
            ObjectType::Bootstrap => unimplemented!("Bootstrap is not stored"),
            ObjectType::Cache => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Cache(Box::new(obj)))
            }
            ObjectType::Calendar => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Calendar(Box::new(obj)))
            }
            ObjectType::CalendarAlarm => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::CalendarAlarm(Box::new(obj)))
            }
            ObjectType::CalendarScheduling => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::CalendarScheduling(Box::new(obj)))
            }
            ObjectType::Certificate => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Certificate(Box::new(obj)))
            }
            ObjectType::ClusterNode => unimplemented!("ClusterNode is not stored"),
            ObjectType::ClusterRole => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::ClusterRole(Box::new(obj)))
            }
            ObjectType::Coordinator => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Coordinator(Box::new(obj)))
            }
            ObjectType::DataRetention => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DataRetention(Box::new(obj)))
            }
            ObjectType::DataStore => unimplemented!("DataStore is not stored"),
            ObjectType::Directory => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Directory(Box::new(obj)))
            }
            ObjectType::DkimReportSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DkimReportSettings(Box::new(obj)))
            }
            ObjectType::DkimSignature => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DkimSignature(Box::new(obj)))
            }
            ObjectType::DmarcExternalReport => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DmarcExternalReport(Box::new(obj)))
            }
            ObjectType::DmarcInternalReport => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DmarcInternalReport(Box::new(obj)))
            }
            ObjectType::DmarcReportSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DmarcReportSettings(Box::new(obj)))
            }
            ObjectType::DnsResolver => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DnsResolver(Box::new(obj)))
            }
            ObjectType::DnsServer => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DnsServer(Box::new(obj)))
            }
            ObjectType::Domain => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Domain(Box::new(obj)))
            }
            ObjectType::DsnReportSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::DsnReportSettings(Box::new(obj)))
            }
            ObjectType::Email => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Email(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Enterprise(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::EventTracingLevel(Box::new(obj)))
            }
            ObjectType::FileStorage => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::FileStorage(Box::new(obj)))
            }
            ObjectType::Http => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Http(Box::new(obj)))
            }
            ObjectType::HttpForm => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::HttpForm(Box::new(obj)))
            }
            ObjectType::HttpLookup => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::HttpLookup(Box::new(obj)))
            }
            ObjectType::Imap => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Imap(Box::new(obj)))
            }
            ObjectType::InMemoryStore => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::InMemoryStore(Box::new(obj)))
            }
            ObjectType::IndexQueueStatus => unimplemented!("IndexQueueStatus is not stored"),
            ObjectType::Jmap => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Jmap(Box::new(obj)))
            }
            ObjectType::Log => unimplemented!("Log is not stored"),
            ObjectType::MailingList => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MailingList(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MaskedEmail(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MemoryLookupKey(Box::new(obj)))
            }
            ObjectType::MemoryLookupKeyValue => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MemoryLookupKeyValue(Box::new(obj)))
            }
            ObjectType::Metadata => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Metadata(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Metric(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::Metrics => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Metrics(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MetricsStore(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => Pickle::unpickle(stream)
                .map(|obj| ObjectInner::MtaConnectionStrategy(Box::new(obj))),
            ObjectType::MtaDeliverySchedule => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaDeliverySchedule(Box::new(obj)))
            }
            ObjectType::MtaExtensions => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaExtensions(Box::new(obj)))
            }
            ObjectType::MtaHook => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaHook(Box::new(obj)))
            }
            ObjectType::MtaInboundSession => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaInboundSession(Box::new(obj)))
            }
            ObjectType::MtaInboundThrottle => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaInboundThrottle(Box::new(obj)))
            }
            ObjectType::MtaMilter => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaMilter(Box::new(obj)))
            }
            ObjectType::MtaOutboundStrategy => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaOutboundStrategy(Box::new(obj)))
            }
            ObjectType::MtaOutboundThrottle => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaOutboundThrottle(Box::new(obj)))
            }
            ObjectType::MtaQueueQuota => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaQueueQuota(Box::new(obj)))
            }
            ObjectType::MtaRoute => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaRoute(Box::new(obj)))
            }
            ObjectType::MtaStageAuth => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaStageAuth(Box::new(obj)))
            }
            ObjectType::MtaStageConnect => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaStageConnect(Box::new(obj)))
            }
            ObjectType::MtaStageData => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaStageData(Box::new(obj)))
            }
            ObjectType::MtaStageEhlo => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaStageEhlo(Box::new(obj)))
            }
            ObjectType::MtaStageMail => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaStageMail(Box::new(obj)))
            }
            ObjectType::MtaStageRcpt => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaStageRcpt(Box::new(obj)))
            }
            ObjectType::MtaSts => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaSts(Box::new(obj)))
            }
            ObjectType::MtaTlsStrategy => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaTlsStrategy(Box::new(obj)))
            }
            ObjectType::MtaVirtualQueue => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::MtaVirtualQueue(Box::new(obj)))
            }
            ObjectType::NetworkListener => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::NetworkListener(Box::new(obj)))
            }
            ObjectType::OAuthClient => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::OAuthClient(Box::new(obj)))
            }
            ObjectType::OAuthGrant => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::OAuthGrant(Box::new(obj)))
            }
            ObjectType::OidcProvider => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::OidcProvider(Box::new(obj)))
            }
            ObjectType::PublicKey => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::PublicKey(Box::new(obj)))
            }
            ObjectType::QueuedMessage => unimplemented!("QueuedMessage is not stored"),
            ObjectType::ReportSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::ReportSettings(Box::new(obj)))
            }
            ObjectType::Role => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Role(Box::new(obj)))
            }
            ObjectType::Search => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Search(Box::new(obj)))
            }
            ObjectType::SearchStore => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SearchStore(Box::new(obj)))
            }
            ObjectType::Security => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Security(Box::new(obj)))
            }
            ObjectType::SenderAuth => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SenderAuth(Box::new(obj)))
            }
            ObjectType::Sharing => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Sharing(Box::new(obj)))
            }
            ObjectType::SieveSystemInterpreter => Pickle::unpickle(stream)
                .map(|obj| ObjectInner::SieveSystemInterpreter(Box::new(obj))),
            ObjectType::SieveSystemScript => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SieveSystemScript(Box::new(obj)))
            }
            ObjectType::SieveUserInterpreter => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SieveUserInterpreter(Box::new(obj)))
            }
            ObjectType::SieveUserScript => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SieveUserScript(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamAi(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamClassifier(Box::new(obj)))
            }
            ObjectType::SpamDnsblServer => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamDnsblServer(Box::new(obj)))
            }
            ObjectType::SpamDnsblSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamDnsblSettings(Box::new(obj)))
            }
            ObjectType::SpamFileExtension => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamFileExtension(Box::new(obj)))
            }
            ObjectType::SpamPyzor => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamPyzor(Box::new(obj)))
            }
            ObjectType::SpamRule => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamRule(Box::new(obj)))
            }
            ObjectType::SpamSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamSettings(Box::new(obj)))
            }
            ObjectType::SpamTag => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamTag(Box::new(obj)))
            }
            ObjectType::SpamTrainingSample => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpamTrainingSample(Box::new(obj)))
            }
            ObjectType::SpfReportSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SpfReportSettings(Box::new(obj)))
            }
            ObjectType::StoreLookup => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::StoreLookup(Box::new(obj)))
            }
            ObjectType::SystemSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::SystemSettings(Box::new(obj)))
            }
            ObjectType::Task => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Task(Box::new(obj)))
            }
            ObjectType::TaskManager => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::TaskManager(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Tenant(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::TlsExternalReport(Box::new(obj)))
            }
            ObjectType::TlsInternalReport => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::TlsInternalReport(Box::new(obj)))
            }
            ObjectType::TlsReportSettings => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::TlsReportSettings(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Trace(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::Tracer => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::Tracer(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::TracingStore(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::WebDav => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::WebDav(Box::new(obj)))
            }
            ObjectType::WebHook => {
                Pickle::unpickle(stream).map(|obj| ObjectInner::WebHook(Box::new(obj)))
            }
        }
    }

    pub fn deserialize<'de, D>(object: ObjectType, deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match object {
            ObjectType::Account => {
                Account::deserialize(deserializer).map(|obj| ObjectInner::Account(Box::new(obj)))
            }
            ObjectType::AccountPassword => AccountPassword::deserialize(deserializer)
                .map(|obj| ObjectInner::AccountPassword(Box::new(obj))),
            ObjectType::AccountSettings => AccountSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::AccountSettings(Box::new(obj))),
            ObjectType::AcmeProvider => AcmeProvider::deserialize(deserializer)
                .map(|obj| ObjectInner::AcmeProvider(Box::new(obj))),
            ObjectType::Action => {
                Action::deserialize(deserializer).map(|obj| ObjectInner::Action(Box::new(obj)))
            }
            ObjectType::AddressBook => AddressBook::deserialize(deserializer)
                .map(|obj| ObjectInner::AddressBook(Box::new(obj))),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => {
                AiModel::deserialize(deserializer).map(|obj| ObjectInner::AiModel(Box::new(obj)))
            }
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => {
                Alert::deserialize(deserializer).map(|obj| ObjectInner::Alert(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => AllowedIp::deserialize(deserializer)
                .map(|obj| ObjectInner::AllowedIp(Box::new(obj))),
            ObjectType::ApiKey => {
                ApiKey::deserialize(deserializer).map(|obj| ObjectInner::ApiKey(Box::new(obj)))
            }
            ObjectType::AppPassword => AppPassword::deserialize(deserializer)
                .map(|obj| ObjectInner::AppPassword(Box::new(obj))),
            ObjectType::Application => Application::deserialize(deserializer)
                .map(|obj| ObjectInner::Application(Box::new(obj))),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => ArchivedItem::deserialize(deserializer)
                .map(|obj| ObjectInner::ArchivedItem(Box::new(obj))),
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => ArfExternalReport::deserialize(deserializer)
                .map(|obj| ObjectInner::ArfExternalReport(Box::new(obj))),
            ObjectType::Asn => {
                Asn::deserialize(deserializer).map(|obj| ObjectInner::Asn(Box::new(obj)))
            }
            ObjectType::Authentication => Authentication::deserialize(deserializer)
                .map(|obj| ObjectInner::Authentication(Box::new(obj))),
            ObjectType::BlobStore => BlobStore::deserialize(deserializer)
                .map(|obj| ObjectInner::BlobStore(Box::new(obj))),
            ObjectType::BlockedIp => BlockedIp::deserialize(deserializer)
                .map(|obj| ObjectInner::BlockedIp(Box::new(obj))),
            ObjectType::Bootstrap => Bootstrap::deserialize(deserializer)
                .map(|obj| ObjectInner::Bootstrap(Box::new(obj))),
            ObjectType::Cache => {
                Cache::deserialize(deserializer).map(|obj| ObjectInner::Cache(Box::new(obj)))
            }
            ObjectType::Calendar => {
                Calendar::deserialize(deserializer).map(|obj| ObjectInner::Calendar(Box::new(obj)))
            }
            ObjectType::CalendarAlarm => CalendarAlarm::deserialize(deserializer)
                .map(|obj| ObjectInner::CalendarAlarm(Box::new(obj))),
            ObjectType::CalendarScheduling => CalendarScheduling::deserialize(deserializer)
                .map(|obj| ObjectInner::CalendarScheduling(Box::new(obj))),
            ObjectType::Certificate => Certificate::deserialize(deserializer)
                .map(|obj| ObjectInner::Certificate(Box::new(obj))),
            ObjectType::ClusterNode => ClusterNode::deserialize(deserializer)
                .map(|obj| ObjectInner::ClusterNode(Box::new(obj))),
            ObjectType::ClusterRole => ClusterRole::deserialize(deserializer)
                .map(|obj| ObjectInner::ClusterRole(Box::new(obj))),
            ObjectType::Coordinator => Coordinator::deserialize(deserializer)
                .map(|obj| ObjectInner::Coordinator(Box::new(obj))),
            ObjectType::DataRetention => DataRetention::deserialize(deserializer)
                .map(|obj| ObjectInner::DataRetention(Box::new(obj))),
            ObjectType::DataStore => DataStore::deserialize(deserializer)
                .map(|obj| ObjectInner::DataStore(Box::new(obj))),
            ObjectType::Directory => Directory::deserialize(deserializer)
                .map(|obj| ObjectInner::Directory(Box::new(obj))),
            ObjectType::DkimReportSettings => DkimReportSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::DkimReportSettings(Box::new(obj))),
            ObjectType::DkimSignature => DkimSignature::deserialize(deserializer)
                .map(|obj| ObjectInner::DkimSignature(Box::new(obj))),
            ObjectType::DmarcExternalReport => DmarcExternalReport::deserialize(deserializer)
                .map(|obj| ObjectInner::DmarcExternalReport(Box::new(obj))),
            ObjectType::DmarcInternalReport => DmarcInternalReport::deserialize(deserializer)
                .map(|obj| ObjectInner::DmarcInternalReport(Box::new(obj))),
            ObjectType::DmarcReportSettings => DmarcReportSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::DmarcReportSettings(Box::new(obj))),
            ObjectType::DnsResolver => DnsResolver::deserialize(deserializer)
                .map(|obj| ObjectInner::DnsResolver(Box::new(obj))),
            ObjectType::DnsServer => DnsServer::deserialize(deserializer)
                .map(|obj| ObjectInner::DnsServer(Box::new(obj))),
            ObjectType::Domain => {
                Domain::deserialize(deserializer).map(|obj| ObjectInner::Domain(Box::new(obj)))
            }
            ObjectType::DsnReportSettings => DsnReportSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::DsnReportSettings(Box::new(obj))),
            ObjectType::Email => {
                Email::deserialize(deserializer).map(|obj| ObjectInner::Email(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => Enterprise::deserialize(deserializer)
                .map(|obj| ObjectInner::Enterprise(Box::new(obj))),
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => EventTracingLevel::deserialize(deserializer)
                .map(|obj| ObjectInner::EventTracingLevel(Box::new(obj))),
            ObjectType::FileStorage => FileStorage::deserialize(deserializer)
                .map(|obj| ObjectInner::FileStorage(Box::new(obj))),
            ObjectType::Http => {
                Http::deserialize(deserializer).map(|obj| ObjectInner::Http(Box::new(obj)))
            }
            ObjectType::HttpForm => {
                HttpForm::deserialize(deserializer).map(|obj| ObjectInner::HttpForm(Box::new(obj)))
            }
            ObjectType::HttpLookup => HttpLookup::deserialize(deserializer)
                .map(|obj| ObjectInner::HttpLookup(Box::new(obj))),
            ObjectType::Imap => {
                Imap::deserialize(deserializer).map(|obj| ObjectInner::Imap(Box::new(obj)))
            }
            ObjectType::InMemoryStore => InMemoryStore::deserialize(deserializer)
                .map(|obj| ObjectInner::InMemoryStore(Box::new(obj))),
            ObjectType::IndexQueueStatus => IndexQueueStatus::deserialize(deserializer)
                .map(|obj| ObjectInner::IndexQueueStatus(Box::new(obj))),
            ObjectType::Jmap => {
                Jmap::deserialize(deserializer).map(|obj| ObjectInner::Jmap(Box::new(obj)))
            }
            ObjectType::Log => {
                Log::deserialize(deserializer).map(|obj| ObjectInner::Log(Box::new(obj)))
            }
            ObjectType::MailingList => MailingList::deserialize(deserializer)
                .map(|obj| ObjectInner::MailingList(Box::new(obj))),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => MaskedEmail::deserialize(deserializer)
                .map(|obj| ObjectInner::MaskedEmail(Box::new(obj))),
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => MemoryLookupKey::deserialize(deserializer)
                .map(|obj| ObjectInner::MemoryLookupKey(Box::new(obj))),
            ObjectType::MemoryLookupKeyValue => MemoryLookupKeyValue::deserialize(deserializer)
                .map(|obj| ObjectInner::MemoryLookupKeyValue(Box::new(obj))),
            ObjectType::Metadata => {
                Metadata::deserialize(deserializer).map(|obj| ObjectInner::Metadata(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => {
                Metric::deserialize(deserializer).map(|obj| ObjectInner::Metric(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::Metrics => {
                Metrics::deserialize(deserializer).map(|obj| ObjectInner::Metrics(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => MetricsStore::deserialize(deserializer)
                .map(|obj| ObjectInner::MetricsStore(Box::new(obj))),
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => MtaConnectionStrategy::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaConnectionStrategy(Box::new(obj))),
            ObjectType::MtaDeliverySchedule => MtaDeliverySchedule::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaDeliverySchedule(Box::new(obj))),
            ObjectType::MtaExtensions => MtaExtensions::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaExtensions(Box::new(obj))),
            ObjectType::MtaHook => {
                MtaHook::deserialize(deserializer).map(|obj| ObjectInner::MtaHook(Box::new(obj)))
            }
            ObjectType::MtaInboundSession => MtaInboundSession::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaInboundSession(Box::new(obj))),
            ObjectType::MtaInboundThrottle => MtaInboundThrottle::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaInboundThrottle(Box::new(obj))),
            ObjectType::MtaMilter => MtaMilter::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaMilter(Box::new(obj))),
            ObjectType::MtaOutboundStrategy => MtaOutboundStrategy::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaOutboundStrategy(Box::new(obj))),
            ObjectType::MtaOutboundThrottle => MtaOutboundThrottle::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaOutboundThrottle(Box::new(obj))),
            ObjectType::MtaQueueQuota => MtaQueueQuota::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaQueueQuota(Box::new(obj))),
            ObjectType::MtaRoute => {
                MtaRoute::deserialize(deserializer).map(|obj| ObjectInner::MtaRoute(Box::new(obj)))
            }
            ObjectType::MtaStageAuth => MtaStageAuth::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaStageAuth(Box::new(obj))),
            ObjectType::MtaStageConnect => MtaStageConnect::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaStageConnect(Box::new(obj))),
            ObjectType::MtaStageData => MtaStageData::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaStageData(Box::new(obj))),
            ObjectType::MtaStageEhlo => MtaStageEhlo::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaStageEhlo(Box::new(obj))),
            ObjectType::MtaStageMail => MtaStageMail::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaStageMail(Box::new(obj))),
            ObjectType::MtaStageRcpt => MtaStageRcpt::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaStageRcpt(Box::new(obj))),
            ObjectType::MtaSts => {
                MtaSts::deserialize(deserializer).map(|obj| ObjectInner::MtaSts(Box::new(obj)))
            }
            ObjectType::MtaTlsStrategy => MtaTlsStrategy::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaTlsStrategy(Box::new(obj))),
            ObjectType::MtaVirtualQueue => MtaVirtualQueue::deserialize(deserializer)
                .map(|obj| ObjectInner::MtaVirtualQueue(Box::new(obj))),
            ObjectType::NetworkListener => NetworkListener::deserialize(deserializer)
                .map(|obj| ObjectInner::NetworkListener(Box::new(obj))),
            ObjectType::OAuthClient => OAuthClient::deserialize(deserializer)
                .map(|obj| ObjectInner::OAuthClient(Box::new(obj))),
            ObjectType::OAuthGrant => OAuthGrant::deserialize(deserializer)
                .map(|obj| ObjectInner::OAuthGrant(Box::new(obj))),
            ObjectType::OidcProvider => OidcProvider::deserialize(deserializer)
                .map(|obj| ObjectInner::OidcProvider(Box::new(obj))),
            ObjectType::PublicKey => PublicKey::deserialize(deserializer)
                .map(|obj| ObjectInner::PublicKey(Box::new(obj))),
            ObjectType::QueuedMessage => QueuedMessage::deserialize(deserializer)
                .map(|obj| ObjectInner::QueuedMessage(Box::new(obj))),
            ObjectType::ReportSettings => ReportSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::ReportSettings(Box::new(obj))),
            ObjectType::Role => {
                Role::deserialize(deserializer).map(|obj| ObjectInner::Role(Box::new(obj)))
            }
            ObjectType::Search => {
                Search::deserialize(deserializer).map(|obj| ObjectInner::Search(Box::new(obj)))
            }
            ObjectType::SearchStore => SearchStore::deserialize(deserializer)
                .map(|obj| ObjectInner::SearchStore(Box::new(obj))),
            ObjectType::Security => {
                Security::deserialize(deserializer).map(|obj| ObjectInner::Security(Box::new(obj)))
            }
            ObjectType::SenderAuth => SenderAuth::deserialize(deserializer)
                .map(|obj| ObjectInner::SenderAuth(Box::new(obj))),
            ObjectType::Sharing => {
                Sharing::deserialize(deserializer).map(|obj| ObjectInner::Sharing(Box::new(obj)))
            }
            ObjectType::SieveSystemInterpreter => SieveSystemInterpreter::deserialize(deserializer)
                .map(|obj| ObjectInner::SieveSystemInterpreter(Box::new(obj))),
            ObjectType::SieveSystemScript => SieveSystemScript::deserialize(deserializer)
                .map(|obj| ObjectInner::SieveSystemScript(Box::new(obj))),
            ObjectType::SieveUserInterpreter => SieveUserInterpreter::deserialize(deserializer)
                .map(|obj| ObjectInner::SieveUserInterpreter(Box::new(obj))),
            ObjectType::SieveUserScript => SieveUserScript::deserialize(deserializer)
                .map(|obj| ObjectInner::SieveUserScript(Box::new(obj))),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => {
                SpamAi::deserialize(deserializer).map(|obj| ObjectInner::SpamAi(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => SpamClassifier::deserialize(deserializer)
                .map(|obj| ObjectInner::SpamClassifier(Box::new(obj))),
            ObjectType::SpamDnsblServer => SpamDnsblServer::deserialize(deserializer)
                .map(|obj| ObjectInner::SpamDnsblServer(Box::new(obj))),
            ObjectType::SpamDnsblSettings => SpamDnsblSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::SpamDnsblSettings(Box::new(obj))),
            ObjectType::SpamFileExtension => SpamFileExtension::deserialize(deserializer)
                .map(|obj| ObjectInner::SpamFileExtension(Box::new(obj))),
            ObjectType::SpamPyzor => SpamPyzor::deserialize(deserializer)
                .map(|obj| ObjectInner::SpamPyzor(Box::new(obj))),
            ObjectType::SpamRule => {
                SpamRule::deserialize(deserializer).map(|obj| ObjectInner::SpamRule(Box::new(obj)))
            }
            ObjectType::SpamSettings => SpamSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::SpamSettings(Box::new(obj))),
            ObjectType::SpamTag => {
                SpamTag::deserialize(deserializer).map(|obj| ObjectInner::SpamTag(Box::new(obj)))
            }
            ObjectType::SpamTrainingSample => SpamTrainingSample::deserialize(deserializer)
                .map(|obj| ObjectInner::SpamTrainingSample(Box::new(obj))),
            ObjectType::SpfReportSettings => SpfReportSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::SpfReportSettings(Box::new(obj))),
            ObjectType::StoreLookup => StoreLookup::deserialize(deserializer)
                .map(|obj| ObjectInner::StoreLookup(Box::new(obj))),
            ObjectType::SystemSettings => SystemSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::SystemSettings(Box::new(obj))),
            ObjectType::Task => {
                Task::deserialize(deserializer).map(|obj| ObjectInner::Task(Box::new(obj)))
            }
            ObjectType::TaskManager => TaskManager::deserialize(deserializer)
                .map(|obj| ObjectInner::TaskManager(Box::new(obj))),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => {
                Tenant::deserialize(deserializer).map(|obj| ObjectInner::Tenant(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => TlsExternalReport::deserialize(deserializer)
                .map(|obj| ObjectInner::TlsExternalReport(Box::new(obj))),
            ObjectType::TlsInternalReport => TlsInternalReport::deserialize(deserializer)
                .map(|obj| ObjectInner::TlsInternalReport(Box::new(obj))),
            ObjectType::TlsReportSettings => TlsReportSettings::deserialize(deserializer)
                .map(|obj| ObjectInner::TlsReportSettings(Box::new(obj))),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => {
                Trace::deserialize(deserializer).map(|obj| ObjectInner::Trace(Box::new(obj)))
            }
            // SPDX-SnippetEnd
            ObjectType::Tracer => {
                Tracer::deserialize(deserializer).map(|obj| ObjectInner::Tracer(Box::new(obj)))
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => TracingStore::deserialize(deserializer)
                .map(|obj| ObjectInner::TracingStore(Box::new(obj))),
            // SPDX-SnippetEnd
            ObjectType::WebDav => {
                WebDav::deserialize(deserializer).map(|obj| ObjectInner::WebDav(Box::new(obj)))
            }
            ObjectType::WebHook => {
                WebHook::deserialize(deserializer).map(|obj| ObjectInner::WebHook(Box::new(obj)))
            }
        }
    }

    pub fn expression_ctxs(&self) -> Option<Vec<ExpressionContext<'_>>> {
        match &self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(obj) => Some(obj.expression_ctxs()),
            // SPDX-SnippetEnd
            ObjectInner::DkimReportSettings(obj) => Some(obj.expression_ctxs()),
            ObjectInner::DmarcReportSettings(obj) => Some(obj.expression_ctxs()),
            ObjectInner::DsnReportSettings(obj) => Some(obj.expression_ctxs()),
            ObjectInner::Http(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaExtensions(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaHook(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaInboundSession(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaInboundThrottle(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaMilter(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaOutboundStrategy(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaOutboundThrottle(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaQueueQuota(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaStageAuth(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaStageConnect(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaStageData(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaStageEhlo(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaStageMail(obj) => Some(obj.expression_ctxs()),
            ObjectInner::MtaStageRcpt(obj) => Some(obj.expression_ctxs()),
            ObjectInner::ReportSettings(obj) => Some(obj.expression_ctxs()),
            ObjectInner::SenderAuth(obj) => Some(obj.expression_ctxs()),
            ObjectInner::SieveSystemInterpreter(obj) => Some(obj.expression_ctxs()),
            ObjectInner::SieveUserInterpreter(obj) => Some(obj.expression_ctxs()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(obj) => Some(obj.expression_ctxs()),
            // SPDX-SnippetEnd
            ObjectInner::SpamDnsblServer(obj) => Some(obj.expression_ctxs()),
            ObjectInner::SpamRule(obj) => Some(obj.expression_ctxs()),
            ObjectInner::SpfReportSettings(obj) => Some(obj.expression_ctxs()),
            ObjectInner::TlsReportSettings(obj) => Some(obj.expression_ctxs()),
            _ => None,
        }
    }
}

impl Object {
    pub fn flags(&self) -> u64 {
        match &self.inner {
            ObjectInner::Account(_) => Account::FLAGS,
            ObjectInner::AccountPassword(_) => AccountPassword::FLAGS,
            ObjectInner::AccountSettings(_) => AccountSettings::FLAGS,
            ObjectInner::AcmeProvider(_) => AcmeProvider::FLAGS,
            ObjectInner::Action(_) => Action::FLAGS,
            ObjectInner::AddressBook(_) => AddressBook::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(_) => AiModel::FLAGS,
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(_) => Alert::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::AllowedIp(_) => AllowedIp::FLAGS,
            ObjectInner::ApiKey(_) => ApiKey::FLAGS,
            ObjectInner::AppPassword(_) => AppPassword::FLAGS,
            ObjectInner::Application(_) => Application::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(_) => ArchivedItem::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::ArfExternalReport(_) => ArfExternalReport::FLAGS,
            ObjectInner::Asn(_) => Asn::FLAGS,
            ObjectInner::Authentication(_) => Authentication::FLAGS,
            ObjectInner::BlobStore(_) => BlobStore::FLAGS,
            ObjectInner::BlockedIp(_) => BlockedIp::FLAGS,
            ObjectInner::Bootstrap(_) => Bootstrap::FLAGS,
            ObjectInner::Cache(_) => Cache::FLAGS,
            ObjectInner::Calendar(_) => Calendar::FLAGS,
            ObjectInner::CalendarAlarm(_) => CalendarAlarm::FLAGS,
            ObjectInner::CalendarScheduling(_) => CalendarScheduling::FLAGS,
            ObjectInner::Certificate(_) => Certificate::FLAGS,
            ObjectInner::ClusterNode(_) => ClusterNode::FLAGS,
            ObjectInner::ClusterRole(_) => ClusterRole::FLAGS,
            ObjectInner::Coordinator(_) => Coordinator::FLAGS,
            ObjectInner::DataRetention(_) => DataRetention::FLAGS,
            ObjectInner::DataStore(_) => DataStore::FLAGS,
            ObjectInner::Directory(_) => Directory::FLAGS,
            ObjectInner::DkimReportSettings(_) => DkimReportSettings::FLAGS,
            ObjectInner::DkimSignature(_) => DkimSignature::FLAGS,
            ObjectInner::DmarcExternalReport(_) => DmarcExternalReport::FLAGS,
            ObjectInner::DmarcInternalReport(_) => DmarcInternalReport::FLAGS,
            ObjectInner::DmarcReportSettings(_) => DmarcReportSettings::FLAGS,
            ObjectInner::DnsResolver(_) => DnsResolver::FLAGS,
            ObjectInner::DnsServer(_) => DnsServer::FLAGS,
            ObjectInner::Domain(_) => Domain::FLAGS,
            ObjectInner::DsnReportSettings(_) => DsnReportSettings::FLAGS,
            ObjectInner::Email(_) => Email::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Enterprise(_) => Enterprise::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::EventTracingLevel(_) => EventTracingLevel::FLAGS,
            ObjectInner::FileStorage(_) => FileStorage::FLAGS,
            ObjectInner::Http(_) => Http::FLAGS,
            ObjectInner::HttpForm(_) => HttpForm::FLAGS,
            ObjectInner::HttpLookup(_) => HttpLookup::FLAGS,
            ObjectInner::Imap(_) => Imap::FLAGS,
            ObjectInner::InMemoryStore(_) => InMemoryStore::FLAGS,
            ObjectInner::IndexQueueStatus(_) => IndexQueueStatus::FLAGS,
            ObjectInner::Jmap(_) => Jmap::FLAGS,
            ObjectInner::Log(_) => Log::FLAGS,
            ObjectInner::MailingList(_) => MailingList::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(_) => MaskedEmail::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::MemoryLookupKey(_) => MemoryLookupKey::FLAGS,
            ObjectInner::MemoryLookupKeyValue(_) => MemoryLookupKeyValue::FLAGS,
            ObjectInner::Metadata(_) => Metadata::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(_) => Metric::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::Metrics(_) => Metrics::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(_) => MetricsStore::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::MtaConnectionStrategy(_) => MtaConnectionStrategy::FLAGS,
            ObjectInner::MtaDeliverySchedule(_) => MtaDeliverySchedule::FLAGS,
            ObjectInner::MtaExtensions(_) => MtaExtensions::FLAGS,
            ObjectInner::MtaHook(_) => MtaHook::FLAGS,
            ObjectInner::MtaInboundSession(_) => MtaInboundSession::FLAGS,
            ObjectInner::MtaInboundThrottle(_) => MtaInboundThrottle::FLAGS,
            ObjectInner::MtaMilter(_) => MtaMilter::FLAGS,
            ObjectInner::MtaOutboundStrategy(_) => MtaOutboundStrategy::FLAGS,
            ObjectInner::MtaOutboundThrottle(_) => MtaOutboundThrottle::FLAGS,
            ObjectInner::MtaQueueQuota(_) => MtaQueueQuota::FLAGS,
            ObjectInner::MtaRoute(_) => MtaRoute::FLAGS,
            ObjectInner::MtaStageAuth(_) => MtaStageAuth::FLAGS,
            ObjectInner::MtaStageConnect(_) => MtaStageConnect::FLAGS,
            ObjectInner::MtaStageData(_) => MtaStageData::FLAGS,
            ObjectInner::MtaStageEhlo(_) => MtaStageEhlo::FLAGS,
            ObjectInner::MtaStageMail(_) => MtaStageMail::FLAGS,
            ObjectInner::MtaStageRcpt(_) => MtaStageRcpt::FLAGS,
            ObjectInner::MtaSts(_) => MtaSts::FLAGS,
            ObjectInner::MtaTlsStrategy(_) => MtaTlsStrategy::FLAGS,
            ObjectInner::MtaVirtualQueue(_) => MtaVirtualQueue::FLAGS,
            ObjectInner::NetworkListener(_) => NetworkListener::FLAGS,
            ObjectInner::OAuthClient(_) => OAuthClient::FLAGS,
            ObjectInner::OAuthGrant(_) => OAuthGrant::FLAGS,
            ObjectInner::OidcProvider(_) => OidcProvider::FLAGS,
            ObjectInner::PublicKey(_) => PublicKey::FLAGS,
            ObjectInner::QueuedMessage(_) => QueuedMessage::FLAGS,
            ObjectInner::ReportSettings(_) => ReportSettings::FLAGS,
            ObjectInner::Role(_) => Role::FLAGS,
            ObjectInner::Search(_) => Search::FLAGS,
            ObjectInner::SearchStore(_) => SearchStore::FLAGS,
            ObjectInner::Security(_) => Security::FLAGS,
            ObjectInner::SenderAuth(_) => SenderAuth::FLAGS,
            ObjectInner::Sharing(_) => Sharing::FLAGS,
            ObjectInner::SieveSystemInterpreter(_) => SieveSystemInterpreter::FLAGS,
            ObjectInner::SieveSystemScript(_) => SieveSystemScript::FLAGS,
            ObjectInner::SieveUserInterpreter(_) => SieveUserInterpreter::FLAGS,
            ObjectInner::SieveUserScript(_) => SieveUserScript::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(_) => SpamAi::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::SpamClassifier(_) => SpamClassifier::FLAGS,
            ObjectInner::SpamDnsblServer(_) => SpamDnsblServer::FLAGS,
            ObjectInner::SpamDnsblSettings(_) => SpamDnsblSettings::FLAGS,
            ObjectInner::SpamFileExtension(_) => SpamFileExtension::FLAGS,
            ObjectInner::SpamPyzor(_) => SpamPyzor::FLAGS,
            ObjectInner::SpamRule(_) => SpamRule::FLAGS,
            ObjectInner::SpamSettings(_) => SpamSettings::FLAGS,
            ObjectInner::SpamTag(_) => SpamTag::FLAGS,
            ObjectInner::SpamTrainingSample(_) => SpamTrainingSample::FLAGS,
            ObjectInner::SpfReportSettings(_) => SpfReportSettings::FLAGS,
            ObjectInner::StoreLookup(_) => StoreLookup::FLAGS,
            ObjectInner::SystemSettings(_) => SystemSettings::FLAGS,
            ObjectInner::Task(_) => Task::FLAGS,
            ObjectInner::TaskManager(_) => TaskManager::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(_) => Tenant::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::TlsExternalReport(_) => TlsExternalReport::FLAGS,
            ObjectInner::TlsInternalReport(_) => TlsInternalReport::FLAGS,
            ObjectInner::TlsReportSettings(_) => TlsReportSettings::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Trace(_) => Trace::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::Tracer(_) => Tracer::FLAGS,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(_) => TracingStore::FLAGS,
            // SPDX-SnippetEnd
            ObjectInner::WebDav(_) => WebDav::FLAGS,
            ObjectInner::WebHook(_) => WebHook::FLAGS,
        }
    }

    pub fn object_type(&self) -> ObjectType {
        match &self.inner {
            ObjectInner::Account(_) => ObjectType::Account,
            ObjectInner::AccountPassword(_) => ObjectType::AccountPassword,
            ObjectInner::AccountSettings(_) => ObjectType::AccountSettings,
            ObjectInner::AcmeProvider(_) => ObjectType::AcmeProvider,
            ObjectInner::Action(_) => ObjectType::Action,
            ObjectInner::AddressBook(_) => ObjectType::AddressBook,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(_) => ObjectType::AiModel,
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(_) => ObjectType::Alert,
            // SPDX-SnippetEnd
            ObjectInner::AllowedIp(_) => ObjectType::AllowedIp,
            ObjectInner::ApiKey(_) => ObjectType::ApiKey,
            ObjectInner::AppPassword(_) => ObjectType::AppPassword,
            ObjectInner::Application(_) => ObjectType::Application,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(_) => ObjectType::ArchivedItem,
            // SPDX-SnippetEnd
            ObjectInner::ArfExternalReport(_) => ObjectType::ArfExternalReport,
            ObjectInner::Asn(_) => ObjectType::Asn,
            ObjectInner::Authentication(_) => ObjectType::Authentication,
            ObjectInner::BlobStore(_) => ObjectType::BlobStore,
            ObjectInner::BlockedIp(_) => ObjectType::BlockedIp,
            ObjectInner::Bootstrap(_) => ObjectType::Bootstrap,
            ObjectInner::Cache(_) => ObjectType::Cache,
            ObjectInner::Calendar(_) => ObjectType::Calendar,
            ObjectInner::CalendarAlarm(_) => ObjectType::CalendarAlarm,
            ObjectInner::CalendarScheduling(_) => ObjectType::CalendarScheduling,
            ObjectInner::Certificate(_) => ObjectType::Certificate,
            ObjectInner::ClusterNode(_) => ObjectType::ClusterNode,
            ObjectInner::ClusterRole(_) => ObjectType::ClusterRole,
            ObjectInner::Coordinator(_) => ObjectType::Coordinator,
            ObjectInner::DataRetention(_) => ObjectType::DataRetention,
            ObjectInner::DataStore(_) => ObjectType::DataStore,
            ObjectInner::Directory(_) => ObjectType::Directory,
            ObjectInner::DkimReportSettings(_) => ObjectType::DkimReportSettings,
            ObjectInner::DkimSignature(_) => ObjectType::DkimSignature,
            ObjectInner::DmarcExternalReport(_) => ObjectType::DmarcExternalReport,
            ObjectInner::DmarcInternalReport(_) => ObjectType::DmarcInternalReport,
            ObjectInner::DmarcReportSettings(_) => ObjectType::DmarcReportSettings,
            ObjectInner::DnsResolver(_) => ObjectType::DnsResolver,
            ObjectInner::DnsServer(_) => ObjectType::DnsServer,
            ObjectInner::Domain(_) => ObjectType::Domain,
            ObjectInner::DsnReportSettings(_) => ObjectType::DsnReportSettings,
            ObjectInner::Email(_) => ObjectType::Email,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Enterprise(_) => ObjectType::Enterprise,
            // SPDX-SnippetEnd
            ObjectInner::EventTracingLevel(_) => ObjectType::EventTracingLevel,
            ObjectInner::FileStorage(_) => ObjectType::FileStorage,
            ObjectInner::Http(_) => ObjectType::Http,
            ObjectInner::HttpForm(_) => ObjectType::HttpForm,
            ObjectInner::HttpLookup(_) => ObjectType::HttpLookup,
            ObjectInner::Imap(_) => ObjectType::Imap,
            ObjectInner::InMemoryStore(_) => ObjectType::InMemoryStore,
            ObjectInner::IndexQueueStatus(_) => ObjectType::IndexQueueStatus,
            ObjectInner::Jmap(_) => ObjectType::Jmap,
            ObjectInner::Log(_) => ObjectType::Log,
            ObjectInner::MailingList(_) => ObjectType::MailingList,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(_) => ObjectType::MaskedEmail,
            // SPDX-SnippetEnd
            ObjectInner::MemoryLookupKey(_) => ObjectType::MemoryLookupKey,
            ObjectInner::MemoryLookupKeyValue(_) => ObjectType::MemoryLookupKeyValue,
            ObjectInner::Metadata(_) => ObjectType::Metadata,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(_) => ObjectType::Metric,
            // SPDX-SnippetEnd
            ObjectInner::Metrics(_) => ObjectType::Metrics,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(_) => ObjectType::MetricsStore,
            // SPDX-SnippetEnd
            ObjectInner::MtaConnectionStrategy(_) => ObjectType::MtaConnectionStrategy,
            ObjectInner::MtaDeliverySchedule(_) => ObjectType::MtaDeliverySchedule,
            ObjectInner::MtaExtensions(_) => ObjectType::MtaExtensions,
            ObjectInner::MtaHook(_) => ObjectType::MtaHook,
            ObjectInner::MtaInboundSession(_) => ObjectType::MtaInboundSession,
            ObjectInner::MtaInboundThrottle(_) => ObjectType::MtaInboundThrottle,
            ObjectInner::MtaMilter(_) => ObjectType::MtaMilter,
            ObjectInner::MtaOutboundStrategy(_) => ObjectType::MtaOutboundStrategy,
            ObjectInner::MtaOutboundThrottle(_) => ObjectType::MtaOutboundThrottle,
            ObjectInner::MtaQueueQuota(_) => ObjectType::MtaQueueQuota,
            ObjectInner::MtaRoute(_) => ObjectType::MtaRoute,
            ObjectInner::MtaStageAuth(_) => ObjectType::MtaStageAuth,
            ObjectInner::MtaStageConnect(_) => ObjectType::MtaStageConnect,
            ObjectInner::MtaStageData(_) => ObjectType::MtaStageData,
            ObjectInner::MtaStageEhlo(_) => ObjectType::MtaStageEhlo,
            ObjectInner::MtaStageMail(_) => ObjectType::MtaStageMail,
            ObjectInner::MtaStageRcpt(_) => ObjectType::MtaStageRcpt,
            ObjectInner::MtaSts(_) => ObjectType::MtaSts,
            ObjectInner::MtaTlsStrategy(_) => ObjectType::MtaTlsStrategy,
            ObjectInner::MtaVirtualQueue(_) => ObjectType::MtaVirtualQueue,
            ObjectInner::NetworkListener(_) => ObjectType::NetworkListener,
            ObjectInner::OAuthClient(_) => ObjectType::OAuthClient,
            ObjectInner::OAuthGrant(_) => ObjectType::OAuthGrant,
            ObjectInner::OidcProvider(_) => ObjectType::OidcProvider,
            ObjectInner::PublicKey(_) => ObjectType::PublicKey,
            ObjectInner::QueuedMessage(_) => ObjectType::QueuedMessage,
            ObjectInner::ReportSettings(_) => ObjectType::ReportSettings,
            ObjectInner::Role(_) => ObjectType::Role,
            ObjectInner::Search(_) => ObjectType::Search,
            ObjectInner::SearchStore(_) => ObjectType::SearchStore,
            ObjectInner::Security(_) => ObjectType::Security,
            ObjectInner::SenderAuth(_) => ObjectType::SenderAuth,
            ObjectInner::Sharing(_) => ObjectType::Sharing,
            ObjectInner::SieveSystemInterpreter(_) => ObjectType::SieveSystemInterpreter,
            ObjectInner::SieveSystemScript(_) => ObjectType::SieveSystemScript,
            ObjectInner::SieveUserInterpreter(_) => ObjectType::SieveUserInterpreter,
            ObjectInner::SieveUserScript(_) => ObjectType::SieveUserScript,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(_) => ObjectType::SpamAi,
            // SPDX-SnippetEnd
            ObjectInner::SpamClassifier(_) => ObjectType::SpamClassifier,
            ObjectInner::SpamDnsblServer(_) => ObjectType::SpamDnsblServer,
            ObjectInner::SpamDnsblSettings(_) => ObjectType::SpamDnsblSettings,
            ObjectInner::SpamFileExtension(_) => ObjectType::SpamFileExtension,
            ObjectInner::SpamPyzor(_) => ObjectType::SpamPyzor,
            ObjectInner::SpamRule(_) => ObjectType::SpamRule,
            ObjectInner::SpamSettings(_) => ObjectType::SpamSettings,
            ObjectInner::SpamTag(_) => ObjectType::SpamTag,
            ObjectInner::SpamTrainingSample(_) => ObjectType::SpamTrainingSample,
            ObjectInner::SpfReportSettings(_) => ObjectType::SpfReportSettings,
            ObjectInner::StoreLookup(_) => ObjectType::StoreLookup,
            ObjectInner::SystemSettings(_) => ObjectType::SystemSettings,
            ObjectInner::Task(_) => ObjectType::Task,
            ObjectInner::TaskManager(_) => ObjectType::TaskManager,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(_) => ObjectType::Tenant,
            // SPDX-SnippetEnd
            ObjectInner::TlsExternalReport(_) => ObjectType::TlsExternalReport,
            ObjectInner::TlsInternalReport(_) => ObjectType::TlsInternalReport,
            ObjectInner::TlsReportSettings(_) => ObjectType::TlsReportSettings,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Trace(_) => ObjectType::Trace,
            // SPDX-SnippetEnd
            ObjectInner::Tracer(_) => ObjectType::Tracer,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(_) => ObjectType::TracingStore,
            // SPDX-SnippetEnd
            ObjectInner::WebDav(_) => ObjectType::WebDav,
            ObjectInner::WebHook(_) => ObjectType::WebHook,
        }
    }

    pub fn object_variant(&self) -> Option<&'static str> {
        match &self.inner {
            ObjectInner::Account(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Action(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(obj) => Some(obj.object_type().as_str()),
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetEnd
            ObjectInner::Asn(obj) => Some(obj.object_type().as_str()),
            ObjectInner::BlobStore(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Coordinator(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DataStore(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Directory(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DkimSignature(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DnsResolver(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DnsServer(obj) => Some(obj.object_type().as_str()),
            ObjectInner::InMemoryStore(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(obj) => Some(obj.object_type().as_str()),
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetEnd
            ObjectInner::MtaRoute(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SearchStore(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetEnd
            ObjectInner::SpamDnsblServer(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SpamRule(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SpamTag(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Task(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Tracer(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(obj) => Some(obj.object_type().as_str()),
            // SPDX-SnippetEnd
            _ => None,
        }
    }

    pub fn validate(&self, errors: &mut Vec<ValidationError>) -> bool {
        match &self.inner {
            ObjectInner::Account(obj) => obj.validate(errors),
            ObjectInner::AccountPassword(obj) => obj.validate(errors),
            ObjectInner::AccountSettings(obj) => obj.validate(errors),
            ObjectInner::AcmeProvider(obj) => obj.validate(errors),
            ObjectInner::Action(obj) => obj.validate(errors),
            ObjectInner::AddressBook(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(obj) => obj.validate(errors),
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::AllowedIp(obj) => obj.validate(errors),
            ObjectInner::ApiKey(obj) => obj.validate(errors),
            ObjectInner::AppPassword(obj) => obj.validate(errors),
            ObjectInner::Application(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::ArfExternalReport(obj) => obj.validate(errors),
            ObjectInner::Asn(obj) => obj.validate(errors),
            ObjectInner::Authentication(obj) => obj.validate(errors),
            ObjectInner::BlobStore(obj) => obj.validate(errors),
            ObjectInner::BlockedIp(obj) => obj.validate(errors),
            ObjectInner::Bootstrap(obj) => obj.validate(errors),
            ObjectInner::Cache(obj) => obj.validate(errors),
            ObjectInner::Calendar(obj) => obj.validate(errors),
            ObjectInner::CalendarAlarm(obj) => obj.validate(errors),
            ObjectInner::CalendarScheduling(obj) => obj.validate(errors),
            ObjectInner::Certificate(obj) => obj.validate(errors),
            ObjectInner::ClusterNode(obj) => obj.validate(errors),
            ObjectInner::ClusterRole(obj) => obj.validate(errors),
            ObjectInner::Coordinator(obj) => obj.validate(errors),
            ObjectInner::DataRetention(obj) => obj.validate(errors),
            ObjectInner::DataStore(obj) => obj.validate(errors),
            ObjectInner::Directory(obj) => obj.validate(errors),
            ObjectInner::DkimReportSettings(obj) => obj.validate(errors),
            ObjectInner::DkimSignature(obj) => obj.validate(errors),
            ObjectInner::DmarcExternalReport(obj) => obj.validate(errors),
            ObjectInner::DmarcInternalReport(obj) => obj.validate(errors),
            ObjectInner::DmarcReportSettings(obj) => obj.validate(errors),
            ObjectInner::DnsResolver(obj) => obj.validate(errors),
            ObjectInner::DnsServer(obj) => obj.validate(errors),
            ObjectInner::Domain(obj) => obj.validate(errors),
            ObjectInner::DsnReportSettings(obj) => obj.validate(errors),
            ObjectInner::Email(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Enterprise(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::EventTracingLevel(obj) => obj.validate(errors),
            ObjectInner::FileStorage(obj) => obj.validate(errors),
            ObjectInner::Http(obj) => obj.validate(errors),
            ObjectInner::HttpForm(obj) => obj.validate(errors),
            ObjectInner::HttpLookup(obj) => obj.validate(errors),
            ObjectInner::Imap(obj) => obj.validate(errors),
            ObjectInner::InMemoryStore(obj) => obj.validate(errors),
            ObjectInner::IndexQueueStatus(obj) => obj.validate(errors),
            ObjectInner::Jmap(obj) => obj.validate(errors),
            ObjectInner::Log(obj) => obj.validate(errors),
            ObjectInner::MailingList(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::MemoryLookupKey(obj) => obj.validate(errors),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.validate(errors),
            ObjectInner::Metadata(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::Metrics(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::MtaConnectionStrategy(obj) => obj.validate(errors),
            ObjectInner::MtaDeliverySchedule(obj) => obj.validate(errors),
            ObjectInner::MtaExtensions(obj) => obj.validate(errors),
            ObjectInner::MtaHook(obj) => obj.validate(errors),
            ObjectInner::MtaInboundSession(obj) => obj.validate(errors),
            ObjectInner::MtaInboundThrottle(obj) => obj.validate(errors),
            ObjectInner::MtaMilter(obj) => obj.validate(errors),
            ObjectInner::MtaOutboundStrategy(obj) => obj.validate(errors),
            ObjectInner::MtaOutboundThrottle(obj) => obj.validate(errors),
            ObjectInner::MtaQueueQuota(obj) => obj.validate(errors),
            ObjectInner::MtaRoute(obj) => obj.validate(errors),
            ObjectInner::MtaStageAuth(obj) => obj.validate(errors),
            ObjectInner::MtaStageConnect(obj) => obj.validate(errors),
            ObjectInner::MtaStageData(obj) => obj.validate(errors),
            ObjectInner::MtaStageEhlo(obj) => obj.validate(errors),
            ObjectInner::MtaStageMail(obj) => obj.validate(errors),
            ObjectInner::MtaStageRcpt(obj) => obj.validate(errors),
            ObjectInner::MtaSts(obj) => obj.validate(errors),
            ObjectInner::MtaTlsStrategy(obj) => obj.validate(errors),
            ObjectInner::MtaVirtualQueue(obj) => obj.validate(errors),
            ObjectInner::NetworkListener(obj) => obj.validate(errors),
            ObjectInner::OAuthClient(obj) => obj.validate(errors),
            ObjectInner::OAuthGrant(obj) => obj.validate(errors),
            ObjectInner::OidcProvider(obj) => obj.validate(errors),
            ObjectInner::PublicKey(obj) => obj.validate(errors),
            ObjectInner::QueuedMessage(obj) => obj.validate(errors),
            ObjectInner::ReportSettings(obj) => obj.validate(errors),
            ObjectInner::Role(obj) => obj.validate(errors),
            ObjectInner::Search(obj) => obj.validate(errors),
            ObjectInner::SearchStore(obj) => obj.validate(errors),
            ObjectInner::Security(obj) => obj.validate(errors),
            ObjectInner::SenderAuth(obj) => obj.validate(errors),
            ObjectInner::Sharing(obj) => obj.validate(errors),
            ObjectInner::SieveSystemInterpreter(obj) => obj.validate(errors),
            ObjectInner::SieveSystemScript(obj) => obj.validate(errors),
            ObjectInner::SieveUserInterpreter(obj) => obj.validate(errors),
            ObjectInner::SieveUserScript(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::SpamClassifier(obj) => obj.validate(errors),
            ObjectInner::SpamDnsblServer(obj) => obj.validate(errors),
            ObjectInner::SpamDnsblSettings(obj) => obj.validate(errors),
            ObjectInner::SpamFileExtension(obj) => obj.validate(errors),
            ObjectInner::SpamPyzor(obj) => obj.validate(errors),
            ObjectInner::SpamRule(obj) => obj.validate(errors),
            ObjectInner::SpamSettings(obj) => obj.validate(errors),
            ObjectInner::SpamTag(obj) => obj.validate(errors),
            ObjectInner::SpamTrainingSample(obj) => obj.validate(errors),
            ObjectInner::SpfReportSettings(obj) => obj.validate(errors),
            ObjectInner::StoreLookup(obj) => obj.validate(errors),
            ObjectInner::SystemSettings(obj) => obj.validate(errors),
            ObjectInner::Task(obj) => obj.validate(errors),
            ObjectInner::TaskManager(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::TlsExternalReport(obj) => obj.validate(errors),
            ObjectInner::TlsInternalReport(obj) => obj.validate(errors),
            ObjectInner::TlsReportSettings(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Trace(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::Tracer(obj) => obj.validate(errors),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(obj) => obj.validate(errors),
            // SPDX-SnippetEnd
            ObjectInner::WebDav(obj) => obj.validate(errors),
            ObjectInner::WebHook(obj) => obj.validate(errors),
        }
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn validate_inline_secrets(&self, errors: &mut Vec<ValidationError>) {
        match &self.inner {
            ObjectInner::AiModel(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Asn(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::BlobStore(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Bootstrap(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Cache(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Certificate(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Coordinator(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::DataStore(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Directory(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::DkimSignature(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::DnsServer(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Enterprise(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::HttpLookup(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::InMemoryStore(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Jmap(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Metrics(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::MetricsStore(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::MtaHook(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::MtaRoute(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::OidcProvider(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::SearchStore(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::StoreLookup(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::Tracer(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::TracingStore(obj) => obj.validate_inline_secrets(errors),
            ObjectInner::WebHook(obj) => obj.validate_inline_secrets(errors),
            _ => {}
        }
    }

    // SPDX-SnippetEnd
    pub fn index<'x>(&'x self, i: &mut IndexBuilder<'x>) {
        match &self.inner {
            ObjectInner::Account(obj) => obj.index(i),
            ObjectInner::AccountPassword(obj) => obj.index(i),
            ObjectInner::AccountSettings(obj) => obj.index(i),
            ObjectInner::AcmeProvider(obj) => obj.index(i),
            ObjectInner::Action(obj) => obj.index(i),
            ObjectInner::AddressBook(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(obj) => obj.index(i),
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::AllowedIp(obj) => obj.index(i),
            ObjectInner::ApiKey(obj) => obj.index(i),
            ObjectInner::AppPassword(obj) => obj.index(i),
            ObjectInner::Application(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::ArfExternalReport(obj) => obj.index(i),
            ObjectInner::Asn(obj) => obj.index(i),
            ObjectInner::Authentication(obj) => obj.index(i),
            ObjectInner::BlobStore(obj) => obj.index(i),
            ObjectInner::BlockedIp(obj) => obj.index(i),
            ObjectInner::Bootstrap(obj) => obj.index(i),
            ObjectInner::Cache(obj) => obj.index(i),
            ObjectInner::Calendar(obj) => obj.index(i),
            ObjectInner::CalendarAlarm(obj) => obj.index(i),
            ObjectInner::CalendarScheduling(obj) => obj.index(i),
            ObjectInner::Certificate(obj) => obj.index(i),
            ObjectInner::ClusterNode(obj) => obj.index(i),
            ObjectInner::ClusterRole(obj) => obj.index(i),
            ObjectInner::Coordinator(obj) => obj.index(i),
            ObjectInner::DataRetention(obj) => obj.index(i),
            ObjectInner::DataStore(obj) => obj.index(i),
            ObjectInner::Directory(obj) => obj.index(i),
            ObjectInner::DkimReportSettings(obj) => obj.index(i),
            ObjectInner::DkimSignature(obj) => obj.index(i),
            ObjectInner::DmarcExternalReport(obj) => obj.index(i),
            ObjectInner::DmarcInternalReport(obj) => obj.index(i),
            ObjectInner::DmarcReportSettings(obj) => obj.index(i),
            ObjectInner::DnsResolver(obj) => obj.index(i),
            ObjectInner::DnsServer(obj) => obj.index(i),
            ObjectInner::Domain(obj) => obj.index(i),
            ObjectInner::DsnReportSettings(obj) => obj.index(i),
            ObjectInner::Email(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Enterprise(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::EventTracingLevel(obj) => obj.index(i),
            ObjectInner::FileStorage(obj) => obj.index(i),
            ObjectInner::Http(obj) => obj.index(i),
            ObjectInner::HttpForm(obj) => obj.index(i),
            ObjectInner::HttpLookup(obj) => obj.index(i),
            ObjectInner::Imap(obj) => obj.index(i),
            ObjectInner::InMemoryStore(obj) => obj.index(i),
            ObjectInner::IndexQueueStatus(obj) => obj.index(i),
            ObjectInner::Jmap(obj) => obj.index(i),
            ObjectInner::Log(obj) => obj.index(i),
            ObjectInner::MailingList(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::MemoryLookupKey(obj) => obj.index(i),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.index(i),
            ObjectInner::Metadata(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::Metrics(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::MtaConnectionStrategy(obj) => obj.index(i),
            ObjectInner::MtaDeliverySchedule(obj) => obj.index(i),
            ObjectInner::MtaExtensions(obj) => obj.index(i),
            ObjectInner::MtaHook(obj) => obj.index(i),
            ObjectInner::MtaInboundSession(obj) => obj.index(i),
            ObjectInner::MtaInboundThrottle(obj) => obj.index(i),
            ObjectInner::MtaMilter(obj) => obj.index(i),
            ObjectInner::MtaOutboundStrategy(obj) => obj.index(i),
            ObjectInner::MtaOutboundThrottle(obj) => obj.index(i),
            ObjectInner::MtaQueueQuota(obj) => obj.index(i),
            ObjectInner::MtaRoute(obj) => obj.index(i),
            ObjectInner::MtaStageAuth(obj) => obj.index(i),
            ObjectInner::MtaStageConnect(obj) => obj.index(i),
            ObjectInner::MtaStageData(obj) => obj.index(i),
            ObjectInner::MtaStageEhlo(obj) => obj.index(i),
            ObjectInner::MtaStageMail(obj) => obj.index(i),
            ObjectInner::MtaStageRcpt(obj) => obj.index(i),
            ObjectInner::MtaSts(obj) => obj.index(i),
            ObjectInner::MtaTlsStrategy(obj) => obj.index(i),
            ObjectInner::MtaVirtualQueue(obj) => obj.index(i),
            ObjectInner::NetworkListener(obj) => obj.index(i),
            ObjectInner::OAuthClient(obj) => obj.index(i),
            ObjectInner::OAuthGrant(obj) => obj.index(i),
            ObjectInner::OidcProvider(obj) => obj.index(i),
            ObjectInner::PublicKey(obj) => obj.index(i),
            ObjectInner::QueuedMessage(obj) => obj.index(i),
            ObjectInner::ReportSettings(obj) => obj.index(i),
            ObjectInner::Role(obj) => obj.index(i),
            ObjectInner::Search(obj) => obj.index(i),
            ObjectInner::SearchStore(obj) => obj.index(i),
            ObjectInner::Security(obj) => obj.index(i),
            ObjectInner::SenderAuth(obj) => obj.index(i),
            ObjectInner::Sharing(obj) => obj.index(i),
            ObjectInner::SieveSystemInterpreter(obj) => obj.index(i),
            ObjectInner::SieveSystemScript(obj) => obj.index(i),
            ObjectInner::SieveUserInterpreter(obj) => obj.index(i),
            ObjectInner::SieveUserScript(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::SpamClassifier(obj) => obj.index(i),
            ObjectInner::SpamDnsblServer(obj) => obj.index(i),
            ObjectInner::SpamDnsblSettings(obj) => obj.index(i),
            ObjectInner::SpamFileExtension(obj) => obj.index(i),
            ObjectInner::SpamPyzor(obj) => obj.index(i),
            ObjectInner::SpamRule(obj) => obj.index(i),
            ObjectInner::SpamSettings(obj) => obj.index(i),
            ObjectInner::SpamTag(obj) => obj.index(i),
            ObjectInner::SpamTrainingSample(obj) => obj.index(i),
            ObjectInner::SpfReportSettings(obj) => obj.index(i),
            ObjectInner::StoreLookup(obj) => obj.index(i),
            ObjectInner::SystemSettings(obj) => obj.index(i),
            ObjectInner::Task(obj) => obj.index(i),
            ObjectInner::TaskManager(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::TlsExternalReport(obj) => obj.index(i),
            ObjectInner::TlsInternalReport(obj) => obj.index(i),
            ObjectInner::TlsReportSettings(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Trace(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::Tracer(obj) => obj.index(i),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(obj) => obj.index(i),
            // SPDX-SnippetEnd
            ObjectInner::WebDav(obj) => obj.index(i),
            ObjectInner::WebHook(obj) => obj.index(i),
        }
    }

    pub fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match &mut self.inner {
            ObjectInner::Account(obj) => obj.patch(pointer, value),
            ObjectInner::AccountPassword(obj) => obj.patch(pointer, value),
            ObjectInner::AccountSettings(obj) => obj.patch(pointer, value),
            ObjectInner::AcmeProvider(obj) => obj.patch(pointer, value),
            ObjectInner::Action(obj) => obj.patch(pointer, value),
            ObjectInner::AddressBook(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(obj) => obj.patch(pointer, value),
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::AllowedIp(obj) => obj.patch(pointer, value),
            ObjectInner::ApiKey(obj) => obj.patch(pointer, value),
            ObjectInner::AppPassword(obj) => obj.patch(pointer, value),
            ObjectInner::Application(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::ArfExternalReport(obj) => obj.patch(pointer, value),
            ObjectInner::Asn(obj) => obj.patch(pointer, value),
            ObjectInner::Authentication(obj) => obj.patch(pointer, value),
            ObjectInner::BlobStore(obj) => obj.patch(pointer, value),
            ObjectInner::BlockedIp(obj) => obj.patch(pointer, value),
            ObjectInner::Bootstrap(obj) => obj.patch(pointer, value),
            ObjectInner::Cache(obj) => obj.patch(pointer, value),
            ObjectInner::Calendar(obj) => obj.patch(pointer, value),
            ObjectInner::CalendarAlarm(obj) => obj.patch(pointer, value),
            ObjectInner::CalendarScheduling(obj) => obj.patch(pointer, value),
            ObjectInner::Certificate(obj) => obj.patch(pointer, value),
            ObjectInner::ClusterNode(obj) => obj.patch(pointer, value),
            ObjectInner::ClusterRole(obj) => obj.patch(pointer, value),
            ObjectInner::Coordinator(obj) => obj.patch(pointer, value),
            ObjectInner::DataRetention(obj) => obj.patch(pointer, value),
            ObjectInner::DataStore(obj) => obj.patch(pointer, value),
            ObjectInner::Directory(obj) => obj.patch(pointer, value),
            ObjectInner::DkimReportSettings(obj) => obj.patch(pointer, value),
            ObjectInner::DkimSignature(obj) => obj.patch(pointer, value),
            ObjectInner::DmarcExternalReport(obj) => obj.patch(pointer, value),
            ObjectInner::DmarcInternalReport(obj) => obj.patch(pointer, value),
            ObjectInner::DmarcReportSettings(obj) => obj.patch(pointer, value),
            ObjectInner::DnsResolver(obj) => obj.patch(pointer, value),
            ObjectInner::DnsServer(obj) => obj.patch(pointer, value),
            ObjectInner::Domain(obj) => obj.patch(pointer, value),
            ObjectInner::DsnReportSettings(obj) => obj.patch(pointer, value),
            ObjectInner::Email(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Enterprise(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::EventTracingLevel(obj) => obj.patch(pointer, value),
            ObjectInner::FileStorage(obj) => obj.patch(pointer, value),
            ObjectInner::Http(obj) => obj.patch(pointer, value),
            ObjectInner::HttpForm(obj) => obj.patch(pointer, value),
            ObjectInner::HttpLookup(obj) => obj.patch(pointer, value),
            ObjectInner::Imap(obj) => obj.patch(pointer, value),
            ObjectInner::InMemoryStore(obj) => obj.patch(pointer, value),
            ObjectInner::IndexQueueStatus(obj) => obj.patch(pointer, value),
            ObjectInner::Jmap(obj) => obj.patch(pointer, value),
            ObjectInner::Log(obj) => obj.patch(pointer, value),
            ObjectInner::MailingList(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::MemoryLookupKey(obj) => obj.patch(pointer, value),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.patch(pointer, value),
            ObjectInner::Metadata(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::Metrics(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::MtaConnectionStrategy(obj) => obj.patch(pointer, value),
            ObjectInner::MtaDeliverySchedule(obj) => obj.patch(pointer, value),
            ObjectInner::MtaExtensions(obj) => obj.patch(pointer, value),
            ObjectInner::MtaHook(obj) => obj.patch(pointer, value),
            ObjectInner::MtaInboundSession(obj) => obj.patch(pointer, value),
            ObjectInner::MtaInboundThrottle(obj) => obj.patch(pointer, value),
            ObjectInner::MtaMilter(obj) => obj.patch(pointer, value),
            ObjectInner::MtaOutboundStrategy(obj) => obj.patch(pointer, value),
            ObjectInner::MtaOutboundThrottle(obj) => obj.patch(pointer, value),
            ObjectInner::MtaQueueQuota(obj) => obj.patch(pointer, value),
            ObjectInner::MtaRoute(obj) => obj.patch(pointer, value),
            ObjectInner::MtaStageAuth(obj) => obj.patch(pointer, value),
            ObjectInner::MtaStageConnect(obj) => obj.patch(pointer, value),
            ObjectInner::MtaStageData(obj) => obj.patch(pointer, value),
            ObjectInner::MtaStageEhlo(obj) => obj.patch(pointer, value),
            ObjectInner::MtaStageMail(obj) => obj.patch(pointer, value),
            ObjectInner::MtaStageRcpt(obj) => obj.patch(pointer, value),
            ObjectInner::MtaSts(obj) => obj.patch(pointer, value),
            ObjectInner::MtaTlsStrategy(obj) => obj.patch(pointer, value),
            ObjectInner::MtaVirtualQueue(obj) => obj.patch(pointer, value),
            ObjectInner::NetworkListener(obj) => obj.patch(pointer, value),
            ObjectInner::OAuthClient(obj) => obj.patch(pointer, value),
            ObjectInner::OAuthGrant(obj) => obj.patch(pointer, value),
            ObjectInner::OidcProvider(obj) => obj.patch(pointer, value),
            ObjectInner::PublicKey(obj) => obj.patch(pointer, value),
            ObjectInner::QueuedMessage(obj) => obj.patch(pointer, value),
            ObjectInner::ReportSettings(obj) => obj.patch(pointer, value),
            ObjectInner::Role(obj) => obj.patch(pointer, value),
            ObjectInner::Search(obj) => obj.patch(pointer, value),
            ObjectInner::SearchStore(obj) => obj.patch(pointer, value),
            ObjectInner::Security(obj) => obj.patch(pointer, value),
            ObjectInner::SenderAuth(obj) => obj.patch(pointer, value),
            ObjectInner::Sharing(obj) => obj.patch(pointer, value),
            ObjectInner::SieveSystemInterpreter(obj) => obj.patch(pointer, value),
            ObjectInner::SieveSystemScript(obj) => obj.patch(pointer, value),
            ObjectInner::SieveUserInterpreter(obj) => obj.patch(pointer, value),
            ObjectInner::SieveUserScript(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::SpamClassifier(obj) => obj.patch(pointer, value),
            ObjectInner::SpamDnsblServer(obj) => obj.patch(pointer, value),
            ObjectInner::SpamDnsblSettings(obj) => obj.patch(pointer, value),
            ObjectInner::SpamFileExtension(obj) => obj.patch(pointer, value),
            ObjectInner::SpamPyzor(obj) => obj.patch(pointer, value),
            ObjectInner::SpamRule(obj) => obj.patch(pointer, value),
            ObjectInner::SpamSettings(obj) => obj.patch(pointer, value),
            ObjectInner::SpamTag(obj) => obj.patch(pointer, value),
            ObjectInner::SpamTrainingSample(obj) => obj.patch(pointer, value),
            ObjectInner::SpfReportSettings(obj) => obj.patch(pointer, value),
            ObjectInner::StoreLookup(obj) => obj.patch(pointer, value),
            ObjectInner::SystemSettings(obj) => obj.patch(pointer, value),
            ObjectInner::Task(obj) => obj.patch(pointer, value),
            ObjectInner::TaskManager(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::TlsExternalReport(obj) => obj.patch(pointer, value),
            ObjectInner::TlsInternalReport(obj) => obj.patch(pointer, value),
            ObjectInner::TlsReportSettings(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Trace(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::Tracer(obj) => obj.patch(pointer, value),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(obj) => obj.patch(pointer, value),
            // SPDX-SnippetEnd
            ObjectInner::WebDav(obj) => obj.patch(pointer, value),
            ObjectInner::WebHook(obj) => obj.patch(pointer, value),
        }
    }
}

impl IntoValue for Object {
    fn into_value(self) -> JmapValue<'static> {
        self.into_value_with(ValueOptions::default())
    }

    fn into_value_with(self, opts: ValueOptions) -> JmapValue<'static> {
        match self.inner {
            ObjectInner::Account(obj) => (*obj).into_value_with(opts),
            ObjectInner::AccountPassword(obj) => (*obj).into_value_with(opts),
            ObjectInner::AccountSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::AcmeProvider(obj) => (*obj).into_value_with(opts),
            ObjectInner::Action(obj) => (*obj).into_value_with(opts),
            ObjectInner::AddressBook(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::AiModel(obj) => (*obj).into_value_with(opts),
            #[cfg(feature = "enterprise")]
            ObjectInner::Alert(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::AllowedIp(obj) => (*obj).into_value_with(opts),
            ObjectInner::ApiKey(obj) => (*obj).into_value_with(opts),
            ObjectInner::AppPassword(obj) => (*obj).into_value_with(opts),
            ObjectInner::Application(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::ArchivedItem(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::ArfExternalReport(obj) => (*obj).into_value_with(opts),
            ObjectInner::Asn(obj) => (*obj).into_value_with(opts),
            ObjectInner::Authentication(obj) => (*obj).into_value_with(opts),
            ObjectInner::BlobStore(obj) => (*obj).into_value_with(opts),
            ObjectInner::BlockedIp(obj) => (*obj).into_value_with(opts),
            ObjectInner::Bootstrap(obj) => (*obj).into_value_with(opts),
            ObjectInner::Cache(obj) => (*obj).into_value_with(opts),
            ObjectInner::Calendar(obj) => (*obj).into_value_with(opts),
            ObjectInner::CalendarAlarm(obj) => (*obj).into_value_with(opts),
            ObjectInner::CalendarScheduling(obj) => (*obj).into_value_with(opts),
            ObjectInner::Certificate(obj) => (*obj).into_value_with(opts),
            ObjectInner::ClusterNode(obj) => (*obj).into_value_with(opts),
            ObjectInner::ClusterRole(obj) => (*obj).into_value_with(opts),
            ObjectInner::Coordinator(obj) => (*obj).into_value_with(opts),
            ObjectInner::DataRetention(obj) => (*obj).into_value_with(opts),
            ObjectInner::DataStore(obj) => (*obj).into_value_with(opts),
            ObjectInner::Directory(obj) => (*obj).into_value_with(opts),
            ObjectInner::DkimReportSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::DkimSignature(obj) => (*obj).into_value_with(opts),
            ObjectInner::DmarcExternalReport(obj) => (*obj).into_value_with(opts),
            ObjectInner::DmarcInternalReport(obj) => (*obj).into_value_with(opts),
            ObjectInner::DmarcReportSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::DnsResolver(obj) => (*obj).into_value_with(opts),
            ObjectInner::DnsServer(obj) => (*obj).into_value_with(opts),
            ObjectInner::Domain(obj) => (*obj).into_value_with(opts),
            ObjectInner::DsnReportSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::Email(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Enterprise(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::EventTracingLevel(obj) => (*obj).into_value_with(opts),
            ObjectInner::FileStorage(obj) => (*obj).into_value_with(opts),
            ObjectInner::Http(obj) => (*obj).into_value_with(opts),
            ObjectInner::HttpForm(obj) => (*obj).into_value_with(opts),
            ObjectInner::HttpLookup(obj) => (*obj).into_value_with(opts),
            ObjectInner::Imap(obj) => (*obj).into_value_with(opts),
            ObjectInner::InMemoryStore(obj) => (*obj).into_value_with(opts),
            ObjectInner::IndexQueueStatus(obj) => (*obj).into_value_with(opts),
            ObjectInner::Jmap(obj) => (*obj).into_value_with(opts),
            ObjectInner::Log(obj) => (*obj).into_value_with(opts),
            ObjectInner::MailingList(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MaskedEmail(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::MemoryLookupKey(obj) => (*obj).into_value_with(opts),
            ObjectInner::MemoryLookupKeyValue(obj) => (*obj).into_value_with(opts),
            ObjectInner::Metadata(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Metric(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::Metrics(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::MetricsStore(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::MtaConnectionStrategy(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaDeliverySchedule(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaExtensions(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaHook(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaInboundSession(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaInboundThrottle(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaMilter(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaOutboundStrategy(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaOutboundThrottle(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaQueueQuota(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaRoute(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaStageAuth(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaStageConnect(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaStageData(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaStageEhlo(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaStageMail(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaStageRcpt(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaSts(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaTlsStrategy(obj) => (*obj).into_value_with(opts),
            ObjectInner::MtaVirtualQueue(obj) => (*obj).into_value_with(opts),
            ObjectInner::NetworkListener(obj) => (*obj).into_value_with(opts),
            ObjectInner::OAuthClient(obj) => (*obj).into_value_with(opts),
            ObjectInner::OAuthGrant(obj) => (*obj).into_value_with(opts),
            ObjectInner::OidcProvider(obj) => (*obj).into_value_with(opts),
            ObjectInner::PublicKey(obj) => (*obj).into_value_with(opts),
            ObjectInner::QueuedMessage(obj) => (*obj).into_value_with(opts),
            ObjectInner::ReportSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::Role(obj) => (*obj).into_value_with(opts),
            ObjectInner::Search(obj) => (*obj).into_value_with(opts),
            ObjectInner::SearchStore(obj) => (*obj).into_value_with(opts),
            ObjectInner::Security(obj) => (*obj).into_value_with(opts),
            ObjectInner::SenderAuth(obj) => (*obj).into_value_with(opts),
            ObjectInner::Sharing(obj) => (*obj).into_value_with(opts),
            ObjectInner::SieveSystemInterpreter(obj) => (*obj).into_value_with(opts),
            ObjectInner::SieveSystemScript(obj) => (*obj).into_value_with(opts),
            ObjectInner::SieveUserInterpreter(obj) => (*obj).into_value_with(opts),
            ObjectInner::SieveUserScript(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::SpamAi(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::SpamClassifier(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamDnsblServer(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamDnsblSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamFileExtension(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamPyzor(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamRule(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamTag(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpamTrainingSample(obj) => (*obj).into_value_with(opts),
            ObjectInner::SpfReportSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::StoreLookup(obj) => (*obj).into_value_with(opts),
            ObjectInner::SystemSettings(obj) => (*obj).into_value_with(opts),
            ObjectInner::Task(obj) => (*obj).into_value_with(opts),
            ObjectInner::TaskManager(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Tenant(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::TlsExternalReport(obj) => (*obj).into_value_with(opts),
            ObjectInner::TlsInternalReport(obj) => (*obj).into_value_with(opts),
            ObjectInner::TlsReportSettings(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::Trace(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::Tracer(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectInner::TracingStore(obj) => (*obj).into_value_with(opts),
            // SPDX-SnippetEnd
            ObjectInner::WebDav(obj) => (*obj).into_value_with(opts),
            ObjectInner::WebHook(obj) => (*obj).into_value_with(opts),
        }
    }
}

impl From<ObjectType> for ObjectInner {
    fn from(obj: ObjectType) -> Self {
        match obj {
            ObjectType::Account => ObjectInner::Account(Box::default()),
            ObjectType::AccountPassword => ObjectInner::AccountPassword(Box::default()),
            ObjectType::AccountSettings => ObjectInner::AccountSettings(Box::default()),
            ObjectType::AcmeProvider => ObjectInner::AcmeProvider(Box::default()),
            ObjectType::Action => ObjectInner::Action(Box::default()),
            ObjectType::AddressBook => ObjectInner::AddressBook(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::AiModel => ObjectInner::AiModel(Box::default()),
            #[cfg(feature = "enterprise")]
            ObjectType::Alert => ObjectInner::Alert(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::AllowedIp => ObjectInner::AllowedIp(Box::default()),
            ObjectType::ApiKey => ObjectInner::ApiKey(Box::default()),
            ObjectType::AppPassword => ObjectInner::AppPassword(Box::default()),
            ObjectType::Application => ObjectInner::Application(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::ArchivedItem => ObjectInner::ArchivedItem(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::ArfExternalReport => ObjectInner::ArfExternalReport(Box::default()),
            ObjectType::Asn => ObjectInner::Asn(Box::default()),
            ObjectType::Authentication => ObjectInner::Authentication(Box::default()),
            ObjectType::BlobStore => ObjectInner::BlobStore(Box::default()),
            ObjectType::BlockedIp => ObjectInner::BlockedIp(Box::default()),
            ObjectType::Bootstrap => ObjectInner::Bootstrap(Box::default()),
            ObjectType::Cache => ObjectInner::Cache(Box::default()),
            ObjectType::Calendar => ObjectInner::Calendar(Box::default()),
            ObjectType::CalendarAlarm => ObjectInner::CalendarAlarm(Box::default()),
            ObjectType::CalendarScheduling => ObjectInner::CalendarScheduling(Box::default()),
            ObjectType::Certificate => ObjectInner::Certificate(Box::default()),
            ObjectType::ClusterNode => ObjectInner::ClusterNode(Box::default()),
            ObjectType::ClusterRole => ObjectInner::ClusterRole(Box::default()),
            ObjectType::Coordinator => ObjectInner::Coordinator(Box::default()),
            ObjectType::DataRetention => ObjectInner::DataRetention(Box::default()),
            ObjectType::DataStore => ObjectInner::DataStore(Box::default()),
            ObjectType::Directory => ObjectInner::Directory(Box::default()),
            ObjectType::DkimReportSettings => ObjectInner::DkimReportSettings(Box::default()),
            ObjectType::DkimSignature => ObjectInner::DkimSignature(Box::default()),
            ObjectType::DmarcExternalReport => ObjectInner::DmarcExternalReport(Box::default()),
            ObjectType::DmarcInternalReport => ObjectInner::DmarcInternalReport(Box::default()),
            ObjectType::DmarcReportSettings => ObjectInner::DmarcReportSettings(Box::default()),
            ObjectType::DnsResolver => ObjectInner::DnsResolver(Box::default()),
            ObjectType::DnsServer => ObjectInner::DnsServer(Box::default()),
            ObjectType::Domain => ObjectInner::Domain(Box::default()),
            ObjectType::DsnReportSettings => ObjectInner::DsnReportSettings(Box::default()),
            ObjectType::Email => ObjectInner::Email(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Enterprise => ObjectInner::Enterprise(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::EventTracingLevel => ObjectInner::EventTracingLevel(Box::default()),
            ObjectType::FileStorage => ObjectInner::FileStorage(Box::default()),
            ObjectType::Http => ObjectInner::Http(Box::default()),
            ObjectType::HttpForm => ObjectInner::HttpForm(Box::default()),
            ObjectType::HttpLookup => ObjectInner::HttpLookup(Box::default()),
            ObjectType::Imap => ObjectInner::Imap(Box::default()),
            ObjectType::InMemoryStore => ObjectInner::InMemoryStore(Box::default()),
            ObjectType::IndexQueueStatus => ObjectInner::IndexQueueStatus(Box::default()),
            ObjectType::Jmap => ObjectInner::Jmap(Box::default()),
            ObjectType::Log => ObjectInner::Log(Box::default()),
            ObjectType::MailingList => ObjectInner::MailingList(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MaskedEmail => ObjectInner::MaskedEmail(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::MemoryLookupKey => ObjectInner::MemoryLookupKey(Box::default()),
            ObjectType::MemoryLookupKeyValue => ObjectInner::MemoryLookupKeyValue(Box::default()),
            ObjectType::Metadata => ObjectInner::Metadata(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Metric => ObjectInner::Metric(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::Metrics => ObjectInner::Metrics(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::MetricsStore => ObjectInner::MetricsStore(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::MtaConnectionStrategy => ObjectInner::MtaConnectionStrategy(Box::default()),
            ObjectType::MtaDeliverySchedule => ObjectInner::MtaDeliverySchedule(Box::default()),
            ObjectType::MtaExtensions => ObjectInner::MtaExtensions(Box::default()),
            ObjectType::MtaHook => ObjectInner::MtaHook(Box::default()),
            ObjectType::MtaInboundSession => ObjectInner::MtaInboundSession(Box::default()),
            ObjectType::MtaInboundThrottle => ObjectInner::MtaInboundThrottle(Box::default()),
            ObjectType::MtaMilter => ObjectInner::MtaMilter(Box::default()),
            ObjectType::MtaOutboundStrategy => ObjectInner::MtaOutboundStrategy(Box::default()),
            ObjectType::MtaOutboundThrottle => ObjectInner::MtaOutboundThrottle(Box::default()),
            ObjectType::MtaQueueQuota => ObjectInner::MtaQueueQuota(Box::default()),
            ObjectType::MtaRoute => ObjectInner::MtaRoute(Box::default()),
            ObjectType::MtaStageAuth => ObjectInner::MtaStageAuth(Box::default()),
            ObjectType::MtaStageConnect => ObjectInner::MtaStageConnect(Box::default()),
            ObjectType::MtaStageData => ObjectInner::MtaStageData(Box::default()),
            ObjectType::MtaStageEhlo => ObjectInner::MtaStageEhlo(Box::default()),
            ObjectType::MtaStageMail => ObjectInner::MtaStageMail(Box::default()),
            ObjectType::MtaStageRcpt => ObjectInner::MtaStageRcpt(Box::default()),
            ObjectType::MtaSts => ObjectInner::MtaSts(Box::default()),
            ObjectType::MtaTlsStrategy => ObjectInner::MtaTlsStrategy(Box::default()),
            ObjectType::MtaVirtualQueue => ObjectInner::MtaVirtualQueue(Box::default()),
            ObjectType::NetworkListener => ObjectInner::NetworkListener(Box::default()),
            ObjectType::OAuthClient => ObjectInner::OAuthClient(Box::default()),
            ObjectType::OAuthGrant => ObjectInner::OAuthGrant(Box::default()),
            ObjectType::OidcProvider => ObjectInner::OidcProvider(Box::default()),
            ObjectType::PublicKey => ObjectInner::PublicKey(Box::default()),
            ObjectType::QueuedMessage => ObjectInner::QueuedMessage(Box::default()),
            ObjectType::ReportSettings => ObjectInner::ReportSettings(Box::default()),
            ObjectType::Role => ObjectInner::Role(Box::default()),
            ObjectType::Search => ObjectInner::Search(Box::default()),
            ObjectType::SearchStore => ObjectInner::SearchStore(Box::default()),
            ObjectType::Security => ObjectInner::Security(Box::default()),
            ObjectType::SenderAuth => ObjectInner::SenderAuth(Box::default()),
            ObjectType::Sharing => ObjectInner::Sharing(Box::default()),
            ObjectType::SieveSystemInterpreter => {
                ObjectInner::SieveSystemInterpreter(Box::default())
            }
            ObjectType::SieveSystemScript => ObjectInner::SieveSystemScript(Box::default()),
            ObjectType::SieveUserInterpreter => ObjectInner::SieveUserInterpreter(Box::default()),
            ObjectType::SieveUserScript => ObjectInner::SieveUserScript(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::SpamAi => ObjectInner::SpamAi(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::SpamClassifier => ObjectInner::SpamClassifier(Box::default()),
            ObjectType::SpamDnsblServer => ObjectInner::SpamDnsblServer(Box::default()),
            ObjectType::SpamDnsblSettings => ObjectInner::SpamDnsblSettings(Box::default()),
            ObjectType::SpamFileExtension => ObjectInner::SpamFileExtension(Box::default()),
            ObjectType::SpamPyzor => ObjectInner::SpamPyzor(Box::default()),
            ObjectType::SpamRule => ObjectInner::SpamRule(Box::default()),
            ObjectType::SpamSettings => ObjectInner::SpamSettings(Box::default()),
            ObjectType::SpamTag => ObjectInner::SpamTag(Box::default()),
            ObjectType::SpamTrainingSample => ObjectInner::SpamTrainingSample(Box::default()),
            ObjectType::SpfReportSettings => ObjectInner::SpfReportSettings(Box::default()),
            ObjectType::StoreLookup => ObjectInner::StoreLookup(Box::default()),
            ObjectType::SystemSettings => ObjectInner::SystemSettings(Box::default()),
            ObjectType::Task => ObjectInner::Task(Box::default()),
            ObjectType::TaskManager => ObjectInner::TaskManager(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Tenant => ObjectInner::Tenant(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::TlsExternalReport => ObjectInner::TlsExternalReport(Box::default()),
            ObjectType::TlsInternalReport => ObjectInner::TlsInternalReport(Box::default()),
            ObjectType::TlsReportSettings => ObjectInner::TlsReportSettings(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::Trace => ObjectInner::Trace(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::Tracer => ObjectInner::Tracer(Box::default()),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            ObjectType::TracingStore => ObjectInner::TracingStore(Box::default()),
            // SPDX-SnippetEnd
            ObjectType::WebDav => ObjectInner::WebDav(Box::default()),
            ObjectType::WebHook => ObjectInner::WebHook(Box::default()),
        }
    }
}

impl From<Account> for ObjectInner {
    fn from(value: Account) -> Self {
        ObjectInner::Account(Box::new(value))
    }
}

impl From<Object> for Account {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Account(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<AccountPassword> for ObjectInner {
    fn from(value: AccountPassword) -> Self {
        ObjectInner::AccountPassword(Box::new(value))
    }
}

impl From<Object> for AccountPassword {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AccountPassword(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<AccountSettings> for ObjectInner {
    fn from(value: AccountSettings) -> Self {
        ObjectInner::AccountSettings(Box::new(value))
    }
}

impl From<Object> for AccountSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AccountSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<AcmeProvider> for ObjectInner {
    fn from(value: AcmeProvider) -> Self {
        ObjectInner::AcmeProvider(Box::new(value))
    }
}

impl From<Object> for AcmeProvider {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AcmeProvider(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Action> for ObjectInner {
    fn from(value: Action) -> Self {
        ObjectInner::Action(Box::new(value))
    }
}

impl From<Object> for Action {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Action(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<AddressBook> for ObjectInner {
    fn from(value: AddressBook) -> Self {
        ObjectInner::AddressBook(Box::new(value))
    }
}

impl From<Object> for AddressBook {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AddressBook(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<AiModel> for ObjectInner {
    fn from(value: AiModel) -> Self {
        ObjectInner::AiModel(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for AiModel {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AiModel(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "enterprise")]
impl From<Alert> for ObjectInner {
    fn from(value: Alert) -> Self {
        ObjectInner::Alert(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for Alert {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Alert(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<AllowedIp> for ObjectInner {
    fn from(value: AllowedIp) -> Self {
        ObjectInner::AllowedIp(Box::new(value))
    }
}

impl From<Object> for AllowedIp {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AllowedIp(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<ApiKey> for ObjectInner {
    fn from(value: ApiKey) -> Self {
        ObjectInner::ApiKey(Box::new(value))
    }
}

impl From<Object> for ApiKey {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ApiKey(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<AppPassword> for ObjectInner {
    fn from(value: AppPassword) -> Self {
        ObjectInner::AppPassword(Box::new(value))
    }
}

impl From<Object> for AppPassword {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AppPassword(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Application> for ObjectInner {
    fn from(value: Application) -> Self {
        ObjectInner::Application(Box::new(value))
    }
}

impl From<Object> for Application {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Application(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<ArchivedItem> for ObjectInner {
    fn from(value: ArchivedItem) -> Self {
        ObjectInner::ArchivedItem(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for ArchivedItem {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ArchivedItem(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<ArfExternalReport> for ObjectInner {
    fn from(value: ArfExternalReport) -> Self {
        ObjectInner::ArfExternalReport(Box::new(value))
    }
}

impl From<Object> for ArfExternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ArfExternalReport(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Asn> for ObjectInner {
    fn from(value: Asn) -> Self {
        ObjectInner::Asn(Box::new(value))
    }
}

impl From<Object> for Asn {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Asn(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Authentication> for ObjectInner {
    fn from(value: Authentication) -> Self {
        ObjectInner::Authentication(Box::new(value))
    }
}

impl From<Object> for Authentication {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Authentication(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<BlobStore> for ObjectInner {
    fn from(value: BlobStore) -> Self {
        ObjectInner::BlobStore(Box::new(value))
    }
}

impl From<Object> for BlobStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::BlobStore(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<BlockedIp> for ObjectInner {
    fn from(value: BlockedIp) -> Self {
        ObjectInner::BlockedIp(Box::new(value))
    }
}

impl From<Object> for BlockedIp {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::BlockedIp(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Bootstrap> for ObjectInner {
    fn from(value: Bootstrap) -> Self {
        ObjectInner::Bootstrap(Box::new(value))
    }
}

impl From<Object> for Bootstrap {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Bootstrap(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Cache> for ObjectInner {
    fn from(value: Cache) -> Self {
        ObjectInner::Cache(Box::new(value))
    }
}

impl From<Object> for Cache {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Cache(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Calendar> for ObjectInner {
    fn from(value: Calendar) -> Self {
        ObjectInner::Calendar(Box::new(value))
    }
}

impl From<Object> for Calendar {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Calendar(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<CalendarAlarm> for ObjectInner {
    fn from(value: CalendarAlarm) -> Self {
        ObjectInner::CalendarAlarm(Box::new(value))
    }
}

impl From<Object> for CalendarAlarm {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::CalendarAlarm(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<CalendarScheduling> for ObjectInner {
    fn from(value: CalendarScheduling) -> Self {
        ObjectInner::CalendarScheduling(Box::new(value))
    }
}

impl From<Object> for CalendarScheduling {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::CalendarScheduling(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Certificate> for ObjectInner {
    fn from(value: Certificate) -> Self {
        ObjectInner::Certificate(Box::new(value))
    }
}

impl From<Object> for Certificate {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Certificate(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<ClusterNode> for ObjectInner {
    fn from(value: ClusterNode) -> Self {
        ObjectInner::ClusterNode(Box::new(value))
    }
}

impl From<Object> for ClusterNode {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ClusterNode(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<ClusterRole> for ObjectInner {
    fn from(value: ClusterRole) -> Self {
        ObjectInner::ClusterRole(Box::new(value))
    }
}

impl From<Object> for ClusterRole {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ClusterRole(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Coordinator> for ObjectInner {
    fn from(value: Coordinator) -> Self {
        ObjectInner::Coordinator(Box::new(value))
    }
}

impl From<Object> for Coordinator {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Coordinator(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DataRetention> for ObjectInner {
    fn from(value: DataRetention) -> Self {
        ObjectInner::DataRetention(Box::new(value))
    }
}

impl From<Object> for DataRetention {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DataRetention(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DataStore> for ObjectInner {
    fn from(value: DataStore) -> Self {
        ObjectInner::DataStore(Box::new(value))
    }
}

impl From<Object> for DataStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DataStore(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Directory> for ObjectInner {
    fn from(value: Directory) -> Self {
        ObjectInner::Directory(Box::new(value))
    }
}

impl From<Object> for Directory {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Directory(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DkimReportSettings> for ObjectInner {
    fn from(value: DkimReportSettings) -> Self {
        ObjectInner::DkimReportSettings(Box::new(value))
    }
}

impl From<Object> for DkimReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DkimReportSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DkimSignature> for ObjectInner {
    fn from(value: DkimSignature) -> Self {
        ObjectInner::DkimSignature(Box::new(value))
    }
}

impl From<Object> for DkimSignature {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DkimSignature(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DmarcExternalReport> for ObjectInner {
    fn from(value: DmarcExternalReport) -> Self {
        ObjectInner::DmarcExternalReport(Box::new(value))
    }
}

impl From<Object> for DmarcExternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DmarcExternalReport(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DmarcInternalReport> for ObjectInner {
    fn from(value: DmarcInternalReport) -> Self {
        ObjectInner::DmarcInternalReport(Box::new(value))
    }
}

impl From<Object> for DmarcInternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DmarcInternalReport(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DmarcReportSettings> for ObjectInner {
    fn from(value: DmarcReportSettings) -> Self {
        ObjectInner::DmarcReportSettings(Box::new(value))
    }
}

impl From<Object> for DmarcReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DmarcReportSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DnsResolver> for ObjectInner {
    fn from(value: DnsResolver) -> Self {
        ObjectInner::DnsResolver(Box::new(value))
    }
}

impl From<Object> for DnsResolver {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DnsResolver(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DnsServer> for ObjectInner {
    fn from(value: DnsServer) -> Self {
        ObjectInner::DnsServer(Box::new(value))
    }
}

impl From<Object> for DnsServer {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DnsServer(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Domain> for ObjectInner {
    fn from(value: Domain) -> Self {
        ObjectInner::Domain(Box::new(value))
    }
}

impl From<Object> for Domain {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Domain(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<DsnReportSettings> for ObjectInner {
    fn from(value: DsnReportSettings) -> Self {
        ObjectInner::DsnReportSettings(Box::new(value))
    }
}

impl From<Object> for DsnReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DsnReportSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Email> for ObjectInner {
    fn from(value: Email) -> Self {
        ObjectInner::Email(Box::new(value))
    }
}

impl From<Object> for Email {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Email(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<Enterprise> for ObjectInner {
    fn from(value: Enterprise) -> Self {
        ObjectInner::Enterprise(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for Enterprise {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Enterprise(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<EventTracingLevel> for ObjectInner {
    fn from(value: EventTracingLevel) -> Self {
        ObjectInner::EventTracingLevel(Box::new(value))
    }
}

impl From<Object> for EventTracingLevel {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::EventTracingLevel(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<FileStorage> for ObjectInner {
    fn from(value: FileStorage) -> Self {
        ObjectInner::FileStorage(Box::new(value))
    }
}

impl From<Object> for FileStorage {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::FileStorage(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Http> for ObjectInner {
    fn from(value: Http) -> Self {
        ObjectInner::Http(Box::new(value))
    }
}

impl From<Object> for Http {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Http(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<HttpForm> for ObjectInner {
    fn from(value: HttpForm) -> Self {
        ObjectInner::HttpForm(Box::new(value))
    }
}

impl From<Object> for HttpForm {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::HttpForm(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<HttpLookup> for ObjectInner {
    fn from(value: HttpLookup) -> Self {
        ObjectInner::HttpLookup(Box::new(value))
    }
}

impl From<Object> for HttpLookup {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::HttpLookup(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Imap> for ObjectInner {
    fn from(value: Imap) -> Self {
        ObjectInner::Imap(Box::new(value))
    }
}

impl From<Object> for Imap {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Imap(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<InMemoryStore> for ObjectInner {
    fn from(value: InMemoryStore) -> Self {
        ObjectInner::InMemoryStore(Box::new(value))
    }
}

impl From<Object> for InMemoryStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::InMemoryStore(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<IndexQueueStatus> for ObjectInner {
    fn from(value: IndexQueueStatus) -> Self {
        ObjectInner::IndexQueueStatus(Box::new(value))
    }
}

impl From<Object> for IndexQueueStatus {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::IndexQueueStatus(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Jmap> for ObjectInner {
    fn from(value: Jmap) -> Self {
        ObjectInner::Jmap(Box::new(value))
    }
}

impl From<Object> for Jmap {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Jmap(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Log> for ObjectInner {
    fn from(value: Log) -> Self {
        ObjectInner::Log(Box::new(value))
    }
}

impl From<Object> for Log {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Log(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MailingList> for ObjectInner {
    fn from(value: MailingList) -> Self {
        ObjectInner::MailingList(Box::new(value))
    }
}

impl From<Object> for MailingList {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MailingList(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<MaskedEmail> for ObjectInner {
    fn from(value: MaskedEmail) -> Self {
        ObjectInner::MaskedEmail(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for MaskedEmail {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MaskedEmail(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<MemoryLookupKey> for ObjectInner {
    fn from(value: MemoryLookupKey) -> Self {
        ObjectInner::MemoryLookupKey(Box::new(value))
    }
}

impl From<Object> for MemoryLookupKey {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MemoryLookupKey(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MemoryLookupKeyValue> for ObjectInner {
    fn from(value: MemoryLookupKeyValue) -> Self {
        ObjectInner::MemoryLookupKeyValue(Box::new(value))
    }
}

impl From<Object> for MemoryLookupKeyValue {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MemoryLookupKeyValue(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Metadata> for ObjectInner {
    fn from(value: Metadata) -> Self {
        ObjectInner::Metadata(Box::new(value))
    }
}

impl From<Object> for Metadata {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Metadata(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<Metric> for ObjectInner {
    fn from(value: Metric) -> Self {
        ObjectInner::Metric(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for Metric {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Metric(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<Metrics> for ObjectInner {
    fn from(value: Metrics) -> Self {
        ObjectInner::Metrics(Box::new(value))
    }
}

impl From<Object> for Metrics {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Metrics(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<MetricsStore> for ObjectInner {
    fn from(value: MetricsStore) -> Self {
        ObjectInner::MetricsStore(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for MetricsStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MetricsStore(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<MtaConnectionStrategy> for ObjectInner {
    fn from(value: MtaConnectionStrategy) -> Self {
        ObjectInner::MtaConnectionStrategy(Box::new(value))
    }
}

impl From<Object> for MtaConnectionStrategy {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaConnectionStrategy(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaDeliverySchedule> for ObjectInner {
    fn from(value: MtaDeliverySchedule) -> Self {
        ObjectInner::MtaDeliverySchedule(Box::new(value))
    }
}

impl From<Object> for MtaDeliverySchedule {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaDeliverySchedule(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaExtensions> for ObjectInner {
    fn from(value: MtaExtensions) -> Self {
        ObjectInner::MtaExtensions(Box::new(value))
    }
}

impl From<Object> for MtaExtensions {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaExtensions(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaHook> for ObjectInner {
    fn from(value: MtaHook) -> Self {
        ObjectInner::MtaHook(Box::new(value))
    }
}

impl From<Object> for MtaHook {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaHook(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaInboundSession> for ObjectInner {
    fn from(value: MtaInboundSession) -> Self {
        ObjectInner::MtaInboundSession(Box::new(value))
    }
}

impl From<Object> for MtaInboundSession {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaInboundSession(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaInboundThrottle> for ObjectInner {
    fn from(value: MtaInboundThrottle) -> Self {
        ObjectInner::MtaInboundThrottle(Box::new(value))
    }
}

impl From<Object> for MtaInboundThrottle {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaInboundThrottle(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaMilter> for ObjectInner {
    fn from(value: MtaMilter) -> Self {
        ObjectInner::MtaMilter(Box::new(value))
    }
}

impl From<Object> for MtaMilter {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaMilter(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaOutboundStrategy> for ObjectInner {
    fn from(value: MtaOutboundStrategy) -> Self {
        ObjectInner::MtaOutboundStrategy(Box::new(value))
    }
}

impl From<Object> for MtaOutboundStrategy {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaOutboundStrategy(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaOutboundThrottle> for ObjectInner {
    fn from(value: MtaOutboundThrottle) -> Self {
        ObjectInner::MtaOutboundThrottle(Box::new(value))
    }
}

impl From<Object> for MtaOutboundThrottle {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaOutboundThrottle(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaQueueQuota> for ObjectInner {
    fn from(value: MtaQueueQuota) -> Self {
        ObjectInner::MtaQueueQuota(Box::new(value))
    }
}

impl From<Object> for MtaQueueQuota {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaQueueQuota(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaRoute> for ObjectInner {
    fn from(value: MtaRoute) -> Self {
        ObjectInner::MtaRoute(Box::new(value))
    }
}

impl From<Object> for MtaRoute {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaRoute(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageAuth> for ObjectInner {
    fn from(value: MtaStageAuth) -> Self {
        ObjectInner::MtaStageAuth(Box::new(value))
    }
}

impl From<Object> for MtaStageAuth {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageAuth(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageConnect> for ObjectInner {
    fn from(value: MtaStageConnect) -> Self {
        ObjectInner::MtaStageConnect(Box::new(value))
    }
}

impl From<Object> for MtaStageConnect {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageConnect(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageData> for ObjectInner {
    fn from(value: MtaStageData) -> Self {
        ObjectInner::MtaStageData(Box::new(value))
    }
}

impl From<Object> for MtaStageData {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageData(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageEhlo> for ObjectInner {
    fn from(value: MtaStageEhlo) -> Self {
        ObjectInner::MtaStageEhlo(Box::new(value))
    }
}

impl From<Object> for MtaStageEhlo {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageEhlo(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageMail> for ObjectInner {
    fn from(value: MtaStageMail) -> Self {
        ObjectInner::MtaStageMail(Box::new(value))
    }
}

impl From<Object> for MtaStageMail {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageMail(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageRcpt> for ObjectInner {
    fn from(value: MtaStageRcpt) -> Self {
        ObjectInner::MtaStageRcpt(Box::new(value))
    }
}

impl From<Object> for MtaStageRcpt {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageRcpt(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaSts> for ObjectInner {
    fn from(value: MtaSts) -> Self {
        ObjectInner::MtaSts(Box::new(value))
    }
}

impl From<Object> for MtaSts {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaSts(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaTlsStrategy> for ObjectInner {
    fn from(value: MtaTlsStrategy) -> Self {
        ObjectInner::MtaTlsStrategy(Box::new(value))
    }
}

impl From<Object> for MtaTlsStrategy {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaTlsStrategy(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaVirtualQueue> for ObjectInner {
    fn from(value: MtaVirtualQueue) -> Self {
        ObjectInner::MtaVirtualQueue(Box::new(value))
    }
}

impl From<Object> for MtaVirtualQueue {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaVirtualQueue(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<NetworkListener> for ObjectInner {
    fn from(value: NetworkListener) -> Self {
        ObjectInner::NetworkListener(Box::new(value))
    }
}

impl From<Object> for NetworkListener {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::NetworkListener(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<OAuthClient> for ObjectInner {
    fn from(value: OAuthClient) -> Self {
        ObjectInner::OAuthClient(Box::new(value))
    }
}

impl From<Object> for OAuthClient {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::OAuthClient(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<OAuthGrant> for ObjectInner {
    fn from(value: OAuthGrant) -> Self {
        ObjectInner::OAuthGrant(Box::new(value))
    }
}

impl From<Object> for OAuthGrant {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::OAuthGrant(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<OidcProvider> for ObjectInner {
    fn from(value: OidcProvider) -> Self {
        ObjectInner::OidcProvider(Box::new(value))
    }
}

impl From<Object> for OidcProvider {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::OidcProvider(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<PublicKey> for ObjectInner {
    fn from(value: PublicKey) -> Self {
        ObjectInner::PublicKey(Box::new(value))
    }
}

impl From<Object> for PublicKey {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::PublicKey(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<QueuedMessage> for ObjectInner {
    fn from(value: QueuedMessage) -> Self {
        ObjectInner::QueuedMessage(Box::new(value))
    }
}

impl From<Object> for QueuedMessage {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::QueuedMessage(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<ReportSettings> for ObjectInner {
    fn from(value: ReportSettings) -> Self {
        ObjectInner::ReportSettings(Box::new(value))
    }
}

impl From<Object> for ReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ReportSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Role> for ObjectInner {
    fn from(value: Role) -> Self {
        ObjectInner::Role(Box::new(value))
    }
}

impl From<Object> for Role {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Role(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Search> for ObjectInner {
    fn from(value: Search) -> Self {
        ObjectInner::Search(Box::new(value))
    }
}

impl From<Object> for Search {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Search(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SearchStore> for ObjectInner {
    fn from(value: SearchStore) -> Self {
        ObjectInner::SearchStore(Box::new(value))
    }
}

impl From<Object> for SearchStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SearchStore(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Security> for ObjectInner {
    fn from(value: Security) -> Self {
        ObjectInner::Security(Box::new(value))
    }
}

impl From<Object> for Security {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Security(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SenderAuth> for ObjectInner {
    fn from(value: SenderAuth) -> Self {
        ObjectInner::SenderAuth(Box::new(value))
    }
}

impl From<Object> for SenderAuth {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SenderAuth(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Sharing> for ObjectInner {
    fn from(value: Sharing) -> Self {
        ObjectInner::Sharing(Box::new(value))
    }
}

impl From<Object> for Sharing {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Sharing(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveSystemInterpreter> for ObjectInner {
    fn from(value: SieveSystemInterpreter) -> Self {
        ObjectInner::SieveSystemInterpreter(Box::new(value))
    }
}

impl From<Object> for SieveSystemInterpreter {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveSystemInterpreter(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveSystemScript> for ObjectInner {
    fn from(value: SieveSystemScript) -> Self {
        ObjectInner::SieveSystemScript(Box::new(value))
    }
}

impl From<Object> for SieveSystemScript {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveSystemScript(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveUserInterpreter> for ObjectInner {
    fn from(value: SieveUserInterpreter) -> Self {
        ObjectInner::SieveUserInterpreter(Box::new(value))
    }
}

impl From<Object> for SieveUserInterpreter {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveUserInterpreter(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveUserScript> for ObjectInner {
    fn from(value: SieveUserScript) -> Self {
        ObjectInner::SieveUserScript(Box::new(value))
    }
}

impl From<Object> for SieveUserScript {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveUserScript(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<SpamAi> for ObjectInner {
    fn from(value: SpamAi) -> Self {
        ObjectInner::SpamAi(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for SpamAi {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamAi(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<SpamClassifier> for ObjectInner {
    fn from(value: SpamClassifier) -> Self {
        ObjectInner::SpamClassifier(Box::new(value))
    }
}

impl From<Object> for SpamClassifier {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamClassifier(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamDnsblServer> for ObjectInner {
    fn from(value: SpamDnsblServer) -> Self {
        ObjectInner::SpamDnsblServer(Box::new(value))
    }
}

impl From<Object> for SpamDnsblServer {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamDnsblServer(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamDnsblSettings> for ObjectInner {
    fn from(value: SpamDnsblSettings) -> Self {
        ObjectInner::SpamDnsblSettings(Box::new(value))
    }
}

impl From<Object> for SpamDnsblSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamDnsblSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamFileExtension> for ObjectInner {
    fn from(value: SpamFileExtension) -> Self {
        ObjectInner::SpamFileExtension(Box::new(value))
    }
}

impl From<Object> for SpamFileExtension {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamFileExtension(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamPyzor> for ObjectInner {
    fn from(value: SpamPyzor) -> Self {
        ObjectInner::SpamPyzor(Box::new(value))
    }
}

impl From<Object> for SpamPyzor {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamPyzor(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamRule> for ObjectInner {
    fn from(value: SpamRule) -> Self {
        ObjectInner::SpamRule(Box::new(value))
    }
}

impl From<Object> for SpamRule {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamRule(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamSettings> for ObjectInner {
    fn from(value: SpamSettings) -> Self {
        ObjectInner::SpamSettings(Box::new(value))
    }
}

impl From<Object> for SpamSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamTag> for ObjectInner {
    fn from(value: SpamTag) -> Self {
        ObjectInner::SpamTag(Box::new(value))
    }
}

impl From<Object> for SpamTag {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamTag(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamTrainingSample> for ObjectInner {
    fn from(value: SpamTrainingSample) -> Self {
        ObjectInner::SpamTrainingSample(Box::new(value))
    }
}

impl From<Object> for SpamTrainingSample {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamTrainingSample(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpfReportSettings> for ObjectInner {
    fn from(value: SpfReportSettings) -> Self {
        ObjectInner::SpfReportSettings(Box::new(value))
    }
}

impl From<Object> for SpfReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpfReportSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<StoreLookup> for ObjectInner {
    fn from(value: StoreLookup) -> Self {
        ObjectInner::StoreLookup(Box::new(value))
    }
}

impl From<Object> for StoreLookup {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::StoreLookup(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<SystemSettings> for ObjectInner {
    fn from(value: SystemSettings) -> Self {
        ObjectInner::SystemSettings(Box::new(value))
    }
}

impl From<Object> for SystemSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SystemSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<Task> for ObjectInner {
    fn from(value: Task) -> Self {
        ObjectInner::Task(Box::new(value))
    }
}

impl From<Object> for Task {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Task(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<TaskManager> for ObjectInner {
    fn from(value: TaskManager) -> Self {
        ObjectInner::TaskManager(Box::new(value))
    }
}

impl From<Object> for TaskManager {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TaskManager(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<Tenant> for ObjectInner {
    fn from(value: Tenant) -> Self {
        ObjectInner::Tenant(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for Tenant {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Tenant(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<TlsExternalReport> for ObjectInner {
    fn from(value: TlsExternalReport) -> Self {
        ObjectInner::TlsExternalReport(Box::new(value))
    }
}

impl From<Object> for TlsExternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TlsExternalReport(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<TlsInternalReport> for ObjectInner {
    fn from(value: TlsInternalReport) -> Self {
        ObjectInner::TlsInternalReport(Box::new(value))
    }
}

impl From<Object> for TlsInternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TlsInternalReport(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<TlsReportSettings> for ObjectInner {
    fn from(value: TlsReportSettings) -> Self {
        ObjectInner::TlsReportSettings(Box::new(value))
    }
}

impl From<Object> for TlsReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TlsReportSettings(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<Trace> for ObjectInner {
    fn from(value: Trace) -> Self {
        ObjectInner::Trace(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for Trace {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Trace(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<Tracer> for ObjectInner {
    fn from(value: Tracer) -> Self {
        ObjectInner::Tracer(Box::new(value))
    }
}

impl From<Object> for Tracer {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Tracer(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
impl From<TracingStore> for ObjectInner {
    fn from(value: TracingStore) -> Self {
        ObjectInner::TracingStore(Box::new(value))
    }
}

#[cfg(feature = "enterprise")]
impl From<Object> for TracingStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TracingStore(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

// SPDX-SnippetEnd
impl From<WebDav> for ObjectInner {
    fn from(value: WebDav) -> Self {
        ObjectInner::WebDav(Box::new(value))
    }
}

impl From<Object> for WebDav {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::WebDav(obj) => *obj,
            _ => unreachable!(),
        }
    }
}

impl From<WebHook> for ObjectInner {
    fn from(value: WebHook) -> Self {
        ObjectInner::WebHook(Box::new(value))
    }
}

impl From<Object> for WebHook {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::WebHook(obj) => *obj,
            _ => unreachable!(),
        }
    }
}
