/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

use crate::schema::prelude::*;

impl EnumImpl for ObjectType {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
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
            b"Jmap" => ObjectType::Jmap,
            b"Log" => ObjectType::Log,
            b"MailingList" => ObjectType::MailingList,
            b"MaskedEmail" => ObjectType::MaskedEmail,
            b"MemoryLookupKey" => ObjectType::MemoryLookupKey,
            b"MemoryLookupKeyValue" => ObjectType::MemoryLookupKeyValue,
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
            b"SpamLlm" => ObjectType::SpamLlm,
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
    }

    fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Account => "Account",
            ObjectType::AccountPassword => "AccountPassword",
            ObjectType::AccountSettings => "AccountSettings",
            ObjectType::AcmeProvider => "AcmeProvider",
            ObjectType::Action => "Action",
            ObjectType::AddressBook => "AddressBook",
            ObjectType::AiModel => "AiModel",
            ObjectType::Alert => "Alert",
            ObjectType::AllowedIp => "AllowedIp",
            ObjectType::ApiKey => "ApiKey",
            ObjectType::AppPassword => "AppPassword",
            ObjectType::Application => "Application",
            ObjectType::ArchivedItem => "ArchivedItem",
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
            ObjectType::Enterprise => "Enterprise",
            ObjectType::EventTracingLevel => "EventTracingLevel",
            ObjectType::FileStorage => "FileStorage",
            ObjectType::Http => "Http",
            ObjectType::HttpForm => "HttpForm",
            ObjectType::HttpLookup => "HttpLookup",
            ObjectType::Imap => "Imap",
            ObjectType::InMemoryStore => "InMemoryStore",
            ObjectType::Jmap => "Jmap",
            ObjectType::Log => "Log",
            ObjectType::MailingList => "MailingList",
            ObjectType::MaskedEmail => "MaskedEmail",
            ObjectType::MemoryLookupKey => "MemoryLookupKey",
            ObjectType::MemoryLookupKeyValue => "MemoryLookupKeyValue",
            ObjectType::Metric => "Metric",
            ObjectType::Metrics => "Metrics",
            ObjectType::MetricsStore => "MetricsStore",
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
            ObjectType::SpamClassifier => "SpamClassifier",
            ObjectType::SpamDnsblServer => "SpamDnsblServer",
            ObjectType::SpamDnsblSettings => "SpamDnsblSettings",
            ObjectType::SpamFileExtension => "SpamFileExtension",
            ObjectType::SpamLlm => "SpamLlm",
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
            ObjectType::Tenant => "Tenant",
            ObjectType::TlsExternalReport => "TlsExternalReport",
            ObjectType::TlsInternalReport => "TlsInternalReport",
            ObjectType::TlsReportSettings => "TlsReportSettings",
            ObjectType::Trace => "Trace",
            ObjectType::Tracer => "Tracer",
            ObjectType::TracingStore => "TracingStore",
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
            6 => Some(ObjectType::AiModel),
            7 => Some(ObjectType::Alert),
            8 => Some(ObjectType::AllowedIp),
            9 => Some(ObjectType::ApiKey),
            10 => Some(ObjectType::AppPassword),
            11 => Some(ObjectType::Application),
            12 => Some(ObjectType::ArchivedItem),
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
            40 => Some(ObjectType::Enterprise),
            41 => Some(ObjectType::EventTracingLevel),
            42 => Some(ObjectType::FileStorage),
            43 => Some(ObjectType::Http),
            44 => Some(ObjectType::HttpForm),
            45 => Some(ObjectType::HttpLookup),
            46 => Some(ObjectType::Imap),
            47 => Some(ObjectType::InMemoryStore),
            48 => Some(ObjectType::Jmap),
            49 => Some(ObjectType::Log),
            50 => Some(ObjectType::MailingList),
            51 => Some(ObjectType::MaskedEmail),
            52 => Some(ObjectType::MemoryLookupKey),
            53 => Some(ObjectType::MemoryLookupKeyValue),
            54 => Some(ObjectType::Metric),
            55 => Some(ObjectType::Metrics),
            56 => Some(ObjectType::MetricsStore),
            57 => Some(ObjectType::MtaConnectionStrategy),
            58 => Some(ObjectType::MtaDeliverySchedule),
            59 => Some(ObjectType::MtaExtensions),
            60 => Some(ObjectType::MtaHook),
            61 => Some(ObjectType::MtaInboundSession),
            62 => Some(ObjectType::MtaInboundThrottle),
            63 => Some(ObjectType::MtaMilter),
            64 => Some(ObjectType::MtaOutboundStrategy),
            65 => Some(ObjectType::MtaOutboundThrottle),
            66 => Some(ObjectType::MtaQueueQuota),
            67 => Some(ObjectType::MtaRoute),
            68 => Some(ObjectType::MtaStageAuth),
            69 => Some(ObjectType::MtaStageConnect),
            70 => Some(ObjectType::MtaStageData),
            71 => Some(ObjectType::MtaStageEhlo),
            72 => Some(ObjectType::MtaStageMail),
            73 => Some(ObjectType::MtaStageRcpt),
            74 => Some(ObjectType::MtaSts),
            75 => Some(ObjectType::MtaTlsStrategy),
            76 => Some(ObjectType::MtaVirtualQueue),
            77 => Some(ObjectType::NetworkListener),
            78 => Some(ObjectType::OAuthClient),
            79 => Some(ObjectType::OidcProvider),
            80 => Some(ObjectType::PublicKey),
            81 => Some(ObjectType::QueuedMessage),
            82 => Some(ObjectType::ReportSettings),
            83 => Some(ObjectType::Role),
            84 => Some(ObjectType::Search),
            85 => Some(ObjectType::SearchStore),
            86 => Some(ObjectType::Security),
            87 => Some(ObjectType::SenderAuth),
            88 => Some(ObjectType::Sharing),
            89 => Some(ObjectType::SieveSystemInterpreter),
            90 => Some(ObjectType::SieveSystemScript),
            91 => Some(ObjectType::SieveUserInterpreter),
            92 => Some(ObjectType::SieveUserScript),
            93 => Some(ObjectType::SpamClassifier),
            94 => Some(ObjectType::SpamDnsblServer),
            95 => Some(ObjectType::SpamDnsblSettings),
            96 => Some(ObjectType::SpamFileExtension),
            97 => Some(ObjectType::SpamLlm),
            98 => Some(ObjectType::SpamPyzor),
            99 => Some(ObjectType::SpamRule),
            100 => Some(ObjectType::SpamSettings),
            101 => Some(ObjectType::SpamTag),
            102 => Some(ObjectType::SpamTrainingSample),
            103 => Some(ObjectType::SpfReportSettings),
            104 => Some(ObjectType::StoreLookup),
            105 => Some(ObjectType::SystemSettings),
            106 => Some(ObjectType::Task),
            107 => Some(ObjectType::TaskManager),
            108 => Some(ObjectType::Tenant),
            109 => Some(ObjectType::TlsExternalReport),
            110 => Some(ObjectType::TlsInternalReport),
            111 => Some(ObjectType::TlsReportSettings),
            112 => Some(ObjectType::Trace),
            113 => Some(ObjectType::Tracer),
            114 => Some(ObjectType::TracingStore),
            115 => Some(ObjectType::WebDav),
            116 => Some(ObjectType::WebHook),
            _ => None,
        }
    }

    const COUNT: usize = 117;
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
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map! {
            value.as_bytes(),
            b"@type" => Property::Type,
            b"abuseBanPeriod" => Property::AbuseBanPeriod,
            b"abuseBanRate" => Property::AbuseBanRate,
            b"accessKey" => Property::AccessKey,
            b"accessKeyId" => Property::AccessKeyId,
            b"accessToken" => Property::AccessToken,
            b"accessTokenExpiry" => Property::AccessTokenExpiry,
            b"accessTokens" => Property::AccessTokens,
            b"accountDomainId" => Property::AccountDomainId,
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
            b"addresses" => Property::Addresses,
            b"aggregateContactInfo" => Property::AggregateContactInfo,
            b"aggregateDkimSignDomain" => Property::AggregateDkimSignDomain,
            b"aggregateFromAddress" => Property::AggregateFromAddress,
            b"aggregateFromName" => Property::AggregateFromName,
            b"aggregateMaxReportSize" => Property::AggregateMaxReportSize,
            b"aggregateOrgName" => Property::AggregateOrgName,
            b"aggregateSendFrequency" => Property::AggregateSendFrequency,
            b"aggregateSubject" => Property::AggregateSubject,
            b"alarmId" => Property::AlarmId,
            b"algorithms" => Property::Algorithms,
            b"aliases" => Property::Aliases,
            b"allowCount" => Property::AllowCount,
            b"allowDirectoryQueries" => Property::AllowDirectoryQueries,
            b"allowExternalRcpts" => Property::AllowExternalRcpts,
            b"allowInvalidCerts" => Property::AllowInvalidCerts,
            b"allowPlainTextAuth" => Property::AllowPlainTextAuth,
            b"allowRelaying" => Property::AllowRelaying,
            b"allowSpamTraining" => Property::AllowSpamTraining,
            b"allowedEndpoints" => Property::AllowedEndpoints,
            b"allowedIps" => Property::AllowedIps,
            b"allowedNotifyUris" => Property::AllowedNotifyUris,
            b"alpha" => Property::Alpha,
            b"anonymousClientRegistration" => Property::AnonymousClientRegistration,
            b"ansi" => Property::Ansi,
            b"apiKey" => Property::ApiKey,
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
            b"authCodeMaxAttempts" => Property::AuthCodeMaxAttempts,
            b"authFailure" => Property::AuthFailure,
            b"authId" => Property::AuthId,
            b"authSecret" => Property::AuthSecret,
            b"authToken" => Property::AuthToken,
            b"authUsername" => Property::AuthUsername,
            b"authenticatedAs" => Property::AuthenticatedAs,
            b"authenticationResults" => Property::AuthenticationResults,
            b"autoAddInvitations" => Property::AutoAddInvitations,
            b"autoUpdateFrequency" => Property::AutoUpdateFrequency,
            b"baseDn" => Property::BaseDn,
            b"baseUrl" => Property::BaseUrl,
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
            b"brokers" => Property::Brokers,
            b"bucket" => Property::Bucket,
            b"bufferSize" => Property::BufferSize,
            b"buffered" => Property::Buffered,
            b"canonicalization" => Property::Canonicalization,
            b"capacityClient" => Property::CapacityClient,
            b"capacityReadBuffer" => Property::CapacityReadBuffer,
            b"capacitySubscription" => Property::CapacitySubscription,
            b"catchAllAddress" => Property::CatchAllAddress,
            b"categories" => Property::Categories,
            b"certificate" => Property::Certificate,
            b"certificateManagement" => Property::CertificateManagement,
            b"challengeType" => Property::ChallengeType,
            b"changesMaxResults" => Property::ChangesMaxResults,
            b"chunking" => Property::Chunking,
            b"claimGroups" => Property::ClaimGroups,
            b"claimName" => Property::ClaimName,
            b"claimUsername" => Property::ClaimUsername,
            b"cleartext" => Property::Cleartext,
            b"clientId" => Property::ClientId,
            b"clientIp" => Property::ClientIp,
            b"clientSecret" => Property::ClientSecret,
            b"clientToken" => Property::ClientToken,
            b"clusterFile" => Property::ClusterFile,
            b"columnClass" => Property::ColumnClass,
            b"columnDescription" => Property::ColumnDescription,
            b"columnEmail" => Property::ColumnEmail,
            b"columnSecret" => Property::ColumnSecret,
            b"comment" => Property::Comment,
            b"compartmentOcid" => Property::CompartmentOcid,
            b"compressionAlgorithm" => Property::CompressionAlgorithm,
            b"concurrency" => Property::Concurrency,
            b"condition" => Property::Condition,
            b"confidence" => Property::Confidence,
            b"config" => Property::Config,
            b"configName" => Property::ConfigName,
            b"connectTimeout" => Property::ConnectTimeout,
            b"connection" => Property::Connection,
            b"consumerKey" => Property::ConsumerKey,
            b"contact" => Property::Contact,
            b"contactInfo" => Property::ContactInfo,
            b"contacts" => Property::Contacts,
            b"container" => Property::Container,
            b"content" => Property::Content,
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
            b"customEndpoint" => Property::CustomEndpoint,
            b"customRegion" => Property::CustomRegion,
            b"customRule" => Property::CustomRule,
            b"customerNumber" => Property::CustomerNumber,
            b"dane" => Property::Dane,
            b"dataCleanupSchedule" => Property::DataCleanupSchedule,
            b"dataStore" => Property::DataStore,
            b"dataTimeout" => Property::DataTimeout,
            b"database" => Property::Database,
            b"datacenterId" => Property::DatacenterId,
            b"dateRangeBegin" => Property::DateRangeBegin,
            b"dateRangeEnd" => Property::DateRangeEnd,
            b"dateRangeStart" => Property::DateRangeStart,
            b"day" => Property::Day,
            b"deadPropertyMaxSize" => Property::DeadPropertyMaxSize,
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
            b"dnsRbl" => Property::DnsRbl,
            b"dnsServer" => Property::DnsServer,
            b"dnsServerId" => Property::DnsServerId,
            b"dnsTlsa" => Property::DnsTlsa,
            b"dnsTxt" => Property::DnsTxt,
            b"dnsView" => Property::DnsView,
            b"dnsZoneFile" => Property::DnsZoneFile,
            b"documentId" => Property::DocumentId,
            b"documentType" => Property::DocumentType,
            b"domain" => Property::Domain,
            b"domainId" => Property::DomainId,
            b"domainLimit" => Property::DomainLimit,
            b"domainNames" => Property::DomainNames,
            b"domainNamesNegative" => Property::DomainNamesNegative,
            b"domains" => Property::Domains,
            b"dsn" => Property::Dsn,
            b"due" => Property::Due,
            b"duplicateExpiry" => Property::DuplicateExpiry,
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
            b"enabled" => Property::Enabled,
            b"enabledPermissions" => Property::EnabledPermissions,
            b"encryptAtRest" => Property::EncryptAtRest,
            b"encryptOnAppend" => Property::EncryptOnAppend,
            b"encryptionAtRest" => Property::EncryptionAtRest,
            b"encryptionKey" => Property::EncryptionKey,
            b"endpoint" => Property::Endpoint,
            b"envFrom" => Property::EnvFrom,
            b"envFromParameters" => Property::EnvFromParameters,
            b"envId" => Property::EnvId,
            b"envRcptTo" => Property::EnvRcptTo,
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
            b"filterMailbox" => Property::FilterMailbox,
            b"filterMemberOf" => Property::FilterMemberOf,
            b"fingerprint" => Property::Fingerprint,
            b"flags" => Property::Flags,
            b"flagsAction" => Property::FlagsAction,
            b"flagsProtocol" => Property::FlagsProtocol,
            b"folderId" => Property::FolderId,
            b"forDomain" => Property::ForDomain,
            b"format" => Property::Format,
            b"from" => Property::From,
            b"fromAddress" => Property::FromAddress,
            b"fromEmail" => Property::FromEmail,
            b"fromName" => Property::FromName,
            b"futureRelease" => Property::FutureRelease,
            b"generateDkimKeys" => Property::GenerateDkimKeys,
            b"generator" => Property::Generator,
            b"geoUrls" => Property::GeoUrls,
            b"getMaxResults" => Property::GetMaxResults,
            b"greetingTimeout" => Property::GreetingTimeout,
            b"greylistFor" => Property::GreylistFor,
            b"groupClass" => Property::GroupClass,
            b"groupId" => Property::GroupId,
            b"headerFrom" => Property::HeaderFrom,
            b"headers" => Property::Headers,
            b"holdMetricsFor" => Property::HoldMetricsFor,
            b"holdMtaReportsFor" => Property::HoldMtaReportsFor,
            b"holdSamplesFor" => Property::HoldSamplesFor,
            b"holdTracesFor" => Property::HoldTracesFor,
            b"host" => Property::Host,
            b"hostedZoneId" => Property::HostedZoneId,
            b"hostname" => Property::Hostname,
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
            b"if" => Property::If,
            b"impersonateServiceAccount" => Property::ImpersonateServiceAccount,
            b"implicitTls" => Property::ImplicitTls,
            b"inMemoryStore" => Property::InMemoryStore,
            b"inboundReportAddresses" => Property::InboundReportAddresses,
            b"inboundReportForwarding" => Property::InboundReportForwarding,
            b"incidents" => Property::Incidents,
            b"includeSource" => Property::IncludeSource,
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
            b"indexKey" => Property::IndexKey,
            b"indexTelemetry" => Property::IndexTelemetry,
            b"indexTracingFields" => Property::IndexTracingFields,
            b"indexValue" => Property::IndexValue,
            b"indicatorParameters" => Property::IndicatorParameters,
            b"initialDelay" => Property::InitialDelay,
            b"interval" => Property::Interval,
            b"intervals" => Property::Intervals,
            b"ipLimit" => Property::IpLimit,
            b"ipLookupStrategy" => Property::IpLookupStrategy,
            b"ipRevPtr" => Property::IpRevPtr,
            b"ipRevResult" => Property::IpRevResult,
            b"isActive" => Property::IsActive,
            b"isArchive" => Property::IsArchive,
            b"isBad" => Property::IsBad,
            b"isEnabled" => Property::IsEnabled,
            b"isFromOrganizer" => Property::IsFromOrganizer,
            b"isGlobPattern" => Property::IsGlobPattern,
            b"isGzipped" => Property::IsGzipped,
            b"isNz" => Property::IsNz,
            b"isSenderAllowed" => Property::IsSenderAllowed,
            b"isSpam" => Property::IsSpam,
            b"isTls" => Property::IsTls,
            b"issuer" => Property::Issuer,
            b"issuerUrl" => Property::IssuerUrl,
            b"itipMaxSize" => Property::ItipMaxSize,
            b"jitter" => Property::Jitter,
            b"key" => Property::Key,
            b"keyName" => Property::KeyName,
            b"keyPrefix" => Property::KeyPrefix,
            b"keyValues" => Property::KeyValues,
            b"l1Ratio" => Property::L1Ratio,
            b"l2Ratio" => Property::L2Ratio,
            b"lastRenewal" => Property::LastRenewal,
            b"learnHamFromCard" => Property::LearnHamFromCard,
            b"learnHamFromReply" => Property::LearnHamFromReply,
            b"learnSpamFromRblHits" => Property::LearnSpamFromRblHits,
            b"learnSpamFromTraps" => Property::LearnSpamFromTraps,
            b"level" => Property::Level,
            b"licenseKey" => Property::LicenseKey,
            b"line" => Property::Line,
            b"listenerIds" => Property::ListenerIds,
            b"listeners" => Property::Listeners,
            b"livePropertyMaxSize" => Property::LivePropertyMaxSize,
            b"locale" => Property::Locale,
            b"logo" => Property::Logo,
            b"logoUrl" => Property::LogoUrl,
            b"loiterBanPeriod" => Property::LoiterBanPeriod,
            b"loiterBanRate" => Property::LoiterBanRate,
            b"lossy" => Property::Lossy,
            b"machineId" => Property::MachineId,
            b"mailExchangers" => Property::MailExchangers,
            b"mailFrom" => Property::MailFrom,
            b"mailFromTimeout" => Property::MailFromTimeout,
            b"mailRua" => Property::MailRua,
            b"mailingLists" => Property::MailingLists,
            b"maintenanceType" => Property::MaintenanceType,
            b"managedZone" => Property::ManagedZone,
            b"match" => Property::Match,
            b"maxAddressBooks" => Property::MaxAddressBooks,
            b"maxAge" => Property::MaxAge,
            b"maxAllowedPacket" => Property::MaxAllowedPacket,
            b"maxApiKeys" => Property::MaxApiKeys,
            b"maxAppPasswords" => Property::MaxAppPasswords,
            b"maxAttachmentSize" => Property::MaxAttachmentSize,
            b"maxAttempts" => Property::MaxAttempts,
            b"maxAttendees" => Property::MaxAttendees,
            b"maxAuthFailures" => Property::MaxAuthFailures,
            b"maxCalendars" => Property::MaxCalendars,
            b"maxChangesHistory" => Property::MaxChangesHistory,
            b"maxConcurrent" => Property::MaxConcurrent,
            b"maxConcurrentRequests" => Property::MaxConcurrentRequests,
            b"maxConcurrentUploads" => Property::MaxConcurrentUploads,
            b"maxConnections" => Property::MaxConnections,
            b"maxContacts" => Property::MaxContacts,
            b"maxCpuCycles" => Property::MaxCpuCycles,
            b"maxDelay" => Property::MaxDelay,
            b"maxDuration" => Property::MaxDuration,
            b"maxEntries" => Property::MaxEntries,
            b"maxEntrySize" => Property::MaxEntrySize,
            b"maxEventNotifications" => Property::MaxEventNotifications,
            b"maxEvents" => Property::MaxEvents,
            b"maxFailures" => Property::MaxFailures,
            b"maxFiles" => Property::MaxFiles,
            b"maxFolders" => Property::MaxFolders,
            b"maxHeaderSize" => Property::MaxHeaderSize,
            b"maxICalendarSize" => Property::MaxICalendarSize,
            b"maxIdentities" => Property::MaxIdentities,
            b"maxIncludes" => Property::MaxIncludes,
            b"maxLocalVars" => Property::MaxLocalVars,
            b"maxLockTimeout" => Property::MaxLockTimeout,
            b"maxLocks" => Property::MaxLocks,
            b"maxMailboxDepth" => Property::MaxMailboxDepth,
            b"maxMailboxNameLength" => Property::MaxMailboxNameLength,
            b"maxMailboxes" => Property::MaxMailboxes,
            b"maxMaskedAddresses" => Property::MaxMaskedAddresses,
            b"maxMatchVars" => Property::MaxMatchVars,
            b"maxMessageSize" => Property::MaxMessageSize,
            b"maxMessages" => Property::MaxMessages,
            b"maxMethodCalls" => Property::MaxMethodCalls,
            b"maxMultihomed" => Property::MaxMultihomed,
            b"maxMxHosts" => Property::MaxMxHosts,
            b"maxNestedBlocks" => Property::MaxNestedBlocks,
            b"maxNestedForEvery" => Property::MaxNestedForEvery,
            b"maxNestedIncludes" => Property::MaxNestedIncludes,
            b"maxNestedTests" => Property::MaxNestedTests,
            b"maxOutMessages" => Property::MaxOutMessages,
            b"maxParticipantIdentities" => Property::MaxParticipantIdentities,
            b"maxPublicKeys" => Property::MaxPublicKeys,
            b"maxReceivedHeaders" => Property::MaxReceivedHeaders,
            b"maxRecipients" => Property::MaxRecipients,
            b"maxReconnects" => Property::MaxReconnects,
            b"maxRecurrenceExpansions" => Property::MaxRecurrenceExpansions,
            b"maxRedirects" => Property::MaxRedirects,
            b"maxReportSize" => Property::MaxReportSize,
            b"maxRequestRate" => Property::MaxRequestRate,
            b"maxRequestSize" => Property::MaxRequestSize,
            b"maxResponseSize" => Property::MaxResponseSize,
            b"maxResults" => Property::MaxResults,
            b"maxRetries" => Property::MaxRetries,
            b"maxRetryWait" => Property::MaxRetryWait,
            b"maxScriptNameLength" => Property::MaxScriptNameLength,
            b"maxScriptSize" => Property::MaxScriptSize,
            b"maxScripts" => Property::MaxScripts,
            b"maxShares" => Property::MaxShares,
            b"maxSize" => Property::MaxSize,
            b"maxStringLength" => Property::MaxStringLength,
            b"maxSubmissions" => Property::MaxSubmissions,
            b"maxSubscriptions" => Property::MaxSubscriptions,
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
            b"messages" => Property::Messages,
            b"metric" => Property::Metric,
            b"metrics" => Property::Metrics,
            b"metricsCollectionInterval" => Property::MetricsCollectionInterval,
            b"metricsPolicy" => Property::MetricsPolicy,
            b"minHamSamples" => Property::MinHamSamples,
            b"minRetryWait" => Property::MinRetryWait,
            b"minSpamSamples" => Property::MinSpamSamples,
            b"minTriggerInterval" => Property::MinTriggerInterval,
            b"minute" => Property::Minute,
            b"mode" => Property::Mode,
            b"model" => Property::Model,
            b"modelId" => Property::ModelId,
            b"modelType" => Property::ModelType,
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
            b"onSuccessRenewCertificate" => Property::OnSuccessRenewCertificate,
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
            b"password" => Property::Password,
            b"passwordDefaultExpiry" => Property::PasswordDefaultExpiry,
            b"passwordHashAlgorithm" => Property::PasswordHashAlgorithm,
            b"passwordMaxLength" => Property::PasswordMaxLength,
            b"passwordMinLength" => Property::PasswordMinLength,
            b"passwordMinStrength" => Property::PasswordMinStrength,
            b"path" => Property::Path,
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
            b"pollingInterval" => Property::PollingInterval,
            b"poolMaxConnections" => Property::PoolMaxConnections,
            b"poolMinConnections" => Property::PoolMinConnections,
            b"poolRecyclingMethod" => Property::PoolRecyclingMethod,
            b"poolTimeoutCreate" => Property::PoolTimeoutCreate,
            b"poolTimeoutRecycle" => Property::PoolTimeoutRecycle,
            b"poolTimeoutWait" => Property::PoolTimeoutWait,
            b"poolWorkers" => Property::PoolWorkers,
            b"port" => Property::Port,
            b"preferredChain" => Property::PreferredChain,
            b"prefix" => Property::Prefix,
            b"preserveIntermediates" => Property::PreserveIntermediates,
            b"priority" => Property::Priority,
            b"privateKey" => Property::PrivateKey,
            b"privateKeyPassword" => Property::PrivateKeyPassword,
            b"privateKeyPem" => Property::PrivateKeyPem,
            b"privateZone" => Property::PrivateZone,
            b"privateZoneOnly" => Property::PrivateZoneOnly,
            b"profile" => Property::Profile,
            b"projectId" => Property::ProjectId,
            b"prometheus" => Property::Prometheus,
            b"prompt" => Property::Prompt,
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
            b"pushMaxAttempts" => Property::PushMaxAttempts,
            b"pushRequestTimeout" => Property::PushRequestTimeout,
            b"pushRetryWait" => Property::PushRetryWait,
            b"pushShardsTotal" => Property::PushShardsTotal,
            b"pushThrottle" => Property::PushThrottle,
            b"pushVerifyTimeout" => Property::PushVerifyTimeout,
            b"queryEmailAliases" => Property::QueryEmailAliases,
            b"queryLogin" => Property::QueryLogin,
            b"queryMaxResults" => Property::QueryMaxResults,
            b"queryMemberOf" => Property::QueryMemberOf,
            b"queryRecipient" => Property::QueryRecipient,
            b"queueId" => Property::QueueId,
            b"queueName" => Property::QueueName,
            b"quotas" => Property::Quotas,
            b"rate" => Property::Rate,
            b"rateLimit" => Property::RateLimit,
            b"rateLimitAnonymous" => Property::RateLimitAnonymous,
            b"rateLimitAuthenticated" => Property::RateLimitAuthenticated,
            b"ratio" => Property::Ratio,
            b"rcptToTimeout" => Property::RcptToTimeout,
            b"readFromReplicas" => Property::ReadFromReplicas,
            b"readReplicas" => Property::ReadReplicas,
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
            b"redirectRoot" => Property::RedirectRoot,
            b"redirectUris" => Property::RedirectUris,
            b"refresh" => Property::Refresh,
            b"refreshTokenExpiry" => Property::RefreshTokenExpiry,
            b"refreshTokenRenewal" => Property::RefreshTokenRenewal,
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
            b"requestMaxSize" => Property::RequestMaxSize,
            b"requestTlsCertificate" => Property::RequestTlsCertificate,
            b"require" => Property::Require,
            b"requireAudience" => Property::RequireAudience,
            b"requireClientRegistration" => Property::RequireClientRegistration,
            b"requireScopes" => Property::RequireScopes,
            b"requireTls" => Property::RequireTls,
            b"reservoirCapacity" => Property::ReservoirCapacity,
            b"resourceGroup" => Property::ResourceGroup,
            b"resourceUrl" => Property::ResourceUrl,
            b"responseCode" => Property::ResponseCode,
            b"responseEnhanced" => Property::ResponseEnhanced,
            b"responseHeaders" => Property::ResponseHeaders,
            b"responseHostname" => Property::ResponseHostname,
            b"responseMessage" => Property::ResponseMessage,
            b"responsePosCategory" => Property::ResponsePosCategory,
            b"responsePosConfidence" => Property::ResponsePosConfidence,
            b"responsePosExplanation" => Property::ResponsePosExplanation,
            b"result" => Property::Result,
            b"resultType" => Property::ResultType,
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
            b"score" => Property::Score,
            b"scoreDiscard" => Property::ScoreDiscard,
            b"scoreReject" => Property::ScoreReject,
            b"scoreSpam" => Property::ScoreSpam,
            b"script" => Property::Script,
            b"searchStore" => Property::SearchStore,
            b"secret" => Property::Secret,
            b"secretAccessKey" => Property::SecretAccessKey,
            b"secretApiKey" => Property::SecretApiKey,
            b"secretId" => Property::SecretId,
            b"secretKey" => Property::SecretKey,
            b"securityToken" => Property::SecurityToken,
            b"selector" => Property::Selector,
            b"selectorTemplate" => Property::SelectorTemplate,
            b"sendFrequency" => Property::SendFrequency,
            b"sendingMtaIp" => Property::SendingMtaIp,
            b"sentinelSecret" => Property::SentinelSecret,
            b"sentinelUsername" => Property::SentinelUsername,
            b"separator" => Property::Separator,
            b"serverHostname" => Property::ServerHostname,
            b"servers" => Property::Servers,
            b"serviceAccountJson" => Property::ServiceAccountJson,
            b"serviceName" => Property::ServiceName,
            b"services" => Property::Services,
            b"sessionToken" => Property::SessionToken,
            b"setMaxObjects" => Property::SetMaxObjects,
            b"shardIndex" => Property::ShardIndex,
            b"sharedSecret" => Property::SharedSecret,
            b"sig0Algorithm" => Property::Sig0Algorithm,
            b"signatureAlgorithm" => Property::SignatureAlgorithm,
            b"signatureKey" => Property::SignatureKey,
            b"signerName" => Property::SignerName,
            b"size" => Property::Size,
            b"skipDeploy" => Property::SkipDeploy,
            b"skipFirst" => Property::SkipFirst,
            b"smtpGreeting" => Property::SmtpGreeting,
            b"snippetMaxResults" => Property::SnippetMaxResults,
            b"socketBacklog" => Property::SocketBacklog,
            b"socketNoDelay" => Property::SocketNoDelay,
            b"socketReceiveBufferSize" => Property::SocketReceiveBufferSize,
            b"socketReuseAddress" => Property::SocketReuseAddress,
            b"socketReusePort" => Property::SocketReusePort,
            b"socketSendBufferSize" => Property::SocketSendBufferSize,
            b"socketTosV4" => Property::SocketTosV4,
            b"socketTtl" => Property::SocketTtl,
            b"sourceIp" => Property::SourceIp,
            b"sourceIps" => Property::SourceIps,
            b"sourcePort" => Property::SourcePort,
            b"spamFilterRulesUrl" => Property::SpamFilterRulesUrl,
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
            b"subscriptionId" => Property::SubscriptionId,
            b"sum" => Property::Sum,
            b"summary" => Property::Summary,
            b"supportedLanguages" => Property::SupportedLanguages,
            b"tag" => Property::Tag,
            b"tags" => Property::Tags,
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
            b"threadPoolSize" => Property::ThreadPoolSize,
            b"threadsPerNode" => Property::ThreadsPerNode,
            b"throttle" => Property::Throttle,
            b"timeZone" => Property::TimeZone,
            b"timeout" => Property::Timeout,
            b"timeoutAnonymous" => Property::TimeoutAnonymous,
            b"timeoutAuthenticated" => Property::TimeoutAuthenticated,
            b"timeoutCommand" => Property::TimeoutCommand,
            b"timeoutConnect" => Property::TimeoutConnect,
            b"timeoutConnection" => Property::TimeoutConnection,
            b"timeoutData" => Property::TimeoutData,
            b"timeoutIdle" => Property::TimeoutIdle,
            b"timeoutMessage" => Property::TimeoutMessage,
            b"timeoutRequest" => Property::TimeoutRequest,
            b"timeoutSession" => Property::TimeoutSession,
            b"timestamp" => Property::Timestamp,
            b"title" => Property::Title,
            b"tls" => Property::Tls,
            b"tlsDisableCipherSuites" => Property::TlsDisableCipherSuites,
            b"tlsDisableProtocols" => Property::TlsDisableProtocols,
            b"tlsIgnoreClientOrder" => Property::TlsIgnoreClientOrder,
            b"tlsImplicit" => Property::TlsImplicit,
            b"tlsTimeout" => Property::TlsTimeout,
            b"to" => Property::To,
            b"token" => Property::Token,
            b"totalDeadline" => Property::TotalDeadline,
            b"totalFailedSessions" => Property::TotalFailedSessions,
            b"totalSuccessfulSessions" => Property::TotalSuccessfulSessions,
            b"traceId" => Property::TraceId,
            b"tracer" => Property::Tracer,
            b"trainFrequency" => Property::TrainFrequency,
            b"transactionRetryDelay" => Property::TransactionRetryDelay,
            b"transactionRetryLimit" => Property::TransactionRetryLimit,
            b"transactionTimeout" => Property::TransactionTimeout,
            b"transferLimit" => Property::TransferLimit,
            b"trustContacts" => Property::TrustContacts,
            b"trustReplies" => Property::TrustReplies,
            b"tsigAlgorithm" => Property::TsigAlgorithm,
            b"ttl" => Property::Ttl,
            b"unpackDirectory" => Property::UnpackDirectory,
            b"updateRecords" => Property::UpdateRecords,
            b"uploadQuota" => Property::UploadQuota,
            b"uploadTtl" => Property::UploadTtl,
            b"url" => Property::Url,
            b"urlLimit" => Property::UrlLimit,
            b"urlPrefix" => Property::UrlPrefix,
            b"urls" => Property::Urls,
            b"usePermissiveCors" => Property::UsePermissiveCors,
            b"useTls" => Property::UseTls,
            b"useXForwarded" => Property::UseXForwarded,
            b"usedDiskQuota" => Property::UsedDiskQuota,
            b"userAgent" => Property::UserAgent,
            b"userCodeExpiry" => Property::UserCodeExpiry,
            b"userOcid" => Property::UserOcid,
            b"username" => Property::Username,
            b"usernameDomain" => Property::UsernameDomain,
            b"validateDomain" => Property::ValidateDomain,
            b"value" => Property::Value,
            b"variableName" => Property::VariableName,
            b"verifyAfterWrite" => Property::VerifyAfterWrite,
            b"version" => Property::Version,
            b"viewName" => Property::ViewName,
            b"vrfy" => Property::Vrfy,
            b"waitOnFail" => Property::WaitOnFail,
            b"wapiVersion" => Property::WapiVersion,
            b"webPushContact" => Property::WebPushContact,
            b"webPushKey" => Property::WebPushKey,
            b"websocketHeartbeat" => Property::WebsocketHeartbeat,
            b"websocketThrottle" => Property::WebsocketThrottle,
            b"websocketTimeout" => Property::WebsocketTimeout,
            b"zone" => Property::Zone,
            b"zoneIpV4" => Property::ZoneIpV4,
            b"zoneIpV6" => Property::ZoneIpV6,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Property::Type => "@type",
            Property::AbuseBanPeriod => "abuseBanPeriod",
            Property::AbuseBanRate => "abuseBanRate",
            Property::AccessKey => "accessKey",
            Property::AccessKeyId => "accessKeyId",
            Property::AccessToken => "accessToken",
            Property::AccessTokenExpiry => "accessTokenExpiry",
            Property::AccessTokens => "accessTokens",
            Property::AccountDomainId => "accountDomainId",
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
            Property::AddMessageIdHeader => "addMessageIdHeader",
            Property::AddReceivedHeader => "addReceivedHeader",
            Property::AddReceivedSpfHeader => "addReceivedSpfHeader",
            Property::AddReturnPathHeader => "addReturnPathHeader",
            Property::AdditionalInformation => "additionalInformation",
            Property::Address => "address",
            Property::Addresses => "addresses",
            Property::AggregateContactInfo => "aggregateContactInfo",
            Property::AggregateDkimSignDomain => "aggregateDkimSignDomain",
            Property::AggregateFromAddress => "aggregateFromAddress",
            Property::AggregateFromName => "aggregateFromName",
            Property::AggregateMaxReportSize => "aggregateMaxReportSize",
            Property::AggregateOrgName => "aggregateOrgName",
            Property::AggregateSendFrequency => "aggregateSendFrequency",
            Property::AggregateSubject => "aggregateSubject",
            Property::AlarmId => "alarmId",
            Property::Algorithms => "algorithms",
            Property::Aliases => "aliases",
            Property::AllowCount => "allowCount",
            Property::AllowDirectoryQueries => "allowDirectoryQueries",
            Property::AllowExternalRcpts => "allowExternalRcpts",
            Property::AllowInvalidCerts => "allowInvalidCerts",
            Property::AllowPlainTextAuth => "allowPlainTextAuth",
            Property::AllowRelaying => "allowRelaying",
            Property::AllowSpamTraining => "allowSpamTraining",
            Property::AllowedEndpoints => "allowedEndpoints",
            Property::AllowedIps => "allowedIps",
            Property::AllowedNotifyUris => "allowedNotifyUris",
            Property::Alpha => "alpha",
            Property::AnonymousClientRegistration => "anonymousClientRegistration",
            Property::Ansi => "ansi",
            Property::ApiKey => "apiKey",
            Property::ApiUser => "apiUser",
            Property::ApplicationKey => "applicationKey",
            Property::ApplicationSecret => "applicationSecret",
            Property::ArcResult => "arcResult",
            Property::ArcVerify => "arcVerify",
            Property::ArchiveDeletedAccountsFor => "archiveDeletedAccountsFor",
            Property::ArchiveDeletedItemsFor => "archiveDeletedItemsFor",
            Property::ArchivedAt => "archivedAt",
            Property::ArchivedItemType => "archivedItemType",
            Property::ArchivedUntil => "archivedUntil",
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
            Property::AuthCodeMaxAttempts => "authCodeMaxAttempts",
            Property::AuthFailure => "authFailure",
            Property::AuthId => "authId",
            Property::AuthSecret => "authSecret",
            Property::AuthToken => "authToken",
            Property::AuthUsername => "authUsername",
            Property::AuthenticatedAs => "authenticatedAs",
            Property::AuthenticationResults => "authenticationResults",
            Property::AutoAddInvitations => "autoAddInvitations",
            Property::AutoUpdateFrequency => "autoUpdateFrequency",
            Property::BaseDn => "baseDn",
            Property::BaseUrl => "baseUrl",
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
            Property::Body => "body",
            Property::Brokers => "brokers",
            Property::Bucket => "bucket",
            Property::BufferSize => "bufferSize",
            Property::Buffered => "buffered",
            Property::Canonicalization => "canonicalization",
            Property::CapacityClient => "capacityClient",
            Property::CapacityReadBuffer => "capacityReadBuffer",
            Property::CapacitySubscription => "capacitySubscription",
            Property::CatchAllAddress => "catchAllAddress",
            Property::Categories => "categories",
            Property::Certificate => "certificate",
            Property::CertificateManagement => "certificateManagement",
            Property::ChallengeType => "challengeType",
            Property::ChangesMaxResults => "changesMaxResults",
            Property::Chunking => "chunking",
            Property::ClaimGroups => "claimGroups",
            Property::ClaimName => "claimName",
            Property::ClaimUsername => "claimUsername",
            Property::Cleartext => "cleartext",
            Property::ClientId => "clientId",
            Property::ClientIp => "clientIp",
            Property::ClientSecret => "clientSecret",
            Property::ClientToken => "clientToken",
            Property::ClusterFile => "clusterFile",
            Property::ColumnClass => "columnClass",
            Property::ColumnDescription => "columnDescription",
            Property::ColumnEmail => "columnEmail",
            Property::ColumnSecret => "columnSecret",
            Property::Comment => "comment",
            Property::CompartmentOcid => "compartmentOcid",
            Property::CompressionAlgorithm => "compressionAlgorithm",
            Property::Concurrency => "concurrency",
            Property::Condition => "condition",
            Property::Confidence => "confidence",
            Property::Config => "config",
            Property::ConfigName => "configName",
            Property::ConnectTimeout => "connectTimeout",
            Property::Connection => "connection",
            Property::ConsumerKey => "consumerKey",
            Property::Contact => "contact",
            Property::ContactInfo => "contactInfo",
            Property::Contacts => "contacts",
            Property::Container => "container",
            Property::Content => "content",
            Property::ContentTypes => "contentTypes",
            Property::Contents => "contents",
            Property::Context => "context",
            Property::Count => "count",
            Property::Create => "create",
            Property::CreatedAt => "createdAt",
            Property::CreatedBy => "createdBy",
            Property::CredentialId => "credentialId",
            Property::Credentials => "credentials",
            Property::CurrentSecret => "currentSecret",
            Property::CustomEndpoint => "customEndpoint",
            Property::CustomRegion => "customRegion",
            Property::CustomRule => "customRule",
            Property::CustomerNumber => "customerNumber",
            Property::Dane => "dane",
            Property::DataCleanupSchedule => "dataCleanupSchedule",
            Property::DataStore => "dataStore",
            Property::DataTimeout => "dataTimeout",
            Property::Database => "database",
            Property::DatacenterId => "datacenterId",
            Property::DateRangeBegin => "dateRangeBegin",
            Property::DateRangeEnd => "dateRangeEnd",
            Property::DateRangeStart => "dateRangeStart",
            Property::Day => "day",
            Property::DeadPropertyMaxSize => "deadPropertyMaxSize",
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
            Property::DefaultTenantRoleIds => "defaultTenantRoleIds",
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
            Property::DnsRbl => "dnsRbl",
            Property::DnsServer => "dnsServer",
            Property::DnsServerId => "dnsServerId",
            Property::DnsTlsa => "dnsTlsa",
            Property::DnsTxt => "dnsTxt",
            Property::DnsView => "dnsView",
            Property::DnsZoneFile => "dnsZoneFile",
            Property::DocumentId => "documentId",
            Property::DocumentType => "documentType",
            Property::Domain => "domain",
            Property::DomainId => "domainId",
            Property::DomainLimit => "domainLimit",
            Property::DomainNames => "domainNames",
            Property::DomainNamesNegative => "domainNamesNegative",
            Property::Domains => "domains",
            Property::Dsn => "dsn",
            Property::Due => "due",
            Property::DuplicateExpiry => "duplicateExpiry",
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
            Property::EmailAlert => "emailAlert",
            Property::EmailDomain => "emailDomain",
            Property::EmailLimit => "emailLimit",
            Property::EmailPrefix => "emailPrefix",
            Property::EmailTemplate => "emailTemplate",
            Property::Enable => "enable",
            Property::EnableAssistedDiscovery => "enableAssistedDiscovery",
            Property::EnableEdns => "enableEdns",
            Property::EnableHsts => "enableHsts",
            Property::EnableLogExporter => "enableLogExporter",
            Property::EnableSpamFilter => "enableSpamFilter",
            Property::EnableSpanExporter => "enableSpanExporter",
            Property::Enabled => "enabled",
            Property::EnabledPermissions => "enabledPermissions",
            Property::EncryptAtRest => "encryptAtRest",
            Property::EncryptOnAppend => "encryptOnAppend",
            Property::EncryptionAtRest => "encryptionAtRest",
            Property::EncryptionKey => "encryptionKey",
            Property::Endpoint => "endpoint",
            Property::EnvFrom => "envFrom",
            Property::EnvFromParameters => "envFromParameters",
            Property::EnvId => "envId",
            Property::EnvRcptTo => "envRcptTo",
            Property::EnvelopeFrom => "envelopeFrom",
            Property::EnvelopeTo => "envelopeTo",
            Property::Environment => "environment",
            Property::ErrorCommand => "errorCommand",
            Property::ErrorMessage => "errorMessage",
            Property::ErrorType => "errorType",
            Property::Errors => "errors",
            Property::EvaluatedDisposition => "evaluatedDisposition",
            Property::EvaluatedDkim => "evaluatedDkim",
            Property::EvaluatedSpf => "evaluatedSpf",
            Property::Event => "event",
            Property::EventAlert => "eventAlert",
            Property::EventEnd => "eventEnd",
            Property::EventEndTz => "eventEndTz",
            Property::EventId => "eventId",
            Property::EventMessage => "eventMessage",
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
            Property::Expn => "expn",
            Property::ExpungeSchedule => "expungeSchedule",
            Property::ExpungeSchedulingInboxAfter => "expungeSchedulingInboxAfter",
            Property::ExpungeShareNotifyAfter => "expungeShareNotifyAfter",
            Property::ExpungeSubmissionsAfter => "expungeSubmissionsAfter",
            Property::ExpungeTrashAfter => "expungeTrashAfter",
            Property::Extension => "extension",
            Property::Extensions => "extensions",
            Property::ExtraContactInfo => "extraContactInfo",
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
            Property::FilterMailbox => "filterMailbox",
            Property::FilterMemberOf => "filterMemberOf",
            Property::Fingerprint => "fingerprint",
            Property::Flags => "flags",
            Property::FlagsAction => "flagsAction",
            Property::FlagsProtocol => "flagsProtocol",
            Property::FolderId => "folderId",
            Property::ForDomain => "forDomain",
            Property::Format => "format",
            Property::From => "from",
            Property::FromAddress => "fromAddress",
            Property::FromEmail => "fromEmail",
            Property::FromName => "fromName",
            Property::FutureRelease => "futureRelease",
            Property::GenerateDkimKeys => "generateDkimKeys",
            Property::Generator => "generator",
            Property::GeoUrls => "geoUrls",
            Property::GetMaxResults => "getMaxResults",
            Property::GreetingTimeout => "greetingTimeout",
            Property::GreylistFor => "greylistFor",
            Property::GroupClass => "groupClass",
            Property::GroupId => "groupId",
            Property::HeaderFrom => "headerFrom",
            Property::Headers => "headers",
            Property::HoldMetricsFor => "holdMetricsFor",
            Property::HoldMtaReportsFor => "holdMtaReportsFor",
            Property::HoldSamplesFor => "holdSamplesFor",
            Property::HoldTracesFor => "holdTracesFor",
            Property::Host => "host",
            Property::HostedZoneId => "hostedZoneId",
            Property::Hostname => "hostname",
            Property::Hour => "hour",
            Property::HttpAuth => "httpAuth",
            Property::HttpHeaders => "httpHeaders",
            Property::HttpRsvpEnable => "httpRsvpEnable",
            Property::HttpRsvpLinkExpiry => "httpRsvpLinkExpiry",
            Property::HttpRsvpTemplate => "httpRsvpTemplate",
            Property::HttpRsvpUrl => "httpRsvpUrl",
            Property::HttpRua => "httpRua",
            Property::HumanResult => "humanResult",
            Property::ICalendarData => "iCalendarData",
            Property::Id => "id",
            Property::IdTokenExpiry => "idTokenExpiry",
            Property::IdentityAlignment => "identityAlignment",
            Property::If => "if",
            Property::ImpersonateServiceAccount => "impersonateServiceAccount",
            Property::ImplicitTls => "implicitTls",
            Property::InMemoryStore => "inMemoryStore",
            Property::InboundReportAddresses => "inboundReportAddresses",
            Property::InboundReportForwarding => "inboundReportForwarding",
            Property::Incidents => "incidents",
            Property::IncludeSource => "includeSource",
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
            Property::IndexKey => "indexKey",
            Property::IndexTelemetry => "indexTelemetry",
            Property::IndexTracingFields => "indexTracingFields",
            Property::IndexValue => "indexValue",
            Property::IndicatorParameters => "indicatorParameters",
            Property::InitialDelay => "initialDelay",
            Property::Interval => "interval",
            Property::Intervals => "intervals",
            Property::IpLimit => "ipLimit",
            Property::IpLookupStrategy => "ipLookupStrategy",
            Property::IpRevPtr => "ipRevPtr",
            Property::IpRevResult => "ipRevResult",
            Property::IsActive => "isActive",
            Property::IsArchive => "isArchive",
            Property::IsBad => "isBad",
            Property::IsEnabled => "isEnabled",
            Property::IsFromOrganizer => "isFromOrganizer",
            Property::IsGlobPattern => "isGlobPattern",
            Property::IsGzipped => "isGzipped",
            Property::IsNz => "isNz",
            Property::IsSenderAllowed => "isSenderAllowed",
            Property::IsSpam => "isSpam",
            Property::IsTls => "isTls",
            Property::Issuer => "issuer",
            Property::IssuerUrl => "issuerUrl",
            Property::ItipMaxSize => "itipMaxSize",
            Property::Jitter => "jitter",
            Property::Key => "key",
            Property::KeyName => "keyName",
            Property::KeyPrefix => "keyPrefix",
            Property::KeyValues => "keyValues",
            Property::L1Ratio => "l1Ratio",
            Property::L2Ratio => "l2Ratio",
            Property::LastRenewal => "lastRenewal",
            Property::LearnHamFromCard => "learnHamFromCard",
            Property::LearnHamFromReply => "learnHamFromReply",
            Property::LearnSpamFromRblHits => "learnSpamFromRblHits",
            Property::LearnSpamFromTraps => "learnSpamFromTraps",
            Property::Level => "level",
            Property::LicenseKey => "licenseKey",
            Property::Line => "line",
            Property::ListenerIds => "listenerIds",
            Property::Listeners => "listeners",
            Property::LivePropertyMaxSize => "livePropertyMaxSize",
            Property::Locale => "locale",
            Property::Logo => "logo",
            Property::LogoUrl => "logoUrl",
            Property::LoiterBanPeriod => "loiterBanPeriod",
            Property::LoiterBanRate => "loiterBanRate",
            Property::Lossy => "lossy",
            Property::MachineId => "machineId",
            Property::MailExchangers => "mailExchangers",
            Property::MailFrom => "mailFrom",
            Property::MailFromTimeout => "mailFromTimeout",
            Property::MailRua => "mailRua",
            Property::MailingLists => "mailingLists",
            Property::MaintenanceType => "maintenanceType",
            Property::ManagedZone => "managedZone",
            Property::Match => "match",
            Property::MaxAddressBooks => "maxAddressBooks",
            Property::MaxAge => "maxAge",
            Property::MaxAllowedPacket => "maxAllowedPacket",
            Property::MaxApiKeys => "maxApiKeys",
            Property::MaxAppPasswords => "maxAppPasswords",
            Property::MaxAttachmentSize => "maxAttachmentSize",
            Property::MaxAttempts => "maxAttempts",
            Property::MaxAttendees => "maxAttendees",
            Property::MaxAuthFailures => "maxAuthFailures",
            Property::MaxCalendars => "maxCalendars",
            Property::MaxChangesHistory => "maxChangesHistory",
            Property::MaxConcurrent => "maxConcurrent",
            Property::MaxConcurrentRequests => "maxConcurrentRequests",
            Property::MaxConcurrentUploads => "maxConcurrentUploads",
            Property::MaxConnections => "maxConnections",
            Property::MaxContacts => "maxContacts",
            Property::MaxCpuCycles => "maxCpuCycles",
            Property::MaxDelay => "maxDelay",
            Property::MaxDuration => "maxDuration",
            Property::MaxEntries => "maxEntries",
            Property::MaxEntrySize => "maxEntrySize",
            Property::MaxEventNotifications => "maxEventNotifications",
            Property::MaxEvents => "maxEvents",
            Property::MaxFailures => "maxFailures",
            Property::MaxFiles => "maxFiles",
            Property::MaxFolders => "maxFolders",
            Property::MaxHeaderSize => "maxHeaderSize",
            Property::MaxICalendarSize => "maxICalendarSize",
            Property::MaxIdentities => "maxIdentities",
            Property::MaxIncludes => "maxIncludes",
            Property::MaxLocalVars => "maxLocalVars",
            Property::MaxLockTimeout => "maxLockTimeout",
            Property::MaxLocks => "maxLocks",
            Property::MaxMailboxDepth => "maxMailboxDepth",
            Property::MaxMailboxNameLength => "maxMailboxNameLength",
            Property::MaxMailboxes => "maxMailboxes",
            Property::MaxMaskedAddresses => "maxMaskedAddresses",
            Property::MaxMatchVars => "maxMatchVars",
            Property::MaxMessageSize => "maxMessageSize",
            Property::MaxMessages => "maxMessages",
            Property::MaxMethodCalls => "maxMethodCalls",
            Property::MaxMultihomed => "maxMultihomed",
            Property::MaxMxHosts => "maxMxHosts",
            Property::MaxNestedBlocks => "maxNestedBlocks",
            Property::MaxNestedForEvery => "maxNestedForEvery",
            Property::MaxNestedIncludes => "maxNestedIncludes",
            Property::MaxNestedTests => "maxNestedTests",
            Property::MaxOutMessages => "maxOutMessages",
            Property::MaxParticipantIdentities => "maxParticipantIdentities",
            Property::MaxPublicKeys => "maxPublicKeys",
            Property::MaxReceivedHeaders => "maxReceivedHeaders",
            Property::MaxRecipients => "maxRecipients",
            Property::MaxReconnects => "maxReconnects",
            Property::MaxRecurrenceExpansions => "maxRecurrenceExpansions",
            Property::MaxRedirects => "maxRedirects",
            Property::MaxReportSize => "maxReportSize",
            Property::MaxRequestRate => "maxRequestRate",
            Property::MaxRequestSize => "maxRequestSize",
            Property::MaxResponseSize => "maxResponseSize",
            Property::MaxResults => "maxResults",
            Property::MaxRetries => "maxRetries",
            Property::MaxRetryWait => "maxRetryWait",
            Property::MaxScriptNameLength => "maxScriptNameLength",
            Property::MaxScriptSize => "maxScriptSize",
            Property::MaxScripts => "maxScripts",
            Property::MaxShares => "maxShares",
            Property::MaxSize => "maxSize",
            Property::MaxStringLength => "maxStringLength",
            Property::MaxSubmissions => "maxSubmissions",
            Property::MaxSubscriptions => "maxSubscriptions",
            Property::MaxUploadCount => "maxUploadCount",
            Property::MaxUploadSize => "maxUploadSize",
            Property::MaxVCardSize => "maxVCardSize",
            Property::MaxVarNameLength => "maxVarNameLength",
            Property::MaxVarSize => "maxVarSize",
            Property::MemberGroupIds => "memberGroupIds",
            Property::MemberTenantId => "memberTenantId",
            Property::Message => "message",
            Property::MessageIdHostname => "messageIdHostname",
            Property::MessageIds => "messageIds",
            Property::Messages => "messages",
            Property::Metric => "metric",
            Property::Metrics => "metrics",
            Property::MetricsCollectionInterval => "metricsCollectionInterval",
            Property::MetricsPolicy => "metricsPolicy",
            Property::MinHamSamples => "minHamSamples",
            Property::MinRetryWait => "minRetryWait",
            Property::MinSpamSamples => "minSpamSamples",
            Property::MinTriggerInterval => "minTriggerInterval",
            Property::Minute => "minute",
            Property::Mode => "mode",
            Property::Model => "model",
            Property::ModelId => "modelId",
            Property::ModelType => "modelType",
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
            Property::OnSuccessRenewCertificate => "onSuccessRenewCertificate",
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
            Property::Password => "password",
            Property::PasswordDefaultExpiry => "passwordDefaultExpiry",
            Property::PasswordHashAlgorithm => "passwordHashAlgorithm",
            Property::PasswordMaxLength => "passwordMaxLength",
            Property::PasswordMinLength => "passwordMinLength",
            Property::PasswordMinStrength => "passwordMinStrength",
            Property::Path => "path",
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
            Property::PollingInterval => "pollingInterval",
            Property::PoolMaxConnections => "poolMaxConnections",
            Property::PoolMinConnections => "poolMinConnections",
            Property::PoolRecyclingMethod => "poolRecyclingMethod",
            Property::PoolTimeoutCreate => "poolTimeoutCreate",
            Property::PoolTimeoutRecycle => "poolTimeoutRecycle",
            Property::PoolTimeoutWait => "poolTimeoutWait",
            Property::PoolWorkers => "poolWorkers",
            Property::Port => "port",
            Property::PreferredChain => "preferredChain",
            Property::Prefix => "prefix",
            Property::PreserveIntermediates => "preserveIntermediates",
            Property::Priority => "priority",
            Property::PrivateKey => "privateKey",
            Property::PrivateKeyPassword => "privateKeyPassword",
            Property::PrivateKeyPem => "privateKeyPem",
            Property::PrivateZone => "privateZone",
            Property::PrivateZoneOnly => "privateZoneOnly",
            Property::Profile => "profile",
            Property::ProjectId => "projectId",
            Property::Prometheus => "prometheus",
            Property::Prompt => "prompt",
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
            Property::PushMaxAttempts => "pushMaxAttempts",
            Property::PushRequestTimeout => "pushRequestTimeout",
            Property::PushRetryWait => "pushRetryWait",
            Property::PushShardsTotal => "pushShardsTotal",
            Property::PushThrottle => "pushThrottle",
            Property::PushVerifyTimeout => "pushVerifyTimeout",
            Property::QueryEmailAliases => "queryEmailAliases",
            Property::QueryLogin => "queryLogin",
            Property::QueryMaxResults => "queryMaxResults",
            Property::QueryMemberOf => "queryMemberOf",
            Property::QueryRecipient => "queryRecipient",
            Property::QueueId => "queueId",
            Property::QueueName => "queueName",
            Property::Quotas => "quotas",
            Property::Rate => "rate",
            Property::RateLimit => "rateLimit",
            Property::RateLimitAnonymous => "rateLimitAnonymous",
            Property::RateLimitAuthenticated => "rateLimitAuthenticated",
            Property::Ratio => "ratio",
            Property::RcptToTimeout => "rcptToTimeout",
            Property::ReadFromReplicas => "readFromReplicas",
            Property::ReadReplicas => "readReplicas",
            Property::Reason => "reason",
            Property::ReceivedAt => "receivedAt",
            Property::ReceivedFromIp => "receivedFromIp",
            Property::ReceivedViaPort => "receivedViaPort",
            Property::ReceivingIp => "receivingIp",
            Property::ReceivingMxHelo => "receivingMxHelo",
            Property::ReceivingMxHostname => "receivingMxHostname",
            Property::Recipients => "recipients",
            Property::Records => "records",
            Property::RecurrenceId => "recurrenceId",
            Property::RedirectRoot => "redirectRoot",
            Property::RedirectUris => "redirectUris",
            Property::Refresh => "refresh",
            Property::RefreshTokenExpiry => "refreshTokenExpiry",
            Property::RefreshTokenRenewal => "refreshTokenRenewal",
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
            Property::RequestMaxSize => "requestMaxSize",
            Property::RequestTlsCertificate => "requestTlsCertificate",
            Property::Require => "require",
            Property::RequireAudience => "requireAudience",
            Property::RequireClientRegistration => "requireClientRegistration",
            Property::RequireScopes => "requireScopes",
            Property::RequireTls => "requireTls",
            Property::ReservoirCapacity => "reservoirCapacity",
            Property::ResourceGroup => "resourceGroup",
            Property::ResourceUrl => "resourceUrl",
            Property::ResponseCode => "responseCode",
            Property::ResponseEnhanced => "responseEnhanced",
            Property::ResponseHeaders => "responseHeaders",
            Property::ResponseHostname => "responseHostname",
            Property::ResponseMessage => "responseMessage",
            Property::ResponsePosCategory => "responsePosCategory",
            Property::ResponsePosConfidence => "responsePosConfidence",
            Property::ResponsePosExplanation => "responsePosExplanation",
            Property::Result => "result",
            Property::ResultType => "resultType",
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
            Property::Score => "score",
            Property::ScoreDiscard => "scoreDiscard",
            Property::ScoreReject => "scoreReject",
            Property::ScoreSpam => "scoreSpam",
            Property::Script => "script",
            Property::SearchStore => "searchStore",
            Property::Secret => "secret",
            Property::SecretAccessKey => "secretAccessKey",
            Property::SecretApiKey => "secretApiKey",
            Property::SecretId => "secretId",
            Property::SecretKey => "secretKey",
            Property::SecurityToken => "securityToken",
            Property::Selector => "selector",
            Property::SelectorTemplate => "selectorTemplate",
            Property::SendFrequency => "sendFrequency",
            Property::SendingMtaIp => "sendingMtaIp",
            Property::SentinelSecret => "sentinelSecret",
            Property::SentinelUsername => "sentinelUsername",
            Property::Separator => "separator",
            Property::ServerHostname => "serverHostname",
            Property::Servers => "servers",
            Property::ServiceAccountJson => "serviceAccountJson",
            Property::ServiceName => "serviceName",
            Property::Services => "services",
            Property::SessionToken => "sessionToken",
            Property::SetMaxObjects => "setMaxObjects",
            Property::ShardIndex => "shardIndex",
            Property::SharedSecret => "sharedSecret",
            Property::Sig0Algorithm => "sig0Algorithm",
            Property::SignatureAlgorithm => "signatureAlgorithm",
            Property::SignatureKey => "signatureKey",
            Property::SignerName => "signerName",
            Property::Size => "size",
            Property::SkipDeploy => "skipDeploy",
            Property::SkipFirst => "skipFirst",
            Property::SmtpGreeting => "smtpGreeting",
            Property::SnippetMaxResults => "snippetMaxResults",
            Property::SocketBacklog => "socketBacklog",
            Property::SocketNoDelay => "socketNoDelay",
            Property::SocketReceiveBufferSize => "socketReceiveBufferSize",
            Property::SocketReuseAddress => "socketReuseAddress",
            Property::SocketReusePort => "socketReusePort",
            Property::SocketSendBufferSize => "socketSendBufferSize",
            Property::SocketTosV4 => "socketTosV4",
            Property::SocketTtl => "socketTtl",
            Property::SourceIp => "sourceIp",
            Property::SourceIps => "sourceIps",
            Property::SourcePort => "sourcePort",
            Property::SpamFilterRulesUrl => "spamFilterRulesUrl",
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
            Property::StartTime => "startTime",
            Property::StartTls => "startTls",
            Property::Status => "status",
            Property::StorageAccount => "storageAccount",
            Property::Store => "store",
            Property::Stores => "stores",
            Property::Strategy => "strategy",
            Property::SubAddressing => "subAddressing",
            Property::SubAuthId => "subAuthId",
            Property::Subject => "subject",
            Property::SubjectAlternativeNames => "subjectAlternativeNames",
            Property::Subscribe => "subscribe",
            Property::SubscriptionId => "subscriptionId",
            Property::Sum => "sum",
            Property::Summary => "summary",
            Property::SupportedLanguages => "supportedLanguages",
            Property::Tag => "tag",
            Property::Tags => "tags",
            Property::TaskTypes => "taskTypes",
            Property::Tasks => "tasks",
            Property::TcpOnError => "tcpOnError",
            Property::TeamId => "teamId",
            Property::TempFailOnError => "tempFailOnError",
            Property::Temperature => "temperature",
            Property::Template => "template",
            Property::TenancyOcid => "tenancyOcid",
            Property::TenantId => "tenantId",
            Property::Tenants => "tenants",
            Property::Text => "text",
            Property::Then => "then",
            Property::ThirdParty => "thirdParty",
            Property::ThirdPartyHash => "thirdPartyHash",
            Property::ThreadName => "threadName",
            Property::ThreadPoolSize => "threadPoolSize",
            Property::ThreadsPerNode => "threadsPerNode",
            Property::Throttle => "throttle",
            Property::TimeZone => "timeZone",
            Property::Timeout => "timeout",
            Property::TimeoutAnonymous => "timeoutAnonymous",
            Property::TimeoutAuthenticated => "timeoutAuthenticated",
            Property::TimeoutCommand => "timeoutCommand",
            Property::TimeoutConnect => "timeoutConnect",
            Property::TimeoutConnection => "timeoutConnection",
            Property::TimeoutData => "timeoutData",
            Property::TimeoutIdle => "timeoutIdle",
            Property::TimeoutMessage => "timeoutMessage",
            Property::TimeoutRequest => "timeoutRequest",
            Property::TimeoutSession => "timeoutSession",
            Property::Timestamp => "timestamp",
            Property::Title => "title",
            Property::Tls => "tls",
            Property::TlsDisableCipherSuites => "tlsDisableCipherSuites",
            Property::TlsDisableProtocols => "tlsDisableProtocols",
            Property::TlsIgnoreClientOrder => "tlsIgnoreClientOrder",
            Property::TlsImplicit => "tlsImplicit",
            Property::TlsTimeout => "tlsTimeout",
            Property::To => "to",
            Property::Token => "token",
            Property::TotalDeadline => "totalDeadline",
            Property::TotalFailedSessions => "totalFailedSessions",
            Property::TotalSuccessfulSessions => "totalSuccessfulSessions",
            Property::TraceId => "traceId",
            Property::Tracer => "tracer",
            Property::TrainFrequency => "trainFrequency",
            Property::TransactionRetryDelay => "transactionRetryDelay",
            Property::TransactionRetryLimit => "transactionRetryLimit",
            Property::TransactionTimeout => "transactionTimeout",
            Property::TransferLimit => "transferLimit",
            Property::TrustContacts => "trustContacts",
            Property::TrustReplies => "trustReplies",
            Property::TsigAlgorithm => "tsigAlgorithm",
            Property::Ttl => "ttl",
            Property::UnpackDirectory => "unpackDirectory",
            Property::UpdateRecords => "updateRecords",
            Property::UploadQuota => "uploadQuota",
            Property::UploadTtl => "uploadTtl",
            Property::Url => "url",
            Property::UrlLimit => "urlLimit",
            Property::UrlPrefix => "urlPrefix",
            Property::Urls => "urls",
            Property::UsePermissiveCors => "usePermissiveCors",
            Property::UseTls => "useTls",
            Property::UseXForwarded => "useXForwarded",
            Property::UsedDiskQuota => "usedDiskQuota",
            Property::UserAgent => "userAgent",
            Property::UserCodeExpiry => "userCodeExpiry",
            Property::UserOcid => "userOcid",
            Property::Username => "username",
            Property::UsernameDomain => "usernameDomain",
            Property::ValidateDomain => "validateDomain",
            Property::Value => "value",
            Property::VariableName => "variableName",
            Property::VerifyAfterWrite => "verifyAfterWrite",
            Property::Version => "version",
            Property::ViewName => "viewName",
            Property::Vrfy => "vrfy",
            Property::WaitOnFail => "waitOnFail",
            Property::WapiVersion => "wapiVersion",
            Property::WebPushContact => "webPushContact",
            Property::WebPushKey => "webPushKey",
            Property::WebsocketHeartbeat => "websocketHeartbeat",
            Property::WebsocketThrottle => "websocketThrottle",
            Property::WebsocketTimeout => "websocketTimeout",
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
            678 => Some(Property::AbuseBanPeriod),
            677 => Some(Property::AbuseBanRate),
            118 => Some(Property::AccessKey),
            327 => Some(Property::AccessKeyId),
            890 => Some(Property::AccessToken),
            619 => Some(Property::AccessTokenExpiry),
            132 => Some(Property::AccessTokens),
            810 => Some(Property::AccountDomainId),
            57 => Some(Property::AccountId),
            315 => Some(Property::AccountIdentifier),
            15 => Some(Property::AccountKey),
            809 => Some(Property::AccountName),
            891 => Some(Property::AccountSwitchKey),
            811 => Some(Property::AccountType),
            16 => Some(Property::AccountUri),
            151 => Some(Property::Accounts),
            182 => Some(Property::AcmeProviderId),
            554 => Some(Property::AddAuthResultsHeader),
            555 => Some(Property::AddDateHeader),
            556 => Some(Property::AddDeliveredToHeader),
            557 => Some(Property::AddMessageIdHeader),
            558 => Some(Property::AddReceivedHeader),
            559 => Some(Property::AddReceivedSpfHeader),
            560 => Some(Property::AddReturnPathHeader),
            838 => Some(Property::AdditionalInformation),
            44 => Some(Property::Address),
            579 => Some(Property::Addresses),
            268 => Some(Property::AggregateContactInfo),
            274 => Some(Property::AggregateDkimSignDomain),
            269 => Some(Property::AggregateFromAddress),
            270 => Some(Property::AggregateFromName),
            271 => Some(Property::AggregateMaxReportSize),
            272 => Some(Property::AggregateOrgName),
            273 => Some(Property::AggregateSendFrequency),
            275 => Some(Property::AggregateSubject),
            798 => Some(Property::AlarmId),
            225 => Some(Property::Algorithms),
            339 => Some(Property::Aliases),
            768 => Some(Property::AllowCount),
            695 => Some(Property::AllowDirectoryQueries),
            164 => Some(Property::AllowExternalRcpts),
            26 => Some(Property::AllowInvalidCerts),
            424 => Some(Property::AllowPlainTextAuth),
            348 => Some(Property::AllowRelaying),
            369 => Some(Property::AllowSpamTraining),
            398 => Some(Property::AllowedEndpoints),
            49 => Some(Property::AllowedIps),
            712 => Some(Property::AllowedNotifyUris),
            388 => Some(Property::Alpha),
            614 => Some(Property::AnonymousClientRegistration),
            858 => Some(Property::Ansi),
            325 => Some(Property::ApiKey),
            892 => Some(Property::ApiUser),
            321 => Some(Property::ApplicationKey),
            322 => Some(Property::ApplicationSecret),
            292 => Some(Property::ArcResult),
            690 => Some(Property::ArcVerify),
            203 => Some(Property::ArchiveDeletedAccountsFor),
            202 => Some(Property::ArchiveDeletedItemsFor),
            58 => Some(Property::ArchivedAt),
            820 => Some(Property::ArchivedItemType),
            59 => Some(Property::ArchivedUntil),
            68 => Some(Property::ArrivalDate),
            102 => Some(Property::AsnUrls),
            829 => Some(Property::AttemptNumber),
            303 => Some(Property::Attempts),
            470 => Some(Property::AttrClass),
            471 => Some(Property::AttrDescription),
            472 => Some(Property::AttrEmail),
            473 => Some(Property::AttrEmailAlias),
            474 => Some(Property::AttrMemberOf),
            475 => Some(Property::AttrSecret),
            476 => Some(Property::AttrSecretChanged),
            215 => Some(Property::Auid),
            897 => Some(Property::Auth),
            680 => Some(Property::AuthBanPeriod),
            679 => Some(Property::AuthBanRate),
            616 => Some(Property::AuthCodeExpiry),
            613 => Some(Property::AuthCodeMaxAttempts),
            81 => Some(Property::AuthFailure),
            886 => Some(Property::AuthId),
            501 => Some(Property::AuthSecret),
            314 => Some(Property::AuthToken),
            502 => Some(Property::AuthUsername),
            740 => Some(Property::AuthenticatedAs),
            69 => Some(Property::AuthenticationResults),
            171 => Some(Property::AutoAddInvitations),
            53 => Some(Property::AutoUpdateFrequency),
            463 => Some(Property::BaseDn),
            882 => Some(Property::BaseUrl),
            403 => Some(Property::BearerToken),
            389 => Some(Property::Beta),
            589 => Some(Property::Bind),
            466 => Some(Property::BindAuthentication),
            464 => Some(Property::BindDn),
            465 => Some(Property::BindSecret),
            200 => Some(Property::BlobCleanupSchedule),
            60 => Some(Property::BlobId),
            655 => Some(Property::BlobSize),
            126 => Some(Property::BlobStore),
            766 => Some(Property::BlockCount),
            38 => Some(Property::Body),
            459 => Some(Property::Brokers),
            658 => Some(Property::Bucket),
            656 => Some(Property::BufferSize),
            863 => Some(Property::Buffered),
            216 => Some(Property::Canonicalization),
            584 => Some(Property::CapacityClient),
            585 => Some(Property::CapacityReadBuffer),
            586 => Some(Property::CapacitySubscription),
            346 => Some(Property::CatchAllAddress),
            759 => Some(Property::Categories),
            176 => Some(Property::Certificate),
            342 => Some(Property::CertificateManagement),
            10 => Some(Property::ChallengeType),
            435 => Some(Property::ChangesMaxResults),
            517 => Some(Property::Chunking),
            612 => Some(Property::ClaimGroups),
            611 => Some(Property::ClaimName),
            609 => Some(Property::ClaimUsername),
            693 => Some(Property::Cleartext),
            604 => Some(Property::ClientId),
            898 => Some(Property::ClientIp),
            878 => Some(Property::ClientSecret),
            889 => Some(Property::ClientToken),
            382 => Some(Property::ClusterFile),
            781 => Some(Property::ColumnClass),
            782 => Some(Property::ColumnDescription),
            779 => Some(Property::ColumnEmail),
            780 => Some(Property::ColumnSecret),
            240 => Some(Property::Comment),
            905 => Some(Property::CompartmentOcid),
            359 => Some(Property::CompressionAlgorithm),
            304 => Some(Property::Concurrency),
            34 => Some(Property::Condition),
            760 => Some(Property::Confidence),
            873 => Some(Property::Config),
            883 => Some(Property::ConfigName),
            505 => Some(Property::ConnectTimeout),
            539 => Some(Property::Connection),
            323 => Some(Property::ConsumerKey),
            11 => Some(Property::Contact),
            844 => Some(Property::ContactInfo),
            133 => Some(Property::Contacts),
            117 => Some(Property::Container),
            65 => Some(Property::Content),
            758 => Some(Property::ContentTypes),
            708 => Some(Property::Contents),
            877 => Some(Property::Context),
            258 => Some(Property::Count),
            367 => Some(Property::Create),
            46 => Some(Property::CreatedAt),
            486 => Some(Property::CreatedBy),
            627 => Some(Property::CredentialId),
            588 => Some(Property::Credentials),
            4 => Some(Property::CurrentSecret),
            662 => Some(Property::CustomEndpoint),
            663 => Some(Property::CustomRegion),
            787 => Some(Property::CustomRule),
            899 => Some(Property::CustomerNumber),
            569 => Some(Property::Dane),
            199 => Some(Property::DataCleanupSchedule),
            125 => Some(Property::DataStore),
            506 => Some(Property::DataTimeout),
            575 => Some(Property::Database),
            383 => Some(Property::DatacenterId),
            245 => Some(Property::DateRangeBegin),
            246 => Some(Property::DateRangeEnd),
            845 => Some(Property::DateRangeStart),
            192 => Some(Property::Day),
            868 => Some(Property::DeadPropertyMaxSize),
            108 => Some(Property::DefaultAdminRoleIds),
            790 => Some(Property::DefaultCertificateId),
            20 => Some(Property::DefaultDisplayName),
            122 => Some(Property::DefaultDomain),
            789 => Some(Property::DefaultDomainId),
            709 => Some(Property::DefaultExpiryDuplicate),
            710 => Some(Property::DefaultExpiryVacation),
            360 => Some(Property::DefaultFolders),
            405 => Some(Property::DefaultFromAddress),
            697 => Some(Property::DefaultFromName),
            106 => Some(Property::DefaultGroupRoleIds),
            788 => Some(Property::DefaultHostname),
            21 => Some(Property::DefaultHrefName),
            665 => Some(Property::DefaultLanguage),
            408 => Some(Property::DefaultName),
            701 => Some(Property::DefaultReturnPath),
            411 => Some(Property::DefaultSubject),
            714 => Some(Property::DefaultSubjectPrefix),
            107 => Some(Property::DefaultTenantRoleIds),
            105 => Some(Property::DefaultUserRoleIds),
            235 => Some(Property::Definition),
            825 => Some(Property::Delay),
            229 => Some(Property::DeleteAfter),
            777 => Some(Property::DeleteAfterUse),
            238 => Some(Property::DeliverAt),
            518 => Some(Property::DeliverBy),
            404 => Some(Property::DeliverTo),
            82 => Some(Property::DeliveryResult),
            381 => Some(Property::Depth),
            6 => Some(Property::Description),
            297 => Some(Property::Details),
            12 => Some(Property::Directory),
            104 => Some(Property::DirectoryId),
            711 => Some(Property::DisableCapabilities),
            629 => Some(Property::DisabledPermissions),
            872 => Some(Property::DiscardAfter),
            747 => Some(Property::Disposition),
            917 => Some(Property::Dkim2Pass),
            916 => Some(Property::Dkim2Result),
            83 => Some(Property::DkimAdspDns),
            84 => Some(Property::DkimCanonicalizedBody),
            85 => Some(Property::DkimCanonicalizedHeader),
            86 => Some(Property::DkimDomain),
            87 => Some(Property::DkimIdentity),
            343 => Some(Property::DkimManagement),
            291 => Some(Property::DkimPass),
            266 => Some(Property::DkimResults),
            88 => Some(Property::DkimSelector),
            89 => Some(Property::DkimSelectorDns),
            231 => Some(Property::DkimSignDomain),
            155 => Some(Property::DkimSignatures),
            686 => Some(Property::DkimStrict),
            687 => Some(Property::DkimVerify),
            294 => Some(Property::DmarcPass),
            295 => Some(Property::DmarcPolicy),
            293 => Some(Property::DmarcResult),
            691 => Some(Property::DmarcVerify),
            134 => Some(Property::DnsIpv4),
            135 => Some(Property::DnsIpv6),
            344 => Some(Property::DnsManagement),
            136 => Some(Property::DnsMtaSts),
            137 => Some(Property::DnsMx),
            138 => Some(Property::DnsPtr),
            139 => Some(Property::DnsRbl),
            130 => Some(Property::DnsServer),
            300 => Some(Property::DnsServerId),
            140 => Some(Property::DnsTlsa),
            141 => Some(Property::DnsTxt),
            894 => Some(Property::DnsView),
            345 => Some(Property::DnsZoneFile),
            804 => Some(Property::DocumentId),
            814 => Some(Property::DocumentType),
            232 => Some(Property::Domain),
            221 => Some(Property::DomainId),
            750 => Some(Property::DomainLimit),
            147 => Some(Property::DomainNames),
            148 => Some(Property::DomainNamesNegative),
            146 => Some(Property::Domains),
            519 => Some(Property::Dsn),
            797 => Some(Property::Due),
            699 => Some(Property::DuplicateExpiry),
            515 => Some(Property::Duration),
            13 => Some(Property::EabHmacKey),
            14 => Some(Property::EabKeyId),
            283 => Some(Property::EhloDomain),
            503 => Some(Property::EhloHostname),
            507 => Some(Property::EhloTimeout),
            296 => Some(Property::Elapsed),
            375 => Some(Property::Else),
            242 => Some(Property::Email),
            393 => Some(Property::EmailAddress),
            149 => Some(Property::EmailAddresses),
            150 => Some(Property::EmailAddressesNegative),
            35 => Some(Property::EmailAlert),
            488 => Some(Property::EmailDomain),
            751 => Some(Property::EmailLimit),
            487 => Some(Property::EmailPrefix),
            174 => Some(Property::EmailTemplate),
            37 => Some(Property::Enable),
            865 => Some(Property::EnableAssistedDiscovery),
            305 => Some(Property::EnableEdns),
            399 => Some(Property::EnableHsts),
            860 => Some(Property::EnableLogExporter),
            562 => Some(Property::EnableSpamFilter),
            861 => Some(Property::EnableSpanExporter),
            50 => Some(Property::Enabled),
            628 => Some(Property::EnabledPermissions),
            358 => Some(Property::EncryptAtRest),
            357 => Some(Property::EncryptOnAppend),
            9 => Some(Property::EncryptionAtRest),
            622 => Some(Property::EncryptionKey),
            499 => Some(Property::Endpoint),
            742 => Some(Property::EnvFrom),
            743 => Some(Property::EnvFromParameters),
            639 => Some(Property::EnvId),
            744 => Some(Property::EnvRcptTo),
            264 => Some(Property::EnvelopeFrom),
            263 => Some(Property::EnvelopeTo),
            881 => Some(Property::Environment),
            210 => Some(Property::ErrorCommand),
            209 => Some(Property::ErrorMessage),
            208 => Some(Property::ErrorType),
            247 => Some(Property::Errors),
            259 => Some(Property::EvaluatedDisposition),
            260 => Some(Property::EvaluatedDkim),
            261 => Some(Property::EvaluatedSpf),
            372 => Some(Property::Event),
            36 => Some(Property::EventAlert),
            801 => Some(Property::EventEnd),
            803 => Some(Property::EventEndTz),
            799 => Some(Property::EventId),
            43 => Some(Property::EventMessage),
            447 => Some(Property::EventSourceThrottle),
            800 => Some(Property::EventStart),
            802 => Some(Property::EventStartTz),
            142 => Some(Property::Events),
            855 => Some(Property::EventsPolicy),
            217 => Some(Property::Expire),
            100 => Some(Property::Expires),
            47 => Some(Property::ExpiresAt),
            632 => Some(Property::ExpiresAttempts),
            512 => Some(Property::Expiry),
            520 => Some(Property::Expn),
            198 => Some(Property::ExpungeSchedule),
            197 => Some(Property::ExpungeSchedulingInboxAfter),
            196 => Some(Property::ExpungeShareNotifyAfter),
            195 => Some(Property::ExpungeSubmissionsAfter),
            194 => Some(Property::ExpungeTrashAfter),
            754 => Some(Property::Extension),
            257 => Some(Property::Extensions),
            243 => Some(Property::ExtraContactInfo),
            821 => Some(Property::Factor),
            490 => Some(Property::FailOnTimeout),
            826 => Some(Property::FailedAt),
            827 => Some(Property::FailedAttemptNumber),
            837 => Some(Property::FailedSessionCount),
            851 => Some(Property::FailureDetails),
            279 => Some(Property::FailureDkimSignDomain),
            276 => Some(Property::FailureFromAddress),
            277 => Some(Property::FailureFromName),
            828 => Some(Property::FailureReason),
            839 => Some(Property::FailureReasonCode),
            278 => Some(Property::FailureSendFrequency),
            280 => Some(Property::FailureSubject),
            738 => Some(Property::FeatureL2Normalize),
            739 => Some(Property::FeatureLogScale),
            67 => Some(Property::FeedbackType),
            406 => Some(Property::FieldEmail),
            407 => Some(Property::FieldHoneyPot),
            409 => Some(Property::FieldName),
            412 => Some(Property::FieldSubject),
            676 => Some(Property::FilePath),
            144 => Some(Property::Files),
            467 => Some(Property::FilterLogin),
            468 => Some(Property::FilterMailbox),
            469 => Some(Property::FilterMemberOf),
            902 => Some(Property::Fingerprint),
            638 => Some(Property::Flags),
            537 => Some(Property::FlagsAction),
            538 => Some(Property::FlagsProtocol),
            909 => Some(Property::FolderId),
            485 => Some(Property::ForDomain),
            415 => Some(Property::Format),
            62 => Some(Property::From),
            39 => Some(Property::FromAddress),
            165 => Some(Property::FromEmail),
            40 => Some(Property::FromName),
            521 => Some(Property::FutureRelease),
            124 => Some(Property::GenerateDkimKeys),
            918 => Some(Property::Generator),
            103 => Some(Property::GeoUrls),
            436 => Some(Property::GetMaxResults),
            508 => Some(Property::GreetingTimeout),
            770 => Some(Property::GreylistFor),
            477 => Some(Property::GroupClass),
            460 => Some(Property::GroupId),
            265 => Some(Property::HeaderFrom),
            93 => Some(Property::Headers),
            206 => Some(Property::HoldMetricsFor),
            204 => Some(Property::HoldMtaReportsFor),
            730 => Some(Property::HoldSamplesFor),
            205 => Some(Property::HoldTracesFor),
            333 => Some(Property::Host),
            331 => Some(Property::HostedZoneId),
            185 => Some(Property::Hostname),
            190 => Some(Property::Hour),
            32 => Some(Property::HttpAuth),
            33 => Some(Property::HttpHeaders),
            168 => Some(Property::HttpRsvpEnable),
            169 => Some(Property::HttpRsvpLinkExpiry),
            175 => Some(Property::HttpRsvpTemplate),
            170 => Some(Property::HttpRsvpUrl),
            842 => Some(Property::HttpRua),
            234 => Some(Property::HumanResult),
            807 => Some(Property::ICalendarData),
            1 => Some(Property::Id),
            621 => Some(Property::IdTokenExpiry),
            91 => Some(Property::IdentityAlignment),
            376 => Some(Property::If),
            320 => Some(Property::ImpersonateServiceAccount),
            546 => Some(Property::ImplicitTls),
            128 => Some(Property::InMemoryStore),
            651 => Some(Property::InboundReportAddresses),
            652 => Some(Property::InboundReportForwarding),
            70 => Some(Property::Incidents),
            352 => Some(Property::IncludeSource),
            94 => Some(Property::IndexAsn),
            95 => Some(Property::IndexAsnName),
            664 => Some(Property::IndexBatchSize),
            667 => Some(Property::IndexCalendar),
            668 => Some(Property::IndexCalendarFields),
            670 => Some(Property::IndexContactFields),
            669 => Some(Property::IndexContacts),
            96 => Some(Property::IndexCountry),
            671 => Some(Property::IndexEmail),
            672 => Some(Property::IndexEmailFields),
            421 => Some(Property::IndexKey),
            673 => Some(Property::IndexTelemetry),
            674 => Some(Property::IndexTracingFields),
            422 => Some(Property::IndexValue),
            736 => Some(Property::IndicatorParameters),
            822 => Some(Property::InitialDelay),
            500 => Some(Property::Interval),
            516 => Some(Property::Intervals),
            752 => Some(Property::IpLimit),
            543 => Some(Property::IpLookupStrategy),
            290 => Some(Property::IpRevPtr),
            289 => Some(Property::IpRevResult),
            707 => Some(Property::IsActive),
            755 => Some(Property::IsArchive),
            756 => Some(Property::IsBad),
            340 => Some(Property::IsEnabled),
            806 => Some(Property::IsFromOrganizer),
            491 => Some(Property::IsGlobPattern),
            416 => Some(Property::IsGzipped),
            757 => Some(Property::IsNz),
            564 => Some(Property::IsSenderAllowed),
            776 => Some(Property::IsSpam),
            741 => Some(Property::IsTls),
            181 => Some(Property::Issuer),
            606 => Some(Property::IssuerUrl),
            172 => Some(Property::ItipMaxSize),
            824 => Some(Property::Jitter),
            334 => Some(Property::Key),
            337 => Some(Property::KeyName),
            120 => Some(Property::KeyPrefix),
            853 => Some(Property::KeyValues),
            391 => Some(Property::L1Ratio),
            392 => Some(Property::L2Ratio),
            186 => Some(Property::LastRenewal),
            727 => Some(Property::LearnHamFromCard),
            735 => Some(Property::LearnHamFromReply),
            728 => Some(Property::LearnSpamFromRblHits),
            729 => Some(Property::LearnSpamFromTraps),
            373 => Some(Property::Level),
            370 => Some(Property::LicenseKey),
            875 => Some(Property::Line),
            183 => Some(Property::ListenerIds),
            188 => Some(Property::Listeners),
            869 => Some(Property::LivePropertyMaxSize),
            7 => Some(Property::Locale),
            341 => Some(Property::Logo),
            371 => Some(Property::LogoUrl),
            682 => Some(Property::LoiterBanPeriod),
            681 => Some(Property::LoiterBanRate),
            854 => Some(Property::Lossy),
            384 => Some(Property::MachineId),
            793 => Some(Property::MailExchangers),
            284 => Some(Property::MailFrom),
            509 => Some(Property::MailFromTimeout),
            841 => Some(Property::MailRua),
            154 => Some(Property::MailingLists),
            796 => Some(Property::MaintenanceType),
            318 => Some(Property::ManagedZone),
            374 => Some(Property::Match),
            23 => Some(Property::MaxAddressBooks),
            566 => Some(Property::MaxAge),
            576 => Some(Property::MaxAllowedPacket),
            115 => Some(Property::MaxApiKeys),
            114 => Some(Property::MaxAppPasswords),
            353 => Some(Property::MaxAttachmentSize),
            511 => Some(Property::MaxAttempts),
            157 => Some(Property::MaxAttendees),
            425 => Some(Property::MaxAuthFailures),
            160 => Some(Property::MaxCalendars),
            201 => Some(Property::MaxChangesHistory),
            426 => Some(Property::MaxConcurrent),
            439 => Some(Property::MaxConcurrentRequests),
            442 => Some(Property::MaxConcurrentUploads),
            603 => Some(Property::MaxConnections),
            24 => Some(Property::MaxContacts),
            702 => Some(Property::MaxCpuCycles),
            823 => Some(Property::MaxDelay),
            530 => Some(Property::MaxDuration),
            417 => Some(Property::MaxEntries),
            418 => Some(Property::MaxEntrySize),
            163 => Some(Property::MaxEventNotifications),
            161 => Some(Property::MaxEvents),
            547 => Some(Property::MaxFailures),
            378 => Some(Property::MaxFiles),
            379 => Some(Property::MaxFolders),
            715 => Some(Property::MaxHeaderSize),
            159 => Some(Property::MaxICalendarSize),
            363 => Some(Property::MaxIdentities),
            716 => Some(Property::MaxIncludes),
            717 => Some(Property::MaxLocalVars),
            866 => Some(Property::MaxLockTimeout),
            867 => Some(Property::MaxLocks),
            355 => Some(Property::MaxMailboxDepth),
            356 => Some(Property::MaxMailboxNameLength),
            364 => Some(Property::MaxMailboxes),
            365 => Some(Property::MaxMaskedAddresses),
            718 => Some(Property::MaxMatchVars),
            354 => Some(Property::MaxMessageSize),
            361 => Some(Property::MaxMessages),
            438 => Some(Property::MaxMethodCalls),
            544 => Some(Property::MaxMultihomed),
            545 => Some(Property::MaxMxHosts),
            720 => Some(Property::MaxNestedBlocks),
            721 => Some(Property::MaxNestedForEvery),
            703 => Some(Property::MaxNestedIncludes),
            722 => Some(Property::MaxNestedTests),
            704 => Some(Property::MaxOutMessages),
            162 => Some(Property::MaxParticipantIdentities),
            366 => Some(Property::MaxPublicKeys),
            561 => Some(Property::MaxReceivedHeaders),
            173 => Some(Property::MaxRecipients),
            580 => Some(Property::MaxReconnects),
            158 => Some(Property::MaxRecurrenceExpansions),
            705 => Some(Property::MaxRedirects),
            852 => Some(Property::MaxReportSize),
            427 => Some(Property::MaxRequestRate),
            428 => Some(Property::MaxRequestSize),
            527 => Some(Property::MaxResponseSize),
            871 => Some(Property::MaxResults),
            18 => Some(Property::MaxRetries),
            648 => Some(Property::MaxRetryWait),
            719 => Some(Property::MaxScriptNameLength),
            723 => Some(Property::MaxScriptSize),
            726 => Some(Property::MaxScripts),
            696 => Some(Property::MaxShares),
            101 => Some(Property::MaxSize),
            724 => Some(Property::MaxStringLength),
            362 => Some(Property::MaxSubmissions),
            458 => Some(Property::MaxSubscriptions),
            444 => Some(Property::MaxUploadCount),
            443 => Some(Property::MaxUploadSize),
            22 => Some(Property::MaxVCardSize),
            725 => Some(Property::MaxVarNameLength),
            706 => Some(Property::MaxVarSize),
            864 => Some(Property::MemberGroupIds),
            19 => Some(Property::MemberTenantId),
            92 => Some(Property::Message),
            698 => Some(Property::MessageIdHostname),
            819 => Some(Property::MessageIds),
            145 => Some(Property::Messages),
            493 => Some(Property::Metric),
            497 => Some(Property::Metrics),
            207 => Some(Property::MetricsCollectionInterval),
            498 => Some(Property::MetricsPolicy),
            731 => Some(Property::MinHamSamples),
            649 => Some(Property::MinRetryWait),
            732 => Some(Property::MinSpamSamples),
            166 => Some(Property::MinTriggerInterval),
            191 => Some(Property::Minute),
            567 => Some(Property::Mode),
            28 => Some(Property::Model),
            764 => Some(Property::ModelId),
            30 => Some(Property::ModelType),
            522 => Some(Property::MtPriority),
            570 => Some(Property::MtaSts),
            572 => Some(Property::MtaStsTimeout),
            859 => Some(Property::Multiline),
            550 => Some(Property::MustMatchSender),
            568 => Some(Property::MxHosts),
            25 => Some(Property::Name),
            414 => Some(Property::Namespace),
            156 => Some(Property::NegativeTtl),
            634 => Some(Property::NextNotify),
            633 => Some(Property::NextRetry),
            223 => Some(Property::NextTransitionAt),
            700 => Some(Property::NoCapabilityCheck),
            587 => Some(Property::NoEcho),
            523 => Some(Property::NoSoliciting),
            184 => Some(Property::NodeId),
            179 => Some(Property::NotValidAfter),
            180 => Some(Property::NotValidBefore),
            513 => Some(Property::Notify),
            642 => Some(Property::NotifyCount),
            643 => Some(Property::NotifyDue),
            390 => Some(Property::NumFeatures),
            350 => Some(Property::NumReplicas),
            351 => Some(Property::NumShards),
            813 => Some(Property::OnSuccessRenewCertificate),
            495 => Some(Property::OpenTelemetry),
            630 => Some(Property::Options),
            645 => Some(Property::Orcpt),
            241 => Some(Property::OrgName),
            843 => Some(Property::OrganizationName),
            301 => Some(Property::Origin),
            71 => Some(Property::OriginalEnvelopeId),
            72 => Some(Property::OriginalMailFrom),
            73 => Some(Property::OriginalRcptTo),
            5 => Some(Property::OtpAuth),
            625 => Some(Property::OtpCode),
            626 => Some(Property::OtpUrl),
            653 => Some(Property::OutboundReportDomain),
            654 => Some(Property::OutboundReportSubmitter),
            590 => Some(Property::OverrideProxyTrustedNetworks),
            239 => Some(Property::OverrideType),
            324 => Some(Property::OvhEndpoint),
            737 => Some(Property::Parameters),
            433 => Some(Property::ParseLimitContact),
            434 => Some(Property::ParseLimitEmail),
            432 => Some(Property::ParseLimitEvent),
            876 => Some(Property::Password),
            113 => Some(Property::PasswordDefaultExpiry),
            109 => Some(Property::PasswordHashAlgorithm),
            111 => Some(Property::PasswordMaxLength),
            110 => Some(Property::PasswordMinLength),
            112 => Some(Property::PasswordMinStrength),
            380 => Some(Property::Path),
            646 => Some(Property::Period),
            48 => Some(Property::Permissions),
            583 => Some(Property::PingInterval),
            524 => Some(Property::Pipelining),
            846 => Some(Property::Policies),
            250 => Some(Property::PolicyAdkim),
            251 => Some(Property::PolicyAspf),
            920 => Some(Property::PolicyDiscoveryMethod),
            252 => Some(Property::PolicyDisposition),
            248 => Some(Property::PolicyDomain),
            255 => Some(Property::PolicyFailureReportingOptions),
            237 => Some(Property::PolicyIdentifier),
            840 => Some(Property::PolicyIdentifiers),
            919 => Some(Property::PolicyNp),
            262 => Some(Property::PolicyOverrideReasons),
            848 => Some(Property::PolicyStrings),
            253 => Some(Property::PolicySubdomainDisposition),
            254 => Some(Property::PolicyTestingMode),
            847 => Some(Property::PolicyType),
            249 => Some(Property::PolicyVersion),
            489 => Some(Property::PollInterval),
            311 => Some(Property::PollingInterval),
            478 => Some(Property::PoolMaxConnections),
            577 => Some(Property::PoolMinConnections),
            631 => Some(Property::PoolRecyclingMethod),
            479 => Some(Property::PoolTimeoutCreate),
            480 => Some(Property::PoolTimeoutRecycle),
            481 => Some(Property::PoolTimeoutWait),
            657 => Some(Property::PoolWorkers),
            299 => Some(Property::Port),
            910 => Some(Property::PreferredChain),
            856 => Some(Property::Prefix),
            306 => Some(Property::PreserveIntermediates),
            483 => Some(Property::Priority),
            177 => Some(Property::PrivateKey),
            904 => Some(Property::PrivateKeyPassword),
            903 => Some(Property::PrivateKeyPem),
            319 => Some(Property::PrivateZone),
            332 => Some(Property::PrivateZoneOnly),
            661 => Some(Property::Profile),
            317 => Some(Property::ProjectId),
            496 => Some(Property::Prometheus),
            765 => Some(Property::Prompt),
            313 => Some(Property::PropagationDelay),
            312 => Some(Property::PropagationTimeout),
            713 => Some(Property::ProtectedHeaders),
            298 => Some(Property::Protocol),
            533 => Some(Property::ProtocolVersion),
            795 => Some(Property::ProviderInfo),
            792 => Some(Property::ProxyTrustedNetworks),
            218 => Some(Property::PublicKey),
            302 => Some(Property::PublishRecords),
            448 => Some(Property::PushAttemptWait),
            449 => Some(Property::PushMaxAttempts),
            452 => Some(Property::PushRequestTimeout),
            450 => Some(Property::PushRetryWait),
            454 => Some(Property::PushShardsTotal),
            451 => Some(Property::PushThrottle),
            453 => Some(Property::PushVerifyTimeout),
            786 => Some(Property::QueryEmailAliases),
            783 => Some(Property::QueryLogin),
            437 => Some(Property::QueryMaxResults),
            785 => Some(Property::QueryMemberOf),
            784 => Some(Property::QueryRecipient),
            514 => Some(Property::QueueId),
            644 => Some(Property::QueueName),
            394 => Some(Property::Quotas),
            532 => Some(Property::Rate),
            410 => Some(Property::RateLimit),
            397 => Some(Property::RateLimitAnonymous),
            396 => Some(Property::RateLimitAuthenticated),
            767 => Some(Property::Ratio),
            510 => Some(Property::RcptToTimeout),
            650 => Some(Property::ReadFromReplicas),
            578 => Some(Property::ReadReplicas),
            45 => Some(Property::Reason),
            63 => Some(Property::ReceivedAt),
            636 => Some(Property::ReceivedFromIp),
            637 => Some(Property::ReceivedViaPort),
            836 => Some(Property::ReceivingIp),
            835 => Some(Property::ReceivingMxHelo),
            834 => Some(Property::ReceivingMxHostname),
            484 => Some(Property::Recipients),
            256 => Some(Property::Records),
            805 => Some(Property::RecurrenceId),
            911 => Some(Property::RedirectRoot),
            605 => Some(Property::RedirectUris),
            419 => Some(Property::Refresh),
            617 => Some(Property::RefreshTokenExpiry),
            618 => Some(Property::RefreshTokenRenewal),
            330 => Some(Property::Region),
            563 => Some(Property::RejectNonFqdn),
            282 => Some(Property::RemoteIp),
            17 => Some(Property::RenewBefore),
            66 => Some(Property::Report),
            349 => Some(Property::ReportAddressUri),
            244 => Some(Property::ReportId),
            74 => Some(Property::ReportedDomains),
            75 => Some(Property::ReportedUris),
            76 => Some(Property::ReportingMta),
            870 => Some(Property::RequestMaxSize),
            123 => Some(Property::RequestTlsCertificate),
            551 => Some(Property::Require),
            607 => Some(Property::RequireAudience),
            615 => Some(Property::RequireClientRegistration),
            608 => Some(Property::RequireScopes),
            525 => Some(Property::RequireTls),
            733 => Some(Property::ReservoirCapacity),
            880 => Some(Property::ResourceGroup),
            51 => Some(Property::ResourceUrl),
            212 => Some(Property::ResponseCode),
            213 => Some(Property::ResponseEnhanced),
            401 => Some(Property::ResponseHeaders),
            211 => Some(Property::ResponseHostname),
            214 => Some(Property::ResponseMessage),
            761 => Some(Property::ResponsePosCategory),
            762 => Some(Property::ResponsePosConfidence),
            763 => Some(Property::ResponsePosExplanation),
            233 => Some(Property::Result),
            832 => Some(Property::ResultType),
            228 => Some(Property::RetireAfter),
            420 => Some(Property::Retry),
            640 => Some(Property::RetryCount),
            641 => Some(Property::RetryDue),
            635 => Some(Property::ReturnPath),
            912 => Some(Property::ReuseKey),
            692 => Some(Property::ReverseIpVerify),
            565 => Some(Property::Rewrite),
            193 => Some(Property::RoleIds),
            152 => Some(Property::Roles),
            857 => Some(Property::Rotate),
            227 => Some(Property::RotateAfter),
            540 => Some(Property::Route),
            236 => Some(Property::Rua),
            896 => Some(Property::Sandbox),
            119 => Some(Property::SasToken),
            549 => Some(Property::SaslMechanisms),
            683 => Some(Property::ScanBanPaths),
            685 => Some(Property::ScanBanPeriod),
            684 => Some(Property::ScanBanRate),
            541 => Some(Property::Schedule),
            143 => Some(Property::Scheduling),
            908 => Some(Property::Scheme),
            281 => Some(Property::Scope),
            745 => Some(Property::Score),
            771 => Some(Property::ScoreDiscard),
            772 => Some(Property::ScoreReject),
            773 => Some(Property::ScoreSpam),
            553 => Some(Property::Script),
            127 => Some(Property::SearchStore),
            3 => Some(Property::Secret),
            328 => Some(Property::SecretAccessKey),
            326 => Some(Property::SecretApiKey),
            906 => Some(Property::SecretId),
            659 => Some(Property::SecretKey),
            660 => Some(Property::SecurityToken),
            222 => Some(Property::Selector),
            226 => Some(Property::SelectorTemplate),
            230 => Some(Property::SendFrequency),
            833 => Some(Property::SendingMtaIp),
            915 => Some(Property::SentinelSecret),
            914 => Some(Property::SentinelUsername),
            97 => Some(Property::Separator),
            121 => Some(Property::ServerHostname),
            308 => Some(Property::Servers),
            316 => Some(Property::ServiceAccountJson),
            913 => Some(Property::ServiceName),
            794 => Some(Property::Services),
            329 => Some(Property::SessionToken),
            440 => Some(Property::SetMaxObjects),
            830 => Some(Property::ShardIndex),
            895 => Some(Property::SharedSecret),
            336 => Some(Property::Sig0Algorithm),
            623 => Some(Property::SignatureAlgorithm),
            624 => Some(Property::SignatureKey),
            335 => Some(Property::SignerName),
            64 => Some(Property::Size),
            885 => Some(Property::SkipDeploy),
            423 => Some(Property::SkipFirst),
            552 => Some(Property::SmtpGreeting),
            441 => Some(Property::SnippetMaxResults),
            591 => Some(Property::SocketBacklog),
            592 => Some(Property::SocketNoDelay),
            593 => Some(Property::SocketReceiveBufferSize),
            594 => Some(Property::SocketReuseAddress),
            595 => Some(Property::SocketReusePort),
            596 => Some(Property::SocketSendBufferSize),
            597 => Some(Property::SocketTosV4),
            598 => Some(Property::SocketTtl),
            77 => Some(Property::SourceIp),
            504 => Some(Property::SourceIps),
            78 => Some(Property::SourcePort),
            775 => Some(Property::SpamFilterRulesUrl),
            90 => Some(Property::SpfDns),
            285 => Some(Property::SpfEhloDomain),
            286 => Some(Property::SpfEhloResult),
            688 => Some(Property::SpfEhloVerify),
            689 => Some(Property::SpfFromVerify),
            287 => Some(Property::SpfMailFromDomain),
            288 => Some(Property::SpfMailFromResult),
            267 => Some(Property::SpfResults),
            224 => Some(Property::Stage),
            529 => Some(Property::Stages),
            56 => Some(Property::StartTime),
            571 => Some(Property::StartTls),
            61 => Some(Property::Status),
            116 => Some(Property::StorageAccount),
            778 => Some(Property::Store),
            694 => Some(Property::Stores),
            816 => Some(Property::Strategy),
            347 => Some(Property::SubAddressing),
            887 => Some(Property::SubAuthId),
            41 => Some(Property::Subject),
            178 => Some(Property::SubjectAlternativeNames),
            368 => Some(Property::Subscribe),
            879 => Some(Property::SubscriptionId),
            494 => Some(Property::Sum),
            808 => Some(Property::Summary),
            666 => Some(Property::SupportedLanguages),
            748 => Some(Property::Tag),
            746 => Some(Property::Tags),
            189 => Some(Property::TaskTypes),
            187 => Some(Property::Tasks),
            307 => Some(Property::TcpOnError),
            907 => Some(Property::TeamId),
            528 => Some(Property::TempFailOnError),
            27 => Some(Property::Temperature),
            167 => Some(Property::Template),
            900 => Some(Property::TenancyOcid),
            831 => Some(Property::TenantId),
            153 => Some(Property::Tenants),
            2 => Some(Property::Text),
            377 => Some(Property::Then),
            219 => Some(Property::ThirdParty),
            220 => Some(Property::ThirdPartyHash),
            818 => Some(Property::ThreadName),
            791 => Some(Property::ThreadPoolSize),
            574 => Some(Property::ThreadsPerNode),
            862 => Some(Property::Throttle),
            8 => Some(Property::TimeZone),
            29 => Some(Property::Timeout),
            429 => Some(Property::TimeoutAnonymous),
            430 => Some(Property::TimeoutAuthenticated),
            534 => Some(Property::TimeoutCommand),
            535 => Some(Property::TimeoutConnect),
            581 => Some(Property::TimeoutConnection),
            536 => Some(Property::TimeoutData),
            431 => Some(Property::TimeoutIdle),
            461 => Some(Property::TimeoutMessage),
            582 => Some(Property::TimeoutRequest),
            462 => Some(Property::TimeoutSession),
            482 => Some(Property::Timestamp),
            55 => Some(Property::Title),
            542 => Some(Property::Tls),
            599 => Some(Property::TlsDisableCipherSuites),
            600 => Some(Property::TlsDisableProtocols),
            601 => Some(Property::TlsIgnoreClientOrder),
            602 => Some(Property::TlsImplicit),
            573 => Some(Property::TlsTimeout),
            42 => Some(Property::To),
            888 => Some(Property::Token),
            817 => Some(Property::TotalDeadline),
            850 => Some(Property::TotalFailedSessions),
            849 => Some(Property::TotalSuccessfulSessions),
            815 => Some(Property::TraceId),
            129 => Some(Property::Tracer),
            734 => Some(Property::TrainFrequency),
            385 => Some(Property::TransactionRetryDelay),
            386 => Some(Property::TransactionRetryLimit),
            387 => Some(Property::TransactionTimeout),
            531 => Some(Property::TransferLimit),
            769 => Some(Property::TrustContacts),
            774 => Some(Property::TrustReplies),
            338 => Some(Property::TsigAlgorithm),
            310 => Some(Property::Ttl),
            54 => Some(Property::UnpackDirectory),
            812 => Some(Property::UpdateRecords),
            445 => Some(Property::UploadQuota),
            446 => Some(Property::UploadTtl),
            31 => Some(Property::Url),
            753 => Some(Property::UrlLimit),
            52 => Some(Property::UrlPrefix),
            647 => Some(Property::Urls),
            400 => Some(Property::UsePermissiveCors),
            309 => Some(Property::UseTls),
            402 => Some(Property::UseXForwarded),
            395 => Some(Property::UsedDiskQuota),
            79 => Some(Property::UserAgent),
            620 => Some(Property::UserCodeExpiry),
            901 => Some(Property::UserOcid),
            131 => Some(Property::Username),
            610 => Some(Property::UsernameDomain),
            413 => Some(Property::ValidateDomain),
            492 => Some(Property::Value),
            675 => Some(Property::VariableName),
            874 => Some(Property::VerifyAfterWrite),
            80 => Some(Property::Version),
            884 => Some(Property::ViewName),
            526 => Some(Property::Vrfy),
            548 => Some(Property::WaitOnFail),
            893 => Some(Property::WapiVersion),
            922 => Some(Property::WebPushContact),
            921 => Some(Property::WebPushKey),
            455 => Some(Property::WebsocketHeartbeat),
            456 => Some(Property::WebsocketThrottle),
            457 => Some(Property::WebsocketTimeout),
            749 => Some(Property::Zone),
            98 => Some(Property::ZoneIpV4),
            99 => Some(Property::ZoneIpV6),
            _ => None,
        }
    }

    const COUNT: usize = 923;
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
            ObjectType::AiModel => AiModel::FLAGS,
            ObjectType::Alert => Alert::FLAGS,
            ObjectType::AllowedIp => AllowedIp::FLAGS,
            ObjectType::ApiKey => ApiKey::FLAGS,
            ObjectType::AppPassword => AppPassword::FLAGS,
            ObjectType::Application => Application::FLAGS,
            ObjectType::ArchivedItem => ArchivedItem::FLAGS,
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
            ObjectType::Enterprise => Enterprise::FLAGS,
            ObjectType::EventTracingLevel => EventTracingLevel::FLAGS,
            ObjectType::FileStorage => FileStorage::FLAGS,
            ObjectType::Http => Http::FLAGS,
            ObjectType::HttpForm => HttpForm::FLAGS,
            ObjectType::HttpLookup => HttpLookup::FLAGS,
            ObjectType::Imap => Imap::FLAGS,
            ObjectType::InMemoryStore => InMemoryStore::FLAGS,
            ObjectType::Jmap => Jmap::FLAGS,
            ObjectType::Log => Log::FLAGS,
            ObjectType::MailingList => MailingList::FLAGS,
            ObjectType::MaskedEmail => MaskedEmail::FLAGS,
            ObjectType::MemoryLookupKey => MemoryLookupKey::FLAGS,
            ObjectType::MemoryLookupKeyValue => MemoryLookupKeyValue::FLAGS,
            ObjectType::Metric => Metric::FLAGS,
            ObjectType::Metrics => Metrics::FLAGS,
            ObjectType::MetricsStore => MetricsStore::FLAGS,
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
            ObjectType::SpamClassifier => SpamClassifier::FLAGS,
            ObjectType::SpamDnsblServer => SpamDnsblServer::FLAGS,
            ObjectType::SpamDnsblSettings => SpamDnsblSettings::FLAGS,
            ObjectType::SpamFileExtension => SpamFileExtension::FLAGS,
            ObjectType::SpamLlm => SpamLlm::FLAGS,
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
            ObjectType::Tenant => Tenant::FLAGS,
            ObjectType::TlsExternalReport => TlsExternalReport::FLAGS,
            ObjectType::TlsInternalReport => TlsInternalReport::FLAGS,
            ObjectType::TlsReportSettings => TlsReportSettings::FLAGS,
            ObjectType::Trace => Trace::FLAGS,
            ObjectType::Tracer => Tracer::FLAGS,
            ObjectType::TracingStore => TracingStore::FLAGS,
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
                IndexSchema::new(
                    Property::MemberGroupIds,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
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
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
            ],
            ObjectType::AllowedIp => vec![IndexSchema::new(
                Property::Address,
                IndexSchemaType::Unique,
                IndexSchemaValueType::IpMask,
            )],
            ObjectType::ArchivedItem => vec![IndexSchema::new(
                Property::AccountId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
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
            ObjectType::Directory => vec![IndexSchema::new(
                Property::MemberTenantId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
            ObjectType::DkimSignature => vec![
                IndexSchema::new(
                    Property::DomainId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
            ],
            ObjectType::DnsServer => vec![IndexSchema::new(
                Property::MemberTenantId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
            ObjectType::Domain => vec![
                IndexSchema::new(
                    Property::Text,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Text,
                ),
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
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
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
            ],
            ObjectType::MaskedEmail => vec![IndexSchema::new(
                Property::AccountId,
                IndexSchemaType::Search,
                IndexSchemaValueType::Id,
            )],
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
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
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
                IndexSchema::new(
                    Property::MemberTenantId,
                    IndexSchemaType::Search,
                    IndexSchemaValueType::Id,
                ),
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
            ObjectType::Tenant => vec![IndexSchema::new(
                Property::Text,
                IndexSchemaType::Search,
                IndexSchemaValueType::Text,
            )],
            _ => vec![],
        }
    }

    pub fn get_permission(&self) -> Permission {
        match self {
            ObjectType::Account => Permission::SysAccountGet,
            ObjectType::AccountPassword => Permission::SysAccountPasswordGet,
            ObjectType::AccountSettings => Permission::SysAccountSettingsGet,
            ObjectType::AcmeProvider => Permission::SysAcmeProviderGet,
            ObjectType::Action => Permission::SysActionGet,
            ObjectType::AddressBook => Permission::SysAddressBookGet,
            ObjectType::AiModel => Permission::SysAiModelGet,
            ObjectType::Alert => Permission::SysAlertGet,
            ObjectType::AllowedIp => Permission::SysAllowedIpGet,
            ObjectType::ApiKey => Permission::SysApiKeyGet,
            ObjectType::AppPassword => Permission::SysAppPasswordGet,
            ObjectType::Application => Permission::SysApplicationGet,
            ObjectType::ArchivedItem => Permission::SysArchivedItemGet,
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
            ObjectType::Enterprise => Permission::SysEnterpriseGet,
            ObjectType::EventTracingLevel => Permission::SysEventTracingLevelGet,
            ObjectType::FileStorage => Permission::SysFileStorageGet,
            ObjectType::Http => Permission::SysHttpGet,
            ObjectType::HttpForm => Permission::SysHttpFormGet,
            ObjectType::HttpLookup => Permission::SysHttpLookupGet,
            ObjectType::Imap => Permission::SysImapGet,
            ObjectType::InMemoryStore => Permission::SysInMemoryStoreGet,
            ObjectType::Jmap => Permission::SysJmapGet,
            ObjectType::Log => Permission::SysLogGet,
            ObjectType::MailingList => Permission::SysMailingListGet,
            ObjectType::MaskedEmail => Permission::SysMaskedEmailGet,
            ObjectType::MemoryLookupKey => Permission::SysMemoryLookupKeyGet,
            ObjectType::MemoryLookupKeyValue => Permission::SysMemoryLookupKeyValueGet,
            ObjectType::Metric => Permission::SysMetricGet,
            ObjectType::Metrics => Permission::SysMetricsGet,
            ObjectType::MetricsStore => Permission::SysMetricsStoreGet,
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
            ObjectType::SpamClassifier => Permission::SysSpamClassifierGet,
            ObjectType::SpamDnsblServer => Permission::SysSpamDnsblServerGet,
            ObjectType::SpamDnsblSettings => Permission::SysSpamDnsblSettingsGet,
            ObjectType::SpamFileExtension => Permission::SysSpamFileExtensionGet,
            ObjectType::SpamLlm => Permission::SysSpamLlmGet,
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
            ObjectType::Tenant => Permission::SysTenantGet,
            ObjectType::TlsExternalReport => Permission::SysTlsExternalReportGet,
            ObjectType::TlsInternalReport => Permission::SysTlsInternalReportGet,
            ObjectType::TlsReportSettings => Permission::SysTlsReportSettingsGet,
            ObjectType::Trace => Permission::SysTraceGet,
            ObjectType::Tracer => Permission::SysTracerGet,
            ObjectType::TracingStore => Permission::SysTracingStoreGet,
            ObjectType::WebDav => Permission::SysWebDavGet,
            ObjectType::WebHook => Permission::SysWebHookGet,
        }
    }

    pub fn query_permission(&self) -> Permission {
        match self {
            ObjectType::Account => Permission::SysAccountQuery,
            ObjectType::AcmeProvider => Permission::SysAcmeProviderQuery,
            ObjectType::Action => Permission::SysActionQuery,
            ObjectType::AiModel => Permission::SysAiModelQuery,
            ObjectType::Alert => Permission::SysAlertQuery,
            ObjectType::AllowedIp => Permission::SysAllowedIpQuery,
            ObjectType::ApiKey => Permission::SysApiKeyQuery,
            ObjectType::AppPassword => Permission::SysAppPasswordQuery,
            ObjectType::Application => Permission::SysApplicationQuery,
            ObjectType::ArchivedItem => Permission::SysArchivedItemQuery,
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
            ObjectType::Log => Permission::SysLogQuery,
            ObjectType::MailingList => Permission::SysMailingListQuery,
            ObjectType::MaskedEmail => Permission::SysMaskedEmailQuery,
            ObjectType::MemoryLookupKey => Permission::SysMemoryLookupKeyQuery,
            ObjectType::MemoryLookupKeyValue => Permission::SysMemoryLookupKeyValueQuery,
            ObjectType::Metric => Permission::SysMetricQuery,
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
            ObjectType::Tenant => Permission::SysTenantQuery,
            ObjectType::TlsExternalReport => Permission::SysTlsExternalReportQuery,
            ObjectType::TlsInternalReport => Permission::SysTlsInternalReportQuery,
            ObjectType::Trace => Permission::SysTraceQuery,
            ObjectType::Tracer => Permission::SysTracerQuery,
            ObjectType::WebHook => Permission::SysWebHookQuery,
            _ => unreachable!(),
        }
    }

    pub fn set_permission(&self) -> [Permission; 3] {
        match self {
            ObjectType::Account => [
                Permission::SysAccountCreate,
                Permission::SysAccountUpdate,
                Permission::SysAccountDestroy,
            ],
            ObjectType::AccountPassword => [
                Permission::SysAccountPasswordUpdate,
                Permission::SysAccountPasswordUpdate,
                Permission::SysAccountPasswordUpdate,
            ],
            ObjectType::AccountSettings => [
                Permission::SysAccountSettingsUpdate,
                Permission::SysAccountSettingsUpdate,
                Permission::SysAccountSettingsUpdate,
            ],
            ObjectType::AcmeProvider => [
                Permission::SysAcmeProviderCreate,
                Permission::SysAcmeProviderUpdate,
                Permission::SysAcmeProviderDestroy,
            ],
            ObjectType::Action => [
                Permission::SysActionCreate,
                Permission::SysActionUpdate,
                Permission::SysActionDestroy,
            ],
            ObjectType::AddressBook => [
                Permission::SysAddressBookUpdate,
                Permission::SysAddressBookUpdate,
                Permission::SysAddressBookUpdate,
            ],
            ObjectType::AiModel => [
                Permission::SysAiModelCreate,
                Permission::SysAiModelUpdate,
                Permission::SysAiModelDestroy,
            ],
            ObjectType::Alert => [
                Permission::SysAlertCreate,
                Permission::SysAlertUpdate,
                Permission::SysAlertDestroy,
            ],
            ObjectType::AllowedIp => [
                Permission::SysAllowedIpCreate,
                Permission::SysAllowedIpUpdate,
                Permission::SysAllowedIpDestroy,
            ],
            ObjectType::ApiKey => [
                Permission::SysApiKeyCreate,
                Permission::SysApiKeyUpdate,
                Permission::SysApiKeyDestroy,
            ],
            ObjectType::AppPassword => [
                Permission::SysAppPasswordCreate,
                Permission::SysAppPasswordUpdate,
                Permission::SysAppPasswordDestroy,
            ],
            ObjectType::Application => [
                Permission::SysApplicationCreate,
                Permission::SysApplicationUpdate,
                Permission::SysApplicationDestroy,
            ],
            ObjectType::ArchivedItem => [
                Permission::SysArchivedItemCreate,
                Permission::SysArchivedItemUpdate,
                Permission::SysArchivedItemDestroy,
            ],
            ObjectType::ArfExternalReport => [
                Permission::SysArfExternalReportCreate,
                Permission::SysArfExternalReportUpdate,
                Permission::SysArfExternalReportDestroy,
            ],
            ObjectType::Asn => [
                Permission::SysAsnUpdate,
                Permission::SysAsnUpdate,
                Permission::SysAsnUpdate,
            ],
            ObjectType::Authentication => [
                Permission::SysAuthenticationUpdate,
                Permission::SysAuthenticationUpdate,
                Permission::SysAuthenticationUpdate,
            ],
            ObjectType::BlobStore => [
                Permission::SysBlobStoreUpdate,
                Permission::SysBlobStoreUpdate,
                Permission::SysBlobStoreUpdate,
            ],
            ObjectType::BlockedIp => [
                Permission::SysBlockedIpCreate,
                Permission::SysBlockedIpUpdate,
                Permission::SysBlockedIpDestroy,
            ],
            ObjectType::Bootstrap => [
                Permission::SysBootstrapUpdate,
                Permission::SysBootstrapUpdate,
                Permission::SysBootstrapUpdate,
            ],
            ObjectType::Cache => [
                Permission::SysCacheUpdate,
                Permission::SysCacheUpdate,
                Permission::SysCacheUpdate,
            ],
            ObjectType::Calendar => [
                Permission::SysCalendarUpdate,
                Permission::SysCalendarUpdate,
                Permission::SysCalendarUpdate,
            ],
            ObjectType::CalendarAlarm => [
                Permission::SysCalendarAlarmUpdate,
                Permission::SysCalendarAlarmUpdate,
                Permission::SysCalendarAlarmUpdate,
            ],
            ObjectType::CalendarScheduling => [
                Permission::SysCalendarSchedulingUpdate,
                Permission::SysCalendarSchedulingUpdate,
                Permission::SysCalendarSchedulingUpdate,
            ],
            ObjectType::Certificate => [
                Permission::SysCertificateCreate,
                Permission::SysCertificateUpdate,
                Permission::SysCertificateDestroy,
            ],
            ObjectType::ClusterNode => [
                Permission::SysClusterNodeCreate,
                Permission::SysClusterNodeUpdate,
                Permission::SysClusterNodeDestroy,
            ],
            ObjectType::ClusterRole => [
                Permission::SysClusterRoleCreate,
                Permission::SysClusterRoleUpdate,
                Permission::SysClusterRoleDestroy,
            ],
            ObjectType::Coordinator => [
                Permission::SysCoordinatorUpdate,
                Permission::SysCoordinatorUpdate,
                Permission::SysCoordinatorUpdate,
            ],
            ObjectType::DataRetention => [
                Permission::SysDataRetentionUpdate,
                Permission::SysDataRetentionUpdate,
                Permission::SysDataRetentionUpdate,
            ],
            ObjectType::DataStore => [
                Permission::SysDataStoreUpdate,
                Permission::SysDataStoreUpdate,
                Permission::SysDataStoreUpdate,
            ],
            ObjectType::Directory => [
                Permission::SysDirectoryCreate,
                Permission::SysDirectoryUpdate,
                Permission::SysDirectoryDestroy,
            ],
            ObjectType::DkimReportSettings => [
                Permission::SysDkimReportSettingsUpdate,
                Permission::SysDkimReportSettingsUpdate,
                Permission::SysDkimReportSettingsUpdate,
            ],
            ObjectType::DkimSignature => [
                Permission::SysDkimSignatureCreate,
                Permission::SysDkimSignatureUpdate,
                Permission::SysDkimSignatureDestroy,
            ],
            ObjectType::DmarcExternalReport => [
                Permission::SysDmarcExternalReportCreate,
                Permission::SysDmarcExternalReportUpdate,
                Permission::SysDmarcExternalReportDestroy,
            ],
            ObjectType::DmarcInternalReport => [
                Permission::SysDmarcInternalReportCreate,
                Permission::SysDmarcInternalReportUpdate,
                Permission::SysDmarcInternalReportDestroy,
            ],
            ObjectType::DmarcReportSettings => [
                Permission::SysDmarcReportSettingsUpdate,
                Permission::SysDmarcReportSettingsUpdate,
                Permission::SysDmarcReportSettingsUpdate,
            ],
            ObjectType::DnsResolver => [
                Permission::SysDnsResolverUpdate,
                Permission::SysDnsResolverUpdate,
                Permission::SysDnsResolverUpdate,
            ],
            ObjectType::DnsServer => [
                Permission::SysDnsServerCreate,
                Permission::SysDnsServerUpdate,
                Permission::SysDnsServerDestroy,
            ],
            ObjectType::Domain => [
                Permission::SysDomainCreate,
                Permission::SysDomainUpdate,
                Permission::SysDomainDestroy,
            ],
            ObjectType::DsnReportSettings => [
                Permission::SysDsnReportSettingsUpdate,
                Permission::SysDsnReportSettingsUpdate,
                Permission::SysDsnReportSettingsUpdate,
            ],
            ObjectType::Email => [
                Permission::SysEmailUpdate,
                Permission::SysEmailUpdate,
                Permission::SysEmailUpdate,
            ],
            ObjectType::Enterprise => [
                Permission::SysEnterpriseUpdate,
                Permission::SysEnterpriseUpdate,
                Permission::SysEnterpriseUpdate,
            ],
            ObjectType::EventTracingLevel => [
                Permission::SysEventTracingLevelCreate,
                Permission::SysEventTracingLevelUpdate,
                Permission::SysEventTracingLevelDestroy,
            ],
            ObjectType::FileStorage => [
                Permission::SysFileStorageUpdate,
                Permission::SysFileStorageUpdate,
                Permission::SysFileStorageUpdate,
            ],
            ObjectType::Http => [
                Permission::SysHttpUpdate,
                Permission::SysHttpUpdate,
                Permission::SysHttpUpdate,
            ],
            ObjectType::HttpForm => [
                Permission::SysHttpFormUpdate,
                Permission::SysHttpFormUpdate,
                Permission::SysHttpFormUpdate,
            ],
            ObjectType::HttpLookup => [
                Permission::SysHttpLookupCreate,
                Permission::SysHttpLookupUpdate,
                Permission::SysHttpLookupDestroy,
            ],
            ObjectType::Imap => [
                Permission::SysImapUpdate,
                Permission::SysImapUpdate,
                Permission::SysImapUpdate,
            ],
            ObjectType::InMemoryStore => [
                Permission::SysInMemoryStoreUpdate,
                Permission::SysInMemoryStoreUpdate,
                Permission::SysInMemoryStoreUpdate,
            ],
            ObjectType::Jmap => [
                Permission::SysJmapUpdate,
                Permission::SysJmapUpdate,
                Permission::SysJmapUpdate,
            ],
            ObjectType::Log => [
                Permission::SysLogCreate,
                Permission::SysLogUpdate,
                Permission::SysLogDestroy,
            ],
            ObjectType::MailingList => [
                Permission::SysMailingListCreate,
                Permission::SysMailingListUpdate,
                Permission::SysMailingListDestroy,
            ],
            ObjectType::MaskedEmail => [
                Permission::SysMaskedEmailCreate,
                Permission::SysMaskedEmailUpdate,
                Permission::SysMaskedEmailDestroy,
            ],
            ObjectType::MemoryLookupKey => [
                Permission::SysMemoryLookupKeyCreate,
                Permission::SysMemoryLookupKeyUpdate,
                Permission::SysMemoryLookupKeyDestroy,
            ],
            ObjectType::MemoryLookupKeyValue => [
                Permission::SysMemoryLookupKeyValueCreate,
                Permission::SysMemoryLookupKeyValueUpdate,
                Permission::SysMemoryLookupKeyValueDestroy,
            ],
            ObjectType::Metric => [
                Permission::SysMetricCreate,
                Permission::SysMetricUpdate,
                Permission::SysMetricDestroy,
            ],
            ObjectType::Metrics => [
                Permission::SysMetricsUpdate,
                Permission::SysMetricsUpdate,
                Permission::SysMetricsUpdate,
            ],
            ObjectType::MetricsStore => [
                Permission::SysMetricsStoreUpdate,
                Permission::SysMetricsStoreUpdate,
                Permission::SysMetricsStoreUpdate,
            ],
            ObjectType::MtaConnectionStrategy => [
                Permission::SysMtaConnectionStrategyCreate,
                Permission::SysMtaConnectionStrategyUpdate,
                Permission::SysMtaConnectionStrategyDestroy,
            ],
            ObjectType::MtaDeliverySchedule => [
                Permission::SysMtaDeliveryScheduleCreate,
                Permission::SysMtaDeliveryScheduleUpdate,
                Permission::SysMtaDeliveryScheduleDestroy,
            ],
            ObjectType::MtaExtensions => [
                Permission::SysMtaExtensionsUpdate,
                Permission::SysMtaExtensionsUpdate,
                Permission::SysMtaExtensionsUpdate,
            ],
            ObjectType::MtaHook => [
                Permission::SysMtaHookCreate,
                Permission::SysMtaHookUpdate,
                Permission::SysMtaHookDestroy,
            ],
            ObjectType::MtaInboundSession => [
                Permission::SysMtaInboundSessionUpdate,
                Permission::SysMtaInboundSessionUpdate,
                Permission::SysMtaInboundSessionUpdate,
            ],
            ObjectType::MtaInboundThrottle => [
                Permission::SysMtaInboundThrottleCreate,
                Permission::SysMtaInboundThrottleUpdate,
                Permission::SysMtaInboundThrottleDestroy,
            ],
            ObjectType::MtaMilter => [
                Permission::SysMtaMilterCreate,
                Permission::SysMtaMilterUpdate,
                Permission::SysMtaMilterDestroy,
            ],
            ObjectType::MtaOutboundStrategy => [
                Permission::SysMtaOutboundStrategyUpdate,
                Permission::SysMtaOutboundStrategyUpdate,
                Permission::SysMtaOutboundStrategyUpdate,
            ],
            ObjectType::MtaOutboundThrottle => [
                Permission::SysMtaOutboundThrottleCreate,
                Permission::SysMtaOutboundThrottleUpdate,
                Permission::SysMtaOutboundThrottleDestroy,
            ],
            ObjectType::MtaQueueQuota => [
                Permission::SysMtaQueueQuotaCreate,
                Permission::SysMtaQueueQuotaUpdate,
                Permission::SysMtaQueueQuotaDestroy,
            ],
            ObjectType::MtaRoute => [
                Permission::SysMtaRouteCreate,
                Permission::SysMtaRouteUpdate,
                Permission::SysMtaRouteDestroy,
            ],
            ObjectType::MtaStageAuth => [
                Permission::SysMtaStageAuthUpdate,
                Permission::SysMtaStageAuthUpdate,
                Permission::SysMtaStageAuthUpdate,
            ],
            ObjectType::MtaStageConnect => [
                Permission::SysMtaStageConnectUpdate,
                Permission::SysMtaStageConnectUpdate,
                Permission::SysMtaStageConnectUpdate,
            ],
            ObjectType::MtaStageData => [
                Permission::SysMtaStageDataUpdate,
                Permission::SysMtaStageDataUpdate,
                Permission::SysMtaStageDataUpdate,
            ],
            ObjectType::MtaStageEhlo => [
                Permission::SysMtaStageEhloUpdate,
                Permission::SysMtaStageEhloUpdate,
                Permission::SysMtaStageEhloUpdate,
            ],
            ObjectType::MtaStageMail => [
                Permission::SysMtaStageMailUpdate,
                Permission::SysMtaStageMailUpdate,
                Permission::SysMtaStageMailUpdate,
            ],
            ObjectType::MtaStageRcpt => [
                Permission::SysMtaStageRcptUpdate,
                Permission::SysMtaStageRcptUpdate,
                Permission::SysMtaStageRcptUpdate,
            ],
            ObjectType::MtaSts => [
                Permission::SysMtaStsUpdate,
                Permission::SysMtaStsUpdate,
                Permission::SysMtaStsUpdate,
            ],
            ObjectType::MtaTlsStrategy => [
                Permission::SysMtaTlsStrategyCreate,
                Permission::SysMtaTlsStrategyUpdate,
                Permission::SysMtaTlsStrategyDestroy,
            ],
            ObjectType::MtaVirtualQueue => [
                Permission::SysMtaVirtualQueueCreate,
                Permission::SysMtaVirtualQueueUpdate,
                Permission::SysMtaVirtualQueueDestroy,
            ],
            ObjectType::NetworkListener => [
                Permission::SysNetworkListenerCreate,
                Permission::SysNetworkListenerUpdate,
                Permission::SysNetworkListenerDestroy,
            ],
            ObjectType::OAuthClient => [
                Permission::SysOAuthClientCreate,
                Permission::SysOAuthClientUpdate,
                Permission::SysOAuthClientDestroy,
            ],
            ObjectType::OidcProvider => [
                Permission::SysOidcProviderUpdate,
                Permission::SysOidcProviderUpdate,
                Permission::SysOidcProviderUpdate,
            ],
            ObjectType::PublicKey => [
                Permission::SysPublicKeyCreate,
                Permission::SysPublicKeyUpdate,
                Permission::SysPublicKeyDestroy,
            ],
            ObjectType::QueuedMessage => [
                Permission::SysQueuedMessageCreate,
                Permission::SysQueuedMessageUpdate,
                Permission::SysQueuedMessageDestroy,
            ],
            ObjectType::ReportSettings => [
                Permission::SysReportSettingsUpdate,
                Permission::SysReportSettingsUpdate,
                Permission::SysReportSettingsUpdate,
            ],
            ObjectType::Role => [
                Permission::SysRoleCreate,
                Permission::SysRoleUpdate,
                Permission::SysRoleDestroy,
            ],
            ObjectType::Search => [
                Permission::SysSearchUpdate,
                Permission::SysSearchUpdate,
                Permission::SysSearchUpdate,
            ],
            ObjectType::SearchStore => [
                Permission::SysSearchStoreUpdate,
                Permission::SysSearchStoreUpdate,
                Permission::SysSearchStoreUpdate,
            ],
            ObjectType::Security => [
                Permission::SysSecurityUpdate,
                Permission::SysSecurityUpdate,
                Permission::SysSecurityUpdate,
            ],
            ObjectType::SenderAuth => [
                Permission::SysSenderAuthUpdate,
                Permission::SysSenderAuthUpdate,
                Permission::SysSenderAuthUpdate,
            ],
            ObjectType::Sharing => [
                Permission::SysSharingUpdate,
                Permission::SysSharingUpdate,
                Permission::SysSharingUpdate,
            ],
            ObjectType::SieveSystemInterpreter => [
                Permission::SysSieveSystemInterpreterUpdate,
                Permission::SysSieveSystemInterpreterUpdate,
                Permission::SysSieveSystemInterpreterUpdate,
            ],
            ObjectType::SieveSystemScript => [
                Permission::SysSieveSystemScriptCreate,
                Permission::SysSieveSystemScriptUpdate,
                Permission::SysSieveSystemScriptDestroy,
            ],
            ObjectType::SieveUserInterpreter => [
                Permission::SysSieveUserInterpreterUpdate,
                Permission::SysSieveUserInterpreterUpdate,
                Permission::SysSieveUserInterpreterUpdate,
            ],
            ObjectType::SieveUserScript => [
                Permission::SysSieveUserScriptCreate,
                Permission::SysSieveUserScriptUpdate,
                Permission::SysSieveUserScriptDestroy,
            ],
            ObjectType::SpamClassifier => [
                Permission::SysSpamClassifierUpdate,
                Permission::SysSpamClassifierUpdate,
                Permission::SysSpamClassifierUpdate,
            ],
            ObjectType::SpamDnsblServer => [
                Permission::SysSpamDnsblServerCreate,
                Permission::SysSpamDnsblServerUpdate,
                Permission::SysSpamDnsblServerDestroy,
            ],
            ObjectType::SpamDnsblSettings => [
                Permission::SysSpamDnsblSettingsUpdate,
                Permission::SysSpamDnsblSettingsUpdate,
                Permission::SysSpamDnsblSettingsUpdate,
            ],
            ObjectType::SpamFileExtension => [
                Permission::SysSpamFileExtensionCreate,
                Permission::SysSpamFileExtensionUpdate,
                Permission::SysSpamFileExtensionDestroy,
            ],
            ObjectType::SpamLlm => [
                Permission::SysSpamLlmUpdate,
                Permission::SysSpamLlmUpdate,
                Permission::SysSpamLlmUpdate,
            ],
            ObjectType::SpamPyzor => [
                Permission::SysSpamPyzorUpdate,
                Permission::SysSpamPyzorUpdate,
                Permission::SysSpamPyzorUpdate,
            ],
            ObjectType::SpamRule => [
                Permission::SysSpamRuleCreate,
                Permission::SysSpamRuleUpdate,
                Permission::SysSpamRuleDestroy,
            ],
            ObjectType::SpamSettings => [
                Permission::SysSpamSettingsUpdate,
                Permission::SysSpamSettingsUpdate,
                Permission::SysSpamSettingsUpdate,
            ],
            ObjectType::SpamTag => [
                Permission::SysSpamTagCreate,
                Permission::SysSpamTagUpdate,
                Permission::SysSpamTagDestroy,
            ],
            ObjectType::SpamTrainingSample => [
                Permission::SysSpamTrainingSampleCreate,
                Permission::SysSpamTrainingSampleUpdate,
                Permission::SysSpamTrainingSampleDestroy,
            ],
            ObjectType::SpfReportSettings => [
                Permission::SysSpfReportSettingsUpdate,
                Permission::SysSpfReportSettingsUpdate,
                Permission::SysSpfReportSettingsUpdate,
            ],
            ObjectType::StoreLookup => [
                Permission::SysStoreLookupCreate,
                Permission::SysStoreLookupUpdate,
                Permission::SysStoreLookupDestroy,
            ],
            ObjectType::SystemSettings => [
                Permission::SysSystemSettingsUpdate,
                Permission::SysSystemSettingsUpdate,
                Permission::SysSystemSettingsUpdate,
            ],
            ObjectType::Task => [
                Permission::SysTaskCreate,
                Permission::SysTaskUpdate,
                Permission::SysTaskDestroy,
            ],
            ObjectType::TaskManager => [
                Permission::SysTaskManagerUpdate,
                Permission::SysTaskManagerUpdate,
                Permission::SysTaskManagerUpdate,
            ],
            ObjectType::Tenant => [
                Permission::SysTenantCreate,
                Permission::SysTenantUpdate,
                Permission::SysTenantDestroy,
            ],
            ObjectType::TlsExternalReport => [
                Permission::SysTlsExternalReportCreate,
                Permission::SysTlsExternalReportUpdate,
                Permission::SysTlsExternalReportDestroy,
            ],
            ObjectType::TlsInternalReport => [
                Permission::SysTlsInternalReportCreate,
                Permission::SysTlsInternalReportUpdate,
                Permission::SysTlsInternalReportDestroy,
            ],
            ObjectType::TlsReportSettings => [
                Permission::SysTlsReportSettingsUpdate,
                Permission::SysTlsReportSettingsUpdate,
                Permission::SysTlsReportSettingsUpdate,
            ],
            ObjectType::Trace => [
                Permission::SysTraceCreate,
                Permission::SysTraceUpdate,
                Permission::SysTraceDestroy,
            ],
            ObjectType::Tracer => [
                Permission::SysTracerCreate,
                Permission::SysTracerUpdate,
                Permission::SysTracerDestroy,
            ],
            ObjectType::TracingStore => [
                Permission::SysTracingStoreUpdate,
                Permission::SysTracingStoreUpdate,
                Permission::SysTracingStoreUpdate,
            ],
            ObjectType::WebDav => [
                Permission::SysWebDavUpdate,
                Permission::SysWebDavUpdate,
                Permission::SysWebDavUpdate,
            ],
            ObjectType::WebHook => [
                Permission::SysWebHookCreate,
                Permission::SysWebHookUpdate,
                Permission::SysWebHookDestroy,
            ],
        }
    }
}

impl ObjectInner {
    pub fn member_tenant_id(&self) -> Option<Id> {
        match self {
            ObjectInner::Account(Account::User(obj)) => obj.member_tenant_id,
            ObjectInner::Account(Account::Group(obj)) => obj.member_tenant_id,
            ObjectInner::AcmeProvider(obj) => obj.member_tenant_id,
            ObjectInner::ArfExternalReport(obj) => obj.member_tenant_id,
            ObjectInner::Directory(Directory::Ldap(obj)) => obj.member_tenant_id,
            ObjectInner::Directory(Directory::Sql(obj)) => obj.member_tenant_id,
            ObjectInner::Directory(Directory::Oidc(obj)) => obj.member_tenant_id,
            ObjectInner::DkimSignature(DkimSignature::Dkim1Ed25519Sha256(obj)) => {
                obj.member_tenant_id
            }
            ObjectInner::DkimSignature(DkimSignature::Dkim1RsaSha256(obj)) => obj.member_tenant_id,
            ObjectInner::DkimSignature(DkimSignature::Dkim2Ed25519Sha256(obj)) => {
                obj.member_tenant_id
            }
            ObjectInner::DkimSignature(DkimSignature::Dkim2RsaSha256(obj)) => obj.member_tenant_id,
            ObjectInner::DmarcExternalReport(obj) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Tsig(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Cloudflare(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::DigitalOcean(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::DeSEC(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Ovh(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Bunny(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Porkbun(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Dnsimple(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Spaceship(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Route53(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::GoogleCloudDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Alidns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::ArvanCloud(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Autodns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::AzureDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::BaiduCloud(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::BluecatV2(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::ClouDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Constellix(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Cpanel(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Ddnss(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::DnsMadeEasy(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Domeneshop(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Dreamhost(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::DuckDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Dynu(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::EasyDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::EdgeDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Exoscale(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::FreeMyIp(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::GandiV5(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Gcore(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Glesys(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Godaddy(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Hetzner(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::HostingDe(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Hostinger(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::HuaweiCloud(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Hurricane(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::IbmCloud(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Infoblox(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Infomaniak(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Inwx(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Ionos(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Ipv64(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Joker(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Lightsail(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Linode(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::LuaDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::MythicBeasts(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Namecheap(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::NameDotCom(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::NameSilo(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Netcup(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Netlify(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Nifcloud(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Ns1(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::OracleCloud(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Plesk(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Safedns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Scaleway(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::TencentCloud(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Transip(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::UltraDns(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Vercel(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Volcengine(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::Vultr(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::WebSupport(obj)) => obj.member_tenant_id,
            ObjectInner::DnsServer(DnsServer::YandexCloud(obj)) => obj.member_tenant_id,
            ObjectInner::Domain(obj) => obj.member_tenant_id,
            ObjectInner::MailingList(obj) => obj.member_tenant_id,
            ObjectInner::OAuthClient(obj) => obj.member_tenant_id,
            ObjectInner::Role(obj) => obj.member_tenant_id,
            ObjectInner::TlsExternalReport(obj) => obj.member_tenant_id,
            _ => None,
        }
    }

    pub fn set_member_tenant_id(&mut self, id: Id) {
        match self {
            ObjectInner::Account(Account::User(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::Account(Account::Group(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::AcmeProvider(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::ArfExternalReport(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::Directory(Directory::Ldap(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::Directory(Directory::Sql(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::Directory(Directory::Oidc(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DkimSignature(DkimSignature::Dkim1Ed25519Sha256(obj)) => {
                obj.member_tenant_id = Some(id)
            }
            ObjectInner::DkimSignature(DkimSignature::Dkim1RsaSha256(obj)) => {
                obj.member_tenant_id = Some(id)
            }
            ObjectInner::DkimSignature(DkimSignature::Dkim2Ed25519Sha256(obj)) => {
                obj.member_tenant_id = Some(id)
            }
            ObjectInner::DkimSignature(DkimSignature::Dkim2RsaSha256(obj)) => {
                obj.member_tenant_id = Some(id)
            }
            ObjectInner::DmarcExternalReport(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Tsig(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Cloudflare(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::DigitalOcean(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::DeSEC(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Ovh(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Bunny(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Porkbun(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Dnsimple(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Spaceship(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Route53(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::GoogleCloudDns(obj)) => {
                obj.member_tenant_id = Some(id)
            }
            ObjectInner::DnsServer(DnsServer::Alidns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::ArvanCloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Autodns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::AzureDns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::BaiduCloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::BluecatV2(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::ClouDns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Constellix(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Cpanel(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Ddnss(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::DnsMadeEasy(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Domeneshop(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Dreamhost(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::DuckDns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Dynu(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::EasyDns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::EdgeDns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Exoscale(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::FreeMyIp(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::GandiV5(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Gcore(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Glesys(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Godaddy(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Hetzner(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::HostingDe(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Hostinger(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::HuaweiCloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Hurricane(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::IbmCloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Infoblox(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Infomaniak(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Inwx(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Ionos(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Ipv64(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Joker(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Lightsail(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Linode(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::LuaDns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::MythicBeasts(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Namecheap(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::NameDotCom(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::NameSilo(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Netcup(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Netlify(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Nifcloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Ns1(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::OracleCloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Plesk(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Safedns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Scaleway(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::TencentCloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Transip(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::UltraDns(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Vercel(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Volcengine(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::Vultr(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::WebSupport(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::DnsServer(DnsServer::YandexCloud(obj)) => obj.member_tenant_id = Some(id),
            ObjectInner::Domain(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::MailingList(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::OAuthClient(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::Role(obj) => obj.member_tenant_id = Some(id),
            ObjectInner::TlsExternalReport(obj) => obj.member_tenant_id = Some(id),
            _ => {}
        }
    }

    pub fn account_id(&self) -> Option<Id> {
        match self {
            ObjectInner::ArchivedItem(ArchivedItem::Email(obj)) => Some(obj.account_id),
            ObjectInner::ArchivedItem(ArchivedItem::FileNode(obj)) => Some(obj.account_id),
            ObjectInner::ArchivedItem(ArchivedItem::CalendarEvent(obj)) => Some(obj.account_id),
            ObjectInner::ArchivedItem(ArchivedItem::ContactCard(obj)) => Some(obj.account_id),
            ObjectInner::ArchivedItem(ArchivedItem::SieveScript(obj)) => Some(obj.account_id),
            ObjectInner::MaskedEmail(obj) => Some(obj.account_id),
            ObjectInner::PublicKey(obj) => Some(obj.account_id),
            ObjectInner::SpamTrainingSample(obj) => obj.account_id,
            ObjectInner::Task(Task::IndexDocument(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::UnindexDocument(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::CalendarAlarmEmail(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::CalendarAlarmNotification(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::CalendarItipMessage(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::MergeThreads(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::RestoreArchivedItem(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::DestroyAccount(obj)) => Some(obj.account_id),
            ObjectInner::Task(Task::AccountMaintenance(obj)) => Some(obj.account_id),
            _ => None,
        }
    }

    pub fn set_account_id(&mut self, id: Id) {
        match self {
            ObjectInner::ArchivedItem(ArchivedItem::Email(obj)) => obj.account_id = id,
            ObjectInner::ArchivedItem(ArchivedItem::FileNode(obj)) => obj.account_id = id,
            ObjectInner::ArchivedItem(ArchivedItem::CalendarEvent(obj)) => obj.account_id = id,
            ObjectInner::ArchivedItem(ArchivedItem::ContactCard(obj)) => obj.account_id = id,
            ObjectInner::ArchivedItem(ArchivedItem::SieveScript(obj)) => obj.account_id = id,
            ObjectInner::MaskedEmail(obj) => obj.account_id = id,
            ObjectInner::PublicKey(obj) => obj.account_id = id,
            ObjectInner::SpamTrainingSample(obj) => obj.account_id = Some(id),
            ObjectInner::Task(Task::IndexDocument(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::UnindexDocument(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::CalendarAlarmEmail(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::CalendarAlarmNotification(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::CalendarItipMessage(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::MergeThreads(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::RestoreArchivedItem(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::DestroyAccount(obj)) => obj.account_id = id,
            ObjectInner::Task(Task::AccountMaintenance(obj)) => obj.account_id = id,
            _ => {}
        }
    }

    pub fn to_pickled_vec(&self) -> Vec<u8> {
        match &self {
            ObjectInner::Account(obj) => obj.to_pickled_vec(),
            ObjectInner::AccountPassword(obj) => obj.to_pickled_vec(),
            ObjectInner::AccountSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::AcmeProvider(obj) => obj.to_pickled_vec(),
            ObjectInner::Action(obj) => obj.to_pickled_vec(),
            ObjectInner::AddressBook(obj) => obj.to_pickled_vec(),
            ObjectInner::AiModel(obj) => obj.to_pickled_vec(),
            ObjectInner::Alert(obj) => obj.to_pickled_vec(),
            ObjectInner::AllowedIp(obj) => obj.to_pickled_vec(),
            ObjectInner::ApiKey(obj) => obj.to_pickled_vec(),
            ObjectInner::AppPassword(obj) => obj.to_pickled_vec(),
            ObjectInner::Application(obj) => obj.to_pickled_vec(),
            ObjectInner::ArchivedItem(obj) => obj.to_pickled_vec(),
            ObjectInner::ArfExternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::Asn(obj) => obj.to_pickled_vec(),
            ObjectInner::Authentication(obj) => obj.to_pickled_vec(),
            ObjectInner::BlobStore(obj) => obj.to_pickled_vec(),
            ObjectInner::BlockedIp(obj) => obj.to_pickled_vec(),
            ObjectInner::Bootstrap(obj) => obj.to_pickled_vec(),
            ObjectInner::Cache(obj) => obj.to_pickled_vec(),
            ObjectInner::Calendar(obj) => obj.to_pickled_vec(),
            ObjectInner::CalendarAlarm(obj) => obj.to_pickled_vec(),
            ObjectInner::CalendarScheduling(obj) => obj.to_pickled_vec(),
            ObjectInner::Certificate(obj) => obj.to_pickled_vec(),
            ObjectInner::ClusterNode(obj) => obj.to_pickled_vec(),
            ObjectInner::ClusterRole(obj) => obj.to_pickled_vec(),
            ObjectInner::Coordinator(obj) => obj.to_pickled_vec(),
            ObjectInner::DataRetention(obj) => obj.to_pickled_vec(),
            ObjectInner::DataStore(obj) => obj.to_pickled_vec(),
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
            ObjectInner::Enterprise(obj) => obj.to_pickled_vec(),
            ObjectInner::EventTracingLevel(obj) => obj.to_pickled_vec(),
            ObjectInner::FileStorage(obj) => obj.to_pickled_vec(),
            ObjectInner::Http(obj) => obj.to_pickled_vec(),
            ObjectInner::HttpForm(obj) => obj.to_pickled_vec(),
            ObjectInner::HttpLookup(obj) => obj.to_pickled_vec(),
            ObjectInner::Imap(obj) => obj.to_pickled_vec(),
            ObjectInner::InMemoryStore(obj) => obj.to_pickled_vec(),
            ObjectInner::Jmap(obj) => obj.to_pickled_vec(),
            ObjectInner::Log(obj) => obj.to_pickled_vec(),
            ObjectInner::MailingList(obj) => obj.to_pickled_vec(),
            ObjectInner::MaskedEmail(obj) => obj.to_pickled_vec(),
            ObjectInner::MemoryLookupKey(obj) => obj.to_pickled_vec(),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.to_pickled_vec(),
            ObjectInner::Metric(obj) => obj.to_pickled_vec(),
            ObjectInner::Metrics(obj) => obj.to_pickled_vec(),
            ObjectInner::MetricsStore(obj) => obj.to_pickled_vec(),
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
            ObjectInner::OidcProvider(obj) => obj.to_pickled_vec(),
            ObjectInner::PublicKey(obj) => obj.to_pickled_vec(),
            ObjectInner::QueuedMessage(obj) => obj.to_pickled_vec(),
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
            ObjectInner::SpamClassifier(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamDnsblServer(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamDnsblSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamFileExtension(obj) => obj.to_pickled_vec(),
            ObjectInner::SpamLlm(obj) => obj.to_pickled_vec(),
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
            ObjectInner::Tenant(obj) => obj.to_pickled_vec(),
            ObjectInner::TlsExternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::TlsInternalReport(obj) => obj.to_pickled_vec(),
            ObjectInner::TlsReportSettings(obj) => obj.to_pickled_vec(),
            ObjectInner::Trace(obj) => obj.to_pickled_vec(),
            ObjectInner::Tracer(obj) => obj.to_pickled_vec(),
            ObjectInner::TracingStore(obj) => obj.to_pickled_vec(),
            ObjectInner::WebDav(obj) => obj.to_pickled_vec(),
            ObjectInner::WebHook(obj) => obj.to_pickled_vec(),
        }
    }

    pub fn unpickle(
        object: ObjectType,
        stream: &mut crate::pickle::PickledStream<'_>,
    ) -> Option<Self> {
        match object {
            ObjectType::Account => Pickle::unpickle(stream).map(ObjectInner::Account),
            ObjectType::AccountPassword => {
                Pickle::unpickle(stream).map(ObjectInner::AccountPassword)
            }
            ObjectType::AccountSettings => {
                Pickle::unpickle(stream).map(ObjectInner::AccountSettings)
            }
            ObjectType::AcmeProvider => Pickle::unpickle(stream).map(ObjectInner::AcmeProvider),
            ObjectType::Action => Pickle::unpickle(stream).map(ObjectInner::Action),
            ObjectType::AddressBook => Pickle::unpickle(stream).map(ObjectInner::AddressBook),
            ObjectType::AiModel => Pickle::unpickle(stream).map(ObjectInner::AiModel),
            ObjectType::Alert => Pickle::unpickle(stream).map(ObjectInner::Alert),
            ObjectType::AllowedIp => Pickle::unpickle(stream).map(ObjectInner::AllowedIp),
            ObjectType::ApiKey => Pickle::unpickle(stream).map(ObjectInner::ApiKey),
            ObjectType::AppPassword => Pickle::unpickle(stream).map(ObjectInner::AppPassword),
            ObjectType::Application => Pickle::unpickle(stream).map(ObjectInner::Application),
            ObjectType::ArchivedItem => Pickle::unpickle(stream).map(ObjectInner::ArchivedItem),
            ObjectType::ArfExternalReport => {
                Pickle::unpickle(stream).map(ObjectInner::ArfExternalReport)
            }
            ObjectType::Asn => Pickle::unpickle(stream).map(ObjectInner::Asn),
            ObjectType::Authentication => Pickle::unpickle(stream).map(ObjectInner::Authentication),
            ObjectType::BlobStore => Pickle::unpickle(stream).map(ObjectInner::BlobStore),
            ObjectType::BlockedIp => Pickle::unpickle(stream).map(ObjectInner::BlockedIp),
            ObjectType::Bootstrap => Pickle::unpickle(stream).map(ObjectInner::Bootstrap),
            ObjectType::Cache => Pickle::unpickle(stream).map(ObjectInner::Cache),
            ObjectType::Calendar => Pickle::unpickle(stream).map(ObjectInner::Calendar),
            ObjectType::CalendarAlarm => Pickle::unpickle(stream).map(ObjectInner::CalendarAlarm),
            ObjectType::CalendarScheduling => {
                Pickle::unpickle(stream).map(ObjectInner::CalendarScheduling)
            }
            ObjectType::Certificate => Pickle::unpickle(stream).map(ObjectInner::Certificate),
            ObjectType::ClusterNode => Pickle::unpickle(stream).map(ObjectInner::ClusterNode),
            ObjectType::ClusterRole => Pickle::unpickle(stream).map(ObjectInner::ClusterRole),
            ObjectType::Coordinator => Pickle::unpickle(stream).map(ObjectInner::Coordinator),
            ObjectType::DataRetention => Pickle::unpickle(stream).map(ObjectInner::DataRetention),
            ObjectType::DataStore => Pickle::unpickle(stream).map(ObjectInner::DataStore),
            ObjectType::Directory => Pickle::unpickle(stream).map(ObjectInner::Directory),
            ObjectType::DkimReportSettings => {
                Pickle::unpickle(stream).map(ObjectInner::DkimReportSettings)
            }
            ObjectType::DkimSignature => Pickle::unpickle(stream).map(ObjectInner::DkimSignature),
            ObjectType::DmarcExternalReport => {
                Pickle::unpickle(stream).map(ObjectInner::DmarcExternalReport)
            }
            ObjectType::DmarcInternalReport => {
                Pickle::unpickle(stream).map(ObjectInner::DmarcInternalReport)
            }
            ObjectType::DmarcReportSettings => {
                Pickle::unpickle(stream).map(ObjectInner::DmarcReportSettings)
            }
            ObjectType::DnsResolver => Pickle::unpickle(stream).map(ObjectInner::DnsResolver),
            ObjectType::DnsServer => Pickle::unpickle(stream).map(ObjectInner::DnsServer),
            ObjectType::Domain => Pickle::unpickle(stream).map(ObjectInner::Domain),
            ObjectType::DsnReportSettings => {
                Pickle::unpickle(stream).map(ObjectInner::DsnReportSettings)
            }
            ObjectType::Email => Pickle::unpickle(stream).map(ObjectInner::Email),
            ObjectType::Enterprise => Pickle::unpickle(stream).map(ObjectInner::Enterprise),
            ObjectType::EventTracingLevel => {
                Pickle::unpickle(stream).map(ObjectInner::EventTracingLevel)
            }
            ObjectType::FileStorage => Pickle::unpickle(stream).map(ObjectInner::FileStorage),
            ObjectType::Http => Pickle::unpickle(stream).map(ObjectInner::Http),
            ObjectType::HttpForm => Pickle::unpickle(stream).map(ObjectInner::HttpForm),
            ObjectType::HttpLookup => Pickle::unpickle(stream).map(ObjectInner::HttpLookup),
            ObjectType::Imap => Pickle::unpickle(stream).map(ObjectInner::Imap),
            ObjectType::InMemoryStore => Pickle::unpickle(stream).map(ObjectInner::InMemoryStore),
            ObjectType::Jmap => Pickle::unpickle(stream).map(ObjectInner::Jmap),
            ObjectType::Log => Pickle::unpickle(stream).map(ObjectInner::Log),
            ObjectType::MailingList => Pickle::unpickle(stream).map(ObjectInner::MailingList),
            ObjectType::MaskedEmail => Pickle::unpickle(stream).map(ObjectInner::MaskedEmail),
            ObjectType::MemoryLookupKey => {
                Pickle::unpickle(stream).map(ObjectInner::MemoryLookupKey)
            }
            ObjectType::MemoryLookupKeyValue => {
                Pickle::unpickle(stream).map(ObjectInner::MemoryLookupKeyValue)
            }
            ObjectType::Metric => Pickle::unpickle(stream).map(ObjectInner::Metric),
            ObjectType::Metrics => Pickle::unpickle(stream).map(ObjectInner::Metrics),
            ObjectType::MetricsStore => Pickle::unpickle(stream).map(ObjectInner::MetricsStore),
            ObjectType::MtaConnectionStrategy => {
                Pickle::unpickle(stream).map(ObjectInner::MtaConnectionStrategy)
            }
            ObjectType::MtaDeliverySchedule => {
                Pickle::unpickle(stream).map(ObjectInner::MtaDeliverySchedule)
            }
            ObjectType::MtaExtensions => Pickle::unpickle(stream).map(ObjectInner::MtaExtensions),
            ObjectType::MtaHook => Pickle::unpickle(stream).map(ObjectInner::MtaHook),
            ObjectType::MtaInboundSession => {
                Pickle::unpickle(stream).map(ObjectInner::MtaInboundSession)
            }
            ObjectType::MtaInboundThrottle => {
                Pickle::unpickle(stream).map(ObjectInner::MtaInboundThrottle)
            }
            ObjectType::MtaMilter => Pickle::unpickle(stream).map(ObjectInner::MtaMilter),
            ObjectType::MtaOutboundStrategy => {
                Pickle::unpickle(stream).map(ObjectInner::MtaOutboundStrategy)
            }
            ObjectType::MtaOutboundThrottle => {
                Pickle::unpickle(stream).map(ObjectInner::MtaOutboundThrottle)
            }
            ObjectType::MtaQueueQuota => Pickle::unpickle(stream).map(ObjectInner::MtaQueueQuota),
            ObjectType::MtaRoute => Pickle::unpickle(stream).map(ObjectInner::MtaRoute),
            ObjectType::MtaStageAuth => Pickle::unpickle(stream).map(ObjectInner::MtaStageAuth),
            ObjectType::MtaStageConnect => {
                Pickle::unpickle(stream).map(ObjectInner::MtaStageConnect)
            }
            ObjectType::MtaStageData => Pickle::unpickle(stream).map(ObjectInner::MtaStageData),
            ObjectType::MtaStageEhlo => Pickle::unpickle(stream).map(ObjectInner::MtaStageEhlo),
            ObjectType::MtaStageMail => Pickle::unpickle(stream).map(ObjectInner::MtaStageMail),
            ObjectType::MtaStageRcpt => Pickle::unpickle(stream).map(ObjectInner::MtaStageRcpt),
            ObjectType::MtaSts => Pickle::unpickle(stream).map(ObjectInner::MtaSts),
            ObjectType::MtaTlsStrategy => Pickle::unpickle(stream).map(ObjectInner::MtaTlsStrategy),
            ObjectType::MtaVirtualQueue => {
                Pickle::unpickle(stream).map(ObjectInner::MtaVirtualQueue)
            }
            ObjectType::NetworkListener => {
                Pickle::unpickle(stream).map(ObjectInner::NetworkListener)
            }
            ObjectType::OAuthClient => Pickle::unpickle(stream).map(ObjectInner::OAuthClient),
            ObjectType::OidcProvider => Pickle::unpickle(stream).map(ObjectInner::OidcProvider),
            ObjectType::PublicKey => Pickle::unpickle(stream).map(ObjectInner::PublicKey),
            ObjectType::QueuedMessage => Pickle::unpickle(stream).map(ObjectInner::QueuedMessage),
            ObjectType::ReportSettings => Pickle::unpickle(stream).map(ObjectInner::ReportSettings),
            ObjectType::Role => Pickle::unpickle(stream).map(ObjectInner::Role),
            ObjectType::Search => Pickle::unpickle(stream).map(ObjectInner::Search),
            ObjectType::SearchStore => Pickle::unpickle(stream).map(ObjectInner::SearchStore),
            ObjectType::Security => Pickle::unpickle(stream).map(ObjectInner::Security),
            ObjectType::SenderAuth => Pickle::unpickle(stream).map(ObjectInner::SenderAuth),
            ObjectType::Sharing => Pickle::unpickle(stream).map(ObjectInner::Sharing),
            ObjectType::SieveSystemInterpreter => {
                Pickle::unpickle(stream).map(ObjectInner::SieveSystemInterpreter)
            }
            ObjectType::SieveSystemScript => {
                Pickle::unpickle(stream).map(ObjectInner::SieveSystemScript)
            }
            ObjectType::SieveUserInterpreter => {
                Pickle::unpickle(stream).map(ObjectInner::SieveUserInterpreter)
            }
            ObjectType::SieveUserScript => {
                Pickle::unpickle(stream).map(ObjectInner::SieveUserScript)
            }
            ObjectType::SpamClassifier => Pickle::unpickle(stream).map(ObjectInner::SpamClassifier),
            ObjectType::SpamDnsblServer => {
                Pickle::unpickle(stream).map(ObjectInner::SpamDnsblServer)
            }
            ObjectType::SpamDnsblSettings => {
                Pickle::unpickle(stream).map(ObjectInner::SpamDnsblSettings)
            }
            ObjectType::SpamFileExtension => {
                Pickle::unpickle(stream).map(ObjectInner::SpamFileExtension)
            }
            ObjectType::SpamLlm => Pickle::unpickle(stream).map(ObjectInner::SpamLlm),
            ObjectType::SpamPyzor => Pickle::unpickle(stream).map(ObjectInner::SpamPyzor),
            ObjectType::SpamRule => Pickle::unpickle(stream).map(ObjectInner::SpamRule),
            ObjectType::SpamSettings => Pickle::unpickle(stream).map(ObjectInner::SpamSettings),
            ObjectType::SpamTag => Pickle::unpickle(stream).map(ObjectInner::SpamTag),
            ObjectType::SpamTrainingSample => {
                Pickle::unpickle(stream).map(ObjectInner::SpamTrainingSample)
            }
            ObjectType::SpfReportSettings => {
                Pickle::unpickle(stream).map(ObjectInner::SpfReportSettings)
            }
            ObjectType::StoreLookup => Pickle::unpickle(stream).map(ObjectInner::StoreLookup),
            ObjectType::SystemSettings => Pickle::unpickle(stream).map(ObjectInner::SystemSettings),
            ObjectType::Task => Pickle::unpickle(stream).map(ObjectInner::Task),
            ObjectType::TaskManager => Pickle::unpickle(stream).map(ObjectInner::TaskManager),
            ObjectType::Tenant => Pickle::unpickle(stream).map(ObjectInner::Tenant),
            ObjectType::TlsExternalReport => {
                Pickle::unpickle(stream).map(ObjectInner::TlsExternalReport)
            }
            ObjectType::TlsInternalReport => {
                Pickle::unpickle(stream).map(ObjectInner::TlsInternalReport)
            }
            ObjectType::TlsReportSettings => {
                Pickle::unpickle(stream).map(ObjectInner::TlsReportSettings)
            }
            ObjectType::Trace => Pickle::unpickle(stream).map(ObjectInner::Trace),
            ObjectType::Tracer => Pickle::unpickle(stream).map(ObjectInner::Tracer),
            ObjectType::TracingStore => Pickle::unpickle(stream).map(ObjectInner::TracingStore),
            ObjectType::WebDav => Pickle::unpickle(stream).map(ObjectInner::WebDav),
            ObjectType::WebHook => Pickle::unpickle(stream).map(ObjectInner::WebHook),
        }
    }

    pub fn deserialize<'de, D>(object: ObjectType, deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match object {
            ObjectType::Account => Account::deserialize(deserializer).map(ObjectInner::Account),
            ObjectType::AccountPassword => {
                AccountPassword::deserialize(deserializer).map(ObjectInner::AccountPassword)
            }
            ObjectType::AccountSettings => {
                AccountSettings::deserialize(deserializer).map(ObjectInner::AccountSettings)
            }
            ObjectType::AcmeProvider => {
                AcmeProvider::deserialize(deserializer).map(ObjectInner::AcmeProvider)
            }
            ObjectType::Action => Action::deserialize(deserializer).map(ObjectInner::Action),
            ObjectType::AddressBook => {
                AddressBook::deserialize(deserializer).map(ObjectInner::AddressBook)
            }
            ObjectType::AiModel => AiModel::deserialize(deserializer).map(ObjectInner::AiModel),
            ObjectType::Alert => Alert::deserialize(deserializer).map(ObjectInner::Alert),
            ObjectType::AllowedIp => {
                AllowedIp::deserialize(deserializer).map(ObjectInner::AllowedIp)
            }
            ObjectType::ApiKey => ApiKey::deserialize(deserializer).map(ObjectInner::ApiKey),
            ObjectType::AppPassword => {
                AppPassword::deserialize(deserializer).map(ObjectInner::AppPassword)
            }
            ObjectType::Application => {
                Application::deserialize(deserializer).map(ObjectInner::Application)
            }
            ObjectType::ArchivedItem => {
                ArchivedItem::deserialize(deserializer).map(ObjectInner::ArchivedItem)
            }
            ObjectType::ArfExternalReport => {
                ArfExternalReport::deserialize(deserializer).map(ObjectInner::ArfExternalReport)
            }
            ObjectType::Asn => Asn::deserialize(deserializer).map(ObjectInner::Asn),
            ObjectType::Authentication => {
                Authentication::deserialize(deserializer).map(ObjectInner::Authentication)
            }
            ObjectType::BlobStore => {
                BlobStore::deserialize(deserializer).map(ObjectInner::BlobStore)
            }
            ObjectType::BlockedIp => {
                BlockedIp::deserialize(deserializer).map(ObjectInner::BlockedIp)
            }
            ObjectType::Bootstrap => {
                Bootstrap::deserialize(deserializer).map(ObjectInner::Bootstrap)
            }
            ObjectType::Cache => Cache::deserialize(deserializer).map(ObjectInner::Cache),
            ObjectType::Calendar => Calendar::deserialize(deserializer).map(ObjectInner::Calendar),
            ObjectType::CalendarAlarm => {
                CalendarAlarm::deserialize(deserializer).map(ObjectInner::CalendarAlarm)
            }
            ObjectType::CalendarScheduling => {
                CalendarScheduling::deserialize(deserializer).map(ObjectInner::CalendarScheduling)
            }
            ObjectType::Certificate => {
                Certificate::deserialize(deserializer).map(ObjectInner::Certificate)
            }
            ObjectType::ClusterNode => {
                ClusterNode::deserialize(deserializer).map(ObjectInner::ClusterNode)
            }
            ObjectType::ClusterRole => {
                ClusterRole::deserialize(deserializer).map(ObjectInner::ClusterRole)
            }
            ObjectType::Coordinator => {
                Coordinator::deserialize(deserializer).map(ObjectInner::Coordinator)
            }
            ObjectType::DataRetention => {
                DataRetention::deserialize(deserializer).map(ObjectInner::DataRetention)
            }
            ObjectType::DataStore => {
                DataStore::deserialize(deserializer).map(ObjectInner::DataStore)
            }
            ObjectType::Directory => {
                Directory::deserialize(deserializer).map(ObjectInner::Directory)
            }
            ObjectType::DkimReportSettings => {
                DkimReportSettings::deserialize(deserializer).map(ObjectInner::DkimReportSettings)
            }
            ObjectType::DkimSignature => {
                DkimSignature::deserialize(deserializer).map(ObjectInner::DkimSignature)
            }
            ObjectType::DmarcExternalReport => {
                DmarcExternalReport::deserialize(deserializer).map(ObjectInner::DmarcExternalReport)
            }
            ObjectType::DmarcInternalReport => {
                DmarcInternalReport::deserialize(deserializer).map(ObjectInner::DmarcInternalReport)
            }
            ObjectType::DmarcReportSettings => {
                DmarcReportSettings::deserialize(deserializer).map(ObjectInner::DmarcReportSettings)
            }
            ObjectType::DnsResolver => {
                DnsResolver::deserialize(deserializer).map(ObjectInner::DnsResolver)
            }
            ObjectType::DnsServer => {
                DnsServer::deserialize(deserializer).map(ObjectInner::DnsServer)
            }
            ObjectType::Domain => Domain::deserialize(deserializer).map(ObjectInner::Domain),
            ObjectType::DsnReportSettings => {
                DsnReportSettings::deserialize(deserializer).map(ObjectInner::DsnReportSettings)
            }
            ObjectType::Email => Email::deserialize(deserializer).map(ObjectInner::Email),
            ObjectType::Enterprise => {
                Enterprise::deserialize(deserializer).map(ObjectInner::Enterprise)
            }
            ObjectType::EventTracingLevel => {
                EventTracingLevel::deserialize(deserializer).map(ObjectInner::EventTracingLevel)
            }
            ObjectType::FileStorage => {
                FileStorage::deserialize(deserializer).map(ObjectInner::FileStorage)
            }
            ObjectType::Http => Http::deserialize(deserializer).map(ObjectInner::Http),
            ObjectType::HttpForm => HttpForm::deserialize(deserializer).map(ObjectInner::HttpForm),
            ObjectType::HttpLookup => {
                HttpLookup::deserialize(deserializer).map(ObjectInner::HttpLookup)
            }
            ObjectType::Imap => Imap::deserialize(deserializer).map(ObjectInner::Imap),
            ObjectType::InMemoryStore => {
                InMemoryStore::deserialize(deserializer).map(ObjectInner::InMemoryStore)
            }
            ObjectType::Jmap => Jmap::deserialize(deserializer).map(ObjectInner::Jmap),
            ObjectType::Log => Log::deserialize(deserializer).map(ObjectInner::Log),
            ObjectType::MailingList => {
                MailingList::deserialize(deserializer).map(ObjectInner::MailingList)
            }
            ObjectType::MaskedEmail => {
                MaskedEmail::deserialize(deserializer).map(ObjectInner::MaskedEmail)
            }
            ObjectType::MemoryLookupKey => {
                MemoryLookupKey::deserialize(deserializer).map(ObjectInner::MemoryLookupKey)
            }
            ObjectType::MemoryLookupKeyValue => MemoryLookupKeyValue::deserialize(deserializer)
                .map(ObjectInner::MemoryLookupKeyValue),
            ObjectType::Metric => Metric::deserialize(deserializer).map(ObjectInner::Metric),
            ObjectType::Metrics => Metrics::deserialize(deserializer).map(ObjectInner::Metrics),
            ObjectType::MetricsStore => {
                MetricsStore::deserialize(deserializer).map(ObjectInner::MetricsStore)
            }
            ObjectType::MtaConnectionStrategy => MtaConnectionStrategy::deserialize(deserializer)
                .map(ObjectInner::MtaConnectionStrategy),
            ObjectType::MtaDeliverySchedule => {
                MtaDeliverySchedule::deserialize(deserializer).map(ObjectInner::MtaDeliverySchedule)
            }
            ObjectType::MtaExtensions => {
                MtaExtensions::deserialize(deserializer).map(ObjectInner::MtaExtensions)
            }
            ObjectType::MtaHook => MtaHook::deserialize(deserializer).map(ObjectInner::MtaHook),
            ObjectType::MtaInboundSession => {
                MtaInboundSession::deserialize(deserializer).map(ObjectInner::MtaInboundSession)
            }
            ObjectType::MtaInboundThrottle => {
                MtaInboundThrottle::deserialize(deserializer).map(ObjectInner::MtaInboundThrottle)
            }
            ObjectType::MtaMilter => {
                MtaMilter::deserialize(deserializer).map(ObjectInner::MtaMilter)
            }
            ObjectType::MtaOutboundStrategy => {
                MtaOutboundStrategy::deserialize(deserializer).map(ObjectInner::MtaOutboundStrategy)
            }
            ObjectType::MtaOutboundThrottle => {
                MtaOutboundThrottle::deserialize(deserializer).map(ObjectInner::MtaOutboundThrottle)
            }
            ObjectType::MtaQueueQuota => {
                MtaQueueQuota::deserialize(deserializer).map(ObjectInner::MtaQueueQuota)
            }
            ObjectType::MtaRoute => MtaRoute::deserialize(deserializer).map(ObjectInner::MtaRoute),
            ObjectType::MtaStageAuth => {
                MtaStageAuth::deserialize(deserializer).map(ObjectInner::MtaStageAuth)
            }
            ObjectType::MtaStageConnect => {
                MtaStageConnect::deserialize(deserializer).map(ObjectInner::MtaStageConnect)
            }
            ObjectType::MtaStageData => {
                MtaStageData::deserialize(deserializer).map(ObjectInner::MtaStageData)
            }
            ObjectType::MtaStageEhlo => {
                MtaStageEhlo::deserialize(deserializer).map(ObjectInner::MtaStageEhlo)
            }
            ObjectType::MtaStageMail => {
                MtaStageMail::deserialize(deserializer).map(ObjectInner::MtaStageMail)
            }
            ObjectType::MtaStageRcpt => {
                MtaStageRcpt::deserialize(deserializer).map(ObjectInner::MtaStageRcpt)
            }
            ObjectType::MtaSts => MtaSts::deserialize(deserializer).map(ObjectInner::MtaSts),
            ObjectType::MtaTlsStrategy => {
                MtaTlsStrategy::deserialize(deserializer).map(ObjectInner::MtaTlsStrategy)
            }
            ObjectType::MtaVirtualQueue => {
                MtaVirtualQueue::deserialize(deserializer).map(ObjectInner::MtaVirtualQueue)
            }
            ObjectType::NetworkListener => {
                NetworkListener::deserialize(deserializer).map(ObjectInner::NetworkListener)
            }
            ObjectType::OAuthClient => {
                OAuthClient::deserialize(deserializer).map(ObjectInner::OAuthClient)
            }
            ObjectType::OidcProvider => {
                OidcProvider::deserialize(deserializer).map(ObjectInner::OidcProvider)
            }
            ObjectType::PublicKey => {
                PublicKey::deserialize(deserializer).map(ObjectInner::PublicKey)
            }
            ObjectType::QueuedMessage => {
                QueuedMessage::deserialize(deserializer).map(ObjectInner::QueuedMessage)
            }
            ObjectType::ReportSettings => {
                ReportSettings::deserialize(deserializer).map(ObjectInner::ReportSettings)
            }
            ObjectType::Role => Role::deserialize(deserializer).map(ObjectInner::Role),
            ObjectType::Search => Search::deserialize(deserializer).map(ObjectInner::Search),
            ObjectType::SearchStore => {
                SearchStore::deserialize(deserializer).map(ObjectInner::SearchStore)
            }
            ObjectType::Security => Security::deserialize(deserializer).map(ObjectInner::Security),
            ObjectType::SenderAuth => {
                SenderAuth::deserialize(deserializer).map(ObjectInner::SenderAuth)
            }
            ObjectType::Sharing => Sharing::deserialize(deserializer).map(ObjectInner::Sharing),
            ObjectType::SieveSystemInterpreter => SieveSystemInterpreter::deserialize(deserializer)
                .map(ObjectInner::SieveSystemInterpreter),
            ObjectType::SieveSystemScript => {
                SieveSystemScript::deserialize(deserializer).map(ObjectInner::SieveSystemScript)
            }
            ObjectType::SieveUserInterpreter => SieveUserInterpreter::deserialize(deserializer)
                .map(ObjectInner::SieveUserInterpreter),
            ObjectType::SieveUserScript => {
                SieveUserScript::deserialize(deserializer).map(ObjectInner::SieveUserScript)
            }
            ObjectType::SpamClassifier => {
                SpamClassifier::deserialize(deserializer).map(ObjectInner::SpamClassifier)
            }
            ObjectType::SpamDnsblServer => {
                SpamDnsblServer::deserialize(deserializer).map(ObjectInner::SpamDnsblServer)
            }
            ObjectType::SpamDnsblSettings => {
                SpamDnsblSettings::deserialize(deserializer).map(ObjectInner::SpamDnsblSettings)
            }
            ObjectType::SpamFileExtension => {
                SpamFileExtension::deserialize(deserializer).map(ObjectInner::SpamFileExtension)
            }
            ObjectType::SpamLlm => SpamLlm::deserialize(deserializer).map(ObjectInner::SpamLlm),
            ObjectType::SpamPyzor => {
                SpamPyzor::deserialize(deserializer).map(ObjectInner::SpamPyzor)
            }
            ObjectType::SpamRule => SpamRule::deserialize(deserializer).map(ObjectInner::SpamRule),
            ObjectType::SpamSettings => {
                SpamSettings::deserialize(deserializer).map(ObjectInner::SpamSettings)
            }
            ObjectType::SpamTag => SpamTag::deserialize(deserializer).map(ObjectInner::SpamTag),
            ObjectType::SpamTrainingSample => {
                SpamTrainingSample::deserialize(deserializer).map(ObjectInner::SpamTrainingSample)
            }
            ObjectType::SpfReportSettings => {
                SpfReportSettings::deserialize(deserializer).map(ObjectInner::SpfReportSettings)
            }
            ObjectType::StoreLookup => {
                StoreLookup::deserialize(deserializer).map(ObjectInner::StoreLookup)
            }
            ObjectType::SystemSettings => {
                SystemSettings::deserialize(deserializer).map(ObjectInner::SystemSettings)
            }
            ObjectType::Task => Task::deserialize(deserializer).map(ObjectInner::Task),
            ObjectType::TaskManager => {
                TaskManager::deserialize(deserializer).map(ObjectInner::TaskManager)
            }
            ObjectType::Tenant => Tenant::deserialize(deserializer).map(ObjectInner::Tenant),
            ObjectType::TlsExternalReport => {
                TlsExternalReport::deserialize(deserializer).map(ObjectInner::TlsExternalReport)
            }
            ObjectType::TlsInternalReport => {
                TlsInternalReport::deserialize(deserializer).map(ObjectInner::TlsInternalReport)
            }
            ObjectType::TlsReportSettings => {
                TlsReportSettings::deserialize(deserializer).map(ObjectInner::TlsReportSettings)
            }
            ObjectType::Trace => Trace::deserialize(deserializer).map(ObjectInner::Trace),
            ObjectType::Tracer => Tracer::deserialize(deserializer).map(ObjectInner::Tracer),
            ObjectType::TracingStore => {
                TracingStore::deserialize(deserializer).map(ObjectInner::TracingStore)
            }
            ObjectType::WebDav => WebDav::deserialize(deserializer).map(ObjectInner::WebDav),
            ObjectType::WebHook => WebHook::deserialize(deserializer).map(ObjectInner::WebHook),
        }
    }

    pub fn expression_ctxs(&self) -> Option<Vec<ExpressionContext<'_>>> {
        match &self {
            ObjectInner::Alert(obj) => Some(obj.expression_ctxs()),
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
            ObjectInner::AiModel(_) => AiModel::FLAGS,
            ObjectInner::Alert(_) => Alert::FLAGS,
            ObjectInner::AllowedIp(_) => AllowedIp::FLAGS,
            ObjectInner::ApiKey(_) => ApiKey::FLAGS,
            ObjectInner::AppPassword(_) => AppPassword::FLAGS,
            ObjectInner::Application(_) => Application::FLAGS,
            ObjectInner::ArchivedItem(_) => ArchivedItem::FLAGS,
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
            ObjectInner::Enterprise(_) => Enterprise::FLAGS,
            ObjectInner::EventTracingLevel(_) => EventTracingLevel::FLAGS,
            ObjectInner::FileStorage(_) => FileStorage::FLAGS,
            ObjectInner::Http(_) => Http::FLAGS,
            ObjectInner::HttpForm(_) => HttpForm::FLAGS,
            ObjectInner::HttpLookup(_) => HttpLookup::FLAGS,
            ObjectInner::Imap(_) => Imap::FLAGS,
            ObjectInner::InMemoryStore(_) => InMemoryStore::FLAGS,
            ObjectInner::Jmap(_) => Jmap::FLAGS,
            ObjectInner::Log(_) => Log::FLAGS,
            ObjectInner::MailingList(_) => MailingList::FLAGS,
            ObjectInner::MaskedEmail(_) => MaskedEmail::FLAGS,
            ObjectInner::MemoryLookupKey(_) => MemoryLookupKey::FLAGS,
            ObjectInner::MemoryLookupKeyValue(_) => MemoryLookupKeyValue::FLAGS,
            ObjectInner::Metric(_) => Metric::FLAGS,
            ObjectInner::Metrics(_) => Metrics::FLAGS,
            ObjectInner::MetricsStore(_) => MetricsStore::FLAGS,
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
            ObjectInner::SpamClassifier(_) => SpamClassifier::FLAGS,
            ObjectInner::SpamDnsblServer(_) => SpamDnsblServer::FLAGS,
            ObjectInner::SpamDnsblSettings(_) => SpamDnsblSettings::FLAGS,
            ObjectInner::SpamFileExtension(_) => SpamFileExtension::FLAGS,
            ObjectInner::SpamLlm(_) => SpamLlm::FLAGS,
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
            ObjectInner::Tenant(_) => Tenant::FLAGS,
            ObjectInner::TlsExternalReport(_) => TlsExternalReport::FLAGS,
            ObjectInner::TlsInternalReport(_) => TlsInternalReport::FLAGS,
            ObjectInner::TlsReportSettings(_) => TlsReportSettings::FLAGS,
            ObjectInner::Trace(_) => Trace::FLAGS,
            ObjectInner::Tracer(_) => Tracer::FLAGS,
            ObjectInner::TracingStore(_) => TracingStore::FLAGS,
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
            ObjectInner::AiModel(_) => ObjectType::AiModel,
            ObjectInner::Alert(_) => ObjectType::Alert,
            ObjectInner::AllowedIp(_) => ObjectType::AllowedIp,
            ObjectInner::ApiKey(_) => ObjectType::ApiKey,
            ObjectInner::AppPassword(_) => ObjectType::AppPassword,
            ObjectInner::Application(_) => ObjectType::Application,
            ObjectInner::ArchivedItem(_) => ObjectType::ArchivedItem,
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
            ObjectInner::Enterprise(_) => ObjectType::Enterprise,
            ObjectInner::EventTracingLevel(_) => ObjectType::EventTracingLevel,
            ObjectInner::FileStorage(_) => ObjectType::FileStorage,
            ObjectInner::Http(_) => ObjectType::Http,
            ObjectInner::HttpForm(_) => ObjectType::HttpForm,
            ObjectInner::HttpLookup(_) => ObjectType::HttpLookup,
            ObjectInner::Imap(_) => ObjectType::Imap,
            ObjectInner::InMemoryStore(_) => ObjectType::InMemoryStore,
            ObjectInner::Jmap(_) => ObjectType::Jmap,
            ObjectInner::Log(_) => ObjectType::Log,
            ObjectInner::MailingList(_) => ObjectType::MailingList,
            ObjectInner::MaskedEmail(_) => ObjectType::MaskedEmail,
            ObjectInner::MemoryLookupKey(_) => ObjectType::MemoryLookupKey,
            ObjectInner::MemoryLookupKeyValue(_) => ObjectType::MemoryLookupKeyValue,
            ObjectInner::Metric(_) => ObjectType::Metric,
            ObjectInner::Metrics(_) => ObjectType::Metrics,
            ObjectInner::MetricsStore(_) => ObjectType::MetricsStore,
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
            ObjectInner::SpamClassifier(_) => ObjectType::SpamClassifier,
            ObjectInner::SpamDnsblServer(_) => ObjectType::SpamDnsblServer,
            ObjectInner::SpamDnsblSettings(_) => ObjectType::SpamDnsblSettings,
            ObjectInner::SpamFileExtension(_) => ObjectType::SpamFileExtension,
            ObjectInner::SpamLlm(_) => ObjectType::SpamLlm,
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
            ObjectInner::Tenant(_) => ObjectType::Tenant,
            ObjectInner::TlsExternalReport(_) => ObjectType::TlsExternalReport,
            ObjectInner::TlsInternalReport(_) => ObjectType::TlsInternalReport,
            ObjectInner::TlsReportSettings(_) => ObjectType::TlsReportSettings,
            ObjectInner::Trace(_) => ObjectType::Trace,
            ObjectInner::Tracer(_) => ObjectType::Tracer,
            ObjectInner::TracingStore(_) => ObjectType::TracingStore,
            ObjectInner::WebDav(_) => ObjectType::WebDav,
            ObjectInner::WebHook(_) => ObjectType::WebHook,
        }
    }

    pub fn object_variant(&self) -> Option<&'static str> {
        match &self.inner {
            ObjectInner::Account(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Action(obj) => Some(obj.object_type().as_str()),
            ObjectInner::ArchivedItem(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Asn(obj) => Some(obj.object_type().as_str()),
            ObjectInner::BlobStore(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Coordinator(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DataStore(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Directory(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DkimSignature(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DnsResolver(obj) => Some(obj.object_type().as_str()),
            ObjectInner::DnsServer(obj) => Some(obj.object_type().as_str()),
            ObjectInner::InMemoryStore(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Metric(obj) => Some(obj.object_type().as_str()),
            ObjectInner::MetricsStore(obj) => Some(obj.object_type().as_str()),
            ObjectInner::MtaRoute(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SearchStore(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SpamDnsblServer(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SpamLlm(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SpamRule(obj) => Some(obj.object_type().as_str()),
            ObjectInner::SpamTag(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Task(obj) => Some(obj.object_type().as_str()),
            ObjectInner::Tracer(obj) => Some(obj.object_type().as_str()),
            ObjectInner::TracingStore(obj) => Some(obj.object_type().as_str()),
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
            ObjectInner::AiModel(obj) => obj.validate(errors),
            ObjectInner::Alert(obj) => obj.validate(errors),
            ObjectInner::AllowedIp(obj) => obj.validate(errors),
            ObjectInner::ApiKey(obj) => obj.validate(errors),
            ObjectInner::AppPassword(obj) => obj.validate(errors),
            ObjectInner::Application(obj) => obj.validate(errors),
            ObjectInner::ArchivedItem(obj) => obj.validate(errors),
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
            ObjectInner::Enterprise(obj) => obj.validate(errors),
            ObjectInner::EventTracingLevel(obj) => obj.validate(errors),
            ObjectInner::FileStorage(obj) => obj.validate(errors),
            ObjectInner::Http(obj) => obj.validate(errors),
            ObjectInner::HttpForm(obj) => obj.validate(errors),
            ObjectInner::HttpLookup(obj) => obj.validate(errors),
            ObjectInner::Imap(obj) => obj.validate(errors),
            ObjectInner::InMemoryStore(obj) => obj.validate(errors),
            ObjectInner::Jmap(obj) => obj.validate(errors),
            ObjectInner::Log(obj) => obj.validate(errors),
            ObjectInner::MailingList(obj) => obj.validate(errors),
            ObjectInner::MaskedEmail(obj) => obj.validate(errors),
            ObjectInner::MemoryLookupKey(obj) => obj.validate(errors),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.validate(errors),
            ObjectInner::Metric(obj) => obj.validate(errors),
            ObjectInner::Metrics(obj) => obj.validate(errors),
            ObjectInner::MetricsStore(obj) => obj.validate(errors),
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
            ObjectInner::SpamClassifier(obj) => obj.validate(errors),
            ObjectInner::SpamDnsblServer(obj) => obj.validate(errors),
            ObjectInner::SpamDnsblSettings(obj) => obj.validate(errors),
            ObjectInner::SpamFileExtension(obj) => obj.validate(errors),
            ObjectInner::SpamLlm(obj) => obj.validate(errors),
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
            ObjectInner::Tenant(obj) => obj.validate(errors),
            ObjectInner::TlsExternalReport(obj) => obj.validate(errors),
            ObjectInner::TlsInternalReport(obj) => obj.validate(errors),
            ObjectInner::TlsReportSettings(obj) => obj.validate(errors),
            ObjectInner::Trace(obj) => obj.validate(errors),
            ObjectInner::Tracer(obj) => obj.validate(errors),
            ObjectInner::TracingStore(obj) => obj.validate(errors),
            ObjectInner::WebDav(obj) => obj.validate(errors),
            ObjectInner::WebHook(obj) => obj.validate(errors),
        }
    }

    pub fn index<'x>(&'x self, i: &mut IndexBuilder<'x>) {
        match &self.inner {
            ObjectInner::Account(obj) => obj.index(i),
            ObjectInner::AccountPassword(obj) => obj.index(i),
            ObjectInner::AccountSettings(obj) => obj.index(i),
            ObjectInner::AcmeProvider(obj) => obj.index(i),
            ObjectInner::Action(obj) => obj.index(i),
            ObjectInner::AddressBook(obj) => obj.index(i),
            ObjectInner::AiModel(obj) => obj.index(i),
            ObjectInner::Alert(obj) => obj.index(i),
            ObjectInner::AllowedIp(obj) => obj.index(i),
            ObjectInner::ApiKey(obj) => obj.index(i),
            ObjectInner::AppPassword(obj) => obj.index(i),
            ObjectInner::Application(obj) => obj.index(i),
            ObjectInner::ArchivedItem(obj) => obj.index(i),
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
            ObjectInner::Enterprise(obj) => obj.index(i),
            ObjectInner::EventTracingLevel(obj) => obj.index(i),
            ObjectInner::FileStorage(obj) => obj.index(i),
            ObjectInner::Http(obj) => obj.index(i),
            ObjectInner::HttpForm(obj) => obj.index(i),
            ObjectInner::HttpLookup(obj) => obj.index(i),
            ObjectInner::Imap(obj) => obj.index(i),
            ObjectInner::InMemoryStore(obj) => obj.index(i),
            ObjectInner::Jmap(obj) => obj.index(i),
            ObjectInner::Log(obj) => obj.index(i),
            ObjectInner::MailingList(obj) => obj.index(i),
            ObjectInner::MaskedEmail(obj) => obj.index(i),
            ObjectInner::MemoryLookupKey(obj) => obj.index(i),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.index(i),
            ObjectInner::Metric(obj) => obj.index(i),
            ObjectInner::Metrics(obj) => obj.index(i),
            ObjectInner::MetricsStore(obj) => obj.index(i),
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
            ObjectInner::SpamClassifier(obj) => obj.index(i),
            ObjectInner::SpamDnsblServer(obj) => obj.index(i),
            ObjectInner::SpamDnsblSettings(obj) => obj.index(i),
            ObjectInner::SpamFileExtension(obj) => obj.index(i),
            ObjectInner::SpamLlm(obj) => obj.index(i),
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
            ObjectInner::Tenant(obj) => obj.index(i),
            ObjectInner::TlsExternalReport(obj) => obj.index(i),
            ObjectInner::TlsInternalReport(obj) => obj.index(i),
            ObjectInner::TlsReportSettings(obj) => obj.index(i),
            ObjectInner::Trace(obj) => obj.index(i),
            ObjectInner::Tracer(obj) => obj.index(i),
            ObjectInner::TracingStore(obj) => obj.index(i),
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
            ObjectInner::AiModel(obj) => obj.patch(pointer, value),
            ObjectInner::Alert(obj) => obj.patch(pointer, value),
            ObjectInner::AllowedIp(obj) => obj.patch(pointer, value),
            ObjectInner::ApiKey(obj) => obj.patch(pointer, value),
            ObjectInner::AppPassword(obj) => obj.patch(pointer, value),
            ObjectInner::Application(obj) => obj.patch(pointer, value),
            ObjectInner::ArchivedItem(obj) => obj.patch(pointer, value),
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
            ObjectInner::Enterprise(obj) => obj.patch(pointer, value),
            ObjectInner::EventTracingLevel(obj) => obj.patch(pointer, value),
            ObjectInner::FileStorage(obj) => obj.patch(pointer, value),
            ObjectInner::Http(obj) => obj.patch(pointer, value),
            ObjectInner::HttpForm(obj) => obj.patch(pointer, value),
            ObjectInner::HttpLookup(obj) => obj.patch(pointer, value),
            ObjectInner::Imap(obj) => obj.patch(pointer, value),
            ObjectInner::InMemoryStore(obj) => obj.patch(pointer, value),
            ObjectInner::Jmap(obj) => obj.patch(pointer, value),
            ObjectInner::Log(obj) => obj.patch(pointer, value),
            ObjectInner::MailingList(obj) => obj.patch(pointer, value),
            ObjectInner::MaskedEmail(obj) => obj.patch(pointer, value),
            ObjectInner::MemoryLookupKey(obj) => obj.patch(pointer, value),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.patch(pointer, value),
            ObjectInner::Metric(obj) => obj.patch(pointer, value),
            ObjectInner::Metrics(obj) => obj.patch(pointer, value),
            ObjectInner::MetricsStore(obj) => obj.patch(pointer, value),
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
            ObjectInner::SpamClassifier(obj) => obj.patch(pointer, value),
            ObjectInner::SpamDnsblServer(obj) => obj.patch(pointer, value),
            ObjectInner::SpamDnsblSettings(obj) => obj.patch(pointer, value),
            ObjectInner::SpamFileExtension(obj) => obj.patch(pointer, value),
            ObjectInner::SpamLlm(obj) => obj.patch(pointer, value),
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
            ObjectInner::Tenant(obj) => obj.patch(pointer, value),
            ObjectInner::TlsExternalReport(obj) => obj.patch(pointer, value),
            ObjectInner::TlsInternalReport(obj) => obj.patch(pointer, value),
            ObjectInner::TlsReportSettings(obj) => obj.patch(pointer, value),
            ObjectInner::Trace(obj) => obj.patch(pointer, value),
            ObjectInner::Tracer(obj) => obj.patch(pointer, value),
            ObjectInner::TracingStore(obj) => obj.patch(pointer, value),
            ObjectInner::WebDav(obj) => obj.patch(pointer, value),
            ObjectInner::WebHook(obj) => obj.patch(pointer, value),
        }
    }
}

impl IntoValue for Object {
    fn into_value(self) -> JmapValue<'static> {
        match self.inner {
            ObjectInner::Account(obj) => obj.into_value(),
            ObjectInner::AccountPassword(obj) => obj.into_value(),
            ObjectInner::AccountSettings(obj) => obj.into_value(),
            ObjectInner::AcmeProvider(obj) => obj.into_value(),
            ObjectInner::Action(obj) => obj.into_value(),
            ObjectInner::AddressBook(obj) => obj.into_value(),
            ObjectInner::AiModel(obj) => obj.into_value(),
            ObjectInner::Alert(obj) => obj.into_value(),
            ObjectInner::AllowedIp(obj) => obj.into_value(),
            ObjectInner::ApiKey(obj) => obj.into_value(),
            ObjectInner::AppPassword(obj) => obj.into_value(),
            ObjectInner::Application(obj) => obj.into_value(),
            ObjectInner::ArchivedItem(obj) => obj.into_value(),
            ObjectInner::ArfExternalReport(obj) => obj.into_value(),
            ObjectInner::Asn(obj) => obj.into_value(),
            ObjectInner::Authentication(obj) => obj.into_value(),
            ObjectInner::BlobStore(obj) => obj.into_value(),
            ObjectInner::BlockedIp(obj) => obj.into_value(),
            ObjectInner::Bootstrap(obj) => obj.into_value(),
            ObjectInner::Cache(obj) => obj.into_value(),
            ObjectInner::Calendar(obj) => obj.into_value(),
            ObjectInner::CalendarAlarm(obj) => obj.into_value(),
            ObjectInner::CalendarScheduling(obj) => obj.into_value(),
            ObjectInner::Certificate(obj) => obj.into_value(),
            ObjectInner::ClusterNode(obj) => obj.into_value(),
            ObjectInner::ClusterRole(obj) => obj.into_value(),
            ObjectInner::Coordinator(obj) => obj.into_value(),
            ObjectInner::DataRetention(obj) => obj.into_value(),
            ObjectInner::DataStore(obj) => obj.into_value(),
            ObjectInner::Directory(obj) => obj.into_value(),
            ObjectInner::DkimReportSettings(obj) => obj.into_value(),
            ObjectInner::DkimSignature(obj) => obj.into_value(),
            ObjectInner::DmarcExternalReport(obj) => obj.into_value(),
            ObjectInner::DmarcInternalReport(obj) => obj.into_value(),
            ObjectInner::DmarcReportSettings(obj) => obj.into_value(),
            ObjectInner::DnsResolver(obj) => obj.into_value(),
            ObjectInner::DnsServer(obj) => obj.into_value(),
            ObjectInner::Domain(obj) => obj.into_value(),
            ObjectInner::DsnReportSettings(obj) => obj.into_value(),
            ObjectInner::Email(obj) => obj.into_value(),
            ObjectInner::Enterprise(obj) => obj.into_value(),
            ObjectInner::EventTracingLevel(obj) => obj.into_value(),
            ObjectInner::FileStorage(obj) => obj.into_value(),
            ObjectInner::Http(obj) => obj.into_value(),
            ObjectInner::HttpForm(obj) => obj.into_value(),
            ObjectInner::HttpLookup(obj) => obj.into_value(),
            ObjectInner::Imap(obj) => obj.into_value(),
            ObjectInner::InMemoryStore(obj) => obj.into_value(),
            ObjectInner::Jmap(obj) => obj.into_value(),
            ObjectInner::Log(obj) => obj.into_value(),
            ObjectInner::MailingList(obj) => obj.into_value(),
            ObjectInner::MaskedEmail(obj) => obj.into_value(),
            ObjectInner::MemoryLookupKey(obj) => obj.into_value(),
            ObjectInner::MemoryLookupKeyValue(obj) => obj.into_value(),
            ObjectInner::Metric(obj) => obj.into_value(),
            ObjectInner::Metrics(obj) => obj.into_value(),
            ObjectInner::MetricsStore(obj) => obj.into_value(),
            ObjectInner::MtaConnectionStrategy(obj) => obj.into_value(),
            ObjectInner::MtaDeliverySchedule(obj) => obj.into_value(),
            ObjectInner::MtaExtensions(obj) => obj.into_value(),
            ObjectInner::MtaHook(obj) => obj.into_value(),
            ObjectInner::MtaInboundSession(obj) => obj.into_value(),
            ObjectInner::MtaInboundThrottle(obj) => obj.into_value(),
            ObjectInner::MtaMilter(obj) => obj.into_value(),
            ObjectInner::MtaOutboundStrategy(obj) => obj.into_value(),
            ObjectInner::MtaOutboundThrottle(obj) => obj.into_value(),
            ObjectInner::MtaQueueQuota(obj) => obj.into_value(),
            ObjectInner::MtaRoute(obj) => obj.into_value(),
            ObjectInner::MtaStageAuth(obj) => obj.into_value(),
            ObjectInner::MtaStageConnect(obj) => obj.into_value(),
            ObjectInner::MtaStageData(obj) => obj.into_value(),
            ObjectInner::MtaStageEhlo(obj) => obj.into_value(),
            ObjectInner::MtaStageMail(obj) => obj.into_value(),
            ObjectInner::MtaStageRcpt(obj) => obj.into_value(),
            ObjectInner::MtaSts(obj) => obj.into_value(),
            ObjectInner::MtaTlsStrategy(obj) => obj.into_value(),
            ObjectInner::MtaVirtualQueue(obj) => obj.into_value(),
            ObjectInner::NetworkListener(obj) => obj.into_value(),
            ObjectInner::OAuthClient(obj) => obj.into_value(),
            ObjectInner::OidcProvider(obj) => obj.into_value(),
            ObjectInner::PublicKey(obj) => obj.into_value(),
            ObjectInner::QueuedMessage(obj) => obj.into_value(),
            ObjectInner::ReportSettings(obj) => obj.into_value(),
            ObjectInner::Role(obj) => obj.into_value(),
            ObjectInner::Search(obj) => obj.into_value(),
            ObjectInner::SearchStore(obj) => obj.into_value(),
            ObjectInner::Security(obj) => obj.into_value(),
            ObjectInner::SenderAuth(obj) => obj.into_value(),
            ObjectInner::Sharing(obj) => obj.into_value(),
            ObjectInner::SieveSystemInterpreter(obj) => obj.into_value(),
            ObjectInner::SieveSystemScript(obj) => obj.into_value(),
            ObjectInner::SieveUserInterpreter(obj) => obj.into_value(),
            ObjectInner::SieveUserScript(obj) => obj.into_value(),
            ObjectInner::SpamClassifier(obj) => obj.into_value(),
            ObjectInner::SpamDnsblServer(obj) => obj.into_value(),
            ObjectInner::SpamDnsblSettings(obj) => obj.into_value(),
            ObjectInner::SpamFileExtension(obj) => obj.into_value(),
            ObjectInner::SpamLlm(obj) => obj.into_value(),
            ObjectInner::SpamPyzor(obj) => obj.into_value(),
            ObjectInner::SpamRule(obj) => obj.into_value(),
            ObjectInner::SpamSettings(obj) => obj.into_value(),
            ObjectInner::SpamTag(obj) => obj.into_value(),
            ObjectInner::SpamTrainingSample(obj) => obj.into_value(),
            ObjectInner::SpfReportSettings(obj) => obj.into_value(),
            ObjectInner::StoreLookup(obj) => obj.into_value(),
            ObjectInner::SystemSettings(obj) => obj.into_value(),
            ObjectInner::Task(obj) => obj.into_value(),
            ObjectInner::TaskManager(obj) => obj.into_value(),
            ObjectInner::Tenant(obj) => obj.into_value(),
            ObjectInner::TlsExternalReport(obj) => obj.into_value(),
            ObjectInner::TlsInternalReport(obj) => obj.into_value(),
            ObjectInner::TlsReportSettings(obj) => obj.into_value(),
            ObjectInner::Trace(obj) => obj.into_value(),
            ObjectInner::Tracer(obj) => obj.into_value(),
            ObjectInner::TracingStore(obj) => obj.into_value(),
            ObjectInner::WebDav(obj) => obj.into_value(),
            ObjectInner::WebHook(obj) => obj.into_value(),
        }
    }
}

impl From<ObjectType> for ObjectInner {
    fn from(obj: ObjectType) -> Self {
        match obj {
            ObjectType::Account => ObjectInner::Account(Default::default()),
            ObjectType::AccountPassword => ObjectInner::AccountPassword(Default::default()),
            ObjectType::AccountSettings => ObjectInner::AccountSettings(Default::default()),
            ObjectType::AcmeProvider => ObjectInner::AcmeProvider(Default::default()),
            ObjectType::Action => ObjectInner::Action(Default::default()),
            ObjectType::AddressBook => ObjectInner::AddressBook(Default::default()),
            ObjectType::AiModel => ObjectInner::AiModel(Default::default()),
            ObjectType::Alert => ObjectInner::Alert(Default::default()),
            ObjectType::AllowedIp => ObjectInner::AllowedIp(Default::default()),
            ObjectType::ApiKey => ObjectInner::ApiKey(Default::default()),
            ObjectType::AppPassword => ObjectInner::AppPassword(Default::default()),
            ObjectType::Application => ObjectInner::Application(Default::default()),
            ObjectType::ArchivedItem => ObjectInner::ArchivedItem(Default::default()),
            ObjectType::ArfExternalReport => ObjectInner::ArfExternalReport(Default::default()),
            ObjectType::Asn => ObjectInner::Asn(Default::default()),
            ObjectType::Authentication => ObjectInner::Authentication(Default::default()),
            ObjectType::BlobStore => ObjectInner::BlobStore(Default::default()),
            ObjectType::BlockedIp => ObjectInner::BlockedIp(Default::default()),
            ObjectType::Bootstrap => ObjectInner::Bootstrap(Default::default()),
            ObjectType::Cache => ObjectInner::Cache(Default::default()),
            ObjectType::Calendar => ObjectInner::Calendar(Default::default()),
            ObjectType::CalendarAlarm => ObjectInner::CalendarAlarm(Default::default()),
            ObjectType::CalendarScheduling => ObjectInner::CalendarScheduling(Default::default()),
            ObjectType::Certificate => ObjectInner::Certificate(Default::default()),
            ObjectType::ClusterNode => ObjectInner::ClusterNode(Default::default()),
            ObjectType::ClusterRole => ObjectInner::ClusterRole(Default::default()),
            ObjectType::Coordinator => ObjectInner::Coordinator(Default::default()),
            ObjectType::DataRetention => ObjectInner::DataRetention(Default::default()),
            ObjectType::DataStore => ObjectInner::DataStore(Default::default()),
            ObjectType::Directory => ObjectInner::Directory(Default::default()),
            ObjectType::DkimReportSettings => ObjectInner::DkimReportSettings(Default::default()),
            ObjectType::DkimSignature => ObjectInner::DkimSignature(Default::default()),
            ObjectType::DmarcExternalReport => ObjectInner::DmarcExternalReport(Default::default()),
            ObjectType::DmarcInternalReport => ObjectInner::DmarcInternalReport(Default::default()),
            ObjectType::DmarcReportSettings => ObjectInner::DmarcReportSettings(Default::default()),
            ObjectType::DnsResolver => ObjectInner::DnsResolver(Default::default()),
            ObjectType::DnsServer => ObjectInner::DnsServer(Default::default()),
            ObjectType::Domain => ObjectInner::Domain(Default::default()),
            ObjectType::DsnReportSettings => ObjectInner::DsnReportSettings(Default::default()),
            ObjectType::Email => ObjectInner::Email(Default::default()),
            ObjectType::Enterprise => ObjectInner::Enterprise(Default::default()),
            ObjectType::EventTracingLevel => ObjectInner::EventTracingLevel(Default::default()),
            ObjectType::FileStorage => ObjectInner::FileStorage(Default::default()),
            ObjectType::Http => ObjectInner::Http(Default::default()),
            ObjectType::HttpForm => ObjectInner::HttpForm(Default::default()),
            ObjectType::HttpLookup => ObjectInner::HttpLookup(Default::default()),
            ObjectType::Imap => ObjectInner::Imap(Default::default()),
            ObjectType::InMemoryStore => ObjectInner::InMemoryStore(Default::default()),
            ObjectType::Jmap => ObjectInner::Jmap(Default::default()),
            ObjectType::Log => ObjectInner::Log(Default::default()),
            ObjectType::MailingList => ObjectInner::MailingList(Default::default()),
            ObjectType::MaskedEmail => ObjectInner::MaskedEmail(Default::default()),
            ObjectType::MemoryLookupKey => ObjectInner::MemoryLookupKey(Default::default()),
            ObjectType::MemoryLookupKeyValue => {
                ObjectInner::MemoryLookupKeyValue(Default::default())
            }
            ObjectType::Metric => ObjectInner::Metric(Default::default()),
            ObjectType::Metrics => ObjectInner::Metrics(Default::default()),
            ObjectType::MetricsStore => ObjectInner::MetricsStore(Default::default()),
            ObjectType::MtaConnectionStrategy => {
                ObjectInner::MtaConnectionStrategy(Default::default())
            }
            ObjectType::MtaDeliverySchedule => ObjectInner::MtaDeliverySchedule(Default::default()),
            ObjectType::MtaExtensions => ObjectInner::MtaExtensions(Default::default()),
            ObjectType::MtaHook => ObjectInner::MtaHook(Default::default()),
            ObjectType::MtaInboundSession => ObjectInner::MtaInboundSession(Default::default()),
            ObjectType::MtaInboundThrottle => ObjectInner::MtaInboundThrottle(Default::default()),
            ObjectType::MtaMilter => ObjectInner::MtaMilter(Default::default()),
            ObjectType::MtaOutboundStrategy => ObjectInner::MtaOutboundStrategy(Default::default()),
            ObjectType::MtaOutboundThrottle => ObjectInner::MtaOutboundThrottle(Default::default()),
            ObjectType::MtaQueueQuota => ObjectInner::MtaQueueQuota(Default::default()),
            ObjectType::MtaRoute => ObjectInner::MtaRoute(Default::default()),
            ObjectType::MtaStageAuth => ObjectInner::MtaStageAuth(Default::default()),
            ObjectType::MtaStageConnect => ObjectInner::MtaStageConnect(Default::default()),
            ObjectType::MtaStageData => ObjectInner::MtaStageData(Default::default()),
            ObjectType::MtaStageEhlo => ObjectInner::MtaStageEhlo(Default::default()),
            ObjectType::MtaStageMail => ObjectInner::MtaStageMail(Default::default()),
            ObjectType::MtaStageRcpt => ObjectInner::MtaStageRcpt(Default::default()),
            ObjectType::MtaSts => ObjectInner::MtaSts(Default::default()),
            ObjectType::MtaTlsStrategy => ObjectInner::MtaTlsStrategy(Default::default()),
            ObjectType::MtaVirtualQueue => ObjectInner::MtaVirtualQueue(Default::default()),
            ObjectType::NetworkListener => ObjectInner::NetworkListener(Default::default()),
            ObjectType::OAuthClient => ObjectInner::OAuthClient(Default::default()),
            ObjectType::OidcProvider => ObjectInner::OidcProvider(Default::default()),
            ObjectType::PublicKey => ObjectInner::PublicKey(Default::default()),
            ObjectType::QueuedMessage => ObjectInner::QueuedMessage(Default::default()),
            ObjectType::ReportSettings => ObjectInner::ReportSettings(Default::default()),
            ObjectType::Role => ObjectInner::Role(Default::default()),
            ObjectType::Search => ObjectInner::Search(Default::default()),
            ObjectType::SearchStore => ObjectInner::SearchStore(Default::default()),
            ObjectType::Security => ObjectInner::Security(Default::default()),
            ObjectType::SenderAuth => ObjectInner::SenderAuth(Default::default()),
            ObjectType::Sharing => ObjectInner::Sharing(Default::default()),
            ObjectType::SieveSystemInterpreter => {
                ObjectInner::SieveSystemInterpreter(Default::default())
            }
            ObjectType::SieveSystemScript => ObjectInner::SieveSystemScript(Default::default()),
            ObjectType::SieveUserInterpreter => {
                ObjectInner::SieveUserInterpreter(Default::default())
            }
            ObjectType::SieveUserScript => ObjectInner::SieveUserScript(Default::default()),
            ObjectType::SpamClassifier => ObjectInner::SpamClassifier(Default::default()),
            ObjectType::SpamDnsblServer => ObjectInner::SpamDnsblServer(Default::default()),
            ObjectType::SpamDnsblSettings => ObjectInner::SpamDnsblSettings(Default::default()),
            ObjectType::SpamFileExtension => ObjectInner::SpamFileExtension(Default::default()),
            ObjectType::SpamLlm => ObjectInner::SpamLlm(Default::default()),
            ObjectType::SpamPyzor => ObjectInner::SpamPyzor(Default::default()),
            ObjectType::SpamRule => ObjectInner::SpamRule(Default::default()),
            ObjectType::SpamSettings => ObjectInner::SpamSettings(Default::default()),
            ObjectType::SpamTag => ObjectInner::SpamTag(Default::default()),
            ObjectType::SpamTrainingSample => ObjectInner::SpamTrainingSample(Default::default()),
            ObjectType::SpfReportSettings => ObjectInner::SpfReportSettings(Default::default()),
            ObjectType::StoreLookup => ObjectInner::StoreLookup(Default::default()),
            ObjectType::SystemSettings => ObjectInner::SystemSettings(Default::default()),
            ObjectType::Task => ObjectInner::Task(Default::default()),
            ObjectType::TaskManager => ObjectInner::TaskManager(Default::default()),
            ObjectType::Tenant => ObjectInner::Tenant(Default::default()),
            ObjectType::TlsExternalReport => ObjectInner::TlsExternalReport(Default::default()),
            ObjectType::TlsInternalReport => ObjectInner::TlsInternalReport(Default::default()),
            ObjectType::TlsReportSettings => ObjectInner::TlsReportSettings(Default::default()),
            ObjectType::Trace => ObjectInner::Trace(Default::default()),
            ObjectType::Tracer => ObjectInner::Tracer(Default::default()),
            ObjectType::TracingStore => ObjectInner::TracingStore(Default::default()),
            ObjectType::WebDav => ObjectInner::WebDav(Default::default()),
            ObjectType::WebHook => ObjectInner::WebHook(Default::default()),
        }
    }
}

impl From<Account> for ObjectInner {
    fn from(value: Account) -> Self {
        ObjectInner::Account(value)
    }
}

impl From<Object> for Account {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Account(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<AccountPassword> for ObjectInner {
    fn from(value: AccountPassword) -> Self {
        ObjectInner::AccountPassword(value)
    }
}

impl From<Object> for AccountPassword {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AccountPassword(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<AccountSettings> for ObjectInner {
    fn from(value: AccountSettings) -> Self {
        ObjectInner::AccountSettings(value)
    }
}

impl From<Object> for AccountSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AccountSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<AcmeProvider> for ObjectInner {
    fn from(value: AcmeProvider) -> Self {
        ObjectInner::AcmeProvider(value)
    }
}

impl From<Object> for AcmeProvider {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AcmeProvider(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Action> for ObjectInner {
    fn from(value: Action) -> Self {
        ObjectInner::Action(value)
    }
}

impl From<Object> for Action {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Action(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<AddressBook> for ObjectInner {
    fn from(value: AddressBook) -> Self {
        ObjectInner::AddressBook(value)
    }
}

impl From<Object> for AddressBook {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AddressBook(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<AiModel> for ObjectInner {
    fn from(value: AiModel) -> Self {
        ObjectInner::AiModel(value)
    }
}

impl From<Object> for AiModel {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AiModel(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Alert> for ObjectInner {
    fn from(value: Alert) -> Self {
        ObjectInner::Alert(value)
    }
}

impl From<Object> for Alert {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Alert(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<AllowedIp> for ObjectInner {
    fn from(value: AllowedIp) -> Self {
        ObjectInner::AllowedIp(value)
    }
}

impl From<Object> for AllowedIp {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AllowedIp(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<ApiKey> for ObjectInner {
    fn from(value: ApiKey) -> Self {
        ObjectInner::ApiKey(value)
    }
}

impl From<Object> for ApiKey {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ApiKey(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<AppPassword> for ObjectInner {
    fn from(value: AppPassword) -> Self {
        ObjectInner::AppPassword(value)
    }
}

impl From<Object> for AppPassword {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::AppPassword(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Application> for ObjectInner {
    fn from(value: Application) -> Self {
        ObjectInner::Application(value)
    }
}

impl From<Object> for Application {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Application(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<ArchivedItem> for ObjectInner {
    fn from(value: ArchivedItem) -> Self {
        ObjectInner::ArchivedItem(value)
    }
}

impl From<Object> for ArchivedItem {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ArchivedItem(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<ArfExternalReport> for ObjectInner {
    fn from(value: ArfExternalReport) -> Self {
        ObjectInner::ArfExternalReport(value)
    }
}

impl From<Object> for ArfExternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ArfExternalReport(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Asn> for ObjectInner {
    fn from(value: Asn) -> Self {
        ObjectInner::Asn(value)
    }
}

impl From<Object> for Asn {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Asn(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Authentication> for ObjectInner {
    fn from(value: Authentication) -> Self {
        ObjectInner::Authentication(value)
    }
}

impl From<Object> for Authentication {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Authentication(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<BlobStore> for ObjectInner {
    fn from(value: BlobStore) -> Self {
        ObjectInner::BlobStore(value)
    }
}

impl From<Object> for BlobStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::BlobStore(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<BlockedIp> for ObjectInner {
    fn from(value: BlockedIp) -> Self {
        ObjectInner::BlockedIp(value)
    }
}

impl From<Object> for BlockedIp {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::BlockedIp(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Bootstrap> for ObjectInner {
    fn from(value: Bootstrap) -> Self {
        ObjectInner::Bootstrap(value)
    }
}

impl From<Object> for Bootstrap {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Bootstrap(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Cache> for ObjectInner {
    fn from(value: Cache) -> Self {
        ObjectInner::Cache(value)
    }
}

impl From<Object> for Cache {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Cache(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Calendar> for ObjectInner {
    fn from(value: Calendar) -> Self {
        ObjectInner::Calendar(value)
    }
}

impl From<Object> for Calendar {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Calendar(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<CalendarAlarm> for ObjectInner {
    fn from(value: CalendarAlarm) -> Self {
        ObjectInner::CalendarAlarm(value)
    }
}

impl From<Object> for CalendarAlarm {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::CalendarAlarm(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<CalendarScheduling> for ObjectInner {
    fn from(value: CalendarScheduling) -> Self {
        ObjectInner::CalendarScheduling(value)
    }
}

impl From<Object> for CalendarScheduling {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::CalendarScheduling(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Certificate> for ObjectInner {
    fn from(value: Certificate) -> Self {
        ObjectInner::Certificate(value)
    }
}

impl From<Object> for Certificate {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Certificate(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<ClusterNode> for ObjectInner {
    fn from(value: ClusterNode) -> Self {
        ObjectInner::ClusterNode(value)
    }
}

impl From<Object> for ClusterNode {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ClusterNode(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<ClusterRole> for ObjectInner {
    fn from(value: ClusterRole) -> Self {
        ObjectInner::ClusterRole(value)
    }
}

impl From<Object> for ClusterRole {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ClusterRole(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Coordinator> for ObjectInner {
    fn from(value: Coordinator) -> Self {
        ObjectInner::Coordinator(value)
    }
}

impl From<Object> for Coordinator {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Coordinator(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DataRetention> for ObjectInner {
    fn from(value: DataRetention) -> Self {
        ObjectInner::DataRetention(value)
    }
}

impl From<Object> for DataRetention {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DataRetention(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DataStore> for ObjectInner {
    fn from(value: DataStore) -> Self {
        ObjectInner::DataStore(value)
    }
}

impl From<Object> for DataStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DataStore(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Directory> for ObjectInner {
    fn from(value: Directory) -> Self {
        ObjectInner::Directory(value)
    }
}

impl From<Object> for Directory {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Directory(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DkimReportSettings> for ObjectInner {
    fn from(value: DkimReportSettings) -> Self {
        ObjectInner::DkimReportSettings(value)
    }
}

impl From<Object> for DkimReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DkimReportSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DkimSignature> for ObjectInner {
    fn from(value: DkimSignature) -> Self {
        ObjectInner::DkimSignature(value)
    }
}

impl From<Object> for DkimSignature {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DkimSignature(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DmarcExternalReport> for ObjectInner {
    fn from(value: DmarcExternalReport) -> Self {
        ObjectInner::DmarcExternalReport(value)
    }
}

impl From<Object> for DmarcExternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DmarcExternalReport(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DmarcInternalReport> for ObjectInner {
    fn from(value: DmarcInternalReport) -> Self {
        ObjectInner::DmarcInternalReport(value)
    }
}

impl From<Object> for DmarcInternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DmarcInternalReport(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DmarcReportSettings> for ObjectInner {
    fn from(value: DmarcReportSettings) -> Self {
        ObjectInner::DmarcReportSettings(value)
    }
}

impl From<Object> for DmarcReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DmarcReportSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DnsResolver> for ObjectInner {
    fn from(value: DnsResolver) -> Self {
        ObjectInner::DnsResolver(value)
    }
}

impl From<Object> for DnsResolver {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DnsResolver(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DnsServer> for ObjectInner {
    fn from(value: DnsServer) -> Self {
        ObjectInner::DnsServer(value)
    }
}

impl From<Object> for DnsServer {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DnsServer(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Domain> for ObjectInner {
    fn from(value: Domain) -> Self {
        ObjectInner::Domain(value)
    }
}

impl From<Object> for Domain {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Domain(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<DsnReportSettings> for ObjectInner {
    fn from(value: DsnReportSettings) -> Self {
        ObjectInner::DsnReportSettings(value)
    }
}

impl From<Object> for DsnReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::DsnReportSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Email> for ObjectInner {
    fn from(value: Email) -> Self {
        ObjectInner::Email(value)
    }
}

impl From<Object> for Email {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Email(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Enterprise> for ObjectInner {
    fn from(value: Enterprise) -> Self {
        ObjectInner::Enterprise(value)
    }
}

impl From<Object> for Enterprise {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Enterprise(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<EventTracingLevel> for ObjectInner {
    fn from(value: EventTracingLevel) -> Self {
        ObjectInner::EventTracingLevel(value)
    }
}

impl From<Object> for EventTracingLevel {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::EventTracingLevel(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<FileStorage> for ObjectInner {
    fn from(value: FileStorage) -> Self {
        ObjectInner::FileStorage(value)
    }
}

impl From<Object> for FileStorage {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::FileStorage(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Http> for ObjectInner {
    fn from(value: Http) -> Self {
        ObjectInner::Http(value)
    }
}

impl From<Object> for Http {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Http(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<HttpForm> for ObjectInner {
    fn from(value: HttpForm) -> Self {
        ObjectInner::HttpForm(value)
    }
}

impl From<Object> for HttpForm {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::HttpForm(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<HttpLookup> for ObjectInner {
    fn from(value: HttpLookup) -> Self {
        ObjectInner::HttpLookup(value)
    }
}

impl From<Object> for HttpLookup {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::HttpLookup(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Imap> for ObjectInner {
    fn from(value: Imap) -> Self {
        ObjectInner::Imap(value)
    }
}

impl From<Object> for Imap {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Imap(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<InMemoryStore> for ObjectInner {
    fn from(value: InMemoryStore) -> Self {
        ObjectInner::InMemoryStore(value)
    }
}

impl From<Object> for InMemoryStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::InMemoryStore(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Jmap> for ObjectInner {
    fn from(value: Jmap) -> Self {
        ObjectInner::Jmap(value)
    }
}

impl From<Object> for Jmap {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Jmap(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Log> for ObjectInner {
    fn from(value: Log) -> Self {
        ObjectInner::Log(value)
    }
}

impl From<Object> for Log {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Log(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MailingList> for ObjectInner {
    fn from(value: MailingList) -> Self {
        ObjectInner::MailingList(value)
    }
}

impl From<Object> for MailingList {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MailingList(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MaskedEmail> for ObjectInner {
    fn from(value: MaskedEmail) -> Self {
        ObjectInner::MaskedEmail(value)
    }
}

impl From<Object> for MaskedEmail {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MaskedEmail(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MemoryLookupKey> for ObjectInner {
    fn from(value: MemoryLookupKey) -> Self {
        ObjectInner::MemoryLookupKey(value)
    }
}

impl From<Object> for MemoryLookupKey {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MemoryLookupKey(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MemoryLookupKeyValue> for ObjectInner {
    fn from(value: MemoryLookupKeyValue) -> Self {
        ObjectInner::MemoryLookupKeyValue(value)
    }
}

impl From<Object> for MemoryLookupKeyValue {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MemoryLookupKeyValue(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Metric> for ObjectInner {
    fn from(value: Metric) -> Self {
        ObjectInner::Metric(value)
    }
}

impl From<Object> for Metric {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Metric(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Metrics> for ObjectInner {
    fn from(value: Metrics) -> Self {
        ObjectInner::Metrics(value)
    }
}

impl From<Object> for Metrics {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Metrics(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MetricsStore> for ObjectInner {
    fn from(value: MetricsStore) -> Self {
        ObjectInner::MetricsStore(value)
    }
}

impl From<Object> for MetricsStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MetricsStore(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaConnectionStrategy> for ObjectInner {
    fn from(value: MtaConnectionStrategy) -> Self {
        ObjectInner::MtaConnectionStrategy(value)
    }
}

impl From<Object> for MtaConnectionStrategy {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaConnectionStrategy(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaDeliverySchedule> for ObjectInner {
    fn from(value: MtaDeliverySchedule) -> Self {
        ObjectInner::MtaDeliverySchedule(value)
    }
}

impl From<Object> for MtaDeliverySchedule {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaDeliverySchedule(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaExtensions> for ObjectInner {
    fn from(value: MtaExtensions) -> Self {
        ObjectInner::MtaExtensions(value)
    }
}

impl From<Object> for MtaExtensions {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaExtensions(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaHook> for ObjectInner {
    fn from(value: MtaHook) -> Self {
        ObjectInner::MtaHook(value)
    }
}

impl From<Object> for MtaHook {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaHook(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaInboundSession> for ObjectInner {
    fn from(value: MtaInboundSession) -> Self {
        ObjectInner::MtaInboundSession(value)
    }
}

impl From<Object> for MtaInboundSession {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaInboundSession(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaInboundThrottle> for ObjectInner {
    fn from(value: MtaInboundThrottle) -> Self {
        ObjectInner::MtaInboundThrottle(value)
    }
}

impl From<Object> for MtaInboundThrottle {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaInboundThrottle(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaMilter> for ObjectInner {
    fn from(value: MtaMilter) -> Self {
        ObjectInner::MtaMilter(value)
    }
}

impl From<Object> for MtaMilter {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaMilter(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaOutboundStrategy> for ObjectInner {
    fn from(value: MtaOutboundStrategy) -> Self {
        ObjectInner::MtaOutboundStrategy(value)
    }
}

impl From<Object> for MtaOutboundStrategy {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaOutboundStrategy(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaOutboundThrottle> for ObjectInner {
    fn from(value: MtaOutboundThrottle) -> Self {
        ObjectInner::MtaOutboundThrottle(value)
    }
}

impl From<Object> for MtaOutboundThrottle {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaOutboundThrottle(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaQueueQuota> for ObjectInner {
    fn from(value: MtaQueueQuota) -> Self {
        ObjectInner::MtaQueueQuota(value)
    }
}

impl From<Object> for MtaQueueQuota {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaQueueQuota(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaRoute> for ObjectInner {
    fn from(value: MtaRoute) -> Self {
        ObjectInner::MtaRoute(value)
    }
}

impl From<Object> for MtaRoute {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaRoute(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageAuth> for ObjectInner {
    fn from(value: MtaStageAuth) -> Self {
        ObjectInner::MtaStageAuth(value)
    }
}

impl From<Object> for MtaStageAuth {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageAuth(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageConnect> for ObjectInner {
    fn from(value: MtaStageConnect) -> Self {
        ObjectInner::MtaStageConnect(value)
    }
}

impl From<Object> for MtaStageConnect {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageConnect(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageData> for ObjectInner {
    fn from(value: MtaStageData) -> Self {
        ObjectInner::MtaStageData(value)
    }
}

impl From<Object> for MtaStageData {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageData(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageEhlo> for ObjectInner {
    fn from(value: MtaStageEhlo) -> Self {
        ObjectInner::MtaStageEhlo(value)
    }
}

impl From<Object> for MtaStageEhlo {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageEhlo(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageMail> for ObjectInner {
    fn from(value: MtaStageMail) -> Self {
        ObjectInner::MtaStageMail(value)
    }
}

impl From<Object> for MtaStageMail {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageMail(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaStageRcpt> for ObjectInner {
    fn from(value: MtaStageRcpt) -> Self {
        ObjectInner::MtaStageRcpt(value)
    }
}

impl From<Object> for MtaStageRcpt {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaStageRcpt(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaSts> for ObjectInner {
    fn from(value: MtaSts) -> Self {
        ObjectInner::MtaSts(value)
    }
}

impl From<Object> for MtaSts {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaSts(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaTlsStrategy> for ObjectInner {
    fn from(value: MtaTlsStrategy) -> Self {
        ObjectInner::MtaTlsStrategy(value)
    }
}

impl From<Object> for MtaTlsStrategy {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaTlsStrategy(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<MtaVirtualQueue> for ObjectInner {
    fn from(value: MtaVirtualQueue) -> Self {
        ObjectInner::MtaVirtualQueue(value)
    }
}

impl From<Object> for MtaVirtualQueue {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::MtaVirtualQueue(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<NetworkListener> for ObjectInner {
    fn from(value: NetworkListener) -> Self {
        ObjectInner::NetworkListener(value)
    }
}

impl From<Object> for NetworkListener {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::NetworkListener(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<OAuthClient> for ObjectInner {
    fn from(value: OAuthClient) -> Self {
        ObjectInner::OAuthClient(value)
    }
}

impl From<Object> for OAuthClient {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::OAuthClient(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<OidcProvider> for ObjectInner {
    fn from(value: OidcProvider) -> Self {
        ObjectInner::OidcProvider(value)
    }
}

impl From<Object> for OidcProvider {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::OidcProvider(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<PublicKey> for ObjectInner {
    fn from(value: PublicKey) -> Self {
        ObjectInner::PublicKey(value)
    }
}

impl From<Object> for PublicKey {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::PublicKey(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<QueuedMessage> for ObjectInner {
    fn from(value: QueuedMessage) -> Self {
        ObjectInner::QueuedMessage(value)
    }
}

impl From<Object> for QueuedMessage {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::QueuedMessage(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<ReportSettings> for ObjectInner {
    fn from(value: ReportSettings) -> Self {
        ObjectInner::ReportSettings(value)
    }
}

impl From<Object> for ReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::ReportSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Role> for ObjectInner {
    fn from(value: Role) -> Self {
        ObjectInner::Role(value)
    }
}

impl From<Object> for Role {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Role(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Search> for ObjectInner {
    fn from(value: Search) -> Self {
        ObjectInner::Search(value)
    }
}

impl From<Object> for Search {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Search(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SearchStore> for ObjectInner {
    fn from(value: SearchStore) -> Self {
        ObjectInner::SearchStore(value)
    }
}

impl From<Object> for SearchStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SearchStore(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Security> for ObjectInner {
    fn from(value: Security) -> Self {
        ObjectInner::Security(value)
    }
}

impl From<Object> for Security {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Security(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SenderAuth> for ObjectInner {
    fn from(value: SenderAuth) -> Self {
        ObjectInner::SenderAuth(value)
    }
}

impl From<Object> for SenderAuth {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SenderAuth(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Sharing> for ObjectInner {
    fn from(value: Sharing) -> Self {
        ObjectInner::Sharing(value)
    }
}

impl From<Object> for Sharing {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Sharing(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveSystemInterpreter> for ObjectInner {
    fn from(value: SieveSystemInterpreter) -> Self {
        ObjectInner::SieveSystemInterpreter(value)
    }
}

impl From<Object> for SieveSystemInterpreter {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveSystemInterpreter(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveSystemScript> for ObjectInner {
    fn from(value: SieveSystemScript) -> Self {
        ObjectInner::SieveSystemScript(value)
    }
}

impl From<Object> for SieveSystemScript {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveSystemScript(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveUserInterpreter> for ObjectInner {
    fn from(value: SieveUserInterpreter) -> Self {
        ObjectInner::SieveUserInterpreter(value)
    }
}

impl From<Object> for SieveUserInterpreter {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveUserInterpreter(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SieveUserScript> for ObjectInner {
    fn from(value: SieveUserScript) -> Self {
        ObjectInner::SieveUserScript(value)
    }
}

impl From<Object> for SieveUserScript {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SieveUserScript(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamClassifier> for ObjectInner {
    fn from(value: SpamClassifier) -> Self {
        ObjectInner::SpamClassifier(value)
    }
}

impl From<Object> for SpamClassifier {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamClassifier(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamDnsblServer> for ObjectInner {
    fn from(value: SpamDnsblServer) -> Self {
        ObjectInner::SpamDnsblServer(value)
    }
}

impl From<Object> for SpamDnsblServer {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamDnsblServer(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamDnsblSettings> for ObjectInner {
    fn from(value: SpamDnsblSettings) -> Self {
        ObjectInner::SpamDnsblSettings(value)
    }
}

impl From<Object> for SpamDnsblSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamDnsblSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamFileExtension> for ObjectInner {
    fn from(value: SpamFileExtension) -> Self {
        ObjectInner::SpamFileExtension(value)
    }
}

impl From<Object> for SpamFileExtension {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamFileExtension(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamLlm> for ObjectInner {
    fn from(value: SpamLlm) -> Self {
        ObjectInner::SpamLlm(value)
    }
}

impl From<Object> for SpamLlm {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamLlm(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamPyzor> for ObjectInner {
    fn from(value: SpamPyzor) -> Self {
        ObjectInner::SpamPyzor(value)
    }
}

impl From<Object> for SpamPyzor {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamPyzor(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamRule> for ObjectInner {
    fn from(value: SpamRule) -> Self {
        ObjectInner::SpamRule(value)
    }
}

impl From<Object> for SpamRule {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamRule(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamSettings> for ObjectInner {
    fn from(value: SpamSettings) -> Self {
        ObjectInner::SpamSettings(value)
    }
}

impl From<Object> for SpamSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamTag> for ObjectInner {
    fn from(value: SpamTag) -> Self {
        ObjectInner::SpamTag(value)
    }
}

impl From<Object> for SpamTag {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamTag(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpamTrainingSample> for ObjectInner {
    fn from(value: SpamTrainingSample) -> Self {
        ObjectInner::SpamTrainingSample(value)
    }
}

impl From<Object> for SpamTrainingSample {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpamTrainingSample(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SpfReportSettings> for ObjectInner {
    fn from(value: SpfReportSettings) -> Self {
        ObjectInner::SpfReportSettings(value)
    }
}

impl From<Object> for SpfReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SpfReportSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<StoreLookup> for ObjectInner {
    fn from(value: StoreLookup) -> Self {
        ObjectInner::StoreLookup(value)
    }
}

impl From<Object> for StoreLookup {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::StoreLookup(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<SystemSettings> for ObjectInner {
    fn from(value: SystemSettings) -> Self {
        ObjectInner::SystemSettings(value)
    }
}

impl From<Object> for SystemSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::SystemSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Task> for ObjectInner {
    fn from(value: Task) -> Self {
        ObjectInner::Task(value)
    }
}

impl From<Object> for Task {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Task(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<TaskManager> for ObjectInner {
    fn from(value: TaskManager) -> Self {
        ObjectInner::TaskManager(value)
    }
}

impl From<Object> for TaskManager {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TaskManager(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Tenant> for ObjectInner {
    fn from(value: Tenant) -> Self {
        ObjectInner::Tenant(value)
    }
}

impl From<Object> for Tenant {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Tenant(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<TlsExternalReport> for ObjectInner {
    fn from(value: TlsExternalReport) -> Self {
        ObjectInner::TlsExternalReport(value)
    }
}

impl From<Object> for TlsExternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TlsExternalReport(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<TlsInternalReport> for ObjectInner {
    fn from(value: TlsInternalReport) -> Self {
        ObjectInner::TlsInternalReport(value)
    }
}

impl From<Object> for TlsInternalReport {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TlsInternalReport(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<TlsReportSettings> for ObjectInner {
    fn from(value: TlsReportSettings) -> Self {
        ObjectInner::TlsReportSettings(value)
    }
}

impl From<Object> for TlsReportSettings {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TlsReportSettings(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Trace> for ObjectInner {
    fn from(value: Trace) -> Self {
        ObjectInner::Trace(value)
    }
}

impl From<Object> for Trace {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Trace(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<Tracer> for ObjectInner {
    fn from(value: Tracer) -> Self {
        ObjectInner::Tracer(value)
    }
}

impl From<Object> for Tracer {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::Tracer(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<TracingStore> for ObjectInner {
    fn from(value: TracingStore) -> Self {
        ObjectInner::TracingStore(value)
    }
}

impl From<Object> for TracingStore {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::TracingStore(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<WebDav> for ObjectInner {
    fn from(value: WebDav) -> Self {
        ObjectInner::WebDav(value)
    }
}

impl From<Object> for WebDav {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::WebDav(obj) => obj,
            _ => unreachable!(),
        }
    }
}

impl From<WebHook> for ObjectInner {
    fn from(value: WebHook) -> Self {
        ObjectInner::WebHook(value)
    }
}

impl From<Object> for WebHook {
    fn from(obj: Object) -> Self {
        match obj.inner {
            ObjectInner::WebHook(obj) => obj,
            _ => unreachable!(),
        }
    }
}
