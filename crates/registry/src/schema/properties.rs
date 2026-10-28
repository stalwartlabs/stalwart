/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

use crate::schema::prelude::*;
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ObjectInner {
    Account(Box<Account>),
    AccountPassword(Box<AccountPassword>),
    AccountSettings(Box<AccountSettings>),
    AcmeProvider(Box<AcmeProvider>),
    Action(Box<Action>),
    AddressBook(Box<AddressBook>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    AiModel(Box<AiModel>),
    #[cfg(feature = "enterprise")]
    Alert(Box<Alert>),
    // SPDX-SnippetEnd
    AllowedIp(Box<AllowedIp>),
    ApiKey(Box<ApiKey>),
    AppPassword(Box<AppPassword>),
    Application(Box<Application>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ArchivedItem(Box<ArchivedItem>),
    // SPDX-SnippetEnd
    ArfExternalReport(Box<ArfExternalReport>),
    Asn(Box<Asn>),
    Authentication(Box<Authentication>),
    BlobStore(Box<BlobStore>),
    BlockedIp(Box<BlockedIp>),
    Bootstrap(Box<Bootstrap>),
    Cache(Box<Cache>),
    Calendar(Box<Calendar>),
    CalendarAlarm(Box<CalendarAlarm>),
    CalendarScheduling(Box<CalendarScheduling>),
    Certificate(Box<Certificate>),
    ClusterNode(Box<ClusterNode>),
    ClusterRole(Box<ClusterRole>),
    Coordinator(Box<Coordinator>),
    DataRetention(Box<DataRetention>),
    DataStore(Box<DataStore>),
    Directory(Box<Directory>),
    DkimReportSettings(Box<DkimReportSettings>),
    DkimSignature(Box<DkimSignature>),
    DmarcExternalReport(Box<DmarcExternalReport>),
    DmarcInternalReport(Box<DmarcInternalReport>),
    DmarcReportSettings(Box<DmarcReportSettings>),
    DnsResolver(Box<DnsResolver>),
    DnsServer(Box<DnsServer>),
    Domain(Box<Domain>),
    DsnReportSettings(Box<DsnReportSettings>),
    Email(Box<Email>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Enterprise(Box<Enterprise>),
    // SPDX-SnippetEnd
    EventTracingLevel(Box<EventTracingLevel>),
    FileStorage(Box<FileStorage>),
    Http(Box<Http>),
    HttpForm(Box<HttpForm>),
    HttpLookup(Box<HttpLookup>),
    Imap(Box<Imap>),
    InMemoryStore(Box<InMemoryStore>),
    IndexQueueStatus(Box<IndexQueueStatus>),
    Jmap(Box<Jmap>),
    Log(Box<Log>),
    MailingList(Box<MailingList>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaskedEmail(Box<MaskedEmail>),
    // SPDX-SnippetEnd
    MemoryLookupKey(Box<MemoryLookupKey>),
    MemoryLookupKeyValue(Box<MemoryLookupKeyValue>),
    Metadata(Box<Metadata>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Metric(Box<Metric>),
    // SPDX-SnippetEnd
    Metrics(Box<Metrics>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MetricsStore(Box<MetricsStore>),
    // SPDX-SnippetEnd
    MtaConnectionStrategy(Box<MtaConnectionStrategy>),
    MtaDeliverySchedule(Box<MtaDeliverySchedule>),
    MtaExtensions(Box<MtaExtensions>),
    MtaHook(Box<MtaHook>),
    MtaInboundSession(Box<MtaInboundSession>),
    MtaInboundThrottle(Box<MtaInboundThrottle>),
    MtaMilter(Box<MtaMilter>),
    MtaOutboundStrategy(Box<MtaOutboundStrategy>),
    MtaOutboundThrottle(Box<MtaOutboundThrottle>),
    MtaQueueQuota(Box<MtaQueueQuota>),
    MtaRoute(Box<MtaRoute>),
    MtaStageAuth(Box<MtaStageAuth>),
    MtaStageConnect(Box<MtaStageConnect>),
    MtaStageData(Box<MtaStageData>),
    MtaStageEhlo(Box<MtaStageEhlo>),
    MtaStageMail(Box<MtaStageMail>),
    MtaStageRcpt(Box<MtaStageRcpt>),
    MtaSts(Box<MtaSts>),
    MtaTlsStrategy(Box<MtaTlsStrategy>),
    MtaVirtualQueue(Box<MtaVirtualQueue>),
    NetworkListener(Box<NetworkListener>),
    OAuthClient(Box<OAuthClient>),
    OAuthGrant(Box<OAuthGrant>),
    OidcProvider(Box<OidcProvider>),
    PublicKey(Box<PublicKey>),
    QueuedMessage(Box<QueuedMessage>),
    ReportSettings(Box<ReportSettings>),
    Role(Box<Role>),
    Search(Box<Search>),
    SearchStore(Box<SearchStore>),
    Security(Box<Security>),
    SenderAuth(Box<SenderAuth>),
    Sharing(Box<Sharing>),
    SieveSystemInterpreter(Box<SieveSystemInterpreter>),
    SieveSystemScript(Box<SieveSystemScript>),
    SieveUserInterpreter(Box<SieveUserInterpreter>),
    SieveUserScript(Box<SieveUserScript>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SpamAi(Box<SpamAi>),
    // SPDX-SnippetEnd
    SpamClassifier(Box<SpamClassifier>),
    SpamDnsblServer(Box<SpamDnsblServer>),
    SpamDnsblSettings(Box<SpamDnsblSettings>),
    SpamFileExtension(Box<SpamFileExtension>),
    SpamPyzor(Box<SpamPyzor>),
    SpamRule(Box<SpamRule>),
    SpamSettings(Box<SpamSettings>),
    SpamTag(Box<SpamTag>),
    SpamTrainingSample(Box<SpamTrainingSample>),
    SpfReportSettings(Box<SpfReportSettings>),
    StoreLookup(Box<StoreLookup>),
    SystemSettings(Box<SystemSettings>),
    Task(Box<Task>),
    TaskManager(Box<TaskManager>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Tenant(Box<Tenant>),
    // SPDX-SnippetEnd
    TlsExternalReport(Box<TlsExternalReport>),
    TlsInternalReport(Box<TlsInternalReport>),
    TlsReportSettings(Box<TlsReportSettings>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Trace(Box<Trace>),
    // SPDX-SnippetEnd
    Tracer(Box<Tracer>),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TracingStore(Box<TracingStore>),
    // SPDX-SnippetEnd
    WebDav(Box<WebDav>),
    WebHook(Box<WebHook>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ObjectType {
    Account = 0,
    AccountPassword = 1,
    AccountSettings = 2,
    AcmeProvider = 3,
    Action = 4,
    AddressBook = 5,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    AiModel = 6,
    #[cfg(feature = "enterprise")]
    Alert = 7,
    // SPDX-SnippetEnd
    AllowedIp = 8,
    ApiKey = 9,
    AppPassword = 10,
    Application = 11,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ArchivedItem = 12,
    // SPDX-SnippetEnd
    ArfExternalReport = 13,
    Asn = 14,
    Authentication = 15,
    BlobStore = 16,
    BlockedIp = 17,
    Bootstrap = 18,
    Cache = 19,
    Calendar = 20,
    CalendarAlarm = 21,
    CalendarScheduling = 22,
    Certificate = 23,
    ClusterNode = 24,
    ClusterRole = 25,
    Coordinator = 26,
    DataRetention = 27,
    DataStore = 28,
    Directory = 29,
    DkimReportSettings = 30,
    DkimSignature = 31,
    DmarcExternalReport = 32,
    DmarcInternalReport = 33,
    DmarcReportSettings = 34,
    DnsResolver = 35,
    DnsServer = 36,
    Domain = 37,
    DsnReportSettings = 38,
    Email = 39,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Enterprise = 40,
    // SPDX-SnippetEnd
    EventTracingLevel = 41,
    FileStorage = 42,
    Http = 43,
    HttpForm = 44,
    HttpLookup = 45,
    Imap = 46,
    InMemoryStore = 47,
    IndexQueueStatus = 48,
    Jmap = 49,
    Log = 50,
    MailingList = 51,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaskedEmail = 52,
    // SPDX-SnippetEnd
    MemoryLookupKey = 53,
    MemoryLookupKeyValue = 54,
    Metadata = 55,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Metric = 56,
    // SPDX-SnippetEnd
    Metrics = 57,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MetricsStore = 58,
    // SPDX-SnippetEnd
    MtaConnectionStrategy = 59,
    MtaDeliverySchedule = 60,
    MtaExtensions = 61,
    MtaHook = 62,
    MtaInboundSession = 63,
    MtaInboundThrottle = 64,
    MtaMilter = 65,
    MtaOutboundStrategy = 66,
    MtaOutboundThrottle = 67,
    MtaQueueQuota = 68,
    MtaRoute = 69,
    MtaStageAuth = 70,
    MtaStageConnect = 71,
    MtaStageData = 72,
    MtaStageEhlo = 73,
    MtaStageMail = 74,
    MtaStageRcpt = 75,
    MtaSts = 76,
    MtaTlsStrategy = 77,
    MtaVirtualQueue = 78,
    NetworkListener = 79,
    OAuthClient = 80,
    OAuthGrant = 81,
    OidcProvider = 82,
    PublicKey = 83,
    QueuedMessage = 84,
    ReportSettings = 85,
    Role = 86,
    Search = 87,
    SearchStore = 88,
    Security = 89,
    SenderAuth = 90,
    Sharing = 91,
    SieveSystemInterpreter = 92,
    SieveSystemScript = 93,
    SieveUserInterpreter = 94,
    SieveUserScript = 95,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SpamAi = 96,
    // SPDX-SnippetEnd
    SpamClassifier = 97,
    SpamDnsblServer = 98,
    SpamDnsblSettings = 99,
    SpamFileExtension = 100,
    SpamPyzor = 101,
    SpamRule = 102,
    SpamSettings = 103,
    SpamTag = 104,
    SpamTrainingSample = 105,
    SpfReportSettings = 106,
    StoreLookup = 107,
    SystemSettings = 108,
    Task = 109,
    TaskManager = 110,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Tenant = 111,
    // SPDX-SnippetEnd
    TlsExternalReport = 112,
    TlsInternalReport = 113,
    TlsReportSettings = 114,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Trace = 115,
    // SPDX-SnippetEnd
    Tracer = 116,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TracingStore = 117,
    // SPDX-SnippetEnd
    WebDav = 118,
    WebHook = 119,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Property {
    Type = 0,
    AbuseBanPeriod = 792,
    AbuseBanRate = 791,
    AcceptedAudiences = 710,
    AccessKeyId = 354,
    AccessToken = 378,
    AccessTokenExpiry = 721,
    AccessTokens = 159,
    AccountDomainId = 951,
    AccountHashPrefix = 17,
    AccountId = 71,
    AccountIdentifier = 374,
    AccountKey = 15,
    AccountName = 950,
    AccountSwitchKey = 379,
    AccountType = 952,
    AccountUri = 16,
    Accounts = 182,
    AcmeProviderId = 220,
    AddAuthResultsHeader = 649,
    AddDateHeader = 650,
    AddDeliveredToHeader = 651,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    AddHeader = 852,
    // SPDX-SnippetEnd
    AddMessageIdHeader = 652,
    AddReceivedHeader = 653,
    AddReceivedSpfHeader = 654,
    AddReturnPathHeader = 655,
    AdditionalInformation = 980,
    Address = 58,
    AggregateContactInfo = 311,
    AggregateDkimSignDomain = 317,
    AggregateFromAddress = 312,
    AggregateFromName = 313,
    AggregateOrgName = 315,
    AggregateSendFrequency = 316,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    AiFacts = 888,
    #[cfg(feature = "enterprise")]
    AiGate = 887,
    #[cfg(feature = "enterprise")]
    AiVerdict = 889,
    // SPDX-SnippetEnd
    AlarmId = 938,
    AlertAfter = 957,
    Algorithms = 265,
    Aliases = 411,
    AllowCount = 903,
    AllowDirectoryQueries = 809,
    AllowExternalRcpts = 203,
    AllowIdTokenClaims = 717,
    AllowInvalidCerts = 41,
    AllowPlainTextAuth = 502,
    AllowRelaying = 419,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    AllowScimProvisioning = 421,
    // SPDX-SnippetEnd
    AllowSpamTraining = 446,
    AllowedEndpoints = 475,
    AllowedIps = 63,
    AllowedNotifyUris = 824,
    Alpha = 464,
    AnonymousTimeout = 506,
    Ansi = 999,
    ApiKey = 39,
    ApiKeyId = 372,
    ApiUser = 390,
    ApplicationKey = 399,
    ApplicationSecret = 400,
    ArcResult = 337,
    ArcVerify = 804,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ArchiveDeletedAccountsFor = 241,
    #[cfg(feature = "enterprise")]
    ArchiveDeletedItemsFor = 240,
    #[cfg(feature = "enterprise")]
    ArchivedAt = 72,
    #[cfg(feature = "enterprise")]
    ArchivedItemType = 961,
    #[cfg(feature = "enterprise")]
    ArchivedUntil = 73,
    // SPDX-SnippetEnd
    ArrivalDate = 82,
    AsnUrls = 116,
    AttemptNumber = 971,
    Attempts = 348,
    AttrClass = 559,
    AttrDescription = 560,
    AttrEmail = 561,
    AttrEmailAlias = 562,
    AttrMemberOf = 563,
    AttrSecret = 564,
    AttrSecretChanged = 565,
    Auid = 253,
    Auth = 139,
    AuthBanPeriod = 794,
    AuthBanRate = 793,
    AuthCodeExpiry = 719,
    AuthFailure = 95,
    AuthId = 370,
    AuthSecret = 597,
    AuthUsername = 598,
    AuthenticatedAs = 882,
    AuthenticatedTimeout = 507,
    AuthenticationResults = 83,
    AutoAddInvitations = 209,
    AutoUpdateInterval = 66,
    AvailabilityRateLimit = 201,
    BaseDn = 552,
    BearerToken = 482,
    Beta = 465,
    Bind = 681,
    BindAuthentication = 555,
    BindDn = 553,
    BindSecret = 554,
    BlobCleanupSchedule = 238,
    BlobId = 74,
    BlobSize = 763,
    BlobStore = 153,
    BlockCount = 901,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Body = 52,
    #[cfg(feature = "enterprise")]
    BreakerCooldown = 862,
    #[cfg(feature = "enterprise")]
    BreakerThreshold = 861,
    // SPDX-SnippetEnd
    Bucket = 767,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    BucketHigh = 845,
    #[cfg(feature = "enterprise")]
    BucketMedium = 846,
    // SPDX-SnippetEnd
    BufferSize = 764,
    Buffered = 1004,
    CaaIdentities = 19,
    CacheSize = 766,
    Canonicalization = 254,
    CatchAllAddress = 417,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Categories = 843,
    // SPDX-SnippetEnd
    Certificate = 214,
    CertificateManagement = 413,
    ChallengeType = 10,
    ChunkSize = 756,
    Chunking = 614,
    ClaimGroups = 709,
    ClaimName = 708,
    ClaimUsername = 706,
    Cleartext = 807,
    ClientCapacity = 677,
    ClientHash = 1012,
    ClientId = 132,
    ClientIp = 391,
    ClientIpSource = 479,
    ClientKind = 701,
    ClientMetadataDocuments = 727,
    ClientName = 700,
    ClientSecret = 133,
    ClientToken = 377,
    ClusterFile = 458,
    ColumnClass = 921,
    ColumnDescription = 922,
    ColumnEmail = 919,
    ColumnSecret = 920,
    CommandTimeout = 631,
    Comment = 280,
    CompartmentOcid = 398,
    CompressionAlgorithm = 431,
    Condition = 48,
    Config = 1011,
    ConfigName = 367,
    ConnectTimeout = 602,
    Connection = 634,
    ConsumerKey = 401,
    Contact = 11,
    ContactInfo = 986,
    Contacts = 160,
    Container = 137,
    ContentTypes = 900,
    Contents = 79,
    Context = 364,
    Count = 301,
    Create = 444,
    CreatedAt = 60,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    CreatedBy = 575,
    // SPDX-SnippetEnd
    CredentialId = 730,
    Credentials = 385,
    CurrentSecret = 4,
    CustomRule = 927,
    CustomerNumber = 392,
    Dane = 664,
    DataCleanupSchedule = 237,
    DataStore = 152,
    DataTimeout = 603,
    DataTypes = 582,
    Database = 670,
    DatacenterId = 459,
    DateRangeEnd = 286,
    DateRangeStart = 285,
    Day = 230,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Deadline = 860,
    // SPDX-SnippetEnd
    DefaultAdminRoleIds = 123,
    DefaultCertificateId = 929,
    DefaultDisplayName = 24,
    DefaultDomain = 149,
    DefaultDomainId = 928,
    DefaultExpiryDuplicate = 821,
    DefaultExpiryVacation = 822,
    DefaultFolders = 432,
    DefaultFromAddress = 484,
    DefaultFromName = 811,
    DefaultGroupRoleIds = 121,
    DefaultHostname = 148,
    DefaultHrefName = 25,
    DefaultLanguage = 770,
    DefaultName = 487,
    DefaultReturnPath = 814,
    DefaultSubject = 489,
    DefaultSubjectPrefix = 826,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    DefaultTenantRoleIds = 122,
    // SPDX-SnippetEnd
    DefaultUserRoleIds = 120,
    Definition = 275,
    Delay = 966,
    DeleteAfter = 269,
    DeleteAfterUse = 918,
    DeliverAt = 278,
    DeliverBy = 615,
    DeliverTo = 483,
    DeliveryResult = 96,
    Depth = 457,
    Description = 6,
    Details = 342,
    Directory = 12,
    DirectoryId = 119,
    DirectoryRecipients = 188,
    DirectoryRecipientsTtl = 189,
    DisableCapabilities = 823,
    DisabledPermissions = 732,
    DiscardAfter = 1010,
    Disposition = 890,
    Dkim2Pass = 336,
    Dkim2Result = 335,
    DkimAdspDns = 97,
    DkimCanonicalizedBody = 98,
    DkimCanonicalizedHeader = 99,
    DkimDomain = 100,
    DkimIdentity = 101,
    DkimManagement = 414,
    DkimPass = 334,
    DkimResults = 309,
    DkimSelector = 102,
    DkimSelectorDns = 103,
    DkimSignDomain = 271,
    DkimSignatures = 186,
    DkimStrict = 800,
    DkimVerify = 801,
    DmarcPass = 339,
    DmarcPolicy = 340,
    DmarcResult = 338,
    DmarcVerify = 805,
    DnsIpv4 = 161,
    DnsIpv6 = 162,
    DnsManagement = 415,
    DnsMtaSts = 163,
    DnsMx = 164,
    DnsPtr = 165,
    DnsServer = 157,
    DnsServerId = 345,
    DnsTlsa = 167,
    DnsTxt = 168,
    DnsView = 387,
    DnsZoneFile = 416,
    DocumentId = 946,
    Domain = 272,
    DomainId = 259,
    DomainLimit = 892,
    DomainNames = 178,
    DomainNamesNegative = 179,
    Domains = 177,
    Dsn = 616,
    Due = 937,
    Duration = 612,
    EabHmacKey = 13,
    EabKeyId = 14,
    EhloDomain = 325,
    EhloHostname = 599,
    EhloTimeout = 604,
    Elapsed = 341,
    Else = 451,
    Email = 282,
    EmailAddress = 469,
    EmailAddresses = 180,
    EmailAddressesNegative = 181,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    EmailAlert = 49,
    #[cfg(feature = "enterprise")]
    EmailDomain = 577,
    // SPDX-SnippetEnd
    EmailLimit = 893,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    EmailPrefix = 576,
    #[cfg(feature = "enterprise")]
    EmailTemplate = 212,
    // SPDX-SnippetEnd
    Enable = 51,
    EnableAssistedDiscovery = 1005,
    EnableEdns = 349,
    EnableHsts = 476,
    EnableLogExporter = 1001,
    EnableSpamFilter = 657,
    EnableSpanExporter = 1002,
    EnabledPermissions = 731,
    EncryptAtRest = 430,
    EncryptOnAppend = 429,
    EncryptionAtRest = 9,
    EncryptionKey = 724,
    EnvId = 740,
    EnvelopeFrom = 307,
    EnvelopeTo = 306,
    Environment = 138,
    ErrorCommand = 248,
    ErrorMessage = 247,
    ErrorType = 246,
    Errors = 287,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    EscalateBelow = 867,
    #[cfg(feature = "enterprise")]
    EscalateOn = 868,
    // SPDX-SnippetEnd
    EvaluatedDisposition = 302,
    EvaluatedDkim = 303,
    EvaluatedSpf = 304,
    Event = 448,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    EventAlert = 50,
    // SPDX-SnippetEnd
    EventEnd = 941,
    EventEndTz = 943,
    EventId = 939,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    EventMessage = 57,
    // SPDX-SnippetEnd
    EventSourceThrottle = 532,
    EventStart = 940,
    EventStartTz = 942,
    Events = 169,
    EventsPolicy = 996,
    Expire = 255,
    Expires = 745,
    ExpiresAt = 61,
    ExpiresAttempts = 735,
    Expiry = 609,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Explanation = 851,
    // SPDX-SnippetEnd
    Expn = 617,
    ExpungeSchedule = 236,
    ExpungeSchedulingInboxAfter = 235,
    ExpungeShareNotifyAfter = 234,
    ExpungeSubmissionsAfter = 233,
    ExpungeTrashAfter = 232,
    Extension = 896,
    Extensions = 297,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ExternalId = 472,
    // SPDX-SnippetEnd
    ExtraContactInfo = 283,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ExtraParameters = 35,
    // SPDX-SnippetEnd
    Factor = 962,
    FailOnTimeout = 579,
    FailedAt = 968,
    FailedAttemptNumber = 969,
    FailedSessionCount = 979,
    FailureDetails = 992,
    FailureDkimSignDomain = 321,
    FailureFromAddress = 318,
    FailureFromName = 319,
    FailureReason = 970,
    FailureReasonCode = 981,
    FailureSendFrequency = 320,
    FailureSubject = 322,
    FeatureL2Normalize = 880,
    FeatureLogScale = 881,
    FeedbackType = 81,
    FieldEmail = 485,
    FieldHoneyPot = 486,
    FieldName = 488,
    FieldSubject = 490,
    FilePath = 790,
    Files = 171,
    FilterLogin = 556,
    FilterMemberOf = 558,
    FilterRecipient = 557,
    Fingerprint = 395,
    FirstFailedAt = 972,
    FirstParty = 697,
    Flags = 263,
    FlagsAction = 632,
    FlagsProtocol = 633,
    FlushChanges = 144,
    FlushInterval = 145,
    FolderId = 410,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ForDomain = 574,
    // SPDX-SnippetEnd
    Format = 493,
    ForwardedHops = 480,
    From = 76,
    FromAddress = 53,
    FromName = 54,
    FutureRelease = 618,
    GenerateDkimKeys = 151,
    Generation = 703,
    Generator = 298,
    GeoUrls = 117,
    GrantTypes = 699,
    GreetingTimeout = 605,
    GreylistFor = 905,
    GroupClass = 566,
    GroupId = 548,
    GroupwareLarge = 175,
    GroupwareLargeTtl = 176,
    HeaderFrom = 308,
    Headers = 107,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    HoldMetricsFor = 244,
    // SPDX-SnippetEnd
    HoldMtaReportsFor = 242,
    HoldSamplesFor = 872,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    HoldTracesFor = 243,
    // SPDX-SnippetEnd
    Host = 376,
    HostedZoneId = 404,
    Hostname = 223,
    Hosts = 547,
    Hour = 228,
    HttpAuth = 118,
    HttpHeaders = 40,
    HttpRsvpEnable = 206,
    HttpRsvpLinkExpiry = 207,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    HttpRsvpTemplate = 213,
    // SPDX-SnippetEnd
    HttpRsvpUrl = 208,
    HttpRua = 984,
    HumanResult = 274,
    ICalendarData = 948,
    Id = 1,
    IdTokenExpiry = 723,
    IdentityAlignment = 105,
    IdleTimeout = 508,
    If = 452,
    ImapServerAdmin = 589,
    ImapServerComment = 588,
    ImpersonateServiceAccount = 384,
    ImplicitTls = 641,
    InMemoryStore = 155,
    InboundReportAddresses = 758,
    InboundReportForwarding = 759,
    Incidents = 84,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    IncludeAttachments = 859,
    #[cfg(feature = "enterprise")]
    IncludeAuth = 857,
    #[cfg(feature = "enterprise")]
    IncludeLinks = 858,
    // SPDX-SnippetEnd
    IncludeSecrets = 935,
    IncludeSource = 424,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Includes = 838,
    // SPDX-SnippetEnd
    Index = 513,
    IndexAsn = 108,
    IndexAsnName = 109,
    IndexBatchSize = 769,
    IndexCalendar = 772,
    IndexCalendarFields = 773,
    IndexContactFields = 775,
    IndexContacts = 774,
    IndexCountry = 110,
    IndexEmail = 776,
    IndexEmailFields = 777,
    IndexFiles = 780,
    IndexKey = 498,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    IndexTelemetry = 778,
    // SPDX-SnippetEnd
    IndexValue = 499,
    IndicatorParameters = 878,
    InitialDelay = 963,
    InstanceHashes = 264,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Instructions = 842,
    // SPDX-SnippetEnd
    Interval = 596,
    Intervals = 613,
    IntrospectionAuthMethod = 714,
    IntrospectionClientId = 712,
    IntrospectionClientSecret = 713,
    IpLimit = 894,
    IpLookupStrategy = 638,
    IpRevPtr = 333,
    IpRevResult = 332,
    IsActive = 820,
    IsArchive = 897,
    IsBad = 898,
    IsFromOrganizer = 947,
    IsGlobPattern = 580,
    IsGzipped = 494,
    IsNz = 899,
    IsSenderAllowed = 659,
    IsSpam = 917,
    IsTls = 883,
    Issuer = 219,
    IssuerDomainNames = 18,
    IssuerUrl = 705,
    Jitter = 965,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    KeepAlive = 46,
    // SPDX-SnippetEnd
    Key = 375,
    KeyName = 406,
    KeyPrefix = 141,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    KeyValues = 994,
    // SPDX-SnippetEnd
    L1Ratio = 467,
    L2Ratio = 468,
    LastRenewal = 224,
    LastUsedAt = 702,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Learn = 863,
    // SPDX-SnippetEnd
    LearnHamFromCard = 869,
    LearnHamFromReply = 877,
    LearnSpamFromRblHits = 870,
    LearnSpamFromTraps = 871,
    LenientIssuerMatch = 718,
    Level = 449,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    LicenseKey = 447,
    // SPDX-SnippetEnd
    Line = 358,
    ListenerIds = 221,
    Listeners = 226,
    LocalIp = 600,
    LocalIps = 601,
    Locale = 7,
    Logo = 412,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Logprobs = 45,
    // SPDX-SnippetEnd
    LoiterBanPeriod = 796,
    LoiterBanRate = 795,
    Lossy = 995,
    MachineId = 460,
    MailExchangers = 932,
    MailFrom = 326,
    MailFromParameters = 884,
    MailFromTimeout = 606,
    MailRua = 983,
    MailingLists = 185,
    MaintenanceType = 936,
    ManagedZone = 382,
    Match = 450,
    MaxAccountSize = 146,
    MaxAddressBooks = 27,
    MaxAddressBooksPerCard = 30,
    MaxAge = 661,
    MaxAggregateReportSize = 314,
    MaxAllowedPacket = 671,
    MaxApiKeys = 130,
    MaxAppPasswords = 129,
    MaxAttachmentSize = 425,
    MaxAttachmentText = 912,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaxAttachments = 855,
    // SPDX-SnippetEnd
    MaxAttachmentsSize = 202,
    MaxAttempts = 608,
    MaxAttendees = 191,
    MaxAuthFailures = 503,
    MaxAvailabilityDuration = 200,
    MaxBodyText = 911,
    MaxBufferedMemory = 930,
    MaxCalendars = 194,
    MaxCalendarsPerEvent = 198,
    MaxChangesHistory = 239,
    MaxChangesResults = 521,
    MaxConcurrentConnections = 504,
    MaxConcurrentIndexTasks = 779,
    MaxConcurrentRequests = 43,
    MaxConcurrentUploads = 527,
    MaxConnections = 694,
    MaxContacts = 28,
    MaxCpuCycles = 815,
    MaxDelay = 964,
    MaxDepth = 585,
    MaxDuration = 627,
    MaxEntries = 495,
    MaxEntrySize = 496,
    MaxEventNotifications = 197,
    MaxEvents = 195,
    MaxExpandedQueryDuration = 199,
    MaxExtractArchiveEntries = 786,
    MaxExtractDecompressedSize = 783,
    MaxExtractDocumentSize = 781,
    MaxExtractPartSize = 784,
    MaxExtractParts = 785,
    MaxExtractPdfObjects = 787,
    MaxExtractRtfDepth = 788,
    MaxExtractTextSize = 782,
    MaxFailures = 642,
    MaxFiles = 454,
    MaxFlagLength = 441,
    MaxFlagsPerEmail = 440,
    MaxFolders = 455,
    MaxGetResults = 522,
    MaxHeaderCount = 443,
    MaxHeaderSize = 442,
    MaxICalendarSize = 193,
    MaxIdentities = 435,
    MaxInboundReportSize = 762,
    MaxIncludes = 827,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaxInputChars = 853,
    // SPDX-SnippetEnd
    MaxItipSize = 210,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaxLinks = 854,
    // SPDX-SnippetEnd
    MaxLivePropertySize = 1008,
    MaxLocalVars = 828,
    MaxLockTimeout = 1006,
    MaxLocks = 1007,
    MaxMailboxDepth = 427,
    MaxMailboxNameLength = 428,
    MaxMailboxes = 436,
    MaxMailboxesPerEmail = 439,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaxMaskedAddresses = 437,
    // SPDX-SnippetEnd
    MaxMatchVars = 829,
    MaxMediaSize = 31,
    MaxMessageSize = 426,
    MaxMessageText = 913,
    MaxMessages = 433,
    MaxMessagesPerCommand = 509,
    MaxMessagesPerSave = 512,
    MaxMethodCalls = 524,
    MaxMultihomed = 639,
    MaxMxHosts = 640,
    MaxNestedBlocks = 831,
    MaxNestedForEvery = 832,
    MaxNestedIncludes = 816,
    MaxNestedTests = 833,
    MaxOutMessages = 817,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaxOutputTokens = 32,
    // SPDX-SnippetEnd
    MaxParticipantIdentities = 196,
    MaxPasswordLength = 126,
    MaxPolls = 578,
    MaxPrivateSize = 586,
    MaxPublicKeys = 438,
    MaxPushAttempts = 534,
    MaxPushSize = 546,
    MaxQueryResults = 523,
    MaxQueryScan = 587,
    MaxReceivedHeaders = 656,
    MaxRecipients = 211,
    MaxReconnects = 674,
    MaxRecurrenceExpansions = 192,
    MaxRedirectUrls = 914,
    MaxRedirects = 818,
    MaxReportSize = 993,
    MaxRequestSize = 505,
    MaxResponseSize = 624,
    MaxResults = 1009,
    MaxRetries = 140,
    MaxRetryWait = 750,
    MaxScriptNameLength = 830,
    MaxScriptSize = 834,
    MaxScripts = 837,
    MaxSetObjects = 525,
    MaxShares = 810,
    MaxSize = 115,
    MaxSnippetResults = 526,
    MaxStringLength = 835,
    MaxSubmissions = 434,
    MaxSubscriptions = 543,
    MaxUidBatches = 511,
    MaxUploadCount = 529,
    MaxUploadSize = 528,
    MaxVCardSize = 26,
    MaxVarNameLength = 836,
    MaxVarSize = 819,
    MemberGroupIds = 953,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MemberTenantId = 21,
    // SPDX-SnippetEnd
    Message = 106,
    MessageIdHostname = 812,
    MessageIds = 959,
    MessageTimeout = 549,
    Messages = 172,
    MessagesLarge = 173,
    MessagesLargeTtl = 174,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Metric = 590,
    // SPDX-SnippetEnd
    Metrics = 594,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MetricsCollectionInterval = 245,
    // SPDX-SnippetEnd
    MetricsPolicy = 595,
    MinAccountSize = 147,
    MinHamSamples = 873,
    MinPasswordLength = 125,
    MinPasswordStrength = 127,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MinProbability = 839,
    // SPDX-SnippetEnd
    MinRetryWait = 751,
    MinSpamSamples = 874,
    MinTriggerInterval = 204,
    MinUidBatchSize = 510,
    Minute = 229,
    Mode = 662,
    Model = 37,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ModelId = 866,
    // SPDX-SnippetEnd
    MtPriority = 619,
    MtaSts = 665,
    MtaStsTimeout = 667,
    Multiline = 1000,
    MustMatchSender = 645,
    MxHosts = 663,
    Name = 36,
    Namespace = 492,
    NegativeTtl = 187,
    NextNotify = 736,
    NextRetry = 517,
    NextTransitionAt = 261,
    NoCapabilityCheck = 813,
    NoEcho = 680,
    NoSoliciting = 620,
    NodeId = 222,
    NotValidAfter = 217,
    NotValidBefore = 218,
    Notify = 610,
    NotifyCount = 743,
    NotifyDue = 744,
    NumFeatures = 466,
    NumReplicas = 422,
    NumShards = 423,
    OauthClientId = 68,
    ObjectType = 967,
    OnSuccessRenewCertificate = 955,
    OpaqueTokenValidation = 711,
    OpenTelemetry = 592,
    Options = 733,
    Orcpt = 747,
    OrgName = 281,
    OrganizationName = 985,
    Origin = 346,
    OriginalEnvelopeId = 85,
    OriginalMailFrom = 86,
    OriginalRcptTo = 87,
    OtpAuth = 5,
    OtpCode = 728,
    OtpUrl = 729,
    OutboundReportDomain = 760,
    OutboundReportSubmitter = 761,
    OverrideProxyTrustedNetworks = 682,
    OverrideType = 279,
    OvhEndpoint = 402,
    Parameters = 879,
    ParseLimitContact = 519,
    ParseLimitEmail = 520,
    ParseLimitEvent = 518,
    Partition = 514,
    Password = 363,
    PasswordDefaultExpiry = 128,
    PasswordHashAlgorithm = 124,
    Path = 456,
    Pending = 704,
    Period = 748,
    Permissions = 62,
    PingInterval = 676,
    Pipelining = 621,
    Policies = 987,
    PolicyAdkim = 290,
    PolicyAspf = 291,
    PolicyDiscoveryMethod = 300,
    PolicyDisposition = 292,
    PolicyDomain = 288,
    PolicyFailureReportingOptions = 295,
    PolicyIdentifier = 277,
    PolicyIdentifiers = 982,
    PolicyNp = 299,
    PolicyOverrideReasons = 305,
    PolicyStrings = 989,
    PolicySubdomainDisposition = 293,
    PolicyTestingMode = 294,
    PolicyType = 988,
    PolicyVersion = 289,
    PollInterval = 360,
    PoolMaxConnections = 567,
    PoolMinConnections = 672,
    PoolRecyclingMethod = 734,
    PoolTimeoutCreate = 568,
    PoolTimeoutRecycle = 569,
    PoolTimeoutWait = 570,
    PoolWorkers = 765,
    Port = 344,
    PostLogoutRedirectUris = 696,
    PreferredChain = 22,
    Prefix = 997,
    PreserveIntermediates = 350,
    Priority = 572,
    PrivateKey = 215,
    PrivateKeyPassword = 397,
    PrivateKeyPem = 396,
    PrivateMetadata = 584,
    PrivateZone = 383,
    PrivateZoneOnly = 405,
    Profile = 47,
    ProjectId = 381,
    Prometheus = 593,
    PropagationDelay = 362,
    PropagationTimeout = 361,
    ProtectedHeaders = 825,
    Protocol = 343,
    ProtocolVersion = 630,
    ProviderInfo = 934,
    ProxyTrustedNetworks = 931,
    PublicKey = 256,
    PublishRecords = 347,
    PushAttemptWait = 533,
    PushRequestTimeout = 537,
    PushRetryWait = 535,
    PushShardsTotal = 539,
    PushThrottle = 536,
    PushVerifyTimeout = 538,
    QueryEmailAliases = 926,
    QueryLogin = 923,
    QueryMemberOf = 925,
    QueryRecipient = 924,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Question = 865,
    // SPDX-SnippetEnd
    QueueId = 611,
    QueueName = 746,
    QueuedDeletions = 516,
    QueuedUpdates = 515,
    Quotas = 470,
    Rate = 629,
    RateLimit = 44,
    RateLimitAnonymous = 474,
    RateLimitAuthenticated = 473,
    Ratio = 902,
    RcptTo = 327,
    RcptToTimeout = 607,
    ReadBufferCapacity = 678,
    ReadFromReplicas = 752,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ReadReplicas = 673,
    // SPDX-SnippetEnd
    Reason = 59,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Reasoning = 34,
    // SPDX-SnippetEnd
    ReceivedAt = 77,
    ReceivedFromIp = 738,
    ReceivedViaPort = 739,
    ReceivingIp = 978,
    ReceivingMxHelo = 977,
    ReceivingMxHostname = 976,
    Recipients = 573,
    Records = 296,
    RecurrenceId = 945,
    RedirectCacheTtl = 916,
    RedirectRoot = 481,
    RedirectTimeout = 915,
    RedirectUris = 695,
    RefreshInterval = 114,
    RefreshTokenExpiry = 720,
    Region = 356,
    RejectNonFqdn = 658,
    RemoteIp = 324,
    RenewBefore = 20,
    Report = 80,
    ReportAddressUri = 420,
    ReportId = 284,
    ReportedDomains = 88,
    ReportedUris = 89,
    ReportingMta = 90,
    RequestTimeout = 675,
    RequestTlsCertificate = 150,
    Require = 646,
    RequireTls = 622,
    ReservoirCapacity = 875,
    ResourceAttributes = 1014,
    ResourceGroup = 366,
    ResourceUrl = 64,
    ResponseCode = 250,
    ResponseEnhanced = 251,
    ResponseHeaders = 478,
    ResponseHostname = 249,
    ResponseMessage = 252,
    Result = 273,
    ResultType = 974,
    Retention = 143,
    RetireAfter = 268,
    Retry = 497,
    RetryCount = 741,
    RetryDue = 742,
    ReturnPath = 737,
    ReuseKey = 23,
    ReverseIpVerify = 806,
    Rewrite = 660,
    RoleIds = 231,
    Roles = 183,
    Rotate = 998,
    RotateAfter = 267,
    Route = 635,
    Rua = 276,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SampleRate = 840,
    // SPDX-SnippetEnd
    Sandbox = 389,
    SasToken = 134,
    SaslMechanisms = 644,
    ScanBanPaths = 797,
    ScanBanPeriod = 799,
    ScanBanRate = 798,
    Schedule = 636,
    Scheduling = 170,
    Scheme = 409,
    Scope = 323,
    Scopes = 698,
    Score = 885,
    ScoreDiscard = 906,
    ScoreReject = 907,
    ScoreSpam = 908,
    Script = 648,
    SearchStore = 154,
    Secret = 3,
    SecretKey = 355,
    Selector = 260,
    SelectorTemplate = 266,
    SendFrequency = 270,
    SendingMtaIp = 975,
    SentinelSecret = 755,
    SentinelUsername = 754,
    Separator = 111,
    ServerId = 403,
    Servers = 352,
    ServiceAccountJson = 380,
    ServiceName = 753,
    ServiceNamespace = 1013,
    Services = 933,
    SessionTimeout = 550,
    SessionToken = 357,
    ShardIndex = 973,
    SharedSecret = 388,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Signals = 844,
    // SPDX-SnippetEnd
    SignatureAlgorithm = 725,
    SignatureKey = 726,
    Size = 78,
    SkipAudienceValidation = 716,
    SkipDeploy = 369,
    SkipFirst = 500,
    SmtpGreeting = 647,
    SocketBacklog = 683,
    SocketNoDelay = 684,
    SocketReceiveBufferSize = 685,
    SocketReuseAddress = 686,
    SocketReusePort = 687,
    SocketSendBufferSize = 688,
    SocketTosV4 = 689,
    SocketTtl = 690,
    SourceIp = 91,
    SourcePort = 92,
    SpamFilterRulesUrl = 910,
    SpamLookup = 166,
    SpfDns = 104,
    SpfEhloDomain = 328,
    SpfEhloResult = 329,
    SpfEhloVerify = 802,
    SpfFromVerify = 803,
    SpfMailFromDomain = 330,
    SpfMailFromResult = 331,
    SpfResults = 310,
    Stage = 262,
    Stages = 626,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    StartTime = 70,
    // SPDX-SnippetEnd
    StartTls = 666,
    Status = 75,
    StorageAccount = 136,
    Store = 142,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Stores = 808,
    // SPDX-SnippetEnd
    Strategy = 956,
    SubAddressing = 418,
    SubAuthId = 371,
    Subject = 55,
    SubjectAlternativeNames = 216,
    Subscribe = 445,
    SubscriptionCapacity = 679,
    SubscriptionId = 365,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sum = 591,
    // SPDX-SnippetEnd
    Summary = 949,
    SupportedLanguages = 771,
    Swap = 190,
    Tag = 891,
    Tags = 886,
    TargetAccountId = 944,
    TaskTypes = 227,
    Tasks = 225,
    TcpOnError = 351,
    TeamId = 408,
    TempFailOnError = 625,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Temperature = 33,
    #[cfg(feature = "enterprise")]
    Template = 205,
    // SPDX-SnippetEnd
    TenancyOcid = 393,
    TenantId = 131,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Tenants = 184,
    // SPDX-SnippetEnd
    Text = 2,
    Then = 453,
    ThirdParty = 257,
    ThirdPartyHash = 258,
    ThreadName = 958,
    ThreadsPerNode = 669,
    Throttle = 1003,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Tiers = 841,
    // SPDX-SnippetEnd
    TimeZone = 8,
    Timeout = 42,
    Timestamp = 571,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Title = 69,
    // SPDX-SnippetEnd
    Tls = 637,
    TlsDisableCipherSuites = 691,
    TlsDisableProtocols = 692,
    TlsIgnoreClientOrder = 693,
    TlsTimeout = 668,
    To = 56,
    Token = 373,
    TokenFile = 135,
    TotalFailedSessions = 991,
    TotalSuccessfulSessions = 990,
    Tracer = 156,
    TrainInterval = 876,
    TransactionRetryDelay = 461,
    TransactionRetryLimit = 462,
    TransactionTimeout = 463,
    TransferLimit = 628,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TrimQuotes = 856,
    // SPDX-SnippetEnd
    TrustContacts = 904,
    TrustReplies = 909,
    TsigAlgorithm = 407,
    Ttl = 359,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    UncertainBelow = 847,
    // SPDX-SnippetEnd
    UnpackDirectory = 67,
    UnscopedTokens = 715,
    UpdateRecords = 954,
    UploadQuota = 530,
    UploadTtl = 531,
    Url = 38,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    UrlFailover = 551,
    // SPDX-SnippetEnd
    UrlLimit = 895,
    UrlPrefix = 65,
    Urls = 749,
    UsePermissiveCors = 477,
    UseTls = 353,
    UsedDiskQuota = 471,
    UserAgent = 93,
    UserCodeExpiry = 722,
    UserOcid = 394,
    Username = 158,
    UsernameDomain = 707,
    VCardVersion = 29,
    ValidateDomain = 491,
    Value = 581,
    VariableName = 789,
    VendorNamespaces = 583,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    VerbalHigh = 848,
    #[cfg(feature = "enterprise")]
    VerbalLow = 850,
    #[cfg(feature = "enterprise")]
    VerbalMedium = 849,
    // SPDX-SnippetEnd
    VerifyAfterWrite = 768,
    Version = 94,
    ViewName = 368,
    Vrfy = 623,
    WaitOnFail = 643,
    WapiVersion = 386,
    Warnings = 757,
    WebPushContact = 545,
    WebPushKey = 544,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    WebSearch = 864,
    // SPDX-SnippetEnd
    WebsocketHeartbeat = 540,
    WebsocketThrottle = 541,
    WebsocketTimeout = 542,
    WindowEnd = 960,
    Zone = 501,
    ZoneIpV4 = 112,
    ZoneIpV6 = 113,
}
