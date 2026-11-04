/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AccountType {
    #[default]
    User = 0,
    Group = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AcmeChallengeType {
    #[default]
    TlsAlpn01 = 0,
    DnsPersist01 = 1,
    Dns01 = 2,
    Http01 = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AcmeRenewBefore {
    #[default]
    R12 = 0,
    R23 = 1,
    R34 = 2,
    R45 = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ActionType {
    #[default]
    ReloadSettings = 0,
    ReloadTlsCertificates = 1,
    ReloadLookupStores = 2,
    ReloadBlockedIps = 3,
    UpdateApps = 4,
    TroubleshootDmarc = 5,
    ClassifySpam = 6,
    InvalidateCaches = 7,
    InvalidateNegativeCaches = 8,
    PauseMtaQueue = 9,
    ResumeMtaQueue = 10,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AiModelType {
    #[default]
    OpenAi = 0,
    Anthropic = 1,
    Gemini = 2,
    Ollama = 3,
    TypeSafe = 4,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AiOpenAiProfile {
    #[default]
    OpenAi = 0,
    Azure = 1,
    Vllm = 2,
    LlamaCpp = 3,
    Generic = 4,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AiReasoning {
    #[default]
    Default = 0,
    Off = 1,
    Low = 2,
    Medium = 3,
    High = 4,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlertEmailType {
    #[default]
    Disabled = 0,
    Enabled = 1,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlertEventType {
    #[default]
    Disabled = 0,
    Enabled = 1,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArchivedItemStatus {
    #[default]
    Archived = 0,
    RequestRestore = 1,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArchivedItemType {
    #[default]
    Email = 0,
    FileNode = 1,
    CalendarEvent = 2,
    ContactCard = 3,
    SieveScript = 4,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArfAuthFailureType {
    #[default]
    Adsp = 0,
    BodyHash = 1,
    Revoked = 2,
    Signature = 3,
    Spf = 4,
    Dmarc = 5,
    Unspecified = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArfDeliveryResult {
    #[default]
    Delivered = 0,
    Spam = 1,
    Policy = 2,
    Reject = 3,
    Other = 4,
    Unspecified = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArfFeedbackType {
    #[default]
    Abuse = 0,
    AuthFailure = 1,
    Fraud = 2,
    NotSpam = 3,
    Virus = 4,
    Other = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArfIdentityAlignment {
    #[default]
    None = 0,
    Spf = 1,
    Dkim = 2,
    DkimSpf = 3,
    Unspecified = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AsnType {
    #[default]
    Disabled = 0,
    Resource = 1,
    Dns = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AzureAuthType {
    #[default]
    SharedKey = 0,
    SasToken = 1,
    ClientSecret = 2,
    ManagedIdentity = 3,
    WorkloadIdentity = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AzureEnvironment {
    #[default]
    Public = 0,
    China = 1,
    UsGovernment = 2,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BlobStoreBaseType {
    #[default]
    S3 = 0,
    Azure = 1,
    FileSystem = 2,
    FoundationDb = 3,
    PostgreSql = 4,
    MySql = 5,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BlobStoreType {
    #[default]
    Default = 0,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded = 1,
    // SPDX-SnippetEnd
    S3 = 2,
    Azure = 3,
    FileSystem = 4,
    FoundationDb = 5,
    PostgreSql = 6,
    MySql = 7,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BlobSwapStoreType {
    #[default]
    Default = 0,
    S3 = 1,
    Azure = 2,
    FileSystem = 3,
    FoundationDb = 4,
    PostgreSql = 5,
    MySql = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BlockReason {
    #[default]
    RcptToFailure = 0,
    AuthFailure = 1,
    Loitering = 2,
    PortScanning = 3,
    Manual = 4,
    Other = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CacheSwapType {
    #[default]
    Disabled = 0,
    LocalFile = 1,
    Redis = 2,
    BlobStore = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CertificateManagementType {
    #[default]
    Manual = 0,
    Automatic = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClientIpSource {
    #[default]
    Peer = 0,
    XForwardedFor = 1,
    Forwarded = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClusterListenerGroupType {
    #[default]
    EnableAll = 0,
    DisableAll = 1,
    EnableSome = 2,
    DisableSome = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClusterNodeStatus {
    #[default]
    Active = 0,
    Stale = 1,
    Inactive = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClusterTaskGroupType {
    #[default]
    EnableAll = 0,
    DisableAll = 1,
    EnableSome = 2,
    DisableSome = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClusterTaskType {
    #[default]
    StoreMaintenance = 0,
    AccountMaintenance = 1,
    MetricsCalculate = 2,
    MetricsPush = 3,
    PushNotifications = 4,
    SearchIndexing = 5,
    SpamClassifierTraining = 6,
    OutboundMta = 7,
    TaskQueueProcessing = 8,
    TaskScheduler = 9,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CompressionAlgo {
    #[default]
    Lz4 = 0,
    None = 1,
    Zstd = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CoordinatorType {
    #[default]
    Disabled = 0,
    Default = 1,
    Kafka = 2,
    Nats = 3,
    Zenoh = 4,
    Redis = 5,
    RedisCluster = 6,
    RedisSentinel = 7,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CredentialPermissionsType {
    #[default]
    Inherit = 0,
    Disable = 1,
    Replace = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CredentialType {
    #[default]
    Password = 0,
    AppPassword = 1,
    ApiKey = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CronType {
    #[default]
    Daily = 0,
    Weekly = 1,
    Hourly = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DataStoreType {
    #[default]
    RocksDb = 0,
    Sqlite = 1,
    FoundationDb = 2,
    PostgreSql = 3,
    MySql = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DeliveryErrorType {
    #[default]
    DnsError = 0,
    UnexpectedResponse = 1,
    ConnectionError = 2,
    TlsError = 3,
    DaneError = 4,
    MtaStsError = 5,
    RateLimited = 6,
    ConcurrencyLimited = 7,
    Io = 8,
    EncryptionError = 9,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DirectoryBootstrapType {
    #[default]
    Internal = 0,
    Ldap = 1,
    Sql = 2,
    Oidc = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DirectoryType {
    #[default]
    Ldap = 0,
    Sql = 1,
    Oidc = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Dkim2Flag {
    #[default]
    Feedback = 0,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Dkim2HashAlgorithm {
    #[default]
    Sha256 = 0,
    Sha512 = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimAuthResult {
    #[default]
    None = 0,
    Pass = 1,
    Fail = 2,
    Policy = 3,
    Neutral = 4,
    TempError = 5,
    PermError = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimCanonicalization {
    #[default]
    RelaxedRelaxed = 0,
    SimpleSimple = 1,
    RelaxedSimple = 2,
    SimpleRelaxed = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimHash {
    #[default]
    Sha256 = 0,
    Sha1 = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimManagementType {
    #[default]
    Automatic = 0,
    Manual = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimRotationStage {
    #[default]
    Active = 0,
    Pending = 1,
    Retiring = 2,
    Retired = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimSignatureType {
    #[default]
    Dkim1Ed25519Sha256 = 0,
    Dkim1RsaSha256 = 1,
    Dkim2Ed25519Sha256 = 2,
    Dkim2RsaSha256 = 3,
    Dkim2MlDsa44 = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcActionDisposition {
    #[default]
    None = 0,
    Pass = 1,
    Quarantine = 2,
    Reject = 3,
    Unspecified = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcAlignment {
    #[default]
    Relaxed = 0,
    Strict = 1,
    Unspecified = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcDiscovery {
    #[default]
    Psl = 0,
    Treewalk = 1,
    Unspecified = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcDisposition {
    #[default]
    None = 0,
    Quarantine = 1,
    Reject = 2,
    Unspecified = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcPolicyOverride {
    #[default]
    Forwarded = 0,
    SampledOut = 1,
    TrustedForwarder = 2,
    MailingList = 3,
    LocalPolicy = 4,
    Other = 5,
    PolicyTestMode = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcResult {
    #[default]
    Pass = 0,
    Fail = 1,
    Unspecified = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcTroubleshootAuthResultType {
    #[default]
    Pass = 0,
    Fail = 1,
    SoftFail = 2,
    TempError = 3,
    PermError = 4,
    Neutral = 5,
    None = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsManagementType {
    #[default]
    Manual = 0,
    Automatic = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsPublishStatus {
    #[default]
    Synced = 0,
    Pending = 1,
    Failed = 2,
    Unknown = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsRecordType {
    #[default]
    Dkim = 0,
    Tlsa = 1,
    Spf = 2,
    Mx = 3,
    Dmarc = 4,
    Srv = 5,
    MtaSts = 6,
    TlsRpt = 7,
    Caa = 8,
    AutoConfig = 9,
    AutoConfigLegacy = 10,
    AutoDiscover = 11,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsResolverProtocol {
    #[default]
    Tls = 0,
    Udp = 1,
    Tcp = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsResolverType {
    #[default]
    System = 0,
    Custom = 1,
    Cloudflare = 2,
    Quad9 = 3,
    Google = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsServerBootstrapType {
    #[default]
    Manual = 0,
    Tsig = 1,
    Cloudflare = 2,
    DigitalOcean = 3,
    DeSEC = 4,
    Ovh = 5,
    Bunny = 6,
    Porkbun = 7,
    Dnsimple = 8,
    Spaceship = 9,
    Route53 = 10,
    GoogleCloudDns = 11,
    Alidns = 12,
    ArvanCloud = 13,
    Autodns = 14,
    AzureDns = 15,
    BaiduCloud = 16,
    BluecatV2 = 17,
    ClouDns = 18,
    Constellix = 19,
    Cpanel = 20,
    Ddnss = 21,
    DnsMadeEasy = 22,
    Domeneshop = 23,
    Dreamhost = 24,
    DuckDns = 25,
    Dynu = 26,
    EasyDns = 27,
    EdgeDns = 28,
    Exoscale = 29,
    FreeMyIp = 30,
    GandiV5 = 31,
    Gcore = 32,
    Glesys = 33,
    Godaddy = 34,
    Hetzner = 35,
    HostingDe = 36,
    Hostinger = 37,
    HuaweiCloud = 38,
    Hurricane = 39,
    IbmCloud = 40,
    Infoblox = 41,
    Infomaniak = 42,
    Inwx = 43,
    Ionos = 44,
    Ipv64 = 45,
    Joker = 46,
    Lightsail = 47,
    Linode = 48,
    LuaDns = 49,
    MythicBeasts = 50,
    Namecheap = 51,
    NameDotCom = 52,
    NameSilo = 53,
    Netcup = 54,
    Netlify = 55,
    Nifcloud = 56,
    Ns1 = 57,
    OracleCloud = 58,
    Plesk = 59,
    Safedns = 60,
    Scaleway = 61,
    TencentCloud = 62,
    Transip = 63,
    UltraDns = 64,
    Vercel = 65,
    Volcengine = 66,
    Vultr = 67,
    WebSupport = 68,
    YandexCloud = 69,
    PowerDns = 70,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsServerType {
    #[default]
    Tsig = 0,
    Cloudflare = 1,
    DigitalOcean = 2,
    DeSEC = 3,
    Ovh = 4,
    Bunny = 5,
    Porkbun = 6,
    Dnsimple = 7,
    Spaceship = 8,
    Route53 = 9,
    GoogleCloudDns = 10,
    Alidns = 11,
    ArvanCloud = 12,
    Autodns = 13,
    AzureDns = 14,
    BaiduCloud = 15,
    BluecatV2 = 16,
    ClouDns = 17,
    Constellix = 18,
    Cpanel = 19,
    Ddnss = 20,
    DnsMadeEasy = 21,
    Domeneshop = 22,
    Dreamhost = 23,
    DuckDns = 24,
    Dynu = 25,
    EasyDns = 26,
    EdgeDns = 27,
    Exoscale = 28,
    FreeMyIp = 29,
    GandiV5 = 30,
    Gcore = 31,
    Glesys = 32,
    Godaddy = 33,
    Hetzner = 34,
    HostingDe = 35,
    Hostinger = 36,
    HuaweiCloud = 37,
    Hurricane = 38,
    IbmCloud = 39,
    Infoblox = 40,
    Infomaniak = 41,
    Inwx = 42,
    Ionos = 43,
    Ipv64 = 44,
    Joker = 45,
    Lightsail = 46,
    Linode = 47,
    LuaDns = 48,
    MythicBeasts = 49,
    Namecheap = 50,
    NameDotCom = 51,
    NameSilo = 52,
    Netcup = 53,
    Netlify = 54,
    Nifcloud = 55,
    Ns1 = 56,
    OracleCloud = 57,
    Plesk = 58,
    Safedns = 59,
    Scaleway = 60,
    TencentCloud = 61,
    Transip = 62,
    UltraDns = 63,
    Vercel = 64,
    Volcengine = 65,
    Vultr = 66,
    WebSupport = 67,
    YandexCloud = 68,
    PowerDns = 69,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EncryptionAtRestType {
    #[default]
    Disabled = 0,
    Enabled = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EventPolicy {
    #[default]
    Include = 0,
    Exclude = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExpressionConstant {
    #[default]
    Relaxed = 0,
    Strict = 1,
    Disable = 2,
    Hourly = 3,
    Daily = 4,
    Weekly = 5,
    Login = 6,
    Plain = 7,
    Xoauth2 = 8,
    Oauthbearer = 9,
    Mixer = 10,
    Stanag4406 = 11,
    Nsep = 12,
    Opportunistic = 13,
    Required = 14,
    Manual = 15,
    Verified = 16,
    Discovered = 17,
    Harvested = 18,
    Unverified = 19,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExpressionVariable {
    #[default]
    Asn = 0,
    Attributes = 1,
    AuthenticatedAs = 2,
    Authority = 3,
    Bcc = 4,
    BccDomain = 5,
    BccLocal = 6,
    BccName = 7,
    Body = 8,
    BodyHtml = 9,
    BodyRaw = 10,
    BodyText = 11,
    BodyWords = 12,
    Cc = 13,
    CcDomain = 14,
    CcLocal = 15,
    CcName = 16,
    Country = 17,
    Domain = 18,
    Email = 19,
    EmailLower = 20,
    EnvFrom = 21,
    EnvFromDomain = 22,
    EnvFromLocal = 23,
    EnvTo = 24,
    ExpiresIn = 25,
    From = 26,
    FromDomain = 27,
    FromLocal = 28,
    FromName = 29,
    Headers = 30,
    HeloDomain = 31,
    Host = 32,
    Ip = 33,
    IpReverse = 34,
    IsTls = 35,
    IsV4 = 36,
    IsV6 = 37,
    LastError = 38,
    LastStatus = 39,
    Listener = 40,
    Local = 41,
    LocalIp = 42,
    LocalPort = 43,
    Location = 44,
    Method = 45,
    Mx = 46,
    Name = 47,
    NameLower = 48,
    NotifyNum = 49,
    Octets = 50,
    Path = 51,
    PathQuery = 52,
    Port = 53,
    Priority = 54,
    Protocol = 55,
    Query = 56,
    QueueAge = 57,
    QueueName = 58,
    Raw = 59,
    RawLower = 60,
    Rcpt = 61,
    RcptDomain = 62,
    ReceivedFromIp = 63,
    ReceivedViaPort = 64,
    Recipients = 65,
    RemoteIp = 66,
    RemoteIpPtr = 67,
    RemotePort = 68,
    ReplyTo = 69,
    ReplyToDomain = 70,
    ReplyToLocal = 71,
    ReplyToName = 72,
    RetryNum = 73,
    Scheme = 74,
    Sender = 75,
    SenderDomain = 76,
    Size = 77,
    Sld = 78,
    Source = 79,
    Subject = 80,
    SubjectThread = 81,
    SubjectWords = 82,
    To = 83,
    ToDomain = 84,
    ToLocal = 85,
    ToName = 86,
    Url = 87,
    UrlOriginal = 88,
    Value = 89,
    ValueLower = 90,
    SpamScore = 91,
    SpamProbability = 92,
    SpamThreshold = 93,
    IsSigned = 94,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExternalPublicKeyStatus {
    #[default]
    Active = 0,
    Disabled = 1,
    PendingApproval = 2,
    Rejected = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FailureReportingOption {
    #[default]
    All = 0,
    Any = 1,
    DkimFailure = 2,
    SpfFailure = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HeaderProtection {
    #[default]
    None = 0,
    NoConfidentiality = 1,
    Baseline = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HttpAuthType {
    #[default]
    Unauthenticated = 0,
    Basic = 1,
    Bearer = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HttpLookupFormatType {
    #[default]
    Csv = 0,
    List = 1,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum InMemoryStoreBaseType {
    #[default]
    Redis = 0,
    RedisCluster = 1,
    RedisSentinel = 2,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum InMemoryStoreType {
    #[default]
    Default = 0,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded = 1,
    // SPDX-SnippetEnd
    Redis = 2,
    RedisCluster = 3,
    RedisSentinel = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IndexStatusType {
    #[default]
    Running = 0,
    Failed = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IndexType {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[default]
    Telemetry = 0,
    // SPDX-SnippetEnd
    #[cfg_attr(not(feature = "enterprise"), default)]
    Email = 1,
    Calendar = 2,
    Contacts = 3,
    File = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IpProtocol {
    #[default]
    Udp = 0,
    Tcp = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum JokerAuthType {
    #[default]
    ApiKey = 0,
    UsernamePassword = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum JwtSignatureAlgorithm {
    #[default]
    Es256 = 0,
    Es384 = 1,
    Ps256 = 2,
    Ps384 = 3,
    Ps512 = 4,
    Rs256 = 5,
    Rs384 = 6,
    Rs512 = 7,
    Hs256 = 8,
    Hs384 = 9,
    Hs512 = 10,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum KeyDiscoverySource {
    #[default]
    Dnssec = 0,
    Wkd = 1,
    Vks = 2,
    Hkp = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum KeySourceType {
    #[default]
    Manual = 0,
    Automatic = 1,
    HarvestedSmime = 2,
    HarvestedPgp = 3,
    Autocrypt = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum KeyTrust {
    #[default]
    Manual = 0,
    Verified = 1,
    Discovered = 2,
    Harvested = 3,
    Unverified = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Locale {
    #[default]
    EnUS = 0,
    AaDJ = 1,
    AaER = 2,
    SsyER = 3,
    AaET = 4,
    AfZA = 5,
    AgrPE = 6,
    AkGH = 7,
    AmET = 8,
    AnES = 9,
    AnpIN = 10,
    ArAE = 11,
    ArBH = 12,
    ArDZ = 13,
    ArEG = 14,
    ArIN = 15,
    ArIQ = 16,
    ArJO = 17,
    ArKW = 18,
    ArLB = 19,
    ArLY = 20,
    ArMA = 21,
    ArOM = 22,
    ArQA = 23,
    ArSA = 24,
    ArSD = 25,
    ArSS = 26,
    ArSY = 27,
    ArTN = 28,
    ArYE = 29,
    AsIN = 30,
    AstES = 31,
    AycPE = 32,
    AzAZ = 33,
    AzIR = 34,
    BeBY = 35,
    BeLatnBY = 36,
    BemZM = 37,
    BerDZ = 38,
    BerMA = 39,
    BgBG = 40,
    BhbIN = 41,
    BhoIN = 42,
    BhoNP = 43,
    BiVU = 44,
    BnBD = 45,
    BnIN = 46,
    BoCN = 47,
    BoIN = 48,
    BrFR = 49,
    Es419 = 50,
    BrxIN = 51,
    BsBA = 52,
    BynER = 53,
    CaAD = 54,
    CaES = 55,
    En150 = 56,
    CaESValencia = 57,
    CaFR = 58,
    CaIT = 59,
    CeRU = 60,
    ChrUS = 61,
    CmnTW = 62,
    CrhUA = 63,
    CsCZ = 64,
    CsbPL = 65,
    CvRU = 66,
    CyGB = 67,
    DaDK = 68,
    DeAT = 69,
    DeBE = 70,
    En001 = 71,
    DeCH = 72,
    DeDE = 73,
    DeIT = 74,
    DeLI = 75,
    DeLU = 76,
    Ar001 = 77,
    DoiIN = 78,
    DsbDE = 79,
    DvMV = 80,
    DzBT = 81,
    ElCY = 82,
    ElGR = 83,
    EnAG = 84,
    EnAU = 85,
    EnBW = 86,
    EnCA = 87,
    EnDK = 88,
    EnGB = 89,
    EnHK = 90,
    EnIE = 91,
    EnIL = 92,
    EnIN = 93,
    EnNG = 94,
    EnNZ = 95,
    EnPH = 96,
    EnSC = 97,
    EnSG = 98,
    EnZA = 99,
    EnZM = 100,
    EnZW = 101,
    Eo = 102,
    EsAR = 103,
    EsBO = 104,
    EsCL = 105,
    EsCO = 106,
    EsCR = 107,
    EsCU = 108,
    EsDO = 109,
    EsEC = 110,
    EsES = 111,
    EsGT = 112,
    EsHN = 113,
    EsMX = 114,
    EsNI = 115,
    EsPA = 116,
    EsPE = 117,
    EsPR = 118,
    EsPY = 119,
    EsSV = 120,
    EsUS = 121,
    EsUY = 122,
    EsVE = 123,
    EtEE = 124,
    EuES = 125,
    ZhHans = 126,
    FaIR = 127,
    FfSN = 128,
    FiFI = 129,
    FilPH = 130,
    FoFO = 131,
    FrBE = 132,
    FrCA = 133,
    FrCH = 134,
    FrFR = 135,
    FrLU = 136,
    ZhHant = 137,
    FurIT = 138,
    FyDE = 139,
    FyNL = 140,
    GaIE = 141,
    ZhHantHK = 142,
    GdGB = 143,
    GezER = 144,
    SrLatnBA = 145,
    GezET = 146,
    SrLatnME = 147,
    GlES = 148,
    AzLatnAZ = 149,
    GuIN = 150,
    GvGB = 151,
    HaNG = 152,
    HakTW = 153,
    HeIL = 154,
    HiIN = 155,
    HifFJ = 156,
    HneIN = 157,
    HrHR = 158,
    HsbDE = 159,
    HtHT = 160,
    HuHU = 161,
    HyAM = 162,
    IaFR = 163,
    IdID = 164,
    IgNG = 165,
    IkCA = 166,
    IsIS = 167,
    ItCH = 168,
    ItIT = 169,
    IuCA = 170,
    JaJP = 171,
    KaGE = 172,
    KabDZ = 173,
    KkKZ = 174,
    KlGL = 175,
    KmKH = 176,
    KnIN = 177,
    KoKR = 178,
    KokIN = 179,
    KsIN = 180,
    KsDevaIN = 181,
    KuTR = 182,
    KwGB = 183,
    KyKG = 184,
    LbLU = 185,
    LgUG = 186,
    LiBE = 187,
    LiNL = 188,
    LijIT = 189,
    LnCD = 190,
    LoLA = 191,
    LtLT = 192,
    LvLV = 193,
    LzhTW = 194,
    MagIN = 195,
    MaiIN = 196,
    MaiNP = 197,
    MfeMU = 198,
    MgMG = 199,
    MhrRU = 200,
    MiNZ = 201,
    MiqNI = 202,
    MjwIN = 203,
    MkMK = 204,
    MlIN = 205,
    MnMN = 206,
    MniIN = 207,
    MnwMM = 208,
    MrIN = 209,
    MsMY = 210,
    MtMT = 211,
    MyMM = 212,
    NanTW = 213,
    NanLatnTW = 214,
    NbNO = 215,
    NdsDE = 216,
    NdsNL = 217,
    NeNP = 218,
    NhnMX = 219,
    NiuNU = 220,
    NiuNZ = 221,
    NlAW = 222,
    NlBE = 223,
    NlNL = 224,
    NnNO = 225,
    NrZA = 226,
    NsoZA = 227,
    OcFR = 228,
    OmET = 229,
    OmKE = 230,
    OrIN = 231,
    OsRU = 232,
    PaIN = 233,
    PaPK = 234,
    PapAW = 235,
    PapCW = 236,
    PlPL = 237,
    PsAF = 238,
    PtBR = 239,
    PtPT = 240,
    QuzPE = 241,
    RajIN = 242,
    RoRO = 243,
    RuRU = 244,
    RuUA = 245,
    RwRW = 246,
    SaIN = 247,
    SahRU = 248,
    SatIN = 249,
    ScIT = 250,
    SdIN = 251,
    SdDevaIN = 252,
    SeNO = 253,
    SgsLT = 254,
    ShnMM = 255,
    ShsCA = 256,
    SiLK = 257,
    SidET = 258,
    SkSK = 259,
    SlSI = 260,
    SmWS = 261,
    SoDJ = 262,
    SoET = 263,
    SoKE = 264,
    SoSO = 265,
    SqAL = 266,
    SqMK = 267,
    SrME = 268,
    SrRS = 269,
    SrLatnRS = 270,
    SsZA = 271,
    StZA = 272,
    SvFI = 273,
    SvSE = 274,
    SwKE = 275,
    SwTZ = 276,
    SzlPL = 277,
    TaIN = 278,
    TaLK = 279,
    TcyIN = 280,
    TeIN = 281,
    TgTJ = 282,
    ThTH = 283,
    TheNP = 284,
    TiER = 285,
    TiET = 286,
    TigER = 287,
    TkTM = 288,
    TlPH = 289,
    TnZA = 290,
    ToTO = 291,
    TpiPG = 292,
    TrCY = 293,
    TrTR = 294,
    TsZA = 295,
    TtRU = 296,
    TtLatnRU = 297,
    UgCN = 298,
    UkUA = 299,
    UnmUS = 300,
    UrIN = 301,
    UrPK = 302,
    UzUZ = 303,
    UzCyrlUZ = 304,
    VeZA = 305,
    ViVN = 306,
    WaBE = 307,
    UzLatnUZ = 308,
    WaeCH = 309,
    WalET = 310,
    WoSN = 311,
    XhZA = 312,
    YiUS = 313,
    YoNG = 314,
    YueHK = 315,
    YuwPG = 316,
    ZhCN = 317,
    ZhHK = 318,
    ZhSG = 319,
    ZhTW = 320,
    ZuZA = 321,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LogRotateFrequency {
    #[default]
    Daily = 0,
    Hourly = 1,
    Minutely = 2,
    Never = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LookupStoreType {
    #[default]
    PostgreSql = 0,
    MySql = 1,
    Sqlite = 2,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded = 3,
    // SPDX-SnippetEnd
    Redis = 4,
    RedisCluster = 5,
    RedisSentinel = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MessageFlag {
    #[default]
    Authenticated = 0,
    Unauthenticated = 1,
    UnauthenticatedDmarc = 2,
    Dsn = 3,
    Report = 4,
    Autogenerated = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MetadataDataType {
    #[default]
    Email = 0,
    Mailbox = 1,
    SieveScript = 2,
    Calendar = 3,
    CalendarEvent = 4,
    AddressBook = 5,
    ContactCard = 6,
    FileNode = 7,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MetricType {
    #[default]
    Counter = 0,
    Gauge = 1,
    Histogram = 2,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MetricsOtelType {
    #[default]
    Disabled = 0,
    Http = 1,
    Grpc = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MetricsPrometheusType {
    #[default]
    Disabled = 0,
    Enabled = 1,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MetricsStoreType {
    #[default]
    Disabled = 0,
    Default = 1,
    FoundationDb = 2,
    PostgreSql = 3,
    MySql = 4,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MilterVersion {
    #[default]
    V2 = 0,
    V6 = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ModelSize {
    #[default]
    V16 = 0,
    V17 = 1,
    V18 = 2,
    V19 = 3,
    V20 = 4,
    V21 = 5,
    V22 = 6,
    V23 = 7,
    V24 = 8,
    V25 = 9,
    V26 = 10,
    V27 = 11,
    V28 = 12,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaDeliveryExpirationType {
    #[default]
    Ttl = 0,
    Attempts = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaDeliveryScheduleIntervalsOrDefaultType {
    #[default]
    Default = 0,
    Custom = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaInboundThrottleKey {
    #[default]
    Listener = 0,
    RemoteIp = 1,
    LocalIp = 2,
    AuthenticatedAs = 3,
    HeloDomain = 4,
    Sender = 5,
    SenderDomain = 6,
    Rcpt = 7,
    RcptDomain = 8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaIpStrategy {
    #[default]
    V4ThenV6 = 0,
    V6ThenV4 = 1,
    V4Only = 2,
    V6Only = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaOutboundThrottleKey {
    #[default]
    Mx = 0,
    RemoteIp = 1,
    LocalIp = 2,
    Sender = 3,
    SenderDomain = 4,
    RcptDomain = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaProtocol {
    #[default]
    Smtp = 0,
    Lmtp = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaQueueQuotaKey {
    #[default]
    Sender = 0,
    SenderDomain = 1,
    Rcpt = 2,
    RcptDomain = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaRequiredOrOptional {
    #[default]
    Optional = 0,
    Require = 1,
    Disable = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaRouteType {
    #[default]
    Mx = 0,
    Relay = 1,
    Local = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaStage {
    #[default]
    Connect = 0,
    Ehlo = 1,
    Auth = 2,
    Mail = 3,
    Rcpt = 4,
    Data = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NetworkListenerProtocol {
    #[default]
    Smtp = 0,
    Lmtp = 1,
    Http = 2,
    Imap = 3,
    Pop3 = 4,
    ManageSieve = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OAuthClientKind {
    #[default]
    Registered = 0,
    Dynamic = 1,
    MetadataDocument = 2,
    FirstParty = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OAuthClientMetadataPolicy {
    #[default]
    Disabled = 0,
    SameDomain = 1,
    Any = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OAuthGrantType {
    #[default]
    AuthorizationCode = 0,
    RefreshToken = 1,
    DeviceCode = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OAuthScope {
    #[default]
    Mail = 0,
    Contacts = 1,
    Calendars = 2,
    Files = 3,
    Full = 4,
    Security = 5,
    Settings = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OidcIntrospectionAuth {
    #[default]
    ClientSecretBasic = 0,
    ClientSecretPost = 1,
    None = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OidcOpaqueTokenValidation {
    #[default]
    None = 0,
    UserInfo = 1,
    Introspection = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OidcUnscopedTokenPolicy {
    #[default]
    Reject = 0,
    Interoperable = 1,
    Full = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OvhEndpoint {
    #[default]
    OvhEu = 0,
    OvhCa = 1,
    KimsufiEu = 2,
    KimsufiCa = 3,
    SoyoustartEu = 4,
    SoyoustartCa = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PasswordHashAlgorithm {
    #[default]
    Argon2id = 0,
    Bcrypt = 1,
    Scrypt = 2,
    Pbkdf2 = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PasswordStrength {
    #[default]
    Zero = 0,
    One = 1,
    Two = 2,
    Three = 3,
    Four = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Permission {
    #[default]
    Authenticate = 0,
    AuthenticateWithAlias = 1,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    InteractAi = 2,
    // SPDX-SnippetEnd
    Impersonate = 3,
    UnlimitedRequests = 4,
    UnlimitedUploads = 5,
    FetchAnyBlob = 6,
    EmailSend = 7,
    EmailReceive = 8,
    CalendarAlarmsSend = 9,
    CalendarSchedulingSend = 10,
    CalendarSchedulingReceive = 11,
    JmapPushSubscriptionGet = 12,
    JmapPushSubscriptionCreate = 13,
    JmapPushSubscriptionUpdate = 14,
    JmapPushSubscriptionDestroy = 15,
    JmapMailboxGet = 16,
    JmapMailboxChanges = 17,
    JmapMailboxQuery = 18,
    JmapMailboxQueryChanges = 19,
    JmapMailboxCreate = 20,
    JmapMailboxUpdate = 21,
    JmapMailboxDestroy = 22,
    JmapThreadGet = 23,
    JmapThreadChanges = 24,
    JmapEmailGet = 25,
    JmapEmailChanges = 26,
    JmapEmailQuery = 27,
    JmapEmailQueryChanges = 28,
    JmapEmailCreate = 29,
    JmapEmailUpdate = 30,
    JmapEmailDestroy = 31,
    JmapEmailCopy = 32,
    JmapEmailImport = 33,
    JmapEmailParse = 34,
    JmapSearchSnippetGet = 35,
    JmapIdentityGet = 36,
    JmapIdentityChanges = 37,
    JmapIdentityCreate = 38,
    JmapIdentityUpdate = 39,
    JmapIdentityDestroy = 40,
    JmapEmailSubmissionGet = 41,
    JmapEmailSubmissionChanges = 42,
    JmapEmailSubmissionQuery = 43,
    JmapEmailSubmissionQueryChanges = 44,
    JmapEmailSubmissionCreate = 45,
    JmapEmailSubmissionUpdate = 46,
    JmapEmailSubmissionDestroy = 47,
    JmapVacationResponseGet = 48,
    JmapVacationResponseCreate = 49,
    JmapVacationResponseUpdate = 50,
    JmapVacationResponseDestroy = 51,
    JmapSieveScriptGet = 52,
    JmapSieveScriptQuery = 53,
    JmapSieveScriptValidate = 54,
    JmapSieveScriptCreate = 55,
    JmapSieveScriptUpdate = 56,
    JmapSieveScriptDestroy = 57,
    JmapPrincipalGet = 58,
    JmapPrincipalQuery = 59,
    JmapPrincipalChanges = 60,
    JmapPrincipalQueryChanges = 61,
    JmapPrincipalGetAvailability = 62,
    JmapQuotaGet = 63,
    JmapQuotaChanges = 64,
    JmapQuotaQuery = 65,
    JmapQuotaQueryChanges = 66,
    JmapBlobGet = 67,
    JmapBlobCopy = 68,
    JmapBlobLookup = 69,
    JmapBlobUpload = 70,
    JmapAddressBookGet = 71,
    JmapAddressBookChanges = 72,
    JmapAddressBookCreate = 73,
    JmapAddressBookUpdate = 74,
    JmapAddressBookDestroy = 75,
    JmapContactCardGet = 76,
    JmapContactCardChanges = 77,
    JmapContactCardQuery = 78,
    JmapContactCardQueryChanges = 79,
    JmapContactCardCreate = 80,
    JmapContactCardUpdate = 81,
    JmapContactCardDestroy = 82,
    JmapContactCardCopy = 83,
    JmapContactCardParse = 84,
    JmapFileNodeGet = 85,
    JmapFileNodeChanges = 86,
    JmapFileNodeQuery = 87,
    JmapFileNodeQueryChanges = 88,
    JmapFileNodeCreate = 89,
    JmapFileNodeUpdate = 90,
    JmapFileNodeDestroy = 91,
    JmapFileNodeCopy = 92,
    JmapShareNotificationGet = 93,
    JmapShareNotificationChanges = 94,
    JmapShareNotificationQuery = 95,
    JmapShareNotificationQueryChanges = 96,
    JmapShareNotificationCreate = 97,
    JmapShareNotificationUpdate = 98,
    JmapShareNotificationDestroy = 99,
    JmapCalendarGet = 100,
    JmapCalendarChanges = 101,
    JmapCalendarCreate = 102,
    JmapCalendarUpdate = 103,
    JmapCalendarDestroy = 104,
    JmapCalendarEventGet = 105,
    JmapCalendarEventChanges = 106,
    JmapCalendarEventQuery = 107,
    JmapCalendarEventQueryChanges = 108,
    JmapCalendarEventCreate = 109,
    JmapCalendarEventUpdate = 110,
    JmapCalendarEventDestroy = 111,
    JmapCalendarEventCopy = 112,
    JmapCalendarEventParse = 113,
    JmapCalendarEventNotificationGet = 114,
    JmapCalendarEventNotificationChanges = 115,
    JmapCalendarEventNotificationQuery = 116,
    JmapCalendarEventNotificationQueryChanges = 117,
    JmapCalendarEventNotificationCreate = 118,
    JmapCalendarEventNotificationUpdate = 119,
    JmapCalendarEventNotificationDestroy = 120,
    JmapParticipantIdentityGet = 121,
    JmapParticipantIdentityChanges = 122,
    JmapParticipantIdentityCreate = 123,
    JmapParticipantIdentityUpdate = 124,
    JmapParticipantIdentityDestroy = 125,
    JmapCoreEcho = 126,
    JmapMetadataGet = 127,
    JmapMetadataSet = 128,
    JmapMetadataPrivate = 129,
    ImapAuthenticate = 130,
    ImapAclGet = 131,
    ImapAclSet = 132,
    ImapMyRights = 133,
    ImapListRights = 134,
    ImapAppend = 135,
    ImapCapability = 136,
    ImapId = 137,
    ImapCopy = 138,
    ImapMove = 139,
    ImapCreate = 140,
    ImapDelete = 141,
    ImapEnable = 142,
    ImapExpunge = 143,
    ImapFetch = 144,
    ImapIdle = 145,
    ImapList = 146,
    ImapLsub = 147,
    ImapNamespace = 148,
    ImapRename = 149,
    ImapSearch = 150,
    ImapSort = 151,
    ImapSelect = 152,
    ImapExamine = 153,
    ImapStatus = 154,
    ImapStore = 155,
    ImapSubscribe = 156,
    ImapThread = 157,
    ImapMetadataGet = 158,
    ImapMetadataSet = 159,
    ImapMetadataPrivate = 160,
    Pop3Authenticate = 161,
    Pop3List = 162,
    Pop3Uidl = 163,
    Pop3Stat = 164,
    Pop3Retr = 165,
    Pop3Dele = 166,
    SieveAuthenticate = 167,
    SieveListScripts = 168,
    SieveSetActive = 169,
    SieveGetScript = 170,
    SievePutScript = 171,
    SieveDeleteScript = 172,
    SieveRenameScript = 173,
    SieveCheckScript = 174,
    SieveHaveSpace = 175,
    DavSyncCollection = 176,
    DavExpandProperty = 177,
    DavPrincipalAcl = 178,
    DavPrincipalList = 179,
    DavPrincipalMatch = 180,
    DavPrincipalSearch = 181,
    DavPrincipalSearchPropSet = 182,
    DavFilePropFind = 183,
    DavFilePropPatch = 184,
    DavFileGet = 185,
    DavFileMkCol = 186,
    DavFileDelete = 187,
    DavFilePut = 188,
    DavFileCopy = 189,
    DavFileMove = 190,
    DavFileLock = 191,
    DavFileAcl = 192,
    DavCardPropFind = 193,
    DavCardPropPatch = 194,
    DavCardGet = 195,
    DavCardMkCol = 196,
    DavCardDelete = 197,
    DavCardPut = 198,
    DavCardCopy = 199,
    DavCardMove = 200,
    DavCardLock = 201,
    DavCardAcl = 202,
    DavCardQuery = 203,
    DavCardMultiGet = 204,
    DavCalPropFind = 205,
    DavCalPropPatch = 206,
    DavCalGet = 207,
    DavCalMkCol = 208,
    DavCalDelete = 209,
    DavCalPut = 210,
    DavCalCopy = 211,
    DavCalMove = 212,
    DavCalLock = 213,
    DavCalAcl = 214,
    DavCalQuery = 215,
    DavCalMultiGet = 216,
    DavCalFreeBusyQuery = 217,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    LiveTracing = 218,
    #[cfg(feature = "enterprise")]
    LiveMetrics = 219,
    // SPDX-SnippetEnd
    LiveDeliveryTest = 220,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ScimAccess = 221,
    // SPDX-SnippetEnd
    SysAccountGet = 222,
    SysAccountCreate = 223,
    SysAccountUpdate = 224,
    SysAccountDestroy = 225,
    SysAccountQuery = 226,
    SysAccountPasswordGet = 227,
    SysAccountPasswordUpdate = 228,
    SysAccountSettingsGet = 229,
    SysAccountSettingsUpdate = 230,
    SysAcmeProviderGet = 231,
    SysAcmeProviderCreate = 232,
    SysAcmeProviderUpdate = 233,
    SysAcmeProviderDestroy = 234,
    SysAcmeProviderQuery = 235,
    ActionReloadSettings = 236,
    ActionReloadTlsCertificates = 237,
    ActionReloadLookupStores = 238,
    ActionReloadBlockedIps = 239,
    ActionUpdateApps = 240,
    ActionTroubleshootDmarc = 241,
    ActionClassifySpam = 242,
    ActionInvalidateCaches = 243,
    ActionInvalidateNegativeCaches = 244,
    ActionPauseMtaQueue = 245,
    ActionResumeMtaQueue = 246,
    SysActionCreate = 247,
    SysAddressBookGet = 248,
    SysAddressBookUpdate = 249,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysAiModelGet = 250,
    #[cfg(feature = "enterprise")]
    SysAiModelCreate = 251,
    #[cfg(feature = "enterprise")]
    SysAiModelUpdate = 252,
    #[cfg(feature = "enterprise")]
    SysAiModelDestroy = 253,
    #[cfg(feature = "enterprise")]
    SysAiModelQuery = 254,
    #[cfg(feature = "enterprise")]
    SysAlertGet = 255,
    #[cfg(feature = "enterprise")]
    SysAlertCreate = 256,
    #[cfg(feature = "enterprise")]
    SysAlertUpdate = 257,
    #[cfg(feature = "enterprise")]
    SysAlertDestroy = 258,
    #[cfg(feature = "enterprise")]
    SysAlertQuery = 259,
    // SPDX-SnippetEnd
    SysAllowedIpGet = 260,
    SysAllowedIpCreate = 261,
    SysAllowedIpUpdate = 262,
    SysAllowedIpDestroy = 263,
    SysAllowedIpQuery = 264,
    SysApiKeyGet = 265,
    SysApiKeyCreate = 266,
    SysApiKeyUpdate = 267,
    SysApiKeyDestroy = 268,
    SysApiKeyQuery = 269,
    SysAppPasswordGet = 270,
    SysAppPasswordCreate = 271,
    SysAppPasswordUpdate = 272,
    SysAppPasswordDestroy = 273,
    SysAppPasswordQuery = 274,
    SysApplicationGet = 275,
    SysApplicationCreate = 276,
    SysApplicationUpdate = 277,
    SysApplicationDestroy = 278,
    SysApplicationQuery = 279,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysArchivedItemGet = 280,
    #[cfg(feature = "enterprise")]
    SysArchivedItemUpdate = 281,
    #[cfg(feature = "enterprise")]
    SysArchivedItemDestroy = 282,
    #[cfg(feature = "enterprise")]
    SysArchivedItemQuery = 283,
    // SPDX-SnippetEnd
    SysArfExternalReportGet = 284,
    SysArfExternalReportDestroy = 285,
    SysArfExternalReportQuery = 286,
    SysAsnGet = 287,
    SysAsnUpdate = 288,
    SysAuthenticationGet = 289,
    SysAuthenticationUpdate = 290,
    SysBlobStoreGet = 291,
    SysBlobStoreUpdate = 292,
    SysBlockedIpGet = 293,
    SysBlockedIpCreate = 294,
    SysBlockedIpUpdate = 295,
    SysBlockedIpDestroy = 296,
    SysBlockedIpQuery = 297,
    SysBootstrapGet = 298,
    SysBootstrapUpdate = 299,
    SysCacheGet = 300,
    SysCacheUpdate = 301,
    SysCalendarGet = 302,
    SysCalendarUpdate = 303,
    SysCalendarAlarmGet = 304,
    SysCalendarAlarmUpdate = 305,
    SysCalendarSchedulingGet = 306,
    SysCalendarSchedulingUpdate = 307,
    SysCertificateGet = 308,
    SysCertificateCreate = 309,
    SysCertificateUpdate = 310,
    SysCertificateDestroy = 311,
    SysCertificateQuery = 312,
    SysClusterNodeGet = 313,
    SysClusterNodeQuery = 314,
    SysClusterRoleGet = 315,
    SysClusterRoleCreate = 316,
    SysClusterRoleUpdate = 317,
    SysClusterRoleDestroy = 318,
    SysClusterRoleQuery = 319,
    SysCoordinatorGet = 320,
    SysCoordinatorUpdate = 321,
    SysDataRetentionGet = 322,
    SysDataRetentionUpdate = 323,
    SysDataStoreGet = 324,
    SysDataStoreUpdate = 325,
    SysDirectoryGet = 326,
    SysDirectoryCreate = 327,
    SysDirectoryUpdate = 328,
    SysDirectoryDestroy = 329,
    SysDirectoryQuery = 330,
    SysDkimReportSettingsGet = 331,
    SysDkimReportSettingsUpdate = 332,
    SysDkimSignatureGet = 333,
    SysDkimSignatureCreate = 334,
    SysDkimSignatureUpdate = 335,
    SysDkimSignatureDestroy = 336,
    SysDkimSignatureQuery = 337,
    SysDmarcExternalReportGet = 338,
    SysDmarcExternalReportDestroy = 339,
    SysDmarcExternalReportQuery = 340,
    SysDmarcInternalReportGet = 341,
    SysDmarcInternalReportUpdate = 342,
    SysDmarcInternalReportDestroy = 343,
    SysDmarcInternalReportQuery = 344,
    SysDmarcReportSettingsGet = 345,
    SysDmarcReportSettingsUpdate = 346,
    SysDnsResolverGet = 347,
    SysDnsResolverUpdate = 348,
    SysDnsServerGet = 349,
    SysDnsServerCreate = 350,
    SysDnsServerUpdate = 351,
    SysDnsServerDestroy = 352,
    SysDnsServerQuery = 353,
    SysDomainGet = 354,
    SysDomainCreate = 355,
    SysDomainUpdate = 356,
    SysDomainDestroy = 357,
    SysDomainQuery = 358,
    SysDsnReportSettingsGet = 359,
    SysDsnReportSettingsUpdate = 360,
    SysEmailGet = 361,
    SysEmailUpdate = 362,
    SysEncryptionGet = 643,
    SysEncryptionUpdate = 644,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysEnterpriseGet = 363,
    #[cfg(feature = "enterprise")]
    SysEnterpriseUpdate = 364,
    // SPDX-SnippetEnd
    SysEventTracingLevelGet = 365,
    SysEventTracingLevelCreate = 366,
    SysEventTracingLevelUpdate = 367,
    SysEventTracingLevelDestroy = 368,
    SysEventTracingLevelQuery = 369,
    SysExternalPublicKeyGet = 645,
    SysExternalPublicKeyCreate = 646,
    SysExternalPublicKeyUpdate = 647,
    SysExternalPublicKeyDestroy = 648,
    SysExternalPublicKeyQuery = 649,
    SysFileStorageGet = 370,
    SysFileStorageUpdate = 371,
    SysHttpGet = 372,
    SysHttpUpdate = 373,
    SysHttpFormGet = 374,
    SysHttpFormUpdate = 375,
    SysHttpLookupGet = 376,
    SysHttpLookupCreate = 377,
    SysHttpLookupUpdate = 378,
    SysHttpLookupDestroy = 379,
    SysHttpLookupQuery = 380,
    SysImapGet = 381,
    SysImapUpdate = 382,
    SysInMemoryStoreGet = 383,
    SysInMemoryStoreUpdate = 384,
    SysIndexQueueStatusGet = 385,
    SysIndexQueueStatusUpdate = 386,
    SysIndexQueueStatusQuery = 387,
    SysJmapGet = 388,
    SysJmapUpdate = 389,
    SysLogGet = 390,
    SysLogQuery = 391,
    SysMailingListGet = 392,
    SysMailingListCreate = 393,
    SysMailingListUpdate = 394,
    SysMailingListDestroy = 395,
    SysMailingListQuery = 396,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysMaskedEmailGet = 397,
    #[cfg(feature = "enterprise")]
    SysMaskedEmailCreate = 398,
    #[cfg(feature = "enterprise")]
    SysMaskedEmailUpdate = 399,
    #[cfg(feature = "enterprise")]
    SysMaskedEmailDestroy = 400,
    #[cfg(feature = "enterprise")]
    SysMaskedEmailQuery = 401,
    // SPDX-SnippetEnd
    SysMemoryLookupKeyGet = 402,
    SysMemoryLookupKeyCreate = 403,
    SysMemoryLookupKeyUpdate = 404,
    SysMemoryLookupKeyDestroy = 405,
    SysMemoryLookupKeyQuery = 406,
    SysMemoryLookupKeyValueGet = 407,
    SysMemoryLookupKeyValueCreate = 408,
    SysMemoryLookupKeyValueUpdate = 409,
    SysMemoryLookupKeyValueDestroy = 410,
    SysMemoryLookupKeyValueQuery = 411,
    SysMetadataGet = 412,
    SysMetadataUpdate = 413,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysMetricGet = 414,
    #[cfg(feature = "enterprise")]
    SysMetricQuery = 415,
    // SPDX-SnippetEnd
    SysMetricsGet = 416,
    SysMetricsUpdate = 417,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysMetricsStoreGet = 418,
    #[cfg(feature = "enterprise")]
    SysMetricsStoreUpdate = 419,
    // SPDX-SnippetEnd
    SysMtaConnectionStrategyGet = 420,
    SysMtaConnectionStrategyCreate = 421,
    SysMtaConnectionStrategyUpdate = 422,
    SysMtaConnectionStrategyDestroy = 423,
    SysMtaConnectionStrategyQuery = 424,
    SysMtaDeliveryScheduleGet = 425,
    SysMtaDeliveryScheduleCreate = 426,
    SysMtaDeliveryScheduleUpdate = 427,
    SysMtaDeliveryScheduleDestroy = 428,
    SysMtaDeliveryScheduleQuery = 429,
    SysMtaExtensionsGet = 430,
    SysMtaExtensionsUpdate = 431,
    SysMtaHookGet = 432,
    SysMtaHookCreate = 433,
    SysMtaHookUpdate = 434,
    SysMtaHookDestroy = 435,
    SysMtaHookQuery = 436,
    SysMtaInboundSessionGet = 437,
    SysMtaInboundSessionUpdate = 438,
    SysMtaInboundThrottleGet = 439,
    SysMtaInboundThrottleCreate = 440,
    SysMtaInboundThrottleUpdate = 441,
    SysMtaInboundThrottleDestroy = 442,
    SysMtaInboundThrottleQuery = 443,
    SysMtaMilterGet = 444,
    SysMtaMilterCreate = 445,
    SysMtaMilterUpdate = 446,
    SysMtaMilterDestroy = 447,
    SysMtaMilterQuery = 448,
    SysMtaOutboundStrategyGet = 449,
    SysMtaOutboundStrategyUpdate = 450,
    SysMtaOutboundThrottleGet = 451,
    SysMtaOutboundThrottleCreate = 452,
    SysMtaOutboundThrottleUpdate = 453,
    SysMtaOutboundThrottleDestroy = 454,
    SysMtaOutboundThrottleQuery = 455,
    SysMtaQueueQuotaGet = 456,
    SysMtaQueueQuotaCreate = 457,
    SysMtaQueueQuotaUpdate = 458,
    SysMtaQueueQuotaDestroy = 459,
    SysMtaQueueQuotaQuery = 460,
    SysMtaRouteGet = 461,
    SysMtaRouteCreate = 462,
    SysMtaRouteUpdate = 463,
    SysMtaRouteDestroy = 464,
    SysMtaRouteQuery = 465,
    SysMtaStageAuthGet = 466,
    SysMtaStageAuthUpdate = 467,
    SysMtaStageConnectGet = 468,
    SysMtaStageConnectUpdate = 469,
    SysMtaStageDataGet = 470,
    SysMtaStageDataUpdate = 471,
    SysMtaStageEhloGet = 472,
    SysMtaStageEhloUpdate = 473,
    SysMtaStageMailGet = 474,
    SysMtaStageMailUpdate = 475,
    SysMtaStageRcptGet = 476,
    SysMtaStageRcptUpdate = 477,
    SysMtaStsGet = 478,
    SysMtaStsUpdate = 479,
    SysMtaTlsStrategyGet = 480,
    SysMtaTlsStrategyCreate = 481,
    SysMtaTlsStrategyUpdate = 482,
    SysMtaTlsStrategyDestroy = 483,
    SysMtaTlsStrategyQuery = 484,
    SysMtaVirtualQueueGet = 485,
    SysMtaVirtualQueueCreate = 486,
    SysMtaVirtualQueueUpdate = 487,
    SysMtaVirtualQueueDestroy = 488,
    SysMtaVirtualQueueQuery = 489,
    SysNetworkListenerGet = 490,
    SysNetworkListenerCreate = 491,
    SysNetworkListenerUpdate = 492,
    SysNetworkListenerDestroy = 493,
    SysNetworkListenerQuery = 494,
    SysOAuthClientGet = 495,
    SysOAuthClientCreate = 496,
    SysOAuthClientUpdate = 497,
    SysOAuthClientDestroy = 498,
    SysOAuthClientQuery = 499,
    SysOAuthGrantGet = 500,
    SysOAuthGrantDestroy = 501,
    SysOAuthGrantQuery = 502,
    SysOidcProviderGet = 503,
    SysOidcProviderUpdate = 504,
    SysPublicKeyGet = 505,
    SysPublicKeyCreate = 506,
    SysPublicKeyUpdate = 507,
    SysPublicKeyDestroy = 508,
    SysPublicKeyQuery = 509,
    SysQueuedMessageGet = 510,
    SysQueuedMessageUpdate = 511,
    SysQueuedMessageDestroy = 512,
    SysQueuedMessageQuery = 513,
    SysReportSettingsGet = 514,
    SysReportSettingsUpdate = 515,
    SysRoleGet = 516,
    SysRoleCreate = 517,
    SysRoleUpdate = 518,
    SysRoleDestroy = 519,
    SysRoleQuery = 520,
    SysSearchGet = 521,
    SysSearchUpdate = 522,
    SysSearchStoreGet = 523,
    SysSearchStoreUpdate = 524,
    SysSecurityGet = 525,
    SysSecurityUpdate = 526,
    SysSenderAuthGet = 527,
    SysSenderAuthUpdate = 528,
    SysSharingGet = 529,
    SysSharingUpdate = 530,
    SysSieveSystemInterpreterGet = 531,
    SysSieveSystemInterpreterUpdate = 532,
    SysSieveSystemScriptGet = 533,
    SysSieveSystemScriptCreate = 534,
    SysSieveSystemScriptUpdate = 535,
    SysSieveSystemScriptDestroy = 536,
    SysSieveSystemScriptQuery = 537,
    SysSieveUserInterpreterGet = 538,
    SysSieveUserInterpreterUpdate = 539,
    SysSieveUserScriptGet = 540,
    SysSieveUserScriptCreate = 541,
    SysSieveUserScriptUpdate = 542,
    SysSieveUserScriptDestroy = 543,
    SysSieveUserScriptQuery = 544,
    SysSmimeTrustAnchorGet = 650,
    SysSmimeTrustAnchorCreate = 651,
    SysSmimeTrustAnchorUpdate = 652,
    SysSmimeTrustAnchorDestroy = 653,
    SysSmimeTrustAnchorQuery = 654,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysSpamAiGet = 545,
    #[cfg(feature = "enterprise")]
    SysSpamAiUpdate = 546,
    // SPDX-SnippetEnd
    SysSpamClassifierGet = 547,
    SysSpamClassifierUpdate = 548,
    SysSpamDnsblServerGet = 549,
    SysSpamDnsblServerCreate = 550,
    SysSpamDnsblServerUpdate = 551,
    SysSpamDnsblServerDestroy = 552,
    SysSpamDnsblServerQuery = 553,
    SysSpamDnsblSettingsGet = 554,
    SysSpamDnsblSettingsUpdate = 555,
    SysSpamFileExtensionGet = 556,
    SysSpamFileExtensionCreate = 557,
    SysSpamFileExtensionUpdate = 558,
    SysSpamFileExtensionDestroy = 559,
    SysSpamFileExtensionQuery = 560,
    SysSpamPyzorGet = 561,
    SysSpamPyzorUpdate = 562,
    SysSpamRuleGet = 563,
    SysSpamRuleCreate = 564,
    SysSpamRuleUpdate = 565,
    SysSpamRuleDestroy = 566,
    SysSpamRuleQuery = 567,
    SysSpamSettingsGet = 568,
    SysSpamSettingsUpdate = 569,
    SysSpamTagGet = 570,
    SysSpamTagCreate = 571,
    SysSpamTagUpdate = 572,
    SysSpamTagDestroy = 573,
    SysSpamTagQuery = 574,
    SysSpamTrainingSampleGet = 575,
    SysSpamTrainingSampleCreate = 576,
    SysSpamTrainingSampleDestroy = 577,
    SysSpamTrainingSampleQuery = 578,
    SysSpfReportSettingsGet = 579,
    SysSpfReportSettingsUpdate = 580,
    SysStoreLookupGet = 581,
    SysStoreLookupCreate = 582,
    SysStoreLookupUpdate = 583,
    SysStoreLookupDestroy = 584,
    SysStoreLookupQuery = 585,
    SysSymmetricKeyGet = 656,
    SysSymmetricKeyCreate = 657,
    SysSymmetricKeyUpdate = 658,
    SysSymmetricKeyDestroy = 659,
    SysSymmetricKeyQuery = 660,
    SysSystemSettingsGet = 586,
    SysSystemSettingsUpdate = 587,
    TaskCalendarAlarmEmail = 588,
    TaskCalendarAlarmNotification = 589,
    TaskCalendarItipMessage = 590,
    TaskMergeThreads = 591,
    TaskDmarcReport = 592,
    TaskTlsReport = 593,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TaskRestoreArchivedItem = 594,
    // SPDX-SnippetEnd
    TaskDestroyAccount = 595,
    TaskAccountMaintenance = 596,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TaskTenantMaintenance = 597,
    // SPDX-SnippetEnd
    TaskStoreMaintenance = 598,
    TaskSpamFilterMaintenance = 599,
    TaskAcmeRenewal = 600,
    TaskDkimManagement = 601,
    TaskDnsManagement = 602,
    TaskShareRevokeCleanup = 603,
    TaskDmarcReportWindow = 604,
    TaskTlsReportWindow = 605,
    TaskExternalPublicKeyMaintenance = 655,
    TaskBlobRecode = 661,
    SysTaskGet = 606,
    SysTaskCreate = 607,
    SysTaskUpdate = 608,
    SysTaskDestroy = 609,
    SysTaskQuery = 610,
    SysTaskManagerGet = 611,
    SysTaskManagerUpdate = 612,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysTenantGet = 613,
    #[cfg(feature = "enterprise")]
    SysTenantCreate = 614,
    #[cfg(feature = "enterprise")]
    SysTenantUpdate = 615,
    #[cfg(feature = "enterprise")]
    SysTenantDestroy = 616,
    #[cfg(feature = "enterprise")]
    SysTenantQuery = 617,
    // SPDX-SnippetEnd
    SysTlsExternalReportGet = 618,
    SysTlsExternalReportDestroy = 619,
    SysTlsExternalReportQuery = 620,
    SysTlsInternalReportGet = 621,
    SysTlsInternalReportUpdate = 622,
    SysTlsInternalReportDestroy = 623,
    SysTlsInternalReportQuery = 624,
    SysTlsReportSettingsGet = 625,
    SysTlsReportSettingsUpdate = 626,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysTraceGet = 627,
    #[cfg(feature = "enterprise")]
    SysTraceQuery = 628,
    // SPDX-SnippetEnd
    SysTracerGet = 629,
    SysTracerCreate = 630,
    SysTracerUpdate = 631,
    SysTracerDestroy = 632,
    SysTracerQuery = 633,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SysTracingStoreGet = 634,
    #[cfg(feature = "enterprise")]
    SysTracingStoreUpdate = 635,
    // SPDX-SnippetEnd
    SysWebDavGet = 636,
    SysWebDavUpdate = 637,
    SysWebHookGet = 638,
    SysWebHookCreate = 639,
    SysWebHookUpdate = 640,
    SysWebHookDestroy = 641,
    SysWebHookQuery = 642,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PermissionsType {
    #[default]
    Inherit = 0,
    Merge = 1,
    Replace = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PolicyEnforcement {
    #[default]
    Enforce = 0,
    Testing = 1,
    Disable = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PostgreSqlRecyclingMethod {
    #[default]
    Fast = 0,
    Verified = 1,
    Clean = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ProviderInfo {
    #[default]
    ProviderName = 0,
    ProviderShortName = 1,
    UserDocumentation = 2,
    DeveloperDocumentation = 3,
    ContactUri = 4,
    LogoUrl = 5,
    LogoWidth = 6,
    LogoHeight = 7,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PublicKeyCapability {
    #[default]
    Aead = 0,
    PostQuantum = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PublicKeyKind {
    #[default]
    OpenPgp = 0,
    Smime = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PublicKeyWarning {
    #[default]
    WeakRsa = 0,
    NoKnownDecryptor = 1,
    PostQuantumOnly = 2,
    ExpiresSoon = 3,
    AddressMismatch = 4,
    Unusable = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PublicStringOptionalType {
    #[default]
    None = 0,
    Value = 1,
    EnvironmentVariable = 2,
    File = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PublicTextType {
    #[default]
    Text = 0,
    EnvironmentVariable = 1,
    File = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum QueueExpiryType {
    #[default]
    Ttl = 0,
    Attempts = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecipientFlag {
    #[default]
    DsnSent = 0,
    SpamPayload = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecipientStatusType {
    #[default]
    Scheduled = 0,
    Completed = 1,
    TemporaryFailure = 2,
    PermanentFailure = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RedisProtocol {
    #[default]
    Resp2 = 0,
    Resp3 = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RedisSwapStoreType {
    #[default]
    Default = 0,
    Redis = 1,
    RedisCluster = 2,
    RedisSentinel = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RolesType {
    #[default]
    Default = 0,
    Custom = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum S3StoreRegionType {
    #[default]
    UsEast1 = 0,
    UsEast2 = 1,
    UsWest1 = 2,
    UsWest2 = 3,
    CaCentral1 = 4,
    AfSouth1 = 5,
    ApEast1 = 6,
    ApSouth1 = 7,
    ApNortheast1 = 8,
    ApNortheast2 = 9,
    ApNortheast3 = 10,
    ApSoutheast1 = 11,
    ApSoutheast2 = 12,
    CnNorth1 = 13,
    CnNorthwest1 = 14,
    EuNorth1 = 15,
    EuCentral1 = 16,
    EuCentral2 = 17,
    EuWest1 = 18,
    EuWest2 = 19,
    EuWest3 = 20,
    IlCentral1 = 21,
    MeSouth1 = 22,
    SaEast1 = 23,
    DoNyc3 = 24,
    DoAms3 = 25,
    DoSgp1 = 26,
    DoFra1 = 27,
    Yandex = 28,
    WaUsEast1 = 29,
    WaUsEast2 = 30,
    WaUsCentral1 = 31,
    WaUsWest1 = 32,
    WaCaCentral1 = 33,
    WaEuCentral1 = 34,
    WaEuCentral2 = 35,
    WaEuWest1 = 36,
    WaEuWest2 = 37,
    WaApNortheast1 = 38,
    WaApNortheast2 = 39,
    WaApSoutheast1 = 40,
    WaApSoutheast2 = 41,
    Custom = 42,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SearchCalendarField {
    #[default]
    Title = 0,
    Description = 1,
    Location = 2,
    Owner = 3,
    Attendee = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SearchContactField {
    #[default]
    Member = 0,
    Kind = 1,
    Name = 2,
    Nickname = 3,
    Organization = 4,
    Email = 5,
    Phone = 6,
    OnlineService = 7,
    Address = 8,
    Note = 9,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SearchEmailField {
    #[default]
    From = 0,
    To = 1,
    Cc = 2,
    Bcc = 3,
    Subject = 4,
    Body = 5,
    Attachment = 6,
    Headers = 7,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SearchFileField {
    #[default]
    Name = 0,
    Content = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SearchStoreType {
    #[default]
    Default = 0,
    ElasticSearch = 1,
    Meilisearch = 2,
    FoundationDb = 3,
    PostgreSql = 4,
    MySql = 5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecretKeyOptionalType {
    #[default]
    None = 0,
    Value = 1,
    EnvironmentVariable = 2,
    File = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecretKeyType {
    #[default]
    Value = 0,
    EnvironmentVariable = 1,
    File = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecretTextOptionalType {
    #[default]
    None = 0,
    Text = 1,
    EnvironmentVariable = 2,
    File = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecretTextType {
    #[default]
    Text = 0,
    EnvironmentVariable = 1,
    File = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ServiceProtocol {
    #[default]
    Jmap = 0,
    Imap = 1,
    Pop3 = 2,
    Smtp = 3,
    Caldav = 4,
    Carddav = 5,
    Webdav = 6,
    Managesieve = 7,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SharedObjectType {
    #[default]
    Mailbox = 0,
    Calendar = 1,
    AddressBook = 2,
    FileNode = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SieveCapability {
    #[default]
    Envelope = 0,
    EnvelopeDsn = 1,
    EnvelopeDeliverby = 2,
    Fileinto = 3,
    EncodedCharacter = 4,
    ComparatorElbonia = 5,
    ComparatorIOctet = 6,
    ComparatorIAsciiCasemap = 7,
    ComparatorIAsciiNumeric = 8,
    Body = 9,
    Convert = 10,
    Copy = 11,
    Relational = 12,
    Date = 13,
    Index = 14,
    Duplicate = 15,
    Variables = 16,
    Editheader = 17,
    Foreverypart = 18,
    Mime = 19,
    Replace = 20,
    Enclose = 21,
    Extracttext = 22,
    Enotify = 23,
    RedirectDsn = 24,
    RedirectDeliverby = 25,
    Environment = 26,
    Reject = 27,
    Ereject = 28,
    Extlists = 29,
    Subaddress = 30,
    Vacation = 31,
    VacationSeconds = 32,
    Fcc = 33,
    Mailbox = 34,
    Mailboxid = 35,
    Mboxmetadata = 36,
    Servermetadata = 37,
    SpecialUse = 38,
    Imap4flags = 39,
    Ihave = 40,
    Imapsieve = 41,
    Include = 42,
    Regex = 43,
    Spamtest = 44,
    Spamtestplus = 45,
    Virustest = 46,
    VndStalwartWhile = 47,
    VndStalwartExpressions = 48,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Sig0Algorithm {
    #[default]
    EcdsaP256Sha256 = 0,
    EcdsaP384Sha384 = 1,
    Ed25519 = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SmimeCipher {
    #[default]
    Aes128Cbc = 0,
    Aes192Cbc = 1,
    Aes256Cbc = 2,
    Aes128Gcm = 3,
    Aes192Gcm = 4,
    Aes256Gcm = 5,
    ChaCha20Poly1305 = 6,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamAiLearnType {
    #[default]
    Disable = 0,
    Enable = 1,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamAiMode {
    #[default]
    Automatic = 0,
    Shadow = 1,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamAiType {
    #[default]
    Disable = 0,
    Enable = 1,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamAiWebSearchType {
    #[default]
    Disable = 0,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamClassifierModelType {
    #[default]
    FtrlFh = 0,
    FtrlCcfh = 1,
    Disabled = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamClassifyParameters {
    #[default]
    Bit7 = 0,
    Bit8Mime8BitMIMEMessageContent = 1,
    BinaryMime = 2,
    SmtpUtf8 = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamClassifyResult {
    #[default]
    Spam = 0,
    Ham = 1,
    Reject = 2,
    Discard = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamClassifyTagDisposition {
    #[default]
    Score = 0,
    Reject = 1,
    Discard = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamDnsblServerType {
    #[default]
    Any = 0,
    Url = 1,
    Domain = 2,
    Email = 3,
    Ip = 4,
    Header = 5,
    Body = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamRuleType {
    #[default]
    Any = 0,
    Url = 1,
    Domain = 2,
    Email = 3,
    Ip = 4,
    Header = 5,
    Body = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamTagType {
    #[default]
    Score = 0,
    Discard = 1,
    Reject = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpecialUse {
    #[default]
    Inbox = 0,
    Trash = 1,
    Junk = 2,
    Drafts = 3,
    Archive = 4,
    Sent = 5,
    Shared = 6,
    Important = 7,
    Memos = 8,
    Scheduled = 9,
    Snoozed = 10,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpfAuthResult {
    #[default]
    None = 0,
    Neutral = 1,
    Pass = 2,
    Fail = 3,
    SoftFail = 4,
    TempError = 5,
    PermError = 6,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpfDomainScope {
    #[default]
    Helo = 0,
    MailFrom = 1,
    Unspecified = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SqlAuthStoreType {
    #[default]
    Default = 0,
    PostgreSql = 1,
    MySql = 2,
    Sqlite = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StorageQuota {
    #[default]
    MaxEmails = 0,
    MaxMailboxes = 1,
    MaxEmailSubmissions = 2,
    MaxEmailIdentities = 3,
    MaxParticipantIdentities = 4,
    MaxSieveScripts = 5,
    MaxPushSubscriptions = 6,
    MaxCalendars = 7,
    MaxCalendarEvents = 8,
    MaxCalendarEventNotifications = 9,
    MaxAddressBooks = 10,
    MaxContactCards = 11,
    MaxFiles = 12,
    MaxFolders = 13,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MaxMaskedAddresses = 14,
    // SPDX-SnippetEnd
    MaxAppPasswords = 15,
    MaxApiKeys = 16,
    MaxPublicKeys = 17,
    MaxDiskQuota = 18,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SubAddressingType {
    #[default]
    Enabled = 0,
    Custom = 1,
    Disabled = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SymmetricCipher {
    #[default]
    Aes256Gcm = 0,
    Chacha20Poly1305 = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskAccountMaintenanceType {
    #[default]
    Purge = 0,
    Reindex = 1,
    RecalculateImapUid = 2,
    RecalculateQuota = 3,
    RebuildShares = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskBlobRecodeCompression {
    #[default]
    Keep = 0,
    Disable = 1,
    Lz4 = 2,
    Zstd = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskBlobRecodeEncryptionType {
    #[default]
    Keep = 0,
    Disable = 1,
    Encrypt = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskRetryStrategyType {
    #[default]
    ExponentialBackoff = 0,
    FixedDelay = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskSpamFilterMaintenanceType {
    #[default]
    Train = 0,
    Retrain = 1,
    Abort = 2,
    Reset = 3,
    UpdateRules = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskStatusType {
    #[default]
    Pending = 0,
    Retry = 1,
    Failed = 2,
    Stalled = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskStoreMaintenanceType {
    #[default]
    ReindexAccounts = 0,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ReindexTelemetry = 1,
    // SPDX-SnippetEnd
    PurgeAccounts = 2,
    PurgeData = 3,
    PurgeBlob = 4,
    ResetRateLimiters = 5,
    ResetUserQuotas = 6,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    ResetTenantQuotas = 7,
    // SPDX-SnippetEnd
    ResetBlobQuotas = 8,
    RemoveAuthTokens = 9,
    RemoveLockQueueMessage = 10,
    RemoveLockTask = 11,
    RemoveLockDav = 12,
    RemoveGreylist = 13,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskTenantMaintenanceType {
    #[default]
    RecalculateQuota = 0,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskType {
    #[default]
    CalendarAlarmEmail = 0,
    CalendarAlarmNotification = 1,
    CalendarItipMessage = 2,
    MergeThreads = 3,
    DmarcReport = 4,
    TlsReport = 5,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    RestoreArchivedItem = 6,
    // SPDX-SnippetEnd
    DestroyAccount = 7,
    AccountMaintenance = 8,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TenantMaintenance = 9,
    // SPDX-SnippetEnd
    StoreMaintenance = 10,
    SpamFilterMaintenance = 11,
    AcmeRenewal = 12,
    DkimManagement = 13,
    DnsManagement = 14,
    ShareRevokeCleanup = 15,
    DmarcReportWindow = 16,
    TlsReportWindow = 17,
    ExternalPublicKeyMaintenance = 18,
    BlobRecode = 19,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TenantStorageQuota {
    #[default]
    MaxAccounts = 0,
    MaxGroups = 1,
    MaxDomains = 2,
    MaxMailingLists = 3,
    MaxRoles = 4,
    MaxOauthClients = 5,
    MaxDkimKeys = 6,
    MaxDnsServers = 7,
    MaxDirectories = 8,
    MaxAcmeProviders = 9,
    MaxDiskQuota = 10,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TimeZone {
    #[default]
    AfricaAbidjan = 0,
    AfricaAccra = 1,
    AfricaAddisAbaba = 2,
    AfricaAlgiers = 3,
    AfricaAsmara = 4,
    AfricaAsmera = 5,
    AfricaBamako = 6,
    AfricaBangui = 7,
    AfricaBanjul = 8,
    AfricaBissau = 9,
    AfricaBlantyre = 10,
    AfricaBrazzaville = 11,
    AfricaBujumbura = 12,
    AfricaCairo = 13,
    AfricaCasablanca = 14,
    AfricaCeuta = 15,
    AfricaConakry = 16,
    AfricaDakar = 17,
    AfricaDarEsSalaam = 18,
    AfricaDjibouti = 19,
    AfricaDouala = 20,
    AfricaElAaiun = 21,
    AfricaFreetown = 22,
    AfricaGaborone = 23,
    AfricaHarare = 24,
    AfricaJohannesburg = 25,
    AfricaJuba = 26,
    AfricaKampala = 27,
    AfricaKhartoum = 28,
    AfricaKigali = 29,
    AfricaKinshasa = 30,
    AfricaLagos = 31,
    AfricaLibreville = 32,
    AfricaLome = 33,
    AfricaLuanda = 34,
    AfricaLubumbashi = 35,
    AfricaLusaka = 36,
    AfricaMalabo = 37,
    AfricaMaputo = 38,
    AfricaMaseru = 39,
    AfricaMbabane = 40,
    AfricaMogadishu = 41,
    AfricaMonrovia = 42,
    AfricaNairobi = 43,
    AfricaNdjamena = 44,
    AfricaNiamey = 45,
    AfricaNouakchott = 46,
    AfricaOuagadougou = 47,
    AfricaPortoNovo = 48,
    AfricaSaoTome = 49,
    AfricaTimbuktu = 50,
    AfricaTripoli = 51,
    AfricaTunis = 52,
    AfricaWindhoek = 53,
    AmericaAdak = 54,
    AmericaAnchorage = 55,
    AmericaAnguilla = 56,
    AmericaAntigua = 57,
    AmericaAraguaina = 58,
    AmericaArgentinaBuenosAires = 59,
    AmericaArgentinaCatamarca = 60,
    AmericaArgentinaComodRivadavia = 61,
    AmericaArgentinaCordoba = 62,
    AmericaArgentinaJujuy = 63,
    AmericaArgentinaLaRioja = 64,
    AmericaArgentinaMendoza = 65,
    AmericaArgentinaRioGallegos = 66,
    AmericaArgentinaSalta = 67,
    AmericaArgentinaSanJuan = 68,
    AmericaArgentinaSanLuis = 69,
    AmericaArgentinaTucuman = 70,
    AmericaArgentinaUshuaia = 71,
    AmericaAruba = 72,
    AmericaAsuncion = 73,
    AmericaAtikokan = 74,
    AmericaAtka = 75,
    AmericaBahia = 76,
    AmericaBahiaBanderas = 77,
    AmericaBarbados = 78,
    AmericaBelem = 79,
    AmericaBelize = 80,
    AmericaBlancSablon = 81,
    AmericaBoaVista = 82,
    AmericaBogota = 83,
    AmericaBoise = 84,
    AmericaBuenosAires = 85,
    AmericaCambridgeBay = 86,
    AmericaCampoGrande = 87,
    AmericaCancun = 88,
    AmericaCaracas = 89,
    AmericaCatamarca = 90,
    AmericaCayenne = 91,
    AmericaCayman = 92,
    AmericaChicago = 93,
    AmericaChihuahua = 94,
    AmericaCiudadJuarez = 95,
    AmericaCoralHarbour = 96,
    AmericaCordoba = 97,
    AmericaCostaRica = 98,
    AmericaCoyhaique = 99,
    AmericaCreston = 100,
    AmericaCuiaba = 101,
    AmericaCuracao = 102,
    AmericaDanmarkshavn = 103,
    AmericaDawson = 104,
    AmericaDawsonCreek = 105,
    AmericaDenver = 106,
    AmericaDetroit = 107,
    AmericaDominica = 108,
    AmericaEdmonton = 109,
    AmericaEirunepe = 110,
    AmericaElSalvador = 111,
    AmericaEnsenada = 112,
    AmericaFortNelson = 113,
    AmericaFortWayne = 114,
    AmericaFortaleza = 115,
    AmericaGlaceBay = 116,
    AmericaGodthab = 117,
    AmericaGooseBay = 118,
    AmericaGrandTurk = 119,
    AmericaGrenada = 120,
    AmericaGuadeloupe = 121,
    AmericaGuatemala = 122,
    AmericaGuayaquil = 123,
    AmericaGuyana = 124,
    AmericaHalifax = 125,
    AmericaHavana = 126,
    AmericaHermosillo = 127,
    AmericaIndianaIndianapolis = 128,
    AmericaIndianaKnox = 129,
    AmericaIndianaMarengo = 130,
    AmericaIndianaPetersburg = 131,
    AmericaIndianaTellCity = 132,
    AmericaIndianaVevay = 133,
    AmericaIndianaVincennes = 134,
    AmericaIndianaWinamac = 135,
    AmericaIndianapolis = 136,
    AmericaInuvik = 137,
    AmericaIqaluit = 138,
    AmericaJamaica = 139,
    AmericaJujuy = 140,
    AmericaJuneau = 141,
    AmericaKentuckyLouisville = 142,
    AmericaKentuckyMonticello = 143,
    AmericaKnoxIN = 144,
    AmericaKralendijk = 145,
    AmericaLaPaz = 146,
    AmericaLima = 147,
    AmericaLosAngeles = 148,
    AmericaLouisville = 149,
    AmericaLowerPrinces = 150,
    AmericaMaceio = 151,
    AmericaManagua = 152,
    AmericaManaus = 153,
    AmericaMarigot = 154,
    AmericaMartinique = 155,
    AmericaMatamoros = 156,
    AmericaMazatlan = 157,
    AmericaMendoza = 158,
    AmericaMenominee = 159,
    AmericaMerida = 160,
    AmericaMetlakatla = 161,
    AmericaMexicoCity = 162,
    AmericaMiquelon = 163,
    AmericaMoncton = 164,
    AmericaMonterrey = 165,
    AmericaMontevideo = 166,
    AmericaMontreal = 167,
    AmericaMontserrat = 168,
    AmericaNassau = 169,
    AmericaNewYork = 170,
    AmericaNipigon = 171,
    AmericaNome = 172,
    AmericaNoronha = 173,
    AmericaNorthDakotaBeulah = 174,
    AmericaNorthDakotaCenter = 175,
    AmericaNorthDakotaNewSalem = 176,
    AmericaNuuk = 177,
    AmericaOjinaga = 178,
    AmericaPanama = 179,
    AmericaPangnirtung = 180,
    AmericaParamaribo = 181,
    AmericaPhoenix = 182,
    AmericaPortAuPrince = 183,
    AmericaPortOfSpain = 184,
    AmericaPortoAcre = 185,
    AmericaPortoVelho = 186,
    AmericaPuertoRico = 187,
    AmericaPuntaArenas = 188,
    AmericaRainyRiver = 189,
    AmericaRankinInlet = 190,
    AmericaRecife = 191,
    AmericaRegina = 192,
    AmericaResolute = 193,
    AmericaRioBranco = 194,
    AmericaRosario = 195,
    AmericaSantaIsabel = 196,
    AmericaSantarem = 197,
    AmericaSantiago = 198,
    AmericaSantoDomingo = 199,
    AmericaSaoPaulo = 200,
    AmericaScoresbysund = 201,
    AmericaShiprock = 202,
    AmericaSitka = 203,
    AmericaStBarthelemy = 204,
    AmericaStJohns = 205,
    AmericaStKitts = 206,
    AmericaStLucia = 207,
    AmericaStThomas = 208,
    AmericaStVincent = 209,
    AmericaSwiftCurrent = 210,
    AmericaTegucigalpa = 211,
    AmericaThule = 212,
    AmericaThunderBay = 213,
    AmericaTijuana = 214,
    AmericaToronto = 215,
    AmericaTortola = 216,
    AmericaVancouver = 217,
    AmericaVirgin = 218,
    AmericaWhitehorse = 219,
    AmericaWinnipeg = 220,
    AmericaYakutat = 221,
    AmericaYellowknife = 222,
    AntarcticaCasey = 223,
    AntarcticaDavis = 224,
    AntarcticaDumontDUrville = 225,
    AntarcticaMacquarie = 226,
    AntarcticaMawson = 227,
    AntarcticaMcMurdo = 228,
    AntarcticaPalmer = 229,
    AntarcticaRothera = 230,
    AntarcticaSouthPole = 231,
    AntarcticaSyowa = 232,
    AntarcticaTroll = 233,
    AntarcticaVostok = 234,
    ArcticLongyearbyen = 235,
    AsiaAden = 236,
    AsiaAlmaty = 237,
    AsiaAmman = 238,
    AsiaAnadyr = 239,
    AsiaAqtau = 240,
    AsiaAqtobe = 241,
    AsiaAshgabat = 242,
    AsiaAshkhabad = 243,
    AsiaAtyrau = 244,
    AsiaBaghdad = 245,
    AsiaBahrain = 246,
    AsiaBaku = 247,
    AsiaBangkok = 248,
    AsiaBarnaul = 249,
    AsiaBeirut = 250,
    AsiaBishkek = 251,
    AsiaBrunei = 252,
    AsiaCalcutta = 253,
    AsiaChita = 254,
    AsiaChoibalsan = 255,
    AsiaChongqing = 256,
    AsiaChungking = 257,
    AsiaColombo = 258,
    AsiaDacca = 259,
    AsiaDamascus = 260,
    AsiaDhaka = 261,
    AsiaDili = 262,
    AsiaDubai = 263,
    AsiaDushanbe = 264,
    AsiaFamagusta = 265,
    AsiaGaza = 266,
    AsiaHarbin = 267,
    AsiaHebron = 268,
    AsiaHoChiMinh = 269,
    AsiaHongKong = 270,
    AsiaHovd = 271,
    AsiaIrkutsk = 272,
    AsiaIstanbul = 273,
    AsiaJakarta = 274,
    AsiaJayapura = 275,
    AsiaJerusalem = 276,
    AsiaKabul = 277,
    AsiaKamchatka = 278,
    AsiaKarachi = 279,
    AsiaKashgar = 280,
    AsiaKathmandu = 281,
    AsiaKatmandu = 282,
    AsiaKhandyga = 283,
    AsiaKolkata = 284,
    AsiaKrasnoyarsk = 285,
    AsiaKualaLumpur = 286,
    AsiaKuching = 287,
    AsiaKuwait = 288,
    AsiaMacao = 289,
    AsiaMacau = 290,
    AsiaMagadan = 291,
    AsiaMakassar = 292,
    AsiaManila = 293,
    AsiaMuscat = 294,
    AsiaNicosia = 295,
    AsiaNovokuznetsk = 296,
    AsiaNovosibirsk = 297,
    AsiaOmsk = 298,
    AsiaOral = 299,
    AsiaPhnomPenh = 300,
    AsiaPontianak = 301,
    AsiaPyongyang = 302,
    AsiaQatar = 303,
    AsiaQostanay = 304,
    AsiaQyzylorda = 305,
    AsiaRangoon = 306,
    AsiaRiyadh = 307,
    AsiaSaigon = 308,
    AsiaSakhalin = 309,
    AsiaSamarkand = 310,
    AsiaSeoul = 311,
    AsiaShanghai = 312,
    AsiaSingapore = 313,
    AsiaSrednekolymsk = 314,
    AsiaTaipei = 315,
    AsiaTashkent = 316,
    AsiaTbilisi = 317,
    AsiaTehran = 318,
    AsiaTelAviv = 319,
    AsiaThimbu = 320,
    AsiaThimphu = 321,
    AsiaTokyo = 322,
    AsiaTomsk = 323,
    AsiaUjungPandang = 324,
    AsiaUlaanbaatar = 325,
    AsiaUlanBator = 326,
    AsiaUrumqi = 327,
    AsiaUstNera = 328,
    AsiaVientiane = 329,
    AsiaVladivostok = 330,
    AsiaYakutsk = 331,
    AsiaYangon = 332,
    AsiaYekaterinburg = 333,
    AsiaYerevan = 334,
    AtlanticAzores = 335,
    AtlanticBermuda = 336,
    AtlanticCanary = 337,
    AtlanticCapeVerde = 338,
    AtlanticFaeroe = 339,
    AtlanticFaroe = 340,
    AtlanticJanMayen = 341,
    AtlanticMadeira = 342,
    AtlanticReykjavik = 343,
    AtlanticSouthGeorgia = 344,
    AtlanticStHelena = 345,
    AtlanticStanley = 346,
    AustraliaACT = 347,
    AustraliaAdelaide = 348,
    AustraliaBrisbane = 349,
    AustraliaBrokenHill = 350,
    AustraliaCanberra = 351,
    AustraliaCurrie = 352,
    AustraliaDarwin = 353,
    AustraliaEucla = 354,
    AustraliaHobart = 355,
    AustraliaLHI = 356,
    AustraliaLindeman = 357,
    AustraliaLordHowe = 358,
    AustraliaMelbourne = 359,
    AustraliaNSW = 360,
    AustraliaNorth = 361,
    AustraliaPerth = 362,
    AustraliaQueensland = 363,
    AustraliaSouth = 364,
    AustraliaSydney = 365,
    AustraliaTasmania = 366,
    AustraliaVictoria = 367,
    AustraliaWest = 368,
    AustraliaYancowinna = 369,
    BrazilAcre = 370,
    BrazilDeNoronha = 371,
    BrazilEast = 372,
    BrazilWest = 373,
    CET = 374,
    CST6CDT = 375,
    CanadaAtlantic = 376,
    CanadaCentral = 377,
    CanadaEastern = 378,
    CanadaMountain = 379,
    CanadaNewfoundland = 380,
    CanadaPacific = 381,
    CanadaSaskatchewan = 382,
    CanadaYukon = 383,
    ChileContinental = 384,
    ChileEasterIsland = 385,
    Cuba = 386,
    EET = 387,
    EST = 388,
    EST5EDT = 389,
    Egypt = 390,
    Eire = 391,
    EtcGMT = 392,
    EtcGMTPlus0 = 393,
    EtcGMTPlus1 = 394,
    EtcGMTPlus10 = 395,
    EtcGMTPlus11 = 396,
    EtcGMTPlus12 = 397,
    EtcGMTPlus2 = 398,
    EtcGMTPlus3 = 399,
    EtcGMTPlus4 = 400,
    EtcGMTPlus5 = 401,
    EtcGMTPlus6 = 402,
    EtcGMTPlus7 = 403,
    EtcGMTPlus8 = 404,
    EtcGMTPlus9 = 405,
    EtcGMTMinus0 = 406,
    EtcGMTMinus1 = 407,
    EtcGMTMinus10 = 408,
    EtcGMTMinus11 = 409,
    EtcGMTMinus12 = 410,
    EtcGMTMinus13 = 411,
    EtcGMTMinus14 = 412,
    EtcGMTMinus2 = 413,
    EtcGMTMinus3 = 414,
    EtcGMTMinus4 = 415,
    EtcGMTMinus5 = 416,
    EtcGMTMinus6 = 417,
    EtcGMTMinus7 = 418,
    EtcGMTMinus8 = 419,
    EtcGMTMinus9 = 420,
    EtcGMT0 = 421,
    EtcGreenwich = 422,
    EtcUCT = 423,
    EtcUTC = 424,
    EtcUniversal = 425,
    EtcZulu = 426,
    EuropeAmsterdam = 427,
    EuropeAndorra = 428,
    EuropeAstrakhan = 429,
    EuropeAthens = 430,
    EuropeBelfast = 431,
    EuropeBelgrade = 432,
    EuropeBerlin = 433,
    EuropeBratislava = 434,
    EuropeBrussels = 435,
    EuropeBucharest = 436,
    EuropeBudapest = 437,
    EuropeBusingen = 438,
    EuropeChisinau = 439,
    EuropeCopenhagen = 440,
    EuropeDublin = 441,
    EuropeGibraltar = 442,
    EuropeGuernsey = 443,
    EuropeHelsinki = 444,
    EuropeIsleOfMan = 445,
    EuropeIstanbul = 446,
    EuropeJersey = 447,
    EuropeKaliningrad = 448,
    EuropeKiev = 449,
    EuropeKirov = 450,
    EuropeKyiv = 451,
    EuropeLisbon = 452,
    EuropeLjubljana = 453,
    EuropeLondon = 454,
    EuropeLuxembourg = 455,
    EuropeMadrid = 456,
    EuropeMalta = 457,
    EuropeMariehamn = 458,
    EuropeMinsk = 459,
    EuropeMonaco = 460,
    EuropeMoscow = 461,
    EuropeNicosia = 462,
    EuropeOslo = 463,
    EuropeParis = 464,
    EuropePodgorica = 465,
    EuropePrague = 466,
    EuropeRiga = 467,
    EuropeRome = 468,
    EuropeSamara = 469,
    EuropeSanMarino = 470,
    EuropeSarajevo = 471,
    EuropeSaratov = 472,
    EuropeSimferopol = 473,
    EuropeSkopje = 474,
    EuropeSofia = 475,
    EuropeStockholm = 476,
    EuropeTallinn = 477,
    EuropeTirane = 478,
    EuropeTiraspol = 479,
    EuropeUlyanovsk = 480,
    EuropeUzhgorod = 481,
    EuropeVaduz = 482,
    EuropeVatican = 483,
    EuropeVienna = 484,
    EuropeVilnius = 485,
    EuropeVolgograd = 486,
    EuropeWarsaw = 487,
    EuropeZagreb = 488,
    EuropeZaporozhye = 489,
    EuropeZurich = 490,
    Factory = 491,
    GB = 492,
    GBEire = 493,
    GMT = 494,
    GMTPlus0 = 495,
    GMTMinus0 = 496,
    GMT0 = 497,
    Greenwich = 498,
    HST = 499,
    Hongkong = 500,
    Iceland = 501,
    IndianAntananarivo = 502,
    IndianChagos = 503,
    IndianChristmas = 504,
    IndianCocos = 505,
    IndianComoro = 506,
    IndianKerguelen = 507,
    IndianMahe = 508,
    IndianMaldives = 509,
    IndianMauritius = 510,
    IndianMayotte = 511,
    IndianReunion = 512,
    Iran = 513,
    Israel = 514,
    Jamaica = 515,
    Japan = 516,
    Kwajalein = 517,
    Libya = 518,
    MET = 519,
    MST = 520,
    MST7MDT = 521,
    MexicoBajaNorte = 522,
    MexicoBajaSur = 523,
    MexicoGeneral = 524,
    NZ = 525,
    NZCHAT = 526,
    Navajo = 527,
    PRC = 528,
    PST8PDT = 529,
    PacificApia = 530,
    PacificAuckland = 531,
    PacificBougainville = 532,
    PacificChatham = 533,
    PacificChuuk = 534,
    PacificEaster = 535,
    PacificEfate = 536,
    PacificEnderbury = 537,
    PacificFakaofo = 538,
    PacificFiji = 539,
    PacificFunafuti = 540,
    PacificGalapagos = 541,
    PacificGambier = 542,
    PacificGuadalcanal = 543,
    PacificGuam = 544,
    PacificHonolulu = 545,
    PacificJohnston = 546,
    PacificKanton = 547,
    PacificKiritimati = 548,
    PacificKosrae = 549,
    PacificKwajalein = 550,
    PacificMajuro = 551,
    PacificMarquesas = 552,
    PacificMidway = 553,
    PacificNauru = 554,
    PacificNiue = 555,
    PacificNorfolk = 556,
    PacificNoumea = 557,
    PacificPagoPago = 558,
    PacificPalau = 559,
    PacificPitcairn = 560,
    PacificPohnpei = 561,
    PacificPonape = 562,
    PacificPortMoresby = 563,
    PacificRarotonga = 564,
    PacificSaipan = 565,
    PacificSamoa = 566,
    PacificTahiti = 567,
    PacificTarawa = 568,
    PacificTongatapu = 569,
    PacificTruk = 570,
    PacificWake = 571,
    PacificWallis = 572,
    PacificYap = 573,
    Poland = 574,
    Portugal = 575,
    ROC = 576,
    ROK = 577,
    Singapore = 578,
    Turkey = 579,
    UCT = 580,
    USAlaska = 581,
    USAleutian = 582,
    USArizona = 583,
    USCentral = 584,
    USEastIndiana = 585,
    USEastern = 586,
    USHawaii = 587,
    USIndianaStarke = 588,
    USMichigan = 589,
    USMountain = 590,
    USPacific = 591,
    USSamoa = 592,
    UTC = 593,
    Universal = 594,
    WSU = 595,
    WET = 596,
    Zulu = 597,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsCipherSuite {
    #[default]
    Tls13Aes256GcmSha384 = 0,
    Tls13Aes128GcmSha256 = 1,
    Tls13Chacha20Poly1305Sha256 = 2,
    TlsEcdheEcdsaWithAes256GcmSha384 = 3,
    TlsEcdheEcdsaWithAes128GcmSha256 = 4,
    TlsEcdheEcdsaWithChacha20Poly1305Sha256 = 5,
    TlsEcdheRsaWithAes256GcmSha384 = 6,
    TlsEcdheRsaWithAes128GcmSha256 = 7,
    TlsEcdheRsaWithChacha20Poly1305Sha256 = 8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsPolicyType {
    #[default]
    Tlsa = 0,
    Sts = 1,
    NoPolicyFound = 2,
    Other = 3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsResultType {
    #[default]
    StartTlsNotSupported = 0,
    CertificateHostMismatch = 1,
    CertificateExpired = 2,
    CertificateNotTrusted = 3,
    ValidationFailure = 4,
    TlsaInvalid = 5,
    DnssecInvalid = 6,
    DaneRequired = 7,
    StsPolicyFetchError = 8,
    StsPolicyInvalid = 9,
    StsWebpkiInvalid = 10,
    Other = 11,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsVersion {
    #[default]
    Tls12 = 0,
    Tls13 = 1,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TraceValueType {
    #[default]
    String = 0,
    UnsignedInt = 1,
    Integer = 2,
    Boolean = 3,
    Float = 4,
    UTCDateTime = 5,
    Duration = 6,
    IpAddr = 7,
    List = 8,
    Event = 9,
    Null = 10,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TracerType {
    #[default]
    Log = 0,
    Stdout = 1,
    Journal = 2,
    OtelHttp = 3,
    OtelGrpc = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TracingLevel {
    #[default]
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TracingLevelOpt {
    #[default]
    Disable = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TracingStoreType {
    #[default]
    Disabled = 0,
    Default = 1,
    FoundationDb = 2,
    PostgreSql = 3,
    MySql = 4,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TsigAlgorithm {
    #[default]
    HmacMd5 = 0,
    Gss = 1,
    HmacSha1 = 2,
    HmacSha224 = 3,
    HmacSha256 = 4,
    HmacSha256128 = 5,
    HmacSha384 = 6,
    HmacSha384192 = 7,
    HmacSha512 = 8,
    HmacSha512256 = 9,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum UserRolesType {
    #[default]
    User = 0,
    Admin = 1,
    Custom = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum VCardVersion {
    #[default]
    V4 = 0,
    V3 = 1,
}

pub static ENCRYPTION_HARVEST_VARIABLE: &[ExpressionVariable] =
    &[ExpressionVariable::Sender, ExpressionVariable::SenderDomain];

pub static HTTP_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Listener,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemotePort,
    ExpressionVariable::LocalIp,
    ExpressionVariable::LocalPort,
    ExpressionVariable::Protocol,
    ExpressionVariable::IsTls,
    ExpressionVariable::Url,
    ExpressionVariable::Path,
    ExpressionVariable::Headers,
    ExpressionVariable::Method,
];

pub static MTA_CONNECTION_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Listener,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemotePort,
    ExpressionVariable::LocalIp,
    ExpressionVariable::LocalPort,
    ExpressionVariable::Protocol,
    ExpressionVariable::IsTls,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
];

pub static MTA_EHLO_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Listener,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemotePort,
    ExpressionVariable::LocalIp,
    ExpressionVariable::LocalPort,
    ExpressionVariable::Protocol,
    ExpressionVariable::IsTls,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
];

pub static MTA_MAIL_FROM_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Listener,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemotePort,
    ExpressionVariable::LocalIp,
    ExpressionVariable::LocalPort,
    ExpressionVariable::Protocol,
    ExpressionVariable::IsTls,
    ExpressionVariable::Sender,
    ExpressionVariable::SenderDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
];

pub static MTA_QUEUE_HOST_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Sender,
    ExpressionVariable::SenderDomain,
    ExpressionVariable::RcptDomain,
    ExpressionVariable::Rcpt,
    ExpressionVariable::Recipients,
    ExpressionVariable::Mx,
    ExpressionVariable::Priority,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::LocalIp,
    ExpressionVariable::RetryNum,
    ExpressionVariable::NotifyNum,
    ExpressionVariable::ExpiresIn,
    ExpressionVariable::LastStatus,
    ExpressionVariable::LastError,
    ExpressionVariable::QueueName,
    ExpressionVariable::QueueAge,
    ExpressionVariable::ReceivedFromIp,
    ExpressionVariable::ReceivedViaPort,
    ExpressionVariable::Source,
    ExpressionVariable::Size,
];

pub static MTA_QUEUE_RCPT_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Rcpt,
    ExpressionVariable::RcptDomain,
    ExpressionVariable::Recipients,
    ExpressionVariable::Sender,
    ExpressionVariable::SenderDomain,
    ExpressionVariable::Priority,
    ExpressionVariable::RetryNum,
    ExpressionVariable::NotifyNum,
    ExpressionVariable::ExpiresIn,
    ExpressionVariable::LastStatus,
    ExpressionVariable::LastError,
    ExpressionVariable::QueueName,
    ExpressionVariable::QueueAge,
    ExpressionVariable::ReceivedFromIp,
    ExpressionVariable::ReceivedViaPort,
    ExpressionVariable::Source,
    ExpressionVariable::Size,
];

pub static MTA_QUEUE_SENDER_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Sender,
    ExpressionVariable::SenderDomain,
    ExpressionVariable::Priority,
    ExpressionVariable::Recipients,
];

pub static MTA_RCPT_DOMAIN_VARIABLE: &[ExpressionVariable] = &[ExpressionVariable::RcptDomain];

pub static MTA_RCPT_TO_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Sender,
    ExpressionVariable::SenderDomain,
    ExpressionVariable::Recipients,
    ExpressionVariable::Rcpt,
    ExpressionVariable::RcptDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Listener,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemotePort,
    ExpressionVariable::LocalIp,
    ExpressionVariable::LocalPort,
    ExpressionVariable::Protocol,
    ExpressionVariable::IsTls,
    ExpressionVariable::Priority,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
];

pub static MTA_RCPT_VARIABLE: &[ExpressionVariable] = &[ExpressionVariable::Rcpt];

pub static SPAM_AI_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::SpamScore,
    ExpressionVariable::SpamThreshold,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemoteIpPtr,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
    ExpressionVariable::IsTls,
    ExpressionVariable::EnvFrom,
    ExpressionVariable::EnvFromLocal,
    ExpressionVariable::EnvFromDomain,
    ExpressionVariable::EnvTo,
    ExpressionVariable::From,
    ExpressionVariable::FromName,
    ExpressionVariable::FromLocal,
    ExpressionVariable::FromDomain,
    ExpressionVariable::ReplyTo,
    ExpressionVariable::ReplyToName,
    ExpressionVariable::ReplyToLocal,
    ExpressionVariable::ReplyToDomain,
    ExpressionVariable::To,
    ExpressionVariable::ToName,
    ExpressionVariable::ToLocal,
    ExpressionVariable::ToDomain,
    ExpressionVariable::Cc,
    ExpressionVariable::CcName,
    ExpressionVariable::CcLocal,
    ExpressionVariable::CcDomain,
    ExpressionVariable::Bcc,
    ExpressionVariable::BccName,
    ExpressionVariable::BccLocal,
    ExpressionVariable::BccDomain,
    ExpressionVariable::Body,
    ExpressionVariable::BodyText,
    ExpressionVariable::BodyHtml,
    ExpressionVariable::BodyWords,
    ExpressionVariable::BodyRaw,
    ExpressionVariable::Subject,
    ExpressionVariable::SubjectThread,
    ExpressionVariable::SubjectWords,
    ExpressionVariable::Location,
    ExpressionVariable::SpamProbability,
];

pub static SPAM_DEFAULT_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemoteIpPtr,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
    ExpressionVariable::IsTls,
    ExpressionVariable::EnvFrom,
    ExpressionVariable::EnvFromLocal,
    ExpressionVariable::EnvFromDomain,
    ExpressionVariable::EnvTo,
    ExpressionVariable::From,
    ExpressionVariable::FromName,
    ExpressionVariable::FromLocal,
    ExpressionVariable::FromDomain,
    ExpressionVariable::ReplyTo,
    ExpressionVariable::ReplyToName,
    ExpressionVariable::ReplyToLocal,
    ExpressionVariable::ReplyToDomain,
    ExpressionVariable::To,
    ExpressionVariable::ToName,
    ExpressionVariable::ToLocal,
    ExpressionVariable::ToDomain,
    ExpressionVariable::Cc,
    ExpressionVariable::CcName,
    ExpressionVariable::CcLocal,
    ExpressionVariable::CcDomain,
    ExpressionVariable::Bcc,
    ExpressionVariable::BccName,
    ExpressionVariable::BccLocal,
    ExpressionVariable::BccDomain,
    ExpressionVariable::Body,
    ExpressionVariable::BodyText,
    ExpressionVariable::BodyHtml,
    ExpressionVariable::BodyWords,
    ExpressionVariable::BodyRaw,
    ExpressionVariable::Subject,
    ExpressionVariable::SubjectThread,
    ExpressionVariable::SubjectWords,
    ExpressionVariable::Location,
    ExpressionVariable::SpamProbability,
];

pub static SPAM_EMAIL_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Email,
    ExpressionVariable::Value,
    ExpressionVariable::Name,
    ExpressionVariable::Local,
    ExpressionVariable::Domain,
    ExpressionVariable::Sld,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemoteIpPtr,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
    ExpressionVariable::IsTls,
    ExpressionVariable::EnvFrom,
    ExpressionVariable::EnvFromLocal,
    ExpressionVariable::EnvFromDomain,
    ExpressionVariable::EnvTo,
    ExpressionVariable::From,
    ExpressionVariable::FromName,
    ExpressionVariable::FromLocal,
    ExpressionVariable::FromDomain,
    ExpressionVariable::ReplyTo,
    ExpressionVariable::ReplyToName,
    ExpressionVariable::ReplyToLocal,
    ExpressionVariable::ReplyToDomain,
    ExpressionVariable::To,
    ExpressionVariable::ToName,
    ExpressionVariable::ToLocal,
    ExpressionVariable::ToDomain,
    ExpressionVariable::Cc,
    ExpressionVariable::CcName,
    ExpressionVariable::CcLocal,
    ExpressionVariable::CcDomain,
    ExpressionVariable::Bcc,
    ExpressionVariable::BccName,
    ExpressionVariable::BccLocal,
    ExpressionVariable::BccDomain,
    ExpressionVariable::Body,
    ExpressionVariable::BodyText,
    ExpressionVariable::BodyHtml,
    ExpressionVariable::BodyWords,
    ExpressionVariable::BodyRaw,
    ExpressionVariable::Subject,
    ExpressionVariable::SubjectThread,
    ExpressionVariable::SubjectWords,
    ExpressionVariable::Location,
    ExpressionVariable::SpamProbability,
];

pub static SPAM_GENERIC_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Value,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemoteIpPtr,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
    ExpressionVariable::IsTls,
    ExpressionVariable::EnvFrom,
    ExpressionVariable::EnvFromLocal,
    ExpressionVariable::EnvFromDomain,
    ExpressionVariable::EnvTo,
    ExpressionVariable::From,
    ExpressionVariable::FromName,
    ExpressionVariable::FromLocal,
    ExpressionVariable::FromDomain,
    ExpressionVariable::ReplyTo,
    ExpressionVariable::ReplyToName,
    ExpressionVariable::ReplyToLocal,
    ExpressionVariable::ReplyToDomain,
    ExpressionVariable::To,
    ExpressionVariable::ToName,
    ExpressionVariable::ToLocal,
    ExpressionVariable::ToDomain,
    ExpressionVariable::Cc,
    ExpressionVariable::CcName,
    ExpressionVariable::CcLocal,
    ExpressionVariable::CcDomain,
    ExpressionVariable::Bcc,
    ExpressionVariable::BccName,
    ExpressionVariable::BccLocal,
    ExpressionVariable::BccDomain,
    ExpressionVariable::Body,
    ExpressionVariable::BodyText,
    ExpressionVariable::BodyHtml,
    ExpressionVariable::BodyWords,
    ExpressionVariable::BodyRaw,
    ExpressionVariable::Subject,
    ExpressionVariable::SubjectThread,
    ExpressionVariable::SubjectWords,
    ExpressionVariable::Location,
    ExpressionVariable::SpamProbability,
];

pub static SPAM_HEADER_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Name,
    ExpressionVariable::NameLower,
    ExpressionVariable::Value,
    ExpressionVariable::ValueLower,
    ExpressionVariable::Attributes,
    ExpressionVariable::Raw,
    ExpressionVariable::RawLower,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemoteIpPtr,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
    ExpressionVariable::IsTls,
    ExpressionVariable::EnvFrom,
    ExpressionVariable::EnvFromLocal,
    ExpressionVariable::EnvFromDomain,
    ExpressionVariable::EnvTo,
    ExpressionVariable::From,
    ExpressionVariable::FromName,
    ExpressionVariable::FromLocal,
    ExpressionVariable::FromDomain,
    ExpressionVariable::ReplyTo,
    ExpressionVariable::ReplyToName,
    ExpressionVariable::ReplyToLocal,
    ExpressionVariable::ReplyToDomain,
    ExpressionVariable::To,
    ExpressionVariable::ToName,
    ExpressionVariable::ToLocal,
    ExpressionVariable::ToDomain,
    ExpressionVariable::Cc,
    ExpressionVariable::CcName,
    ExpressionVariable::CcLocal,
    ExpressionVariable::CcDomain,
    ExpressionVariable::Bcc,
    ExpressionVariable::BccName,
    ExpressionVariable::BccLocal,
    ExpressionVariable::BccDomain,
    ExpressionVariable::Body,
    ExpressionVariable::BodyText,
    ExpressionVariable::BodyHtml,
    ExpressionVariable::BodyWords,
    ExpressionVariable::BodyRaw,
    ExpressionVariable::Subject,
    ExpressionVariable::SubjectThread,
    ExpressionVariable::SubjectWords,
    ExpressionVariable::Location,
    ExpressionVariable::SpamProbability,
];

pub static SPAM_IP_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Ip,
    ExpressionVariable::Value,
    ExpressionVariable::IpReverse,
    ExpressionVariable::Octets,
    ExpressionVariable::IsV4,
    ExpressionVariable::IsV6,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemoteIpPtr,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
    ExpressionVariable::IsTls,
    ExpressionVariable::EnvFrom,
    ExpressionVariable::EnvFromLocal,
    ExpressionVariable::EnvFromDomain,
    ExpressionVariable::EnvTo,
    ExpressionVariable::From,
    ExpressionVariable::FromName,
    ExpressionVariable::FromLocal,
    ExpressionVariable::FromDomain,
    ExpressionVariable::ReplyTo,
    ExpressionVariable::ReplyToName,
    ExpressionVariable::ReplyToLocal,
    ExpressionVariable::ReplyToDomain,
    ExpressionVariable::To,
    ExpressionVariable::ToName,
    ExpressionVariable::ToLocal,
    ExpressionVariable::ToDomain,
    ExpressionVariable::Cc,
    ExpressionVariable::CcName,
    ExpressionVariable::CcLocal,
    ExpressionVariable::CcDomain,
    ExpressionVariable::Bcc,
    ExpressionVariable::BccName,
    ExpressionVariable::BccLocal,
    ExpressionVariable::BccDomain,
    ExpressionVariable::Body,
    ExpressionVariable::BodyText,
    ExpressionVariable::BodyHtml,
    ExpressionVariable::BodyWords,
    ExpressionVariable::BodyRaw,
    ExpressionVariable::Subject,
    ExpressionVariable::SubjectThread,
    ExpressionVariable::SubjectWords,
    ExpressionVariable::Location,
    ExpressionVariable::SpamProbability,
];

pub static SPAM_URL_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Url,
    ExpressionVariable::UrlOriginal,
    ExpressionVariable::Value,
    ExpressionVariable::PathQuery,
    ExpressionVariable::Path,
    ExpressionVariable::Query,
    ExpressionVariable::Scheme,
    ExpressionVariable::Authority,
    ExpressionVariable::Host,
    ExpressionVariable::Sld,
    ExpressionVariable::Port,
    ExpressionVariable::RemoteIp,
    ExpressionVariable::RemoteIpPtr,
    ExpressionVariable::HeloDomain,
    ExpressionVariable::AuthenticatedAs,
    ExpressionVariable::Asn,
    ExpressionVariable::Country,
    ExpressionVariable::IsTls,
    ExpressionVariable::EnvFrom,
    ExpressionVariable::EnvFromLocal,
    ExpressionVariable::EnvFromDomain,
    ExpressionVariable::EnvTo,
    ExpressionVariable::From,
    ExpressionVariable::FromName,
    ExpressionVariable::FromLocal,
    ExpressionVariable::FromDomain,
    ExpressionVariable::ReplyTo,
    ExpressionVariable::ReplyToName,
    ExpressionVariable::ReplyToLocal,
    ExpressionVariable::ReplyToDomain,
    ExpressionVariable::To,
    ExpressionVariable::ToName,
    ExpressionVariable::ToLocal,
    ExpressionVariable::ToDomain,
    ExpressionVariable::Cc,
    ExpressionVariable::CcName,
    ExpressionVariable::CcLocal,
    ExpressionVariable::CcDomain,
    ExpressionVariable::Bcc,
    ExpressionVariable::BccName,
    ExpressionVariable::BccLocal,
    ExpressionVariable::BccDomain,
    ExpressionVariable::Body,
    ExpressionVariable::BodyText,
    ExpressionVariable::BodyHtml,
    ExpressionVariable::BodyWords,
    ExpressionVariable::BodyRaw,
    ExpressionVariable::Subject,
    ExpressionVariable::SubjectThread,
    ExpressionVariable::SubjectWords,
    ExpressionVariable::Location,
    ExpressionVariable::SpamProbability,
];

pub static ENCRYPTION_MODE_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Disable,
    ExpressionConstant::Opportunistic,
    ExpressionConstant::Required,
];

pub static KEY_TRUST_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Manual,
    ExpressionConstant::Verified,
    ExpressionConstant::Discovered,
    ExpressionConstant::Harvested,
    ExpressionConstant::Unverified,
];

pub static MTA_AGGREGATE_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Hourly,
    ExpressionConstant::Daily,
    ExpressionConstant::Weekly,
    ExpressionConstant::Disable,
];

pub static MTA_AUTH_TYPE_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Login,
    ExpressionConstant::Plain,
    ExpressionConstant::Xoauth2,
    ExpressionConstant::Oauthbearer,
];

pub static MTA_PRIORITY_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Mixer,
    ExpressionConstant::Stanag4406,
    ExpressionConstant::Nsep,
];

pub static MTA_VERIFY_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Relaxed,
    ExpressionConstant::Strict,
    ExpressionConstant::Disable,
];
