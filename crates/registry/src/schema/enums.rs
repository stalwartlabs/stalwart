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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AiModelType {
    #[default]
    Chat = 0,
    Text = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlertEmailType {
    #[default]
    Disabled = 0,
    Enabled = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlertEventType {
    #[default]
    Disabled = 0,
    Enabled = 1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArchivedItemStatus {
    #[default]
    Archived = 0,
    RequestRestore = 1,
}

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
pub enum AzureEnvironment {
    #[default]
    Public = 0,
    China = 1,
    UsGovernment = 2,
}

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BlobStoreType {
    #[default]
    Default = 0,
    Sharded = 1,
    S3 = 2,
    Azure = 3,
    FileSystem = 4,
    FoundationDb = 5,
    PostgreSql = 6,
    MySql = 7,
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
pub enum CertificateManagementType {
    #[default]
    Manual = 0,
    Automatic = 1,
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
    Donotmodify = 0,
    Donotexplode = 1,
    Feedback = 2,
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
    Deprecated1 = 2,
    Cloudflare = 3,
    DigitalOcean = 4,
    DeSEC = 5,
    Ovh = 6,
    Bunny = 7,
    Porkbun = 8,
    Dnsimple = 9,
    Spaceship = 10,
    Route53 = 11,
    GoogleCloudDns = 12,
    Alidns = 13,
    ArvanCloud = 14,
    Autodns = 15,
    AzureDns = 16,
    BaiduCloud = 17,
    BluecatV2 = 18,
    ClouDns = 19,
    Constellix = 20,
    Cpanel = 21,
    Ddnss = 22,
    DnsMadeEasy = 23,
    Domeneshop = 24,
    Dreamhost = 25,
    DuckDns = 26,
    Dynu = 27,
    EasyDns = 28,
    EdgeDns = 29,
    Exoscale = 30,
    FreeMyIp = 31,
    GandiV5 = 32,
    Gcore = 33,
    Glesys = 34,
    Godaddy = 35,
    Hetzner = 36,
    HostingDe = 37,
    Hostinger = 38,
    HuaweiCloud = 39,
    Hurricane = 40,
    IbmCloud = 41,
    Infoblox = 42,
    Infomaniak = 43,
    Inwx = 44,
    Ionos = 45,
    Ipv64 = 46,
    Joker = 47,
    Lightsail = 48,
    Linode = 49,
    LuaDns = 50,
    MythicBeasts = 51,
    Namecheap = 52,
    NameDotCom = 53,
    NameSilo = 54,
    Netcup = 55,
    Netlify = 56,
    Nifcloud = 57,
    Ns1 = 58,
    OracleCloud = 59,
    Plesk = 60,
    Safedns = 61,
    Scaleway = 62,
    TencentCloud = 63,
    Transip = 64,
    UltraDns = 65,
    Vercel = 66,
    Volcengine = 67,
    Vultr = 68,
    WebSupport = 69,
    YandexCloud = 70,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsServerType {
    #[default]
    Tsig = 0,
    Deprecated1 = 1,
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EncryptionAtRestType {
    #[default]
    Disabled = 0,
    Aes128 = 1,
    Aes256 = 2,
    Aes256Gcm = 3,
    ChaCha20Poly1305 = 4,
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
    Optional = 3,
    Require = 4,
    Ipv4Only = 5,
    Ipv6Only = 6,
    Ipv6ThenIpv4 = 7,
    Ipv4ThenIpv6 = 8,
    Hourly = 9,
    Daily = 10,
    Weekly = 11,
    Login = 12,
    Plain = 13,
    Xoauth2 = 14,
    Oauthbearer = 15,
    Mixer = 16,
    Stanag4406 = 17,
    Nsep = 18,
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
    ReverseIp = 74,
    Scheme = 75,
    Sender = 76,
    SenderDomain = 77,
    Size = 78,
    Sld = 79,
    Source = 80,
    Subject = 81,
    SubjectThread = 82,
    SubjectWords = 83,
    To = 84,
    ToDomain = 85,
    ToLocal = 86,
    ToName = 87,
    Url = 88,
    Value = 89,
    ValueLower = 90,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum InMemoryStoreBaseType {
    #[default]
    Redis = 0,
    RedisCluster = 1,
    RedisSentinel = 2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum InMemoryStoreType {
    #[default]
    Default = 0,
    Sharded = 1,
    Redis = 2,
    RedisCluster = 3,
    RedisSentinel = 4,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IndexDocumentType {
    #[default]
    Email = 0,
    Calendar = 1,
    Contacts = 2,
    File = 3,
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
pub enum Locale {
    #[default]
    POSIX = 0,
    AaDJ = 1,
    AaER = 2,
    AaERSaaho = 3,
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
    BeBYLatin = 36,
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
    BrFREuro = 50,
    BrxIN = 51,
    BsBA = 52,
    BynER = 53,
    CaAD = 54,
    CaES = 55,
    CaESEuro = 56,
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
    DeATEuro = 70,
    DeBE = 71,
    DeBEEuro = 72,
    DeCH = 73,
    DeDE = 74,
    DeDEEuro = 75,
    DeIT = 76,
    DeLI = 77,
    DeLU = 78,
    DeLUEuro = 79,
    DoiIN = 80,
    DsbDE = 81,
    DvMV = 82,
    DzBT = 83,
    ElCY = 84,
    ElGR = 85,
    ElGREuro = 86,
    EnAG = 87,
    EnAU = 88,
    EnBW = 89,
    EnCA = 90,
    EnDK = 91,
    EnGB = 92,
    EnHK = 93,
    EnIE = 94,
    EnIEEuro = 95,
    EnIL = 96,
    EnIN = 97,
    EnNG = 98,
    EnNZ = 99,
    EnPH = 100,
    EnSC = 101,
    EnSG = 102,
    EnUS = 103,
    EnZA = 104,
    EnZM = 105,
    EnZW = 106,
    Eo = 107,
    EsAR = 108,
    EsBO = 109,
    EsCL = 110,
    EsCO = 111,
    EsCR = 112,
    EsCU = 113,
    EsDO = 114,
    EsEC = 115,
    EsES = 116,
    EsESEuro = 117,
    EsGT = 118,
    EsHN = 119,
    EsMX = 120,
    EsNI = 121,
    EsPA = 122,
    EsPE = 123,
    EsPR = 124,
    EsPY = 125,
    EsSV = 126,
    EsUS = 127,
    EsUY = 128,
    EsVE = 129,
    EtEE = 130,
    EuES = 131,
    EuESEuro = 132,
    FaIR = 133,
    FfSN = 134,
    FiFI = 135,
    FiFIEuro = 136,
    FilPH = 137,
    FoFO = 138,
    FrBE = 139,
    FrBEEuro = 140,
    FrCA = 141,
    FrCH = 142,
    FrFR = 143,
    FrFREuro = 144,
    FrLU = 145,
    FrLUEuro = 146,
    FurIT = 147,
    FyDE = 148,
    FyNL = 149,
    GaIE = 150,
    GaIEEuro = 151,
    GdGB = 152,
    GezER = 153,
    GezERAbegede = 154,
    GezET = 155,
    GezETAbegede = 156,
    GlES = 157,
    GlESEuro = 158,
    GuIN = 159,
    GvGB = 160,
    HaNG = 161,
    HakTW = 162,
    HeIL = 163,
    HiIN = 164,
    HifFJ = 165,
    HneIN = 166,
    HrHR = 167,
    HsbDE = 168,
    HtHT = 169,
    HuHU = 170,
    HyAM = 171,
    IaFR = 172,
    IdID = 173,
    IgNG = 174,
    IkCA = 175,
    IsIS = 176,
    ItCH = 177,
    ItIT = 178,
    ItITEuro = 179,
    IuCA = 180,
    JaJP = 181,
    KaGE = 182,
    KabDZ = 183,
    KkKZ = 184,
    KlGL = 185,
    KmKH = 186,
    KnIN = 187,
    KoKR = 188,
    KokIN = 189,
    KsIN = 190,
    KsINDevanagari = 191,
    KuTR = 192,
    KwGB = 193,
    KyKG = 194,
    LbLU = 195,
    LgUG = 196,
    LiBE = 197,
    LiNL = 198,
    LijIT = 199,
    LnCD = 200,
    LoLA = 201,
    LtLT = 202,
    LvLV = 203,
    LzhTW = 204,
    MagIN = 205,
    MaiIN = 206,
    MaiNP = 207,
    MfeMU = 208,
    MgMG = 209,
    MhrRU = 210,
    MiNZ = 211,
    MiqNI = 212,
    MjwIN = 213,
    MkMK = 214,
    MlIN = 215,
    MnMN = 216,
    MniIN = 217,
    MnwMM = 218,
    MrIN = 219,
    MsMY = 220,
    MtMT = 221,
    MyMM = 222,
    NanTW = 223,
    NanTWLatin = 224,
    NbNO = 225,
    NdsDE = 226,
    NdsNL = 227,
    NeNP = 228,
    NhnMX = 229,
    NiuNU = 230,
    NiuNZ = 231,
    NlAW = 232,
    NlBE = 233,
    NlBEEuro = 234,
    NlNL = 235,
    NlNLEuro = 236,
    NnNO = 237,
    NrZA = 238,
    NsoZA = 239,
    OcFR = 240,
    OmET = 241,
    OmKE = 242,
    OrIN = 243,
    OsRU = 244,
    PaIN = 245,
    PaPK = 246,
    PapAW = 247,
    PapCW = 248,
    PlPL = 249,
    PsAF = 250,
    PtBR = 251,
    PtPT = 252,
    PtPTEuro = 253,
    QuzPE = 254,
    RajIN = 255,
    RoRO = 256,
    RuRU = 257,
    RuUA = 258,
    RwRW = 259,
    SaIN = 260,
    SahRU = 261,
    SatIN = 262,
    ScIT = 263,
    SdIN = 264,
    SdINDevanagari = 265,
    SeNO = 266,
    SgsLT = 267,
    ShnMM = 268,
    ShsCA = 269,
    SiLK = 270,
    SidET = 271,
    SkSK = 272,
    SlSI = 273,
    SmWS = 274,
    SoDJ = 275,
    SoET = 276,
    SoKE = 277,
    SoSO = 278,
    SqAL = 279,
    SqMK = 280,
    SrME = 281,
    SrRS = 282,
    SrRSLatin = 283,
    SsZA = 284,
    StZA = 285,
    SvFI = 286,
    SvFIEuro = 287,
    SvSE = 288,
    SwKE = 289,
    SwTZ = 290,
    SzlPL = 291,
    TaIN = 292,
    TaLK = 293,
    TcyIN = 294,
    TeIN = 295,
    TgTJ = 296,
    ThTH = 297,
    TheNP = 298,
    TiER = 299,
    TiET = 300,
    TigER = 301,
    TkTM = 302,
    TlPH = 303,
    TnZA = 304,
    ToTO = 305,
    TpiPG = 306,
    TrCY = 307,
    TrTR = 308,
    TsZA = 309,
    TtRU = 310,
    TtRUIqtelif = 311,
    UgCN = 312,
    UkUA = 313,
    UnmUS = 314,
    UrIN = 315,
    UrPK = 316,
    UzUZ = 317,
    UzUZCyrillic = 318,
    VeZA = 319,
    ViVN = 320,
    WaBE = 321,
    WaBEEuro = 322,
    WaeCH = 323,
    WalET = 324,
    WoSN = 325,
    XhZA = 326,
    YiUS = 327,
    YoNG = 328,
    YueHK = 329,
    YuwPG = 330,
    ZhCN = 331,
    ZhHK = 332,
    ZhSG = 333,
    ZhTW = 334,
    ZuZA = 335,
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
    Sharded = 3,
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
pub enum MetricType {
    #[default]
    Counter = 0,
    Gauge = 1,
    Histogram = 2,
}

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
    InteractAi = 2,
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
    JmapPrincipalCreate = 63,
    JmapPrincipalUpdate = 64,
    JmapPrincipalDestroy = 65,
    JmapQuotaGet = 66,
    JmapQuotaChanges = 67,
    JmapQuotaQuery = 68,
    JmapQuotaQueryChanges = 69,
    JmapBlobGet = 70,
    JmapBlobCopy = 71,
    JmapBlobLookup = 72,
    JmapBlobUpload = 73,
    JmapAddressBookGet = 74,
    JmapAddressBookChanges = 75,
    JmapAddressBookCreate = 76,
    JmapAddressBookUpdate = 77,
    JmapAddressBookDestroy = 78,
    JmapContactCardGet = 79,
    JmapContactCardChanges = 80,
    JmapContactCardQuery = 81,
    JmapContactCardQueryChanges = 82,
    JmapContactCardCreate = 83,
    JmapContactCardUpdate = 84,
    JmapContactCardDestroy = 85,
    JmapContactCardCopy = 86,
    JmapContactCardParse = 87,
    JmapFileNodeGet = 88,
    JmapFileNodeChanges = 89,
    JmapFileNodeQuery = 90,
    JmapFileNodeQueryChanges = 91,
    JmapFileNodeCreate = 92,
    JmapFileNodeUpdate = 93,
    JmapFileNodeDestroy = 94,
    JmapFileNodeCopy = 659,
    JmapShareNotificationGet = 95,
    JmapShareNotificationChanges = 96,
    JmapShareNotificationQuery = 97,
    JmapShareNotificationQueryChanges = 98,
    JmapShareNotificationCreate = 99,
    JmapShareNotificationUpdate = 100,
    JmapShareNotificationDestroy = 101,
    JmapCalendarGet = 102,
    JmapCalendarChanges = 103,
    JmapCalendarCreate = 104,
    JmapCalendarUpdate = 105,
    JmapCalendarDestroy = 106,
    JmapCalendarEventGet = 107,
    JmapCalendarEventChanges = 108,
    JmapCalendarEventQuery = 109,
    JmapCalendarEventQueryChanges = 110,
    JmapCalendarEventCreate = 111,
    JmapCalendarEventUpdate = 112,
    JmapCalendarEventDestroy = 113,
    JmapCalendarEventCopy = 114,
    JmapCalendarEventParse = 115,
    JmapCalendarEventNotificationGet = 116,
    JmapCalendarEventNotificationChanges = 117,
    JmapCalendarEventNotificationQuery = 118,
    JmapCalendarEventNotificationQueryChanges = 119,
    JmapCalendarEventNotificationCreate = 120,
    JmapCalendarEventNotificationUpdate = 121,
    JmapCalendarEventNotificationDestroy = 122,
    JmapParticipantIdentityGet = 123,
    JmapParticipantIdentityChanges = 124,
    JmapParticipantIdentityCreate = 125,
    JmapParticipantIdentityUpdate = 126,
    JmapParticipantIdentityDestroy = 127,
    JmapCoreEcho = 128,
    ImapAuthenticate = 129,
    ImapAclGet = 130,
    ImapAclSet = 131,
    ImapMyRights = 132,
    ImapListRights = 133,
    ImapAppend = 134,
    ImapCapability = 135,
    ImapId = 136,
    ImapCopy = 137,
    ImapMove = 138,
    ImapCreate = 139,
    ImapDelete = 140,
    ImapEnable = 141,
    ImapExpunge = 142,
    ImapFetch = 143,
    ImapIdle = 144,
    ImapList = 145,
    ImapLsub = 146,
    ImapNamespace = 147,
    ImapRename = 148,
    ImapSearch = 149,
    ImapSort = 150,
    ImapSelect = 151,
    ImapExamine = 152,
    ImapStatus = 153,
    ImapStore = 154,
    ImapSubscribe = 155,
    ImapThread = 156,
    Pop3Authenticate = 157,
    Pop3List = 158,
    Pop3Uidl = 159,
    Pop3Stat = 160,
    Pop3Retr = 161,
    Pop3Dele = 162,
    SieveAuthenticate = 163,
    SieveListScripts = 164,
    SieveSetActive = 165,
    SieveGetScript = 166,
    SievePutScript = 167,
    SieveDeleteScript = 168,
    SieveRenameScript = 169,
    SieveCheckScript = 170,
    SieveHaveSpace = 171,
    DavSyncCollection = 172,
    DavExpandProperty = 173,
    DavPrincipalAcl = 174,
    DavPrincipalList = 175,
    DavPrincipalMatch = 176,
    DavPrincipalSearch = 177,
    DavPrincipalSearchPropSet = 178,
    DavFilePropFind = 179,
    DavFilePropPatch = 180,
    DavFileGet = 181,
    DavFileMkCol = 182,
    DavFileDelete = 183,
    DavFilePut = 184,
    DavFileCopy = 185,
    DavFileMove = 186,
    DavFileLock = 187,
    DavFileAcl = 188,
    DavCardPropFind = 189,
    DavCardPropPatch = 190,
    DavCardGet = 191,
    DavCardMkCol = 192,
    DavCardDelete = 193,
    DavCardPut = 194,
    DavCardCopy = 195,
    DavCardMove = 196,
    DavCardLock = 197,
    DavCardAcl = 198,
    DavCardQuery = 199,
    DavCardMultiGet = 200,
    DavCalPropFind = 201,
    DavCalPropPatch = 202,
    DavCalGet = 203,
    DavCalMkCol = 204,
    DavCalDelete = 205,
    DavCalPut = 206,
    DavCalCopy = 207,
    DavCalMove = 208,
    DavCalLock = 209,
    DavCalAcl = 210,
    DavCalQuery = 211,
    DavCalMultiGet = 212,
    DavCalFreeBusyQuery = 213,
    OAuthClientRegistration = 214,
    OAuthClientOverride = 215,
    LiveTracing = 216,
    LiveMetrics = 217,
    LiveDeliveryTest = 218,
    SysAccountGet = 219,
    SysAccountCreate = 220,
    SysAccountUpdate = 221,
    SysAccountDestroy = 222,
    SysAccountQuery = 223,
    SysAccountPasswordGet = 224,
    SysAccountPasswordUpdate = 225,
    SysAccountSettingsGet = 226,
    SysAccountSettingsUpdate = 227,
    SysAcmeProviderGet = 228,
    SysAcmeProviderCreate = 229,
    SysAcmeProviderUpdate = 230,
    SysAcmeProviderDestroy = 231,
    SysAcmeProviderQuery = 232,
    ActionReloadSettings = 233,
    ActionReloadTlsCertificates = 234,
    ActionReloadLookupStores = 235,
    ActionReloadBlockedIps = 236,
    ActionUpdateApps = 237,
    ActionTroubleshootDmarc = 238,
    ActionClassifySpam = 239,
    ActionInvalidateCaches = 240,
    ActionInvalidateNegativeCaches = 241,
    ActionPauseMtaQueue = 242,
    ActionResumeMtaQueue = 243,
    SysActionGet = 244,
    SysActionCreate = 245,
    SysActionUpdate = 246,
    SysActionDestroy = 247,
    SysActionQuery = 248,
    SysAddressBookGet = 249,
    SysAddressBookUpdate = 250,
    SysAiModelGet = 251,
    SysAiModelCreate = 252,
    SysAiModelUpdate = 253,
    SysAiModelDestroy = 254,
    SysAiModelQuery = 255,
    SysAlertGet = 256,
    SysAlertCreate = 257,
    SysAlertUpdate = 258,
    SysAlertDestroy = 259,
    SysAlertQuery = 260,
    SysAllowedIpGet = 261,
    SysAllowedIpCreate = 262,
    SysAllowedIpUpdate = 263,
    SysAllowedIpDestroy = 264,
    SysAllowedIpQuery = 265,
    SysApiKeyGet = 266,
    SysApiKeyCreate = 267,
    SysApiKeyUpdate = 268,
    SysApiKeyDestroy = 269,
    SysApiKeyQuery = 270,
    SysAppPasswordGet = 271,
    SysAppPasswordCreate = 272,
    SysAppPasswordUpdate = 273,
    SysAppPasswordDestroy = 274,
    SysAppPasswordQuery = 275,
    SysApplicationGet = 276,
    SysApplicationCreate = 277,
    SysApplicationUpdate = 278,
    SysApplicationDestroy = 279,
    SysApplicationQuery = 280,
    SysArchivedItemGet = 281,
    SysArchivedItemCreate = 282,
    SysArchivedItemUpdate = 283,
    SysArchivedItemDestroy = 284,
    SysArchivedItemQuery = 285,
    SysArfExternalReportGet = 286,
    SysArfExternalReportCreate = 287,
    SysArfExternalReportUpdate = 288,
    SysArfExternalReportDestroy = 289,
    SysArfExternalReportQuery = 290,
    SysAsnGet = 291,
    SysAsnUpdate = 292,
    SysAuthenticationGet = 293,
    SysAuthenticationUpdate = 294,
    SysBlobStoreGet = 295,
    SysBlobStoreUpdate = 296,
    SysBlockedIpGet = 297,
    SysBlockedIpCreate = 298,
    SysBlockedIpUpdate = 299,
    SysBlockedIpDestroy = 300,
    SysBlockedIpQuery = 301,
    SysBootstrapGet = 302,
    SysBootstrapUpdate = 303,
    SysCacheGet = 304,
    SysCacheUpdate = 305,
    SysCalendarGet = 306,
    SysCalendarUpdate = 307,
    SysCalendarAlarmGet = 308,
    SysCalendarAlarmUpdate = 309,
    SysCalendarSchedulingGet = 310,
    SysCalendarSchedulingUpdate = 311,
    SysCertificateGet = 312,
    SysCertificateCreate = 313,
    SysCertificateUpdate = 314,
    SysCertificateDestroy = 315,
    SysCertificateQuery = 316,
    SysClusterNodeGet = 317,
    SysClusterNodeCreate = 318,
    SysClusterNodeUpdate = 319,
    SysClusterNodeDestroy = 320,
    SysClusterNodeQuery = 321,
    SysClusterRoleGet = 322,
    SysClusterRoleCreate = 323,
    SysClusterRoleUpdate = 324,
    SysClusterRoleDestroy = 325,
    SysClusterRoleQuery = 326,
    SysCoordinatorGet = 327,
    SysCoordinatorUpdate = 328,
    SysDataRetentionGet = 329,
    SysDataRetentionUpdate = 330,
    SysDataStoreGet = 331,
    SysDataStoreUpdate = 332,
    SysDirectoryGet = 333,
    SysDirectoryCreate = 334,
    SysDirectoryUpdate = 335,
    SysDirectoryDestroy = 336,
    SysDirectoryQuery = 337,
    SysDkimReportSettingsGet = 338,
    SysDkimReportSettingsUpdate = 339,
    SysDkimSignatureGet = 340,
    SysDkimSignatureCreate = 341,
    SysDkimSignatureUpdate = 342,
    SysDkimSignatureDestroy = 343,
    SysDkimSignatureQuery = 344,
    SysDmarcExternalReportGet = 345,
    SysDmarcExternalReportCreate = 346,
    SysDmarcExternalReportUpdate = 347,
    SysDmarcExternalReportDestroy = 348,
    SysDmarcExternalReportQuery = 349,
    SysDmarcInternalReportGet = 350,
    SysDmarcInternalReportCreate = 351,
    SysDmarcInternalReportUpdate = 352,
    SysDmarcInternalReportDestroy = 353,
    SysDmarcInternalReportQuery = 354,
    SysDmarcReportSettingsGet = 355,
    SysDmarcReportSettingsUpdate = 356,
    SysDnsResolverGet = 357,
    SysDnsResolverUpdate = 358,
    SysDnsServerGet = 359,
    SysDnsServerCreate = 360,
    SysDnsServerUpdate = 361,
    SysDnsServerDestroy = 362,
    SysDnsServerQuery = 363,
    SysDomainGet = 364,
    SysDomainCreate = 365,
    SysDomainUpdate = 366,
    SysDomainDestroy = 367,
    SysDomainQuery = 368,
    SysDsnReportSettingsGet = 369,
    SysDsnReportSettingsUpdate = 370,
    SysEmailGet = 371,
    SysEmailUpdate = 372,
    SysEnterpriseGet = 373,
    SysEnterpriseUpdate = 374,
    SysEventTracingLevelGet = 375,
    SysEventTracingLevelCreate = 376,
    SysEventTracingLevelUpdate = 377,
    SysEventTracingLevelDestroy = 378,
    SysEventTracingLevelQuery = 379,
    SysFileStorageGet = 380,
    SysFileStorageUpdate = 381,
    SysHttpGet = 382,
    SysHttpUpdate = 383,
    SysHttpFormGet = 384,
    SysHttpFormUpdate = 385,
    SysHttpLookupGet = 386,
    SysHttpLookupCreate = 387,
    SysHttpLookupUpdate = 388,
    SysHttpLookupDestroy = 389,
    SysHttpLookupQuery = 390,
    SysImapGet = 391,
    SysImapUpdate = 392,
    SysInMemoryStoreGet = 393,
    SysInMemoryStoreUpdate = 394,
    SysJmapGet = 395,
    SysJmapUpdate = 396,
    SysLogGet = 397,
    SysLogCreate = 398,
    SysLogUpdate = 399,
    SysLogDestroy = 400,
    SysLogQuery = 401,
    SysMailingListGet = 402,
    SysMailingListCreate = 403,
    SysMailingListUpdate = 404,
    SysMailingListDestroy = 405,
    SysMailingListQuery = 406,
    SysMaskedEmailGet = 407,
    SysMaskedEmailCreate = 408,
    SysMaskedEmailUpdate = 409,
    SysMaskedEmailDestroy = 410,
    SysMaskedEmailQuery = 411,
    SysMemoryLookupKeyGet = 412,
    SysMemoryLookupKeyCreate = 413,
    SysMemoryLookupKeyUpdate = 414,
    SysMemoryLookupKeyDestroy = 415,
    SysMemoryLookupKeyQuery = 416,
    SysMemoryLookupKeyValueGet = 417,
    SysMemoryLookupKeyValueCreate = 418,
    SysMemoryLookupKeyValueUpdate = 419,
    SysMemoryLookupKeyValueDestroy = 420,
    SysMemoryLookupKeyValueQuery = 421,
    SysMetricGet = 422,
    SysMetricCreate = 423,
    SysMetricUpdate = 424,
    SysMetricDestroy = 425,
    SysMetricQuery = 426,
    SysMetricsGet = 427,
    SysMetricsUpdate = 428,
    SysMetricsStoreGet = 429,
    SysMetricsStoreUpdate = 430,
    SysMtaConnectionStrategyGet = 431,
    SysMtaConnectionStrategyCreate = 432,
    SysMtaConnectionStrategyUpdate = 433,
    SysMtaConnectionStrategyDestroy = 434,
    SysMtaConnectionStrategyQuery = 435,
    SysMtaDeliveryScheduleGet = 436,
    SysMtaDeliveryScheduleCreate = 437,
    SysMtaDeliveryScheduleUpdate = 438,
    SysMtaDeliveryScheduleDestroy = 439,
    SysMtaDeliveryScheduleQuery = 440,
    SysMtaExtensionsGet = 441,
    SysMtaExtensionsUpdate = 442,
    SysMtaHookGet = 443,
    SysMtaHookCreate = 444,
    SysMtaHookUpdate = 445,
    SysMtaHookDestroy = 446,
    SysMtaHookQuery = 447,
    SysMtaInboundSessionGet = 448,
    SysMtaInboundSessionUpdate = 449,
    SysMtaInboundThrottleGet = 450,
    SysMtaInboundThrottleCreate = 451,
    SysMtaInboundThrottleUpdate = 452,
    SysMtaInboundThrottleDestroy = 453,
    SysMtaInboundThrottleQuery = 454,
    SysMtaMilterGet = 455,
    SysMtaMilterCreate = 456,
    SysMtaMilterUpdate = 457,
    SysMtaMilterDestroy = 458,
    SysMtaMilterQuery = 459,
    SysMtaOutboundStrategyGet = 460,
    SysMtaOutboundStrategyUpdate = 461,
    SysMtaOutboundThrottleGet = 462,
    SysMtaOutboundThrottleCreate = 463,
    SysMtaOutboundThrottleUpdate = 464,
    SysMtaOutboundThrottleDestroy = 465,
    SysMtaOutboundThrottleQuery = 466,
    SysMtaQueueQuotaGet = 467,
    SysMtaQueueQuotaCreate = 468,
    SysMtaQueueQuotaUpdate = 469,
    SysMtaQueueQuotaDestroy = 470,
    SysMtaQueueQuotaQuery = 471,
    SysMtaRouteGet = 472,
    SysMtaRouteCreate = 473,
    SysMtaRouteUpdate = 474,
    SysMtaRouteDestroy = 475,
    SysMtaRouteQuery = 476,
    SysMtaStageAuthGet = 477,
    SysMtaStageAuthUpdate = 478,
    SysMtaStageConnectGet = 479,
    SysMtaStageConnectUpdate = 480,
    SysMtaStageDataGet = 481,
    SysMtaStageDataUpdate = 482,
    SysMtaStageEhloGet = 483,
    SysMtaStageEhloUpdate = 484,
    SysMtaStageMailGet = 485,
    SysMtaStageMailUpdate = 486,
    SysMtaStageRcptGet = 487,
    SysMtaStageRcptUpdate = 488,
    SysMtaStsGet = 489,
    SysMtaStsUpdate = 490,
    SysMtaTlsStrategyGet = 491,
    SysMtaTlsStrategyCreate = 492,
    SysMtaTlsStrategyUpdate = 493,
    SysMtaTlsStrategyDestroy = 494,
    SysMtaTlsStrategyQuery = 495,
    SysMtaVirtualQueueGet = 496,
    SysMtaVirtualQueueCreate = 497,
    SysMtaVirtualQueueUpdate = 498,
    SysMtaVirtualQueueDestroy = 499,
    SysMtaVirtualQueueQuery = 500,
    SysNetworkListenerGet = 501,
    SysNetworkListenerCreate = 502,
    SysNetworkListenerUpdate = 503,
    SysNetworkListenerDestroy = 504,
    SysNetworkListenerQuery = 505,
    SysOAuthClientGet = 506,
    SysOAuthClientCreate = 507,
    SysOAuthClientUpdate = 508,
    SysOAuthClientDestroy = 509,
    SysOAuthClientQuery = 510,
    SysOidcProviderGet = 511,
    SysOidcProviderUpdate = 512,
    SysPublicKeyGet = 513,
    SysPublicKeyCreate = 514,
    SysPublicKeyUpdate = 515,
    SysPublicKeyDestroy = 516,
    SysPublicKeyQuery = 517,
    SysQueuedMessageGet = 518,
    SysQueuedMessageCreate = 519,
    SysQueuedMessageUpdate = 520,
    SysQueuedMessageDestroy = 521,
    SysQueuedMessageQuery = 522,
    SysReportSettingsGet = 523,
    SysReportSettingsUpdate = 524,
    SysRoleGet = 525,
    SysRoleCreate = 526,
    SysRoleUpdate = 527,
    SysRoleDestroy = 528,
    SysRoleQuery = 529,
    SysSearchGet = 530,
    SysSearchUpdate = 531,
    SysSearchStoreGet = 532,
    SysSearchStoreUpdate = 533,
    SysSecurityGet = 534,
    SysSecurityUpdate = 535,
    SysSenderAuthGet = 536,
    SysSenderAuthUpdate = 537,
    SysSharingGet = 538,
    SysSharingUpdate = 539,
    SysSieveSystemInterpreterGet = 540,
    SysSieveSystemInterpreterUpdate = 541,
    SysSieveSystemScriptGet = 542,
    SysSieveSystemScriptCreate = 543,
    SysSieveSystemScriptUpdate = 544,
    SysSieveSystemScriptDestroy = 545,
    SysSieveSystemScriptQuery = 546,
    SysSieveUserInterpreterGet = 547,
    SysSieveUserInterpreterUpdate = 548,
    SysSieveUserScriptGet = 549,
    SysSieveUserScriptCreate = 550,
    SysSieveUserScriptUpdate = 551,
    SysSieveUserScriptDestroy = 552,
    SysSieveUserScriptQuery = 553,
    SysSpamClassifierGet = 554,
    SysSpamClassifierUpdate = 555,
    SysSpamDnsblServerGet = 556,
    SysSpamDnsblServerCreate = 557,
    SysSpamDnsblServerUpdate = 558,
    SysSpamDnsblServerDestroy = 559,
    SysSpamDnsblServerQuery = 560,
    SysSpamDnsblSettingsGet = 561,
    SysSpamDnsblSettingsUpdate = 562,
    SysSpamFileExtensionGet = 563,
    SysSpamFileExtensionCreate = 564,
    SysSpamFileExtensionUpdate = 565,
    SysSpamFileExtensionDestroy = 566,
    SysSpamFileExtensionQuery = 567,
    SysSpamLlmGet = 568,
    SysSpamLlmUpdate = 569,
    SysSpamPyzorGet = 570,
    SysSpamPyzorUpdate = 571,
    SysSpamRuleGet = 572,
    SysSpamRuleCreate = 573,
    SysSpamRuleUpdate = 574,
    SysSpamRuleDestroy = 575,
    SysSpamRuleQuery = 576,
    SysSpamSettingsGet = 577,
    SysSpamSettingsUpdate = 578,
    SysSpamTagGet = 579,
    SysSpamTagCreate = 580,
    SysSpamTagUpdate = 581,
    SysSpamTagDestroy = 582,
    SysSpamTagQuery = 583,
    SysSpamTrainingSampleGet = 584,
    SysSpamTrainingSampleCreate = 585,
    SysSpamTrainingSampleUpdate = 586,
    SysSpamTrainingSampleDestroy = 587,
    SysSpamTrainingSampleQuery = 588,
    SysSpfReportSettingsGet = 589,
    SysSpfReportSettingsUpdate = 590,
    SysStoreLookupGet = 591,
    SysStoreLookupCreate = 592,
    SysStoreLookupUpdate = 593,
    SysStoreLookupDestroy = 594,
    SysStoreLookupQuery = 595,
    SysSystemSettingsGet = 596,
    SysSystemSettingsUpdate = 597,
    TaskIndexDocument = 598,
    TaskUnindexDocument = 599,
    TaskIndexTrace = 600,
    TaskCalendarAlarmEmail = 601,
    TaskCalendarAlarmNotification = 602,
    TaskCalendarItipMessage = 603,
    TaskMergeThreads = 604,
    TaskDmarcReport = 605,
    TaskTlsReport = 606,
    TaskRestoreArchivedItem = 607,
    TaskDestroyAccount = 608,
    TaskAccountMaintenance = 609,
    TaskTenantMaintenance = 610,
    TaskStoreMaintenance = 611,
    TaskSpamFilterMaintenance = 612,
    TaskAcmeRenewal = 613,
    TaskDkimManagement = 614,
    TaskDnsManagement = 615,
    SysTaskGet = 616,
    SysTaskCreate = 617,
    SysTaskUpdate = 618,
    SysTaskDestroy = 619,
    SysTaskQuery = 620,
    SysTaskManagerGet = 621,
    SysTaskManagerUpdate = 622,
    SysTenantGet = 623,
    SysTenantCreate = 624,
    SysTenantUpdate = 625,
    SysTenantDestroy = 626,
    SysTenantQuery = 627,
    SysTlsExternalReportGet = 628,
    SysTlsExternalReportCreate = 629,
    SysTlsExternalReportUpdate = 630,
    SysTlsExternalReportDestroy = 631,
    SysTlsExternalReportQuery = 632,
    SysTlsInternalReportGet = 633,
    SysTlsInternalReportCreate = 634,
    SysTlsInternalReportUpdate = 635,
    SysTlsInternalReportDestroy = 636,
    SysTlsInternalReportQuery = 637,
    SysTlsReportSettingsGet = 638,
    SysTlsReportSettingsUpdate = 639,
    SysTraceGet = 640,
    SysTraceCreate = 641,
    SysTraceUpdate = 642,
    SysTraceDestroy = 643,
    SysTraceQuery = 644,
    SysTracerGet = 645,
    SysTracerCreate = 646,
    SysTracerUpdate = 647,
    SysTracerDestroy = 648,
    SysTracerQuery = 649,
    SysTracingStoreGet = 650,
    SysTracingStoreUpdate = 651,
    SysWebDavGet = 652,
    SysWebDavUpdate = 653,
    SysWebHookGet = 654,
    SysWebHookCreate = 655,
    SysWebHookUpdate = 656,
    SysWebHookDestroy = 657,
    SysWebHookQuery = 658,
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
    Start = 5,
    Uid = 6,
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
    Uid = 10,
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
    ReceivedAt = 7,
    SentAt = 8,
    Size = 9,
    HasAttachment = 10,
    Headers = 11,
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
pub enum SearchTracingField {
    #[default]
    EventType = 0,
    QueueId = 1,
    Keywords = 2,
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
pub enum SpamLlmType {
    #[default]
    Disable = 0,
    Enable = 1,
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
    MaxMaskedAddresses = 14,
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
pub enum TaskAccountMaintenanceType {
    #[default]
    Purge = 0,
    Reindex = 1,
    RecalculateImapUid = 2,
    RecalculateQuota = 3,
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
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskStoreMaintenanceType {
    #[default]
    ReindexAccounts = 0,
    ReindexTelemetry = 1,
    PurgeAccounts = 2,
    PurgeData = 3,
    PurgeBlob = 4,
    ResetRateLimiters = 5,
    ResetUserQuotas = 6,
    ResetTenantQuotas = 7,
    ResetBlobQuotas = 8,
    RemoveAuthTokens = 9,
    RemoveLockQueueMessage = 10,
    RemoveLockTask = 11,
    RemoveLockDav = 12,
    RemoveSieveId = 13,
    RemoveGreylist = 14,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskTenantMaintenanceType {
    #[default]
    RecalculateQuota = 0,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskType {
    #[default]
    IndexDocument = 0,
    UnindexDocument = 1,
    IndexTrace = 2,
    CalendarAlarmEmail = 3,
    CalendarAlarmNotification = 4,
    CalendarItipMessage = 5,
    MergeThreads = 6,
    DmarcReport = 7,
    TlsReport = 8,
    RestoreArchivedItem = 9,
    DestroyAccount = 10,
    AccountMaintenance = 11,
    TenantMaintenance = 12,
    StoreMaintenance = 13,
    SpamFilterMaintenance = 14,
    AcmeRenewal = 15,
    DkimManagement = 16,
    DnsManagement = 17,
}

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
    ExpressionVariable::RetryNum,
    ExpressionVariable::NotifyNum,
    ExpressionVariable::ExpiresIn,
    ExpressionVariable::LastStatus,
    ExpressionVariable::LastError,
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
];

pub static SPAM_IP_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Ip,
    ExpressionVariable::Value,
    ExpressionVariable::ReverseIp,
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
];

pub static SPAM_URL_VARIABLE: &[ExpressionVariable] = &[
    ExpressionVariable::Url,
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

pub static MTA_IP_STRATEGY_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Ipv4Only,
    ExpressionConstant::Ipv6Only,
    ExpressionConstant::Ipv6ThenIpv4,
    ExpressionConstant::Ipv4ThenIpv6,
];

pub static MTA_PRIORITY_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Mixer,
    ExpressionConstant::Stanag4406,
    ExpressionConstant::Nsep,
];

pub static MTA_REQUIRE_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Optional,
    ExpressionConstant::Require,
    ExpressionConstant::Disable,
];

pub static MTA_VERIFY_CONSTANT: &[ExpressionConstant] = &[
    ExpressionConstant::Relaxed,
    ExpressionConstant::Strict,
    ExpressionConstant::Disable,
];
