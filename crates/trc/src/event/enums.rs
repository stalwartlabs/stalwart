/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

pub const TOTAL_EVENT_COUNT: usize = 596;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    Acme(AcmeEvent),
    Ai(AiEvent),
    Arc(ArcEvent),
    Auth(AuthEvent),
    Calendar(CalendarEvent),
    Cluster(ClusterEvent),
    Config(ConfigEvent),
    Dane(DaneEvent),
    Delivery(DeliveryEvent),
    Dkim(DkimEvent),
    Dmarc(DmarcEvent),
    Dns(DnsEvent),
    Eval(EvalEvent),
    Housekeeper(HousekeeperEvent),
    Http(HttpEvent),
    Imap(ImapEvent),
    IncomingReport(IncomingReportEvent),
    Iprev(IprevEvent),
    Jmap(JmapEvent),
    Limit(LimitEvent),
    MailAuth(MailAuthEvent),
    Manage(ManageEvent),
    ManageSieve(ManageSieveEvent),
    MessageIngest(MessageIngestEvent),
    Milter(MilterEvent),
    MtaHook(MtaHookEvent),
    MtaSts(MtaStsEvent),
    Network(NetworkEvent),
    OutgoingReport(OutgoingReportEvent),
    Pop3(Pop3Event),
    Purge(PurgeEvent),
    PushSubscription(PushSubscriptionEvent),
    Queue(QueueEvent),
    Resource(ResourceEvent),
    Security(SecurityEvent),
    Server(ServerEvent),
    Sieve(SieveEvent),
    Smtp(SmtpEvent),
    Spam(SpamEvent),
    Spf(SpfEvent),
    Store(StoreEvent),
    TaskQueue(TaskQueueEvent),
    Telemetry(TelemetryEvent),
    Tls(TlsEvent),
    TlsRpt(TlsRptEvent),
    WebDav(WebDavEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AcmeEvent {
    AuthStart = 3,
    AuthPending = 2,
    AuthValid = 5,
    AuthCompleted = 0,
    AuthError = 1,
    AuthTooManyAttempts = 4,
    ProcessCert = 22,
    OrderStart = 20,
    OrderProcessing = 18,
    OrderCompleted = 16,
    OrderReady = 19,
    OrderValid = 21,
    OrderInvalid = 17,
    RenewBackoff = 23,
    ClientSuppliedSni = 7,
    ClientMissingSni = 6,
    TlsAlpnReceived = 25,
    TlsAlpnError = 24,
    TokenNotFound = 26,
    Error = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AiEvent {
    LlmResponse = 556,
    ApiError = 557,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArcEvent {
    ChainTooLong = 28,
    InvalidInstance = 31,
    InvalidCv = 30,
    HasHeaderTag = 29,
    BrokenChain = 27,
    SealerNotFound = 32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AuthEvent {
    Success = 37,
    Failed = 35,
    TokenExpired = 554,
    MissingTotp = 36,
    TooManyAttempts = 38,
    ClientRegistration = 555,
    Error = 34,
    Warning = 595,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CalendarEvent {
    RuleExpansionError = 576,
    AlarmSent = 579,
    AlarmSkipped = 580,
    AlarmRecipientOverride = 581,
    AlarmFailed = 582,
    ItipMessageSent = 583,
    ItipMessageReceived = 584,
    ItipMessageError = 585,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClusterEvent {
    SubscriberStart = 39,
    SubscriberStop = 40,
    SubscriberError = 41,
    SubscriberDisconnected = 42,
    PublisherStart = 43,
    PublisherStop = 44,
    PublisherError = 45,
    MessageReceived = 46,
    MessageSkipped = 47,
    MessageInvalid = 49,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ConfigEvent {
    ParseError = 62,
    BuildError = 54,
    MacroError = 60,
    WriteError = 65,
    FetchError = 58,
    DefaultApplied = 56,
    MissingSetting = 61,
    UnusedSetting = 64,
    ParseWarning = 63,
    BuildWarning = 55,
    ImportExternal = 59,
    AlreadyUpToDate = 53,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DaneEvent {
    AuthenticationSuccess = 67,
    AuthenticationFailure = 66,
    NoCertificatesFound = 69,
    CertificateParseError = 68,
    TlsaRecordMatch = 73,
    TlsaRecordFetch = 70,
    TlsaRecordFetchError = 71,
    TlsaRecordNotFound = 75,
    TlsaRecordNotDnssecSigned = 74,
    TlsaRecordInvalid = 72,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DeliveryEvent {
    AttemptStart = 77,
    AttemptEnd = 76,
    Completed = 80,
    Failed = 92,
    DomainDeliveryStart = 85,
    MxLookup = 101,
    MxLookupFailed = 102,
    IpLookup = 95,
    IpLookupFailed = 96,
    NullMx = 103,
    Connect = 82,
    ConnectError = 83,
    MissingOutboundHostname = 100,
    GreetingFailed = 93,
    Ehlo = 90,
    EhloRejected = 91,
    Auth = 78,
    AuthFailed = 79,
    MailFrom = 97,
    MailFromRejected = 98,
    Delivered = 84,
    RcptTo = 107,
    RcptToRejected = 109,
    RcptToFailed = 108,
    MessageRejected = 99,
    StartTls = 110,
    StartTlsUnavailable = 113,
    StartTlsError = 112,
    StartTlsDisabled = 111,
    ImplicitTlsError = 94,
    ConcurrencyLimitExceeded = 81,
    RateLimitExceeded = 104,
    DoubleBounce = 86,
    DsnSuccess = 88,
    DsnTempFail = 89,
    DsnPermFail = 87,
    RawInput = 105,
    RawOutput = 106,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimEvent {
    Pass = 121,
    Neutral = 119,
    Fail = 114,
    PermError = 122,
    TempError = 127,
    None = 120,
    UnsupportedVersion = 131,
    UnsupportedAlgorithm = 128,
    UnsupportedCanonicalization = 129,
    UnsupportedKeyType = 130,
    FailedBodyHashMatch = 116,
    FailedVerification = 117,
    FailedAuidMatch = 115,
    RevokedPublicKey = 123,
    IncompatibleAlgorithms = 118,
    SignatureExpired = 124,
    SignatureLength = 125,
    SignerNotFound = 126,
    BuildError = 592,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcEvent {
    Pass = 134,
    Fail = 132,
    PermError = 135,
    TempError = 136,
    None = 133,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsEvent {
    RecordCreated = 8,
    RecordCreationFailed = 9,
    RecordDeletionFailed = 10,
    RecordNotPropagated = 12,
    RecordLookupFailed = 11,
    RecordPropagated = 13,
    RecordPropagationTimeout = 14,
    BuildError = 591,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EvalEvent {
    Result = 139,
    Error = 138,
    DirectoryNotFound = 137,
    StoreNotFound = 140,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HousekeeperEvent {
    Start = 150,
    Stop = 151,
    Schedule = 149,
    Run = 146,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HttpEvent {
    ConnectionStart = 153,
    ConnectionEnd = 152,
    Error = 154,
    RequestUrl = 156,
    RequestBody = 155,
    ResponseBody = 157,
    XForwardedMissing = 158,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ImapEvent {
    ConnectionStart = 163,
    ConnectionEnd = 162,
    GetAcl = 171,
    SetAcl = 188,
    MyRights = 180,
    ListRights = 176,
    Append = 159,
    Capabilities = 160,
    Id = 172,
    Close = 161,
    Copy = 164,
    Move = 179,
    CreateMailbox = 165,
    DeleteMailbox = 166,
    RenameMailbox = 185,
    Enable = 167,
    Expunge = 169,
    Fetch = 170,
    IdleStart = 173,
    IdleStop = 174,
    List = 175,
    Lsub = 178,
    Logout = 177,
    Namespace = 181,
    Noop = 182,
    Search = 186,
    Sort = 189,
    Select = 187,
    Status = 190,
    Store = 191,
    Subscribe = 192,
    Unsubscribe = 194,
    Thread = 193,
    GetQuota = 57,
    Error = 168,
    RawInput = 183,
    RawOutput = 184,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IncomingReportEvent {
    DmarcReport = 200,
    DmarcReportWithWarnings = 201,
    TlsReport = 206,
    TlsReportWithWarnings = 207,
    AbuseReport = 195,
    AuthFailureReport = 197,
    FraudReport = 202,
    NotSpamReport = 204,
    VirusReport = 209,
    OtherReport = 205,
    MessageParseFailed = 203,
    DmarcParseFailed = 199,
    TlsRpcParseFailed = 208,
    ArfParseFailed = 196,
    DecompressError = 198,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IprevEvent {
    Pass = 212,
    Fail = 210,
    PermError = 213,
    TempError = 214,
    None = 211,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum JmapEvent {
    MethodCall = 223,
    InvalidArguments = 221,
    RequestTooLarge = 227,
    StateMismatch = 228,
    AnchorNotFound = 218,
    UnsupportedFilter = 232,
    UnsupportedSort = 233,
    UnknownMethod = 231,
    InvalidResultReference = 222,
    Forbidden = 220,
    AccountNotFound = 215,
    AccountNotSupportedByMethod = 216,
    AccountReadOnly = 217,
    NotFound = 224,
    CannotCalculateChanges = 219,
    UnknownDataType = 230,
    UnknownCapability = 229,
    NotJson = 225,
    NotRequest = 226,
    WebsocketStart = 235,
    WebsocketStop = 236,
    WebsocketError = 234,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LimitEvent {
    SizeRequest = 243,
    SizeUpload = 244,
    CallsIn = 238,
    ConcurrentRequest = 240,
    ConcurrentUpload = 241,
    ConcurrentConnection = 239,
    Quota = 242,
    BlobQuota = 237,
    TenantQuota = 553,
    TooManyRequests = 245,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MailAuthEvent {
    ParseError = 254,
    MissingParameters = 252,
    NoHeadersFound = 253,
    Crypto = 247,
    Io = 251,
    Base64 = 246,
    DnsError = 248,
    DnsRecordNotFound = 250,
    DnsInvalidRecordType = 249,
    PolicyNotAligned = 255,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ManageEvent {
    MissingParameter = 278,
    AlreadyExists = 275,
    AssertFailed = 276,
    NotFound = 279,
    NotSupported = 280,
    Error = 277,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ManageSieveEvent {
    ConnectionStart = 259,
    ConnectionEnd = 258,
    CreateScript = 260,
    UpdateScript = 274,
    GetScript = 263,
    DeleteScript = 261,
    RenameScript = 270,
    CheckScript = 257,
    HaveSpace = 264,
    ListScripts = 265,
    SetActive = 271,
    Capabilities = 256,
    StartTls = 272,
    Unauthenticate = 273,
    Logout = 266,
    Noop = 267,
    Error = 262,
    RawInput = 268,
    RawOutput = 269,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MessageIngestEvent {
    Ham = 283,
    Spam = 286,
    ImapAppend = 284,
    JmapAppend = 285,
    Duplicate = 281,
    Error = 282,
    FtsIndex = 142,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MilterEvent {
    Read = 299,
    Write = 303,
    ActionAccept = 287,
    ActionDiscard = 289,
    ActionReject = 290,
    ActionTempFail = 293,
    ActionReplyCode = 291,
    ActionConnectionFailure = 288,
    ActionShutdown = 292,
    IoError = 297,
    FrameTooLarge = 296,
    FrameInvalid = 295,
    UnexpectedResponse = 302,
    Timeout = 300,
    TlsInvalidName = 301,
    Disconnected = 294,
    ParseError = 298,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaHookEvent {
    ActionAccept = 304,
    ActionDiscard = 305,
    ActionReject = 307,
    ActionQuarantine = 306,
    Error = 308,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaStsEvent {
    Authorized = 309,
    NotAuthorized = 311,
    PolicyFetch = 312,
    PolicyNotFound = 314,
    PolicyFetchError = 313,
    InvalidPolicy = 310,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NetworkEvent {
    ListenStart = 321,
    ListenStop = 322,
    ListenError = 320,
    BindError = 316,
    ReadError = 324,
    WriteError = 328,
    FlushError = 319,
    AcceptError = 315,
    SplitError = 326,
    Timeout = 327,
    Closed = 317,
    ProxyError = 323,
    SetOptError = 325,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OutgoingReportEvent {
    SpfReport = 342,
    SpfRateLimited = 341,
    DkimReport = 330,
    DkimRateLimited = 329,
    DmarcReport = 333,
    DmarcRateLimited = 332,
    DmarcAggregateReport = 331,
    TlsAggregate = 344,
    HttpSubmission = 334,
    UnauthorizedReportingAddress = 345,
    ReportingAddressValidationError = 340,
    NotFound = 339,
    SubmissionError = 343,
    NoRecipientsFound = 338,
    Locked = 337,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Pop3Event {
    ConnectionStart = 348,
    ConnectionEnd = 347,
    Delete = 349,
    Reset = 358,
    Quit = 355,
    Fetch = 351,
    List = 352,
    ListMessage = 353,
    Uidl = 361,
    UidlMessage = 362,
    Stat = 360,
    Noop = 354,
    Capabilities = 346,
    StartTls = 359,
    Utf8 = 363,
    Error = 350,
    RawInput = 356,
    RawOutput = 357,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PurgeEvent {
    Started = 369,
    Finished = 366,
    Running = 368,
    Error = 365,
    InProgress = 367,
    AutoExpunge = 364,
    BlobCleanup = 370,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PushSubscriptionEvent {
    Success = 373,
    Error = 371,
    NotFound = 372,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum QueueEvent {
    QueueMessage = 380,
    QueueMessageAuthenticated = 381,
    QueueReport = 382,
    QueueDsn = 379,
    QueueAutogenerated = 378,
    Rescheduled = 385,
    Locked = 377,
    BlobNotFound = 374,
    RateLimitExceeded = 384,
    ConcurrencyLimitExceeded = 375,
    QuotaExceeded = 383,
    BackPressure = 48,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ResourceEvent {
    NotFound = 389,
    BadParameters = 386,
    Error = 388,
    DownloadExternal = 387,
    WebadminUnpacked = 390,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecurityEvent {
    AuthenticationBan = 33,
    AbuseBan = 549,
    ScanBan = 558,
    LoiterBan = 550,
    IpBlocked = 318,
    IpBlockExpired = 593,
    IpAllowExpired = 594,
    Unauthorized = 552,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ServerEvent {
    Startup = 393,
    Shutdown = 392,
    StartupError = 394,
    ThreadError = 395,
    Licensing = 391,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SieveEvent {
    ActionAccept = 396,
    ActionAcceptReplace = 397,
    ActionDiscard = 398,
    ActionReject = 399,
    SendMessage = 406,
    MessageTooLarge = 401,
    ScriptNotFound = 405,
    ListNotFound = 400,
    RuntimeError = 404,
    UnexpectedError = 407,
    NotSupported = 402,
    QuotaExceeded = 403,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SmtpEvent {
    ConnectionStart = 417,
    ConnectionEnd = 416,
    Error = 428,
    IdNotFound = 469,
    ConcurrencyLimitExceeded = 415,
    TransferLimitExceeded = 485,
    RateLimitExceeded = 461,
    TimeLimitExceeded = 481,
    MissingAuthDirectory = 452,
    MessageParseFailed = 450,
    MessageTooLarge = 451,
    LoopDetected = 443,
    DkimPass = 422,
    DkimFail = 421,
    ArcPass = 410,
    ArcFail = 409,
    SpfEhloPass = 474,
    SpfEhloFail = 473,
    SpfFromPass = 476,
    SpfFromFail = 475,
    DmarcPass = 424,
    DmarcFail = 423,
    IprevPass = 441,
    IprevFail = 440,
    TooManyMessages = 483,
    Ehlo = 426,
    InvalidEhlo = 436,
    DidNotSayEhlo = 420,
    EhloExpected = 427,
    LhloExpected = 442,
    MailFromUnauthenticated = 447,
    MailFromUnauthorized = 448,
    MailFromNotAllowed = 551,
    MailFromRewritten = 446,
    MailFromMissing = 445,
    MailFrom = 444,
    MultipleMailFrom = 456,
    MailboxDoesNotExist = 449,
    RelayNotAllowed = 468,
    RcptTo = 464,
    RcptToDuplicate = 465,
    RcptToRewritten = 467,
    RcptToMissing = 466,
    RcptToGreylisted = 561,
    TooManyRecipients = 484,
    TooManyInvalidRcpt = 482,
    RawInput = 462,
    RawOutput = 463,
    MissingLocalHostname = 453,
    Vrfy = 487,
    VrfyNotFound = 489,
    VrfyDisabled = 488,
    Expn = 429,
    ExpnNotFound = 431,
    ExpnDisabled = 430,
    RequireTlsDisabled = 471,
    DeliverByDisabled = 418,
    DeliverByInvalid = 419,
    FutureReleaseDisabled = 432,
    FutureReleaseInvalid = 433,
    MtPriorityDisabled = 454,
    MtPriorityInvalid = 455,
    DsnDisabled = 425,
    AuthNotAllowed = 413,
    AuthMechanismNotSupported = 412,
    AuthExchangeTooLong = 411,
    AlreadyAuthenticated = 408,
    Noop = 457,
    StartTls = 477,
    StartTlsUnavailable = 479,
    StartTlsAlready = 478,
    Rset = 472,
    Quit = 460,
    Help = 434,
    CommandNotImplemented = 414,
    InvalidCommand = 435,
    InvalidSenderAddress = 439,
    InvalidRecipientAddress = 438,
    InvalidParameter = 437,
    UnsupportedParameter = 486,
    SyntaxError = 480,
    RequestTooLarge = 470,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamEvent {
    Pyzor = 564,
    PyzorError = 494,
    Dnsbl = 562,
    DnsblError = 563,
    TrainStarted = 588,
    TrainCompleted = 495,
    TrainSampleAdded = 143,
    TrainSampleNotFound = 491,
    Classify = 490,
    ModelLoaded = 589,
    ModelNotReady = 496,
    ModelNotFound = 497,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpfEvent {
    Pass = 501,
    Fail = 498,
    SoftFail = 503,
    Neutral = 499,
    TempError = 504,
    PermError = 502,
    None = 500,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StoreEvent {
    AssertValueFailed = 505,
    FoundationdbError = 518,
    MysqlError = 522,
    PostgresqlError = 527,
    RocksdbError = 529,
    SqliteError = 532,
    LdapError = 520,
    ElasticsearchError = 516,
    MeilisearchError = 590,
    RedisError = 528,
    S3Error = 530,
    AzureError = 559,
    FilesystemError = 517,
    PoolError = 526,
    DataCorruption = 511,
    DecompressError = 514,
    DeserializeError = 515,
    NotFound = 524,
    NotConfigured = 523,
    NotSupported = 525,
    UnexpectedError = 533,
    CryptoError = 510,
    HttpStoreError = 493,
    CacheMiss = 50,
    CacheHit = 51,
    CacheStale = 52,
    CacheUpdate = 577,
    BlobMissingMarker = 507,
    DataWrite = 513,
    DataIterate = 512,
    BlobRead = 508,
    BlobWrite = 509,
    BlobDelete = 506,
    SqlQuery = 531,
    LdapQuery = 521,
    LdapWarning = 519,
    HttpStoreFetch = 492,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskQueueEvent {
    TaskAcquired = 578,
    TaskLocked = 144,
    TaskIgnored = 586,
    TaskFailed = 587,
    BlobNotFound = 141,
    MetadataNotFound = 145,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TelemetryEvent {
    Alert = 548,
    LogError = 535,
    WebhookError = 539,
    OtelExporterError = 536,
    OtelMetricsExporterError = 537,
    PrometheusExporterError = 538,
    JournalError = 534,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsEvent {
    Handshake = 543,
    HandshakeError = 544,
    NotConfigured = 547,
    CertificateNotFound = 542,
    NoCertificatesAvailable = 546,
    MultipleCertificatesAvailable = 545,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsRptEvent {
    RecordFetch = 540,
    RecordFetchError = 541,
    RecordNotFound = 560,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum WebDavEvent {
    Propfind = 147,
    Proppatch = 148,
    Get = 335,
    Head = 574,
    Report = 336,
    Mkcol = 376,
    Mkcalendar = 575,
    Delete = 458,
    Put = 459,
    Post = 565,
    Patch = 566,
    Copy = 567,
    Move = 568,
    Lock = 569,
    Unlock = 570,
    Acl = 571,
    Options = 573,
    Error = 572,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MetricType {
    AcmeAuthError = 27,
    AcmeAuthTooManyAttempts = 28,
    AcmeOrderCompleted = 29,
    AcmeOrderInvalid = 30,
    AcmeClientMissingSni = 31,
    AcmeTlsAlpnError = 32,
    AcmeTokenNotFound = 33,
    AcmeError = 34,
    ArcChainTooLong = 39,
    ArcInvalidInstance = 40,
    ArcInvalidCv = 41,
    ArcHasHeaderTag = 42,
    ArcBrokenChain = 43,
    AuthSuccess = 44,
    AuthFailed = 45,
    AuthTooManyAttempts = 46,
    AuthError = 47,
    CalendarAlarmSent = 48,
    CalendarAlarmFailed = 49,
    CalendarItipMessageSent = 50,
    CalendarItipMessageReceived = 51,
    CalendarItipMessageError = 52,
    ClusterSubscriberError = 53,
    ClusterSubscriberDisconnected = 54,
    ClusterPublisherError = 55,
    DaneAuthenticationSuccess = 56,
    DaneAuthenticationFailure = 57,
    DaneNoCertificatesFound = 58,
    DaneCertificateParseError = 59,
    DaneTlsaRecordFetchError = 60,
    DaneTlsaRecordNotFound = 61,
    DaneTlsaRecordNotDnssecSigned = 62,
    DaneTlsaRecordInvalid = 63,
    DeliveryTotalTime = 2,
    DeliveryAttemptTime = 3,
    DeliveryActiveConnections = 22,
    DeliveryAttemptStart = 64,
    DeliveryAttemptEnd = 65,
    DeliveryCompleted = 66,
    DeliveryMxLookupFailed = 67,
    DeliveryIpLookupFailed = 68,
    DeliveryNullMx = 69,
    DeliveryGreetingFailed = 70,
    DeliveryEhloRejected = 71,
    DeliveryAuthFailed = 72,
    DeliveryMailFromRejected = 73,
    DeliveryDelivered = 74,
    DeliveryRcptToRejected = 75,
    DeliveryRcptToFailed = 76,
    DeliveryMessageRejected = 77,
    DeliveryStartTlsUnavailable = 78,
    DeliveryStartTlsError = 79,
    DeliveryStartTlsDisabled = 80,
    DeliveryImplicitTlsError = 81,
    DeliveryConcurrencyLimitExceeded = 82,
    DeliveryRateLimitExceeded = 83,
    DeliveryDoubleBounce = 84,
    DeliveryDsnSuccess = 85,
    DeliveryDsnTempFail = 86,
    DeliveryDsnPermFail = 87,
    DkimPass = 88,
    DkimNeutral = 89,
    DkimFail = 90,
    DkimPermError = 91,
    DkimTempError = 92,
    DkimNone = 93,
    DkimUnsupportedVersion = 94,
    DkimUnsupportedAlgorithm = 95,
    DkimUnsupportedCanonicalization = 96,
    DkimUnsupportedKeyType = 97,
    DkimFailedBodyHashMatch = 98,
    DkimFailedVerification = 99,
    DkimFailedAuidMatch = 100,
    DkimRevokedPublicKey = 101,
    DkimIncompatibleAlgorithms = 102,
    DkimSignatureExpired = 103,
    DkimSignatureLength = 104,
    DkimSignerNotFound = 105,
    DmarcPass = 106,
    DmarcFail = 107,
    DmarcPermError = 108,
    DmarcTempError = 109,
    DmarcNone = 110,
    DnsLookupTime = 11,
    DnsRecordCreationFailed = 35,
    DnsRecordDeletionFailed = 36,
    DnsRecordLookupFailed = 37,
    DnsRecordPropagationTimeout = 38,
    DomainCount = 26,
    EvalError = 111,
    EvalDirectoryNotFound = 112,
    EvalStoreNotFound = 113,
    HttpRequestTime = 12,
    HttpActiveConnections = 17,
    HttpError = 114,
    HttpRequestBody = 115,
    HttpResponseBody = 116,
    HttpXForwardedMissing = 117,
    ImapRequestTime = 13,
    ImapActiveConnections = 18,
    ImapConnectionStart = 118,
    ImapConnectionEnd = 119,
    IncomingReportDmarcReport = 120,
    IncomingReportDmarcReportWithWarnings = 121,
    IncomingReportTlsReport = 122,
    IncomingReportTlsReportWithWarnings = 123,
    IncomingReportAbuseReport = 124,
    IncomingReportAuthFailureReport = 125,
    IncomingReportFraudReport = 126,
    IncomingReportNotSpamReport = 127,
    IncomingReportVirusReport = 128,
    IncomingReportOtherReport = 129,
    IncomingReportMessageParseFailed = 130,
    IncomingReportDmarcParseFailed = 131,
    IncomingReportTlsRpcParseFailed = 132,
    IncomingReportArfParseFailed = 133,
    IncomingReportDecompressError = 134,
    IprevPass = 135,
    IprevFail = 136,
    IprevPermError = 137,
    IprevTempError = 138,
    IprevNone = 139,
    JmapMethodCall = 140,
    JmapInvalidArguments = 141,
    JmapRequestTooLarge = 142,
    JmapUnsupportedFilter = 143,
    JmapUnsupportedSort = 144,
    JmapUnknownMethod = 145,
    JmapForbidden = 146,
    JmapNotJson = 147,
    JmapNotRequest = 148,
    JmapWebsocketStart = 149,
    JmapWebsocketError = 150,
    LimitSizeRequest = 151,
    LimitSizeUpload = 152,
    LimitCallsIn = 153,
    LimitConcurrentRequest = 154,
    LimitConcurrentUpload = 155,
    LimitConcurrentConnection = 156,
    LimitQuota = 157,
    LimitBlobQuota = 158,
    LimitTenantQuota = 159,
    LimitTooManyRequests = 160,
    MailAuthParseError = 161,
    MailAuthMissingParameters = 162,
    MailAuthNoHeadersFound = 163,
    MailAuthCrypto = 164,
    MailAuthIo = 165,
    MailAuthBase64 = 166,
    MailAuthDnsError = 167,
    MailAuthDnsRecordNotFound = 168,
    MailAuthDnsInvalidRecordType = 169,
    MailAuthPolicyNotAligned = 170,
    ManageSieveConnectionStart = 171,
    ManageSieveConnectionEnd = 172,
    MessageSize = 4,
    MessageAuthenticatedSize = 5,
    MessageIngestTime = 0,
    MessageIngestIndexTime = 1,
    MessageIngestHam = 173,
    MessageIngestSpam = 174,
    MessageIngestImapAppend = 175,
    MessageIngestJmapAppend = 176,
    MessageIngestDuplicate = 177,
    MessageIngestError = 178,
    MessageIngestFtsIndex = 179,
    MilterActionAccept = 180,
    MilterActionDiscard = 181,
    MilterActionReject = 182,
    MilterActionTempFail = 183,
    MilterActionReplyCode = 184,
    MilterActionConnectionFailure = 185,
    MilterActionShutdown = 186,
    MtaHookActionAccept = 187,
    MtaHookActionDiscard = 188,
    MtaHookActionReject = 189,
    MtaHookActionQuarantine = 190,
    MtaHookError = 191,
    MtaStsAuthorized = 192,
    MtaStsNotAuthorized = 193,
    MtaStsInvalidPolicy = 194,
    NetworkTimeout = 195,
    OutgoingReportSize = 6,
    OutgoingReportSpfReport = 196,
    OutgoingReportSpfRateLimited = 197,
    OutgoingReportDkimReport = 198,
    OutgoingReportDkimRateLimited = 199,
    OutgoingReportDmarcReport = 200,
    OutgoingReportDmarcRateLimited = 201,
    OutgoingReportDmarcAggregateReport = 202,
    OutgoingReportTlsAggregate = 203,
    OutgoingReportHttpSubmission = 204,
    OutgoingReportUnauthorizedReportingAddress = 205,
    OutgoingReportReportingAddressValidationError = 206,
    OutgoingReportNotFound = 207,
    OutgoingReportSubmissionError = 208,
    OutgoingReportNoRecipientsFound = 209,
    Pop3RequestTime = 14,
    Pop3ActiveConnections = 19,
    Pop3ConnectionStart = 210,
    Pop3ConnectionEnd = 211,
    PurgeError = 212,
    PushSubscriptionSuccess = 213,
    PushSubscriptionError = 214,
    PushSubscriptionNotFound = 215,
    QueueCount = 24,
    QueueQueueMessage = 216,
    QueueQueueMessageAuthenticated = 217,
    QueueQueueReport = 218,
    QueueQueueDsn = 219,
    QueueQueueAutogenerated = 220,
    QueueRescheduled = 221,
    QueueBlobNotFound = 222,
    QueueRateLimitExceeded = 223,
    QueueConcurrencyLimitExceeded = 224,
    QueueQuotaExceeded = 225,
    ResourceNotFound = 226,
    ResourceBadParameters = 227,
    ResourceError = 228,
    SecurityAuthenticationBan = 229,
    SecurityAbuseBan = 230,
    SecurityScanBan = 231,
    SecurityLoiterBan = 232,
    SecurityIpBlocked = 233,
    SecurityUnauthorized = 234,
    ServerMemory = 23,
    ServerThreadError = 235,
    SieveRequestTime = 16,
    SieveActiveConnections = 21,
    SieveActionAccept = 236,
    SieveActionAcceptReplace = 237,
    SieveActionDiscard = 238,
    SieveActionReject = 239,
    SieveSendMessage = 240,
    SieveMessageTooLarge = 241,
    SieveRuntimeError = 242,
    SieveUnexpectedError = 243,
    SieveNotSupported = 244,
    SieveQuotaExceeded = 245,
    SmtpRequestTime = 15,
    SmtpActiveConnections = 20,
    SmtpConnectionStart = 246,
    SmtpConnectionEnd = 247,
    SmtpError = 248,
    SmtpConcurrencyLimitExceeded = 249,
    SmtpTransferLimitExceeded = 250,
    SmtpRateLimitExceeded = 251,
    SmtpTimeLimitExceeded = 252,
    SmtpMessageParseFailed = 253,
    SmtpMessageTooLarge = 254,
    SmtpLoopDetected = 255,
    SmtpDkimPass = 256,
    SmtpDkimFail = 257,
    SmtpArcPass = 258,
    SmtpArcFail = 259,
    SmtpSpfEhloPass = 260,
    SmtpSpfEhloFail = 261,
    SmtpSpfFromPass = 262,
    SmtpSpfFromFail = 263,
    SmtpDmarcPass = 264,
    SmtpDmarcFail = 265,
    SmtpIprevPass = 266,
    SmtpIprevFail = 267,
    SmtpTooManyMessages = 268,
    SmtpInvalidEhlo = 269,
    SmtpDidNotSayEhlo = 270,
    SmtpMailFromUnauthenticated = 271,
    SmtpMailFromUnauthorized = 272,
    SmtpMailFromMissing = 273,
    SmtpMultipleMailFrom = 274,
    SmtpMailboxDoesNotExist = 275,
    SmtpRelayNotAllowed = 276,
    SmtpRcptToDuplicate = 277,
    SmtpRcptToMissing = 278,
    SmtpTooManyRecipients = 279,
    SmtpTooManyInvalidRcpt = 280,
    SmtpAuthMechanismNotSupported = 281,
    SmtpAuthExchangeTooLong = 282,
    SmtpCommandNotImplemented = 283,
    SmtpInvalidCommand = 284,
    SmtpSyntaxError = 285,
    SmtpRequestTooLarge = 286,
    SpamPyzorError = 287,
    SpamDnsblError = 288,
    SpamTrainCompleted = 289,
    SpamTrainSampleAdded = 290,
    SpamClassify = 291,
    SpamModelNotReady = 292,
    SpfPass = 293,
    SpfFail = 294,
    SpfSoftFail = 295,
    SpfNeutral = 296,
    SpfTempError = 297,
    SpfPermError = 298,
    SpfNone = 299,
    StoreDataReadTime = 7,
    StoreDataWriteTime = 8,
    StoreBlobReadTime = 9,
    StoreBlobWriteTime = 10,
    StoreAssertValueFailed = 300,
    StoreFoundationdbError = 301,
    StoreMysqlError = 302,
    StorePostgresqlError = 303,
    StoreRocksdbError = 304,
    StoreSqliteError = 305,
    StoreLdapError = 306,
    StoreElasticsearchError = 307,
    StoreRedisError = 308,
    StoreS3Error = 309,
    StoreAzureError = 310,
    StoreFilesystemError = 311,
    StorePoolError = 312,
    StoreDataCorruption = 313,
    StoreDecompressError = 314,
    StoreDeserializeError = 315,
    StoreNotFound = 316,
    StoreNotConfigured = 317,
    StoreNotSupported = 318,
    StoreUnexpectedError = 319,
    StoreCryptoError = 320,
    StoreHttpStoreError = 321,
    StoreBlobMissingMarker = 322,
    StoreDataWrite = 323,
    StoreDataIterate = 324,
    StoreBlobRead = 325,
    StoreBlobWrite = 326,
    StoreBlobDelete = 327,
    TaskQueueBlobNotFound = 328,
    TaskQueueMetadataNotFound = 329,
    TelemetryLogError = 330,
    TelemetryWebhookError = 331,
    TelemetryOtelExporterError = 332,
    TelemetryOtelMetricsExporterError = 333,
    TelemetryPrometheusExporterError = 334,
    TelemetryJournalError = 335,
    TlsHandshakeError = 336,
    UserCount = 25,
}
