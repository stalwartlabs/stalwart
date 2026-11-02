/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

pub const TOTAL_EVENT_COUNT: usize = 668;
pub const TOTAL_METRIC_COUNT: usize = 398;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    Acme(AcmeEvent),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Ai(AiEvent),
    // SPDX-SnippetEnd
    Arc(ArcEvent),
    Auth(AuthEvent),
    Cache(CacheEvent),
    Calendar(CalendarEvent),
    Cluster(ClusterEvent),
    Dane(DaneEvent),
    Delivery(DeliveryEvent),
    Dkim(DkimEvent),
    Dkim2(Dkim2Event),
    Dmarc(DmarcEvent),
    Dns(DnsEvent),
    Encryption(EncryptionEvent),
    Eval(EvalEvent),
    Http(HttpEvent),
    Imap(ImapEvent),
    IncomingReport(IncomingReportEvent),
    Iprev(IprevEvent),
    Jmap(JmapEvent),
    Limit(LimitEvent),
    MailAuth(MailAuthEvent),
    ManageSieve(ManageSieveEvent),
    MessageIngest(MessageIngestEvent),
    Milter(MilterEvent),
    MtaHook(MtaHookEvent),
    MtaSts(MtaStsEvent),
    Network(NetworkEvent),
    OutgoingReport(OutgoingReportEvent),
    Pop3(Pop3Event),
    PushSubscription(PushSubscriptionEvent),
    Queue(QueueEvent),
    Registry(RegistryEvent),
    Resource(ResourceEvent),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Scim(ScimEvent),
    // SPDX-SnippetEnd
    SearchIndex(SearchIndexEvent),
    Security(SecurityEvent),
    Server(ServerEvent),
    Sieve(SieveEvent),
    Smtp(SmtpEvent),
    Spam(SpamEvent),
    Spf(SpfEvent),
    Store(StoreEvent),
    TaskManager(TaskManagerEvent),
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

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AiEvent {
    LlmResponse = 539,
    ApiError = 540,
    Request = 621,
    SpamVerdict = 622,
    SpamSkipped = 623,
    BreakerOpen = 624,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ArcEvent {
    ChainInvalid = 647,
    SignatureInvalid = 648,
    HashMismatch = 649,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AuthEvent {
    Success = 32,
    Failed = 30,
    TokenExpired = 537,
    MfaRequired = 31,
    TooManyAttempts = 33,
    ClientRegistration = 538,
    Error = 29,
    Warning = 578,
    CredentialExpired = 260,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CacheEvent {
    Miss = 45,
    Hit = 46,
    Stale = 47,
    Update = 560,
    EntryTooLarge = 592,
    Invalidate = 600,
    SwapHit = 594,
    SwapMiss = 595,
    SwapWrite = 596,
    SwapError = 597,
    SwapMetrics = 598,
    SwapFlush = 599,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CalendarEvent {
    RuleExpansionError = 559,
    AlarmSent = 562,
    AlarmSkipped = 563,
    AlarmRecipientOverride = 564,
    AlarmFailed = 565,
    ItipMessageSent = 566,
    ItipMessageReceived = 567,
    ItipMessageError = 568,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClusterEvent {
    Startup = 262,
    SubscriberStart = 34,
    SubscriberStop = 35,
    SubscriberError = 36,
    SubscriberDisconnected = 37,
    PublisherStart = 38,
    PublisherStop = 39,
    PublisherError = 40,
    MessageReceived = 41,
    MessageSkipped = 42,
    MessageInvalid = 44,
    NodeIdRenewed = 259,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DaneEvent {
    AuthenticationSuccess = 62,
    AuthenticationFailure = 61,
    NoCertificatesFound = 64,
    CertificateParseError = 63,
    TlsaRecordMatch = 68,
    TlsaRecordFetch = 65,
    TlsaRecordFetchError = 66,
    TlsaRecordNotFound = 70,
    TlsaRecordNotDnssecSigned = 69,
    TlsaRecordInvalid = 67,
    BogusDnssecRecord = 588,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DeliveryEvent {
    AttemptStart = 72,
    AttemptEnd = 71,
    Completed = 75,
    Failed = 87,
    DomainDeliveryStart = 80,
    MxLookup = 96,
    MxLookupFailed = 97,
    IpLookup = 90,
    IpLookupFailed = 91,
    NullMx = 98,
    Connect = 77,
    ConnectError = 78,
    MissingOutboundHostname = 95,
    GreetingFailed = 88,
    Ehlo = 85,
    EhloRejected = 86,
    Auth = 73,
    AuthFailed = 74,
    MailFrom = 92,
    MailFromRejected = 93,
    Delivered = 79,
    RcptTo = 102,
    RcptToRejected = 104,
    RcptToFailed = 103,
    MessageRejected = 94,
    StartTls = 105,
    StartTlsUnavailable = 108,
    StartTlsError = 107,
    StartTlsDisabled = 106,
    ImplicitTlsError = 89,
    ConcurrencyLimitExceeded = 76,
    RateLimitExceeded = 99,
    DoubleBounce = 81,
    DsnSuccess = 83,
    DsnTempFail = 84,
    DsnPermFail = 82,
    RawInput = 100,
    RawOutput = 101,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DkimEvent {
    Pass = 112,
    Neutral = 110,
    Fail = 109,
    PermError = 113,
    TempError = 115,
    None = 111,
    SignatureInvalid = 643,
    PublicKeyError = 644,
    VerificationFailed = 645,
    HashMismatch = 646,
    SignerNotFound = 114,
    BuildError = 575,
    SignatureCreated = 579,
    SignaturePublished = 580,
    SignatureRetiring = 581,
    SignatureRetired = 582,
    SignatureDeleted = 583,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Dkim2Event {
    InstanceInvalid = 633,
    SignatureInvalid = 634,
    ChainInvalid = 635,
    TimestampInvalid = 636,
    EnvelopeMismatch = 637,
    CustodyBroken = 638,
    PublicKeyError = 639,
    VerificationFailed = 640,
    HashMismatch = 641,
    RecipeError = 642,
    SigningFailed = 650,
    DsnNotAligned = 666,
    DsnPropagated = 667,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DmarcEvent {
    Pass = 118,
    Fail = 116,
    PermError = 119,
    TempError = 120,
    None = 117,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EncryptionEvent {
    EncryptionSkipped = 655,
    AtRestEncrypted = 658,
    GatewayEncrypted = 656,
    GatewayPlaintext = 657,
    GatewayBounced = 659,
    KeyLookup = 660,
    KeyHarvested = 661,
    KeyChange = 662,
    CrlFetchFailed = 663,
    DnssecBogus = 664,
    KeyUnusable = 665,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum EvalEvent {
    Result = 123,
    Error = 122,
    DirectoryNotFound = 121,
    StoreNotFound = 124,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum HttpEvent {
    ConnectionStart = 137,
    ConnectionEnd = 136,
    Error = 138,
    RequestUrl = 140,
    RequestBody = 139,
    ResponseBody = 141,
    XForwardedMissing = 142,
    XForwardedInvalid = 625,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ImapEvent {
    ConnectionStart = 147,
    ConnectionEnd = 146,
    GetAcl = 155,
    SetAcl = 172,
    MyRights = 164,
    ListRights = 160,
    Append = 143,
    Capabilities = 144,
    Id = 156,
    Close = 145,
    Copy = 148,
    Move = 163,
    CreateMailbox = 149,
    DeleteMailbox = 150,
    RenameMailbox = 169,
    Enable = 151,
    Expunge = 153,
    Fetch = 154,
    IdleStart = 157,
    IdleStop = 158,
    List = 159,
    Lsub = 162,
    Logout = 161,
    Namespace = 165,
    Noop = 166,
    Search = 170,
    Sort = 173,
    Select = 171,
    Status = 174,
    Store = 175,
    Subscribe = 176,
    Unsubscribe = 178,
    Thread = 177,
    UidBatches = 593,
    GetQuota = 52,
    GetMetadata = 607,
    SetMetadata = 608,
    Error = 152,
    RawInput = 167,
    RawOutput = 168,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IncomingReportEvent {
    DmarcReport = 184,
    DmarcReportWithWarnings = 185,
    TlsReport = 190,
    TlsReportWithWarnings = 191,
    AbuseReport = 179,
    AuthFailureReport = 181,
    FraudReport = 186,
    NotSpamReport = 188,
    VirusReport = 193,
    OtherReport = 189,
    MessageParseFailed = 187,
    DmarcParseFailed = 183,
    TlsRpcParseFailed = 192,
    ArfParseFailed = 180,
    DecompressError = 182,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IprevEvent {
    Pass = 196,
    Fail = 194,
    PermError = 197,
    TempError = 198,
    None = 195,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum JmapEvent {
    MethodCall = 207,
    InvalidArguments = 205,
    RequestTooLarge = 211,
    StateMismatch = 212,
    AnchorNotFound = 202,
    UnsupportedFilter = 216,
    UnsupportedSort = 217,
    UnknownMethod = 215,
    InvalidResultReference = 206,
    Forbidden = 204,
    AccountNotFound = 199,
    AccountNotSupportedByMethod = 200,
    AccountReadOnly = 201,
    FromAccountNotFound = 653,
    FromAccountNotSupportedByMethod = 654,
    NotFound = 208,
    CannotCalculateChanges = 203,
    UnknownDataType = 214,
    UnknownCapability = 213,
    NotJson = 209,
    NotRequest = 210,
    WebsocketStart = 219,
    WebsocketStop = 220,
    WebsocketError = 218,
    ExpandDurationTooLarge = 602,
    CannotCalculateOccurrences = 603,
    TooLarge = 604,
    RateLimit = 605,
    ObjectNotFound = 606,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LimitEvent {
    SizeRequest = 227,
    SizeUpload = 228,
    CallsIn = 222,
    ConcurrentRequest = 224,
    ConcurrentUpload = 225,
    ConcurrentConnection = 223,
    Quota = 226,
    BlobQuota = 221,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TenantQuota = 536,
    // SPDX-SnippetEnd
    TooManyRequests = 229,
    MemoryBudget = 627,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MailAuthEvent {
    ParseError = 238,
    MissingParameters = 236,
    NoHeadersFound = 237,
    Crypto = 231,
    Io = 235,
    Base64 = 230,
    DnsError = 232,
    DnsRecordNotFound = 234,
    DnsInvalidRecordType = 233,
    PolicyNotAligned = 239,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ManageSieveEvent {
    ConnectionStart = 243,
    ConnectionEnd = 242,
    CreateScript = 244,
    UpdateScript = 258,
    GetScript = 247,
    DeleteScript = 245,
    RenameScript = 254,
    CheckScript = 241,
    HaveSpace = 248,
    ListScripts = 249,
    SetActive = 255,
    Capabilities = 240,
    StartTls = 256,
    Unauthenticate = 257,
    Logout = 250,
    Noop = 251,
    Error = 246,
    RawInput = 252,
    RawOutput = 253,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MessageIngestEvent {
    Ham = 267,
    Spam = 270,
    ImapAppend = 268,
    JmapAppend = 269,
    Duplicate = 265,
    Error = 266,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MilterEvent {
    Read = 283,
    Write = 287,
    ActionAccept = 271,
    ActionDiscard = 273,
    ActionReject = 274,
    ActionTempFail = 277,
    ActionReplyCode = 275,
    ActionConnectionFailure = 272,
    ActionShutdown = 276,
    IoError = 281,
    FrameTooLarge = 280,
    FrameInvalid = 279,
    UnexpectedResponse = 286,
    Timeout = 284,
    TlsInvalidName = 285,
    Disconnected = 278,
    ParseError = 282,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaHookEvent {
    ActionAccept = 288,
    ActionDiscard = 289,
    ActionReject = 291,
    ActionQuarantine = 290,
    Error = 292,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MtaStsEvent {
    Authorized = 293,
    NotAuthorized = 295,
    PolicyFetch = 296,
    PolicyNotFound = 298,
    PolicyFetchError = 297,
    InvalidPolicy = 294,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NetworkEvent {
    ListenStart = 305,
    ListenStop = 306,
    ListenError = 304,
    BindError = 300,
    ReadError = 308,
    WriteError = 312,
    FlushError = 303,
    AcceptError = 299,
    SplitError = 310,
    Timeout = 311,
    Closed = 301,
    ProxyError = 307,
    SetOptError = 309,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OutgoingReportEvent {
    SpfReport = 326,
    SpfRateLimited = 325,
    DkimReport = 314,
    DkimRateLimited = 313,
    DmarcReport = 317,
    DmarcRateLimited = 316,
    DmarcAggregateReport = 315,
    TlsAggregate = 328,
    HttpSubmission = 318,
    UnauthorizedReportingAddress = 329,
    ReportingAddressValidationError = 324,
    NotFound = 323,
    SubmissionError = 327,
    NoRecipientsFound = 322,
    Locked = 321,
    MaxSizeExceeded = 54,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Pop3Event {
    ConnectionStart = 332,
    ConnectionEnd = 331,
    Delete = 333,
    Reset = 342,
    Quit = 339,
    Fetch = 335,
    List = 336,
    ListMessage = 337,
    Uidl = 345,
    UidlMessage = 346,
    Stat = 344,
    Noop = 338,
    Capabilities = 330,
    StartTls = 343,
    Utf8 = 347,
    Error = 334,
    RawInput = 340,
    RawOutput = 341,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PushSubscriptionEvent {
    Success = 357,
    Error = 355,
    NotFound = 356,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum QueueEvent {
    Started = 374,
    MessageQueued = 364,
    AuthenticatedMessageQueued = 365,
    ReportQueued = 366,
    DsnQueued = 363,
    AutogeneratedQueued = 362,
    Rescheduled = 369,
    Locked = 361,
    BlobNotFound = 358,
    RateLimitExceeded = 368,
    ConcurrencyLimitExceeded = 359,
    QuotaExceeded = 367,
    BackPressure = 43,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RegistryEvent {
    LocalReadError = 57,
    LocalWriteError = 49,
    LocalParseError = 55,
    ReadError = 60,
    WriteError = 53,
    DeserializationError = 51,
    BuildError = 56,
    BuildWarning = 50,
    NotSupported = 59,
    ValidationError = 58,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ResourceEvent {
    NotFound = 373,
    BadParameters = 370,
    Error = 372,
    DownloadExternal = 371,
    ApplicationUpdated = 584,
    ApplicationUnpacked = 585,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ScimEvent {
    Request = 609,
    Forbidden = 610,
    Conflict = 611,
    Error = 612,
    ResourceCreated = 613,
    ResourceUpdated = 614,
    ResourceDeleted = 615,
    Query = 616,
    BulkProcessed = 617,
    BulkAborted = 618,
    RollbackFailed = 619,
    AttributeIgnored = 620,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SearchIndexEvent {
    ManagerStarted = 629,
    PartitionsAcquired = 630,
    PartitionLocked = 631,
    PartitionRetry = 632,
    BatchIndexed = 126,
    DocumentIgnored = 574,
    DocumentTruncated = 628,
    MetadataNotFound = 27,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SecurityEvent {
    AuthenticationBan = 28,
    AbuseBan = 532,
    ScanBan = 541,
    LoiterBan = 533,
    IpBlocked = 302,
    IpBlockExpired = 576,
    IpAllowExpired = 577,
    IpUnauthorized = 263,
    Unauthorized = 535,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ServerEvent {
    Startup = 377,
    Shutdown = 376,
    StartupError = 378,
    ThreadError = 379,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Licensing = 375,
    // SPDX-SnippetEnd
    RecoveryMode = 586,
    BootstrapMode = 587,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SieveEvent {
    ActionAccept = 380,
    ActionAcceptReplace = 381,
    ActionDiscard = 382,
    ActionReject = 383,
    SendMessage = 390,
    MessageTooLarge = 385,
    ScriptNotFound = 389,
    ListNotFound = 384,
    RuntimeError = 388,
    UnexpectedError = 391,
    NotSupported = 386,
    QuotaExceeded = 387,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SmtpEvent {
    ConnectionStart = 401,
    ConnectionEnd = 400,
    Error = 412,
    IdNotFound = 452,
    ConcurrencyLimitExceeded = 399,
    TransferLimitExceeded = 468,
    RateLimitExceeded = 444,
    TimeLimitExceeded = 464,
    MessageParseFailed = 434,
    MessageTooLarge = 435,
    LoopDetected = 427,
    MultipleFromDomains = 626,
    DkimPass = 406,
    DkimFail = 405,
    Dkim2Pass = 589,
    Dkim2Fail = 590,
    Dkim2DsnRejected = 591,
    ArcPass = 394,
    ArcFail = 393,
    SpfEhloPass = 457,
    SpfEhloFail = 456,
    SpfFromPass = 459,
    SpfFromFail = 458,
    DmarcPass = 408,
    DmarcFail = 407,
    IprevPass = 425,
    IprevFail = 424,
    TooManyMessages = 466,
    Ehlo = 410,
    InvalidEhlo = 420,
    DidNotSayEhlo = 404,
    EhloExpected = 411,
    LhloExpected = 426,
    MailFromUnauthenticated = 431,
    MailFromUnauthorized = 432,
    MailFromNotAllowed = 534,
    MailFromRewritten = 430,
    MailFromMissing = 429,
    MailFrom = 428,
    MultipleMailFrom = 439,
    MailboxDoesNotExist = 433,
    RelayNotAllowed = 451,
    RcptTo = 447,
    RcptToDuplicate = 448,
    RcptToRewritten = 450,
    RcptToMissing = 449,
    RcptToGreylisted = 544,
    TooManyRecipients = 467,
    TooManyInvalidRcpt = 465,
    RawInput = 445,
    RawOutput = 446,
    MissingLocalHostname = 436,
    Vrfy = 470,
    VrfyNotFound = 472,
    VrfyDisabled = 471,
    Expn = 413,
    ExpnNotFound = 415,
    ExpnDisabled = 414,
    RequireTlsDisabled = 454,
    DeliverByDisabled = 402,
    DeliverByInvalid = 403,
    FutureReleaseDisabled = 416,
    FutureReleaseInvalid = 417,
    MtPriorityDisabled = 437,
    MtPriorityInvalid = 438,
    DsnDisabled = 409,
    AuthNotAllowed = 397,
    AuthMechanismNotSupported = 396,
    AuthExchangeTooLong = 395,
    AlreadyAuthenticated = 392,
    Noop = 440,
    StartTls = 460,
    StartTlsUnavailable = 462,
    StartTlsAlready = 461,
    Rset = 455,
    Quit = 443,
    Help = 418,
    CommandNotImplemented = 398,
    InvalidCommand = 419,
    InvalidSenderAddress = 423,
    InvalidRecipientAddress = 422,
    InvalidParameter = 421,
    UnsupportedParameter = 469,
    SyntaxError = 463,
    RequestTooLarge = 453,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpamEvent {
    Pyzor = 547,
    PyzorError = 477,
    Dnsbl = 545,
    DnsblError = 546,
    TrainStarted = 571,
    TrainCompleted = 478,
    TrainSampleAdded = 127,
    TrainSampleNotFound = 474,
    Classify = 473,
    ModelLoaded = 572,
    ModelNotReady = 479,
    ModelNotFound = 480,
    RulesUpdated = 264,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SpfEvent {
    Pass = 484,
    Fail = 481,
    SoftFail = 486,
    Neutral = 482,
    TempError = 487,
    PermError = 485,
    None = 483,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StoreEvent {
    AssertValueFailed = 488,
    FoundationdbError = 501,
    MysqlError = 505,
    PostgresqlError = 510,
    RocksdbError = 512,
    SqliteError = 515,
    LdapError = 503,
    ElasticsearchError = 499,
    MeilisearchError = 573,
    RedisError = 511,
    S3Error = 513,
    AzureError = 542,
    FilesystemError = 500,
    PoolError = 509,
    DataCorruption = 494,
    DecompressError = 497,
    DeserializeError = 498,
    NotFound = 507,
    NotConfigured = 506,
    NotSupported = 508,
    UnexpectedError = 516,
    CryptoError = 493,
    HttpStoreError = 476,
    BlobMissingMarker = 490,
    DataWrite = 496,
    DataIterate = 495,
    BlobRead = 491,
    BlobWrite = 492,
    BlobDelete = 489,
    SqlQuery = 514,
    LdapQuery = 504,
    LdapWarning = 502,
    HttpStoreFetch = 475,
    AutoExpunge = 348,
    BlobStorePurged = 353,
    DataStorePurged = 352,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TaskManagerEvent {
    TaskAcquired = 561,
    TaskQueued = 133,
    TaskScheduled = 354,
    TaskLocked = 128,
    TaskIgnored = 569,
    TaskFailed = 570,
    TaskRetry = 48,
    TaskStalled = 651,
    TaskExpired = 652,
    BlobNotFound = 125,
    MetadataNotFound = 129,
    SchedulerStarted = 134,
    ManagerStarted = 351,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TelemetryEvent {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    AlertEvent = 531,
    #[cfg(feature = "enterprise")]
    AlertMessage = 349,
    // SPDX-SnippetEnd
    LogError = 518,
    WebhookError = 522,
    OtelExporterError = 519,
    OtelMetricsExporterError = 520,
    PrometheusExporterError = 521,
    JournalError = 517,
    EventsDropped = 601,
    MetricsCollected = 135,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    MetricsStored = 350,
    // SPDX-SnippetEnd
    MetricsPushed = 130,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsEvent {
    Handshake = 526,
    HandshakeError = 527,
    NotConfigured = 530,
    CertificateNotFound = 525,
    NoCertificatesAvailable = 529,
    MultipleCertificatesAvailable = 528,
    ExpiredCertificateRemoved = 261,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TlsRptEvent {
    RecordFetch = 523,
    RecordFetchError = 524,
    RecordNotFound = 543,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum WebDavEvent {
    Propfind = 131,
    Proppatch = 132,
    Get = 319,
    Head = 557,
    Report = 320,
    Mkcol = 360,
    Mkcalendar = 558,
    Delete = 441,
    Put = 442,
    Post = 548,
    Patch = 549,
    Copy = 550,
    Move = 551,
    Lock = 552,
    Unlock = 553,
    Acl = 554,
    Options = 556,
    Error = 555,
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
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    AiRequestTime = 333,
    #[cfg(feature = "enterprise")]
    AiInputTokens = 334,
    #[cfg(feature = "enterprise")]
    AiOutputTokens = 335,
    #[cfg(feature = "enterprise")]
    AiApiError = 332,
    #[cfg(feature = "enterprise")]
    AiRequest = 328,
    #[cfg(feature = "enterprise")]
    AiSpamVerdict = 329,
    #[cfg(feature = "enterprise")]
    AiSpamSkipped = 330,
    #[cfg(feature = "enterprise")]
    AiBreakerOpen = 331,
    // SPDX-SnippetEnd
    ArcChainInvalid = 379,
    ArcSignatureInvalid = 380,
    ArcHashMismatch = 381,
    AuthSuccess = 39,
    AuthFailed = 40,
    AuthTooManyAttempts = 41,
    AuthError = 42,
    CacheMessagesSize = 348,
    CacheMessagesLargeSize = 349,
    CacheSize = 350,
    CacheSwapPending = 351,
    CacheMiss = 339,
    CacheHit = 340,
    CacheStale = 341,
    CacheEntryTooLarge = 342,
    CacheSwapHit = 343,
    CacheSwapMiss = 344,
    CacheSwapWrite = 345,
    CacheSwapError = 346,
    CalendarAlarmSent = 43,
    CalendarAlarmFailed = 44,
    CalendarItipMessageSent = 45,
    CalendarItipMessageReceived = 46,
    CalendarItipMessageError = 47,
    ClusterSubscriberError = 48,
    ClusterSubscriberDisconnected = 49,
    ClusterPublisherError = 50,
    DaneAuthenticationSuccess = 51,
    DaneAuthenticationFailure = 52,
    DaneNoCertificatesFound = 53,
    DaneCertificateParseError = 54,
    DaneTlsaRecordFetchError = 55,
    DaneTlsaRecordNotFound = 56,
    DaneTlsaRecordNotDnssecSigned = 57,
    DaneTlsaRecordInvalid = 58,
    DaneBogusDnssecRecord = 323,
    DeliveryTotalTime = 2,
    DeliveryAttemptTime = 3,
    DeliveryActiveConnections = 22,
    DeliveryAttemptStart = 59,
    DeliveryAttemptEnd = 60,
    DeliveryCompleted = 61,
    DeliveryMxLookupFailed = 62,
    DeliveryIpLookupFailed = 63,
    DeliveryNullMx = 64,
    DeliveryGreetingFailed = 65,
    DeliveryEhloRejected = 66,
    DeliveryAuthFailed = 67,
    DeliveryMailFromRejected = 68,
    DeliveryDelivered = 69,
    DeliveryRcptToRejected = 70,
    DeliveryRcptToFailed = 71,
    DeliveryMessageRejected = 72,
    DeliveryStartTlsUnavailable = 73,
    DeliveryStartTlsError = 74,
    DeliveryStartTlsDisabled = 75,
    DeliveryImplicitTlsError = 76,
    DeliveryConcurrencyLimitExceeded = 77,
    DeliveryRateLimitExceeded = 78,
    DeliveryDoubleBounce = 79,
    DeliveryDsnSuccess = 80,
    DeliveryDsnTempFail = 81,
    DeliveryDsnPermFail = 82,
    DkimPass = 83,
    DkimNeutral = 84,
    DkimFail = 85,
    DkimPermError = 86,
    DkimTempError = 87,
    DkimNone = 88,
    DkimSignatureInvalid = 375,
    DkimPublicKeyError = 376,
    DkimVerificationFailed = 377,
    DkimHashMismatch = 378,
    DkimSignerNotFound = 89,
    Dkim2InstanceInvalid = 365,
    Dkim2SignatureInvalid = 366,
    Dkim2ChainInvalid = 367,
    Dkim2TimestampInvalid = 368,
    Dkim2EnvelopeMismatch = 369,
    Dkim2CustodyBroken = 370,
    Dkim2PublicKeyError = 371,
    Dkim2VerificationFailed = 372,
    Dkim2HashMismatch = 373,
    Dkim2RecipeError = 374,
    Dkim2SigningFailed = 382,
    Dkim2DsnNotAligned = 392,
    Dkim2DsnPropagated = 393,
    DmarcPass = 90,
    DmarcFail = 91,
    DmarcPermError = 92,
    DmarcTempError = 93,
    DmarcNone = 94,
    DnsLookupTime = 11,
    DnsRecordCreationFailed = 35,
    DnsRecordDeletionFailed = 36,
    DnsRecordLookupFailed = 37,
    DnsRecordPropagationTimeout = 38,
    DomainCount = 26,
    EncryptionKeyLookupTime = 397,
    EncryptionEncryptionSkipped = 385,
    EncryptionAtRestEncrypted = 388,
    EncryptionGatewayEncrypted = 386,
    EncryptionGatewayPlaintext = 387,
    EncryptionGatewayBounced = 389,
    EncryptionKeyLookup = 390,
    EncryptionKeyHarvested = 391,
    EncryptionKeyChange = 394,
    EncryptionCrlFetchFailed = 395,
    EncryptionDnssecBogus = 396,
    EvalError = 95,
    EvalDirectoryNotFound = 96,
    EvalStoreNotFound = 97,
    HttpRequestTime = 12,
    HttpActiveConnections = 17,
    HttpConnectionStart = 321,
    HttpError = 98,
    HttpRequestBody = 99,
    HttpResponseBody = 100,
    HttpXForwardedMissing = 101,
    HttpXForwardedInvalid = 336,
    ImapRequestTime = 13,
    ImapActiveConnections = 18,
    ImapConnectionStart = 102,
    ImapConnectionEnd = 103,
    IncomingReportDmarcReport = 104,
    IncomingReportDmarcReportWithWarnings = 105,
    IncomingReportTlsReport = 106,
    IncomingReportTlsReportWithWarnings = 107,
    IncomingReportAbuseReport = 108,
    IncomingReportAuthFailureReport = 109,
    IncomingReportFraudReport = 110,
    IncomingReportNotSpamReport = 111,
    IncomingReportVirusReport = 112,
    IncomingReportOtherReport = 113,
    IncomingReportMessageParseFailed = 114,
    IncomingReportDmarcParseFailed = 115,
    IncomingReportTlsRpcParseFailed = 116,
    IncomingReportArfParseFailed = 117,
    IncomingReportDecompressError = 118,
    IprevPass = 119,
    IprevFail = 120,
    IprevPermError = 121,
    IprevTempError = 122,
    IprevNone = 123,
    JmapMethodCall = 124,
    JmapInvalidArguments = 125,
    JmapRequestTooLarge = 126,
    JmapUnsupportedFilter = 127,
    JmapUnsupportedSort = 128,
    JmapUnknownMethod = 129,
    JmapForbidden = 130,
    JmapNotJson = 131,
    JmapNotRequest = 132,
    JmapWebsocketStart = 133,
    JmapWebsocketError = 134,
    LimitSizeRequest = 135,
    LimitSizeUpload = 136,
    LimitCallsIn = 137,
    LimitConcurrentRequest = 138,
    LimitConcurrentUpload = 139,
    LimitConcurrentConnection = 140,
    LimitQuota = 141,
    LimitBlobQuota = 142,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    LimitTenantQuota = 143,
    // SPDX-SnippetEnd
    LimitTooManyRequests = 144,
    LimitMemoryBudget = 338,
    MailAuthParseError = 145,
    MailAuthMissingParameters = 146,
    MailAuthNoHeadersFound = 147,
    MailAuthCrypto = 148,
    MailAuthIo = 149,
    MailAuthBase64 = 150,
    MailAuthDnsError = 151,
    MailAuthDnsRecordNotFound = 152,
    MailAuthDnsInvalidRecordType = 153,
    MailAuthPolicyNotAligned = 154,
    ManageSieveConnectionStart = 155,
    ManageSieveConnectionEnd = 156,
    MessageSize = 4,
    MessageAuthenticatedSize = 5,
    MessageIngestTime = 0,
    MessageIngestHam = 157,
    MessageIngestSpam = 158,
    MessageIngestImapAppend = 159,
    MessageIngestJmapAppend = 160,
    MessageIngestDuplicate = 161,
    MessageIngestError = 162,
    MilterActionAccept = 164,
    MilterActionDiscard = 165,
    MilterActionReject = 166,
    MilterActionTempFail = 167,
    MilterActionReplyCode = 168,
    MilterActionConnectionFailure = 169,
    MilterActionShutdown = 170,
    MtaHookActionAccept = 171,
    MtaHookActionDiscard = 172,
    MtaHookActionReject = 173,
    MtaHookActionQuarantine = 174,
    MtaHookError = 175,
    MtaStsAuthorized = 176,
    MtaStsNotAuthorized = 177,
    MtaStsInvalidPolicy = 178,
    NetworkTimeout = 179,
    OutgoingReportSize = 6,
    OutgoingReportSpfReport = 180,
    OutgoingReportSpfRateLimited = 181,
    OutgoingReportDkimReport = 182,
    OutgoingReportDkimRateLimited = 183,
    OutgoingReportDmarcReport = 184,
    OutgoingReportDmarcRateLimited = 185,
    OutgoingReportDmarcAggregateReport = 186,
    OutgoingReportTlsAggregate = 187,
    OutgoingReportHttpSubmission = 188,
    OutgoingReportUnauthorizedReportingAddress = 189,
    OutgoingReportReportingAddressValidationError = 190,
    OutgoingReportNotFound = 191,
    OutgoingReportSubmissionError = 192,
    OutgoingReportNoRecipientsFound = 193,
    Pop3RequestTime = 14,
    Pop3ActiveConnections = 19,
    Pop3ConnectionStart = 194,
    Pop3ConnectionEnd = 195,
    PushSubscriptionSuccess = 197,
    PushSubscriptionError = 198,
    PushSubscriptionNotFound = 199,
    QueueCount = 24,
    QueueMessageQueued = 200,
    QueueAuthenticatedMessageQueued = 201,
    QueueReportQueued = 202,
    QueueDsnQueued = 203,
    QueueAutogeneratedQueued = 204,
    QueueRescheduled = 205,
    QueueBlobNotFound = 206,
    QueueRateLimitExceeded = 207,
    QueueConcurrencyLimitExceeded = 208,
    QueueQuotaExceeded = 209,
    QueueBackPressure = 347,
    ResourceNotFound = 210,
    ResourceBadParameters = 211,
    ResourceError = 212,
    SearchIndexIndexTime = 1,
    SearchIndexPendingEmail = 354,
    SearchIndexPendingCalendar = 355,
    SearchIndexPendingContacts = 356,
    SearchIndexPendingFile = 357,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    SearchIndexPendingTracing = 358,
    // SPDX-SnippetEnd
    SearchIndexPartitionRetry = 360,
    SearchIndexBatchIndexed = 163,
    SearchIndexDocumentTruncated = 359,
    SecurityAuthenticationBan = 213,
    SecurityAbuseBan = 214,
    SecurityScanBan = 215,
    SecurityLoiterBan = 216,
    SecurityIpBlocked = 217,
    SecurityUnauthorized = 218,
    ServerMemory = 23,
    ServerBufferedMemorySmtp = 352,
    ServerBufferedMemoryRead = 353,
    ServerThreadError = 219,
    SieveRequestTime = 16,
    SieveActiveConnections = 21,
    SieveActionAccept = 220,
    SieveActionAcceptReplace = 221,
    SieveActionDiscard = 222,
    SieveActionReject = 223,
    SieveSendMessage = 224,
    SieveMessageTooLarge = 225,
    SieveRuntimeError = 226,
    SieveUnexpectedError = 227,
    SieveNotSupported = 228,
    SieveQuotaExceeded = 229,
    SmtpRequestTime = 15,
    SmtpActiveConnections = 20,
    SmtpConnectionStart = 230,
    SmtpConnectionEnd = 231,
    SmtpError = 232,
    SmtpConcurrencyLimitExceeded = 233,
    SmtpTransferLimitExceeded = 234,
    SmtpRateLimitExceeded = 235,
    SmtpTimeLimitExceeded = 236,
    SmtpMessageParseFailed = 237,
    SmtpMessageTooLarge = 238,
    SmtpLoopDetected = 239,
    SmtpMultipleFromDomains = 337,
    SmtpDkimPass = 240,
    SmtpDkimFail = 241,
    SmtpDkim2Pass = 324,
    SmtpDkim2Fail = 325,
    SmtpDkim2DsnRejected = 326,
    SmtpArcPass = 242,
    SmtpArcFail = 243,
    SmtpSpfEhloPass = 244,
    SmtpSpfEhloFail = 245,
    SmtpSpfFromPass = 246,
    SmtpSpfFromFail = 247,
    SmtpDmarcPass = 248,
    SmtpDmarcFail = 249,
    SmtpIprevPass = 250,
    SmtpIprevFail = 251,
    SmtpTooManyMessages = 252,
    SmtpInvalidEhlo = 253,
    SmtpDidNotSayEhlo = 254,
    SmtpMailFromUnauthenticated = 255,
    SmtpMailFromUnauthorized = 256,
    SmtpMailFromMissing = 257,
    SmtpMultipleMailFrom = 258,
    SmtpMailboxDoesNotExist = 259,
    SmtpRelayNotAllowed = 260,
    SmtpRcptToDuplicate = 261,
    SmtpRcptToMissing = 262,
    SmtpTooManyRecipients = 263,
    SmtpTooManyInvalidRcpt = 264,
    SmtpAuthMechanismNotSupported = 265,
    SmtpAuthExchangeTooLong = 266,
    SmtpCommandNotImplemented = 267,
    SmtpInvalidCommand = 268,
    SmtpSyntaxError = 269,
    SmtpRequestTooLarge = 270,
    SpamPyzorError = 271,
    SpamDnsblError = 272,
    SpamTrainCompleted = 273,
    SpamTrainSampleAdded = 274,
    SpamClassify = 275,
    SpamModelNotReady = 276,
    SpfPass = 277,
    SpfFail = 278,
    SpfSoftFail = 279,
    SpfNeutral = 280,
    SpfTempError = 281,
    SpfPermError = 282,
    SpfNone = 283,
    StoreDataReadTime = 7,
    StoreDataWriteTime = 8,
    StoreBlobReadTime = 9,
    StoreBlobWriteTime = 10,
    StoreAssertValueFailed = 284,
    StoreFoundationdbError = 285,
    StoreMysqlError = 286,
    StorePostgresqlError = 287,
    StoreRocksdbError = 288,
    StoreSqliteError = 289,
    StoreLdapError = 290,
    StoreElasticsearchError = 291,
    StoreRedisError = 292,
    StoreS3Error = 293,
    StoreAzureError = 294,
    StoreFilesystemError = 295,
    StorePoolError = 296,
    StoreDataCorruption = 297,
    StoreDecompressError = 298,
    StoreDeserializeError = 299,
    StoreNotFound = 300,
    StoreNotConfigured = 301,
    StoreNotSupported = 302,
    StoreUnexpectedError = 303,
    StoreCryptoError = 304,
    StoreHttpStoreError = 305,
    StoreBlobMissingMarker = 306,
    StoreDataWrite = 307,
    StoreDataIterate = 308,
    StoreBlobRead = 309,
    StoreBlobWrite = 310,
    StoreBlobDelete = 311,
    TaskManagerPending = 363,
    TaskManagerDue = 364,
    TaskManagerTaskFailed = 361,
    TaskManagerTaskRetry = 362,
    TaskManagerTaskStalled = 383,
    TaskManagerTaskExpired = 384,
    TaskManagerBlobNotFound = 312,
    TaskManagerMetadataNotFound = 313,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TelemetryAlertEvent = 322,
    #[cfg(feature = "enterprise")]
    TelemetryAlertMessage = 196,
    // SPDX-SnippetEnd
    TelemetryLogError = 314,
    TelemetryWebhookError = 315,
    TelemetryOtelExporterError = 316,
    TelemetryOtelMetricsExporterError = 317,
    TelemetryPrometheusExporterError = 318,
    TelemetryJournalError = 319,
    TelemetryEventsDropped = 327,
    TlsHandshakeError = 320,
    UserCount = 25,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Key {
    #[default]
    AccountName = 0,
    AccountId = 1,
    BlobId = 2,
    CausedBy = 3,
    ChangeId = 4,
    Code = 5,
    Collection = 6,
    Contents = 7,
    Details = 8,
    DkimFail = 9,
    DkimNone = 10,
    DkimPass = 11,
    DmarcNone = 12,
    DmarcPass = 13,
    DmarcQuarantine = 14,
    DmarcReject = 15,
    DocumentId = 16,
    Domain = 17,
    Due = 18,
    Elapsed = 19,
    Expires = 20,
    From = 21,
    Hostname = 22,
    Id = 23,
    Key = 24,
    Limit = 25,
    ListenerId = 26,
    LocalIp = 27,
    LocalPort = 28,
    MailboxName = 29,
    MailboxId = 30,
    MessageId = 31,
    NextDsn = 32,
    NextRetry = 33,
    Path = 34,
    Policy = 35,
    QueueId = 36,
    RangeFrom = 37,
    RangeTo = 38,
    Reason = 39,
    RemoteIp = 40,
    RemotePort = 41,
    ReportId = 42,
    Result = 43,
    Size = 44,
    Source = 45,
    SpanId = 46,
    SpfFail = 47,
    SpfNone = 48,
    SpfPass = 49,
    Strict = 50,
    Tls = 51,
    To = 52,
    Total = 53,
    TotalFailures = 54,
    TotalSuccesses = 55,
    Type = 56,
    Uid = 57,
    UidNext = 58,
    UidValidity = 59,
    Url = 60,
    ValidFrom = 61,
    ValidTo = 62,
    Value = 63,
    Version = 64,
    QueueName = 65,
    Name = 66,
    ObjectType = 67,
    Property = 68,
    NodeId = 69,
    RemoteNodeId = 70,
    TaskId = 71,
    Partition = 72,
    Index = 73,
    Attempt = 74,
    Used = 75,
    Period = 76,
    RetryAfter = 77,
    Command = 78,
    Tag = 79,
    Address = 80,
    Ip = 81,
    Headers = 82,
    Query = 83,
    Cipher = 84,
    ResourceUid = 85,
    Script = 86,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Model = 87,
    #[cfg(feature = "enterprise")]
    InputTokens = 88,
    #[cfg(feature = "enterprise")]
    OutputTokens = 89,
    #[cfg(feature = "enterprise")]
    CachedTokens = 90,
    #[cfg(feature = "enterprise")]
    FinishReason = 91,
    #[cfg(feature = "enterprise")]
    Category = 92,
    #[cfg(feature = "enterprise")]
    Probability = 93,
    #[cfg(feature = "enterprise")]
    Confidence = 94,
    #[cfg(feature = "enterprise")]
    Tier = 95,
    // SPDX-SnippetEnd
    Fingerprint = 96,
}
