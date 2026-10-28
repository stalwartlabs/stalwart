/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

use crate::{Level, event::enums::*};
use std::borrow::Cow;

impl EventType {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            EventType,
            b"acme.auth-start" => EventType::Acme(AcmeEvent::AuthStart),
            b"acme.auth-pending" => EventType::Acme(AcmeEvent::AuthPending),
            b"acme.auth-valid" => EventType::Acme(AcmeEvent::AuthValid),
            b"acme.auth-completed" => EventType::Acme(AcmeEvent::AuthCompleted),
            b"acme.auth-error" => EventType::Acme(AcmeEvent::AuthError),
            b"acme.auth-too-many-attempts" => EventType::Acme(AcmeEvent::AuthTooManyAttempts),
            b"acme.process-cert" => EventType::Acme(AcmeEvent::ProcessCert),
            b"acme.order-start" => EventType::Acme(AcmeEvent::OrderStart),
            b"acme.order-processing" => EventType::Acme(AcmeEvent::OrderProcessing),
            b"acme.order-completed" => EventType::Acme(AcmeEvent::OrderCompleted),
            b"acme.order-ready" => EventType::Acme(AcmeEvent::OrderReady),
            b"acme.order-valid" => EventType::Acme(AcmeEvent::OrderValid),
            b"acme.order-invalid" => EventType::Acme(AcmeEvent::OrderInvalid),
            b"acme.renew-backoff" => EventType::Acme(AcmeEvent::RenewBackoff),
            b"acme.client-supplied-sni" => EventType::Acme(AcmeEvent::ClientSuppliedSni),
            b"acme.client-missing-sni" => EventType::Acme(AcmeEvent::ClientMissingSni),
            b"acme.tls-alpn-received" => EventType::Acme(AcmeEvent::TlsAlpnReceived),
            b"acme.tls-alpn-error" => EventType::Acme(AcmeEvent::TlsAlpnError),
            b"acme.token-not-found" => EventType::Acme(AcmeEvent::TokenNotFound),
            b"acme.error" => EventType::Acme(AcmeEvent::Error),
            b"ai.llm-response" => EventType::Ai(AiEvent::LlmResponse),
            b"ai.api-error" => EventType::Ai(AiEvent::ApiError),
            b"ai.request" => EventType::Ai(AiEvent::Request),
            b"ai.spam-verdict" => EventType::Ai(AiEvent::SpamVerdict),
            b"ai.spam-skipped" => EventType::Ai(AiEvent::SpamSkipped),
            b"ai.breaker-open" => EventType::Ai(AiEvent::BreakerOpen),
            b"arc.chain-invalid" => EventType::Arc(ArcEvent::ChainInvalid),
            b"arc.signature-invalid" => EventType::Arc(ArcEvent::SignatureInvalid),
            b"arc.hash-mismatch" => EventType::Arc(ArcEvent::HashMismatch),
            b"auth.success" => EventType::Auth(AuthEvent::Success),
            b"auth.failed" => EventType::Auth(AuthEvent::Failed),
            b"auth.token-expired" => EventType::Auth(AuthEvent::TokenExpired),
            b"auth.mfa-required" => EventType::Auth(AuthEvent::MfaRequired),
            b"auth.too-many-attempts" => EventType::Auth(AuthEvent::TooManyAttempts),
            b"auth.client-registration" => EventType::Auth(AuthEvent::ClientRegistration),
            b"auth.error" => EventType::Auth(AuthEvent::Error),
            b"auth.warning" => EventType::Auth(AuthEvent::Warning),
            b"auth.credential-expired" => EventType::Auth(AuthEvent::CredentialExpired),
            b"cache.miss" => EventType::Cache(CacheEvent::Miss),
            b"cache.hit" => EventType::Cache(CacheEvent::Hit),
            b"cache.stale" => EventType::Cache(CacheEvent::Stale),
            b"cache.update" => EventType::Cache(CacheEvent::Update),
            b"cache.entry-too-large" => EventType::Cache(CacheEvent::EntryTooLarge),
            b"cache.invalidate" => EventType::Cache(CacheEvent::Invalidate),
            b"cache.swap-hit" => EventType::Cache(CacheEvent::SwapHit),
            b"cache.swap-miss" => EventType::Cache(CacheEvent::SwapMiss),
            b"cache.swap-write" => EventType::Cache(CacheEvent::SwapWrite),
            b"cache.swap-error" => EventType::Cache(CacheEvent::SwapError),
            b"cache.swap-metrics" => EventType::Cache(CacheEvent::SwapMetrics),
            b"cache.swap-flush" => EventType::Cache(CacheEvent::SwapFlush),
            b"calendar.rule-expansion-error" => EventType::Calendar(CalendarEvent::RuleExpansionError),
            b"calendar.alarm-sent" => EventType::Calendar(CalendarEvent::AlarmSent),
            b"calendar.alarm-skipped" => EventType::Calendar(CalendarEvent::AlarmSkipped),
            b"calendar.alarm-recipient-override" => EventType::Calendar(CalendarEvent::AlarmRecipientOverride),
            b"calendar.alarm-failed" => EventType::Calendar(CalendarEvent::AlarmFailed),
            b"calendar.itip-message-sent" => EventType::Calendar(CalendarEvent::ItipMessageSent),
            b"calendar.itip-message-received" => EventType::Calendar(CalendarEvent::ItipMessageReceived),
            b"calendar.itip-message-error" => EventType::Calendar(CalendarEvent::ItipMessageError),
            b"cluster.startup" => EventType::Cluster(ClusterEvent::Startup),
            b"cluster.subscriber-start" => EventType::Cluster(ClusterEvent::SubscriberStart),
            b"cluster.subscriber-stop" => EventType::Cluster(ClusterEvent::SubscriberStop),
            b"cluster.subscriber-error" => EventType::Cluster(ClusterEvent::SubscriberError),
            b"cluster.subscriber-disconnected" => EventType::Cluster(ClusterEvent::SubscriberDisconnected),
            b"cluster.publisher-start" => EventType::Cluster(ClusterEvent::PublisherStart),
            b"cluster.publisher-stop" => EventType::Cluster(ClusterEvent::PublisherStop),
            b"cluster.publisher-error" => EventType::Cluster(ClusterEvent::PublisherError),
            b"cluster.message-received" => EventType::Cluster(ClusterEvent::MessageReceived),
            b"cluster.message-skipped" => EventType::Cluster(ClusterEvent::MessageSkipped),
            b"cluster.message-invalid" => EventType::Cluster(ClusterEvent::MessageInvalid),
            b"cluster.node-id-renewed" => EventType::Cluster(ClusterEvent::NodeIdRenewed),
            b"dane.authentication-success" => EventType::Dane(DaneEvent::AuthenticationSuccess),
            b"dane.authentication-failure" => EventType::Dane(DaneEvent::AuthenticationFailure),
            b"dane.no-certificates-found" => EventType::Dane(DaneEvent::NoCertificatesFound),
            b"dane.certificate-parse-error" => EventType::Dane(DaneEvent::CertificateParseError),
            b"dane.tlsa-record-match" => EventType::Dane(DaneEvent::TlsaRecordMatch),
            b"dane.tlsa-record-fetch" => EventType::Dane(DaneEvent::TlsaRecordFetch),
            b"dane.tlsa-record-fetch-error" => EventType::Dane(DaneEvent::TlsaRecordFetchError),
            b"dane.tlsa-record-not-found" => EventType::Dane(DaneEvent::TlsaRecordNotFound),
            b"dane.tlsa-record-not-dnssec-signed" => EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned),
            b"dane.tlsa-record-invalid" => EventType::Dane(DaneEvent::TlsaRecordInvalid),
            b"dane.bogus-dnssec-record" => EventType::Dane(DaneEvent::BogusDnssecRecord),
            b"delivery.attempt-start" => EventType::Delivery(DeliveryEvent::AttemptStart),
            b"delivery.attempt-end" => EventType::Delivery(DeliveryEvent::AttemptEnd),
            b"delivery.completed" => EventType::Delivery(DeliveryEvent::Completed),
            b"delivery.failed" => EventType::Delivery(DeliveryEvent::Failed),
            b"delivery.domain-delivery-start" => EventType::Delivery(DeliveryEvent::DomainDeliveryStart),
            b"delivery.mx-lookup" => EventType::Delivery(DeliveryEvent::MxLookup),
            b"delivery.mx-lookup-failed" => EventType::Delivery(DeliveryEvent::MxLookupFailed),
            b"delivery.ip-lookup" => EventType::Delivery(DeliveryEvent::IpLookup),
            b"delivery.ip-lookup-failed" => EventType::Delivery(DeliveryEvent::IpLookupFailed),
            b"delivery.null-mx" => EventType::Delivery(DeliveryEvent::NullMx),
            b"delivery.connect" => EventType::Delivery(DeliveryEvent::Connect),
            b"delivery.connect-error" => EventType::Delivery(DeliveryEvent::ConnectError),
            b"delivery.missing-outbound-hostname" => EventType::Delivery(DeliveryEvent::MissingOutboundHostname),
            b"delivery.greeting-failed" => EventType::Delivery(DeliveryEvent::GreetingFailed),
            b"delivery.ehlo" => EventType::Delivery(DeliveryEvent::Ehlo),
            b"delivery.ehlo-rejected" => EventType::Delivery(DeliveryEvent::EhloRejected),
            b"delivery.auth" => EventType::Delivery(DeliveryEvent::Auth),
            b"delivery.auth-failed" => EventType::Delivery(DeliveryEvent::AuthFailed),
            b"delivery.mail-from" => EventType::Delivery(DeliveryEvent::MailFrom),
            b"delivery.mail-from-rejected" => EventType::Delivery(DeliveryEvent::MailFromRejected),
            b"delivery.delivered" => EventType::Delivery(DeliveryEvent::Delivered),
            b"delivery.rcpt-to" => EventType::Delivery(DeliveryEvent::RcptTo),
            b"delivery.rcpt-to-rejected" => EventType::Delivery(DeliveryEvent::RcptToRejected),
            b"delivery.rcpt-to-failed" => EventType::Delivery(DeliveryEvent::RcptToFailed),
            b"delivery.message-rejected" => EventType::Delivery(DeliveryEvent::MessageRejected),
            b"delivery.start-tls" => EventType::Delivery(DeliveryEvent::StartTls),
            b"delivery.start-tls-unavailable" => EventType::Delivery(DeliveryEvent::StartTlsUnavailable),
            b"delivery.start-tls-error" => EventType::Delivery(DeliveryEvent::StartTlsError),
            b"delivery.start-tls-disabled" => EventType::Delivery(DeliveryEvent::StartTlsDisabled),
            b"delivery.implicit-tls-error" => EventType::Delivery(DeliveryEvent::ImplicitTlsError),
            b"delivery.concurrency-limit-exceeded" => EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded),
            b"delivery.rate-limit-exceeded" => EventType::Delivery(DeliveryEvent::RateLimitExceeded),
            b"delivery.double-bounce" => EventType::Delivery(DeliveryEvent::DoubleBounce),
            b"delivery.dsn-success" => EventType::Delivery(DeliveryEvent::DsnSuccess),
            b"delivery.dsn-temp-fail" => EventType::Delivery(DeliveryEvent::DsnTempFail),
            b"delivery.dsn-perm-fail" => EventType::Delivery(DeliveryEvent::DsnPermFail),
            b"delivery.raw-input" => EventType::Delivery(DeliveryEvent::RawInput),
            b"delivery.raw-output" => EventType::Delivery(DeliveryEvent::RawOutput),
            b"dkim.pass" => EventType::Dkim(DkimEvent::Pass),
            b"dkim.neutral" => EventType::Dkim(DkimEvent::Neutral),
            b"dkim.fail" => EventType::Dkim(DkimEvent::Fail),
            b"dkim.perm-error" => EventType::Dkim(DkimEvent::PermError),
            b"dkim.temp-error" => EventType::Dkim(DkimEvent::TempError),
            b"dkim.none" => EventType::Dkim(DkimEvent::None),
            b"dkim.signature-invalid" => EventType::Dkim(DkimEvent::SignatureInvalid),
            b"dkim.public-key-error" => EventType::Dkim(DkimEvent::PublicKeyError),
            b"dkim.verification-failed" => EventType::Dkim(DkimEvent::VerificationFailed),
            b"dkim.hash-mismatch" => EventType::Dkim(DkimEvent::HashMismatch),
            b"dkim.signer-not-found" => EventType::Dkim(DkimEvent::SignerNotFound),
            b"dkim.build-error" => EventType::Dkim(DkimEvent::BuildError),
            b"dkim.signature-created" => EventType::Dkim(DkimEvent::SignatureCreated),
            b"dkim.signature-published" => EventType::Dkim(DkimEvent::SignaturePublished),
            b"dkim.signature-retiring" => EventType::Dkim(DkimEvent::SignatureRetiring),
            b"dkim.signature-retired" => EventType::Dkim(DkimEvent::SignatureRetired),
            b"dkim.signature-deleted" => EventType::Dkim(DkimEvent::SignatureDeleted),
            b"dkim2.instance-invalid" => EventType::Dkim2(Dkim2Event::InstanceInvalid),
            b"dkim2.signature-invalid" => EventType::Dkim2(Dkim2Event::SignatureInvalid),
            b"dkim2.chain-invalid" => EventType::Dkim2(Dkim2Event::ChainInvalid),
            b"dkim2.timestamp-invalid" => EventType::Dkim2(Dkim2Event::TimestampInvalid),
            b"dkim2.envelope-mismatch" => EventType::Dkim2(Dkim2Event::EnvelopeMismatch),
            b"dkim2.custody-broken" => EventType::Dkim2(Dkim2Event::CustodyBroken),
            b"dkim2.public-key-error" => EventType::Dkim2(Dkim2Event::PublicKeyError),
            b"dkim2.verification-failed" => EventType::Dkim2(Dkim2Event::VerificationFailed),
            b"dkim2.hash-mismatch" => EventType::Dkim2(Dkim2Event::HashMismatch),
            b"dkim2.recipe-error" => EventType::Dkim2(Dkim2Event::RecipeError),
            b"dkim2.signing-failed" => EventType::Dkim2(Dkim2Event::SigningFailed),
            b"dmarc.pass" => EventType::Dmarc(DmarcEvent::Pass),
            b"dmarc.fail" => EventType::Dmarc(DmarcEvent::Fail),
            b"dmarc.perm-error" => EventType::Dmarc(DmarcEvent::PermError),
            b"dmarc.temp-error" => EventType::Dmarc(DmarcEvent::TempError),
            b"dmarc.none" => EventType::Dmarc(DmarcEvent::None),
            b"dns.record-created" => EventType::Dns(DnsEvent::RecordCreated),
            b"dns.record-creation-failed" => EventType::Dns(DnsEvent::RecordCreationFailed),
            b"dns.record-deletion-failed" => EventType::Dns(DnsEvent::RecordDeletionFailed),
            b"dns.record-not-propagated" => EventType::Dns(DnsEvent::RecordNotPropagated),
            b"dns.record-lookup-failed" => EventType::Dns(DnsEvent::RecordLookupFailed),
            b"dns.record-propagated" => EventType::Dns(DnsEvent::RecordPropagated),
            b"dns.record-propagation-timeout" => EventType::Dns(DnsEvent::RecordPropagationTimeout),
            b"eval.result" => EventType::Eval(EvalEvent::Result),
            b"eval.error" => EventType::Eval(EvalEvent::Error),
            b"eval.directory-not-found" => EventType::Eval(EvalEvent::DirectoryNotFound),
            b"eval.store-not-found" => EventType::Eval(EvalEvent::StoreNotFound),
            b"http.connection-start" => EventType::Http(HttpEvent::ConnectionStart),
            b"http.connection-end" => EventType::Http(HttpEvent::ConnectionEnd),
            b"http.error" => EventType::Http(HttpEvent::Error),
            b"http.request-url" => EventType::Http(HttpEvent::RequestUrl),
            b"http.request-body" => EventType::Http(HttpEvent::RequestBody),
            b"http.response-body" => EventType::Http(HttpEvent::ResponseBody),
            b"http.x-forwarded-missing" => EventType::Http(HttpEvent::XForwardedMissing),
            b"http.x-forwarded-invalid" => EventType::Http(HttpEvent::XForwardedInvalid),
            b"imap.connection-start" => EventType::Imap(ImapEvent::ConnectionStart),
            b"imap.connection-end" => EventType::Imap(ImapEvent::ConnectionEnd),
            b"imap.get-acl" => EventType::Imap(ImapEvent::GetAcl),
            b"imap.set-acl" => EventType::Imap(ImapEvent::SetAcl),
            b"imap.my-rights" => EventType::Imap(ImapEvent::MyRights),
            b"imap.list-rights" => EventType::Imap(ImapEvent::ListRights),
            b"imap.append" => EventType::Imap(ImapEvent::Append),
            b"imap.capabilities" => EventType::Imap(ImapEvent::Capabilities),
            b"imap.id" => EventType::Imap(ImapEvent::Id),
            b"imap.close" => EventType::Imap(ImapEvent::Close),
            b"imap.copy" => EventType::Imap(ImapEvent::Copy),
            b"imap.move" => EventType::Imap(ImapEvent::Move),
            b"imap.create-mailbox" => EventType::Imap(ImapEvent::CreateMailbox),
            b"imap.delete-mailbox" => EventType::Imap(ImapEvent::DeleteMailbox),
            b"imap.rename-mailbox" => EventType::Imap(ImapEvent::RenameMailbox),
            b"imap.enable" => EventType::Imap(ImapEvent::Enable),
            b"imap.expunge" => EventType::Imap(ImapEvent::Expunge),
            b"imap.fetch" => EventType::Imap(ImapEvent::Fetch),
            b"imap.idle-start" => EventType::Imap(ImapEvent::IdleStart),
            b"imap.idle-stop" => EventType::Imap(ImapEvent::IdleStop),
            b"imap.list" => EventType::Imap(ImapEvent::List),
            b"imap.lsub" => EventType::Imap(ImapEvent::Lsub),
            b"imap.logout" => EventType::Imap(ImapEvent::Logout),
            b"imap.namespace" => EventType::Imap(ImapEvent::Namespace),
            b"imap.noop" => EventType::Imap(ImapEvent::Noop),
            b"imap.search" => EventType::Imap(ImapEvent::Search),
            b"imap.sort" => EventType::Imap(ImapEvent::Sort),
            b"imap.select" => EventType::Imap(ImapEvent::Select),
            b"imap.status" => EventType::Imap(ImapEvent::Status),
            b"imap.store" => EventType::Imap(ImapEvent::Store),
            b"imap.subscribe" => EventType::Imap(ImapEvent::Subscribe),
            b"imap.unsubscribe" => EventType::Imap(ImapEvent::Unsubscribe),
            b"imap.thread" => EventType::Imap(ImapEvent::Thread),
            b"imap.uid-batches" => EventType::Imap(ImapEvent::UidBatches),
            b"imap.get-quota" => EventType::Imap(ImapEvent::GetQuota),
            b"imap.get-metadata" => EventType::Imap(ImapEvent::GetMetadata),
            b"imap.set-metadata" => EventType::Imap(ImapEvent::SetMetadata),
            b"imap.error" => EventType::Imap(ImapEvent::Error),
            b"imap.raw-input" => EventType::Imap(ImapEvent::RawInput),
            b"imap.raw-output" => EventType::Imap(ImapEvent::RawOutput),
            b"incoming-report.dmarc-report" => EventType::IncomingReport(IncomingReportEvent::DmarcReport),
            b"incoming-report.dmarc-report-with-warnings" => EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings),
            b"incoming-report.tls-report" => EventType::IncomingReport(IncomingReportEvent::TlsReport),
            b"incoming-report.tls-report-with-warnings" => EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings),
            b"incoming-report.abuse-report" => EventType::IncomingReport(IncomingReportEvent::AbuseReport),
            b"incoming-report.auth-failure-report" => EventType::IncomingReport(IncomingReportEvent::AuthFailureReport),
            b"incoming-report.fraud-report" => EventType::IncomingReport(IncomingReportEvent::FraudReport),
            b"incoming-report.not-spam-report" => EventType::IncomingReport(IncomingReportEvent::NotSpamReport),
            b"incoming-report.virus-report" => EventType::IncomingReport(IncomingReportEvent::VirusReport),
            b"incoming-report.other-report" => EventType::IncomingReport(IncomingReportEvent::OtherReport),
            b"incoming-report.message-parse-failed" => EventType::IncomingReport(IncomingReportEvent::MessageParseFailed),
            b"incoming-report.dmarc-parse-failed" => EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed),
            b"incoming-report.tls-rpc-parse-failed" => EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed),
            b"incoming-report.arf-parse-failed" => EventType::IncomingReport(IncomingReportEvent::ArfParseFailed),
            b"incoming-report.decompress-error" => EventType::IncomingReport(IncomingReportEvent::DecompressError),
            b"iprev.pass" => EventType::Iprev(IprevEvent::Pass),
            b"iprev.fail" => EventType::Iprev(IprevEvent::Fail),
            b"iprev.perm-error" => EventType::Iprev(IprevEvent::PermError),
            b"iprev.temp-error" => EventType::Iprev(IprevEvent::TempError),
            b"iprev.none" => EventType::Iprev(IprevEvent::None),
            b"jmap.method-call" => EventType::Jmap(JmapEvent::MethodCall),
            b"jmap.invalid-arguments" => EventType::Jmap(JmapEvent::InvalidArguments),
            b"jmap.request-too-large" => EventType::Jmap(JmapEvent::RequestTooLarge),
            b"jmap.state-mismatch" => EventType::Jmap(JmapEvent::StateMismatch),
            b"jmap.anchor-not-found" => EventType::Jmap(JmapEvent::AnchorNotFound),
            b"jmap.unsupported-filter" => EventType::Jmap(JmapEvent::UnsupportedFilter),
            b"jmap.unsupported-sort" => EventType::Jmap(JmapEvent::UnsupportedSort),
            b"jmap.unknown-method" => EventType::Jmap(JmapEvent::UnknownMethod),
            b"jmap.invalid-result-reference" => EventType::Jmap(JmapEvent::InvalidResultReference),
            b"jmap.forbidden" => EventType::Jmap(JmapEvent::Forbidden),
            b"jmap.account-not-found" => EventType::Jmap(JmapEvent::AccountNotFound),
            b"jmap.account-not-supported-by-method" => EventType::Jmap(JmapEvent::AccountNotSupportedByMethod),
            b"jmap.account-read-only" => EventType::Jmap(JmapEvent::AccountReadOnly),
            b"jmap.from-account-not-found" => EventType::Jmap(JmapEvent::FromAccountNotFound),
            b"jmap.from-account-not-supported-by-method" => EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod),
            b"jmap.not-found" => EventType::Jmap(JmapEvent::NotFound),
            b"jmap.cannot-calculate-changes" => EventType::Jmap(JmapEvent::CannotCalculateChanges),
            b"jmap.unknown-data-type" => EventType::Jmap(JmapEvent::UnknownDataType),
            b"jmap.unknown-capability" => EventType::Jmap(JmapEvent::UnknownCapability),
            b"jmap.not-json" => EventType::Jmap(JmapEvent::NotJson),
            b"jmap.not-request" => EventType::Jmap(JmapEvent::NotRequest),
            b"jmap.websocket-start" => EventType::Jmap(JmapEvent::WebsocketStart),
            b"jmap.websocket-stop" => EventType::Jmap(JmapEvent::WebsocketStop),
            b"jmap.websocket-error" => EventType::Jmap(JmapEvent::WebsocketError),
            b"jmap.expand-duration-too-large" => EventType::Jmap(JmapEvent::ExpandDurationTooLarge),
            b"jmap.cannot-calculate-occurrences" => EventType::Jmap(JmapEvent::CannotCalculateOccurrences),
            b"jmap.too-large" => EventType::Jmap(JmapEvent::TooLarge),
            b"jmap.rate-limit" => EventType::Jmap(JmapEvent::RateLimit),
            b"jmap.object-not-found" => EventType::Jmap(JmapEvent::ObjectNotFound),
            b"limit.size-request" => EventType::Limit(LimitEvent::SizeRequest),
            b"limit.size-upload" => EventType::Limit(LimitEvent::SizeUpload),
            b"limit.calls-in" => EventType::Limit(LimitEvent::CallsIn),
            b"limit.concurrent-request" => EventType::Limit(LimitEvent::ConcurrentRequest),
            b"limit.concurrent-upload" => EventType::Limit(LimitEvent::ConcurrentUpload),
            b"limit.concurrent-connection" => EventType::Limit(LimitEvent::ConcurrentConnection),
            b"limit.quota" => EventType::Limit(LimitEvent::Quota),
            b"limit.blob-quota" => EventType::Limit(LimitEvent::BlobQuota),
            b"limit.tenant-quota" => EventType::Limit(LimitEvent::TenantQuota),
            b"limit.too-many-requests" => EventType::Limit(LimitEvent::TooManyRequests),
            b"limit.memory-budget" => EventType::Limit(LimitEvent::MemoryBudget),
            b"mail-auth.parse-error" => EventType::MailAuth(MailAuthEvent::ParseError),
            b"mail-auth.missing-parameters" => EventType::MailAuth(MailAuthEvent::MissingParameters),
            b"mail-auth.no-headers-found" => EventType::MailAuth(MailAuthEvent::NoHeadersFound),
            b"mail-auth.crypto" => EventType::MailAuth(MailAuthEvent::Crypto),
            b"mail-auth.io" => EventType::MailAuth(MailAuthEvent::Io),
            b"mail-auth.base64" => EventType::MailAuth(MailAuthEvent::Base64),
            b"mail-auth.dns-error" => EventType::MailAuth(MailAuthEvent::DnsError),
            b"mail-auth.dns-record-not-found" => EventType::MailAuth(MailAuthEvent::DnsRecordNotFound),
            b"mail-auth.dns-invalid-record-type" => EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType),
            b"mail-auth.policy-not-aligned" => EventType::MailAuth(MailAuthEvent::PolicyNotAligned),
            b"manage-sieve.connection-start" => EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
            b"manage-sieve.connection-end" => EventType::ManageSieve(ManageSieveEvent::ConnectionEnd),
            b"manage-sieve.create-script" => EventType::ManageSieve(ManageSieveEvent::CreateScript),
            b"manage-sieve.update-script" => EventType::ManageSieve(ManageSieveEvent::UpdateScript),
            b"manage-sieve.get-script" => EventType::ManageSieve(ManageSieveEvent::GetScript),
            b"manage-sieve.delete-script" => EventType::ManageSieve(ManageSieveEvent::DeleteScript),
            b"manage-sieve.rename-script" => EventType::ManageSieve(ManageSieveEvent::RenameScript),
            b"manage-sieve.check-script" => EventType::ManageSieve(ManageSieveEvent::CheckScript),
            b"manage-sieve.have-space" => EventType::ManageSieve(ManageSieveEvent::HaveSpace),
            b"manage-sieve.list-scripts" => EventType::ManageSieve(ManageSieveEvent::ListScripts),
            b"manage-sieve.set-active" => EventType::ManageSieve(ManageSieveEvent::SetActive),
            b"manage-sieve.capabilities" => EventType::ManageSieve(ManageSieveEvent::Capabilities),
            b"manage-sieve.start-tls" => EventType::ManageSieve(ManageSieveEvent::StartTls),
            b"manage-sieve.unauthenticate" => EventType::ManageSieve(ManageSieveEvent::Unauthenticate),
            b"manage-sieve.logout" => EventType::ManageSieve(ManageSieveEvent::Logout),
            b"manage-sieve.noop" => EventType::ManageSieve(ManageSieveEvent::Noop),
            b"manage-sieve.error" => EventType::ManageSieve(ManageSieveEvent::Error),
            b"manage-sieve.raw-input" => EventType::ManageSieve(ManageSieveEvent::RawInput),
            b"manage-sieve.raw-output" => EventType::ManageSieve(ManageSieveEvent::RawOutput),
            b"message-ingest.ham" => EventType::MessageIngest(MessageIngestEvent::Ham),
            b"message-ingest.spam" => EventType::MessageIngest(MessageIngestEvent::Spam),
            b"message-ingest.imap-append" => EventType::MessageIngest(MessageIngestEvent::ImapAppend),
            b"message-ingest.jmap-append" => EventType::MessageIngest(MessageIngestEvent::JmapAppend),
            b"message-ingest.duplicate" => EventType::MessageIngest(MessageIngestEvent::Duplicate),
            b"message-ingest.error" => EventType::MessageIngest(MessageIngestEvent::Error),
            b"milter.read" => EventType::Milter(MilterEvent::Read),
            b"milter.write" => EventType::Milter(MilterEvent::Write),
            b"milter.action-accept" => EventType::Milter(MilterEvent::ActionAccept),
            b"milter.action-discard" => EventType::Milter(MilterEvent::ActionDiscard),
            b"milter.action-reject" => EventType::Milter(MilterEvent::ActionReject),
            b"milter.action-temp-fail" => EventType::Milter(MilterEvent::ActionTempFail),
            b"milter.action-reply-code" => EventType::Milter(MilterEvent::ActionReplyCode),
            b"milter.action-connection-failure" => EventType::Milter(MilterEvent::ActionConnectionFailure),
            b"milter.action-shutdown" => EventType::Milter(MilterEvent::ActionShutdown),
            b"milter.io-error" => EventType::Milter(MilterEvent::IoError),
            b"milter.frame-too-large" => EventType::Milter(MilterEvent::FrameTooLarge),
            b"milter.frame-invalid" => EventType::Milter(MilterEvent::FrameInvalid),
            b"milter.unexpected-response" => EventType::Milter(MilterEvent::UnexpectedResponse),
            b"milter.timeout" => EventType::Milter(MilterEvent::Timeout),
            b"milter.tls-invalid-name" => EventType::Milter(MilterEvent::TlsInvalidName),
            b"milter.disconnected" => EventType::Milter(MilterEvent::Disconnected),
            b"milter.parse-error" => EventType::Milter(MilterEvent::ParseError),
            b"mta-hook.action-accept" => EventType::MtaHook(MtaHookEvent::ActionAccept),
            b"mta-hook.action-discard" => EventType::MtaHook(MtaHookEvent::ActionDiscard),
            b"mta-hook.action-reject" => EventType::MtaHook(MtaHookEvent::ActionReject),
            b"mta-hook.action-quarantine" => EventType::MtaHook(MtaHookEvent::ActionQuarantine),
            b"mta-hook.error" => EventType::MtaHook(MtaHookEvent::Error),
            b"mta-sts.authorized" => EventType::MtaSts(MtaStsEvent::Authorized),
            b"mta-sts.not-authorized" => EventType::MtaSts(MtaStsEvent::NotAuthorized),
            b"mta-sts.policy-fetch" => EventType::MtaSts(MtaStsEvent::PolicyFetch),
            b"mta-sts.policy-not-found" => EventType::MtaSts(MtaStsEvent::PolicyNotFound),
            b"mta-sts.policy-fetch-error" => EventType::MtaSts(MtaStsEvent::PolicyFetchError),
            b"mta-sts.invalid-policy" => EventType::MtaSts(MtaStsEvent::InvalidPolicy),
            b"network.listen-start" => EventType::Network(NetworkEvent::ListenStart),
            b"network.listen-stop" => EventType::Network(NetworkEvent::ListenStop),
            b"network.listen-error" => EventType::Network(NetworkEvent::ListenError),
            b"network.bind-error" => EventType::Network(NetworkEvent::BindError),
            b"network.read-error" => EventType::Network(NetworkEvent::ReadError),
            b"network.write-error" => EventType::Network(NetworkEvent::WriteError),
            b"network.flush-error" => EventType::Network(NetworkEvent::FlushError),
            b"network.accept-error" => EventType::Network(NetworkEvent::AcceptError),
            b"network.split-error" => EventType::Network(NetworkEvent::SplitError),
            b"network.timeout" => EventType::Network(NetworkEvent::Timeout),
            b"network.closed" => EventType::Network(NetworkEvent::Closed),
            b"network.proxy-error" => EventType::Network(NetworkEvent::ProxyError),
            b"network.set-opt-error" => EventType::Network(NetworkEvent::SetOptError),
            b"outgoing-report.spf-report" => EventType::OutgoingReport(OutgoingReportEvent::SpfReport),
            b"outgoing-report.spf-rate-limited" => EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited),
            b"outgoing-report.dkim-report" => EventType::OutgoingReport(OutgoingReportEvent::DkimReport),
            b"outgoing-report.dkim-rate-limited" => EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited),
            b"outgoing-report.dmarc-report" => EventType::OutgoingReport(OutgoingReportEvent::DmarcReport),
            b"outgoing-report.dmarc-rate-limited" => EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited),
            b"outgoing-report.dmarc-aggregate-report" => EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport),
            b"outgoing-report.tls-aggregate" => EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate),
            b"outgoing-report.http-submission" => EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission),
            b"outgoing-report.unauthorized-reporting-address" => EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
            b"outgoing-report.reporting-address-validation-error" => EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError),
            b"outgoing-report.not-found" => EventType::OutgoingReport(OutgoingReportEvent::NotFound),
            b"outgoing-report.submission-error" => EventType::OutgoingReport(OutgoingReportEvent::SubmissionError),
            b"outgoing-report.no-recipients-found" => EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound),
            b"outgoing-report.locked" => EventType::OutgoingReport(OutgoingReportEvent::Locked),
            b"outgoing-report.max-size-exceeded" => EventType::OutgoingReport(OutgoingReportEvent::MaxSizeExceeded),
            b"pop3.connection-start" => EventType::Pop3(Pop3Event::ConnectionStart),
            b"pop3.connection-end" => EventType::Pop3(Pop3Event::ConnectionEnd),
            b"pop3.delete" => EventType::Pop3(Pop3Event::Delete),
            b"pop3.reset" => EventType::Pop3(Pop3Event::Reset),
            b"pop3.quit" => EventType::Pop3(Pop3Event::Quit),
            b"pop3.fetch" => EventType::Pop3(Pop3Event::Fetch),
            b"pop3.list" => EventType::Pop3(Pop3Event::List),
            b"pop3.list-message" => EventType::Pop3(Pop3Event::ListMessage),
            b"pop3.uidl" => EventType::Pop3(Pop3Event::Uidl),
            b"pop3.uidl-message" => EventType::Pop3(Pop3Event::UidlMessage),
            b"pop3.stat" => EventType::Pop3(Pop3Event::Stat),
            b"pop3.noop" => EventType::Pop3(Pop3Event::Noop),
            b"pop3.capabilities" => EventType::Pop3(Pop3Event::Capabilities),
            b"pop3.start-tls" => EventType::Pop3(Pop3Event::StartTls),
            b"pop3.utf8" => EventType::Pop3(Pop3Event::Utf8),
            b"pop3.error" => EventType::Pop3(Pop3Event::Error),
            b"pop3.raw-input" => EventType::Pop3(Pop3Event::RawInput),
            b"pop3.raw-output" => EventType::Pop3(Pop3Event::RawOutput),
            b"push-subscription.success" => EventType::PushSubscription(PushSubscriptionEvent::Success),
            b"push-subscription.error" => EventType::PushSubscription(PushSubscriptionEvent::Error),
            b"push-subscription.not-found" => EventType::PushSubscription(PushSubscriptionEvent::NotFound),
            b"queue.started" => EventType::Queue(QueueEvent::Started),
            b"queue.message-queued" => EventType::Queue(QueueEvent::MessageQueued),
            b"queue.authenticated-message-queued" => EventType::Queue(QueueEvent::AuthenticatedMessageQueued),
            b"queue.report-queued" => EventType::Queue(QueueEvent::ReportQueued),
            b"queue.dsn-queued" => EventType::Queue(QueueEvent::DsnQueued),
            b"queue.autogenerated-queued" => EventType::Queue(QueueEvent::AutogeneratedQueued),
            b"queue.rescheduled" => EventType::Queue(QueueEvent::Rescheduled),
            b"queue.locked" => EventType::Queue(QueueEvent::Locked),
            b"queue.blob-not-found" => EventType::Queue(QueueEvent::BlobNotFound),
            b"queue.rate-limit-exceeded" => EventType::Queue(QueueEvent::RateLimitExceeded),
            b"queue.concurrency-limit-exceeded" => EventType::Queue(QueueEvent::ConcurrencyLimitExceeded),
            b"queue.quota-exceeded" => EventType::Queue(QueueEvent::QuotaExceeded),
            b"queue.back-pressure" => EventType::Queue(QueueEvent::BackPressure),
            b"registry.local-read-error" => EventType::Registry(RegistryEvent::LocalReadError),
            b"registry.local-write-error" => EventType::Registry(RegistryEvent::LocalWriteError),
            b"registry.local-parse-error" => EventType::Registry(RegistryEvent::LocalParseError),
            b"registry.read-error" => EventType::Registry(RegistryEvent::ReadError),
            b"registry.write-error" => EventType::Registry(RegistryEvent::WriteError),
            b"registry.deserialization-error" => EventType::Registry(RegistryEvent::DeserializationError),
            b"registry.build-error" => EventType::Registry(RegistryEvent::BuildError),
            b"registry.build-warning" => EventType::Registry(RegistryEvent::BuildWarning),
            b"registry.not-supported" => EventType::Registry(RegistryEvent::NotSupported),
            b"registry.validation-error" => EventType::Registry(RegistryEvent::ValidationError),
            b"resource.not-found" => EventType::Resource(ResourceEvent::NotFound),
            b"resource.bad-parameters" => EventType::Resource(ResourceEvent::BadParameters),
            b"resource.error" => EventType::Resource(ResourceEvent::Error),
            b"resource.download-external" => EventType::Resource(ResourceEvent::DownloadExternal),
            b"resource.application-updated" => EventType::Resource(ResourceEvent::ApplicationUpdated),
            b"resource.application-unpacked" => EventType::Resource(ResourceEvent::ApplicationUnpacked),
            b"scim.request" => EventType::Scim(ScimEvent::Request),
            b"scim.forbidden" => EventType::Scim(ScimEvent::Forbidden),
            b"scim.conflict" => EventType::Scim(ScimEvent::Conflict),
            b"scim.error" => EventType::Scim(ScimEvent::Error),
            b"scim.resource-created" => EventType::Scim(ScimEvent::ResourceCreated),
            b"scim.resource-updated" => EventType::Scim(ScimEvent::ResourceUpdated),
            b"scim.resource-deleted" => EventType::Scim(ScimEvent::ResourceDeleted),
            b"scim.query" => EventType::Scim(ScimEvent::Query),
            b"scim.bulk-processed" => EventType::Scim(ScimEvent::BulkProcessed),
            b"scim.bulk-aborted" => EventType::Scim(ScimEvent::BulkAborted),
            b"scim.rollback-failed" => EventType::Scim(ScimEvent::RollbackFailed),
            b"scim.attribute-ignored" => EventType::Scim(ScimEvent::AttributeIgnored),
            b"search-index.manager-started" => EventType::SearchIndex(SearchIndexEvent::ManagerStarted),
            b"search-index.partitions-acquired" => EventType::SearchIndex(SearchIndexEvent::PartitionsAcquired),
            b"search-index.partition-locked" => EventType::SearchIndex(SearchIndexEvent::PartitionLocked),
            b"search-index.partition-retry" => EventType::SearchIndex(SearchIndexEvent::PartitionRetry),
            b"search-index.batch-indexed" => EventType::SearchIndex(SearchIndexEvent::BatchIndexed),
            b"search-index.document-ignored" => EventType::SearchIndex(SearchIndexEvent::DocumentIgnored),
            b"search-index.document-truncated" => EventType::SearchIndex(SearchIndexEvent::DocumentTruncated),
            b"search-index.metadata-not-found" => EventType::SearchIndex(SearchIndexEvent::MetadataNotFound),
            b"security.authentication-ban" => EventType::Security(SecurityEvent::AuthenticationBan),
            b"security.abuse-ban" => EventType::Security(SecurityEvent::AbuseBan),
            b"security.scan-ban" => EventType::Security(SecurityEvent::ScanBan),
            b"security.loiter-ban" => EventType::Security(SecurityEvent::LoiterBan),
            b"security.ip-blocked" => EventType::Security(SecurityEvent::IpBlocked),
            b"security.ip-block-expired" => EventType::Security(SecurityEvent::IpBlockExpired),
            b"security.ip-allow-expired" => EventType::Security(SecurityEvent::IpAllowExpired),
            b"security.ip-unauthorized" => EventType::Security(SecurityEvent::IpUnauthorized),
            b"security.unauthorized" => EventType::Security(SecurityEvent::Unauthorized),
            b"server.startup" => EventType::Server(ServerEvent::Startup),
            b"server.shutdown" => EventType::Server(ServerEvent::Shutdown),
            b"server.startup-error" => EventType::Server(ServerEvent::StartupError),
            b"server.thread-error" => EventType::Server(ServerEvent::ThreadError),
            b"server.licensing" => EventType::Server(ServerEvent::Licensing),
            b"server.recovery-mode" => EventType::Server(ServerEvent::RecoveryMode),
            b"server.bootstrap-mode" => EventType::Server(ServerEvent::BootstrapMode),
            b"sieve.action-accept" => EventType::Sieve(SieveEvent::ActionAccept),
            b"sieve.action-accept-replace" => EventType::Sieve(SieveEvent::ActionAcceptReplace),
            b"sieve.action-discard" => EventType::Sieve(SieveEvent::ActionDiscard),
            b"sieve.action-reject" => EventType::Sieve(SieveEvent::ActionReject),
            b"sieve.send-message" => EventType::Sieve(SieveEvent::SendMessage),
            b"sieve.message-too-large" => EventType::Sieve(SieveEvent::MessageTooLarge),
            b"sieve.script-not-found" => EventType::Sieve(SieveEvent::ScriptNotFound),
            b"sieve.list-not-found" => EventType::Sieve(SieveEvent::ListNotFound),
            b"sieve.runtime-error" => EventType::Sieve(SieveEvent::RuntimeError),
            b"sieve.unexpected-error" => EventType::Sieve(SieveEvent::UnexpectedError),
            b"sieve.not-supported" => EventType::Sieve(SieveEvent::NotSupported),
            b"sieve.quota-exceeded" => EventType::Sieve(SieveEvent::QuotaExceeded),
            b"smtp.connection-start" => EventType::Smtp(SmtpEvent::ConnectionStart),
            b"smtp.connection-end" => EventType::Smtp(SmtpEvent::ConnectionEnd),
            b"smtp.error" => EventType::Smtp(SmtpEvent::Error),
            b"smtp.id-not-found" => EventType::Smtp(SmtpEvent::IdNotFound),
            b"smtp.concurrency-limit-exceeded" => EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded),
            b"smtp.transfer-limit-exceeded" => EventType::Smtp(SmtpEvent::TransferLimitExceeded),
            b"smtp.rate-limit-exceeded" => EventType::Smtp(SmtpEvent::RateLimitExceeded),
            b"smtp.time-limit-exceeded" => EventType::Smtp(SmtpEvent::TimeLimitExceeded),
            b"smtp.message-parse-failed" => EventType::Smtp(SmtpEvent::MessageParseFailed),
            b"smtp.message-too-large" => EventType::Smtp(SmtpEvent::MessageTooLarge),
            b"smtp.loop-detected" => EventType::Smtp(SmtpEvent::LoopDetected),
            b"smtp.multiple-from-domains" => EventType::Smtp(SmtpEvent::MultipleFromDomains),
            b"smtp.dkim-pass" => EventType::Smtp(SmtpEvent::DkimPass),
            b"smtp.dkim-fail" => EventType::Smtp(SmtpEvent::DkimFail),
            b"smtp.dkim2-pass" => EventType::Smtp(SmtpEvent::Dkim2Pass),
            b"smtp.dkim2-fail" => EventType::Smtp(SmtpEvent::Dkim2Fail),
            b"smtp.dkim2-dsn-rejected" => EventType::Smtp(SmtpEvent::Dkim2DsnRejected),
            b"smtp.arc-pass" => EventType::Smtp(SmtpEvent::ArcPass),
            b"smtp.arc-fail" => EventType::Smtp(SmtpEvent::ArcFail),
            b"smtp.spf-ehlo-pass" => EventType::Smtp(SmtpEvent::SpfEhloPass),
            b"smtp.spf-ehlo-fail" => EventType::Smtp(SmtpEvent::SpfEhloFail),
            b"smtp.spf-from-pass" => EventType::Smtp(SmtpEvent::SpfFromPass),
            b"smtp.spf-from-fail" => EventType::Smtp(SmtpEvent::SpfFromFail),
            b"smtp.dmarc-pass" => EventType::Smtp(SmtpEvent::DmarcPass),
            b"smtp.dmarc-fail" => EventType::Smtp(SmtpEvent::DmarcFail),
            b"smtp.iprev-pass" => EventType::Smtp(SmtpEvent::IprevPass),
            b"smtp.iprev-fail" => EventType::Smtp(SmtpEvent::IprevFail),
            b"smtp.too-many-messages" => EventType::Smtp(SmtpEvent::TooManyMessages),
            b"smtp.ehlo" => EventType::Smtp(SmtpEvent::Ehlo),
            b"smtp.invalid-ehlo" => EventType::Smtp(SmtpEvent::InvalidEhlo),
            b"smtp.did-not-say-ehlo" => EventType::Smtp(SmtpEvent::DidNotSayEhlo),
            b"smtp.ehlo-expected" => EventType::Smtp(SmtpEvent::EhloExpected),
            b"smtp.lhlo-expected" => EventType::Smtp(SmtpEvent::LhloExpected),
            b"smtp.mail-from-unauthenticated" => EventType::Smtp(SmtpEvent::MailFromUnauthenticated),
            b"smtp.mail-from-unauthorized" => EventType::Smtp(SmtpEvent::MailFromUnauthorized),
            b"smtp.mail-from-not-allowed" => EventType::Smtp(SmtpEvent::MailFromNotAllowed),
            b"smtp.mail-from-rewritten" => EventType::Smtp(SmtpEvent::MailFromRewritten),
            b"smtp.mail-from-missing" => EventType::Smtp(SmtpEvent::MailFromMissing),
            b"smtp.mail-from" => EventType::Smtp(SmtpEvent::MailFrom),
            b"smtp.multiple-mail-from" => EventType::Smtp(SmtpEvent::MultipleMailFrom),
            b"smtp.mailbox-does-not-exist" => EventType::Smtp(SmtpEvent::MailboxDoesNotExist),
            b"smtp.relay-not-allowed" => EventType::Smtp(SmtpEvent::RelayNotAllowed),
            b"smtp.rcpt-to" => EventType::Smtp(SmtpEvent::RcptTo),
            b"smtp.rcpt-to-duplicate" => EventType::Smtp(SmtpEvent::RcptToDuplicate),
            b"smtp.rcpt-to-rewritten" => EventType::Smtp(SmtpEvent::RcptToRewritten),
            b"smtp.rcpt-to-missing" => EventType::Smtp(SmtpEvent::RcptToMissing),
            b"smtp.rcpt-to-greylisted" => EventType::Smtp(SmtpEvent::RcptToGreylisted),
            b"smtp.too-many-recipients" => EventType::Smtp(SmtpEvent::TooManyRecipients),
            b"smtp.too-many-invalid-rcpt" => EventType::Smtp(SmtpEvent::TooManyInvalidRcpt),
            b"smtp.raw-input" => EventType::Smtp(SmtpEvent::RawInput),
            b"smtp.raw-output" => EventType::Smtp(SmtpEvent::RawOutput),
            b"smtp.missing-local-hostname" => EventType::Smtp(SmtpEvent::MissingLocalHostname),
            b"smtp.vrfy" => EventType::Smtp(SmtpEvent::Vrfy),
            b"smtp.vrfy-not-found" => EventType::Smtp(SmtpEvent::VrfyNotFound),
            b"smtp.vrfy-disabled" => EventType::Smtp(SmtpEvent::VrfyDisabled),
            b"smtp.expn" => EventType::Smtp(SmtpEvent::Expn),
            b"smtp.expn-not-found" => EventType::Smtp(SmtpEvent::ExpnNotFound),
            b"smtp.expn-disabled" => EventType::Smtp(SmtpEvent::ExpnDisabled),
            b"smtp.require-tls-disabled" => EventType::Smtp(SmtpEvent::RequireTlsDisabled),
            b"smtp.deliver-by-disabled" => EventType::Smtp(SmtpEvent::DeliverByDisabled),
            b"smtp.deliver-by-invalid" => EventType::Smtp(SmtpEvent::DeliverByInvalid),
            b"smtp.future-release-disabled" => EventType::Smtp(SmtpEvent::FutureReleaseDisabled),
            b"smtp.future-release-invalid" => EventType::Smtp(SmtpEvent::FutureReleaseInvalid),
            b"smtp.mt-priority-disabled" => EventType::Smtp(SmtpEvent::MtPriorityDisabled),
            b"smtp.mt-priority-invalid" => EventType::Smtp(SmtpEvent::MtPriorityInvalid),
            b"smtp.dsn-disabled" => EventType::Smtp(SmtpEvent::DsnDisabled),
            b"smtp.auth-not-allowed" => EventType::Smtp(SmtpEvent::AuthNotAllowed),
            b"smtp.auth-mechanism-not-supported" => EventType::Smtp(SmtpEvent::AuthMechanismNotSupported),
            b"smtp.auth-exchange-too-long" => EventType::Smtp(SmtpEvent::AuthExchangeTooLong),
            b"smtp.already-authenticated" => EventType::Smtp(SmtpEvent::AlreadyAuthenticated),
            b"smtp.noop" => EventType::Smtp(SmtpEvent::Noop),
            b"smtp.start-tls" => EventType::Smtp(SmtpEvent::StartTls),
            b"smtp.start-tls-unavailable" => EventType::Smtp(SmtpEvent::StartTlsUnavailable),
            b"smtp.start-tls-already" => EventType::Smtp(SmtpEvent::StartTlsAlready),
            b"smtp.rset" => EventType::Smtp(SmtpEvent::Rset),
            b"smtp.quit" => EventType::Smtp(SmtpEvent::Quit),
            b"smtp.help" => EventType::Smtp(SmtpEvent::Help),
            b"smtp.command-not-implemented" => EventType::Smtp(SmtpEvent::CommandNotImplemented),
            b"smtp.invalid-command" => EventType::Smtp(SmtpEvent::InvalidCommand),
            b"smtp.invalid-sender-address" => EventType::Smtp(SmtpEvent::InvalidSenderAddress),
            b"smtp.invalid-recipient-address" => EventType::Smtp(SmtpEvent::InvalidRecipientAddress),
            b"smtp.invalid-parameter" => EventType::Smtp(SmtpEvent::InvalidParameter),
            b"smtp.unsupported-parameter" => EventType::Smtp(SmtpEvent::UnsupportedParameter),
            b"smtp.syntax-error" => EventType::Smtp(SmtpEvent::SyntaxError),
            b"smtp.request-too-large" => EventType::Smtp(SmtpEvent::RequestTooLarge),
            b"spam.pyzor" => EventType::Spam(SpamEvent::Pyzor),
            b"spam.pyzor-error" => EventType::Spam(SpamEvent::PyzorError),
            b"spam.dnsbl" => EventType::Spam(SpamEvent::Dnsbl),
            b"spam.dnsbl-error" => EventType::Spam(SpamEvent::DnsblError),
            b"spam.train-started" => EventType::Spam(SpamEvent::TrainStarted),
            b"spam.train-completed" => EventType::Spam(SpamEvent::TrainCompleted),
            b"spam.train-sample-added" => EventType::Spam(SpamEvent::TrainSampleAdded),
            b"spam.train-sample-not-found" => EventType::Spam(SpamEvent::TrainSampleNotFound),
            b"spam.classify" => EventType::Spam(SpamEvent::Classify),
            b"spam.model-loaded" => EventType::Spam(SpamEvent::ModelLoaded),
            b"spam.model-not-ready" => EventType::Spam(SpamEvent::ModelNotReady),
            b"spam.model-not-found" => EventType::Spam(SpamEvent::ModelNotFound),
            b"spam.rules-updated" => EventType::Spam(SpamEvent::RulesUpdated),
            b"spf.pass" => EventType::Spf(SpfEvent::Pass),
            b"spf.fail" => EventType::Spf(SpfEvent::Fail),
            b"spf.soft-fail" => EventType::Spf(SpfEvent::SoftFail),
            b"spf.neutral" => EventType::Spf(SpfEvent::Neutral),
            b"spf.temp-error" => EventType::Spf(SpfEvent::TempError),
            b"spf.perm-error" => EventType::Spf(SpfEvent::PermError),
            b"spf.none" => EventType::Spf(SpfEvent::None),
            b"store.assert-value-failed" => EventType::Store(StoreEvent::AssertValueFailed),
            b"store.foundationdb-error" => EventType::Store(StoreEvent::FoundationdbError),
            b"store.mysql-error" => EventType::Store(StoreEvent::MysqlError),
            b"store.postgresql-error" => EventType::Store(StoreEvent::PostgresqlError),
            b"store.rocksdb-error" => EventType::Store(StoreEvent::RocksdbError),
            b"store.sqlite-error" => EventType::Store(StoreEvent::SqliteError),
            b"store.ldap-error" => EventType::Store(StoreEvent::LdapError),
            b"store.elasticsearch-error" => EventType::Store(StoreEvent::ElasticsearchError),
            b"store.meilisearch-error" => EventType::Store(StoreEvent::MeilisearchError),
            b"store.redis-error" => EventType::Store(StoreEvent::RedisError),
            b"store.s3-error" => EventType::Store(StoreEvent::S3Error),
            b"store.azure-error" => EventType::Store(StoreEvent::AzureError),
            b"store.filesystem-error" => EventType::Store(StoreEvent::FilesystemError),
            b"store.pool-error" => EventType::Store(StoreEvent::PoolError),
            b"store.data-corruption" => EventType::Store(StoreEvent::DataCorruption),
            b"store.decompress-error" => EventType::Store(StoreEvent::DecompressError),
            b"store.deserialize-error" => EventType::Store(StoreEvent::DeserializeError),
            b"store.not-found" => EventType::Store(StoreEvent::NotFound),
            b"store.not-configured" => EventType::Store(StoreEvent::NotConfigured),
            b"store.not-supported" => EventType::Store(StoreEvent::NotSupported),
            b"store.unexpected-error" => EventType::Store(StoreEvent::UnexpectedError),
            b"store.crypto-error" => EventType::Store(StoreEvent::CryptoError),
            b"store.http-store-error" => EventType::Store(StoreEvent::HttpStoreError),
            b"store.blob-missing-marker" => EventType::Store(StoreEvent::BlobMissingMarker),
            b"store.data-write" => EventType::Store(StoreEvent::DataWrite),
            b"store.data-iterate" => EventType::Store(StoreEvent::DataIterate),
            b"store.blob-read" => EventType::Store(StoreEvent::BlobRead),
            b"store.blob-write" => EventType::Store(StoreEvent::BlobWrite),
            b"store.blob-delete" => EventType::Store(StoreEvent::BlobDelete),
            b"store.sql-query" => EventType::Store(StoreEvent::SqlQuery),
            b"store.ldap-query" => EventType::Store(StoreEvent::LdapQuery),
            b"store.ldap-warning" => EventType::Store(StoreEvent::LdapWarning),
            b"store.http-store-fetch" => EventType::Store(StoreEvent::HttpStoreFetch),
            b"store.auto-expunge" => EventType::Store(StoreEvent::AutoExpunge),
            b"store.blob-store-purged" => EventType::Store(StoreEvent::BlobStorePurged),
            b"store.data-store-purged" => EventType::Store(StoreEvent::DataStorePurged),
            b"task-manager.task-acquired" => EventType::TaskManager(TaskManagerEvent::TaskAcquired),
            b"task-manager.task-queued" => EventType::TaskManager(TaskManagerEvent::TaskQueued),
            b"task-manager.task-scheduled" => EventType::TaskManager(TaskManagerEvent::TaskScheduled),
            b"task-manager.task-locked" => EventType::TaskManager(TaskManagerEvent::TaskLocked),
            b"task-manager.task-ignored" => EventType::TaskManager(TaskManagerEvent::TaskIgnored),
            b"task-manager.task-failed" => EventType::TaskManager(TaskManagerEvent::TaskFailed),
            b"task-manager.task-retry" => EventType::TaskManager(TaskManagerEvent::TaskRetry),
            b"task-manager.task-stalled" => EventType::TaskManager(TaskManagerEvent::TaskStalled),
            b"task-manager.task-expired" => EventType::TaskManager(TaskManagerEvent::TaskExpired),
            b"task-manager.blob-not-found" => EventType::TaskManager(TaskManagerEvent::BlobNotFound),
            b"task-manager.metadata-not-found" => EventType::TaskManager(TaskManagerEvent::MetadataNotFound),
            b"task-manager.scheduler-started" => EventType::TaskManager(TaskManagerEvent::SchedulerStarted),
            b"task-manager.manager-started" => EventType::TaskManager(TaskManagerEvent::ManagerStarted),
            b"telemetry.alert-event" => EventType::Telemetry(TelemetryEvent::AlertEvent),
            b"telemetry.alert-message" => EventType::Telemetry(TelemetryEvent::AlertMessage),
            b"telemetry.log-error" => EventType::Telemetry(TelemetryEvent::LogError),
            b"telemetry.webhook-error" => EventType::Telemetry(TelemetryEvent::WebhookError),
            b"telemetry.otel-exporter-error" => EventType::Telemetry(TelemetryEvent::OtelExporterError),
            b"telemetry.otel-metrics-exporter-error" => EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError),
            b"telemetry.prometheus-exporter-error" => EventType::Telemetry(TelemetryEvent::PrometheusExporterError),
            b"telemetry.journal-error" => EventType::Telemetry(TelemetryEvent::JournalError),
            b"telemetry.events-dropped" => EventType::Telemetry(TelemetryEvent::EventsDropped),
            b"telemetry.metrics-collected" => EventType::Telemetry(TelemetryEvent::MetricsCollected),
            b"telemetry.metrics-stored" => EventType::Telemetry(TelemetryEvent::MetricsStored),
            b"telemetry.metrics-pushed" => EventType::Telemetry(TelemetryEvent::MetricsPushed),
            b"tls.handshake" => EventType::Tls(TlsEvent::Handshake),
            b"tls.handshake-error" => EventType::Tls(TlsEvent::HandshakeError),
            b"tls.not-configured" => EventType::Tls(TlsEvent::NotConfigured),
            b"tls.certificate-not-found" => EventType::Tls(TlsEvent::CertificateNotFound),
            b"tls.no-certificates-available" => EventType::Tls(TlsEvent::NoCertificatesAvailable),
            b"tls.multiple-certificates-available" => EventType::Tls(TlsEvent::MultipleCertificatesAvailable),
            b"tls.expired-certificate-removed" => EventType::Tls(TlsEvent::ExpiredCertificateRemoved),
            b"tls-rpt.record-fetch" => EventType::TlsRpt(TlsRptEvent::RecordFetch),
            b"tls-rpt.record-fetch-error" => EventType::TlsRpt(TlsRptEvent::RecordFetchError),
            b"tls-rpt.record-not-found" => EventType::TlsRpt(TlsRptEvent::RecordNotFound),
            b"web-dav.propfind" => EventType::WebDav(WebDavEvent::Propfind),
            b"web-dav.proppatch" => EventType::WebDav(WebDavEvent::Proppatch),
            b"web-dav.get" => EventType::WebDav(WebDavEvent::Get),
            b"web-dav.head" => EventType::WebDav(WebDavEvent::Head),
            b"web-dav.report" => EventType::WebDav(WebDavEvent::Report),
            b"web-dav.mkcol" => EventType::WebDav(WebDavEvent::Mkcol),
            b"web-dav.mkcalendar" => EventType::WebDav(WebDavEvent::Mkcalendar),
            b"web-dav.delete" => EventType::WebDav(WebDavEvent::Delete),
            b"web-dav.put" => EventType::WebDav(WebDavEvent::Put),
            b"web-dav.post" => EventType::WebDav(WebDavEvent::Post),
            b"web-dav.patch" => EventType::WebDav(WebDavEvent::Patch),
            b"web-dav.copy" => EventType::WebDav(WebDavEvent::Copy),
            b"web-dav.move" => EventType::WebDav(WebDavEvent::Move),
            b"web-dav.lock" => EventType::WebDav(WebDavEvent::Lock),
            b"web-dav.unlock" => EventType::WebDav(WebDavEvent::Unlock),
            b"web-dav.acl" => EventType::WebDav(WebDavEvent::Acl),
            b"web-dav.options" => EventType::WebDav(WebDavEvent::Options),
            b"web-dav.error" => EventType::WebDav(WebDavEvent::Error),
        }
        .copied()
    }

    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            EventType,
            b"acme.auth-start" => EventType::Acme(AcmeEvent::AuthStart),
            b"acme.auth-pending" => EventType::Acme(AcmeEvent::AuthPending),
            b"acme.auth-valid" => EventType::Acme(AcmeEvent::AuthValid),
            b"acme.auth-completed" => EventType::Acme(AcmeEvent::AuthCompleted),
            b"acme.auth-error" => EventType::Acme(AcmeEvent::AuthError),
            b"acme.auth-too-many-attempts" => EventType::Acme(AcmeEvent::AuthTooManyAttempts),
            b"acme.process-cert" => EventType::Acme(AcmeEvent::ProcessCert),
            b"acme.order-start" => EventType::Acme(AcmeEvent::OrderStart),
            b"acme.order-processing" => EventType::Acme(AcmeEvent::OrderProcessing),
            b"acme.order-completed" => EventType::Acme(AcmeEvent::OrderCompleted),
            b"acme.order-ready" => EventType::Acme(AcmeEvent::OrderReady),
            b"acme.order-valid" => EventType::Acme(AcmeEvent::OrderValid),
            b"acme.order-invalid" => EventType::Acme(AcmeEvent::OrderInvalid),
            b"acme.renew-backoff" => EventType::Acme(AcmeEvent::RenewBackoff),
            b"acme.client-supplied-sni" => EventType::Acme(AcmeEvent::ClientSuppliedSni),
            b"acme.client-missing-sni" => EventType::Acme(AcmeEvent::ClientMissingSni),
            b"acme.tls-alpn-received" => EventType::Acme(AcmeEvent::TlsAlpnReceived),
            b"acme.tls-alpn-error" => EventType::Acme(AcmeEvent::TlsAlpnError),
            b"acme.token-not-found" => EventType::Acme(AcmeEvent::TokenNotFound),
            b"acme.error" => EventType::Acme(AcmeEvent::Error),
            b"arc.chain-invalid" => EventType::Arc(ArcEvent::ChainInvalid),
            b"arc.signature-invalid" => EventType::Arc(ArcEvent::SignatureInvalid),
            b"arc.hash-mismatch" => EventType::Arc(ArcEvent::HashMismatch),
            b"auth.success" => EventType::Auth(AuthEvent::Success),
            b"auth.failed" => EventType::Auth(AuthEvent::Failed),
            b"auth.token-expired" => EventType::Auth(AuthEvent::TokenExpired),
            b"auth.mfa-required" => EventType::Auth(AuthEvent::MfaRequired),
            b"auth.too-many-attempts" => EventType::Auth(AuthEvent::TooManyAttempts),
            b"auth.client-registration" => EventType::Auth(AuthEvent::ClientRegistration),
            b"auth.error" => EventType::Auth(AuthEvent::Error),
            b"auth.warning" => EventType::Auth(AuthEvent::Warning),
            b"auth.credential-expired" => EventType::Auth(AuthEvent::CredentialExpired),
            b"cache.miss" => EventType::Cache(CacheEvent::Miss),
            b"cache.hit" => EventType::Cache(CacheEvent::Hit),
            b"cache.stale" => EventType::Cache(CacheEvent::Stale),
            b"cache.update" => EventType::Cache(CacheEvent::Update),
            b"cache.entry-too-large" => EventType::Cache(CacheEvent::EntryTooLarge),
            b"cache.invalidate" => EventType::Cache(CacheEvent::Invalidate),
            b"cache.swap-hit" => EventType::Cache(CacheEvent::SwapHit),
            b"cache.swap-miss" => EventType::Cache(CacheEvent::SwapMiss),
            b"cache.swap-write" => EventType::Cache(CacheEvent::SwapWrite),
            b"cache.swap-error" => EventType::Cache(CacheEvent::SwapError),
            b"cache.swap-metrics" => EventType::Cache(CacheEvent::SwapMetrics),
            b"cache.swap-flush" => EventType::Cache(CacheEvent::SwapFlush),
            b"calendar.rule-expansion-error" => EventType::Calendar(CalendarEvent::RuleExpansionError),
            b"calendar.alarm-sent" => EventType::Calendar(CalendarEvent::AlarmSent),
            b"calendar.alarm-skipped" => EventType::Calendar(CalendarEvent::AlarmSkipped),
            b"calendar.alarm-recipient-override" => EventType::Calendar(CalendarEvent::AlarmRecipientOverride),
            b"calendar.alarm-failed" => EventType::Calendar(CalendarEvent::AlarmFailed),
            b"calendar.itip-message-sent" => EventType::Calendar(CalendarEvent::ItipMessageSent),
            b"calendar.itip-message-received" => EventType::Calendar(CalendarEvent::ItipMessageReceived),
            b"calendar.itip-message-error" => EventType::Calendar(CalendarEvent::ItipMessageError),
            b"cluster.startup" => EventType::Cluster(ClusterEvent::Startup),
            b"cluster.subscriber-start" => EventType::Cluster(ClusterEvent::SubscriberStart),
            b"cluster.subscriber-stop" => EventType::Cluster(ClusterEvent::SubscriberStop),
            b"cluster.subscriber-error" => EventType::Cluster(ClusterEvent::SubscriberError),
            b"cluster.subscriber-disconnected" => EventType::Cluster(ClusterEvent::SubscriberDisconnected),
            b"cluster.publisher-start" => EventType::Cluster(ClusterEvent::PublisherStart),
            b"cluster.publisher-stop" => EventType::Cluster(ClusterEvent::PublisherStop),
            b"cluster.publisher-error" => EventType::Cluster(ClusterEvent::PublisherError),
            b"cluster.message-received" => EventType::Cluster(ClusterEvent::MessageReceived),
            b"cluster.message-skipped" => EventType::Cluster(ClusterEvent::MessageSkipped),
            b"cluster.message-invalid" => EventType::Cluster(ClusterEvent::MessageInvalid),
            b"cluster.node-id-renewed" => EventType::Cluster(ClusterEvent::NodeIdRenewed),
            b"dane.authentication-success" => EventType::Dane(DaneEvent::AuthenticationSuccess),
            b"dane.authentication-failure" => EventType::Dane(DaneEvent::AuthenticationFailure),
            b"dane.no-certificates-found" => EventType::Dane(DaneEvent::NoCertificatesFound),
            b"dane.certificate-parse-error" => EventType::Dane(DaneEvent::CertificateParseError),
            b"dane.tlsa-record-match" => EventType::Dane(DaneEvent::TlsaRecordMatch),
            b"dane.tlsa-record-fetch" => EventType::Dane(DaneEvent::TlsaRecordFetch),
            b"dane.tlsa-record-fetch-error" => EventType::Dane(DaneEvent::TlsaRecordFetchError),
            b"dane.tlsa-record-not-found" => EventType::Dane(DaneEvent::TlsaRecordNotFound),
            b"dane.tlsa-record-not-dnssec-signed" => EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned),
            b"dane.tlsa-record-invalid" => EventType::Dane(DaneEvent::TlsaRecordInvalid),
            b"dane.bogus-dnssec-record" => EventType::Dane(DaneEvent::BogusDnssecRecord),
            b"delivery.attempt-start" => EventType::Delivery(DeliveryEvent::AttemptStart),
            b"delivery.attempt-end" => EventType::Delivery(DeliveryEvent::AttemptEnd),
            b"delivery.completed" => EventType::Delivery(DeliveryEvent::Completed),
            b"delivery.failed" => EventType::Delivery(DeliveryEvent::Failed),
            b"delivery.domain-delivery-start" => EventType::Delivery(DeliveryEvent::DomainDeliveryStart),
            b"delivery.mx-lookup" => EventType::Delivery(DeliveryEvent::MxLookup),
            b"delivery.mx-lookup-failed" => EventType::Delivery(DeliveryEvent::MxLookupFailed),
            b"delivery.ip-lookup" => EventType::Delivery(DeliveryEvent::IpLookup),
            b"delivery.ip-lookup-failed" => EventType::Delivery(DeliveryEvent::IpLookupFailed),
            b"delivery.null-mx" => EventType::Delivery(DeliveryEvent::NullMx),
            b"delivery.connect" => EventType::Delivery(DeliveryEvent::Connect),
            b"delivery.connect-error" => EventType::Delivery(DeliveryEvent::ConnectError),
            b"delivery.missing-outbound-hostname" => EventType::Delivery(DeliveryEvent::MissingOutboundHostname),
            b"delivery.greeting-failed" => EventType::Delivery(DeliveryEvent::GreetingFailed),
            b"delivery.ehlo" => EventType::Delivery(DeliveryEvent::Ehlo),
            b"delivery.ehlo-rejected" => EventType::Delivery(DeliveryEvent::EhloRejected),
            b"delivery.auth" => EventType::Delivery(DeliveryEvent::Auth),
            b"delivery.auth-failed" => EventType::Delivery(DeliveryEvent::AuthFailed),
            b"delivery.mail-from" => EventType::Delivery(DeliveryEvent::MailFrom),
            b"delivery.mail-from-rejected" => EventType::Delivery(DeliveryEvent::MailFromRejected),
            b"delivery.delivered" => EventType::Delivery(DeliveryEvent::Delivered),
            b"delivery.rcpt-to" => EventType::Delivery(DeliveryEvent::RcptTo),
            b"delivery.rcpt-to-rejected" => EventType::Delivery(DeliveryEvent::RcptToRejected),
            b"delivery.rcpt-to-failed" => EventType::Delivery(DeliveryEvent::RcptToFailed),
            b"delivery.message-rejected" => EventType::Delivery(DeliveryEvent::MessageRejected),
            b"delivery.start-tls" => EventType::Delivery(DeliveryEvent::StartTls),
            b"delivery.start-tls-unavailable" => EventType::Delivery(DeliveryEvent::StartTlsUnavailable),
            b"delivery.start-tls-error" => EventType::Delivery(DeliveryEvent::StartTlsError),
            b"delivery.start-tls-disabled" => EventType::Delivery(DeliveryEvent::StartTlsDisabled),
            b"delivery.implicit-tls-error" => EventType::Delivery(DeliveryEvent::ImplicitTlsError),
            b"delivery.concurrency-limit-exceeded" => EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded),
            b"delivery.rate-limit-exceeded" => EventType::Delivery(DeliveryEvent::RateLimitExceeded),
            b"delivery.double-bounce" => EventType::Delivery(DeliveryEvent::DoubleBounce),
            b"delivery.dsn-success" => EventType::Delivery(DeliveryEvent::DsnSuccess),
            b"delivery.dsn-temp-fail" => EventType::Delivery(DeliveryEvent::DsnTempFail),
            b"delivery.dsn-perm-fail" => EventType::Delivery(DeliveryEvent::DsnPermFail),
            b"delivery.raw-input" => EventType::Delivery(DeliveryEvent::RawInput),
            b"delivery.raw-output" => EventType::Delivery(DeliveryEvent::RawOutput),
            b"dkim.pass" => EventType::Dkim(DkimEvent::Pass),
            b"dkim.neutral" => EventType::Dkim(DkimEvent::Neutral),
            b"dkim.fail" => EventType::Dkim(DkimEvent::Fail),
            b"dkim.perm-error" => EventType::Dkim(DkimEvent::PermError),
            b"dkim.temp-error" => EventType::Dkim(DkimEvent::TempError),
            b"dkim.none" => EventType::Dkim(DkimEvent::None),
            b"dkim.signature-invalid" => EventType::Dkim(DkimEvent::SignatureInvalid),
            b"dkim.public-key-error" => EventType::Dkim(DkimEvent::PublicKeyError),
            b"dkim.verification-failed" => EventType::Dkim(DkimEvent::VerificationFailed),
            b"dkim.hash-mismatch" => EventType::Dkim(DkimEvent::HashMismatch),
            b"dkim.signer-not-found" => EventType::Dkim(DkimEvent::SignerNotFound),
            b"dkim.build-error" => EventType::Dkim(DkimEvent::BuildError),
            b"dkim.signature-created" => EventType::Dkim(DkimEvent::SignatureCreated),
            b"dkim.signature-published" => EventType::Dkim(DkimEvent::SignaturePublished),
            b"dkim.signature-retiring" => EventType::Dkim(DkimEvent::SignatureRetiring),
            b"dkim.signature-retired" => EventType::Dkim(DkimEvent::SignatureRetired),
            b"dkim.signature-deleted" => EventType::Dkim(DkimEvent::SignatureDeleted),
            b"dkim2.instance-invalid" => EventType::Dkim2(Dkim2Event::InstanceInvalid),
            b"dkim2.signature-invalid" => EventType::Dkim2(Dkim2Event::SignatureInvalid),
            b"dkim2.chain-invalid" => EventType::Dkim2(Dkim2Event::ChainInvalid),
            b"dkim2.timestamp-invalid" => EventType::Dkim2(Dkim2Event::TimestampInvalid),
            b"dkim2.envelope-mismatch" => EventType::Dkim2(Dkim2Event::EnvelopeMismatch),
            b"dkim2.custody-broken" => EventType::Dkim2(Dkim2Event::CustodyBroken),
            b"dkim2.public-key-error" => EventType::Dkim2(Dkim2Event::PublicKeyError),
            b"dkim2.verification-failed" => EventType::Dkim2(Dkim2Event::VerificationFailed),
            b"dkim2.hash-mismatch" => EventType::Dkim2(Dkim2Event::HashMismatch),
            b"dkim2.recipe-error" => EventType::Dkim2(Dkim2Event::RecipeError),
            b"dkim2.signing-failed" => EventType::Dkim2(Dkim2Event::SigningFailed),
            b"dmarc.pass" => EventType::Dmarc(DmarcEvent::Pass),
            b"dmarc.fail" => EventType::Dmarc(DmarcEvent::Fail),
            b"dmarc.perm-error" => EventType::Dmarc(DmarcEvent::PermError),
            b"dmarc.temp-error" => EventType::Dmarc(DmarcEvent::TempError),
            b"dmarc.none" => EventType::Dmarc(DmarcEvent::None),
            b"dns.record-created" => EventType::Dns(DnsEvent::RecordCreated),
            b"dns.record-creation-failed" => EventType::Dns(DnsEvent::RecordCreationFailed),
            b"dns.record-deletion-failed" => EventType::Dns(DnsEvent::RecordDeletionFailed),
            b"dns.record-not-propagated" => EventType::Dns(DnsEvent::RecordNotPropagated),
            b"dns.record-lookup-failed" => EventType::Dns(DnsEvent::RecordLookupFailed),
            b"dns.record-propagated" => EventType::Dns(DnsEvent::RecordPropagated),
            b"dns.record-propagation-timeout" => EventType::Dns(DnsEvent::RecordPropagationTimeout),
            b"eval.result" => EventType::Eval(EvalEvent::Result),
            b"eval.error" => EventType::Eval(EvalEvent::Error),
            b"eval.directory-not-found" => EventType::Eval(EvalEvent::DirectoryNotFound),
            b"eval.store-not-found" => EventType::Eval(EvalEvent::StoreNotFound),
            b"http.connection-start" => EventType::Http(HttpEvent::ConnectionStart),
            b"http.connection-end" => EventType::Http(HttpEvent::ConnectionEnd),
            b"http.error" => EventType::Http(HttpEvent::Error),
            b"http.request-url" => EventType::Http(HttpEvent::RequestUrl),
            b"http.request-body" => EventType::Http(HttpEvent::RequestBody),
            b"http.response-body" => EventType::Http(HttpEvent::ResponseBody),
            b"http.x-forwarded-missing" => EventType::Http(HttpEvent::XForwardedMissing),
            b"http.x-forwarded-invalid" => EventType::Http(HttpEvent::XForwardedInvalid),
            b"imap.connection-start" => EventType::Imap(ImapEvent::ConnectionStart),
            b"imap.connection-end" => EventType::Imap(ImapEvent::ConnectionEnd),
            b"imap.get-acl" => EventType::Imap(ImapEvent::GetAcl),
            b"imap.set-acl" => EventType::Imap(ImapEvent::SetAcl),
            b"imap.my-rights" => EventType::Imap(ImapEvent::MyRights),
            b"imap.list-rights" => EventType::Imap(ImapEvent::ListRights),
            b"imap.append" => EventType::Imap(ImapEvent::Append),
            b"imap.capabilities" => EventType::Imap(ImapEvent::Capabilities),
            b"imap.id" => EventType::Imap(ImapEvent::Id),
            b"imap.close" => EventType::Imap(ImapEvent::Close),
            b"imap.copy" => EventType::Imap(ImapEvent::Copy),
            b"imap.move" => EventType::Imap(ImapEvent::Move),
            b"imap.create-mailbox" => EventType::Imap(ImapEvent::CreateMailbox),
            b"imap.delete-mailbox" => EventType::Imap(ImapEvent::DeleteMailbox),
            b"imap.rename-mailbox" => EventType::Imap(ImapEvent::RenameMailbox),
            b"imap.enable" => EventType::Imap(ImapEvent::Enable),
            b"imap.expunge" => EventType::Imap(ImapEvent::Expunge),
            b"imap.fetch" => EventType::Imap(ImapEvent::Fetch),
            b"imap.idle-start" => EventType::Imap(ImapEvent::IdleStart),
            b"imap.idle-stop" => EventType::Imap(ImapEvent::IdleStop),
            b"imap.list" => EventType::Imap(ImapEvent::List),
            b"imap.lsub" => EventType::Imap(ImapEvent::Lsub),
            b"imap.logout" => EventType::Imap(ImapEvent::Logout),
            b"imap.namespace" => EventType::Imap(ImapEvent::Namespace),
            b"imap.noop" => EventType::Imap(ImapEvent::Noop),
            b"imap.search" => EventType::Imap(ImapEvent::Search),
            b"imap.sort" => EventType::Imap(ImapEvent::Sort),
            b"imap.select" => EventType::Imap(ImapEvent::Select),
            b"imap.status" => EventType::Imap(ImapEvent::Status),
            b"imap.store" => EventType::Imap(ImapEvent::Store),
            b"imap.subscribe" => EventType::Imap(ImapEvent::Subscribe),
            b"imap.unsubscribe" => EventType::Imap(ImapEvent::Unsubscribe),
            b"imap.thread" => EventType::Imap(ImapEvent::Thread),
            b"imap.uid-batches" => EventType::Imap(ImapEvent::UidBatches),
            b"imap.get-quota" => EventType::Imap(ImapEvent::GetQuota),
            b"imap.get-metadata" => EventType::Imap(ImapEvent::GetMetadata),
            b"imap.set-metadata" => EventType::Imap(ImapEvent::SetMetadata),
            b"imap.error" => EventType::Imap(ImapEvent::Error),
            b"imap.raw-input" => EventType::Imap(ImapEvent::RawInput),
            b"imap.raw-output" => EventType::Imap(ImapEvent::RawOutput),
            b"incoming-report.dmarc-report" => EventType::IncomingReport(IncomingReportEvent::DmarcReport),
            b"incoming-report.dmarc-report-with-warnings" => EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings),
            b"incoming-report.tls-report" => EventType::IncomingReport(IncomingReportEvent::TlsReport),
            b"incoming-report.tls-report-with-warnings" => EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings),
            b"incoming-report.abuse-report" => EventType::IncomingReport(IncomingReportEvent::AbuseReport),
            b"incoming-report.auth-failure-report" => EventType::IncomingReport(IncomingReportEvent::AuthFailureReport),
            b"incoming-report.fraud-report" => EventType::IncomingReport(IncomingReportEvent::FraudReport),
            b"incoming-report.not-spam-report" => EventType::IncomingReport(IncomingReportEvent::NotSpamReport),
            b"incoming-report.virus-report" => EventType::IncomingReport(IncomingReportEvent::VirusReport),
            b"incoming-report.other-report" => EventType::IncomingReport(IncomingReportEvent::OtherReport),
            b"incoming-report.message-parse-failed" => EventType::IncomingReport(IncomingReportEvent::MessageParseFailed),
            b"incoming-report.dmarc-parse-failed" => EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed),
            b"incoming-report.tls-rpc-parse-failed" => EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed),
            b"incoming-report.arf-parse-failed" => EventType::IncomingReport(IncomingReportEvent::ArfParseFailed),
            b"incoming-report.decompress-error" => EventType::IncomingReport(IncomingReportEvent::DecompressError),
            b"iprev.pass" => EventType::Iprev(IprevEvent::Pass),
            b"iprev.fail" => EventType::Iprev(IprevEvent::Fail),
            b"iprev.perm-error" => EventType::Iprev(IprevEvent::PermError),
            b"iprev.temp-error" => EventType::Iprev(IprevEvent::TempError),
            b"iprev.none" => EventType::Iprev(IprevEvent::None),
            b"jmap.method-call" => EventType::Jmap(JmapEvent::MethodCall),
            b"jmap.invalid-arguments" => EventType::Jmap(JmapEvent::InvalidArguments),
            b"jmap.request-too-large" => EventType::Jmap(JmapEvent::RequestTooLarge),
            b"jmap.state-mismatch" => EventType::Jmap(JmapEvent::StateMismatch),
            b"jmap.anchor-not-found" => EventType::Jmap(JmapEvent::AnchorNotFound),
            b"jmap.unsupported-filter" => EventType::Jmap(JmapEvent::UnsupportedFilter),
            b"jmap.unsupported-sort" => EventType::Jmap(JmapEvent::UnsupportedSort),
            b"jmap.unknown-method" => EventType::Jmap(JmapEvent::UnknownMethod),
            b"jmap.invalid-result-reference" => EventType::Jmap(JmapEvent::InvalidResultReference),
            b"jmap.forbidden" => EventType::Jmap(JmapEvent::Forbidden),
            b"jmap.account-not-found" => EventType::Jmap(JmapEvent::AccountNotFound),
            b"jmap.account-not-supported-by-method" => EventType::Jmap(JmapEvent::AccountNotSupportedByMethod),
            b"jmap.account-read-only" => EventType::Jmap(JmapEvent::AccountReadOnly),
            b"jmap.from-account-not-found" => EventType::Jmap(JmapEvent::FromAccountNotFound),
            b"jmap.from-account-not-supported-by-method" => EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod),
            b"jmap.not-found" => EventType::Jmap(JmapEvent::NotFound),
            b"jmap.cannot-calculate-changes" => EventType::Jmap(JmapEvent::CannotCalculateChanges),
            b"jmap.unknown-data-type" => EventType::Jmap(JmapEvent::UnknownDataType),
            b"jmap.unknown-capability" => EventType::Jmap(JmapEvent::UnknownCapability),
            b"jmap.not-json" => EventType::Jmap(JmapEvent::NotJson),
            b"jmap.not-request" => EventType::Jmap(JmapEvent::NotRequest),
            b"jmap.websocket-start" => EventType::Jmap(JmapEvent::WebsocketStart),
            b"jmap.websocket-stop" => EventType::Jmap(JmapEvent::WebsocketStop),
            b"jmap.websocket-error" => EventType::Jmap(JmapEvent::WebsocketError),
            b"jmap.expand-duration-too-large" => EventType::Jmap(JmapEvent::ExpandDurationTooLarge),
            b"jmap.cannot-calculate-occurrences" => EventType::Jmap(JmapEvent::CannotCalculateOccurrences),
            b"jmap.too-large" => EventType::Jmap(JmapEvent::TooLarge),
            b"jmap.rate-limit" => EventType::Jmap(JmapEvent::RateLimit),
            b"jmap.object-not-found" => EventType::Jmap(JmapEvent::ObjectNotFound),
            b"limit.size-request" => EventType::Limit(LimitEvent::SizeRequest),
            b"limit.size-upload" => EventType::Limit(LimitEvent::SizeUpload),
            b"limit.calls-in" => EventType::Limit(LimitEvent::CallsIn),
            b"limit.concurrent-request" => EventType::Limit(LimitEvent::ConcurrentRequest),
            b"limit.concurrent-upload" => EventType::Limit(LimitEvent::ConcurrentUpload),
            b"limit.concurrent-connection" => EventType::Limit(LimitEvent::ConcurrentConnection),
            b"limit.quota" => EventType::Limit(LimitEvent::Quota),
            b"limit.blob-quota" => EventType::Limit(LimitEvent::BlobQuota),
            b"limit.too-many-requests" => EventType::Limit(LimitEvent::TooManyRequests),
            b"limit.memory-budget" => EventType::Limit(LimitEvent::MemoryBudget),
            b"mail-auth.parse-error" => EventType::MailAuth(MailAuthEvent::ParseError),
            b"mail-auth.missing-parameters" => EventType::MailAuth(MailAuthEvent::MissingParameters),
            b"mail-auth.no-headers-found" => EventType::MailAuth(MailAuthEvent::NoHeadersFound),
            b"mail-auth.crypto" => EventType::MailAuth(MailAuthEvent::Crypto),
            b"mail-auth.io" => EventType::MailAuth(MailAuthEvent::Io),
            b"mail-auth.base64" => EventType::MailAuth(MailAuthEvent::Base64),
            b"mail-auth.dns-error" => EventType::MailAuth(MailAuthEvent::DnsError),
            b"mail-auth.dns-record-not-found" => EventType::MailAuth(MailAuthEvent::DnsRecordNotFound),
            b"mail-auth.dns-invalid-record-type" => EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType),
            b"mail-auth.policy-not-aligned" => EventType::MailAuth(MailAuthEvent::PolicyNotAligned),
            b"manage-sieve.connection-start" => EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
            b"manage-sieve.connection-end" => EventType::ManageSieve(ManageSieveEvent::ConnectionEnd),
            b"manage-sieve.create-script" => EventType::ManageSieve(ManageSieveEvent::CreateScript),
            b"manage-sieve.update-script" => EventType::ManageSieve(ManageSieveEvent::UpdateScript),
            b"manage-sieve.get-script" => EventType::ManageSieve(ManageSieveEvent::GetScript),
            b"manage-sieve.delete-script" => EventType::ManageSieve(ManageSieveEvent::DeleteScript),
            b"manage-sieve.rename-script" => EventType::ManageSieve(ManageSieveEvent::RenameScript),
            b"manage-sieve.check-script" => EventType::ManageSieve(ManageSieveEvent::CheckScript),
            b"manage-sieve.have-space" => EventType::ManageSieve(ManageSieveEvent::HaveSpace),
            b"manage-sieve.list-scripts" => EventType::ManageSieve(ManageSieveEvent::ListScripts),
            b"manage-sieve.set-active" => EventType::ManageSieve(ManageSieveEvent::SetActive),
            b"manage-sieve.capabilities" => EventType::ManageSieve(ManageSieveEvent::Capabilities),
            b"manage-sieve.start-tls" => EventType::ManageSieve(ManageSieveEvent::StartTls),
            b"manage-sieve.unauthenticate" => EventType::ManageSieve(ManageSieveEvent::Unauthenticate),
            b"manage-sieve.logout" => EventType::ManageSieve(ManageSieveEvent::Logout),
            b"manage-sieve.noop" => EventType::ManageSieve(ManageSieveEvent::Noop),
            b"manage-sieve.error" => EventType::ManageSieve(ManageSieveEvent::Error),
            b"manage-sieve.raw-input" => EventType::ManageSieve(ManageSieveEvent::RawInput),
            b"manage-sieve.raw-output" => EventType::ManageSieve(ManageSieveEvent::RawOutput),
            b"message-ingest.ham" => EventType::MessageIngest(MessageIngestEvent::Ham),
            b"message-ingest.spam" => EventType::MessageIngest(MessageIngestEvent::Spam),
            b"message-ingest.imap-append" => EventType::MessageIngest(MessageIngestEvent::ImapAppend),
            b"message-ingest.jmap-append" => EventType::MessageIngest(MessageIngestEvent::JmapAppend),
            b"message-ingest.duplicate" => EventType::MessageIngest(MessageIngestEvent::Duplicate),
            b"message-ingest.error" => EventType::MessageIngest(MessageIngestEvent::Error),
            b"milter.read" => EventType::Milter(MilterEvent::Read),
            b"milter.write" => EventType::Milter(MilterEvent::Write),
            b"milter.action-accept" => EventType::Milter(MilterEvent::ActionAccept),
            b"milter.action-discard" => EventType::Milter(MilterEvent::ActionDiscard),
            b"milter.action-reject" => EventType::Milter(MilterEvent::ActionReject),
            b"milter.action-temp-fail" => EventType::Milter(MilterEvent::ActionTempFail),
            b"milter.action-reply-code" => EventType::Milter(MilterEvent::ActionReplyCode),
            b"milter.action-connection-failure" => EventType::Milter(MilterEvent::ActionConnectionFailure),
            b"milter.action-shutdown" => EventType::Milter(MilterEvent::ActionShutdown),
            b"milter.io-error" => EventType::Milter(MilterEvent::IoError),
            b"milter.frame-too-large" => EventType::Milter(MilterEvent::FrameTooLarge),
            b"milter.frame-invalid" => EventType::Milter(MilterEvent::FrameInvalid),
            b"milter.unexpected-response" => EventType::Milter(MilterEvent::UnexpectedResponse),
            b"milter.timeout" => EventType::Milter(MilterEvent::Timeout),
            b"milter.tls-invalid-name" => EventType::Milter(MilterEvent::TlsInvalidName),
            b"milter.disconnected" => EventType::Milter(MilterEvent::Disconnected),
            b"milter.parse-error" => EventType::Milter(MilterEvent::ParseError),
            b"mta-hook.action-accept" => EventType::MtaHook(MtaHookEvent::ActionAccept),
            b"mta-hook.action-discard" => EventType::MtaHook(MtaHookEvent::ActionDiscard),
            b"mta-hook.action-reject" => EventType::MtaHook(MtaHookEvent::ActionReject),
            b"mta-hook.action-quarantine" => EventType::MtaHook(MtaHookEvent::ActionQuarantine),
            b"mta-hook.error" => EventType::MtaHook(MtaHookEvent::Error),
            b"mta-sts.authorized" => EventType::MtaSts(MtaStsEvent::Authorized),
            b"mta-sts.not-authorized" => EventType::MtaSts(MtaStsEvent::NotAuthorized),
            b"mta-sts.policy-fetch" => EventType::MtaSts(MtaStsEvent::PolicyFetch),
            b"mta-sts.policy-not-found" => EventType::MtaSts(MtaStsEvent::PolicyNotFound),
            b"mta-sts.policy-fetch-error" => EventType::MtaSts(MtaStsEvent::PolicyFetchError),
            b"mta-sts.invalid-policy" => EventType::MtaSts(MtaStsEvent::InvalidPolicy),
            b"network.listen-start" => EventType::Network(NetworkEvent::ListenStart),
            b"network.listen-stop" => EventType::Network(NetworkEvent::ListenStop),
            b"network.listen-error" => EventType::Network(NetworkEvent::ListenError),
            b"network.bind-error" => EventType::Network(NetworkEvent::BindError),
            b"network.read-error" => EventType::Network(NetworkEvent::ReadError),
            b"network.write-error" => EventType::Network(NetworkEvent::WriteError),
            b"network.flush-error" => EventType::Network(NetworkEvent::FlushError),
            b"network.accept-error" => EventType::Network(NetworkEvent::AcceptError),
            b"network.split-error" => EventType::Network(NetworkEvent::SplitError),
            b"network.timeout" => EventType::Network(NetworkEvent::Timeout),
            b"network.closed" => EventType::Network(NetworkEvent::Closed),
            b"network.proxy-error" => EventType::Network(NetworkEvent::ProxyError),
            b"network.set-opt-error" => EventType::Network(NetworkEvent::SetOptError),
            b"outgoing-report.spf-report" => EventType::OutgoingReport(OutgoingReportEvent::SpfReport),
            b"outgoing-report.spf-rate-limited" => EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited),
            b"outgoing-report.dkim-report" => EventType::OutgoingReport(OutgoingReportEvent::DkimReport),
            b"outgoing-report.dkim-rate-limited" => EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited),
            b"outgoing-report.dmarc-report" => EventType::OutgoingReport(OutgoingReportEvent::DmarcReport),
            b"outgoing-report.dmarc-rate-limited" => EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited),
            b"outgoing-report.dmarc-aggregate-report" => EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport),
            b"outgoing-report.tls-aggregate" => EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate),
            b"outgoing-report.http-submission" => EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission),
            b"outgoing-report.unauthorized-reporting-address" => EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
            b"outgoing-report.reporting-address-validation-error" => EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError),
            b"outgoing-report.not-found" => EventType::OutgoingReport(OutgoingReportEvent::NotFound),
            b"outgoing-report.submission-error" => EventType::OutgoingReport(OutgoingReportEvent::SubmissionError),
            b"outgoing-report.no-recipients-found" => EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound),
            b"outgoing-report.locked" => EventType::OutgoingReport(OutgoingReportEvent::Locked),
            b"outgoing-report.max-size-exceeded" => EventType::OutgoingReport(OutgoingReportEvent::MaxSizeExceeded),
            b"pop3.connection-start" => EventType::Pop3(Pop3Event::ConnectionStart),
            b"pop3.connection-end" => EventType::Pop3(Pop3Event::ConnectionEnd),
            b"pop3.delete" => EventType::Pop3(Pop3Event::Delete),
            b"pop3.reset" => EventType::Pop3(Pop3Event::Reset),
            b"pop3.quit" => EventType::Pop3(Pop3Event::Quit),
            b"pop3.fetch" => EventType::Pop3(Pop3Event::Fetch),
            b"pop3.list" => EventType::Pop3(Pop3Event::List),
            b"pop3.list-message" => EventType::Pop3(Pop3Event::ListMessage),
            b"pop3.uidl" => EventType::Pop3(Pop3Event::Uidl),
            b"pop3.uidl-message" => EventType::Pop3(Pop3Event::UidlMessage),
            b"pop3.stat" => EventType::Pop3(Pop3Event::Stat),
            b"pop3.noop" => EventType::Pop3(Pop3Event::Noop),
            b"pop3.capabilities" => EventType::Pop3(Pop3Event::Capabilities),
            b"pop3.start-tls" => EventType::Pop3(Pop3Event::StartTls),
            b"pop3.utf8" => EventType::Pop3(Pop3Event::Utf8),
            b"pop3.error" => EventType::Pop3(Pop3Event::Error),
            b"pop3.raw-input" => EventType::Pop3(Pop3Event::RawInput),
            b"pop3.raw-output" => EventType::Pop3(Pop3Event::RawOutput),
            b"push-subscription.success" => EventType::PushSubscription(PushSubscriptionEvent::Success),
            b"push-subscription.error" => EventType::PushSubscription(PushSubscriptionEvent::Error),
            b"push-subscription.not-found" => EventType::PushSubscription(PushSubscriptionEvent::NotFound),
            b"queue.started" => EventType::Queue(QueueEvent::Started),
            b"queue.message-queued" => EventType::Queue(QueueEvent::MessageQueued),
            b"queue.authenticated-message-queued" => EventType::Queue(QueueEvent::AuthenticatedMessageQueued),
            b"queue.report-queued" => EventType::Queue(QueueEvent::ReportQueued),
            b"queue.dsn-queued" => EventType::Queue(QueueEvent::DsnQueued),
            b"queue.autogenerated-queued" => EventType::Queue(QueueEvent::AutogeneratedQueued),
            b"queue.rescheduled" => EventType::Queue(QueueEvent::Rescheduled),
            b"queue.locked" => EventType::Queue(QueueEvent::Locked),
            b"queue.blob-not-found" => EventType::Queue(QueueEvent::BlobNotFound),
            b"queue.rate-limit-exceeded" => EventType::Queue(QueueEvent::RateLimitExceeded),
            b"queue.concurrency-limit-exceeded" => EventType::Queue(QueueEvent::ConcurrencyLimitExceeded),
            b"queue.quota-exceeded" => EventType::Queue(QueueEvent::QuotaExceeded),
            b"queue.back-pressure" => EventType::Queue(QueueEvent::BackPressure),
            b"registry.local-read-error" => EventType::Registry(RegistryEvent::LocalReadError),
            b"registry.local-write-error" => EventType::Registry(RegistryEvent::LocalWriteError),
            b"registry.local-parse-error" => EventType::Registry(RegistryEvent::LocalParseError),
            b"registry.read-error" => EventType::Registry(RegistryEvent::ReadError),
            b"registry.write-error" => EventType::Registry(RegistryEvent::WriteError),
            b"registry.deserialization-error" => EventType::Registry(RegistryEvent::DeserializationError),
            b"registry.build-error" => EventType::Registry(RegistryEvent::BuildError),
            b"registry.build-warning" => EventType::Registry(RegistryEvent::BuildWarning),
            b"registry.not-supported" => EventType::Registry(RegistryEvent::NotSupported),
            b"registry.validation-error" => EventType::Registry(RegistryEvent::ValidationError),
            b"resource.not-found" => EventType::Resource(ResourceEvent::NotFound),
            b"resource.bad-parameters" => EventType::Resource(ResourceEvent::BadParameters),
            b"resource.error" => EventType::Resource(ResourceEvent::Error),
            b"resource.download-external" => EventType::Resource(ResourceEvent::DownloadExternal),
            b"resource.application-updated" => EventType::Resource(ResourceEvent::ApplicationUpdated),
            b"resource.application-unpacked" => EventType::Resource(ResourceEvent::ApplicationUnpacked),
            b"search-index.manager-started" => EventType::SearchIndex(SearchIndexEvent::ManagerStarted),
            b"search-index.partitions-acquired" => EventType::SearchIndex(SearchIndexEvent::PartitionsAcquired),
            b"search-index.partition-locked" => EventType::SearchIndex(SearchIndexEvent::PartitionLocked),
            b"search-index.partition-retry" => EventType::SearchIndex(SearchIndexEvent::PartitionRetry),
            b"search-index.batch-indexed" => EventType::SearchIndex(SearchIndexEvent::BatchIndexed),
            b"search-index.document-ignored" => EventType::SearchIndex(SearchIndexEvent::DocumentIgnored),
            b"search-index.document-truncated" => EventType::SearchIndex(SearchIndexEvent::DocumentTruncated),
            b"search-index.metadata-not-found" => EventType::SearchIndex(SearchIndexEvent::MetadataNotFound),
            b"security.authentication-ban" => EventType::Security(SecurityEvent::AuthenticationBan),
            b"security.abuse-ban" => EventType::Security(SecurityEvent::AbuseBan),
            b"security.scan-ban" => EventType::Security(SecurityEvent::ScanBan),
            b"security.loiter-ban" => EventType::Security(SecurityEvent::LoiterBan),
            b"security.ip-blocked" => EventType::Security(SecurityEvent::IpBlocked),
            b"security.ip-block-expired" => EventType::Security(SecurityEvent::IpBlockExpired),
            b"security.ip-allow-expired" => EventType::Security(SecurityEvent::IpAllowExpired),
            b"security.ip-unauthorized" => EventType::Security(SecurityEvent::IpUnauthorized),
            b"security.unauthorized" => EventType::Security(SecurityEvent::Unauthorized),
            b"server.startup" => EventType::Server(ServerEvent::Startup),
            b"server.shutdown" => EventType::Server(ServerEvent::Shutdown),
            b"server.startup-error" => EventType::Server(ServerEvent::StartupError),
            b"server.thread-error" => EventType::Server(ServerEvent::ThreadError),
            b"server.recovery-mode" => EventType::Server(ServerEvent::RecoveryMode),
            b"server.bootstrap-mode" => EventType::Server(ServerEvent::BootstrapMode),
            b"sieve.action-accept" => EventType::Sieve(SieveEvent::ActionAccept),
            b"sieve.action-accept-replace" => EventType::Sieve(SieveEvent::ActionAcceptReplace),
            b"sieve.action-discard" => EventType::Sieve(SieveEvent::ActionDiscard),
            b"sieve.action-reject" => EventType::Sieve(SieveEvent::ActionReject),
            b"sieve.send-message" => EventType::Sieve(SieveEvent::SendMessage),
            b"sieve.message-too-large" => EventType::Sieve(SieveEvent::MessageTooLarge),
            b"sieve.script-not-found" => EventType::Sieve(SieveEvent::ScriptNotFound),
            b"sieve.list-not-found" => EventType::Sieve(SieveEvent::ListNotFound),
            b"sieve.runtime-error" => EventType::Sieve(SieveEvent::RuntimeError),
            b"sieve.unexpected-error" => EventType::Sieve(SieveEvent::UnexpectedError),
            b"sieve.not-supported" => EventType::Sieve(SieveEvent::NotSupported),
            b"sieve.quota-exceeded" => EventType::Sieve(SieveEvent::QuotaExceeded),
            b"smtp.connection-start" => EventType::Smtp(SmtpEvent::ConnectionStart),
            b"smtp.connection-end" => EventType::Smtp(SmtpEvent::ConnectionEnd),
            b"smtp.error" => EventType::Smtp(SmtpEvent::Error),
            b"smtp.id-not-found" => EventType::Smtp(SmtpEvent::IdNotFound),
            b"smtp.concurrency-limit-exceeded" => EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded),
            b"smtp.transfer-limit-exceeded" => EventType::Smtp(SmtpEvent::TransferLimitExceeded),
            b"smtp.rate-limit-exceeded" => EventType::Smtp(SmtpEvent::RateLimitExceeded),
            b"smtp.time-limit-exceeded" => EventType::Smtp(SmtpEvent::TimeLimitExceeded),
            b"smtp.message-parse-failed" => EventType::Smtp(SmtpEvent::MessageParseFailed),
            b"smtp.message-too-large" => EventType::Smtp(SmtpEvent::MessageTooLarge),
            b"smtp.loop-detected" => EventType::Smtp(SmtpEvent::LoopDetected),
            b"smtp.multiple-from-domains" => EventType::Smtp(SmtpEvent::MultipleFromDomains),
            b"smtp.dkim-pass" => EventType::Smtp(SmtpEvent::DkimPass),
            b"smtp.dkim-fail" => EventType::Smtp(SmtpEvent::DkimFail),
            b"smtp.dkim2-pass" => EventType::Smtp(SmtpEvent::Dkim2Pass),
            b"smtp.dkim2-fail" => EventType::Smtp(SmtpEvent::Dkim2Fail),
            b"smtp.dkim2-dsn-rejected" => EventType::Smtp(SmtpEvent::Dkim2DsnRejected),
            b"smtp.arc-pass" => EventType::Smtp(SmtpEvent::ArcPass),
            b"smtp.arc-fail" => EventType::Smtp(SmtpEvent::ArcFail),
            b"smtp.spf-ehlo-pass" => EventType::Smtp(SmtpEvent::SpfEhloPass),
            b"smtp.spf-ehlo-fail" => EventType::Smtp(SmtpEvent::SpfEhloFail),
            b"smtp.spf-from-pass" => EventType::Smtp(SmtpEvent::SpfFromPass),
            b"smtp.spf-from-fail" => EventType::Smtp(SmtpEvent::SpfFromFail),
            b"smtp.dmarc-pass" => EventType::Smtp(SmtpEvent::DmarcPass),
            b"smtp.dmarc-fail" => EventType::Smtp(SmtpEvent::DmarcFail),
            b"smtp.iprev-pass" => EventType::Smtp(SmtpEvent::IprevPass),
            b"smtp.iprev-fail" => EventType::Smtp(SmtpEvent::IprevFail),
            b"smtp.too-many-messages" => EventType::Smtp(SmtpEvent::TooManyMessages),
            b"smtp.ehlo" => EventType::Smtp(SmtpEvent::Ehlo),
            b"smtp.invalid-ehlo" => EventType::Smtp(SmtpEvent::InvalidEhlo),
            b"smtp.did-not-say-ehlo" => EventType::Smtp(SmtpEvent::DidNotSayEhlo),
            b"smtp.ehlo-expected" => EventType::Smtp(SmtpEvent::EhloExpected),
            b"smtp.lhlo-expected" => EventType::Smtp(SmtpEvent::LhloExpected),
            b"smtp.mail-from-unauthenticated" => EventType::Smtp(SmtpEvent::MailFromUnauthenticated),
            b"smtp.mail-from-unauthorized" => EventType::Smtp(SmtpEvent::MailFromUnauthorized),
            b"smtp.mail-from-not-allowed" => EventType::Smtp(SmtpEvent::MailFromNotAllowed),
            b"smtp.mail-from-rewritten" => EventType::Smtp(SmtpEvent::MailFromRewritten),
            b"smtp.mail-from-missing" => EventType::Smtp(SmtpEvent::MailFromMissing),
            b"smtp.mail-from" => EventType::Smtp(SmtpEvent::MailFrom),
            b"smtp.multiple-mail-from" => EventType::Smtp(SmtpEvent::MultipleMailFrom),
            b"smtp.mailbox-does-not-exist" => EventType::Smtp(SmtpEvent::MailboxDoesNotExist),
            b"smtp.relay-not-allowed" => EventType::Smtp(SmtpEvent::RelayNotAllowed),
            b"smtp.rcpt-to" => EventType::Smtp(SmtpEvent::RcptTo),
            b"smtp.rcpt-to-duplicate" => EventType::Smtp(SmtpEvent::RcptToDuplicate),
            b"smtp.rcpt-to-rewritten" => EventType::Smtp(SmtpEvent::RcptToRewritten),
            b"smtp.rcpt-to-missing" => EventType::Smtp(SmtpEvent::RcptToMissing),
            b"smtp.rcpt-to-greylisted" => EventType::Smtp(SmtpEvent::RcptToGreylisted),
            b"smtp.too-many-recipients" => EventType::Smtp(SmtpEvent::TooManyRecipients),
            b"smtp.too-many-invalid-rcpt" => EventType::Smtp(SmtpEvent::TooManyInvalidRcpt),
            b"smtp.raw-input" => EventType::Smtp(SmtpEvent::RawInput),
            b"smtp.raw-output" => EventType::Smtp(SmtpEvent::RawOutput),
            b"smtp.missing-local-hostname" => EventType::Smtp(SmtpEvent::MissingLocalHostname),
            b"smtp.vrfy" => EventType::Smtp(SmtpEvent::Vrfy),
            b"smtp.vrfy-not-found" => EventType::Smtp(SmtpEvent::VrfyNotFound),
            b"smtp.vrfy-disabled" => EventType::Smtp(SmtpEvent::VrfyDisabled),
            b"smtp.expn" => EventType::Smtp(SmtpEvent::Expn),
            b"smtp.expn-not-found" => EventType::Smtp(SmtpEvent::ExpnNotFound),
            b"smtp.expn-disabled" => EventType::Smtp(SmtpEvent::ExpnDisabled),
            b"smtp.require-tls-disabled" => EventType::Smtp(SmtpEvent::RequireTlsDisabled),
            b"smtp.deliver-by-disabled" => EventType::Smtp(SmtpEvent::DeliverByDisabled),
            b"smtp.deliver-by-invalid" => EventType::Smtp(SmtpEvent::DeliverByInvalid),
            b"smtp.future-release-disabled" => EventType::Smtp(SmtpEvent::FutureReleaseDisabled),
            b"smtp.future-release-invalid" => EventType::Smtp(SmtpEvent::FutureReleaseInvalid),
            b"smtp.mt-priority-disabled" => EventType::Smtp(SmtpEvent::MtPriorityDisabled),
            b"smtp.mt-priority-invalid" => EventType::Smtp(SmtpEvent::MtPriorityInvalid),
            b"smtp.dsn-disabled" => EventType::Smtp(SmtpEvent::DsnDisabled),
            b"smtp.auth-not-allowed" => EventType::Smtp(SmtpEvent::AuthNotAllowed),
            b"smtp.auth-mechanism-not-supported" => EventType::Smtp(SmtpEvent::AuthMechanismNotSupported),
            b"smtp.auth-exchange-too-long" => EventType::Smtp(SmtpEvent::AuthExchangeTooLong),
            b"smtp.already-authenticated" => EventType::Smtp(SmtpEvent::AlreadyAuthenticated),
            b"smtp.noop" => EventType::Smtp(SmtpEvent::Noop),
            b"smtp.start-tls" => EventType::Smtp(SmtpEvent::StartTls),
            b"smtp.start-tls-unavailable" => EventType::Smtp(SmtpEvent::StartTlsUnavailable),
            b"smtp.start-tls-already" => EventType::Smtp(SmtpEvent::StartTlsAlready),
            b"smtp.rset" => EventType::Smtp(SmtpEvent::Rset),
            b"smtp.quit" => EventType::Smtp(SmtpEvent::Quit),
            b"smtp.help" => EventType::Smtp(SmtpEvent::Help),
            b"smtp.command-not-implemented" => EventType::Smtp(SmtpEvent::CommandNotImplemented),
            b"smtp.invalid-command" => EventType::Smtp(SmtpEvent::InvalidCommand),
            b"smtp.invalid-sender-address" => EventType::Smtp(SmtpEvent::InvalidSenderAddress),
            b"smtp.invalid-recipient-address" => EventType::Smtp(SmtpEvent::InvalidRecipientAddress),
            b"smtp.invalid-parameter" => EventType::Smtp(SmtpEvent::InvalidParameter),
            b"smtp.unsupported-parameter" => EventType::Smtp(SmtpEvent::UnsupportedParameter),
            b"smtp.syntax-error" => EventType::Smtp(SmtpEvent::SyntaxError),
            b"smtp.request-too-large" => EventType::Smtp(SmtpEvent::RequestTooLarge),
            b"spam.pyzor" => EventType::Spam(SpamEvent::Pyzor),
            b"spam.pyzor-error" => EventType::Spam(SpamEvent::PyzorError),
            b"spam.dnsbl" => EventType::Spam(SpamEvent::Dnsbl),
            b"spam.dnsbl-error" => EventType::Spam(SpamEvent::DnsblError),
            b"spam.train-started" => EventType::Spam(SpamEvent::TrainStarted),
            b"spam.train-completed" => EventType::Spam(SpamEvent::TrainCompleted),
            b"spam.train-sample-added" => EventType::Spam(SpamEvent::TrainSampleAdded),
            b"spam.train-sample-not-found" => EventType::Spam(SpamEvent::TrainSampleNotFound),
            b"spam.classify" => EventType::Spam(SpamEvent::Classify),
            b"spam.model-loaded" => EventType::Spam(SpamEvent::ModelLoaded),
            b"spam.model-not-ready" => EventType::Spam(SpamEvent::ModelNotReady),
            b"spam.model-not-found" => EventType::Spam(SpamEvent::ModelNotFound),
            b"spam.rules-updated" => EventType::Spam(SpamEvent::RulesUpdated),
            b"spf.pass" => EventType::Spf(SpfEvent::Pass),
            b"spf.fail" => EventType::Spf(SpfEvent::Fail),
            b"spf.soft-fail" => EventType::Spf(SpfEvent::SoftFail),
            b"spf.neutral" => EventType::Spf(SpfEvent::Neutral),
            b"spf.temp-error" => EventType::Spf(SpfEvent::TempError),
            b"spf.perm-error" => EventType::Spf(SpfEvent::PermError),
            b"spf.none" => EventType::Spf(SpfEvent::None),
            b"store.assert-value-failed" => EventType::Store(StoreEvent::AssertValueFailed),
            b"store.foundationdb-error" => EventType::Store(StoreEvent::FoundationdbError),
            b"store.mysql-error" => EventType::Store(StoreEvent::MysqlError),
            b"store.postgresql-error" => EventType::Store(StoreEvent::PostgresqlError),
            b"store.rocksdb-error" => EventType::Store(StoreEvent::RocksdbError),
            b"store.sqlite-error" => EventType::Store(StoreEvent::SqliteError),
            b"store.ldap-error" => EventType::Store(StoreEvent::LdapError),
            b"store.elasticsearch-error" => EventType::Store(StoreEvent::ElasticsearchError),
            b"store.meilisearch-error" => EventType::Store(StoreEvent::MeilisearchError),
            b"store.redis-error" => EventType::Store(StoreEvent::RedisError),
            b"store.s3-error" => EventType::Store(StoreEvent::S3Error),
            b"store.azure-error" => EventType::Store(StoreEvent::AzureError),
            b"store.filesystem-error" => EventType::Store(StoreEvent::FilesystemError),
            b"store.pool-error" => EventType::Store(StoreEvent::PoolError),
            b"store.data-corruption" => EventType::Store(StoreEvent::DataCorruption),
            b"store.decompress-error" => EventType::Store(StoreEvent::DecompressError),
            b"store.deserialize-error" => EventType::Store(StoreEvent::DeserializeError),
            b"store.not-found" => EventType::Store(StoreEvent::NotFound),
            b"store.not-configured" => EventType::Store(StoreEvent::NotConfigured),
            b"store.not-supported" => EventType::Store(StoreEvent::NotSupported),
            b"store.unexpected-error" => EventType::Store(StoreEvent::UnexpectedError),
            b"store.crypto-error" => EventType::Store(StoreEvent::CryptoError),
            b"store.http-store-error" => EventType::Store(StoreEvent::HttpStoreError),
            b"store.blob-missing-marker" => EventType::Store(StoreEvent::BlobMissingMarker),
            b"store.data-write" => EventType::Store(StoreEvent::DataWrite),
            b"store.data-iterate" => EventType::Store(StoreEvent::DataIterate),
            b"store.blob-read" => EventType::Store(StoreEvent::BlobRead),
            b"store.blob-write" => EventType::Store(StoreEvent::BlobWrite),
            b"store.blob-delete" => EventType::Store(StoreEvent::BlobDelete),
            b"store.sql-query" => EventType::Store(StoreEvent::SqlQuery),
            b"store.ldap-query" => EventType::Store(StoreEvent::LdapQuery),
            b"store.ldap-warning" => EventType::Store(StoreEvent::LdapWarning),
            b"store.http-store-fetch" => EventType::Store(StoreEvent::HttpStoreFetch),
            b"store.auto-expunge" => EventType::Store(StoreEvent::AutoExpunge),
            b"store.blob-store-purged" => EventType::Store(StoreEvent::BlobStorePurged),
            b"store.data-store-purged" => EventType::Store(StoreEvent::DataStorePurged),
            b"task-manager.task-acquired" => EventType::TaskManager(TaskManagerEvent::TaskAcquired),
            b"task-manager.task-queued" => EventType::TaskManager(TaskManagerEvent::TaskQueued),
            b"task-manager.task-scheduled" => EventType::TaskManager(TaskManagerEvent::TaskScheduled),
            b"task-manager.task-locked" => EventType::TaskManager(TaskManagerEvent::TaskLocked),
            b"task-manager.task-ignored" => EventType::TaskManager(TaskManagerEvent::TaskIgnored),
            b"task-manager.task-failed" => EventType::TaskManager(TaskManagerEvent::TaskFailed),
            b"task-manager.task-retry" => EventType::TaskManager(TaskManagerEvent::TaskRetry),
            b"task-manager.task-stalled" => EventType::TaskManager(TaskManagerEvent::TaskStalled),
            b"task-manager.task-expired" => EventType::TaskManager(TaskManagerEvent::TaskExpired),
            b"task-manager.blob-not-found" => EventType::TaskManager(TaskManagerEvent::BlobNotFound),
            b"task-manager.metadata-not-found" => EventType::TaskManager(TaskManagerEvent::MetadataNotFound),
            b"task-manager.scheduler-started" => EventType::TaskManager(TaskManagerEvent::SchedulerStarted),
            b"task-manager.manager-started" => EventType::TaskManager(TaskManagerEvent::ManagerStarted),
            b"telemetry.log-error" => EventType::Telemetry(TelemetryEvent::LogError),
            b"telemetry.webhook-error" => EventType::Telemetry(TelemetryEvent::WebhookError),
            b"telemetry.otel-exporter-error" => EventType::Telemetry(TelemetryEvent::OtelExporterError),
            b"telemetry.otel-metrics-exporter-error" => EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError),
            b"telemetry.prometheus-exporter-error" => EventType::Telemetry(TelemetryEvent::PrometheusExporterError),
            b"telemetry.journal-error" => EventType::Telemetry(TelemetryEvent::JournalError),
            b"telemetry.events-dropped" => EventType::Telemetry(TelemetryEvent::EventsDropped),
            b"telemetry.metrics-collected" => EventType::Telemetry(TelemetryEvent::MetricsCollected),
            b"telemetry.metrics-pushed" => EventType::Telemetry(TelemetryEvent::MetricsPushed),
            b"tls.handshake" => EventType::Tls(TlsEvent::Handshake),
            b"tls.handshake-error" => EventType::Tls(TlsEvent::HandshakeError),
            b"tls.not-configured" => EventType::Tls(TlsEvent::NotConfigured),
            b"tls.certificate-not-found" => EventType::Tls(TlsEvent::CertificateNotFound),
            b"tls.no-certificates-available" => EventType::Tls(TlsEvent::NoCertificatesAvailable),
            b"tls.multiple-certificates-available" => EventType::Tls(TlsEvent::MultipleCertificatesAvailable),
            b"tls.expired-certificate-removed" => EventType::Tls(TlsEvent::ExpiredCertificateRemoved),
            b"tls-rpt.record-fetch" => EventType::TlsRpt(TlsRptEvent::RecordFetch),
            b"tls-rpt.record-fetch-error" => EventType::TlsRpt(TlsRptEvent::RecordFetchError),
            b"tls-rpt.record-not-found" => EventType::TlsRpt(TlsRptEvent::RecordNotFound),
            b"web-dav.propfind" => EventType::WebDav(WebDavEvent::Propfind),
            b"web-dav.proppatch" => EventType::WebDav(WebDavEvent::Proppatch),
            b"web-dav.get" => EventType::WebDav(WebDavEvent::Get),
            b"web-dav.head" => EventType::WebDav(WebDavEvent::Head),
            b"web-dav.report" => EventType::WebDav(WebDavEvent::Report),
            b"web-dav.mkcol" => EventType::WebDav(WebDavEvent::Mkcol),
            b"web-dav.mkcalendar" => EventType::WebDav(WebDavEvent::Mkcalendar),
            b"web-dav.delete" => EventType::WebDav(WebDavEvent::Delete),
            b"web-dav.put" => EventType::WebDav(WebDavEvent::Put),
            b"web-dav.post" => EventType::WebDav(WebDavEvent::Post),
            b"web-dav.patch" => EventType::WebDav(WebDavEvent::Patch),
            b"web-dav.copy" => EventType::WebDav(WebDavEvent::Copy),
            b"web-dav.move" => EventType::WebDav(WebDavEvent::Move),
            b"web-dav.lock" => EventType::WebDav(WebDavEvent::Lock),
            b"web-dav.unlock" => EventType::WebDav(WebDavEvent::Unlock),
            b"web-dav.acl" => EventType::WebDav(WebDavEvent::Acl),
            b"web-dav.options" => EventType::WebDav(WebDavEvent::Options),
            b"web-dav.error" => EventType::WebDav(WebDavEvent::Error),
        }
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Acme(AcmeEvent::AuthStart) => "acme.auth-start",
            EventType::Acme(AcmeEvent::AuthPending) => "acme.auth-pending",
            EventType::Acme(AcmeEvent::AuthValid) => "acme.auth-valid",
            EventType::Acme(AcmeEvent::AuthCompleted) => "acme.auth-completed",
            EventType::Acme(AcmeEvent::AuthError) => "acme.auth-error",
            EventType::Acme(AcmeEvent::AuthTooManyAttempts) => "acme.auth-too-many-attempts",
            EventType::Acme(AcmeEvent::ProcessCert) => "acme.process-cert",
            EventType::Acme(AcmeEvent::OrderStart) => "acme.order-start",
            EventType::Acme(AcmeEvent::OrderProcessing) => "acme.order-processing",
            EventType::Acme(AcmeEvent::OrderCompleted) => "acme.order-completed",
            EventType::Acme(AcmeEvent::OrderReady) => "acme.order-ready",
            EventType::Acme(AcmeEvent::OrderValid) => "acme.order-valid",
            EventType::Acme(AcmeEvent::OrderInvalid) => "acme.order-invalid",
            EventType::Acme(AcmeEvent::RenewBackoff) => "acme.renew-backoff",
            EventType::Acme(AcmeEvent::ClientSuppliedSni) => "acme.client-supplied-sni",
            EventType::Acme(AcmeEvent::ClientMissingSni) => "acme.client-missing-sni",
            EventType::Acme(AcmeEvent::TlsAlpnReceived) => "acme.tls-alpn-received",
            EventType::Acme(AcmeEvent::TlsAlpnError) => "acme.tls-alpn-error",
            EventType::Acme(AcmeEvent::TokenNotFound) => "acme.token-not-found",
            EventType::Acme(AcmeEvent::Error) => "acme.error",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::LlmResponse) => "ai.llm-response",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::ApiError) => "ai.api-error",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::Request) => "ai.request",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamVerdict) => "ai.spam-verdict",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamSkipped) => "ai.spam-skipped",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::BreakerOpen) => "ai.breaker-open",
            // SPDX-SnippetEnd
            EventType::Arc(ArcEvent::ChainInvalid) => "arc.chain-invalid",
            EventType::Arc(ArcEvent::SignatureInvalid) => "arc.signature-invalid",
            EventType::Arc(ArcEvent::HashMismatch) => "arc.hash-mismatch",
            EventType::Auth(AuthEvent::Success) => "auth.success",
            EventType::Auth(AuthEvent::Failed) => "auth.failed",
            EventType::Auth(AuthEvent::TokenExpired) => "auth.token-expired",
            EventType::Auth(AuthEvent::MfaRequired) => "auth.mfa-required",
            EventType::Auth(AuthEvent::TooManyAttempts) => "auth.too-many-attempts",
            EventType::Auth(AuthEvent::ClientRegistration) => "auth.client-registration",
            EventType::Auth(AuthEvent::Error) => "auth.error",
            EventType::Auth(AuthEvent::Warning) => "auth.warning",
            EventType::Auth(AuthEvent::CredentialExpired) => "auth.credential-expired",
            EventType::Cache(CacheEvent::Miss) => "cache.miss",
            EventType::Cache(CacheEvent::Hit) => "cache.hit",
            EventType::Cache(CacheEvent::Stale) => "cache.stale",
            EventType::Cache(CacheEvent::Update) => "cache.update",
            EventType::Cache(CacheEvent::EntryTooLarge) => "cache.entry-too-large",
            EventType::Cache(CacheEvent::Invalidate) => "cache.invalidate",
            EventType::Cache(CacheEvent::SwapHit) => "cache.swap-hit",
            EventType::Cache(CacheEvent::SwapMiss) => "cache.swap-miss",
            EventType::Cache(CacheEvent::SwapWrite) => "cache.swap-write",
            EventType::Cache(CacheEvent::SwapError) => "cache.swap-error",
            EventType::Cache(CacheEvent::SwapMetrics) => "cache.swap-metrics",
            EventType::Cache(CacheEvent::SwapFlush) => "cache.swap-flush",
            EventType::Calendar(CalendarEvent::RuleExpansionError) => {
                "calendar.rule-expansion-error"
            }
            EventType::Calendar(CalendarEvent::AlarmSent) => "calendar.alarm-sent",
            EventType::Calendar(CalendarEvent::AlarmSkipped) => "calendar.alarm-skipped",
            EventType::Calendar(CalendarEvent::AlarmRecipientOverride) => {
                "calendar.alarm-recipient-override"
            }
            EventType::Calendar(CalendarEvent::AlarmFailed) => "calendar.alarm-failed",
            EventType::Calendar(CalendarEvent::ItipMessageSent) => "calendar.itip-message-sent",
            EventType::Calendar(CalendarEvent::ItipMessageReceived) => {
                "calendar.itip-message-received"
            }
            EventType::Calendar(CalendarEvent::ItipMessageError) => "calendar.itip-message-error",
            EventType::Cluster(ClusterEvent::Startup) => "cluster.startup",
            EventType::Cluster(ClusterEvent::SubscriberStart) => "cluster.subscriber-start",
            EventType::Cluster(ClusterEvent::SubscriberStop) => "cluster.subscriber-stop",
            EventType::Cluster(ClusterEvent::SubscriberError) => "cluster.subscriber-error",
            EventType::Cluster(ClusterEvent::SubscriberDisconnected) => {
                "cluster.subscriber-disconnected"
            }
            EventType::Cluster(ClusterEvent::PublisherStart) => "cluster.publisher-start",
            EventType::Cluster(ClusterEvent::PublisherStop) => "cluster.publisher-stop",
            EventType::Cluster(ClusterEvent::PublisherError) => "cluster.publisher-error",
            EventType::Cluster(ClusterEvent::MessageReceived) => "cluster.message-received",
            EventType::Cluster(ClusterEvent::MessageSkipped) => "cluster.message-skipped",
            EventType::Cluster(ClusterEvent::MessageInvalid) => "cluster.message-invalid",
            EventType::Cluster(ClusterEvent::NodeIdRenewed) => "cluster.node-id-renewed",
            EventType::Dane(DaneEvent::AuthenticationSuccess) => "dane.authentication-success",
            EventType::Dane(DaneEvent::AuthenticationFailure) => "dane.authentication-failure",
            EventType::Dane(DaneEvent::NoCertificatesFound) => "dane.no-certificates-found",
            EventType::Dane(DaneEvent::CertificateParseError) => "dane.certificate-parse-error",
            EventType::Dane(DaneEvent::TlsaRecordMatch) => "dane.tlsa-record-match",
            EventType::Dane(DaneEvent::TlsaRecordFetch) => "dane.tlsa-record-fetch",
            EventType::Dane(DaneEvent::TlsaRecordFetchError) => "dane.tlsa-record-fetch-error",
            EventType::Dane(DaneEvent::TlsaRecordNotFound) => "dane.tlsa-record-not-found",
            EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned) => {
                "dane.tlsa-record-not-dnssec-signed"
            }
            EventType::Dane(DaneEvent::TlsaRecordInvalid) => "dane.tlsa-record-invalid",
            EventType::Dane(DaneEvent::BogusDnssecRecord) => "dane.bogus-dnssec-record",
            EventType::Delivery(DeliveryEvent::AttemptStart) => "delivery.attempt-start",
            EventType::Delivery(DeliveryEvent::AttemptEnd) => "delivery.attempt-end",
            EventType::Delivery(DeliveryEvent::Completed) => "delivery.completed",
            EventType::Delivery(DeliveryEvent::Failed) => "delivery.failed",
            EventType::Delivery(DeliveryEvent::DomainDeliveryStart) => {
                "delivery.domain-delivery-start"
            }
            EventType::Delivery(DeliveryEvent::MxLookup) => "delivery.mx-lookup",
            EventType::Delivery(DeliveryEvent::MxLookupFailed) => "delivery.mx-lookup-failed",
            EventType::Delivery(DeliveryEvent::IpLookup) => "delivery.ip-lookup",
            EventType::Delivery(DeliveryEvent::IpLookupFailed) => "delivery.ip-lookup-failed",
            EventType::Delivery(DeliveryEvent::NullMx) => "delivery.null-mx",
            EventType::Delivery(DeliveryEvent::Connect) => "delivery.connect",
            EventType::Delivery(DeliveryEvent::ConnectError) => "delivery.connect-error",
            EventType::Delivery(DeliveryEvent::MissingOutboundHostname) => {
                "delivery.missing-outbound-hostname"
            }
            EventType::Delivery(DeliveryEvent::GreetingFailed) => "delivery.greeting-failed",
            EventType::Delivery(DeliveryEvent::Ehlo) => "delivery.ehlo",
            EventType::Delivery(DeliveryEvent::EhloRejected) => "delivery.ehlo-rejected",
            EventType::Delivery(DeliveryEvent::Auth) => "delivery.auth",
            EventType::Delivery(DeliveryEvent::AuthFailed) => "delivery.auth-failed",
            EventType::Delivery(DeliveryEvent::MailFrom) => "delivery.mail-from",
            EventType::Delivery(DeliveryEvent::MailFromRejected) => "delivery.mail-from-rejected",
            EventType::Delivery(DeliveryEvent::Delivered) => "delivery.delivered",
            EventType::Delivery(DeliveryEvent::RcptTo) => "delivery.rcpt-to",
            EventType::Delivery(DeliveryEvent::RcptToRejected) => "delivery.rcpt-to-rejected",
            EventType::Delivery(DeliveryEvent::RcptToFailed) => "delivery.rcpt-to-failed",
            EventType::Delivery(DeliveryEvent::MessageRejected) => "delivery.message-rejected",
            EventType::Delivery(DeliveryEvent::StartTls) => "delivery.start-tls",
            EventType::Delivery(DeliveryEvent::StartTlsUnavailable) => {
                "delivery.start-tls-unavailable"
            }
            EventType::Delivery(DeliveryEvent::StartTlsError) => "delivery.start-tls-error",
            EventType::Delivery(DeliveryEvent::StartTlsDisabled) => "delivery.start-tls-disabled",
            EventType::Delivery(DeliveryEvent::ImplicitTlsError) => "delivery.implicit-tls-error",
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded) => {
                "delivery.concurrency-limit-exceeded"
            }
            EventType::Delivery(DeliveryEvent::RateLimitExceeded) => "delivery.rate-limit-exceeded",
            EventType::Delivery(DeliveryEvent::DoubleBounce) => "delivery.double-bounce",
            EventType::Delivery(DeliveryEvent::DsnSuccess) => "delivery.dsn-success",
            EventType::Delivery(DeliveryEvent::DsnTempFail) => "delivery.dsn-temp-fail",
            EventType::Delivery(DeliveryEvent::DsnPermFail) => "delivery.dsn-perm-fail",
            EventType::Delivery(DeliveryEvent::RawInput) => "delivery.raw-input",
            EventType::Delivery(DeliveryEvent::RawOutput) => "delivery.raw-output",
            EventType::Dkim(DkimEvent::Pass) => "dkim.pass",
            EventType::Dkim(DkimEvent::Neutral) => "dkim.neutral",
            EventType::Dkim(DkimEvent::Fail) => "dkim.fail",
            EventType::Dkim(DkimEvent::PermError) => "dkim.perm-error",
            EventType::Dkim(DkimEvent::TempError) => "dkim.temp-error",
            EventType::Dkim(DkimEvent::None) => "dkim.none",
            EventType::Dkim(DkimEvent::SignatureInvalid) => "dkim.signature-invalid",
            EventType::Dkim(DkimEvent::PublicKeyError) => "dkim.public-key-error",
            EventType::Dkim(DkimEvent::VerificationFailed) => "dkim.verification-failed",
            EventType::Dkim(DkimEvent::HashMismatch) => "dkim.hash-mismatch",
            EventType::Dkim(DkimEvent::SignerNotFound) => "dkim.signer-not-found",
            EventType::Dkim(DkimEvent::BuildError) => "dkim.build-error",
            EventType::Dkim(DkimEvent::SignatureCreated) => "dkim.signature-created",
            EventType::Dkim(DkimEvent::SignaturePublished) => "dkim.signature-published",
            EventType::Dkim(DkimEvent::SignatureRetiring) => "dkim.signature-retiring",
            EventType::Dkim(DkimEvent::SignatureRetired) => "dkim.signature-retired",
            EventType::Dkim(DkimEvent::SignatureDeleted) => "dkim.signature-deleted",
            EventType::Dkim2(Dkim2Event::InstanceInvalid) => "dkim2.instance-invalid",
            EventType::Dkim2(Dkim2Event::SignatureInvalid) => "dkim2.signature-invalid",
            EventType::Dkim2(Dkim2Event::ChainInvalid) => "dkim2.chain-invalid",
            EventType::Dkim2(Dkim2Event::TimestampInvalid) => "dkim2.timestamp-invalid",
            EventType::Dkim2(Dkim2Event::EnvelopeMismatch) => "dkim2.envelope-mismatch",
            EventType::Dkim2(Dkim2Event::CustodyBroken) => "dkim2.custody-broken",
            EventType::Dkim2(Dkim2Event::PublicKeyError) => "dkim2.public-key-error",
            EventType::Dkim2(Dkim2Event::VerificationFailed) => "dkim2.verification-failed",
            EventType::Dkim2(Dkim2Event::HashMismatch) => "dkim2.hash-mismatch",
            EventType::Dkim2(Dkim2Event::RecipeError) => "dkim2.recipe-error",
            EventType::Dkim2(Dkim2Event::SigningFailed) => "dkim2.signing-failed",
            EventType::Dmarc(DmarcEvent::Pass) => "dmarc.pass",
            EventType::Dmarc(DmarcEvent::Fail) => "dmarc.fail",
            EventType::Dmarc(DmarcEvent::PermError) => "dmarc.perm-error",
            EventType::Dmarc(DmarcEvent::TempError) => "dmarc.temp-error",
            EventType::Dmarc(DmarcEvent::None) => "dmarc.none",
            EventType::Dns(DnsEvent::RecordCreated) => "dns.record-created",
            EventType::Dns(DnsEvent::RecordCreationFailed) => "dns.record-creation-failed",
            EventType::Dns(DnsEvent::RecordDeletionFailed) => "dns.record-deletion-failed",
            EventType::Dns(DnsEvent::RecordNotPropagated) => "dns.record-not-propagated",
            EventType::Dns(DnsEvent::RecordLookupFailed) => "dns.record-lookup-failed",
            EventType::Dns(DnsEvent::RecordPropagated) => "dns.record-propagated",
            EventType::Dns(DnsEvent::RecordPropagationTimeout) => "dns.record-propagation-timeout",
            EventType::Eval(EvalEvent::Result) => "eval.result",
            EventType::Eval(EvalEvent::Error) => "eval.error",
            EventType::Eval(EvalEvent::DirectoryNotFound) => "eval.directory-not-found",
            EventType::Eval(EvalEvent::StoreNotFound) => "eval.store-not-found",
            EventType::Http(HttpEvent::ConnectionStart) => "http.connection-start",
            EventType::Http(HttpEvent::ConnectionEnd) => "http.connection-end",
            EventType::Http(HttpEvent::Error) => "http.error",
            EventType::Http(HttpEvent::RequestUrl) => "http.request-url",
            EventType::Http(HttpEvent::RequestBody) => "http.request-body",
            EventType::Http(HttpEvent::ResponseBody) => "http.response-body",
            EventType::Http(HttpEvent::XForwardedMissing) => "http.x-forwarded-missing",
            EventType::Http(HttpEvent::XForwardedInvalid) => "http.x-forwarded-invalid",
            EventType::Imap(ImapEvent::ConnectionStart) => "imap.connection-start",
            EventType::Imap(ImapEvent::ConnectionEnd) => "imap.connection-end",
            EventType::Imap(ImapEvent::GetAcl) => "imap.get-acl",
            EventType::Imap(ImapEvent::SetAcl) => "imap.set-acl",
            EventType::Imap(ImapEvent::MyRights) => "imap.my-rights",
            EventType::Imap(ImapEvent::ListRights) => "imap.list-rights",
            EventType::Imap(ImapEvent::Append) => "imap.append",
            EventType::Imap(ImapEvent::Capabilities) => "imap.capabilities",
            EventType::Imap(ImapEvent::Id) => "imap.id",
            EventType::Imap(ImapEvent::Close) => "imap.close",
            EventType::Imap(ImapEvent::Copy) => "imap.copy",
            EventType::Imap(ImapEvent::Move) => "imap.move",
            EventType::Imap(ImapEvent::CreateMailbox) => "imap.create-mailbox",
            EventType::Imap(ImapEvent::DeleteMailbox) => "imap.delete-mailbox",
            EventType::Imap(ImapEvent::RenameMailbox) => "imap.rename-mailbox",
            EventType::Imap(ImapEvent::Enable) => "imap.enable",
            EventType::Imap(ImapEvent::Expunge) => "imap.expunge",
            EventType::Imap(ImapEvent::Fetch) => "imap.fetch",
            EventType::Imap(ImapEvent::IdleStart) => "imap.idle-start",
            EventType::Imap(ImapEvent::IdleStop) => "imap.idle-stop",
            EventType::Imap(ImapEvent::List) => "imap.list",
            EventType::Imap(ImapEvent::Lsub) => "imap.lsub",
            EventType::Imap(ImapEvent::Logout) => "imap.logout",
            EventType::Imap(ImapEvent::Namespace) => "imap.namespace",
            EventType::Imap(ImapEvent::Noop) => "imap.noop",
            EventType::Imap(ImapEvent::Search) => "imap.search",
            EventType::Imap(ImapEvent::Sort) => "imap.sort",
            EventType::Imap(ImapEvent::Select) => "imap.select",
            EventType::Imap(ImapEvent::Status) => "imap.status",
            EventType::Imap(ImapEvent::Store) => "imap.store",
            EventType::Imap(ImapEvent::Subscribe) => "imap.subscribe",
            EventType::Imap(ImapEvent::Unsubscribe) => "imap.unsubscribe",
            EventType::Imap(ImapEvent::Thread) => "imap.thread",
            EventType::Imap(ImapEvent::UidBatches) => "imap.uid-batches",
            EventType::Imap(ImapEvent::GetQuota) => "imap.get-quota",
            EventType::Imap(ImapEvent::GetMetadata) => "imap.get-metadata",
            EventType::Imap(ImapEvent::SetMetadata) => "imap.set-metadata",
            EventType::Imap(ImapEvent::Error) => "imap.error",
            EventType::Imap(ImapEvent::RawInput) => "imap.raw-input",
            EventType::Imap(ImapEvent::RawOutput) => "imap.raw-output",
            EventType::IncomingReport(IncomingReportEvent::DmarcReport) => {
                "incoming-report.dmarc-report"
            }
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings) => {
                "incoming-report.dmarc-report-with-warnings"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsReport) => {
                "incoming-report.tls-report"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings) => {
                "incoming-report.tls-report-with-warnings"
            }
            EventType::IncomingReport(IncomingReportEvent::AbuseReport) => {
                "incoming-report.abuse-report"
            }
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport) => {
                "incoming-report.auth-failure-report"
            }
            EventType::IncomingReport(IncomingReportEvent::FraudReport) => {
                "incoming-report.fraud-report"
            }
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport) => {
                "incoming-report.not-spam-report"
            }
            EventType::IncomingReport(IncomingReportEvent::VirusReport) => {
                "incoming-report.virus-report"
            }
            EventType::IncomingReport(IncomingReportEvent::OtherReport) => {
                "incoming-report.other-report"
            }
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed) => {
                "incoming-report.message-parse-failed"
            }
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed) => {
                "incoming-report.dmarc-parse-failed"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed) => {
                "incoming-report.tls-rpc-parse-failed"
            }
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed) => {
                "incoming-report.arf-parse-failed"
            }
            EventType::IncomingReport(IncomingReportEvent::DecompressError) => {
                "incoming-report.decompress-error"
            }
            EventType::Iprev(IprevEvent::Pass) => "iprev.pass",
            EventType::Iprev(IprevEvent::Fail) => "iprev.fail",
            EventType::Iprev(IprevEvent::PermError) => "iprev.perm-error",
            EventType::Iprev(IprevEvent::TempError) => "iprev.temp-error",
            EventType::Iprev(IprevEvent::None) => "iprev.none",
            EventType::Jmap(JmapEvent::MethodCall) => "jmap.method-call",
            EventType::Jmap(JmapEvent::InvalidArguments) => "jmap.invalid-arguments",
            EventType::Jmap(JmapEvent::RequestTooLarge) => "jmap.request-too-large",
            EventType::Jmap(JmapEvent::StateMismatch) => "jmap.state-mismatch",
            EventType::Jmap(JmapEvent::AnchorNotFound) => "jmap.anchor-not-found",
            EventType::Jmap(JmapEvent::UnsupportedFilter) => "jmap.unsupported-filter",
            EventType::Jmap(JmapEvent::UnsupportedSort) => "jmap.unsupported-sort",
            EventType::Jmap(JmapEvent::UnknownMethod) => "jmap.unknown-method",
            EventType::Jmap(JmapEvent::InvalidResultReference) => "jmap.invalid-result-reference",
            EventType::Jmap(JmapEvent::Forbidden) => "jmap.forbidden",
            EventType::Jmap(JmapEvent::AccountNotFound) => "jmap.account-not-found",
            EventType::Jmap(JmapEvent::AccountNotSupportedByMethod) => {
                "jmap.account-not-supported-by-method"
            }
            EventType::Jmap(JmapEvent::AccountReadOnly) => "jmap.account-read-only",
            EventType::Jmap(JmapEvent::FromAccountNotFound) => "jmap.from-account-not-found",
            EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod) => {
                "jmap.from-account-not-supported-by-method"
            }
            EventType::Jmap(JmapEvent::NotFound) => "jmap.not-found",
            EventType::Jmap(JmapEvent::CannotCalculateChanges) => "jmap.cannot-calculate-changes",
            EventType::Jmap(JmapEvent::UnknownDataType) => "jmap.unknown-data-type",
            EventType::Jmap(JmapEvent::UnknownCapability) => "jmap.unknown-capability",
            EventType::Jmap(JmapEvent::NotJson) => "jmap.not-json",
            EventType::Jmap(JmapEvent::NotRequest) => "jmap.not-request",
            EventType::Jmap(JmapEvent::WebsocketStart) => "jmap.websocket-start",
            EventType::Jmap(JmapEvent::WebsocketStop) => "jmap.websocket-stop",
            EventType::Jmap(JmapEvent::WebsocketError) => "jmap.websocket-error",
            EventType::Jmap(JmapEvent::ExpandDurationTooLarge) => "jmap.expand-duration-too-large",
            EventType::Jmap(JmapEvent::CannotCalculateOccurrences) => {
                "jmap.cannot-calculate-occurrences"
            }
            EventType::Jmap(JmapEvent::TooLarge) => "jmap.too-large",
            EventType::Jmap(JmapEvent::RateLimit) => "jmap.rate-limit",
            EventType::Jmap(JmapEvent::ObjectNotFound) => "jmap.object-not-found",
            EventType::Limit(LimitEvent::SizeRequest) => "limit.size-request",
            EventType::Limit(LimitEvent::SizeUpload) => "limit.size-upload",
            EventType::Limit(LimitEvent::CallsIn) => "limit.calls-in",
            EventType::Limit(LimitEvent::ConcurrentRequest) => "limit.concurrent-request",
            EventType::Limit(LimitEvent::ConcurrentUpload) => "limit.concurrent-upload",
            EventType::Limit(LimitEvent::ConcurrentConnection) => "limit.concurrent-connection",
            EventType::Limit(LimitEvent::Quota) => "limit.quota",
            EventType::Limit(LimitEvent::BlobQuota) => "limit.blob-quota",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => "limit.tenant-quota",
            // SPDX-SnippetEnd
            EventType::Limit(LimitEvent::TooManyRequests) => "limit.too-many-requests",
            EventType::Limit(LimitEvent::MemoryBudget) => "limit.memory-budget",
            EventType::MailAuth(MailAuthEvent::ParseError) => "mail-auth.parse-error",
            EventType::MailAuth(MailAuthEvent::MissingParameters) => "mail-auth.missing-parameters",
            EventType::MailAuth(MailAuthEvent::NoHeadersFound) => "mail-auth.no-headers-found",
            EventType::MailAuth(MailAuthEvent::Crypto) => "mail-auth.crypto",
            EventType::MailAuth(MailAuthEvent::Io) => "mail-auth.io",
            EventType::MailAuth(MailAuthEvent::Base64) => "mail-auth.base64",
            EventType::MailAuth(MailAuthEvent::DnsError) => "mail-auth.dns-error",
            EventType::MailAuth(MailAuthEvent::DnsRecordNotFound) => {
                "mail-auth.dns-record-not-found"
            }
            EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType) => {
                "mail-auth.dns-invalid-record-type"
            }
            EventType::MailAuth(MailAuthEvent::PolicyNotAligned) => "mail-auth.policy-not-aligned",
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => {
                "manage-sieve.connection-start"
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => {
                "manage-sieve.connection-end"
            }
            EventType::ManageSieve(ManageSieveEvent::CreateScript) => "manage-sieve.create-script",
            EventType::ManageSieve(ManageSieveEvent::UpdateScript) => "manage-sieve.update-script",
            EventType::ManageSieve(ManageSieveEvent::GetScript) => "manage-sieve.get-script",
            EventType::ManageSieve(ManageSieveEvent::DeleteScript) => "manage-sieve.delete-script",
            EventType::ManageSieve(ManageSieveEvent::RenameScript) => "manage-sieve.rename-script",
            EventType::ManageSieve(ManageSieveEvent::CheckScript) => "manage-sieve.check-script",
            EventType::ManageSieve(ManageSieveEvent::HaveSpace) => "manage-sieve.have-space",
            EventType::ManageSieve(ManageSieveEvent::ListScripts) => "manage-sieve.list-scripts",
            EventType::ManageSieve(ManageSieveEvent::SetActive) => "manage-sieve.set-active",
            EventType::ManageSieve(ManageSieveEvent::Capabilities) => "manage-sieve.capabilities",
            EventType::ManageSieve(ManageSieveEvent::StartTls) => "manage-sieve.start-tls",
            EventType::ManageSieve(ManageSieveEvent::Unauthenticate) => {
                "manage-sieve.unauthenticate"
            }
            EventType::ManageSieve(ManageSieveEvent::Logout) => "manage-sieve.logout",
            EventType::ManageSieve(ManageSieveEvent::Noop) => "manage-sieve.noop",
            EventType::ManageSieve(ManageSieveEvent::Error) => "manage-sieve.error",
            EventType::ManageSieve(ManageSieveEvent::RawInput) => "manage-sieve.raw-input",
            EventType::ManageSieve(ManageSieveEvent::RawOutput) => "manage-sieve.raw-output",
            EventType::MessageIngest(MessageIngestEvent::Ham) => "message-ingest.ham",
            EventType::MessageIngest(MessageIngestEvent::Spam) => "message-ingest.spam",
            EventType::MessageIngest(MessageIngestEvent::ImapAppend) => {
                "message-ingest.imap-append"
            }
            EventType::MessageIngest(MessageIngestEvent::JmapAppend) => {
                "message-ingest.jmap-append"
            }
            EventType::MessageIngest(MessageIngestEvent::Duplicate) => "message-ingest.duplicate",
            EventType::MessageIngest(MessageIngestEvent::Error) => "message-ingest.error",
            EventType::Milter(MilterEvent::Read) => "milter.read",
            EventType::Milter(MilterEvent::Write) => "milter.write",
            EventType::Milter(MilterEvent::ActionAccept) => "milter.action-accept",
            EventType::Milter(MilterEvent::ActionDiscard) => "milter.action-discard",
            EventType::Milter(MilterEvent::ActionReject) => "milter.action-reject",
            EventType::Milter(MilterEvent::ActionTempFail) => "milter.action-temp-fail",
            EventType::Milter(MilterEvent::ActionReplyCode) => "milter.action-reply-code",
            EventType::Milter(MilterEvent::ActionConnectionFailure) => {
                "milter.action-connection-failure"
            }
            EventType::Milter(MilterEvent::ActionShutdown) => "milter.action-shutdown",
            EventType::Milter(MilterEvent::IoError) => "milter.io-error",
            EventType::Milter(MilterEvent::FrameTooLarge) => "milter.frame-too-large",
            EventType::Milter(MilterEvent::FrameInvalid) => "milter.frame-invalid",
            EventType::Milter(MilterEvent::UnexpectedResponse) => "milter.unexpected-response",
            EventType::Milter(MilterEvent::Timeout) => "milter.timeout",
            EventType::Milter(MilterEvent::TlsInvalidName) => "milter.tls-invalid-name",
            EventType::Milter(MilterEvent::Disconnected) => "milter.disconnected",
            EventType::Milter(MilterEvent::ParseError) => "milter.parse-error",
            EventType::MtaHook(MtaHookEvent::ActionAccept) => "mta-hook.action-accept",
            EventType::MtaHook(MtaHookEvent::ActionDiscard) => "mta-hook.action-discard",
            EventType::MtaHook(MtaHookEvent::ActionReject) => "mta-hook.action-reject",
            EventType::MtaHook(MtaHookEvent::ActionQuarantine) => "mta-hook.action-quarantine",
            EventType::MtaHook(MtaHookEvent::Error) => "mta-hook.error",
            EventType::MtaSts(MtaStsEvent::Authorized) => "mta-sts.authorized",
            EventType::MtaSts(MtaStsEvent::NotAuthorized) => "mta-sts.not-authorized",
            EventType::MtaSts(MtaStsEvent::PolicyFetch) => "mta-sts.policy-fetch",
            EventType::MtaSts(MtaStsEvent::PolicyNotFound) => "mta-sts.policy-not-found",
            EventType::MtaSts(MtaStsEvent::PolicyFetchError) => "mta-sts.policy-fetch-error",
            EventType::MtaSts(MtaStsEvent::InvalidPolicy) => "mta-sts.invalid-policy",
            EventType::Network(NetworkEvent::ListenStart) => "network.listen-start",
            EventType::Network(NetworkEvent::ListenStop) => "network.listen-stop",
            EventType::Network(NetworkEvent::ListenError) => "network.listen-error",
            EventType::Network(NetworkEvent::BindError) => "network.bind-error",
            EventType::Network(NetworkEvent::ReadError) => "network.read-error",
            EventType::Network(NetworkEvent::WriteError) => "network.write-error",
            EventType::Network(NetworkEvent::FlushError) => "network.flush-error",
            EventType::Network(NetworkEvent::AcceptError) => "network.accept-error",
            EventType::Network(NetworkEvent::SplitError) => "network.split-error",
            EventType::Network(NetworkEvent::Timeout) => "network.timeout",
            EventType::Network(NetworkEvent::Closed) => "network.closed",
            EventType::Network(NetworkEvent::ProxyError) => "network.proxy-error",
            EventType::Network(NetworkEvent::SetOptError) => "network.set-opt-error",
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport) => {
                "outgoing-report.spf-report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited) => {
                "outgoing-report.spf-rate-limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport) => {
                "outgoing-report.dkim-report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited) => {
                "outgoing-report.dkim-rate-limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport) => {
                "outgoing-report.dmarc-report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited) => {
                "outgoing-report.dmarc-rate-limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport) => {
                "outgoing-report.dmarc-aggregate-report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate) => {
                "outgoing-report.tls-aggregate"
            }
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission) => {
                "outgoing-report.http-submission"
            }
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress) => {
                "outgoing-report.unauthorized-reporting-address"
            }
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError) => {
                "outgoing-report.reporting-address-validation-error"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NotFound) => "outgoing-report.not-found",
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError) => {
                "outgoing-report.submission-error"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound) => {
                "outgoing-report.no-recipients-found"
            }
            EventType::OutgoingReport(OutgoingReportEvent::Locked) => "outgoing-report.locked",
            EventType::OutgoingReport(OutgoingReportEvent::MaxSizeExceeded) => {
                "outgoing-report.max-size-exceeded"
            }
            EventType::Pop3(Pop3Event::ConnectionStart) => "pop3.connection-start",
            EventType::Pop3(Pop3Event::ConnectionEnd) => "pop3.connection-end",
            EventType::Pop3(Pop3Event::Delete) => "pop3.delete",
            EventType::Pop3(Pop3Event::Reset) => "pop3.reset",
            EventType::Pop3(Pop3Event::Quit) => "pop3.quit",
            EventType::Pop3(Pop3Event::Fetch) => "pop3.fetch",
            EventType::Pop3(Pop3Event::List) => "pop3.list",
            EventType::Pop3(Pop3Event::ListMessage) => "pop3.list-message",
            EventType::Pop3(Pop3Event::Uidl) => "pop3.uidl",
            EventType::Pop3(Pop3Event::UidlMessage) => "pop3.uidl-message",
            EventType::Pop3(Pop3Event::Stat) => "pop3.stat",
            EventType::Pop3(Pop3Event::Noop) => "pop3.noop",
            EventType::Pop3(Pop3Event::Capabilities) => "pop3.capabilities",
            EventType::Pop3(Pop3Event::StartTls) => "pop3.start-tls",
            EventType::Pop3(Pop3Event::Utf8) => "pop3.utf8",
            EventType::Pop3(Pop3Event::Error) => "pop3.error",
            EventType::Pop3(Pop3Event::RawInput) => "pop3.raw-input",
            EventType::Pop3(Pop3Event::RawOutput) => "pop3.raw-output",
            EventType::PushSubscription(PushSubscriptionEvent::Success) => {
                "push-subscription.success"
            }
            EventType::PushSubscription(PushSubscriptionEvent::Error) => "push-subscription.error",
            EventType::PushSubscription(PushSubscriptionEvent::NotFound) => {
                "push-subscription.not-found"
            }
            EventType::Queue(QueueEvent::Started) => "queue.started",
            EventType::Queue(QueueEvent::MessageQueued) => "queue.message-queued",
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued) => {
                "queue.authenticated-message-queued"
            }
            EventType::Queue(QueueEvent::ReportQueued) => "queue.report-queued",
            EventType::Queue(QueueEvent::DsnQueued) => "queue.dsn-queued",
            EventType::Queue(QueueEvent::AutogeneratedQueued) => "queue.autogenerated-queued",
            EventType::Queue(QueueEvent::Rescheduled) => "queue.rescheduled",
            EventType::Queue(QueueEvent::Locked) => "queue.locked",
            EventType::Queue(QueueEvent::BlobNotFound) => "queue.blob-not-found",
            EventType::Queue(QueueEvent::RateLimitExceeded) => "queue.rate-limit-exceeded",
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded) => {
                "queue.concurrency-limit-exceeded"
            }
            EventType::Queue(QueueEvent::QuotaExceeded) => "queue.quota-exceeded",
            EventType::Queue(QueueEvent::BackPressure) => "queue.back-pressure",
            EventType::Registry(RegistryEvent::LocalReadError) => "registry.local-read-error",
            EventType::Registry(RegistryEvent::LocalWriteError) => "registry.local-write-error",
            EventType::Registry(RegistryEvent::LocalParseError) => "registry.local-parse-error",
            EventType::Registry(RegistryEvent::ReadError) => "registry.read-error",
            EventType::Registry(RegistryEvent::WriteError) => "registry.write-error",
            EventType::Registry(RegistryEvent::DeserializationError) => {
                "registry.deserialization-error"
            }
            EventType::Registry(RegistryEvent::BuildError) => "registry.build-error",
            EventType::Registry(RegistryEvent::BuildWarning) => "registry.build-warning",
            EventType::Registry(RegistryEvent::NotSupported) => "registry.not-supported",
            EventType::Registry(RegistryEvent::ValidationError) => "registry.validation-error",
            EventType::Resource(ResourceEvent::NotFound) => "resource.not-found",
            EventType::Resource(ResourceEvent::BadParameters) => "resource.bad-parameters",
            EventType::Resource(ResourceEvent::Error) => "resource.error",
            EventType::Resource(ResourceEvent::DownloadExternal) => "resource.download-external",
            EventType::Resource(ResourceEvent::ApplicationUpdated) => {
                "resource.application-updated"
            }
            EventType::Resource(ResourceEvent::ApplicationUnpacked) => {
                "resource.application-unpacked"
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Request) => "scim.request",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Forbidden) => "scim.forbidden",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Conflict) => "scim.conflict",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Error) => "scim.error",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceCreated) => "scim.resource-created",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceUpdated) => "scim.resource-updated",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceDeleted) => "scim.resource-deleted",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Query) => "scim.query",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkProcessed) => "scim.bulk-processed",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkAborted) => "scim.bulk-aborted",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::RollbackFailed) => "scim.rollback-failed",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::AttributeIgnored) => "scim.attribute-ignored",
            // SPDX-SnippetEnd
            EventType::SearchIndex(SearchIndexEvent::ManagerStarted) => {
                "search-index.manager-started"
            }
            EventType::SearchIndex(SearchIndexEvent::PartitionsAcquired) => {
                "search-index.partitions-acquired"
            }
            EventType::SearchIndex(SearchIndexEvent::PartitionLocked) => {
                "search-index.partition-locked"
            }
            EventType::SearchIndex(SearchIndexEvent::PartitionRetry) => {
                "search-index.partition-retry"
            }
            EventType::SearchIndex(SearchIndexEvent::BatchIndexed) => "search-index.batch-indexed",
            EventType::SearchIndex(SearchIndexEvent::DocumentIgnored) => {
                "search-index.document-ignored"
            }
            EventType::SearchIndex(SearchIndexEvent::DocumentTruncated) => {
                "search-index.document-truncated"
            }
            EventType::SearchIndex(SearchIndexEvent::MetadataNotFound) => {
                "search-index.metadata-not-found"
            }
            EventType::Security(SecurityEvent::AuthenticationBan) => "security.authentication-ban",
            EventType::Security(SecurityEvent::AbuseBan) => "security.abuse-ban",
            EventType::Security(SecurityEvent::ScanBan) => "security.scan-ban",
            EventType::Security(SecurityEvent::LoiterBan) => "security.loiter-ban",
            EventType::Security(SecurityEvent::IpBlocked) => "security.ip-blocked",
            EventType::Security(SecurityEvent::IpBlockExpired) => "security.ip-block-expired",
            EventType::Security(SecurityEvent::IpAllowExpired) => "security.ip-allow-expired",
            EventType::Security(SecurityEvent::IpUnauthorized) => "security.ip-unauthorized",
            EventType::Security(SecurityEvent::Unauthorized) => "security.unauthorized",
            EventType::Server(ServerEvent::Startup) => "server.startup",
            EventType::Server(ServerEvent::Shutdown) => "server.shutdown",
            EventType::Server(ServerEvent::StartupError) => "server.startup-error",
            EventType::Server(ServerEvent::ThreadError) => "server.thread-error",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Server(ServerEvent::Licensing) => "server.licensing",
            // SPDX-SnippetEnd
            EventType::Server(ServerEvent::RecoveryMode) => "server.recovery-mode",
            EventType::Server(ServerEvent::BootstrapMode) => "server.bootstrap-mode",
            EventType::Sieve(SieveEvent::ActionAccept) => "sieve.action-accept",
            EventType::Sieve(SieveEvent::ActionAcceptReplace) => "sieve.action-accept-replace",
            EventType::Sieve(SieveEvent::ActionDiscard) => "sieve.action-discard",
            EventType::Sieve(SieveEvent::ActionReject) => "sieve.action-reject",
            EventType::Sieve(SieveEvent::SendMessage) => "sieve.send-message",
            EventType::Sieve(SieveEvent::MessageTooLarge) => "sieve.message-too-large",
            EventType::Sieve(SieveEvent::ScriptNotFound) => "sieve.script-not-found",
            EventType::Sieve(SieveEvent::ListNotFound) => "sieve.list-not-found",
            EventType::Sieve(SieveEvent::RuntimeError) => "sieve.runtime-error",
            EventType::Sieve(SieveEvent::UnexpectedError) => "sieve.unexpected-error",
            EventType::Sieve(SieveEvent::NotSupported) => "sieve.not-supported",
            EventType::Sieve(SieveEvent::QuotaExceeded) => "sieve.quota-exceeded",
            EventType::Smtp(SmtpEvent::ConnectionStart) => "smtp.connection-start",
            EventType::Smtp(SmtpEvent::ConnectionEnd) => "smtp.connection-end",
            EventType::Smtp(SmtpEvent::Error) => "smtp.error",
            EventType::Smtp(SmtpEvent::IdNotFound) => "smtp.id-not-found",
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => {
                "smtp.concurrency-limit-exceeded"
            }
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => "smtp.transfer-limit-exceeded",
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => "smtp.rate-limit-exceeded",
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => "smtp.time-limit-exceeded",
            EventType::Smtp(SmtpEvent::MessageParseFailed) => "smtp.message-parse-failed",
            EventType::Smtp(SmtpEvent::MessageTooLarge) => "smtp.message-too-large",
            EventType::Smtp(SmtpEvent::LoopDetected) => "smtp.loop-detected",
            EventType::Smtp(SmtpEvent::MultipleFromDomains) => "smtp.multiple-from-domains",
            EventType::Smtp(SmtpEvent::DkimPass) => "smtp.dkim-pass",
            EventType::Smtp(SmtpEvent::DkimFail) => "smtp.dkim-fail",
            EventType::Smtp(SmtpEvent::Dkim2Pass) => "smtp.dkim2-pass",
            EventType::Smtp(SmtpEvent::Dkim2Fail) => "smtp.dkim2-fail",
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected) => "smtp.dkim2-dsn-rejected",
            EventType::Smtp(SmtpEvent::ArcPass) => "smtp.arc-pass",
            EventType::Smtp(SmtpEvent::ArcFail) => "smtp.arc-fail",
            EventType::Smtp(SmtpEvent::SpfEhloPass) => "smtp.spf-ehlo-pass",
            EventType::Smtp(SmtpEvent::SpfEhloFail) => "smtp.spf-ehlo-fail",
            EventType::Smtp(SmtpEvent::SpfFromPass) => "smtp.spf-from-pass",
            EventType::Smtp(SmtpEvent::SpfFromFail) => "smtp.spf-from-fail",
            EventType::Smtp(SmtpEvent::DmarcPass) => "smtp.dmarc-pass",
            EventType::Smtp(SmtpEvent::DmarcFail) => "smtp.dmarc-fail",
            EventType::Smtp(SmtpEvent::IprevPass) => "smtp.iprev-pass",
            EventType::Smtp(SmtpEvent::IprevFail) => "smtp.iprev-fail",
            EventType::Smtp(SmtpEvent::TooManyMessages) => "smtp.too-many-messages",
            EventType::Smtp(SmtpEvent::Ehlo) => "smtp.ehlo",
            EventType::Smtp(SmtpEvent::InvalidEhlo) => "smtp.invalid-ehlo",
            EventType::Smtp(SmtpEvent::DidNotSayEhlo) => "smtp.did-not-say-ehlo",
            EventType::Smtp(SmtpEvent::EhloExpected) => "smtp.ehlo-expected",
            EventType::Smtp(SmtpEvent::LhloExpected) => "smtp.lhlo-expected",
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated) => "smtp.mail-from-unauthenticated",
            EventType::Smtp(SmtpEvent::MailFromUnauthorized) => "smtp.mail-from-unauthorized",
            EventType::Smtp(SmtpEvent::MailFromNotAllowed) => "smtp.mail-from-not-allowed",
            EventType::Smtp(SmtpEvent::MailFromRewritten) => "smtp.mail-from-rewritten",
            EventType::Smtp(SmtpEvent::MailFromMissing) => "smtp.mail-from-missing",
            EventType::Smtp(SmtpEvent::MailFrom) => "smtp.mail-from",
            EventType::Smtp(SmtpEvent::MultipleMailFrom) => "smtp.multiple-mail-from",
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => "smtp.mailbox-does-not-exist",
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => "smtp.relay-not-allowed",
            EventType::Smtp(SmtpEvent::RcptTo) => "smtp.rcpt-to",
            EventType::Smtp(SmtpEvent::RcptToDuplicate) => "smtp.rcpt-to-duplicate",
            EventType::Smtp(SmtpEvent::RcptToRewritten) => "smtp.rcpt-to-rewritten",
            EventType::Smtp(SmtpEvent::RcptToMissing) => "smtp.rcpt-to-missing",
            EventType::Smtp(SmtpEvent::RcptToGreylisted) => "smtp.rcpt-to-greylisted",
            EventType::Smtp(SmtpEvent::TooManyRecipients) => "smtp.too-many-recipients",
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => "smtp.too-many-invalid-rcpt",
            EventType::Smtp(SmtpEvent::RawInput) => "smtp.raw-input",
            EventType::Smtp(SmtpEvent::RawOutput) => "smtp.raw-output",
            EventType::Smtp(SmtpEvent::MissingLocalHostname) => "smtp.missing-local-hostname",
            EventType::Smtp(SmtpEvent::Vrfy) => "smtp.vrfy",
            EventType::Smtp(SmtpEvent::VrfyNotFound) => "smtp.vrfy-not-found",
            EventType::Smtp(SmtpEvent::VrfyDisabled) => "smtp.vrfy-disabled",
            EventType::Smtp(SmtpEvent::Expn) => "smtp.expn",
            EventType::Smtp(SmtpEvent::ExpnNotFound) => "smtp.expn-not-found",
            EventType::Smtp(SmtpEvent::ExpnDisabled) => "smtp.expn-disabled",
            EventType::Smtp(SmtpEvent::RequireTlsDisabled) => "smtp.require-tls-disabled",
            EventType::Smtp(SmtpEvent::DeliverByDisabled) => "smtp.deliver-by-disabled",
            EventType::Smtp(SmtpEvent::DeliverByInvalid) => "smtp.deliver-by-invalid",
            EventType::Smtp(SmtpEvent::FutureReleaseDisabled) => "smtp.future-release-disabled",
            EventType::Smtp(SmtpEvent::FutureReleaseInvalid) => "smtp.future-release-invalid",
            EventType::Smtp(SmtpEvent::MtPriorityDisabled) => "smtp.mt-priority-disabled",
            EventType::Smtp(SmtpEvent::MtPriorityInvalid) => "smtp.mt-priority-invalid",
            EventType::Smtp(SmtpEvent::DsnDisabled) => "smtp.dsn-disabled",
            EventType::Smtp(SmtpEvent::AuthNotAllowed) => "smtp.auth-not-allowed",
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => {
                "smtp.auth-mechanism-not-supported"
            }
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong) => "smtp.auth-exchange-too-long",
            EventType::Smtp(SmtpEvent::AlreadyAuthenticated) => "smtp.already-authenticated",
            EventType::Smtp(SmtpEvent::Noop) => "smtp.noop",
            EventType::Smtp(SmtpEvent::StartTls) => "smtp.start-tls",
            EventType::Smtp(SmtpEvent::StartTlsUnavailable) => "smtp.start-tls-unavailable",
            EventType::Smtp(SmtpEvent::StartTlsAlready) => "smtp.start-tls-already",
            EventType::Smtp(SmtpEvent::Rset) => "smtp.rset",
            EventType::Smtp(SmtpEvent::Quit) => "smtp.quit",
            EventType::Smtp(SmtpEvent::Help) => "smtp.help",
            EventType::Smtp(SmtpEvent::CommandNotImplemented) => "smtp.command-not-implemented",
            EventType::Smtp(SmtpEvent::InvalidCommand) => "smtp.invalid-command",
            EventType::Smtp(SmtpEvent::InvalidSenderAddress) => "smtp.invalid-sender-address",
            EventType::Smtp(SmtpEvent::InvalidRecipientAddress) => "smtp.invalid-recipient-address",
            EventType::Smtp(SmtpEvent::InvalidParameter) => "smtp.invalid-parameter",
            EventType::Smtp(SmtpEvent::UnsupportedParameter) => "smtp.unsupported-parameter",
            EventType::Smtp(SmtpEvent::SyntaxError) => "smtp.syntax-error",
            EventType::Smtp(SmtpEvent::RequestTooLarge) => "smtp.request-too-large",
            EventType::Spam(SpamEvent::Pyzor) => "spam.pyzor",
            EventType::Spam(SpamEvent::PyzorError) => "spam.pyzor-error",
            EventType::Spam(SpamEvent::Dnsbl) => "spam.dnsbl",
            EventType::Spam(SpamEvent::DnsblError) => "spam.dnsbl-error",
            EventType::Spam(SpamEvent::TrainStarted) => "spam.train-started",
            EventType::Spam(SpamEvent::TrainCompleted) => "spam.train-completed",
            EventType::Spam(SpamEvent::TrainSampleAdded) => "spam.train-sample-added",
            EventType::Spam(SpamEvent::TrainSampleNotFound) => "spam.train-sample-not-found",
            EventType::Spam(SpamEvent::Classify) => "spam.classify",
            EventType::Spam(SpamEvent::ModelLoaded) => "spam.model-loaded",
            EventType::Spam(SpamEvent::ModelNotReady) => "spam.model-not-ready",
            EventType::Spam(SpamEvent::ModelNotFound) => "spam.model-not-found",
            EventType::Spam(SpamEvent::RulesUpdated) => "spam.rules-updated",
            EventType::Spf(SpfEvent::Pass) => "spf.pass",
            EventType::Spf(SpfEvent::Fail) => "spf.fail",
            EventType::Spf(SpfEvent::SoftFail) => "spf.soft-fail",
            EventType::Spf(SpfEvent::Neutral) => "spf.neutral",
            EventType::Spf(SpfEvent::TempError) => "spf.temp-error",
            EventType::Spf(SpfEvent::PermError) => "spf.perm-error",
            EventType::Spf(SpfEvent::None) => "spf.none",
            EventType::Store(StoreEvent::AssertValueFailed) => "store.assert-value-failed",
            EventType::Store(StoreEvent::FoundationdbError) => "store.foundationdb-error",
            EventType::Store(StoreEvent::MysqlError) => "store.mysql-error",
            EventType::Store(StoreEvent::PostgresqlError) => "store.postgresql-error",
            EventType::Store(StoreEvent::RocksdbError) => "store.rocksdb-error",
            EventType::Store(StoreEvent::SqliteError) => "store.sqlite-error",
            EventType::Store(StoreEvent::LdapError) => "store.ldap-error",
            EventType::Store(StoreEvent::ElasticsearchError) => "store.elasticsearch-error",
            EventType::Store(StoreEvent::MeilisearchError) => "store.meilisearch-error",
            EventType::Store(StoreEvent::RedisError) => "store.redis-error",
            EventType::Store(StoreEvent::S3Error) => "store.s3-error",
            EventType::Store(StoreEvent::AzureError) => "store.azure-error",
            EventType::Store(StoreEvent::FilesystemError) => "store.filesystem-error",
            EventType::Store(StoreEvent::PoolError) => "store.pool-error",
            EventType::Store(StoreEvent::DataCorruption) => "store.data-corruption",
            EventType::Store(StoreEvent::DecompressError) => "store.decompress-error",
            EventType::Store(StoreEvent::DeserializeError) => "store.deserialize-error",
            EventType::Store(StoreEvent::NotFound) => "store.not-found",
            EventType::Store(StoreEvent::NotConfigured) => "store.not-configured",
            EventType::Store(StoreEvent::NotSupported) => "store.not-supported",
            EventType::Store(StoreEvent::UnexpectedError) => "store.unexpected-error",
            EventType::Store(StoreEvent::CryptoError) => "store.crypto-error",
            EventType::Store(StoreEvent::HttpStoreError) => "store.http-store-error",
            EventType::Store(StoreEvent::BlobMissingMarker) => "store.blob-missing-marker",
            EventType::Store(StoreEvent::DataWrite) => "store.data-write",
            EventType::Store(StoreEvent::DataIterate) => "store.data-iterate",
            EventType::Store(StoreEvent::BlobRead) => "store.blob-read",
            EventType::Store(StoreEvent::BlobWrite) => "store.blob-write",
            EventType::Store(StoreEvent::BlobDelete) => "store.blob-delete",
            EventType::Store(StoreEvent::SqlQuery) => "store.sql-query",
            EventType::Store(StoreEvent::LdapQuery) => "store.ldap-query",
            EventType::Store(StoreEvent::LdapWarning) => "store.ldap-warning",
            EventType::Store(StoreEvent::HttpStoreFetch) => "store.http-store-fetch",
            EventType::Store(StoreEvent::AutoExpunge) => "store.auto-expunge",
            EventType::Store(StoreEvent::BlobStorePurged) => "store.blob-store-purged",
            EventType::Store(StoreEvent::DataStorePurged) => "store.data-store-purged",
            EventType::TaskManager(TaskManagerEvent::TaskAcquired) => "task-manager.task-acquired",
            EventType::TaskManager(TaskManagerEvent::TaskQueued) => "task-manager.task-queued",
            EventType::TaskManager(TaskManagerEvent::TaskScheduled) => {
                "task-manager.task-scheduled"
            }
            EventType::TaskManager(TaskManagerEvent::TaskLocked) => "task-manager.task-locked",
            EventType::TaskManager(TaskManagerEvent::TaskIgnored) => "task-manager.task-ignored",
            EventType::TaskManager(TaskManagerEvent::TaskFailed) => "task-manager.task-failed",
            EventType::TaskManager(TaskManagerEvent::TaskRetry) => "task-manager.task-retry",
            EventType::TaskManager(TaskManagerEvent::TaskStalled) => "task-manager.task-stalled",
            EventType::TaskManager(TaskManagerEvent::TaskExpired) => "task-manager.task-expired",
            EventType::TaskManager(TaskManagerEvent::BlobNotFound) => "task-manager.blob-not-found",
            EventType::TaskManager(TaskManagerEvent::MetadataNotFound) => {
                "task-manager.metadata-not-found"
            }
            EventType::TaskManager(TaskManagerEvent::SchedulerStarted) => {
                "task-manager.scheduler-started"
            }
            EventType::TaskManager(TaskManagerEvent::ManagerStarted) => {
                "task-manager.manager-started"
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertEvent) => "telemetry.alert-event",
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertMessage) => "telemetry.alert-message",
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::LogError) => "telemetry.log-error",
            EventType::Telemetry(TelemetryEvent::WebhookError) => "telemetry.webhook-error",
            EventType::Telemetry(TelemetryEvent::OtelExporterError) => {
                "telemetry.otel-exporter-error"
            }
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError) => {
                "telemetry.otel-metrics-exporter-error"
            }
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError) => {
                "telemetry.prometheus-exporter-error"
            }
            EventType::Telemetry(TelemetryEvent::JournalError) => "telemetry.journal-error",
            EventType::Telemetry(TelemetryEvent::EventsDropped) => "telemetry.events-dropped",
            EventType::Telemetry(TelemetryEvent::MetricsCollected) => "telemetry.metrics-collected",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::MetricsStored) => "telemetry.metrics-stored",
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::MetricsPushed) => "telemetry.metrics-pushed",
            EventType::Tls(TlsEvent::Handshake) => "tls.handshake",
            EventType::Tls(TlsEvent::HandshakeError) => "tls.handshake-error",
            EventType::Tls(TlsEvent::NotConfigured) => "tls.not-configured",
            EventType::Tls(TlsEvent::CertificateNotFound) => "tls.certificate-not-found",
            EventType::Tls(TlsEvent::NoCertificatesAvailable) => "tls.no-certificates-available",
            EventType::Tls(TlsEvent::MultipleCertificatesAvailable) => {
                "tls.multiple-certificates-available"
            }
            EventType::Tls(TlsEvent::ExpiredCertificateRemoved) => {
                "tls.expired-certificate-removed"
            }
            EventType::TlsRpt(TlsRptEvent::RecordFetch) => "tls-rpt.record-fetch",
            EventType::TlsRpt(TlsRptEvent::RecordFetchError) => "tls-rpt.record-fetch-error",
            EventType::TlsRpt(TlsRptEvent::RecordNotFound) => "tls-rpt.record-not-found",
            EventType::WebDav(WebDavEvent::Propfind) => "web-dav.propfind",
            EventType::WebDav(WebDavEvent::Proppatch) => "web-dav.proppatch",
            EventType::WebDav(WebDavEvent::Get) => "web-dav.get",
            EventType::WebDav(WebDavEvent::Head) => "web-dav.head",
            EventType::WebDav(WebDavEvent::Report) => "web-dav.report",
            EventType::WebDav(WebDavEvent::Mkcol) => "web-dav.mkcol",
            EventType::WebDav(WebDavEvent::Mkcalendar) => "web-dav.mkcalendar",
            EventType::WebDav(WebDavEvent::Delete) => "web-dav.delete",
            EventType::WebDav(WebDavEvent::Put) => "web-dav.put",
            EventType::WebDav(WebDavEvent::Post) => "web-dav.post",
            EventType::WebDav(WebDavEvent::Patch) => "web-dav.patch",
            EventType::WebDav(WebDavEvent::Copy) => "web-dav.copy",
            EventType::WebDav(WebDavEvent::Move) => "web-dav.move",
            EventType::WebDav(WebDavEvent::Lock) => "web-dav.lock",
            EventType::WebDav(WebDavEvent::Unlock) => "web-dav.unlock",
            EventType::WebDav(WebDavEvent::Acl) => "web-dav.acl",
            EventType::WebDav(WebDavEvent::Options) => "web-dav.options",
            EventType::WebDav(WebDavEvent::Error) => "web-dav.error",
        }
    }

    pub const fn to_id(&self) -> u16 {
        match self {
            EventType::Acme(AcmeEvent::AuthStart) => 3,
            EventType::Acme(AcmeEvent::AuthPending) => 2,
            EventType::Acme(AcmeEvent::AuthValid) => 5,
            EventType::Acme(AcmeEvent::AuthCompleted) => 0,
            EventType::Acme(AcmeEvent::AuthError) => 1,
            EventType::Acme(AcmeEvent::AuthTooManyAttempts) => 4,
            EventType::Acme(AcmeEvent::ProcessCert) => 22,
            EventType::Acme(AcmeEvent::OrderStart) => 20,
            EventType::Acme(AcmeEvent::OrderProcessing) => 18,
            EventType::Acme(AcmeEvent::OrderCompleted) => 16,
            EventType::Acme(AcmeEvent::OrderReady) => 19,
            EventType::Acme(AcmeEvent::OrderValid) => 21,
            EventType::Acme(AcmeEvent::OrderInvalid) => 17,
            EventType::Acme(AcmeEvent::RenewBackoff) => 23,
            EventType::Acme(AcmeEvent::ClientSuppliedSni) => 7,
            EventType::Acme(AcmeEvent::ClientMissingSni) => 6,
            EventType::Acme(AcmeEvent::TlsAlpnReceived) => 25,
            EventType::Acme(AcmeEvent::TlsAlpnError) => 24,
            EventType::Acme(AcmeEvent::TokenNotFound) => 26,
            EventType::Acme(AcmeEvent::Error) => 15,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::LlmResponse) => 539,
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::ApiError) => 540,
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::Request) => 621,
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamVerdict) => 622,
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamSkipped) => 623,
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::BreakerOpen) => 624,
            // SPDX-SnippetEnd
            EventType::Arc(ArcEvent::ChainInvalid) => 647,
            EventType::Arc(ArcEvent::SignatureInvalid) => 648,
            EventType::Arc(ArcEvent::HashMismatch) => 649,
            EventType::Auth(AuthEvent::Success) => 32,
            EventType::Auth(AuthEvent::Failed) => 30,
            EventType::Auth(AuthEvent::TokenExpired) => 537,
            EventType::Auth(AuthEvent::MfaRequired) => 31,
            EventType::Auth(AuthEvent::TooManyAttempts) => 33,
            EventType::Auth(AuthEvent::ClientRegistration) => 538,
            EventType::Auth(AuthEvent::Error) => 29,
            EventType::Auth(AuthEvent::Warning) => 578,
            EventType::Auth(AuthEvent::CredentialExpired) => 260,
            EventType::Cache(CacheEvent::Miss) => 45,
            EventType::Cache(CacheEvent::Hit) => 46,
            EventType::Cache(CacheEvent::Stale) => 47,
            EventType::Cache(CacheEvent::Update) => 560,
            EventType::Cache(CacheEvent::EntryTooLarge) => 592,
            EventType::Cache(CacheEvent::Invalidate) => 600,
            EventType::Cache(CacheEvent::SwapHit) => 594,
            EventType::Cache(CacheEvent::SwapMiss) => 595,
            EventType::Cache(CacheEvent::SwapWrite) => 596,
            EventType::Cache(CacheEvent::SwapError) => 597,
            EventType::Cache(CacheEvent::SwapMetrics) => 598,
            EventType::Cache(CacheEvent::SwapFlush) => 599,
            EventType::Calendar(CalendarEvent::RuleExpansionError) => 559,
            EventType::Calendar(CalendarEvent::AlarmSent) => 562,
            EventType::Calendar(CalendarEvent::AlarmSkipped) => 563,
            EventType::Calendar(CalendarEvent::AlarmRecipientOverride) => 564,
            EventType::Calendar(CalendarEvent::AlarmFailed) => 565,
            EventType::Calendar(CalendarEvent::ItipMessageSent) => 566,
            EventType::Calendar(CalendarEvent::ItipMessageReceived) => 567,
            EventType::Calendar(CalendarEvent::ItipMessageError) => 568,
            EventType::Cluster(ClusterEvent::Startup) => 262,
            EventType::Cluster(ClusterEvent::SubscriberStart) => 34,
            EventType::Cluster(ClusterEvent::SubscriberStop) => 35,
            EventType::Cluster(ClusterEvent::SubscriberError) => 36,
            EventType::Cluster(ClusterEvent::SubscriberDisconnected) => 37,
            EventType::Cluster(ClusterEvent::PublisherStart) => 38,
            EventType::Cluster(ClusterEvent::PublisherStop) => 39,
            EventType::Cluster(ClusterEvent::PublisherError) => 40,
            EventType::Cluster(ClusterEvent::MessageReceived) => 41,
            EventType::Cluster(ClusterEvent::MessageSkipped) => 42,
            EventType::Cluster(ClusterEvent::MessageInvalid) => 44,
            EventType::Cluster(ClusterEvent::NodeIdRenewed) => 259,
            EventType::Dane(DaneEvent::AuthenticationSuccess) => 62,
            EventType::Dane(DaneEvent::AuthenticationFailure) => 61,
            EventType::Dane(DaneEvent::NoCertificatesFound) => 64,
            EventType::Dane(DaneEvent::CertificateParseError) => 63,
            EventType::Dane(DaneEvent::TlsaRecordMatch) => 68,
            EventType::Dane(DaneEvent::TlsaRecordFetch) => 65,
            EventType::Dane(DaneEvent::TlsaRecordFetchError) => 66,
            EventType::Dane(DaneEvent::TlsaRecordNotFound) => 70,
            EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned) => 69,
            EventType::Dane(DaneEvent::TlsaRecordInvalid) => 67,
            EventType::Dane(DaneEvent::BogusDnssecRecord) => 588,
            EventType::Delivery(DeliveryEvent::AttemptStart) => 72,
            EventType::Delivery(DeliveryEvent::AttemptEnd) => 71,
            EventType::Delivery(DeliveryEvent::Completed) => 75,
            EventType::Delivery(DeliveryEvent::Failed) => 87,
            EventType::Delivery(DeliveryEvent::DomainDeliveryStart) => 80,
            EventType::Delivery(DeliveryEvent::MxLookup) => 96,
            EventType::Delivery(DeliveryEvent::MxLookupFailed) => 97,
            EventType::Delivery(DeliveryEvent::IpLookup) => 90,
            EventType::Delivery(DeliveryEvent::IpLookupFailed) => 91,
            EventType::Delivery(DeliveryEvent::NullMx) => 98,
            EventType::Delivery(DeliveryEvent::Connect) => 77,
            EventType::Delivery(DeliveryEvent::ConnectError) => 78,
            EventType::Delivery(DeliveryEvent::MissingOutboundHostname) => 95,
            EventType::Delivery(DeliveryEvent::GreetingFailed) => 88,
            EventType::Delivery(DeliveryEvent::Ehlo) => 85,
            EventType::Delivery(DeliveryEvent::EhloRejected) => 86,
            EventType::Delivery(DeliveryEvent::Auth) => 73,
            EventType::Delivery(DeliveryEvent::AuthFailed) => 74,
            EventType::Delivery(DeliveryEvent::MailFrom) => 92,
            EventType::Delivery(DeliveryEvent::MailFromRejected) => 93,
            EventType::Delivery(DeliveryEvent::Delivered) => 79,
            EventType::Delivery(DeliveryEvent::RcptTo) => 102,
            EventType::Delivery(DeliveryEvent::RcptToRejected) => 104,
            EventType::Delivery(DeliveryEvent::RcptToFailed) => 103,
            EventType::Delivery(DeliveryEvent::MessageRejected) => 94,
            EventType::Delivery(DeliveryEvent::StartTls) => 105,
            EventType::Delivery(DeliveryEvent::StartTlsUnavailable) => 108,
            EventType::Delivery(DeliveryEvent::StartTlsError) => 107,
            EventType::Delivery(DeliveryEvent::StartTlsDisabled) => 106,
            EventType::Delivery(DeliveryEvent::ImplicitTlsError) => 89,
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded) => 76,
            EventType::Delivery(DeliveryEvent::RateLimitExceeded) => 99,
            EventType::Delivery(DeliveryEvent::DoubleBounce) => 81,
            EventType::Delivery(DeliveryEvent::DsnSuccess) => 83,
            EventType::Delivery(DeliveryEvent::DsnTempFail) => 84,
            EventType::Delivery(DeliveryEvent::DsnPermFail) => 82,
            EventType::Delivery(DeliveryEvent::RawInput) => 100,
            EventType::Delivery(DeliveryEvent::RawOutput) => 101,
            EventType::Dkim(DkimEvent::Pass) => 112,
            EventType::Dkim(DkimEvent::Neutral) => 110,
            EventType::Dkim(DkimEvent::Fail) => 109,
            EventType::Dkim(DkimEvent::PermError) => 113,
            EventType::Dkim(DkimEvent::TempError) => 115,
            EventType::Dkim(DkimEvent::None) => 111,
            EventType::Dkim(DkimEvent::SignatureInvalid) => 643,
            EventType::Dkim(DkimEvent::PublicKeyError) => 644,
            EventType::Dkim(DkimEvent::VerificationFailed) => 645,
            EventType::Dkim(DkimEvent::HashMismatch) => 646,
            EventType::Dkim(DkimEvent::SignerNotFound) => 114,
            EventType::Dkim(DkimEvent::BuildError) => 575,
            EventType::Dkim(DkimEvent::SignatureCreated) => 579,
            EventType::Dkim(DkimEvent::SignaturePublished) => 580,
            EventType::Dkim(DkimEvent::SignatureRetiring) => 581,
            EventType::Dkim(DkimEvent::SignatureRetired) => 582,
            EventType::Dkim(DkimEvent::SignatureDeleted) => 583,
            EventType::Dkim2(Dkim2Event::InstanceInvalid) => 633,
            EventType::Dkim2(Dkim2Event::SignatureInvalid) => 634,
            EventType::Dkim2(Dkim2Event::ChainInvalid) => 635,
            EventType::Dkim2(Dkim2Event::TimestampInvalid) => 636,
            EventType::Dkim2(Dkim2Event::EnvelopeMismatch) => 637,
            EventType::Dkim2(Dkim2Event::CustodyBroken) => 638,
            EventType::Dkim2(Dkim2Event::PublicKeyError) => 639,
            EventType::Dkim2(Dkim2Event::VerificationFailed) => 640,
            EventType::Dkim2(Dkim2Event::HashMismatch) => 641,
            EventType::Dkim2(Dkim2Event::RecipeError) => 642,
            EventType::Dkim2(Dkim2Event::SigningFailed) => 650,
            EventType::Dmarc(DmarcEvent::Pass) => 118,
            EventType::Dmarc(DmarcEvent::Fail) => 116,
            EventType::Dmarc(DmarcEvent::PermError) => 119,
            EventType::Dmarc(DmarcEvent::TempError) => 120,
            EventType::Dmarc(DmarcEvent::None) => 117,
            EventType::Dns(DnsEvent::RecordCreated) => 8,
            EventType::Dns(DnsEvent::RecordCreationFailed) => 9,
            EventType::Dns(DnsEvent::RecordDeletionFailed) => 10,
            EventType::Dns(DnsEvent::RecordNotPropagated) => 12,
            EventType::Dns(DnsEvent::RecordLookupFailed) => 11,
            EventType::Dns(DnsEvent::RecordPropagated) => 13,
            EventType::Dns(DnsEvent::RecordPropagationTimeout) => 14,
            EventType::Eval(EvalEvent::Result) => 123,
            EventType::Eval(EvalEvent::Error) => 122,
            EventType::Eval(EvalEvent::DirectoryNotFound) => 121,
            EventType::Eval(EvalEvent::StoreNotFound) => 124,
            EventType::Http(HttpEvent::ConnectionStart) => 137,
            EventType::Http(HttpEvent::ConnectionEnd) => 136,
            EventType::Http(HttpEvent::Error) => 138,
            EventType::Http(HttpEvent::RequestUrl) => 140,
            EventType::Http(HttpEvent::RequestBody) => 139,
            EventType::Http(HttpEvent::ResponseBody) => 141,
            EventType::Http(HttpEvent::XForwardedMissing) => 142,
            EventType::Http(HttpEvent::XForwardedInvalid) => 625,
            EventType::Imap(ImapEvent::ConnectionStart) => 147,
            EventType::Imap(ImapEvent::ConnectionEnd) => 146,
            EventType::Imap(ImapEvent::GetAcl) => 155,
            EventType::Imap(ImapEvent::SetAcl) => 172,
            EventType::Imap(ImapEvent::MyRights) => 164,
            EventType::Imap(ImapEvent::ListRights) => 160,
            EventType::Imap(ImapEvent::Append) => 143,
            EventType::Imap(ImapEvent::Capabilities) => 144,
            EventType::Imap(ImapEvent::Id) => 156,
            EventType::Imap(ImapEvent::Close) => 145,
            EventType::Imap(ImapEvent::Copy) => 148,
            EventType::Imap(ImapEvent::Move) => 163,
            EventType::Imap(ImapEvent::CreateMailbox) => 149,
            EventType::Imap(ImapEvent::DeleteMailbox) => 150,
            EventType::Imap(ImapEvent::RenameMailbox) => 169,
            EventType::Imap(ImapEvent::Enable) => 151,
            EventType::Imap(ImapEvent::Expunge) => 153,
            EventType::Imap(ImapEvent::Fetch) => 154,
            EventType::Imap(ImapEvent::IdleStart) => 157,
            EventType::Imap(ImapEvent::IdleStop) => 158,
            EventType::Imap(ImapEvent::List) => 159,
            EventType::Imap(ImapEvent::Lsub) => 162,
            EventType::Imap(ImapEvent::Logout) => 161,
            EventType::Imap(ImapEvent::Namespace) => 165,
            EventType::Imap(ImapEvent::Noop) => 166,
            EventType::Imap(ImapEvent::Search) => 170,
            EventType::Imap(ImapEvent::Sort) => 173,
            EventType::Imap(ImapEvent::Select) => 171,
            EventType::Imap(ImapEvent::Status) => 174,
            EventType::Imap(ImapEvent::Store) => 175,
            EventType::Imap(ImapEvent::Subscribe) => 176,
            EventType::Imap(ImapEvent::Unsubscribe) => 178,
            EventType::Imap(ImapEvent::Thread) => 177,
            EventType::Imap(ImapEvent::UidBatches) => 593,
            EventType::Imap(ImapEvent::GetQuota) => 52,
            EventType::Imap(ImapEvent::GetMetadata) => 607,
            EventType::Imap(ImapEvent::SetMetadata) => 608,
            EventType::Imap(ImapEvent::Error) => 152,
            EventType::Imap(ImapEvent::RawInput) => 167,
            EventType::Imap(ImapEvent::RawOutput) => 168,
            EventType::IncomingReport(IncomingReportEvent::DmarcReport) => 184,
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings) => 185,
            EventType::IncomingReport(IncomingReportEvent::TlsReport) => 190,
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings) => 191,
            EventType::IncomingReport(IncomingReportEvent::AbuseReport) => 179,
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport) => 181,
            EventType::IncomingReport(IncomingReportEvent::FraudReport) => 186,
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport) => 188,
            EventType::IncomingReport(IncomingReportEvent::VirusReport) => 193,
            EventType::IncomingReport(IncomingReportEvent::OtherReport) => 189,
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed) => 187,
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed) => 183,
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed) => 192,
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed) => 180,
            EventType::IncomingReport(IncomingReportEvent::DecompressError) => 182,
            EventType::Iprev(IprevEvent::Pass) => 196,
            EventType::Iprev(IprevEvent::Fail) => 194,
            EventType::Iprev(IprevEvent::PermError) => 197,
            EventType::Iprev(IprevEvent::TempError) => 198,
            EventType::Iprev(IprevEvent::None) => 195,
            EventType::Jmap(JmapEvent::MethodCall) => 207,
            EventType::Jmap(JmapEvent::InvalidArguments) => 205,
            EventType::Jmap(JmapEvent::RequestTooLarge) => 211,
            EventType::Jmap(JmapEvent::StateMismatch) => 212,
            EventType::Jmap(JmapEvent::AnchorNotFound) => 202,
            EventType::Jmap(JmapEvent::UnsupportedFilter) => 216,
            EventType::Jmap(JmapEvent::UnsupportedSort) => 217,
            EventType::Jmap(JmapEvent::UnknownMethod) => 215,
            EventType::Jmap(JmapEvent::InvalidResultReference) => 206,
            EventType::Jmap(JmapEvent::Forbidden) => 204,
            EventType::Jmap(JmapEvent::AccountNotFound) => 199,
            EventType::Jmap(JmapEvent::AccountNotSupportedByMethod) => 200,
            EventType::Jmap(JmapEvent::AccountReadOnly) => 201,
            EventType::Jmap(JmapEvent::FromAccountNotFound) => 653,
            EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod) => 654,
            EventType::Jmap(JmapEvent::NotFound) => 208,
            EventType::Jmap(JmapEvent::CannotCalculateChanges) => 203,
            EventType::Jmap(JmapEvent::UnknownDataType) => 214,
            EventType::Jmap(JmapEvent::UnknownCapability) => 213,
            EventType::Jmap(JmapEvent::NotJson) => 209,
            EventType::Jmap(JmapEvent::NotRequest) => 210,
            EventType::Jmap(JmapEvent::WebsocketStart) => 219,
            EventType::Jmap(JmapEvent::WebsocketStop) => 220,
            EventType::Jmap(JmapEvent::WebsocketError) => 218,
            EventType::Jmap(JmapEvent::ExpandDurationTooLarge) => 602,
            EventType::Jmap(JmapEvent::CannotCalculateOccurrences) => 603,
            EventType::Jmap(JmapEvent::TooLarge) => 604,
            EventType::Jmap(JmapEvent::RateLimit) => 605,
            EventType::Jmap(JmapEvent::ObjectNotFound) => 606,
            EventType::Limit(LimitEvent::SizeRequest) => 227,
            EventType::Limit(LimitEvent::SizeUpload) => 228,
            EventType::Limit(LimitEvent::CallsIn) => 222,
            EventType::Limit(LimitEvent::ConcurrentRequest) => 224,
            EventType::Limit(LimitEvent::ConcurrentUpload) => 225,
            EventType::Limit(LimitEvent::ConcurrentConnection) => 223,
            EventType::Limit(LimitEvent::Quota) => 226,
            EventType::Limit(LimitEvent::BlobQuota) => 221,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => 536,
            // SPDX-SnippetEnd
            EventType::Limit(LimitEvent::TooManyRequests) => 229,
            EventType::Limit(LimitEvent::MemoryBudget) => 627,
            EventType::MailAuth(MailAuthEvent::ParseError) => 238,
            EventType::MailAuth(MailAuthEvent::MissingParameters) => 236,
            EventType::MailAuth(MailAuthEvent::NoHeadersFound) => 237,
            EventType::MailAuth(MailAuthEvent::Crypto) => 231,
            EventType::MailAuth(MailAuthEvent::Io) => 235,
            EventType::MailAuth(MailAuthEvent::Base64) => 230,
            EventType::MailAuth(MailAuthEvent::DnsError) => 232,
            EventType::MailAuth(MailAuthEvent::DnsRecordNotFound) => 234,
            EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType) => 233,
            EventType::MailAuth(MailAuthEvent::PolicyNotAligned) => 239,
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => 243,
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => 242,
            EventType::ManageSieve(ManageSieveEvent::CreateScript) => 244,
            EventType::ManageSieve(ManageSieveEvent::UpdateScript) => 258,
            EventType::ManageSieve(ManageSieveEvent::GetScript) => 247,
            EventType::ManageSieve(ManageSieveEvent::DeleteScript) => 245,
            EventType::ManageSieve(ManageSieveEvent::RenameScript) => 254,
            EventType::ManageSieve(ManageSieveEvent::CheckScript) => 241,
            EventType::ManageSieve(ManageSieveEvent::HaveSpace) => 248,
            EventType::ManageSieve(ManageSieveEvent::ListScripts) => 249,
            EventType::ManageSieve(ManageSieveEvent::SetActive) => 255,
            EventType::ManageSieve(ManageSieveEvent::Capabilities) => 240,
            EventType::ManageSieve(ManageSieveEvent::StartTls) => 256,
            EventType::ManageSieve(ManageSieveEvent::Unauthenticate) => 257,
            EventType::ManageSieve(ManageSieveEvent::Logout) => 250,
            EventType::ManageSieve(ManageSieveEvent::Noop) => 251,
            EventType::ManageSieve(ManageSieveEvent::Error) => 246,
            EventType::ManageSieve(ManageSieveEvent::RawInput) => 252,
            EventType::ManageSieve(ManageSieveEvent::RawOutput) => 253,
            EventType::MessageIngest(MessageIngestEvent::Ham) => 267,
            EventType::MessageIngest(MessageIngestEvent::Spam) => 270,
            EventType::MessageIngest(MessageIngestEvent::ImapAppend) => 268,
            EventType::MessageIngest(MessageIngestEvent::JmapAppend) => 269,
            EventType::MessageIngest(MessageIngestEvent::Duplicate) => 265,
            EventType::MessageIngest(MessageIngestEvent::Error) => 266,
            EventType::Milter(MilterEvent::Read) => 283,
            EventType::Milter(MilterEvent::Write) => 287,
            EventType::Milter(MilterEvent::ActionAccept) => 271,
            EventType::Milter(MilterEvent::ActionDiscard) => 273,
            EventType::Milter(MilterEvent::ActionReject) => 274,
            EventType::Milter(MilterEvent::ActionTempFail) => 277,
            EventType::Milter(MilterEvent::ActionReplyCode) => 275,
            EventType::Milter(MilterEvent::ActionConnectionFailure) => 272,
            EventType::Milter(MilterEvent::ActionShutdown) => 276,
            EventType::Milter(MilterEvent::IoError) => 281,
            EventType::Milter(MilterEvent::FrameTooLarge) => 280,
            EventType::Milter(MilterEvent::FrameInvalid) => 279,
            EventType::Milter(MilterEvent::UnexpectedResponse) => 286,
            EventType::Milter(MilterEvent::Timeout) => 284,
            EventType::Milter(MilterEvent::TlsInvalidName) => 285,
            EventType::Milter(MilterEvent::Disconnected) => 278,
            EventType::Milter(MilterEvent::ParseError) => 282,
            EventType::MtaHook(MtaHookEvent::ActionAccept) => 288,
            EventType::MtaHook(MtaHookEvent::ActionDiscard) => 289,
            EventType::MtaHook(MtaHookEvent::ActionReject) => 291,
            EventType::MtaHook(MtaHookEvent::ActionQuarantine) => 290,
            EventType::MtaHook(MtaHookEvent::Error) => 292,
            EventType::MtaSts(MtaStsEvent::Authorized) => 293,
            EventType::MtaSts(MtaStsEvent::NotAuthorized) => 295,
            EventType::MtaSts(MtaStsEvent::PolicyFetch) => 296,
            EventType::MtaSts(MtaStsEvent::PolicyNotFound) => 298,
            EventType::MtaSts(MtaStsEvent::PolicyFetchError) => 297,
            EventType::MtaSts(MtaStsEvent::InvalidPolicy) => 294,
            EventType::Network(NetworkEvent::ListenStart) => 305,
            EventType::Network(NetworkEvent::ListenStop) => 306,
            EventType::Network(NetworkEvent::ListenError) => 304,
            EventType::Network(NetworkEvent::BindError) => 300,
            EventType::Network(NetworkEvent::ReadError) => 308,
            EventType::Network(NetworkEvent::WriteError) => 312,
            EventType::Network(NetworkEvent::FlushError) => 303,
            EventType::Network(NetworkEvent::AcceptError) => 299,
            EventType::Network(NetworkEvent::SplitError) => 310,
            EventType::Network(NetworkEvent::Timeout) => 311,
            EventType::Network(NetworkEvent::Closed) => 301,
            EventType::Network(NetworkEvent::ProxyError) => 307,
            EventType::Network(NetworkEvent::SetOptError) => 309,
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport) => 326,
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited) => 325,
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport) => 314,
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited) => 313,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport) => 317,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited) => 316,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport) => 315,
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate) => 328,
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission) => 318,
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress) => 329,
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError) => 324,
            EventType::OutgoingReport(OutgoingReportEvent::NotFound) => 323,
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError) => 327,
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound) => 322,
            EventType::OutgoingReport(OutgoingReportEvent::Locked) => 321,
            EventType::OutgoingReport(OutgoingReportEvent::MaxSizeExceeded) => 54,
            EventType::Pop3(Pop3Event::ConnectionStart) => 332,
            EventType::Pop3(Pop3Event::ConnectionEnd) => 331,
            EventType::Pop3(Pop3Event::Delete) => 333,
            EventType::Pop3(Pop3Event::Reset) => 342,
            EventType::Pop3(Pop3Event::Quit) => 339,
            EventType::Pop3(Pop3Event::Fetch) => 335,
            EventType::Pop3(Pop3Event::List) => 336,
            EventType::Pop3(Pop3Event::ListMessage) => 337,
            EventType::Pop3(Pop3Event::Uidl) => 345,
            EventType::Pop3(Pop3Event::UidlMessage) => 346,
            EventType::Pop3(Pop3Event::Stat) => 344,
            EventType::Pop3(Pop3Event::Noop) => 338,
            EventType::Pop3(Pop3Event::Capabilities) => 330,
            EventType::Pop3(Pop3Event::StartTls) => 343,
            EventType::Pop3(Pop3Event::Utf8) => 347,
            EventType::Pop3(Pop3Event::Error) => 334,
            EventType::Pop3(Pop3Event::RawInput) => 340,
            EventType::Pop3(Pop3Event::RawOutput) => 341,
            EventType::PushSubscription(PushSubscriptionEvent::Success) => 357,
            EventType::PushSubscription(PushSubscriptionEvent::Error) => 355,
            EventType::PushSubscription(PushSubscriptionEvent::NotFound) => 356,
            EventType::Queue(QueueEvent::Started) => 374,
            EventType::Queue(QueueEvent::MessageQueued) => 364,
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued) => 365,
            EventType::Queue(QueueEvent::ReportQueued) => 366,
            EventType::Queue(QueueEvent::DsnQueued) => 363,
            EventType::Queue(QueueEvent::AutogeneratedQueued) => 362,
            EventType::Queue(QueueEvent::Rescheduled) => 369,
            EventType::Queue(QueueEvent::Locked) => 361,
            EventType::Queue(QueueEvent::BlobNotFound) => 358,
            EventType::Queue(QueueEvent::RateLimitExceeded) => 368,
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded) => 359,
            EventType::Queue(QueueEvent::QuotaExceeded) => 367,
            EventType::Queue(QueueEvent::BackPressure) => 43,
            EventType::Registry(RegistryEvent::LocalReadError) => 57,
            EventType::Registry(RegistryEvent::LocalWriteError) => 49,
            EventType::Registry(RegistryEvent::LocalParseError) => 55,
            EventType::Registry(RegistryEvent::ReadError) => 60,
            EventType::Registry(RegistryEvent::WriteError) => 53,
            EventType::Registry(RegistryEvent::DeserializationError) => 51,
            EventType::Registry(RegistryEvent::BuildError) => 56,
            EventType::Registry(RegistryEvent::BuildWarning) => 50,
            EventType::Registry(RegistryEvent::NotSupported) => 59,
            EventType::Registry(RegistryEvent::ValidationError) => 58,
            EventType::Resource(ResourceEvent::NotFound) => 373,
            EventType::Resource(ResourceEvent::BadParameters) => 370,
            EventType::Resource(ResourceEvent::Error) => 372,
            EventType::Resource(ResourceEvent::DownloadExternal) => 371,
            EventType::Resource(ResourceEvent::ApplicationUpdated) => 584,
            EventType::Resource(ResourceEvent::ApplicationUnpacked) => 585,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Request) => 609,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Forbidden) => 610,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Conflict) => 611,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Error) => 612,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceCreated) => 613,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceUpdated) => 614,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceDeleted) => 615,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Query) => 616,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkProcessed) => 617,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkAborted) => 618,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::RollbackFailed) => 619,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::AttributeIgnored) => 620,
            // SPDX-SnippetEnd
            EventType::SearchIndex(SearchIndexEvent::ManagerStarted) => 629,
            EventType::SearchIndex(SearchIndexEvent::PartitionsAcquired) => 630,
            EventType::SearchIndex(SearchIndexEvent::PartitionLocked) => 631,
            EventType::SearchIndex(SearchIndexEvent::PartitionRetry) => 632,
            EventType::SearchIndex(SearchIndexEvent::BatchIndexed) => 126,
            EventType::SearchIndex(SearchIndexEvent::DocumentIgnored) => 574,
            EventType::SearchIndex(SearchIndexEvent::DocumentTruncated) => 628,
            EventType::SearchIndex(SearchIndexEvent::MetadataNotFound) => 27,
            EventType::Security(SecurityEvent::AuthenticationBan) => 28,
            EventType::Security(SecurityEvent::AbuseBan) => 532,
            EventType::Security(SecurityEvent::ScanBan) => 541,
            EventType::Security(SecurityEvent::LoiterBan) => 533,
            EventType::Security(SecurityEvent::IpBlocked) => 302,
            EventType::Security(SecurityEvent::IpBlockExpired) => 576,
            EventType::Security(SecurityEvent::IpAllowExpired) => 577,
            EventType::Security(SecurityEvent::IpUnauthorized) => 263,
            EventType::Security(SecurityEvent::Unauthorized) => 535,
            EventType::Server(ServerEvent::Startup) => 377,
            EventType::Server(ServerEvent::Shutdown) => 376,
            EventType::Server(ServerEvent::StartupError) => 378,
            EventType::Server(ServerEvent::ThreadError) => 379,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Server(ServerEvent::Licensing) => 375,
            // SPDX-SnippetEnd
            EventType::Server(ServerEvent::RecoveryMode) => 586,
            EventType::Server(ServerEvent::BootstrapMode) => 587,
            EventType::Sieve(SieveEvent::ActionAccept) => 380,
            EventType::Sieve(SieveEvent::ActionAcceptReplace) => 381,
            EventType::Sieve(SieveEvent::ActionDiscard) => 382,
            EventType::Sieve(SieveEvent::ActionReject) => 383,
            EventType::Sieve(SieveEvent::SendMessage) => 390,
            EventType::Sieve(SieveEvent::MessageTooLarge) => 385,
            EventType::Sieve(SieveEvent::ScriptNotFound) => 389,
            EventType::Sieve(SieveEvent::ListNotFound) => 384,
            EventType::Sieve(SieveEvent::RuntimeError) => 388,
            EventType::Sieve(SieveEvent::UnexpectedError) => 391,
            EventType::Sieve(SieveEvent::NotSupported) => 386,
            EventType::Sieve(SieveEvent::QuotaExceeded) => 387,
            EventType::Smtp(SmtpEvent::ConnectionStart) => 401,
            EventType::Smtp(SmtpEvent::ConnectionEnd) => 400,
            EventType::Smtp(SmtpEvent::Error) => 412,
            EventType::Smtp(SmtpEvent::IdNotFound) => 452,
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => 399,
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => 468,
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => 444,
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => 464,
            EventType::Smtp(SmtpEvent::MessageParseFailed) => 434,
            EventType::Smtp(SmtpEvent::MessageTooLarge) => 435,
            EventType::Smtp(SmtpEvent::LoopDetected) => 427,
            EventType::Smtp(SmtpEvent::MultipleFromDomains) => 626,
            EventType::Smtp(SmtpEvent::DkimPass) => 406,
            EventType::Smtp(SmtpEvent::DkimFail) => 405,
            EventType::Smtp(SmtpEvent::Dkim2Pass) => 589,
            EventType::Smtp(SmtpEvent::Dkim2Fail) => 590,
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected) => 591,
            EventType::Smtp(SmtpEvent::ArcPass) => 394,
            EventType::Smtp(SmtpEvent::ArcFail) => 393,
            EventType::Smtp(SmtpEvent::SpfEhloPass) => 457,
            EventType::Smtp(SmtpEvent::SpfEhloFail) => 456,
            EventType::Smtp(SmtpEvent::SpfFromPass) => 459,
            EventType::Smtp(SmtpEvent::SpfFromFail) => 458,
            EventType::Smtp(SmtpEvent::DmarcPass) => 408,
            EventType::Smtp(SmtpEvent::DmarcFail) => 407,
            EventType::Smtp(SmtpEvent::IprevPass) => 425,
            EventType::Smtp(SmtpEvent::IprevFail) => 424,
            EventType::Smtp(SmtpEvent::TooManyMessages) => 466,
            EventType::Smtp(SmtpEvent::Ehlo) => 410,
            EventType::Smtp(SmtpEvent::InvalidEhlo) => 420,
            EventType::Smtp(SmtpEvent::DidNotSayEhlo) => 404,
            EventType::Smtp(SmtpEvent::EhloExpected) => 411,
            EventType::Smtp(SmtpEvent::LhloExpected) => 426,
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated) => 431,
            EventType::Smtp(SmtpEvent::MailFromUnauthorized) => 432,
            EventType::Smtp(SmtpEvent::MailFromNotAllowed) => 534,
            EventType::Smtp(SmtpEvent::MailFromRewritten) => 430,
            EventType::Smtp(SmtpEvent::MailFromMissing) => 429,
            EventType::Smtp(SmtpEvent::MailFrom) => 428,
            EventType::Smtp(SmtpEvent::MultipleMailFrom) => 439,
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => 433,
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => 451,
            EventType::Smtp(SmtpEvent::RcptTo) => 447,
            EventType::Smtp(SmtpEvent::RcptToDuplicate) => 448,
            EventType::Smtp(SmtpEvent::RcptToRewritten) => 450,
            EventType::Smtp(SmtpEvent::RcptToMissing) => 449,
            EventType::Smtp(SmtpEvent::RcptToGreylisted) => 544,
            EventType::Smtp(SmtpEvent::TooManyRecipients) => 467,
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => 465,
            EventType::Smtp(SmtpEvent::RawInput) => 445,
            EventType::Smtp(SmtpEvent::RawOutput) => 446,
            EventType::Smtp(SmtpEvent::MissingLocalHostname) => 436,
            EventType::Smtp(SmtpEvent::Vrfy) => 470,
            EventType::Smtp(SmtpEvent::VrfyNotFound) => 472,
            EventType::Smtp(SmtpEvent::VrfyDisabled) => 471,
            EventType::Smtp(SmtpEvent::Expn) => 413,
            EventType::Smtp(SmtpEvent::ExpnNotFound) => 415,
            EventType::Smtp(SmtpEvent::ExpnDisabled) => 414,
            EventType::Smtp(SmtpEvent::RequireTlsDisabled) => 454,
            EventType::Smtp(SmtpEvent::DeliverByDisabled) => 402,
            EventType::Smtp(SmtpEvent::DeliverByInvalid) => 403,
            EventType::Smtp(SmtpEvent::FutureReleaseDisabled) => 416,
            EventType::Smtp(SmtpEvent::FutureReleaseInvalid) => 417,
            EventType::Smtp(SmtpEvent::MtPriorityDisabled) => 437,
            EventType::Smtp(SmtpEvent::MtPriorityInvalid) => 438,
            EventType::Smtp(SmtpEvent::DsnDisabled) => 409,
            EventType::Smtp(SmtpEvent::AuthNotAllowed) => 397,
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => 396,
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong) => 395,
            EventType::Smtp(SmtpEvent::AlreadyAuthenticated) => 392,
            EventType::Smtp(SmtpEvent::Noop) => 440,
            EventType::Smtp(SmtpEvent::StartTls) => 460,
            EventType::Smtp(SmtpEvent::StartTlsUnavailable) => 462,
            EventType::Smtp(SmtpEvent::StartTlsAlready) => 461,
            EventType::Smtp(SmtpEvent::Rset) => 455,
            EventType::Smtp(SmtpEvent::Quit) => 443,
            EventType::Smtp(SmtpEvent::Help) => 418,
            EventType::Smtp(SmtpEvent::CommandNotImplemented) => 398,
            EventType::Smtp(SmtpEvent::InvalidCommand) => 419,
            EventType::Smtp(SmtpEvent::InvalidSenderAddress) => 423,
            EventType::Smtp(SmtpEvent::InvalidRecipientAddress) => 422,
            EventType::Smtp(SmtpEvent::InvalidParameter) => 421,
            EventType::Smtp(SmtpEvent::UnsupportedParameter) => 469,
            EventType::Smtp(SmtpEvent::SyntaxError) => 463,
            EventType::Smtp(SmtpEvent::RequestTooLarge) => 453,
            EventType::Spam(SpamEvent::Pyzor) => 547,
            EventType::Spam(SpamEvent::PyzorError) => 477,
            EventType::Spam(SpamEvent::Dnsbl) => 545,
            EventType::Spam(SpamEvent::DnsblError) => 546,
            EventType::Spam(SpamEvent::TrainStarted) => 571,
            EventType::Spam(SpamEvent::TrainCompleted) => 478,
            EventType::Spam(SpamEvent::TrainSampleAdded) => 127,
            EventType::Spam(SpamEvent::TrainSampleNotFound) => 474,
            EventType::Spam(SpamEvent::Classify) => 473,
            EventType::Spam(SpamEvent::ModelLoaded) => 572,
            EventType::Spam(SpamEvent::ModelNotReady) => 479,
            EventType::Spam(SpamEvent::ModelNotFound) => 480,
            EventType::Spam(SpamEvent::RulesUpdated) => 264,
            EventType::Spf(SpfEvent::Pass) => 484,
            EventType::Spf(SpfEvent::Fail) => 481,
            EventType::Spf(SpfEvent::SoftFail) => 486,
            EventType::Spf(SpfEvent::Neutral) => 482,
            EventType::Spf(SpfEvent::TempError) => 487,
            EventType::Spf(SpfEvent::PermError) => 485,
            EventType::Spf(SpfEvent::None) => 483,
            EventType::Store(StoreEvent::AssertValueFailed) => 488,
            EventType::Store(StoreEvent::FoundationdbError) => 501,
            EventType::Store(StoreEvent::MysqlError) => 505,
            EventType::Store(StoreEvent::PostgresqlError) => 510,
            EventType::Store(StoreEvent::RocksdbError) => 512,
            EventType::Store(StoreEvent::SqliteError) => 515,
            EventType::Store(StoreEvent::LdapError) => 503,
            EventType::Store(StoreEvent::ElasticsearchError) => 499,
            EventType::Store(StoreEvent::MeilisearchError) => 573,
            EventType::Store(StoreEvent::RedisError) => 511,
            EventType::Store(StoreEvent::S3Error) => 513,
            EventType::Store(StoreEvent::AzureError) => 542,
            EventType::Store(StoreEvent::FilesystemError) => 500,
            EventType::Store(StoreEvent::PoolError) => 509,
            EventType::Store(StoreEvent::DataCorruption) => 494,
            EventType::Store(StoreEvent::DecompressError) => 497,
            EventType::Store(StoreEvent::DeserializeError) => 498,
            EventType::Store(StoreEvent::NotFound) => 507,
            EventType::Store(StoreEvent::NotConfigured) => 506,
            EventType::Store(StoreEvent::NotSupported) => 508,
            EventType::Store(StoreEvent::UnexpectedError) => 516,
            EventType::Store(StoreEvent::CryptoError) => 493,
            EventType::Store(StoreEvent::HttpStoreError) => 476,
            EventType::Store(StoreEvent::BlobMissingMarker) => 490,
            EventType::Store(StoreEvent::DataWrite) => 496,
            EventType::Store(StoreEvent::DataIterate) => 495,
            EventType::Store(StoreEvent::BlobRead) => 491,
            EventType::Store(StoreEvent::BlobWrite) => 492,
            EventType::Store(StoreEvent::BlobDelete) => 489,
            EventType::Store(StoreEvent::SqlQuery) => 514,
            EventType::Store(StoreEvent::LdapQuery) => 504,
            EventType::Store(StoreEvent::LdapWarning) => 502,
            EventType::Store(StoreEvent::HttpStoreFetch) => 475,
            EventType::Store(StoreEvent::AutoExpunge) => 348,
            EventType::Store(StoreEvent::BlobStorePurged) => 353,
            EventType::Store(StoreEvent::DataStorePurged) => 352,
            EventType::TaskManager(TaskManagerEvent::TaskAcquired) => 561,
            EventType::TaskManager(TaskManagerEvent::TaskQueued) => 133,
            EventType::TaskManager(TaskManagerEvent::TaskScheduled) => 354,
            EventType::TaskManager(TaskManagerEvent::TaskLocked) => 128,
            EventType::TaskManager(TaskManagerEvent::TaskIgnored) => 569,
            EventType::TaskManager(TaskManagerEvent::TaskFailed) => 570,
            EventType::TaskManager(TaskManagerEvent::TaskRetry) => 48,
            EventType::TaskManager(TaskManagerEvent::TaskStalled) => 651,
            EventType::TaskManager(TaskManagerEvent::TaskExpired) => 652,
            EventType::TaskManager(TaskManagerEvent::BlobNotFound) => 125,
            EventType::TaskManager(TaskManagerEvent::MetadataNotFound) => 129,
            EventType::TaskManager(TaskManagerEvent::SchedulerStarted) => 134,
            EventType::TaskManager(TaskManagerEvent::ManagerStarted) => 351,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertEvent) => 531,
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertMessage) => 349,
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::LogError) => 518,
            EventType::Telemetry(TelemetryEvent::WebhookError) => 522,
            EventType::Telemetry(TelemetryEvent::OtelExporterError) => 519,
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError) => 520,
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError) => 521,
            EventType::Telemetry(TelemetryEvent::JournalError) => 517,
            EventType::Telemetry(TelemetryEvent::EventsDropped) => 601,
            EventType::Telemetry(TelemetryEvent::MetricsCollected) => 135,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::MetricsStored) => 350,
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::MetricsPushed) => 130,
            EventType::Tls(TlsEvent::Handshake) => 526,
            EventType::Tls(TlsEvent::HandshakeError) => 527,
            EventType::Tls(TlsEvent::NotConfigured) => 530,
            EventType::Tls(TlsEvent::CertificateNotFound) => 525,
            EventType::Tls(TlsEvent::NoCertificatesAvailable) => 529,
            EventType::Tls(TlsEvent::MultipleCertificatesAvailable) => 528,
            EventType::Tls(TlsEvent::ExpiredCertificateRemoved) => 261,
            EventType::TlsRpt(TlsRptEvent::RecordFetch) => 523,
            EventType::TlsRpt(TlsRptEvent::RecordFetchError) => 524,
            EventType::TlsRpt(TlsRptEvent::RecordNotFound) => 543,
            EventType::WebDav(WebDavEvent::Propfind) => 131,
            EventType::WebDav(WebDavEvent::Proppatch) => 132,
            EventType::WebDav(WebDavEvent::Get) => 319,
            EventType::WebDav(WebDavEvent::Head) => 557,
            EventType::WebDav(WebDavEvent::Report) => 320,
            EventType::WebDav(WebDavEvent::Mkcol) => 360,
            EventType::WebDav(WebDavEvent::Mkcalendar) => 558,
            EventType::WebDav(WebDavEvent::Delete) => 441,
            EventType::WebDav(WebDavEvent::Put) => 442,
            EventType::WebDav(WebDavEvent::Post) => 548,
            EventType::WebDav(WebDavEvent::Patch) => 549,
            EventType::WebDav(WebDavEvent::Copy) => 550,
            EventType::WebDav(WebDavEvent::Move) => 551,
            EventType::WebDav(WebDavEvent::Lock) => 552,
            EventType::WebDav(WebDavEvent::Unlock) => 553,
            EventType::WebDav(WebDavEvent::Acl) => 554,
            EventType::WebDav(WebDavEvent::Options) => 556,
            EventType::WebDav(WebDavEvent::Error) => 555,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            3 => Some(EventType::Acme(AcmeEvent::AuthStart)),
            2 => Some(EventType::Acme(AcmeEvent::AuthPending)),
            5 => Some(EventType::Acme(AcmeEvent::AuthValid)),
            0 => Some(EventType::Acme(AcmeEvent::AuthCompleted)),
            1 => Some(EventType::Acme(AcmeEvent::AuthError)),
            4 => Some(EventType::Acme(AcmeEvent::AuthTooManyAttempts)),
            22 => Some(EventType::Acme(AcmeEvent::ProcessCert)),
            20 => Some(EventType::Acme(AcmeEvent::OrderStart)),
            18 => Some(EventType::Acme(AcmeEvent::OrderProcessing)),
            16 => Some(EventType::Acme(AcmeEvent::OrderCompleted)),
            19 => Some(EventType::Acme(AcmeEvent::OrderReady)),
            21 => Some(EventType::Acme(AcmeEvent::OrderValid)),
            17 => Some(EventType::Acme(AcmeEvent::OrderInvalid)),
            23 => Some(EventType::Acme(AcmeEvent::RenewBackoff)),
            7 => Some(EventType::Acme(AcmeEvent::ClientSuppliedSni)),
            6 => Some(EventType::Acme(AcmeEvent::ClientMissingSni)),
            25 => Some(EventType::Acme(AcmeEvent::TlsAlpnReceived)),
            24 => Some(EventType::Acme(AcmeEvent::TlsAlpnError)),
            26 => Some(EventType::Acme(AcmeEvent::TokenNotFound)),
            15 => Some(EventType::Acme(AcmeEvent::Error)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            539 => Some(EventType::Ai(AiEvent::LlmResponse)),
            #[cfg(feature = "enterprise")]
            540 => Some(EventType::Ai(AiEvent::ApiError)),
            #[cfg(feature = "enterprise")]
            621 => Some(EventType::Ai(AiEvent::Request)),
            #[cfg(feature = "enterprise")]
            622 => Some(EventType::Ai(AiEvent::SpamVerdict)),
            #[cfg(feature = "enterprise")]
            623 => Some(EventType::Ai(AiEvent::SpamSkipped)),
            #[cfg(feature = "enterprise")]
            624 => Some(EventType::Ai(AiEvent::BreakerOpen)),
            // SPDX-SnippetEnd
            647 => Some(EventType::Arc(ArcEvent::ChainInvalid)),
            648 => Some(EventType::Arc(ArcEvent::SignatureInvalid)),
            649 => Some(EventType::Arc(ArcEvent::HashMismatch)),
            32 => Some(EventType::Auth(AuthEvent::Success)),
            30 => Some(EventType::Auth(AuthEvent::Failed)),
            537 => Some(EventType::Auth(AuthEvent::TokenExpired)),
            31 => Some(EventType::Auth(AuthEvent::MfaRequired)),
            33 => Some(EventType::Auth(AuthEvent::TooManyAttempts)),
            538 => Some(EventType::Auth(AuthEvent::ClientRegistration)),
            29 => Some(EventType::Auth(AuthEvent::Error)),
            578 => Some(EventType::Auth(AuthEvent::Warning)),
            260 => Some(EventType::Auth(AuthEvent::CredentialExpired)),
            45 => Some(EventType::Cache(CacheEvent::Miss)),
            46 => Some(EventType::Cache(CacheEvent::Hit)),
            47 => Some(EventType::Cache(CacheEvent::Stale)),
            560 => Some(EventType::Cache(CacheEvent::Update)),
            592 => Some(EventType::Cache(CacheEvent::EntryTooLarge)),
            600 => Some(EventType::Cache(CacheEvent::Invalidate)),
            594 => Some(EventType::Cache(CacheEvent::SwapHit)),
            595 => Some(EventType::Cache(CacheEvent::SwapMiss)),
            596 => Some(EventType::Cache(CacheEvent::SwapWrite)),
            597 => Some(EventType::Cache(CacheEvent::SwapError)),
            598 => Some(EventType::Cache(CacheEvent::SwapMetrics)),
            599 => Some(EventType::Cache(CacheEvent::SwapFlush)),
            559 => Some(EventType::Calendar(CalendarEvent::RuleExpansionError)),
            562 => Some(EventType::Calendar(CalendarEvent::AlarmSent)),
            563 => Some(EventType::Calendar(CalendarEvent::AlarmSkipped)),
            564 => Some(EventType::Calendar(CalendarEvent::AlarmRecipientOverride)),
            565 => Some(EventType::Calendar(CalendarEvent::AlarmFailed)),
            566 => Some(EventType::Calendar(CalendarEvent::ItipMessageSent)),
            567 => Some(EventType::Calendar(CalendarEvent::ItipMessageReceived)),
            568 => Some(EventType::Calendar(CalendarEvent::ItipMessageError)),
            262 => Some(EventType::Cluster(ClusterEvent::Startup)),
            34 => Some(EventType::Cluster(ClusterEvent::SubscriberStart)),
            35 => Some(EventType::Cluster(ClusterEvent::SubscriberStop)),
            36 => Some(EventType::Cluster(ClusterEvent::SubscriberError)),
            37 => Some(EventType::Cluster(ClusterEvent::SubscriberDisconnected)),
            38 => Some(EventType::Cluster(ClusterEvent::PublisherStart)),
            39 => Some(EventType::Cluster(ClusterEvent::PublisherStop)),
            40 => Some(EventType::Cluster(ClusterEvent::PublisherError)),
            41 => Some(EventType::Cluster(ClusterEvent::MessageReceived)),
            42 => Some(EventType::Cluster(ClusterEvent::MessageSkipped)),
            44 => Some(EventType::Cluster(ClusterEvent::MessageInvalid)),
            259 => Some(EventType::Cluster(ClusterEvent::NodeIdRenewed)),
            62 => Some(EventType::Dane(DaneEvent::AuthenticationSuccess)),
            61 => Some(EventType::Dane(DaneEvent::AuthenticationFailure)),
            64 => Some(EventType::Dane(DaneEvent::NoCertificatesFound)),
            63 => Some(EventType::Dane(DaneEvent::CertificateParseError)),
            68 => Some(EventType::Dane(DaneEvent::TlsaRecordMatch)),
            65 => Some(EventType::Dane(DaneEvent::TlsaRecordFetch)),
            66 => Some(EventType::Dane(DaneEvent::TlsaRecordFetchError)),
            70 => Some(EventType::Dane(DaneEvent::TlsaRecordNotFound)),
            69 => Some(EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned)),
            67 => Some(EventType::Dane(DaneEvent::TlsaRecordInvalid)),
            588 => Some(EventType::Dane(DaneEvent::BogusDnssecRecord)),
            72 => Some(EventType::Delivery(DeliveryEvent::AttemptStart)),
            71 => Some(EventType::Delivery(DeliveryEvent::AttemptEnd)),
            75 => Some(EventType::Delivery(DeliveryEvent::Completed)),
            87 => Some(EventType::Delivery(DeliveryEvent::Failed)),
            80 => Some(EventType::Delivery(DeliveryEvent::DomainDeliveryStart)),
            96 => Some(EventType::Delivery(DeliveryEvent::MxLookup)),
            97 => Some(EventType::Delivery(DeliveryEvent::MxLookupFailed)),
            90 => Some(EventType::Delivery(DeliveryEvent::IpLookup)),
            91 => Some(EventType::Delivery(DeliveryEvent::IpLookupFailed)),
            98 => Some(EventType::Delivery(DeliveryEvent::NullMx)),
            77 => Some(EventType::Delivery(DeliveryEvent::Connect)),
            78 => Some(EventType::Delivery(DeliveryEvent::ConnectError)),
            95 => Some(EventType::Delivery(DeliveryEvent::MissingOutboundHostname)),
            88 => Some(EventType::Delivery(DeliveryEvent::GreetingFailed)),
            85 => Some(EventType::Delivery(DeliveryEvent::Ehlo)),
            86 => Some(EventType::Delivery(DeliveryEvent::EhloRejected)),
            73 => Some(EventType::Delivery(DeliveryEvent::Auth)),
            74 => Some(EventType::Delivery(DeliveryEvent::AuthFailed)),
            92 => Some(EventType::Delivery(DeliveryEvent::MailFrom)),
            93 => Some(EventType::Delivery(DeliveryEvent::MailFromRejected)),
            79 => Some(EventType::Delivery(DeliveryEvent::Delivered)),
            102 => Some(EventType::Delivery(DeliveryEvent::RcptTo)),
            104 => Some(EventType::Delivery(DeliveryEvent::RcptToRejected)),
            103 => Some(EventType::Delivery(DeliveryEvent::RcptToFailed)),
            94 => Some(EventType::Delivery(DeliveryEvent::MessageRejected)),
            105 => Some(EventType::Delivery(DeliveryEvent::StartTls)),
            108 => Some(EventType::Delivery(DeliveryEvent::StartTlsUnavailable)),
            107 => Some(EventType::Delivery(DeliveryEvent::StartTlsError)),
            106 => Some(EventType::Delivery(DeliveryEvent::StartTlsDisabled)),
            89 => Some(EventType::Delivery(DeliveryEvent::ImplicitTlsError)),
            76 => Some(EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded)),
            99 => Some(EventType::Delivery(DeliveryEvent::RateLimitExceeded)),
            81 => Some(EventType::Delivery(DeliveryEvent::DoubleBounce)),
            83 => Some(EventType::Delivery(DeliveryEvent::DsnSuccess)),
            84 => Some(EventType::Delivery(DeliveryEvent::DsnTempFail)),
            82 => Some(EventType::Delivery(DeliveryEvent::DsnPermFail)),
            100 => Some(EventType::Delivery(DeliveryEvent::RawInput)),
            101 => Some(EventType::Delivery(DeliveryEvent::RawOutput)),
            112 => Some(EventType::Dkim(DkimEvent::Pass)),
            110 => Some(EventType::Dkim(DkimEvent::Neutral)),
            109 => Some(EventType::Dkim(DkimEvent::Fail)),
            113 => Some(EventType::Dkim(DkimEvent::PermError)),
            115 => Some(EventType::Dkim(DkimEvent::TempError)),
            111 => Some(EventType::Dkim(DkimEvent::None)),
            643 => Some(EventType::Dkim(DkimEvent::SignatureInvalid)),
            644 => Some(EventType::Dkim(DkimEvent::PublicKeyError)),
            645 => Some(EventType::Dkim(DkimEvent::VerificationFailed)),
            646 => Some(EventType::Dkim(DkimEvent::HashMismatch)),
            114 => Some(EventType::Dkim(DkimEvent::SignerNotFound)),
            575 => Some(EventType::Dkim(DkimEvent::BuildError)),
            579 => Some(EventType::Dkim(DkimEvent::SignatureCreated)),
            580 => Some(EventType::Dkim(DkimEvent::SignaturePublished)),
            581 => Some(EventType::Dkim(DkimEvent::SignatureRetiring)),
            582 => Some(EventType::Dkim(DkimEvent::SignatureRetired)),
            583 => Some(EventType::Dkim(DkimEvent::SignatureDeleted)),
            633 => Some(EventType::Dkim2(Dkim2Event::InstanceInvalid)),
            634 => Some(EventType::Dkim2(Dkim2Event::SignatureInvalid)),
            635 => Some(EventType::Dkim2(Dkim2Event::ChainInvalid)),
            636 => Some(EventType::Dkim2(Dkim2Event::TimestampInvalid)),
            637 => Some(EventType::Dkim2(Dkim2Event::EnvelopeMismatch)),
            638 => Some(EventType::Dkim2(Dkim2Event::CustodyBroken)),
            639 => Some(EventType::Dkim2(Dkim2Event::PublicKeyError)),
            640 => Some(EventType::Dkim2(Dkim2Event::VerificationFailed)),
            641 => Some(EventType::Dkim2(Dkim2Event::HashMismatch)),
            642 => Some(EventType::Dkim2(Dkim2Event::RecipeError)),
            650 => Some(EventType::Dkim2(Dkim2Event::SigningFailed)),
            118 => Some(EventType::Dmarc(DmarcEvent::Pass)),
            116 => Some(EventType::Dmarc(DmarcEvent::Fail)),
            119 => Some(EventType::Dmarc(DmarcEvent::PermError)),
            120 => Some(EventType::Dmarc(DmarcEvent::TempError)),
            117 => Some(EventType::Dmarc(DmarcEvent::None)),
            8 => Some(EventType::Dns(DnsEvent::RecordCreated)),
            9 => Some(EventType::Dns(DnsEvent::RecordCreationFailed)),
            10 => Some(EventType::Dns(DnsEvent::RecordDeletionFailed)),
            12 => Some(EventType::Dns(DnsEvent::RecordNotPropagated)),
            11 => Some(EventType::Dns(DnsEvent::RecordLookupFailed)),
            13 => Some(EventType::Dns(DnsEvent::RecordPropagated)),
            14 => Some(EventType::Dns(DnsEvent::RecordPropagationTimeout)),
            123 => Some(EventType::Eval(EvalEvent::Result)),
            122 => Some(EventType::Eval(EvalEvent::Error)),
            121 => Some(EventType::Eval(EvalEvent::DirectoryNotFound)),
            124 => Some(EventType::Eval(EvalEvent::StoreNotFound)),
            137 => Some(EventType::Http(HttpEvent::ConnectionStart)),
            136 => Some(EventType::Http(HttpEvent::ConnectionEnd)),
            138 => Some(EventType::Http(HttpEvent::Error)),
            140 => Some(EventType::Http(HttpEvent::RequestUrl)),
            139 => Some(EventType::Http(HttpEvent::RequestBody)),
            141 => Some(EventType::Http(HttpEvent::ResponseBody)),
            142 => Some(EventType::Http(HttpEvent::XForwardedMissing)),
            625 => Some(EventType::Http(HttpEvent::XForwardedInvalid)),
            147 => Some(EventType::Imap(ImapEvent::ConnectionStart)),
            146 => Some(EventType::Imap(ImapEvent::ConnectionEnd)),
            155 => Some(EventType::Imap(ImapEvent::GetAcl)),
            172 => Some(EventType::Imap(ImapEvent::SetAcl)),
            164 => Some(EventType::Imap(ImapEvent::MyRights)),
            160 => Some(EventType::Imap(ImapEvent::ListRights)),
            143 => Some(EventType::Imap(ImapEvent::Append)),
            144 => Some(EventType::Imap(ImapEvent::Capabilities)),
            156 => Some(EventType::Imap(ImapEvent::Id)),
            145 => Some(EventType::Imap(ImapEvent::Close)),
            148 => Some(EventType::Imap(ImapEvent::Copy)),
            163 => Some(EventType::Imap(ImapEvent::Move)),
            149 => Some(EventType::Imap(ImapEvent::CreateMailbox)),
            150 => Some(EventType::Imap(ImapEvent::DeleteMailbox)),
            169 => Some(EventType::Imap(ImapEvent::RenameMailbox)),
            151 => Some(EventType::Imap(ImapEvent::Enable)),
            153 => Some(EventType::Imap(ImapEvent::Expunge)),
            154 => Some(EventType::Imap(ImapEvent::Fetch)),
            157 => Some(EventType::Imap(ImapEvent::IdleStart)),
            158 => Some(EventType::Imap(ImapEvent::IdleStop)),
            159 => Some(EventType::Imap(ImapEvent::List)),
            162 => Some(EventType::Imap(ImapEvent::Lsub)),
            161 => Some(EventType::Imap(ImapEvent::Logout)),
            165 => Some(EventType::Imap(ImapEvent::Namespace)),
            166 => Some(EventType::Imap(ImapEvent::Noop)),
            170 => Some(EventType::Imap(ImapEvent::Search)),
            173 => Some(EventType::Imap(ImapEvent::Sort)),
            171 => Some(EventType::Imap(ImapEvent::Select)),
            174 => Some(EventType::Imap(ImapEvent::Status)),
            175 => Some(EventType::Imap(ImapEvent::Store)),
            176 => Some(EventType::Imap(ImapEvent::Subscribe)),
            178 => Some(EventType::Imap(ImapEvent::Unsubscribe)),
            177 => Some(EventType::Imap(ImapEvent::Thread)),
            593 => Some(EventType::Imap(ImapEvent::UidBatches)),
            52 => Some(EventType::Imap(ImapEvent::GetQuota)),
            607 => Some(EventType::Imap(ImapEvent::GetMetadata)),
            608 => Some(EventType::Imap(ImapEvent::SetMetadata)),
            152 => Some(EventType::Imap(ImapEvent::Error)),
            167 => Some(EventType::Imap(ImapEvent::RawInput)),
            168 => Some(EventType::Imap(ImapEvent::RawOutput)),
            184 => Some(EventType::IncomingReport(IncomingReportEvent::DmarcReport)),
            185 => Some(EventType::IncomingReport(
                IncomingReportEvent::DmarcReportWithWarnings,
            )),
            190 => Some(EventType::IncomingReport(IncomingReportEvent::TlsReport)),
            191 => Some(EventType::IncomingReport(
                IncomingReportEvent::TlsReportWithWarnings,
            )),
            179 => Some(EventType::IncomingReport(IncomingReportEvent::AbuseReport)),
            181 => Some(EventType::IncomingReport(
                IncomingReportEvent::AuthFailureReport,
            )),
            186 => Some(EventType::IncomingReport(IncomingReportEvent::FraudReport)),
            188 => Some(EventType::IncomingReport(
                IncomingReportEvent::NotSpamReport,
            )),
            193 => Some(EventType::IncomingReport(IncomingReportEvent::VirusReport)),
            189 => Some(EventType::IncomingReport(IncomingReportEvent::OtherReport)),
            187 => Some(EventType::IncomingReport(
                IncomingReportEvent::MessageParseFailed,
            )),
            183 => Some(EventType::IncomingReport(
                IncomingReportEvent::DmarcParseFailed,
            )),
            192 => Some(EventType::IncomingReport(
                IncomingReportEvent::TlsRpcParseFailed,
            )),
            180 => Some(EventType::IncomingReport(
                IncomingReportEvent::ArfParseFailed,
            )),
            182 => Some(EventType::IncomingReport(
                IncomingReportEvent::DecompressError,
            )),
            196 => Some(EventType::Iprev(IprevEvent::Pass)),
            194 => Some(EventType::Iprev(IprevEvent::Fail)),
            197 => Some(EventType::Iprev(IprevEvent::PermError)),
            198 => Some(EventType::Iprev(IprevEvent::TempError)),
            195 => Some(EventType::Iprev(IprevEvent::None)),
            207 => Some(EventType::Jmap(JmapEvent::MethodCall)),
            205 => Some(EventType::Jmap(JmapEvent::InvalidArguments)),
            211 => Some(EventType::Jmap(JmapEvent::RequestTooLarge)),
            212 => Some(EventType::Jmap(JmapEvent::StateMismatch)),
            202 => Some(EventType::Jmap(JmapEvent::AnchorNotFound)),
            216 => Some(EventType::Jmap(JmapEvent::UnsupportedFilter)),
            217 => Some(EventType::Jmap(JmapEvent::UnsupportedSort)),
            215 => Some(EventType::Jmap(JmapEvent::UnknownMethod)),
            206 => Some(EventType::Jmap(JmapEvent::InvalidResultReference)),
            204 => Some(EventType::Jmap(JmapEvent::Forbidden)),
            199 => Some(EventType::Jmap(JmapEvent::AccountNotFound)),
            200 => Some(EventType::Jmap(JmapEvent::AccountNotSupportedByMethod)),
            201 => Some(EventType::Jmap(JmapEvent::AccountReadOnly)),
            653 => Some(EventType::Jmap(JmapEvent::FromAccountNotFound)),
            654 => Some(EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod)),
            208 => Some(EventType::Jmap(JmapEvent::NotFound)),
            203 => Some(EventType::Jmap(JmapEvent::CannotCalculateChanges)),
            214 => Some(EventType::Jmap(JmapEvent::UnknownDataType)),
            213 => Some(EventType::Jmap(JmapEvent::UnknownCapability)),
            209 => Some(EventType::Jmap(JmapEvent::NotJson)),
            210 => Some(EventType::Jmap(JmapEvent::NotRequest)),
            219 => Some(EventType::Jmap(JmapEvent::WebsocketStart)),
            220 => Some(EventType::Jmap(JmapEvent::WebsocketStop)),
            218 => Some(EventType::Jmap(JmapEvent::WebsocketError)),
            602 => Some(EventType::Jmap(JmapEvent::ExpandDurationTooLarge)),
            603 => Some(EventType::Jmap(JmapEvent::CannotCalculateOccurrences)),
            604 => Some(EventType::Jmap(JmapEvent::TooLarge)),
            605 => Some(EventType::Jmap(JmapEvent::RateLimit)),
            606 => Some(EventType::Jmap(JmapEvent::ObjectNotFound)),
            227 => Some(EventType::Limit(LimitEvent::SizeRequest)),
            228 => Some(EventType::Limit(LimitEvent::SizeUpload)),
            222 => Some(EventType::Limit(LimitEvent::CallsIn)),
            224 => Some(EventType::Limit(LimitEvent::ConcurrentRequest)),
            225 => Some(EventType::Limit(LimitEvent::ConcurrentUpload)),
            223 => Some(EventType::Limit(LimitEvent::ConcurrentConnection)),
            226 => Some(EventType::Limit(LimitEvent::Quota)),
            221 => Some(EventType::Limit(LimitEvent::BlobQuota)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            536 => Some(EventType::Limit(LimitEvent::TenantQuota)),
            // SPDX-SnippetEnd
            229 => Some(EventType::Limit(LimitEvent::TooManyRequests)),
            627 => Some(EventType::Limit(LimitEvent::MemoryBudget)),
            238 => Some(EventType::MailAuth(MailAuthEvent::ParseError)),
            236 => Some(EventType::MailAuth(MailAuthEvent::MissingParameters)),
            237 => Some(EventType::MailAuth(MailAuthEvent::NoHeadersFound)),
            231 => Some(EventType::MailAuth(MailAuthEvent::Crypto)),
            235 => Some(EventType::MailAuth(MailAuthEvent::Io)),
            230 => Some(EventType::MailAuth(MailAuthEvent::Base64)),
            232 => Some(EventType::MailAuth(MailAuthEvent::DnsError)),
            234 => Some(EventType::MailAuth(MailAuthEvent::DnsRecordNotFound)),
            233 => Some(EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType)),
            239 => Some(EventType::MailAuth(MailAuthEvent::PolicyNotAligned)),
            243 => Some(EventType::ManageSieve(ManageSieveEvent::ConnectionStart)),
            242 => Some(EventType::ManageSieve(ManageSieveEvent::ConnectionEnd)),
            244 => Some(EventType::ManageSieve(ManageSieveEvent::CreateScript)),
            258 => Some(EventType::ManageSieve(ManageSieveEvent::UpdateScript)),
            247 => Some(EventType::ManageSieve(ManageSieveEvent::GetScript)),
            245 => Some(EventType::ManageSieve(ManageSieveEvent::DeleteScript)),
            254 => Some(EventType::ManageSieve(ManageSieveEvent::RenameScript)),
            241 => Some(EventType::ManageSieve(ManageSieveEvent::CheckScript)),
            248 => Some(EventType::ManageSieve(ManageSieveEvent::HaveSpace)),
            249 => Some(EventType::ManageSieve(ManageSieveEvent::ListScripts)),
            255 => Some(EventType::ManageSieve(ManageSieveEvent::SetActive)),
            240 => Some(EventType::ManageSieve(ManageSieveEvent::Capabilities)),
            256 => Some(EventType::ManageSieve(ManageSieveEvent::StartTls)),
            257 => Some(EventType::ManageSieve(ManageSieveEvent::Unauthenticate)),
            250 => Some(EventType::ManageSieve(ManageSieveEvent::Logout)),
            251 => Some(EventType::ManageSieve(ManageSieveEvent::Noop)),
            246 => Some(EventType::ManageSieve(ManageSieveEvent::Error)),
            252 => Some(EventType::ManageSieve(ManageSieveEvent::RawInput)),
            253 => Some(EventType::ManageSieve(ManageSieveEvent::RawOutput)),
            267 => Some(EventType::MessageIngest(MessageIngestEvent::Ham)),
            270 => Some(EventType::MessageIngest(MessageIngestEvent::Spam)),
            268 => Some(EventType::MessageIngest(MessageIngestEvent::ImapAppend)),
            269 => Some(EventType::MessageIngest(MessageIngestEvent::JmapAppend)),
            265 => Some(EventType::MessageIngest(MessageIngestEvent::Duplicate)),
            266 => Some(EventType::MessageIngest(MessageIngestEvent::Error)),
            283 => Some(EventType::Milter(MilterEvent::Read)),
            287 => Some(EventType::Milter(MilterEvent::Write)),
            271 => Some(EventType::Milter(MilterEvent::ActionAccept)),
            273 => Some(EventType::Milter(MilterEvent::ActionDiscard)),
            274 => Some(EventType::Milter(MilterEvent::ActionReject)),
            277 => Some(EventType::Milter(MilterEvent::ActionTempFail)),
            275 => Some(EventType::Milter(MilterEvent::ActionReplyCode)),
            272 => Some(EventType::Milter(MilterEvent::ActionConnectionFailure)),
            276 => Some(EventType::Milter(MilterEvent::ActionShutdown)),
            281 => Some(EventType::Milter(MilterEvent::IoError)),
            280 => Some(EventType::Milter(MilterEvent::FrameTooLarge)),
            279 => Some(EventType::Milter(MilterEvent::FrameInvalid)),
            286 => Some(EventType::Milter(MilterEvent::UnexpectedResponse)),
            284 => Some(EventType::Milter(MilterEvent::Timeout)),
            285 => Some(EventType::Milter(MilterEvent::TlsInvalidName)),
            278 => Some(EventType::Milter(MilterEvent::Disconnected)),
            282 => Some(EventType::Milter(MilterEvent::ParseError)),
            288 => Some(EventType::MtaHook(MtaHookEvent::ActionAccept)),
            289 => Some(EventType::MtaHook(MtaHookEvent::ActionDiscard)),
            291 => Some(EventType::MtaHook(MtaHookEvent::ActionReject)),
            290 => Some(EventType::MtaHook(MtaHookEvent::ActionQuarantine)),
            292 => Some(EventType::MtaHook(MtaHookEvent::Error)),
            293 => Some(EventType::MtaSts(MtaStsEvent::Authorized)),
            295 => Some(EventType::MtaSts(MtaStsEvent::NotAuthorized)),
            296 => Some(EventType::MtaSts(MtaStsEvent::PolicyFetch)),
            298 => Some(EventType::MtaSts(MtaStsEvent::PolicyNotFound)),
            297 => Some(EventType::MtaSts(MtaStsEvent::PolicyFetchError)),
            294 => Some(EventType::MtaSts(MtaStsEvent::InvalidPolicy)),
            305 => Some(EventType::Network(NetworkEvent::ListenStart)),
            306 => Some(EventType::Network(NetworkEvent::ListenStop)),
            304 => Some(EventType::Network(NetworkEvent::ListenError)),
            300 => Some(EventType::Network(NetworkEvent::BindError)),
            308 => Some(EventType::Network(NetworkEvent::ReadError)),
            312 => Some(EventType::Network(NetworkEvent::WriteError)),
            303 => Some(EventType::Network(NetworkEvent::FlushError)),
            299 => Some(EventType::Network(NetworkEvent::AcceptError)),
            310 => Some(EventType::Network(NetworkEvent::SplitError)),
            311 => Some(EventType::Network(NetworkEvent::Timeout)),
            301 => Some(EventType::Network(NetworkEvent::Closed)),
            307 => Some(EventType::Network(NetworkEvent::ProxyError)),
            309 => Some(EventType::Network(NetworkEvent::SetOptError)),
            326 => Some(EventType::OutgoingReport(OutgoingReportEvent::SpfReport)),
            325 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::SpfRateLimited,
            )),
            314 => Some(EventType::OutgoingReport(OutgoingReportEvent::DkimReport)),
            313 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::DkimRateLimited,
            )),
            317 => Some(EventType::OutgoingReport(OutgoingReportEvent::DmarcReport)),
            316 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::DmarcRateLimited,
            )),
            315 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::DmarcAggregateReport,
            )),
            328 => Some(EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate)),
            318 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::HttpSubmission,
            )),
            329 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::UnauthorizedReportingAddress,
            )),
            324 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::ReportingAddressValidationError,
            )),
            323 => Some(EventType::OutgoingReport(OutgoingReportEvent::NotFound)),
            327 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::SubmissionError,
            )),
            322 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::NoRecipientsFound,
            )),
            321 => Some(EventType::OutgoingReport(OutgoingReportEvent::Locked)),
            54 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::MaxSizeExceeded,
            )),
            332 => Some(EventType::Pop3(Pop3Event::ConnectionStart)),
            331 => Some(EventType::Pop3(Pop3Event::ConnectionEnd)),
            333 => Some(EventType::Pop3(Pop3Event::Delete)),
            342 => Some(EventType::Pop3(Pop3Event::Reset)),
            339 => Some(EventType::Pop3(Pop3Event::Quit)),
            335 => Some(EventType::Pop3(Pop3Event::Fetch)),
            336 => Some(EventType::Pop3(Pop3Event::List)),
            337 => Some(EventType::Pop3(Pop3Event::ListMessage)),
            345 => Some(EventType::Pop3(Pop3Event::Uidl)),
            346 => Some(EventType::Pop3(Pop3Event::UidlMessage)),
            344 => Some(EventType::Pop3(Pop3Event::Stat)),
            338 => Some(EventType::Pop3(Pop3Event::Noop)),
            330 => Some(EventType::Pop3(Pop3Event::Capabilities)),
            343 => Some(EventType::Pop3(Pop3Event::StartTls)),
            347 => Some(EventType::Pop3(Pop3Event::Utf8)),
            334 => Some(EventType::Pop3(Pop3Event::Error)),
            340 => Some(EventType::Pop3(Pop3Event::RawInput)),
            341 => Some(EventType::Pop3(Pop3Event::RawOutput)),
            357 => Some(EventType::PushSubscription(PushSubscriptionEvent::Success)),
            355 => Some(EventType::PushSubscription(PushSubscriptionEvent::Error)),
            356 => Some(EventType::PushSubscription(PushSubscriptionEvent::NotFound)),
            374 => Some(EventType::Queue(QueueEvent::Started)),
            364 => Some(EventType::Queue(QueueEvent::MessageQueued)),
            365 => Some(EventType::Queue(QueueEvent::AuthenticatedMessageQueued)),
            366 => Some(EventType::Queue(QueueEvent::ReportQueued)),
            363 => Some(EventType::Queue(QueueEvent::DsnQueued)),
            362 => Some(EventType::Queue(QueueEvent::AutogeneratedQueued)),
            369 => Some(EventType::Queue(QueueEvent::Rescheduled)),
            361 => Some(EventType::Queue(QueueEvent::Locked)),
            358 => Some(EventType::Queue(QueueEvent::BlobNotFound)),
            368 => Some(EventType::Queue(QueueEvent::RateLimitExceeded)),
            359 => Some(EventType::Queue(QueueEvent::ConcurrencyLimitExceeded)),
            367 => Some(EventType::Queue(QueueEvent::QuotaExceeded)),
            43 => Some(EventType::Queue(QueueEvent::BackPressure)),
            57 => Some(EventType::Registry(RegistryEvent::LocalReadError)),
            49 => Some(EventType::Registry(RegistryEvent::LocalWriteError)),
            55 => Some(EventType::Registry(RegistryEvent::LocalParseError)),
            60 => Some(EventType::Registry(RegistryEvent::ReadError)),
            53 => Some(EventType::Registry(RegistryEvent::WriteError)),
            51 => Some(EventType::Registry(RegistryEvent::DeserializationError)),
            56 => Some(EventType::Registry(RegistryEvent::BuildError)),
            50 => Some(EventType::Registry(RegistryEvent::BuildWarning)),
            59 => Some(EventType::Registry(RegistryEvent::NotSupported)),
            58 => Some(EventType::Registry(RegistryEvent::ValidationError)),
            373 => Some(EventType::Resource(ResourceEvent::NotFound)),
            370 => Some(EventType::Resource(ResourceEvent::BadParameters)),
            372 => Some(EventType::Resource(ResourceEvent::Error)),
            371 => Some(EventType::Resource(ResourceEvent::DownloadExternal)),
            584 => Some(EventType::Resource(ResourceEvent::ApplicationUpdated)),
            585 => Some(EventType::Resource(ResourceEvent::ApplicationUnpacked)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            609 => Some(EventType::Scim(ScimEvent::Request)),
            #[cfg(feature = "enterprise")]
            610 => Some(EventType::Scim(ScimEvent::Forbidden)),
            #[cfg(feature = "enterprise")]
            611 => Some(EventType::Scim(ScimEvent::Conflict)),
            #[cfg(feature = "enterprise")]
            612 => Some(EventType::Scim(ScimEvent::Error)),
            #[cfg(feature = "enterprise")]
            613 => Some(EventType::Scim(ScimEvent::ResourceCreated)),
            #[cfg(feature = "enterprise")]
            614 => Some(EventType::Scim(ScimEvent::ResourceUpdated)),
            #[cfg(feature = "enterprise")]
            615 => Some(EventType::Scim(ScimEvent::ResourceDeleted)),
            #[cfg(feature = "enterprise")]
            616 => Some(EventType::Scim(ScimEvent::Query)),
            #[cfg(feature = "enterprise")]
            617 => Some(EventType::Scim(ScimEvent::BulkProcessed)),
            #[cfg(feature = "enterprise")]
            618 => Some(EventType::Scim(ScimEvent::BulkAborted)),
            #[cfg(feature = "enterprise")]
            619 => Some(EventType::Scim(ScimEvent::RollbackFailed)),
            #[cfg(feature = "enterprise")]
            620 => Some(EventType::Scim(ScimEvent::AttributeIgnored)),
            // SPDX-SnippetEnd
            629 => Some(EventType::SearchIndex(SearchIndexEvent::ManagerStarted)),
            630 => Some(EventType::SearchIndex(SearchIndexEvent::PartitionsAcquired)),
            631 => Some(EventType::SearchIndex(SearchIndexEvent::PartitionLocked)),
            632 => Some(EventType::SearchIndex(SearchIndexEvent::PartitionRetry)),
            126 => Some(EventType::SearchIndex(SearchIndexEvent::BatchIndexed)),
            574 => Some(EventType::SearchIndex(SearchIndexEvent::DocumentIgnored)),
            628 => Some(EventType::SearchIndex(SearchIndexEvent::DocumentTruncated)),
            27 => Some(EventType::SearchIndex(SearchIndexEvent::MetadataNotFound)),
            28 => Some(EventType::Security(SecurityEvent::AuthenticationBan)),
            532 => Some(EventType::Security(SecurityEvent::AbuseBan)),
            541 => Some(EventType::Security(SecurityEvent::ScanBan)),
            533 => Some(EventType::Security(SecurityEvent::LoiterBan)),
            302 => Some(EventType::Security(SecurityEvent::IpBlocked)),
            576 => Some(EventType::Security(SecurityEvent::IpBlockExpired)),
            577 => Some(EventType::Security(SecurityEvent::IpAllowExpired)),
            263 => Some(EventType::Security(SecurityEvent::IpUnauthorized)),
            535 => Some(EventType::Security(SecurityEvent::Unauthorized)),
            377 => Some(EventType::Server(ServerEvent::Startup)),
            376 => Some(EventType::Server(ServerEvent::Shutdown)),
            378 => Some(EventType::Server(ServerEvent::StartupError)),
            379 => Some(EventType::Server(ServerEvent::ThreadError)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            375 => Some(EventType::Server(ServerEvent::Licensing)),
            // SPDX-SnippetEnd
            586 => Some(EventType::Server(ServerEvent::RecoveryMode)),
            587 => Some(EventType::Server(ServerEvent::BootstrapMode)),
            380 => Some(EventType::Sieve(SieveEvent::ActionAccept)),
            381 => Some(EventType::Sieve(SieveEvent::ActionAcceptReplace)),
            382 => Some(EventType::Sieve(SieveEvent::ActionDiscard)),
            383 => Some(EventType::Sieve(SieveEvent::ActionReject)),
            390 => Some(EventType::Sieve(SieveEvent::SendMessage)),
            385 => Some(EventType::Sieve(SieveEvent::MessageTooLarge)),
            389 => Some(EventType::Sieve(SieveEvent::ScriptNotFound)),
            384 => Some(EventType::Sieve(SieveEvent::ListNotFound)),
            388 => Some(EventType::Sieve(SieveEvent::RuntimeError)),
            391 => Some(EventType::Sieve(SieveEvent::UnexpectedError)),
            386 => Some(EventType::Sieve(SieveEvent::NotSupported)),
            387 => Some(EventType::Sieve(SieveEvent::QuotaExceeded)),
            401 => Some(EventType::Smtp(SmtpEvent::ConnectionStart)),
            400 => Some(EventType::Smtp(SmtpEvent::ConnectionEnd)),
            412 => Some(EventType::Smtp(SmtpEvent::Error)),
            452 => Some(EventType::Smtp(SmtpEvent::IdNotFound)),
            399 => Some(EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded)),
            468 => Some(EventType::Smtp(SmtpEvent::TransferLimitExceeded)),
            444 => Some(EventType::Smtp(SmtpEvent::RateLimitExceeded)),
            464 => Some(EventType::Smtp(SmtpEvent::TimeLimitExceeded)),
            434 => Some(EventType::Smtp(SmtpEvent::MessageParseFailed)),
            435 => Some(EventType::Smtp(SmtpEvent::MessageTooLarge)),
            427 => Some(EventType::Smtp(SmtpEvent::LoopDetected)),
            626 => Some(EventType::Smtp(SmtpEvent::MultipleFromDomains)),
            406 => Some(EventType::Smtp(SmtpEvent::DkimPass)),
            405 => Some(EventType::Smtp(SmtpEvent::DkimFail)),
            589 => Some(EventType::Smtp(SmtpEvent::Dkim2Pass)),
            590 => Some(EventType::Smtp(SmtpEvent::Dkim2Fail)),
            591 => Some(EventType::Smtp(SmtpEvent::Dkim2DsnRejected)),
            394 => Some(EventType::Smtp(SmtpEvent::ArcPass)),
            393 => Some(EventType::Smtp(SmtpEvent::ArcFail)),
            457 => Some(EventType::Smtp(SmtpEvent::SpfEhloPass)),
            456 => Some(EventType::Smtp(SmtpEvent::SpfEhloFail)),
            459 => Some(EventType::Smtp(SmtpEvent::SpfFromPass)),
            458 => Some(EventType::Smtp(SmtpEvent::SpfFromFail)),
            408 => Some(EventType::Smtp(SmtpEvent::DmarcPass)),
            407 => Some(EventType::Smtp(SmtpEvent::DmarcFail)),
            425 => Some(EventType::Smtp(SmtpEvent::IprevPass)),
            424 => Some(EventType::Smtp(SmtpEvent::IprevFail)),
            466 => Some(EventType::Smtp(SmtpEvent::TooManyMessages)),
            410 => Some(EventType::Smtp(SmtpEvent::Ehlo)),
            420 => Some(EventType::Smtp(SmtpEvent::InvalidEhlo)),
            404 => Some(EventType::Smtp(SmtpEvent::DidNotSayEhlo)),
            411 => Some(EventType::Smtp(SmtpEvent::EhloExpected)),
            426 => Some(EventType::Smtp(SmtpEvent::LhloExpected)),
            431 => Some(EventType::Smtp(SmtpEvent::MailFromUnauthenticated)),
            432 => Some(EventType::Smtp(SmtpEvent::MailFromUnauthorized)),
            534 => Some(EventType::Smtp(SmtpEvent::MailFromNotAllowed)),
            430 => Some(EventType::Smtp(SmtpEvent::MailFromRewritten)),
            429 => Some(EventType::Smtp(SmtpEvent::MailFromMissing)),
            428 => Some(EventType::Smtp(SmtpEvent::MailFrom)),
            439 => Some(EventType::Smtp(SmtpEvent::MultipleMailFrom)),
            433 => Some(EventType::Smtp(SmtpEvent::MailboxDoesNotExist)),
            451 => Some(EventType::Smtp(SmtpEvent::RelayNotAllowed)),
            447 => Some(EventType::Smtp(SmtpEvent::RcptTo)),
            448 => Some(EventType::Smtp(SmtpEvent::RcptToDuplicate)),
            450 => Some(EventType::Smtp(SmtpEvent::RcptToRewritten)),
            449 => Some(EventType::Smtp(SmtpEvent::RcptToMissing)),
            544 => Some(EventType::Smtp(SmtpEvent::RcptToGreylisted)),
            467 => Some(EventType::Smtp(SmtpEvent::TooManyRecipients)),
            465 => Some(EventType::Smtp(SmtpEvent::TooManyInvalidRcpt)),
            445 => Some(EventType::Smtp(SmtpEvent::RawInput)),
            446 => Some(EventType::Smtp(SmtpEvent::RawOutput)),
            436 => Some(EventType::Smtp(SmtpEvent::MissingLocalHostname)),
            470 => Some(EventType::Smtp(SmtpEvent::Vrfy)),
            472 => Some(EventType::Smtp(SmtpEvent::VrfyNotFound)),
            471 => Some(EventType::Smtp(SmtpEvent::VrfyDisabled)),
            413 => Some(EventType::Smtp(SmtpEvent::Expn)),
            415 => Some(EventType::Smtp(SmtpEvent::ExpnNotFound)),
            414 => Some(EventType::Smtp(SmtpEvent::ExpnDisabled)),
            454 => Some(EventType::Smtp(SmtpEvent::RequireTlsDisabled)),
            402 => Some(EventType::Smtp(SmtpEvent::DeliverByDisabled)),
            403 => Some(EventType::Smtp(SmtpEvent::DeliverByInvalid)),
            416 => Some(EventType::Smtp(SmtpEvent::FutureReleaseDisabled)),
            417 => Some(EventType::Smtp(SmtpEvent::FutureReleaseInvalid)),
            437 => Some(EventType::Smtp(SmtpEvent::MtPriorityDisabled)),
            438 => Some(EventType::Smtp(SmtpEvent::MtPriorityInvalid)),
            409 => Some(EventType::Smtp(SmtpEvent::DsnDisabled)),
            397 => Some(EventType::Smtp(SmtpEvent::AuthNotAllowed)),
            396 => Some(EventType::Smtp(SmtpEvent::AuthMechanismNotSupported)),
            395 => Some(EventType::Smtp(SmtpEvent::AuthExchangeTooLong)),
            392 => Some(EventType::Smtp(SmtpEvent::AlreadyAuthenticated)),
            440 => Some(EventType::Smtp(SmtpEvent::Noop)),
            460 => Some(EventType::Smtp(SmtpEvent::StartTls)),
            462 => Some(EventType::Smtp(SmtpEvent::StartTlsUnavailable)),
            461 => Some(EventType::Smtp(SmtpEvent::StartTlsAlready)),
            455 => Some(EventType::Smtp(SmtpEvent::Rset)),
            443 => Some(EventType::Smtp(SmtpEvent::Quit)),
            418 => Some(EventType::Smtp(SmtpEvent::Help)),
            398 => Some(EventType::Smtp(SmtpEvent::CommandNotImplemented)),
            419 => Some(EventType::Smtp(SmtpEvent::InvalidCommand)),
            423 => Some(EventType::Smtp(SmtpEvent::InvalidSenderAddress)),
            422 => Some(EventType::Smtp(SmtpEvent::InvalidRecipientAddress)),
            421 => Some(EventType::Smtp(SmtpEvent::InvalidParameter)),
            469 => Some(EventType::Smtp(SmtpEvent::UnsupportedParameter)),
            463 => Some(EventType::Smtp(SmtpEvent::SyntaxError)),
            453 => Some(EventType::Smtp(SmtpEvent::RequestTooLarge)),
            547 => Some(EventType::Spam(SpamEvent::Pyzor)),
            477 => Some(EventType::Spam(SpamEvent::PyzorError)),
            545 => Some(EventType::Spam(SpamEvent::Dnsbl)),
            546 => Some(EventType::Spam(SpamEvent::DnsblError)),
            571 => Some(EventType::Spam(SpamEvent::TrainStarted)),
            478 => Some(EventType::Spam(SpamEvent::TrainCompleted)),
            127 => Some(EventType::Spam(SpamEvent::TrainSampleAdded)),
            474 => Some(EventType::Spam(SpamEvent::TrainSampleNotFound)),
            473 => Some(EventType::Spam(SpamEvent::Classify)),
            572 => Some(EventType::Spam(SpamEvent::ModelLoaded)),
            479 => Some(EventType::Spam(SpamEvent::ModelNotReady)),
            480 => Some(EventType::Spam(SpamEvent::ModelNotFound)),
            264 => Some(EventType::Spam(SpamEvent::RulesUpdated)),
            484 => Some(EventType::Spf(SpfEvent::Pass)),
            481 => Some(EventType::Spf(SpfEvent::Fail)),
            486 => Some(EventType::Spf(SpfEvent::SoftFail)),
            482 => Some(EventType::Spf(SpfEvent::Neutral)),
            487 => Some(EventType::Spf(SpfEvent::TempError)),
            485 => Some(EventType::Spf(SpfEvent::PermError)),
            483 => Some(EventType::Spf(SpfEvent::None)),
            488 => Some(EventType::Store(StoreEvent::AssertValueFailed)),
            501 => Some(EventType::Store(StoreEvent::FoundationdbError)),
            505 => Some(EventType::Store(StoreEvent::MysqlError)),
            510 => Some(EventType::Store(StoreEvent::PostgresqlError)),
            512 => Some(EventType::Store(StoreEvent::RocksdbError)),
            515 => Some(EventType::Store(StoreEvent::SqliteError)),
            503 => Some(EventType::Store(StoreEvent::LdapError)),
            499 => Some(EventType::Store(StoreEvent::ElasticsearchError)),
            573 => Some(EventType::Store(StoreEvent::MeilisearchError)),
            511 => Some(EventType::Store(StoreEvent::RedisError)),
            513 => Some(EventType::Store(StoreEvent::S3Error)),
            542 => Some(EventType::Store(StoreEvent::AzureError)),
            500 => Some(EventType::Store(StoreEvent::FilesystemError)),
            509 => Some(EventType::Store(StoreEvent::PoolError)),
            494 => Some(EventType::Store(StoreEvent::DataCorruption)),
            497 => Some(EventType::Store(StoreEvent::DecompressError)),
            498 => Some(EventType::Store(StoreEvent::DeserializeError)),
            507 => Some(EventType::Store(StoreEvent::NotFound)),
            506 => Some(EventType::Store(StoreEvent::NotConfigured)),
            508 => Some(EventType::Store(StoreEvent::NotSupported)),
            516 => Some(EventType::Store(StoreEvent::UnexpectedError)),
            493 => Some(EventType::Store(StoreEvent::CryptoError)),
            476 => Some(EventType::Store(StoreEvent::HttpStoreError)),
            490 => Some(EventType::Store(StoreEvent::BlobMissingMarker)),
            496 => Some(EventType::Store(StoreEvent::DataWrite)),
            495 => Some(EventType::Store(StoreEvent::DataIterate)),
            491 => Some(EventType::Store(StoreEvent::BlobRead)),
            492 => Some(EventType::Store(StoreEvent::BlobWrite)),
            489 => Some(EventType::Store(StoreEvent::BlobDelete)),
            514 => Some(EventType::Store(StoreEvent::SqlQuery)),
            504 => Some(EventType::Store(StoreEvent::LdapQuery)),
            502 => Some(EventType::Store(StoreEvent::LdapWarning)),
            475 => Some(EventType::Store(StoreEvent::HttpStoreFetch)),
            348 => Some(EventType::Store(StoreEvent::AutoExpunge)),
            353 => Some(EventType::Store(StoreEvent::BlobStorePurged)),
            352 => Some(EventType::Store(StoreEvent::DataStorePurged)),
            561 => Some(EventType::TaskManager(TaskManagerEvent::TaskAcquired)),
            133 => Some(EventType::TaskManager(TaskManagerEvent::TaskQueued)),
            354 => Some(EventType::TaskManager(TaskManagerEvent::TaskScheduled)),
            128 => Some(EventType::TaskManager(TaskManagerEvent::TaskLocked)),
            569 => Some(EventType::TaskManager(TaskManagerEvent::TaskIgnored)),
            570 => Some(EventType::TaskManager(TaskManagerEvent::TaskFailed)),
            48 => Some(EventType::TaskManager(TaskManagerEvent::TaskRetry)),
            651 => Some(EventType::TaskManager(TaskManagerEvent::TaskStalled)),
            652 => Some(EventType::TaskManager(TaskManagerEvent::TaskExpired)),
            125 => Some(EventType::TaskManager(TaskManagerEvent::BlobNotFound)),
            129 => Some(EventType::TaskManager(TaskManagerEvent::MetadataNotFound)),
            134 => Some(EventType::TaskManager(TaskManagerEvent::SchedulerStarted)),
            351 => Some(EventType::TaskManager(TaskManagerEvent::ManagerStarted)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            531 => Some(EventType::Telemetry(TelemetryEvent::AlertEvent)),
            #[cfg(feature = "enterprise")]
            349 => Some(EventType::Telemetry(TelemetryEvent::AlertMessage)),
            // SPDX-SnippetEnd
            518 => Some(EventType::Telemetry(TelemetryEvent::LogError)),
            522 => Some(EventType::Telemetry(TelemetryEvent::WebhookError)),
            519 => Some(EventType::Telemetry(TelemetryEvent::OtelExporterError)),
            520 => Some(EventType::Telemetry(
                TelemetryEvent::OtelMetricsExporterError,
            )),
            521 => Some(EventType::Telemetry(
                TelemetryEvent::PrometheusExporterError,
            )),
            517 => Some(EventType::Telemetry(TelemetryEvent::JournalError)),
            601 => Some(EventType::Telemetry(TelemetryEvent::EventsDropped)),
            135 => Some(EventType::Telemetry(TelemetryEvent::MetricsCollected)),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            350 => Some(EventType::Telemetry(TelemetryEvent::MetricsStored)),
            // SPDX-SnippetEnd
            130 => Some(EventType::Telemetry(TelemetryEvent::MetricsPushed)),
            526 => Some(EventType::Tls(TlsEvent::Handshake)),
            527 => Some(EventType::Tls(TlsEvent::HandshakeError)),
            530 => Some(EventType::Tls(TlsEvent::NotConfigured)),
            525 => Some(EventType::Tls(TlsEvent::CertificateNotFound)),
            529 => Some(EventType::Tls(TlsEvent::NoCertificatesAvailable)),
            528 => Some(EventType::Tls(TlsEvent::MultipleCertificatesAvailable)),
            261 => Some(EventType::Tls(TlsEvent::ExpiredCertificateRemoved)),
            523 => Some(EventType::TlsRpt(TlsRptEvent::RecordFetch)),
            524 => Some(EventType::TlsRpt(TlsRptEvent::RecordFetchError)),
            543 => Some(EventType::TlsRpt(TlsRptEvent::RecordNotFound)),
            131 => Some(EventType::WebDav(WebDavEvent::Propfind)),
            132 => Some(EventType::WebDav(WebDavEvent::Proppatch)),
            319 => Some(EventType::WebDav(WebDavEvent::Get)),
            557 => Some(EventType::WebDav(WebDavEvent::Head)),
            320 => Some(EventType::WebDav(WebDavEvent::Report)),
            360 => Some(EventType::WebDav(WebDavEvent::Mkcol)),
            558 => Some(EventType::WebDav(WebDavEvent::Mkcalendar)),
            441 => Some(EventType::WebDav(WebDavEvent::Delete)),
            442 => Some(EventType::WebDav(WebDavEvent::Put)),
            548 => Some(EventType::WebDav(WebDavEvent::Post)),
            549 => Some(EventType::WebDav(WebDavEvent::Patch)),
            550 => Some(EventType::WebDav(WebDavEvent::Copy)),
            551 => Some(EventType::WebDav(WebDavEvent::Move)),
            552 => Some(EventType::WebDav(WebDavEvent::Lock)),
            553 => Some(EventType::WebDav(WebDavEvent::Unlock)),
            554 => Some(EventType::WebDav(WebDavEvent::Acl)),
            556 => Some(EventType::WebDav(WebDavEvent::Options)),
            555 => Some(EventType::WebDav(WebDavEvent::Error)),
            _ => None,
        }
    }

    pub fn level(&self) -> Level {
        match self {
            EventType::Acme(AcmeEvent::Error) => Level::Error,
            EventType::Auth(AuthEvent::Error) => Level::Error,
            EventType::Cluster(ClusterEvent::SubscriberError) => Level::Error,
            EventType::Cluster(ClusterEvent::PublisherError) => Level::Error,
            EventType::Cluster(ClusterEvent::MessageInvalid) => Level::Error,
            EventType::Dkim(DkimEvent::BuildError) => Level::Error,
            EventType::MessageIngest(MessageIngestEvent::Error) => Level::Error,
            EventType::Network(NetworkEvent::ListenError) => Level::Error,
            EventType::Network(NetworkEvent::BindError) => Level::Error,
            EventType::Network(NetworkEvent::SplitError) => Level::Error,
            EventType::Network(NetworkEvent::SetOptError) => Level::Error,
            EventType::Registry(RegistryEvent::LocalReadError) => Level::Error,
            EventType::Registry(RegistryEvent::LocalWriteError) => Level::Error,
            EventType::Registry(RegistryEvent::LocalParseError) => Level::Error,
            EventType::Registry(RegistryEvent::ReadError) => Level::Error,
            EventType::Registry(RegistryEvent::WriteError) => Level::Error,
            EventType::Registry(RegistryEvent::DeserializationError) => Level::Error,
            EventType::Registry(RegistryEvent::BuildError) => Level::Error,
            EventType::Registry(RegistryEvent::ValidationError) => Level::Error,
            EventType::Resource(ResourceEvent::BadParameters) => Level::Error,
            EventType::Resource(ResourceEvent::Error) => Level::Error,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::RollbackFailed) => Level::Error,
            // SPDX-SnippetEnd
            EventType::Server(ServerEvent::StartupError) => Level::Error,
            EventType::Server(ServerEvent::ThreadError) => Level::Error,
            EventType::Sieve(SieveEvent::UnexpectedError) => Level::Error,
            EventType::Store(StoreEvent::AssertValueFailed) => Level::Error,
            EventType::Store(StoreEvent::FoundationdbError) => Level::Error,
            EventType::Store(StoreEvent::MysqlError) => Level::Error,
            EventType::Store(StoreEvent::PostgresqlError) => Level::Error,
            EventType::Store(StoreEvent::RocksdbError) => Level::Error,
            EventType::Store(StoreEvent::SqliteError) => Level::Error,
            EventType::Store(StoreEvent::LdapError) => Level::Error,
            EventType::Store(StoreEvent::ElasticsearchError) => Level::Error,
            EventType::Store(StoreEvent::MeilisearchError) => Level::Error,
            EventType::Store(StoreEvent::RedisError) => Level::Error,
            EventType::Store(StoreEvent::S3Error) => Level::Error,
            EventType::Store(StoreEvent::AzureError) => Level::Error,
            EventType::Store(StoreEvent::FilesystemError) => Level::Error,
            EventType::Store(StoreEvent::PoolError) => Level::Error,
            EventType::Store(StoreEvent::DataCorruption) => Level::Error,
            EventType::Store(StoreEvent::DecompressError) => Level::Error,
            EventType::Store(StoreEvent::DeserializeError) => Level::Error,
            EventType::Store(StoreEvent::NotConfigured) => Level::Error,
            EventType::Store(StoreEvent::NotSupported) => Level::Error,
            EventType::Store(StoreEvent::UnexpectedError) => Level::Error,
            EventType::Store(StoreEvent::CryptoError) => Level::Error,
            EventType::Tls(TlsEvent::NotConfigured) => Level::Error,
            EventType::Acme(AcmeEvent::AuthStart) => Level::Info,
            EventType::Acme(AcmeEvent::AuthPending) => Level::Info,
            EventType::Acme(AcmeEvent::AuthValid) => Level::Info,
            EventType::Acme(AcmeEvent::AuthCompleted) => Level::Info,
            EventType::Acme(AcmeEvent::ProcessCert) => Level::Info,
            EventType::Acme(AcmeEvent::OrderStart) => Level::Info,
            EventType::Acme(AcmeEvent::OrderProcessing) => Level::Info,
            EventType::Acme(AcmeEvent::OrderCompleted) => Level::Info,
            EventType::Acme(AcmeEvent::OrderReady) => Level::Info,
            EventType::Acme(AcmeEvent::OrderValid) => Level::Info,
            EventType::Acme(AcmeEvent::TlsAlpnReceived) => Level::Info,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamVerdict) => Level::Info,
            // SPDX-SnippetEnd
            EventType::Auth(AuthEvent::Success) => Level::Info,
            EventType::Auth(AuthEvent::ClientRegistration) => Level::Info,
            EventType::Calendar(CalendarEvent::AlarmSent) => Level::Info,
            EventType::Calendar(CalendarEvent::ItipMessageSent) => Level::Info,
            EventType::Calendar(CalendarEvent::ItipMessageReceived) => Level::Info,
            EventType::Cluster(ClusterEvent::Startup) => Level::Info,
            EventType::Cluster(ClusterEvent::SubscriberStart) => Level::Info,
            EventType::Cluster(ClusterEvent::SubscriberStop) => Level::Info,
            EventType::Cluster(ClusterEvent::PublisherStart) => Level::Info,
            EventType::Cluster(ClusterEvent::PublisherStop) => Level::Info,
            EventType::Dane(DaneEvent::AuthenticationSuccess) => Level::Info,
            EventType::Dane(DaneEvent::AuthenticationFailure) => Level::Info,
            EventType::Dane(DaneEvent::NoCertificatesFound) => Level::Info,
            EventType::Dane(DaneEvent::CertificateParseError) => Level::Info,
            EventType::Dane(DaneEvent::TlsaRecordMatch) => Level::Info,
            EventType::Dane(DaneEvent::TlsaRecordFetch) => Level::Info,
            EventType::Dane(DaneEvent::TlsaRecordFetchError) => Level::Info,
            EventType::Dane(DaneEvent::TlsaRecordNotFound) => Level::Info,
            EventType::Dane(DaneEvent::TlsaRecordInvalid) => Level::Info,
            EventType::Dane(DaneEvent::BogusDnssecRecord) => Level::Info,
            EventType::Delivery(DeliveryEvent::Failed) => Level::Info,
            EventType::Delivery(DeliveryEvent::MxLookupFailed) => Level::Info,
            EventType::Delivery(DeliveryEvent::IpLookupFailed) => Level::Info,
            EventType::Delivery(DeliveryEvent::NullMx) => Level::Info,
            EventType::Delivery(DeliveryEvent::ConnectError) => Level::Info,
            EventType::Delivery(DeliveryEvent::GreetingFailed) => Level::Info,
            EventType::Delivery(DeliveryEvent::EhloRejected) => Level::Info,
            EventType::Delivery(DeliveryEvent::AuthFailed) => Level::Info,
            EventType::Delivery(DeliveryEvent::MailFromRejected) => Level::Info,
            EventType::Delivery(DeliveryEvent::Delivered) => Level::Info,
            EventType::Delivery(DeliveryEvent::RcptToRejected) => Level::Info,
            EventType::Delivery(DeliveryEvent::RcptToFailed) => Level::Info,
            EventType::Delivery(DeliveryEvent::MessageRejected) => Level::Info,
            EventType::Delivery(DeliveryEvent::StartTlsError) => Level::Info,
            EventType::Delivery(DeliveryEvent::StartTlsDisabled) => Level::Info,
            EventType::Delivery(DeliveryEvent::ImplicitTlsError) => Level::Info,
            EventType::Delivery(DeliveryEvent::DoubleBounce) => Level::Info,
            EventType::Delivery(DeliveryEvent::DsnTempFail) => Level::Info,
            EventType::Delivery(DeliveryEvent::DsnPermFail) => Level::Info,
            EventType::Dkim(DkimEvent::SignatureCreated) => Level::Info,
            EventType::Dkim(DkimEvent::SignaturePublished) => Level::Info,
            EventType::Dkim(DkimEvent::SignatureRetiring) => Level::Info,
            EventType::Dkim(DkimEvent::SignatureRetired) => Level::Info,
            EventType::Dkim(DkimEvent::SignatureDeleted) => Level::Info,
            EventType::Dns(DnsEvent::RecordCreated) => Level::Info,
            EventType::Dns(DnsEvent::RecordPropagated) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::DmarcReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::TlsReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::AbuseReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::FraudReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::VirusReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::OtherReport) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed) => Level::Info,
            EventType::IncomingReport(IncomingReportEvent::DecompressError) => Level::Info,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => Level::Info,
            // SPDX-SnippetEnd
            EventType::MessageIngest(MessageIngestEvent::Ham) => Level::Info,
            EventType::MessageIngest(MessageIngestEvent::Spam) => Level::Info,
            EventType::MessageIngest(MessageIngestEvent::ImapAppend) => Level::Info,
            EventType::MessageIngest(MessageIngestEvent::JmapAppend) => Level::Info,
            EventType::MessageIngest(MessageIngestEvent::Duplicate) => Level::Info,
            EventType::Milter(MilterEvent::ActionAccept) => Level::Info,
            EventType::Milter(MilterEvent::ActionDiscard) => Level::Info,
            EventType::Milter(MilterEvent::ActionReject) => Level::Info,
            EventType::Milter(MilterEvent::ActionTempFail) => Level::Info,
            EventType::Milter(MilterEvent::ActionReplyCode) => Level::Info,
            EventType::Milter(MilterEvent::ActionConnectionFailure) => Level::Info,
            EventType::Milter(MilterEvent::ActionShutdown) => Level::Info,
            EventType::MtaHook(MtaHookEvent::ActionAccept) => Level::Info,
            EventType::MtaHook(MtaHookEvent::ActionDiscard) => Level::Info,
            EventType::MtaHook(MtaHookEvent::ActionReject) => Level::Info,
            EventType::MtaHook(MtaHookEvent::ActionQuarantine) => Level::Info,
            EventType::MtaSts(MtaStsEvent::NotAuthorized) => Level::Info,
            EventType::MtaSts(MtaStsEvent::PolicyFetchError) => Level::Info,
            EventType::MtaSts(MtaStsEvent::InvalidPolicy) => Level::Info,
            EventType::Network(NetworkEvent::ListenStart) => Level::Info,
            EventType::Network(NetworkEvent::ListenStop) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress) => {
                Level::Info
            }
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError) => {
                Level::Info
            }
            EventType::OutgoingReport(OutgoingReportEvent::NotFound) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound) => Level::Info,
            EventType::OutgoingReport(OutgoingReportEvent::Locked) => Level::Info,
            EventType::Queue(QueueEvent::Started) => Level::Info,
            EventType::Queue(QueueEvent::MessageQueued) => Level::Info,
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued) => Level::Info,
            EventType::Queue(QueueEvent::ReportQueued) => Level::Info,
            EventType::Queue(QueueEvent::DsnQueued) => Level::Info,
            EventType::Queue(QueueEvent::AutogeneratedQueued) => Level::Info,
            EventType::Queue(QueueEvent::Rescheduled) => Level::Info,
            EventType::Queue(QueueEvent::RateLimitExceeded) => Level::Info,
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded) => Level::Info,
            EventType::Queue(QueueEvent::QuotaExceeded) => Level::Info,
            EventType::Resource(ResourceEvent::DownloadExternal) => Level::Info,
            EventType::Resource(ResourceEvent::ApplicationUpdated) => Level::Info,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Forbidden) => Level::Info,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Conflict) => Level::Info,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceCreated) => Level::Info,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceUpdated) => Level::Info,
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceDeleted) => Level::Info,
            // SPDX-SnippetEnd
            EventType::SearchIndex(SearchIndexEvent::ManagerStarted) => Level::Info,
            EventType::Security(SecurityEvent::AuthenticationBan) => Level::Info,
            EventType::Security(SecurityEvent::AbuseBan) => Level::Info,
            EventType::Security(SecurityEvent::ScanBan) => Level::Info,
            EventType::Security(SecurityEvent::LoiterBan) => Level::Info,
            EventType::Security(SecurityEvent::IpBlocked) => Level::Info,
            EventType::Security(SecurityEvent::IpBlockExpired) => Level::Info,
            EventType::Security(SecurityEvent::IpAllowExpired) => Level::Info,
            EventType::Security(SecurityEvent::IpUnauthorized) => Level::Info,
            EventType::Security(SecurityEvent::Unauthorized) => Level::Info,
            EventType::Server(ServerEvent::Startup) => Level::Info,
            EventType::Server(ServerEvent::Shutdown) => Level::Info,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Server(ServerEvent::Licensing) => Level::Info,
            // SPDX-SnippetEnd
            EventType::Sieve(SieveEvent::SendMessage) => Level::Info,
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => Level::Info,
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => Level::Info,
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => Level::Info,
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => Level::Info,
            EventType::Smtp(SmtpEvent::MessageParseFailed) => Level::Info,
            EventType::Smtp(SmtpEvent::MessageTooLarge) => Level::Info,
            EventType::Smtp(SmtpEvent::LoopDetected) => Level::Info,
            EventType::Smtp(SmtpEvent::MultipleFromDomains) => Level::Info,
            EventType::Smtp(SmtpEvent::DkimPass) => Level::Info,
            EventType::Smtp(SmtpEvent::DkimFail) => Level::Info,
            EventType::Smtp(SmtpEvent::Dkim2Pass) => Level::Info,
            EventType::Smtp(SmtpEvent::Dkim2Fail) => Level::Info,
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected) => Level::Info,
            EventType::Smtp(SmtpEvent::ArcPass) => Level::Info,
            EventType::Smtp(SmtpEvent::ArcFail) => Level::Info,
            EventType::Smtp(SmtpEvent::SpfEhloPass) => Level::Info,
            EventType::Smtp(SmtpEvent::SpfEhloFail) => Level::Info,
            EventType::Smtp(SmtpEvent::SpfFromPass) => Level::Info,
            EventType::Smtp(SmtpEvent::SpfFromFail) => Level::Info,
            EventType::Smtp(SmtpEvent::DmarcPass) => Level::Info,
            EventType::Smtp(SmtpEvent::DmarcFail) => Level::Info,
            EventType::Smtp(SmtpEvent::IprevPass) => Level::Info,
            EventType::Smtp(SmtpEvent::IprevFail) => Level::Info,
            EventType::Smtp(SmtpEvent::TooManyMessages) => Level::Info,
            EventType::Smtp(SmtpEvent::Ehlo) => Level::Info,
            EventType::Smtp(SmtpEvent::InvalidEhlo) => Level::Info,
            EventType::Smtp(SmtpEvent::MailFrom) => Level::Info,
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => Level::Info,
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => Level::Info,
            EventType::Smtp(SmtpEvent::RcptTo) => Level::Info,
            EventType::Smtp(SmtpEvent::RcptToGreylisted) => Level::Info,
            EventType::Smtp(SmtpEvent::TooManyRecipients) => Level::Info,
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => Level::Info,
            EventType::Smtp(SmtpEvent::Vrfy) => Level::Info,
            EventType::Smtp(SmtpEvent::VrfyNotFound) => Level::Info,
            EventType::Smtp(SmtpEvent::VrfyDisabled) => Level::Info,
            EventType::Smtp(SmtpEvent::Expn) => Level::Info,
            EventType::Smtp(SmtpEvent::ExpnNotFound) => Level::Info,
            EventType::Smtp(SmtpEvent::ExpnDisabled) => Level::Info,
            EventType::Smtp(SmtpEvent::AuthNotAllowed) => Level::Info,
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => Level::Info,
            EventType::Smtp(SmtpEvent::RequestTooLarge) => Level::Info,
            EventType::Spam(SpamEvent::TrainStarted) => Level::Info,
            EventType::Spam(SpamEvent::TrainCompleted) => Level::Info,
            EventType::Spam(SpamEvent::ModelLoaded) => Level::Info,
            EventType::Spam(SpamEvent::ModelNotReady) => Level::Info,
            EventType::Spam(SpamEvent::ModelNotFound) => Level::Info,
            EventType::Spam(SpamEvent::RulesUpdated) => Level::Info,
            EventType::Store(StoreEvent::BlobStorePurged) => Level::Info,
            EventType::Store(StoreEvent::DataStorePurged) => Level::Info,
            EventType::TaskManager(TaskManagerEvent::TaskQueued) => Level::Info,
            EventType::TaskManager(TaskManagerEvent::TaskScheduled) => Level::Info,
            EventType::TaskManager(TaskManagerEvent::TaskExpired) => Level::Info,
            EventType::TaskManager(TaskManagerEvent::SchedulerStarted) => Level::Info,
            EventType::TaskManager(TaskManagerEvent::ManagerStarted) => Level::Info,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertMessage) => Level::Info,
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::MetricsCollected) => Level::Info,
            EventType::Tls(TlsEvent::Handshake) => Level::Info,
            EventType::Tls(TlsEvent::ExpiredCertificateRemoved) => Level::Info,
            EventType::TlsRpt(TlsRptEvent::RecordFetchError) => Level::Info,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::LlmResponse) => Level::Trace,
            // SPDX-SnippetEnd
            EventType::Auth(AuthEvent::MfaRequired) => Level::Trace,
            EventType::Cache(CacheEvent::Invalidate) => Level::Trace,
            EventType::Cluster(ClusterEvent::MessageReceived) => Level::Trace,
            EventType::Cluster(ClusterEvent::MessageSkipped) => Level::Trace,
            EventType::Delivery(DeliveryEvent::RawInput) => Level::Trace,
            EventType::Delivery(DeliveryEvent::RawOutput) => Level::Trace,
            EventType::Eval(EvalEvent::Result) => Level::Trace,
            EventType::Http(HttpEvent::RequestBody) => Level::Trace,
            EventType::Http(HttpEvent::ResponseBody) => Level::Trace,
            EventType::Imap(ImapEvent::RawInput) => Level::Trace,
            EventType::Imap(ImapEvent::RawOutput) => Level::Trace,
            EventType::ManageSieve(ManageSieveEvent::RawInput) => Level::Trace,
            EventType::ManageSieve(ManageSieveEvent::RawOutput) => Level::Trace,
            EventType::Milter(MilterEvent::Read) => Level::Trace,
            EventType::Milter(MilterEvent::Write) => Level::Trace,
            EventType::Network(NetworkEvent::ReadError) => Level::Trace,
            EventType::Network(NetworkEvent::WriteError) => Level::Trace,
            EventType::Network(NetworkEvent::FlushError) => Level::Trace,
            EventType::Network(NetworkEvent::Closed) => Level::Trace,
            EventType::Pop3(Pop3Event::RawInput) => Level::Trace,
            EventType::Pop3(Pop3Event::RawOutput) => Level::Trace,
            EventType::PushSubscription(PushSubscriptionEvent::Success) => Level::Trace,
            EventType::Smtp(SmtpEvent::RawInput) => Level::Trace,
            EventType::Smtp(SmtpEvent::RawOutput) => Level::Trace,
            EventType::Store(StoreEvent::DataWrite) => Level::Trace,
            EventType::Store(StoreEvent::DataIterate) => Level::Trace,
            EventType::Store(StoreEvent::BlobRead) => Level::Trace,
            EventType::Store(StoreEvent::BlobWrite) => Level::Trace,
            EventType::Store(StoreEvent::BlobDelete) => Level::Trace,
            EventType::Store(StoreEvent::SqlQuery) => Level::Trace,
            EventType::Store(StoreEvent::LdapQuery) => Level::Trace,
            EventType::Acme(AcmeEvent::AuthError) => Level::Warn,
            EventType::Acme(AcmeEvent::AuthTooManyAttempts) => Level::Warn,
            EventType::Acme(AcmeEvent::OrderInvalid) => Level::Warn,
            EventType::Acme(AcmeEvent::TlsAlpnError) => Level::Warn,
            EventType::Acme(AcmeEvent::TokenNotFound) => Level::Warn,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::ApiError) => Level::Warn,
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::BreakerOpen) => Level::Warn,
            // SPDX-SnippetEnd
            EventType::Auth(AuthEvent::TooManyAttempts) => Level::Warn,
            EventType::Cache(CacheEvent::SwapError) => Level::Warn,
            EventType::Calendar(CalendarEvent::AlarmFailed) => Level::Warn,
            EventType::Cluster(ClusterEvent::SubscriberDisconnected) => Level::Warn,
            EventType::Delivery(DeliveryEvent::MissingOutboundHostname) => Level::Warn,
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded) => Level::Warn,
            EventType::Delivery(DeliveryEvent::RateLimitExceeded) => Level::Warn,
            EventType::Dkim(DkimEvent::SignerNotFound) => Level::Warn,
            EventType::Dkim2(Dkim2Event::SigningFailed) => Level::Warn,
            EventType::Dns(DnsEvent::RecordCreationFailed) => Level::Warn,
            EventType::Dns(DnsEvent::RecordPropagationTimeout) => Level::Warn,
            EventType::Eval(EvalEvent::DirectoryNotFound) => Level::Warn,
            EventType::Http(HttpEvent::XForwardedMissing) => Level::Warn,
            EventType::Http(HttpEvent::XForwardedInvalid) => Level::Warn,
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings) => Level::Warn,
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings) => Level::Warn,
            EventType::Limit(LimitEvent::ConcurrentConnection) => Level::Warn,
            EventType::Limit(LimitEvent::TooManyRequests) => Level::Warn,
            EventType::Limit(LimitEvent::MemoryBudget) => Level::Warn,
            EventType::Milter(MilterEvent::IoError) => Level::Warn,
            EventType::Milter(MilterEvent::FrameTooLarge) => Level::Warn,
            EventType::Milter(MilterEvent::FrameInvalid) => Level::Warn,
            EventType::Milter(MilterEvent::UnexpectedResponse) => Level::Warn,
            EventType::Milter(MilterEvent::Timeout) => Level::Warn,
            EventType::Milter(MilterEvent::TlsInvalidName) => Level::Warn,
            EventType::Milter(MilterEvent::Disconnected) => Level::Warn,
            EventType::Milter(MilterEvent::ParseError) => Level::Warn,
            EventType::MtaHook(MtaHookEvent::Error) => Level::Warn,
            EventType::Network(NetworkEvent::ProxyError) => Level::Warn,
            EventType::Queue(QueueEvent::BackPressure) => Level::Warn,
            EventType::Registry(RegistryEvent::BuildWarning) => Level::Warn,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkAborted) => Level::Warn,
            // SPDX-SnippetEnd
            EventType::Server(ServerEvent::RecoveryMode) => Level::Warn,
            EventType::Server(ServerEvent::BootstrapMode) => Level::Warn,
            EventType::Sieve(SieveEvent::MessageTooLarge) => Level::Warn,
            EventType::Sieve(SieveEvent::ScriptNotFound) => Level::Warn,
            EventType::Sieve(SieveEvent::ListNotFound) => Level::Warn,
            EventType::Sieve(SieveEvent::NotSupported) => Level::Warn,
            EventType::Sieve(SieveEvent::QuotaExceeded) => Level::Warn,
            EventType::Smtp(SmtpEvent::IdNotFound) => Level::Warn,
            EventType::Smtp(SmtpEvent::MissingLocalHostname) => Level::Warn,
            EventType::Spam(SpamEvent::TrainSampleNotFound) => Level::Warn,
            EventType::Store(StoreEvent::HttpStoreError) => Level::Warn,
            EventType::Store(StoreEvent::BlobMissingMarker) => Level::Warn,
            EventType::TaskManager(TaskManagerEvent::TaskFailed) => Level::Warn,
            EventType::TaskManager(TaskManagerEvent::TaskStalled) => Level::Warn,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertEvent) => Level::Warn,
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::LogError) => Level::Warn,
            EventType::Telemetry(TelemetryEvent::WebhookError) => Level::Warn,
            EventType::Telemetry(TelemetryEvent::OtelExporterError) => Level::Warn,
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError) => Level::Warn,
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError) => Level::Warn,
            EventType::Telemetry(TelemetryEvent::JournalError) => Level::Warn,
            EventType::Telemetry(TelemetryEvent::EventsDropped) => Level::Warn,
            EventType::Tls(TlsEvent::NoCertificatesAvailable) => Level::Warn,
            EventType::Tls(TlsEvent::MultipleCertificatesAvailable) => Level::Warn,
            _ => Level::Debug,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            EventType::Acme(AcmeEvent::AuthStart) => "ACME authentication started",
            EventType::Acme(AcmeEvent::AuthPending) => "ACME authentication pending",
            EventType::Acme(AcmeEvent::AuthValid) => "ACME authentication valid",
            EventType::Acme(AcmeEvent::AuthCompleted) => "ACME authentication completed",
            EventType::Acme(AcmeEvent::AuthError) => "ACME authentication error",
            EventType::Acme(AcmeEvent::AuthTooManyAttempts) => {
                "Too many ACME authentication attempts"
            }
            EventType::Acme(AcmeEvent::ProcessCert) => "Processing ACME certificate",
            EventType::Acme(AcmeEvent::OrderStart) => "ACME order started",
            EventType::Acme(AcmeEvent::OrderProcessing) => "ACME order processing",
            EventType::Acme(AcmeEvent::OrderCompleted) => "ACME order completed",
            EventType::Acme(AcmeEvent::OrderReady) => "ACME order ready",
            EventType::Acme(AcmeEvent::OrderValid) => "ACME order valid",
            EventType::Acme(AcmeEvent::OrderInvalid) => "ACME order invalid",
            EventType::Acme(AcmeEvent::RenewBackoff) => "ACME renew backoff",
            EventType::Acme(AcmeEvent::ClientSuppliedSni) => "ACME client supplied SNI",
            EventType::Acme(AcmeEvent::ClientMissingSni) => "ACME client missing SNI",
            EventType::Acme(AcmeEvent::TlsAlpnReceived) => "ACME TLS ALPN received",
            EventType::Acme(AcmeEvent::TlsAlpnError) => "ACME TLS ALPN error",
            EventType::Acme(AcmeEvent::TokenNotFound) => "ACME token not found",
            EventType::Acme(AcmeEvent::Error) => "ACME error",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::LlmResponse) => "LLM response",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::ApiError) => "AI API error",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::Request) => "AI request completed",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamVerdict) => "AI spam verdict",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamSkipped) => "AI spam classifier skipped",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::BreakerOpen) => "AI model circuit breaker open",
            // SPDX-SnippetEnd
            EventType::Arc(ArcEvent::ChainInvalid) => "ARC chain invalid",
            EventType::Arc(ArcEvent::SignatureInvalid) => "ARC signature invalid",
            EventType::Arc(ArcEvent::HashMismatch) => "ARC body hash mismatch",
            EventType::Auth(AuthEvent::Success) => "Authentication successful",
            EventType::Auth(AuthEvent::Failed) => "Authentication failed",
            EventType::Auth(AuthEvent::TokenExpired) => "OAuth token expired",
            EventType::Auth(AuthEvent::MfaRequired) => "Missing MFA token for authentication",
            EventType::Auth(AuthEvent::TooManyAttempts) => "Too many authentication attempts",
            EventType::Auth(AuthEvent::ClientRegistration) => "OAuth Client registration",
            EventType::Auth(AuthEvent::Error) => "Authentication error",
            EventType::Auth(AuthEvent::Warning) => "Authentication warning",
            EventType::Auth(AuthEvent::CredentialExpired) => "Credential expired",
            EventType::Cache(CacheEvent::Miss) => "Cache miss",
            EventType::Cache(CacheEvent::Hit) => "Cache hit",
            EventType::Cache(CacheEvent::Stale) => "Cache is stale",
            EventType::Cache(CacheEvent::Update) => "Cache update",
            EventType::Cache(CacheEvent::EntryTooLarge) => "Cache entry too large",
            EventType::Cache(CacheEvent::Invalidate) => "Cache invalidation",
            EventType::Cache(CacheEvent::SwapHit) => "Cache snapshot loaded",
            EventType::Cache(CacheEvent::SwapMiss) => "Cache snapshot unavailable",
            EventType::Cache(CacheEvent::SwapWrite) => "Cache snapshot written",
            EventType::Cache(CacheEvent::SwapError) => "Cache swap tier error",
            EventType::Cache(CacheEvent::SwapMetrics) => "Cache swap metrics",
            EventType::Cache(CacheEvent::SwapFlush) => "Cache swap flushed",
            EventType::Calendar(CalendarEvent::RuleExpansionError) => {
                "Calendar rule expansion error"
            }
            EventType::Calendar(CalendarEvent::AlarmSent) => "Calendar alarm sent",
            EventType::Calendar(CalendarEvent::AlarmSkipped) => "Calendar alarm skipped",
            EventType::Calendar(CalendarEvent::AlarmRecipientOverride) => {
                "Calendar alarm recipient overriden"
            }
            EventType::Calendar(CalendarEvent::AlarmFailed) => "Calendar alarm could not be sent",
            EventType::Calendar(CalendarEvent::ItipMessageSent) => "Calendar iTIP message sent",
            EventType::Calendar(CalendarEvent::ItipMessageReceived) => {
                "Calendar iTIP message received"
            }
            EventType::Calendar(CalendarEvent::ItipMessageError) => "iTIP message error",
            EventType::Cluster(ClusterEvent::Startup) => "Clustering enabled",
            EventType::Cluster(ClusterEvent::SubscriberStart) => "PubSub subscriber started",
            EventType::Cluster(ClusterEvent::SubscriberStop) => "PubSub subscriber stopped",
            EventType::Cluster(ClusterEvent::SubscriberError) => "PubSub subscriber error",
            EventType::Cluster(ClusterEvent::SubscriberDisconnected) => {
                "PubSub subscriber disconnected"
            }
            EventType::Cluster(ClusterEvent::PublisherStart) => "PubSub publisher started",
            EventType::Cluster(ClusterEvent::PublisherStop) => "PubSub publisher stopped",
            EventType::Cluster(ClusterEvent::PublisherError) => "PubSub publisher error",
            EventType::Cluster(ClusterEvent::MessageReceived) => "PubSub message received",
            EventType::Cluster(ClusterEvent::MessageSkipped) => "PubSub message skipped",
            EventType::Cluster(ClusterEvent::MessageInvalid) => "Invalid PubSub message",
            EventType::Cluster(ClusterEvent::NodeIdRenewed) => "Node ID renewed",
            EventType::Dane(DaneEvent::AuthenticationSuccess) => "DANE authentication successful",
            EventType::Dane(DaneEvent::AuthenticationFailure) => "DANE authentication failed",
            EventType::Dane(DaneEvent::NoCertificatesFound) => "No certificates found for DANE",
            EventType::Dane(DaneEvent::CertificateParseError) => {
                "Error parsing certificate for DANE"
            }
            EventType::Dane(DaneEvent::TlsaRecordMatch) => "TLSA record match found",
            EventType::Dane(DaneEvent::TlsaRecordFetch) => "Fetching TLSA record",
            EventType::Dane(DaneEvent::TlsaRecordFetchError) => "Error fetching TLSA record",
            EventType::Dane(DaneEvent::TlsaRecordNotFound) => "TLSA record not found",
            EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned) => {
                "TLSA record not DNSSEC signed"
            }
            EventType::Dane(DaneEvent::TlsaRecordInvalid) => "Invalid TLSA record",
            EventType::Dane(DaneEvent::BogusDnssecRecord) => "Bogus DNSSEC record",
            EventType::Delivery(DeliveryEvent::AttemptStart) => "Delivery attempt started",
            EventType::Delivery(DeliveryEvent::AttemptEnd) => "Delivery attempt ended",
            EventType::Delivery(DeliveryEvent::Completed) => "Delivery completed",
            EventType::Delivery(DeliveryEvent::Failed) => "Delivery failed",
            EventType::Delivery(DeliveryEvent::DomainDeliveryStart) => {
                "New delivery attempt for domain"
            }
            EventType::Delivery(DeliveryEvent::MxLookup) => "MX record lookup",
            EventType::Delivery(DeliveryEvent::MxLookupFailed) => "MX record lookup failed",
            EventType::Delivery(DeliveryEvent::IpLookup) => "IP address lookup",
            EventType::Delivery(DeliveryEvent::IpLookupFailed) => "IP address lookup failed",
            EventType::Delivery(DeliveryEvent::NullMx) => "Null MX record found",
            EventType::Delivery(DeliveryEvent::Connect) => "Connecting to remote server",
            EventType::Delivery(DeliveryEvent::ConnectError) => "Connection error",
            EventType::Delivery(DeliveryEvent::MissingOutboundHostname) => {
                "Missing outbound hostname in configuration"
            }
            EventType::Delivery(DeliveryEvent::GreetingFailed) => "SMTP greeting failed",
            EventType::Delivery(DeliveryEvent::Ehlo) => "SMTP EHLO command",
            EventType::Delivery(DeliveryEvent::EhloRejected) => "SMTP EHLO rejected",
            EventType::Delivery(DeliveryEvent::Auth) => "SMTP authentication",
            EventType::Delivery(DeliveryEvent::AuthFailed) => "SMTP authentication failed",
            EventType::Delivery(DeliveryEvent::MailFrom) => "SMTP MAIL FROM command",
            EventType::Delivery(DeliveryEvent::MailFromRejected) => "SMTP MAIL FROM rejected",
            EventType::Delivery(DeliveryEvent::Delivered) => "Message delivered",
            EventType::Delivery(DeliveryEvent::RcptTo) => "SMTP RCPT TO command",
            EventType::Delivery(DeliveryEvent::RcptToRejected) => "SMTP RCPT TO rejected",
            EventType::Delivery(DeliveryEvent::RcptToFailed) => "SMTP RCPT TO failed",
            EventType::Delivery(DeliveryEvent::MessageRejected) => {
                "Message rejected by remote server"
            }
            EventType::Delivery(DeliveryEvent::StartTls) => "SMTP STARTTLS command",
            EventType::Delivery(DeliveryEvent::StartTlsUnavailable) => "STARTTLS unavailable",
            EventType::Delivery(DeliveryEvent::StartTlsError) => "STARTTLS error",
            EventType::Delivery(DeliveryEvent::StartTlsDisabled) => "STARTTLS disabled",
            EventType::Delivery(DeliveryEvent::ImplicitTlsError) => "Implicit TLS error",
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded) => {
                "Concurrency limit exceeded"
            }
            EventType::Delivery(DeliveryEvent::RateLimitExceeded) => "Rate limit exceeded",
            EventType::Delivery(DeliveryEvent::DoubleBounce) => {
                "Discarding message after double bounce"
            }
            EventType::Delivery(DeliveryEvent::DsnSuccess) => "DSN success notification",
            EventType::Delivery(DeliveryEvent::DsnTempFail) => "DSN temporary failure notification",
            EventType::Delivery(DeliveryEvent::DsnPermFail) => "DSN permanent failure notification",
            EventType::Delivery(DeliveryEvent::RawInput) => "Raw SMTP input received",
            EventType::Delivery(DeliveryEvent::RawOutput) => "Raw SMTP output sent",
            EventType::Dkim(DkimEvent::Pass) => "DKIM verification passed",
            EventType::Dkim(DkimEvent::Neutral) => "DKIM verification neutral",
            EventType::Dkim(DkimEvent::Fail) => "DKIM verification failed",
            EventType::Dkim(DkimEvent::PermError) => "DKIM permanent error",
            EventType::Dkim(DkimEvent::TempError) => "DKIM temporary error",
            EventType::Dkim(DkimEvent::None) => "No DKIM signature",
            EventType::Dkim(DkimEvent::SignatureInvalid) => "DKIM signature invalid",
            EventType::Dkim(DkimEvent::PublicKeyError) => "DKIM public key error",
            EventType::Dkim(DkimEvent::VerificationFailed) => "DKIM signature verification failed",
            EventType::Dkim(DkimEvent::HashMismatch) => "DKIM body hash mismatch",
            EventType::Dkim(DkimEvent::SignerNotFound) => "DKIM signer not found",
            EventType::Dkim(DkimEvent::BuildError) => "DKIM build error",
            EventType::Dkim(DkimEvent::SignatureCreated) => "DKIM signature created",
            EventType::Dkim(DkimEvent::SignaturePublished) => "DKIM signature published",
            EventType::Dkim(DkimEvent::SignatureRetiring) => "DKIM signature retiring",
            EventType::Dkim(DkimEvent::SignatureRetired) => "DKIM signature retired",
            EventType::Dkim(DkimEvent::SignatureDeleted) => "DKIM signature deleted",
            EventType::Dkim2(Dkim2Event::InstanceInvalid) => "DKIM2 Message-Instance invalid",
            EventType::Dkim2(Dkim2Event::SignatureInvalid) => "DKIM2 signature invalid",
            EventType::Dkim2(Dkim2Event::ChainInvalid) => "DKIM2 chain invalid",
            EventType::Dkim2(Dkim2Event::TimestampInvalid) => "DKIM2 timestamp invalid",
            EventType::Dkim2(Dkim2Event::EnvelopeMismatch) => "DKIM2 envelope mismatch",
            EventType::Dkim2(Dkim2Event::CustodyBroken) => "DKIM2 chain of custody broken",
            EventType::Dkim2(Dkim2Event::PublicKeyError) => "DKIM2 public key error",
            EventType::Dkim2(Dkim2Event::VerificationFailed) => {
                "DKIM2 signature verification failed"
            }
            EventType::Dkim2(Dkim2Event::HashMismatch) => "DKIM2 hash mismatch",
            EventType::Dkim2(Dkim2Event::RecipeError) => "DKIM2 recipe error",
            EventType::Dkim2(Dkim2Event::SigningFailed) => "DKIM2 signing failed",
            EventType::Dmarc(DmarcEvent::Pass) => "DMARC check passed",
            EventType::Dmarc(DmarcEvent::Fail) => "DMARC check failed",
            EventType::Dmarc(DmarcEvent::PermError) => "DMARC permanent error",
            EventType::Dmarc(DmarcEvent::TempError) => "DMARC temporary error",
            EventType::Dmarc(DmarcEvent::None) => "No DMARC record",
            EventType::Dns(DnsEvent::RecordCreated) => "DNS record created",
            EventType::Dns(DnsEvent::RecordCreationFailed) => "DNS record creation failed",
            EventType::Dns(DnsEvent::RecordDeletionFailed) => "DNS record deletion failed",
            EventType::Dns(DnsEvent::RecordNotPropagated) => "DNS record not propagated",
            EventType::Dns(DnsEvent::RecordLookupFailed) => "DNS record lookup failed",
            EventType::Dns(DnsEvent::RecordPropagated) => "DNS record propagated",
            EventType::Dns(DnsEvent::RecordPropagationTimeout) => "DNS record propagation timeout",
            EventType::Eval(EvalEvent::Result) => "Expression evaluation result",
            EventType::Eval(EvalEvent::Error) => "Expression evaluation error",
            EventType::Eval(EvalEvent::DirectoryNotFound) => {
                "Directory not found while evaluating expression"
            }
            EventType::Eval(EvalEvent::StoreNotFound) => {
                "Store not found while evaluating expression"
            }
            EventType::Http(HttpEvent::ConnectionStart) => "HTTP connection started",
            EventType::Http(HttpEvent::ConnectionEnd) => "HTTP connection ended",
            EventType::Http(HttpEvent::Error) => "HTTP error occurred",
            EventType::Http(HttpEvent::RequestUrl) => "HTTP request URL",
            EventType::Http(HttpEvent::RequestBody) => "HTTP request body",
            EventType::Http(HttpEvent::ResponseBody) => "HTTP response body",
            EventType::Http(HttpEvent::XForwardedMissing) => "X-Forwarded-For header is missing",
            EventType::Http(HttpEvent::XForwardedInvalid) => "Invalid forwarding header",
            EventType::Imap(ImapEvent::ConnectionStart) => "IMAP connection started",
            EventType::Imap(ImapEvent::ConnectionEnd) => "IMAP connection ended",
            EventType::Imap(ImapEvent::GetAcl) => "IMAP GET ACL command",
            EventType::Imap(ImapEvent::SetAcl) => "IMAP SET ACL command",
            EventType::Imap(ImapEvent::MyRights) => "IMAP MYRIGHTS command",
            EventType::Imap(ImapEvent::ListRights) => "IMAP LISTRIGHTS command",
            EventType::Imap(ImapEvent::Append) => "IMAP APPEND command",
            EventType::Imap(ImapEvent::Capabilities) => "IMAP CAPABILITIES command",
            EventType::Imap(ImapEvent::Id) => "IMAP ID command",
            EventType::Imap(ImapEvent::Close) => "IMAP CLOSE command",
            EventType::Imap(ImapEvent::Copy) => "IMAP COPY command",
            EventType::Imap(ImapEvent::Move) => "IMAP MOVE command",
            EventType::Imap(ImapEvent::CreateMailbox) => "IMAP CREATE mailbox command",
            EventType::Imap(ImapEvent::DeleteMailbox) => "IMAP DELETE mailbox command",
            EventType::Imap(ImapEvent::RenameMailbox) => "IMAP RENAME mailbox command",
            EventType::Imap(ImapEvent::Enable) => "IMAP ENABLE command",
            EventType::Imap(ImapEvent::Expunge) => "IMAP EXPUNGE command",
            EventType::Imap(ImapEvent::Fetch) => "IMAP FETCH command",
            EventType::Imap(ImapEvent::IdleStart) => "IMAP IDLE start",
            EventType::Imap(ImapEvent::IdleStop) => "IMAP IDLE stop",
            EventType::Imap(ImapEvent::List) => "IMAP LIST command",
            EventType::Imap(ImapEvent::Lsub) => "IMAP LSUB command",
            EventType::Imap(ImapEvent::Logout) => "IMAP LOGOUT command",
            EventType::Imap(ImapEvent::Namespace) => "IMAP NAMESPACE command",
            EventType::Imap(ImapEvent::Noop) => "IMAP NOOP command",
            EventType::Imap(ImapEvent::Search) => "IMAP SEARCH command",
            EventType::Imap(ImapEvent::Sort) => "IMAP SORT command",
            EventType::Imap(ImapEvent::Select) => "IMAP SELECT command",
            EventType::Imap(ImapEvent::Status) => "IMAP STATUS command",
            EventType::Imap(ImapEvent::Store) => "IMAP STORE command",
            EventType::Imap(ImapEvent::Subscribe) => "IMAP SUBSCRIBE command",
            EventType::Imap(ImapEvent::Unsubscribe) => "IMAP UNSUBSCRIBE command",
            EventType::Imap(ImapEvent::Thread) => "IMAP THREAD command",
            EventType::Imap(ImapEvent::UidBatches) => "IMAP UIDBATCHES command",
            EventType::Imap(ImapEvent::GetQuota) => "IMAP GETQUOTA command",
            EventType::Imap(ImapEvent::GetMetadata) => "IMAP GETMETADATA command",
            EventType::Imap(ImapEvent::SetMetadata) => "IMAP SETMETADATA command",
            EventType::Imap(ImapEvent::Error) => "IMAP error occurred",
            EventType::Imap(ImapEvent::RawInput) => "Raw IMAP input received",
            EventType::Imap(ImapEvent::RawOutput) => "Raw IMAP output sent",
            EventType::IncomingReport(IncomingReportEvent::DmarcReport) => "DMARC report received",
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings) => {
                "DMARC report received with warnings"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsReport) => "TLS report received",
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings) => {
                "TLS report received with warnings"
            }
            EventType::IncomingReport(IncomingReportEvent::AbuseReport) => "Abuse report received",
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport) => {
                "Authentication failure report received"
            }
            EventType::IncomingReport(IncomingReportEvent::FraudReport) => "Fraud report received",
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport) => {
                "Not spam report received"
            }
            EventType::IncomingReport(IncomingReportEvent::VirusReport) => "Virus report received",
            EventType::IncomingReport(IncomingReportEvent::OtherReport) => {
                "Other type of report received"
            }
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed) => {
                "Failed to parse incoming report message"
            }
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed) => {
                "Failed to parse DMARC report"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed) => {
                "Failed to parse TLS RPC report"
            }
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed) => {
                "Failed to parse ARF report"
            }
            EventType::IncomingReport(IncomingReportEvent::DecompressError) => {
                "Error decompressing report"
            }
            EventType::Iprev(IprevEvent::Pass) => "IPREV check passed",
            EventType::Iprev(IprevEvent::Fail) => "IPREV check failed",
            EventType::Iprev(IprevEvent::PermError) => "IPREV permanent error",
            EventType::Iprev(IprevEvent::TempError) => "IPREV temporary error",
            EventType::Iprev(IprevEvent::None) => "No IPREV record",
            EventType::Jmap(JmapEvent::MethodCall) => "JMAP method call",
            EventType::Jmap(JmapEvent::InvalidArguments) => "Invalid JMAP arguments",
            EventType::Jmap(JmapEvent::RequestTooLarge) => "JMAP request too large",
            EventType::Jmap(JmapEvent::StateMismatch) => "JMAP state mismatch",
            EventType::Jmap(JmapEvent::AnchorNotFound) => "JMAP anchor not found",
            EventType::Jmap(JmapEvent::UnsupportedFilter) => "Unsupported JMAP filter",
            EventType::Jmap(JmapEvent::UnsupportedSort) => "Unsupported JMAP sort",
            EventType::Jmap(JmapEvent::UnknownMethod) => "Unknown JMAP method",
            EventType::Jmap(JmapEvent::InvalidResultReference) => "Invalid JMAP result reference",
            EventType::Jmap(JmapEvent::Forbidden) => "JMAP operation forbidden",
            EventType::Jmap(JmapEvent::AccountNotFound) => "JMAP account not found",
            EventType::Jmap(JmapEvent::AccountNotSupportedByMethod) => {
                "JMAP account not supported by method"
            }
            EventType::Jmap(JmapEvent::AccountReadOnly) => "JMAP account is read-only",
            EventType::Jmap(JmapEvent::FromAccountNotFound) => "JMAP source account not found",
            EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod) => {
                "JMAP source account not supported by method"
            }
            EventType::Jmap(JmapEvent::NotFound) => "JMAP resource not found",
            EventType::Jmap(JmapEvent::CannotCalculateChanges) => "Cannot calculate JMAP changes",
            EventType::Jmap(JmapEvent::UnknownDataType) => "Unknown JMAP data type",
            EventType::Jmap(JmapEvent::UnknownCapability) => "Unknown JMAP capability",
            EventType::Jmap(JmapEvent::NotJson) => "JMAP request is not JSON",
            EventType::Jmap(JmapEvent::NotRequest) => "JMAP input is not a request",
            EventType::Jmap(JmapEvent::WebsocketStart) => "JMAP WebSocket connection started",
            EventType::Jmap(JmapEvent::WebsocketStop) => "JMAP WebSocket connection stopped",
            EventType::Jmap(JmapEvent::WebsocketError) => "JMAP WebSocket error",
            EventType::Jmap(JmapEvent::ExpandDurationTooLarge) => {
                "JMAP expansion duration too large"
            }
            EventType::Jmap(JmapEvent::CannotCalculateOccurrences) => {
                "Cannot calculate JMAP occurrences"
            }
            EventType::Jmap(JmapEvent::TooLarge) => "JMAP time span too large",
            EventType::Jmap(JmapEvent::RateLimit) => "JMAP rate limit exceeded",
            EventType::Jmap(JmapEvent::ObjectNotFound) => "JMAP object not found",
            EventType::Limit(LimitEvent::SizeRequest) => "Request size limit reached",
            EventType::Limit(LimitEvent::SizeUpload) => "Upload size limit reached",
            EventType::Limit(LimitEvent::CallsIn) => "Incoming calls limit reached",
            EventType::Limit(LimitEvent::ConcurrentRequest) => "Concurrent request limit reached",
            EventType::Limit(LimitEvent::ConcurrentUpload) => "Concurrent upload limit reached",
            EventType::Limit(LimitEvent::ConcurrentConnection) => {
                "Concurrent connection limit reached"
            }
            EventType::Limit(LimitEvent::Quota) => "Quota limit reached",
            EventType::Limit(LimitEvent::BlobQuota) => "Blob quota limit reached",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => "Tenant quota limit reached",
            // SPDX-SnippetEnd
            EventType::Limit(LimitEvent::TooManyRequests) => "Too many requests",
            EventType::Limit(LimitEvent::MemoryBudget) => "Memory budget exceeded",
            EventType::MailAuth(MailAuthEvent::ParseError) => "Mail authentication parse error",
            EventType::MailAuth(MailAuthEvent::MissingParameters) => {
                "Missing mail authentication parameters"
            }
            EventType::MailAuth(MailAuthEvent::NoHeadersFound) => "No headers found in message",
            EventType::MailAuth(MailAuthEvent::Crypto) => "Crypto error during mail authentication",
            EventType::MailAuth(MailAuthEvent::Io) => "I/O error during mail authentication",
            EventType::MailAuth(MailAuthEvent::Base64) => "Base64 error during mail authentication",
            EventType::MailAuth(MailAuthEvent::DnsError) => "DNS error",
            EventType::MailAuth(MailAuthEvent::DnsRecordNotFound) => "DNS record not found",
            EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType) => "Invalid DNS record type",
            EventType::MailAuth(MailAuthEvent::PolicyNotAligned) => "Policy not aligned",
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => {
                "ManageSieve connection started"
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => {
                "ManageSieve connection ended"
            }
            EventType::ManageSieve(ManageSieveEvent::CreateScript) => {
                "ManageSieve CREATE script command"
            }
            EventType::ManageSieve(ManageSieveEvent::UpdateScript) => {
                "ManageSieve UPDATE script command"
            }
            EventType::ManageSieve(ManageSieveEvent::GetScript) => "ManageSieve GET script command",
            EventType::ManageSieve(ManageSieveEvent::DeleteScript) => {
                "ManageSieve DELETE script command"
            }
            EventType::ManageSieve(ManageSieveEvent::RenameScript) => {
                "ManageSieve RENAME script command"
            }
            EventType::ManageSieve(ManageSieveEvent::CheckScript) => {
                "ManageSieve CHECK script command"
            }
            EventType::ManageSieve(ManageSieveEvent::HaveSpace) => "ManageSieve HAVESPACE command",
            EventType::ManageSieve(ManageSieveEvent::ListScripts) => {
                "ManageSieve LIST scripts command"
            }
            EventType::ManageSieve(ManageSieveEvent::SetActive) => "ManageSieve SET ACTIVE command",
            EventType::ManageSieve(ManageSieveEvent::Capabilities) => {
                "ManageSieve CAPABILITIES command"
            }
            EventType::ManageSieve(ManageSieveEvent::StartTls) => "ManageSieve STARTTLS command",
            EventType::ManageSieve(ManageSieveEvent::Unauthenticate) => {
                "ManageSieve UNAUTHENTICATE command"
            }
            EventType::ManageSieve(ManageSieveEvent::Logout) => "ManageSieve LOGOUT command",
            EventType::ManageSieve(ManageSieveEvent::Noop) => "ManageSieve NOOP command",
            EventType::ManageSieve(ManageSieveEvent::Error) => "ManageSieve error occurred",
            EventType::ManageSieve(ManageSieveEvent::RawInput) => "Raw ManageSieve input received",
            EventType::ManageSieve(ManageSieveEvent::RawOutput) => "Raw ManageSieve output sent",
            EventType::MessageIngest(MessageIngestEvent::Ham) => "Message ingested",
            EventType::MessageIngest(MessageIngestEvent::Spam) => "Possible spam message ingested",
            EventType::MessageIngest(MessageIngestEvent::ImapAppend) => "Message appended via IMAP",
            EventType::MessageIngest(MessageIngestEvent::JmapAppend) => "Message appended via JMAP",
            EventType::MessageIngest(MessageIngestEvent::Duplicate) => "Skipping duplicate message",
            EventType::MessageIngest(MessageIngestEvent::Error) => "Message ingestion error",
            EventType::Milter(MilterEvent::Read) => "Reading from Milter",
            EventType::Milter(MilterEvent::Write) => "Writing to Milter",
            EventType::Milter(MilterEvent::ActionAccept) => "Milter action: Accept",
            EventType::Milter(MilterEvent::ActionDiscard) => "Milter action: Discard",
            EventType::Milter(MilterEvent::ActionReject) => "Milter action: Reject",
            EventType::Milter(MilterEvent::ActionTempFail) => "Milter action: Temporary failure",
            EventType::Milter(MilterEvent::ActionReplyCode) => "Milter action: Reply code",
            EventType::Milter(MilterEvent::ActionConnectionFailure) => {
                "Milter action: Connection failure"
            }
            EventType::Milter(MilterEvent::ActionShutdown) => "Milter action: Shutdown",
            EventType::Milter(MilterEvent::IoError) => "Milter I/O error",
            EventType::Milter(MilterEvent::FrameTooLarge) => "Milter frame too large",
            EventType::Milter(MilterEvent::FrameInvalid) => "Invalid Milter frame",
            EventType::Milter(MilterEvent::UnexpectedResponse) => "Unexpected Milter response",
            EventType::Milter(MilterEvent::Timeout) => "Milter timeout",
            EventType::Milter(MilterEvent::TlsInvalidName) => "Invalid TLS name for Milter",
            EventType::Milter(MilterEvent::Disconnected) => "Milter disconnected",
            EventType::Milter(MilterEvent::ParseError) => "Milter parse error",
            EventType::MtaHook(MtaHookEvent::ActionAccept) => "MTA hook action: Accept",
            EventType::MtaHook(MtaHookEvent::ActionDiscard) => "MTA hook action: Discard",
            EventType::MtaHook(MtaHookEvent::ActionReject) => "MTA hook action: Reject",
            EventType::MtaHook(MtaHookEvent::ActionQuarantine) => "MTA hook action: Quarantine",
            EventType::MtaHook(MtaHookEvent::Error) => "MTA hook error",
            EventType::MtaSts(MtaStsEvent::Authorized) => "Host authorized by MTA-STS policy",
            EventType::MtaSts(MtaStsEvent::NotAuthorized) => {
                "Host not authorized by MTA-STS policy"
            }
            EventType::MtaSts(MtaStsEvent::PolicyFetch) => "Fetched MTA-STS policy",
            EventType::MtaSts(MtaStsEvent::PolicyNotFound) => "MTA-STS policy not found",
            EventType::MtaSts(MtaStsEvent::PolicyFetchError) => "Error fetching MTA-STS policy",
            EventType::MtaSts(MtaStsEvent::InvalidPolicy) => "Invalid MTA-STS policy",
            EventType::Network(NetworkEvent::ListenStart) => "Network listener started",
            EventType::Network(NetworkEvent::ListenStop) => "Network listener stopped",
            EventType::Network(NetworkEvent::ListenError) => "Network listener error",
            EventType::Network(NetworkEvent::BindError) => "Network bind error",
            EventType::Network(NetworkEvent::ReadError) => "Network read error",
            EventType::Network(NetworkEvent::WriteError) => "Network write error",
            EventType::Network(NetworkEvent::FlushError) => "Network flush error",
            EventType::Network(NetworkEvent::AcceptError) => "Network accept error",
            EventType::Network(NetworkEvent::SplitError) => "Network split error",
            EventType::Network(NetworkEvent::Timeout) => "Network timeout",
            EventType::Network(NetworkEvent::Closed) => "Network connection closed",
            EventType::Network(NetworkEvent::ProxyError) => "Proxy protocol error",
            EventType::Network(NetworkEvent::SetOptError) => "Network set option error",
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport) => "SPF report sent",
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited) => {
                "SPF report rate limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport) => "DKIM report sent",
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited) => {
                "DKIM report rate limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport) => "DMARC report sent",
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited) => {
                "DMARC report rate limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport) => {
                "DMARC aggregate is being prepared"
            }
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate) => {
                "TLS aggregate report is being prepared"
            }
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission) => {
                "Report submitted via HTTP"
            }
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress) => {
                "Unauthorized reporting address"
            }
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError) => {
                "Error validating reporting address"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NotFound) => "Report not found",
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError) => {
                "Error submitting report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound) => {
                "No recipients found for report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::Locked) => {
                "Report is locked by another process"
            }
            EventType::OutgoingReport(OutgoingReportEvent::MaxSizeExceeded) => {
                "Report size exceeds maximum"
            }
            EventType::Pop3(Pop3Event::ConnectionStart) => "POP3 connection started",
            EventType::Pop3(Pop3Event::ConnectionEnd) => "POP3 connection ended",
            EventType::Pop3(Pop3Event::Delete) => "POP3 DELETE command",
            EventType::Pop3(Pop3Event::Reset) => "POP3 RESET command",
            EventType::Pop3(Pop3Event::Quit) => "POP3 QUIT command",
            EventType::Pop3(Pop3Event::Fetch) => "POP3 FETCH command",
            EventType::Pop3(Pop3Event::List) => "POP3 LIST command",
            EventType::Pop3(Pop3Event::ListMessage) => "POP3 LIST specific message command",
            EventType::Pop3(Pop3Event::Uidl) => "POP3 UIDL command",
            EventType::Pop3(Pop3Event::UidlMessage) => "POP3 UIDL specific message command",
            EventType::Pop3(Pop3Event::Stat) => "POP3 STAT command",
            EventType::Pop3(Pop3Event::Noop) => "POP3 NOOP command",
            EventType::Pop3(Pop3Event::Capabilities) => "POP3 CAPABILITIES command",
            EventType::Pop3(Pop3Event::StartTls) => "POP3 STARTTLS command",
            EventType::Pop3(Pop3Event::Utf8) => "POP3 UTF8 command",
            EventType::Pop3(Pop3Event::Error) => "POP3 error occurred",
            EventType::Pop3(Pop3Event::RawInput) => "Raw POP3 input received",
            EventType::Pop3(Pop3Event::RawOutput) => "Raw POP3 output sent",
            EventType::PushSubscription(PushSubscriptionEvent::Success) => {
                "Push subscription successful"
            }
            EventType::PushSubscription(PushSubscriptionEvent::Error) => "Push subscription error",
            EventType::PushSubscription(PushSubscriptionEvent::NotFound) => {
                "Push subscription not found"
            }
            EventType::Queue(QueueEvent::Started) => "MTA queue started",
            EventType::Queue(QueueEvent::MessageQueued) => "Queued message for delivery",
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued) => {
                "Queued message submission for delivery"
            }
            EventType::Queue(QueueEvent::ReportQueued) => "Queued report for delivery",
            EventType::Queue(QueueEvent::DsnQueued) => "Queued DSN for delivery",
            EventType::Queue(QueueEvent::AutogeneratedQueued) => {
                "Queued autogenerated message for delivery"
            }
            EventType::Queue(QueueEvent::Rescheduled) => "Message rescheduled for delivery",
            EventType::Queue(QueueEvent::Locked) => "Queue event is locked by another process",
            EventType::Queue(QueueEvent::BlobNotFound) => "Message blob not found",
            EventType::Queue(QueueEvent::RateLimitExceeded) => "Rate limit exceeded",
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded) => "Concurrency limit exceeded",
            EventType::Queue(QueueEvent::QuotaExceeded) => "Quota exceeded",
            EventType::Queue(QueueEvent::BackPressure) => "Queue backpressure detected",
            EventType::Registry(RegistryEvent::LocalReadError) => "Local registry read error",
            EventType::Registry(RegistryEvent::LocalWriteError) => "Local registry write error",
            EventType::Registry(RegistryEvent::LocalParseError) => "Local registry parse error",
            EventType::Registry(RegistryEvent::ReadError) => "Registry read error",
            EventType::Registry(RegistryEvent::WriteError) => "Registry write error",
            EventType::Registry(RegistryEvent::DeserializationError) => {
                "Registry deserialization error"
            }
            EventType::Registry(RegistryEvent::BuildError) => "Configuration build error",
            EventType::Registry(RegistryEvent::BuildWarning) => "Configuration build warning",
            EventType::Registry(RegistryEvent::NotSupported) => {
                "Operation not supported by local registry"
            }
            EventType::Registry(RegistryEvent::ValidationError) => "Object validation error",
            EventType::Resource(ResourceEvent::NotFound) => "Resource not found",
            EventType::Resource(ResourceEvent::BadParameters) => "Bad resource parameters",
            EventType::Resource(ResourceEvent::Error) => "Resource error",
            EventType::Resource(ResourceEvent::DownloadExternal) => "Downloading external resource",
            EventType::Resource(ResourceEvent::ApplicationUpdated) => {
                "Application resource updated"
            }
            EventType::Resource(ResourceEvent::ApplicationUnpacked) => {
                "Application resource unpacked"
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Request) => "SCIM request handled",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Forbidden) => "SCIM operation forbidden",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Conflict) => "SCIM resource conflict",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Error) => "SCIM request failed",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceCreated) => "SCIM resource created",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceUpdated) => "SCIM resource updated",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceDeleted) => "SCIM resource deleted",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Query) => "SCIM query executed",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkProcessed) => "SCIM bulk request processed",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkAborted) => "SCIM bulk request aborted",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::RollbackFailed) => "SCIM rollback failed",
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::AttributeIgnored) => "SCIM attribute ignored",
            // SPDX-SnippetEnd
            EventType::SearchIndex(SearchIndexEvent::ManagerStarted) => {
                "Search index manager started"
            }
            EventType::SearchIndex(SearchIndexEvent::PartitionsAcquired) => {
                "Index partitions acquired from queue"
            }
            EventType::SearchIndex(SearchIndexEvent::PartitionLocked) => {
                "Index partition is locked by another process"
            }
            EventType::SearchIndex(SearchIndexEvent::PartitionRetry) => {
                "Index partition will be retried"
            }
            EventType::SearchIndex(SearchIndexEvent::BatchIndexed) => "Search index batch written",
            EventType::SearchIndex(SearchIndexEvent::DocumentIgnored) => {
                "Document ignored by the indexer"
            }
            EventType::SearchIndex(SearchIndexEvent::DocumentTruncated) => {
                "Search document truncated"
            }
            EventType::SearchIndex(SearchIndexEvent::MetadataNotFound) => {
                "Metadata not found for indexed document"
            }
            EventType::Security(SecurityEvent::AuthenticationBan) => {
                "Banned due to authentication errors"
            }
            EventType::Security(SecurityEvent::AbuseBan) => "Banned due to abuse",
            EventType::Security(SecurityEvent::ScanBan) => "Banned due to scan",
            EventType::Security(SecurityEvent::LoiterBan) => "Banned due to loitering",
            EventType::Security(SecurityEvent::IpBlocked) => "Blocked IP address",
            EventType::Security(SecurityEvent::IpBlockExpired) => "IP block expired",
            EventType::Security(SecurityEvent::IpAllowExpired) => "IP allow expired",
            EventType::Security(SecurityEvent::IpUnauthorized) => "Unauthorized IP address",
            EventType::Security(SecurityEvent::Unauthorized) => "Unauthorized access",
            EventType::Server(ServerEvent::Startup) => "Starting Stalwart Server",
            EventType::Server(ServerEvent::Shutdown) => "Shutting down Stalwart Server",
            EventType::Server(ServerEvent::StartupError) => "Server startup error",
            EventType::Server(ServerEvent::ThreadError) => "Server thread error",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Server(ServerEvent::Licensing) => "Server licensing event",
            // SPDX-SnippetEnd
            EventType::Server(ServerEvent::RecoveryMode) => "Server started in recovery mode",
            EventType::Server(ServerEvent::BootstrapMode) => "Server started in bootstrap mode",
            EventType::Sieve(SieveEvent::ActionAccept) => "Sieve action: Accept",
            EventType::Sieve(SieveEvent::ActionAcceptReplace) => "Sieve action: Accept and replace",
            EventType::Sieve(SieveEvent::ActionDiscard) => "Sieve action: Discard",
            EventType::Sieve(SieveEvent::ActionReject) => "Sieve action: Reject",
            EventType::Sieve(SieveEvent::SendMessage) => "Sieve sending message",
            EventType::Sieve(SieveEvent::MessageTooLarge) => "Sieve message too large",
            EventType::Sieve(SieveEvent::ScriptNotFound) => "Sieve script not found",
            EventType::Sieve(SieveEvent::ListNotFound) => "Sieve list not found",
            EventType::Sieve(SieveEvent::RuntimeError) => "Sieve runtime error",
            EventType::Sieve(SieveEvent::UnexpectedError) => "Unexpected Sieve error",
            EventType::Sieve(SieveEvent::NotSupported) => "Sieve action not supported",
            EventType::Sieve(SieveEvent::QuotaExceeded) => "Sieve quota exceeded",
            EventType::Smtp(SmtpEvent::ConnectionStart) => "SMTP connection started",
            EventType::Smtp(SmtpEvent::ConnectionEnd) => "SMTP connection ended",
            EventType::Smtp(SmtpEvent::Error) => "SMTP error occurred",
            EventType::Smtp(SmtpEvent::IdNotFound) => "Strategy not found",
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => "Concurrency limit exceeded",
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => "Transfer limit exceeded",
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => "Rate limit exceeded",
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => "Time limit exceeded",
            EventType::Smtp(SmtpEvent::MessageParseFailed) => "Message parsing failed",
            EventType::Smtp(SmtpEvent::MessageTooLarge) => "Message too large",
            EventType::Smtp(SmtpEvent::LoopDetected) => "Mail loop detected",
            EventType::Smtp(SmtpEvent::MultipleFromDomains) => "Multiple From domains",
            EventType::Smtp(SmtpEvent::DkimPass) => "DKIM verification passed",
            EventType::Smtp(SmtpEvent::DkimFail) => "DKIM verification failed",
            EventType::Smtp(SmtpEvent::Dkim2Pass) => "DKIM2 verification passed",
            EventType::Smtp(SmtpEvent::Dkim2Fail) => "DKIM2 verification failed",
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected) => "DKIM2 DSN rejected",
            EventType::Smtp(SmtpEvent::ArcPass) => "ARC verification passed",
            EventType::Smtp(SmtpEvent::ArcFail) => "ARC verification failed",
            EventType::Smtp(SmtpEvent::SpfEhloPass) => "SPF EHLO check passed",
            EventType::Smtp(SmtpEvent::SpfEhloFail) => "SPF EHLO check failed",
            EventType::Smtp(SmtpEvent::SpfFromPass) => "SPF From check passed",
            EventType::Smtp(SmtpEvent::SpfFromFail) => "SPF From check failed",
            EventType::Smtp(SmtpEvent::DmarcPass) => "DMARC check passed",
            EventType::Smtp(SmtpEvent::DmarcFail) => "DMARC check failed",
            EventType::Smtp(SmtpEvent::IprevPass) => "IPREV check passed",
            EventType::Smtp(SmtpEvent::IprevFail) => "IPREV check failed",
            EventType::Smtp(SmtpEvent::TooManyMessages) => "Too many messages",
            EventType::Smtp(SmtpEvent::Ehlo) => "SMTP EHLO command",
            EventType::Smtp(SmtpEvent::InvalidEhlo) => "Invalid EHLO command",
            EventType::Smtp(SmtpEvent::DidNotSayEhlo) => "Client did not say EHLO",
            EventType::Smtp(SmtpEvent::EhloExpected) => "EHLO command expected",
            EventType::Smtp(SmtpEvent::LhloExpected) => "LHLO command expected",
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated) => {
                "MAIL FROM without authentication"
            }
            EventType::Smtp(SmtpEvent::MailFromUnauthorized) => "MAIL FROM unauthorized",
            EventType::Smtp(SmtpEvent::MailFromNotAllowed) => "MAIL FROM not allowed",
            EventType::Smtp(SmtpEvent::MailFromRewritten) => "MAIL FROM address rewritten",
            EventType::Smtp(SmtpEvent::MailFromMissing) => "MAIL FROM address missing",
            EventType::Smtp(SmtpEvent::MailFrom) => "SMTP MAIL FROM command",
            EventType::Smtp(SmtpEvent::MultipleMailFrom) => "Multiple MAIL FROM commands",
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => "Mailbox does not exist",
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => "Relay not allowed",
            EventType::Smtp(SmtpEvent::RcptTo) => "SMTP RCPT TO command",
            EventType::Smtp(SmtpEvent::RcptToDuplicate) => "Duplicate RCPT TO",
            EventType::Smtp(SmtpEvent::RcptToRewritten) => "RCPT TO address rewritten",
            EventType::Smtp(SmtpEvent::RcptToMissing) => "RCPT TO address missing",
            EventType::Smtp(SmtpEvent::RcptToGreylisted) => "RCPT TO greylisted",
            EventType::Smtp(SmtpEvent::TooManyRecipients) => "Too many recipients",
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => "Too many invalid recipients",
            EventType::Smtp(SmtpEvent::RawInput) => "Raw SMTP input received",
            EventType::Smtp(SmtpEvent::RawOutput) => "Raw SMTP output sent",
            EventType::Smtp(SmtpEvent::MissingLocalHostname) => "Missing local hostname",
            EventType::Smtp(SmtpEvent::Vrfy) => "SMTP VRFY command",
            EventType::Smtp(SmtpEvent::VrfyNotFound) => "VRFY address not found",
            EventType::Smtp(SmtpEvent::VrfyDisabled) => "VRFY command disabled",
            EventType::Smtp(SmtpEvent::Expn) => "SMTP EXPN command",
            EventType::Smtp(SmtpEvent::ExpnNotFound) => "EXPN address not found",
            EventType::Smtp(SmtpEvent::ExpnDisabled) => "EXPN command disabled",
            EventType::Smtp(SmtpEvent::RequireTlsDisabled) => "REQUIRETLS extension disabled",
            EventType::Smtp(SmtpEvent::DeliverByDisabled) => "DELIVERBY extension disabled",
            EventType::Smtp(SmtpEvent::DeliverByInvalid) => "Invalid DELIVERBY parameter",
            EventType::Smtp(SmtpEvent::FutureReleaseDisabled) => {
                "FUTURE RELEASE extension disabled"
            }
            EventType::Smtp(SmtpEvent::FutureReleaseInvalid) => "Invalid FUTURE RELEASE parameter",
            EventType::Smtp(SmtpEvent::MtPriorityDisabled) => "MT-PRIORITY extension disabled",
            EventType::Smtp(SmtpEvent::MtPriorityInvalid) => "Invalid MT-PRIORITY parameter",
            EventType::Smtp(SmtpEvent::DsnDisabled) => "DSN extension disabled",
            EventType::Smtp(SmtpEvent::AuthNotAllowed) => "Authentication not allowed",
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => "Auth mechanism not supported",
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong) => "Auth exchange too long",
            EventType::Smtp(SmtpEvent::AlreadyAuthenticated) => "Already authenticated",
            EventType::Smtp(SmtpEvent::Noop) => "SMTP NOOP command",
            EventType::Smtp(SmtpEvent::StartTls) => "SMTP STARTTLS command",
            EventType::Smtp(SmtpEvent::StartTlsUnavailable) => "STARTTLS unavailable",
            EventType::Smtp(SmtpEvent::StartTlsAlready) => "TLS already active",
            EventType::Smtp(SmtpEvent::Rset) => "SMTP RSET command",
            EventType::Smtp(SmtpEvent::Quit) => "SMTP QUIT command",
            EventType::Smtp(SmtpEvent::Help) => "SMTP HELP command",
            EventType::Smtp(SmtpEvent::CommandNotImplemented) => "Command not implemented",
            EventType::Smtp(SmtpEvent::InvalidCommand) => "Invalid command",
            EventType::Smtp(SmtpEvent::InvalidSenderAddress) => "Invalid sender address",
            EventType::Smtp(SmtpEvent::InvalidRecipientAddress) => "Invalid recipient address",
            EventType::Smtp(SmtpEvent::InvalidParameter) => "Invalid parameter",
            EventType::Smtp(SmtpEvent::UnsupportedParameter) => "Unsupported parameter",
            EventType::Smtp(SmtpEvent::SyntaxError) => "Syntax error",
            EventType::Smtp(SmtpEvent::RequestTooLarge) => "Request too large",
            EventType::Spam(SpamEvent::Pyzor) => "Pyzor success",
            EventType::Spam(SpamEvent::PyzorError) => "Pyzor error",
            EventType::Spam(SpamEvent::Dnsbl) => "DNSBL query",
            EventType::Spam(SpamEvent::DnsblError) => "Error querying DNSBL",
            EventType::Spam(SpamEvent::TrainStarted) => "Spam classifier training started",
            EventType::Spam(SpamEvent::TrainCompleted) => "Spam classifier training completed",
            EventType::Spam(SpamEvent::TrainSampleAdded) => "New training sample added",
            EventType::Spam(SpamEvent::TrainSampleNotFound) => "Training sample not found",
            EventType::Spam(SpamEvent::Classify) => "Classifying message for spam",
            EventType::Spam(SpamEvent::ModelLoaded) => "Spam classifier model loaded",
            EventType::Spam(SpamEvent::ModelNotReady) => "Spam classifier model not ready",
            EventType::Spam(SpamEvent::ModelNotFound) => "Spam classifier model not found",
            EventType::Spam(SpamEvent::RulesUpdated) => "Spam filter rules updated",
            EventType::Spf(SpfEvent::Pass) => "SPF check passed",
            EventType::Spf(SpfEvent::Fail) => "SPF check failed",
            EventType::Spf(SpfEvent::SoftFail) => "SPF soft fail",
            EventType::Spf(SpfEvent::Neutral) => "SPF neutral result",
            EventType::Spf(SpfEvent::TempError) => "SPF temporary error",
            EventType::Spf(SpfEvent::PermError) => "SPF permanent error",
            EventType::Spf(SpfEvent::None) => "No SPF record",
            EventType::Store(StoreEvent::AssertValueFailed) => {
                "Another process modified the record"
            }
            EventType::Store(StoreEvent::FoundationdbError) => "FoundationDB error",
            EventType::Store(StoreEvent::MysqlError) => "MySQL error",
            EventType::Store(StoreEvent::PostgresqlError) => "PostgreSQL error",
            EventType::Store(StoreEvent::RocksdbError) => "RocksDB error",
            EventType::Store(StoreEvent::SqliteError) => "SQLite error",
            EventType::Store(StoreEvent::LdapError) => "LDAP error",
            EventType::Store(StoreEvent::ElasticsearchError) => "ElasticSearch error",
            EventType::Store(StoreEvent::MeilisearchError) => "Meilisearch error",
            EventType::Store(StoreEvent::RedisError) => "Redis error",
            EventType::Store(StoreEvent::S3Error) => "S3 error",
            EventType::Store(StoreEvent::AzureError) => "Azure error",
            EventType::Store(StoreEvent::FilesystemError) => "Filesystem error",
            EventType::Store(StoreEvent::PoolError) => "Connection pool error",
            EventType::Store(StoreEvent::DataCorruption) => "Data corruption detected",
            EventType::Store(StoreEvent::DecompressError) => "Decompression error",
            EventType::Store(StoreEvent::DeserializeError) => "Deserialization error",
            EventType::Store(StoreEvent::NotFound) => "Record not found in database",
            EventType::Store(StoreEvent::NotConfigured) => "Store not configured",
            EventType::Store(StoreEvent::NotSupported) => "Operation not supported by store",
            EventType::Store(StoreEvent::UnexpectedError) => "Unexpected store error",
            EventType::Store(StoreEvent::CryptoError) => "Store crypto error",
            EventType::Store(StoreEvent::HttpStoreError) => "Error updating HTTP store",
            EventType::Store(StoreEvent::BlobMissingMarker) => "Blob missing marker",
            EventType::Store(StoreEvent::DataWrite) => "Write batch operation",
            EventType::Store(StoreEvent::DataIterate) => "Data store iteration operation",
            EventType::Store(StoreEvent::BlobRead) => "Blob read operation",
            EventType::Store(StoreEvent::BlobWrite) => "Blob write operation",
            EventType::Store(StoreEvent::BlobDelete) => "Blob delete operation",
            EventType::Store(StoreEvent::SqlQuery) => "SQL query executed",
            EventType::Store(StoreEvent::LdapQuery) => "LDAP query executed",
            EventType::Store(StoreEvent::LdapWarning) => "LDAP authentication warning",
            EventType::Store(StoreEvent::HttpStoreFetch) => "HTTP store updated",
            EventType::Store(StoreEvent::AutoExpunge) => "Auto-expunge executed",
            EventType::Store(StoreEvent::BlobStorePurged) => "Blob store purge completed",
            EventType::Store(StoreEvent::DataStorePurged) => "Data store purge completed",
            EventType::TaskManager(TaskManagerEvent::TaskAcquired) => "Task acquired from queue",
            EventType::TaskManager(TaskManagerEvent::TaskQueued) => "Task queued for processing",
            EventType::TaskManager(TaskManagerEvent::TaskScheduled) => {
                "Task scheduled for future execution"
            }
            EventType::TaskManager(TaskManagerEvent::TaskLocked) => {
                "Task is locked by another process"
            }
            EventType::TaskManager(TaskManagerEvent::TaskIgnored) => "Task ignored",
            EventType::TaskManager(TaskManagerEvent::TaskFailed) => "Task failed permanently",
            EventType::TaskManager(TaskManagerEvent::TaskRetry) => "Task will be retried",
            EventType::TaskManager(TaskManagerEvent::TaskStalled) => "Task stalled",
            EventType::TaskManager(TaskManagerEvent::TaskExpired) => "Task expired",
            EventType::TaskManager(TaskManagerEvent::BlobNotFound) => "Blob not found for task",
            EventType::TaskManager(TaskManagerEvent::MetadataNotFound) => {
                "Metadata not found for task"
            }
            EventType::TaskManager(TaskManagerEvent::SchedulerStarted) => "Task scheduler started",
            EventType::TaskManager(TaskManagerEvent::ManagerStarted) => "Task manager started",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertEvent) => "Alert event triggered",
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertMessage) => "Alert message sent",
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::LogError) => "Log collector error",
            EventType::Telemetry(TelemetryEvent::WebhookError) => "Webhook collector error",
            EventType::Telemetry(TelemetryEvent::OtelExporterError) => {
                "OpenTelemetry exporter error"
            }
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError) => {
                "OpenTelemetry metrics exporter error"
            }
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError) => {
                "Prometheus exporter error"
            }
            EventType::Telemetry(TelemetryEvent::JournalError) => "Journal collector error",
            EventType::Telemetry(TelemetryEvent::EventsDropped) => "Telemetry events dropped",
            EventType::Telemetry(TelemetryEvent::MetricsCollected) => "Metrics collected",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::MetricsStored) => "Metric store",
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::MetricsPushed) => "Metrics pushed",
            EventType::Tls(TlsEvent::Handshake) => "TLS handshake",
            EventType::Tls(TlsEvent::HandshakeError) => "TLS handshake error",
            EventType::Tls(TlsEvent::NotConfigured) => "TLS not configured",
            EventType::Tls(TlsEvent::CertificateNotFound) => "TLS certificate not found",
            EventType::Tls(TlsEvent::NoCertificatesAvailable) => "No TLS certificates available",
            EventType::Tls(TlsEvent::MultipleCertificatesAvailable) => {
                "Multiple TLS certificates available"
            }
            EventType::Tls(TlsEvent::ExpiredCertificateRemoved) => {
                "Certificate expired and removed"
            }
            EventType::TlsRpt(TlsRptEvent::RecordFetch) => "Fetched TLS-RPT record",
            EventType::TlsRpt(TlsRptEvent::RecordFetchError) => "Error fetching TLS-RPT record",
            EventType::TlsRpt(TlsRptEvent::RecordNotFound) => "TLS-RPT record not found",
            EventType::WebDav(WebDavEvent::Propfind) => "WebDAV PROPFIND request",
            EventType::WebDav(WebDavEvent::Proppatch) => "WebDAV PROPPATCH request",
            EventType::WebDav(WebDavEvent::Get) => "WebDAV GET request",
            EventType::WebDav(WebDavEvent::Head) => "WebDAV HEAD request",
            EventType::WebDav(WebDavEvent::Report) => "WebDAV REPORT request",
            EventType::WebDav(WebDavEvent::Mkcol) => "WebDAV MKCOL request",
            EventType::WebDav(WebDavEvent::Mkcalendar) => "WebDAV MKCALENDAR request",
            EventType::WebDav(WebDavEvent::Delete) => "WebDAV DELETE request",
            EventType::WebDav(WebDavEvent::Put) => "WebDAV PUT request",
            EventType::WebDav(WebDavEvent::Post) => "WebDAV POST request",
            EventType::WebDav(WebDavEvent::Patch) => "WebDAV PATCH request",
            EventType::WebDav(WebDavEvent::Copy) => "WebDAV COPY request",
            EventType::WebDav(WebDavEvent::Move) => "WebDAV MOVE request",
            EventType::WebDav(WebDavEvent::Lock) => "WebDAV LOCK request",
            EventType::WebDav(WebDavEvent::Unlock) => "WebDAV UNLOCK request",
            EventType::WebDav(WebDavEvent::Acl) => "WebDAV ACL request",
            EventType::WebDav(WebDavEvent::Options) => "WebDAV OPTIONS request",
            EventType::WebDav(WebDavEvent::Error) => "WebDAV error",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            EventType::Auth(AuthEvent::Success) => "Authentication error",
            EventType::Auth(AuthEvent::Failed) => "Authentication failed",
            EventType::Auth(AuthEvent::TokenExpired) => "Authentication error",
            EventType::Auth(AuthEvent::MfaRequired) => {
                "This account requires multi-factor authentication. Alternatively, you can use an app password if your account has one."
            }
            EventType::Auth(AuthEvent::TooManyAttempts) => "Too many authentication attempts",
            EventType::Auth(AuthEvent::ClientRegistration) => "Authentication error",
            EventType::Auth(AuthEvent::Error) => "Authentication error",
            EventType::Auth(AuthEvent::CredentialExpired) => "Credential expired",
            EventType::Cache(CacheEvent::Miss) => "Cache miss",
            EventType::Cache(CacheEvent::Hit) => "Cache hit",
            EventType::Cache(CacheEvent::Stale) => "Cache stale",
            EventType::Cache(CacheEvent::Update) => "Cache updated",
            EventType::Cache(CacheEvent::EntryTooLarge) => "Cache entry too large",
            EventType::Cache(CacheEvent::Invalidate) => "Cache invalidated",
            EventType::Cache(CacheEvent::SwapHit) => "Cache snapshot loaded",
            EventType::Cache(CacheEvent::SwapMiss) => "Cache snapshot unavailable",
            EventType::Cache(CacheEvent::SwapWrite) => "Cache snapshot written",
            EventType::Cache(CacheEvent::SwapError) => "Cache swap error",
            EventType::Cache(CacheEvent::SwapMetrics) => "Cache swap metrics",
            EventType::Cache(CacheEvent::SwapFlush) => "Cache swap flushed",
            EventType::Imap(ImapEvent::ConnectionStart) => "IMAP error",
            EventType::Imap(ImapEvent::ConnectionEnd) => "IMAP error",
            EventType::Imap(ImapEvent::GetAcl) => "IMAP error",
            EventType::Imap(ImapEvent::SetAcl) => "IMAP error",
            EventType::Imap(ImapEvent::MyRights) => "IMAP error",
            EventType::Imap(ImapEvent::ListRights) => "IMAP error",
            EventType::Imap(ImapEvent::Append) => "IMAP error",
            EventType::Imap(ImapEvent::Capabilities) => "IMAP error",
            EventType::Imap(ImapEvent::Id) => "IMAP error",
            EventType::Imap(ImapEvent::Close) => "IMAP error",
            EventType::Imap(ImapEvent::Copy) => "IMAP error",
            EventType::Imap(ImapEvent::Move) => "IMAP error",
            EventType::Imap(ImapEvent::CreateMailbox) => "IMAP error",
            EventType::Imap(ImapEvent::DeleteMailbox) => "IMAP error",
            EventType::Imap(ImapEvent::RenameMailbox) => "IMAP error",
            EventType::Imap(ImapEvent::Enable) => "IMAP error",
            EventType::Imap(ImapEvent::Expunge) => "IMAP error",
            EventType::Imap(ImapEvent::Fetch) => "IMAP error",
            EventType::Imap(ImapEvent::IdleStart) => "IMAP error",
            EventType::Imap(ImapEvent::IdleStop) => "IMAP error",
            EventType::Imap(ImapEvent::List) => "IMAP error",
            EventType::Imap(ImapEvent::Lsub) => "IMAP error",
            EventType::Imap(ImapEvent::Logout) => "IMAP error",
            EventType::Imap(ImapEvent::Namespace) => "IMAP error",
            EventType::Imap(ImapEvent::Noop) => "IMAP error",
            EventType::Imap(ImapEvent::Search) => "IMAP error",
            EventType::Imap(ImapEvent::Sort) => "IMAP error",
            EventType::Imap(ImapEvent::Select) => "IMAP error",
            EventType::Imap(ImapEvent::Status) => "IMAP error",
            EventType::Imap(ImapEvent::Store) => "IMAP error",
            EventType::Imap(ImapEvent::Subscribe) => "IMAP error",
            EventType::Imap(ImapEvent::Unsubscribe) => "IMAP error",
            EventType::Imap(ImapEvent::Thread) => "IMAP error",
            EventType::Imap(ImapEvent::UidBatches) => "IMAP error",
            EventType::Imap(ImapEvent::GetQuota) => "IMAP error",
            EventType::Imap(ImapEvent::GetMetadata) => "IMAP error",
            EventType::Imap(ImapEvent::SetMetadata) => "IMAP error",
            EventType::Imap(ImapEvent::Error) => "IMAP error",
            EventType::Imap(ImapEvent::RawInput) => "IMAP error",
            EventType::Imap(ImapEvent::RawOutput) => "IMAP error",
            EventType::Jmap(JmapEvent::MethodCall) => "Other message",
            EventType::Jmap(JmapEvent::InvalidArguments) => "Invalid arguments",
            EventType::Jmap(JmapEvent::RequestTooLarge) => "Request too large",
            EventType::Jmap(JmapEvent::StateMismatch) => "State mismatch",
            EventType::Jmap(JmapEvent::AnchorNotFound) => "Anchor not found",
            EventType::Jmap(JmapEvent::UnsupportedFilter) => "Unsupported filter",
            EventType::Jmap(JmapEvent::UnsupportedSort) => "Unsupported sort",
            EventType::Jmap(JmapEvent::UnknownMethod) => "Unknown method",
            EventType::Jmap(JmapEvent::InvalidResultReference) => "Invalid result reference",
            EventType::Jmap(JmapEvent::Forbidden) => "Forbidden",
            EventType::Jmap(JmapEvent::AccountNotFound) => "Account not found",
            EventType::Jmap(JmapEvent::AccountNotSupportedByMethod) => {
                "Account not supported by method"
            }
            EventType::Jmap(JmapEvent::AccountReadOnly) => "Account read-only",
            EventType::Jmap(JmapEvent::FromAccountNotFound) => "Source account not found",
            EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod) => {
                "Source account not supported by method"
            }
            EventType::Jmap(JmapEvent::NotFound) => "Not found",
            EventType::Jmap(JmapEvent::CannotCalculateChanges) => "Cannot calculate changes",
            EventType::Jmap(JmapEvent::UnknownDataType) => "Unknown data type",
            EventType::Jmap(JmapEvent::UnknownCapability) => "Unknown capability",
            EventType::Jmap(JmapEvent::NotJson) => "Not JSON",
            EventType::Jmap(JmapEvent::NotRequest) => "Not a request",
            EventType::Jmap(JmapEvent::WebsocketStart) => "Other message",
            EventType::Jmap(JmapEvent::WebsocketStop) => "Other message",
            EventType::Jmap(JmapEvent::WebsocketError) => "Other message",
            EventType::Jmap(JmapEvent::ExpandDurationTooLarge) => "Expand duration too large",
            EventType::Jmap(JmapEvent::CannotCalculateOccurrences) => {
                "Cannot calculate occurrences"
            }
            EventType::Jmap(JmapEvent::TooLarge) => "Too large",
            EventType::Jmap(JmapEvent::RateLimit) => "Rate limit",
            EventType::Jmap(JmapEvent::ObjectNotFound) => "Object not found",
            EventType::Limit(LimitEvent::SizeRequest) => "Request too large",
            EventType::Limit(LimitEvent::SizeUpload) => "Upload too large",
            EventType::Limit(LimitEvent::CallsIn) => "Too many calls in",
            EventType::Limit(LimitEvent::ConcurrentRequest) => "Too many concurrent requests",
            EventType::Limit(LimitEvent::ConcurrentUpload) => "Too many concurrent uploads",
            EventType::Limit(LimitEvent::ConcurrentConnection) => "Too many concurrent connections",
            EventType::Limit(LimitEvent::Quota) => "Quota exceeded",
            EventType::Limit(LimitEvent::BlobQuota) => "Blob quota exceeded",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => "Tenant quota exceeded",
            // SPDX-SnippetEnd
            EventType::Limit(LimitEvent::TooManyRequests) => "Too many requests",
            EventType::Limit(LimitEvent::MemoryBudget) => "Insufficient memory available",
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::CreateScript) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::UpdateScript) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::GetScript) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::DeleteScript) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::RenameScript) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::CheckScript) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::HaveSpace) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::ListScripts) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::SetActive) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::Capabilities) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::StartTls) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::Unauthenticate) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::Logout) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::Noop) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::Error) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::RawInput) => "ManageSieve error",
            EventType::ManageSieve(ManageSieveEvent::RawOutput) => "ManageSieve error",
            EventType::Network(NetworkEvent::ListenStart) => "Network error",
            EventType::Network(NetworkEvent::ListenStop) => "Network error",
            EventType::Network(NetworkEvent::ListenError) => "Network error",
            EventType::Network(NetworkEvent::BindError) => "Network error",
            EventType::Network(NetworkEvent::ReadError) => "Network error",
            EventType::Network(NetworkEvent::WriteError) => "Network error",
            EventType::Network(NetworkEvent::FlushError) => "Network error",
            EventType::Network(NetworkEvent::AcceptError) => "Network error",
            EventType::Network(NetworkEvent::SplitError) => "Network error",
            EventType::Network(NetworkEvent::Timeout) => "Network error",
            EventType::Network(NetworkEvent::Closed) => "Network error",
            EventType::Network(NetworkEvent::ProxyError) => "Network error",
            EventType::Network(NetworkEvent::SetOptError) => "Network error",
            EventType::Pop3(Pop3Event::ConnectionStart) => "POP3 error",
            EventType::Pop3(Pop3Event::ConnectionEnd) => "POP3 error",
            EventType::Pop3(Pop3Event::Delete) => "POP3 error",
            EventType::Pop3(Pop3Event::Reset) => "POP3 error",
            EventType::Pop3(Pop3Event::Quit) => "POP3 error",
            EventType::Pop3(Pop3Event::Fetch) => "POP3 error",
            EventType::Pop3(Pop3Event::List) => "POP3 error",
            EventType::Pop3(Pop3Event::ListMessage) => "POP3 error",
            EventType::Pop3(Pop3Event::Uidl) => "POP3 error",
            EventType::Pop3(Pop3Event::UidlMessage) => "POP3 error",
            EventType::Pop3(Pop3Event::Stat) => "POP3 error",
            EventType::Pop3(Pop3Event::Noop) => "POP3 error",
            EventType::Pop3(Pop3Event::Capabilities) => "POP3 error",
            EventType::Pop3(Pop3Event::StartTls) => "POP3 error",
            EventType::Pop3(Pop3Event::Utf8) => "POP3 error",
            EventType::Pop3(Pop3Event::Error) => "POP3 error",
            EventType::Pop3(Pop3Event::RawInput) => "POP3 error",
            EventType::Pop3(Pop3Event::RawOutput) => "POP3 error",
            EventType::Resource(ResourceEvent::NotFound) => "Not found",
            EventType::Resource(ResourceEvent::BadParameters) => "Bad parameters",
            EventType::Resource(ResourceEvent::Error) => "Resource error",
            EventType::Resource(ResourceEvent::DownloadExternal) => "Other status",
            EventType::SearchIndex(SearchIndexEvent::DocumentTruncated) => {
                "Search document truncated"
            }
            EventType::Security(SecurityEvent::AuthenticationBan) => "Insufficient permissions",
            EventType::Security(SecurityEvent::AbuseBan) => "Insufficient permissions",
            EventType::Security(SecurityEvent::ScanBan) => "Insufficient permissions",
            EventType::Security(SecurityEvent::LoiterBan) => "Insufficient permissions",
            EventType::Security(SecurityEvent::IpBlocked) => "Insufficient permissions",
            EventType::Security(SecurityEvent::IpBlockExpired) => "Insufficient permissions",
            EventType::Security(SecurityEvent::IpAllowExpired) => "Insufficient permissions",
            EventType::Security(SecurityEvent::IpUnauthorized) => "Unauthorized IP address",
            EventType::Security(SecurityEvent::Unauthorized) => "Insufficient permissions",
            EventType::Smtp(SmtpEvent::ConnectionStart) => "SMTP error",
            EventType::Smtp(SmtpEvent::ConnectionEnd) => "SMTP error",
            EventType::Smtp(SmtpEvent::Error) => "SMTP error",
            EventType::Smtp(SmtpEvent::IdNotFound) => "SMTP error",
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => "SMTP error",
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => "SMTP error",
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => "SMTP error",
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => "SMTP error",
            EventType::Smtp(SmtpEvent::MessageParseFailed) => "SMTP error",
            EventType::Smtp(SmtpEvent::MessageTooLarge) => "SMTP error",
            EventType::Smtp(SmtpEvent::LoopDetected) => "SMTP error",
            EventType::Smtp(SmtpEvent::MultipleFromDomains) => "SMTP error",
            EventType::Smtp(SmtpEvent::DkimPass) => "SMTP error",
            EventType::Smtp(SmtpEvent::DkimFail) => "SMTP error",
            EventType::Smtp(SmtpEvent::Dkim2Pass) => "SMTP error",
            EventType::Smtp(SmtpEvent::Dkim2Fail) => "SMTP error",
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected) => "SMTP error",
            EventType::Smtp(SmtpEvent::ArcPass) => "SMTP error",
            EventType::Smtp(SmtpEvent::ArcFail) => "SMTP error",
            EventType::Smtp(SmtpEvent::SpfEhloPass) => "SMTP error",
            EventType::Smtp(SmtpEvent::SpfEhloFail) => "SMTP error",
            EventType::Smtp(SmtpEvent::SpfFromPass) => "SMTP error",
            EventType::Smtp(SmtpEvent::SpfFromFail) => "SMTP error",
            EventType::Smtp(SmtpEvent::DmarcPass) => "SMTP error",
            EventType::Smtp(SmtpEvent::DmarcFail) => "SMTP error",
            EventType::Smtp(SmtpEvent::IprevPass) => "SMTP error",
            EventType::Smtp(SmtpEvent::IprevFail) => "SMTP error",
            EventType::Smtp(SmtpEvent::TooManyMessages) => "SMTP error",
            EventType::Smtp(SmtpEvent::Ehlo) => "SMTP error",
            EventType::Smtp(SmtpEvent::InvalidEhlo) => "SMTP error",
            EventType::Smtp(SmtpEvent::DidNotSayEhlo) => "SMTP error",
            EventType::Smtp(SmtpEvent::EhloExpected) => "SMTP error",
            EventType::Smtp(SmtpEvent::LhloExpected) => "SMTP error",
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated) => "SMTP error",
            EventType::Smtp(SmtpEvent::MailFromUnauthorized) => "SMTP error",
            EventType::Smtp(SmtpEvent::MailFromNotAllowed) => "SMTP error",
            EventType::Smtp(SmtpEvent::MailFromRewritten) => "SMTP error",
            EventType::Smtp(SmtpEvent::MailFromMissing) => "SMTP error",
            EventType::Smtp(SmtpEvent::MailFrom) => "SMTP error",
            EventType::Smtp(SmtpEvent::MultipleMailFrom) => "SMTP error",
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => "SMTP error",
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => "SMTP error",
            EventType::Smtp(SmtpEvent::RcptTo) => "SMTP error",
            EventType::Smtp(SmtpEvent::RcptToDuplicate) => "SMTP error",
            EventType::Smtp(SmtpEvent::RcptToRewritten) => "SMTP error",
            EventType::Smtp(SmtpEvent::RcptToMissing) => "SMTP error",
            EventType::Smtp(SmtpEvent::RcptToGreylisted) => "SMTP error",
            EventType::Smtp(SmtpEvent::TooManyRecipients) => "SMTP error",
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => "SMTP error",
            EventType::Smtp(SmtpEvent::RawInput) => "SMTP error",
            EventType::Smtp(SmtpEvent::RawOutput) => "SMTP error",
            EventType::Smtp(SmtpEvent::MissingLocalHostname) => "SMTP error",
            EventType::Smtp(SmtpEvent::Vrfy) => "SMTP error",
            EventType::Smtp(SmtpEvent::VrfyNotFound) => "SMTP error",
            EventType::Smtp(SmtpEvent::VrfyDisabled) => "SMTP error",
            EventType::Smtp(SmtpEvent::Expn) => "SMTP error",
            EventType::Smtp(SmtpEvent::ExpnNotFound) => "SMTP error",
            EventType::Smtp(SmtpEvent::ExpnDisabled) => "SMTP error",
            EventType::Smtp(SmtpEvent::RequireTlsDisabled) => "SMTP error",
            EventType::Smtp(SmtpEvent::DeliverByDisabled) => "SMTP error",
            EventType::Smtp(SmtpEvent::DeliverByInvalid) => "SMTP error",
            EventType::Smtp(SmtpEvent::FutureReleaseDisabled) => "SMTP error",
            EventType::Smtp(SmtpEvent::FutureReleaseInvalid) => "SMTP error",
            EventType::Smtp(SmtpEvent::MtPriorityDisabled) => "SMTP error",
            EventType::Smtp(SmtpEvent::MtPriorityInvalid) => "SMTP error",
            EventType::Smtp(SmtpEvent::DsnDisabled) => "SMTP error",
            EventType::Smtp(SmtpEvent::AuthNotAllowed) => "SMTP error",
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => "SMTP error",
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong) => "SMTP error",
            EventType::Smtp(SmtpEvent::AlreadyAuthenticated) => "SMTP error",
            EventType::Smtp(SmtpEvent::Noop) => "SMTP error",
            EventType::Smtp(SmtpEvent::StartTls) => "SMTP error",
            EventType::Smtp(SmtpEvent::StartTlsUnavailable) => "SMTP error",
            EventType::Smtp(SmtpEvent::StartTlsAlready) => "SMTP error",
            EventType::Smtp(SmtpEvent::Rset) => "SMTP error",
            EventType::Smtp(SmtpEvent::Quit) => "SMTP error",
            EventType::Smtp(SmtpEvent::Help) => "SMTP error",
            EventType::Smtp(SmtpEvent::CommandNotImplemented) => "SMTP error",
            EventType::Smtp(SmtpEvent::InvalidCommand) => "SMTP error",
            EventType::Smtp(SmtpEvent::InvalidSenderAddress) => "SMTP error",
            EventType::Smtp(SmtpEvent::InvalidRecipientAddress) => "SMTP error",
            EventType::Smtp(SmtpEvent::InvalidParameter) => "SMTP error",
            EventType::Smtp(SmtpEvent::UnsupportedParameter) => "SMTP error",
            EventType::Smtp(SmtpEvent::SyntaxError) => "SMTP error",
            EventType::Smtp(SmtpEvent::RequestTooLarge) => "SMTP error",
            EventType::Store(StoreEvent::AssertValueFailed) => {
                "Another process has modified the value"
            }
            EventType::Store(StoreEvent::FoundationdbError) => "FoundationDB error",
            EventType::Store(StoreEvent::MysqlError) => "MySQL error",
            EventType::Store(StoreEvent::PostgresqlError) => "PostgreSQL error",
            EventType::Store(StoreEvent::RocksdbError) => "RocksDB error",
            EventType::Store(StoreEvent::SqliteError) => "SQLite error",
            EventType::Store(StoreEvent::LdapError) => "LDAP error",
            EventType::Store(StoreEvent::ElasticsearchError) => "ElasticSearch error",
            EventType::Store(StoreEvent::MeilisearchError) => "Store error",
            EventType::Store(StoreEvent::RedisError) => "Redis error",
            EventType::Store(StoreEvent::S3Error) => "S3 error",
            EventType::Store(StoreEvent::AzureError) => "Azure error",
            EventType::Store(StoreEvent::FilesystemError) => "Filesystem error",
            EventType::Store(StoreEvent::PoolError) => "Connection pool error",
            EventType::Store(StoreEvent::DataCorruption) => "Data corruption",
            EventType::Store(StoreEvent::DecompressError) => "Decompression error",
            EventType::Store(StoreEvent::DeserializeError) => "Deserialization error",
            EventType::Store(StoreEvent::NotFound) => "Not found",
            EventType::Store(StoreEvent::NotConfigured) => "Not configured",
            EventType::Store(StoreEvent::NotSupported) => "Operation not supported",
            EventType::Store(StoreEvent::UnexpectedError) => "Unexpected error",
            EventType::Store(StoreEvent::CryptoError) => "Crypto error",
            EventType::Store(StoreEvent::HttpStoreError) => "Store error",
            EventType::Store(StoreEvent::BlobMissingMarker) => "Blob is missing marker",
            EventType::Store(StoreEvent::DataWrite) => "Store error",
            EventType::Store(StoreEvent::DataIterate) => "Store error",
            EventType::Store(StoreEvent::BlobRead) => "Store error",
            EventType::Store(StoreEvent::BlobWrite) => "Store error",
            EventType::Store(StoreEvent::BlobDelete) => "Store error",
            EventType::Store(StoreEvent::SqlQuery) => "Store error",
            EventType::Store(StoreEvent::LdapQuery) => "Store error",
            EventType::Store(StoreEvent::LdapWarning) => "Store error",
            EventType::Store(StoreEvent::HttpStoreFetch) => "Store error",
            _ => "Internal Server Error",
        }
    }

    pub fn otel_metric_name(&self) -> &'static str {
        match self {
            EventType::Acme(AcmeEvent::AuthError) => "stalwart.acme.auth_error",
            EventType::Acme(AcmeEvent::AuthTooManyAttempts) => {
                "stalwart.acme.auth_too_many_attempts"
            }
            EventType::Acme(AcmeEvent::OrderCompleted) => "stalwart.acme.order_completed",
            EventType::Acme(AcmeEvent::OrderInvalid) => "stalwart.acme.order_invalid",
            EventType::Acme(AcmeEvent::ClientMissingSni) => "stalwart.acme.client_missing_sni",
            EventType::Acme(AcmeEvent::TlsAlpnError) => "stalwart.acme.tls_alpn_error",
            EventType::Acme(AcmeEvent::TokenNotFound) => "stalwart.acme.token_not_found",
            EventType::Acme(AcmeEvent::Error) => "stalwart.acme.error",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::ApiError) => "stalwart.ai.api_error",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::Request) => "stalwart.ai.request",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamVerdict) => "stalwart.ai.spam_verdict",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamSkipped) => "stalwart.ai.spam_skipped",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::BreakerOpen) => "stalwart.ai.breaker_open",
            // SPDX-SnippetEnd
            EventType::Arc(ArcEvent::ChainInvalid) => "stalwart.arc.chain_invalid",
            EventType::Arc(ArcEvent::SignatureInvalid) => "stalwart.arc.signature_invalid",
            EventType::Arc(ArcEvent::HashMismatch) => "stalwart.arc.hash_mismatch",
            EventType::Auth(AuthEvent::Success) => "stalwart.auth.success",
            EventType::Auth(AuthEvent::Failed) => "stalwart.auth.failed",
            EventType::Auth(AuthEvent::TooManyAttempts) => "stalwart.auth.too_many_attempts",
            EventType::Auth(AuthEvent::Error) => "stalwart.auth.error",
            EventType::Cache(CacheEvent::Miss) => "stalwart.cache.miss",
            EventType::Cache(CacheEvent::Hit) => "stalwart.cache.hit",
            EventType::Cache(CacheEvent::Stale) => "stalwart.cache.stale",
            EventType::Cache(CacheEvent::EntryTooLarge) => "stalwart.cache.entry_too_large",
            EventType::Cache(CacheEvent::SwapHit) => "stalwart.cache.swap_hit",
            EventType::Cache(CacheEvent::SwapMiss) => "stalwart.cache.swap_miss",
            EventType::Cache(CacheEvent::SwapWrite) => "stalwart.cache.swap_write",
            EventType::Cache(CacheEvent::SwapError) => "stalwart.cache.swap_error",
            EventType::Calendar(CalendarEvent::AlarmSent) => "stalwart.calendar.alarm_sent",
            EventType::Calendar(CalendarEvent::AlarmFailed) => "stalwart.calendar.alarm_failed",
            EventType::Calendar(CalendarEvent::ItipMessageSent) => {
                "stalwart.calendar.itip_message_sent"
            }
            EventType::Calendar(CalendarEvent::ItipMessageReceived) => {
                "stalwart.calendar.itip_message_received"
            }
            EventType::Calendar(CalendarEvent::ItipMessageError) => {
                "stalwart.calendar.itip_message_error"
            }
            EventType::Cluster(ClusterEvent::SubscriberError) => {
                "stalwart.cluster.subscriber_error"
            }
            EventType::Cluster(ClusterEvent::SubscriberDisconnected) => {
                "stalwart.cluster.subscriber_disconnected"
            }
            EventType::Cluster(ClusterEvent::PublisherError) => "stalwart.cluster.publisher_error",
            EventType::Dane(DaneEvent::AuthenticationSuccess) => {
                "stalwart.dane.authentication_success"
            }
            EventType::Dane(DaneEvent::AuthenticationFailure) => {
                "stalwart.dane.authentication_failure"
            }
            EventType::Dane(DaneEvent::NoCertificatesFound) => {
                "stalwart.dane.no_certificates_found"
            }
            EventType::Dane(DaneEvent::CertificateParseError) => {
                "stalwart.dane.certificate_parse_error"
            }
            EventType::Dane(DaneEvent::TlsaRecordFetchError) => {
                "stalwart.dane.tlsa_record_fetch_error"
            }
            EventType::Dane(DaneEvent::TlsaRecordNotFound) => "stalwart.dane.tlsa_record_not_found",
            EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned) => {
                "stalwart.dane.tlsa_record_not_dnssec_signed"
            }
            EventType::Dane(DaneEvent::TlsaRecordInvalid) => "stalwart.dane.tlsa_record_invalid",
            EventType::Dane(DaneEvent::BogusDnssecRecord) => "stalwart.dane.bogus_dnssec_record",
            EventType::Delivery(DeliveryEvent::AttemptStart) => "stalwart.delivery.attempt_start",
            EventType::Delivery(DeliveryEvent::AttemptEnd) => "stalwart.delivery.attempt_end",
            EventType::Delivery(DeliveryEvent::Completed) => "stalwart.delivery.completed",
            EventType::Delivery(DeliveryEvent::MxLookupFailed) => {
                "stalwart.delivery.mx_lookup_failed"
            }
            EventType::Delivery(DeliveryEvent::IpLookupFailed) => {
                "stalwart.delivery.ip_lookup_failed"
            }
            EventType::Delivery(DeliveryEvent::NullMx) => "stalwart.delivery.null_mx",
            EventType::Delivery(DeliveryEvent::GreetingFailed) => {
                "stalwart.delivery.greeting_failed"
            }
            EventType::Delivery(DeliveryEvent::EhloRejected) => "stalwart.delivery.ehlo_rejected",
            EventType::Delivery(DeliveryEvent::AuthFailed) => "stalwart.delivery.auth_failed",
            EventType::Delivery(DeliveryEvent::MailFromRejected) => {
                "stalwart.delivery.mail_from_rejected"
            }
            EventType::Delivery(DeliveryEvent::Delivered) => "stalwart.delivery.delivered",
            EventType::Delivery(DeliveryEvent::RcptToRejected) => {
                "stalwart.delivery.rcpt_to_rejected"
            }
            EventType::Delivery(DeliveryEvent::RcptToFailed) => "stalwart.delivery.rcpt_to_failed",
            EventType::Delivery(DeliveryEvent::MessageRejected) => {
                "stalwart.delivery.message_rejected"
            }
            EventType::Delivery(DeliveryEvent::StartTlsUnavailable) => {
                "stalwart.delivery.start_tls_unavailable"
            }
            EventType::Delivery(DeliveryEvent::StartTlsError) => {
                "stalwart.delivery.start_tls_error"
            }
            EventType::Delivery(DeliveryEvent::StartTlsDisabled) => {
                "stalwart.delivery.start_tls_disabled"
            }
            EventType::Delivery(DeliveryEvent::ImplicitTlsError) => {
                "stalwart.delivery.implicit_tls_error"
            }
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded) => {
                "stalwart.delivery.concurrency_limit_exceeded"
            }
            EventType::Delivery(DeliveryEvent::RateLimitExceeded) => {
                "stalwart.delivery.rate_limit_exceeded"
            }
            EventType::Delivery(DeliveryEvent::DoubleBounce) => "stalwart.delivery.double_bounce",
            EventType::Delivery(DeliveryEvent::DsnSuccess) => "stalwart.delivery.dsn_success",
            EventType::Delivery(DeliveryEvent::DsnTempFail) => "stalwart.delivery.dsn_temp_fail",
            EventType::Delivery(DeliveryEvent::DsnPermFail) => "stalwart.delivery.dsn_perm_fail",
            EventType::Dkim(DkimEvent::Pass) => "stalwart.dkim.pass",
            EventType::Dkim(DkimEvent::Neutral) => "stalwart.dkim.neutral",
            EventType::Dkim(DkimEvent::Fail) => "stalwart.dkim.fail",
            EventType::Dkim(DkimEvent::PermError) => "stalwart.dkim.perm_error",
            EventType::Dkim(DkimEvent::TempError) => "stalwart.dkim.temp_error",
            EventType::Dkim(DkimEvent::None) => "stalwart.dkim.none",
            EventType::Dkim(DkimEvent::SignatureInvalid) => "stalwart.dkim.signature_invalid",
            EventType::Dkim(DkimEvent::PublicKeyError) => "stalwart.dkim.public_key_error",
            EventType::Dkim(DkimEvent::VerificationFailed) => "stalwart.dkim.verification_failed",
            EventType::Dkim(DkimEvent::HashMismatch) => "stalwart.dkim.hash_mismatch",
            EventType::Dkim(DkimEvent::SignerNotFound) => "stalwart.dkim.signer_not_found",
            EventType::Dkim2(Dkim2Event::InstanceInvalid) => "stalwart.dkim2.instance_invalid",
            EventType::Dkim2(Dkim2Event::SignatureInvalid) => "stalwart.dkim2.signature_invalid",
            EventType::Dkim2(Dkim2Event::ChainInvalid) => "stalwart.dkim2.chain_invalid",
            EventType::Dkim2(Dkim2Event::TimestampInvalid) => "stalwart.dkim2.timestamp_invalid",
            EventType::Dkim2(Dkim2Event::EnvelopeMismatch) => "stalwart.dkim2.envelope_mismatch",
            EventType::Dkim2(Dkim2Event::CustodyBroken) => "stalwart.dkim2.custody_broken",
            EventType::Dkim2(Dkim2Event::PublicKeyError) => "stalwart.dkim2.public_key_error",
            EventType::Dkim2(Dkim2Event::VerificationFailed) => {
                "stalwart.dkim2.verification_failed"
            }
            EventType::Dkim2(Dkim2Event::HashMismatch) => "stalwart.dkim2.hash_mismatch",
            EventType::Dkim2(Dkim2Event::RecipeError) => "stalwart.dkim2.recipe_error",
            EventType::Dkim2(Dkim2Event::SigningFailed) => "stalwart.dkim2.signing_failed",
            EventType::Dmarc(DmarcEvent::Pass) => "stalwart.dmarc.pass",
            EventType::Dmarc(DmarcEvent::Fail) => "stalwart.dmarc.fail",
            EventType::Dmarc(DmarcEvent::PermError) => "stalwart.dmarc.perm_error",
            EventType::Dmarc(DmarcEvent::TempError) => "stalwart.dmarc.temp_error",
            EventType::Dmarc(DmarcEvent::None) => "stalwart.dmarc.none",
            EventType::Dns(DnsEvent::RecordCreationFailed) => "stalwart.dns.record_creation_failed",
            EventType::Dns(DnsEvent::RecordDeletionFailed) => "stalwart.dns.record_deletion_failed",
            EventType::Dns(DnsEvent::RecordLookupFailed) => "stalwart.dns.record_lookup_failed",
            EventType::Dns(DnsEvent::RecordPropagationTimeout) => {
                "stalwart.dns.record_propagation_timeout"
            }
            EventType::Eval(EvalEvent::Error) => "stalwart.eval.error",
            EventType::Eval(EvalEvent::DirectoryNotFound) => "stalwart.eval.directory_not_found",
            EventType::Eval(EvalEvent::StoreNotFound) => "stalwart.eval.store_not_found",
            EventType::Http(HttpEvent::ConnectionStart) => "stalwart.http.connection_start",
            EventType::Http(HttpEvent::Error) => "stalwart.http.error",
            EventType::Http(HttpEvent::RequestBody) => "stalwart.http.request_body",
            EventType::Http(HttpEvent::ResponseBody) => "stalwart.http.response_body",
            EventType::Http(HttpEvent::XForwardedMissing) => "stalwart.http.x_forwarded_missing",
            EventType::Http(HttpEvent::XForwardedInvalid) => "stalwart.http.x_forwarded_invalid",
            EventType::Imap(ImapEvent::ConnectionStart) => "stalwart.imap.connection_start",
            EventType::Imap(ImapEvent::ConnectionEnd) => "stalwart.imap.connection_end",
            EventType::IncomingReport(IncomingReportEvent::DmarcReport) => {
                "stalwart.incoming_report.dmarc_report"
            }
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings) => {
                "stalwart.incoming_report.dmarc_report_with_warnings"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsReport) => {
                "stalwart.incoming_report.tls_report"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings) => {
                "stalwart.incoming_report.tls_report_with_warnings"
            }
            EventType::IncomingReport(IncomingReportEvent::AbuseReport) => {
                "stalwart.incoming_report.abuse_report"
            }
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport) => {
                "stalwart.incoming_report.auth_failure_report"
            }
            EventType::IncomingReport(IncomingReportEvent::FraudReport) => {
                "stalwart.incoming_report.fraud_report"
            }
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport) => {
                "stalwart.incoming_report.not_spam_report"
            }
            EventType::IncomingReport(IncomingReportEvent::VirusReport) => {
                "stalwart.incoming_report.virus_report"
            }
            EventType::IncomingReport(IncomingReportEvent::OtherReport) => {
                "stalwart.incoming_report.other_report"
            }
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed) => {
                "stalwart.incoming_report.message_parse_failed"
            }
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed) => {
                "stalwart.incoming_report.dmarc_parse_failed"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed) => {
                "stalwart.incoming_report.tls_rpc_parse_failed"
            }
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed) => {
                "stalwart.incoming_report.arf_parse_failed"
            }
            EventType::IncomingReport(IncomingReportEvent::DecompressError) => {
                "stalwart.incoming_report.decompress_error"
            }
            EventType::Iprev(IprevEvent::Pass) => "stalwart.iprev.pass",
            EventType::Iprev(IprevEvent::Fail) => "stalwart.iprev.fail",
            EventType::Iprev(IprevEvent::PermError) => "stalwart.iprev.perm_error",
            EventType::Iprev(IprevEvent::TempError) => "stalwart.iprev.temp_error",
            EventType::Iprev(IprevEvent::None) => "stalwart.iprev.none",
            EventType::Jmap(JmapEvent::MethodCall) => "stalwart.jmap.method_call",
            EventType::Jmap(JmapEvent::InvalidArguments) => "stalwart.jmap.invalid_arguments",
            EventType::Jmap(JmapEvent::RequestTooLarge) => "stalwart.jmap.request_too_large",
            EventType::Jmap(JmapEvent::UnsupportedFilter) => "stalwart.jmap.unsupported_filter",
            EventType::Jmap(JmapEvent::UnsupportedSort) => "stalwart.jmap.unsupported_sort",
            EventType::Jmap(JmapEvent::UnknownMethod) => "stalwart.jmap.unknown_method",
            EventType::Jmap(JmapEvent::Forbidden) => "stalwart.jmap.forbidden",
            EventType::Jmap(JmapEvent::NotJson) => "stalwart.jmap.not_json",
            EventType::Jmap(JmapEvent::NotRequest) => "stalwart.jmap.not_request",
            EventType::Jmap(JmapEvent::WebsocketStart) => "stalwart.jmap.websocket_start",
            EventType::Jmap(JmapEvent::WebsocketError) => "stalwart.jmap.websocket_error",
            EventType::Limit(LimitEvent::SizeRequest) => "stalwart.limit.size_request",
            EventType::Limit(LimitEvent::SizeUpload) => "stalwart.limit.size_upload",
            EventType::Limit(LimitEvent::CallsIn) => "stalwart.limit.calls_in",
            EventType::Limit(LimitEvent::ConcurrentRequest) => "stalwart.limit.concurrent_request",
            EventType::Limit(LimitEvent::ConcurrentUpload) => "stalwart.limit.concurrent_upload",
            EventType::Limit(LimitEvent::ConcurrentConnection) => {
                "stalwart.limit.concurrent_connection"
            }
            EventType::Limit(LimitEvent::Quota) => "stalwart.limit.quota",
            EventType::Limit(LimitEvent::BlobQuota) => "stalwart.limit.blob_quota",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => "stalwart.limit.tenant_quota",
            // SPDX-SnippetEnd
            EventType::Limit(LimitEvent::TooManyRequests) => "stalwart.limit.too_many_requests",
            EventType::Limit(LimitEvent::MemoryBudget) => "stalwart.limit.memory_budget",
            EventType::MailAuth(MailAuthEvent::ParseError) => "stalwart.mail_auth.parse_error",
            EventType::MailAuth(MailAuthEvent::MissingParameters) => {
                "stalwart.mail_auth.missing_parameters"
            }
            EventType::MailAuth(MailAuthEvent::NoHeadersFound) => {
                "stalwart.mail_auth.no_headers_found"
            }
            EventType::MailAuth(MailAuthEvent::Crypto) => "stalwart.mail_auth.crypto",
            EventType::MailAuth(MailAuthEvent::Io) => "stalwart.mail_auth.io",
            EventType::MailAuth(MailAuthEvent::Base64) => "stalwart.mail_auth.base64",
            EventType::MailAuth(MailAuthEvent::DnsError) => "stalwart.mail_auth.dns_error",
            EventType::MailAuth(MailAuthEvent::DnsRecordNotFound) => {
                "stalwart.mail_auth.dns_record_not_found"
            }
            EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType) => {
                "stalwart.mail_auth.dns_invalid_record_type"
            }
            EventType::MailAuth(MailAuthEvent::PolicyNotAligned) => {
                "stalwart.mail_auth.policy_not_aligned"
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => {
                "stalwart.manage_sieve.connection_start"
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => {
                "stalwart.manage_sieve.connection_end"
            }
            EventType::MessageIngest(MessageIngestEvent::Ham) => "stalwart.message_ingest.ham",
            EventType::MessageIngest(MessageIngestEvent::Spam) => "stalwart.message_ingest.spam",
            EventType::MessageIngest(MessageIngestEvent::ImapAppend) => {
                "stalwart.message_ingest.imap_append"
            }
            EventType::MessageIngest(MessageIngestEvent::JmapAppend) => {
                "stalwart.message_ingest.jmap_append"
            }
            EventType::MessageIngest(MessageIngestEvent::Duplicate) => {
                "stalwart.message_ingest.duplicate"
            }
            EventType::MessageIngest(MessageIngestEvent::Error) => "stalwart.message_ingest.error",
            EventType::Milter(MilterEvent::ActionAccept) => "stalwart.milter.action_accept",
            EventType::Milter(MilterEvent::ActionDiscard) => "stalwart.milter.action_discard",
            EventType::Milter(MilterEvent::ActionReject) => "stalwart.milter.action_reject",
            EventType::Milter(MilterEvent::ActionTempFail) => "stalwart.milter.action_temp_fail",
            EventType::Milter(MilterEvent::ActionReplyCode) => "stalwart.milter.action_reply_code",
            EventType::Milter(MilterEvent::ActionConnectionFailure) => {
                "stalwart.milter.action_connection_failure"
            }
            EventType::Milter(MilterEvent::ActionShutdown) => "stalwart.milter.action_shutdown",
            EventType::MtaHook(MtaHookEvent::ActionAccept) => "stalwart.mta_hook.action_accept",
            EventType::MtaHook(MtaHookEvent::ActionDiscard) => "stalwart.mta_hook.action_discard",
            EventType::MtaHook(MtaHookEvent::ActionReject) => "stalwart.mta_hook.action_reject",
            EventType::MtaHook(MtaHookEvent::ActionQuarantine) => {
                "stalwart.mta_hook.action_quarantine"
            }
            EventType::MtaHook(MtaHookEvent::Error) => "stalwart.mta_hook.error",
            EventType::MtaSts(MtaStsEvent::Authorized) => "stalwart.mta_sts.authorized",
            EventType::MtaSts(MtaStsEvent::NotAuthorized) => "stalwart.mta_sts.not_authorized",
            EventType::MtaSts(MtaStsEvent::InvalidPolicy) => "stalwart.mta_sts.invalid_policy",
            EventType::Network(NetworkEvent::Timeout) => "stalwart.network.timeout",
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport) => {
                "stalwart.outgoing_report.spf_report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited) => {
                "stalwart.outgoing_report.spf_rate_limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport) => {
                "stalwart.outgoing_report.dkim_report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited) => {
                "stalwart.outgoing_report.dkim_rate_limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport) => {
                "stalwart.outgoing_report.dmarc_report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited) => {
                "stalwart.outgoing_report.dmarc_rate_limited"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport) => {
                "stalwart.outgoing_report.dmarc_aggregate_report"
            }
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate) => {
                "stalwart.outgoing_report.tls_aggregate"
            }
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission) => {
                "stalwart.outgoing_report.http_submission"
            }
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress) => {
                "stalwart.outgoing_report.unauthorized_reporting_address"
            }
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError) => {
                "stalwart.outgoing_report.reporting_address_validation_error"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NotFound) => {
                "stalwart.outgoing_report.not_found"
            }
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError) => {
                "stalwart.outgoing_report.submission_error"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound) => {
                "stalwart.outgoing_report.no_recipients_found"
            }
            EventType::Pop3(Pop3Event::ConnectionStart) => "stalwart.pop3.connection_start",
            EventType::Pop3(Pop3Event::ConnectionEnd) => "stalwart.pop3.connection_end",
            EventType::PushSubscription(PushSubscriptionEvent::Success) => {
                "stalwart.push_subscription.success"
            }
            EventType::PushSubscription(PushSubscriptionEvent::Error) => {
                "stalwart.push_subscription.error"
            }
            EventType::PushSubscription(PushSubscriptionEvent::NotFound) => {
                "stalwart.push_subscription.not_found"
            }
            EventType::Queue(QueueEvent::MessageQueued) => "stalwart.queue.message_queued",
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued) => {
                "stalwart.queue.authenticated_message_queued"
            }
            EventType::Queue(QueueEvent::ReportQueued) => "stalwart.queue.report_queued",
            EventType::Queue(QueueEvent::DsnQueued) => "stalwart.queue.dsn_queued",
            EventType::Queue(QueueEvent::AutogeneratedQueued) => {
                "stalwart.queue.autogenerated_queued"
            }
            EventType::Queue(QueueEvent::Rescheduled) => "stalwart.queue.rescheduled",
            EventType::Queue(QueueEvent::BlobNotFound) => "stalwart.queue.blob_not_found",
            EventType::Queue(QueueEvent::RateLimitExceeded) => "stalwart.queue.rate_limit_exceeded",
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded) => {
                "stalwart.queue.concurrency_limit_exceeded"
            }
            EventType::Queue(QueueEvent::QuotaExceeded) => "stalwart.queue.quota_exceeded",
            EventType::Queue(QueueEvent::BackPressure) => "stalwart.queue.back_pressure",
            EventType::Resource(ResourceEvent::NotFound) => "stalwart.resource.not_found",
            EventType::Resource(ResourceEvent::BadParameters) => "stalwart.resource.bad_parameters",
            EventType::Resource(ResourceEvent::Error) => "stalwart.resource.error",
            EventType::SearchIndex(SearchIndexEvent::PartitionRetry) => {
                "stalwart.search_index.partition_retry"
            }
            EventType::SearchIndex(SearchIndexEvent::BatchIndexed) => {
                "stalwart.search_index.batch_indexed"
            }
            EventType::SearchIndex(SearchIndexEvent::DocumentTruncated) => {
                "stalwart.search_index.document_truncated"
            }
            EventType::Security(SecurityEvent::AuthenticationBan) => {
                "stalwart.security.authentication_ban"
            }
            EventType::Security(SecurityEvent::AbuseBan) => "stalwart.security.abuse_ban",
            EventType::Security(SecurityEvent::ScanBan) => "stalwart.security.scan_ban",
            EventType::Security(SecurityEvent::LoiterBan) => "stalwart.security.loiter_ban",
            EventType::Security(SecurityEvent::IpBlocked) => "stalwart.security.ip_blocked",
            EventType::Security(SecurityEvent::Unauthorized) => "stalwart.security.unauthorized",
            EventType::Server(ServerEvent::ThreadError) => "stalwart.server.thread_error",
            EventType::Sieve(SieveEvent::ActionAccept) => "stalwart.sieve.action_accept",
            EventType::Sieve(SieveEvent::ActionAcceptReplace) => {
                "stalwart.sieve.action_accept_replace"
            }
            EventType::Sieve(SieveEvent::ActionDiscard) => "stalwart.sieve.action_discard",
            EventType::Sieve(SieveEvent::ActionReject) => "stalwart.sieve.action_reject",
            EventType::Sieve(SieveEvent::SendMessage) => "stalwart.sieve.send_message",
            EventType::Sieve(SieveEvent::MessageTooLarge) => "stalwart.sieve.message_too_large",
            EventType::Sieve(SieveEvent::RuntimeError) => "stalwart.sieve.runtime_error",
            EventType::Sieve(SieveEvent::UnexpectedError) => "stalwart.sieve.unexpected_error",
            EventType::Sieve(SieveEvent::NotSupported) => "stalwart.sieve.not_supported",
            EventType::Sieve(SieveEvent::QuotaExceeded) => "stalwart.sieve.quota_exceeded",
            EventType::Smtp(SmtpEvent::ConnectionStart) => "stalwart.smtp.connection_start",
            EventType::Smtp(SmtpEvent::ConnectionEnd) => "stalwart.smtp.connection_end",
            EventType::Smtp(SmtpEvent::Error) => "stalwart.smtp.error",
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => {
                "stalwart.smtp.concurrency_limit_exceeded"
            }
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => {
                "stalwart.smtp.transfer_limit_exceeded"
            }
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => "stalwart.smtp.rate_limit_exceeded",
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => "stalwart.smtp.time_limit_exceeded",
            EventType::Smtp(SmtpEvent::MessageParseFailed) => "stalwart.smtp.message_parse_failed",
            EventType::Smtp(SmtpEvent::MessageTooLarge) => "stalwart.smtp.message_too_large",
            EventType::Smtp(SmtpEvent::LoopDetected) => "stalwart.smtp.loop_detected",
            EventType::Smtp(SmtpEvent::MultipleFromDomains) => {
                "stalwart.smtp.multiple_from_domains"
            }
            EventType::Smtp(SmtpEvent::DkimPass) => "stalwart.smtp.dkim_pass",
            EventType::Smtp(SmtpEvent::DkimFail) => "stalwart.smtp.dkim_fail",
            EventType::Smtp(SmtpEvent::Dkim2Pass) => "stalwart.smtp.dkim2_pass",
            EventType::Smtp(SmtpEvent::Dkim2Fail) => "stalwart.smtp.dkim2_fail",
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected) => "stalwart.smtp.dkim2_dsn_rejected",
            EventType::Smtp(SmtpEvent::ArcPass) => "stalwart.smtp.arc_pass",
            EventType::Smtp(SmtpEvent::ArcFail) => "stalwart.smtp.arc_fail",
            EventType::Smtp(SmtpEvent::SpfEhloPass) => "stalwart.smtp.spf_ehlo_pass",
            EventType::Smtp(SmtpEvent::SpfEhloFail) => "stalwart.smtp.spf_ehlo_fail",
            EventType::Smtp(SmtpEvent::SpfFromPass) => "stalwart.smtp.spf_from_pass",
            EventType::Smtp(SmtpEvent::SpfFromFail) => "stalwart.smtp.spf_from_fail",
            EventType::Smtp(SmtpEvent::DmarcPass) => "stalwart.smtp.dmarc_pass",
            EventType::Smtp(SmtpEvent::DmarcFail) => "stalwart.smtp.dmarc_fail",
            EventType::Smtp(SmtpEvent::IprevPass) => "stalwart.smtp.iprev_pass",
            EventType::Smtp(SmtpEvent::IprevFail) => "stalwart.smtp.iprev_fail",
            EventType::Smtp(SmtpEvent::TooManyMessages) => "stalwart.smtp.too_many_messages",
            EventType::Smtp(SmtpEvent::InvalidEhlo) => "stalwart.smtp.invalid_ehlo",
            EventType::Smtp(SmtpEvent::DidNotSayEhlo) => "stalwart.smtp.did_not_say_ehlo",
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated) => {
                "stalwart.smtp.mail_from_unauthenticated"
            }
            EventType::Smtp(SmtpEvent::MailFromUnauthorized) => {
                "stalwart.smtp.mail_from_unauthorized"
            }
            EventType::Smtp(SmtpEvent::MailFromMissing) => "stalwart.smtp.mail_from_missing",
            EventType::Smtp(SmtpEvent::MultipleMailFrom) => "stalwart.smtp.multiple_mail_from",
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => {
                "stalwart.smtp.mailbox_does_not_exist"
            }
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => "stalwart.smtp.relay_not_allowed",
            EventType::Smtp(SmtpEvent::RcptToDuplicate) => "stalwart.smtp.rcpt_to_duplicate",
            EventType::Smtp(SmtpEvent::RcptToMissing) => "stalwart.smtp.rcpt_to_missing",
            EventType::Smtp(SmtpEvent::TooManyRecipients) => "stalwart.smtp.too_many_recipients",
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => "stalwart.smtp.too_many_invalid_rcpt",
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => {
                "stalwart.smtp.auth_mechanism_not_supported"
            }
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong) => {
                "stalwart.smtp.auth_exchange_too_long"
            }
            EventType::Smtp(SmtpEvent::CommandNotImplemented) => {
                "stalwart.smtp.command_not_implemented"
            }
            EventType::Smtp(SmtpEvent::InvalidCommand) => "stalwart.smtp.invalid_command",
            EventType::Smtp(SmtpEvent::SyntaxError) => "stalwart.smtp.syntax_error",
            EventType::Smtp(SmtpEvent::RequestTooLarge) => "stalwart.smtp.request_too_large",
            EventType::Spam(SpamEvent::PyzorError) => "stalwart.spam.pyzor_error",
            EventType::Spam(SpamEvent::DnsblError) => "stalwart.spam.dnsbl_error",
            EventType::Spam(SpamEvent::TrainCompleted) => "stalwart.spam.train_completed",
            EventType::Spam(SpamEvent::TrainSampleAdded) => "stalwart.spam.train_sample_added",
            EventType::Spam(SpamEvent::Classify) => "stalwart.spam.classify",
            EventType::Spam(SpamEvent::ModelNotReady) => "stalwart.spam.model_not_ready",
            EventType::Spf(SpfEvent::Pass) => "stalwart.spf.pass",
            EventType::Spf(SpfEvent::Fail) => "stalwart.spf.fail",
            EventType::Spf(SpfEvent::SoftFail) => "stalwart.spf.soft_fail",
            EventType::Spf(SpfEvent::Neutral) => "stalwart.spf.neutral",
            EventType::Spf(SpfEvent::TempError) => "stalwart.spf.temp_error",
            EventType::Spf(SpfEvent::PermError) => "stalwart.spf.perm_error",
            EventType::Spf(SpfEvent::None) => "stalwart.spf.none",
            EventType::Store(StoreEvent::AssertValueFailed) => "stalwart.store.assert_value_failed",
            EventType::Store(StoreEvent::FoundationdbError) => "stalwart.store.foundationdb_error",
            EventType::Store(StoreEvent::MysqlError) => "stalwart.store.mysql_error",
            EventType::Store(StoreEvent::PostgresqlError) => "stalwart.store.postgresql_error",
            EventType::Store(StoreEvent::RocksdbError) => "stalwart.store.rocksdb_error",
            EventType::Store(StoreEvent::SqliteError) => "stalwart.store.sqlite_error",
            EventType::Store(StoreEvent::LdapError) => "stalwart.store.ldap_error",
            EventType::Store(StoreEvent::ElasticsearchError) => {
                "stalwart.store.elasticsearch_error"
            }
            EventType::Store(StoreEvent::RedisError) => "stalwart.store.redis_error",
            EventType::Store(StoreEvent::S3Error) => "stalwart.store.s3_error",
            EventType::Store(StoreEvent::AzureError) => "stalwart.store.azure_error",
            EventType::Store(StoreEvent::FilesystemError) => "stalwart.store.filesystem_error",
            EventType::Store(StoreEvent::PoolError) => "stalwart.store.pool_error",
            EventType::Store(StoreEvent::DataCorruption) => "stalwart.store.data_corruption",
            EventType::Store(StoreEvent::DecompressError) => "stalwart.store.decompress_error",
            EventType::Store(StoreEvent::DeserializeError) => "stalwart.store.deserialize_error",
            EventType::Store(StoreEvent::NotFound) => "stalwart.store.not_found",
            EventType::Store(StoreEvent::NotConfigured) => "stalwart.store.not_configured",
            EventType::Store(StoreEvent::NotSupported) => "stalwart.store.not_supported",
            EventType::Store(StoreEvent::UnexpectedError) => "stalwart.store.unexpected_error",
            EventType::Store(StoreEvent::CryptoError) => "stalwart.store.crypto_error",
            EventType::Store(StoreEvent::HttpStoreError) => "stalwart.store.http_store_error",
            EventType::Store(StoreEvent::BlobMissingMarker) => "stalwart.store.blob_missing_marker",
            EventType::Store(StoreEvent::DataWrite) => "stalwart.store.data_write",
            EventType::Store(StoreEvent::DataIterate) => "stalwart.store.data_iterate",
            EventType::Store(StoreEvent::BlobRead) => "stalwart.store.blob_read",
            EventType::Store(StoreEvent::BlobWrite) => "stalwart.store.blob_write",
            EventType::Store(StoreEvent::BlobDelete) => "stalwart.store.blob_delete",
            EventType::TaskManager(TaskManagerEvent::TaskFailed) => {
                "stalwart.task_manager.task_failed"
            }
            EventType::TaskManager(TaskManagerEvent::TaskRetry) => {
                "stalwart.task_manager.task_retry"
            }
            EventType::TaskManager(TaskManagerEvent::TaskStalled) => {
                "stalwart.task_manager.task_stalled"
            }
            EventType::TaskManager(TaskManagerEvent::TaskExpired) => {
                "stalwart.task_manager.task_expired"
            }
            EventType::TaskManager(TaskManagerEvent::BlobNotFound) => {
                "stalwart.task_manager.blob_not_found"
            }
            EventType::TaskManager(TaskManagerEvent::MetadataNotFound) => {
                "stalwart.task_manager.metadata_not_found"
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertEvent) => "stalwart.telemetry.alert_event",
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertMessage) => {
                "stalwart.telemetry.alert_message"
            }
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::LogError) => "stalwart.telemetry.log_error",
            EventType::Telemetry(TelemetryEvent::WebhookError) => {
                "stalwart.telemetry.webhook_error"
            }
            EventType::Telemetry(TelemetryEvent::OtelExporterError) => {
                "stalwart.telemetry.otel_exporter_error"
            }
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError) => {
                "stalwart.telemetry.otel_metrics_exporter_error"
            }
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError) => {
                "stalwart.telemetry.prometheus_exporter_error"
            }
            EventType::Telemetry(TelemetryEvent::JournalError) => {
                "stalwart.telemetry.journal_error"
            }
            EventType::Telemetry(TelemetryEvent::EventsDropped) => {
                "stalwart.telemetry.events_dropped"
            }
            EventType::Tls(TlsEvent::HandshakeError) => "stalwart.tls.handshake_error",
            _ => "",
        }
    }

    pub fn prom_metric_name(&self) -> &'static str {
        match self {
            EventType::Acme(AcmeEvent::AuthError) => "stalwart_acme_auth_error_total",
            EventType::Acme(AcmeEvent::AuthTooManyAttempts) => {
                "stalwart_acme_auth_too_many_attempts_total"
            }
            EventType::Acme(AcmeEvent::OrderCompleted) => "stalwart_acme_order_completed_total",
            EventType::Acme(AcmeEvent::OrderInvalid) => "stalwart_acme_order_invalid_total",
            EventType::Acme(AcmeEvent::ClientMissingSni) => {
                "stalwart_acme_client_missing_sni_total"
            }
            EventType::Acme(AcmeEvent::TlsAlpnError) => "stalwart_acme_tls_alpn_error_total",
            EventType::Acme(AcmeEvent::TokenNotFound) => "stalwart_acme_token_not_found_total",
            EventType::Acme(AcmeEvent::Error) => "stalwart_acme_error_total",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::ApiError) => "stalwart_ai_api_error_total",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::Request) => "stalwart_ai_request_total",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamVerdict) => "stalwart_ai_spam_verdict_total",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamSkipped) => "stalwart_ai_spam_skipped_total",
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::BreakerOpen) => "stalwart_ai_breaker_open_total",
            // SPDX-SnippetEnd
            EventType::Arc(ArcEvent::ChainInvalid) => "stalwart_arc_chain_invalid_total",
            EventType::Arc(ArcEvent::SignatureInvalid) => "stalwart_arc_signature_invalid_total",
            EventType::Arc(ArcEvent::HashMismatch) => "stalwart_arc_hash_mismatch_total",
            EventType::Auth(AuthEvent::Success) => "stalwart_auth_success_total",
            EventType::Auth(AuthEvent::Failed) => "stalwart_auth_failed_total",
            EventType::Auth(AuthEvent::TooManyAttempts) => "stalwart_auth_too_many_attempts_total",
            EventType::Auth(AuthEvent::Error) => "stalwart_auth_error_total",
            EventType::Cache(CacheEvent::Miss) => "stalwart_cache_miss_total",
            EventType::Cache(CacheEvent::Hit) => "stalwart_cache_hit_total",
            EventType::Cache(CacheEvent::Stale) => "stalwart_cache_stale_total",
            EventType::Cache(CacheEvent::EntryTooLarge) => "stalwart_cache_entry_too_large_total",
            EventType::Cache(CacheEvent::SwapHit) => "stalwart_cache_swap_hit_total",
            EventType::Cache(CacheEvent::SwapMiss) => "stalwart_cache_swap_miss_total",
            EventType::Cache(CacheEvent::SwapWrite) => "stalwart_cache_swap_write_total",
            EventType::Cache(CacheEvent::SwapError) => "stalwart_cache_swap_error_total",
            EventType::Calendar(CalendarEvent::AlarmSent) => "stalwart_calendar_alarm_sent_total",
            EventType::Calendar(CalendarEvent::AlarmFailed) => {
                "stalwart_calendar_alarm_failed_total"
            }
            EventType::Calendar(CalendarEvent::ItipMessageSent) => {
                "stalwart_calendar_itip_message_sent_total"
            }
            EventType::Calendar(CalendarEvent::ItipMessageReceived) => {
                "stalwart_calendar_itip_message_received_total"
            }
            EventType::Calendar(CalendarEvent::ItipMessageError) => {
                "stalwart_calendar_itip_message_error_total"
            }
            EventType::Cluster(ClusterEvent::SubscriberError) => {
                "stalwart_cluster_subscriber_error_total"
            }
            EventType::Cluster(ClusterEvent::SubscriberDisconnected) => {
                "stalwart_cluster_subscriber_disconnected_total"
            }
            EventType::Cluster(ClusterEvent::PublisherError) => {
                "stalwart_cluster_publisher_error_total"
            }
            EventType::Dane(DaneEvent::AuthenticationSuccess) => {
                "stalwart_dane_authentication_success_total"
            }
            EventType::Dane(DaneEvent::AuthenticationFailure) => {
                "stalwart_dane_authentication_failure_total"
            }
            EventType::Dane(DaneEvent::NoCertificatesFound) => {
                "stalwart_dane_no_certificates_found_total"
            }
            EventType::Dane(DaneEvent::CertificateParseError) => {
                "stalwart_dane_certificate_parse_error_total"
            }
            EventType::Dane(DaneEvent::TlsaRecordFetchError) => {
                "stalwart_dane_tlsa_record_fetch_error_total"
            }
            EventType::Dane(DaneEvent::TlsaRecordNotFound) => {
                "stalwart_dane_tlsa_record_not_found_total"
            }
            EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned) => {
                "stalwart_dane_tlsa_record_not_dnssec_signed_total"
            }
            EventType::Dane(DaneEvent::TlsaRecordInvalid) => {
                "stalwart_dane_tlsa_record_invalid_total"
            }
            EventType::Dane(DaneEvent::BogusDnssecRecord) => {
                "stalwart_dane_bogus_dnssec_record_total"
            }
            EventType::Delivery(DeliveryEvent::AttemptStart) => {
                "stalwart_delivery_attempt_start_total"
            }
            EventType::Delivery(DeliveryEvent::AttemptEnd) => "stalwart_delivery_attempt_end_total",
            EventType::Delivery(DeliveryEvent::Completed) => "stalwart_delivery_completed_total",
            EventType::Delivery(DeliveryEvent::MxLookupFailed) => {
                "stalwart_delivery_mx_lookup_failed_total"
            }
            EventType::Delivery(DeliveryEvent::IpLookupFailed) => {
                "stalwart_delivery_ip_lookup_failed_total"
            }
            EventType::Delivery(DeliveryEvent::NullMx) => "stalwart_delivery_null_mx_total",
            EventType::Delivery(DeliveryEvent::GreetingFailed) => {
                "stalwart_delivery_greeting_failed_total"
            }
            EventType::Delivery(DeliveryEvent::EhloRejected) => {
                "stalwart_delivery_ehlo_rejected_total"
            }
            EventType::Delivery(DeliveryEvent::AuthFailed) => "stalwart_delivery_auth_failed_total",
            EventType::Delivery(DeliveryEvent::MailFromRejected) => {
                "stalwart_delivery_mail_from_rejected_total"
            }
            EventType::Delivery(DeliveryEvent::Delivered) => "stalwart_delivery_delivered_total",
            EventType::Delivery(DeliveryEvent::RcptToRejected) => {
                "stalwart_delivery_rcpt_to_rejected_total"
            }
            EventType::Delivery(DeliveryEvent::RcptToFailed) => {
                "stalwart_delivery_rcpt_to_failed_total"
            }
            EventType::Delivery(DeliveryEvent::MessageRejected) => {
                "stalwart_delivery_message_rejected_total"
            }
            EventType::Delivery(DeliveryEvent::StartTlsUnavailable) => {
                "stalwart_delivery_start_tls_unavailable_total"
            }
            EventType::Delivery(DeliveryEvent::StartTlsError) => {
                "stalwart_delivery_start_tls_error_total"
            }
            EventType::Delivery(DeliveryEvent::StartTlsDisabled) => {
                "stalwart_delivery_start_tls_disabled_total"
            }
            EventType::Delivery(DeliveryEvent::ImplicitTlsError) => {
                "stalwart_delivery_implicit_tls_error_total"
            }
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded) => {
                "stalwart_delivery_concurrency_limit_exceeded_total"
            }
            EventType::Delivery(DeliveryEvent::RateLimitExceeded) => {
                "stalwart_delivery_rate_limit_exceeded_total"
            }
            EventType::Delivery(DeliveryEvent::DoubleBounce) => {
                "stalwart_delivery_double_bounce_total"
            }
            EventType::Delivery(DeliveryEvent::DsnSuccess) => "stalwart_delivery_dsn_success_total",
            EventType::Delivery(DeliveryEvent::DsnTempFail) => {
                "stalwart_delivery_dsn_temp_fail_total"
            }
            EventType::Delivery(DeliveryEvent::DsnPermFail) => {
                "stalwart_delivery_dsn_perm_fail_total"
            }
            EventType::Dkim(DkimEvent::Pass) => "stalwart_dkim_pass_total",
            EventType::Dkim(DkimEvent::Neutral) => "stalwart_dkim_neutral_total",
            EventType::Dkim(DkimEvent::Fail) => "stalwart_dkim_fail_total",
            EventType::Dkim(DkimEvent::PermError) => "stalwart_dkim_perm_error_total",
            EventType::Dkim(DkimEvent::TempError) => "stalwart_dkim_temp_error_total",
            EventType::Dkim(DkimEvent::None) => "stalwart_dkim_none_total",
            EventType::Dkim(DkimEvent::SignatureInvalid) => "stalwart_dkim_signature_invalid_total",
            EventType::Dkim(DkimEvent::PublicKeyError) => "stalwart_dkim_public_key_error_total",
            EventType::Dkim(DkimEvent::VerificationFailed) => {
                "stalwart_dkim_verification_failed_total"
            }
            EventType::Dkim(DkimEvent::HashMismatch) => "stalwart_dkim_hash_mismatch_total",
            EventType::Dkim(DkimEvent::SignerNotFound) => "stalwart_dkim_signer_not_found_total",
            EventType::Dkim2(Dkim2Event::InstanceInvalid) => {
                "stalwart_dkim2_instance_invalid_total"
            }
            EventType::Dkim2(Dkim2Event::SignatureInvalid) => {
                "stalwart_dkim2_signature_invalid_total"
            }
            EventType::Dkim2(Dkim2Event::ChainInvalid) => "stalwart_dkim2_chain_invalid_total",
            EventType::Dkim2(Dkim2Event::TimestampInvalid) => {
                "stalwart_dkim2_timestamp_invalid_total"
            }
            EventType::Dkim2(Dkim2Event::EnvelopeMismatch) => {
                "stalwart_dkim2_envelope_mismatch_total"
            }
            EventType::Dkim2(Dkim2Event::CustodyBroken) => "stalwart_dkim2_custody_broken_total",
            EventType::Dkim2(Dkim2Event::PublicKeyError) => "stalwart_dkim2_public_key_error_total",
            EventType::Dkim2(Dkim2Event::VerificationFailed) => {
                "stalwart_dkim2_verification_failed_total"
            }
            EventType::Dkim2(Dkim2Event::HashMismatch) => "stalwart_dkim2_hash_mismatch_total",
            EventType::Dkim2(Dkim2Event::RecipeError) => "stalwart_dkim2_recipe_error_total",
            EventType::Dkim2(Dkim2Event::SigningFailed) => "stalwart_dkim2_signing_failed_total",
            EventType::Dmarc(DmarcEvent::Pass) => "stalwart_dmarc_pass_total",
            EventType::Dmarc(DmarcEvent::Fail) => "stalwart_dmarc_fail_total",
            EventType::Dmarc(DmarcEvent::PermError) => "stalwart_dmarc_perm_error_total",
            EventType::Dmarc(DmarcEvent::TempError) => "stalwart_dmarc_temp_error_total",
            EventType::Dmarc(DmarcEvent::None) => "stalwart_dmarc_none_total",
            EventType::Dns(DnsEvent::RecordCreationFailed) => {
                "stalwart_dns_record_creation_failed_total"
            }
            EventType::Dns(DnsEvent::RecordDeletionFailed) => {
                "stalwart_dns_record_deletion_failed_total"
            }
            EventType::Dns(DnsEvent::RecordLookupFailed) => {
                "stalwart_dns_record_lookup_failed_total"
            }
            EventType::Dns(DnsEvent::RecordPropagationTimeout) => {
                "stalwart_dns_record_propagation_timeout_total"
            }
            EventType::Eval(EvalEvent::Error) => "stalwart_eval_error_total",
            EventType::Eval(EvalEvent::DirectoryNotFound) => {
                "stalwart_eval_directory_not_found_total"
            }
            EventType::Eval(EvalEvent::StoreNotFound) => "stalwart_eval_store_not_found_total",
            EventType::Http(HttpEvent::ConnectionStart) => "stalwart_http_connection_start_total",
            EventType::Http(HttpEvent::Error) => "stalwart_http_error_total",
            EventType::Http(HttpEvent::RequestBody) => "stalwart_http_request_body_total",
            EventType::Http(HttpEvent::ResponseBody) => "stalwart_http_response_body_total",
            EventType::Http(HttpEvent::XForwardedMissing) => {
                "stalwart_http_x_forwarded_missing_total"
            }
            EventType::Http(HttpEvent::XForwardedInvalid) => {
                "stalwart_http_x_forwarded_invalid_total"
            }
            EventType::Imap(ImapEvent::ConnectionStart) => "stalwart_imap_connection_start_total",
            EventType::Imap(ImapEvent::ConnectionEnd) => "stalwart_imap_connection_end_total",
            EventType::IncomingReport(IncomingReportEvent::DmarcReport) => {
                "stalwart_incoming_report_dmarc_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings) => {
                "stalwart_incoming_report_dmarc_report_with_warnings_total"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsReport) => {
                "stalwart_incoming_report_tls_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings) => {
                "stalwart_incoming_report_tls_report_with_warnings_total"
            }
            EventType::IncomingReport(IncomingReportEvent::AbuseReport) => {
                "stalwart_incoming_report_abuse_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport) => {
                "stalwart_incoming_report_auth_failure_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::FraudReport) => {
                "stalwart_incoming_report_fraud_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport) => {
                "stalwart_incoming_report_not_spam_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::VirusReport) => {
                "stalwart_incoming_report_virus_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::OtherReport) => {
                "stalwart_incoming_report_other_report_total"
            }
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed) => {
                "stalwart_incoming_report_message_parse_failed_total"
            }
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed) => {
                "stalwart_incoming_report_dmarc_parse_failed_total"
            }
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed) => {
                "stalwart_incoming_report_tls_rpc_parse_failed_total"
            }
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed) => {
                "stalwart_incoming_report_arf_parse_failed_total"
            }
            EventType::IncomingReport(IncomingReportEvent::DecompressError) => {
                "stalwart_incoming_report_decompress_error_total"
            }
            EventType::Iprev(IprevEvent::Pass) => "stalwart_iprev_pass_total",
            EventType::Iprev(IprevEvent::Fail) => "stalwart_iprev_fail_total",
            EventType::Iprev(IprevEvent::PermError) => "stalwart_iprev_perm_error_total",
            EventType::Iprev(IprevEvent::TempError) => "stalwart_iprev_temp_error_total",
            EventType::Iprev(IprevEvent::None) => "stalwart_iprev_none_total",
            EventType::Jmap(JmapEvent::MethodCall) => "stalwart_jmap_method_call_total",
            EventType::Jmap(JmapEvent::InvalidArguments) => "stalwart_jmap_invalid_arguments_total",
            EventType::Jmap(JmapEvent::RequestTooLarge) => "stalwart_jmap_request_too_large_total",
            EventType::Jmap(JmapEvent::UnsupportedFilter) => {
                "stalwart_jmap_unsupported_filter_total"
            }
            EventType::Jmap(JmapEvent::UnsupportedSort) => "stalwart_jmap_unsupported_sort_total",
            EventType::Jmap(JmapEvent::UnknownMethod) => "stalwart_jmap_unknown_method_total",
            EventType::Jmap(JmapEvent::Forbidden) => "stalwart_jmap_forbidden_total",
            EventType::Jmap(JmapEvent::NotJson) => "stalwart_jmap_not_json_total",
            EventType::Jmap(JmapEvent::NotRequest) => "stalwart_jmap_not_request_total",
            EventType::Jmap(JmapEvent::WebsocketStart) => "stalwart_jmap_websocket_start_total",
            EventType::Jmap(JmapEvent::WebsocketError) => "stalwart_jmap_websocket_error_total",
            EventType::Limit(LimitEvent::SizeRequest) => "stalwart_limit_size_request_total",
            EventType::Limit(LimitEvent::SizeUpload) => "stalwart_limit_size_upload_total",
            EventType::Limit(LimitEvent::CallsIn) => "stalwart_limit_calls_in_total",
            EventType::Limit(LimitEvent::ConcurrentRequest) => {
                "stalwart_limit_concurrent_request_total"
            }
            EventType::Limit(LimitEvent::ConcurrentUpload) => {
                "stalwart_limit_concurrent_upload_total"
            }
            EventType::Limit(LimitEvent::ConcurrentConnection) => {
                "stalwart_limit_concurrent_connection_total"
            }
            EventType::Limit(LimitEvent::Quota) => "stalwart_limit_quota_total",
            EventType::Limit(LimitEvent::BlobQuota) => "stalwart_limit_blob_quota_total",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => "stalwart_limit_tenant_quota_total",
            // SPDX-SnippetEnd
            EventType::Limit(LimitEvent::TooManyRequests) => {
                "stalwart_limit_too_many_requests_total"
            }
            EventType::Limit(LimitEvent::MemoryBudget) => "stalwart_limit_memory_budget_total",
            EventType::MailAuth(MailAuthEvent::ParseError) => {
                "stalwart_mail_auth_parse_error_total"
            }
            EventType::MailAuth(MailAuthEvent::MissingParameters) => {
                "stalwart_mail_auth_missing_parameters_total"
            }
            EventType::MailAuth(MailAuthEvent::NoHeadersFound) => {
                "stalwart_mail_auth_no_headers_found_total"
            }
            EventType::MailAuth(MailAuthEvent::Crypto) => "stalwart_mail_auth_crypto_total",
            EventType::MailAuth(MailAuthEvent::Io) => "stalwart_mail_auth_io_total",
            EventType::MailAuth(MailAuthEvent::Base64) => "stalwart_mail_auth_base64_total",
            EventType::MailAuth(MailAuthEvent::DnsError) => "stalwart_mail_auth_dns_error_total",
            EventType::MailAuth(MailAuthEvent::DnsRecordNotFound) => {
                "stalwart_mail_auth_dns_record_not_found_total"
            }
            EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType) => {
                "stalwart_mail_auth_dns_invalid_record_type_total"
            }
            EventType::MailAuth(MailAuthEvent::PolicyNotAligned) => {
                "stalwart_mail_auth_policy_not_aligned_total"
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => {
                "stalwart_manage_sieve_connection_start_total"
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => {
                "stalwart_manage_sieve_connection_end_total"
            }
            EventType::MessageIngest(MessageIngestEvent::Ham) => {
                "stalwart_message_ingest_ham_total"
            }
            EventType::MessageIngest(MessageIngestEvent::Spam) => {
                "stalwart_message_ingest_spam_total"
            }
            EventType::MessageIngest(MessageIngestEvent::ImapAppend) => {
                "stalwart_message_ingest_imap_append_total"
            }
            EventType::MessageIngest(MessageIngestEvent::JmapAppend) => {
                "stalwart_message_ingest_jmap_append_total"
            }
            EventType::MessageIngest(MessageIngestEvent::Duplicate) => {
                "stalwart_message_ingest_duplicate_total"
            }
            EventType::MessageIngest(MessageIngestEvent::Error) => {
                "stalwart_message_ingest_error_total"
            }
            EventType::Milter(MilterEvent::ActionAccept) => "stalwart_milter_action_accept_total",
            EventType::Milter(MilterEvent::ActionDiscard) => "stalwart_milter_action_discard_total",
            EventType::Milter(MilterEvent::ActionReject) => "stalwart_milter_action_reject_total",
            EventType::Milter(MilterEvent::ActionTempFail) => {
                "stalwart_milter_action_temp_fail_total"
            }
            EventType::Milter(MilterEvent::ActionReplyCode) => {
                "stalwart_milter_action_reply_code_total"
            }
            EventType::Milter(MilterEvent::ActionConnectionFailure) => {
                "stalwart_milter_action_connection_failure_total"
            }
            EventType::Milter(MilterEvent::ActionShutdown) => {
                "stalwart_milter_action_shutdown_total"
            }
            EventType::MtaHook(MtaHookEvent::ActionAccept) => {
                "stalwart_mta_hook_action_accept_total"
            }
            EventType::MtaHook(MtaHookEvent::ActionDiscard) => {
                "stalwart_mta_hook_action_discard_total"
            }
            EventType::MtaHook(MtaHookEvent::ActionReject) => {
                "stalwart_mta_hook_action_reject_total"
            }
            EventType::MtaHook(MtaHookEvent::ActionQuarantine) => {
                "stalwart_mta_hook_action_quarantine_total"
            }
            EventType::MtaHook(MtaHookEvent::Error) => "stalwart_mta_hook_error_total",
            EventType::MtaSts(MtaStsEvent::Authorized) => "stalwart_mta_sts_authorized_total",
            EventType::MtaSts(MtaStsEvent::NotAuthorized) => {
                "stalwart_mta_sts_not_authorized_total"
            }
            EventType::MtaSts(MtaStsEvent::InvalidPolicy) => {
                "stalwart_mta_sts_invalid_policy_total"
            }
            EventType::Network(NetworkEvent::Timeout) => "stalwart_network_timeout_total",
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport) => {
                "stalwart_outgoing_report_spf_report_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited) => {
                "stalwart_outgoing_report_spf_rate_limited_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport) => {
                "stalwart_outgoing_report_dkim_report_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited) => {
                "stalwart_outgoing_report_dkim_rate_limited_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport) => {
                "stalwart_outgoing_report_dmarc_report_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited) => {
                "stalwart_outgoing_report_dmarc_rate_limited_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport) => {
                "stalwart_outgoing_report_dmarc_aggregate_report_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate) => {
                "stalwart_outgoing_report_tls_aggregate_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission) => {
                "stalwart_outgoing_report_http_submission_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress) => {
                "stalwart_outgoing_report_unauthorized_reporting_address_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError) => {
                "stalwart_outgoing_report_reporting_address_validation_error_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NotFound) => {
                "stalwart_outgoing_report_not_found_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError) => {
                "stalwart_outgoing_report_submission_error_total"
            }
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound) => {
                "stalwart_outgoing_report_no_recipients_found_total"
            }
            EventType::Pop3(Pop3Event::ConnectionStart) => "stalwart_pop3_connection_start_total",
            EventType::Pop3(Pop3Event::ConnectionEnd) => "stalwart_pop3_connection_end_total",
            EventType::PushSubscription(PushSubscriptionEvent::Success) => {
                "stalwart_push_subscription_success_total"
            }
            EventType::PushSubscription(PushSubscriptionEvent::Error) => {
                "stalwart_push_subscription_error_total"
            }
            EventType::PushSubscription(PushSubscriptionEvent::NotFound) => {
                "stalwart_push_subscription_not_found_total"
            }
            EventType::Queue(QueueEvent::MessageQueued) => "stalwart_queue_message_queued_total",
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued) => {
                "stalwart_queue_authenticated_message_queued_total"
            }
            EventType::Queue(QueueEvent::ReportQueued) => "stalwart_queue_report_queued_total",
            EventType::Queue(QueueEvent::DsnQueued) => "stalwart_queue_dsn_queued_total",
            EventType::Queue(QueueEvent::AutogeneratedQueued) => {
                "stalwart_queue_autogenerated_queued_total"
            }
            EventType::Queue(QueueEvent::Rescheduled) => "stalwart_queue_rescheduled_total",
            EventType::Queue(QueueEvent::BlobNotFound) => "stalwart_queue_blob_not_found_total",
            EventType::Queue(QueueEvent::RateLimitExceeded) => {
                "stalwart_queue_rate_limit_exceeded_total"
            }
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded) => {
                "stalwart_queue_concurrency_limit_exceeded_total"
            }
            EventType::Queue(QueueEvent::QuotaExceeded) => "stalwart_queue_quota_exceeded_total",
            EventType::Queue(QueueEvent::BackPressure) => "stalwart_queue_back_pressure_total",
            EventType::Resource(ResourceEvent::NotFound) => "stalwart_resource_not_found_total",
            EventType::Resource(ResourceEvent::BadParameters) => {
                "stalwart_resource_bad_parameters_total"
            }
            EventType::Resource(ResourceEvent::Error) => "stalwart_resource_error_total",
            EventType::SearchIndex(SearchIndexEvent::PartitionRetry) => {
                "stalwart_search_index_partition_retry_total"
            }
            EventType::SearchIndex(SearchIndexEvent::BatchIndexed) => {
                "stalwart_search_index_batch_indexed_total"
            }
            EventType::SearchIndex(SearchIndexEvent::DocumentTruncated) => {
                "stalwart_search_index_document_truncated_total"
            }
            EventType::Security(SecurityEvent::AuthenticationBan) => {
                "stalwart_security_authentication_ban_total"
            }
            EventType::Security(SecurityEvent::AbuseBan) => "stalwart_security_abuse_ban_total",
            EventType::Security(SecurityEvent::ScanBan) => "stalwart_security_scan_ban_total",
            EventType::Security(SecurityEvent::LoiterBan) => "stalwart_security_loiter_ban_total",
            EventType::Security(SecurityEvent::IpBlocked) => "stalwart_security_ip_blocked_total",
            EventType::Security(SecurityEvent::Unauthorized) => {
                "stalwart_security_unauthorized_total"
            }
            EventType::Server(ServerEvent::ThreadError) => "stalwart_server_thread_error_total",
            EventType::Sieve(SieveEvent::ActionAccept) => "stalwart_sieve_action_accept_total",
            EventType::Sieve(SieveEvent::ActionAcceptReplace) => {
                "stalwart_sieve_action_accept_replace_total"
            }
            EventType::Sieve(SieveEvent::ActionDiscard) => "stalwart_sieve_action_discard_total",
            EventType::Sieve(SieveEvent::ActionReject) => "stalwart_sieve_action_reject_total",
            EventType::Sieve(SieveEvent::SendMessage) => "stalwart_sieve_send_message_total",
            EventType::Sieve(SieveEvent::MessageTooLarge) => {
                "stalwart_sieve_message_too_large_total"
            }
            EventType::Sieve(SieveEvent::RuntimeError) => "stalwart_sieve_runtime_error_total",
            EventType::Sieve(SieveEvent::UnexpectedError) => {
                "stalwart_sieve_unexpected_error_total"
            }
            EventType::Sieve(SieveEvent::NotSupported) => "stalwart_sieve_not_supported_total",
            EventType::Sieve(SieveEvent::QuotaExceeded) => "stalwart_sieve_quota_exceeded_total",
            EventType::Smtp(SmtpEvent::ConnectionStart) => "stalwart_smtp_connection_start_total",
            EventType::Smtp(SmtpEvent::ConnectionEnd) => "stalwart_smtp_connection_end_total",
            EventType::Smtp(SmtpEvent::Error) => "stalwart_smtp_error_total",
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => {
                "stalwart_smtp_concurrency_limit_exceeded_total"
            }
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => {
                "stalwart_smtp_transfer_limit_exceeded_total"
            }
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => {
                "stalwart_smtp_rate_limit_exceeded_total"
            }
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => {
                "stalwart_smtp_time_limit_exceeded_total"
            }
            EventType::Smtp(SmtpEvent::MessageParseFailed) => {
                "stalwart_smtp_message_parse_failed_total"
            }
            EventType::Smtp(SmtpEvent::MessageTooLarge) => "stalwart_smtp_message_too_large_total",
            EventType::Smtp(SmtpEvent::LoopDetected) => "stalwart_smtp_loop_detected_total",
            EventType::Smtp(SmtpEvent::MultipleFromDomains) => {
                "stalwart_smtp_multiple_from_domains_total"
            }
            EventType::Smtp(SmtpEvent::DkimPass) => "stalwart_smtp_dkim_pass_total",
            EventType::Smtp(SmtpEvent::DkimFail) => "stalwart_smtp_dkim_fail_total",
            EventType::Smtp(SmtpEvent::Dkim2Pass) => "stalwart_smtp_dkim2_pass_total",
            EventType::Smtp(SmtpEvent::Dkim2Fail) => "stalwart_smtp_dkim2_fail_total",
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected) => {
                "stalwart_smtp_dkim2_dsn_rejected_total"
            }
            EventType::Smtp(SmtpEvent::ArcPass) => "stalwart_smtp_arc_pass_total",
            EventType::Smtp(SmtpEvent::ArcFail) => "stalwart_smtp_arc_fail_total",
            EventType::Smtp(SmtpEvent::SpfEhloPass) => "stalwart_smtp_spf_ehlo_pass_total",
            EventType::Smtp(SmtpEvent::SpfEhloFail) => "stalwart_smtp_spf_ehlo_fail_total",
            EventType::Smtp(SmtpEvent::SpfFromPass) => "stalwart_smtp_spf_from_pass_total",
            EventType::Smtp(SmtpEvent::SpfFromFail) => "stalwart_smtp_spf_from_fail_total",
            EventType::Smtp(SmtpEvent::DmarcPass) => "stalwart_smtp_dmarc_pass_total",
            EventType::Smtp(SmtpEvent::DmarcFail) => "stalwart_smtp_dmarc_fail_total",
            EventType::Smtp(SmtpEvent::IprevPass) => "stalwart_smtp_iprev_pass_total",
            EventType::Smtp(SmtpEvent::IprevFail) => "stalwart_smtp_iprev_fail_total",
            EventType::Smtp(SmtpEvent::TooManyMessages) => "stalwart_smtp_too_many_messages_total",
            EventType::Smtp(SmtpEvent::InvalidEhlo) => "stalwart_smtp_invalid_ehlo_total",
            EventType::Smtp(SmtpEvent::DidNotSayEhlo) => "stalwart_smtp_did_not_say_ehlo_total",
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated) => {
                "stalwart_smtp_mail_from_unauthenticated_total"
            }
            EventType::Smtp(SmtpEvent::MailFromUnauthorized) => {
                "stalwart_smtp_mail_from_unauthorized_total"
            }
            EventType::Smtp(SmtpEvent::MailFromMissing) => "stalwart_smtp_mail_from_missing_total",
            EventType::Smtp(SmtpEvent::MultipleMailFrom) => {
                "stalwart_smtp_multiple_mail_from_total"
            }
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => {
                "stalwart_smtp_mailbox_does_not_exist_total"
            }
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => "stalwart_smtp_relay_not_allowed_total",
            EventType::Smtp(SmtpEvent::RcptToDuplicate) => "stalwart_smtp_rcpt_to_duplicate_total",
            EventType::Smtp(SmtpEvent::RcptToMissing) => "stalwart_smtp_rcpt_to_missing_total",
            EventType::Smtp(SmtpEvent::TooManyRecipients) => {
                "stalwart_smtp_too_many_recipients_total"
            }
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => {
                "stalwart_smtp_too_many_invalid_rcpt_total"
            }
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => {
                "stalwart_smtp_auth_mechanism_not_supported_total"
            }
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong) => {
                "stalwart_smtp_auth_exchange_too_long_total"
            }
            EventType::Smtp(SmtpEvent::CommandNotImplemented) => {
                "stalwart_smtp_command_not_implemented_total"
            }
            EventType::Smtp(SmtpEvent::InvalidCommand) => "stalwart_smtp_invalid_command_total",
            EventType::Smtp(SmtpEvent::SyntaxError) => "stalwart_smtp_syntax_error_total",
            EventType::Smtp(SmtpEvent::RequestTooLarge) => "stalwart_smtp_request_too_large_total",
            EventType::Spam(SpamEvent::PyzorError) => "stalwart_spam_pyzor_error_total",
            EventType::Spam(SpamEvent::DnsblError) => "stalwart_spam_dnsbl_error_total",
            EventType::Spam(SpamEvent::TrainCompleted) => "stalwart_spam_train_completed_total",
            EventType::Spam(SpamEvent::TrainSampleAdded) => {
                "stalwart_spam_train_sample_added_total"
            }
            EventType::Spam(SpamEvent::Classify) => "stalwart_spam_classify_total",
            EventType::Spam(SpamEvent::ModelNotReady) => "stalwart_spam_model_not_ready_total",
            EventType::Spf(SpfEvent::Pass) => "stalwart_spf_pass_total",
            EventType::Spf(SpfEvent::Fail) => "stalwart_spf_fail_total",
            EventType::Spf(SpfEvent::SoftFail) => "stalwart_spf_soft_fail_total",
            EventType::Spf(SpfEvent::Neutral) => "stalwart_spf_neutral_total",
            EventType::Spf(SpfEvent::TempError) => "stalwart_spf_temp_error_total",
            EventType::Spf(SpfEvent::PermError) => "stalwart_spf_perm_error_total",
            EventType::Spf(SpfEvent::None) => "stalwart_spf_none_total",
            EventType::Store(StoreEvent::AssertValueFailed) => {
                "stalwart_store_assert_value_failed_total"
            }
            EventType::Store(StoreEvent::FoundationdbError) => {
                "stalwart_store_foundationdb_error_total"
            }
            EventType::Store(StoreEvent::MysqlError) => "stalwart_store_mysql_error_total",
            EventType::Store(StoreEvent::PostgresqlError) => {
                "stalwart_store_postgresql_error_total"
            }
            EventType::Store(StoreEvent::RocksdbError) => "stalwart_store_rocksdb_error_total",
            EventType::Store(StoreEvent::SqliteError) => "stalwart_store_sqlite_error_total",
            EventType::Store(StoreEvent::LdapError) => "stalwart_store_ldap_error_total",
            EventType::Store(StoreEvent::ElasticsearchError) => {
                "stalwart_store_elasticsearch_error_total"
            }
            EventType::Store(StoreEvent::RedisError) => "stalwart_store_redis_error_total",
            EventType::Store(StoreEvent::S3Error) => "stalwart_store_s3_error_total",
            EventType::Store(StoreEvent::AzureError) => "stalwart_store_azure_error_total",
            EventType::Store(StoreEvent::FilesystemError) => {
                "stalwart_store_filesystem_error_total"
            }
            EventType::Store(StoreEvent::PoolError) => "stalwart_store_pool_error_total",
            EventType::Store(StoreEvent::DataCorruption) => "stalwart_store_data_corruption_total",
            EventType::Store(StoreEvent::DecompressError) => {
                "stalwart_store_decompress_error_total"
            }
            EventType::Store(StoreEvent::DeserializeError) => {
                "stalwart_store_deserialize_error_total"
            }
            EventType::Store(StoreEvent::NotFound) => "stalwart_store_not_found_total",
            EventType::Store(StoreEvent::NotConfigured) => "stalwart_store_not_configured_total",
            EventType::Store(StoreEvent::NotSupported) => "stalwart_store_not_supported_total",
            EventType::Store(StoreEvent::UnexpectedError) => {
                "stalwart_store_unexpected_error_total"
            }
            EventType::Store(StoreEvent::CryptoError) => "stalwart_store_crypto_error_total",
            EventType::Store(StoreEvent::HttpStoreError) => "stalwart_store_http_store_error_total",
            EventType::Store(StoreEvent::BlobMissingMarker) => {
                "stalwart_store_blob_missing_marker_total"
            }
            EventType::Store(StoreEvent::DataWrite) => "stalwart_store_data_write_total",
            EventType::Store(StoreEvent::DataIterate) => "stalwart_store_data_iterate_total",
            EventType::Store(StoreEvent::BlobRead) => "stalwart_store_blob_read_total",
            EventType::Store(StoreEvent::BlobWrite) => "stalwart_store_blob_write_total",
            EventType::Store(StoreEvent::BlobDelete) => "stalwart_store_blob_delete_total",
            EventType::TaskManager(TaskManagerEvent::TaskFailed) => {
                "stalwart_task_manager_task_failed_total"
            }
            EventType::TaskManager(TaskManagerEvent::TaskRetry) => {
                "stalwart_task_manager_task_retry_total"
            }
            EventType::TaskManager(TaskManagerEvent::TaskStalled) => {
                "stalwart_task_manager_task_stalled_total"
            }
            EventType::TaskManager(TaskManagerEvent::TaskExpired) => {
                "stalwart_task_manager_task_expired_total"
            }
            EventType::TaskManager(TaskManagerEvent::BlobNotFound) => {
                "stalwart_task_manager_blob_not_found_total"
            }
            EventType::TaskManager(TaskManagerEvent::MetadataNotFound) => {
                "stalwart_task_manager_metadata_not_found_total"
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertEvent) => {
                "stalwart_telemetry_alert_event_total"
            }
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertMessage) => {
                "stalwart_telemetry_alert_message_total"
            }
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::LogError) => "stalwart_telemetry_log_error_total",
            EventType::Telemetry(TelemetryEvent::WebhookError) => {
                "stalwart_telemetry_webhook_error_total"
            }
            EventType::Telemetry(TelemetryEvent::OtelExporterError) => {
                "stalwart_telemetry_otel_exporter_error_total"
            }
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError) => {
                "stalwart_telemetry_otel_metrics_exporter_error_total"
            }
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError) => {
                "stalwart_telemetry_prometheus_exporter_error_total"
            }
            EventType::Telemetry(TelemetryEvent::JournalError) => {
                "stalwart_telemetry_journal_error_total"
            }
            EventType::Telemetry(TelemetryEvent::EventsDropped) => {
                "stalwart_telemetry_events_dropped_total"
            }
            EventType::Tls(TlsEvent::HandshakeError) => "stalwart_tls_handshake_error_total",
            _ => "",
        }
    }

    pub const fn variants() -> &'static [Self] {
        &[
            EventType::Acme(AcmeEvent::AuthStart),
            EventType::Acme(AcmeEvent::AuthPending),
            EventType::Acme(AcmeEvent::AuthValid),
            EventType::Acme(AcmeEvent::AuthCompleted),
            EventType::Acme(AcmeEvent::AuthError),
            EventType::Acme(AcmeEvent::AuthTooManyAttempts),
            EventType::Acme(AcmeEvent::ProcessCert),
            EventType::Acme(AcmeEvent::OrderStart),
            EventType::Acme(AcmeEvent::OrderProcessing),
            EventType::Acme(AcmeEvent::OrderCompleted),
            EventType::Acme(AcmeEvent::OrderReady),
            EventType::Acme(AcmeEvent::OrderValid),
            EventType::Acme(AcmeEvent::OrderInvalid),
            EventType::Acme(AcmeEvent::RenewBackoff),
            EventType::Acme(AcmeEvent::ClientSuppliedSni),
            EventType::Acme(AcmeEvent::ClientMissingSni),
            EventType::Acme(AcmeEvent::TlsAlpnReceived),
            EventType::Acme(AcmeEvent::TlsAlpnError),
            EventType::Acme(AcmeEvent::TokenNotFound),
            EventType::Acme(AcmeEvent::Error),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::LlmResponse),
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::ApiError),
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::Request),
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamVerdict),
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::SpamSkipped),
            #[cfg(feature = "enterprise")]
            EventType::Ai(AiEvent::BreakerOpen),
            // SPDX-SnippetEnd
            EventType::Arc(ArcEvent::ChainInvalid),
            EventType::Arc(ArcEvent::SignatureInvalid),
            EventType::Arc(ArcEvent::HashMismatch),
            EventType::Auth(AuthEvent::Success),
            EventType::Auth(AuthEvent::Failed),
            EventType::Auth(AuthEvent::TokenExpired),
            EventType::Auth(AuthEvent::MfaRequired),
            EventType::Auth(AuthEvent::TooManyAttempts),
            EventType::Auth(AuthEvent::ClientRegistration),
            EventType::Auth(AuthEvent::Error),
            EventType::Auth(AuthEvent::Warning),
            EventType::Auth(AuthEvent::CredentialExpired),
            EventType::Cache(CacheEvent::Miss),
            EventType::Cache(CacheEvent::Hit),
            EventType::Cache(CacheEvent::Stale),
            EventType::Cache(CacheEvent::Update),
            EventType::Cache(CacheEvent::EntryTooLarge),
            EventType::Cache(CacheEvent::Invalidate),
            EventType::Cache(CacheEvent::SwapHit),
            EventType::Cache(CacheEvent::SwapMiss),
            EventType::Cache(CacheEvent::SwapWrite),
            EventType::Cache(CacheEvent::SwapError),
            EventType::Cache(CacheEvent::SwapMetrics),
            EventType::Cache(CacheEvent::SwapFlush),
            EventType::Calendar(CalendarEvent::RuleExpansionError),
            EventType::Calendar(CalendarEvent::AlarmSent),
            EventType::Calendar(CalendarEvent::AlarmSkipped),
            EventType::Calendar(CalendarEvent::AlarmRecipientOverride),
            EventType::Calendar(CalendarEvent::AlarmFailed),
            EventType::Calendar(CalendarEvent::ItipMessageSent),
            EventType::Calendar(CalendarEvent::ItipMessageReceived),
            EventType::Calendar(CalendarEvent::ItipMessageError),
            EventType::Cluster(ClusterEvent::Startup),
            EventType::Cluster(ClusterEvent::SubscriberStart),
            EventType::Cluster(ClusterEvent::SubscriberStop),
            EventType::Cluster(ClusterEvent::SubscriberError),
            EventType::Cluster(ClusterEvent::SubscriberDisconnected),
            EventType::Cluster(ClusterEvent::PublisherStart),
            EventType::Cluster(ClusterEvent::PublisherStop),
            EventType::Cluster(ClusterEvent::PublisherError),
            EventType::Cluster(ClusterEvent::MessageReceived),
            EventType::Cluster(ClusterEvent::MessageSkipped),
            EventType::Cluster(ClusterEvent::MessageInvalid),
            EventType::Cluster(ClusterEvent::NodeIdRenewed),
            EventType::Dane(DaneEvent::AuthenticationSuccess),
            EventType::Dane(DaneEvent::AuthenticationFailure),
            EventType::Dane(DaneEvent::NoCertificatesFound),
            EventType::Dane(DaneEvent::CertificateParseError),
            EventType::Dane(DaneEvent::TlsaRecordMatch),
            EventType::Dane(DaneEvent::TlsaRecordFetch),
            EventType::Dane(DaneEvent::TlsaRecordFetchError),
            EventType::Dane(DaneEvent::TlsaRecordNotFound),
            EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned),
            EventType::Dane(DaneEvent::TlsaRecordInvalid),
            EventType::Dane(DaneEvent::BogusDnssecRecord),
            EventType::Delivery(DeliveryEvent::AttemptStart),
            EventType::Delivery(DeliveryEvent::AttemptEnd),
            EventType::Delivery(DeliveryEvent::Completed),
            EventType::Delivery(DeliveryEvent::Failed),
            EventType::Delivery(DeliveryEvent::DomainDeliveryStart),
            EventType::Delivery(DeliveryEvent::MxLookup),
            EventType::Delivery(DeliveryEvent::MxLookupFailed),
            EventType::Delivery(DeliveryEvent::IpLookup),
            EventType::Delivery(DeliveryEvent::IpLookupFailed),
            EventType::Delivery(DeliveryEvent::NullMx),
            EventType::Delivery(DeliveryEvent::Connect),
            EventType::Delivery(DeliveryEvent::ConnectError),
            EventType::Delivery(DeliveryEvent::MissingOutboundHostname),
            EventType::Delivery(DeliveryEvent::GreetingFailed),
            EventType::Delivery(DeliveryEvent::Ehlo),
            EventType::Delivery(DeliveryEvent::EhloRejected),
            EventType::Delivery(DeliveryEvent::Auth),
            EventType::Delivery(DeliveryEvent::AuthFailed),
            EventType::Delivery(DeliveryEvent::MailFrom),
            EventType::Delivery(DeliveryEvent::MailFromRejected),
            EventType::Delivery(DeliveryEvent::Delivered),
            EventType::Delivery(DeliveryEvent::RcptTo),
            EventType::Delivery(DeliveryEvent::RcptToRejected),
            EventType::Delivery(DeliveryEvent::RcptToFailed),
            EventType::Delivery(DeliveryEvent::MessageRejected),
            EventType::Delivery(DeliveryEvent::StartTls),
            EventType::Delivery(DeliveryEvent::StartTlsUnavailable),
            EventType::Delivery(DeliveryEvent::StartTlsError),
            EventType::Delivery(DeliveryEvent::StartTlsDisabled),
            EventType::Delivery(DeliveryEvent::ImplicitTlsError),
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded),
            EventType::Delivery(DeliveryEvent::RateLimitExceeded),
            EventType::Delivery(DeliveryEvent::DoubleBounce),
            EventType::Delivery(DeliveryEvent::DsnSuccess),
            EventType::Delivery(DeliveryEvent::DsnTempFail),
            EventType::Delivery(DeliveryEvent::DsnPermFail),
            EventType::Delivery(DeliveryEvent::RawInput),
            EventType::Delivery(DeliveryEvent::RawOutput),
            EventType::Dkim(DkimEvent::Pass),
            EventType::Dkim(DkimEvent::Neutral),
            EventType::Dkim(DkimEvent::Fail),
            EventType::Dkim(DkimEvent::PermError),
            EventType::Dkim(DkimEvent::TempError),
            EventType::Dkim(DkimEvent::None),
            EventType::Dkim(DkimEvent::SignatureInvalid),
            EventType::Dkim(DkimEvent::PublicKeyError),
            EventType::Dkim(DkimEvent::VerificationFailed),
            EventType::Dkim(DkimEvent::HashMismatch),
            EventType::Dkim(DkimEvent::SignerNotFound),
            EventType::Dkim(DkimEvent::BuildError),
            EventType::Dkim(DkimEvent::SignatureCreated),
            EventType::Dkim(DkimEvent::SignaturePublished),
            EventType::Dkim(DkimEvent::SignatureRetiring),
            EventType::Dkim(DkimEvent::SignatureRetired),
            EventType::Dkim(DkimEvent::SignatureDeleted),
            EventType::Dkim2(Dkim2Event::InstanceInvalid),
            EventType::Dkim2(Dkim2Event::SignatureInvalid),
            EventType::Dkim2(Dkim2Event::ChainInvalid),
            EventType::Dkim2(Dkim2Event::TimestampInvalid),
            EventType::Dkim2(Dkim2Event::EnvelopeMismatch),
            EventType::Dkim2(Dkim2Event::CustodyBroken),
            EventType::Dkim2(Dkim2Event::PublicKeyError),
            EventType::Dkim2(Dkim2Event::VerificationFailed),
            EventType::Dkim2(Dkim2Event::HashMismatch),
            EventType::Dkim2(Dkim2Event::RecipeError),
            EventType::Dkim2(Dkim2Event::SigningFailed),
            EventType::Dmarc(DmarcEvent::Pass),
            EventType::Dmarc(DmarcEvent::Fail),
            EventType::Dmarc(DmarcEvent::PermError),
            EventType::Dmarc(DmarcEvent::TempError),
            EventType::Dmarc(DmarcEvent::None),
            EventType::Dns(DnsEvent::RecordCreated),
            EventType::Dns(DnsEvent::RecordCreationFailed),
            EventType::Dns(DnsEvent::RecordDeletionFailed),
            EventType::Dns(DnsEvent::RecordNotPropagated),
            EventType::Dns(DnsEvent::RecordLookupFailed),
            EventType::Dns(DnsEvent::RecordPropagated),
            EventType::Dns(DnsEvent::RecordPropagationTimeout),
            EventType::Eval(EvalEvent::Result),
            EventType::Eval(EvalEvent::Error),
            EventType::Eval(EvalEvent::DirectoryNotFound),
            EventType::Eval(EvalEvent::StoreNotFound),
            EventType::Http(HttpEvent::ConnectionStart),
            EventType::Http(HttpEvent::ConnectionEnd),
            EventType::Http(HttpEvent::Error),
            EventType::Http(HttpEvent::RequestUrl),
            EventType::Http(HttpEvent::RequestBody),
            EventType::Http(HttpEvent::ResponseBody),
            EventType::Http(HttpEvent::XForwardedMissing),
            EventType::Http(HttpEvent::XForwardedInvalid),
            EventType::Imap(ImapEvent::ConnectionStart),
            EventType::Imap(ImapEvent::ConnectionEnd),
            EventType::Imap(ImapEvent::GetAcl),
            EventType::Imap(ImapEvent::SetAcl),
            EventType::Imap(ImapEvent::MyRights),
            EventType::Imap(ImapEvent::ListRights),
            EventType::Imap(ImapEvent::Append),
            EventType::Imap(ImapEvent::Capabilities),
            EventType::Imap(ImapEvent::Id),
            EventType::Imap(ImapEvent::Close),
            EventType::Imap(ImapEvent::Copy),
            EventType::Imap(ImapEvent::Move),
            EventType::Imap(ImapEvent::CreateMailbox),
            EventType::Imap(ImapEvent::DeleteMailbox),
            EventType::Imap(ImapEvent::RenameMailbox),
            EventType::Imap(ImapEvent::Enable),
            EventType::Imap(ImapEvent::Expunge),
            EventType::Imap(ImapEvent::Fetch),
            EventType::Imap(ImapEvent::IdleStart),
            EventType::Imap(ImapEvent::IdleStop),
            EventType::Imap(ImapEvent::List),
            EventType::Imap(ImapEvent::Lsub),
            EventType::Imap(ImapEvent::Logout),
            EventType::Imap(ImapEvent::Namespace),
            EventType::Imap(ImapEvent::Noop),
            EventType::Imap(ImapEvent::Search),
            EventType::Imap(ImapEvent::Sort),
            EventType::Imap(ImapEvent::Select),
            EventType::Imap(ImapEvent::Status),
            EventType::Imap(ImapEvent::Store),
            EventType::Imap(ImapEvent::Subscribe),
            EventType::Imap(ImapEvent::Unsubscribe),
            EventType::Imap(ImapEvent::Thread),
            EventType::Imap(ImapEvent::UidBatches),
            EventType::Imap(ImapEvent::GetQuota),
            EventType::Imap(ImapEvent::GetMetadata),
            EventType::Imap(ImapEvent::SetMetadata),
            EventType::Imap(ImapEvent::Error),
            EventType::Imap(ImapEvent::RawInput),
            EventType::Imap(ImapEvent::RawOutput),
            EventType::IncomingReport(IncomingReportEvent::DmarcReport),
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings),
            EventType::IncomingReport(IncomingReportEvent::TlsReport),
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings),
            EventType::IncomingReport(IncomingReportEvent::AbuseReport),
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport),
            EventType::IncomingReport(IncomingReportEvent::FraudReport),
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport),
            EventType::IncomingReport(IncomingReportEvent::VirusReport),
            EventType::IncomingReport(IncomingReportEvent::OtherReport),
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed),
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed),
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed),
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed),
            EventType::IncomingReport(IncomingReportEvent::DecompressError),
            EventType::Iprev(IprevEvent::Pass),
            EventType::Iprev(IprevEvent::Fail),
            EventType::Iprev(IprevEvent::PermError),
            EventType::Iprev(IprevEvent::TempError),
            EventType::Iprev(IprevEvent::None),
            EventType::Jmap(JmapEvent::MethodCall),
            EventType::Jmap(JmapEvent::InvalidArguments),
            EventType::Jmap(JmapEvent::RequestTooLarge),
            EventType::Jmap(JmapEvent::StateMismatch),
            EventType::Jmap(JmapEvent::AnchorNotFound),
            EventType::Jmap(JmapEvent::UnsupportedFilter),
            EventType::Jmap(JmapEvent::UnsupportedSort),
            EventType::Jmap(JmapEvent::UnknownMethod),
            EventType::Jmap(JmapEvent::InvalidResultReference),
            EventType::Jmap(JmapEvent::Forbidden),
            EventType::Jmap(JmapEvent::AccountNotFound),
            EventType::Jmap(JmapEvent::AccountNotSupportedByMethod),
            EventType::Jmap(JmapEvent::AccountReadOnly),
            EventType::Jmap(JmapEvent::FromAccountNotFound),
            EventType::Jmap(JmapEvent::FromAccountNotSupportedByMethod),
            EventType::Jmap(JmapEvent::NotFound),
            EventType::Jmap(JmapEvent::CannotCalculateChanges),
            EventType::Jmap(JmapEvent::UnknownDataType),
            EventType::Jmap(JmapEvent::UnknownCapability),
            EventType::Jmap(JmapEvent::NotJson),
            EventType::Jmap(JmapEvent::NotRequest),
            EventType::Jmap(JmapEvent::WebsocketStart),
            EventType::Jmap(JmapEvent::WebsocketStop),
            EventType::Jmap(JmapEvent::WebsocketError),
            EventType::Jmap(JmapEvent::ExpandDurationTooLarge),
            EventType::Jmap(JmapEvent::CannotCalculateOccurrences),
            EventType::Jmap(JmapEvent::TooLarge),
            EventType::Jmap(JmapEvent::RateLimit),
            EventType::Jmap(JmapEvent::ObjectNotFound),
            EventType::Limit(LimitEvent::SizeRequest),
            EventType::Limit(LimitEvent::SizeUpload),
            EventType::Limit(LimitEvent::CallsIn),
            EventType::Limit(LimitEvent::ConcurrentRequest),
            EventType::Limit(LimitEvent::ConcurrentUpload),
            EventType::Limit(LimitEvent::ConcurrentConnection),
            EventType::Limit(LimitEvent::Quota),
            EventType::Limit(LimitEvent::BlobQuota),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota),
            // SPDX-SnippetEnd
            EventType::Limit(LimitEvent::TooManyRequests),
            EventType::Limit(LimitEvent::MemoryBudget),
            EventType::MailAuth(MailAuthEvent::ParseError),
            EventType::MailAuth(MailAuthEvent::MissingParameters),
            EventType::MailAuth(MailAuthEvent::NoHeadersFound),
            EventType::MailAuth(MailAuthEvent::Crypto),
            EventType::MailAuth(MailAuthEvent::Io),
            EventType::MailAuth(MailAuthEvent::Base64),
            EventType::MailAuth(MailAuthEvent::DnsError),
            EventType::MailAuth(MailAuthEvent::DnsRecordNotFound),
            EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType),
            EventType::MailAuth(MailAuthEvent::PolicyNotAligned),
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd),
            EventType::ManageSieve(ManageSieveEvent::CreateScript),
            EventType::ManageSieve(ManageSieveEvent::UpdateScript),
            EventType::ManageSieve(ManageSieveEvent::GetScript),
            EventType::ManageSieve(ManageSieveEvent::DeleteScript),
            EventType::ManageSieve(ManageSieveEvent::RenameScript),
            EventType::ManageSieve(ManageSieveEvent::CheckScript),
            EventType::ManageSieve(ManageSieveEvent::HaveSpace),
            EventType::ManageSieve(ManageSieveEvent::ListScripts),
            EventType::ManageSieve(ManageSieveEvent::SetActive),
            EventType::ManageSieve(ManageSieveEvent::Capabilities),
            EventType::ManageSieve(ManageSieveEvent::StartTls),
            EventType::ManageSieve(ManageSieveEvent::Unauthenticate),
            EventType::ManageSieve(ManageSieveEvent::Logout),
            EventType::ManageSieve(ManageSieveEvent::Noop),
            EventType::ManageSieve(ManageSieveEvent::Error),
            EventType::ManageSieve(ManageSieveEvent::RawInput),
            EventType::ManageSieve(ManageSieveEvent::RawOutput),
            EventType::MessageIngest(MessageIngestEvent::Ham),
            EventType::MessageIngest(MessageIngestEvent::Spam),
            EventType::MessageIngest(MessageIngestEvent::ImapAppend),
            EventType::MessageIngest(MessageIngestEvent::JmapAppend),
            EventType::MessageIngest(MessageIngestEvent::Duplicate),
            EventType::MessageIngest(MessageIngestEvent::Error),
            EventType::Milter(MilterEvent::Read),
            EventType::Milter(MilterEvent::Write),
            EventType::Milter(MilterEvent::ActionAccept),
            EventType::Milter(MilterEvent::ActionDiscard),
            EventType::Milter(MilterEvent::ActionReject),
            EventType::Milter(MilterEvent::ActionTempFail),
            EventType::Milter(MilterEvent::ActionReplyCode),
            EventType::Milter(MilterEvent::ActionConnectionFailure),
            EventType::Milter(MilterEvent::ActionShutdown),
            EventType::Milter(MilterEvent::IoError),
            EventType::Milter(MilterEvent::FrameTooLarge),
            EventType::Milter(MilterEvent::FrameInvalid),
            EventType::Milter(MilterEvent::UnexpectedResponse),
            EventType::Milter(MilterEvent::Timeout),
            EventType::Milter(MilterEvent::TlsInvalidName),
            EventType::Milter(MilterEvent::Disconnected),
            EventType::Milter(MilterEvent::ParseError),
            EventType::MtaHook(MtaHookEvent::ActionAccept),
            EventType::MtaHook(MtaHookEvent::ActionDiscard),
            EventType::MtaHook(MtaHookEvent::ActionReject),
            EventType::MtaHook(MtaHookEvent::ActionQuarantine),
            EventType::MtaHook(MtaHookEvent::Error),
            EventType::MtaSts(MtaStsEvent::Authorized),
            EventType::MtaSts(MtaStsEvent::NotAuthorized),
            EventType::MtaSts(MtaStsEvent::PolicyFetch),
            EventType::MtaSts(MtaStsEvent::PolicyNotFound),
            EventType::MtaSts(MtaStsEvent::PolicyFetchError),
            EventType::MtaSts(MtaStsEvent::InvalidPolicy),
            EventType::Network(NetworkEvent::ListenStart),
            EventType::Network(NetworkEvent::ListenStop),
            EventType::Network(NetworkEvent::ListenError),
            EventType::Network(NetworkEvent::BindError),
            EventType::Network(NetworkEvent::ReadError),
            EventType::Network(NetworkEvent::WriteError),
            EventType::Network(NetworkEvent::FlushError),
            EventType::Network(NetworkEvent::AcceptError),
            EventType::Network(NetworkEvent::SplitError),
            EventType::Network(NetworkEvent::Timeout),
            EventType::Network(NetworkEvent::Closed),
            EventType::Network(NetworkEvent::ProxyError),
            EventType::Network(NetworkEvent::SetOptError),
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport),
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited),
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport),
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited),
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport),
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited),
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport),
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate),
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission),
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError),
            EventType::OutgoingReport(OutgoingReportEvent::NotFound),
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError),
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound),
            EventType::OutgoingReport(OutgoingReportEvent::Locked),
            EventType::OutgoingReport(OutgoingReportEvent::MaxSizeExceeded),
            EventType::Pop3(Pop3Event::ConnectionStart),
            EventType::Pop3(Pop3Event::ConnectionEnd),
            EventType::Pop3(Pop3Event::Delete),
            EventType::Pop3(Pop3Event::Reset),
            EventType::Pop3(Pop3Event::Quit),
            EventType::Pop3(Pop3Event::Fetch),
            EventType::Pop3(Pop3Event::List),
            EventType::Pop3(Pop3Event::ListMessage),
            EventType::Pop3(Pop3Event::Uidl),
            EventType::Pop3(Pop3Event::UidlMessage),
            EventType::Pop3(Pop3Event::Stat),
            EventType::Pop3(Pop3Event::Noop),
            EventType::Pop3(Pop3Event::Capabilities),
            EventType::Pop3(Pop3Event::StartTls),
            EventType::Pop3(Pop3Event::Utf8),
            EventType::Pop3(Pop3Event::Error),
            EventType::Pop3(Pop3Event::RawInput),
            EventType::Pop3(Pop3Event::RawOutput),
            EventType::PushSubscription(PushSubscriptionEvent::Success),
            EventType::PushSubscription(PushSubscriptionEvent::Error),
            EventType::PushSubscription(PushSubscriptionEvent::NotFound),
            EventType::Queue(QueueEvent::Started),
            EventType::Queue(QueueEvent::MessageQueued),
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued),
            EventType::Queue(QueueEvent::ReportQueued),
            EventType::Queue(QueueEvent::DsnQueued),
            EventType::Queue(QueueEvent::AutogeneratedQueued),
            EventType::Queue(QueueEvent::Rescheduled),
            EventType::Queue(QueueEvent::Locked),
            EventType::Queue(QueueEvent::BlobNotFound),
            EventType::Queue(QueueEvent::RateLimitExceeded),
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded),
            EventType::Queue(QueueEvent::QuotaExceeded),
            EventType::Queue(QueueEvent::BackPressure),
            EventType::Registry(RegistryEvent::LocalReadError),
            EventType::Registry(RegistryEvent::LocalWriteError),
            EventType::Registry(RegistryEvent::LocalParseError),
            EventType::Registry(RegistryEvent::ReadError),
            EventType::Registry(RegistryEvent::WriteError),
            EventType::Registry(RegistryEvent::DeserializationError),
            EventType::Registry(RegistryEvent::BuildError),
            EventType::Registry(RegistryEvent::BuildWarning),
            EventType::Registry(RegistryEvent::NotSupported),
            EventType::Registry(RegistryEvent::ValidationError),
            EventType::Resource(ResourceEvent::NotFound),
            EventType::Resource(ResourceEvent::BadParameters),
            EventType::Resource(ResourceEvent::Error),
            EventType::Resource(ResourceEvent::DownloadExternal),
            EventType::Resource(ResourceEvent::ApplicationUpdated),
            EventType::Resource(ResourceEvent::ApplicationUnpacked),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Request),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Forbidden),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Conflict),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Error),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceCreated),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceUpdated),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::ResourceDeleted),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::Query),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkProcessed),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::BulkAborted),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::RollbackFailed),
            #[cfg(feature = "enterprise")]
            EventType::Scim(ScimEvent::AttributeIgnored),
            // SPDX-SnippetEnd
            EventType::SearchIndex(SearchIndexEvent::ManagerStarted),
            EventType::SearchIndex(SearchIndexEvent::PartitionsAcquired),
            EventType::SearchIndex(SearchIndexEvent::PartitionLocked),
            EventType::SearchIndex(SearchIndexEvent::PartitionRetry),
            EventType::SearchIndex(SearchIndexEvent::BatchIndexed),
            EventType::SearchIndex(SearchIndexEvent::DocumentIgnored),
            EventType::SearchIndex(SearchIndexEvent::DocumentTruncated),
            EventType::SearchIndex(SearchIndexEvent::MetadataNotFound),
            EventType::Security(SecurityEvent::AuthenticationBan),
            EventType::Security(SecurityEvent::AbuseBan),
            EventType::Security(SecurityEvent::ScanBan),
            EventType::Security(SecurityEvent::LoiterBan),
            EventType::Security(SecurityEvent::IpBlocked),
            EventType::Security(SecurityEvent::IpBlockExpired),
            EventType::Security(SecurityEvent::IpAllowExpired),
            EventType::Security(SecurityEvent::IpUnauthorized),
            EventType::Security(SecurityEvent::Unauthorized),
            EventType::Server(ServerEvent::Startup),
            EventType::Server(ServerEvent::Shutdown),
            EventType::Server(ServerEvent::StartupError),
            EventType::Server(ServerEvent::ThreadError),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Server(ServerEvent::Licensing),
            // SPDX-SnippetEnd
            EventType::Server(ServerEvent::RecoveryMode),
            EventType::Server(ServerEvent::BootstrapMode),
            EventType::Sieve(SieveEvent::ActionAccept),
            EventType::Sieve(SieveEvent::ActionAcceptReplace),
            EventType::Sieve(SieveEvent::ActionDiscard),
            EventType::Sieve(SieveEvent::ActionReject),
            EventType::Sieve(SieveEvent::SendMessage),
            EventType::Sieve(SieveEvent::MessageTooLarge),
            EventType::Sieve(SieveEvent::ScriptNotFound),
            EventType::Sieve(SieveEvent::ListNotFound),
            EventType::Sieve(SieveEvent::RuntimeError),
            EventType::Sieve(SieveEvent::UnexpectedError),
            EventType::Sieve(SieveEvent::NotSupported),
            EventType::Sieve(SieveEvent::QuotaExceeded),
            EventType::Smtp(SmtpEvent::ConnectionStart),
            EventType::Smtp(SmtpEvent::ConnectionEnd),
            EventType::Smtp(SmtpEvent::Error),
            EventType::Smtp(SmtpEvent::IdNotFound),
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded),
            EventType::Smtp(SmtpEvent::TransferLimitExceeded),
            EventType::Smtp(SmtpEvent::RateLimitExceeded),
            EventType::Smtp(SmtpEvent::TimeLimitExceeded),
            EventType::Smtp(SmtpEvent::MessageParseFailed),
            EventType::Smtp(SmtpEvent::MessageTooLarge),
            EventType::Smtp(SmtpEvent::LoopDetected),
            EventType::Smtp(SmtpEvent::MultipleFromDomains),
            EventType::Smtp(SmtpEvent::DkimPass),
            EventType::Smtp(SmtpEvent::DkimFail),
            EventType::Smtp(SmtpEvent::Dkim2Pass),
            EventType::Smtp(SmtpEvent::Dkim2Fail),
            EventType::Smtp(SmtpEvent::Dkim2DsnRejected),
            EventType::Smtp(SmtpEvent::ArcPass),
            EventType::Smtp(SmtpEvent::ArcFail),
            EventType::Smtp(SmtpEvent::SpfEhloPass),
            EventType::Smtp(SmtpEvent::SpfEhloFail),
            EventType::Smtp(SmtpEvent::SpfFromPass),
            EventType::Smtp(SmtpEvent::SpfFromFail),
            EventType::Smtp(SmtpEvent::DmarcPass),
            EventType::Smtp(SmtpEvent::DmarcFail),
            EventType::Smtp(SmtpEvent::IprevPass),
            EventType::Smtp(SmtpEvent::IprevFail),
            EventType::Smtp(SmtpEvent::TooManyMessages),
            EventType::Smtp(SmtpEvent::Ehlo),
            EventType::Smtp(SmtpEvent::InvalidEhlo),
            EventType::Smtp(SmtpEvent::DidNotSayEhlo),
            EventType::Smtp(SmtpEvent::EhloExpected),
            EventType::Smtp(SmtpEvent::LhloExpected),
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated),
            EventType::Smtp(SmtpEvent::MailFromUnauthorized),
            EventType::Smtp(SmtpEvent::MailFromNotAllowed),
            EventType::Smtp(SmtpEvent::MailFromRewritten),
            EventType::Smtp(SmtpEvent::MailFromMissing),
            EventType::Smtp(SmtpEvent::MailFrom),
            EventType::Smtp(SmtpEvent::MultipleMailFrom),
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist),
            EventType::Smtp(SmtpEvent::RelayNotAllowed),
            EventType::Smtp(SmtpEvent::RcptTo),
            EventType::Smtp(SmtpEvent::RcptToDuplicate),
            EventType::Smtp(SmtpEvent::RcptToRewritten),
            EventType::Smtp(SmtpEvent::RcptToMissing),
            EventType::Smtp(SmtpEvent::RcptToGreylisted),
            EventType::Smtp(SmtpEvent::TooManyRecipients),
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt),
            EventType::Smtp(SmtpEvent::RawInput),
            EventType::Smtp(SmtpEvent::RawOutput),
            EventType::Smtp(SmtpEvent::MissingLocalHostname),
            EventType::Smtp(SmtpEvent::Vrfy),
            EventType::Smtp(SmtpEvent::VrfyNotFound),
            EventType::Smtp(SmtpEvent::VrfyDisabled),
            EventType::Smtp(SmtpEvent::Expn),
            EventType::Smtp(SmtpEvent::ExpnNotFound),
            EventType::Smtp(SmtpEvent::ExpnDisabled),
            EventType::Smtp(SmtpEvent::RequireTlsDisabled),
            EventType::Smtp(SmtpEvent::DeliverByDisabled),
            EventType::Smtp(SmtpEvent::DeliverByInvalid),
            EventType::Smtp(SmtpEvent::FutureReleaseDisabled),
            EventType::Smtp(SmtpEvent::FutureReleaseInvalid),
            EventType::Smtp(SmtpEvent::MtPriorityDisabled),
            EventType::Smtp(SmtpEvent::MtPriorityInvalid),
            EventType::Smtp(SmtpEvent::DsnDisabled),
            EventType::Smtp(SmtpEvent::AuthNotAllowed),
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported),
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong),
            EventType::Smtp(SmtpEvent::AlreadyAuthenticated),
            EventType::Smtp(SmtpEvent::Noop),
            EventType::Smtp(SmtpEvent::StartTls),
            EventType::Smtp(SmtpEvent::StartTlsUnavailable),
            EventType::Smtp(SmtpEvent::StartTlsAlready),
            EventType::Smtp(SmtpEvent::Rset),
            EventType::Smtp(SmtpEvent::Quit),
            EventType::Smtp(SmtpEvent::Help),
            EventType::Smtp(SmtpEvent::CommandNotImplemented),
            EventType::Smtp(SmtpEvent::InvalidCommand),
            EventType::Smtp(SmtpEvent::InvalidSenderAddress),
            EventType::Smtp(SmtpEvent::InvalidRecipientAddress),
            EventType::Smtp(SmtpEvent::InvalidParameter),
            EventType::Smtp(SmtpEvent::UnsupportedParameter),
            EventType::Smtp(SmtpEvent::SyntaxError),
            EventType::Smtp(SmtpEvent::RequestTooLarge),
            EventType::Spam(SpamEvent::Pyzor),
            EventType::Spam(SpamEvent::PyzorError),
            EventType::Spam(SpamEvent::Dnsbl),
            EventType::Spam(SpamEvent::DnsblError),
            EventType::Spam(SpamEvent::TrainStarted),
            EventType::Spam(SpamEvent::TrainCompleted),
            EventType::Spam(SpamEvent::TrainSampleAdded),
            EventType::Spam(SpamEvent::TrainSampleNotFound),
            EventType::Spam(SpamEvent::Classify),
            EventType::Spam(SpamEvent::ModelLoaded),
            EventType::Spam(SpamEvent::ModelNotReady),
            EventType::Spam(SpamEvent::ModelNotFound),
            EventType::Spam(SpamEvent::RulesUpdated),
            EventType::Spf(SpfEvent::Pass),
            EventType::Spf(SpfEvent::Fail),
            EventType::Spf(SpfEvent::SoftFail),
            EventType::Spf(SpfEvent::Neutral),
            EventType::Spf(SpfEvent::TempError),
            EventType::Spf(SpfEvent::PermError),
            EventType::Spf(SpfEvent::None),
            EventType::Store(StoreEvent::AssertValueFailed),
            EventType::Store(StoreEvent::FoundationdbError),
            EventType::Store(StoreEvent::MysqlError),
            EventType::Store(StoreEvent::PostgresqlError),
            EventType::Store(StoreEvent::RocksdbError),
            EventType::Store(StoreEvent::SqliteError),
            EventType::Store(StoreEvent::LdapError),
            EventType::Store(StoreEvent::ElasticsearchError),
            EventType::Store(StoreEvent::MeilisearchError),
            EventType::Store(StoreEvent::RedisError),
            EventType::Store(StoreEvent::S3Error),
            EventType::Store(StoreEvent::AzureError),
            EventType::Store(StoreEvent::FilesystemError),
            EventType::Store(StoreEvent::PoolError),
            EventType::Store(StoreEvent::DataCorruption),
            EventType::Store(StoreEvent::DecompressError),
            EventType::Store(StoreEvent::DeserializeError),
            EventType::Store(StoreEvent::NotFound),
            EventType::Store(StoreEvent::NotConfigured),
            EventType::Store(StoreEvent::NotSupported),
            EventType::Store(StoreEvent::UnexpectedError),
            EventType::Store(StoreEvent::CryptoError),
            EventType::Store(StoreEvent::HttpStoreError),
            EventType::Store(StoreEvent::BlobMissingMarker),
            EventType::Store(StoreEvent::DataWrite),
            EventType::Store(StoreEvent::DataIterate),
            EventType::Store(StoreEvent::BlobRead),
            EventType::Store(StoreEvent::BlobWrite),
            EventType::Store(StoreEvent::BlobDelete),
            EventType::Store(StoreEvent::SqlQuery),
            EventType::Store(StoreEvent::LdapQuery),
            EventType::Store(StoreEvent::LdapWarning),
            EventType::Store(StoreEvent::HttpStoreFetch),
            EventType::Store(StoreEvent::AutoExpunge),
            EventType::Store(StoreEvent::BlobStorePurged),
            EventType::Store(StoreEvent::DataStorePurged),
            EventType::TaskManager(TaskManagerEvent::TaskAcquired),
            EventType::TaskManager(TaskManagerEvent::TaskQueued),
            EventType::TaskManager(TaskManagerEvent::TaskScheduled),
            EventType::TaskManager(TaskManagerEvent::TaskLocked),
            EventType::TaskManager(TaskManagerEvent::TaskIgnored),
            EventType::TaskManager(TaskManagerEvent::TaskFailed),
            EventType::TaskManager(TaskManagerEvent::TaskRetry),
            EventType::TaskManager(TaskManagerEvent::TaskStalled),
            EventType::TaskManager(TaskManagerEvent::TaskExpired),
            EventType::TaskManager(TaskManagerEvent::BlobNotFound),
            EventType::TaskManager(TaskManagerEvent::MetadataNotFound),
            EventType::TaskManager(TaskManagerEvent::SchedulerStarted),
            EventType::TaskManager(TaskManagerEvent::ManagerStarted),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertEvent),
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::AlertMessage),
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::LogError),
            EventType::Telemetry(TelemetryEvent::WebhookError),
            EventType::Telemetry(TelemetryEvent::OtelExporterError),
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError),
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError),
            EventType::Telemetry(TelemetryEvent::JournalError),
            EventType::Telemetry(TelemetryEvent::EventsDropped),
            EventType::Telemetry(TelemetryEvent::MetricsCollected),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            EventType::Telemetry(TelemetryEvent::MetricsStored),
            // SPDX-SnippetEnd
            EventType::Telemetry(TelemetryEvent::MetricsPushed),
            EventType::Tls(TlsEvent::Handshake),
            EventType::Tls(TlsEvent::HandshakeError),
            EventType::Tls(TlsEvent::NotConfigured),
            EventType::Tls(TlsEvent::CertificateNotFound),
            EventType::Tls(TlsEvent::NoCertificatesAvailable),
            EventType::Tls(TlsEvent::MultipleCertificatesAvailable),
            EventType::Tls(TlsEvent::ExpiredCertificateRemoved),
            EventType::TlsRpt(TlsRptEvent::RecordFetch),
            EventType::TlsRpt(TlsRptEvent::RecordFetchError),
            EventType::TlsRpt(TlsRptEvent::RecordNotFound),
            EventType::WebDav(WebDavEvent::Propfind),
            EventType::WebDav(WebDavEvent::Proppatch),
            EventType::WebDav(WebDavEvent::Get),
            EventType::WebDav(WebDavEvent::Head),
            EventType::WebDav(WebDavEvent::Report),
            EventType::WebDav(WebDavEvent::Mkcol),
            EventType::WebDav(WebDavEvent::Mkcalendar),
            EventType::WebDav(WebDavEvent::Delete),
            EventType::WebDav(WebDavEvent::Put),
            EventType::WebDav(WebDavEvent::Post),
            EventType::WebDav(WebDavEvent::Patch),
            EventType::WebDav(WebDavEvent::Copy),
            EventType::WebDav(WebDavEvent::Move),
            EventType::WebDav(WebDavEvent::Lock),
            EventType::WebDav(WebDavEvent::Unlock),
            EventType::WebDav(WebDavEvent::Acl),
            EventType::WebDav(WebDavEvent::Options),
            EventType::WebDav(WebDavEvent::Error),
        ]
    }
}

impl MetricType {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            MetricType,
            b"acme.auth-error" => MetricType::AcmeAuthError,
            b"acme.auth-too-many-attempts" => MetricType::AcmeAuthTooManyAttempts,
            b"acme.order-completed" => MetricType::AcmeOrderCompleted,
            b"acme.order-invalid" => MetricType::AcmeOrderInvalid,
            b"acme.client-missing-sni" => MetricType::AcmeClientMissingSni,
            b"acme.tls-alpn-error" => MetricType::AcmeTlsAlpnError,
            b"acme.token-not-found" => MetricType::AcmeTokenNotFound,
            b"acme.error" => MetricType::AcmeError,
            b"ai.request-time" => MetricType::AiRequestTime,
            b"ai.input-tokens" => MetricType::AiInputTokens,
            b"ai.output-tokens" => MetricType::AiOutputTokens,
            b"ai.api-error" => MetricType::AiApiError,
            b"ai.request" => MetricType::AiRequest,
            b"ai.spam-verdict" => MetricType::AiSpamVerdict,
            b"ai.spam-skipped" => MetricType::AiSpamSkipped,
            b"ai.breaker-open" => MetricType::AiBreakerOpen,
            b"arc.chain-invalid" => MetricType::ArcChainInvalid,
            b"arc.signature-invalid" => MetricType::ArcSignatureInvalid,
            b"arc.hash-mismatch" => MetricType::ArcHashMismatch,
            b"auth.success" => MetricType::AuthSuccess,
            b"auth.failed" => MetricType::AuthFailed,
            b"auth.too-many-attempts" => MetricType::AuthTooManyAttempts,
            b"auth.error" => MetricType::AuthError,
            b"cache.messages-size" => MetricType::CacheMessagesSize,
            b"cache.messages-large-size" => MetricType::CacheMessagesLargeSize,
            b"cache.size" => MetricType::CacheSize,
            b"cache.swap-pending" => MetricType::CacheSwapPending,
            b"cache.miss" => MetricType::CacheMiss,
            b"cache.hit" => MetricType::CacheHit,
            b"cache.stale" => MetricType::CacheStale,
            b"cache.entry-too-large" => MetricType::CacheEntryTooLarge,
            b"cache.swap-hit" => MetricType::CacheSwapHit,
            b"cache.swap-miss" => MetricType::CacheSwapMiss,
            b"cache.swap-write" => MetricType::CacheSwapWrite,
            b"cache.swap-error" => MetricType::CacheSwapError,
            b"calendar.alarm-sent" => MetricType::CalendarAlarmSent,
            b"calendar.alarm-failed" => MetricType::CalendarAlarmFailed,
            b"calendar.itip-message-sent" => MetricType::CalendarItipMessageSent,
            b"calendar.itip-message-received" => MetricType::CalendarItipMessageReceived,
            b"calendar.itip-message-error" => MetricType::CalendarItipMessageError,
            b"cluster.subscriber-error" => MetricType::ClusterSubscriberError,
            b"cluster.subscriber-disconnected" => MetricType::ClusterSubscriberDisconnected,
            b"cluster.publisher-error" => MetricType::ClusterPublisherError,
            b"dane.authentication-success" => MetricType::DaneAuthenticationSuccess,
            b"dane.authentication-failure" => MetricType::DaneAuthenticationFailure,
            b"dane.no-certificates-found" => MetricType::DaneNoCertificatesFound,
            b"dane.certificate-parse-error" => MetricType::DaneCertificateParseError,
            b"dane.tlsa-record-fetch-error" => MetricType::DaneTlsaRecordFetchError,
            b"dane.tlsa-record-not-found" => MetricType::DaneTlsaRecordNotFound,
            b"dane.tlsa-record-not-dnssec-signed" => MetricType::DaneTlsaRecordNotDnssecSigned,
            b"dane.tlsa-record-invalid" => MetricType::DaneTlsaRecordInvalid,
            b"dane.bogus-dnssec-record" => MetricType::DaneBogusDnssecRecord,
            b"delivery.total-time" => MetricType::DeliveryTotalTime,
            b"delivery.attempt-time" => MetricType::DeliveryAttemptTime,
            b"delivery.active-connections" => MetricType::DeliveryActiveConnections,
            b"delivery.attempt-start" => MetricType::DeliveryAttemptStart,
            b"delivery.attempt-end" => MetricType::DeliveryAttemptEnd,
            b"delivery.completed" => MetricType::DeliveryCompleted,
            b"delivery.mx-lookup-failed" => MetricType::DeliveryMxLookupFailed,
            b"delivery.ip-lookup-failed" => MetricType::DeliveryIpLookupFailed,
            b"delivery.null-mx" => MetricType::DeliveryNullMx,
            b"delivery.greeting-failed" => MetricType::DeliveryGreetingFailed,
            b"delivery.ehlo-rejected" => MetricType::DeliveryEhloRejected,
            b"delivery.auth-failed" => MetricType::DeliveryAuthFailed,
            b"delivery.mail-from-rejected" => MetricType::DeliveryMailFromRejected,
            b"delivery.delivered" => MetricType::DeliveryDelivered,
            b"delivery.rcpt-to-rejected" => MetricType::DeliveryRcptToRejected,
            b"delivery.rcpt-to-failed" => MetricType::DeliveryRcptToFailed,
            b"delivery.message-rejected" => MetricType::DeliveryMessageRejected,
            b"delivery.start-tls-unavailable" => MetricType::DeliveryStartTlsUnavailable,
            b"delivery.start-tls-error" => MetricType::DeliveryStartTlsError,
            b"delivery.start-tls-disabled" => MetricType::DeliveryStartTlsDisabled,
            b"delivery.implicit-tls-error" => MetricType::DeliveryImplicitTlsError,
            b"delivery.concurrency-limit-exceeded" => MetricType::DeliveryConcurrencyLimitExceeded,
            b"delivery.rate-limit-exceeded" => MetricType::DeliveryRateLimitExceeded,
            b"delivery.double-bounce" => MetricType::DeliveryDoubleBounce,
            b"delivery.dsn-success" => MetricType::DeliveryDsnSuccess,
            b"delivery.dsn-temp-fail" => MetricType::DeliveryDsnTempFail,
            b"delivery.dsn-perm-fail" => MetricType::DeliveryDsnPermFail,
            b"dkim.pass" => MetricType::DkimPass,
            b"dkim.neutral" => MetricType::DkimNeutral,
            b"dkim.fail" => MetricType::DkimFail,
            b"dkim.perm-error" => MetricType::DkimPermError,
            b"dkim.temp-error" => MetricType::DkimTempError,
            b"dkim.none" => MetricType::DkimNone,
            b"dkim.signature-invalid" => MetricType::DkimSignatureInvalid,
            b"dkim.public-key-error" => MetricType::DkimPublicKeyError,
            b"dkim.verification-failed" => MetricType::DkimVerificationFailed,
            b"dkim.hash-mismatch" => MetricType::DkimHashMismatch,
            b"dkim.signer-not-found" => MetricType::DkimSignerNotFound,
            b"dkim2.instance-invalid" => MetricType::Dkim2InstanceInvalid,
            b"dkim2.signature-invalid" => MetricType::Dkim2SignatureInvalid,
            b"dkim2.chain-invalid" => MetricType::Dkim2ChainInvalid,
            b"dkim2.timestamp-invalid" => MetricType::Dkim2TimestampInvalid,
            b"dkim2.envelope-mismatch" => MetricType::Dkim2EnvelopeMismatch,
            b"dkim2.custody-broken" => MetricType::Dkim2CustodyBroken,
            b"dkim2.public-key-error" => MetricType::Dkim2PublicKeyError,
            b"dkim2.verification-failed" => MetricType::Dkim2VerificationFailed,
            b"dkim2.hash-mismatch" => MetricType::Dkim2HashMismatch,
            b"dkim2.recipe-error" => MetricType::Dkim2RecipeError,
            b"dkim2.signing-failed" => MetricType::Dkim2SigningFailed,
            b"dmarc.pass" => MetricType::DmarcPass,
            b"dmarc.fail" => MetricType::DmarcFail,
            b"dmarc.perm-error" => MetricType::DmarcPermError,
            b"dmarc.temp-error" => MetricType::DmarcTempError,
            b"dmarc.none" => MetricType::DmarcNone,
            b"dns.lookup-time" => MetricType::DnsLookupTime,
            b"dns.record-creation-failed" => MetricType::DnsRecordCreationFailed,
            b"dns.record-deletion-failed" => MetricType::DnsRecordDeletionFailed,
            b"dns.record-lookup-failed" => MetricType::DnsRecordLookupFailed,
            b"dns.record-propagation-timeout" => MetricType::DnsRecordPropagationTimeout,
            b"domain.count" => MetricType::DomainCount,
            b"eval.error" => MetricType::EvalError,
            b"eval.directory-not-found" => MetricType::EvalDirectoryNotFound,
            b"eval.store-not-found" => MetricType::EvalStoreNotFound,
            b"http.request-time" => MetricType::HttpRequestTime,
            b"http.active-connections" => MetricType::HttpActiveConnections,
            b"http.connection-start" => MetricType::HttpConnectionStart,
            b"http.error" => MetricType::HttpError,
            b"http.request-body" => MetricType::HttpRequestBody,
            b"http.response-body" => MetricType::HttpResponseBody,
            b"http.x-forwarded-missing" => MetricType::HttpXForwardedMissing,
            b"http.x-forwarded-invalid" => MetricType::HttpXForwardedInvalid,
            b"imap.request-time" => MetricType::ImapRequestTime,
            b"imap.active-connections" => MetricType::ImapActiveConnections,
            b"imap.connection-start" => MetricType::ImapConnectionStart,
            b"imap.connection-end" => MetricType::ImapConnectionEnd,
            b"incoming-report.dmarc-report" => MetricType::IncomingReportDmarcReport,
            b"incoming-report.dmarc-report-with-warnings" => MetricType::IncomingReportDmarcReportWithWarnings,
            b"incoming-report.tls-report" => MetricType::IncomingReportTlsReport,
            b"incoming-report.tls-report-with-warnings" => MetricType::IncomingReportTlsReportWithWarnings,
            b"incoming-report.abuse-report" => MetricType::IncomingReportAbuseReport,
            b"incoming-report.auth-failure-report" => MetricType::IncomingReportAuthFailureReport,
            b"incoming-report.fraud-report" => MetricType::IncomingReportFraudReport,
            b"incoming-report.not-spam-report" => MetricType::IncomingReportNotSpamReport,
            b"incoming-report.virus-report" => MetricType::IncomingReportVirusReport,
            b"incoming-report.other-report" => MetricType::IncomingReportOtherReport,
            b"incoming-report.message-parse-failed" => MetricType::IncomingReportMessageParseFailed,
            b"incoming-report.dmarc-parse-failed" => MetricType::IncomingReportDmarcParseFailed,
            b"incoming-report.tls-rpc-parse-failed" => MetricType::IncomingReportTlsRpcParseFailed,
            b"incoming-report.arf-parse-failed" => MetricType::IncomingReportArfParseFailed,
            b"incoming-report.decompress-error" => MetricType::IncomingReportDecompressError,
            b"iprev.pass" => MetricType::IprevPass,
            b"iprev.fail" => MetricType::IprevFail,
            b"iprev.perm-error" => MetricType::IprevPermError,
            b"iprev.temp-error" => MetricType::IprevTempError,
            b"iprev.none" => MetricType::IprevNone,
            b"jmap.method-call" => MetricType::JmapMethodCall,
            b"jmap.invalid-arguments" => MetricType::JmapInvalidArguments,
            b"jmap.request-too-large" => MetricType::JmapRequestTooLarge,
            b"jmap.unsupported-filter" => MetricType::JmapUnsupportedFilter,
            b"jmap.unsupported-sort" => MetricType::JmapUnsupportedSort,
            b"jmap.unknown-method" => MetricType::JmapUnknownMethod,
            b"jmap.forbidden" => MetricType::JmapForbidden,
            b"jmap.not-json" => MetricType::JmapNotJson,
            b"jmap.not-request" => MetricType::JmapNotRequest,
            b"jmap.websocket-start" => MetricType::JmapWebsocketStart,
            b"jmap.websocket-error" => MetricType::JmapWebsocketError,
            b"limit.size-request" => MetricType::LimitSizeRequest,
            b"limit.size-upload" => MetricType::LimitSizeUpload,
            b"limit.calls-in" => MetricType::LimitCallsIn,
            b"limit.concurrent-request" => MetricType::LimitConcurrentRequest,
            b"limit.concurrent-upload" => MetricType::LimitConcurrentUpload,
            b"limit.concurrent-connection" => MetricType::LimitConcurrentConnection,
            b"limit.quota" => MetricType::LimitQuota,
            b"limit.blob-quota" => MetricType::LimitBlobQuota,
            b"limit.tenant-quota" => MetricType::LimitTenantQuota,
            b"limit.too-many-requests" => MetricType::LimitTooManyRequests,
            b"limit.memory-budget" => MetricType::LimitMemoryBudget,
            b"mail-auth.parse-error" => MetricType::MailAuthParseError,
            b"mail-auth.missing-parameters" => MetricType::MailAuthMissingParameters,
            b"mail-auth.no-headers-found" => MetricType::MailAuthNoHeadersFound,
            b"mail-auth.crypto" => MetricType::MailAuthCrypto,
            b"mail-auth.io" => MetricType::MailAuthIo,
            b"mail-auth.base64" => MetricType::MailAuthBase64,
            b"mail-auth.dns-error" => MetricType::MailAuthDnsError,
            b"mail-auth.dns-record-not-found" => MetricType::MailAuthDnsRecordNotFound,
            b"mail-auth.dns-invalid-record-type" => MetricType::MailAuthDnsInvalidRecordType,
            b"mail-auth.policy-not-aligned" => MetricType::MailAuthPolicyNotAligned,
            b"manage-sieve.connection-start" => MetricType::ManageSieveConnectionStart,
            b"manage-sieve.connection-end" => MetricType::ManageSieveConnectionEnd,
            b"message.size" => MetricType::MessageSize,
            b"message.authenticated-size" => MetricType::MessageAuthenticatedSize,
            b"message-ingest.time" => MetricType::MessageIngestTime,
            b"message-ingest.ham" => MetricType::MessageIngestHam,
            b"message-ingest.spam" => MetricType::MessageIngestSpam,
            b"message-ingest.imap-append" => MetricType::MessageIngestImapAppend,
            b"message-ingest.jmap-append" => MetricType::MessageIngestJmapAppend,
            b"message-ingest.duplicate" => MetricType::MessageIngestDuplicate,
            b"message-ingest.error" => MetricType::MessageIngestError,
            b"milter.action-accept" => MetricType::MilterActionAccept,
            b"milter.action-discard" => MetricType::MilterActionDiscard,
            b"milter.action-reject" => MetricType::MilterActionReject,
            b"milter.action-temp-fail" => MetricType::MilterActionTempFail,
            b"milter.action-reply-code" => MetricType::MilterActionReplyCode,
            b"milter.action-connection-failure" => MetricType::MilterActionConnectionFailure,
            b"milter.action-shutdown" => MetricType::MilterActionShutdown,
            b"mta-hook.action-accept" => MetricType::MtaHookActionAccept,
            b"mta-hook.action-discard" => MetricType::MtaHookActionDiscard,
            b"mta-hook.action-reject" => MetricType::MtaHookActionReject,
            b"mta-hook.action-quarantine" => MetricType::MtaHookActionQuarantine,
            b"mta-hook.error" => MetricType::MtaHookError,
            b"mta-sts.authorized" => MetricType::MtaStsAuthorized,
            b"mta-sts.not-authorized" => MetricType::MtaStsNotAuthorized,
            b"mta-sts.invalid-policy" => MetricType::MtaStsInvalidPolicy,
            b"network.timeout" => MetricType::NetworkTimeout,
            b"outgoing-report.size" => MetricType::OutgoingReportSize,
            b"outgoing-report.spf-report" => MetricType::OutgoingReportSpfReport,
            b"outgoing-report.spf-rate-limited" => MetricType::OutgoingReportSpfRateLimited,
            b"outgoing-report.dkim-report" => MetricType::OutgoingReportDkimReport,
            b"outgoing-report.dkim-rate-limited" => MetricType::OutgoingReportDkimRateLimited,
            b"outgoing-report.dmarc-report" => MetricType::OutgoingReportDmarcReport,
            b"outgoing-report.dmarc-rate-limited" => MetricType::OutgoingReportDmarcRateLimited,
            b"outgoing-report.dmarc-aggregate-report" => MetricType::OutgoingReportDmarcAggregateReport,
            b"outgoing-report.tls-aggregate" => MetricType::OutgoingReportTlsAggregate,
            b"outgoing-report.http-submission" => MetricType::OutgoingReportHttpSubmission,
            b"outgoing-report.unauthorized-reporting-address" => MetricType::OutgoingReportUnauthorizedReportingAddress,
            b"outgoing-report.reporting-address-validation-error" => MetricType::OutgoingReportReportingAddressValidationError,
            b"outgoing-report.not-found" => MetricType::OutgoingReportNotFound,
            b"outgoing-report.submission-error" => MetricType::OutgoingReportSubmissionError,
            b"outgoing-report.no-recipients-found" => MetricType::OutgoingReportNoRecipientsFound,
            b"pop3.request-time" => MetricType::Pop3RequestTime,
            b"pop3.active-connections" => MetricType::Pop3ActiveConnections,
            b"pop3.connection-start" => MetricType::Pop3ConnectionStart,
            b"pop3.connection-end" => MetricType::Pop3ConnectionEnd,
            b"push-subscription.success" => MetricType::PushSubscriptionSuccess,
            b"push-subscription.error" => MetricType::PushSubscriptionError,
            b"push-subscription.not-found" => MetricType::PushSubscriptionNotFound,
            b"queue.count" => MetricType::QueueCount,
            b"queue.message-queued" => MetricType::QueueMessageQueued,
            b"queue.authenticated-message-queued" => MetricType::QueueAuthenticatedMessageQueued,
            b"queue.report-queued" => MetricType::QueueReportQueued,
            b"queue.dsn-queued" => MetricType::QueueDsnQueued,
            b"queue.autogenerated-queued" => MetricType::QueueAutogeneratedQueued,
            b"queue.rescheduled" => MetricType::QueueRescheduled,
            b"queue.blob-not-found" => MetricType::QueueBlobNotFound,
            b"queue.rate-limit-exceeded" => MetricType::QueueRateLimitExceeded,
            b"queue.concurrency-limit-exceeded" => MetricType::QueueConcurrencyLimitExceeded,
            b"queue.quota-exceeded" => MetricType::QueueQuotaExceeded,
            b"queue.back-pressure" => MetricType::QueueBackPressure,
            b"resource.not-found" => MetricType::ResourceNotFound,
            b"resource.bad-parameters" => MetricType::ResourceBadParameters,
            b"resource.error" => MetricType::ResourceError,
            b"search-index.index-time" => MetricType::SearchIndexIndexTime,
            b"search-index.pending-email" => MetricType::SearchIndexPendingEmail,
            b"search-index.pending-calendar" => MetricType::SearchIndexPendingCalendar,
            b"search-index.pending-contacts" => MetricType::SearchIndexPendingContacts,
            b"search-index.pending-file" => MetricType::SearchIndexPendingFile,
            b"search-index.pending-tracing" => MetricType::SearchIndexPendingTracing,
            b"search-index.partition-retry" => MetricType::SearchIndexPartitionRetry,
            b"search-index.batch-indexed" => MetricType::SearchIndexBatchIndexed,
            b"search-index.document-truncated" => MetricType::SearchIndexDocumentTruncated,
            b"security.authentication-ban" => MetricType::SecurityAuthenticationBan,
            b"security.abuse-ban" => MetricType::SecurityAbuseBan,
            b"security.scan-ban" => MetricType::SecurityScanBan,
            b"security.loiter-ban" => MetricType::SecurityLoiterBan,
            b"security.ip-blocked" => MetricType::SecurityIpBlocked,
            b"security.unauthorized" => MetricType::SecurityUnauthorized,
            b"server.memory" => MetricType::ServerMemory,
            b"server.buffered-memory-smtp" => MetricType::ServerBufferedMemorySmtp,
            b"server.buffered-memory-read" => MetricType::ServerBufferedMemoryRead,
            b"server.thread-error" => MetricType::ServerThreadError,
            b"sieve.request-time" => MetricType::SieveRequestTime,
            b"sieve.active-connections" => MetricType::SieveActiveConnections,
            b"sieve.action-accept" => MetricType::SieveActionAccept,
            b"sieve.action-accept-replace" => MetricType::SieveActionAcceptReplace,
            b"sieve.action-discard" => MetricType::SieveActionDiscard,
            b"sieve.action-reject" => MetricType::SieveActionReject,
            b"sieve.send-message" => MetricType::SieveSendMessage,
            b"sieve.message-too-large" => MetricType::SieveMessageTooLarge,
            b"sieve.runtime-error" => MetricType::SieveRuntimeError,
            b"sieve.unexpected-error" => MetricType::SieveUnexpectedError,
            b"sieve.not-supported" => MetricType::SieveNotSupported,
            b"sieve.quota-exceeded" => MetricType::SieveQuotaExceeded,
            b"smtp.request-time" => MetricType::SmtpRequestTime,
            b"smtp.active-connections" => MetricType::SmtpActiveConnections,
            b"smtp.connection-start" => MetricType::SmtpConnectionStart,
            b"smtp.connection-end" => MetricType::SmtpConnectionEnd,
            b"smtp.error" => MetricType::SmtpError,
            b"smtp.concurrency-limit-exceeded" => MetricType::SmtpConcurrencyLimitExceeded,
            b"smtp.transfer-limit-exceeded" => MetricType::SmtpTransferLimitExceeded,
            b"smtp.rate-limit-exceeded" => MetricType::SmtpRateLimitExceeded,
            b"smtp.time-limit-exceeded" => MetricType::SmtpTimeLimitExceeded,
            b"smtp.message-parse-failed" => MetricType::SmtpMessageParseFailed,
            b"smtp.message-too-large" => MetricType::SmtpMessageTooLarge,
            b"smtp.loop-detected" => MetricType::SmtpLoopDetected,
            b"smtp.multiple-from-domains" => MetricType::SmtpMultipleFromDomains,
            b"smtp.dkim-pass" => MetricType::SmtpDkimPass,
            b"smtp.dkim-fail" => MetricType::SmtpDkimFail,
            b"smtp.dkim2-pass" => MetricType::SmtpDkim2Pass,
            b"smtp.dkim2-fail" => MetricType::SmtpDkim2Fail,
            b"smtp.dkim2-dsn-rejected" => MetricType::SmtpDkim2DsnRejected,
            b"smtp.arc-pass" => MetricType::SmtpArcPass,
            b"smtp.arc-fail" => MetricType::SmtpArcFail,
            b"smtp.spf-ehlo-pass" => MetricType::SmtpSpfEhloPass,
            b"smtp.spf-ehlo-fail" => MetricType::SmtpSpfEhloFail,
            b"smtp.spf-from-pass" => MetricType::SmtpSpfFromPass,
            b"smtp.spf-from-fail" => MetricType::SmtpSpfFromFail,
            b"smtp.dmarc-pass" => MetricType::SmtpDmarcPass,
            b"smtp.dmarc-fail" => MetricType::SmtpDmarcFail,
            b"smtp.iprev-pass" => MetricType::SmtpIprevPass,
            b"smtp.iprev-fail" => MetricType::SmtpIprevFail,
            b"smtp.too-many-messages" => MetricType::SmtpTooManyMessages,
            b"smtp.invalid-ehlo" => MetricType::SmtpInvalidEhlo,
            b"smtp.did-not-say-ehlo" => MetricType::SmtpDidNotSayEhlo,
            b"smtp.mail-from-unauthenticated" => MetricType::SmtpMailFromUnauthenticated,
            b"smtp.mail-from-unauthorized" => MetricType::SmtpMailFromUnauthorized,
            b"smtp.mail-from-missing" => MetricType::SmtpMailFromMissing,
            b"smtp.multiple-mail-from" => MetricType::SmtpMultipleMailFrom,
            b"smtp.mailbox-does-not-exist" => MetricType::SmtpMailboxDoesNotExist,
            b"smtp.relay-not-allowed" => MetricType::SmtpRelayNotAllowed,
            b"smtp.rcpt-to-duplicate" => MetricType::SmtpRcptToDuplicate,
            b"smtp.rcpt-to-missing" => MetricType::SmtpRcptToMissing,
            b"smtp.too-many-recipients" => MetricType::SmtpTooManyRecipients,
            b"smtp.too-many-invalid-rcpt" => MetricType::SmtpTooManyInvalidRcpt,
            b"smtp.auth-mechanism-not-supported" => MetricType::SmtpAuthMechanismNotSupported,
            b"smtp.auth-exchange-too-long" => MetricType::SmtpAuthExchangeTooLong,
            b"smtp.command-not-implemented" => MetricType::SmtpCommandNotImplemented,
            b"smtp.invalid-command" => MetricType::SmtpInvalidCommand,
            b"smtp.syntax-error" => MetricType::SmtpSyntaxError,
            b"smtp.request-too-large" => MetricType::SmtpRequestTooLarge,
            b"spam.pyzor-error" => MetricType::SpamPyzorError,
            b"spam.dnsbl-error" => MetricType::SpamDnsblError,
            b"spam.train-completed" => MetricType::SpamTrainCompleted,
            b"spam.train-sample-added" => MetricType::SpamTrainSampleAdded,
            b"spam.classify" => MetricType::SpamClassify,
            b"spam.model-not-ready" => MetricType::SpamModelNotReady,
            b"spf.pass" => MetricType::SpfPass,
            b"spf.fail" => MetricType::SpfFail,
            b"spf.soft-fail" => MetricType::SpfSoftFail,
            b"spf.neutral" => MetricType::SpfNeutral,
            b"spf.temp-error" => MetricType::SpfTempError,
            b"spf.perm-error" => MetricType::SpfPermError,
            b"spf.none" => MetricType::SpfNone,
            b"store.data-read-time" => MetricType::StoreDataReadTime,
            b"store.data-write-time" => MetricType::StoreDataWriteTime,
            b"store.blob-read-time" => MetricType::StoreBlobReadTime,
            b"store.blob-write-time" => MetricType::StoreBlobWriteTime,
            b"store.assert-value-failed" => MetricType::StoreAssertValueFailed,
            b"store.foundationdb-error" => MetricType::StoreFoundationdbError,
            b"store.mysql-error" => MetricType::StoreMysqlError,
            b"store.postgresql-error" => MetricType::StorePostgresqlError,
            b"store.rocksdb-error" => MetricType::StoreRocksdbError,
            b"store.sqlite-error" => MetricType::StoreSqliteError,
            b"store.ldap-error" => MetricType::StoreLdapError,
            b"store.elasticsearch-error" => MetricType::StoreElasticsearchError,
            b"store.redis-error" => MetricType::StoreRedisError,
            b"store.s3-error" => MetricType::StoreS3Error,
            b"store.azure-error" => MetricType::StoreAzureError,
            b"store.filesystem-error" => MetricType::StoreFilesystemError,
            b"store.pool-error" => MetricType::StorePoolError,
            b"store.data-corruption" => MetricType::StoreDataCorruption,
            b"store.decompress-error" => MetricType::StoreDecompressError,
            b"store.deserialize-error" => MetricType::StoreDeserializeError,
            b"store.not-found" => MetricType::StoreNotFound,
            b"store.not-configured" => MetricType::StoreNotConfigured,
            b"store.not-supported" => MetricType::StoreNotSupported,
            b"store.unexpected-error" => MetricType::StoreUnexpectedError,
            b"store.crypto-error" => MetricType::StoreCryptoError,
            b"store.http-store-error" => MetricType::StoreHttpStoreError,
            b"store.blob-missing-marker" => MetricType::StoreBlobMissingMarker,
            b"store.data-write" => MetricType::StoreDataWrite,
            b"store.data-iterate" => MetricType::StoreDataIterate,
            b"store.blob-read" => MetricType::StoreBlobRead,
            b"store.blob-write" => MetricType::StoreBlobWrite,
            b"store.blob-delete" => MetricType::StoreBlobDelete,
            b"task-manager.pending" => MetricType::TaskManagerPending,
            b"task-manager.due" => MetricType::TaskManagerDue,
            b"task-manager.task-failed" => MetricType::TaskManagerTaskFailed,
            b"task-manager.task-retry" => MetricType::TaskManagerTaskRetry,
            b"task-manager.task-stalled" => MetricType::TaskManagerTaskStalled,
            b"task-manager.task-expired" => MetricType::TaskManagerTaskExpired,
            b"task-manager.blob-not-found" => MetricType::TaskManagerBlobNotFound,
            b"task-manager.metadata-not-found" => MetricType::TaskManagerMetadataNotFound,
            b"telemetry.alert-event" => MetricType::TelemetryAlertEvent,
            b"telemetry.alert-message" => MetricType::TelemetryAlertMessage,
            b"telemetry.log-error" => MetricType::TelemetryLogError,
            b"telemetry.webhook-error" => MetricType::TelemetryWebhookError,
            b"telemetry.otel-exporter-error" => MetricType::TelemetryOtelExporterError,
            b"telemetry.otel-metrics-exporter-error" => MetricType::TelemetryOtelMetricsExporterError,
            b"telemetry.prometheus-exporter-error" => MetricType::TelemetryPrometheusExporterError,
            b"telemetry.journal-error" => MetricType::TelemetryJournalError,
            b"telemetry.events-dropped" => MetricType::TelemetryEventsDropped,
            b"tls.handshake-error" => MetricType::TlsHandshakeError,
            b"user.count" => MetricType::UserCount,
        }
        .copied()
    }

    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            MetricType,
            b"acme.auth-error" => MetricType::AcmeAuthError,
            b"acme.auth-too-many-attempts" => MetricType::AcmeAuthTooManyAttempts,
            b"acme.order-completed" => MetricType::AcmeOrderCompleted,
            b"acme.order-invalid" => MetricType::AcmeOrderInvalid,
            b"acme.client-missing-sni" => MetricType::AcmeClientMissingSni,
            b"acme.tls-alpn-error" => MetricType::AcmeTlsAlpnError,
            b"acme.token-not-found" => MetricType::AcmeTokenNotFound,
            b"acme.error" => MetricType::AcmeError,
            b"arc.chain-invalid" => MetricType::ArcChainInvalid,
            b"arc.signature-invalid" => MetricType::ArcSignatureInvalid,
            b"arc.hash-mismatch" => MetricType::ArcHashMismatch,
            b"auth.success" => MetricType::AuthSuccess,
            b"auth.failed" => MetricType::AuthFailed,
            b"auth.too-many-attempts" => MetricType::AuthTooManyAttempts,
            b"auth.error" => MetricType::AuthError,
            b"cache.messages-size" => MetricType::CacheMessagesSize,
            b"cache.messages-large-size" => MetricType::CacheMessagesLargeSize,
            b"cache.size" => MetricType::CacheSize,
            b"cache.swap-pending" => MetricType::CacheSwapPending,
            b"cache.miss" => MetricType::CacheMiss,
            b"cache.hit" => MetricType::CacheHit,
            b"cache.stale" => MetricType::CacheStale,
            b"cache.entry-too-large" => MetricType::CacheEntryTooLarge,
            b"cache.swap-hit" => MetricType::CacheSwapHit,
            b"cache.swap-miss" => MetricType::CacheSwapMiss,
            b"cache.swap-write" => MetricType::CacheSwapWrite,
            b"cache.swap-error" => MetricType::CacheSwapError,
            b"calendar.alarm-sent" => MetricType::CalendarAlarmSent,
            b"calendar.alarm-failed" => MetricType::CalendarAlarmFailed,
            b"calendar.itip-message-sent" => MetricType::CalendarItipMessageSent,
            b"calendar.itip-message-received" => MetricType::CalendarItipMessageReceived,
            b"calendar.itip-message-error" => MetricType::CalendarItipMessageError,
            b"cluster.subscriber-error" => MetricType::ClusterSubscriberError,
            b"cluster.subscriber-disconnected" => MetricType::ClusterSubscriberDisconnected,
            b"cluster.publisher-error" => MetricType::ClusterPublisherError,
            b"dane.authentication-success" => MetricType::DaneAuthenticationSuccess,
            b"dane.authentication-failure" => MetricType::DaneAuthenticationFailure,
            b"dane.no-certificates-found" => MetricType::DaneNoCertificatesFound,
            b"dane.certificate-parse-error" => MetricType::DaneCertificateParseError,
            b"dane.tlsa-record-fetch-error" => MetricType::DaneTlsaRecordFetchError,
            b"dane.tlsa-record-not-found" => MetricType::DaneTlsaRecordNotFound,
            b"dane.tlsa-record-not-dnssec-signed" => MetricType::DaneTlsaRecordNotDnssecSigned,
            b"dane.tlsa-record-invalid" => MetricType::DaneTlsaRecordInvalid,
            b"dane.bogus-dnssec-record" => MetricType::DaneBogusDnssecRecord,
            b"delivery.total-time" => MetricType::DeliveryTotalTime,
            b"delivery.attempt-time" => MetricType::DeliveryAttemptTime,
            b"delivery.active-connections" => MetricType::DeliveryActiveConnections,
            b"delivery.attempt-start" => MetricType::DeliveryAttemptStart,
            b"delivery.attempt-end" => MetricType::DeliveryAttemptEnd,
            b"delivery.completed" => MetricType::DeliveryCompleted,
            b"delivery.mx-lookup-failed" => MetricType::DeliveryMxLookupFailed,
            b"delivery.ip-lookup-failed" => MetricType::DeliveryIpLookupFailed,
            b"delivery.null-mx" => MetricType::DeliveryNullMx,
            b"delivery.greeting-failed" => MetricType::DeliveryGreetingFailed,
            b"delivery.ehlo-rejected" => MetricType::DeliveryEhloRejected,
            b"delivery.auth-failed" => MetricType::DeliveryAuthFailed,
            b"delivery.mail-from-rejected" => MetricType::DeliveryMailFromRejected,
            b"delivery.delivered" => MetricType::DeliveryDelivered,
            b"delivery.rcpt-to-rejected" => MetricType::DeliveryRcptToRejected,
            b"delivery.rcpt-to-failed" => MetricType::DeliveryRcptToFailed,
            b"delivery.message-rejected" => MetricType::DeliveryMessageRejected,
            b"delivery.start-tls-unavailable" => MetricType::DeliveryStartTlsUnavailable,
            b"delivery.start-tls-error" => MetricType::DeliveryStartTlsError,
            b"delivery.start-tls-disabled" => MetricType::DeliveryStartTlsDisabled,
            b"delivery.implicit-tls-error" => MetricType::DeliveryImplicitTlsError,
            b"delivery.concurrency-limit-exceeded" => MetricType::DeliveryConcurrencyLimitExceeded,
            b"delivery.rate-limit-exceeded" => MetricType::DeliveryRateLimitExceeded,
            b"delivery.double-bounce" => MetricType::DeliveryDoubleBounce,
            b"delivery.dsn-success" => MetricType::DeliveryDsnSuccess,
            b"delivery.dsn-temp-fail" => MetricType::DeliveryDsnTempFail,
            b"delivery.dsn-perm-fail" => MetricType::DeliveryDsnPermFail,
            b"dkim.pass" => MetricType::DkimPass,
            b"dkim.neutral" => MetricType::DkimNeutral,
            b"dkim.fail" => MetricType::DkimFail,
            b"dkim.perm-error" => MetricType::DkimPermError,
            b"dkim.temp-error" => MetricType::DkimTempError,
            b"dkim.none" => MetricType::DkimNone,
            b"dkim.signature-invalid" => MetricType::DkimSignatureInvalid,
            b"dkim.public-key-error" => MetricType::DkimPublicKeyError,
            b"dkim.verification-failed" => MetricType::DkimVerificationFailed,
            b"dkim.hash-mismatch" => MetricType::DkimHashMismatch,
            b"dkim.signer-not-found" => MetricType::DkimSignerNotFound,
            b"dkim2.instance-invalid" => MetricType::Dkim2InstanceInvalid,
            b"dkim2.signature-invalid" => MetricType::Dkim2SignatureInvalid,
            b"dkim2.chain-invalid" => MetricType::Dkim2ChainInvalid,
            b"dkim2.timestamp-invalid" => MetricType::Dkim2TimestampInvalid,
            b"dkim2.envelope-mismatch" => MetricType::Dkim2EnvelopeMismatch,
            b"dkim2.custody-broken" => MetricType::Dkim2CustodyBroken,
            b"dkim2.public-key-error" => MetricType::Dkim2PublicKeyError,
            b"dkim2.verification-failed" => MetricType::Dkim2VerificationFailed,
            b"dkim2.hash-mismatch" => MetricType::Dkim2HashMismatch,
            b"dkim2.recipe-error" => MetricType::Dkim2RecipeError,
            b"dkim2.signing-failed" => MetricType::Dkim2SigningFailed,
            b"dmarc.pass" => MetricType::DmarcPass,
            b"dmarc.fail" => MetricType::DmarcFail,
            b"dmarc.perm-error" => MetricType::DmarcPermError,
            b"dmarc.temp-error" => MetricType::DmarcTempError,
            b"dmarc.none" => MetricType::DmarcNone,
            b"dns.lookup-time" => MetricType::DnsLookupTime,
            b"dns.record-creation-failed" => MetricType::DnsRecordCreationFailed,
            b"dns.record-deletion-failed" => MetricType::DnsRecordDeletionFailed,
            b"dns.record-lookup-failed" => MetricType::DnsRecordLookupFailed,
            b"dns.record-propagation-timeout" => MetricType::DnsRecordPropagationTimeout,
            b"domain.count" => MetricType::DomainCount,
            b"eval.error" => MetricType::EvalError,
            b"eval.directory-not-found" => MetricType::EvalDirectoryNotFound,
            b"eval.store-not-found" => MetricType::EvalStoreNotFound,
            b"http.request-time" => MetricType::HttpRequestTime,
            b"http.active-connections" => MetricType::HttpActiveConnections,
            b"http.connection-start" => MetricType::HttpConnectionStart,
            b"http.error" => MetricType::HttpError,
            b"http.request-body" => MetricType::HttpRequestBody,
            b"http.response-body" => MetricType::HttpResponseBody,
            b"http.x-forwarded-missing" => MetricType::HttpXForwardedMissing,
            b"http.x-forwarded-invalid" => MetricType::HttpXForwardedInvalid,
            b"imap.request-time" => MetricType::ImapRequestTime,
            b"imap.active-connections" => MetricType::ImapActiveConnections,
            b"imap.connection-start" => MetricType::ImapConnectionStart,
            b"imap.connection-end" => MetricType::ImapConnectionEnd,
            b"incoming-report.dmarc-report" => MetricType::IncomingReportDmarcReport,
            b"incoming-report.dmarc-report-with-warnings" => MetricType::IncomingReportDmarcReportWithWarnings,
            b"incoming-report.tls-report" => MetricType::IncomingReportTlsReport,
            b"incoming-report.tls-report-with-warnings" => MetricType::IncomingReportTlsReportWithWarnings,
            b"incoming-report.abuse-report" => MetricType::IncomingReportAbuseReport,
            b"incoming-report.auth-failure-report" => MetricType::IncomingReportAuthFailureReport,
            b"incoming-report.fraud-report" => MetricType::IncomingReportFraudReport,
            b"incoming-report.not-spam-report" => MetricType::IncomingReportNotSpamReport,
            b"incoming-report.virus-report" => MetricType::IncomingReportVirusReport,
            b"incoming-report.other-report" => MetricType::IncomingReportOtherReport,
            b"incoming-report.message-parse-failed" => MetricType::IncomingReportMessageParseFailed,
            b"incoming-report.dmarc-parse-failed" => MetricType::IncomingReportDmarcParseFailed,
            b"incoming-report.tls-rpc-parse-failed" => MetricType::IncomingReportTlsRpcParseFailed,
            b"incoming-report.arf-parse-failed" => MetricType::IncomingReportArfParseFailed,
            b"incoming-report.decompress-error" => MetricType::IncomingReportDecompressError,
            b"iprev.pass" => MetricType::IprevPass,
            b"iprev.fail" => MetricType::IprevFail,
            b"iprev.perm-error" => MetricType::IprevPermError,
            b"iprev.temp-error" => MetricType::IprevTempError,
            b"iprev.none" => MetricType::IprevNone,
            b"jmap.method-call" => MetricType::JmapMethodCall,
            b"jmap.invalid-arguments" => MetricType::JmapInvalidArguments,
            b"jmap.request-too-large" => MetricType::JmapRequestTooLarge,
            b"jmap.unsupported-filter" => MetricType::JmapUnsupportedFilter,
            b"jmap.unsupported-sort" => MetricType::JmapUnsupportedSort,
            b"jmap.unknown-method" => MetricType::JmapUnknownMethod,
            b"jmap.forbidden" => MetricType::JmapForbidden,
            b"jmap.not-json" => MetricType::JmapNotJson,
            b"jmap.not-request" => MetricType::JmapNotRequest,
            b"jmap.websocket-start" => MetricType::JmapWebsocketStart,
            b"jmap.websocket-error" => MetricType::JmapWebsocketError,
            b"limit.size-request" => MetricType::LimitSizeRequest,
            b"limit.size-upload" => MetricType::LimitSizeUpload,
            b"limit.calls-in" => MetricType::LimitCallsIn,
            b"limit.concurrent-request" => MetricType::LimitConcurrentRequest,
            b"limit.concurrent-upload" => MetricType::LimitConcurrentUpload,
            b"limit.concurrent-connection" => MetricType::LimitConcurrentConnection,
            b"limit.quota" => MetricType::LimitQuota,
            b"limit.blob-quota" => MetricType::LimitBlobQuota,
            b"limit.too-many-requests" => MetricType::LimitTooManyRequests,
            b"limit.memory-budget" => MetricType::LimitMemoryBudget,
            b"mail-auth.parse-error" => MetricType::MailAuthParseError,
            b"mail-auth.missing-parameters" => MetricType::MailAuthMissingParameters,
            b"mail-auth.no-headers-found" => MetricType::MailAuthNoHeadersFound,
            b"mail-auth.crypto" => MetricType::MailAuthCrypto,
            b"mail-auth.io" => MetricType::MailAuthIo,
            b"mail-auth.base64" => MetricType::MailAuthBase64,
            b"mail-auth.dns-error" => MetricType::MailAuthDnsError,
            b"mail-auth.dns-record-not-found" => MetricType::MailAuthDnsRecordNotFound,
            b"mail-auth.dns-invalid-record-type" => MetricType::MailAuthDnsInvalidRecordType,
            b"mail-auth.policy-not-aligned" => MetricType::MailAuthPolicyNotAligned,
            b"manage-sieve.connection-start" => MetricType::ManageSieveConnectionStart,
            b"manage-sieve.connection-end" => MetricType::ManageSieveConnectionEnd,
            b"message.size" => MetricType::MessageSize,
            b"message.authenticated-size" => MetricType::MessageAuthenticatedSize,
            b"message-ingest.time" => MetricType::MessageIngestTime,
            b"message-ingest.ham" => MetricType::MessageIngestHam,
            b"message-ingest.spam" => MetricType::MessageIngestSpam,
            b"message-ingest.imap-append" => MetricType::MessageIngestImapAppend,
            b"message-ingest.jmap-append" => MetricType::MessageIngestJmapAppend,
            b"message-ingest.duplicate" => MetricType::MessageIngestDuplicate,
            b"message-ingest.error" => MetricType::MessageIngestError,
            b"milter.action-accept" => MetricType::MilterActionAccept,
            b"milter.action-discard" => MetricType::MilterActionDiscard,
            b"milter.action-reject" => MetricType::MilterActionReject,
            b"milter.action-temp-fail" => MetricType::MilterActionTempFail,
            b"milter.action-reply-code" => MetricType::MilterActionReplyCode,
            b"milter.action-connection-failure" => MetricType::MilterActionConnectionFailure,
            b"milter.action-shutdown" => MetricType::MilterActionShutdown,
            b"mta-hook.action-accept" => MetricType::MtaHookActionAccept,
            b"mta-hook.action-discard" => MetricType::MtaHookActionDiscard,
            b"mta-hook.action-reject" => MetricType::MtaHookActionReject,
            b"mta-hook.action-quarantine" => MetricType::MtaHookActionQuarantine,
            b"mta-hook.error" => MetricType::MtaHookError,
            b"mta-sts.authorized" => MetricType::MtaStsAuthorized,
            b"mta-sts.not-authorized" => MetricType::MtaStsNotAuthorized,
            b"mta-sts.invalid-policy" => MetricType::MtaStsInvalidPolicy,
            b"network.timeout" => MetricType::NetworkTimeout,
            b"outgoing-report.size" => MetricType::OutgoingReportSize,
            b"outgoing-report.spf-report" => MetricType::OutgoingReportSpfReport,
            b"outgoing-report.spf-rate-limited" => MetricType::OutgoingReportSpfRateLimited,
            b"outgoing-report.dkim-report" => MetricType::OutgoingReportDkimReport,
            b"outgoing-report.dkim-rate-limited" => MetricType::OutgoingReportDkimRateLimited,
            b"outgoing-report.dmarc-report" => MetricType::OutgoingReportDmarcReport,
            b"outgoing-report.dmarc-rate-limited" => MetricType::OutgoingReportDmarcRateLimited,
            b"outgoing-report.dmarc-aggregate-report" => MetricType::OutgoingReportDmarcAggregateReport,
            b"outgoing-report.tls-aggregate" => MetricType::OutgoingReportTlsAggregate,
            b"outgoing-report.http-submission" => MetricType::OutgoingReportHttpSubmission,
            b"outgoing-report.unauthorized-reporting-address" => MetricType::OutgoingReportUnauthorizedReportingAddress,
            b"outgoing-report.reporting-address-validation-error" => MetricType::OutgoingReportReportingAddressValidationError,
            b"outgoing-report.not-found" => MetricType::OutgoingReportNotFound,
            b"outgoing-report.submission-error" => MetricType::OutgoingReportSubmissionError,
            b"outgoing-report.no-recipients-found" => MetricType::OutgoingReportNoRecipientsFound,
            b"pop3.request-time" => MetricType::Pop3RequestTime,
            b"pop3.active-connections" => MetricType::Pop3ActiveConnections,
            b"pop3.connection-start" => MetricType::Pop3ConnectionStart,
            b"pop3.connection-end" => MetricType::Pop3ConnectionEnd,
            b"push-subscription.success" => MetricType::PushSubscriptionSuccess,
            b"push-subscription.error" => MetricType::PushSubscriptionError,
            b"push-subscription.not-found" => MetricType::PushSubscriptionNotFound,
            b"queue.count" => MetricType::QueueCount,
            b"queue.message-queued" => MetricType::QueueMessageQueued,
            b"queue.authenticated-message-queued" => MetricType::QueueAuthenticatedMessageQueued,
            b"queue.report-queued" => MetricType::QueueReportQueued,
            b"queue.dsn-queued" => MetricType::QueueDsnQueued,
            b"queue.autogenerated-queued" => MetricType::QueueAutogeneratedQueued,
            b"queue.rescheduled" => MetricType::QueueRescheduled,
            b"queue.blob-not-found" => MetricType::QueueBlobNotFound,
            b"queue.rate-limit-exceeded" => MetricType::QueueRateLimitExceeded,
            b"queue.concurrency-limit-exceeded" => MetricType::QueueConcurrencyLimitExceeded,
            b"queue.quota-exceeded" => MetricType::QueueQuotaExceeded,
            b"queue.back-pressure" => MetricType::QueueBackPressure,
            b"resource.not-found" => MetricType::ResourceNotFound,
            b"resource.bad-parameters" => MetricType::ResourceBadParameters,
            b"resource.error" => MetricType::ResourceError,
            b"search-index.index-time" => MetricType::SearchIndexIndexTime,
            b"search-index.pending-email" => MetricType::SearchIndexPendingEmail,
            b"search-index.pending-calendar" => MetricType::SearchIndexPendingCalendar,
            b"search-index.pending-contacts" => MetricType::SearchIndexPendingContacts,
            b"search-index.pending-file" => MetricType::SearchIndexPendingFile,
            b"search-index.partition-retry" => MetricType::SearchIndexPartitionRetry,
            b"search-index.batch-indexed" => MetricType::SearchIndexBatchIndexed,
            b"search-index.document-truncated" => MetricType::SearchIndexDocumentTruncated,
            b"security.authentication-ban" => MetricType::SecurityAuthenticationBan,
            b"security.abuse-ban" => MetricType::SecurityAbuseBan,
            b"security.scan-ban" => MetricType::SecurityScanBan,
            b"security.loiter-ban" => MetricType::SecurityLoiterBan,
            b"security.ip-blocked" => MetricType::SecurityIpBlocked,
            b"security.unauthorized" => MetricType::SecurityUnauthorized,
            b"server.memory" => MetricType::ServerMemory,
            b"server.buffered-memory-smtp" => MetricType::ServerBufferedMemorySmtp,
            b"server.buffered-memory-read" => MetricType::ServerBufferedMemoryRead,
            b"server.thread-error" => MetricType::ServerThreadError,
            b"sieve.request-time" => MetricType::SieveRequestTime,
            b"sieve.active-connections" => MetricType::SieveActiveConnections,
            b"sieve.action-accept" => MetricType::SieveActionAccept,
            b"sieve.action-accept-replace" => MetricType::SieveActionAcceptReplace,
            b"sieve.action-discard" => MetricType::SieveActionDiscard,
            b"sieve.action-reject" => MetricType::SieveActionReject,
            b"sieve.send-message" => MetricType::SieveSendMessage,
            b"sieve.message-too-large" => MetricType::SieveMessageTooLarge,
            b"sieve.runtime-error" => MetricType::SieveRuntimeError,
            b"sieve.unexpected-error" => MetricType::SieveUnexpectedError,
            b"sieve.not-supported" => MetricType::SieveNotSupported,
            b"sieve.quota-exceeded" => MetricType::SieveQuotaExceeded,
            b"smtp.request-time" => MetricType::SmtpRequestTime,
            b"smtp.active-connections" => MetricType::SmtpActiveConnections,
            b"smtp.connection-start" => MetricType::SmtpConnectionStart,
            b"smtp.connection-end" => MetricType::SmtpConnectionEnd,
            b"smtp.error" => MetricType::SmtpError,
            b"smtp.concurrency-limit-exceeded" => MetricType::SmtpConcurrencyLimitExceeded,
            b"smtp.transfer-limit-exceeded" => MetricType::SmtpTransferLimitExceeded,
            b"smtp.rate-limit-exceeded" => MetricType::SmtpRateLimitExceeded,
            b"smtp.time-limit-exceeded" => MetricType::SmtpTimeLimitExceeded,
            b"smtp.message-parse-failed" => MetricType::SmtpMessageParseFailed,
            b"smtp.message-too-large" => MetricType::SmtpMessageTooLarge,
            b"smtp.loop-detected" => MetricType::SmtpLoopDetected,
            b"smtp.multiple-from-domains" => MetricType::SmtpMultipleFromDomains,
            b"smtp.dkim-pass" => MetricType::SmtpDkimPass,
            b"smtp.dkim-fail" => MetricType::SmtpDkimFail,
            b"smtp.dkim2-pass" => MetricType::SmtpDkim2Pass,
            b"smtp.dkim2-fail" => MetricType::SmtpDkim2Fail,
            b"smtp.dkim2-dsn-rejected" => MetricType::SmtpDkim2DsnRejected,
            b"smtp.arc-pass" => MetricType::SmtpArcPass,
            b"smtp.arc-fail" => MetricType::SmtpArcFail,
            b"smtp.spf-ehlo-pass" => MetricType::SmtpSpfEhloPass,
            b"smtp.spf-ehlo-fail" => MetricType::SmtpSpfEhloFail,
            b"smtp.spf-from-pass" => MetricType::SmtpSpfFromPass,
            b"smtp.spf-from-fail" => MetricType::SmtpSpfFromFail,
            b"smtp.dmarc-pass" => MetricType::SmtpDmarcPass,
            b"smtp.dmarc-fail" => MetricType::SmtpDmarcFail,
            b"smtp.iprev-pass" => MetricType::SmtpIprevPass,
            b"smtp.iprev-fail" => MetricType::SmtpIprevFail,
            b"smtp.too-many-messages" => MetricType::SmtpTooManyMessages,
            b"smtp.invalid-ehlo" => MetricType::SmtpInvalidEhlo,
            b"smtp.did-not-say-ehlo" => MetricType::SmtpDidNotSayEhlo,
            b"smtp.mail-from-unauthenticated" => MetricType::SmtpMailFromUnauthenticated,
            b"smtp.mail-from-unauthorized" => MetricType::SmtpMailFromUnauthorized,
            b"smtp.mail-from-missing" => MetricType::SmtpMailFromMissing,
            b"smtp.multiple-mail-from" => MetricType::SmtpMultipleMailFrom,
            b"smtp.mailbox-does-not-exist" => MetricType::SmtpMailboxDoesNotExist,
            b"smtp.relay-not-allowed" => MetricType::SmtpRelayNotAllowed,
            b"smtp.rcpt-to-duplicate" => MetricType::SmtpRcptToDuplicate,
            b"smtp.rcpt-to-missing" => MetricType::SmtpRcptToMissing,
            b"smtp.too-many-recipients" => MetricType::SmtpTooManyRecipients,
            b"smtp.too-many-invalid-rcpt" => MetricType::SmtpTooManyInvalidRcpt,
            b"smtp.auth-mechanism-not-supported" => MetricType::SmtpAuthMechanismNotSupported,
            b"smtp.auth-exchange-too-long" => MetricType::SmtpAuthExchangeTooLong,
            b"smtp.command-not-implemented" => MetricType::SmtpCommandNotImplemented,
            b"smtp.invalid-command" => MetricType::SmtpInvalidCommand,
            b"smtp.syntax-error" => MetricType::SmtpSyntaxError,
            b"smtp.request-too-large" => MetricType::SmtpRequestTooLarge,
            b"spam.pyzor-error" => MetricType::SpamPyzorError,
            b"spam.dnsbl-error" => MetricType::SpamDnsblError,
            b"spam.train-completed" => MetricType::SpamTrainCompleted,
            b"spam.train-sample-added" => MetricType::SpamTrainSampleAdded,
            b"spam.classify" => MetricType::SpamClassify,
            b"spam.model-not-ready" => MetricType::SpamModelNotReady,
            b"spf.pass" => MetricType::SpfPass,
            b"spf.fail" => MetricType::SpfFail,
            b"spf.soft-fail" => MetricType::SpfSoftFail,
            b"spf.neutral" => MetricType::SpfNeutral,
            b"spf.temp-error" => MetricType::SpfTempError,
            b"spf.perm-error" => MetricType::SpfPermError,
            b"spf.none" => MetricType::SpfNone,
            b"store.data-read-time" => MetricType::StoreDataReadTime,
            b"store.data-write-time" => MetricType::StoreDataWriteTime,
            b"store.blob-read-time" => MetricType::StoreBlobReadTime,
            b"store.blob-write-time" => MetricType::StoreBlobWriteTime,
            b"store.assert-value-failed" => MetricType::StoreAssertValueFailed,
            b"store.foundationdb-error" => MetricType::StoreFoundationdbError,
            b"store.mysql-error" => MetricType::StoreMysqlError,
            b"store.postgresql-error" => MetricType::StorePostgresqlError,
            b"store.rocksdb-error" => MetricType::StoreRocksdbError,
            b"store.sqlite-error" => MetricType::StoreSqliteError,
            b"store.ldap-error" => MetricType::StoreLdapError,
            b"store.elasticsearch-error" => MetricType::StoreElasticsearchError,
            b"store.redis-error" => MetricType::StoreRedisError,
            b"store.s3-error" => MetricType::StoreS3Error,
            b"store.azure-error" => MetricType::StoreAzureError,
            b"store.filesystem-error" => MetricType::StoreFilesystemError,
            b"store.pool-error" => MetricType::StorePoolError,
            b"store.data-corruption" => MetricType::StoreDataCorruption,
            b"store.decompress-error" => MetricType::StoreDecompressError,
            b"store.deserialize-error" => MetricType::StoreDeserializeError,
            b"store.not-found" => MetricType::StoreNotFound,
            b"store.not-configured" => MetricType::StoreNotConfigured,
            b"store.not-supported" => MetricType::StoreNotSupported,
            b"store.unexpected-error" => MetricType::StoreUnexpectedError,
            b"store.crypto-error" => MetricType::StoreCryptoError,
            b"store.http-store-error" => MetricType::StoreHttpStoreError,
            b"store.blob-missing-marker" => MetricType::StoreBlobMissingMarker,
            b"store.data-write" => MetricType::StoreDataWrite,
            b"store.data-iterate" => MetricType::StoreDataIterate,
            b"store.blob-read" => MetricType::StoreBlobRead,
            b"store.blob-write" => MetricType::StoreBlobWrite,
            b"store.blob-delete" => MetricType::StoreBlobDelete,
            b"task-manager.pending" => MetricType::TaskManagerPending,
            b"task-manager.due" => MetricType::TaskManagerDue,
            b"task-manager.task-failed" => MetricType::TaskManagerTaskFailed,
            b"task-manager.task-retry" => MetricType::TaskManagerTaskRetry,
            b"task-manager.task-stalled" => MetricType::TaskManagerTaskStalled,
            b"task-manager.task-expired" => MetricType::TaskManagerTaskExpired,
            b"task-manager.blob-not-found" => MetricType::TaskManagerBlobNotFound,
            b"task-manager.metadata-not-found" => MetricType::TaskManagerMetadataNotFound,
            b"telemetry.log-error" => MetricType::TelemetryLogError,
            b"telemetry.webhook-error" => MetricType::TelemetryWebhookError,
            b"telemetry.otel-exporter-error" => MetricType::TelemetryOtelExporterError,
            b"telemetry.otel-metrics-exporter-error" => MetricType::TelemetryOtelMetricsExporterError,
            b"telemetry.prometheus-exporter-error" => MetricType::TelemetryPrometheusExporterError,
            b"telemetry.journal-error" => MetricType::TelemetryJournalError,
            b"telemetry.events-dropped" => MetricType::TelemetryEventsDropped,
            b"tls.handshake-error" => MetricType::TlsHandshakeError,
            b"user.count" => MetricType::UserCount,
        }
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MetricType::AcmeAuthError => "acme.auth-error",
            MetricType::AcmeAuthTooManyAttempts => "acme.auth-too-many-attempts",
            MetricType::AcmeOrderCompleted => "acme.order-completed",
            MetricType::AcmeOrderInvalid => "acme.order-invalid",
            MetricType::AcmeClientMissingSni => "acme.client-missing-sni",
            MetricType::AcmeTlsAlpnError => "acme.tls-alpn-error",
            MetricType::AcmeTokenNotFound => "acme.token-not-found",
            MetricType::AcmeError => "acme.error",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => "ai.request-time",
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => "ai.input-tokens",
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => "ai.output-tokens",
            #[cfg(feature = "enterprise")]
            MetricType::AiApiError => "ai.api-error",
            #[cfg(feature = "enterprise")]
            MetricType::AiRequest => "ai.request",
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamVerdict => "ai.spam-verdict",
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamSkipped => "ai.spam-skipped",
            #[cfg(feature = "enterprise")]
            MetricType::AiBreakerOpen => "ai.breaker-open",
            // SPDX-SnippetEnd
            MetricType::ArcChainInvalid => "arc.chain-invalid",
            MetricType::ArcSignatureInvalid => "arc.signature-invalid",
            MetricType::ArcHashMismatch => "arc.hash-mismatch",
            MetricType::AuthSuccess => "auth.success",
            MetricType::AuthFailed => "auth.failed",
            MetricType::AuthTooManyAttempts => "auth.too-many-attempts",
            MetricType::AuthError => "auth.error",
            MetricType::CacheMessagesSize => "cache.messages-size",
            MetricType::CacheMessagesLargeSize => "cache.messages-large-size",
            MetricType::CacheSize => "cache.size",
            MetricType::CacheSwapPending => "cache.swap-pending",
            MetricType::CacheMiss => "cache.miss",
            MetricType::CacheHit => "cache.hit",
            MetricType::CacheStale => "cache.stale",
            MetricType::CacheEntryTooLarge => "cache.entry-too-large",
            MetricType::CacheSwapHit => "cache.swap-hit",
            MetricType::CacheSwapMiss => "cache.swap-miss",
            MetricType::CacheSwapWrite => "cache.swap-write",
            MetricType::CacheSwapError => "cache.swap-error",
            MetricType::CalendarAlarmSent => "calendar.alarm-sent",
            MetricType::CalendarAlarmFailed => "calendar.alarm-failed",
            MetricType::CalendarItipMessageSent => "calendar.itip-message-sent",
            MetricType::CalendarItipMessageReceived => "calendar.itip-message-received",
            MetricType::CalendarItipMessageError => "calendar.itip-message-error",
            MetricType::ClusterSubscriberError => "cluster.subscriber-error",
            MetricType::ClusterSubscriberDisconnected => "cluster.subscriber-disconnected",
            MetricType::ClusterPublisherError => "cluster.publisher-error",
            MetricType::DaneAuthenticationSuccess => "dane.authentication-success",
            MetricType::DaneAuthenticationFailure => "dane.authentication-failure",
            MetricType::DaneNoCertificatesFound => "dane.no-certificates-found",
            MetricType::DaneCertificateParseError => "dane.certificate-parse-error",
            MetricType::DaneTlsaRecordFetchError => "dane.tlsa-record-fetch-error",
            MetricType::DaneTlsaRecordNotFound => "dane.tlsa-record-not-found",
            MetricType::DaneTlsaRecordNotDnssecSigned => "dane.tlsa-record-not-dnssec-signed",
            MetricType::DaneTlsaRecordInvalid => "dane.tlsa-record-invalid",
            MetricType::DaneBogusDnssecRecord => "dane.bogus-dnssec-record",
            MetricType::DeliveryTotalTime => "delivery.total-time",
            MetricType::DeliveryAttemptTime => "delivery.attempt-time",
            MetricType::DeliveryActiveConnections => "delivery.active-connections",
            MetricType::DeliveryAttemptStart => "delivery.attempt-start",
            MetricType::DeliveryAttemptEnd => "delivery.attempt-end",
            MetricType::DeliveryCompleted => "delivery.completed",
            MetricType::DeliveryMxLookupFailed => "delivery.mx-lookup-failed",
            MetricType::DeliveryIpLookupFailed => "delivery.ip-lookup-failed",
            MetricType::DeliveryNullMx => "delivery.null-mx",
            MetricType::DeliveryGreetingFailed => "delivery.greeting-failed",
            MetricType::DeliveryEhloRejected => "delivery.ehlo-rejected",
            MetricType::DeliveryAuthFailed => "delivery.auth-failed",
            MetricType::DeliveryMailFromRejected => "delivery.mail-from-rejected",
            MetricType::DeliveryDelivered => "delivery.delivered",
            MetricType::DeliveryRcptToRejected => "delivery.rcpt-to-rejected",
            MetricType::DeliveryRcptToFailed => "delivery.rcpt-to-failed",
            MetricType::DeliveryMessageRejected => "delivery.message-rejected",
            MetricType::DeliveryStartTlsUnavailable => "delivery.start-tls-unavailable",
            MetricType::DeliveryStartTlsError => "delivery.start-tls-error",
            MetricType::DeliveryStartTlsDisabled => "delivery.start-tls-disabled",
            MetricType::DeliveryImplicitTlsError => "delivery.implicit-tls-error",
            MetricType::DeliveryConcurrencyLimitExceeded => "delivery.concurrency-limit-exceeded",
            MetricType::DeliveryRateLimitExceeded => "delivery.rate-limit-exceeded",
            MetricType::DeliveryDoubleBounce => "delivery.double-bounce",
            MetricType::DeliveryDsnSuccess => "delivery.dsn-success",
            MetricType::DeliveryDsnTempFail => "delivery.dsn-temp-fail",
            MetricType::DeliveryDsnPermFail => "delivery.dsn-perm-fail",
            MetricType::DkimPass => "dkim.pass",
            MetricType::DkimNeutral => "dkim.neutral",
            MetricType::DkimFail => "dkim.fail",
            MetricType::DkimPermError => "dkim.perm-error",
            MetricType::DkimTempError => "dkim.temp-error",
            MetricType::DkimNone => "dkim.none",
            MetricType::DkimSignatureInvalid => "dkim.signature-invalid",
            MetricType::DkimPublicKeyError => "dkim.public-key-error",
            MetricType::DkimVerificationFailed => "dkim.verification-failed",
            MetricType::DkimHashMismatch => "dkim.hash-mismatch",
            MetricType::DkimSignerNotFound => "dkim.signer-not-found",
            MetricType::Dkim2InstanceInvalid => "dkim2.instance-invalid",
            MetricType::Dkim2SignatureInvalid => "dkim2.signature-invalid",
            MetricType::Dkim2ChainInvalid => "dkim2.chain-invalid",
            MetricType::Dkim2TimestampInvalid => "dkim2.timestamp-invalid",
            MetricType::Dkim2EnvelopeMismatch => "dkim2.envelope-mismatch",
            MetricType::Dkim2CustodyBroken => "dkim2.custody-broken",
            MetricType::Dkim2PublicKeyError => "dkim2.public-key-error",
            MetricType::Dkim2VerificationFailed => "dkim2.verification-failed",
            MetricType::Dkim2HashMismatch => "dkim2.hash-mismatch",
            MetricType::Dkim2RecipeError => "dkim2.recipe-error",
            MetricType::Dkim2SigningFailed => "dkim2.signing-failed",
            MetricType::DmarcPass => "dmarc.pass",
            MetricType::DmarcFail => "dmarc.fail",
            MetricType::DmarcPermError => "dmarc.perm-error",
            MetricType::DmarcTempError => "dmarc.temp-error",
            MetricType::DmarcNone => "dmarc.none",
            MetricType::DnsLookupTime => "dns.lookup-time",
            MetricType::DnsRecordCreationFailed => "dns.record-creation-failed",
            MetricType::DnsRecordDeletionFailed => "dns.record-deletion-failed",
            MetricType::DnsRecordLookupFailed => "dns.record-lookup-failed",
            MetricType::DnsRecordPropagationTimeout => "dns.record-propagation-timeout",
            MetricType::DomainCount => "domain.count",
            MetricType::EvalError => "eval.error",
            MetricType::EvalDirectoryNotFound => "eval.directory-not-found",
            MetricType::EvalStoreNotFound => "eval.store-not-found",
            MetricType::HttpRequestTime => "http.request-time",
            MetricType::HttpActiveConnections => "http.active-connections",
            MetricType::HttpConnectionStart => "http.connection-start",
            MetricType::HttpError => "http.error",
            MetricType::HttpRequestBody => "http.request-body",
            MetricType::HttpResponseBody => "http.response-body",
            MetricType::HttpXForwardedMissing => "http.x-forwarded-missing",
            MetricType::HttpXForwardedInvalid => "http.x-forwarded-invalid",
            MetricType::ImapRequestTime => "imap.request-time",
            MetricType::ImapActiveConnections => "imap.active-connections",
            MetricType::ImapConnectionStart => "imap.connection-start",
            MetricType::ImapConnectionEnd => "imap.connection-end",
            MetricType::IncomingReportDmarcReport => "incoming-report.dmarc-report",
            MetricType::IncomingReportDmarcReportWithWarnings => {
                "incoming-report.dmarc-report-with-warnings"
            }
            MetricType::IncomingReportTlsReport => "incoming-report.tls-report",
            MetricType::IncomingReportTlsReportWithWarnings => {
                "incoming-report.tls-report-with-warnings"
            }
            MetricType::IncomingReportAbuseReport => "incoming-report.abuse-report",
            MetricType::IncomingReportAuthFailureReport => "incoming-report.auth-failure-report",
            MetricType::IncomingReportFraudReport => "incoming-report.fraud-report",
            MetricType::IncomingReportNotSpamReport => "incoming-report.not-spam-report",
            MetricType::IncomingReportVirusReport => "incoming-report.virus-report",
            MetricType::IncomingReportOtherReport => "incoming-report.other-report",
            MetricType::IncomingReportMessageParseFailed => "incoming-report.message-parse-failed",
            MetricType::IncomingReportDmarcParseFailed => "incoming-report.dmarc-parse-failed",
            MetricType::IncomingReportTlsRpcParseFailed => "incoming-report.tls-rpc-parse-failed",
            MetricType::IncomingReportArfParseFailed => "incoming-report.arf-parse-failed",
            MetricType::IncomingReportDecompressError => "incoming-report.decompress-error",
            MetricType::IprevPass => "iprev.pass",
            MetricType::IprevFail => "iprev.fail",
            MetricType::IprevPermError => "iprev.perm-error",
            MetricType::IprevTempError => "iprev.temp-error",
            MetricType::IprevNone => "iprev.none",
            MetricType::JmapMethodCall => "jmap.method-call",
            MetricType::JmapInvalidArguments => "jmap.invalid-arguments",
            MetricType::JmapRequestTooLarge => "jmap.request-too-large",
            MetricType::JmapUnsupportedFilter => "jmap.unsupported-filter",
            MetricType::JmapUnsupportedSort => "jmap.unsupported-sort",
            MetricType::JmapUnknownMethod => "jmap.unknown-method",
            MetricType::JmapForbidden => "jmap.forbidden",
            MetricType::JmapNotJson => "jmap.not-json",
            MetricType::JmapNotRequest => "jmap.not-request",
            MetricType::JmapWebsocketStart => "jmap.websocket-start",
            MetricType::JmapWebsocketError => "jmap.websocket-error",
            MetricType::LimitSizeRequest => "limit.size-request",
            MetricType::LimitSizeUpload => "limit.size-upload",
            MetricType::LimitCallsIn => "limit.calls-in",
            MetricType::LimitConcurrentRequest => "limit.concurrent-request",
            MetricType::LimitConcurrentUpload => "limit.concurrent-upload",
            MetricType::LimitConcurrentConnection => "limit.concurrent-connection",
            MetricType::LimitQuota => "limit.quota",
            MetricType::LimitBlobQuota => "limit.blob-quota",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::LimitTenantQuota => "limit.tenant-quota",
            // SPDX-SnippetEnd
            MetricType::LimitTooManyRequests => "limit.too-many-requests",
            MetricType::LimitMemoryBudget => "limit.memory-budget",
            MetricType::MailAuthParseError => "mail-auth.parse-error",
            MetricType::MailAuthMissingParameters => "mail-auth.missing-parameters",
            MetricType::MailAuthNoHeadersFound => "mail-auth.no-headers-found",
            MetricType::MailAuthCrypto => "mail-auth.crypto",
            MetricType::MailAuthIo => "mail-auth.io",
            MetricType::MailAuthBase64 => "mail-auth.base64",
            MetricType::MailAuthDnsError => "mail-auth.dns-error",
            MetricType::MailAuthDnsRecordNotFound => "mail-auth.dns-record-not-found",
            MetricType::MailAuthDnsInvalidRecordType => "mail-auth.dns-invalid-record-type",
            MetricType::MailAuthPolicyNotAligned => "mail-auth.policy-not-aligned",
            MetricType::ManageSieveConnectionStart => "manage-sieve.connection-start",
            MetricType::ManageSieveConnectionEnd => "manage-sieve.connection-end",
            MetricType::MessageSize => "message.size",
            MetricType::MessageAuthenticatedSize => "message.authenticated-size",
            MetricType::MessageIngestTime => "message-ingest.time",
            MetricType::MessageIngestHam => "message-ingest.ham",
            MetricType::MessageIngestSpam => "message-ingest.spam",
            MetricType::MessageIngestImapAppend => "message-ingest.imap-append",
            MetricType::MessageIngestJmapAppend => "message-ingest.jmap-append",
            MetricType::MessageIngestDuplicate => "message-ingest.duplicate",
            MetricType::MessageIngestError => "message-ingest.error",
            MetricType::MilterActionAccept => "milter.action-accept",
            MetricType::MilterActionDiscard => "milter.action-discard",
            MetricType::MilterActionReject => "milter.action-reject",
            MetricType::MilterActionTempFail => "milter.action-temp-fail",
            MetricType::MilterActionReplyCode => "milter.action-reply-code",
            MetricType::MilterActionConnectionFailure => "milter.action-connection-failure",
            MetricType::MilterActionShutdown => "milter.action-shutdown",
            MetricType::MtaHookActionAccept => "mta-hook.action-accept",
            MetricType::MtaHookActionDiscard => "mta-hook.action-discard",
            MetricType::MtaHookActionReject => "mta-hook.action-reject",
            MetricType::MtaHookActionQuarantine => "mta-hook.action-quarantine",
            MetricType::MtaHookError => "mta-hook.error",
            MetricType::MtaStsAuthorized => "mta-sts.authorized",
            MetricType::MtaStsNotAuthorized => "mta-sts.not-authorized",
            MetricType::MtaStsInvalidPolicy => "mta-sts.invalid-policy",
            MetricType::NetworkTimeout => "network.timeout",
            MetricType::OutgoingReportSize => "outgoing-report.size",
            MetricType::OutgoingReportSpfReport => "outgoing-report.spf-report",
            MetricType::OutgoingReportSpfRateLimited => "outgoing-report.spf-rate-limited",
            MetricType::OutgoingReportDkimReport => "outgoing-report.dkim-report",
            MetricType::OutgoingReportDkimRateLimited => "outgoing-report.dkim-rate-limited",
            MetricType::OutgoingReportDmarcReport => "outgoing-report.dmarc-report",
            MetricType::OutgoingReportDmarcRateLimited => "outgoing-report.dmarc-rate-limited",
            MetricType::OutgoingReportDmarcAggregateReport => {
                "outgoing-report.dmarc-aggregate-report"
            }
            MetricType::OutgoingReportTlsAggregate => "outgoing-report.tls-aggregate",
            MetricType::OutgoingReportHttpSubmission => "outgoing-report.http-submission",
            MetricType::OutgoingReportUnauthorizedReportingAddress => {
                "outgoing-report.unauthorized-reporting-address"
            }
            MetricType::OutgoingReportReportingAddressValidationError => {
                "outgoing-report.reporting-address-validation-error"
            }
            MetricType::OutgoingReportNotFound => "outgoing-report.not-found",
            MetricType::OutgoingReportSubmissionError => "outgoing-report.submission-error",
            MetricType::OutgoingReportNoRecipientsFound => "outgoing-report.no-recipients-found",
            MetricType::Pop3RequestTime => "pop3.request-time",
            MetricType::Pop3ActiveConnections => "pop3.active-connections",
            MetricType::Pop3ConnectionStart => "pop3.connection-start",
            MetricType::Pop3ConnectionEnd => "pop3.connection-end",
            MetricType::PushSubscriptionSuccess => "push-subscription.success",
            MetricType::PushSubscriptionError => "push-subscription.error",
            MetricType::PushSubscriptionNotFound => "push-subscription.not-found",
            MetricType::QueueCount => "queue.count",
            MetricType::QueueMessageQueued => "queue.message-queued",
            MetricType::QueueAuthenticatedMessageQueued => "queue.authenticated-message-queued",
            MetricType::QueueReportQueued => "queue.report-queued",
            MetricType::QueueDsnQueued => "queue.dsn-queued",
            MetricType::QueueAutogeneratedQueued => "queue.autogenerated-queued",
            MetricType::QueueRescheduled => "queue.rescheduled",
            MetricType::QueueBlobNotFound => "queue.blob-not-found",
            MetricType::QueueRateLimitExceeded => "queue.rate-limit-exceeded",
            MetricType::QueueConcurrencyLimitExceeded => "queue.concurrency-limit-exceeded",
            MetricType::QueueQuotaExceeded => "queue.quota-exceeded",
            MetricType::QueueBackPressure => "queue.back-pressure",
            MetricType::ResourceNotFound => "resource.not-found",
            MetricType::ResourceBadParameters => "resource.bad-parameters",
            MetricType::ResourceError => "resource.error",
            MetricType::SearchIndexIndexTime => "search-index.index-time",
            MetricType::SearchIndexPendingEmail => "search-index.pending-email",
            MetricType::SearchIndexPendingCalendar => "search-index.pending-calendar",
            MetricType::SearchIndexPendingContacts => "search-index.pending-contacts",
            MetricType::SearchIndexPendingFile => "search-index.pending-file",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => "search-index.pending-tracing",
            // SPDX-SnippetEnd
            MetricType::SearchIndexPartitionRetry => "search-index.partition-retry",
            MetricType::SearchIndexBatchIndexed => "search-index.batch-indexed",
            MetricType::SearchIndexDocumentTruncated => "search-index.document-truncated",
            MetricType::SecurityAuthenticationBan => "security.authentication-ban",
            MetricType::SecurityAbuseBan => "security.abuse-ban",
            MetricType::SecurityScanBan => "security.scan-ban",
            MetricType::SecurityLoiterBan => "security.loiter-ban",
            MetricType::SecurityIpBlocked => "security.ip-blocked",
            MetricType::SecurityUnauthorized => "security.unauthorized",
            MetricType::ServerMemory => "server.memory",
            MetricType::ServerBufferedMemorySmtp => "server.buffered-memory-smtp",
            MetricType::ServerBufferedMemoryRead => "server.buffered-memory-read",
            MetricType::ServerThreadError => "server.thread-error",
            MetricType::SieveRequestTime => "sieve.request-time",
            MetricType::SieveActiveConnections => "sieve.active-connections",
            MetricType::SieveActionAccept => "sieve.action-accept",
            MetricType::SieveActionAcceptReplace => "sieve.action-accept-replace",
            MetricType::SieveActionDiscard => "sieve.action-discard",
            MetricType::SieveActionReject => "sieve.action-reject",
            MetricType::SieveSendMessage => "sieve.send-message",
            MetricType::SieveMessageTooLarge => "sieve.message-too-large",
            MetricType::SieveRuntimeError => "sieve.runtime-error",
            MetricType::SieveUnexpectedError => "sieve.unexpected-error",
            MetricType::SieveNotSupported => "sieve.not-supported",
            MetricType::SieveQuotaExceeded => "sieve.quota-exceeded",
            MetricType::SmtpRequestTime => "smtp.request-time",
            MetricType::SmtpActiveConnections => "smtp.active-connections",
            MetricType::SmtpConnectionStart => "smtp.connection-start",
            MetricType::SmtpConnectionEnd => "smtp.connection-end",
            MetricType::SmtpError => "smtp.error",
            MetricType::SmtpConcurrencyLimitExceeded => "smtp.concurrency-limit-exceeded",
            MetricType::SmtpTransferLimitExceeded => "smtp.transfer-limit-exceeded",
            MetricType::SmtpRateLimitExceeded => "smtp.rate-limit-exceeded",
            MetricType::SmtpTimeLimitExceeded => "smtp.time-limit-exceeded",
            MetricType::SmtpMessageParseFailed => "smtp.message-parse-failed",
            MetricType::SmtpMessageTooLarge => "smtp.message-too-large",
            MetricType::SmtpLoopDetected => "smtp.loop-detected",
            MetricType::SmtpMultipleFromDomains => "smtp.multiple-from-domains",
            MetricType::SmtpDkimPass => "smtp.dkim-pass",
            MetricType::SmtpDkimFail => "smtp.dkim-fail",
            MetricType::SmtpDkim2Pass => "smtp.dkim2-pass",
            MetricType::SmtpDkim2Fail => "smtp.dkim2-fail",
            MetricType::SmtpDkim2DsnRejected => "smtp.dkim2-dsn-rejected",
            MetricType::SmtpArcPass => "smtp.arc-pass",
            MetricType::SmtpArcFail => "smtp.arc-fail",
            MetricType::SmtpSpfEhloPass => "smtp.spf-ehlo-pass",
            MetricType::SmtpSpfEhloFail => "smtp.spf-ehlo-fail",
            MetricType::SmtpSpfFromPass => "smtp.spf-from-pass",
            MetricType::SmtpSpfFromFail => "smtp.spf-from-fail",
            MetricType::SmtpDmarcPass => "smtp.dmarc-pass",
            MetricType::SmtpDmarcFail => "smtp.dmarc-fail",
            MetricType::SmtpIprevPass => "smtp.iprev-pass",
            MetricType::SmtpIprevFail => "smtp.iprev-fail",
            MetricType::SmtpTooManyMessages => "smtp.too-many-messages",
            MetricType::SmtpInvalidEhlo => "smtp.invalid-ehlo",
            MetricType::SmtpDidNotSayEhlo => "smtp.did-not-say-ehlo",
            MetricType::SmtpMailFromUnauthenticated => "smtp.mail-from-unauthenticated",
            MetricType::SmtpMailFromUnauthorized => "smtp.mail-from-unauthorized",
            MetricType::SmtpMailFromMissing => "smtp.mail-from-missing",
            MetricType::SmtpMultipleMailFrom => "smtp.multiple-mail-from",
            MetricType::SmtpMailboxDoesNotExist => "smtp.mailbox-does-not-exist",
            MetricType::SmtpRelayNotAllowed => "smtp.relay-not-allowed",
            MetricType::SmtpRcptToDuplicate => "smtp.rcpt-to-duplicate",
            MetricType::SmtpRcptToMissing => "smtp.rcpt-to-missing",
            MetricType::SmtpTooManyRecipients => "smtp.too-many-recipients",
            MetricType::SmtpTooManyInvalidRcpt => "smtp.too-many-invalid-rcpt",
            MetricType::SmtpAuthMechanismNotSupported => "smtp.auth-mechanism-not-supported",
            MetricType::SmtpAuthExchangeTooLong => "smtp.auth-exchange-too-long",
            MetricType::SmtpCommandNotImplemented => "smtp.command-not-implemented",
            MetricType::SmtpInvalidCommand => "smtp.invalid-command",
            MetricType::SmtpSyntaxError => "smtp.syntax-error",
            MetricType::SmtpRequestTooLarge => "smtp.request-too-large",
            MetricType::SpamPyzorError => "spam.pyzor-error",
            MetricType::SpamDnsblError => "spam.dnsbl-error",
            MetricType::SpamTrainCompleted => "spam.train-completed",
            MetricType::SpamTrainSampleAdded => "spam.train-sample-added",
            MetricType::SpamClassify => "spam.classify",
            MetricType::SpamModelNotReady => "spam.model-not-ready",
            MetricType::SpfPass => "spf.pass",
            MetricType::SpfFail => "spf.fail",
            MetricType::SpfSoftFail => "spf.soft-fail",
            MetricType::SpfNeutral => "spf.neutral",
            MetricType::SpfTempError => "spf.temp-error",
            MetricType::SpfPermError => "spf.perm-error",
            MetricType::SpfNone => "spf.none",
            MetricType::StoreDataReadTime => "store.data-read-time",
            MetricType::StoreDataWriteTime => "store.data-write-time",
            MetricType::StoreBlobReadTime => "store.blob-read-time",
            MetricType::StoreBlobWriteTime => "store.blob-write-time",
            MetricType::StoreAssertValueFailed => "store.assert-value-failed",
            MetricType::StoreFoundationdbError => "store.foundationdb-error",
            MetricType::StoreMysqlError => "store.mysql-error",
            MetricType::StorePostgresqlError => "store.postgresql-error",
            MetricType::StoreRocksdbError => "store.rocksdb-error",
            MetricType::StoreSqliteError => "store.sqlite-error",
            MetricType::StoreLdapError => "store.ldap-error",
            MetricType::StoreElasticsearchError => "store.elasticsearch-error",
            MetricType::StoreRedisError => "store.redis-error",
            MetricType::StoreS3Error => "store.s3-error",
            MetricType::StoreAzureError => "store.azure-error",
            MetricType::StoreFilesystemError => "store.filesystem-error",
            MetricType::StorePoolError => "store.pool-error",
            MetricType::StoreDataCorruption => "store.data-corruption",
            MetricType::StoreDecompressError => "store.decompress-error",
            MetricType::StoreDeserializeError => "store.deserialize-error",
            MetricType::StoreNotFound => "store.not-found",
            MetricType::StoreNotConfigured => "store.not-configured",
            MetricType::StoreNotSupported => "store.not-supported",
            MetricType::StoreUnexpectedError => "store.unexpected-error",
            MetricType::StoreCryptoError => "store.crypto-error",
            MetricType::StoreHttpStoreError => "store.http-store-error",
            MetricType::StoreBlobMissingMarker => "store.blob-missing-marker",
            MetricType::StoreDataWrite => "store.data-write",
            MetricType::StoreDataIterate => "store.data-iterate",
            MetricType::StoreBlobRead => "store.blob-read",
            MetricType::StoreBlobWrite => "store.blob-write",
            MetricType::StoreBlobDelete => "store.blob-delete",
            MetricType::TaskManagerPending => "task-manager.pending",
            MetricType::TaskManagerDue => "task-manager.due",
            MetricType::TaskManagerTaskFailed => "task-manager.task-failed",
            MetricType::TaskManagerTaskRetry => "task-manager.task-retry",
            MetricType::TaskManagerTaskStalled => "task-manager.task-stalled",
            MetricType::TaskManagerTaskExpired => "task-manager.task-expired",
            MetricType::TaskManagerBlobNotFound => "task-manager.blob-not-found",
            MetricType::TaskManagerMetadataNotFound => "task-manager.metadata-not-found",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertEvent => "telemetry.alert-event",
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertMessage => "telemetry.alert-message",
            // SPDX-SnippetEnd
            MetricType::TelemetryLogError => "telemetry.log-error",
            MetricType::TelemetryWebhookError => "telemetry.webhook-error",
            MetricType::TelemetryOtelExporterError => "telemetry.otel-exporter-error",
            MetricType::TelemetryOtelMetricsExporterError => {
                "telemetry.otel-metrics-exporter-error"
            }
            MetricType::TelemetryPrometheusExporterError => "telemetry.prometheus-exporter-error",
            MetricType::TelemetryJournalError => "telemetry.journal-error",
            MetricType::TelemetryEventsDropped => "telemetry.events-dropped",
            MetricType::TlsHandshakeError => "tls.handshake-error",
            MetricType::UserCount => "user.count",
        }
    }

    pub fn to_id(&self) -> u16 {
        match self {
            MetricType::AcmeAuthError => 27,
            MetricType::AcmeAuthTooManyAttempts => 28,
            MetricType::AcmeOrderCompleted => 29,
            MetricType::AcmeOrderInvalid => 30,
            MetricType::AcmeClientMissingSni => 31,
            MetricType::AcmeTlsAlpnError => 32,
            MetricType::AcmeTokenNotFound => 33,
            MetricType::AcmeError => 34,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => 333,
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => 334,
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => 335,
            #[cfg(feature = "enterprise")]
            MetricType::AiApiError => 332,
            #[cfg(feature = "enterprise")]
            MetricType::AiRequest => 328,
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamVerdict => 329,
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamSkipped => 330,
            #[cfg(feature = "enterprise")]
            MetricType::AiBreakerOpen => 331,
            // SPDX-SnippetEnd
            MetricType::ArcChainInvalid => 379,
            MetricType::ArcSignatureInvalid => 380,
            MetricType::ArcHashMismatch => 381,
            MetricType::AuthSuccess => 39,
            MetricType::AuthFailed => 40,
            MetricType::AuthTooManyAttempts => 41,
            MetricType::AuthError => 42,
            MetricType::CacheMessagesSize => 348,
            MetricType::CacheMessagesLargeSize => 349,
            MetricType::CacheSize => 350,
            MetricType::CacheSwapPending => 351,
            MetricType::CacheMiss => 339,
            MetricType::CacheHit => 340,
            MetricType::CacheStale => 341,
            MetricType::CacheEntryTooLarge => 342,
            MetricType::CacheSwapHit => 343,
            MetricType::CacheSwapMiss => 344,
            MetricType::CacheSwapWrite => 345,
            MetricType::CacheSwapError => 346,
            MetricType::CalendarAlarmSent => 43,
            MetricType::CalendarAlarmFailed => 44,
            MetricType::CalendarItipMessageSent => 45,
            MetricType::CalendarItipMessageReceived => 46,
            MetricType::CalendarItipMessageError => 47,
            MetricType::ClusterSubscriberError => 48,
            MetricType::ClusterSubscriberDisconnected => 49,
            MetricType::ClusterPublisherError => 50,
            MetricType::DaneAuthenticationSuccess => 51,
            MetricType::DaneAuthenticationFailure => 52,
            MetricType::DaneNoCertificatesFound => 53,
            MetricType::DaneCertificateParseError => 54,
            MetricType::DaneTlsaRecordFetchError => 55,
            MetricType::DaneTlsaRecordNotFound => 56,
            MetricType::DaneTlsaRecordNotDnssecSigned => 57,
            MetricType::DaneTlsaRecordInvalid => 58,
            MetricType::DaneBogusDnssecRecord => 323,
            MetricType::DeliveryTotalTime => 2,
            MetricType::DeliveryAttemptTime => 3,
            MetricType::DeliveryActiveConnections => 22,
            MetricType::DeliveryAttemptStart => 59,
            MetricType::DeliveryAttemptEnd => 60,
            MetricType::DeliveryCompleted => 61,
            MetricType::DeliveryMxLookupFailed => 62,
            MetricType::DeliveryIpLookupFailed => 63,
            MetricType::DeliveryNullMx => 64,
            MetricType::DeliveryGreetingFailed => 65,
            MetricType::DeliveryEhloRejected => 66,
            MetricType::DeliveryAuthFailed => 67,
            MetricType::DeliveryMailFromRejected => 68,
            MetricType::DeliveryDelivered => 69,
            MetricType::DeliveryRcptToRejected => 70,
            MetricType::DeliveryRcptToFailed => 71,
            MetricType::DeliveryMessageRejected => 72,
            MetricType::DeliveryStartTlsUnavailable => 73,
            MetricType::DeliveryStartTlsError => 74,
            MetricType::DeliveryStartTlsDisabled => 75,
            MetricType::DeliveryImplicitTlsError => 76,
            MetricType::DeliveryConcurrencyLimitExceeded => 77,
            MetricType::DeliveryRateLimitExceeded => 78,
            MetricType::DeliveryDoubleBounce => 79,
            MetricType::DeliveryDsnSuccess => 80,
            MetricType::DeliveryDsnTempFail => 81,
            MetricType::DeliveryDsnPermFail => 82,
            MetricType::DkimPass => 83,
            MetricType::DkimNeutral => 84,
            MetricType::DkimFail => 85,
            MetricType::DkimPermError => 86,
            MetricType::DkimTempError => 87,
            MetricType::DkimNone => 88,
            MetricType::DkimSignatureInvalid => 375,
            MetricType::DkimPublicKeyError => 376,
            MetricType::DkimVerificationFailed => 377,
            MetricType::DkimHashMismatch => 378,
            MetricType::DkimSignerNotFound => 89,
            MetricType::Dkim2InstanceInvalid => 365,
            MetricType::Dkim2SignatureInvalid => 366,
            MetricType::Dkim2ChainInvalid => 367,
            MetricType::Dkim2TimestampInvalid => 368,
            MetricType::Dkim2EnvelopeMismatch => 369,
            MetricType::Dkim2CustodyBroken => 370,
            MetricType::Dkim2PublicKeyError => 371,
            MetricType::Dkim2VerificationFailed => 372,
            MetricType::Dkim2HashMismatch => 373,
            MetricType::Dkim2RecipeError => 374,
            MetricType::Dkim2SigningFailed => 382,
            MetricType::DmarcPass => 90,
            MetricType::DmarcFail => 91,
            MetricType::DmarcPermError => 92,
            MetricType::DmarcTempError => 93,
            MetricType::DmarcNone => 94,
            MetricType::DnsLookupTime => 11,
            MetricType::DnsRecordCreationFailed => 35,
            MetricType::DnsRecordDeletionFailed => 36,
            MetricType::DnsRecordLookupFailed => 37,
            MetricType::DnsRecordPropagationTimeout => 38,
            MetricType::DomainCount => 26,
            MetricType::EvalError => 95,
            MetricType::EvalDirectoryNotFound => 96,
            MetricType::EvalStoreNotFound => 97,
            MetricType::HttpRequestTime => 12,
            MetricType::HttpActiveConnections => 17,
            MetricType::HttpConnectionStart => 321,
            MetricType::HttpError => 98,
            MetricType::HttpRequestBody => 99,
            MetricType::HttpResponseBody => 100,
            MetricType::HttpXForwardedMissing => 101,
            MetricType::HttpXForwardedInvalid => 336,
            MetricType::ImapRequestTime => 13,
            MetricType::ImapActiveConnections => 18,
            MetricType::ImapConnectionStart => 102,
            MetricType::ImapConnectionEnd => 103,
            MetricType::IncomingReportDmarcReport => 104,
            MetricType::IncomingReportDmarcReportWithWarnings => 105,
            MetricType::IncomingReportTlsReport => 106,
            MetricType::IncomingReportTlsReportWithWarnings => 107,
            MetricType::IncomingReportAbuseReport => 108,
            MetricType::IncomingReportAuthFailureReport => 109,
            MetricType::IncomingReportFraudReport => 110,
            MetricType::IncomingReportNotSpamReport => 111,
            MetricType::IncomingReportVirusReport => 112,
            MetricType::IncomingReportOtherReport => 113,
            MetricType::IncomingReportMessageParseFailed => 114,
            MetricType::IncomingReportDmarcParseFailed => 115,
            MetricType::IncomingReportTlsRpcParseFailed => 116,
            MetricType::IncomingReportArfParseFailed => 117,
            MetricType::IncomingReportDecompressError => 118,
            MetricType::IprevPass => 119,
            MetricType::IprevFail => 120,
            MetricType::IprevPermError => 121,
            MetricType::IprevTempError => 122,
            MetricType::IprevNone => 123,
            MetricType::JmapMethodCall => 124,
            MetricType::JmapInvalidArguments => 125,
            MetricType::JmapRequestTooLarge => 126,
            MetricType::JmapUnsupportedFilter => 127,
            MetricType::JmapUnsupportedSort => 128,
            MetricType::JmapUnknownMethod => 129,
            MetricType::JmapForbidden => 130,
            MetricType::JmapNotJson => 131,
            MetricType::JmapNotRequest => 132,
            MetricType::JmapWebsocketStart => 133,
            MetricType::JmapWebsocketError => 134,
            MetricType::LimitSizeRequest => 135,
            MetricType::LimitSizeUpload => 136,
            MetricType::LimitCallsIn => 137,
            MetricType::LimitConcurrentRequest => 138,
            MetricType::LimitConcurrentUpload => 139,
            MetricType::LimitConcurrentConnection => 140,
            MetricType::LimitQuota => 141,
            MetricType::LimitBlobQuota => 142,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::LimitTenantQuota => 143,
            // SPDX-SnippetEnd
            MetricType::LimitTooManyRequests => 144,
            MetricType::LimitMemoryBudget => 338,
            MetricType::MailAuthParseError => 145,
            MetricType::MailAuthMissingParameters => 146,
            MetricType::MailAuthNoHeadersFound => 147,
            MetricType::MailAuthCrypto => 148,
            MetricType::MailAuthIo => 149,
            MetricType::MailAuthBase64 => 150,
            MetricType::MailAuthDnsError => 151,
            MetricType::MailAuthDnsRecordNotFound => 152,
            MetricType::MailAuthDnsInvalidRecordType => 153,
            MetricType::MailAuthPolicyNotAligned => 154,
            MetricType::ManageSieveConnectionStart => 155,
            MetricType::ManageSieveConnectionEnd => 156,
            MetricType::MessageSize => 4,
            MetricType::MessageAuthenticatedSize => 5,
            MetricType::MessageIngestTime => 0,
            MetricType::MessageIngestHam => 157,
            MetricType::MessageIngestSpam => 158,
            MetricType::MessageIngestImapAppend => 159,
            MetricType::MessageIngestJmapAppend => 160,
            MetricType::MessageIngestDuplicate => 161,
            MetricType::MessageIngestError => 162,
            MetricType::MilterActionAccept => 164,
            MetricType::MilterActionDiscard => 165,
            MetricType::MilterActionReject => 166,
            MetricType::MilterActionTempFail => 167,
            MetricType::MilterActionReplyCode => 168,
            MetricType::MilterActionConnectionFailure => 169,
            MetricType::MilterActionShutdown => 170,
            MetricType::MtaHookActionAccept => 171,
            MetricType::MtaHookActionDiscard => 172,
            MetricType::MtaHookActionReject => 173,
            MetricType::MtaHookActionQuarantine => 174,
            MetricType::MtaHookError => 175,
            MetricType::MtaStsAuthorized => 176,
            MetricType::MtaStsNotAuthorized => 177,
            MetricType::MtaStsInvalidPolicy => 178,
            MetricType::NetworkTimeout => 179,
            MetricType::OutgoingReportSize => 6,
            MetricType::OutgoingReportSpfReport => 180,
            MetricType::OutgoingReportSpfRateLimited => 181,
            MetricType::OutgoingReportDkimReport => 182,
            MetricType::OutgoingReportDkimRateLimited => 183,
            MetricType::OutgoingReportDmarcReport => 184,
            MetricType::OutgoingReportDmarcRateLimited => 185,
            MetricType::OutgoingReportDmarcAggregateReport => 186,
            MetricType::OutgoingReportTlsAggregate => 187,
            MetricType::OutgoingReportHttpSubmission => 188,
            MetricType::OutgoingReportUnauthorizedReportingAddress => 189,
            MetricType::OutgoingReportReportingAddressValidationError => 190,
            MetricType::OutgoingReportNotFound => 191,
            MetricType::OutgoingReportSubmissionError => 192,
            MetricType::OutgoingReportNoRecipientsFound => 193,
            MetricType::Pop3RequestTime => 14,
            MetricType::Pop3ActiveConnections => 19,
            MetricType::Pop3ConnectionStart => 194,
            MetricType::Pop3ConnectionEnd => 195,
            MetricType::PushSubscriptionSuccess => 197,
            MetricType::PushSubscriptionError => 198,
            MetricType::PushSubscriptionNotFound => 199,
            MetricType::QueueCount => 24,
            MetricType::QueueMessageQueued => 200,
            MetricType::QueueAuthenticatedMessageQueued => 201,
            MetricType::QueueReportQueued => 202,
            MetricType::QueueDsnQueued => 203,
            MetricType::QueueAutogeneratedQueued => 204,
            MetricType::QueueRescheduled => 205,
            MetricType::QueueBlobNotFound => 206,
            MetricType::QueueRateLimitExceeded => 207,
            MetricType::QueueConcurrencyLimitExceeded => 208,
            MetricType::QueueQuotaExceeded => 209,
            MetricType::QueueBackPressure => 347,
            MetricType::ResourceNotFound => 210,
            MetricType::ResourceBadParameters => 211,
            MetricType::ResourceError => 212,
            MetricType::SearchIndexIndexTime => 1,
            MetricType::SearchIndexPendingEmail => 354,
            MetricType::SearchIndexPendingCalendar => 355,
            MetricType::SearchIndexPendingContacts => 356,
            MetricType::SearchIndexPendingFile => 357,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => 358,
            // SPDX-SnippetEnd
            MetricType::SearchIndexPartitionRetry => 360,
            MetricType::SearchIndexBatchIndexed => 163,
            MetricType::SearchIndexDocumentTruncated => 359,
            MetricType::SecurityAuthenticationBan => 213,
            MetricType::SecurityAbuseBan => 214,
            MetricType::SecurityScanBan => 215,
            MetricType::SecurityLoiterBan => 216,
            MetricType::SecurityIpBlocked => 217,
            MetricType::SecurityUnauthorized => 218,
            MetricType::ServerMemory => 23,
            MetricType::ServerBufferedMemorySmtp => 352,
            MetricType::ServerBufferedMemoryRead => 353,
            MetricType::ServerThreadError => 219,
            MetricType::SieveRequestTime => 16,
            MetricType::SieveActiveConnections => 21,
            MetricType::SieveActionAccept => 220,
            MetricType::SieveActionAcceptReplace => 221,
            MetricType::SieveActionDiscard => 222,
            MetricType::SieveActionReject => 223,
            MetricType::SieveSendMessage => 224,
            MetricType::SieveMessageTooLarge => 225,
            MetricType::SieveRuntimeError => 226,
            MetricType::SieveUnexpectedError => 227,
            MetricType::SieveNotSupported => 228,
            MetricType::SieveQuotaExceeded => 229,
            MetricType::SmtpRequestTime => 15,
            MetricType::SmtpActiveConnections => 20,
            MetricType::SmtpConnectionStart => 230,
            MetricType::SmtpConnectionEnd => 231,
            MetricType::SmtpError => 232,
            MetricType::SmtpConcurrencyLimitExceeded => 233,
            MetricType::SmtpTransferLimitExceeded => 234,
            MetricType::SmtpRateLimitExceeded => 235,
            MetricType::SmtpTimeLimitExceeded => 236,
            MetricType::SmtpMessageParseFailed => 237,
            MetricType::SmtpMessageTooLarge => 238,
            MetricType::SmtpLoopDetected => 239,
            MetricType::SmtpMultipleFromDomains => 337,
            MetricType::SmtpDkimPass => 240,
            MetricType::SmtpDkimFail => 241,
            MetricType::SmtpDkim2Pass => 324,
            MetricType::SmtpDkim2Fail => 325,
            MetricType::SmtpDkim2DsnRejected => 326,
            MetricType::SmtpArcPass => 242,
            MetricType::SmtpArcFail => 243,
            MetricType::SmtpSpfEhloPass => 244,
            MetricType::SmtpSpfEhloFail => 245,
            MetricType::SmtpSpfFromPass => 246,
            MetricType::SmtpSpfFromFail => 247,
            MetricType::SmtpDmarcPass => 248,
            MetricType::SmtpDmarcFail => 249,
            MetricType::SmtpIprevPass => 250,
            MetricType::SmtpIprevFail => 251,
            MetricType::SmtpTooManyMessages => 252,
            MetricType::SmtpInvalidEhlo => 253,
            MetricType::SmtpDidNotSayEhlo => 254,
            MetricType::SmtpMailFromUnauthenticated => 255,
            MetricType::SmtpMailFromUnauthorized => 256,
            MetricType::SmtpMailFromMissing => 257,
            MetricType::SmtpMultipleMailFrom => 258,
            MetricType::SmtpMailboxDoesNotExist => 259,
            MetricType::SmtpRelayNotAllowed => 260,
            MetricType::SmtpRcptToDuplicate => 261,
            MetricType::SmtpRcptToMissing => 262,
            MetricType::SmtpTooManyRecipients => 263,
            MetricType::SmtpTooManyInvalidRcpt => 264,
            MetricType::SmtpAuthMechanismNotSupported => 265,
            MetricType::SmtpAuthExchangeTooLong => 266,
            MetricType::SmtpCommandNotImplemented => 267,
            MetricType::SmtpInvalidCommand => 268,
            MetricType::SmtpSyntaxError => 269,
            MetricType::SmtpRequestTooLarge => 270,
            MetricType::SpamPyzorError => 271,
            MetricType::SpamDnsblError => 272,
            MetricType::SpamTrainCompleted => 273,
            MetricType::SpamTrainSampleAdded => 274,
            MetricType::SpamClassify => 275,
            MetricType::SpamModelNotReady => 276,
            MetricType::SpfPass => 277,
            MetricType::SpfFail => 278,
            MetricType::SpfSoftFail => 279,
            MetricType::SpfNeutral => 280,
            MetricType::SpfTempError => 281,
            MetricType::SpfPermError => 282,
            MetricType::SpfNone => 283,
            MetricType::StoreDataReadTime => 7,
            MetricType::StoreDataWriteTime => 8,
            MetricType::StoreBlobReadTime => 9,
            MetricType::StoreBlobWriteTime => 10,
            MetricType::StoreAssertValueFailed => 284,
            MetricType::StoreFoundationdbError => 285,
            MetricType::StoreMysqlError => 286,
            MetricType::StorePostgresqlError => 287,
            MetricType::StoreRocksdbError => 288,
            MetricType::StoreSqliteError => 289,
            MetricType::StoreLdapError => 290,
            MetricType::StoreElasticsearchError => 291,
            MetricType::StoreRedisError => 292,
            MetricType::StoreS3Error => 293,
            MetricType::StoreAzureError => 294,
            MetricType::StoreFilesystemError => 295,
            MetricType::StorePoolError => 296,
            MetricType::StoreDataCorruption => 297,
            MetricType::StoreDecompressError => 298,
            MetricType::StoreDeserializeError => 299,
            MetricType::StoreNotFound => 300,
            MetricType::StoreNotConfigured => 301,
            MetricType::StoreNotSupported => 302,
            MetricType::StoreUnexpectedError => 303,
            MetricType::StoreCryptoError => 304,
            MetricType::StoreHttpStoreError => 305,
            MetricType::StoreBlobMissingMarker => 306,
            MetricType::StoreDataWrite => 307,
            MetricType::StoreDataIterate => 308,
            MetricType::StoreBlobRead => 309,
            MetricType::StoreBlobWrite => 310,
            MetricType::StoreBlobDelete => 311,
            MetricType::TaskManagerPending => 363,
            MetricType::TaskManagerDue => 364,
            MetricType::TaskManagerTaskFailed => 361,
            MetricType::TaskManagerTaskRetry => 362,
            MetricType::TaskManagerTaskStalled => 383,
            MetricType::TaskManagerTaskExpired => 384,
            MetricType::TaskManagerBlobNotFound => 312,
            MetricType::TaskManagerMetadataNotFound => 313,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertEvent => 322,
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertMessage => 196,
            // SPDX-SnippetEnd
            MetricType::TelemetryLogError => 314,
            MetricType::TelemetryWebhookError => 315,
            MetricType::TelemetryOtelExporterError => 316,
            MetricType::TelemetryOtelMetricsExporterError => 317,
            MetricType::TelemetryPrometheusExporterError => 318,
            MetricType::TelemetryJournalError => 319,
            MetricType::TelemetryEventsDropped => 327,
            MetricType::TlsHandshakeError => 320,
            MetricType::UserCount => 25,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            27 => Some(MetricType::AcmeAuthError),
            28 => Some(MetricType::AcmeAuthTooManyAttempts),
            29 => Some(MetricType::AcmeOrderCompleted),
            30 => Some(MetricType::AcmeOrderInvalid),
            31 => Some(MetricType::AcmeClientMissingSni),
            32 => Some(MetricType::AcmeTlsAlpnError),
            33 => Some(MetricType::AcmeTokenNotFound),
            34 => Some(MetricType::AcmeError),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            333 => Some(MetricType::AiRequestTime),
            #[cfg(feature = "enterprise")]
            334 => Some(MetricType::AiInputTokens),
            #[cfg(feature = "enterprise")]
            335 => Some(MetricType::AiOutputTokens),
            #[cfg(feature = "enterprise")]
            332 => Some(MetricType::AiApiError),
            #[cfg(feature = "enterprise")]
            328 => Some(MetricType::AiRequest),
            #[cfg(feature = "enterprise")]
            329 => Some(MetricType::AiSpamVerdict),
            #[cfg(feature = "enterprise")]
            330 => Some(MetricType::AiSpamSkipped),
            #[cfg(feature = "enterprise")]
            331 => Some(MetricType::AiBreakerOpen),
            // SPDX-SnippetEnd
            379 => Some(MetricType::ArcChainInvalid),
            380 => Some(MetricType::ArcSignatureInvalid),
            381 => Some(MetricType::ArcHashMismatch),
            39 => Some(MetricType::AuthSuccess),
            40 => Some(MetricType::AuthFailed),
            41 => Some(MetricType::AuthTooManyAttempts),
            42 => Some(MetricType::AuthError),
            348 => Some(MetricType::CacheMessagesSize),
            349 => Some(MetricType::CacheMessagesLargeSize),
            350 => Some(MetricType::CacheSize),
            351 => Some(MetricType::CacheSwapPending),
            339 => Some(MetricType::CacheMiss),
            340 => Some(MetricType::CacheHit),
            341 => Some(MetricType::CacheStale),
            342 => Some(MetricType::CacheEntryTooLarge),
            343 => Some(MetricType::CacheSwapHit),
            344 => Some(MetricType::CacheSwapMiss),
            345 => Some(MetricType::CacheSwapWrite),
            346 => Some(MetricType::CacheSwapError),
            43 => Some(MetricType::CalendarAlarmSent),
            44 => Some(MetricType::CalendarAlarmFailed),
            45 => Some(MetricType::CalendarItipMessageSent),
            46 => Some(MetricType::CalendarItipMessageReceived),
            47 => Some(MetricType::CalendarItipMessageError),
            48 => Some(MetricType::ClusterSubscriberError),
            49 => Some(MetricType::ClusterSubscriberDisconnected),
            50 => Some(MetricType::ClusterPublisherError),
            51 => Some(MetricType::DaneAuthenticationSuccess),
            52 => Some(MetricType::DaneAuthenticationFailure),
            53 => Some(MetricType::DaneNoCertificatesFound),
            54 => Some(MetricType::DaneCertificateParseError),
            55 => Some(MetricType::DaneTlsaRecordFetchError),
            56 => Some(MetricType::DaneTlsaRecordNotFound),
            57 => Some(MetricType::DaneTlsaRecordNotDnssecSigned),
            58 => Some(MetricType::DaneTlsaRecordInvalid),
            323 => Some(MetricType::DaneBogusDnssecRecord),
            2 => Some(MetricType::DeliveryTotalTime),
            3 => Some(MetricType::DeliveryAttemptTime),
            22 => Some(MetricType::DeliveryActiveConnections),
            59 => Some(MetricType::DeliveryAttemptStart),
            60 => Some(MetricType::DeliveryAttemptEnd),
            61 => Some(MetricType::DeliveryCompleted),
            62 => Some(MetricType::DeliveryMxLookupFailed),
            63 => Some(MetricType::DeliveryIpLookupFailed),
            64 => Some(MetricType::DeliveryNullMx),
            65 => Some(MetricType::DeliveryGreetingFailed),
            66 => Some(MetricType::DeliveryEhloRejected),
            67 => Some(MetricType::DeliveryAuthFailed),
            68 => Some(MetricType::DeliveryMailFromRejected),
            69 => Some(MetricType::DeliveryDelivered),
            70 => Some(MetricType::DeliveryRcptToRejected),
            71 => Some(MetricType::DeliveryRcptToFailed),
            72 => Some(MetricType::DeliveryMessageRejected),
            73 => Some(MetricType::DeliveryStartTlsUnavailable),
            74 => Some(MetricType::DeliveryStartTlsError),
            75 => Some(MetricType::DeliveryStartTlsDisabled),
            76 => Some(MetricType::DeliveryImplicitTlsError),
            77 => Some(MetricType::DeliveryConcurrencyLimitExceeded),
            78 => Some(MetricType::DeliveryRateLimitExceeded),
            79 => Some(MetricType::DeliveryDoubleBounce),
            80 => Some(MetricType::DeliveryDsnSuccess),
            81 => Some(MetricType::DeliveryDsnTempFail),
            82 => Some(MetricType::DeliveryDsnPermFail),
            83 => Some(MetricType::DkimPass),
            84 => Some(MetricType::DkimNeutral),
            85 => Some(MetricType::DkimFail),
            86 => Some(MetricType::DkimPermError),
            87 => Some(MetricType::DkimTempError),
            88 => Some(MetricType::DkimNone),
            375 => Some(MetricType::DkimSignatureInvalid),
            376 => Some(MetricType::DkimPublicKeyError),
            377 => Some(MetricType::DkimVerificationFailed),
            378 => Some(MetricType::DkimHashMismatch),
            89 => Some(MetricType::DkimSignerNotFound),
            365 => Some(MetricType::Dkim2InstanceInvalid),
            366 => Some(MetricType::Dkim2SignatureInvalid),
            367 => Some(MetricType::Dkim2ChainInvalid),
            368 => Some(MetricType::Dkim2TimestampInvalid),
            369 => Some(MetricType::Dkim2EnvelopeMismatch),
            370 => Some(MetricType::Dkim2CustodyBroken),
            371 => Some(MetricType::Dkim2PublicKeyError),
            372 => Some(MetricType::Dkim2VerificationFailed),
            373 => Some(MetricType::Dkim2HashMismatch),
            374 => Some(MetricType::Dkim2RecipeError),
            382 => Some(MetricType::Dkim2SigningFailed),
            90 => Some(MetricType::DmarcPass),
            91 => Some(MetricType::DmarcFail),
            92 => Some(MetricType::DmarcPermError),
            93 => Some(MetricType::DmarcTempError),
            94 => Some(MetricType::DmarcNone),
            11 => Some(MetricType::DnsLookupTime),
            35 => Some(MetricType::DnsRecordCreationFailed),
            36 => Some(MetricType::DnsRecordDeletionFailed),
            37 => Some(MetricType::DnsRecordLookupFailed),
            38 => Some(MetricType::DnsRecordPropagationTimeout),
            26 => Some(MetricType::DomainCount),
            95 => Some(MetricType::EvalError),
            96 => Some(MetricType::EvalDirectoryNotFound),
            97 => Some(MetricType::EvalStoreNotFound),
            12 => Some(MetricType::HttpRequestTime),
            17 => Some(MetricType::HttpActiveConnections),
            321 => Some(MetricType::HttpConnectionStart),
            98 => Some(MetricType::HttpError),
            99 => Some(MetricType::HttpRequestBody),
            100 => Some(MetricType::HttpResponseBody),
            101 => Some(MetricType::HttpXForwardedMissing),
            336 => Some(MetricType::HttpXForwardedInvalid),
            13 => Some(MetricType::ImapRequestTime),
            18 => Some(MetricType::ImapActiveConnections),
            102 => Some(MetricType::ImapConnectionStart),
            103 => Some(MetricType::ImapConnectionEnd),
            104 => Some(MetricType::IncomingReportDmarcReport),
            105 => Some(MetricType::IncomingReportDmarcReportWithWarnings),
            106 => Some(MetricType::IncomingReportTlsReport),
            107 => Some(MetricType::IncomingReportTlsReportWithWarnings),
            108 => Some(MetricType::IncomingReportAbuseReport),
            109 => Some(MetricType::IncomingReportAuthFailureReport),
            110 => Some(MetricType::IncomingReportFraudReport),
            111 => Some(MetricType::IncomingReportNotSpamReport),
            112 => Some(MetricType::IncomingReportVirusReport),
            113 => Some(MetricType::IncomingReportOtherReport),
            114 => Some(MetricType::IncomingReportMessageParseFailed),
            115 => Some(MetricType::IncomingReportDmarcParseFailed),
            116 => Some(MetricType::IncomingReportTlsRpcParseFailed),
            117 => Some(MetricType::IncomingReportArfParseFailed),
            118 => Some(MetricType::IncomingReportDecompressError),
            119 => Some(MetricType::IprevPass),
            120 => Some(MetricType::IprevFail),
            121 => Some(MetricType::IprevPermError),
            122 => Some(MetricType::IprevTempError),
            123 => Some(MetricType::IprevNone),
            124 => Some(MetricType::JmapMethodCall),
            125 => Some(MetricType::JmapInvalidArguments),
            126 => Some(MetricType::JmapRequestTooLarge),
            127 => Some(MetricType::JmapUnsupportedFilter),
            128 => Some(MetricType::JmapUnsupportedSort),
            129 => Some(MetricType::JmapUnknownMethod),
            130 => Some(MetricType::JmapForbidden),
            131 => Some(MetricType::JmapNotJson),
            132 => Some(MetricType::JmapNotRequest),
            133 => Some(MetricType::JmapWebsocketStart),
            134 => Some(MetricType::JmapWebsocketError),
            135 => Some(MetricType::LimitSizeRequest),
            136 => Some(MetricType::LimitSizeUpload),
            137 => Some(MetricType::LimitCallsIn),
            138 => Some(MetricType::LimitConcurrentRequest),
            139 => Some(MetricType::LimitConcurrentUpload),
            140 => Some(MetricType::LimitConcurrentConnection),
            141 => Some(MetricType::LimitQuota),
            142 => Some(MetricType::LimitBlobQuota),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            143 => Some(MetricType::LimitTenantQuota),
            // SPDX-SnippetEnd
            144 => Some(MetricType::LimitTooManyRequests),
            338 => Some(MetricType::LimitMemoryBudget),
            145 => Some(MetricType::MailAuthParseError),
            146 => Some(MetricType::MailAuthMissingParameters),
            147 => Some(MetricType::MailAuthNoHeadersFound),
            148 => Some(MetricType::MailAuthCrypto),
            149 => Some(MetricType::MailAuthIo),
            150 => Some(MetricType::MailAuthBase64),
            151 => Some(MetricType::MailAuthDnsError),
            152 => Some(MetricType::MailAuthDnsRecordNotFound),
            153 => Some(MetricType::MailAuthDnsInvalidRecordType),
            154 => Some(MetricType::MailAuthPolicyNotAligned),
            155 => Some(MetricType::ManageSieveConnectionStart),
            156 => Some(MetricType::ManageSieveConnectionEnd),
            4 => Some(MetricType::MessageSize),
            5 => Some(MetricType::MessageAuthenticatedSize),
            0 => Some(MetricType::MessageIngestTime),
            157 => Some(MetricType::MessageIngestHam),
            158 => Some(MetricType::MessageIngestSpam),
            159 => Some(MetricType::MessageIngestImapAppend),
            160 => Some(MetricType::MessageIngestJmapAppend),
            161 => Some(MetricType::MessageIngestDuplicate),
            162 => Some(MetricType::MessageIngestError),
            164 => Some(MetricType::MilterActionAccept),
            165 => Some(MetricType::MilterActionDiscard),
            166 => Some(MetricType::MilterActionReject),
            167 => Some(MetricType::MilterActionTempFail),
            168 => Some(MetricType::MilterActionReplyCode),
            169 => Some(MetricType::MilterActionConnectionFailure),
            170 => Some(MetricType::MilterActionShutdown),
            171 => Some(MetricType::MtaHookActionAccept),
            172 => Some(MetricType::MtaHookActionDiscard),
            173 => Some(MetricType::MtaHookActionReject),
            174 => Some(MetricType::MtaHookActionQuarantine),
            175 => Some(MetricType::MtaHookError),
            176 => Some(MetricType::MtaStsAuthorized),
            177 => Some(MetricType::MtaStsNotAuthorized),
            178 => Some(MetricType::MtaStsInvalidPolicy),
            179 => Some(MetricType::NetworkTimeout),
            6 => Some(MetricType::OutgoingReportSize),
            180 => Some(MetricType::OutgoingReportSpfReport),
            181 => Some(MetricType::OutgoingReportSpfRateLimited),
            182 => Some(MetricType::OutgoingReportDkimReport),
            183 => Some(MetricType::OutgoingReportDkimRateLimited),
            184 => Some(MetricType::OutgoingReportDmarcReport),
            185 => Some(MetricType::OutgoingReportDmarcRateLimited),
            186 => Some(MetricType::OutgoingReportDmarcAggregateReport),
            187 => Some(MetricType::OutgoingReportTlsAggregate),
            188 => Some(MetricType::OutgoingReportHttpSubmission),
            189 => Some(MetricType::OutgoingReportUnauthorizedReportingAddress),
            190 => Some(MetricType::OutgoingReportReportingAddressValidationError),
            191 => Some(MetricType::OutgoingReportNotFound),
            192 => Some(MetricType::OutgoingReportSubmissionError),
            193 => Some(MetricType::OutgoingReportNoRecipientsFound),
            14 => Some(MetricType::Pop3RequestTime),
            19 => Some(MetricType::Pop3ActiveConnections),
            194 => Some(MetricType::Pop3ConnectionStart),
            195 => Some(MetricType::Pop3ConnectionEnd),
            197 => Some(MetricType::PushSubscriptionSuccess),
            198 => Some(MetricType::PushSubscriptionError),
            199 => Some(MetricType::PushSubscriptionNotFound),
            24 => Some(MetricType::QueueCount),
            200 => Some(MetricType::QueueMessageQueued),
            201 => Some(MetricType::QueueAuthenticatedMessageQueued),
            202 => Some(MetricType::QueueReportQueued),
            203 => Some(MetricType::QueueDsnQueued),
            204 => Some(MetricType::QueueAutogeneratedQueued),
            205 => Some(MetricType::QueueRescheduled),
            206 => Some(MetricType::QueueBlobNotFound),
            207 => Some(MetricType::QueueRateLimitExceeded),
            208 => Some(MetricType::QueueConcurrencyLimitExceeded),
            209 => Some(MetricType::QueueQuotaExceeded),
            347 => Some(MetricType::QueueBackPressure),
            210 => Some(MetricType::ResourceNotFound),
            211 => Some(MetricType::ResourceBadParameters),
            212 => Some(MetricType::ResourceError),
            1 => Some(MetricType::SearchIndexIndexTime),
            354 => Some(MetricType::SearchIndexPendingEmail),
            355 => Some(MetricType::SearchIndexPendingCalendar),
            356 => Some(MetricType::SearchIndexPendingContacts),
            357 => Some(MetricType::SearchIndexPendingFile),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            358 => Some(MetricType::SearchIndexPendingTracing),
            // SPDX-SnippetEnd
            360 => Some(MetricType::SearchIndexPartitionRetry),
            163 => Some(MetricType::SearchIndexBatchIndexed),
            359 => Some(MetricType::SearchIndexDocumentTruncated),
            213 => Some(MetricType::SecurityAuthenticationBan),
            214 => Some(MetricType::SecurityAbuseBan),
            215 => Some(MetricType::SecurityScanBan),
            216 => Some(MetricType::SecurityLoiterBan),
            217 => Some(MetricType::SecurityIpBlocked),
            218 => Some(MetricType::SecurityUnauthorized),
            23 => Some(MetricType::ServerMemory),
            352 => Some(MetricType::ServerBufferedMemorySmtp),
            353 => Some(MetricType::ServerBufferedMemoryRead),
            219 => Some(MetricType::ServerThreadError),
            16 => Some(MetricType::SieveRequestTime),
            21 => Some(MetricType::SieveActiveConnections),
            220 => Some(MetricType::SieveActionAccept),
            221 => Some(MetricType::SieveActionAcceptReplace),
            222 => Some(MetricType::SieveActionDiscard),
            223 => Some(MetricType::SieveActionReject),
            224 => Some(MetricType::SieveSendMessage),
            225 => Some(MetricType::SieveMessageTooLarge),
            226 => Some(MetricType::SieveRuntimeError),
            227 => Some(MetricType::SieveUnexpectedError),
            228 => Some(MetricType::SieveNotSupported),
            229 => Some(MetricType::SieveQuotaExceeded),
            15 => Some(MetricType::SmtpRequestTime),
            20 => Some(MetricType::SmtpActiveConnections),
            230 => Some(MetricType::SmtpConnectionStart),
            231 => Some(MetricType::SmtpConnectionEnd),
            232 => Some(MetricType::SmtpError),
            233 => Some(MetricType::SmtpConcurrencyLimitExceeded),
            234 => Some(MetricType::SmtpTransferLimitExceeded),
            235 => Some(MetricType::SmtpRateLimitExceeded),
            236 => Some(MetricType::SmtpTimeLimitExceeded),
            237 => Some(MetricType::SmtpMessageParseFailed),
            238 => Some(MetricType::SmtpMessageTooLarge),
            239 => Some(MetricType::SmtpLoopDetected),
            337 => Some(MetricType::SmtpMultipleFromDomains),
            240 => Some(MetricType::SmtpDkimPass),
            241 => Some(MetricType::SmtpDkimFail),
            324 => Some(MetricType::SmtpDkim2Pass),
            325 => Some(MetricType::SmtpDkim2Fail),
            326 => Some(MetricType::SmtpDkim2DsnRejected),
            242 => Some(MetricType::SmtpArcPass),
            243 => Some(MetricType::SmtpArcFail),
            244 => Some(MetricType::SmtpSpfEhloPass),
            245 => Some(MetricType::SmtpSpfEhloFail),
            246 => Some(MetricType::SmtpSpfFromPass),
            247 => Some(MetricType::SmtpSpfFromFail),
            248 => Some(MetricType::SmtpDmarcPass),
            249 => Some(MetricType::SmtpDmarcFail),
            250 => Some(MetricType::SmtpIprevPass),
            251 => Some(MetricType::SmtpIprevFail),
            252 => Some(MetricType::SmtpTooManyMessages),
            253 => Some(MetricType::SmtpInvalidEhlo),
            254 => Some(MetricType::SmtpDidNotSayEhlo),
            255 => Some(MetricType::SmtpMailFromUnauthenticated),
            256 => Some(MetricType::SmtpMailFromUnauthorized),
            257 => Some(MetricType::SmtpMailFromMissing),
            258 => Some(MetricType::SmtpMultipleMailFrom),
            259 => Some(MetricType::SmtpMailboxDoesNotExist),
            260 => Some(MetricType::SmtpRelayNotAllowed),
            261 => Some(MetricType::SmtpRcptToDuplicate),
            262 => Some(MetricType::SmtpRcptToMissing),
            263 => Some(MetricType::SmtpTooManyRecipients),
            264 => Some(MetricType::SmtpTooManyInvalidRcpt),
            265 => Some(MetricType::SmtpAuthMechanismNotSupported),
            266 => Some(MetricType::SmtpAuthExchangeTooLong),
            267 => Some(MetricType::SmtpCommandNotImplemented),
            268 => Some(MetricType::SmtpInvalidCommand),
            269 => Some(MetricType::SmtpSyntaxError),
            270 => Some(MetricType::SmtpRequestTooLarge),
            271 => Some(MetricType::SpamPyzorError),
            272 => Some(MetricType::SpamDnsblError),
            273 => Some(MetricType::SpamTrainCompleted),
            274 => Some(MetricType::SpamTrainSampleAdded),
            275 => Some(MetricType::SpamClassify),
            276 => Some(MetricType::SpamModelNotReady),
            277 => Some(MetricType::SpfPass),
            278 => Some(MetricType::SpfFail),
            279 => Some(MetricType::SpfSoftFail),
            280 => Some(MetricType::SpfNeutral),
            281 => Some(MetricType::SpfTempError),
            282 => Some(MetricType::SpfPermError),
            283 => Some(MetricType::SpfNone),
            7 => Some(MetricType::StoreDataReadTime),
            8 => Some(MetricType::StoreDataWriteTime),
            9 => Some(MetricType::StoreBlobReadTime),
            10 => Some(MetricType::StoreBlobWriteTime),
            284 => Some(MetricType::StoreAssertValueFailed),
            285 => Some(MetricType::StoreFoundationdbError),
            286 => Some(MetricType::StoreMysqlError),
            287 => Some(MetricType::StorePostgresqlError),
            288 => Some(MetricType::StoreRocksdbError),
            289 => Some(MetricType::StoreSqliteError),
            290 => Some(MetricType::StoreLdapError),
            291 => Some(MetricType::StoreElasticsearchError),
            292 => Some(MetricType::StoreRedisError),
            293 => Some(MetricType::StoreS3Error),
            294 => Some(MetricType::StoreAzureError),
            295 => Some(MetricType::StoreFilesystemError),
            296 => Some(MetricType::StorePoolError),
            297 => Some(MetricType::StoreDataCorruption),
            298 => Some(MetricType::StoreDecompressError),
            299 => Some(MetricType::StoreDeserializeError),
            300 => Some(MetricType::StoreNotFound),
            301 => Some(MetricType::StoreNotConfigured),
            302 => Some(MetricType::StoreNotSupported),
            303 => Some(MetricType::StoreUnexpectedError),
            304 => Some(MetricType::StoreCryptoError),
            305 => Some(MetricType::StoreHttpStoreError),
            306 => Some(MetricType::StoreBlobMissingMarker),
            307 => Some(MetricType::StoreDataWrite),
            308 => Some(MetricType::StoreDataIterate),
            309 => Some(MetricType::StoreBlobRead),
            310 => Some(MetricType::StoreBlobWrite),
            311 => Some(MetricType::StoreBlobDelete),
            363 => Some(MetricType::TaskManagerPending),
            364 => Some(MetricType::TaskManagerDue),
            361 => Some(MetricType::TaskManagerTaskFailed),
            362 => Some(MetricType::TaskManagerTaskRetry),
            383 => Some(MetricType::TaskManagerTaskStalled),
            384 => Some(MetricType::TaskManagerTaskExpired),
            312 => Some(MetricType::TaskManagerBlobNotFound),
            313 => Some(MetricType::TaskManagerMetadataNotFound),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            322 => Some(MetricType::TelemetryAlertEvent),
            #[cfg(feature = "enterprise")]
            196 => Some(MetricType::TelemetryAlertMessage),
            // SPDX-SnippetEnd
            314 => Some(MetricType::TelemetryLogError),
            315 => Some(MetricType::TelemetryWebhookError),
            316 => Some(MetricType::TelemetryOtelExporterError),
            317 => Some(MetricType::TelemetryOtelMetricsExporterError),
            318 => Some(MetricType::TelemetryPrometheusExporterError),
            319 => Some(MetricType::TelemetryJournalError),
            327 => Some(MetricType::TelemetryEventsDropped),
            320 => Some(MetricType::TlsHandshakeError),
            25 => Some(MetricType::UserCount),
            _ => None,
        }
    }

    pub fn event_id(&self) -> usize {
        match self {
            MetricType::AcmeAuthError => 1,
            MetricType::AcmeAuthTooManyAttempts => 4,
            MetricType::AcmeOrderCompleted => 16,
            MetricType::AcmeOrderInvalid => 17,
            MetricType::AcmeClientMissingSni => 6,
            MetricType::AcmeTlsAlpnError => 24,
            MetricType::AcmeTokenNotFound => 26,
            MetricType::AcmeError => 15,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiApiError => 540,
            #[cfg(feature = "enterprise")]
            MetricType::AiRequest => 621,
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamVerdict => 622,
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamSkipped => 623,
            #[cfg(feature = "enterprise")]
            MetricType::AiBreakerOpen => 624,
            // SPDX-SnippetEnd
            MetricType::ArcChainInvalid => 647,
            MetricType::ArcSignatureInvalid => 648,
            MetricType::ArcHashMismatch => 649,
            MetricType::AuthSuccess => 32,
            MetricType::AuthFailed => 30,
            MetricType::AuthTooManyAttempts => 33,
            MetricType::AuthError => 29,
            MetricType::CacheMiss => 45,
            MetricType::CacheHit => 46,
            MetricType::CacheStale => 47,
            MetricType::CacheEntryTooLarge => 592,
            MetricType::CacheSwapHit => 594,
            MetricType::CacheSwapMiss => 595,
            MetricType::CacheSwapWrite => 596,
            MetricType::CacheSwapError => 597,
            MetricType::CalendarAlarmSent => 562,
            MetricType::CalendarAlarmFailed => 565,
            MetricType::CalendarItipMessageSent => 566,
            MetricType::CalendarItipMessageReceived => 567,
            MetricType::CalendarItipMessageError => 568,
            MetricType::ClusterSubscriberError => 36,
            MetricType::ClusterSubscriberDisconnected => 37,
            MetricType::ClusterPublisherError => 40,
            MetricType::DaneAuthenticationSuccess => 62,
            MetricType::DaneAuthenticationFailure => 61,
            MetricType::DaneNoCertificatesFound => 64,
            MetricType::DaneCertificateParseError => 63,
            MetricType::DaneTlsaRecordFetchError => 66,
            MetricType::DaneTlsaRecordNotFound => 70,
            MetricType::DaneTlsaRecordNotDnssecSigned => 69,
            MetricType::DaneTlsaRecordInvalid => 67,
            MetricType::DaneBogusDnssecRecord => 588,
            MetricType::DeliveryAttemptStart => 72,
            MetricType::DeliveryAttemptEnd => 71,
            MetricType::DeliveryCompleted => 75,
            MetricType::DeliveryMxLookupFailed => 97,
            MetricType::DeliveryIpLookupFailed => 91,
            MetricType::DeliveryNullMx => 98,
            MetricType::DeliveryGreetingFailed => 88,
            MetricType::DeliveryEhloRejected => 86,
            MetricType::DeliveryAuthFailed => 74,
            MetricType::DeliveryMailFromRejected => 93,
            MetricType::DeliveryDelivered => 79,
            MetricType::DeliveryRcptToRejected => 104,
            MetricType::DeliveryRcptToFailed => 103,
            MetricType::DeliveryMessageRejected => 94,
            MetricType::DeliveryStartTlsUnavailable => 108,
            MetricType::DeliveryStartTlsError => 107,
            MetricType::DeliveryStartTlsDisabled => 106,
            MetricType::DeliveryImplicitTlsError => 89,
            MetricType::DeliveryConcurrencyLimitExceeded => 76,
            MetricType::DeliveryRateLimitExceeded => 99,
            MetricType::DeliveryDoubleBounce => 81,
            MetricType::DeliveryDsnSuccess => 83,
            MetricType::DeliveryDsnTempFail => 84,
            MetricType::DeliveryDsnPermFail => 82,
            MetricType::DkimPass => 112,
            MetricType::DkimNeutral => 110,
            MetricType::DkimFail => 109,
            MetricType::DkimPermError => 113,
            MetricType::DkimTempError => 115,
            MetricType::DkimNone => 111,
            MetricType::DkimSignatureInvalid => 643,
            MetricType::DkimPublicKeyError => 644,
            MetricType::DkimVerificationFailed => 645,
            MetricType::DkimHashMismatch => 646,
            MetricType::DkimSignerNotFound => 114,
            MetricType::Dkim2InstanceInvalid => 633,
            MetricType::Dkim2SignatureInvalid => 634,
            MetricType::Dkim2ChainInvalid => 635,
            MetricType::Dkim2TimestampInvalid => 636,
            MetricType::Dkim2EnvelopeMismatch => 637,
            MetricType::Dkim2CustodyBroken => 638,
            MetricType::Dkim2PublicKeyError => 639,
            MetricType::Dkim2VerificationFailed => 640,
            MetricType::Dkim2HashMismatch => 641,
            MetricType::Dkim2RecipeError => 642,
            MetricType::Dkim2SigningFailed => 650,
            MetricType::DmarcPass => 118,
            MetricType::DmarcFail => 116,
            MetricType::DmarcPermError => 119,
            MetricType::DmarcTempError => 120,
            MetricType::DmarcNone => 117,
            MetricType::DnsRecordCreationFailed => 9,
            MetricType::DnsRecordDeletionFailed => 10,
            MetricType::DnsRecordLookupFailed => 11,
            MetricType::DnsRecordPropagationTimeout => 14,
            MetricType::EvalError => 122,
            MetricType::EvalDirectoryNotFound => 121,
            MetricType::EvalStoreNotFound => 124,
            MetricType::HttpConnectionStart => 137,
            MetricType::HttpError => 138,
            MetricType::HttpRequestBody => 139,
            MetricType::HttpResponseBody => 141,
            MetricType::HttpXForwardedMissing => 142,
            MetricType::HttpXForwardedInvalid => 625,
            MetricType::ImapConnectionStart => 147,
            MetricType::ImapConnectionEnd => 146,
            MetricType::IncomingReportDmarcReport => 184,
            MetricType::IncomingReportDmarcReportWithWarnings => 185,
            MetricType::IncomingReportTlsReport => 190,
            MetricType::IncomingReportTlsReportWithWarnings => 191,
            MetricType::IncomingReportAbuseReport => 179,
            MetricType::IncomingReportAuthFailureReport => 181,
            MetricType::IncomingReportFraudReport => 186,
            MetricType::IncomingReportNotSpamReport => 188,
            MetricType::IncomingReportVirusReport => 193,
            MetricType::IncomingReportOtherReport => 189,
            MetricType::IncomingReportMessageParseFailed => 187,
            MetricType::IncomingReportDmarcParseFailed => 183,
            MetricType::IncomingReportTlsRpcParseFailed => 192,
            MetricType::IncomingReportArfParseFailed => 180,
            MetricType::IncomingReportDecompressError => 182,
            MetricType::IprevPass => 196,
            MetricType::IprevFail => 194,
            MetricType::IprevPermError => 197,
            MetricType::IprevTempError => 198,
            MetricType::IprevNone => 195,
            MetricType::JmapMethodCall => 207,
            MetricType::JmapInvalidArguments => 205,
            MetricType::JmapRequestTooLarge => 211,
            MetricType::JmapUnsupportedFilter => 216,
            MetricType::JmapUnsupportedSort => 217,
            MetricType::JmapUnknownMethod => 215,
            MetricType::JmapForbidden => 204,
            MetricType::JmapNotJson => 209,
            MetricType::JmapNotRequest => 210,
            MetricType::JmapWebsocketStart => 219,
            MetricType::JmapWebsocketError => 218,
            MetricType::LimitSizeRequest => 227,
            MetricType::LimitSizeUpload => 228,
            MetricType::LimitCallsIn => 222,
            MetricType::LimitConcurrentRequest => 224,
            MetricType::LimitConcurrentUpload => 225,
            MetricType::LimitConcurrentConnection => 223,
            MetricType::LimitQuota => 226,
            MetricType::LimitBlobQuota => 221,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::LimitTenantQuota => 536,
            // SPDX-SnippetEnd
            MetricType::LimitTooManyRequests => 229,
            MetricType::LimitMemoryBudget => 627,
            MetricType::MailAuthParseError => 238,
            MetricType::MailAuthMissingParameters => 236,
            MetricType::MailAuthNoHeadersFound => 237,
            MetricType::MailAuthCrypto => 231,
            MetricType::MailAuthIo => 235,
            MetricType::MailAuthBase64 => 230,
            MetricType::MailAuthDnsError => 232,
            MetricType::MailAuthDnsRecordNotFound => 234,
            MetricType::MailAuthDnsInvalidRecordType => 233,
            MetricType::MailAuthPolicyNotAligned => 239,
            MetricType::ManageSieveConnectionStart => 243,
            MetricType::ManageSieveConnectionEnd => 242,
            MetricType::MessageIngestHam => 267,
            MetricType::MessageIngestSpam => 270,
            MetricType::MessageIngestImapAppend => 268,
            MetricType::MessageIngestJmapAppend => 269,
            MetricType::MessageIngestDuplicate => 265,
            MetricType::MessageIngestError => 266,
            MetricType::MilterActionAccept => 271,
            MetricType::MilterActionDiscard => 273,
            MetricType::MilterActionReject => 274,
            MetricType::MilterActionTempFail => 277,
            MetricType::MilterActionReplyCode => 275,
            MetricType::MilterActionConnectionFailure => 272,
            MetricType::MilterActionShutdown => 276,
            MetricType::MtaHookActionAccept => 288,
            MetricType::MtaHookActionDiscard => 289,
            MetricType::MtaHookActionReject => 291,
            MetricType::MtaHookActionQuarantine => 290,
            MetricType::MtaHookError => 292,
            MetricType::MtaStsAuthorized => 293,
            MetricType::MtaStsNotAuthorized => 295,
            MetricType::MtaStsInvalidPolicy => 294,
            MetricType::NetworkTimeout => 311,
            MetricType::OutgoingReportSpfReport => 326,
            MetricType::OutgoingReportSpfRateLimited => 325,
            MetricType::OutgoingReportDkimReport => 314,
            MetricType::OutgoingReportDkimRateLimited => 313,
            MetricType::OutgoingReportDmarcReport => 317,
            MetricType::OutgoingReportDmarcRateLimited => 316,
            MetricType::OutgoingReportDmarcAggregateReport => 315,
            MetricType::OutgoingReportTlsAggregate => 328,
            MetricType::OutgoingReportHttpSubmission => 318,
            MetricType::OutgoingReportUnauthorizedReportingAddress => 329,
            MetricType::OutgoingReportReportingAddressValidationError => 324,
            MetricType::OutgoingReportNotFound => 323,
            MetricType::OutgoingReportSubmissionError => 327,
            MetricType::OutgoingReportNoRecipientsFound => 322,
            MetricType::Pop3ConnectionStart => 332,
            MetricType::Pop3ConnectionEnd => 331,
            MetricType::PushSubscriptionSuccess => 357,
            MetricType::PushSubscriptionError => 355,
            MetricType::PushSubscriptionNotFound => 356,
            MetricType::QueueMessageQueued => 364,
            MetricType::QueueAuthenticatedMessageQueued => 365,
            MetricType::QueueReportQueued => 366,
            MetricType::QueueDsnQueued => 363,
            MetricType::QueueAutogeneratedQueued => 362,
            MetricType::QueueRescheduled => 369,
            MetricType::QueueBlobNotFound => 358,
            MetricType::QueueRateLimitExceeded => 368,
            MetricType::QueueConcurrencyLimitExceeded => 359,
            MetricType::QueueQuotaExceeded => 367,
            MetricType::QueueBackPressure => 43,
            MetricType::ResourceNotFound => 373,
            MetricType::ResourceBadParameters => 370,
            MetricType::ResourceError => 372,
            MetricType::SearchIndexPartitionRetry => 632,
            MetricType::SearchIndexBatchIndexed => 126,
            MetricType::SearchIndexDocumentTruncated => 628,
            MetricType::SecurityAuthenticationBan => 28,
            MetricType::SecurityAbuseBan => 532,
            MetricType::SecurityScanBan => 541,
            MetricType::SecurityLoiterBan => 533,
            MetricType::SecurityIpBlocked => 302,
            MetricType::SecurityUnauthorized => 535,
            MetricType::ServerThreadError => 379,
            MetricType::SieveActionAccept => 380,
            MetricType::SieveActionAcceptReplace => 381,
            MetricType::SieveActionDiscard => 382,
            MetricType::SieveActionReject => 383,
            MetricType::SieveSendMessage => 390,
            MetricType::SieveMessageTooLarge => 385,
            MetricType::SieveRuntimeError => 388,
            MetricType::SieveUnexpectedError => 391,
            MetricType::SieveNotSupported => 386,
            MetricType::SieveQuotaExceeded => 387,
            MetricType::SmtpConnectionStart => 401,
            MetricType::SmtpConnectionEnd => 400,
            MetricType::SmtpError => 412,
            MetricType::SmtpConcurrencyLimitExceeded => 399,
            MetricType::SmtpTransferLimitExceeded => 468,
            MetricType::SmtpRateLimitExceeded => 444,
            MetricType::SmtpTimeLimitExceeded => 464,
            MetricType::SmtpMessageParseFailed => 434,
            MetricType::SmtpMessageTooLarge => 435,
            MetricType::SmtpLoopDetected => 427,
            MetricType::SmtpMultipleFromDomains => 626,
            MetricType::SmtpDkimPass => 406,
            MetricType::SmtpDkimFail => 405,
            MetricType::SmtpDkim2Pass => 589,
            MetricType::SmtpDkim2Fail => 590,
            MetricType::SmtpDkim2DsnRejected => 591,
            MetricType::SmtpArcPass => 394,
            MetricType::SmtpArcFail => 393,
            MetricType::SmtpSpfEhloPass => 457,
            MetricType::SmtpSpfEhloFail => 456,
            MetricType::SmtpSpfFromPass => 459,
            MetricType::SmtpSpfFromFail => 458,
            MetricType::SmtpDmarcPass => 408,
            MetricType::SmtpDmarcFail => 407,
            MetricType::SmtpIprevPass => 425,
            MetricType::SmtpIprevFail => 424,
            MetricType::SmtpTooManyMessages => 466,
            MetricType::SmtpInvalidEhlo => 420,
            MetricType::SmtpDidNotSayEhlo => 404,
            MetricType::SmtpMailFromUnauthenticated => 431,
            MetricType::SmtpMailFromUnauthorized => 432,
            MetricType::SmtpMailFromMissing => 429,
            MetricType::SmtpMultipleMailFrom => 439,
            MetricType::SmtpMailboxDoesNotExist => 433,
            MetricType::SmtpRelayNotAllowed => 451,
            MetricType::SmtpRcptToDuplicate => 448,
            MetricType::SmtpRcptToMissing => 449,
            MetricType::SmtpTooManyRecipients => 467,
            MetricType::SmtpTooManyInvalidRcpt => 465,
            MetricType::SmtpAuthMechanismNotSupported => 396,
            MetricType::SmtpAuthExchangeTooLong => 395,
            MetricType::SmtpCommandNotImplemented => 398,
            MetricType::SmtpInvalidCommand => 419,
            MetricType::SmtpSyntaxError => 463,
            MetricType::SmtpRequestTooLarge => 453,
            MetricType::SpamPyzorError => 477,
            MetricType::SpamDnsblError => 546,
            MetricType::SpamTrainCompleted => 478,
            MetricType::SpamTrainSampleAdded => 127,
            MetricType::SpamClassify => 473,
            MetricType::SpamModelNotReady => 479,
            MetricType::SpfPass => 484,
            MetricType::SpfFail => 481,
            MetricType::SpfSoftFail => 486,
            MetricType::SpfNeutral => 482,
            MetricType::SpfTempError => 487,
            MetricType::SpfPermError => 485,
            MetricType::SpfNone => 483,
            MetricType::StoreAssertValueFailed => 488,
            MetricType::StoreFoundationdbError => 501,
            MetricType::StoreMysqlError => 505,
            MetricType::StorePostgresqlError => 510,
            MetricType::StoreRocksdbError => 512,
            MetricType::StoreSqliteError => 515,
            MetricType::StoreLdapError => 503,
            MetricType::StoreElasticsearchError => 499,
            MetricType::StoreRedisError => 511,
            MetricType::StoreS3Error => 513,
            MetricType::StoreAzureError => 542,
            MetricType::StoreFilesystemError => 500,
            MetricType::StorePoolError => 509,
            MetricType::StoreDataCorruption => 494,
            MetricType::StoreDecompressError => 497,
            MetricType::StoreDeserializeError => 498,
            MetricType::StoreNotFound => 507,
            MetricType::StoreNotConfigured => 506,
            MetricType::StoreNotSupported => 508,
            MetricType::StoreUnexpectedError => 516,
            MetricType::StoreCryptoError => 493,
            MetricType::StoreHttpStoreError => 476,
            MetricType::StoreBlobMissingMarker => 490,
            MetricType::StoreDataWrite => 496,
            MetricType::StoreDataIterate => 495,
            MetricType::StoreBlobRead => 491,
            MetricType::StoreBlobWrite => 492,
            MetricType::StoreBlobDelete => 489,
            MetricType::TaskManagerTaskFailed => 570,
            MetricType::TaskManagerTaskRetry => 48,
            MetricType::TaskManagerTaskStalled => 651,
            MetricType::TaskManagerTaskExpired => 652,
            MetricType::TaskManagerBlobNotFound => 125,
            MetricType::TaskManagerMetadataNotFound => 129,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertEvent => 531,
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertMessage => 349,
            // SPDX-SnippetEnd
            MetricType::TelemetryLogError => 518,
            MetricType::TelemetryWebhookError => 522,
            MetricType::TelemetryOtelExporterError => 519,
            MetricType::TelemetryOtelMetricsExporterError => 520,
            MetricType::TelemetryPrometheusExporterError => 521,
            MetricType::TelemetryJournalError => 517,
            MetricType::TelemetryEventsDropped => 601,
            MetricType::TlsHandshakeError => 527,
            _ => usize::MAX,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            MetricType::AcmeAuthError => "ACME authentication error",
            MetricType::AcmeAuthTooManyAttempts => "Too many ACME authentication attempts",
            MetricType::AcmeOrderCompleted => "ACME order completed",
            MetricType::AcmeOrderInvalid => "ACME order invalid",
            MetricType::AcmeClientMissingSni => "ACME client missing SNI",
            MetricType::AcmeTlsAlpnError => "ACME TLS ALPN error",
            MetricType::AcmeTokenNotFound => "ACME token not found",
            MetricType::AcmeError => "ACME error",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => "AI request duration",
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => "AI input tokens per request",
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => "AI output tokens per request",
            #[cfg(feature = "enterprise")]
            MetricType::AiApiError => "AI API error",
            #[cfg(feature = "enterprise")]
            MetricType::AiRequest => "AI request completed",
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamVerdict => "AI spam verdict",
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamSkipped => "AI spam classifier skipped",
            #[cfg(feature = "enterprise")]
            MetricType::AiBreakerOpen => "AI model circuit breaker open",
            // SPDX-SnippetEnd
            MetricType::ArcChainInvalid => "ARC chain invalid",
            MetricType::ArcSignatureInvalid => "ARC signature invalid",
            MetricType::ArcHashMismatch => "ARC body hash mismatch",
            MetricType::AuthSuccess => "Authentication successful",
            MetricType::AuthFailed => "Authentication failed",
            MetricType::AuthTooManyAttempts => "Too many authentication attempts",
            MetricType::AuthError => "Authentication error",
            MetricType::CacheMessagesSize => "Memory used by the e-mail data cache",
            MetricType::CacheMessagesLargeSize => {
                "Total size of the large-account e-mail data caches held in memory, both those retained by the large tier and those still referenced by in-flight requests"
            }
            MetricType::CacheSize => "Memory used by all other caches",
            MetricType::CacheSwapPending => {
                "Cache snapshots with changes not yet written to the swap tier"
            }
            MetricType::CacheMiss => "Cache miss",
            MetricType::CacheHit => "Cache hit",
            MetricType::CacheStale => "Cache is stale",
            MetricType::CacheEntryTooLarge => "Cache entry too large",
            MetricType::CacheSwapHit => "Cache snapshot loaded",
            MetricType::CacheSwapMiss => "Cache snapshot unavailable",
            MetricType::CacheSwapWrite => "Cache snapshot written",
            MetricType::CacheSwapError => "Cache swap tier error",
            MetricType::CalendarAlarmSent => "Calendar alarm sent",
            MetricType::CalendarAlarmFailed => "Calendar alarm could not be sent",
            MetricType::CalendarItipMessageSent => "Calendar iTIP message sent",
            MetricType::CalendarItipMessageReceived => "Calendar iTIP message received",
            MetricType::CalendarItipMessageError => "iTIP message error",
            MetricType::ClusterSubscriberError => "PubSub subscriber error",
            MetricType::ClusterSubscriberDisconnected => "PubSub subscriber disconnected",
            MetricType::ClusterPublisherError => "PubSub publisher error",
            MetricType::DaneAuthenticationSuccess => "DANE authentication successful",
            MetricType::DaneAuthenticationFailure => "DANE authentication failed",
            MetricType::DaneNoCertificatesFound => "No certificates found for DANE",
            MetricType::DaneCertificateParseError => "Error parsing certificate for DANE",
            MetricType::DaneTlsaRecordFetchError => "Error fetching TLSA record",
            MetricType::DaneTlsaRecordNotFound => "TLSA record not found",
            MetricType::DaneTlsaRecordNotDnssecSigned => "TLSA record not DNSSEC signed",
            MetricType::DaneTlsaRecordInvalid => "Invalid TLSA record",
            MetricType::DaneBogusDnssecRecord => "Bogus DNSSEC record",
            MetricType::DeliveryTotalTime => {
                "Total message delivery time from submission to delivery"
            }
            MetricType::DeliveryAttemptTime => "Message delivery time",
            MetricType::DeliveryActiveConnections => "Active delivery connections",
            MetricType::DeliveryAttemptStart => "Delivery attempt started",
            MetricType::DeliveryAttemptEnd => "Delivery attempt ended",
            MetricType::DeliveryCompleted => "Delivery completed",
            MetricType::DeliveryMxLookupFailed => "MX record lookup failed",
            MetricType::DeliveryIpLookupFailed => "IP address lookup failed",
            MetricType::DeliveryNullMx => "Null MX record found",
            MetricType::DeliveryGreetingFailed => "SMTP greeting failed",
            MetricType::DeliveryEhloRejected => "SMTP EHLO rejected",
            MetricType::DeliveryAuthFailed => "SMTP authentication failed",
            MetricType::DeliveryMailFromRejected => "SMTP MAIL FROM rejected",
            MetricType::DeliveryDelivered => "Message delivered",
            MetricType::DeliveryRcptToRejected => "SMTP RCPT TO rejected",
            MetricType::DeliveryRcptToFailed => "SMTP RCPT TO failed",
            MetricType::DeliveryMessageRejected => "Message rejected by remote server",
            MetricType::DeliveryStartTlsUnavailable => "STARTTLS unavailable",
            MetricType::DeliveryStartTlsError => "STARTTLS error",
            MetricType::DeliveryStartTlsDisabled => "STARTTLS disabled",
            MetricType::DeliveryImplicitTlsError => "Implicit TLS error",
            MetricType::DeliveryConcurrencyLimitExceeded => "Concurrency limit exceeded",
            MetricType::DeliveryRateLimitExceeded => "Rate limit exceeded",
            MetricType::DeliveryDoubleBounce => "Discarding message after double bounce",
            MetricType::DeliveryDsnSuccess => "DSN success notification",
            MetricType::DeliveryDsnTempFail => "DSN temporary failure notification",
            MetricType::DeliveryDsnPermFail => "DSN permanent failure notification",
            MetricType::DkimPass => "DKIM verification passed",
            MetricType::DkimNeutral => "DKIM verification neutral",
            MetricType::DkimFail => "DKIM verification failed",
            MetricType::DkimPermError => "DKIM permanent error",
            MetricType::DkimTempError => "DKIM temporary error",
            MetricType::DkimNone => "No DKIM signature",
            MetricType::DkimSignatureInvalid => "DKIM signature invalid",
            MetricType::DkimPublicKeyError => "DKIM public key error",
            MetricType::DkimVerificationFailed => "DKIM signature verification failed",
            MetricType::DkimHashMismatch => "DKIM body hash mismatch",
            MetricType::DkimSignerNotFound => "DKIM signer not found",
            MetricType::Dkim2InstanceInvalid => "DKIM2 Message-Instance invalid",
            MetricType::Dkim2SignatureInvalid => "DKIM2 signature invalid",
            MetricType::Dkim2ChainInvalid => "DKIM2 chain invalid",
            MetricType::Dkim2TimestampInvalid => "DKIM2 timestamp invalid",
            MetricType::Dkim2EnvelopeMismatch => "DKIM2 envelope mismatch",
            MetricType::Dkim2CustodyBroken => "DKIM2 chain of custody broken",
            MetricType::Dkim2PublicKeyError => "DKIM2 public key error",
            MetricType::Dkim2VerificationFailed => "DKIM2 signature verification failed",
            MetricType::Dkim2HashMismatch => "DKIM2 hash mismatch",
            MetricType::Dkim2RecipeError => "DKIM2 recipe error",
            MetricType::Dkim2SigningFailed => "DKIM2 signing failed",
            MetricType::DmarcPass => "DMARC check passed",
            MetricType::DmarcFail => "DMARC check failed",
            MetricType::DmarcPermError => "DMARC permanent error",
            MetricType::DmarcTempError => "DMARC temporary error",
            MetricType::DmarcNone => "No DMARC record",
            MetricType::DnsLookupTime => "DNS lookup time",
            MetricType::DnsRecordCreationFailed => "DNS record creation failed",
            MetricType::DnsRecordDeletionFailed => "DNS record deletion failed",
            MetricType::DnsRecordLookupFailed => "DNS record lookup failed",
            MetricType::DnsRecordPropagationTimeout => "DNS record propagation timeout",
            MetricType::DomainCount => "Total number of domains",
            MetricType::EvalError => "Expression evaluation error",
            MetricType::EvalDirectoryNotFound => "Directory not found while evaluating expression",
            MetricType::EvalStoreNotFound => "Store not found while evaluating expression",
            MetricType::HttpRequestTime => "HTTP connection duration",
            MetricType::HttpActiveConnections => "Active HTTP connections",
            MetricType::HttpConnectionStart => "HTTP connection started",
            MetricType::HttpError => "HTTP error occurred",
            MetricType::HttpRequestBody => "HTTP request body",
            MetricType::HttpResponseBody => "HTTP response body",
            MetricType::HttpXForwardedMissing => "X-Forwarded-For header is missing",
            MetricType::HttpXForwardedInvalid => "Invalid forwarding header",
            MetricType::ImapRequestTime => "IMAP connection duration",
            MetricType::ImapActiveConnections => "Active IMAP connections",
            MetricType::ImapConnectionStart => "IMAP connection started",
            MetricType::ImapConnectionEnd => "IMAP connection ended",
            MetricType::IncomingReportDmarcReport => "DMARC report received",
            MetricType::IncomingReportDmarcReportWithWarnings => {
                "DMARC report received with warnings"
            }
            MetricType::IncomingReportTlsReport => "TLS report received",
            MetricType::IncomingReportTlsReportWithWarnings => "TLS report received with warnings",
            MetricType::IncomingReportAbuseReport => "Abuse report received",
            MetricType::IncomingReportAuthFailureReport => "Authentication failure report received",
            MetricType::IncomingReportFraudReport => "Fraud report received",
            MetricType::IncomingReportNotSpamReport => "Not spam report received",
            MetricType::IncomingReportVirusReport => "Virus report received",
            MetricType::IncomingReportOtherReport => "Other type of report received",
            MetricType::IncomingReportMessageParseFailed => {
                "Failed to parse incoming report message"
            }
            MetricType::IncomingReportDmarcParseFailed => "Failed to parse DMARC report",
            MetricType::IncomingReportTlsRpcParseFailed => "Failed to parse TLS RPC report",
            MetricType::IncomingReportArfParseFailed => "Failed to parse ARF report",
            MetricType::IncomingReportDecompressError => "Error decompressing report",
            MetricType::IprevPass => "IPREV check passed",
            MetricType::IprevFail => "IPREV check failed",
            MetricType::IprevPermError => "IPREV permanent error",
            MetricType::IprevTempError => "IPREV temporary error",
            MetricType::IprevNone => "No IPREV record",
            MetricType::JmapMethodCall => "JMAP method call",
            MetricType::JmapInvalidArguments => "Invalid JMAP arguments",
            MetricType::JmapRequestTooLarge => "JMAP request too large",
            MetricType::JmapUnsupportedFilter => "Unsupported JMAP filter",
            MetricType::JmapUnsupportedSort => "Unsupported JMAP sort",
            MetricType::JmapUnknownMethod => "Unknown JMAP method",
            MetricType::JmapForbidden => "JMAP operation forbidden",
            MetricType::JmapNotJson => "JMAP request is not JSON",
            MetricType::JmapNotRequest => "JMAP input is not a request",
            MetricType::JmapWebsocketStart => "JMAP WebSocket connection started",
            MetricType::JmapWebsocketError => "JMAP WebSocket error",
            MetricType::LimitSizeRequest => "Request size limit reached",
            MetricType::LimitSizeUpload => "Upload size limit reached",
            MetricType::LimitCallsIn => "Incoming calls limit reached",
            MetricType::LimitConcurrentRequest => "Concurrent request limit reached",
            MetricType::LimitConcurrentUpload => "Concurrent upload limit reached",
            MetricType::LimitConcurrentConnection => "Concurrent connection limit reached",
            MetricType::LimitQuota => "Quota limit reached",
            MetricType::LimitBlobQuota => "Blob quota limit reached",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::LimitTenantQuota => "Tenant quota limit reached",
            // SPDX-SnippetEnd
            MetricType::LimitTooManyRequests => "Too many requests",
            MetricType::LimitMemoryBudget => "Memory budget exceeded",
            MetricType::MailAuthParseError => "Mail authentication parse error",
            MetricType::MailAuthMissingParameters => "Missing mail authentication parameters",
            MetricType::MailAuthNoHeadersFound => "No headers found in message",
            MetricType::MailAuthCrypto => "Crypto error during mail authentication",
            MetricType::MailAuthIo => "I/O error during mail authentication",
            MetricType::MailAuthBase64 => "Base64 error during mail authentication",
            MetricType::MailAuthDnsError => "DNS error",
            MetricType::MailAuthDnsRecordNotFound => "DNS record not found",
            MetricType::MailAuthDnsInvalidRecordType => "Invalid DNS record type",
            MetricType::MailAuthPolicyNotAligned => "Policy not aligned",
            MetricType::ManageSieveConnectionStart => "ManageSieve connection started",
            MetricType::ManageSieveConnectionEnd => "ManageSieve connection ended",
            MetricType::MessageSize => "Received message size",
            MetricType::MessageAuthenticatedSize => {
                "Received message size from authenticated users"
            }
            MetricType::MessageIngestTime => "Message ingestion time",
            MetricType::MessageIngestHam => "Message ingested",
            MetricType::MessageIngestSpam => "Possible spam message ingested",
            MetricType::MessageIngestImapAppend => "Message appended via IMAP",
            MetricType::MessageIngestJmapAppend => "Message appended via JMAP",
            MetricType::MessageIngestDuplicate => "Skipping duplicate message",
            MetricType::MessageIngestError => "Message ingestion error",
            MetricType::MilterActionAccept => "Milter action: Accept",
            MetricType::MilterActionDiscard => "Milter action: Discard",
            MetricType::MilterActionReject => "Milter action: Reject",
            MetricType::MilterActionTempFail => "Milter action: Temporary failure",
            MetricType::MilterActionReplyCode => "Milter action: Reply code",
            MetricType::MilterActionConnectionFailure => "Milter action: Connection failure",
            MetricType::MilterActionShutdown => "Milter action: Shutdown",
            MetricType::MtaHookActionAccept => "MTA hook action: Accept",
            MetricType::MtaHookActionDiscard => "MTA hook action: Discard",
            MetricType::MtaHookActionReject => "MTA hook action: Reject",
            MetricType::MtaHookActionQuarantine => "MTA hook action: Quarantine",
            MetricType::MtaHookError => "MTA hook error",
            MetricType::MtaStsAuthorized => "Host authorized by MTA-STS policy",
            MetricType::MtaStsNotAuthorized => "Host not authorized by MTA-STS policy",
            MetricType::MtaStsInvalidPolicy => "Invalid MTA-STS policy",
            MetricType::NetworkTimeout => "Network timeout",
            MetricType::OutgoingReportSize => "Outgoing report size",
            MetricType::OutgoingReportSpfReport => "SPF report sent",
            MetricType::OutgoingReportSpfRateLimited => "SPF report rate limited",
            MetricType::OutgoingReportDkimReport => "DKIM report sent",
            MetricType::OutgoingReportDkimRateLimited => "DKIM report rate limited",
            MetricType::OutgoingReportDmarcReport => "DMARC report sent",
            MetricType::OutgoingReportDmarcRateLimited => "DMARC report rate limited",
            MetricType::OutgoingReportDmarcAggregateReport => "DMARC aggregate is being prepared",
            MetricType::OutgoingReportTlsAggregate => "TLS aggregate report is being prepared",
            MetricType::OutgoingReportHttpSubmission => "Report submitted via HTTP",
            MetricType::OutgoingReportUnauthorizedReportingAddress => {
                "Unauthorized reporting address"
            }
            MetricType::OutgoingReportReportingAddressValidationError => {
                "Error validating reporting address"
            }
            MetricType::OutgoingReportNotFound => "Report not found",
            MetricType::OutgoingReportSubmissionError => "Error submitting report",
            MetricType::OutgoingReportNoRecipientsFound => "No recipients found for report",
            MetricType::Pop3RequestTime => "POP3 connection duration",
            MetricType::Pop3ActiveConnections => "Active POP3 connections",
            MetricType::Pop3ConnectionStart => "POP3 connection started",
            MetricType::Pop3ConnectionEnd => "POP3 connection ended",
            MetricType::PushSubscriptionSuccess => "Push subscription successful",
            MetricType::PushSubscriptionError => "Push subscription error",
            MetricType::PushSubscriptionNotFound => "Push subscription not found",
            MetricType::QueueCount => "Total number of messages in the queue",
            MetricType::QueueMessageQueued => "Queued message for delivery",
            MetricType::QueueAuthenticatedMessageQueued => "Queued message submission for delivery",
            MetricType::QueueReportQueued => "Queued report for delivery",
            MetricType::QueueDsnQueued => "Queued DSN for delivery",
            MetricType::QueueAutogeneratedQueued => "Queued autogenerated message for delivery",
            MetricType::QueueRescheduled => "Message rescheduled for delivery",
            MetricType::QueueBlobNotFound => "Message blob not found",
            MetricType::QueueRateLimitExceeded => "Rate limit exceeded",
            MetricType::QueueConcurrencyLimitExceeded => "Concurrency limit exceeded",
            MetricType::QueueQuotaExceeded => "Quota exceeded",
            MetricType::QueueBackPressure => "Queue backpressure detected",
            MetricType::ResourceNotFound => "Resource not found",
            MetricType::ResourceBadParameters => "Bad resource parameters",
            MetricType::ResourceError => "Resource error",
            MetricType::SearchIndexIndexTime => {
                "Time to build and write one batch of documents to the full-text index"
            }
            MetricType::SearchIndexPendingEmail => "E-mail messages waiting to be indexed",
            MetricType::SearchIndexPendingCalendar => "Calendar events waiting to be indexed",
            MetricType::SearchIndexPendingContacts => "Contacts waiting to be indexed",
            MetricType::SearchIndexPendingFile => "Files waiting to be indexed",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => "Traces waiting to be indexed",
            // SPDX-SnippetEnd
            MetricType::SearchIndexPartitionRetry => "Index partition will be retried",
            MetricType::SearchIndexBatchIndexed => "Search index batch written",
            MetricType::SearchIndexDocumentTruncated => "Search document truncated",
            MetricType::SecurityAuthenticationBan => "Banned due to authentication errors",
            MetricType::SecurityAbuseBan => "Banned due to abuse",
            MetricType::SecurityScanBan => "Banned due to scan",
            MetricType::SecurityLoiterBan => "Banned due to loitering",
            MetricType::SecurityIpBlocked => "Blocked IP address",
            MetricType::SecurityUnauthorized => "Unauthorized access",
            MetricType::ServerMemory => "Server memory usage",
            MetricType::ServerBufferedMemorySmtp => {
                "Memory reserved for buffering inbound SMTP messages"
            }
            MetricType::ServerBufferedMemoryRead => {
                "Memory reserved for blobs read from the blob store"
            }
            MetricType::ServerThreadError => "Server thread error",
            MetricType::SieveRequestTime => "ManageSieve connection duration",
            MetricType::SieveActiveConnections => "Active ManageSieve connections",
            MetricType::SieveActionAccept => "Sieve action: Accept",
            MetricType::SieveActionAcceptReplace => "Sieve action: Accept and replace",
            MetricType::SieveActionDiscard => "Sieve action: Discard",
            MetricType::SieveActionReject => "Sieve action: Reject",
            MetricType::SieveSendMessage => "Sieve sending message",
            MetricType::SieveMessageTooLarge => "Sieve message too large",
            MetricType::SieveRuntimeError => "Sieve runtime error",
            MetricType::SieveUnexpectedError => "Unexpected Sieve error",
            MetricType::SieveNotSupported => "Sieve action not supported",
            MetricType::SieveQuotaExceeded => "Sieve quota exceeded",
            MetricType::SmtpRequestTime => "SMTP connection duration",
            MetricType::SmtpActiveConnections => "Active SMTP connections",
            MetricType::SmtpConnectionStart => "SMTP connection started",
            MetricType::SmtpConnectionEnd => "SMTP connection ended",
            MetricType::SmtpError => "SMTP error occurred",
            MetricType::SmtpConcurrencyLimitExceeded => "Concurrency limit exceeded",
            MetricType::SmtpTransferLimitExceeded => "Transfer limit exceeded",
            MetricType::SmtpRateLimitExceeded => "Rate limit exceeded",
            MetricType::SmtpTimeLimitExceeded => "Time limit exceeded",
            MetricType::SmtpMessageParseFailed => "Message parsing failed",
            MetricType::SmtpMessageTooLarge => "Message too large",
            MetricType::SmtpLoopDetected => "Mail loop detected",
            MetricType::SmtpMultipleFromDomains => "Multiple From domains",
            MetricType::SmtpDkimPass => "DKIM verification passed",
            MetricType::SmtpDkimFail => "DKIM verification failed",
            MetricType::SmtpDkim2Pass => "DKIM2 verification passed",
            MetricType::SmtpDkim2Fail => "DKIM2 verification failed",
            MetricType::SmtpDkim2DsnRejected => "DKIM2 DSN rejected",
            MetricType::SmtpArcPass => "ARC verification passed",
            MetricType::SmtpArcFail => "ARC verification failed",
            MetricType::SmtpSpfEhloPass => "SPF EHLO check passed",
            MetricType::SmtpSpfEhloFail => "SPF EHLO check failed",
            MetricType::SmtpSpfFromPass => "SPF From check passed",
            MetricType::SmtpSpfFromFail => "SPF From check failed",
            MetricType::SmtpDmarcPass => "DMARC check passed",
            MetricType::SmtpDmarcFail => "DMARC check failed",
            MetricType::SmtpIprevPass => "IPREV check passed",
            MetricType::SmtpIprevFail => "IPREV check failed",
            MetricType::SmtpTooManyMessages => "Too many messages",
            MetricType::SmtpInvalidEhlo => "Invalid EHLO command",
            MetricType::SmtpDidNotSayEhlo => "Client did not say EHLO",
            MetricType::SmtpMailFromUnauthenticated => "MAIL FROM without authentication",
            MetricType::SmtpMailFromUnauthorized => "MAIL FROM unauthorized",
            MetricType::SmtpMailFromMissing => "MAIL FROM address missing",
            MetricType::SmtpMultipleMailFrom => "Multiple MAIL FROM commands",
            MetricType::SmtpMailboxDoesNotExist => "Mailbox does not exist",
            MetricType::SmtpRelayNotAllowed => "Relay not allowed",
            MetricType::SmtpRcptToDuplicate => "Duplicate RCPT TO",
            MetricType::SmtpRcptToMissing => "RCPT TO address missing",
            MetricType::SmtpTooManyRecipients => "Too many recipients",
            MetricType::SmtpTooManyInvalidRcpt => "Too many invalid recipients",
            MetricType::SmtpAuthMechanismNotSupported => "Auth mechanism not supported",
            MetricType::SmtpAuthExchangeTooLong => "Auth exchange too long",
            MetricType::SmtpCommandNotImplemented => "Command not implemented",
            MetricType::SmtpInvalidCommand => "Invalid command",
            MetricType::SmtpSyntaxError => "Syntax error",
            MetricType::SmtpRequestTooLarge => "Request too large",
            MetricType::SpamPyzorError => "Pyzor error",
            MetricType::SpamDnsblError => "Error querying DNSBL",
            MetricType::SpamTrainCompleted => "Spam classifier training completed",
            MetricType::SpamTrainSampleAdded => "New training sample added",
            MetricType::SpamClassify => "Classifying message for spam",
            MetricType::SpamModelNotReady => "Spam classifier model not ready",
            MetricType::SpfPass => "SPF check passed",
            MetricType::SpfFail => "SPF check failed",
            MetricType::SpfSoftFail => "SPF soft fail",
            MetricType::SpfNeutral => "SPF neutral result",
            MetricType::SpfTempError => "SPF temporary error",
            MetricType::SpfPermError => "SPF permanent error",
            MetricType::SpfNone => "No SPF record",
            MetricType::StoreDataReadTime => "Data store read time",
            MetricType::StoreDataWriteTime => "Data store write time",
            MetricType::StoreBlobReadTime => "Blob store read time",
            MetricType::StoreBlobWriteTime => "Blob store write time",
            MetricType::StoreAssertValueFailed => "Another process modified the record",
            MetricType::StoreFoundationdbError => "FoundationDB error",
            MetricType::StoreMysqlError => "MySQL error",
            MetricType::StorePostgresqlError => "PostgreSQL error",
            MetricType::StoreRocksdbError => "RocksDB error",
            MetricType::StoreSqliteError => "SQLite error",
            MetricType::StoreLdapError => "LDAP error",
            MetricType::StoreElasticsearchError => "ElasticSearch error",
            MetricType::StoreRedisError => "Redis error",
            MetricType::StoreS3Error => "S3 error",
            MetricType::StoreAzureError => "Azure error",
            MetricType::StoreFilesystemError => "Filesystem error",
            MetricType::StorePoolError => "Connection pool error",
            MetricType::StoreDataCorruption => "Data corruption detected",
            MetricType::StoreDecompressError => "Decompression error",
            MetricType::StoreDeserializeError => "Deserialization error",
            MetricType::StoreNotFound => "Record not found in database",
            MetricType::StoreNotConfigured => "Store not configured",
            MetricType::StoreNotSupported => "Operation not supported by store",
            MetricType::StoreUnexpectedError => "Unexpected store error",
            MetricType::StoreCryptoError => "Store crypto error",
            MetricType::StoreHttpStoreError => "Error updating HTTP store",
            MetricType::StoreBlobMissingMarker => "Blob missing marker",
            MetricType::StoreDataWrite => "Write batch operation",
            MetricType::StoreDataIterate => "Data store iteration operation",
            MetricType::StoreBlobRead => "Blob read operation",
            MetricType::StoreBlobWrite => "Blob write operation",
            MetricType::StoreBlobDelete => "Blob delete operation",
            MetricType::TaskManagerPending => "Tasks queued in the task manager",
            MetricType::TaskManagerDue => "Tasks due for execution that have not run yet",
            MetricType::TaskManagerTaskFailed => "Task failed permanently",
            MetricType::TaskManagerTaskRetry => "Task will be retried",
            MetricType::TaskManagerTaskStalled => "Task stalled",
            MetricType::TaskManagerTaskExpired => "Task expired",
            MetricType::TaskManagerBlobNotFound => "Blob not found for task",
            MetricType::TaskManagerMetadataNotFound => "Metadata not found for task",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertEvent => "Alert event triggered",
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertMessage => "Alert message sent",
            // SPDX-SnippetEnd
            MetricType::TelemetryLogError => "Log collector error",
            MetricType::TelemetryWebhookError => "Webhook collector error",
            MetricType::TelemetryOtelExporterError => "OpenTelemetry exporter error",
            MetricType::TelemetryOtelMetricsExporterError => "OpenTelemetry metrics exporter error",
            MetricType::TelemetryPrometheusExporterError => "Prometheus exporter error",
            MetricType::TelemetryJournalError => "Journal collector error",
            MetricType::TelemetryEventsDropped => "Telemetry events dropped",
            MetricType::TlsHandshakeError => "TLS handshake error",
            MetricType::UserCount => "Total number of users",
        }
    }

    pub fn unit(&self) -> &'static str {
        match self {
            MetricType::CacheMessagesSize
            | MetricType::CacheMessagesLargeSize
            | MetricType::CacheSize
            | MetricType::MessageSize
            | MetricType::MessageAuthenticatedSize
            | MetricType::OutgoingReportSize
            | MetricType::ServerMemory
            | MetricType::ServerBufferedMemorySmtp
            | MetricType::ServerBufferedMemoryRead => "bytes",
            MetricType::DeliveryActiveConnections
            | MetricType::HttpActiveConnections
            | MetricType::ImapActiveConnections
            | MetricType::Pop3ActiveConnections
            | MetricType::SieveActiveConnections
            | MetricType::SmtpActiveConnections => "connections",
            MetricType::AcmeAuthError
            | MetricType::AcmeAuthTooManyAttempts
            | MetricType::AcmeOrderCompleted
            | MetricType::AcmeOrderInvalid
            | MetricType::AcmeClientMissingSni
            | MetricType::AcmeTlsAlpnError
            | MetricType::AcmeTokenNotFound
            | MetricType::AcmeError
            | MetricType::ArcChainInvalid
            | MetricType::ArcSignatureInvalid
            | MetricType::ArcHashMismatch
            | MetricType::AuthSuccess
            | MetricType::AuthFailed
            | MetricType::AuthTooManyAttempts
            | MetricType::AuthError
            | MetricType::CacheMiss
            | MetricType::CacheHit
            | MetricType::CacheStale
            | MetricType::CacheEntryTooLarge
            | MetricType::CacheSwapHit
            | MetricType::CacheSwapMiss
            | MetricType::CacheSwapWrite
            | MetricType::CacheSwapError
            | MetricType::CalendarAlarmSent
            | MetricType::CalendarAlarmFailed
            | MetricType::CalendarItipMessageSent
            | MetricType::CalendarItipMessageReceived
            | MetricType::CalendarItipMessageError
            | MetricType::ClusterSubscriberError
            | MetricType::ClusterSubscriberDisconnected
            | MetricType::ClusterPublisherError
            | MetricType::DaneAuthenticationSuccess
            | MetricType::DaneAuthenticationFailure
            | MetricType::DaneNoCertificatesFound
            | MetricType::DaneCertificateParseError
            | MetricType::DaneTlsaRecordFetchError
            | MetricType::DaneTlsaRecordNotFound
            | MetricType::DaneTlsaRecordNotDnssecSigned
            | MetricType::DaneTlsaRecordInvalid
            | MetricType::DaneBogusDnssecRecord
            | MetricType::DeliveryAttemptStart
            | MetricType::DeliveryAttemptEnd
            | MetricType::DeliveryCompleted
            | MetricType::DeliveryMxLookupFailed
            | MetricType::DeliveryIpLookupFailed
            | MetricType::DeliveryNullMx
            | MetricType::DeliveryGreetingFailed
            | MetricType::DeliveryEhloRejected
            | MetricType::DeliveryAuthFailed
            | MetricType::DeliveryMailFromRejected
            | MetricType::DeliveryDelivered
            | MetricType::DeliveryRcptToRejected
            | MetricType::DeliveryRcptToFailed
            | MetricType::DeliveryMessageRejected
            | MetricType::DeliveryStartTlsUnavailable
            | MetricType::DeliveryStartTlsError
            | MetricType::DeliveryStartTlsDisabled
            | MetricType::DeliveryImplicitTlsError
            | MetricType::DeliveryConcurrencyLimitExceeded
            | MetricType::DeliveryRateLimitExceeded
            | MetricType::DeliveryDoubleBounce
            | MetricType::DeliveryDsnSuccess
            | MetricType::DeliveryDsnTempFail
            | MetricType::DeliveryDsnPermFail
            | MetricType::DkimPass
            | MetricType::DkimNeutral
            | MetricType::DkimFail
            | MetricType::DkimPermError
            | MetricType::DkimTempError
            | MetricType::DkimNone
            | MetricType::DkimSignatureInvalid
            | MetricType::DkimPublicKeyError
            | MetricType::DkimVerificationFailed
            | MetricType::DkimHashMismatch
            | MetricType::DkimSignerNotFound
            | MetricType::Dkim2InstanceInvalid
            | MetricType::Dkim2SignatureInvalid
            | MetricType::Dkim2ChainInvalid
            | MetricType::Dkim2TimestampInvalid
            | MetricType::Dkim2EnvelopeMismatch
            | MetricType::Dkim2CustodyBroken
            | MetricType::Dkim2PublicKeyError
            | MetricType::Dkim2VerificationFailed
            | MetricType::Dkim2HashMismatch
            | MetricType::Dkim2RecipeError
            | MetricType::Dkim2SigningFailed
            | MetricType::DmarcPass
            | MetricType::DmarcFail
            | MetricType::DmarcPermError
            | MetricType::DmarcTempError
            | MetricType::DmarcNone
            | MetricType::DnsRecordCreationFailed
            | MetricType::DnsRecordDeletionFailed
            | MetricType::DnsRecordLookupFailed
            | MetricType::DnsRecordPropagationTimeout
            | MetricType::EvalError
            | MetricType::EvalDirectoryNotFound
            | MetricType::EvalStoreNotFound
            | MetricType::HttpConnectionStart
            | MetricType::HttpError
            | MetricType::HttpRequestBody
            | MetricType::HttpResponseBody
            | MetricType::HttpXForwardedMissing
            | MetricType::HttpXForwardedInvalid
            | MetricType::ImapConnectionStart
            | MetricType::ImapConnectionEnd
            | MetricType::IncomingReportDmarcReport
            | MetricType::IncomingReportDmarcReportWithWarnings
            | MetricType::IncomingReportTlsReport
            | MetricType::IncomingReportTlsReportWithWarnings
            | MetricType::IncomingReportAbuseReport
            | MetricType::IncomingReportAuthFailureReport
            | MetricType::IncomingReportFraudReport
            | MetricType::IncomingReportNotSpamReport
            | MetricType::IncomingReportVirusReport
            | MetricType::IncomingReportOtherReport
            | MetricType::IncomingReportMessageParseFailed
            | MetricType::IncomingReportDmarcParseFailed
            | MetricType::IncomingReportTlsRpcParseFailed
            | MetricType::IncomingReportArfParseFailed
            | MetricType::IncomingReportDecompressError
            | MetricType::IprevPass
            | MetricType::IprevFail
            | MetricType::IprevPermError
            | MetricType::IprevTempError
            | MetricType::IprevNone
            | MetricType::JmapMethodCall
            | MetricType::JmapInvalidArguments
            | MetricType::JmapRequestTooLarge
            | MetricType::JmapUnsupportedFilter
            | MetricType::JmapUnsupportedSort
            | MetricType::JmapUnknownMethod
            | MetricType::JmapForbidden
            | MetricType::JmapNotJson
            | MetricType::JmapNotRequest
            | MetricType::JmapWebsocketStart
            | MetricType::JmapWebsocketError
            | MetricType::LimitSizeRequest
            | MetricType::LimitSizeUpload
            | MetricType::LimitCallsIn
            | MetricType::LimitConcurrentRequest
            | MetricType::LimitConcurrentUpload
            | MetricType::LimitConcurrentConnection
            | MetricType::LimitQuota
            | MetricType::LimitBlobQuota
            | MetricType::LimitTooManyRequests
            | MetricType::LimitMemoryBudget
            | MetricType::MailAuthParseError
            | MetricType::MailAuthMissingParameters
            | MetricType::MailAuthNoHeadersFound
            | MetricType::MailAuthCrypto
            | MetricType::MailAuthIo
            | MetricType::MailAuthBase64
            | MetricType::MailAuthDnsError
            | MetricType::MailAuthDnsRecordNotFound
            | MetricType::MailAuthDnsInvalidRecordType
            | MetricType::MailAuthPolicyNotAligned
            | MetricType::ManageSieveConnectionStart
            | MetricType::ManageSieveConnectionEnd
            | MetricType::MessageIngestHam
            | MetricType::MessageIngestSpam
            | MetricType::MessageIngestImapAppend
            | MetricType::MessageIngestJmapAppend
            | MetricType::MessageIngestDuplicate
            | MetricType::MessageIngestError
            | MetricType::MilterActionAccept
            | MetricType::MilterActionDiscard
            | MetricType::MilterActionReject
            | MetricType::MilterActionTempFail
            | MetricType::MilterActionReplyCode
            | MetricType::MilterActionConnectionFailure
            | MetricType::MilterActionShutdown
            | MetricType::MtaHookActionAccept
            | MetricType::MtaHookActionDiscard
            | MetricType::MtaHookActionReject
            | MetricType::MtaHookActionQuarantine
            | MetricType::MtaHookError
            | MetricType::MtaStsAuthorized
            | MetricType::MtaStsNotAuthorized
            | MetricType::MtaStsInvalidPolicy
            | MetricType::NetworkTimeout
            | MetricType::OutgoingReportSpfReport
            | MetricType::OutgoingReportSpfRateLimited
            | MetricType::OutgoingReportDkimReport
            | MetricType::OutgoingReportDkimRateLimited
            | MetricType::OutgoingReportDmarcReport
            | MetricType::OutgoingReportDmarcRateLimited
            | MetricType::OutgoingReportDmarcAggregateReport
            | MetricType::OutgoingReportTlsAggregate
            | MetricType::OutgoingReportHttpSubmission
            | MetricType::OutgoingReportUnauthorizedReportingAddress
            | MetricType::OutgoingReportReportingAddressValidationError
            | MetricType::OutgoingReportNotFound
            | MetricType::OutgoingReportSubmissionError
            | MetricType::OutgoingReportNoRecipientsFound
            | MetricType::Pop3ConnectionStart
            | MetricType::Pop3ConnectionEnd
            | MetricType::PushSubscriptionSuccess
            | MetricType::PushSubscriptionError
            | MetricType::PushSubscriptionNotFound
            | MetricType::QueueMessageQueued
            | MetricType::QueueAuthenticatedMessageQueued
            | MetricType::QueueReportQueued
            | MetricType::QueueDsnQueued
            | MetricType::QueueAutogeneratedQueued
            | MetricType::QueueRescheduled
            | MetricType::QueueBlobNotFound
            | MetricType::QueueRateLimitExceeded
            | MetricType::QueueConcurrencyLimitExceeded
            | MetricType::QueueQuotaExceeded
            | MetricType::QueueBackPressure
            | MetricType::ResourceNotFound
            | MetricType::ResourceBadParameters
            | MetricType::ResourceError
            | MetricType::SearchIndexPartitionRetry
            | MetricType::SearchIndexBatchIndexed
            | MetricType::SearchIndexDocumentTruncated
            | MetricType::SecurityAuthenticationBan
            | MetricType::SecurityAbuseBan
            | MetricType::SecurityScanBan
            | MetricType::SecurityLoiterBan
            | MetricType::SecurityIpBlocked
            | MetricType::SecurityUnauthorized
            | MetricType::ServerThreadError
            | MetricType::SieveActionAccept
            | MetricType::SieveActionAcceptReplace
            | MetricType::SieveActionDiscard
            | MetricType::SieveActionReject
            | MetricType::SieveSendMessage
            | MetricType::SieveMessageTooLarge
            | MetricType::SieveRuntimeError
            | MetricType::SieveUnexpectedError
            | MetricType::SieveNotSupported
            | MetricType::SieveQuotaExceeded
            | MetricType::SmtpConnectionStart
            | MetricType::SmtpConnectionEnd
            | MetricType::SmtpError
            | MetricType::SmtpConcurrencyLimitExceeded
            | MetricType::SmtpTransferLimitExceeded
            | MetricType::SmtpRateLimitExceeded
            | MetricType::SmtpTimeLimitExceeded
            | MetricType::SmtpMessageParseFailed
            | MetricType::SmtpMessageTooLarge
            | MetricType::SmtpLoopDetected
            | MetricType::SmtpMultipleFromDomains
            | MetricType::SmtpDkimPass
            | MetricType::SmtpDkimFail
            | MetricType::SmtpDkim2Pass
            | MetricType::SmtpDkim2Fail
            | MetricType::SmtpDkim2DsnRejected
            | MetricType::SmtpArcPass
            | MetricType::SmtpArcFail
            | MetricType::SmtpSpfEhloPass
            | MetricType::SmtpSpfEhloFail
            | MetricType::SmtpSpfFromPass
            | MetricType::SmtpSpfFromFail
            | MetricType::SmtpDmarcPass
            | MetricType::SmtpDmarcFail
            | MetricType::SmtpIprevPass
            | MetricType::SmtpIprevFail
            | MetricType::SmtpTooManyMessages
            | MetricType::SmtpInvalidEhlo
            | MetricType::SmtpDidNotSayEhlo
            | MetricType::SmtpMailFromUnauthenticated
            | MetricType::SmtpMailFromUnauthorized
            | MetricType::SmtpMailFromMissing
            | MetricType::SmtpMultipleMailFrom
            | MetricType::SmtpMailboxDoesNotExist
            | MetricType::SmtpRelayNotAllowed
            | MetricType::SmtpRcptToDuplicate
            | MetricType::SmtpRcptToMissing
            | MetricType::SmtpTooManyRecipients
            | MetricType::SmtpTooManyInvalidRcpt
            | MetricType::SmtpAuthMechanismNotSupported
            | MetricType::SmtpAuthExchangeTooLong
            | MetricType::SmtpCommandNotImplemented
            | MetricType::SmtpInvalidCommand
            | MetricType::SmtpSyntaxError
            | MetricType::SmtpRequestTooLarge
            | MetricType::SpamPyzorError
            | MetricType::SpamDnsblError
            | MetricType::SpamTrainCompleted
            | MetricType::SpamTrainSampleAdded
            | MetricType::SpamClassify
            | MetricType::SpamModelNotReady
            | MetricType::SpfPass
            | MetricType::SpfFail
            | MetricType::SpfSoftFail
            | MetricType::SpfNeutral
            | MetricType::SpfTempError
            | MetricType::SpfPermError
            | MetricType::SpfNone
            | MetricType::StoreAssertValueFailed
            | MetricType::StoreFoundationdbError
            | MetricType::StoreMysqlError
            | MetricType::StorePostgresqlError
            | MetricType::StoreRocksdbError
            | MetricType::StoreSqliteError
            | MetricType::StoreLdapError
            | MetricType::StoreElasticsearchError
            | MetricType::StoreRedisError
            | MetricType::StoreS3Error
            | MetricType::StoreAzureError
            | MetricType::StoreFilesystemError
            | MetricType::StorePoolError
            | MetricType::StoreDataCorruption
            | MetricType::StoreDecompressError
            | MetricType::StoreDeserializeError
            | MetricType::StoreNotFound
            | MetricType::StoreNotConfigured
            | MetricType::StoreNotSupported
            | MetricType::StoreUnexpectedError
            | MetricType::StoreCryptoError
            | MetricType::StoreHttpStoreError
            | MetricType::StoreBlobMissingMarker
            | MetricType::StoreDataWrite
            | MetricType::StoreDataIterate
            | MetricType::StoreBlobRead
            | MetricType::StoreBlobWrite
            | MetricType::StoreBlobDelete
            | MetricType::TaskManagerTaskFailed
            | MetricType::TaskManagerTaskRetry
            | MetricType::TaskManagerTaskStalled
            | MetricType::TaskManagerTaskExpired
            | MetricType::TaskManagerBlobNotFound
            | MetricType::TaskManagerMetadataNotFound
            | MetricType::TelemetryLogError
            | MetricType::TelemetryWebhookError
            | MetricType::TelemetryOtelExporterError
            | MetricType::TelemetryOtelMetricsExporterError
            | MetricType::TelemetryPrometheusExporterError
            | MetricType::TelemetryJournalError
            | MetricType::TelemetryEventsDropped
            | MetricType::TlsHandshakeError => "count",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiApiError
            | MetricType::AiRequest
            | MetricType::AiSpamVerdict
            | MetricType::AiSpamSkipped
            | MetricType::AiBreakerOpen
            | MetricType::LimitTenantQuota
            | MetricType::TelemetryAlertEvent
            | MetricType::TelemetryAlertMessage => "count",
            // SPDX-SnippetEnd
            MetricType::SearchIndexPendingEmail
            | MetricType::SearchIndexPendingCalendar
            | MetricType::SearchIndexPendingContacts
            | MetricType::SearchIndexPendingFile => "documents",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => "documents",
            // SPDX-SnippetEnd
            MetricType::DomainCount => "domains",
            MetricType::QueueCount => "messages",
            MetricType::DeliveryTotalTime
            | MetricType::DeliveryAttemptTime
            | MetricType::DnsLookupTime
            | MetricType::HttpRequestTime
            | MetricType::ImapRequestTime
            | MetricType::MessageIngestTime
            | MetricType::Pop3RequestTime
            | MetricType::SearchIndexIndexTime
            | MetricType::SieveRequestTime
            | MetricType::SmtpRequestTime
            | MetricType::StoreDataReadTime
            | MetricType::StoreDataWriteTime
            | MetricType::StoreBlobReadTime
            | MetricType::StoreBlobWriteTime => "milliseconds",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => "milliseconds",
            // SPDX-SnippetEnd
            MetricType::CacheSwapPending => "snapshots",
            MetricType::TaskManagerPending | MetricType::TaskManagerDue => "tasks",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens | MetricType::AiOutputTokens => "tokens",
            // SPDX-SnippetEnd
            MetricType::UserCount => "users",
        }
    }

    pub fn otel_name(&self) -> &'static str {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => "stalwart.ai.request_time",
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => "stalwart.ai.input_tokens",
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => "stalwart.ai.output_tokens",
            // SPDX-SnippetEnd
            MetricType::CacheMessagesSize => "stalwart.cache.messages_size",
            MetricType::CacheMessagesLargeSize => "stalwart.cache.messages_large_size",
            MetricType::CacheSize => "stalwart.cache.size",
            MetricType::CacheSwapPending => "stalwart.cache.swap_pending",
            MetricType::DeliveryTotalTime => "stalwart.delivery.total_time",
            MetricType::DeliveryAttemptTime => "stalwart.delivery.attempt_time",
            MetricType::DeliveryActiveConnections => "stalwart.delivery.active_connections",
            MetricType::DnsLookupTime => "stalwart.dns.lookup_time",
            MetricType::DomainCount => "stalwart.domains",
            MetricType::HttpRequestTime => "stalwart.http.request_time",
            MetricType::HttpActiveConnections => "stalwart.http.active_connections",
            MetricType::ImapRequestTime => "stalwart.imap.request_time",
            MetricType::ImapActiveConnections => "stalwart.imap.active_connections",
            MetricType::MessageSize => "stalwart.message.size",
            MetricType::MessageAuthenticatedSize => "stalwart.message.authenticated_size",
            MetricType::MessageIngestTime => "stalwart.message_ingest.time",
            MetricType::OutgoingReportSize => "stalwart.outgoing_report.size",
            MetricType::Pop3RequestTime => "stalwart.pop3.request_time",
            MetricType::Pop3ActiveConnections => "stalwart.pop3.active_connections",
            MetricType::QueueCount => "stalwart.queue.messages",
            MetricType::SearchIndexIndexTime => "stalwart.search_index.index_time",
            MetricType::SearchIndexPendingEmail => "stalwart.search_index.pending_email",
            MetricType::SearchIndexPendingCalendar => "stalwart.search_index.pending_calendar",
            MetricType::SearchIndexPendingContacts => "stalwart.search_index.pending_contacts",
            MetricType::SearchIndexPendingFile => "stalwart.search_index.pending_file",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => "stalwart.search_index.pending_tracing",
            // SPDX-SnippetEnd
            MetricType::ServerMemory => "stalwart.server.memory",
            MetricType::ServerBufferedMemorySmtp => "stalwart.server.buffered_memory_smtp",
            MetricType::ServerBufferedMemoryRead => "stalwart.server.buffered_memory_read",
            MetricType::SieveRequestTime => "stalwart.sieve.request_time",
            MetricType::SieveActiveConnections => "stalwart.sieve.active_connections",
            MetricType::SmtpRequestTime => "stalwart.smtp.request_time",
            MetricType::SmtpActiveConnections => "stalwart.smtp.active_connections",
            MetricType::StoreDataReadTime => "stalwart.store.data_read_time",
            MetricType::StoreDataWriteTime => "stalwart.store.data_write_time",
            MetricType::StoreBlobReadTime => "stalwart.store.blob_read_time",
            MetricType::StoreBlobWriteTime => "stalwart.store.blob_write_time",
            MetricType::TaskManagerPending => "stalwart.task_manager.pending",
            MetricType::TaskManagerDue => "stalwart.task_manager.due",
            MetricType::UserCount => "stalwart.users",
            _ => "",
        }
    }

    pub fn otel_unit(&self) -> &'static str {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => "s",
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => "{token}",
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => "{token}",
            // SPDX-SnippetEnd
            MetricType::CacheMessagesSize => "By",
            MetricType::CacheMessagesLargeSize => "By",
            MetricType::CacheSize => "By",
            MetricType::CacheSwapPending => "{snapshot}",
            MetricType::DeliveryTotalTime => "s",
            MetricType::DeliveryAttemptTime => "s",
            MetricType::DeliveryActiveConnections => "{connection}",
            MetricType::DnsLookupTime => "s",
            MetricType::DomainCount => "{domain}",
            MetricType::HttpRequestTime => "s",
            MetricType::HttpActiveConnections => "{connection}",
            MetricType::ImapRequestTime => "s",
            MetricType::ImapActiveConnections => "{connection}",
            MetricType::MessageSize => "By",
            MetricType::MessageAuthenticatedSize => "By",
            MetricType::MessageIngestTime => "s",
            MetricType::OutgoingReportSize => "By",
            MetricType::Pop3RequestTime => "s",
            MetricType::Pop3ActiveConnections => "{connection}",
            MetricType::QueueCount => "{message}",
            MetricType::SearchIndexIndexTime => "s",
            MetricType::SearchIndexPendingEmail => "{document}",
            MetricType::SearchIndexPendingCalendar => "{document}",
            MetricType::SearchIndexPendingContacts => "{document}",
            MetricType::SearchIndexPendingFile => "{document}",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => "{document}",
            // SPDX-SnippetEnd
            MetricType::ServerMemory => "By",
            MetricType::ServerBufferedMemorySmtp => "By",
            MetricType::ServerBufferedMemoryRead => "By",
            MetricType::SieveRequestTime => "s",
            MetricType::SieveActiveConnections => "{connection}",
            MetricType::SmtpRequestTime => "s",
            MetricType::SmtpActiveConnections => "{connection}",
            MetricType::StoreDataReadTime => "s",
            MetricType::StoreDataWriteTime => "s",
            MetricType::StoreBlobReadTime => "s",
            MetricType::StoreBlobWriteTime => "s",
            MetricType::TaskManagerPending => "{task}",
            MetricType::TaskManagerDue => "{task}",
            MetricType::UserCount => "{user}",
            _ => "",
        }
    }

    pub fn prom_name(&self) -> &'static str {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => "stalwart_ai_request_time_seconds",
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => "stalwart_ai_input_tokens",
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => "stalwart_ai_output_tokens",
            // SPDX-SnippetEnd
            MetricType::CacheMessagesSize => "stalwart_cache_messages_size_bytes",
            MetricType::CacheMessagesLargeSize => "stalwart_cache_messages_large_size_bytes",
            MetricType::CacheSize => "stalwart_cache_size_bytes",
            MetricType::CacheSwapPending => "stalwart_cache_swap_pending",
            MetricType::DeliveryTotalTime => "stalwart_delivery_total_time_seconds",
            MetricType::DeliveryAttemptTime => "stalwart_delivery_attempt_time_seconds",
            MetricType::DeliveryActiveConnections => "stalwart_delivery_active_connections",
            MetricType::DnsLookupTime => "stalwart_dns_lookup_time_seconds",
            MetricType::DomainCount => "stalwart_domains",
            MetricType::HttpRequestTime => "stalwart_http_request_time_seconds",
            MetricType::HttpActiveConnections => "stalwart_http_active_connections",
            MetricType::ImapRequestTime => "stalwart_imap_request_time_seconds",
            MetricType::ImapActiveConnections => "stalwart_imap_active_connections",
            MetricType::MessageSize => "stalwart_message_size_bytes",
            MetricType::MessageAuthenticatedSize => "stalwart_message_authenticated_size_bytes",
            MetricType::MessageIngestTime => "stalwart_message_ingest_time_seconds",
            MetricType::OutgoingReportSize => "stalwart_outgoing_report_size_bytes",
            MetricType::Pop3RequestTime => "stalwart_pop3_request_time_seconds",
            MetricType::Pop3ActiveConnections => "stalwart_pop3_active_connections",
            MetricType::QueueCount => "stalwart_queue_messages",
            MetricType::SearchIndexIndexTime => "stalwart_search_index_index_time_seconds",
            MetricType::SearchIndexPendingEmail => "stalwart_search_index_pending_email",
            MetricType::SearchIndexPendingCalendar => "stalwart_search_index_pending_calendar",
            MetricType::SearchIndexPendingContacts => "stalwart_search_index_pending_contacts",
            MetricType::SearchIndexPendingFile => "stalwart_search_index_pending_file",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => "stalwart_search_index_pending_tracing",
            // SPDX-SnippetEnd
            MetricType::ServerMemory => "stalwart_server_memory_bytes",
            MetricType::ServerBufferedMemorySmtp => "stalwart_server_buffered_memory_smtp_bytes",
            MetricType::ServerBufferedMemoryRead => "stalwart_server_buffered_memory_read_bytes",
            MetricType::SieveRequestTime => "stalwart_sieve_request_time_seconds",
            MetricType::SieveActiveConnections => "stalwart_sieve_active_connections",
            MetricType::SmtpRequestTime => "stalwart_smtp_request_time_seconds",
            MetricType::SmtpActiveConnections => "stalwart_smtp_active_connections",
            MetricType::StoreDataReadTime => "stalwart_store_data_read_time_seconds",
            MetricType::StoreDataWriteTime => "stalwart_store_data_write_time_seconds",
            MetricType::StoreBlobReadTime => "stalwart_store_blob_read_time_seconds",
            MetricType::StoreBlobWriteTime => "stalwart_store_blob_write_time_seconds",
            MetricType::TaskManagerPending => "stalwart_task_manager_pending",
            MetricType::TaskManagerDue => "stalwart_task_manager_due",
            MetricType::UserCount => "stalwart_users",
            _ => "",
        }
    }

    pub fn prom_unit(&self) -> &'static str {
        match self {
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime => "seconds",
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens => "",
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens => "",
            // SPDX-SnippetEnd
            MetricType::CacheMessagesSize => "bytes",
            MetricType::CacheMessagesLargeSize => "bytes",
            MetricType::CacheSize => "bytes",
            MetricType::CacheSwapPending => "",
            MetricType::DeliveryTotalTime => "seconds",
            MetricType::DeliveryAttemptTime => "seconds",
            MetricType::DeliveryActiveConnections => "",
            MetricType::DnsLookupTime => "seconds",
            MetricType::DomainCount => "",
            MetricType::HttpRequestTime => "seconds",
            MetricType::HttpActiveConnections => "",
            MetricType::ImapRequestTime => "seconds",
            MetricType::ImapActiveConnections => "",
            MetricType::MessageSize => "bytes",
            MetricType::MessageAuthenticatedSize => "bytes",
            MetricType::MessageIngestTime => "seconds",
            MetricType::OutgoingReportSize => "bytes",
            MetricType::Pop3RequestTime => "seconds",
            MetricType::Pop3ActiveConnections => "",
            MetricType::QueueCount => "",
            MetricType::SearchIndexIndexTime => "seconds",
            MetricType::SearchIndexPendingEmail => "",
            MetricType::SearchIndexPendingCalendar => "",
            MetricType::SearchIndexPendingContacts => "",
            MetricType::SearchIndexPendingFile => "",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing => "",
            // SPDX-SnippetEnd
            MetricType::ServerMemory => "bytes",
            MetricType::ServerBufferedMemorySmtp => "bytes",
            MetricType::ServerBufferedMemoryRead => "bytes",
            MetricType::SieveRequestTime => "seconds",
            MetricType::SieveActiveConnections => "",
            MetricType::SmtpRequestTime => "seconds",
            MetricType::SmtpActiveConnections => "",
            MetricType::StoreDataReadTime => "seconds",
            MetricType::StoreDataWriteTime => "seconds",
            MetricType::StoreBlobReadTime => "seconds",
            MetricType::StoreBlobWriteTime => "seconds",
            MetricType::TaskManagerPending => "",
            MetricType::TaskManagerDue => "",
            MetricType::UserCount => "",
            _ => "",
        }
    }

    pub const fn variants() -> &'static [Self] {
        &[
            MetricType::AcmeAuthError,
            MetricType::AcmeAuthTooManyAttempts,
            MetricType::AcmeOrderCompleted,
            MetricType::AcmeOrderInvalid,
            MetricType::AcmeClientMissingSni,
            MetricType::AcmeTlsAlpnError,
            MetricType::AcmeTokenNotFound,
            MetricType::AcmeError,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::AiRequestTime,
            #[cfg(feature = "enterprise")]
            MetricType::AiInputTokens,
            #[cfg(feature = "enterprise")]
            MetricType::AiOutputTokens,
            #[cfg(feature = "enterprise")]
            MetricType::AiApiError,
            #[cfg(feature = "enterprise")]
            MetricType::AiRequest,
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamVerdict,
            #[cfg(feature = "enterprise")]
            MetricType::AiSpamSkipped,
            #[cfg(feature = "enterprise")]
            MetricType::AiBreakerOpen,
            // SPDX-SnippetEnd
            MetricType::ArcChainInvalid,
            MetricType::ArcSignatureInvalid,
            MetricType::ArcHashMismatch,
            MetricType::AuthSuccess,
            MetricType::AuthFailed,
            MetricType::AuthTooManyAttempts,
            MetricType::AuthError,
            MetricType::CacheMessagesSize,
            MetricType::CacheMessagesLargeSize,
            MetricType::CacheSize,
            MetricType::CacheSwapPending,
            MetricType::CacheMiss,
            MetricType::CacheHit,
            MetricType::CacheStale,
            MetricType::CacheEntryTooLarge,
            MetricType::CacheSwapHit,
            MetricType::CacheSwapMiss,
            MetricType::CacheSwapWrite,
            MetricType::CacheSwapError,
            MetricType::CalendarAlarmSent,
            MetricType::CalendarAlarmFailed,
            MetricType::CalendarItipMessageSent,
            MetricType::CalendarItipMessageReceived,
            MetricType::CalendarItipMessageError,
            MetricType::ClusterSubscriberError,
            MetricType::ClusterSubscriberDisconnected,
            MetricType::ClusterPublisherError,
            MetricType::DaneAuthenticationSuccess,
            MetricType::DaneAuthenticationFailure,
            MetricType::DaneNoCertificatesFound,
            MetricType::DaneCertificateParseError,
            MetricType::DaneTlsaRecordFetchError,
            MetricType::DaneTlsaRecordNotFound,
            MetricType::DaneTlsaRecordNotDnssecSigned,
            MetricType::DaneTlsaRecordInvalid,
            MetricType::DaneBogusDnssecRecord,
            MetricType::DeliveryTotalTime,
            MetricType::DeliveryAttemptTime,
            MetricType::DeliveryActiveConnections,
            MetricType::DeliveryAttemptStart,
            MetricType::DeliveryAttemptEnd,
            MetricType::DeliveryCompleted,
            MetricType::DeliveryMxLookupFailed,
            MetricType::DeliveryIpLookupFailed,
            MetricType::DeliveryNullMx,
            MetricType::DeliveryGreetingFailed,
            MetricType::DeliveryEhloRejected,
            MetricType::DeliveryAuthFailed,
            MetricType::DeliveryMailFromRejected,
            MetricType::DeliveryDelivered,
            MetricType::DeliveryRcptToRejected,
            MetricType::DeliveryRcptToFailed,
            MetricType::DeliveryMessageRejected,
            MetricType::DeliveryStartTlsUnavailable,
            MetricType::DeliveryStartTlsError,
            MetricType::DeliveryStartTlsDisabled,
            MetricType::DeliveryImplicitTlsError,
            MetricType::DeliveryConcurrencyLimitExceeded,
            MetricType::DeliveryRateLimitExceeded,
            MetricType::DeliveryDoubleBounce,
            MetricType::DeliveryDsnSuccess,
            MetricType::DeliveryDsnTempFail,
            MetricType::DeliveryDsnPermFail,
            MetricType::DkimPass,
            MetricType::DkimNeutral,
            MetricType::DkimFail,
            MetricType::DkimPermError,
            MetricType::DkimTempError,
            MetricType::DkimNone,
            MetricType::DkimSignatureInvalid,
            MetricType::DkimPublicKeyError,
            MetricType::DkimVerificationFailed,
            MetricType::DkimHashMismatch,
            MetricType::DkimSignerNotFound,
            MetricType::Dkim2InstanceInvalid,
            MetricType::Dkim2SignatureInvalid,
            MetricType::Dkim2ChainInvalid,
            MetricType::Dkim2TimestampInvalid,
            MetricType::Dkim2EnvelopeMismatch,
            MetricType::Dkim2CustodyBroken,
            MetricType::Dkim2PublicKeyError,
            MetricType::Dkim2VerificationFailed,
            MetricType::Dkim2HashMismatch,
            MetricType::Dkim2RecipeError,
            MetricType::Dkim2SigningFailed,
            MetricType::DmarcPass,
            MetricType::DmarcFail,
            MetricType::DmarcPermError,
            MetricType::DmarcTempError,
            MetricType::DmarcNone,
            MetricType::DnsLookupTime,
            MetricType::DnsRecordCreationFailed,
            MetricType::DnsRecordDeletionFailed,
            MetricType::DnsRecordLookupFailed,
            MetricType::DnsRecordPropagationTimeout,
            MetricType::DomainCount,
            MetricType::EvalError,
            MetricType::EvalDirectoryNotFound,
            MetricType::EvalStoreNotFound,
            MetricType::HttpRequestTime,
            MetricType::HttpActiveConnections,
            MetricType::HttpConnectionStart,
            MetricType::HttpError,
            MetricType::HttpRequestBody,
            MetricType::HttpResponseBody,
            MetricType::HttpXForwardedMissing,
            MetricType::HttpXForwardedInvalid,
            MetricType::ImapRequestTime,
            MetricType::ImapActiveConnections,
            MetricType::ImapConnectionStart,
            MetricType::ImapConnectionEnd,
            MetricType::IncomingReportDmarcReport,
            MetricType::IncomingReportDmarcReportWithWarnings,
            MetricType::IncomingReportTlsReport,
            MetricType::IncomingReportTlsReportWithWarnings,
            MetricType::IncomingReportAbuseReport,
            MetricType::IncomingReportAuthFailureReport,
            MetricType::IncomingReportFraudReport,
            MetricType::IncomingReportNotSpamReport,
            MetricType::IncomingReportVirusReport,
            MetricType::IncomingReportOtherReport,
            MetricType::IncomingReportMessageParseFailed,
            MetricType::IncomingReportDmarcParseFailed,
            MetricType::IncomingReportTlsRpcParseFailed,
            MetricType::IncomingReportArfParseFailed,
            MetricType::IncomingReportDecompressError,
            MetricType::IprevPass,
            MetricType::IprevFail,
            MetricType::IprevPermError,
            MetricType::IprevTempError,
            MetricType::IprevNone,
            MetricType::JmapMethodCall,
            MetricType::JmapInvalidArguments,
            MetricType::JmapRequestTooLarge,
            MetricType::JmapUnsupportedFilter,
            MetricType::JmapUnsupportedSort,
            MetricType::JmapUnknownMethod,
            MetricType::JmapForbidden,
            MetricType::JmapNotJson,
            MetricType::JmapNotRequest,
            MetricType::JmapWebsocketStart,
            MetricType::JmapWebsocketError,
            MetricType::LimitSizeRequest,
            MetricType::LimitSizeUpload,
            MetricType::LimitCallsIn,
            MetricType::LimitConcurrentRequest,
            MetricType::LimitConcurrentUpload,
            MetricType::LimitConcurrentConnection,
            MetricType::LimitQuota,
            MetricType::LimitBlobQuota,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::LimitTenantQuota,
            // SPDX-SnippetEnd
            MetricType::LimitTooManyRequests,
            MetricType::LimitMemoryBudget,
            MetricType::MailAuthParseError,
            MetricType::MailAuthMissingParameters,
            MetricType::MailAuthNoHeadersFound,
            MetricType::MailAuthCrypto,
            MetricType::MailAuthIo,
            MetricType::MailAuthBase64,
            MetricType::MailAuthDnsError,
            MetricType::MailAuthDnsRecordNotFound,
            MetricType::MailAuthDnsInvalidRecordType,
            MetricType::MailAuthPolicyNotAligned,
            MetricType::ManageSieveConnectionStart,
            MetricType::ManageSieveConnectionEnd,
            MetricType::MessageSize,
            MetricType::MessageAuthenticatedSize,
            MetricType::MessageIngestTime,
            MetricType::MessageIngestHam,
            MetricType::MessageIngestSpam,
            MetricType::MessageIngestImapAppend,
            MetricType::MessageIngestJmapAppend,
            MetricType::MessageIngestDuplicate,
            MetricType::MessageIngestError,
            MetricType::MilterActionAccept,
            MetricType::MilterActionDiscard,
            MetricType::MilterActionReject,
            MetricType::MilterActionTempFail,
            MetricType::MilterActionReplyCode,
            MetricType::MilterActionConnectionFailure,
            MetricType::MilterActionShutdown,
            MetricType::MtaHookActionAccept,
            MetricType::MtaHookActionDiscard,
            MetricType::MtaHookActionReject,
            MetricType::MtaHookActionQuarantine,
            MetricType::MtaHookError,
            MetricType::MtaStsAuthorized,
            MetricType::MtaStsNotAuthorized,
            MetricType::MtaStsInvalidPolicy,
            MetricType::NetworkTimeout,
            MetricType::OutgoingReportSize,
            MetricType::OutgoingReportSpfReport,
            MetricType::OutgoingReportSpfRateLimited,
            MetricType::OutgoingReportDkimReport,
            MetricType::OutgoingReportDkimRateLimited,
            MetricType::OutgoingReportDmarcReport,
            MetricType::OutgoingReportDmarcRateLimited,
            MetricType::OutgoingReportDmarcAggregateReport,
            MetricType::OutgoingReportTlsAggregate,
            MetricType::OutgoingReportHttpSubmission,
            MetricType::OutgoingReportUnauthorizedReportingAddress,
            MetricType::OutgoingReportReportingAddressValidationError,
            MetricType::OutgoingReportNotFound,
            MetricType::OutgoingReportSubmissionError,
            MetricType::OutgoingReportNoRecipientsFound,
            MetricType::Pop3RequestTime,
            MetricType::Pop3ActiveConnections,
            MetricType::Pop3ConnectionStart,
            MetricType::Pop3ConnectionEnd,
            MetricType::PushSubscriptionSuccess,
            MetricType::PushSubscriptionError,
            MetricType::PushSubscriptionNotFound,
            MetricType::QueueCount,
            MetricType::QueueMessageQueued,
            MetricType::QueueAuthenticatedMessageQueued,
            MetricType::QueueReportQueued,
            MetricType::QueueDsnQueued,
            MetricType::QueueAutogeneratedQueued,
            MetricType::QueueRescheduled,
            MetricType::QueueBlobNotFound,
            MetricType::QueueRateLimitExceeded,
            MetricType::QueueConcurrencyLimitExceeded,
            MetricType::QueueQuotaExceeded,
            MetricType::QueueBackPressure,
            MetricType::ResourceNotFound,
            MetricType::ResourceBadParameters,
            MetricType::ResourceError,
            MetricType::SearchIndexIndexTime,
            MetricType::SearchIndexPendingEmail,
            MetricType::SearchIndexPendingCalendar,
            MetricType::SearchIndexPendingContacts,
            MetricType::SearchIndexPendingFile,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::SearchIndexPendingTracing,
            // SPDX-SnippetEnd
            MetricType::SearchIndexPartitionRetry,
            MetricType::SearchIndexBatchIndexed,
            MetricType::SearchIndexDocumentTruncated,
            MetricType::SecurityAuthenticationBan,
            MetricType::SecurityAbuseBan,
            MetricType::SecurityScanBan,
            MetricType::SecurityLoiterBan,
            MetricType::SecurityIpBlocked,
            MetricType::SecurityUnauthorized,
            MetricType::ServerMemory,
            MetricType::ServerBufferedMemorySmtp,
            MetricType::ServerBufferedMemoryRead,
            MetricType::ServerThreadError,
            MetricType::SieveRequestTime,
            MetricType::SieveActiveConnections,
            MetricType::SieveActionAccept,
            MetricType::SieveActionAcceptReplace,
            MetricType::SieveActionDiscard,
            MetricType::SieveActionReject,
            MetricType::SieveSendMessage,
            MetricType::SieveMessageTooLarge,
            MetricType::SieveRuntimeError,
            MetricType::SieveUnexpectedError,
            MetricType::SieveNotSupported,
            MetricType::SieveQuotaExceeded,
            MetricType::SmtpRequestTime,
            MetricType::SmtpActiveConnections,
            MetricType::SmtpConnectionStart,
            MetricType::SmtpConnectionEnd,
            MetricType::SmtpError,
            MetricType::SmtpConcurrencyLimitExceeded,
            MetricType::SmtpTransferLimitExceeded,
            MetricType::SmtpRateLimitExceeded,
            MetricType::SmtpTimeLimitExceeded,
            MetricType::SmtpMessageParseFailed,
            MetricType::SmtpMessageTooLarge,
            MetricType::SmtpLoopDetected,
            MetricType::SmtpMultipleFromDomains,
            MetricType::SmtpDkimPass,
            MetricType::SmtpDkimFail,
            MetricType::SmtpDkim2Pass,
            MetricType::SmtpDkim2Fail,
            MetricType::SmtpDkim2DsnRejected,
            MetricType::SmtpArcPass,
            MetricType::SmtpArcFail,
            MetricType::SmtpSpfEhloPass,
            MetricType::SmtpSpfEhloFail,
            MetricType::SmtpSpfFromPass,
            MetricType::SmtpSpfFromFail,
            MetricType::SmtpDmarcPass,
            MetricType::SmtpDmarcFail,
            MetricType::SmtpIprevPass,
            MetricType::SmtpIprevFail,
            MetricType::SmtpTooManyMessages,
            MetricType::SmtpInvalidEhlo,
            MetricType::SmtpDidNotSayEhlo,
            MetricType::SmtpMailFromUnauthenticated,
            MetricType::SmtpMailFromUnauthorized,
            MetricType::SmtpMailFromMissing,
            MetricType::SmtpMultipleMailFrom,
            MetricType::SmtpMailboxDoesNotExist,
            MetricType::SmtpRelayNotAllowed,
            MetricType::SmtpRcptToDuplicate,
            MetricType::SmtpRcptToMissing,
            MetricType::SmtpTooManyRecipients,
            MetricType::SmtpTooManyInvalidRcpt,
            MetricType::SmtpAuthMechanismNotSupported,
            MetricType::SmtpAuthExchangeTooLong,
            MetricType::SmtpCommandNotImplemented,
            MetricType::SmtpInvalidCommand,
            MetricType::SmtpSyntaxError,
            MetricType::SmtpRequestTooLarge,
            MetricType::SpamPyzorError,
            MetricType::SpamDnsblError,
            MetricType::SpamTrainCompleted,
            MetricType::SpamTrainSampleAdded,
            MetricType::SpamClassify,
            MetricType::SpamModelNotReady,
            MetricType::SpfPass,
            MetricType::SpfFail,
            MetricType::SpfSoftFail,
            MetricType::SpfNeutral,
            MetricType::SpfTempError,
            MetricType::SpfPermError,
            MetricType::SpfNone,
            MetricType::StoreDataReadTime,
            MetricType::StoreDataWriteTime,
            MetricType::StoreBlobReadTime,
            MetricType::StoreBlobWriteTime,
            MetricType::StoreAssertValueFailed,
            MetricType::StoreFoundationdbError,
            MetricType::StoreMysqlError,
            MetricType::StorePostgresqlError,
            MetricType::StoreRocksdbError,
            MetricType::StoreSqliteError,
            MetricType::StoreLdapError,
            MetricType::StoreElasticsearchError,
            MetricType::StoreRedisError,
            MetricType::StoreS3Error,
            MetricType::StoreAzureError,
            MetricType::StoreFilesystemError,
            MetricType::StorePoolError,
            MetricType::StoreDataCorruption,
            MetricType::StoreDecompressError,
            MetricType::StoreDeserializeError,
            MetricType::StoreNotFound,
            MetricType::StoreNotConfigured,
            MetricType::StoreNotSupported,
            MetricType::StoreUnexpectedError,
            MetricType::StoreCryptoError,
            MetricType::StoreHttpStoreError,
            MetricType::StoreBlobMissingMarker,
            MetricType::StoreDataWrite,
            MetricType::StoreDataIterate,
            MetricType::StoreBlobRead,
            MetricType::StoreBlobWrite,
            MetricType::StoreBlobDelete,
            MetricType::TaskManagerPending,
            MetricType::TaskManagerDue,
            MetricType::TaskManagerTaskFailed,
            MetricType::TaskManagerTaskRetry,
            MetricType::TaskManagerTaskStalled,
            MetricType::TaskManagerTaskExpired,
            MetricType::TaskManagerBlobNotFound,
            MetricType::TaskManagerMetadataNotFound,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertEvent,
            #[cfg(feature = "enterprise")]
            MetricType::TelemetryAlertMessage,
            // SPDX-SnippetEnd
            MetricType::TelemetryLogError,
            MetricType::TelemetryWebhookError,
            MetricType::TelemetryOtelExporterError,
            MetricType::TelemetryOtelMetricsExporterError,
            MetricType::TelemetryPrometheusExporterError,
            MetricType::TelemetryJournalError,
            MetricType::TelemetryEventsDropped,
            MetricType::TlsHandshakeError,
            MetricType::UserCount,
        ]
    }
}

impl Key {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            Key,
            b"accountName" => Key::AccountName,
            b"accountId" => Key::AccountId,
            b"blobId" => Key::BlobId,
            b"causedBy" => Key::CausedBy,
            b"changeId" => Key::ChangeId,
            b"code" => Key::Code,
            b"collection" => Key::Collection,
            b"contents" => Key::Contents,
            b"details" => Key::Details,
            b"dkimFail" => Key::DkimFail,
            b"dkimNone" => Key::DkimNone,
            b"dkimPass" => Key::DkimPass,
            b"dmarcNone" => Key::DmarcNone,
            b"dmarcPass" => Key::DmarcPass,
            b"dmarcQuarantine" => Key::DmarcQuarantine,
            b"dmarcReject" => Key::DmarcReject,
            b"documentId" => Key::DocumentId,
            b"domain" => Key::Domain,
            b"due" => Key::Due,
            b"elapsed" => Key::Elapsed,
            b"expires" => Key::Expires,
            b"from" => Key::From,
            b"hostname" => Key::Hostname,
            b"id" => Key::Id,
            b"key" => Key::Key,
            b"limit" => Key::Limit,
            b"listenerId" => Key::ListenerId,
            b"localIp" => Key::LocalIp,
            b"localPort" => Key::LocalPort,
            b"mailboxName" => Key::MailboxName,
            b"mailboxId" => Key::MailboxId,
            b"messageId" => Key::MessageId,
            b"nextDsn" => Key::NextDsn,
            b"nextRetry" => Key::NextRetry,
            b"path" => Key::Path,
            b"policy" => Key::Policy,
            b"queueId" => Key::QueueId,
            b"rangeFrom" => Key::RangeFrom,
            b"rangeTo" => Key::RangeTo,
            b"reason" => Key::Reason,
            b"remoteIp" => Key::RemoteIp,
            b"remotePort" => Key::RemotePort,
            b"reportId" => Key::ReportId,
            b"result" => Key::Result,
            b"size" => Key::Size,
            b"source" => Key::Source,
            b"spanId" => Key::SpanId,
            b"spfFail" => Key::SpfFail,
            b"spfNone" => Key::SpfNone,
            b"spfPass" => Key::SpfPass,
            b"strict" => Key::Strict,
            b"tls" => Key::Tls,
            b"to" => Key::To,
            b"total" => Key::Total,
            b"totalFailures" => Key::TotalFailures,
            b"totalSuccesses" => Key::TotalSuccesses,
            b"type" => Key::Type,
            b"uid" => Key::Uid,
            b"uidNext" => Key::UidNext,
            b"uidValidity" => Key::UidValidity,
            b"url" => Key::Url,
            b"validFrom" => Key::ValidFrom,
            b"validTo" => Key::ValidTo,
            b"value" => Key::Value,
            b"version" => Key::Version,
            b"queueName" => Key::QueueName,
            b"name" => Key::Name,
            b"objectType" => Key::ObjectType,
            b"property" => Key::Property,
            b"nodeId" => Key::NodeId,
            b"remoteNodeId" => Key::RemoteNodeId,
            b"taskId" => Key::TaskId,
            b"partition" => Key::Partition,
            b"index" => Key::Index,
            b"attempt" => Key::Attempt,
            b"used" => Key::Used,
            b"period" => Key::Period,
            b"retryAfter" => Key::RetryAfter,
            b"command" => Key::Command,
            b"tag" => Key::Tag,
            b"address" => Key::Address,
            b"ip" => Key::Ip,
            b"headers" => Key::Headers,
            b"query" => Key::Query,
            b"cipher" => Key::Cipher,
            b"resourceUid" => Key::ResourceUid,
            b"script" => Key::Script,
            b"model" => Key::Model,
            b"inputTokens" => Key::InputTokens,
            b"outputTokens" => Key::OutputTokens,
            b"cachedTokens" => Key::CachedTokens,
            b"finishReason" => Key::FinishReason,
            b"category" => Key::Category,
            b"probability" => Key::Probability,
            b"confidence" => Key::Confidence,
            b"tier" => Key::Tier,
        }
        .copied()
    }

    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    pub fn parse(value: &str) -> Option<Self> {
        hashify::map! {
            value.as_bytes(),
            Key,
            b"accountName" => Key::AccountName,
            b"accountId" => Key::AccountId,
            b"blobId" => Key::BlobId,
            b"causedBy" => Key::CausedBy,
            b"changeId" => Key::ChangeId,
            b"code" => Key::Code,
            b"collection" => Key::Collection,
            b"contents" => Key::Contents,
            b"details" => Key::Details,
            b"dkimFail" => Key::DkimFail,
            b"dkimNone" => Key::DkimNone,
            b"dkimPass" => Key::DkimPass,
            b"dmarcNone" => Key::DmarcNone,
            b"dmarcPass" => Key::DmarcPass,
            b"dmarcQuarantine" => Key::DmarcQuarantine,
            b"dmarcReject" => Key::DmarcReject,
            b"documentId" => Key::DocumentId,
            b"domain" => Key::Domain,
            b"due" => Key::Due,
            b"elapsed" => Key::Elapsed,
            b"expires" => Key::Expires,
            b"from" => Key::From,
            b"hostname" => Key::Hostname,
            b"id" => Key::Id,
            b"key" => Key::Key,
            b"limit" => Key::Limit,
            b"listenerId" => Key::ListenerId,
            b"localIp" => Key::LocalIp,
            b"localPort" => Key::LocalPort,
            b"mailboxName" => Key::MailboxName,
            b"mailboxId" => Key::MailboxId,
            b"messageId" => Key::MessageId,
            b"nextDsn" => Key::NextDsn,
            b"nextRetry" => Key::NextRetry,
            b"path" => Key::Path,
            b"policy" => Key::Policy,
            b"queueId" => Key::QueueId,
            b"rangeFrom" => Key::RangeFrom,
            b"rangeTo" => Key::RangeTo,
            b"reason" => Key::Reason,
            b"remoteIp" => Key::RemoteIp,
            b"remotePort" => Key::RemotePort,
            b"reportId" => Key::ReportId,
            b"result" => Key::Result,
            b"size" => Key::Size,
            b"source" => Key::Source,
            b"spanId" => Key::SpanId,
            b"spfFail" => Key::SpfFail,
            b"spfNone" => Key::SpfNone,
            b"spfPass" => Key::SpfPass,
            b"strict" => Key::Strict,
            b"tls" => Key::Tls,
            b"to" => Key::To,
            b"total" => Key::Total,
            b"totalFailures" => Key::TotalFailures,
            b"totalSuccesses" => Key::TotalSuccesses,
            b"type" => Key::Type,
            b"uid" => Key::Uid,
            b"uidNext" => Key::UidNext,
            b"uidValidity" => Key::UidValidity,
            b"url" => Key::Url,
            b"validFrom" => Key::ValidFrom,
            b"validTo" => Key::ValidTo,
            b"value" => Key::Value,
            b"version" => Key::Version,
            b"queueName" => Key::QueueName,
            b"name" => Key::Name,
            b"objectType" => Key::ObjectType,
            b"property" => Key::Property,
            b"nodeId" => Key::NodeId,
            b"remoteNodeId" => Key::RemoteNodeId,
            b"taskId" => Key::TaskId,
            b"partition" => Key::Partition,
            b"index" => Key::Index,
            b"attempt" => Key::Attempt,
            b"used" => Key::Used,
            b"period" => Key::Period,
            b"retryAfter" => Key::RetryAfter,
            b"command" => Key::Command,
            b"tag" => Key::Tag,
            b"address" => Key::Address,
            b"ip" => Key::Ip,
            b"headers" => Key::Headers,
            b"query" => Key::Query,
            b"cipher" => Key::Cipher,
            b"resourceUid" => Key::ResourceUid,
            b"script" => Key::Script,
        }
        .copied()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Key::AccountName => "accountName",
            Key::AccountId => "accountId",
            Key::BlobId => "blobId",
            Key::CausedBy => "causedBy",
            Key::ChangeId => "changeId",
            Key::Code => "code",
            Key::Collection => "collection",
            Key::Contents => "contents",
            Key::Details => "details",
            Key::DkimFail => "dkimFail",
            Key::DkimNone => "dkimNone",
            Key::DkimPass => "dkimPass",
            Key::DmarcNone => "dmarcNone",
            Key::DmarcPass => "dmarcPass",
            Key::DmarcQuarantine => "dmarcQuarantine",
            Key::DmarcReject => "dmarcReject",
            Key::DocumentId => "documentId",
            Key::Domain => "domain",
            Key::Due => "due",
            Key::Elapsed => "elapsed",
            Key::Expires => "expires",
            Key::From => "from",
            Key::Hostname => "hostname",
            Key::Id => "id",
            Key::Key => "key",
            Key::Limit => "limit",
            Key::ListenerId => "listenerId",
            Key::LocalIp => "localIp",
            Key::LocalPort => "localPort",
            Key::MailboxName => "mailboxName",
            Key::MailboxId => "mailboxId",
            Key::MessageId => "messageId",
            Key::NextDsn => "nextDsn",
            Key::NextRetry => "nextRetry",
            Key::Path => "path",
            Key::Policy => "policy",
            Key::QueueId => "queueId",
            Key::RangeFrom => "rangeFrom",
            Key::RangeTo => "rangeTo",
            Key::Reason => "reason",
            Key::RemoteIp => "remoteIp",
            Key::RemotePort => "remotePort",
            Key::ReportId => "reportId",
            Key::Result => "result",
            Key::Size => "size",
            Key::Source => "source",
            Key::SpanId => "spanId",
            Key::SpfFail => "spfFail",
            Key::SpfNone => "spfNone",
            Key::SpfPass => "spfPass",
            Key::Strict => "strict",
            Key::Tls => "tls",
            Key::To => "to",
            Key::Total => "total",
            Key::TotalFailures => "totalFailures",
            Key::TotalSuccesses => "totalSuccesses",
            Key::Type => "type",
            Key::Uid => "uid",
            Key::UidNext => "uidNext",
            Key::UidValidity => "uidValidity",
            Key::Url => "url",
            Key::ValidFrom => "validFrom",
            Key::ValidTo => "validTo",
            Key::Value => "value",
            Key::Version => "version",
            Key::QueueName => "queueName",
            Key::Name => "name",
            Key::ObjectType => "objectType",
            Key::Property => "property",
            Key::NodeId => "nodeId",
            Key::RemoteNodeId => "remoteNodeId",
            Key::TaskId => "taskId",
            Key::Partition => "partition",
            Key::Index => "index",
            Key::Attempt => "attempt",
            Key::Used => "used",
            Key::Period => "period",
            Key::RetryAfter => "retryAfter",
            Key::Command => "command",
            Key::Tag => "tag",
            Key::Address => "address",
            Key::Ip => "ip",
            Key::Headers => "headers",
            Key::Query => "query",
            Key::Cipher => "cipher",
            Key::ResourceUid => "resourceUid",
            Key::Script => "script",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Key::Model => "model",
            #[cfg(feature = "enterprise")]
            Key::InputTokens => "inputTokens",
            #[cfg(feature = "enterprise")]
            Key::OutputTokens => "outputTokens",
            #[cfg(feature = "enterprise")]
            Key::CachedTokens => "cachedTokens",
            #[cfg(feature = "enterprise")]
            Key::FinishReason => "finishReason",
            #[cfg(feature = "enterprise")]
            Key::Category => "category",
            #[cfg(feature = "enterprise")]
            Key::Probability => "probability",
            #[cfg(feature = "enterprise")]
            Key::Confidence => "confidence",
            #[cfg(feature = "enterprise")]
            Key::Tier => "tier",
            // SPDX-SnippetEnd
        }
    }

    pub fn to_id(&self) -> u16 {
        *self as u16
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(Key::AccountName),
            1 => Some(Key::AccountId),
            2 => Some(Key::BlobId),
            3 => Some(Key::CausedBy),
            4 => Some(Key::ChangeId),
            5 => Some(Key::Code),
            6 => Some(Key::Collection),
            7 => Some(Key::Contents),
            8 => Some(Key::Details),
            9 => Some(Key::DkimFail),
            10 => Some(Key::DkimNone),
            11 => Some(Key::DkimPass),
            12 => Some(Key::DmarcNone),
            13 => Some(Key::DmarcPass),
            14 => Some(Key::DmarcQuarantine),
            15 => Some(Key::DmarcReject),
            16 => Some(Key::DocumentId),
            17 => Some(Key::Domain),
            18 => Some(Key::Due),
            19 => Some(Key::Elapsed),
            20 => Some(Key::Expires),
            21 => Some(Key::From),
            22 => Some(Key::Hostname),
            23 => Some(Key::Id),
            24 => Some(Key::Key),
            25 => Some(Key::Limit),
            26 => Some(Key::ListenerId),
            27 => Some(Key::LocalIp),
            28 => Some(Key::LocalPort),
            29 => Some(Key::MailboxName),
            30 => Some(Key::MailboxId),
            31 => Some(Key::MessageId),
            32 => Some(Key::NextDsn),
            33 => Some(Key::NextRetry),
            34 => Some(Key::Path),
            35 => Some(Key::Policy),
            36 => Some(Key::QueueId),
            37 => Some(Key::RangeFrom),
            38 => Some(Key::RangeTo),
            39 => Some(Key::Reason),
            40 => Some(Key::RemoteIp),
            41 => Some(Key::RemotePort),
            42 => Some(Key::ReportId),
            43 => Some(Key::Result),
            44 => Some(Key::Size),
            45 => Some(Key::Source),
            46 => Some(Key::SpanId),
            47 => Some(Key::SpfFail),
            48 => Some(Key::SpfNone),
            49 => Some(Key::SpfPass),
            50 => Some(Key::Strict),
            51 => Some(Key::Tls),
            52 => Some(Key::To),
            53 => Some(Key::Total),
            54 => Some(Key::TotalFailures),
            55 => Some(Key::TotalSuccesses),
            56 => Some(Key::Type),
            57 => Some(Key::Uid),
            58 => Some(Key::UidNext),
            59 => Some(Key::UidValidity),
            60 => Some(Key::Url),
            61 => Some(Key::ValidFrom),
            62 => Some(Key::ValidTo),
            63 => Some(Key::Value),
            64 => Some(Key::Version),
            65 => Some(Key::QueueName),
            66 => Some(Key::Name),
            67 => Some(Key::ObjectType),
            68 => Some(Key::Property),
            69 => Some(Key::NodeId),
            70 => Some(Key::RemoteNodeId),
            71 => Some(Key::TaskId),
            72 => Some(Key::Partition),
            73 => Some(Key::Index),
            74 => Some(Key::Attempt),
            75 => Some(Key::Used),
            76 => Some(Key::Period),
            77 => Some(Key::RetryAfter),
            78 => Some(Key::Command),
            79 => Some(Key::Tag),
            80 => Some(Key::Address),
            81 => Some(Key::Ip),
            82 => Some(Key::Headers),
            83 => Some(Key::Query),
            84 => Some(Key::Cipher),
            85 => Some(Key::ResourceUid),
            86 => Some(Key::Script),
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            87 => Some(Key::Model),
            #[cfg(feature = "enterprise")]
            88 => Some(Key::InputTokens),
            #[cfg(feature = "enterprise")]
            89 => Some(Key::OutputTokens),
            #[cfg(feature = "enterprise")]
            90 => Some(Key::CachedTokens),
            #[cfg(feature = "enterprise")]
            91 => Some(Key::FinishReason),
            #[cfg(feature = "enterprise")]
            92 => Some(Key::Category),
            #[cfg(feature = "enterprise")]
            93 => Some(Key::Probability),
            #[cfg(feature = "enterprise")]
            94 => Some(Key::Confidence),
            #[cfg(feature = "enterprise")]
            95 => Some(Key::Tier),
            // SPDX-SnippetEnd
            _ => None,
        }
    }

    pub const COUNT: usize = 96;
}

impl serde::Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &[]))
    }
}
