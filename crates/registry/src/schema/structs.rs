/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// This file is auto-generated. Do not edit directly.

use crate::schema::prelude::*;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Account {
    User(UserAccount),
    Group(GroupAccount),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountPassword {
    pub secret: Option<String>,
    #[serde(rename = "currentSecret")]
    pub current_secret: Option<String>,
    #[serde(rename = "otpAuth")]
    pub otp_auth: OtpAuth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountSettings {
    pub description: Option<String>,
    pub locale: Locale,
    #[serde(rename = "timeZone")]
    pub time_zone: Option<TimeZone>,
    #[serde(rename = "encryptionAtRest")]
    pub encryption_at_rest: EncryptionAtRest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeProvider {
    #[serde(rename = "challengeType")]
    pub challenge_type: AcmeChallengeType,
    pub contact: Map<String>,
    pub directory: String,
    #[serde(rename = "accountKey")]
    pub account_key: String,
    #[serde(rename = "accountUri")]
    pub account_uri: String,
    #[serde(rename = "accountHashPrefix")]
    pub account_hash_prefix: Option<String>,
    #[serde(rename = "issuerDomainNames")]
    pub issuer_domain_names: Map<String>,
    #[serde(rename = "caaIdentities")]
    pub caa_identities: Map<String>,
    #[serde(rename = "renewBefore")]
    pub renew_before: AcmeRenewBefore,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    #[serde(rename = "preferredChain")]
    pub preferred_chain: Option<String>,
    #[serde(rename = "reuseKey")]
    pub reuse_key: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Action {
    ReloadSettings(ReloadSettingsResult),
    ReloadTlsCertificates,
    ReloadLookupStores,
    ReloadBlockedIps,
    UpdateApps,
    TroubleshootDmarc(DmarcTroubleshoot),
    ClassifySpam(SpamClassify),
    InvalidateCaches,
    InvalidateNegativeCaches,
    PauseMtaQueue,
    ResumeMtaQueue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AddressBook {
    #[serde(rename = "defaultDisplayName")]
    pub default_display_name: Option<String>,
    #[serde(rename = "defaultHrefName")]
    pub default_href_name: Option<String>,
    #[serde(rename = "maxVCardSize")]
    pub max_v_card_size: u64,
    #[serde(rename = "maxAddressBooks")]
    pub max_address_books: Option<u64>,
    #[serde(rename = "maxContacts")]
    pub max_contacts: Option<u64>,
    #[serde(rename = "vCardVersion")]
    pub v_card_version: VCardVersion,
    #[serde(rename = "maxAddressBooksPerCard")]
    pub max_address_books_per_card: u64,
    #[serde(rename = "maxMediaSize")]
    pub max_media_size: u64,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum AiModel {
    OpenAi(AiModelOpenAi),
    Anthropic(AiModelAnthropic),
    Gemini(AiModelGemini),
    Ollama(AiModelOllama),
    TypeSafe(AiModelTypeSafe),
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiModelAnthropic {
    #[serde(rename = "maxOutputTokens")]
    pub max_output_tokens: u64,
    pub temperature: Option<Float>,
    pub reasoning: AiReasoning,
    #[serde(rename = "extraParameters")]
    pub extra_parameters: Option<String>,
    pub name: String,
    pub model: String,
    pub url: Option<String>,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKeyOptional,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    pub timeout: Duration,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "rateLimit")]
    pub rate_limit: Option<Rate>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiModelGemini {
    pub logprobs: bool,
    #[serde(rename = "maxOutputTokens")]
    pub max_output_tokens: u64,
    pub temperature: Option<Float>,
    pub reasoning: AiReasoning,
    #[serde(rename = "extraParameters")]
    pub extra_parameters: Option<String>,
    pub name: String,
    pub model: String,
    pub url: Option<String>,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKeyOptional,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    pub timeout: Duration,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "rateLimit")]
    pub rate_limit: Option<Rate>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiModelOllama {
    pub logprobs: bool,
    #[serde(rename = "keepAlive")]
    pub keep_alive: Option<Duration>,
    #[serde(rename = "maxOutputTokens")]
    pub max_output_tokens: u64,
    pub temperature: Option<Float>,
    pub reasoning: AiReasoning,
    #[serde(rename = "extraParameters")]
    pub extra_parameters: Option<String>,
    pub name: String,
    pub model: String,
    pub url: Option<String>,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKeyOptional,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    pub timeout: Duration,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "rateLimit")]
    pub rate_limit: Option<Rate>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiModelOpenAi {
    pub profile: AiOpenAiProfile,
    pub logprobs: bool,
    #[serde(rename = "maxOutputTokens")]
    pub max_output_tokens: u64,
    pub temperature: Option<Float>,
    pub reasoning: AiReasoning,
    #[serde(rename = "extraParameters")]
    pub extra_parameters: Option<String>,
    pub name: String,
    pub model: String,
    pub url: Option<String>,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKeyOptional,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    pub timeout: Duration,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "rateLimit")]
    pub rate_limit: Option<Rate>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiModelTypeSafe {
    pub name: String,
    pub model: String,
    pub url: Option<String>,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKeyOptional,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    pub timeout: Duration,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "rateLimit")]
    pub rate_limit: Option<Rate>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Alert {
    pub condition: Expression,
    #[serde(rename = "emailAlert")]
    pub email_alert: AlertEmail,
    #[serde(rename = "eventAlert")]
    pub event_alert: AlertEvent,
    pub enable: bool,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum AlertEmail {
    Disabled,
    Enabled(AlertEmailProperties),
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertEmailProperties {
    pub body: String,
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "fromName")]
    pub from_name: Option<String>,
    pub subject: String,
    pub to: Map<String>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum AlertEvent {
    Disabled,
    Enabled(AlertEventProperties),
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertEventProperties {
    #[serde(rename = "eventMessage")]
    pub event_message: Option<String>,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowedIp {
    pub address: IpAddrOrMask,
    pub reason: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiKey {
    pub description: String,
    pub secret: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
    pub permissions: CredentialPermissions,
    #[serde(rename = "allowedIps")]
    pub allowed_ips: Map<IpAddrOrMask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppPassword {
    pub description: String,
    pub secret: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
    pub permissions: CredentialPermissions,
    #[serde(rename = "allowedIps")]
    pub allowed_ips: Map<IpAddrOrMask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Application {
    pub enable: bool,
    pub description: String,
    #[serde(rename = "resourceUrl")]
    pub resource_url: String,
    #[serde(rename = "urlPrefix")]
    pub url_prefix: Map<String>,
    #[serde(rename = "autoUpdateInterval")]
    pub auto_update_interval: Duration,
    #[serde(rename = "unpackDirectory")]
    pub unpack_directory: Option<String>,
    #[serde(rename = "oauthClientId")]
    pub oauth_client_id: Option<String>,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchivedCalendarEvent {
    pub title: String,
    #[serde(rename = "startTime")]
    pub start_time: Option<UTCDateTime>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "archivedAt")]
    pub archived_at: UTCDateTime,
    #[serde(rename = "archivedUntil")]
    pub archived_until: UTCDateTime,
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchivedContactCard {
    pub name: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "archivedAt")]
    pub archived_at: UTCDateTime,
    #[serde(rename = "archivedUntil")]
    pub archived_until: UTCDateTime,
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchivedEmail {
    pub from: String,
    pub subject: String,
    #[serde(rename = "receivedAt")]
    pub received_at: UTCDateTime,
    pub size: u64,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "archivedAt")]
    pub archived_at: UTCDateTime,
    #[serde(rename = "archivedUntil")]
    pub archived_until: UTCDateTime,
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchivedFileNode {
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "archivedAt")]
    pub archived_at: UTCDateTime,
    #[serde(rename = "archivedUntil")]
    pub archived_until: UTCDateTime,
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum ArchivedItem {
    Email(ArchivedEmail),
    FileNode(ArchivedFileNode),
    CalendarEvent(ArchivedCalendarEvent),
    ContactCard(ArchivedContactCard),
    SieveScript(ArchivedSieveScript),
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchivedSieveScript {
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    pub contents: String,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "archivedAt")]
    pub archived_at: UTCDateTime,
    #[serde(rename = "archivedUntil")]
    pub archived_until: UTCDateTime,
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArfExternalReport {
    pub report: ArfFeedbackReport,
    pub from: String,
    pub subject: String,
    pub to: Map<String>,
    #[serde(rename = "receivedAt")]
    pub received_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: UTCDateTime,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArfFeedbackReport {
    #[serde(rename = "feedbackType")]
    pub feedback_type: ArfFeedbackType,
    #[serde(rename = "arrivalDate")]
    pub arrival_date: Option<UTCDateTime>,
    #[serde(rename = "authenticationResults")]
    pub authentication_results: Map<String>,
    pub incidents: u64,
    #[serde(rename = "originalEnvelopeId")]
    pub original_envelope_id: Option<String>,
    #[serde(rename = "originalMailFrom")]
    pub original_mail_from: Option<String>,
    #[serde(rename = "originalRcptTo")]
    pub original_rcpt_to: Option<String>,
    #[serde(rename = "reportedDomains")]
    pub reported_domains: Map<String>,
    #[serde(rename = "reportedUris")]
    pub reported_uris: Map<String>,
    #[serde(rename = "reportingMta")]
    pub reporting_mta: Option<String>,
    #[serde(rename = "sourceIp")]
    pub source_ip: Option<IpAddr>,
    #[serde(rename = "sourcePort")]
    pub source_port: Option<u64>,
    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,
    pub version: u64,
    #[serde(rename = "authFailure")]
    pub auth_failure: ArfAuthFailureType,
    #[serde(rename = "deliveryResult")]
    pub delivery_result: ArfDeliveryResult,
    #[serde(rename = "dkimAdspDns")]
    pub dkim_adsp_dns: Option<String>,
    #[serde(rename = "dkimCanonicalizedBody")]
    pub dkim_canonicalized_body: Option<String>,
    #[serde(rename = "dkimCanonicalizedHeader")]
    pub dkim_canonicalized_header: Option<String>,
    #[serde(rename = "dkimDomain")]
    pub dkim_domain: Option<String>,
    #[serde(rename = "dkimIdentity")]
    pub dkim_identity: Option<String>,
    #[serde(rename = "dkimSelector")]
    pub dkim_selector: Option<String>,
    #[serde(rename = "dkimSelectorDns")]
    pub dkim_selector_dns: Option<String>,
    #[serde(rename = "spfDns")]
    pub spf_dns: Option<String>,
    #[serde(rename = "identityAlignment")]
    pub identity_alignment: ArfIdentityAlignment,
    pub message: Option<String>,
    pub headers: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Asn {
    Disabled,
    Resource(AsnResource),
    Dns(AsnDns),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AsnDns {
    #[serde(rename = "indexAsn")]
    pub index_asn: u64,
    #[serde(rename = "indexAsnName")]
    pub index_asn_name: Option<u64>,
    #[serde(rename = "indexCountry")]
    pub index_country: Option<u64>,
    pub separator: String,
    #[serde(rename = "zoneIpV4")]
    pub zone_ip_v4: String,
    #[serde(rename = "zoneIpV6")]
    pub zone_ip_v6: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AsnResource {
    #[serde(rename = "refreshInterval")]
    pub refresh_interval: Duration,
    #[serde(rename = "maxSize")]
    pub max_size: u64,
    pub timeout: Duration,
    #[serde(rename = "asnUrls")]
    pub asn_urls: Map<String>,
    #[serde(rename = "geoUrls")]
    pub geo_urls: Map<String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Authentication {
    #[serde(rename = "directoryId")]
    pub directory_id: Option<Id>,
    #[serde(rename = "defaultUserRoleIds")]
    pub default_user_role_ids: Map<Id>,
    #[serde(rename = "defaultGroupRoleIds")]
    pub default_group_role_ids: Map<Id>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "defaultTenantRoleIds")]
    pub default_tenant_role_ids: Map<Id>,
    // SPDX-SnippetEnd
    #[serde(rename = "defaultAdminRoleIds")]
    pub default_admin_role_ids: Map<Id>,
    #[serde(rename = "passwordHashAlgorithm")]
    pub password_hash_algorithm: PasswordHashAlgorithm,
    #[serde(rename = "minPasswordLength")]
    pub min_password_length: u64,
    #[serde(rename = "maxPasswordLength")]
    pub max_password_length: u64,
    #[serde(rename = "minPasswordStrength")]
    pub min_password_strength: PasswordStrength,
    #[serde(rename = "passwordDefaultExpiry")]
    pub password_default_expiry: Option<Duration>,
    #[serde(rename = "maxAppPasswords")]
    pub max_app_passwords: Option<u64>,
    #[serde(rename = "maxApiKeys")]
    pub max_api_keys: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum AzureAuth {
    SharedKey(AzureAuthSharedKey),
    SasToken(AzureAuthSasToken),
    ClientSecret(AzureAuthClientSecret),
    ManagedIdentity(AzureAuthManagedIdentity),
    WorkloadIdentity(AzureAuthWorkloadIdentity),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureAuthClientSecret {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureAuthManagedIdentity {
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureAuthSasToken {
    #[serde(rename = "sasToken")]
    pub sas_token: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureAuthSharedKey {
    #[serde(rename = "accountKey")]
    pub account_key: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureAuthWorkloadIdentity {
    #[serde(rename = "tenantId")]
    pub tenant_id: Option<String>,
    #[serde(rename = "clientId")]
    pub client_id: Option<String>,
    #[serde(rename = "tokenFile")]
    pub token_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureStore {
    #[serde(rename = "storageAccount")]
    pub storage_account: String,
    pub container: String,
    pub environment: AzureEnvironment,
    pub url: Option<String>,
    pub auth: AzureAuth,
    pub timeout: Duration,
    #[serde(rename = "maxRetries")]
    pub max_retries: u64,
    #[serde(rename = "keyPrefix")]
    pub key_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum BlobStore {
    Default,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded(ShardedBlobStore),
    // SPDX-SnippetEnd
    S3(S3Store),
    Azure(AzureStore),
    FileSystem(FileSystemStore),
    FoundationDb(FoundationDbStore),
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum BlobStoreBase {
    S3(S3Store),
    Azure(AzureStore),
    FileSystem(FileSystemStore),
    FoundationDb(FoundationDbStore),
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlobStoreSwap {
    pub store: BlobSwapStore,
    pub retention: Duration,
    #[serde(rename = "flushChanges")]
    pub flush_changes: u64,
    #[serde(rename = "flushInterval")]
    pub flush_interval: Duration,
    #[serde(rename = "maxAccountSize")]
    pub max_account_size: u64,
    #[serde(rename = "minAccountSize")]
    pub min_account_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum BlobSwapStore {
    Default,
    S3(S3Store),
    Azure(AzureStore),
    FileSystem(FileSystemStore),
    FoundationDb(FoundationDbStore),
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockedIp {
    pub address: IpAddrOrMask,
    pub reason: BlockReason,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Bootstrap {
    #[serde(rename = "defaultHostname")]
    pub default_hostname: String,
    #[serde(rename = "defaultDomain")]
    pub default_domain: String,
    #[serde(rename = "requestTlsCertificate")]
    pub request_tls_certificate: bool,
    #[serde(rename = "generateDkimKeys")]
    pub generate_dkim_keys: bool,
    #[serde(rename = "dataStore")]
    pub data_store: DataStore,
    #[serde(rename = "blobStore")]
    pub blob_store: BlobStore,
    #[serde(rename = "searchStore")]
    pub search_store: SearchStore,
    #[serde(rename = "inMemoryStore")]
    pub in_memory_store: InMemoryStore,
    pub directory: DirectoryBootstrap,
    pub tracer: Tracer,
    #[serde(rename = "dnsServer")]
    pub dns_server: DnsServerBootstrap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cache {
    #[serde(rename = "accessTokens")]
    pub access_tokens: u64,
    pub contacts: u64,
    #[serde(rename = "dnsIpv4")]
    pub dns_ipv4: u64,
    #[serde(rename = "dnsIpv6")]
    pub dns_ipv6: u64,
    #[serde(rename = "dnsMtaSts")]
    pub dns_mta_sts: u64,
    #[serde(rename = "dnsMx")]
    pub dns_mx: u64,
    #[serde(rename = "dnsPtr")]
    pub dns_ptr: u64,
    #[serde(rename = "spamLookup")]
    pub spam_lookup: u64,
    #[serde(rename = "dnsTlsa")]
    pub dns_tlsa: u64,
    #[serde(rename = "dnsTxt")]
    pub dns_txt: u64,
    pub events: u64,
    pub scheduling: u64,
    pub files: u64,
    #[serde(rename = "httpAuth")]
    pub http_auth: u64,
    pub messages: u64,
    #[serde(rename = "messagesLarge")]
    pub messages_large: u64,
    #[serde(rename = "messagesLargeTtl")]
    pub messages_large_ttl: Duration,
    #[serde(rename = "groupwareLarge")]
    pub groupware_large: u64,
    #[serde(rename = "groupwareLargeTtl")]
    pub groupware_large_ttl: Duration,
    pub domains: u64,
    #[serde(rename = "domainNames")]
    pub domain_names: u64,
    #[serde(rename = "domainNamesNegative")]
    pub domain_names_negative: u64,
    #[serde(rename = "emailAddresses")]
    pub email_addresses: u64,
    #[serde(rename = "emailAddressesNegative")]
    pub email_addresses_negative: u64,
    pub accounts: u64,
    pub roles: u64,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub tenants: u64,
    // SPDX-SnippetEnd
    #[serde(rename = "mailingLists")]
    pub mailing_lists: u64,
    #[serde(rename = "dkimSignatures")]
    pub dkim_signatures: u64,
    #[serde(rename = "negativeTtl")]
    pub negative_ttl: Duration,
    #[serde(rename = "directoryRecipients")]
    pub directory_recipients: u64,
    #[serde(rename = "directoryRecipientsTtl")]
    pub directory_recipients_ttl: Duration,
    pub swap: CacheSwap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum CacheSwap {
    Disabled,
    LocalFile(LocalFileSwap),
    Redis(RedisSwap),
    BlobStore(BlobStoreSwap),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Calendar {
    #[serde(rename = "defaultDisplayName")]
    pub default_display_name: Option<String>,
    #[serde(rename = "defaultHrefName")]
    pub default_href_name: Option<String>,
    #[serde(rename = "maxAttendees")]
    pub max_attendees: u64,
    #[serde(rename = "maxRecurrenceExpansions")]
    pub max_recurrence_expansions: u64,
    #[serde(rename = "maxICalendarSize")]
    pub max_i_calendar_size: u64,
    #[serde(rename = "maxCalendars")]
    pub max_calendars: Option<u64>,
    #[serde(rename = "maxEvents")]
    pub max_events: Option<u64>,
    #[serde(rename = "maxParticipantIdentities")]
    pub max_participant_identities: Option<u64>,
    #[serde(rename = "maxEventNotifications")]
    pub max_event_notifications: Option<u64>,
    #[serde(rename = "maxCalendarsPerEvent")]
    pub max_calendars_per_event: u64,
    #[serde(rename = "maxExpandedQueryDuration")]
    pub max_expanded_query_duration: Duration,
    #[serde(rename = "maxAvailabilityDuration")]
    pub max_availability_duration: Duration,
    #[serde(rename = "availabilityRateLimit")]
    pub availability_rate_limit: Option<Rate>,
    #[serde(rename = "maxAttachmentsSize")]
    pub max_attachments_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CalendarAlarm {
    #[serde(rename = "allowExternalRcpts")]
    pub allow_external_rcpts: bool,
    pub enable: bool,
    #[serde(rename = "fromAddress")]
    pub from_address: Option<String>,
    #[serde(rename = "fromName")]
    pub from_name: String,
    #[serde(rename = "minTriggerInterval")]
    pub min_trigger_interval: Duration,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub template: Option<String>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CalendarScheduling {
    pub enable: bool,
    #[serde(rename = "httpRsvpEnable")]
    pub http_rsvp_enable: bool,
    #[serde(rename = "httpRsvpLinkExpiry")]
    pub http_rsvp_link_expiry: Duration,
    #[serde(rename = "httpRsvpUrl")]
    pub http_rsvp_url: Option<String>,
    #[serde(rename = "autoAddInvitations")]
    pub auto_add_invitations: bool,
    #[serde(rename = "maxItipSize")]
    pub max_itip_size: u64,
    #[serde(rename = "maxRecipients")]
    pub max_recipients: u64,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "emailTemplate")]
    pub email_template: Option<String>,
    #[cfg(feature = "enterprise")]
    #[serde(rename = "httpRsvpTemplate")]
    pub http_rsvp_template: Option<String>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Certificate {
    pub certificate: PublicText,
    #[serde(rename = "privateKey")]
    pub private_key: SecretText,
    #[serde(rename = "subjectAlternativeNames")]
    pub subject_alternative_names: Map<String>,
    #[serde(rename = "notValidAfter")]
    pub not_valid_after: UTCDateTime,
    #[serde(rename = "notValidBefore")]
    pub not_valid_before: UTCDateTime,
    pub issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum CertificateManagement {
    Manual,
    Automatic(CertificateManagementProperties),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CertificateManagementProperties {
    #[serde(rename = "acmeProviderId")]
    pub acme_provider_id: Id,
    #[serde(rename = "subjectAlternativeNames")]
    pub subject_alternative_names: Map<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum ClusterListenerGroup {
    EnableAll,
    DisableAll,
    EnableSome(ClusterListenerGroupProperties),
    DisableSome(ClusterListenerGroupProperties),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterListenerGroupProperties {
    #[serde(rename = "listenerIds")]
    pub listener_ids: Map<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterNode {
    #[serde(rename = "nodeId")]
    pub node_id: u64,
    pub hostname: String,
    #[serde(rename = "lastRenewal")]
    pub last_renewal: UTCDateTime,
    pub status: ClusterNodeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterRole {
    pub name: String,
    pub description: Option<String>,
    pub tasks: ClusterTaskGroup,
    pub listeners: ClusterListenerGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum ClusterTaskGroup {
    EnableAll,
    DisableAll,
    EnableSome(ClusterTaskGroupProperties),
    DisableSome(ClusterTaskGroupProperties),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterTaskGroupProperties {
    #[serde(rename = "taskTypes")]
    pub task_types: Map<ClusterTaskType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Coordinator {
    Disabled,
    Default,
    Kafka(KafkaCoordinator),
    Nats(NatsCoordinator),
    Zenoh(ZenohCoordinator),
    Redis(RedisStore),
    RedisCluster(RedisClusterStore),
    RedisSentinel(RedisSentinelStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Credential {
    Password(PasswordCredential),
    AppPassword(SecondaryCredential),
    ApiKey(SecondaryCredential),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum CredentialPermissions {
    Inherit,
    Disable(CredentialPermissionsList),
    Replace(CredentialPermissionsList),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CredentialPermissionsList {
    pub permissions: Map<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Cron {
    Daily(CronDaily),
    Weekly(CronWeekly),
    Hourly(CronHourly),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CronDaily {
    pub hour: u64,
    pub minute: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CronHourly {
    pub minute: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CronWeekly {
    pub day: u64,
    pub hour: u64,
    pub minute: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRoles {
    #[serde(rename = "roleIds")]
    pub role_ids: Map<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DataRetention {
    #[serde(rename = "expungeTrashAfter")]
    pub expunge_trash_after: Option<Duration>,
    #[serde(rename = "expungeSubmissionsAfter")]
    pub expunge_submissions_after: Option<Duration>,
    #[serde(rename = "expungeShareNotifyAfter")]
    pub expunge_share_notify_after: Option<Duration>,
    #[serde(rename = "expungeSchedulingInboxAfter")]
    pub expunge_scheduling_inbox_after: Option<Duration>,
    #[serde(rename = "expungeSchedule")]
    pub expunge_schedule: Cron,
    #[serde(rename = "dataCleanupSchedule")]
    pub data_cleanup_schedule: Cron,
    #[serde(rename = "blobCleanupSchedule")]
    pub blob_cleanup_schedule: Cron,
    #[serde(rename = "maxChangesHistory")]
    pub max_changes_history: Option<u64>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "archiveDeletedItemsFor")]
    pub archive_deleted_items_for: Option<Duration>,
    #[cfg(feature = "enterprise")]
    #[serde(rename = "archiveDeletedAccountsFor")]
    pub archive_deleted_accounts_for: Option<Duration>,
    // SPDX-SnippetEnd
    #[serde(rename = "holdMtaReportsFor")]
    pub hold_mta_reports_for: Option<Duration>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "holdTracesFor")]
    pub hold_traces_for: Option<Duration>,
    #[cfg(feature = "enterprise")]
    #[serde(rename = "holdMetricsFor")]
    pub hold_metrics_for: Option<Duration>,
    #[cfg(feature = "enterprise")]
    #[serde(rename = "metricsCollectionInterval")]
    pub metrics_collection_interval: Cron,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DataStore {
    RocksDb(RocksDbStore),
    Sqlite(SqliteStore),
    FoundationDb(FoundationDbStore),
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveryError {
    #[serde(rename = "errorType")]
    pub error_type: DeliveryErrorType,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
    #[serde(rename = "errorCommand")]
    pub error_command: Option<String>,
    #[serde(rename = "responseHostname")]
    pub response_hostname: Option<String>,
    #[serde(rename = "responseCode")]
    pub response_code: Option<u64>,
    #[serde(rename = "responseEnhanced")]
    pub response_enhanced: Option<String>,
    #[serde(rename = "responseMessage")]
    pub response_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Directory {
    Ldap(LdapDirectory),
    Sql(SqlDirectory),
    Oidc(OidcDirectory),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DirectoryBootstrap {
    Internal,
    Ldap(LdapDirectory),
    Sql(SqlDirectory),
    Oidc(OidcDirectory),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dkim1Signature {
    pub auid: Option<String>,
    pub canonicalization: DkimCanonicalization,
    pub expire: Option<Duration>,
    pub headers: Map<String>,
    #[serde(rename = "privateKey")]
    pub private_key: SecretText,
    pub report: bool,
    #[serde(rename = "thirdParty")]
    pub third_party: Option<String>,
    #[serde(rename = "thirdPartyHash")]
    pub third_party_hash: Option<DkimHash>,
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub selector: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "nextTransitionAt")]
    pub next_transition_at: Option<UTCDateTime>,
    pub stage: DkimRotationStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dkim2Signature {
    pub flags: Map<Dkim2Flag>,
    #[serde(rename = "instanceHashes")]
    pub instance_hashes: Map<Dkim2HashAlgorithm>,
    #[serde(rename = "privateKey")]
    pub private_key: SecretText,
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub selector: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "nextTransitionAt")]
    pub next_transition_at: Option<UTCDateTime>,
    pub stage: DkimRotationStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DkimManagement {
    Automatic(DkimManagementProperties),
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DkimManagementProperties {
    pub algorithms: Map<DkimSignatureType>,
    #[serde(rename = "selectorTemplate")]
    pub selector_template: String,
    #[serde(rename = "rotateAfter")]
    pub rotate_after: Duration,
    #[serde(rename = "retireAfter")]
    pub retire_after: Duration,
    #[serde(rename = "deleteAfter")]
    pub delete_after: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DkimReportSettings {
    #[serde(rename = "fromAddress")]
    pub from_address: Expression,
    #[serde(rename = "fromName")]
    pub from_name: Expression,
    #[serde(rename = "sendFrequency")]
    pub send_frequency: Expression,
    #[serde(rename = "dkimSignDomain")]
    pub dkim_sign_domain: Expression,
    pub subject: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DkimSignature {
    Dkim1Ed25519Sha256(Dkim1Signature),
    Dkim1RsaSha256(Dkim1Signature),
    Dkim2Ed25519Sha256(Dkim2Signature),
    Dkim2RsaSha256(Dkim2Signature),
    Dkim2MlDsa44Ed25519Sha512(Dkim2Signature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcDkimResult {
    pub domain: String,
    pub selector: String,
    pub result: DkimAuthResult,
    #[serde(rename = "humanResult")]
    pub human_result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcExtension {
    pub name: String,
    pub definition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcExternalReport {
    pub report: DmarcReport,
    pub from: String,
    pub subject: String,
    pub to: Map<String>,
    #[serde(rename = "receivedAt")]
    pub received_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: UTCDateTime,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcInternalReport {
    pub rua: Map<String>,
    #[serde(rename = "policyIdentifier")]
    pub policy_identifier: u64,
    pub report: DmarcReport,
    pub domain: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "deliverAt")]
    pub deliver_at: UTCDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcPolicyOverrideReason {
    #[serde(rename = "overrideType")]
    pub override_type: DmarcPolicyOverride,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcReport {
    pub version: Float,
    #[serde(rename = "orgName")]
    pub org_name: String,
    pub email: String,
    #[serde(rename = "extraContactInfo")]
    pub extra_contact_info: Option<String>,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "dateRangeStart")]
    pub date_range_start: UTCDateTime,
    #[serde(rename = "dateRangeEnd")]
    pub date_range_end: UTCDateTime,
    pub errors: Map<String>,
    #[serde(rename = "policyDomain")]
    pub policy_domain: String,
    #[serde(rename = "policyVersion")]
    pub policy_version: Option<String>,
    #[serde(rename = "policyAdkim")]
    pub policy_adkim: DmarcAlignment,
    #[serde(rename = "policyAspf")]
    pub policy_aspf: DmarcAlignment,
    #[serde(rename = "policyDisposition")]
    pub policy_disposition: DmarcDisposition,
    #[serde(rename = "policySubdomainDisposition")]
    pub policy_subdomain_disposition: DmarcDisposition,
    #[serde(rename = "policyTestingMode")]
    pub policy_testing_mode: bool,
    #[serde(rename = "policyFailureReportingOptions")]
    pub policy_failure_reporting_options: Map<FailureReportingOption>,
    pub records: List<DmarcReportRecord>,
    pub extensions: List<DmarcExtension>,
    pub generator: Option<String>,
    #[serde(rename = "policyNp")]
    pub policy_np: DmarcDisposition,
    #[serde(rename = "policyDiscoveryMethod")]
    pub policy_discovery_method: DmarcDiscovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcReportRecord {
    #[serde(rename = "sourceIp")]
    pub source_ip: Option<IpAddr>,
    pub count: u64,
    #[serde(rename = "evaluatedDisposition")]
    pub evaluated_disposition: DmarcActionDisposition,
    #[serde(rename = "evaluatedDkim")]
    pub evaluated_dkim: DmarcResult,
    #[serde(rename = "evaluatedSpf")]
    pub evaluated_spf: DmarcResult,
    #[serde(rename = "policyOverrideReasons")]
    pub policy_override_reasons: List<DmarcPolicyOverrideReason>,
    #[serde(rename = "envelopeTo")]
    pub envelope_to: Option<String>,
    #[serde(rename = "envelopeFrom")]
    pub envelope_from: String,
    #[serde(rename = "headerFrom")]
    pub header_from: String,
    #[serde(rename = "dkimResults")]
    pub dkim_results: List<DmarcDkimResult>,
    #[serde(rename = "spfResults")]
    pub spf_results: List<DmarcSpfResult>,
    pub extensions: List<DmarcExtension>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcReportSettings {
    #[serde(rename = "aggregateContactInfo")]
    pub aggregate_contact_info: Expression,
    #[serde(rename = "aggregateFromAddress")]
    pub aggregate_from_address: Expression,
    #[serde(rename = "aggregateFromName")]
    pub aggregate_from_name: Expression,
    #[serde(rename = "maxAggregateReportSize")]
    pub max_aggregate_report_size: Expression,
    #[serde(rename = "aggregateOrgName")]
    pub aggregate_org_name: Expression,
    #[serde(rename = "aggregateSendFrequency")]
    pub aggregate_send_frequency: Expression,
    #[serde(rename = "aggregateDkimSignDomain")]
    pub aggregate_dkim_sign_domain: Expression,
    #[serde(rename = "failureFromAddress")]
    pub failure_from_address: Expression,
    #[serde(rename = "failureFromName")]
    pub failure_from_name: Expression,
    #[serde(rename = "failureSendFrequency")]
    pub failure_send_frequency: Expression,
    #[serde(rename = "failureDkimSignDomain")]
    pub failure_dkim_sign_domain: Expression,
    #[serde(rename = "failureSubject")]
    pub failure_subject: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcSpfResult {
    pub domain: String,
    pub scope: SpfDomainScope,
    pub result: SpfAuthResult,
    #[serde(rename = "humanResult")]
    pub human_result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcTroubleshoot {
    #[serde(rename = "remoteIp")]
    pub remote_ip: IpAddr,
    #[serde(rename = "ehloDomain")]
    pub ehlo_domain: String,
    #[serde(rename = "mailFrom")]
    pub mail_from: String,
    #[serde(rename = "rcptTo")]
    pub rcpt_to: Map<String>,
    pub message: Option<String>,
    #[serde(rename = "spfEhloDomain")]
    pub spf_ehlo_domain: String,
    #[serde(rename = "spfEhloResult")]
    pub spf_ehlo_result: DmarcTroubleshootAuthResult,
    #[serde(rename = "spfMailFromDomain")]
    pub spf_mail_from_domain: String,
    #[serde(rename = "spfMailFromResult")]
    pub spf_mail_from_result: DmarcTroubleshootAuthResult,
    #[serde(rename = "ipRevResult")]
    pub ip_rev_result: DmarcTroubleshootAuthResult,
    #[serde(rename = "ipRevPtr")]
    pub ip_rev_ptr: Map<String>,
    #[serde(rename = "dkimResults")]
    pub dkim_results: List<DmarcTroubleshootAuthResult>,
    #[serde(rename = "dkimPass")]
    pub dkim_pass: bool,
    #[serde(rename = "dkim2Result")]
    pub dkim2_result: DmarcTroubleshootAuthResult,
    #[serde(rename = "dkim2Pass")]
    pub dkim2_pass: bool,
    #[serde(rename = "arcResult")]
    pub arc_result: DmarcTroubleshootAuthResult,
    #[serde(rename = "dmarcResult")]
    pub dmarc_result: DmarcTroubleshootAuthResult,
    #[serde(rename = "dmarcPass")]
    pub dmarc_pass: bool,
    #[serde(rename = "dmarcPolicy")]
    pub dmarc_policy: DmarcDisposition,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DmarcTroubleshootAuthResult {
    Pass,
    Fail(DmarcTroubleshootDetails),
    SoftFail(DmarcTroubleshootDetails),
    TempError(DmarcTroubleshootDetails),
    PermError(DmarcTroubleshootDetails),
    Neutral(DmarcTroubleshootDetails),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DmarcTroubleshootDetails {
    pub details: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsCustomResolver {
    pub protocol: DnsResolverProtocol,
    pub address: IpAddr,
    pub port: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DnsManagement {
    Manual,
    Automatic(DnsManagementProperties),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsManagementProperties {
    #[serde(rename = "dnsServerId")]
    pub dns_server_id: Id,
    pub origin: Option<String>,
    #[serde(rename = "publishRecords")]
    pub publish_records: Map<DnsRecordType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DnsResolver {
    System(DnsResolverCommon),
    Custom(DnsResolverCustom),
    Cloudflare(DnsResolverTls),
    Quad9(DnsResolverTls),
    Google(DnsResolverCommon),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsResolverCommon {
    pub attempts: u64,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "enableEdns")]
    pub enable_edns: bool,
    #[serde(rename = "preserveIntermediates")]
    pub preserve_intermediates: bool,
    pub timeout: Duration,
    #[serde(rename = "tcpOnError")]
    pub tcp_on_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsResolverCustom {
    pub servers: List<DnsCustomResolver>,
    pub attempts: u64,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "enableEdns")]
    pub enable_edns: bool,
    #[serde(rename = "preserveIntermediates")]
    pub preserve_intermediates: bool,
    pub timeout: Duration,
    #[serde(rename = "tcpOnError")]
    pub tcp_on_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsResolverTls {
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    pub attempts: u64,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: u64,
    #[serde(rename = "enableEdns")]
    pub enable_edns: bool,
    #[serde(rename = "preserveIntermediates")]
    pub preserve_intermediates: bool,
    pub timeout: Duration,
    #[serde(rename = "tcpOnError")]
    pub tcp_on_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DnsServer {
    Tsig(DnsServerTsig),
    Cloudflare(DnsServerCloudflare),
    DigitalOcean(DnsServerCloud),
    DeSEC(DnsServerCloud),
    Ovh(DnsServerOvh),
    Bunny(DnsServerCloud),
    Porkbun(DnsServerPorkbun),
    Dnsimple(DnsServerDnsimple),
    Spaceship(DnsServerSpaceship),
    Route53(DnsServerRoute53),
    GoogleCloudDns(DnsServerGoogleCloudDns),
    Alidns(DnsServerAlidns),
    ArvanCloud(DnsServerCloud),
    Autodns(DnsServerAutodns),
    AzureDns(DnsServerAzureDns),
    BaiduCloud(DnsServerBaiduCloud),
    BluecatV2(DnsServerBluecatV2),
    ClouDns(DnsServerClouDns),
    Constellix(DnsServerConstellix),
    Cpanel(DnsServerCpanel),
    Ddnss(DnsServerCloud),
    DnsMadeEasy(DnsServerDnsMadeEasy),
    Domeneshop(DnsServerDomeneshop),
    Dreamhost(DnsServerCloud),
    DuckDns(DnsServerCloud),
    Dynu(DnsServerCloud),
    EasyDns(DnsServerEasyDns),
    EdgeDns(DnsServerEdgeDns),
    Exoscale(DnsServerExoscale),
    FreeMyIp(DnsServerCloud),
    GandiV5(DnsServerCloud),
    Gcore(DnsServerCloud),
    Glesys(DnsServerGlesys),
    Godaddy(DnsServerGodaddy),
    Hetzner(DnsServerCloud),
    HostingDe(DnsServerCloud),
    Hostinger(DnsServerCloud),
    HuaweiCloud(DnsServerHuaweiCloud),
    Hurricane(DnsServerHurricane),
    IbmCloud(DnsServerIbmCloud),
    Infoblox(DnsServerInfoblox),
    Infomaniak(DnsServerCloud),
    Inwx(DnsServerInwx),
    Ionos(DnsServerCloud),
    Ipv64(DnsServerCloud),
    Joker(DnsServerJoker),
    Lightsail(DnsServerLightsail),
    Linode(DnsServerCloud),
    LuaDns(DnsServerLuaDns),
    MythicBeasts(DnsServerMythicBeasts),
    Namecheap(DnsServerNamecheap),
    NameDotCom(DnsServerNameDotCom),
    NameSilo(DnsServerCloud),
    Netcup(DnsServerNetcup),
    Netlify(DnsServerCloud),
    Nifcloud(DnsServerNifcloud),
    Ns1(DnsServerCloud),
    OracleCloud(DnsServerOracleCloud),
    Plesk(DnsServerPlesk),
    Safedns(DnsServerCloud),
    Scaleway(DnsServerCloud),
    TencentCloud(DnsServerTencentCloud),
    Transip(DnsServerTransip),
    UltraDns(DnsServerUltraDns),
    Vercel(DnsServerVercel),
    Volcengine(DnsServerVolcengine),
    Vultr(DnsServerCloud),
    WebSupport(DnsServerWebSupport),
    YandexCloud(DnsServerYandexCloud),
    PowerDns(DnsServerPowerDns),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerAlidns {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    pub region: Option<String>,
    #[serde(rename = "sessionToken")]
    pub session_token: SecretKeyOptional,
    pub line: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerAutodns {
    pub username: String,
    pub password: SecretKey,
    pub context: Option<u64>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerAzureDns {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: SecretKey,
    #[serde(rename = "subscriptionId")]
    pub subscription_id: String,
    #[serde(rename = "resourceGroup")]
    pub resource_group: String,
    pub environment: AzureEnvironment,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerBaiduCloud {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerBluecatV2 {
    pub url: String,
    pub username: String,
    pub password: SecretKey,
    #[serde(rename = "configName")]
    pub config_name: String,
    #[serde(rename = "viewName")]
    pub view_name: String,
    #[serde(rename = "skipDeploy")]
    pub skip_deploy: bool,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum DnsServerBootstrap {
    Manual,
    Tsig(DnsServerTsig),
    Cloudflare(DnsServerCloudflare),
    DigitalOcean(DnsServerCloud),
    DeSEC(DnsServerCloud),
    Ovh(DnsServerOvh),
    Bunny(DnsServerCloud),
    Porkbun(DnsServerPorkbun),
    Dnsimple(DnsServerDnsimple),
    Spaceship(DnsServerSpaceship),
    Route53(DnsServerRoute53),
    GoogleCloudDns(DnsServerGoogleCloudDns),
    Alidns(DnsServerAlidns),
    ArvanCloud(DnsServerCloud),
    Autodns(DnsServerAutodns),
    AzureDns(DnsServerAzureDns),
    BaiduCloud(DnsServerBaiduCloud),
    BluecatV2(DnsServerBluecatV2),
    ClouDns(DnsServerClouDns),
    Constellix(DnsServerConstellix),
    Cpanel(DnsServerCpanel),
    Ddnss(DnsServerCloud),
    DnsMadeEasy(DnsServerDnsMadeEasy),
    Domeneshop(DnsServerDomeneshop),
    Dreamhost(DnsServerCloud),
    DuckDns(DnsServerCloud),
    Dynu(DnsServerCloud),
    EasyDns(DnsServerEasyDns),
    EdgeDns(DnsServerEdgeDns),
    Exoscale(DnsServerExoscale),
    FreeMyIp(DnsServerCloud),
    GandiV5(DnsServerCloud),
    Gcore(DnsServerCloud),
    Glesys(DnsServerGlesys),
    Godaddy(DnsServerGodaddy),
    Hetzner(DnsServerCloud),
    HostingDe(DnsServerCloud),
    Hostinger(DnsServerCloud),
    HuaweiCloud(DnsServerHuaweiCloud),
    Hurricane(DnsServerHurricane),
    IbmCloud(DnsServerIbmCloud),
    Infoblox(DnsServerInfoblox),
    Infomaniak(DnsServerCloud),
    Inwx(DnsServerInwx),
    Ionos(DnsServerCloud),
    Ipv64(DnsServerCloud),
    Joker(DnsServerJoker),
    Lightsail(DnsServerLightsail),
    Linode(DnsServerCloud),
    LuaDns(DnsServerLuaDns),
    MythicBeasts(DnsServerMythicBeasts),
    Namecheap(DnsServerNamecheap),
    NameDotCom(DnsServerNameDotCom),
    NameSilo(DnsServerCloud),
    Netcup(DnsServerNetcup),
    Netlify(DnsServerCloud),
    Nifcloud(DnsServerNifcloud),
    Ns1(DnsServerCloud),
    OracleCloud(DnsServerOracleCloud),
    Plesk(DnsServerPlesk),
    Safedns(DnsServerCloud),
    Scaleway(DnsServerCloud),
    TencentCloud(DnsServerTencentCloud),
    Transip(DnsServerTransip),
    UltraDns(DnsServerUltraDns),
    Vercel(DnsServerVercel),
    Volcengine(DnsServerVolcengine),
    Vultr(DnsServerCloud),
    WebSupport(DnsServerWebSupport),
    YandexCloud(DnsServerYandexCloud),
    PowerDns(DnsServerPowerDns),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerClouDns {
    #[serde(rename = "authId")]
    pub auth_id: Option<String>,
    #[serde(rename = "subAuthId")]
    pub sub_auth_id: Option<String>,
    pub password: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerCloud {
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerCloudflare {
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerConstellix {
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerCpanel {
    pub url: String,
    pub username: String,
    pub token: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerDnsMadeEasy {
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerDnsimple {
    pub token: SecretKey,
    #[serde(rename = "accountIdentifier")]
    pub account_identifier: String,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerDomeneshop {
    pub token: String,
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerEasyDns {
    pub token: String,
    pub key: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerEdgeDns {
    pub host: String,
    #[serde(rename = "clientToken")]
    pub client_token: String,
    #[serde(rename = "clientSecret")]
    pub client_secret: SecretKey,
    #[serde(rename = "accessToken")]
    pub access_token: SecretKey,
    #[serde(rename = "accountSwitchKey")]
    pub account_switch_key: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerExoscale {
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerGlesys {
    pub username: String,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerGodaddy {
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerGoogleCloudDns {
    #[serde(rename = "serviceAccountJson")]
    pub service_account_json: SecretText,
    #[serde(rename = "projectId")]
    pub project_id: String,
    #[serde(rename = "managedZone")]
    pub managed_zone: Option<String>,
    #[serde(rename = "privateZone")]
    pub private_zone: bool,
    #[serde(rename = "impersonateServiceAccount")]
    pub impersonate_service_account: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerHuaweiCloud {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    pub region: String,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerHurricane {
    pub credentials: List<HurricaneCredential>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerIbmCloud {
    pub username: String,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerInfoblox {
    pub host: String,
    pub port: Option<u64>,
    pub username: String,
    pub password: SecretKey,
    #[serde(rename = "wapiVersion")]
    pub wapi_version: Option<String>,
    #[serde(rename = "dnsView")]
    pub dns_view: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerInwx {
    pub username: String,
    pub password: SecretKey,
    #[serde(rename = "sharedSecret")]
    pub shared_secret: SecretKeyOptional,
    pub sandbox: bool,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerJoker {
    pub auth: JokerAuth,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerLightsail {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    #[serde(rename = "sessionToken")]
    pub session_token: SecretKeyOptional,
    pub region: Option<String>,
    pub domain: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerLuaDns {
    pub username: String,
    pub token: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerMythicBeasts {
    pub username: String,
    pub password: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerNameDotCom {
    pub username: String,
    pub token: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerNamecheap {
    #[serde(rename = "apiUser")]
    pub api_user: String,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKey,
    #[serde(rename = "clientIp")]
    pub client_ip: String,
    pub username: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerNetcup {
    #[serde(rename = "customerNumber")]
    pub customer_number: String,
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    pub password: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerNifcloud {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerOracleCloud {
    #[serde(rename = "tenancyOcid")]
    pub tenancy_ocid: String,
    #[serde(rename = "userOcid")]
    pub user_ocid: String,
    pub fingerprint: String,
    #[serde(rename = "privateKeyPem")]
    pub private_key_pem: SecretText,
    #[serde(rename = "privateKeyPassword")]
    pub private_key_password: SecretKeyOptional,
    pub region: String,
    #[serde(rename = "compartmentOcid")]
    pub compartment_ocid: String,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerOvh {
    #[serde(rename = "applicationKey")]
    pub application_key: String,
    #[serde(rename = "applicationSecret")]
    pub application_secret: SecretKey,
    #[serde(rename = "consumerKey")]
    pub consumer_key: SecretKey,
    #[serde(rename = "ovhEndpoint")]
    pub ovh_endpoint: OvhEndpoint,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerPlesk {
    pub url: String,
    #[serde(rename = "apiKey")]
    pub api_key: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerPorkbun {
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerPowerDns {
    #[serde(rename = "apiKey")]
    pub api_key: SecretKey,
    pub url: Option<String>,
    #[serde(rename = "serverId")]
    pub server_id: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerRoute53 {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    #[serde(rename = "sessionToken")]
    pub session_token: SecretKeyOptional,
    pub region: String,
    #[serde(rename = "hostedZoneId")]
    pub hosted_zone_id: Option<String>,
    #[serde(rename = "privateZoneOnly")]
    pub private_zone_only: bool,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerSpaceship {
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerTencentCloud {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    pub region: Option<String>,
    #[serde(rename = "sessionToken")]
    pub session_token: SecretKeyOptional,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerTransip {
    pub username: String,
    #[serde(rename = "privateKeyPem")]
    pub private_key_pem: SecretText,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerTsig {
    pub host: IpAddr,
    pub port: u64,
    #[serde(rename = "keyName")]
    pub key_name: String,
    pub key: SecretKey,
    pub protocol: IpProtocol,
    #[serde(rename = "tsigAlgorithm")]
    pub tsig_algorithm: TsigAlgorithm,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerUltraDns {
    pub username: String,
    pub password: SecretKey,
    pub url: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerVercel {
    pub token: SecretKey,
    #[serde(rename = "teamId")]
    pub team_id: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerVolcengine {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKey,
    pub region: Option<String>,
    pub host: Option<String>,
    pub scheme: Option<String>,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerWebSupport {
    #[serde(rename = "apiKeyId")]
    pub api_key_id: String,
    pub secret: SecretKey,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsServerYandexCloud {
    #[serde(rename = "apiKey")]
    pub api_key: SecretText,
    #[serde(rename = "folderId")]
    pub folder_id: String,
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    pub ttl: Duration,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "propagationTimeout")]
    pub propagation_timeout: Duration,
    #[serde(rename = "propagationDelay")]
    pub propagation_delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Domain {
    pub name: String,
    pub aliases: Map<String>,
    pub enable: bool,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    pub description: Option<String>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub logo: Option<String>,
    // SPDX-SnippetEnd
    #[serde(rename = "certificateManagement")]
    pub certificate_management: CertificateManagement,
    #[serde(rename = "dkimManagement")]
    pub dkim_management: DkimManagement,
    #[serde(rename = "dnsManagement")]
    pub dns_management: DnsManagement,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    #[cfg(feature = "enterprise")]
    #[serde(rename = "directoryId")]
    pub directory_id: Option<Id>,
    // SPDX-SnippetEnd
    #[serde(rename = "catchAllAddress")]
    pub catch_all_address: Option<String>,
    #[serde(rename = "subAddressing")]
    pub sub_addressing: SubAddressing,
    #[serde(rename = "allowRelaying")]
    pub allow_relaying: bool,
    #[serde(rename = "reportAddressUri")]
    pub report_address_uri: Option<String>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "allowScimProvisioning")]
    pub allow_scim_provisioning: bool,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DsnReportSettings {
    #[serde(rename = "fromAddress")]
    pub from_address: Expression,
    #[serde(rename = "fromName")]
    pub from_name: Expression,
    #[serde(rename = "dkimSignDomain")]
    pub dkim_sign_domain: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ElasticSearchStore {
    pub url: String,
    #[serde(rename = "numReplicas")]
    pub num_replicas: u64,
    #[serde(rename = "numShards")]
    pub num_shards: u64,
    #[serde(rename = "includeSource")]
    pub include_source: bool,
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Email {
    #[serde(rename = "maxAttachmentSize")]
    pub max_attachment_size: u64,
    #[serde(rename = "maxMessageSize")]
    pub max_message_size: u64,
    #[serde(rename = "maxMailboxDepth")]
    pub max_mailbox_depth: u64,
    #[serde(rename = "maxMailboxNameLength")]
    pub max_mailbox_name_length: u64,
    #[serde(rename = "encryptOnAppend")]
    pub encrypt_on_append: bool,
    #[serde(rename = "encryptAtRest")]
    pub encrypt_at_rest: bool,
    #[serde(rename = "compressionAlgorithm")]
    pub compression_algorithm: CompressionAlgo,
    #[serde(rename = "defaultFolders")]
    pub default_folders: VecMap<SpecialUse, EmailFolder>,
    #[serde(rename = "maxMessages")]
    pub max_messages: Option<u64>,
    #[serde(rename = "maxSubmissions")]
    pub max_submissions: Option<u64>,
    #[serde(rename = "maxIdentities")]
    pub max_identities: Option<u64>,
    #[serde(rename = "maxMailboxes")]
    pub max_mailboxes: Option<u64>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "maxMaskedAddresses")]
    pub max_masked_addresses: Option<u64>,
    // SPDX-SnippetEnd
    #[serde(rename = "maxPublicKeys")]
    pub max_public_keys: Option<u64>,
    #[serde(rename = "maxMailboxesPerEmail")]
    pub max_mailboxes_per_email: u64,
    #[serde(rename = "maxFlagsPerEmail")]
    pub max_flags_per_email: u64,
    #[serde(rename = "maxFlagLength")]
    pub max_flag_length: u64,
    #[serde(rename = "maxHeaderSize")]
    pub max_header_size: u64,
    #[serde(rename = "maxHeaderCount")]
    pub max_header_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailAlias {
    pub enable: bool,
    pub name: String,
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailFolder {
    pub name: String,
    pub create: bool,
    pub subscribe: bool,
    pub aliases: Map<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum EncryptionAtRest {
    Disabled,
    Aes128(EncryptionSettings),
    Aes256(EncryptionSettings),
    Aes256Gcm(EncryptionSettings),
    ChaCha20Poly1305(EncryptionSettings),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EncryptionSettings {
    #[serde(rename = "publicKey")]
    pub public_key: Id,
    #[serde(rename = "encryptOnAppend")]
    pub encrypt_on_append: bool,
    #[serde(rename = "allowSpamTraining")]
    pub allow_spam_training: bool,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Enterprise {
    #[serde(rename = "apiKey")]
    pub api_key: SecretKeyOptional,
    #[serde(rename = "licenseKey")]
    pub license_key: SecretKeyOptional,
    pub logo: Option<String>,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EventTracingLevel {
    pub event: trc::EventType,
    pub level: TracingLevelOpt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Expression {
    #[serde(rename = "match")]
    pub match_: List<ExpressionMatch>,
    #[serde(rename = "else")]
    pub else_: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExpressionMatch {
    #[serde(rename = "if")]
    pub if_: String,
    pub then: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileStorage {
    #[serde(rename = "maxSize")]
    pub max_size: u64,
    #[serde(rename = "maxFiles")]
    pub max_files: Option<u64>,
    #[serde(rename = "maxFolders")]
    pub max_folders: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileSystemStore {
    pub path: String,
    pub depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FoundationDbStore {
    #[serde(rename = "clusterFile")]
    pub cluster_file: Option<String>,
    #[serde(rename = "datacenterId")]
    pub datacenter_id: Option<String>,
    #[serde(rename = "machineId")]
    pub machine_id: Option<String>,
    #[serde(rename = "transactionRetryDelay")]
    pub transaction_retry_delay: Option<Duration>,
    #[serde(rename = "transactionRetryLimit")]
    pub transaction_retry_limit: Option<u64>,
    #[serde(rename = "transactionTimeout")]
    pub transaction_timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FtrlParameters {
    pub alpha: Float,
    pub beta: Float,
    #[serde(rename = "numFeatures")]
    pub num_features: ModelSize,
    #[serde(rename = "l1Ratio")]
    pub l1_ratio: Float,
    #[serde(rename = "l2Ratio")]
    pub l2_ratio: Float,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GroupAccount {
    pub name: String,
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    pub description: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub roles: Roles,
    pub quotas: VecMap<StorageQuota, u64>,
    pub permissions: Permissions,
    pub aliases: List<EmailAlias>,
    pub locale: Locale,
    #[serde(rename = "timeZone")]
    pub time_zone: Option<TimeZone>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Http {
    #[serde(rename = "rateLimitAuthenticated")]
    pub rate_limit_authenticated: Option<Rate>,
    #[serde(rename = "rateLimitAnonymous")]
    pub rate_limit_anonymous: Option<Rate>,
    #[serde(rename = "allowedEndpoints")]
    pub allowed_endpoints: Expression,
    #[serde(rename = "enableHsts")]
    pub enable_hsts: bool,
    #[serde(rename = "usePermissiveCors")]
    pub use_permissive_cors: bool,
    #[serde(rename = "responseHeaders")]
    pub response_headers: VecMap<String, String>,
    #[serde(rename = "clientIpSource")]
    pub client_ip_source: ClientIpSource,
    #[serde(rename = "forwardedHops")]
    pub forwarded_hops: u64,
    #[serde(rename = "redirectRoot")]
    pub redirect_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum HttpAuth {
    Unauthenticated,
    Basic(HttpAuthBasic),
    Bearer(HttpAuthBearer),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpAuthBasic {
    pub username: String,
    pub secret: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpAuthBearer {
    #[serde(rename = "bearerToken")]
    pub bearer_token: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpForm {
    #[serde(rename = "deliverTo")]
    pub deliver_to: Map<String>,
    #[serde(rename = "defaultFromAddress")]
    pub default_from_address: String,
    #[serde(rename = "fieldEmail")]
    pub field_email: Option<String>,
    pub enable: bool,
    #[serde(rename = "fieldHoneyPot")]
    pub field_honey_pot: Option<String>,
    #[serde(rename = "maxSize")]
    pub max_size: u64,
    #[serde(rename = "defaultName")]
    pub default_name: String,
    #[serde(rename = "fieldName")]
    pub field_name: Option<String>,
    #[serde(rename = "rateLimit")]
    pub rate_limit: Option<Rate>,
    #[serde(rename = "defaultSubject")]
    pub default_subject: String,
    #[serde(rename = "fieldSubject")]
    pub field_subject: Option<String>,
    #[serde(rename = "validateDomain")]
    pub validate_domain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpLookup {
    pub namespace: String,
    pub enable: bool,
    pub format: HttpLookupFormat,
    #[serde(rename = "isGzipped")]
    pub is_gzipped: bool,
    #[serde(rename = "maxEntries")]
    pub max_entries: u64,
    #[serde(rename = "maxEntrySize")]
    pub max_entry_size: u64,
    #[serde(rename = "maxSize")]
    pub max_size: u64,
    #[serde(rename = "refreshInterval")]
    pub refresh_interval: Duration,
    pub retry: Duration,
    pub url: String,
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpLookupCsv {
    #[serde(rename = "indexKey")]
    pub index_key: u64,
    #[serde(rename = "indexValue")]
    pub index_value: Option<u64>,
    pub separator: String,
    #[serde(rename = "skipFirst")]
    pub skip_first: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum HttpLookupFormat {
    Csv(HttpLookupCsv),
    List,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HurricaneCredential {
    pub zone: String,
    pub secret: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Imap {
    #[serde(rename = "allowPlainTextAuth")]
    pub allow_plain_text_auth: bool,
    #[serde(rename = "maxAuthFailures")]
    pub max_auth_failures: u64,
    #[serde(rename = "maxConcurrentConnections")]
    pub max_concurrent_connections: Option<u64>,
    #[serde(rename = "rateLimit")]
    pub rate_limit: Option<Rate>,
    #[serde(rename = "maxRequestSize")]
    pub max_request_size: u64,
    #[serde(rename = "anonymousTimeout")]
    pub anonymous_timeout: Duration,
    #[serde(rename = "authenticatedTimeout")]
    pub authenticated_timeout: Duration,
    #[serde(rename = "idleTimeout")]
    pub idle_timeout: Duration,
    #[serde(rename = "maxMessagesPerCommand")]
    pub max_messages_per_command: u64,
    #[serde(rename = "minUidBatchSize")]
    pub min_uid_batch_size: u64,
    #[serde(rename = "maxUidBatches")]
    pub max_uid_batches: u64,
    #[serde(rename = "maxMessagesPerSave")]
    pub max_messages_per_save: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum InMemoryStore {
    Default,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded(ShardedInMemoryStore),
    // SPDX-SnippetEnd
    Redis(RedisStore),
    RedisCluster(RedisClusterStore),
    RedisSentinel(RedisSentinelStore),
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum InMemoryStoreBase {
    Redis(RedisStore),
    RedisCluster(RedisClusterStore),
    RedisSentinel(RedisSentinelStore),
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IndexQueueStatus {
    pub index: IndexType,
    pub partition: u64,
    #[serde(rename = "queuedUpdates")]
    pub queued_updates: u64,
    #[serde(rename = "queuedDeletions")]
    pub queued_deletions: u64,
    pub status: IndexStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum IndexStatus {
    Running,
    Failed(IndexStatusFailed),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IndexStatusFailed {
    pub reason: String,
    #[serde(rename = "nextRetry")]
    pub next_retry: UTCDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Jmap {
    #[serde(rename = "parseLimitEvent")]
    pub parse_limit_event: u64,
    #[serde(rename = "parseLimitContact")]
    pub parse_limit_contact: u64,
    #[serde(rename = "parseLimitEmail")]
    pub parse_limit_email: u64,
    #[serde(rename = "maxChangesResults")]
    pub max_changes_results: u64,
    #[serde(rename = "maxGetResults")]
    pub max_get_results: u64,
    #[serde(rename = "maxQueryResults")]
    pub max_query_results: u64,
    #[serde(rename = "maxMethodCalls")]
    pub max_method_calls: u64,
    #[serde(rename = "maxConcurrentRequests")]
    pub max_concurrent_requests: Option<u64>,
    #[serde(rename = "maxRequestSize")]
    pub max_request_size: u64,
    #[serde(rename = "maxSetObjects")]
    pub max_set_objects: u64,
    #[serde(rename = "maxSnippetResults")]
    pub max_snippet_results: u64,
    #[serde(rename = "maxConcurrentUploads")]
    pub max_concurrent_uploads: Option<u64>,
    #[serde(rename = "maxUploadSize")]
    pub max_upload_size: u64,
    #[serde(rename = "maxUploadCount")]
    pub max_upload_count: u64,
    #[serde(rename = "uploadQuota")]
    pub upload_quota: u64,
    #[serde(rename = "uploadTtl")]
    pub upload_ttl: Duration,
    #[serde(rename = "eventSourceThrottle")]
    pub event_source_throttle: Duration,
    #[serde(rename = "pushAttemptWait")]
    pub push_attempt_wait: Duration,
    #[serde(rename = "maxPushAttempts")]
    pub max_push_attempts: u64,
    #[serde(rename = "pushRetryWait")]
    pub push_retry_wait: Duration,
    #[serde(rename = "pushThrottle")]
    pub push_throttle: Duration,
    #[serde(rename = "pushRequestTimeout")]
    pub push_request_timeout: Duration,
    #[serde(rename = "pushVerifyTimeout")]
    pub push_verify_timeout: Duration,
    #[serde(rename = "pushShardsTotal")]
    pub push_shards_total: u64,
    #[serde(rename = "websocketHeartbeat")]
    pub websocket_heartbeat: Duration,
    #[serde(rename = "websocketThrottle")]
    pub websocket_throttle: Duration,
    #[serde(rename = "websocketTimeout")]
    pub websocket_timeout: Duration,
    #[serde(rename = "maxSubscriptions")]
    pub max_subscriptions: Option<u64>,
    #[serde(rename = "webPushKey")]
    pub web_push_key: SecretTextOptional,
    #[serde(rename = "webPushContact")]
    pub web_push_contact: Option<String>,
    #[serde(rename = "maxPushSize")]
    pub max_push_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum JokerAuth {
    ApiKey(JokerAuthApiKey),
    UsernamePassword(JokerAuthUsernamePassword),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JokerAuthApiKey {
    #[serde(rename = "apiKey")]
    pub api_key: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JokerAuthUsernamePassword {
    pub username: String,
    pub password: SecretKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KafkaCoordinator {
    pub hosts: Map<String>,
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[serde(rename = "messageTimeout")]
    pub message_timeout: Duration,
    #[serde(rename = "sessionTimeout")]
    pub session_timeout: Duration,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LdapDirectory {
    pub description: String,
    pub url: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "urlFailover")]
    pub url_failover: Map<String>,
    // SPDX-SnippetEnd
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "baseDn")]
    pub base_dn: String,
    #[serde(rename = "bindDn")]
    pub bind_dn: Option<String>,
    #[serde(rename = "bindSecret")]
    pub bind_secret: SecretKeyOptional,
    #[serde(rename = "bindAuthentication")]
    pub bind_authentication: bool,
    #[serde(rename = "filterLogin")]
    pub filter_login: String,
    #[serde(rename = "filterRecipient")]
    pub filter_recipient: String,
    #[serde(rename = "filterMemberOf")]
    pub filter_member_of: Option<String>,
    #[serde(rename = "attrClass")]
    pub attr_class: Map<String>,
    #[serde(rename = "attrDescription")]
    pub attr_description: Map<String>,
    #[serde(rename = "attrEmail")]
    pub attr_email: Map<String>,
    #[serde(rename = "attrEmailAlias")]
    pub attr_email_alias: Map<String>,
    #[serde(rename = "attrMemberOf")]
    pub attr_member_of: Map<String>,
    #[serde(rename = "attrSecret")]
    pub attr_secret: Map<String>,
    #[serde(rename = "attrSecretChanged")]
    pub attr_secret_changed: Map<String>,
    #[serde(rename = "groupClass")]
    pub group_class: String,
    #[serde(rename = "poolMaxConnections")]
    pub pool_max_connections: u64,
    #[serde(rename = "poolTimeoutCreate")]
    pub pool_timeout_create: Duration,
    #[serde(rename = "poolTimeoutRecycle")]
    pub pool_timeout_recycle: Duration,
    #[serde(rename = "poolTimeoutWait")]
    pub pool_timeout_wait: Duration,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalFileSwap {
    pub path: String,
    #[serde(rename = "flushChanges")]
    pub flush_changes: u64,
    #[serde(rename = "flushInterval")]
    pub flush_interval: Duration,
    #[serde(rename = "maxAccountSize")]
    pub max_account_size: u64,
    #[serde(rename = "minAccountSize")]
    pub min_account_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Log {
    pub timestamp: UTCDateTime,
    pub level: TracingLevel,
    pub event: trc::EventType,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum LookupStore {
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
    Sqlite(SqliteStore),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    Sharded(ShardedInMemoryStore),
    // SPDX-SnippetEnd
    Redis(RedisStore),
    RedisCluster(RedisClusterStore),
    RedisSentinel(RedisSentinelStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MailExchanger {
    pub hostname: Option<String>,
    pub priority: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MailingList {
    pub name: String,
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    pub description: Option<String>,
    pub aliases: List<EmailAlias>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub recipients: Map<String>,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MaskedEmail {
    pub enable: bool,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    pub email: String,
    pub description: Option<String>,
    #[serde(rename = "forDomain")]
    pub for_domain: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "createdBy")]
    pub created_by: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
    pub url: Option<String>,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MeilisearchStore {
    pub url: String,
    #[serde(rename = "pollInterval")]
    pub poll_interval: Duration,
    #[serde(rename = "maxPolls")]
    pub max_polls: u64,
    #[serde(rename = "failOnTimeout")]
    pub fail_on_timeout: bool,
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryLookupKey {
    pub namespace: String,
    pub key: String,
    #[serde(rename = "isGlobPattern")]
    pub is_glob_pattern: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryLookupKeyValue {
    pub namespace: String,
    pub key: String,
    pub value: String,
    #[serde(rename = "isGlobPattern")]
    pub is_glob_pattern: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Metadata {
    #[serde(rename = "dataTypes")]
    pub data_types: Map<MetadataDataType>,
    #[serde(rename = "vendorNamespaces")]
    pub vendor_namespaces: bool,
    #[serde(rename = "privateMetadata")]
    pub private_metadata: bool,
    #[serde(rename = "maxDepth")]
    pub max_depth: Option<u64>,
    #[serde(rename = "maxEntrySize")]
    pub max_entry_size: u64,
    #[serde(rename = "maxSize")]
    pub max_size: u64,
    #[serde(rename = "maxPrivateSize")]
    pub max_private_size: u64,
    #[serde(rename = "maxEntries")]
    pub max_entries: u64,
    #[serde(rename = "maxQueryScan")]
    pub max_query_scan: u64,
    #[serde(rename = "imapServerComment")]
    pub imap_server_comment: Option<String>,
    #[serde(rename = "imapServerAdmin")]
    pub imap_server_admin: Option<String>,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Metric {
    Counter(MetricCount),
    Gauge(MetricCount),
    Histogram(MetricSum),
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricCount {
    pub count: u64,
    pub metric: trc::MetricType,
    #[serde(rename = "nodeId")]
    pub node_id: u64,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricSum {
    pub count: u64,
    pub sum: u64,
    pub metric: trc::MetricType,
    #[serde(rename = "nodeId")]
    pub node_id: u64,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Metrics {
    #[serde(rename = "openTelemetry")]
    pub open_telemetry: MetricsOtel,
    pub prometheus: MetricsPrometheus,
    pub metrics: Map<trc::MetricType>,
    #[serde(rename = "metricsPolicy")]
    pub metrics_policy: EventPolicy,
    #[serde(rename = "serviceName")]
    pub service_name: String,
    #[serde(rename = "serviceNamespace")]
    pub service_namespace: Option<String>,
    #[serde(rename = "resourceAttributes")]
    pub resource_attributes: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum MetricsOtel {
    Disabled,
    Http(MetricsOtelHttp),
    Grpc(MetricsOtelGrpc),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsOtelGrpc {
    pub url: Option<String>,
    pub interval: Duration,
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsOtelHttp {
    pub url: String,
    pub interval: Duration,
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum MetricsPrometheus {
    Disabled,
    Enabled(MetricsPrometheusProperties),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsPrometheusProperties {
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum MetricsStore {
    Disabled,
    Default,
    FoundationDb(FoundationDbStore),
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaConnectionIpHost {
    #[serde(rename = "ehloHostname")]
    pub ehlo_hostname: Option<String>,
    #[serde(rename = "localIp")]
    pub local_ip: IpAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaConnectionStrategy {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "ehloHostname")]
    pub ehlo_hostname: Option<String>,
    #[serde(rename = "localIps")]
    pub local_ips: List<MtaConnectionIpHost>,
    #[serde(rename = "connectTimeout")]
    pub connect_timeout: Duration,
    #[serde(rename = "dataTimeout")]
    pub data_timeout: Duration,
    #[serde(rename = "ehloTimeout")]
    pub ehlo_timeout: Duration,
    #[serde(rename = "greetingTimeout")]
    pub greeting_timeout: Duration,
    #[serde(rename = "mailFromTimeout")]
    pub mail_from_timeout: Duration,
    #[serde(rename = "rcptToTimeout")]
    pub rcpt_to_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum MtaDeliveryExpiration {
    Ttl(MtaDeliveryExpirationTtl),
    Attempts(MtaDeliveryExpirationAttempts),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaDeliveryExpirationAttempts {
    #[serde(rename = "maxAttempts")]
    pub max_attempts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaDeliveryExpirationTtl {
    pub expire: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaDeliverySchedule {
    pub name: String,
    pub description: Option<String>,
    pub expiry: MtaDeliveryExpiration,
    pub notify: MtaDeliveryScheduleIntervalsOrDefault,
    #[serde(rename = "queueId")]
    pub queue_id: Id,
    pub retry: MtaDeliveryScheduleIntervalsOrDefault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaDeliveryScheduleInterval {
    pub duration: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaDeliveryScheduleIntervals {
    pub intervals: List<MtaDeliveryScheduleInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum MtaDeliveryScheduleIntervalsOrDefault {
    Default,
    Custom(MtaDeliveryScheduleIntervals),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaExtensions {
    pub chunking: Expression,
    #[serde(rename = "deliverBy")]
    pub deliver_by: Expression,
    pub dsn: Expression,
    pub expn: Expression,
    #[serde(rename = "futureRelease")]
    pub future_release: Expression,
    #[serde(rename = "mtPriority")]
    pub mt_priority: Expression,
    #[serde(rename = "noSoliciting")]
    pub no_soliciting: Expression,
    pub pipelining: Expression,
    #[serde(rename = "requireTls")]
    pub require_tls: Expression,
    pub vrfy: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaHook {
    pub enable: Expression,
    #[serde(rename = "maxResponseSize")]
    pub max_response_size: u64,
    #[serde(rename = "tempFailOnError")]
    pub temp_fail_on_error: bool,
    pub stages: Map<MtaStage>,
    pub url: String,
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaInboundSession {
    #[serde(rename = "maxDuration")]
    pub max_duration: Expression,
    #[serde(rename = "idleTimeout")]
    pub idle_timeout: Expression,
    #[serde(rename = "transferLimit")]
    pub transfer_limit: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaInboundThrottle {
    pub enable: bool,
    pub description: String,
    pub key: Map<MtaInboundThrottleKey>,
    #[serde(rename = "match")]
    pub match_: Expression,
    pub rate: Rate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaMilter {
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    pub enable: Expression,
    pub host: String,
    #[serde(rename = "maxResponseSize")]
    pub max_response_size: u64,
    #[serde(rename = "tempFailOnError")]
    pub temp_fail_on_error: bool,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: MilterVersion,
    pub port: u64,
    pub stages: Map<MtaStage>,
    #[serde(rename = "commandTimeout")]
    pub command_timeout: Duration,
    #[serde(rename = "connectTimeout")]
    pub connect_timeout: Duration,
    #[serde(rename = "dataTimeout")]
    pub data_timeout: Duration,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "flagsAction")]
    pub flags_action: Option<u64>,
    #[serde(rename = "flagsProtocol")]
    pub flags_protocol: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaOutboundStrategy {
    pub connection: Expression,
    pub route: Expression,
    pub schedule: Expression,
    pub tls: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaOutboundThrottle {
    pub enable: bool,
    pub description: String,
    pub key: Map<MtaOutboundThrottleKey>,
    #[serde(rename = "match")]
    pub match_: Expression,
    pub rate: Rate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaQueueQuota {
    pub enable: bool,
    pub description: Option<String>,
    pub key: Map<MtaQueueQuotaKey>,
    #[serde(rename = "match")]
    pub match_: Expression,
    pub messages: Option<u64>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum MtaRoute {
    Mx(MtaRouteMx),
    Relay(MtaRouteRelay),
    Local(MtaRouteCommon),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaRouteCommon {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaRouteMx {
    #[serde(rename = "ipLookupStrategy")]
    pub ip_lookup_strategy: MtaIpStrategy,
    #[serde(rename = "maxMultihomed")]
    pub max_multihomed: u64,
    #[serde(rename = "maxMxHosts")]
    pub max_mx_hosts: u64,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaRouteRelay {
    pub host: String,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    pub port: u64,
    pub protocol: MtaProtocol,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "implicitTls")]
    pub implicit_tls: bool,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaStageAuth {
    #[serde(rename = "maxFailures")]
    pub max_failures: Expression,
    #[serde(rename = "waitOnFail")]
    pub wait_on_fail: Expression,
    #[serde(rename = "saslMechanisms")]
    pub sasl_mechanisms: Expression,
    #[serde(rename = "mustMatchSender")]
    pub must_match_sender: Expression,
    pub require: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaStageConnect {
    #[serde(rename = "smtpGreeting")]
    pub smtp_greeting: Expression,
    pub hostname: Expression,
    pub script: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaStageData {
    #[serde(rename = "addAuthResultsHeader")]
    pub add_auth_results_header: Expression,
    #[serde(rename = "addDateHeader")]
    pub add_date_header: Expression,
    #[serde(rename = "addDeliveredToHeader")]
    pub add_delivered_to_header: bool,
    #[serde(rename = "addMessageIdHeader")]
    pub add_message_id_header: Expression,
    #[serde(rename = "addReceivedHeader")]
    pub add_received_header: Expression,
    #[serde(rename = "addReceivedSpfHeader")]
    pub add_received_spf_header: Expression,
    #[serde(rename = "addReturnPathHeader")]
    pub add_return_path_header: Expression,
    #[serde(rename = "maxMessages")]
    pub max_messages: Expression,
    #[serde(rename = "maxReceivedHeaders")]
    pub max_received_headers: Expression,
    #[serde(rename = "maxMessageSize")]
    pub max_message_size: Expression,
    pub script: Expression,
    #[serde(rename = "enableSpamFilter")]
    pub enable_spam_filter: Expression,
    #[serde(rename = "dkimSignDomain")]
    pub dkim_sign_domain: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaStageEhlo {
    #[serde(rename = "rejectNonFqdn")]
    pub reject_non_fqdn: Expression,
    pub require: Expression,
    pub script: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaStageMail {
    #[serde(rename = "isSenderAllowed")]
    pub is_sender_allowed: Expression,
    pub rewrite: Expression,
    pub script: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaStageRcpt {
    #[serde(rename = "maxFailures")]
    pub max_failures: Expression,
    #[serde(rename = "waitOnFail")]
    pub wait_on_fail: Expression,
    #[serde(rename = "maxRecipients")]
    pub max_recipients: Expression,
    #[serde(rename = "allowRelaying")]
    pub allow_relaying: Expression,
    pub rewrite: Expression,
    pub script: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaSts {
    #[serde(rename = "maxAge")]
    pub max_age: Duration,
    pub mode: PolicyEnforcement,
    #[serde(rename = "mxHosts")]
    pub mx_hosts: Map<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaTlsStrategy {
    pub name: String,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    pub dane: MtaRequiredOrOptional,
    pub description: Option<String>,
    #[serde(rename = "mtaSts")]
    pub mta_sts: MtaRequiredOrOptional,
    #[serde(rename = "startTls")]
    pub start_tls: MtaRequiredOrOptional,
    #[serde(rename = "mtaStsTimeout")]
    pub mta_sts_timeout: Duration,
    #[serde(rename = "tlsTimeout")]
    pub tls_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MtaVirtualQueue {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "threadsPerNode")]
    pub threads_per_node: u64,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MySqlSettings {
    pub host: String,
    pub port: u64,
    pub database: String,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MySqlStore {
    #[serde(rename = "idleTimeout")]
    pub idle_timeout: Option<Duration>,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "maxAllowedPacket")]
    pub max_allowed_packet: Option<u64>,
    #[serde(rename = "poolMaxConnections")]
    pub pool_max_connections: Option<u64>,
    #[serde(rename = "poolMinConnections")]
    pub pool_min_connections: Option<u64>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "readReplicas")]
    pub read_replicas: List<MySqlSettings>,
    // SPDX-SnippetEnd
    pub host: String,
    pub port: u64,
    pub database: String,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NatsCoordinator {
    pub hosts: Map<String>,
    #[serde(rename = "maxReconnects")]
    pub max_reconnects: Option<u64>,
    #[serde(rename = "connectTimeout")]
    pub connect_timeout: Duration,
    #[serde(rename = "requestTimeout")]
    pub request_timeout: Duration,
    #[serde(rename = "pingInterval")]
    pub ping_interval: Duration,
    #[serde(rename = "clientCapacity")]
    pub client_capacity: u64,
    #[serde(rename = "readBufferCapacity")]
    pub read_buffer_capacity: u64,
    #[serde(rename = "subscriptionCapacity")]
    pub subscription_capacity: u64,
    #[serde(rename = "noEcho")]
    pub no_echo: bool,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    pub credentials: SecretTextOptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkListener {
    pub name: String,
    pub bind: Map<SocketAddr>,
    pub protocol: NetworkListenerProtocol,
    #[serde(rename = "overrideProxyTrustedNetworks")]
    pub override_proxy_trusted_networks: Map<IpAddrOrMask>,
    #[serde(rename = "socketBacklog")]
    pub socket_backlog: Option<u64>,
    #[serde(rename = "socketNoDelay")]
    pub socket_no_delay: bool,
    #[serde(rename = "socketReceiveBufferSize")]
    pub socket_receive_buffer_size: Option<u64>,
    #[serde(rename = "socketReuseAddress")]
    pub socket_reuse_address: bool,
    #[serde(rename = "socketReusePort")]
    pub socket_reuse_port: bool,
    #[serde(rename = "socketSendBufferSize")]
    pub socket_send_buffer_size: Option<u64>,
    #[serde(rename = "socketTosV4")]
    pub socket_tos_v4: Option<u64>,
    #[serde(rename = "socketTtl")]
    pub socket_ttl: Option<u64>,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "tlsDisableCipherSuites")]
    pub tls_disable_cipher_suites: Map<TlsCipherSuite>,
    #[serde(rename = "tlsDisableProtocols")]
    pub tls_disable_protocols: Map<TlsVersion>,
    #[serde(rename = "tlsIgnoreClientOrder")]
    pub tls_ignore_client_order: bool,
    #[serde(rename = "implicitTls")]
    pub implicit_tls: bool,
    #[serde(rename = "tlsTimeout")]
    pub tls_timeout: Option<Duration>,
    #[serde(rename = "maxConnections")]
    pub max_connections: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthClient {
    #[serde(rename = "clientId")]
    pub client_id: String,
    pub description: Option<String>,
    pub contacts: Map<String>,
    pub secret: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Map<String>,
    #[serde(rename = "postLogoutRedirectUris")]
    pub post_logout_redirect_uris: Map<String>,
    pub logo: Option<String>,
    #[serde(rename = "firstParty")]
    pub first_party: bool,
    pub scopes: Map<OAuthScope>,
    #[serde(rename = "grantTypes")]
    pub grant_types: Map<OAuthGrantType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthGrant {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[serde(rename = "clientHash")]
    pub client_hash: String,
    #[serde(rename = "clientName")]
    pub client_name: Option<String>,
    #[serde(rename = "clientKind")]
    pub client_kind: OAuthClientKind,
    pub scopes: Map<OAuthScope>,
    #[serde(rename = "remoteIp")]
    pub remote_ip: Option<IpAddr>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: UTCDateTime,
    pub generation: u64,
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcDirectory {
    pub description: String,
    #[serde(rename = "issuerUrl")]
    pub issuer_url: String,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "claimUsername")]
    pub claim_username: String,
    #[serde(rename = "usernameDomain")]
    pub username_domain: Option<String>,
    #[serde(rename = "claimName")]
    pub claim_name: Option<String>,
    #[serde(rename = "claimGroups")]
    pub claim_groups: Option<String>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    #[serde(rename = "acceptedAudiences")]
    pub accepted_audiences: Map<String>,
    #[serde(rename = "opaqueTokenValidation")]
    pub opaque_token_validation: OidcOpaqueTokenValidation,
    #[serde(rename = "introspectionClientId")]
    pub introspection_client_id: Option<String>,
    #[serde(rename = "introspectionClientSecret")]
    pub introspection_client_secret: SecretKeyOptional,
    #[serde(rename = "introspectionAuthMethod")]
    pub introspection_auth_method: OidcIntrospectionAuth,
    #[serde(rename = "unscopedTokens")]
    pub unscoped_tokens: OidcUnscopedTokenPolicy,
    #[serde(rename = "skipAudienceValidation")]
    pub skip_audience_validation: bool,
    #[serde(rename = "allowIdTokenClaims")]
    pub allow_id_token_claims: bool,
    #[serde(rename = "lenientIssuerMatch")]
    pub lenient_issuer_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcProvider {
    #[serde(rename = "authCodeExpiry")]
    pub auth_code_expiry: Duration,
    #[serde(rename = "refreshTokenExpiry")]
    pub refresh_token_expiry: Duration,
    #[serde(rename = "accessTokenExpiry")]
    pub access_token_expiry: Duration,
    #[serde(rename = "userCodeExpiry")]
    pub user_code_expiry: Duration,
    #[serde(rename = "idTokenExpiry")]
    pub id_token_expiry: Duration,
    #[serde(rename = "encryptionKey")]
    pub encryption_key: SecretKey,
    #[serde(rename = "signatureAlgorithm")]
    pub signature_algorithm: JwtSignatureAlgorithm,
    #[serde(rename = "signatureKey")]
    pub signature_key: SecretText,
    #[serde(rename = "clientMetadataDocuments")]
    pub client_metadata_documents: OAuthClientMetadataPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OtpAuth {
    #[serde(rename = "otpCode")]
    pub otp_code: Option<String>,
    #[serde(rename = "otpUrl")]
    pub otp_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordCredential {
    #[serde(rename = "credentialId")]
    pub credential_id: Id,
    pub secret: String,
    #[serde(rename = "otpUrl")]
    pub otp_url: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
    #[serde(rename = "allowedIps")]
    pub allowed_ips: Map<IpAddrOrMask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Permissions {
    Inherit,
    Merge(PermissionsList),
    Replace(PermissionsList),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PermissionsList {
    #[serde(rename = "enabledPermissions")]
    pub enabled_permissions: Map<Permission>,
    #[serde(rename = "disabledPermissions")]
    pub disabled_permissions: Map<Permission>,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PostgreSqlSettings {
    pub host: String,
    pub port: u64,
    pub database: String,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
    pub options: Option<String>,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PostgreSqlStore {
    #[serde(rename = "connectTimeout")]
    pub connect_timeout: Option<Duration>,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "poolMaxConnections")]
    pub pool_max_connections: Option<u64>,
    #[serde(rename = "poolRecyclingMethod")]
    pub pool_recycling_method: PostgreSqlRecyclingMethod,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "readReplicas")]
    pub read_replicas: List<PostgreSqlSettings>,
    // SPDX-SnippetEnd
    pub host: String,
    pub port: u64,
    pub database: String,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
    pub options: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PublicKey {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    pub key: String,
    pub description: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
    #[serde(rename = "emailAddresses")]
    pub email_addresses: Map<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum PublicStringOptional {
    None,
    Value(PublicStringValue),
    EnvironmentVariable(SecretKeyEnvironmentVariable),
    File(SecretKeyFile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PublicStringValue {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum PublicText {
    Text(PublicTextValue),
    EnvironmentVariable(SecretKeyEnvironmentVariable),
    File(SecretKeyFile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PublicTextValue {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum QueueExpiry {
    Ttl(QueueExpiryTtl),
    Attempts(QueueExpiryAttempts),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueExpiryAttempts {
    #[serde(rename = "expiresAttempts")]
    pub expires_attempts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueExpiryTtl {
    #[serde(rename = "expiresAt")]
    pub expires_at: UTCDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueuedMessage {
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "nextRetry")]
    pub next_retry: Option<UTCDateTime>,
    #[serde(rename = "nextNotify")]
    pub next_notify: Option<UTCDateTime>,
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
    #[serde(rename = "returnPath")]
    pub return_path: String,
    pub recipients: VecMap<String, QueuedRecipient>,
    #[serde(rename = "receivedFromIp")]
    pub received_from_ip: IpAddr,
    #[serde(rename = "receivedViaPort")]
    pub received_via_port: u64,
    pub flags: Map<MessageFlag>,
    #[serde(rename = "envId")]
    pub env_id: Option<String>,
    pub priority: i64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueuedRecipient {
    #[serde(rename = "retryCount")]
    pub retry_count: u64,
    #[serde(rename = "retryDue")]
    pub retry_due: UTCDateTime,
    #[serde(rename = "notifyCount")]
    pub notify_count: u64,
    #[serde(rename = "notifyDue")]
    pub notify_due: UTCDateTime,
    pub expires: QueueExpiry,
    #[serde(rename = "queueName")]
    pub queue_name: String,
    pub status: RecipientStatus,
    pub flags: Map<RecipientFlag>,
    pub orcpt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rate {
    pub count: u64,
    pub period: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum RecipientStatus {
    Scheduled,
    Completed(ServerResponse),
    TemporaryFailure(DeliveryError),
    PermanentFailure(DeliveryError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisClusterStore {
    pub urls: Map<String>,
    #[serde(rename = "connectTimeout")]
    pub connect_timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
    #[serde(rename = "maxRetryWait")]
    pub max_retry_wait: Option<Duration>,
    #[serde(rename = "minRetryWait")]
    pub min_retry_wait: Option<Duration>,
    #[serde(rename = "maxRetries")]
    pub max_retries: Option<u64>,
    #[serde(rename = "readFromReplicas")]
    pub read_from_replicas: bool,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: RedisProtocol,
    #[serde(rename = "poolMaxConnections")]
    pub pool_max_connections: u64,
    #[serde(rename = "poolTimeoutCreate")]
    pub pool_timeout_create: Option<Duration>,
    #[serde(rename = "poolTimeoutWait")]
    pub pool_timeout_wait: Option<Duration>,
    #[serde(rename = "poolTimeoutRecycle")]
    pub pool_timeout_recycle: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisSentinelStore {
    pub urls: Map<String>,
    #[serde(rename = "serviceName")]
    pub service_name: String,
    #[serde(rename = "connectTimeout")]
    pub connect_timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "authUsername")]
    pub auth_username: Option<String>,
    #[serde(rename = "authSecret")]
    pub auth_secret: SecretKeyOptional,
    #[serde(rename = "sentinelUsername")]
    pub sentinel_username: Option<String>,
    #[serde(rename = "sentinelSecret")]
    pub sentinel_secret: SecretKeyOptional,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: RedisProtocol,
    #[serde(rename = "poolMaxConnections")]
    pub pool_max_connections: u64,
    #[serde(rename = "poolTimeoutCreate")]
    pub pool_timeout_create: Option<Duration>,
    #[serde(rename = "poolTimeoutWait")]
    pub pool_timeout_wait: Option<Duration>,
    #[serde(rename = "poolTimeoutRecycle")]
    pub pool_timeout_recycle: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisStore {
    pub url: String,
    #[serde(rename = "connectTimeout")]
    pub connect_timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "poolMaxConnections")]
    pub pool_max_connections: u64,
    #[serde(rename = "poolTimeoutCreate")]
    pub pool_timeout_create: Option<Duration>,
    #[serde(rename = "poolTimeoutWait")]
    pub pool_timeout_wait: Option<Duration>,
    #[serde(rename = "poolTimeoutRecycle")]
    pub pool_timeout_recycle: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisSwap {
    pub store: RedisSwapStore,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u64,
    pub retention: Duration,
    #[serde(rename = "flushChanges")]
    pub flush_changes: u64,
    #[serde(rename = "flushInterval")]
    pub flush_interval: Duration,
    #[serde(rename = "maxAccountSize")]
    pub max_account_size: u64,
    #[serde(rename = "minAccountSize")]
    pub min_account_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum RedisSwapStore {
    Default,
    Redis(RedisStore),
    RedisCluster(RedisClusterStore),
    RedisSentinel(RedisSentinelStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReloadSettingsResult {
    pub warnings: Map<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportSettings {
    #[serde(rename = "inboundReportAddresses")]
    pub inbound_report_addresses: Map<String>,
    #[serde(rename = "inboundReportForwarding")]
    pub inbound_report_forwarding: bool,
    #[serde(rename = "outboundReportDomain")]
    pub outbound_report_domain: Option<String>,
    #[serde(rename = "outboundReportSubmitter")]
    pub outbound_report_submitter: Expression,
    #[serde(rename = "maxInboundReportSize")]
    pub max_inbound_report_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RocksDbStore {
    pub path: String,
    #[serde(rename = "blobSize")]
    pub blob_size: u64,
    #[serde(rename = "bufferSize")]
    pub buffer_size: u64,
    #[serde(rename = "poolWorkers")]
    pub pool_workers: Option<u64>,
    #[serde(rename = "cacheSize")]
    pub cache_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Role {
    pub description: String,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    #[serde(rename = "roleIds")]
    pub role_ids: Map<Id>,
    #[serde(rename = "enabledPermissions")]
    pub enabled_permissions: Map<Permission>,
    #[serde(rename = "disabledPermissions")]
    pub disabled_permissions: Map<Permission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Roles {
    Default,
    Custom(CustomRoles),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct S3Store {
    pub region: S3StoreRegion,
    pub bucket: String,
    #[serde(rename = "accessKeyId")]
    pub access_key_id: PublicStringOptional,
    #[serde(rename = "secretKey")]
    pub secret_key: SecretKeyOptional,
    #[serde(rename = "sessionToken")]
    pub session_token: SecretKeyOptional,
    pub profile: Option<String>,
    pub timeout: Duration,
    #[serde(rename = "maxRetries")]
    pub max_retries: u64,
    #[serde(rename = "keyPrefix")]
    pub key_prefix: Option<String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "verifyAfterWrite")]
    pub verify_after_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct S3StoreCustomRegion {
    pub url: String,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum S3StoreRegion {
    UsEast1,
    UsEast2,
    UsWest1,
    UsWest2,
    CaCentral1,
    AfSouth1,
    ApEast1,
    ApSouth1,
    ApNortheast1,
    ApNortheast2,
    ApNortheast3,
    ApSoutheast1,
    ApSoutheast2,
    CnNorth1,
    CnNorthwest1,
    EuNorth1,
    EuCentral1,
    EuCentral2,
    EuWest1,
    EuWest2,
    EuWest3,
    IlCentral1,
    MeSouth1,
    SaEast1,
    DoNyc3,
    DoAms3,
    DoSgp1,
    DoFra1,
    Yandex,
    WaUsEast1,
    WaUsEast2,
    WaUsCentral1,
    WaUsWest1,
    WaCaCentral1,
    WaEuCentral1,
    WaEuCentral2,
    WaEuWest1,
    WaEuWest2,
    WaApNortheast1,
    WaApNortheast2,
    WaApSoutheast1,
    WaApSoutheast2,
    Custom(S3StoreCustomRegion),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Search {
    #[serde(rename = "indexBatchSize")]
    pub index_batch_size: u64,
    #[serde(rename = "defaultLanguage")]
    pub default_language: Locale,
    #[serde(rename = "supportedLanguages")]
    pub supported_languages: Map<Locale>,
    #[serde(rename = "indexCalendar")]
    pub index_calendar: bool,
    #[serde(rename = "indexCalendarFields")]
    pub index_calendar_fields: Map<SearchCalendarField>,
    #[serde(rename = "indexContacts")]
    pub index_contacts: bool,
    #[serde(rename = "indexContactFields")]
    pub index_contact_fields: Map<SearchContactField>,
    #[serde(rename = "indexEmail")]
    pub index_email: bool,
    #[serde(rename = "indexEmailFields")]
    pub index_email_fields: Map<SearchEmailField>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "indexTelemetry")]
    pub index_telemetry: bool,
    // SPDX-SnippetEnd
    #[serde(rename = "maxConcurrentIndexTasks")]
    pub max_concurrent_index_tasks: u64,
    #[serde(rename = "indexFiles")]
    pub index_files: bool,
    #[serde(rename = "maxExtractDocumentSize")]
    pub max_extract_document_size: u64,
    #[serde(rename = "maxExtractTextSize")]
    pub max_extract_text_size: u64,
    #[serde(rename = "maxExtractDecompressedSize")]
    pub max_extract_decompressed_size: u64,
    #[serde(rename = "maxExtractPartSize")]
    pub max_extract_part_size: u64,
    #[serde(rename = "maxExtractParts")]
    pub max_extract_parts: u64,
    #[serde(rename = "maxExtractArchiveEntries")]
    pub max_extract_archive_entries: u64,
    #[serde(rename = "maxExtractPdfObjects")]
    pub max_extract_pdf_objects: u64,
    #[serde(rename = "maxExtractRtfDepth")]
    pub max_extract_rtf_depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SearchStore {
    Default,
    ElasticSearch(ElasticSearchStore),
    Meilisearch(MeilisearchStore),
    FoundationDb(FoundationDbStore),
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecondaryCredential {
    #[serde(rename = "credentialId")]
    pub credential_id: Id,
    pub description: String,
    pub secret: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<UTCDateTime>,
    pub permissions: CredentialPermissions,
    #[serde(rename = "allowedIps")]
    pub allowed_ips: Map<IpAddrOrMask>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SecretKey {
    Value(SecretKeyValue),
    EnvironmentVariable(SecretKeyEnvironmentVariable),
    File(SecretKeyFile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretKeyEnvironmentVariable {
    #[serde(rename = "variableName")]
    pub variable_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretKeyFile {
    #[serde(rename = "filePath")]
    pub file_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SecretKeyOptional {
    None,
    Value(SecretKeyValue),
    EnvironmentVariable(SecretKeyEnvironmentVariable),
    File(SecretKeyFile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretKeyValue {
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SecretText {
    Text(SecretTextValue),
    EnvironmentVariable(SecretKeyEnvironmentVariable),
    File(SecretKeyFile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SecretTextOptional {
    None,
    Text(SecretTextValue),
    EnvironmentVariable(SecretKeyEnvironmentVariable),
    File(SecretKeyFile),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretTextValue {
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    #[serde(rename = "abuseBanRate")]
    pub abuse_ban_rate: Option<Rate>,
    #[serde(rename = "abuseBanPeriod")]
    pub abuse_ban_period: Option<Duration>,
    #[serde(rename = "authBanRate")]
    pub auth_ban_rate: Option<Rate>,
    #[serde(rename = "authBanPeriod")]
    pub auth_ban_period: Option<Duration>,
    #[serde(rename = "loiterBanRate")]
    pub loiter_ban_rate: Option<Rate>,
    #[serde(rename = "loiterBanPeriod")]
    pub loiter_ban_period: Option<Duration>,
    #[serde(rename = "scanBanPaths")]
    pub scan_ban_paths: Map<String>,
    #[serde(rename = "scanBanRate")]
    pub scan_ban_rate: Option<Rate>,
    #[serde(rename = "scanBanPeriod")]
    pub scan_ban_period: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SenderAuth {
    #[serde(rename = "dkimStrict")]
    pub dkim_strict: bool,
    #[serde(rename = "dkimVerify")]
    pub dkim_verify: Expression,
    #[serde(rename = "spfEhloVerify")]
    pub spf_ehlo_verify: Expression,
    #[serde(rename = "spfFromVerify")]
    pub spf_from_verify: Expression,
    #[serde(rename = "arcVerify")]
    pub arc_verify: Expression,
    #[serde(rename = "dmarcVerify")]
    pub dmarc_verify: Expression,
    #[serde(rename = "reverseIpVerify")]
    pub reverse_ip_verify: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerResponse {
    #[serde(rename = "responseHostname")]
    pub response_hostname: Option<String>,
    #[serde(rename = "responseCode")]
    pub response_code: Option<u64>,
    #[serde(rename = "responseEnhanced")]
    pub response_enhanced: Option<String>,
    #[serde(rename = "responseMessage")]
    pub response_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Service {
    pub hostname: Option<String>,
    pub cleartext: bool,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShardedBlobStore {
    pub stores: List<BlobStoreBase>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShardedInMemoryStore {
    pub stores: List<InMemoryStoreBase>,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Sharing {
    #[serde(rename = "allowDirectoryQueries")]
    pub allow_directory_queries: bool,
    #[serde(rename = "maxShares")]
    pub max_shares: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SieveSystemInterpreter {
    #[serde(rename = "defaultFromAddress")]
    pub default_from_address: Expression,
    #[serde(rename = "defaultFromName")]
    pub default_from_name: Expression,
    #[serde(rename = "messageIdHostname")]
    pub message_id_hostname: Option<String>,
    #[serde(rename = "noCapabilityCheck")]
    pub no_capability_check: bool,
    #[serde(rename = "defaultReturnPath")]
    pub default_return_path: Expression,
    #[serde(rename = "dkimSignDomain")]
    pub dkim_sign_domain: Expression,
    #[serde(rename = "maxCpuCycles")]
    pub max_cpu_cycles: u64,
    #[serde(rename = "maxNestedIncludes")]
    pub max_nested_includes: u64,
    #[serde(rename = "maxOutMessages")]
    pub max_out_messages: u64,
    #[serde(rename = "maxReceivedHeaders")]
    pub max_received_headers: u64,
    #[serde(rename = "maxRedirects")]
    pub max_redirects: u64,
    #[serde(rename = "maxVarSize")]
    pub max_var_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SieveSystemScript {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "isActive")]
    pub is_active: bool,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SieveUserInterpreter {
    #[serde(rename = "defaultExpiryDuplicate")]
    pub default_expiry_duplicate: Duration,
    #[serde(rename = "defaultExpiryVacation")]
    pub default_expiry_vacation: Duration,
    #[serde(rename = "disableCapabilities")]
    pub disable_capabilities: Map<SieveCapability>,
    #[serde(rename = "allowedNotifyUris")]
    pub allowed_notify_uris: Map<String>,
    #[serde(rename = "protectedHeaders")]
    pub protected_headers: Map<String>,
    #[serde(rename = "defaultSubject")]
    pub default_subject: String,
    #[serde(rename = "defaultSubjectPrefix")]
    pub default_subject_prefix: String,
    #[serde(rename = "maxCpuCycles")]
    pub max_cpu_cycles: u64,
    #[serde(rename = "maxHeaderSize")]
    pub max_header_size: u64,
    #[serde(rename = "maxIncludes")]
    pub max_includes: u64,
    #[serde(rename = "maxLocalVars")]
    pub max_local_vars: u64,
    #[serde(rename = "maxMatchVars")]
    pub max_match_vars: u64,
    #[serde(rename = "maxScriptNameLength")]
    pub max_script_name_length: u64,
    #[serde(rename = "maxNestedBlocks")]
    pub max_nested_blocks: u64,
    #[serde(rename = "maxNestedForEvery")]
    pub max_nested_for_every: u64,
    #[serde(rename = "maxNestedIncludes")]
    pub max_nested_includes: u64,
    #[serde(rename = "maxNestedTests")]
    pub max_nested_tests: u64,
    #[serde(rename = "maxOutMessages")]
    pub max_out_messages: u64,
    #[serde(rename = "maxReceivedHeaders")]
    pub max_received_headers: u64,
    #[serde(rename = "maxRedirects")]
    pub max_redirects: u64,
    #[serde(rename = "maxScriptSize")]
    pub max_script_size: u64,
    #[serde(rename = "maxStringLength")]
    pub max_string_length: u64,
    #[serde(rename = "maxVarNameLength")]
    pub max_var_name_length: u64,
    #[serde(rename = "maxVarSize")]
    pub max_var_size: u64,
    #[serde(rename = "maxScripts")]
    pub max_scripts: Option<u64>,
    #[serde(rename = "dkimSignDomain")]
    pub dkim_sign_domain: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SieveUserScript {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "isActive")]
    pub is_active: bool,
    pub contents: String,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SpamAi {
    Disable,
    Enable(SpamAiProperties),
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamAiCategory {
    pub name: String,
    pub description: String,
    pub includes: Map<String>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SpamAiLearn {
    Disable,
    Enable(SpamAiLearnProperties),
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamAiLearnProperties {
    #[serde(rename = "minProbability")]
    pub min_probability: Float,
    #[serde(rename = "sampleRate")]
    pub sample_rate: Float,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamAiProperties {
    pub mode: SpamAiMode,
    pub condition: Expression,
    pub tiers: List<SpamAiTier>,
    pub instructions: String,
    pub categories: List<SpamAiCategory>,
    pub signals: List<SpamAiSignal>,
    #[serde(rename = "bucketHigh")]
    pub bucket_high: Float,
    #[serde(rename = "bucketMedium")]
    pub bucket_medium: Float,
    #[serde(rename = "uncertainBelow")]
    pub uncertain_below: Float,
    #[serde(rename = "verbalHigh")]
    pub verbal_high: Float,
    #[serde(rename = "verbalMedium")]
    pub verbal_medium: Float,
    #[serde(rename = "verbalLow")]
    pub verbal_low: Float,
    pub explanation: bool,
    #[serde(rename = "addHeader")]
    pub add_header: bool,
    #[serde(rename = "maxInputChars")]
    pub max_input_chars: u64,
    #[serde(rename = "maxLinks")]
    pub max_links: u64,
    #[serde(rename = "maxAttachments")]
    pub max_attachments: u64,
    #[serde(rename = "trimQuotes")]
    pub trim_quotes: bool,
    #[serde(rename = "includeAuth")]
    pub include_auth: bool,
    #[serde(rename = "includeLinks")]
    pub include_links: bool,
    #[serde(rename = "includeAttachments")]
    pub include_attachments: bool,
    pub deadline: Duration,
    #[serde(rename = "breakerThreshold")]
    pub breaker_threshold: u64,
    #[serde(rename = "breakerCooldown")]
    pub breaker_cooldown: Duration,
    pub learn: SpamAiLearn,
    #[serde(rename = "webSearch")]
    pub web_search: SpamAiWebSearch,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamAiSignal {
    pub name: String,
    pub question: String,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamAiTier {
    #[serde(rename = "modelId")]
    pub model_id: Id,
    #[serde(rename = "escalateBelow")]
    pub escalate_below: Float,
    #[serde(rename = "escalateOn")]
    pub escalate_on: Map<String>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SpamAiWebSearch {
    Disable,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamClassifier {
    pub model: SpamClassifierModel,
    #[serde(rename = "learnHamFromCard")]
    pub learn_ham_from_card: bool,
    #[serde(rename = "learnSpamFromRblHits")]
    pub learn_spam_from_rbl_hits: u64,
    #[serde(rename = "learnSpamFromTraps")]
    pub learn_spam_from_traps: bool,
    #[serde(rename = "holdSamplesFor")]
    pub hold_samples_for: Duration,
    #[serde(rename = "minHamSamples")]
    pub min_ham_samples: u64,
    #[serde(rename = "minSpamSamples")]
    pub min_spam_samples: u64,
    #[serde(rename = "reservoirCapacity")]
    pub reservoir_capacity: u64,
    #[serde(rename = "trainInterval")]
    pub train_interval: Option<Duration>,
    #[serde(rename = "learnHamFromReply")]
    pub learn_ham_from_reply: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamClassifierFtrlCcfh {
    #[serde(rename = "indicatorParameters")]
    pub indicator_parameters: FtrlParameters,
    pub parameters: FtrlParameters,
    #[serde(rename = "featureL2Normalize")]
    pub feature_l2_normalize: bool,
    #[serde(rename = "featureLogScale")]
    pub feature_log_scale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamClassifierFtrlFh {
    pub parameters: FtrlParameters,
    #[serde(rename = "featureL2Normalize")]
    pub feature_l2_normalize: bool,
    #[serde(rename = "featureLogScale")]
    pub feature_log_scale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SpamClassifierModel {
    FtrlFh(SpamClassifierFtrlFh),
    FtrlCcfh(SpamClassifierFtrlCcfh),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamClassify {
    pub message: String,
    #[serde(rename = "remoteIp")]
    pub remote_ip: IpAddr,
    #[serde(rename = "ehloDomain")]
    pub ehlo_domain: String,
    #[serde(rename = "authenticatedAs")]
    pub authenticated_as: Option<String>,
    #[serde(rename = "isTls")]
    pub is_tls: bool,
    #[serde(rename = "mailFrom")]
    pub mail_from: String,
    #[serde(rename = "mailFromParameters")]
    pub mail_from_parameters: Option<SpamClassifyParameters>,
    #[serde(rename = "rcptTo")]
    pub rcpt_to: Map<String>,
    pub score: Float,
    pub tags: VecMap<String, SpamClassifyTag>,
    pub result: SpamClassifyResult,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "aiGate")]
    pub ai_gate: Option<String>,
    #[cfg(feature = "enterprise")]
    #[serde(rename = "aiFacts")]
    pub ai_facts: Option<String>,
    #[cfg(feature = "enterprise")]
    #[serde(rename = "aiVerdict")]
    pub ai_verdict: Option<String>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamClassifyTag {
    pub score: Float,
    pub disposition: SpamClassifyTagDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SpamDnsblServer {
    Any(SpamDnsblServerAny),
    Url(SpamDnsblServerUrl),
    Domain(SpamDnsblServerDomain),
    Email(SpamDnsblServerEmail),
    Ip(SpamDnsblServerIp),
    Header(SpamDnsblServerHeader),
    Body(SpamDnsblServerBody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblServerAny {
    pub tag: Expression,
    pub zone: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblServerBody {
    pub tag: Expression,
    pub zone: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblServerDomain {
    pub tag: Expression,
    pub zone: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblServerEmail {
    pub tag: Expression,
    pub zone: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblServerHeader {
    pub tag: Expression,
    pub zone: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblServerIp {
    pub tag: Expression,
    pub zone: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblServerUrl {
    pub tag: Expression,
    pub zone: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamDnsblSettings {
    #[serde(rename = "domainLimit")]
    pub domain_limit: u64,
    #[serde(rename = "emailLimit")]
    pub email_limit: u64,
    #[serde(rename = "ipLimit")]
    pub ip_limit: u64,
    #[serde(rename = "urlLimit")]
    pub url_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamFileExtension {
    pub extension: String,
    #[serde(rename = "isArchive")]
    pub is_archive: bool,
    #[serde(rename = "isBad")]
    pub is_bad: bool,
    #[serde(rename = "isNz")]
    pub is_nz: bool,
    #[serde(rename = "contentTypes")]
    pub content_types: Map<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamPyzor {
    #[serde(rename = "blockCount")]
    pub block_count: u64,
    pub enable: bool,
    pub host: String,
    pub port: u64,
    pub ratio: Float,
    pub timeout: Duration,
    #[serde(rename = "allowCount")]
    pub allow_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SpamRule {
    Any(SpamRuleAny),
    Url(SpamRuleUrl),
    Domain(SpamRuleDomain),
    Email(SpamRuleEmail),
    Ip(SpamRuleIp),
    Header(SpamRuleHeader),
    Body(SpamRuleBody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamRuleAny {
    pub condition: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamRuleBody {
    pub condition: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamRuleDomain {
    pub condition: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamRuleEmail {
    pub condition: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamRuleHeader {
    pub condition: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamRuleIp {
    pub condition: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamRuleUrl {
    pub condition: Expression,
    pub name: String,
    pub description: Option<String>,
    pub enable: bool,
    pub priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamSettings {
    #[serde(rename = "trustContacts")]
    pub trust_contacts: bool,
    pub enable: bool,
    #[serde(rename = "greylistFor")]
    pub greylist_for: Option<Duration>,
    #[serde(rename = "scoreDiscard")]
    pub score_discard: Float,
    #[serde(rename = "scoreReject")]
    pub score_reject: Float,
    #[serde(rename = "scoreSpam")]
    pub score_spam: Float,
    #[serde(rename = "trustReplies")]
    pub trust_replies: bool,
    #[serde(rename = "spamFilterRulesUrl")]
    pub spam_filter_rules_url: Option<String>,
    #[serde(rename = "maxBodyText")]
    pub max_body_text: u64,
    #[serde(rename = "maxAttachmentText")]
    pub max_attachment_text: u64,
    #[serde(rename = "maxMessageText")]
    pub max_message_text: u64,
    #[serde(rename = "maxRedirectUrls")]
    pub max_redirect_urls: u64,
    #[serde(rename = "redirectTimeout")]
    pub redirect_timeout: Duration,
    #[serde(rename = "redirectCacheTtl")]
    pub redirect_cache_ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SpamTag {
    Score(SpamTagScore),
    Discard(SpamTagAction),
    Reject(SpamTagAction),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamTagAction {
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamTagScore {
    pub tag: String,
    pub score: Float,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpamTrainingSample {
    pub from: String,
    pub subject: String,
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
    #[serde(rename = "isSpam")]
    pub is_spam: bool,
    #[serde(rename = "accountId")]
    pub account_id: Option<Id>,
    #[serde(rename = "expiresAt")]
    pub expires_at: UTCDateTime,
    #[serde(rename = "deleteAfterUse")]
    pub delete_after_use: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpfReportSettings {
    #[serde(rename = "fromAddress")]
    pub from_address: Expression,
    #[serde(rename = "fromName")]
    pub from_name: Expression,
    #[serde(rename = "sendFrequency")]
    pub send_frequency: Expression,
    #[serde(rename = "dkimSignDomain")]
    pub dkim_sign_domain: Expression,
    pub subject: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SqlAuthStore {
    Default,
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
    Sqlite(SqliteStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SqlDirectory {
    pub description: String,
    pub store: SqlAuthStore,
    #[serde(rename = "columnEmail")]
    pub column_email: String,
    #[serde(rename = "columnSecret")]
    pub column_secret: String,
    #[serde(rename = "columnClass")]
    pub column_class: Option<String>,
    #[serde(rename = "columnDescription")]
    pub column_description: Option<String>,
    #[serde(rename = "queryLogin")]
    pub query_login: String,
    #[serde(rename = "queryRecipient")]
    pub query_recipient: String,
    #[serde(rename = "queryMemberOf")]
    pub query_member_of: Option<String>,
    #[serde(rename = "queryEmailAliases")]
    pub query_email_aliases: Option<String>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SqliteStore {
    pub path: String,
    #[serde(rename = "poolWorkers")]
    pub pool_workers: Option<u64>,
    #[serde(rename = "poolMaxConnections")]
    pub pool_max_connections: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoreLookup {
    pub namespace: String,
    pub store: LookupStore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum SubAddressing {
    Enabled,
    Custom(SubAddressingCustom),
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SubAddressingCustom {
    #[serde(rename = "customRule")]
    pub custom_rule: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SystemSettings {
    #[serde(rename = "defaultHostname")]
    pub default_hostname: String,
    #[serde(rename = "defaultDomainId")]
    pub default_domain_id: Id,
    #[serde(rename = "defaultCertificateId")]
    pub default_certificate_id: Option<Id>,
    #[serde(rename = "maxConnections")]
    pub max_connections: u64,
    #[serde(rename = "maxBufferedMemory")]
    pub max_buffered_memory: Option<u64>,
    #[serde(rename = "proxyTrustedNetworks")]
    pub proxy_trusted_networks: Map<IpAddrOrMask>,
    #[serde(rename = "mailExchangers")]
    pub mail_exchangers: List<MailExchanger>,
    pub services: VecMap<ServiceProtocol, Service>,
    #[serde(rename = "providerInfo")]
    pub provider_info: VecMap<ProviderInfo, String>,
    #[serde(rename = "includeSecrets")]
    pub include_secrets: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Task {
    CalendarAlarmEmail(TaskCalendarAlarmEmail),
    CalendarAlarmNotification(TaskCalendarAlarmNotification),
    CalendarItipMessage(TaskCalendarItipMessage),
    MergeThreads(TaskMergeThreads),
    DmarcReport(TaskDmarcReport),
    TlsReport(TaskTlsReport),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    RestoreArchivedItem(TaskRestoreArchivedItem),
    // SPDX-SnippetEnd
    DestroyAccount(TaskDestroyAccount),
    AccountMaintenance(TaskAccountMaintenance),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    TenantMaintenance(TaskTenantMaintenance),
    // SPDX-SnippetEnd
    StoreMaintenance(TaskStoreMaintenance),
    SpamFilterMaintenance(TaskSpamFilterMaintenance),
    AcmeRenewal(TaskDomainManagement),
    DkimManagement(TaskDomainManagement),
    DnsManagement(TaskDnsManagement),
    ShareRevokeCleanup(TaskShareRevokeCleanup),
    DmarcReportWindow(TaskReportWindow),
    TlsReportWindow(TaskReportWindow),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskAccountMaintenance {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "maintenanceType")]
    pub maintenance_type: TaskAccountMaintenanceType,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskCalendarAlarmEmail {
    #[serde(rename = "alarmId")]
    pub alarm_id: u64,
    #[serde(rename = "eventId")]
    pub event_id: u64,
    #[serde(rename = "eventStart")]
    pub event_start: UTCDateTime,
    #[serde(rename = "eventEnd")]
    pub event_end: UTCDateTime,
    #[serde(rename = "eventStartTz")]
    pub event_start_tz: u64,
    #[serde(rename = "eventEndTz")]
    pub event_end_tz: u64,
    #[serde(rename = "targetAccountId")]
    pub target_account_id: Option<Id>,
    #[serde(rename = "recurrenceId")]
    pub recurrence_id: Option<i64>,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "documentId")]
    pub document_id: Id,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskCalendarAlarmNotification {
    #[serde(rename = "alarmId")]
    pub alarm_id: u64,
    #[serde(rename = "eventId")]
    pub event_id: u64,
    #[serde(rename = "recurrenceId")]
    pub recurrence_id: Option<i64>,
    #[serde(rename = "targetAccountId")]
    pub target_account_id: Option<Id>,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "documentId")]
    pub document_id: Id,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskCalendarItipContents {
    pub from: String,
    pub to: Map<String>,
    #[serde(rename = "isFromOrganizer")]
    pub is_from_organizer: bool,
    #[serde(rename = "iCalendarData")]
    pub i_calendar_data: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskCalendarItipMessage {
    pub messages: List<TaskCalendarItipContents>,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "documentId")]
    pub document_id: Id,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskDestroyAccount {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "accountName")]
    pub account_name: String,
    #[serde(rename = "accountDomainId")]
    pub account_domain_id: Id,
    #[serde(rename = "accountType")]
    pub account_type: AccountType,
    #[serde(rename = "memberGroupIds")]
    pub member_group_ids: Map<Id>,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskDmarcReport {
    #[serde(rename = "reportId")]
    pub report_id: Id,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskDnsManagement {
    #[serde(rename = "updateRecords")]
    pub update_records: Map<DnsRecordType>,
    #[serde(rename = "onSuccessRenewCertificate")]
    pub on_success_renew_certificate: bool,
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskDomainManagement {
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskManager {
    pub strategy: TaskRetryStrategy,
    #[serde(rename = "alertAfter")]
    pub alert_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskMergeThreads {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "threadName")]
    pub thread_name: String,
    #[serde(rename = "messageIds")]
    pub message_ids: Map<String>,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskReportWindow {
    #[serde(rename = "windowEnd")]
    pub window_end: UTCDateTime,
    pub status: TaskStatus,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskRestoreArchivedItem {
    #[serde(rename = "blobId")]
    pub blob_id: BlobId,
    #[serde(rename = "archivedItemType")]
    pub archived_item_type: ArchivedItemType,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "archivedUntil")]
    pub archived_until: UTCDateTime,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    pub status: TaskStatus,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum TaskRetryStrategy {
    ExponentialBackoff(TaskRetryStrategyBackoff),
    FixedDelay(TaskRetryStrategyFixed),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskRetryStrategyBackoff {
    pub factor: Float,
    #[serde(rename = "initialDelay")]
    pub initial_delay: Duration,
    #[serde(rename = "maxDelay")]
    pub max_delay: Duration,
    pub jitter: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskRetryStrategyFixed {
    pub delay: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskShareRevokeCleanup {
    #[serde(rename = "objectType")]
    pub object_type: SharedObjectType,
    #[serde(rename = "accountId")]
    pub account_id: Id,
    #[serde(rename = "documentId")]
    pub document_id: Id,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskSpamFilterMaintenance {
    #[serde(rename = "maintenanceType")]
    pub maintenance_type: TaskSpamFilterMaintenanceType,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum TaskStatus {
    Pending(TaskStatusPending),
    Retry(TaskStatusRetry),
    Failed(TaskStatusFailed),
    Stalled(TaskStatusRetry),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskStatusFailed {
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "failedAt")]
    pub failed_at: UTCDateTime,
    #[serde(rename = "failedAttemptNumber")]
    pub failed_attempt_number: u64,
    #[serde(rename = "failureReason")]
    pub failure_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskStatusPending {
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    pub due: UTCDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskStatusRetry {
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    pub due: UTCDateTime,
    #[serde(rename = "attemptNumber")]
    pub attempt_number: u64,
    #[serde(rename = "firstFailedAt")]
    pub first_failed_at: UTCDateTime,
    #[serde(rename = "failureReason")]
    pub failure_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskStoreMaintenance {
    #[serde(rename = "maintenanceType")]
    pub maintenance_type: TaskStoreMaintenanceType,
    #[serde(rename = "shardIndex")]
    pub shard_index: Option<u64>,
    pub status: TaskStatus,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskTenantMaintenance {
    #[serde(rename = "tenantId")]
    pub tenant_id: Id,
    #[serde(rename = "maintenanceType")]
    pub maintenance_type: TaskTenantMaintenanceType,
    pub status: TaskStatus,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskTlsReport {
    #[serde(rename = "reportId")]
    pub report_id: Id,
    pub status: TaskStatus,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tenant {
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    pub logo: Option<String>,
    pub roles: Roles,
    pub permissions: Permissions,
    pub quotas: VecMap<TenantStorageQuota, u64>,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsExternalReport {
    pub report: TlsReport,
    pub from: String,
    pub subject: String,
    pub to: Map<String>,
    #[serde(rename = "receivedAt")]
    pub received_at: UTCDateTime,
    #[serde(rename = "expiresAt")]
    pub expires_at: UTCDateTime,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsFailureDetails {
    #[serde(rename = "resultType")]
    pub result_type: TlsResultType,
    #[serde(rename = "sendingMtaIp")]
    pub sending_mta_ip: Option<IpAddr>,
    #[serde(rename = "receivingMxHostname")]
    pub receiving_mx_hostname: Option<String>,
    #[serde(rename = "receivingMxHelo")]
    pub receiving_mx_helo: Option<String>,
    #[serde(rename = "receivingIp")]
    pub receiving_ip: Option<IpAddr>,
    #[serde(rename = "failedSessionCount")]
    pub failed_session_count: u64,
    #[serde(rename = "additionalInformation")]
    pub additional_information: Option<String>,
    #[serde(rename = "failureReasonCode")]
    pub failure_reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsInternalReport {
    #[serde(rename = "policyIdentifiers")]
    pub policy_identifiers: Map<u64>,
    #[serde(rename = "mailRua")]
    pub mail_rua: Map<String>,
    #[serde(rename = "httpRua")]
    pub http_rua: Map<String>,
    pub report: TlsReport,
    pub domain: String,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "deliverAt")]
    pub deliver_at: UTCDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsReport {
    #[serde(rename = "organizationName")]
    pub organization_name: Option<String>,
    #[serde(rename = "contactInfo")]
    pub contact_info: Option<String>,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "dateRangeStart")]
    pub date_range_start: UTCDateTime,
    #[serde(rename = "dateRangeEnd")]
    pub date_range_end: UTCDateTime,
    pub policies: List<TlsReportPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsReportPolicy {
    #[serde(rename = "policyType")]
    pub policy_type: TlsPolicyType,
    #[serde(rename = "policyStrings")]
    pub policy_strings: Map<String>,
    #[serde(rename = "policyDomain")]
    pub policy_domain: String,
    #[serde(rename = "mxHosts")]
    pub mx_hosts: Map<String>,
    #[serde(rename = "totalSuccessfulSessions")]
    pub total_successful_sessions: u64,
    #[serde(rename = "totalFailedSessions")]
    pub total_failed_sessions: u64,
    #[serde(rename = "failureDetails")]
    pub failure_details: List<TlsFailureDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsReportSettings {
    #[serde(rename = "contactInfo")]
    pub contact_info: Expression,
    #[serde(rename = "fromAddress")]
    pub from_address: Expression,
    #[serde(rename = "fromName")]
    pub from_name: Expression,
    #[serde(rename = "maxReportSize")]
    pub max_report_size: Expression,
    #[serde(rename = "orgName")]
    pub org_name: Expression,
    #[serde(rename = "sendFrequency")]
    pub send_frequency: Expression,
    #[serde(rename = "dkimSignDomain")]
    pub dkim_sign_domain: Expression,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Trace {
    pub events: List<TraceEvent>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceEvent {
    pub event: trc::EventType,
    pub timestamp: UTCDateTime,
    #[serde(rename = "keyValues")]
    pub key_values: List<TraceKeyValue>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceKeyValue {
    pub key: trc::Key,
    pub value: TraceValue,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum TraceValue {
    String(TraceValueString),
    UnsignedInt(TraceValueUnsignedInt),
    Integer(TraceValueInteger),
    Boolean(TraceValueBoolean),
    Float(TraceValueFloat),
    UTCDateTime(TraceValueUTCDateTime),
    Duration(TraceValueDuration),
    IpAddr(TraceValueIpAddr),
    List(TraceValueList),
    Event(TraceValueEvent),
    Null,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueBoolean {
    pub value: bool,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueDuration {
    pub value: u64,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueEvent {
    pub event: trc::EventType,
    pub value: List<TraceKeyValue>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueFloat {
    pub value: Float,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueInteger {
    pub value: i64,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueIpAddr {
    pub value: IpAddr,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueList {
    pub value: List<TraceValue>,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueString {
    pub value: String,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueUTCDateTime {
    pub value: UTCDateTime,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceValueUnsignedInt {
    pub value: u64,
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Tracer {
    Log(TracerLog),
    Stdout(TracerStdout),
    Journal(TracerCommon),
    OtelHttp(TracerOtelHttp),
    OtelGrpc(TracerOtelGrpc),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TracerCommon {
    pub enable: bool,
    pub level: TracingLevel,
    pub lossy: bool,
    pub events: Map<trc::EventType>,
    #[serde(rename = "eventsPolicy")]
    pub events_policy: EventPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TracerLog {
    pub path: String,
    pub prefix: String,
    pub rotate: LogRotateFrequency,
    pub ansi: bool,
    pub multiline: bool,
    pub enable: bool,
    pub level: TracingLevel,
    pub lossy: bool,
    pub events: Map<trc::EventType>,
    #[serde(rename = "eventsPolicy")]
    pub events_policy: EventPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TracerOtelGrpc {
    pub url: Option<String>,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "enableLogExporter")]
    pub enable_log_exporter: bool,
    #[serde(rename = "enableSpanExporter")]
    pub enable_span_exporter: bool,
    pub throttle: Duration,
    pub timeout: Duration,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    pub enable: bool,
    pub level: TracingLevel,
    pub lossy: bool,
    pub events: Map<trc::EventType>,
    #[serde(rename = "eventsPolicy")]
    pub events_policy: EventPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TracerOtelHttp {
    pub url: String,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "enableLogExporter")]
    pub enable_log_exporter: bool,
    #[serde(rename = "enableSpanExporter")]
    pub enable_span_exporter: bool,
    pub throttle: Duration,
    pub timeout: Duration,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    pub enable: bool,
    pub level: TracingLevel,
    pub lossy: bool,
    pub events: Map<trc::EventType>,
    #[serde(rename = "eventsPolicy")]
    pub events_policy: EventPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TracerStdout {
    pub buffered: bool,
    pub ansi: bool,
    pub multiline: bool,
    pub enable: bool,
    pub level: TracingLevel,
    pub lossy: bool,
    pub events: Map<trc::EventType>,
    #[serde(rename = "eventsPolicy")]
    pub events_policy: EventPolicy,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum TracingStore {
    Disabled,
    Default,
    FoundationDb(FoundationDbStore),
    PostgreSql(PostgreSqlStore),
    MySql(MySqlStore),
}

// SPDX-SnippetEnd
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserAccount {
    pub name: String,
    #[serde(rename = "domainId")]
    pub domain_id: Id,
    pub credentials: List<Credential>,
    #[serde(rename = "createdAt")]
    pub created_at: UTCDateTime,
    #[serde(rename = "memberGroupIds")]
    pub member_group_ids: Map<Id>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "memberTenantId")]
    pub member_tenant_id: Option<Id>,
    // SPDX-SnippetEnd
    pub roles: UserRoles,
    pub permissions: Permissions,
    pub quotas: VecMap<StorageQuota, u64>,
    pub aliases: List<EmailAlias>,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    // SPDX-SnippetEnd
    pub description: Option<String>,
    pub locale: Locale,
    #[serde(rename = "timeZone")]
    pub time_zone: Option<TimeZone>,
    #[serde(rename = "encryptionAtRest")]
    pub encryption_at_rest: EncryptionAtRest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum UserRoles {
    User,
    Admin,
    Custom(CustomRoles),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebDav {
    #[serde(rename = "enableAssistedDiscovery")]
    pub enable_assisted_discovery: bool,
    #[serde(rename = "maxLockTimeout")]
    pub max_lock_timeout: Duration,
    #[serde(rename = "maxLocks")]
    pub max_locks: u64,
    #[serde(rename = "maxLivePropertySize")]
    pub max_live_property_size: u64,
    #[serde(rename = "maxRequestSize")]
    pub max_request_size: u64,
    #[serde(rename = "maxResults")]
    pub max_results: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebHook {
    pub enable: bool,
    pub level: TracingLevel,
    pub lossy: bool,
    #[serde(rename = "signatureKey")]
    pub signature_key: SecretKeyOptional,
    pub throttle: Duration,
    #[serde(rename = "discardAfter")]
    pub discard_after: Duration,
    pub url: String,
    pub timeout: Duration,
    #[serde(rename = "allowInvalidCerts")]
    pub allow_invalid_certs: bool,
    #[serde(rename = "httpAuth")]
    pub http_auth: HttpAuth,
    #[serde(rename = "httpHeaders")]
    pub http_headers: VecMap<String, String>,
    pub events: Map<trc::EventType>,
    #[serde(rename = "eventsPolicy")]
    pub events_policy: EventPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ZenohCoordinator {
    pub config: String,
}
