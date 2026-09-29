/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq))]
pub struct HeaderId(pub u8);

macro_rules! header_ids {
    ($($id:ident, $name:literal;)+) => {
        #[allow(non_camel_case_types, clippy::upper_case_acronyms, dead_code)]
        #[repr(u8)]
        enum Slot {
            OTHER,
            $($id,)+
        }

        impl HeaderId {
            pub const OTHER: HeaderId = HeaderId(Slot::OTHER as u8);
            $(pub const $id: HeaderId = HeaderId(Slot::$id as u8);)+

            const NAMES: &'static [&'static str] = &["", $($name,)+];

            pub fn parse(name: &[u8]) -> HeaderId {
                hashify::fnc_map_ignore_case!(name,
                    $($name => HeaderId::$id,)+
                    _ => HeaderId::OTHER
                )
            }
        }
    };
}

header_ids! {
    SUBJECT, "Subject";
    FROM, "From";
    TO, "To";
    CC, "Cc";
    DATE, "Date";
    BCC, "Bcc";
    REPLY_TO, "Reply-To";
    SENDER, "Sender";
    COMMENTS, "Comments";
    IN_REPLY_TO, "In-Reply-To";
    KEYWORDS, "Keywords";
    RECEIVED, "Received";
    MESSAGE_ID, "Message-ID";
    REFERENCES, "References";
    RETURN_PATH, "Return-Path";
    MIME_VERSION, "MIME-Version";
    CONTENT_DESCRIPTION, "Content-Description";
    CONTENT_ID, "Content-ID";
    CONTENT_LANGUAGE, "Content-Language";
    CONTENT_LOCATION, "Content-Location";
    CONTENT_TRANSFER_ENCODING, "Content-Transfer-Encoding";
    CONTENT_TYPE, "Content-Type";
    CONTENT_DISPOSITION, "Content-Disposition";
    RESENT_TO, "Resent-To";
    RESENT_FROM, "Resent-From";
    RESENT_BCC, "Resent-Bcc";
    RESENT_CC, "Resent-Cc";
    RESENT_SENDER, "Resent-Sender";
    RESENT_DATE, "Resent-Date";
    RESENT_MESSAGE_ID, "Resent-Message-ID";
    LIST_ARCHIVE, "List-Archive";
    LIST_HELP, "List-Help";
    LIST_ID, "List-ID";
    LIST_OWNER, "List-Owner";
    LIST_POST, "List-Post";
    LIST_SUBSCRIBE, "List-Subscribe";
    LIST_UNSUBSCRIBE, "List-Unsubscribe";
    DKIM_SIGNATURE, "DKIM-Signature";
    ARC_AUTHENTICATION_RESULTS, "ARC-Authentication-Results";
    ARC_MESSAGE_SIGNATURE, "ARC-Message-Signature";
    ARC_SEAL, "ARC-Seal";
    DELIVERED_TO, "Delivered-To";
    X_ORIGINAL_TO, "X-Original-To";
    RETURN_RECEIPT_TO, "Return-Receipt-To";
    DISPOSITION_NOTIFICATION_TO, "Disposition-Notification-To";
    ERRORS_TO, "Errors-To";
    AUTHENTICATION_RESULTS, "Authentication-Results";
    RECEIVED_SPF, "Received-SPF";
    X_SPAM_STATUS, "X-Spam-Status";
    X_SPAM_SCORE, "X-Spam-Score";
    X_SPAM_FLAG, "X-Spam-Flag";
    X_SPAM_RESULT, "X-Spam-Result";
    IMPORTANCE, "Importance";
    PRIORITY, "Priority";
    X_PRIORITY, "X-Priority";
    XMS_MAIL_PRIORITY, "X-MSMail-Priority";
    X_MAILER, "X-Mailer";
    USER_AGENT, "User-Agent";
    X_MIME_OLE, "X-MimeOLE";
    X_ORIGINATING_IP, "X-Originating-IP";
    X_FORWARDED_TO, "X-Forwarded-To";
    X_FORWARDED_FOR, "X-Forwarded-For";
    AUTO_SUBMITTED, "Auto-Submitted";
    X_AUTO_RESPONSE_SUPPRESS, "X-Auto-Response-Suppress";
    PRECEDENCE, "Precedence";
    ORGANIZATION, "Organization";
    THREAD_INDEX, "Thread-Index";
    THREAD_TOPIC, "Thread-Topic";
    LIST_UNSUBSCRIBE_POST, "List-Unsubscribe-Post";
    FEEDBACK_ID, "Feedback-ID";
    ACCEPT_LANGUAGE, "Accept-Language";
    ARCHIVED_AT, "Archived-At";
    ORIGINAL_RECIPIENT, "Original-Recipient";
    ORIGINAL_SUBJECT, "Original-Subject";
    TLS_REQUIRED, "TLS-Required";
    AUTHOR, "Author";
    DKIM2_SIGNATURE, "DKIM2-Signature";
    MESSAGE_INSTANCE, "Message-Instance";
    X_UNIVERSALLY_UNIQUE_IDENTIFIER, "X-Universally-Unique-Identifier";
    X_VIRUS_SCANNED, "X-Virus-Scanned";
    X_MAIL_FROM, "X-MailFrom";
    X_MAILMAN_VERSION, "X-Mailman-Version";
    MESSAGE_ID_HASH, "Message-ID-Hash";
    X_MESSAGE_ID_HASH, "X-Message-ID-Hash";
    X_MAILMAN_RULE_MISSES, "X-Mailman-Rule-Misses";
    X_SPAM_LEVEL, "X-Spam-Level";
    X_RECEIVED, "X-Received";
    X_GM_MESSAGE_STATE, "X-Gm-Message-State";
    X_GOOGLE_DKIM_SIGNATURE, "X-Google-DKIM-Signature";
    X_MAILBOX_LINE, "X-Mailbox-Line";
    X_GM_GG, "X-Gm-Gg";
    X_ORIGINAL_FROM, "X-Original-From";
    X_GOOGLE_SMTP_SOURCE, "X-Google-Smtp-Source";
    X_MS_TNEF_CORRELATOR, "X-MS-TNEF-Correlator";
    X_MS_HAS_ATTACH, "X-MS-Has-Attach";
    X_ME_PROXY, "X-ME-Proxy";
    X_ME_PROXY_CAUSE, "X-ME-Proxy-Cause";
    X_ME_SENDER, "X-ME-Sender";
    X_GM_FEATURES, "X-Gm-Features";
    X_MS_EXCHANGE_TRANSPORT_CROSS_TENANT_HEADERS_STAMPED, "X-MS-Exchange-Transport-CrossTenantHeadersStamped";
    X_MS_PUBLIC_TRAFFIC_TYPE, "X-MS-PublicTrafficType";
    X_ORIGINATOR_ORG, "X-OriginatorOrg";
    X_MS_EXCHANGE_CROSS_TENANT_NETWORK_MESSAGE_ID, "X-MS-Exchange-CrossTenant-Network-Message-Id";
    X_MS_EXCHANGE_CROSS_TENANT_AUTH_SOURCE, "X-MS-Exchange-CrossTenant-AuthSource";
    X_MS_EXCHANGE_CROSS_TENANT_AUTH_AS, "X-MS-Exchange-CrossTenant-AuthAs";
    X_MS_EXCHANGE_CROSS_TENANT_ORIGINAL_ARRIVAL_TIME, "X-MS-Exchange-CrossTenant-OriginalArrivalTime";
    X_MICROSOFT_ANTISPAM, "X-Microsoft-Antispam";
    X_MS_EXCHANGE_CROSS_TENANT_ID, "X-MS-Exchange-CrossTenant-Id";
    X_MS_TRAFFIC_TYPE_DIAGNOSTIC, "X-MS-TrafficTypeDiagnostic";
    X_MICROSOFT_ANTISPAM_MESSAGE_INFO, "X-Microsoft-Antispam-Message-Info";
    X_MS_OFFICE365_FILTERING_CORRELATION_ID, "X-MS-Office365-Filtering-Correlation-Id";
    X_MS_EXCHANGE_CROSS_TENANT_FROM_ENTITY_HEADER, "X-MS-Exchange-CrossTenant-FromEntityHeader";
    X_MS_EXCHANGE_ANTI_SPAM_MESSAGE_DATA_CHUNK_COUNT, "X-MS-Exchange-AntiSpam-MessageData-ChunkCount";
    X_MS_EXCHANGE_ANTI_SPAM_MESSAGE_DATA0, "X-MS-Exchange-AntiSpam-MessageData-0";
    X_MS_EXCHANGE_SENDER_AD_CHECK, "X-MS-Exchange-SenderADCheck";
    X_FOREFRONT_ANTISPAM_REPORT, "X-Forefront-Antispam-Report";
    X_MS_EXCHANGE_ANTI_SPAM_RELAY, "X-MS-Exchange-AntiSpam-Relay";
    X_MS_EXCHANGE_CROSS_TENANT_MAILBOX_TYPE, "X-MS-Exchange-CrossTenant-MailboxType";
    X_MS_EXCHANGE_CROSS_TENANT_USER_PRINCIPAL_NAME, "X-MS-Exchange-CrossTenant-UserPrincipalName";
    X_GIT_HUB_REASON, "X-GitHub-Reason";
    X_GIT_HUB_RECIPIENT_ADDRESS, "X-GitHub-Recipient-Address";
    X_GIT_HUB_RECIPIENT, "X-GitHub-Recipient";
    DESTINATIONS, "Destinations";
    X_GIT_HUB_SENDER, "X-GitHub-Sender";
    X_GIT_HUB_NOTIFY_PLATFORM, "X-GitHub-Notify-Platform";
    X_THREAD_ID, "X-ThreadId";
    X_SES_OUTGOING, "X-SES-Outgoing";
    X_PROOFPOINT_VIRUS_VERSION, "X-Proofpoint-Virus-Version";
    X_GIT_HUB_ASSIGNEES, "X-GitHub-Assignees";
    X_GIT_HUB_LABELS, "X-GitHub-Labels";
    BIMI_SELECTOR, "BIMI-Selector";
    X_STRIPE_EID, "X-Stripe-EID";
    X_ATTACHMENT_ID, "X-Attachment-Id";
    X_TEST_ID_TRACKER, "X-Test-IDTracker";
    X_IETF_ID_TRACKER, "X-IETF-IDTracker";
    X_PM_MESSAGE_ID, "X-Pm-Message-ID";
    X_ANTI_ABUSE, "X-AntiAbuse";
    AUTOCRYPT, "Autocrypt";
    X_COMPLAINTS_TO, "X-Complaints-To";
    X_PROOFPOINT_ORIG_GUID, "X-Proofpoint-ORIG-GUID";
    X_PROOFPOINT_GUID, "X-Proofpoint-GUID";
    X_GIT_HUB_ISSUE_STATE, "X-GitHub-IssueState";
    X_MS_REACTIONS, "X-MS-Reactions";
    X_PM_MTA_POOL, "X-Pm-MTA-Pool";
    X_PM_RCPT, "X-Pm-RCPT";
    X_PROOFPOINT_SPAM_DETAILS_ENC, "X-Proofpoint-Spam-Details-Enc";
    X_PM_MESSAGE_OPTIONS, "X-Pm-Message-Options";
    X_SENDER_ID, "X-Sender-ID";
    X_GIT_HUB_PULL_REQUEST_STATUS, "X-GitHub-PullRequestStatus";
    X_AUTHORITY_ANALYSIS, "X-Authority-Analysis";
    X_FORWARDED_ENCRYPTED, "X-Forwarded-Encrypted";
    X_MS_EXCHANGE_ANTI_SPAM_EXTERNAL_HOP_MESSAGE_DATA_CHUNK_COUNT, "X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount";
    X_MS_EXCHANGE_ANTI_SPAM_EXTERNAL_HOP_MESSAGE_DATA0, "X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0";
    X_MS_EXCHANGE_CROSS_TENANT_RMS_PERSISTED_CONSUMER_ORG, "X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg";
    X_EXCHANGE_ROUTING_POLICY_CHECKED, "X-Exchange-RoutingPolicyChecked";
    X_MS_EXCHANGE_CROSS_TENANT_ORIGINAL_ATTRIBUTED_TENANT_CONNECTING_IP, "X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp";
    X_MS_EXCHANGE_MESSAGE_SENT_REPRESENTING_TYPE, "X-MS-Exchange-MessageSentRepresentingType";
    X_MS_EXCHANGE_TRANSPORT_CROSS_TENANT_HEADERS_STRIPPED, "X-MS-Exchange-Transport-CrossTenantHeadersStripped";
    X_MS_OFFICE365_FILTERING_CORRELATION_ID_PRVS, "X-MS-Office365-Filtering-Correlation-Id-Prvs";
    X_MICROSOFT_ANTISPAM_MESSAGE_INFO_ORIGINAL, "X-Microsoft-Antispam-Message-Info-Original";
    X_MS_EXCHANGE_AUTHENTICATION_RESULTS, "X-MS-Exchange-Authentication-Results";
    X_FOREFRONT_ANTISPAM_REPORT_UNTRUSTED, "X-Forefront-Antispam-Report-Untrusted";
    X_MS_EXCHANGE_ATP_MESSAGE_PROPERTIES, "X-MS-Exchange-AtpMessageProperties";
    X_MICROSOFT_ANTISPAM_UNTRUSTED, "X-Microsoft-Antispam-Untrusted";
    X_MS_EXCHANGE_ANTI_SPAM_MESSAGE_DATA1, "X-MS-Exchange-AntiSpam-MessageData-1";
    X_MISSIVE_ID, "X-Missive-Id";
    X_IADB_IP_REVERSE, "X-IADB-IP-Reverse";
    X_REPORT_ABUSE, "X-Report-Abuse";
    DKIM_FILTER, "DKIM-Filter";
    X_ME_RECEIVED, "X-ME-Received";
    X_PROOFPOINT_SPAM_DETAILS, "X-Proofpoint-Spam-Details";
    CONTENT_MD5, "Content-MD5";
}

impl HeaderId {
    pub fn as_str(self) -> Option<&'static str> {
        (self.0 != 0)
            .then(|| HeaderId::NAMES.get(self.0 as usize).copied())
            .flatten()
    }

    pub fn is_known(self) -> bool {
        self.0 != 0 && (self.0 as usize) < HeaderId::NAMES.len()
    }

    pub fn is_mime(self) -> bool {
        matches!(
            self,
            HeaderId::CONTENT_DESCRIPTION
                | HeaderId::CONTENT_ID
                | HeaderId::CONTENT_LANGUAGE
                | HeaderId::CONTENT_LOCATION
                | HeaderId::CONTENT_TRANSFER_ENCODING
                | HeaderId::CONTENT_TYPE
                | HeaderId::CONTENT_DISPOSITION
        )
    }

    pub fn bit(self) -> (usize, u64) {
        ((self.0 >> 6) as usize, 1u64 << (self.0 & 63))
    }
}

impl From<&ArchivedHeaderId> for HeaderId {
    fn from(value: &ArchivedHeaderId) -> Self {
        HeaderId(value.0)
    }
}

impl fmt::Display for HeaderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str().unwrap_or("Other"))
    }
}

#[cfg(test)]
mod tests {
    use super::HeaderId;

    #[test]
    fn table_is_consistent() {
        assert_eq!(HeaderId::NAMES.len(), 173);
        for (index, name) in HeaderId::NAMES.iter().enumerate().skip(1) {
            let id = HeaderId::parse(name.as_bytes());
            assert_eq!(id.0 as usize, index, "{name}");
            assert_eq!(id.as_str(), Some(*name));
            assert_eq!(HeaderId::parse(name.to_ascii_lowercase().as_bytes()), id);
        }
        assert_eq!(HeaderId::parse(b"X-Not-Known"), HeaderId::OTHER);
        assert_eq!(HeaderId::OTHER.as_str(), None);
        assert_eq!(HeaderId::SUBJECT.0, 1);
        assert_eq!(HeaderId::CONTENT_MD5.0, 172);
        assert!(HeaderId::CONTENT_TYPE.is_mime());
        assert!(!HeaderId::CONTENT_MD5.is_mime());
    }
}
