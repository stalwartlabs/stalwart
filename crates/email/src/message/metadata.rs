/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::{
    Addr, Address, Attribute, ContentType, DateTime, Encoding, Group, HeaderName, HeaderValue,
    PartType,
    decoders::{
        base64::base64_decode, charsets::map::charset_decoder,
        quoted_printable::quoted_printable_decode,
    },
};
use rkyv::{boxed::ArchivedBox, primitive::ArchivedU16, string::ArchivedString};
use std::{borrow::Cow, collections::VecDeque, ops::Range};
use types::blob_hash::BlobHash;
use utils::chained_bytes::ChainedBytes;

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct MessageMetadata {
    pub contents: Box<[MessageMetadataContents]>,
    pub blob_hash: BlobHash,
    pub blob_body_offset: u32,
    pub preview: Box<str>,
    pub raw_headers: Box<[u8]>,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct MessageMetadataContents {
    pub html_body: Box<[u16]>,
    pub text_body: Box<[u16]>,
    pub attachments: Box<[u16]>,
    pub parts: Box<[MessageMetadataPart]>,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct MessageMetadataPart {
    pub headers: Box<[MetadataHeader]>,
    pub body: MetadataPartType,
    pub flags: u32,
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
}

pub const PART_ENCODING_BASE64: u32 = 1 << 31;
pub const PART_ENCODING_QP: u32 = 1 << 30;
pub const PART_ENCODING_PROBLEM: u32 = 1 << 29;
pub const PART_SIZE_MASK: u32 = !(PART_ENCODING_BASE64 | PART_ENCODING_QP | PART_ENCODING_PROBLEM);

#[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(compare(PartialEq))]
pub struct MetadataHeader {
    pub name: MetadataHeaderName,
    pub value: MetadataHeaderValue,
    pub base_offset: u32,
    pub start: u16,
    pub end: u16,
}

macro_rules! metadata_header_names {
    ($($variant:ident, $name:literal;)+) => {
        #[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
        #[rkyv(compare(PartialEq))]
        pub enum MetadataHeaderName {
            Other(String),
            $($variant,)+
        }

        impl MetadataHeaderName {
            pub fn parse(name: &[u8]) -> Option<MetadataHeaderName> {
                hashify::tiny_map_ignore_case!(name,
                    $($name => MetadataHeaderName::$variant,)+
                )
            }
        }

        impl ArchivedMetadataHeaderName {
            pub fn as_str(&self) -> &str {
                match self {
                    $(ArchivedMetadataHeaderName::$variant => $name,)+
                    ArchivedMetadataHeaderName::Other(name) => name.as_ref(),
                }
            }
        }
    };
}

metadata_header_names! {
    Subject, "Subject";
    From, "From";
    To, "To";
    Cc, "Cc";
    Date, "Date";
    Bcc, "Bcc";
    ReplyTo, "Reply-To";
    Sender, "Sender";
    Comments, "Comments";
    InReplyTo, "In-Reply-To";
    Keywords, "Keywords";
    Received, "Received";
    MessageId, "Message-ID";
    References, "References";
    ReturnPath, "Return-Path";
    MimeVersion, "MIME-Version";
    ContentDescription, "Content-Description";
    ContentId, "Content-ID";
    ContentLanguage, "Content-Language";
    ContentLocation, "Content-Location";
    ContentTransferEncoding, "Content-Transfer-Encoding";
    ContentType, "Content-Type";
    ContentDisposition, "Content-Disposition";
    ResentTo, "Resent-To";
    ResentFrom, "Resent-From";
    ResentBcc, "Resent-Bcc";
    ResentCc, "Resent-Cc";
    ResentSender, "Resent-Sender";
    ResentDate, "Resent-Date";
    ResentMessageId, "Resent-Message-ID";
    ListArchive, "List-Archive";
    ListHelp, "List-Help";
    ListId, "List-ID";
    ListOwner, "List-Owner";
    ListPost, "List-Post";
    ListSubscribe, "List-Subscribe";
    ListUnsubscribe, "List-Unsubscribe";
    DkimSignature, "DKIM-Signature";
    ArcAuthenticationResults, "ARC-Authentication-Results";
    ArcMessageSignature, "ARC-Message-Signature";
    ArcSeal, "ARC-Seal";
    DeliveredTo, "Delivered-To";
    XOriginalTo, "X-Original-To";
    ReturnReceiptTo, "Return-Receipt-To";
    DispositionNotificationTo, "Disposition-Notification-To";
    ErrorsTo, "Errors-To";
    AuthenticationResults, "Authentication-Results";
    ReceivedSpf, "Received-SPF";
    XSpamStatus, "X-Spam-Status";
    XSpamScore, "X-Spam-Score";
    XSpamFlag, "X-Spam-Flag";
    XSpamResult, "X-Spam-Result";
    Importance, "Importance";
    Priority, "Priority";
    XPriority, "X-Priority";
    XMSMailPriority, "X-MSMail-Priority";
    XMailer, "X-Mailer";
    UserAgent, "User-Agent";
    XMimeOLE, "X-MimeOLE";
    XOriginatingIp, "X-Originating-IP";
    XForwardedTo, "X-Forwarded-To";
    XForwardedFor, "X-Forwarded-For";
    AutoSubmitted, "Auto-Submitted";
    XAutoResponseSuppress, "X-Auto-Response-Suppress";
    Precedence, "Precedence";
    Organization, "Organization";
    ThreadIndex, "Thread-Index";
    ThreadTopic, "Thread-Topic";
    ListUnsubscribePost, "List-Unsubscribe-Post";
    FeedbackId, "Feedback-ID";
    AcceptLanguage, "Accept-Language";
    ArchivedAt, "Archived-At";
    OriginalRecipient, "Original-Recipient";
    OriginalSubject, "Original-Subject";
    TlsRequired, "TLS-Required";
    Author, "Author";
    Dkim2Signature, "DKIM2-Signature";
    MessageInstance, "Message-Instance";
    XUniversallyUniqueIdentifier, "X-Universally-Unique-Identifier";
    XVirusScanned, "X-Virus-Scanned";
    XMailFrom, "X-MailFrom";
    XMailmanVersion, "X-Mailman-Version";
    MessageIdHash, "Message-ID-Hash";
    XMessageIdHash, "X-Message-ID-Hash";
    XMailmanRuleMisses, "X-Mailman-Rule-Misses";
    XSpamLevel, "X-Spam-Level";
    XReceived, "X-Received";
    XGmMessageState, "X-Gm-Message-State";
    XGoogleDkimSignature, "X-Google-DKIM-Signature";
    XMailboxLine, "X-Mailbox-Line";
    XGmGg, "X-Gm-Gg";
    XOriginalFrom, "X-Original-From";
    XGoogleSmtpSource, "X-Google-Smtp-Source";
    XMsTnefCorrelator, "X-MS-TNEF-Correlator";
    XMsHasAttach, "X-MS-Has-Attach";
    XMeProxy, "X-ME-Proxy";
    XMeProxyCause, "X-ME-Proxy-Cause";
    XMeSender, "X-ME-Sender";
    XGmFeatures, "X-Gm-Features";
    XMsExchangeTransportCrossTenantHeadersStamped, "X-MS-Exchange-Transport-CrossTenantHeadersStamped";
    XMsPublicTrafficType, "X-MS-PublicTrafficType";
    XOriginatorOrg, "X-OriginatorOrg";
    XMsExchangeCrossTenantNetworkMessageId, "X-MS-Exchange-CrossTenant-Network-Message-Id";
    XMsExchangeCrossTenantAuthSource, "X-MS-Exchange-CrossTenant-AuthSource";
    XMsExchangeCrossTenantAuthAs, "X-MS-Exchange-CrossTenant-AuthAs";
    XMsExchangeCrossTenantOriginalArrivalTime, "X-MS-Exchange-CrossTenant-OriginalArrivalTime";
    XMicrosoftAntispam, "X-Microsoft-Antispam";
    XMsExchangeCrossTenantId, "X-MS-Exchange-CrossTenant-Id";
    XMsTrafficTypeDiagnostic, "X-MS-TrafficTypeDiagnostic";
    XMicrosoftAntispamMessageInfo, "X-Microsoft-Antispam-Message-Info";
    XMsOffice365FilteringCorrelationId, "X-MS-Office365-Filtering-Correlation-Id";
    XMsExchangeCrossTenantFromEntityHeader, "X-MS-Exchange-CrossTenant-FromEntityHeader";
    XMsExchangeAntiSpamMessageDataChunkCount, "X-MS-Exchange-AntiSpam-MessageData-ChunkCount";
    XMsExchangeAntiSpamMessageData0, "X-MS-Exchange-AntiSpam-MessageData-0";
    XMsExchangeSenderADCheck, "X-MS-Exchange-SenderADCheck";
    XForefrontAntispamReport, "X-Forefront-Antispam-Report";
    XMsExchangeAntiSpamRelay, "X-MS-Exchange-AntiSpam-Relay";
    XMsExchangeCrossTenantMailboxType, "X-MS-Exchange-CrossTenant-MailboxType";
    XMsExchangeCrossTenantUserPrincipalName, "X-MS-Exchange-CrossTenant-UserPrincipalName";
    XGitHubReason, "X-GitHub-Reason";
    XGitHubRecipientAddress, "X-GitHub-Recipient-Address";
    XGitHubRecipient, "X-GitHub-Recipient";
    Destinations, "Destinations";
    XGitHubSender, "X-GitHub-Sender";
    XGitHubNotifyPlatform, "X-GitHub-Notify-Platform";
    XThreadId, "X-ThreadId";
    XSesOutgoing, "X-SES-Outgoing";
    XProofpointVirusVersion, "X-Proofpoint-Virus-Version";
    XGitHubAssignees, "X-GitHub-Assignees";
    XGitHubLabels, "X-GitHub-Labels";
    BimiSelector, "BIMI-Selector";
    XStripeEid, "X-Stripe-EID";
    XAttachmentId, "X-Attachment-Id";
    XTestIDTracker, "X-Test-IDTracker";
    XIetfIDTracker, "X-IETF-IDTracker";
    XPmMessageId, "X-Pm-Message-ID";
    XAntiAbuse, "X-AntiAbuse";
    Autocrypt, "Autocrypt";
    XComplaintsTo, "X-Complaints-To";
    XProofpointOrigGuid, "X-Proofpoint-ORIG-GUID";
    XProofpointGuid, "X-Proofpoint-GUID";
    XGitHubIssueState, "X-GitHub-IssueState";
    XMsReactions, "X-MS-Reactions";
    XPmMtaPool, "X-Pm-MTA-Pool";
    XPmRcpt, "X-Pm-RCPT";
    XProofpointSpamDetailsEnc, "X-Proofpoint-Spam-Details-Enc";
    XPmMessageOptions, "X-Pm-Message-Options";
    XSenderId, "X-Sender-ID";
    XGitHubPullRequestStatus, "X-GitHub-PullRequestStatus";
    XAuthorityAnalysis, "X-Authority-Analysis";
    XForwardedEncrypted, "X-Forwarded-Encrypted";
    XMsExchangeAntiSpamExternalHopMessageDataChunkCount, "X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount";
    XMsExchangeAntiSpamExternalHopMessageData0, "X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0";
    XMsExchangeCrossTenantRmsPersistedConsumerOrg, "X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg";
    XExchangeRoutingPolicyChecked, "X-Exchange-RoutingPolicyChecked";
    XMsExchangeCrossTenantOriginalAttributedTenantConnectingIp, "X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp";
    XMsExchangeMessageSentRepresentingType, "X-MS-Exchange-MessageSentRepresentingType";
    XMsExchangeTransportCrossTenantHeadersStripped, "X-MS-Exchange-Transport-CrossTenantHeadersStripped";
    XMsOffice365FilteringCorrelationIdPrvs, "X-MS-Office365-Filtering-Correlation-Id-Prvs";
    XMicrosoftAntispamMessageInfoOriginal, "X-Microsoft-Antispam-Message-Info-Original";
    XMsExchangeAuthenticationResults, "X-MS-Exchange-Authentication-Results";
    XForefrontAntispamReportUntrusted, "X-Forefront-Antispam-Report-Untrusted";
    XMsExchangeAtpMessageProperties, "X-MS-Exchange-AtpMessageProperties";
    XMicrosoftAntispamUntrusted, "X-Microsoft-Antispam-Untrusted";
    XMsExchangeAntiSpamMessageData1, "X-MS-Exchange-AntiSpam-MessageData-1";
    XMissiveId, "X-Missive-Id";
    XIadbIpReverse, "X-IADB-IP-Reverse";
    XReportAbuse, "X-Report-Abuse";
    DkimFilter, "DKIM-Filter";
    XMeReceived, "X-ME-Received";
    XProofpointSpamDetails, "X-Proofpoint-Spam-Details";
}

#[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(compare(PartialEq))]
pub enum MetadataHeaderValue {
    AddressList(Box<[MetadataAddress]>),
    AddressGroup(Box<[MetadataAddressGroup]>),
    Text(String),
    TextList(Box<[String]>),
    DateTime(MetadataDateTime),
    ContentType(Box<MetadataContentType>),
    Empty,
}

#[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(compare(PartialEq))]
pub struct MetadataDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tz_hour: i8,
    pub tz_minute: u8,
}

#[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(compare(PartialEq))]
pub struct MetadataAddress {
    pub name: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(compare(PartialEq))]
pub struct MetadataAddressGroup {
    pub name: Option<String>,
    pub addresses: Box<[MetadataAddress]>,
}

#[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(compare(PartialEq))]
pub struct MetadataContentType {
    pub c_type: String,
    pub c_subtype: Option<String>,
    pub attributes: Box<[MetadataAttribute]>,
}

#[derive(Debug, PartialEq, Eq, Clone, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(compare(PartialEq))]
pub struct MetadataAttribute {
    pub name: String,
    pub value: String,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub enum MetadataPartType {
    Text,
    Html,
    Binary,
    InlineBinary,
    Message(u16),
    Multipart(Box<[u16]>),
}

impl MessageMetadataContents {
    pub fn root_part(&self) -> &MessageMetadataPart {
        &self.parts[0]
    }
}

#[derive(Debug)]
pub struct DecodedParts<'x> {
    pub raw_messages: Vec<DecodedRawMessage<'x>>,
    pub parts: Vec<DecodedPart<'x>>,
}

#[derive(Debug)]
pub enum DecodedRawMessage<'x> {
    Borrowed(ChainedBytes<'x>),
    Owned(Vec<u8>),
}

#[derive(Debug)]
pub struct DecodedPart<'x> {
    pub message_id: usize,
    pub part_offset: usize,
    pub content: DecodedPartContent<'x>,
}

#[derive(Debug)]
pub enum DecodedPartContent<'x> {
    Text(Cow<'x, str>),
    Binary(Cow<'x, [u8]>),
}

impl<'x> DecodedParts<'x> {
    #[inline]
    pub fn raw_message(&self, message_id: usize) -> Option<&DecodedRawMessage<'x>> {
        self.raw_messages.get(message_id)
    }

    #[inline]
    pub fn raw_message_section(
        &'_ self,
        message_id: usize,
        range: Range<usize>,
    ) -> Option<Cow<'_, [u8]>> {
        self.raw_messages.get(message_id).and_then(|m| m.get(range))
    }

    #[inline]
    pub fn part(&self, message_id: usize, part_offset: usize) -> Option<&DecodedPartContent<'x>> {
        self.parts
            .iter()
            .find(|p| p.message_id == message_id && p.part_offset == part_offset)
            .map(|p| &p.content)
    }

    #[inline]
    pub fn text_part(&self, message_id: usize, part_offset: usize) -> Option<&str> {
        self.part(message_id, part_offset).and_then(|p| match p {
            DecodedPartContent::Text(text) => Some(text.as_ref()),
            DecodedPartContent::Binary(_) => None,
        })
    }

    #[inline]
    pub fn binary_part(&self, message_id: usize, part_offset: usize) -> Option<&[u8]> {
        self.part(message_id, part_offset).map(|p| match p {
            DecodedPartContent::Text(part) => part.as_bytes(),
            DecodedPartContent::Binary(binary) => binary.as_ref(),
        })
    }

    #[inline]
    pub fn transfer_decoded_contents(
        &self,
        message_id: usize,
        part: &ArchivedMessageMetadataPart,
    ) -> Option<Cow<'_, [u8]>> {
        match self.raw_messages.get(message_id)? {
            DecodedRawMessage::Borrowed(chain) => Some(part.contents(chain)),
            DecodedRawMessage::Owned(vec) => Some(Cow::Owned(
                part.contents(&ChainedBytes::new(vec)).into_owned(),
            )),
        }
    }
}

impl DecodedPartContent<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DecodedPartContent::Text(text) => text.as_bytes(),
            DecodedPartContent::Binary(binary) => binary,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            DecodedPartContent::Text(text) => text.len(),
            DecodedPartContent::Binary(binary) => binary.len(),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            DecodedPartContent::Text(text) => text,
            DecodedPartContent::Binary(binary) => std::str::from_utf8(binary).unwrap_or_default(),
        }
    }
}

impl<'x> DecodedRawMessage<'x> {
    pub fn get(&'_ self, index: Range<usize>) -> Option<Cow<'_, [u8]>> {
        match self {
            DecodedRawMessage::Borrowed(bytes) => bytes.get(index),
            DecodedRawMessage::Owned(vec) => vec.get(index).map(Cow::Borrowed),
        }
    }
}

impl DecodedParts<'_> {
    pub fn message_end(&self, message_id: usize, enclosing_end: usize) -> usize {
        match self.raw_messages.get(message_id) {
            Some(DecodedRawMessage::Owned(vec)) => vec.len(),
            _ => enclosing_end,
        }
    }
}

impl ArchivedMessageMetadata {
    #[inline(always)]
    pub fn message_id(&self, message_id: ArchivedU16) -> &ArchivedMessageMetadataContents {
        &self.contents[u16::from(message_id) as usize]
    }

    pub fn decode_contents<'x>(&self, raw: ChainedBytes<'x>) -> DecodedParts<'x> {
        let mut result = DecodedParts {
            raw_messages: Vec::with_capacity(self.contents.len()),
            parts: Vec::new(),
        };

        for _ in 0..self.contents.len() {
            result
                .raw_messages
                .push(DecodedRawMessage::Borrowed(raw.clone()));
        }

        for (message_id, contents) in self.contents.iter().enumerate() {
            for part in contents.parts.iter() {
                let part_offset = u32::from(part.offset_header) as usize;
                match &part.body {
                    ArchivedMetadataPartType::Text
                    | ArchivedMetadataPartType::Html
                    | ArchivedMetadataPartType::Binary
                    | ArchivedMetadataPartType::InlineBinary => {
                        match result.raw_messages.get(message_id).unwrap() {
                            DecodedRawMessage::Borrowed(bytes) => {
                                result.parts.push(DecodedPart {
                                    message_id,
                                    part_offset,
                                    content: part.decode_contents(bytes),
                                });
                            }
                            DecodedRawMessage::Owned(bytes) => {
                                result.parts.push(DecodedPart {
                                    message_id,
                                    part_offset,
                                    content: match part.decode_contents(&ChainedBytes::new(bytes)) {
                                        DecodedPartContent::Text(text) => {
                                            DecodedPartContent::Text(text.into_owned().into())
                                        }
                                        DecodedPartContent::Binary(binary) => {
                                            DecodedPartContent::Binary(binary.into_owned().into())
                                        }
                                    },
                                });
                            }
                        }
                    }
                    ArchivedMetadataPartType::Message(nested_message_id) => {
                        let sub_contents =
                            if (part.flags & (PART_ENCODING_BASE64 | PART_ENCODING_QP)) != 0 {
                                match result.raw_messages.get(message_id).unwrap() {
                                    DecodedRawMessage::Borrowed(bytes) => {
                                        part.contents(bytes).into_owned()
                                    }
                                    DecodedRawMessage::Owned(bytes) => {
                                        let bytes = ChainedBytes::new(bytes);
                                        part.contents(&bytes).into_owned()
                                    }
                                }
                            } else if let Some(DecodedRawMessage::Owned(bytes)) =
                                result.raw_messages.get(message_id)
                            {
                                bytes.clone()
                            } else {
                                continue;
                            };

                        result.raw_messages[usize::from(*nested_message_id)] =
                            DecodedRawMessage::Owned(sub_contents);
                    }
                    _ => {}
                }
            }
        }

        result
    }
}

impl ArchivedMessageMetadataPart {
    pub fn contents<'x>(&self, raw_message: &ChainedBytes<'x>) -> Cow<'x, [u8]> {
        let bytes = raw_message.get(self.body_to_end()).unwrap_or_default();

        if (self.flags & PART_ENCODING_BASE64) != 0 {
            base64_decode(bytes.as_ref()).unwrap_or_default().into()
        } else if (self.flags & PART_ENCODING_QP) != 0 {
            quoted_printable_decode(bytes.as_ref())
                .unwrap_or_default()
                .into()
        } else {
            bytes
        }
    }

    #[inline(always)]
    pub fn body_to_end(&self) -> Range<usize> {
        (self.offset_body.to_native() as usize)..(self.offset_end.to_native() as usize)
    }

    #[inline(always)]
    pub fn header_to_end(&self) -> Range<usize> {
        self.offset_header.to_native() as usize..self.offset_end.to_native() as usize
    }

    #[inline(always)]
    pub fn header_to_body(&self) -> Range<usize> {
        self.offset_header.to_native() as usize..self.offset_body.to_native() as usize
    }

    pub fn decode_contents<'x>(&self, raw_message: &ChainedBytes<'x>) -> DecodedPartContent<'x> {
        let bytes = self.contents(raw_message);

        match self.body {
            ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                DecodedPartContent::Text(
                    match (
                        bytes,
                        self.header_value(&MetadataHeaderName::ContentType)
                            .and_then(|c| c.as_content_type())
                            .and_then(|ct| {
                                ct.attribute("charset")
                                    .and_then(|c| charset_decoder(c.as_bytes()))
                            }),
                    ) {
                        (Cow::Owned(vec), Some(charset_decoder)) => charset_decoder(&vec).into(),
                        (Cow::Owned(vec), None) => String::from_utf8(vec)
                            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
                            .into(),
                        (Cow::Borrowed(bytes), Some(charset_decoder)) => {
                            charset_decoder(bytes).into()
                        }
                        (Cow::Borrowed(bytes), None) => String::from_utf8_lossy(bytes),
                    },
                )
            }
            ArchivedMetadataPartType::Binary => DecodedPartContent::Binary(bytes),
            ArchivedMetadataPartType::InlineBinary => DecodedPartContent::Binary(bytes),
            ArchivedMetadataPartType::Message(_) | ArchivedMetadataPartType::Multipart(_) => {
                unreachable!()
            }
        }
    }
}

pub fn build_metadata_contents(
    message: mail_parser::Message<'_>,
) -> Box<[MessageMetadataContents]> {
    let mut messages = VecDeque::from([message]);
    let mut message_id = 0;
    let mut contents = Vec::new();

    while let Some(message) = messages.pop_front() {
        let mut parts = Vec::with_capacity(message.parts.len());

        for part in message.parts {
            let (size, body) = match part.body {
                PartType::Text(contents) => (contents.len(), MetadataPartType::Text),
                PartType::Html(contents) => (contents.len(), MetadataPartType::Html),
                PartType::Binary(contents) => (contents.len(), MetadataPartType::Binary),
                PartType::InlineBinary(contents) => {
                    (contents.len(), MetadataPartType::InlineBinary)
                }
                PartType::Message(message) => {
                    let message_len = message.root_part().raw_len();
                    messages.push_back(message);
                    message_id += 1;

                    (message_len as usize, MetadataPartType::Message(message_id))
                }
                PartType::Multipart(parts) => (
                    0,
                    MetadataPartType::Multipart(parts.into_iter().map(|p| p as u16).collect()),
                ),
            };

            let flags = match part.encoding {
                Encoding::None => 0,
                Encoding::QuotedPrintable => PART_ENCODING_QP,
                Encoding::Base64 => PART_ENCODING_BASE64,
            } | (if part.is_encoding_problem {
                PART_ENCODING_PROBLEM
            } else {
                0
            }) | (size as u32 & PART_SIZE_MASK);

            parts.push(MessageMetadataPart {
                headers: part
                    .headers
                    .into_iter()
                    .map(|hdr| MetadataHeader {
                        value: if matches!(
                            &hdr.name,
                            HeaderName::Subject
                                | HeaderName::From
                                | HeaderName::To
                                | HeaderName::Cc
                                | HeaderName::Date
                                | HeaderName::Bcc
                                | HeaderName::ReplyTo
                                | HeaderName::Sender
                                | HeaderName::Comments
                                | HeaderName::InReplyTo
                                | HeaderName::Keywords
                                | HeaderName::MessageId
                                | HeaderName::References
                                | HeaderName::ResentMessageId
                                | HeaderName::ContentDescription
                                | HeaderName::ContentId
                                | HeaderName::ContentLanguage
                                | HeaderName::ContentLocation
                                | HeaderName::ContentTransferEncoding
                                | HeaderName::ContentType
                                | HeaderName::ContentDisposition
                                | HeaderName::ListId
                        ) {
                            hdr.value
                        } else {
                            HeaderValue::Empty
                        }
                        .into(),
                        name: hdr.name.into(),
                        base_offset: hdr.offset_field,
                        start: (hdr.offset_start - hdr.offset_field) as u16,
                        end: (hdr.offset_end - hdr.offset_field) as u16,
                    })
                    .collect(),
                body,
                flags,
                offset_header: part.offset_header,
                offset_body: part.offset_body,
                offset_end: part.offset_end,
            });
        }
        contents.push(MessageMetadataContents {
            html_body: message.html_body.into_iter().map(|c| c as u16).collect(),
            text_body: message.text_body.into_iter().map(|c| c as u16).collect(),
            attachments: message.attachments.into_iter().map(|c| c as u16).collect(),
            parts: parts.into_boxed_slice(),
        });
    }
    contents.into_boxed_slice()
}

impl ArchivedMessageMetadataPart {
    pub fn is_message(&self) -> bool {
        matches!(self.body, ArchivedMetadataPartType::Message(_))
    }

    pub fn sub_parts(&self) -> Option<&ArchivedBox<[ArchivedU16]>> {
        if let ArchivedMetadataPartType::Multipart(parts) = &self.body {
            Some(parts)
        } else {
            None
        }
    }

    pub fn raw_len(&self) -> usize {
        (u32::from(self.offset_end)).saturating_sub(u32::from(self.offset_header)) as usize
    }

    pub fn header_values(
        &self,
        name: &MetadataHeaderName,
    ) -> impl Iterator<Item = &ArchivedMetadataHeaderValue> + Sync + Send {
        self.headers.iter().filter_map(move |header| {
            if &header.name == name {
                Some(&header.value)
            } else {
                None
            }
        })
    }

    pub fn header_value(&self, name: &MetadataHeaderName) -> Option<&ArchivedMetadataHeaderValue> {
        self.headers.iter().rev().find_map(move |header| {
            if &header.name == name {
                Some(&header.value)
            } else {
                None
            }
        })
    }

    pub fn from(&self) -> Option<&str> {
        self.header_value(&MetadataHeaderName::From)
            .and_then(|header| header.as_single_address())
            .and_then(|addr| addr.address.as_deref())
    }

    pub fn subject(&self) -> Option<&str> {
        self.header_value(&MetadataHeaderName::Subject)
            .and_then(|header| header.as_text())
    }

    pub fn date(&self) -> Option<DateTime> {
        self.header_value(&MetadataHeaderName::Date)
            .and_then(|header| header.as_datetime())
            .map(|dt| dt.into())
    }

    pub fn message_id(&self) -> Option<&str> {
        self.header_value(&MetadataHeaderName::MessageId)
            .and_then(|header| header.as_text())
    }

    pub fn in_reply_to(&self) -> &ArchivedMetadataHeaderValue {
        self.header_value(&MetadataHeaderName::InReplyTo)
            .unwrap_or(&ArchivedMetadataHeaderValue::Empty)
    }

    pub fn content_description(&self) -> Option<&str> {
        self.header_value(&MetadataHeaderName::ContentDescription)
            .and_then(|header| header.as_text())
    }

    pub fn content_disposition(&self) -> Option<&ArchivedMetadataContentType> {
        self.header_value(&MetadataHeaderName::ContentDisposition)
            .and_then(|header| header.as_content_type())
    }

    pub fn content_id(&self) -> Option<&str> {
        self.header_value(&MetadataHeaderName::ContentId)
            .and_then(|header| header.as_text())
    }

    pub fn content_transfer_encoding(&self) -> Option<&str> {
        self.header_value(&MetadataHeaderName::ContentTransferEncoding)
            .and_then(|header| header.as_text())
    }

    pub fn content_type(&self) -> Option<&ArchivedMetadataContentType> {
        self.header_value(&MetadataHeaderName::ContentType)
            .and_then(|header| header.as_content_type())
    }

    pub fn is_text_mime_type(&self) -> bool {
        matches!(
            self.body,
            ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html
        ) && self
            .content_type()
            .is_none_or(|ct| ct.ctype().eq_ignore_ascii_case("text"))
    }

    pub fn content_language(&self) -> &ArchivedMetadataHeaderValue {
        self.header_value(&MetadataHeaderName::ContentLanguage)
            .unwrap_or(&ArchivedMetadataHeaderValue::Empty)
    }

    pub fn content_location(&self) -> Option<&str> {
        self.header_value(&MetadataHeaderName::ContentLocation)
            .and_then(|header| header.as_text())
    }

    pub fn attachment_name(&self) -> Option<&str> {
        self.content_disposition()
            .and_then(|cd| cd.attribute("filename"))
            .or_else(|| self.content_type().and_then(|ct| ct.attribute("name")))
    }
}

impl From<HeaderName<'_>> for MetadataHeaderName {
    fn from(value: HeaderName<'_>) -> Self {
        let known = MetadataHeaderName::parse(value.as_str().as_bytes());

        match known {
            Some(name) => name,
            None => MetadataHeaderName::Other(value.into_string()),
        }
    }
}

impl From<HeaderValue<'_>> for MetadataHeaderValue {
    fn from(value: HeaderValue<'_>) -> Self {
        match value {
            HeaderValue::Address(address) => match address {
                Address::List(address) => MetadataHeaderValue::AddressList(
                    address
                        .into_iter()
                        .map(|a| MetadataAddress {
                            name: a.name.map(|a| a.into_owned()),
                            address: a.address.map(|a| a.into_owned()),
                        })
                        .collect(),
                ),
                Address::Group(groups) => MetadataHeaderValue::AddressGroup(
                    groups
                        .into_iter()
                        .map(|g| MetadataAddressGroup {
                            name: g.name.map(|a| a.into_owned()),
                            addresses: g
                                .addresses
                                .into_iter()
                                .map(|a| MetadataAddress {
                                    name: a.name.map(|a| a.into_owned()),
                                    address: a.address.map(|a| a.into_owned()),
                                })
                                .collect(),
                        })
                        .collect(),
                ),
            },
            HeaderValue::Text(text) => MetadataHeaderValue::Text(text.into_owned()),
            HeaderValue::TextList(texts) => {
                MetadataHeaderValue::TextList(texts.into_iter().map(|v| v.into_owned()).collect())
            }
            HeaderValue::DateTime(dt) => MetadataHeaderValue::DateTime(MetadataDateTime {
                year: dt.year,
                month: dt.month,
                day: dt.day,
                hour: dt.hour,
                minute: dt.minute,
                second: dt.second,
                tz_hour: (if dt.tz_before_gmt { -1 } else { 1 }) * dt.tz_hour as i8,
                tz_minute: dt.tz_minute,
            }),
            HeaderValue::ContentType(ct) => {
                MetadataHeaderValue::ContentType(Box::new(MetadataContentType {
                    c_type: ct.c_type.into_owned(),
                    c_subtype: ct.c_subtype.map(|v| v.into_owned()),
                    attributes: ct
                        .attributes
                        .unwrap_or_default()
                        .into_iter()
                        .map(|a| MetadataAttribute {
                            name: a.name.into_owned(),
                            value: a.value.into_owned(),
                        })
                        .collect(),
                }))
            }
            HeaderValue::Received(_) | HeaderValue::Empty => MetadataHeaderValue::Empty,
        }
    }
}

impl From<&ArchivedMetadataDateTime> for DateTime {
    fn from(dt: &ArchivedMetadataDateTime) -> Self {
        DateTime {
            year: dt.year.to_native(),
            month: dt.month,
            day: dt.day,
            hour: dt.hour,
            minute: dt.minute,
            second: dt.second,
            tz_before_gmt: dt.tz_hour < 0,
            tz_hour: dt.tz_hour.unsigned_abs(),
            tz_minute: dt.tz_minute,
        }
    }
}

impl From<&MetadataDateTime> for DateTime {
    fn from(dt: &MetadataDateTime) -> Self {
        DateTime {
            year: dt.year,
            month: dt.month,
            day: dt.day,
            hour: dt.hour,
            minute: dt.minute,
            second: dt.second,
            tz_before_gmt: dt.tz_hour < 0,
            tz_hour: dt.tz_hour.unsigned_abs(),
            tz_minute: dt.tz_minute,
        }
    }
}

impl ArchivedMessageMetadataContents {
    pub fn root_part(&self) -> &ArchivedMessageMetadataPart {
        &self.parts[0]
    }
}

impl ArchivedMetadataContentType {
    pub fn ctype(&self) -> &str {
        &self.c_type
    }

    pub fn subtype(&self) -> Option<&str> {
        self.c_subtype.as_ref().map(|s| s.as_ref())
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| *a.name == *name)
            .map(|a| a.value.as_ref())
    }

    /// Returns `true` when the provided attribute name is present
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| *a.name == *name)
    }

    pub fn is_attachment(&self) -> bool {
        self.c_type.eq_ignore_ascii_case("attachment")
    }

    pub fn is_inline(&self) -> bool {
        self.c_type.eq_ignore_ascii_case("inline")
    }
}

impl ArchivedMetadataHeaderValue {
    pub fn is_empty(&self) -> bool {
        self == &MetadataHeaderValue::Empty
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            ArchivedMetadataHeaderValue::Text(s) => Some(s.as_ref()),
            ArchivedMetadataHeaderValue::TextList(l) => l.last().map(|v| v.as_ref()),
            _ => None,
        }
    }

    pub fn as_text_list(&self) -> Option<&[ArchivedString]> {
        match self {
            ArchivedMetadataHeaderValue::Text(s) => Some(std::slice::from_ref(s)),
            ArchivedMetadataHeaderValue::TextList(l) => Some(l.as_ref()),
            _ => None,
        }
    }

    pub fn as_content_type(&self) -> Option<&ArchivedMetadataContentType> {
        match self {
            ArchivedMetadataHeaderValue::ContentType(c) => Some(c.as_ref()),
            _ => None,
        }
    }

    pub fn as_datetime(&self) -> Option<&ArchivedMetadataDateTime> {
        match self {
            ArchivedMetadataHeaderValue::DateTime(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_single_address(&self) -> Option<&ArchivedMetadataAddress> {
        match self {
            ArchivedMetadataHeaderValue::AddressList(list) => list.first(),
            ArchivedMetadataHeaderValue::AddressGroup(groups) => {
                groups.first().and_then(|g| g.addresses.first())
            }
            _ => None,
        }
    }
}

impl ArchivedMetadataHeader {
    #[inline(always)]
    pub fn value_range(&self) -> Range<usize> {
        (self.base_offset.to_native() as usize + self.start.to_native() as usize)
            ..(self.base_offset.to_native() as usize + self.end.to_native() as usize)
    }

    #[inline(always)]
    pub fn name_value_range(&self) -> Range<usize> {
        (self.base_offset.to_native() as usize)
            ..(self.base_offset.to_native() as usize + self.end.to_native() as usize)
    }
}

impl ArchivedMetadataHeaderName {
    pub fn is_mime_header(&self) -> bool {
        matches!(
            self,
            ArchivedMetadataHeaderName::ContentDescription
                | ArchivedMetadataHeaderName::ContentId
                | ArchivedMetadataHeaderName::ContentLanguage
                | ArchivedMetadataHeaderName::ContentLocation
                | ArchivedMetadataHeaderName::ContentTransferEncoding
                | ArchivedMetadataHeaderName::ContentType
                | ArchivedMetadataHeaderName::ContentDisposition
        )
    }
}

impl From<&ArchivedMetadataHeaderValue> for HeaderValue<'static> {
    fn from(value: &ArchivedMetadataHeaderValue) -> Self {
        match value {
            ArchivedMetadataHeaderValue::AddressList(addr) => HeaderValue::Address(Address::List(
                addr.as_ref().iter().map(Into::into).collect(),
            )),
            ArchivedMetadataHeaderValue::AddressGroup(addr) => HeaderValue::Address(
                Address::Group(addr.as_ref().iter().map(Into::into).collect()),
            ),
            ArchivedMetadataHeaderValue::Text(text) => HeaderValue::Text(text.to_string().into()),
            ArchivedMetadataHeaderValue::TextList(textlist) => HeaderValue::TextList(
                textlist
                    .as_ref()
                    .iter()
                    .map(|s| s.to_string().into())
                    .collect(),
            ),
            ArchivedMetadataHeaderValue::DateTime(dt) => HeaderValue::DateTime(dt.into()),
            ArchivedMetadataHeaderValue::ContentType(ct) => {
                HeaderValue::ContentType(ct.as_ref().into())
            }
            ArchivedMetadataHeaderValue::Empty => HeaderValue::Empty,
        }
    }
}

impl From<&ArchivedMetadataAddress> for Addr<'static> {
    fn from(value: &ArchivedMetadataAddress) -> Self {
        Addr {
            name: value.name.as_ref().map(|n| n.to_string().into()),
            address: value.address.as_ref().map(|a| a.to_string().into()),
        }
    }
}

impl From<&ArchivedMetadataAddressGroup> for Group<'static> {
    fn from(value: &ArchivedMetadataAddressGroup) -> Self {
        Group {
            name: value.name.as_ref().map(|n| n.to_string().into()),
            addresses: value.addresses.as_ref().iter().map(Into::into).collect(),
        }
    }
}

impl From<&ArchivedMetadataContentType> for ContentType<'static> {
    fn from(value: &ArchivedMetadataContentType) -> Self {
        ContentType {
            c_type: value.ctype().to_string().into(),
            c_subtype: value.subtype().map(|s| s.to_string().into()),
            attributes: Some(
                value
                    .attributes
                    .iter()
                    .map(|a| Attribute {
                        name: a.name.to_string().into(),
                        value: a.value.to_string().into(),
                    })
                    .collect(),
            ),
        }
    }
}
