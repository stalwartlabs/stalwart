/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    inbound::dkim::{DkimSign, SignedMessage, strip_signature_headers},
    queue::{
        Error, ErrorDetails, FROM_DSN, FROM_REPORT, Message, MessageWrapper, Metadata,
        QueueEnvelope, RecipientBlob, Status, spool::QueueParams,
    },
};
use common::{
    Server,
    expr::Bump,
    gateway::{
        config::{GatewayConfig, GatewayMinTrust, GatewayMode},
        resolver::{KeyQuery, KeyResolver, Resolution, ResolvedKey},
    },
    storage::encryption::RecipientEncrypt,
};
use crypto::{EcdhWrapParameters, EncryptOptions, Protection, RecipientIds};
use mail_parser::MessageParser;
use registry::schema::enums::CompressionAlgo;
use std::{borrow::Cow, sync::Arc};
use store::write::{BatchBuilder, BlobLink, BlobOp, blob::BlobLinkValue, now};
use trc::EncryptionEvent;
use types::blob_hash::BlobHash;

const COPY_RESERVE_SECS: u64 = 600;
const MAX_PENDING_COPY_BYTES: usize = 1 << 20;

#[derive(Default)]
pub(crate) struct QueueEncryption {
    pub blobs: Vec<RecipientBlob>,
    pub pending: PendingCopies,
    pub dkim2_signed: bool,
    pub rejected: Vec<(usize, RejectReason)>,
    pub reserved_until: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum RejectReason {
    Policy,
    NoKey,
    Malformed,
    EncryptionFailed,
}

#[derive(Default)]
pub(crate) struct PendingCopies {
    copies: Vec<(BlobHash, Vec<u8>)>,
    bytes: usize,
}

struct EncryptionKey {
    key: Arc<ResolvedKey>,
    required: bool,
    rcpt_idx: usize,
}

struct EncryptedCopy {
    raw: Vec<u8>,
    dkim2_signed: bool,
}

enum RcptEncryption {
    Plaintext,
    Encrypt(EncryptionKey),
    Reject(RejectReason),
}

pub(crate) trait OutboundEncryption: Sync + Send {
    fn encrypt_recipients(
        &self,
        message: &MessageWrapper,
        params: &QueueParams<'_, '_>,
    ) -> impl Future<Output = trc::Result<QueueEncryption>> + Send;
}

trait RecipientPolicy: Sync + Send {
    fn recipient_encryption(
        &self,
        gateway: &GatewayConfig,
        envelope: &QueueEnvelope<'_>,
        rcpt_idx: usize,
        arena: &mut Bump,
        span_id: u64,
    ) -> impl Future<Output = trc::Result<RcptEncryption>> + Send;

    fn encrypted_copy(
        &self,
        gateway: &GatewayConfig,
        message: &MessageWrapper,
        plaintext: &mail_parser::Message<'_>,
        key: &EncryptionKey,
        params: &QueueParams<'_, '_>,
    ) -> impl Future<Output = Option<EncryptedCopy>> + Send;

    fn store_pending_copies(
        &self,
        pending: &mut PendingCopies,
        reserved_until: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl OutboundEncryption for Server {
    async fn encrypt_recipients(
        &self,
        message: &MessageWrapper,
        params: &QueueParams<'_, '_>,
    ) -> trc::Result<QueueEncryption> {
        let mut result = QueueEncryption {
            reserved_until: now() + COPY_RESERVE_SECS,
            ..Default::default()
        };
        let Some(gateway) = self
            .core
            .email
            .gateway
            .as_deref()
            .filter(|gateway| gateway.outbound_enabled)
        else {
            return Ok(result);
        };
        if !message.message.gateway_applies() {
            return Ok(result);
        }

        let mut arena = Bump::new();
        let mut keys = Vec::new();
        let mut rejected = Vec::new();
        for (rcpt_idx, rcpt) in message.message.recipients.iter().enumerate() {
            let envelope = QueueEnvelope::new(&message.message, rcpt);
            match self
                .recipient_encryption(gateway, &envelope, rcpt_idx, &mut arena, message.span_id)
                .await?
            {
                RcptEncryption::Plaintext => {}
                RcptEncryption::Encrypt(key) => keys.push(key),
                RcptEncryption::Reject(reason) => rejected.push((rcpt_idx, reason)),
            }
        }
        if keys.is_empty() && rejected.is_empty() {
            return Ok(result);
        }

        let raw_message = match params.raw_headers.filter(|headers| !headers.is_empty()) {
            Some(headers) => Cow::Owned([headers, params.raw_message].concat()),
            None => Cow::Borrowed(params.raw_message),
        };
        let stripped = strip_signature_headers(&raw_message);
        let Some(plaintext) = MessageParser::default().parse(stripped.as_ref()) else {
            rejected.extend(
                keys.iter()
                    .map(|key| (key.rcpt_idx, RejectReason::Malformed)),
            );
            result.reject(rejected, message.span_id);
            return Ok(result);
        };
        if crypto::is_ciphertext(&plaintext) {
            return Ok(result);
        }
        let skip_signed =
            !gateway.encrypt_signed && crypto::protection(&plaintext) == Protection::Signed;

        for key in keys {
            if skip_signed && !key.required {
                continue;
            }
            match self
                .encrypted_copy(gateway, message, &plaintext, &key, params)
                .await
            {
                Some(copy) => {
                    result.dkim2_signed |= copy.dkim2_signed;
                    result.push_copy(key.rcpt_idx, copy.raw);
                    if result.pending.bytes >= MAX_PENDING_COPY_BYTES {
                        self.store_pending_copies(&mut result.pending, result.reserved_until)
                            .await?;
                    }
                }
                None => rejected.push((key.rcpt_idx, RejectReason::EncryptionFailed)),
            }
        }
        result.reject(rejected, message.span_id);
        Ok(result)
    }
}

impl RecipientPolicy for Server {
    async fn recipient_encryption(
        &self,
        gateway: &GatewayConfig,
        envelope: &QueueEnvelope<'_>,
        rcpt_idx: usize,
        arena: &mut Bump,
        span_id: u64,
    ) -> trc::Result<RcptEncryption> {
        let Some(mode) = self
            .eval_if::<GatewayMode, _>(&gateway.outbound, envelope, arena, span_id)
            .await
        else {
            return Ok(RcptEncryption::Reject(RejectReason::Policy));
        };
        if mode == GatewayMode::Disable {
            return Ok(RcptEncryption::Plaintext);
        }
        let Some(GatewayMinTrust(min_trust)) = self
            .eval_if(&gateway.min_trust, envelope, arena, span_id)
            .await
        else {
            return Ok(RcptEncryption::Reject(RejectReason::Policy));
        };

        let query = KeyQuery {
            address: envelope.rcpt.address(),
            min_trust,
        };
        let required = mode == GatewayMode::Required;
        Ok(match self.resolve_key(&query).await? {
            Resolution::Found(key) => RcptEncryption::Encrypt(EncryptionKey {
                key,
                required,
                rcpt_idx,
            }),
            Resolution::NotFound if required => RcptEncryption::Reject(RejectReason::NoKey),
            Resolution::NotFound => {
                trc::event!(
                    Encryption(EncryptionEvent::GatewayPlaintext),
                    SpanId = span_id,
                    Reason = RejectReason::NoKey.as_str(),
                );
                RcptEncryption::Plaintext
            }
        })
    }

    async fn encrypted_copy(
        &self,
        gateway: &GatewayConfig,
        message: &MessageWrapper,
        plaintext: &mail_parser::Message<'_>,
        key: &EncryptionKey,
        params: &QueueParams<'_, '_>,
    ) -> Option<EncryptedCopy> {
        let options = EncryptOptions {
            profile: key.key.profile,
            header_protection: gateway.header_protection,
            ecdh_wrap_parameters: EcdhWrapParameters::Null,
            recipient_ids: RecipientIds::Real,
        };
        let encrypted = key
            .key
            .recipients
            .encrypt_on_runtime(plaintext, &options)
            .ok()?;

        let mut single = message.for_recipient(key.rcpt_idx);
        let mut sign_params = QueueParams::new(&encrypted.message, message.span_id, self)
            .with_dkim_signers(params.dkim_signers.clone())
            .with_exploded(params.exploded || message.message.recipients.len() > 1);
        let SignedMessage {
            headers,
            dkim2_signed,
            ..
        } = self.sign_message(&mut single, &mut sign_params).await;

        let mut raw = Vec::with_capacity(headers.len() + encrypted.message.len());
        raw.extend_from_slice(&headers);
        raw.extend_from_slice(&encrypted.message);
        trc::event!(
            Encryption(EncryptionEvent::GatewayEncrypted),
            SpanId = message.span_id,
            Fingerprint = key.key.fingerprint.to_string(),
        );
        Some(EncryptedCopy { raw, dkim2_signed })
    }

    async fn store_pending_copies(
        &self,
        pending: &mut PendingCopies,
        reserved_until: u64,
    ) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        pending.link(&mut batch, reserved_until);
        self.store().write_batch(&mut batch).await?;
        pending.put(self).await
    }
}

impl PendingCopies {
    pub(crate) fn link(&self, batch: &mut BatchBuilder, reserved_until: u64) {
        for (hash, raw) in &self.copies {
            batch.set(
                BlobOp::Link {
                    hash: hash.clone(),
                    to: BlobLink::Temporary {
                        until: reserved_until,
                    },
                },
                BlobLinkValue::new(raw.len()),
            );
        }
    }

    pub(crate) async fn put(&mut self, server: &Server) -> trc::Result<()> {
        for (hash, raw) in self.copies.drain(..) {
            server
                .blob_store()
                .put_blob(hash.as_slice(), &raw, CompressionAlgo::None)
                .await?;
        }
        self.bytes = 0;
        Ok(())
    }
}

impl QueueEncryption {
    fn push_copy(&mut self, rcpt_idx: usize, raw: Vec<u8>) {
        let hash = BlobHash::generate(&raw);
        self.blobs.push(RecipientBlob {
            hash: hash.clone(),
            size: raw.len() as u64,
            rcpt_idx: rcpt_idx as u64,
        });
        self.pending.bytes += raw.len();
        self.pending.copies.push((hash, raw));
    }

    pub(crate) fn covers(&self, recipients: usize) -> bool {
        self.blobs.len() + self.rejected.len() == recipients
    }

    fn reject(&mut self, rejected: Vec<(usize, RejectReason)>, span_id: u64) {
        for (rcpt_idx, reason) in rejected {
            trc::event!(
                Encryption(EncryptionEvent::GatewayBounced),
                SpanId = span_id,
                Reason = reason.as_str(),
            );
            self.rejected.push((rcpt_idx, reason));
        }
    }
}

impl RejectReason {
    fn as_str(self) -> &'static str {
        match self {
            RejectReason::Policy => "PolicyEvaluationFailed",
            RejectReason::NoKey => "NoKey",
            RejectReason::Malformed => "MalformedMessage",
            RejectReason::EncryptionFailed => "EncryptionFailed",
        }
    }

    fn details(self) -> &'static str {
        match self {
            RejectReason::Policy => "The encryption policy could not be evaluated",
            RejectReason::NoKey => "No usable encryption key for this recipient",
            RejectReason::Malformed => "The message could not be parsed for encryption",
            RejectReason::EncryptionFailed => "The message could not be encrypted",
        }
    }
}

impl Message {
    fn gateway_applies(&self) -> bool {
        self.flags & (FROM_DSN | FROM_REPORT) == 0
    }

    pub(crate) fn recipient_blobs(&self) -> impl Iterator<Item = &RecipientBlob> {
        self.metadata.iter().filter_map(|metadata| match metadata {
            Metadata::Blob(blob) => Some(blob.as_ref()),
            _ => None,
        })
    }

    pub(crate) fn queued_bytes(&self) -> u64 {
        self.recipient_blobs()
            .fold(self.size, |size, blob| size.saturating_add(blob.size))
    }
}

impl MessageWrapper {
    pub(crate) fn reject_recipients(&mut self, rejected: &[(usize, RejectReason)]) {
        for (rcpt_idx, reason) in rejected {
            if let Some(rcpt) = self.message.recipients.get_mut(*rcpt_idx) {
                rcpt.status = Status::PermanentFailure(Box::new(ErrorDetails::encryption(*reason)));
            }
        }
    }

    fn for_recipient(&self, rcpt_idx: usize) -> MessageWrapper {
        let message = &self.message;
        MessageWrapper {
            queue_id: self.queue_id,
            queue_name: self.queue_name,
            is_multi_queue: false,
            span_id: self.span_id,
            message: Message {
                created: message.created,
                blob_hash: message.blob_hash.clone(),
                return_path: message.return_path.clone(),
                recipients: vec![message.recipients[rcpt_idx].clone()],
                received_from_ip: message.received_from_ip,
                received_via_port: message.received_via_port,
                flags: message.flags,
                env_id: None,
                priority: message.priority,
                size: message.size,
                metadata: Default::default(),
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                tenant_ids: Default::default(),
                // SPDX-SnippetEnd
            },
        }
    }
}

impl ErrorDetails {
    fn encryption(reason: RejectReason) -> Self {
        ErrorDetails {
            entity: "localhost".into(),
            details: Error::EncryptionError(reason.details().into()),
        }
    }
}
