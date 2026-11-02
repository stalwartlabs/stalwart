/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::{MessageWrapper, Metadata, spool::QueueParams};
use ahash::AHashSet;
use common::{
    Server,
    config::smtp::auth::{Dkim1Signer, Dkim2Signers, DkimSigners},
    expr::{Bump, functions::ResolveVariable, if_block::IfBlock},
};
use mail_auth::{
    AuthenticatedMessage, Dkim2Result,
    dkim2::{
        ChainBinding, Dkim2Error, Dkim2Output, Envelope, Hop, MessageInstance, Signature,
        Verification,
    },
    headers::HeaderWriter,
};
use mail_parser::HeaderForm;
use memchr::memchr_iter;
use std::{borrow::Cow, iter::once, sync::Arc};
use trc::{Dkim2Event, EventType};
use utils::sanitize_email;

pub(crate) trait DkimSign: Sync + Send {
    fn sign_message(
        &self,
        message: &mut MessageWrapper,
        params: &mut QueueParams<'_, '_>,
    ) -> impl Future<Output = SignedMessage> + Send;

    fn eval_signers(
        &self,
        if_block: &IfBlock,
        resolver: &impl ResolveVariable,
        session_id: u64,
    ) -> impl Future<Output = Option<Arc<DkimSigners>>> + Send;

    fn dkim2_signing_proof<'x, R>(
        &'x self,
        signers: Option<&DkimSigners>,
        message: &'x AuthenticatedMessage<'x>,
        mail_from: &str,
        rcpt_to: R,
    ) -> impl Future<Output = Option<Dkim2Output<'x>>> + Send
    where
        R: IntoIterator<Item: AsRef<str> + Send, IntoIter: Send> + Send;

    fn dkim2_sign_or_restart(
        &self,
        message: &MessageWrapper,
        params: &mut QueueParams<'_, '_>,
        dkim2: &Dkim2Signers,
        headers: &mut Vec<u8>,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send;

    fn restart_dkim2_chain(
        &self,
        message: &MessageWrapper,
        params: &mut QueueParams<'_, '_>,
        dkim2: &Dkim2Signers,
        headers: &mut Vec<u8>,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send;

    fn has_remote_domain<'x>(
        &self,
        domains: impl Iterator<Item = &'x str> + Send,
    ) -> impl Future<Output = bool> + Send;
}

impl DkimSign for Server {
    async fn sign_message(
        &self,
        message: &mut MessageWrapper,
        params: &mut QueueParams<'_, '_>,
    ) -> SignedMessage {
        let signers = params.dkim_signers.take();
        let dkim2 = signers
            .as_ref()
            .filter(|_| !params.dkim1_only)
            .and_then(|signers| signers.dkim2.as_ref());
        let chain_broken = params.dkim2_verified.is_some_and(|output| {
            matches!(
                output.result(),
                Dkim2Result::Fail(_) | Dkim2Result::PermError(_) | Dkim2Result::TempError(_)
            )
        });

        let mut dkim2_headers = Vec::new();
        let stripped_message = match dkim2 {
            Some(dkim2) if chain_broken => {
                self.restart_dkim2_chain(message, params, dkim2, &mut dkim2_headers)
                    .await
            }
            Some(dkim2) => {
                self.dkim2_sign_or_restart(message, params, dkim2, &mut dkim2_headers)
                    .await
            }
            None => None,
        };

        let mut headers = Vec::new();
        if let Some(signers) = &signers
            && !signers.dkim1.is_empty()
        {
            let raw_message = stripped_message.as_deref().unwrap_or(params.raw_message);
            headers.reserve(64 + dkim2_headers.len());
            for signer in &signers.dkim1 {
                let result = match (signer, params.raw_headers) {
                    (Dkim1Signer::RsaSha256(signer), None) => signer.sign(raw_message),
                    (Dkim1Signer::Ed25519Sha256(signer), None) => signer.sign(raw_message),
                    (Dkim1Signer::RsaSha256(signer), Some(headers)) => {
                        signer.sign_chained([headers, raw_message].iter().copied())
                    }
                    (Dkim1Signer::Ed25519Sha256(signer), Some(headers)) => {
                        signer.sign_chained([headers, raw_message].iter().copied())
                    }
                };

                match result {
                    Ok(signature) => {
                        signature.write_header(&mut headers);
                    }
                    Err(err) => {
                        trc::error!(
                            trc::Error::from(err)
                                .span_id(params.session_id)
                                .details("Failed to sign message")
                                .caused_by(trc::location!())
                        );
                    }
                }
            }
        }
        if headers.is_empty() {
            headers = dkim2_headers;
        } else {
            headers.extend_from_slice(&dkim2_headers);
        }

        SignedMessage {
            headers,
            dkim2_signed: params.dkim2_signed,
            stripped_message,
        }
    }

    async fn dkim2_signing_proof<'x, R>(
        &'x self,
        signers: Option<&DkimSigners>,
        message: &'x AuthenticatedMessage<'x>,
        mail_from: &str,
        rcpt_to: R,
    ) -> Option<Dkim2Output<'x>>
    where
        R: IntoIterator<Item: AsRef<str> + Send, IntoIter: Send> + Send,
    {
        if signers.is_some_and(|signers| signers.dkim2.is_some())
            && (!message.dkim2_signatures().is_empty()
                || !message.dkim2_instances().is_empty()
                || message.has_dkim2_errors())
        {
            Some(
                self.core
                    .smtp
                    .resolvers
                    .dns
                    .verify_dkim2(
                        self.inner.cache.build_auth_parameters(message),
                        Envelope { mail_from, rcpt_to },
                    )
                    .await,
            )
        } else {
            None
        }
    }

    async fn dkim2_sign_or_restart(
        &self,
        message: &MessageWrapper,
        params: &mut QueueParams<'_, '_>,
        dkim2: &Dkim2Signers,
        headers: &mut Vec<u8>,
    ) -> Option<Vec<u8>> {
        let modified =
            AuthenticatedMessage::parse_with_opts(params.raw_message, params.raw_headers, true)?;
        let verified = params.dkim2_verified.filter(|output| {
            matches!(output.result(), Dkim2Result::Pass)
                && output.verification() == Verification::Full
        });
        let has_chain = !modified.dkim2_signatures().is_empty()
            || !modified.dkim2_instances().is_empty()
            || modified.has_dkim2_errors();

        if !has_chain || verified.is_some() {
            let parsed_original;
            let original = match params.original_authenticated_message {
                Some(original) => Some(original),
                None if has_chain => {
                    parsed_original = params
                        .original_raw_message
                        .and_then(AuthenticatedMessage::parse);
                    parsed_original.as_ref()
                }
                None => None,
            };
            match dkim2_sign(
                message, params, dkim2, &modified, original, verified, headers,
            ) {
                Ok(()) => return None,
                Err(mail_auth::Error::Dkim2(Dkim2Error::NotFullyVerified)) => {}
                Err(err) => {
                    log_dkim2_error(err, params.session_id);
                    if !has_chain {
                        return None;
                    }
                }
            }
        }

        self.restart_dkim2_chain(message, params, dkim2, headers)
            .await
    }

    async fn restart_dkim2_chain(
        &self,
        message: &MessageWrapper,
        params: &mut QueueParams<'_, '_>,
        dkim2: &Dkim2Signers,
        headers: &mut Vec<u8>,
    ) -> Option<Vec<u8>> {
        if !self
            .has_remote_domain(
                message
                    .message
                    .recipients
                    .iter()
                    .map(|rcpt| rcpt.domain_part()),
            )
            .await
        {
            return None;
        }

        let stripped = strip_dkim2_headers(params.raw_message);
        if let Some(fresh) = AuthenticatedMessage::parse_with_opts(
            stripped.as_deref().unwrap_or(params.raw_message),
            params.raw_headers,
            true,
        ) && let Err(err) = dkim2_sign(message, params, dkim2, &fresh, None, None, headers)
        {
            log_dkim2_error(err, params.session_id);
        }
        stripped
    }

    async fn has_remote_domain<'x>(&self, domains: impl Iterator<Item = &'x str> + Send) -> bool {
        for domain in domains {
            if !matches!(self.domain(domain).await, Ok(Some(_))) {
                return true;
            }
        }
        false
    }

    async fn eval_signers(
        &self,
        if_block: &IfBlock,
        resolver: &impl ResolveVariable,
        session_id: u64,
    ) -> Option<Arc<DkimSigners>> {
        let mut arena = Bump::new();
        let sign_with_domain = self
            .eval_if::<String, _>(if_block, resolver, &mut arena, session_id)
            .await?;
        match self.dkim_signers(&sign_with_domain).await {
            Ok(signers) => signers,
            Err(err) => {
                trc::error!(
                    err.span_id(session_id)
                        .details("Failed to retrieve DKIM signers")
                );
                None
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct SignedMessage {
    pub headers: Vec<u8>,
    pub dkim2_signed: bool,
    pub stripped_message: Option<Vec<u8>>,
}

fn log_dkim2_error(err: mail_auth::Error, session_id: u64) {
    let err = trc::Error::from(err);
    let err = if matches!(
        err.as_ref(),
        EventType::Dkim2(Dkim2Event::CustodyBroken | Dkim2Event::ChainInvalid)
    ) {
        err
    } else {
        EventType::Dkim2(Dkim2Event::SigningFailed).caused_by(err)
    };
    trc::error!(err.span_id(session_id).caused_by(trc::location!()));
}

fn dkim2_sign(
    message: &MessageWrapper,
    params: &mut QueueParams<'_, '_>,
    dkim2: &Dkim2Signers,
    modified: &AuthenticatedMessage<'_>,
    original: Option<&AuthenticatedMessage<'_>>,
    verified: Option<&Dkim2Output<'_>>,
    headers: &mut Vec<u8>,
) -> mail_auth::Result<()> {
    let instance = MessageInstance::from_message(modified, original, &dkim2.hashes)?;
    let signer = &dkim2.signer;
    let exploded = params.exploded || message.message.recipients.len() > 1;
    let return_path = message.message.return_path.as_ref();
    let envelopes = message.undisclosed_recipients(modified);

    let disclosed = if !envelopes.disclosed_recipients.is_empty() {
        Some(signer.sign_with_message_instance(
            modified,
            instance.as_ref(),
            dkim2_hop(return_path, envelopes.disclosed_recipients, exploded),
            verified,
        )?)
    } else {
        None
    };
    let mut undisclosed = Vec::with_capacity(envelopes.undisclosed_recipients.len() + 1);
    for (pos, rcpt) in envelopes.undisclosed_recipients {
        if params
            .encrypted_recipients
            .binary_search(&(pos as u64))
            .is_ok()
        {
            continue;
        }
        undisclosed.push((
            pos as u64,
            signer.sign_with_message_instance(
                modified,
                instance.as_ref(),
                dkim2_hop(return_path, [rcpt], exploded),
                verified,
            )?,
        ));
    }

    if let Some(instance) = &instance {
        instance.write_header(headers);
    }
    if let Some(signed) = disclosed {
        if undisclosed.is_empty() {
            headers.reserve(signature_header_capacity(&signed.signature));
            signed.signature.write_header(headers);
        } else {
            undisclosed.push((u64::MAX, signed));
        }
    }
    for (id, signed) in undisclosed {
        let mut header = Vec::with_capacity(signature_header_capacity(&signed.signature));
        signed.signature.write_header(&mut header);
        params.metadata.push(Metadata::Headers {
            value: header.into_boxed_slice(),
            id,
        });
    }
    params.dkim2_signed = true;

    Ok(())
}

fn dkim2_hop<'x, R>(return_path: &'x str, rcpt_to: R, exploded: bool) -> Hop<&'x str, R, String>
where
    R: IntoIterator<Item = &'x str>,
{
    let hop = Hop::real(return_path, rcpt_to);
    if exploded { hop.exploded() } else { hop }
}

fn signature_header_capacity(signature: &Signature) -> usize {
    let tags = match &signature.chain {
        ChainBinding::Envelope { mail_from, rcpt_to } => {
            mail_from.len() + rcpt_to.iter().map(|rcpt| rcpt.len() + 1).sum::<usize>()
        }
        ChainBinding::NextDomain(domain) => domain.len(),
    };
    let len = HEADER_BASE_CAPACITY
        + tags.div_ceil(3) * 4
        + signature
            .s
            .iter()
            .map(|value| value.selector.len() + value.b.len().div_ceil(3) * 4 + 32)
            .sum::<usize>();
    len + len / 32
}

const HEADER_BASE_CAPACITY: usize = 256;

fn strip_dkim2_headers(message: &[u8]) -> Option<Vec<u8>> {
    strip_headers(message, is_dkim2_field)
}

fn strip_headers(message: &[u8], is_field: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    let mut stripped: Option<Vec<u8>> = None;
    let mut offset = 0;
    let mut skipping = false;
    for line in header_lines(message) {
        if !is_continuation(line) {
            skipping = is_field(line);
        }
        match &mut stripped {
            Some(stripped) if !skipping => stripped.extend_from_slice(line),
            None if skipping => {
                let mut buf = Vec::with_capacity(message.len());
                buf.extend_from_slice(message.get(..offset).unwrap_or_default());
                stripped = Some(buf);
            }
            _ => {}
        }
        offset += line.len();
    }
    let mut stripped = stripped?;
    stripped.extend_from_slice(message.get(offset..).unwrap_or_default());
    Some(stripped)
}

pub(crate) fn strip_signature_headers(message: &[u8]) -> Cow<'_, [u8]> {
    strip_headers(message, is_signature_field).map_or(Cow::Borrowed(message), Cow::Owned)
}

pub(crate) fn has_dkim2_headers(message: &[u8]) -> bool {
    header_lines(message).any(|line| !is_continuation(line) && is_dkim2_field(line))
}

fn header_lines(message: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut start = 0;
    memchr_iter(b'\n', message)
        .map(|pos| pos + 1)
        .chain(once(message.len()))
        .map_while(move |end| {
            let line = message.get(start..end)?;
            start = end;
            (!matches!(line, b"" | b"\r\n" | b"\n")).then_some(line)
        })
}

fn is_continuation(line: &[u8]) -> bool {
    matches!(line.first(), Some(b' ' | b'\t'))
}

fn is_signature_field(line: &[u8]) -> bool {
    line.split(|&ch| ch == b':').next().is_some_and(|name| {
        hashify::set_ignore_case!(
            name.trim_ascii(),
            "dkim-signature",
            "dkim2-signature",
            "message-instance",
            "arc-seal",
            "arc-message-signature",
            "arc-authentication-results"
        )
    })
}

fn is_dkim2_field(line: &[u8]) -> bool {
    line.split(|&ch| ch == b':').next().is_some_and(|name| {
        hashify::set_ignore_case!(name.trim_ascii(), "dkim2-signature", "message-instance")
    })
}

struct Dkim2Envelopes<'x> {
    undisclosed_recipients: Vec<(usize, &'x str)>,
    disclosed_recipients: Vec<&'x str>,
}

impl MessageWrapper {
    fn undisclosed_recipients<'x>(
        &'x self,
        message: &AuthenticatedMessage<'_>,
    ) -> Dkim2Envelopes<'x> {
        if self.message.recipients.len() == 1 {
            return Dkim2Envelopes {
                undisclosed_recipients: Vec::new(),
                disclosed_recipients: vec![self.message.recipients[0].address.as_ref()],
            };
        }

        let mut recipients = AHashSet::with_capacity(self.message.recipients.len());

        for (name, value) in message.headers() {
            let name = name.trim_ascii();
            if name.len() == 2
                && (name.eq_ignore_ascii_case(b"to") || name.eq_ignore_ascii_case(b"cc"))
            {
                let parsed = HeaderForm::Addresses.parse(value);
                if let Some(addresses) = parsed.value().as_address() {
                    recipients.extend(
                        addresses
                            .mailboxes()
                            .filter_map(|a| a.address())
                            .map(sanitize_or_lower),
                    );
                }
            }
        }

        let mut undisclosed_recipients = Vec::new();
        let mut disclosed_recipients = Vec::new();
        for (i, rcpt) in self.message.recipients.iter().enumerate() {
            if !recipients.contains(rcpt.address.as_ref())
                && !recipients.contains(&sanitize_or_lower(&rcpt.address))
            {
                undisclosed_recipients.push((i, rcpt.address.as_ref()));
            } else {
                disclosed_recipients.push(rcpt.address.as_ref());
            }
        }

        Dkim2Envelopes {
            undisclosed_recipients,
            disclosed_recipients,
        }
    }
}

fn sanitize_or_lower(rcpt: &str) -> String {
    sanitize_email(rcpt).unwrap_or_else(|| rcpt.to_lowercase())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/smtp/src/inbound/dkim/tests.rs"]
mod tests;
