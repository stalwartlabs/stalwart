/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::{MessageWrapper, Metadata, spool::QueueParams};
use common::{
    Server,
    config::smtp::auth::{Dkim1Signer, DkimSigners},
    expr::{functions::ResolveVariable, if_block::IfBlock},
};
use mail_auth::{
    AuthenticatedMessage,
    common::headers::HeaderWriter,
    dkim2::{Hop, MessageInstance},
};
use mail_parser::{Address, parsers::MessageStream};
use std::{collections::HashSet, sync::Arc};
use utils::sanitize_email;

pub(crate) trait DkimSign: Sync + Send {
    fn sign_message(
        &self,
        message: &mut MessageWrapper,
        params: &mut QueueParams<'_, '_>,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send;

    fn eval_signers(
        &self,
        if_block: &IfBlock,
        resolver: &impl ResolveVariable,
        session_id: u64,
    ) -> impl Future<Output = Option<Arc<DkimSigners>>> + Send;
}

impl DkimSign for Server {
    async fn sign_message(
        &self,
        message: &mut MessageWrapper,
        params: &mut QueueParams<'_, '_>,
    ) -> Option<Vec<u8>> {
        let signers = params.dkim_signers.as_ref().unwrap();
        let raw_message = params.raw_message;

        // DKIM1 signing
        let mut headers = Vec::with_capacity(64);
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

        // DKIM2 signing
        if let Some(signer) = &signers.dkim2
            && let Some(modified) =
                AuthenticatedMessage::parse_with_opts(raw_message, params.raw_headers, true)
        {
            // Generate message instance
            let original = params.original_authenticated_message.take().or_else(|| {
                params
                    .original_raw_message
                    .and_then(AuthenticatedMessage::parse)
            });
            let instance = MessageInstance::from_message(&modified, original.as_ref());
            if let Some(instance) = &instance {
                instance.write_header(&mut headers);
            }

            // Obtain disclosed and undisclosed recipients
            let envelopes = message.undisclosed_recipients(&modified);

            // Generate DKIM2 signature for disclosed recipients
            if !envelopes.disclosed_recipients.is_empty() {
                match signer.sign_with_message_instance(
                    &modified,
                    instance.as_ref(),
                    Hop::real(
                        message.message.return_path.as_ref(),
                        envelopes.disclosed_recipients,
                    ),
                ) {
                    Ok(signature) => {
                        if envelopes.undisclosed_recipients.is_empty() {
                            // Happy path: no undisclosed recipients, serialize signature straight to blob
                            signature.write_header(&mut headers);
                        } else {
                            // Undisclosed recipients present, serialize signature to metadata
                            let mut header = Vec::with_capacity(64);
                            signature.write_header(&mut header);
                            params.metadata.push(Metadata::Headers {
                                value: header.into_boxed_slice(),
                                id: u64::MAX,
                            });
                        }
                    }
                    Err(err) => {
                        trc::error!(
                            trc::Error::from(err)
                                .span_id(params.session_id)
                                .details("Failed to DKIM2 sign message")
                        );
                    }
                }
            }

            // Generate DKIM2 signature for undisclosed recipients
            for (pos, rcpt) in envelopes.undisclosed_recipients {
                match signer.sign_with_message_instance(
                    &modified,
                    instance.as_ref(),
                    Hop::real(message.message.return_path.as_ref(), [rcpt]),
                ) {
                    Ok(signature) => {
                        // Serialize signature to metadata
                        let mut header = Vec::with_capacity(64);
                        signature.write_header(&mut header);
                        params.metadata.push(Metadata::Headers {
                            value: header.into_boxed_slice(),
                            id: pos as u64,
                        });
                    }
                    Err(err) => {
                        trc::error!(
                            trc::Error::from(err)
                                .span_id(params.session_id)
                                .details("Failed to DKIM2 sign message")
                        );
                    }
                }
            }
        }

        (!headers.is_empty()).then_some(headers)
    }

    async fn eval_signers(
        &self,
        if_block: &IfBlock,
        resolver: &impl ResolveVariable,
        session_id: u64,
    ) -> Option<Arc<DkimSigners>> {
        let sign_with_domain = self
            .eval_if::<String, _>(if_block, resolver, session_id)
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

        let mut recipients = HashSet::with_capacity(self.message.recipients.len());

        for addr in message.headers.iter().filter_map(|(name, value)| {
            let name = name.trim_ascii();
            if name.len() == 2
                && (name.eq_ignore_ascii_case(b"to") || name.eq_ignore_ascii_case(b"cc"))
            {
                MessageStream::new(value).parse_address().into_address()
            } else {
                None
            }
        }) {
            match addr {
                Address::List(addrs) => {
                    recipients.extend(
                        addrs
                            .iter()
                            .filter_map(|a| a.address())
                            .map(sanitize_or_lower),
                    );
                }
                Address::Group(groups) => {
                    for group in groups {
                        recipients.extend(
                            group
                                .addresses
                                .iter()
                                .filter_map(|a| a.address())
                                .map(sanitize_or_lower),
                        );
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{Message, QueueId, Recipient};
    use common::config::smtp::queue::QueueName;
    use std::net::{IpAddr, Ipv4Addr};

    fn wrapper(recipients: &[&str]) -> MessageWrapper {
        MessageWrapper {
            queue_id: 0 as QueueId,
            queue_name: QueueName::default(),
            is_multi_queue: false,
            span_id: 0,
            message: Message {
                created: 0,
                blob_hash: Default::default(),
                return_path: "sender@example.com".into(),
                recipients: recipients.iter().map(Recipient::new).collect(),
                received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                received_via_port: 0,
                flags: 0,
                env_id: None,
                priority: 0,
                size: 0,
                metadata: Default::default(),
            },
        }
    }

    fn split(headers: &str, recipients: &[&str]) -> (Vec<String>, Vec<String>) {
        let raw = format!("{headers}\r\nSubject: test\r\n\r\nbody\r\n");
        let auth = AuthenticatedMessage::parse(raw.as_bytes()).expect("parse message");
        let message = wrapper(recipients);
        let envelopes = message.undisclosed_recipients(&auth);
        let mut disclosed = envelopes
            .disclosed_recipients
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let mut undisclosed = envelopes
            .undisclosed_recipients
            .iter()
            .map(|(_, s)| s.to_string())
            .collect::<Vec<_>>();
        disclosed.sort();
        undisclosed.sort();
        (disclosed, undisclosed)
    }

    #[test]
    fn single_recipient_is_always_disclosed() {
        let (disclosed, undisclosed) = split("To: someone-else@example.com", &["bcc@example.org"]);
        assert_eq!(disclosed, vec!["bcc@example.org".to_string()]);
        assert!(undisclosed.is_empty());
    }

    #[test]
    fn all_recipients_disclosed() {
        let (disclosed, undisclosed) = split(
            "To: alice@example.com, bob@example.com\r\nCc: carol@example.com",
            &["alice@example.com", "bob@example.com", "carol@example.com"],
        );
        assert_eq!(
            disclosed,
            vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string(),
                "carol@example.com".to_string(),
            ]
        );
        assert!(undisclosed.is_empty());
    }

    #[test]
    fn mixed_disclosed_and_undisclosed() {
        let (disclosed, undisclosed) = split(
            "To: alice@example.com\r\nCc: bob@example.com",
            &[
                "alice@example.com",
                "bob@example.com",
                "eve@secret.example.org",
                "mallory@secret.example.org",
            ],
        );
        assert_eq!(
            disclosed,
            vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string()
            ]
        );
        assert_eq!(
            undisclosed,
            vec![
                "eve@secret.example.org".to_string(),
                "mallory@secret.example.org".to_string(),
            ]
        );
    }

    #[test]
    fn no_to_or_cc_header_all_undisclosed() {
        let (disclosed, undisclosed) = split(
            "From: sender@example.com",
            &["eve@example.org", "mallory@example.org"],
        );
        assert!(disclosed.is_empty());
        assert_eq!(
            undisclosed,
            vec![
                "eve@example.org".to_string(),
                "mallory@example.org".to_string()
            ]
        );
    }

    #[test]
    fn group_addresses_are_disclosed() {
        let (disclosed, undisclosed) = split(
            "To: Team:alice@example.com,bob@example.com;",
            &["alice@example.com", "bob@example.com", "eve@example.org"],
        );
        assert_eq!(
            disclosed,
            vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string()
            ]
        );
        assert_eq!(undisclosed, vec!["eve@example.org".to_string()]);
    }

    #[test]
    fn header_address_casing_is_ignored() {
        let (disclosed, undisclosed) = split(
            "To: Alice@Example.COM, BOB@EXAMPLE.com",
            &["alice@example.com", "bob@example.com", "eve@example.org"],
        );
        assert_eq!(
            disclosed,
            vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string()
            ]
        );
        assert_eq!(undisclosed, vec!["eve@example.org".to_string()]);
    }

    #[test]
    fn display_names_and_brackets_are_ignored() {
        let (disclosed, undisclosed) = split(
            "To: \"Alice Doe\" <alice@example.com>\r\nCc: Bob <bob@example.com>",
            &["alice@example.com", "bob@example.com", "eve@example.org"],
        );
        assert_eq!(
            disclosed,
            vec![
                "alice@example.com".to_string(),
                "bob@example.com".to_string()
            ]
        );
        assert_eq!(undisclosed, vec!["eve@example.org".to_string()]);
    }
}
