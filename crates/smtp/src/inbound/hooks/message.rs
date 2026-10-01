/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Action, Queue, client::send_mta_hook_request};
use crate::{
    core::Session,
    inbound::{
        FilterResponse,
        hooks::{
            Address, Client, Context, Envelope, Message, Protocol, Request, Sasl, Server, Tls,
        },
        milter::Modification,
    },
    queue::QueueId,
};
use ahash::AHashMap;
use common::{DAEMON_NAME, config::smtp::session::Stage, expr::Bump, network::SessionStream};
use compact_str::ToCompactString;
use mail_auth::AuthenticatedMessage;
use std::time::Instant;
use trc::MtaHookEvent;

impl<T: SessionStream> Session<T> {
    pub async fn run_mta_hooks(
        &self,
        stage: Stage,
        message: Option<&AuthenticatedMessage<'_>>,
        queue_id: Option<QueueId>,
    ) -> Result<Vec<Modification>, FilterResponse> {
        let mta_hooks = &self.server.core.smtp.session.hooks;
        if mta_hooks.is_empty() {
            return Ok(Vec::new());
        }

        let mut modifications = Vec::new();
        let mut arena = Bump::new();
        let mut payload = None;
        for (idx, mta_hook) in mta_hooks.iter().enumerate() {
            if !mta_hook.run_on_stage.contains(&stage)
                || !self
                    .server
                    .eval_if(&mta_hook.enable, self, &mut arena, self.data.session_id)
                    .await
                    .unwrap_or(false)
            {
                continue;
            }

            let time = Instant::now();
            let has_next = mta_hooks
                .get(idx + 1..)
                .unwrap_or_default()
                .iter()
                .any(|next| next.run_on_stage.contains(&stage));
            let result = match payload
                .get_or_insert_with(|| self.mta_hook_payload(stage, message, queue_id))
            {
                Ok(body) if has_next => send_mta_hook_request(mta_hook, body.clone()).await,
                Ok(body) => send_mta_hook_request(mta_hook, std::mem::take(body)).await,
                Err(err) => Err(err.clone()),
            };
            match result {
                Ok(response) => {
                    trc::event!(
                        MtaHook(match response.action {
                            Action::Accept => MtaHookEvent::ActionAccept,
                            Action::Discard => MtaHookEvent::ActionDiscard,
                            Action::Reject => MtaHookEvent::ActionReject,
                            Action::Quarantine => MtaHookEvent::ActionQuarantine,
                        }),
                        SpanId = self.data.session_id,
                        QueueId = queue_id,
                        Id = mta_hook.id.to_compact_string(),
                        Elapsed = time.elapsed(),
                    );

                    let mut new_modifications = Vec::with_capacity(response.modifications.len());
                    for modification in response.modifications {
                        new_modifications.push(match modification {
                            super::Modification::ChangeFrom { value, parameters } => {
                                Modification::ChangeFrom {
                                    sender: value,
                                    args: flatten_parameters(parameters),
                                }
                            }
                            super::Modification::AddRecipient { value, parameters } => {
                                Modification::AddRcpt {
                                    recipient: value,
                                    args: flatten_parameters(parameters),
                                }
                            }
                            super::Modification::DeleteRecipient { value } => {
                                Modification::DeleteRcpt { recipient: value }
                            }
                            super::Modification::ReplaceContents { value } => {
                                Modification::ReplaceBody {
                                    value: value.into_bytes(),
                                }
                            }
                            super::Modification::AddHeader { name, value } => {
                                Modification::AddHeader { name, value }
                            }
                            super::Modification::InsertHeader { index, name, value } => {
                                Modification::InsertHeader { index, name, value }
                            }
                            super::Modification::ChangeHeader { index, name, value } => {
                                Modification::ChangeHeader { index, name, value }
                            }
                            super::Modification::DeleteHeader { index, name } => {
                                Modification::ChangeHeader {
                                    index,
                                    name,
                                    value: String::new(),
                                }
                            }
                        });
                    }

                    if !modifications.is_empty() {
                        // The message body can only be replaced once, so we need to remove
                        // any previous replacements.
                        if new_modifications
                            .iter()
                            .any(|m| matches!(m, Modification::ReplaceBody { .. }))
                        {
                            modifications
                                .retain(|m| !matches!(m, Modification::ReplaceBody { .. }));
                        }
                        modifications.extend(new_modifications);
                    } else {
                        modifications = new_modifications;
                    }

                    let mut message = match response.action {
                        Action::Accept => continue,
                        Action::Discard => FilterResponse::accept(),
                        Action::Reject => FilterResponse::reject(),
                        Action::Quarantine => {
                            modifications.push(Modification::AddHeader {
                                name: "X-Quarantine".into(),
                                value: "true".into(),
                            });
                            continue;
                        }
                    };

                    if let Some(response) = response.response {
                        if let (Some(status), Some(text)) = (response.status, response.message) {
                            if let Some(enhanced) = response.enhanced_status {
                                message.message = format!("{status} {enhanced} {text}\r\n").into();
                            } else {
                                message.message = format!("{status} {text}\r\n").into();
                            }
                        }
                        message.disconnect = response.disconnect;
                    }

                    return Err(message);
                }
                Err(err) => {
                    trc::event!(
                        MtaHook(MtaHookEvent::Error),
                        SpanId = self.data.session_id,
                        Id = mta_hook.id.to_compact_string(),
                        Reason = err,
                        Elapsed = time.elapsed(),
                    );

                    if mta_hook.tempfail_on_error {
                        return Err(FilterResponse::server_failure());
                    }
                }
            }
        }

        Ok(modifications)
    }

    pub fn mta_hook_payload(
        &self,
        stage: Stage,
        message: Option<&AuthenticatedMessage<'_>>,
        queue_id: Option<QueueId>,
    ) -> Result<Vec<u8>, String> {
        let (tls_version, tls_cipher) = self.stream.tls_version_and_cipher();
        let request = Request {
            context: Context {
                stage: stage.into(),
                client: Client {
                    ip: self.data.remote_ip_str.clone(),
                    port: self.data.remote_port,
                    ptr: self
                        .data
                        .iprev
                        .as_ref()
                        .and_then(|ip_rev| ip_rev.ptr.as_ref())
                        .and_then(|ptrs| ptrs.first())
                        .map(|ip| ip.to_string()),
                    helo: (!self.data.helo_domain.is_empty())
                        .then(|| self.data.helo_domain.clone()),
                    active_connections: 1,
                },
                sasl: self.authenticated_as().map(|name| Sasl {
                    login: name.into(),
                    method: None,
                }),
                tls: (!tls_version.is_empty()).then(|| Tls {
                    version: tls_version.as_ref().into(),
                    cipher: tls_cipher.as_ref().into(),
                    bits: None,
                    issuer: None,
                    subject: None,
                }),
                server: Server {
                    name: Some(DAEMON_NAME.into()),
                    port: self.data.local_port,
                    ip: self.data.local_ip_str.clone().into(),
                },
                queue: queue_id.map(|id| Queue {
                    id: format!("{:x}", id),
                }),
                protocol: Protocol { version: 1 },
            },
            envelope: self.data.mail_from.as_ref().map(|from| Envelope {
                from: Address {
                    address: from.address_lcase.clone(),
                    parameters: None,
                },
                to: self
                    .data
                    .rcpt_to
                    .iter()
                    .map(|to| Address {
                        address: to.address_lcase.clone(),
                        parameters: None,
                    })
                    .collect(),
            }),
            message: message.map(|message| Message {
                headers: message
                    .headers()
                    .iter()
                    .map(|(k, v)| (String::from_utf8_lossy(k), String::from_utf8_lossy(v)))
                    .collect(),
                server_headers: vec![],
                contents: String::from_utf8_lossy(message.raw_body()),
                size: message.raw_message().len(),
            }),
        };

        let size = message.map_or(0, |message| message.raw_message().len());
        let mut payload = Vec::with_capacity(size + (size / 8) + 1024);
        serde_json::to_writer(&mut payload, &request)
            .map_err(|err| format!("Failed to serialize Hook request: {}", err))?;
        Ok(payload)
    }
}

fn flatten_parameters(parameters: AHashMap<String, Option<String>>) -> String {
    let mut arguments = String::new();
    for (key, value) in parameters {
        if !arguments.is_empty() {
            arguments.push(' ');
        }
        arguments.push_str(key.as_str());
        if let Some(value) = value {
            arguments.push('=');
            arguments.push_str(value.as_str());
        }
    }

    arguments
}
