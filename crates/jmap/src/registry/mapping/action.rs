/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{RegistrySetResponse, map_bootstrap_error};
use common::{
    Server,
    config::mailstore::spamfilter::SpamFilterAction,
    ipc::{BroadcastEvent, QueueEvent, RegistryChange},
    psl,
};
use jmap_proto::error::set::{SetError, SetErrorType};
use jmap_tools::{JsonPointer, Key};
use mail_auth::{
    AuthenticatedMessage, DkimResult, DmarcResult, dmarc::verify::DmarcParameters,
    spf::verify::SpfParameters,
};
use mail_parser::MessageParser;
use registry::{
    jmap::{IntoValue, JsonPointerPatch, RegistryJsonPatch},
    schema::{
        enums::{SpamClassifyParameters, SpamClassifyResult, SpamClassifyTagDisposition},
        prelude::{ObjectType, Property},
        structs::{Action, DmarcTroubleshoot, SpamClassify, SpamClassifyTag},
    },
    types::{EnumImpl, ObjectImpl},
};
use smtp_proto::{MAIL_BODY_7BIT, MAIL_BODY_8BITMIME, MAIL_BODY_BINARYMIME, MAIL_SMTPUTF8};
use spam_filter::{
    SpamFilterInput,
    analysis::{init::SpamFilterInit, score::SpamFilterAnalyzeScore},
};
use std::time::Instant;
use store::{registry::bootstrap::Bootstrap, write::now};
use utils::map::vec_map::VecMap;

pub(crate) async fn action_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    // Actions cannot be uodated or destroyed, so we fail all updates and destroys.
    set.fail_all_update("Actions cannot be updated");
    set.fail_all_destroy("Actions cannot be destroyed");

    // Process creations
    'outer: for (id, value) in set.create.drain() {
        let mut action = Action::default();
        if let Err(err) = action.patch(
            JsonPointerPatch::new(&JsonPointer::new(vec![])).with_create(true),
            value,
        ) {
            set.response.not_created.append(id, err.into());
            continue 'outer;
        }

        let mut validation_errors = Vec::new();
        if !action.validate(&mut validation_errors) {
            set.response.not_created.append(
                id,
                SetError::new(SetErrorType::ValidationFailed)
                    .with_validation_errors(validation_errors),
            );
            continue 'outer;
        }

        if !set.access_token.has_permission(action.permission()) {
            set.response.not_created.append(
                id,
                SetError::forbidden().with_description(format!(
                    "Insufficient permissions to perform action of type {}",
                    action.object_type().as_str()
                )),
            );
            continue 'outer;
        }

        match action {
            Action::ReloadSettings
            | Action::ReloadTlsCertificates
            | Action::ReloadLookupStores
            | Action::ReloadBlockedIps => {
                let object = match action {
                    Action::ReloadSettings => ObjectType::DataStore,
                    Action::ReloadTlsCertificates => ObjectType::Certificate,
                    Action::ReloadLookupStores => ObjectType::StoreLookup,
                    Action::ReloadBlockedIps => ObjectType::BlockedIp,
                    _ => unreachable!(),
                };
                let result =
                    Box::pin(set.server.reload_registry(RegistryChange::Reload(object))).await?;

                if !result.has_errors() {
                    set.server
                        .cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Reload(
                            object,
                        )))
                        .await;
                    set.response.created(id, now());
                } else {
                    set.response
                        .not_created
                        .append(id, map_bootstrap_error(result.errors));
                }
            }
            Action::InvalidateCaches => {
                set.server.invalidate_all_local_caches();
                set.server
                    .cluster_broadcast(BroadcastEvent::CacheInvalidateAll)
                    .await;
                set.response.created(id, now());
            }
            Action::InvalidateNegativeCaches => {
                set.server.invalidate_all_local_negative_caches();
                set.server
                    .cluster_broadcast(BroadcastEvent::CacheInvalidateNegative)
                    .await;
                set.response.created(id, now());
            }
            Action::PauseMtaQueue => {
                let _ = set
                    .server
                    .inner
                    .ipc
                    .queue_tx
                    .send(QueueEvent::Paused(true))
                    .await;
                set.server
                    .cluster_broadcast(BroadcastEvent::MtaQueueStatus { is_running: false })
                    .await;
                set.response.created(id, now());
            }
            Action::ResumeMtaQueue => {
                let _ = set
                    .server
                    .inner
                    .ipc
                    .queue_tx
                    .send(QueueEvent::Paused(false))
                    .await;
                set.server
                    .cluster_broadcast(BroadcastEvent::MtaQueueStatus { is_running: true })
                    .await;
                set.response.created(id, now());
            }
            Action::TroubleshootDmarc(troubleshoot) => {
                if let Some(result) = dmarc_troubleshoot(set.server, troubleshoot).await {
                    let mut result = result.into_value();
                    result
                        .as_object_mut()
                        .unwrap()
                        .as_mut_vec()
                        .retain(|(k, _)| {
                            !matches!(
                                k,
                                Key::Property(
                                    Property::Message
                                        | Property::RemoteIp
                                        | Property::EhloDomain
                                        | Property::MailFrom
                                )
                            )
                        });
                    set.response.created.insert(id, result);
                } else {
                    set.response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::Body)
                            .with_description(
                                "Failed to parse the message for DMARC troubleshooting".to_string(),
                            ),
                    );
                }
            }
            Action::ClassifySpam(classify) => {
                if let Some(result) = classify_spam(set.server, classify).await {
                    let mut result = result.into_value();
                    result
                        .as_object_mut()
                        .unwrap()
                        .as_mut_vec()
                        .retain(|(k, _)| {
                            !matches!(
                                k,
                                Key::Property(
                                    Property::Message
                                        | Property::RemoteIp
                                        | Property::EhloDomain
                                        | Property::AuthenticatedAs
                                        | Property::IsTls
                                        | Property::EnvFrom
                                        | Property::EnvFromParameters
                                        | Property::EnvRcptTo
                                )
                            )
                        });
                    set.response.created.insert(id, result);
                } else {
                    set.response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::Message)
                            .with_description(
                                "Failed to parse the message for spam classification".to_string(),
                            ),
                    );
                }
            }
            Action::UpdateApps => {
                let mut bp = Bootstrap::new_uninitialized(set.server.registry().clone());
                set.server.inner.data.applications.reload(&mut bp).await;
                if bp.errors.is_empty() {
                    set.server
                        .inner
                        .data
                        .applications
                        .unpack_all(set.server, true)
                        .await;
                    set.server
                        .cluster_broadcast(BroadcastEvent::RegistryChange(RegistryChange::Reload(
                            ObjectType::Application,
                        )))
                        .await;
                    set.response.created(id, now());
                } else {
                    set.response
                        .not_created
                        .append(id, map_bootstrap_error(bp.errors));
                }
            }
        }
    }

    Ok(set)
}

async fn classify_spam(server: &Server, mut request: SpamClassify) -> Option<SpamClassify> {
    // Built spam filter input
    let message = MessageParser::new()
        .parse(request.message.as_bytes())
        .filter(|m| m.root_part().headers().iter().any(|h| !h.name.is_other()))?;

    let remote_ip = request.remote_ip.into_inner();
    let ehlo_domain = request.ehlo_domain.to_lowercase();
    let mail_from = request.env_from.to_lowercase();
    let mail_from_domain = mail_from.rsplit_once('@').map(|(_, domain)| domain);
    let local_host = &server.core.network.server_name;

    let spf_ehlo_result = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_spf(
            server
                .inner
                .cache
                .build_auth_parameters(SpfParameters::verify_ehlo(
                    remote_ip,
                    &ehlo_domain,
                    local_host,
                )),
        )
        .await;

    let iprev_result = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_iprev(server.inner.cache.build_auth_parameters(remote_ip))
        .await;

    let spf_mail_from_result = if let Some(mail_from_domain) = mail_from_domain {
        server
            .core
            .smtp
            .resolvers
            .dns
            .check_host(server.inner.cache.build_auth_parameters(SpfParameters::new(
                remote_ip,
                mail_from_domain,
                &ehlo_domain,
                local_host,
                &mail_from,
            )))
            .await
    } else {
        server
            .core
            .smtp
            .resolvers
            .dns
            .check_host(server.inner.cache.build_auth_parameters(SpfParameters::new(
                remote_ip,
                &ehlo_domain,
                &ehlo_domain,
                local_host,
                &format!("postmaster@{ehlo_domain}"),
            )))
            .await
    };

    let auth_message = AuthenticatedMessage::from_parsed(&message, true);

    let dkim_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_dkim(server.inner.cache.build_auth_parameters(&auth_message))
        .await;

    let arc_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_arc(server.inner.cache.build_auth_parameters(&auth_message))
        .await;

    let dmarc_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_dmarc(server.inner.cache.build_auth_parameters(DmarcParameters {
            message: &auth_message,
            dkim_output: &dkim_output,
            rfc5321_mail_from_domain: mail_from_domain.unwrap_or(ehlo_domain.as_str()),
            spf_output: &spf_mail_from_result,
            domain_suffix_fn: |domain| psl::domain_str(domain).unwrap_or(domain),
        }))
        .await;
    let dmarc_pass = matches!(dmarc_output.spf_result(), DmarcResult::Pass)
        || matches!(dmarc_output.dkim_result(), DmarcResult::Pass);
    let dmarc_result = if dmarc_pass {
        DmarcResult::Pass
    } else if dmarc_output.spf_result() != &DmarcResult::None {
        dmarc_output.spf_result().clone()
    } else if dmarc_output.dkim_result() != &DmarcResult::None {
        dmarc_output.dkim_result().clone()
    } else {
        DmarcResult::None
    };
    let dmarc_policy = dmarc_output.policy();

    let asn_geo = server.lookup_asn_country(remote_ip).await;

    let input = SpamFilterInput {
        message: &message,
        span_id: 0,
        arc_result: Some(&arc_output),
        spf_ehlo_result: Some(&spf_ehlo_result),
        spf_mail_from_result: Some(&spf_mail_from_result),
        dkim_result: dkim_output.as_slice(),
        dmarc_result: Some(&dmarc_result),
        dmarc_policy: Some(&dmarc_policy),
        iprev_result: Some(&iprev_result),
        remote_ip,
        ehlo_domain: Some(ehlo_domain.as_str()),
        authenticated_as: request.authenticated_as.as_deref(),
        asn: asn_geo.asn.as_ref().map(|a| a.id),
        country: asn_geo.country.as_ref().map(|c| c.as_str()),
        is_tls: request.is_tls,
        env_from: &request.env_from,
        env_from_flags: match request.env_from_parameters {
            Some(SpamClassifyParameters::Bit7) => MAIL_BODY_7BIT,
            Some(SpamClassifyParameters::Bit8Mime8BitMIMEMessageContent) => MAIL_BODY_BINARYMIME,
            Some(SpamClassifyParameters::BinaryMime) => MAIL_BODY_8BITMIME,
            Some(SpamClassifyParameters::SmtpUtf8) => MAIL_SMTPUTF8,
            None => 0,
        },
        env_rcpt_orig_to: request.env_rcpt_to.iter().map(String::as_str).collect(),
        env_rcpt_rewritten_to: request.env_rcpt_to.iter().map(String::as_str).collect(),
        is_test: true,
        is_train: false,
    };

    // Classify
    let mut ctx = server.spam_filter_init(input);
    let result = server.spam_filter_classify(&mut ctx).await;

    // Build response
    request.result = match result {
        SpamFilterAction::Allow(result) => {
            request.score = (result.score as f64).into();
            if result.is_spam {
                SpamClassifyResult::Spam
            } else {
                SpamClassifyResult::Ham
            }
        }
        SpamFilterAction::Discard => SpamClassifyResult::Discard,
        SpamFilterAction::Reject | SpamFilterAction::Disabled => SpamClassifyResult::Reject,
    };

    request.tags = VecMap::with_capacity(ctx.result.tags.len());
    for tag in ctx.result.tags {
        let (score, disposition) = match server.core.spam.lists.scores.get(&tag) {
            Some(SpamFilterAction::Allow(score)) => (*score, SpamClassifyTagDisposition::Score),
            Some(SpamFilterAction::Discard) => (0.0, SpamClassifyTagDisposition::Discard),
            _ => (0.0, SpamClassifyTagDisposition::Reject),
        };
        request.tags.append(
            tag,
            SpamClassifyTag {
                disposition,
                score: (score as f64).into(),
            },
        );
    }

    Some(request)
}

async fn dmarc_troubleshoot(
    server: &Server,
    mut request: DmarcTroubleshoot,
) -> Option<DmarcTroubleshoot> {
    let remote_ip = request.remote_ip.into_inner();
    let ehlo_domain = request.ehlo_domain.to_lowercase();
    let mail_from = request.mail_from.to_lowercase();
    let mail_from_domain = mail_from.rsplit_once('@').map(|(_, domain)| domain);

    let local_host = &server.core.network.server_name;

    let now = Instant::now();
    let ehlo_spf_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_spf(
            server
                .inner
                .cache
                .build_auth_parameters(SpfParameters::verify_ehlo(
                    remote_ip,
                    &ehlo_domain,
                    local_host,
                )),
        )
        .await;

    let iprev = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_iprev(server.inner.cache.build_auth_parameters(remote_ip))
        .await;
    let mail_spf_output = if let Some(mail_from_domain) = mail_from_domain {
        server
            .core
            .smtp
            .resolvers
            .dns
            .check_host(server.inner.cache.build_auth_parameters(SpfParameters::new(
                remote_ip,
                mail_from_domain,
                &ehlo_domain,
                local_host,
                &mail_from,
            )))
            .await
    } else {
        server
            .core
            .smtp
            .resolvers
            .dns
            .check_host(server.inner.cache.build_auth_parameters(SpfParameters::new(
                remote_ip,
                &ehlo_domain,
                &ehlo_domain,
                local_host,
                &format!("postmaster@{ehlo_domain}"),
            )))
            .await
    };

    let body = request
        .message
        .take()
        .unwrap_or_else(|| format!("From: {mail_from}\r\nSubject: test\r\n\r\ntest"));
    let auth_message = AuthenticatedMessage::parse_with_opts(body.as_bytes(), true)?;

    let dkim_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_dkim(server.inner.cache.build_auth_parameters(&auth_message))
        .await;
    let dkim_pass = dkim_output
        .iter()
        .any(|d| matches!(d.result(), DkimResult::Pass));

    let arc_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_arc(server.inner.cache.build_auth_parameters(&auth_message))
        .await;

    let dmarc_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_dmarc(server.inner.cache.build_auth_parameters(DmarcParameters {
            message: &auth_message,
            dkim_output: &dkim_output,
            rfc5321_mail_from_domain: mail_from_domain.unwrap_or(ehlo_domain.as_str()),
            spf_output: &mail_spf_output,
            domain_suffix_fn: |domain| psl::domain_str(domain).unwrap_or(domain),
        }))
        .await;
    let dmarc_pass = matches!(dmarc_output.spf_result(), DmarcResult::Pass)
        || matches!(dmarc_output.dkim_result(), DmarcResult::Pass);
    let dmarc_result = if dmarc_pass {
        DmarcResult::Pass
    } else if dmarc_output.spf_result() != &DmarcResult::None {
        dmarc_output.spf_result().clone()
    } else if dmarc_output.dkim_result() != &DmarcResult::None {
        dmarc_output.dkim_result().clone()
    } else {
        DmarcResult::None
    };

    request.spf_ehlo_domain = ehlo_spf_output.domain().to_string();
    request.spf_ehlo_result = (&ehlo_spf_output).into();
    request.spf_mail_from_domain = mail_spf_output.domain().to_string();
    request.spf_mail_from_result = (&mail_spf_output).into();
    request.ip_rev_ptr = iprev
        .ptr
        .as_ref()
        .map(|ptr| {
            ptr.iter()
                .map(|label| label.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .into();
    request.ip_rev_result = (&iprev).into();
    request.dkim_pass = dkim_pass;
    request.dkim_results = dkim_output
        .iter()
        .map(|result| result.result().into())
        .collect();
    request.arc_result = arc_output.result().into();
    request.dmarc_result = (&dmarc_result).into();
    request.dmarc_policy = (&dmarc_output.policy()).into();
    request.dmarc_pass = dmarc_pass;
    request.elapsed = now.elapsed().into();

    Some(request)
}
