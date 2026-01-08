/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::AccessToken,
    config::spamfilter::SpamFilterAction,
    manager::{SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY},
    psl,
};
use directory::{
    Permission,
    backend::internal::manage::{self, ManageDirectory},
};
use email::message::ingest::EmailIngest;
use http_proto::{request::decode_path_element, *};
use hyper::Method;
use mail_auth::{
    AuthenticatedMessage, DmarcResult, dmarc::verify::DmarcParameters, spf::verify::SpfParameters,
};
use mail_parser::MessageParser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use spam_filter::{
    SpamFilterInput,
    analysis::{init::SpamFilterInit, score::SpamFilterAnalyzeScore},
    modules::classifier::SpamClassifier,
};
use std::future::Future;
use std::net::IpAddr;
use store::{ahash::AHashMap, write::BatchBuilder};

pub trait ManageSpamHandler: Sync + Send {
    fn handle_manage_spam(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpamClassifyRequest {
    pub message: String,

    // Session details
    pub remote_ip: IpAddr,
    #[serde(default)]
    pub ehlo_domain: String,
    #[serde(default)]
    pub authenticated_as: Option<String>,

    // TLS
    #[serde(default)]
    pub is_tls: bool,

    // Envelope
    pub env_from: String,
    pub env_from_flags: u64,
    pub env_rcpt_to: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpamClassifyResponse {
    pub score: f32,
    pub tags: AHashMap<String, SpamFilterDisposition<f32>>,
    pub disposition: SpamFilterDisposition<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "action")]
pub enum SpamFilterDisposition<T> {
    Allow { value: T },
    Discard,
    Reject,
}

impl ManageSpamHandler for Server {
    async fn handle_manage_spam(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1).copied(), path.get(2).copied(), req.method()) {
            (Some("upload"), Some(class @ ("ham" | "spam")), &Method::POST) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SpamFilterTrain)?;

                let message =
                    body.ok_or_else(|| manage::error("Failed to parse message.", None::<u64>))?;
                let account_id = if let Some(account) =
                    path.get(3).copied().filter(|a| !a.is_empty())
                {
                    let principal = self
                        .store()
                        .get_principal_info(decode_path_element(account).as_ref())
                        .await?
                        .ok_or_else(|| manage::not_found(account.to_string()))?;
                    if access_token.tenant.is_some() && principal.tenant != access_token.tenant_id()
                    {
                        return Err(manage::error(
                            "Account does not belong to this tenant.",
                            None::<u64>,
                        ));
                    }

                    principal.id
                } else if access_token.tenant.is_none() {
                    u32::MAX
                } else {
                    return Err(manage::error(
                        "Account ID is required for tenants.",
                        None::<u64>,
                    ));
                };

                // Write sample
                let (blob_hash, blob_hold) =
                    self.put_temporary_blob(account_id, &message, 60).await?;
                let mut batch = BatchBuilder::new();
                batch.with_account_id(account_id).clear(blob_hold);
                self.add_spam_sample(
                    &mut batch,
                    blob_hash,
                    class == "spam",
                    true,
                    session.session_id,
                );
                self.store().write(batch.build_all()).await?;

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            (Some("train"), request, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SpamFilterTrain)?;

                let result = match request {
                    Some("start") | Some("reset") => {
                        if !self.inner.ipc.train_task_controller.is_running() {
                            let reset = matches!(request, Some("reset"));
                            let server = self.clone();
                            tokio::spawn(async move {
                                if let Err(err) = server.spam_train(reset).await {
                                    trc::error!(err.caused_by(trc::location!()));
                                }
                            });

                            true
                        } else {
                            false
                        }
                    }
                    Some("stop") => {
                        if self.inner.ipc.train_task_controller.is_running() {
                            self.inner.ipc.train_task_controller.stop();
                            true
                        } else {
                            false
                        }
                    }
                    Some("delete") => {
                        for key in [SPAM_CLASSIFIER_KEY, SPAM_TRAINER_KEY] {
                            self.blob_store().delete_blob(key).await?;
                        }
                        true
                    }
                    Some("status") => self.inner.ipc.train_task_controller.is_running(),
                    _ => {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                };

                Ok(JsonResponse::new(json!({
                    "data": result,
                }))
                .into_http_response())
            }
            (Some("classify"), _, &Method::POST) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SpamFilterTest)?;

                // Parse request
                let request = serde_json::from_slice::<SpamClassifyRequest>(
                    body.as_deref().unwrap_or_default(),
                )
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
                })?;

                // Built spam filter input
                let message = MessageParser::new()
                    .parse(request.message.as_bytes())
                    .filter(|m| m.root_part().headers().iter().any(|h| !h.name.is_other()))
                    .ok_or_else(|| manage::error("Failed to parse message.", None::<u64>))?;

                let remote_ip = request.remote_ip;
                let ehlo_domain = request.ehlo_domain.to_lowercase();
                let mail_from = request.env_from.to_lowercase();
                let mail_from_domain = mail_from.rsplit_once('@').map(|(_, domain)| domain);
                let local_host = &self.core.network.server_name;

                let spf_ehlo_result =
                    self.core
                        .smtp
                        .resolvers
                        .dns
                        .verify_spf(self.inner.cache.build_auth_parameters(
                            SpfParameters::verify_ehlo(remote_ip, &ehlo_domain, local_host),
                        ))
                        .await;

                let iprev_result = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_iprev(self.inner.cache.build_auth_parameters(remote_ip))
                    .await;

                let spf_mail_from_result = if let Some(mail_from_domain) = mail_from_domain {
                    self.core
                        .smtp
                        .resolvers
                        .dns
                        .check_host(self.inner.cache.build_auth_parameters(SpfParameters::new(
                            remote_ip,
                            mail_from_domain,
                            &ehlo_domain,
                            local_host,
                            &mail_from,
                        )))
                        .await
                } else {
                    self.core
                        .smtp
                        .resolvers
                        .dns
                        .check_host(self.inner.cache.build_auth_parameters(SpfParameters::new(
                            remote_ip,
                            &ehlo_domain,
                            &ehlo_domain,
                            local_host,
                            &format!("postmaster@{ehlo_domain}"),
                        )))
                        .await
                };

                let auth_message = AuthenticatedMessage::from_parsed(&message, true);

                let dkim_output = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_dkim(self.inner.cache.build_auth_parameters(&auth_message))
                    .await;

                let arc_output = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_arc(self.inner.cache.build_auth_parameters(&auth_message))
                    .await;

                let dmarc_output = self
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_dmarc(self.inner.cache.build_auth_parameters(DmarcParameters {
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

                let asn_geo = self.lookup_asn_country(remote_ip).await;

                let input = SpamFilterInput {
                    message: &message,
                    span_id: session.session_id,
                    arc_result: Some(&arc_output),
                    spf_ehlo_result: Some(&spf_ehlo_result),
                    spf_mail_from_result: Some(&spf_mail_from_result),
                    dkim_result: dkim_output.as_slice(),
                    dmarc_result: Some(&dmarc_result),
                    dmarc_policy: Some(&dmarc_policy),
                    iprev_result: Some(&iprev_result),
                    remote_ip: request.remote_ip,
                    ehlo_domain: Some(ehlo_domain.as_str()),
                    authenticated_as: request.authenticated_as.as_deref(),
                    asn: asn_geo.asn.as_ref().map(|a| a.id),
                    country: asn_geo.country.as_ref().map(|c| c.as_str()),
                    is_tls: request.is_tls,
                    env_from: &request.env_from,
                    env_from_flags: request.env_from_flags,
                    env_rcpt_to: request.env_rcpt_to.iter().map(String::as_str).collect(),
                    is_test: true,
                    is_train: false,
                };

                // Classify
                let mut ctx = self.spam_filter_init(input);
                let result = self.spam_filter_classify(&mut ctx).await;

                // Build response
                let mut response = SpamClassifyResponse {
                    score: ctx.result.score,
                    tags: AHashMap::with_capacity(ctx.result.tags.len()),
                    disposition: match result {
                        SpamFilterAction::Allow(value) => SpamFilterDisposition::Allow {
                            value: value.headers,
                        },
                        SpamFilterAction::Discard => SpamFilterDisposition::Discard,
                        SpamFilterAction::Reject => SpamFilterDisposition::Reject,
                        SpamFilterAction::Disabled => SpamFilterDisposition::Allow {
                            value: String::new(),
                        },
                    },
                };
                for tag in ctx.result.tags {
                    let disposition = match self.core.spam.lists.scores.get(&tag) {
                        Some(SpamFilterAction::Allow(score)) => {
                            SpamFilterDisposition::Allow { value: *score }
                        }
                        Some(SpamFilterAction::Discard) => SpamFilterDisposition::Discard,
                        Some(SpamFilterAction::Reject) => SpamFilterDisposition::Reject,
                        Some(SpamFilterAction::Disabled) | None => {
                            SpamFilterDisposition::Allow { value: 0.0 }
                        }
                    };
                    response.tags.insert(tag, disposition);
                }

                Ok(JsonResponse::new(json!({
                    "data": response,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}
