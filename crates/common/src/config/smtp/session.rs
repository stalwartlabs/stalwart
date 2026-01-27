/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::resolver::Policy;
use super::*;
use crate::expr::if_block::IfBlock;
use ahash::AHashSet;
use hyper::HeaderMap;
use registry::schema::{
    enums::{self, ExpressionConstant, MtaStage},
    prelude::Object,
    structs::{
        MtaExtensions, MtaHook, MtaInboundSession, MtaMilter, MtaStageAuth, MtaStageConnect,
        MtaStageData, MtaStageEhlo, MtaStageMail, MtaStageRcpt,
    },
};
use smtp_proto::*;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};
use utils::config::utils::ParseValue;

#[derive(Clone)]
pub struct SessionConfig {
    pub timeout: IfBlock,
    pub duration: IfBlock,
    pub transfer_limit: IfBlock,

    pub connect: Connect,
    pub ehlo: Ehlo,
    pub auth: Auth,
    pub mail: Mail,
    pub rcpt: Rcpt,
    pub data: Data,
    pub extensions: Extensions,
    pub mta_sts_policy: Option<Policy>,

    pub milters: Vec<Milter>,
    pub hooks: Vec<MTAHook>,
}

#[derive(Clone)]
pub struct Connect {
    pub hostname: IfBlock,
    pub script: IfBlock,
    pub greeting: IfBlock,
}

#[derive(Clone)]
pub struct Ehlo {
    pub script: IfBlock,
    pub require: IfBlock,
    pub reject_non_fqdn: IfBlock,
}

#[derive(Clone)]
pub struct Extensions {
    pub pipelining: IfBlock,
    pub chunking: IfBlock,
    pub requiretls: IfBlock,
    pub dsn: IfBlock,
    pub vrfy: IfBlock,
    pub expn: IfBlock,
    pub no_soliciting: IfBlock,
    pub future_release: IfBlock,
    pub deliver_by: IfBlock,
    pub mt_priority: IfBlock,
}

#[derive(Clone)]
pub struct Auth {
    pub mechanisms: IfBlock,
    pub require: IfBlock,
    pub must_match_sender: IfBlock,
    pub errors_max: IfBlock,
    pub errors_wait: IfBlock,
}

#[derive(Clone)]
pub struct Mail {
    pub script: IfBlock,
    pub rewrite: IfBlock,
    pub is_allowed: IfBlock,
}

#[derive(Clone)]
pub struct Rcpt {
    pub script: IfBlock,
    pub relay: IfBlock,
    pub is_local: IfBlock,
    pub rewrite: IfBlock,
    pub errors_max: IfBlock,
    pub errors_wait: IfBlock,
    pub max_recipients: IfBlock,
}

#[derive(Debug, Default, Clone)]
pub enum AddressMapping {
    Enable,
    Custom(IfBlock),
    #[default]
    Disable,
}

#[derive(Clone)]
pub struct Data {
    pub script: IfBlock,
    pub spam_filter: IfBlock,
    pub max_messages: IfBlock,
    pub max_message_size: IfBlock,
    pub max_received_headers: IfBlock,
    pub add_received: IfBlock,
    pub add_received_spf: IfBlock,
    pub add_return_path: IfBlock,
    pub add_auth_results: IfBlock,
    pub add_message_id: IfBlock,
    pub add_date: IfBlock,
    pub add_delivered_to: bool,
}

#[derive(Clone)]
pub struct Milter {
    pub enable: IfBlock,
    pub id: Arc<String>,
    pub addrs: Vec<SocketAddr>,
    pub hostname: String,
    pub port: u16,
    pub timeout_connect: Duration,
    pub timeout_command: Duration,
    pub timeout_data: Duration,
    pub tls: bool,
    pub tls_allow_invalid_certs: bool,
    pub tempfail_on_error: bool,
    pub max_frame_len: usize,
    pub protocol_version: MilterVersion,
    pub flags_actions: Option<u32>,
    pub flags_protocol: Option<u32>,
    pub run_on_stage: AHashSet<Stage>,
}

#[derive(Clone, Copy)]
pub enum MilterVersion {
    V2,
    V6,
}

#[derive(Clone)]
pub struct MTAHook {
    pub enable: IfBlock,
    pub id: String,
    pub url: String,
    pub timeout: Duration,
    pub headers: HeaderMap,
    pub tls_allow_invalid_certs: bool,
    pub tempfail_on_error: bool,
    pub run_on_stage: AHashSet<Stage>,
    pub max_response_size: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Connect,
    Ehlo,
    Auth,
    Mail,
    Rcpt,
    Data,
}

impl SessionConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let session = bp.setting_infallible::<MtaInboundSession>().await;
        let connect = bp.setting_infallible::<MtaStageConnect>().await;
        let auth = bp.setting_infallible::<MtaStageAuth>().await;
        let ehlo = bp.setting_infallible::<MtaStageEhlo>().await;
        let mail = bp.setting_infallible::<MtaStageMail>().await;
        let rcpt = bp.setting_infallible::<MtaStageRcpt>().await;
        let data = bp.setting_infallible::<MtaStageData>().await;
        let ext = bp.setting_infallible::<MtaExtensions>().await;

        SessionConfig {
            timeout: bp.compile_expr(
                Object::MtaInboundSession.singleton(),
                &session.ctx_timeout(),
            ),
            duration: bp.compile_expr(
                Object::MtaInboundSession.singleton(),
                &session.ctx_max_duration(),
            ),
            transfer_limit: bp.compile_expr(
                Object::MtaInboundSession.singleton(),
                &session.ctx_transfer_limit(),
            ),
            connect: Connect {
                hostname: bp
                    .compile_expr(Object::MtaStageConnect.singleton(), &connect.ctx_hostname()),
                script: bp.compile_expr(Object::MtaStageConnect.singleton(), &connect.ctx_script()),
                greeting: bp.compile_expr(
                    Object::MtaStageConnect.singleton(),
                    &connect.ctx_smtp_greeting(),
                ),
            },
            ehlo: Ehlo {
                script: bp.compile_expr(Object::MtaStageEhlo.singleton(), &ehlo.ctx_script()),
                require: bp.compile_expr(Object::MtaStageEhlo.singleton(), &ehlo.ctx_require()),
                reject_non_fqdn: bp.compile_expr(
                    Object::MtaStageEhlo.singleton(),
                    &ehlo.ctx_reject_non_fqdn(),
                ),
            },
            auth: Auth {
                mechanisms: bp.compile_expr(
                    Object::MtaStageAuth.singleton(),
                    &auth.ctx_sasl_mechanisms(),
                ),
                require: bp.compile_expr(Object::MtaStageAuth.singleton(), &auth.ctx_require()),
                must_match_sender: bp.compile_expr(
                    Object::MtaStageAuth.singleton(),
                    &auth.ctx_must_match_sender(),
                ),
                errors_max: bp
                    .compile_expr(Object::MtaStageAuth.singleton(), &auth.ctx_max_failures()),
                errors_wait: bp
                    .compile_expr(Object::MtaStageAuth.singleton(), &auth.ctx_wait_on_fail()),
            },
            mail: Mail {
                script: bp.compile_expr(Object::MtaStageMail.singleton(), &mail.ctx_script()),
                rewrite: bp.compile_expr(Object::MtaStageMail.singleton(), &mail.ctx_rewrite()),
                is_allowed: bp.compile_expr(
                    Object::MtaStageMail.singleton(),
                    &mail.ctx_is_sender_allowed(),
                ),
            },
            rcpt: Rcpt {
                script: bp.compile_expr(Object::MtaStageRcpt.singleton(), &rcpt.ctx_script()),
                relay: bp
                    .compile_expr(Object::MtaStageRcpt.singleton(), &rcpt.ctx_allow_relaying()),
                is_local: bp.compile_expr(Object::MtaStageRcpt.singleton(), &rcpt.ctx_is_local()),
                rewrite: bp.compile_expr(Object::MtaStageRcpt.singleton(), &rcpt.ctx_rewrite()),
                errors_max: bp
                    .compile_expr(Object::MtaStageRcpt.singleton(), &rcpt.ctx_max_failures()),
                errors_wait: bp
                    .compile_expr(Object::MtaStageRcpt.singleton(), &rcpt.ctx_wait_on_fail()),
                max_recipients: bp
                    .compile_expr(Object::MtaStageRcpt.singleton(), &rcpt.ctx_max_recipients()),
            },
            data: Data {
                script: bp.compile_expr(Object::MtaStageData.singleton(), &data.ctx_script()),
                spam_filter: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_enable_spam_filter(),
                ),
                max_messages: bp
                    .compile_expr(Object::MtaStageData.singleton(), &data.ctx_max_messages()),
                max_message_size: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_max_message_size(),
                ),
                max_received_headers: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_max_received_headers(),
                ),
                add_received: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_add_received_header(),
                ),
                add_received_spf: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_add_received_spf_header(),
                ),
                add_return_path: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_add_return_path_header(),
                ),
                add_auth_results: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_add_auth_results_header(),
                ),
                add_message_id: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_add_message_id_header(),
                ),
                add_date: bp.compile_expr(
                    Object::MtaStageData.singleton(),
                    &data.ctx_add_date_header(),
                ),
                add_delivered_to: data.add_delivered_to_header,
            },
            extensions: Extensions {
                pipelining: bp
                    .compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_pipelining()),
                chunking: bp.compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_chunking()),
                requiretls: bp
                    .compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_require_tls()),
                dsn: bp.compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_dsn()),
                vrfy: bp.compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_vrfy()),
                expn: bp.compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_expn()),
                no_soliciting: bp
                    .compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_no_soliciting()),
                future_release: bp
                    .compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_future_release()),
                deliver_by: bp
                    .compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_deliver_by()),
                mt_priority: bp
                    .compile_expr(Object::MtaExtensions.singleton(), &ext.ctx_mt_priority()),
            },
            mta_sts_policy: Policy::try_parse(bp).await,
            milters: bp
                .list_infallible::<MtaMilter>()
                .await
                .into_iter()
                .filter_map(|milter| {
                    let id = milter.id;
                    let milter = milter.object;

                    Some(Milter {
                        enable: bp.compile_expr(id, &milter.ctx_enable()),
                        id: Arc::new(milter.name.into()),
                        addrs: format!("{}:{}", milter.hostname, milter.port)
                            .to_socket_addrs()
                            .map_err(|err| {
                                bp.build_error(
                                    id,
                                    format!(
                                        "Unable to resolve milter hostname {}: {}",
                                        milter.hostname, err
                                    ),
                                )
                            })
                            .ok()?
                            .collect(),
                        hostname: milter.hostname,
                        port: milter.port as u16,
                        timeout_connect: milter.timeout_connect.into_inner(),
                        timeout_command: milter.timeout_command.into_inner(),
                        timeout_data: milter.timeout_data.into_inner(),
                        tls: milter.use_tls,
                        tls_allow_invalid_certs: milter.allow_invalid_certs,
                        tempfail_on_error: milter.temp_fail_on_error,
                        max_frame_len: milter.max_response_size as usize,
                        protocol_version: match milter.protocol_version {
                            enums::MilterVersion::V2 => MilterVersion::V2,
                            enums::MilterVersion::V6 => MilterVersion::V6,
                        },
                        flags_actions: milter.flags_action.map(|v| v as u32),
                        flags_protocol: milter.flags_protocol.map(|v| v as u32),
                        run_on_stage: milter.stages.into_iter().map(Stage::from).collect(),
                    })
                })
                .collect(),
            hooks: bp
                .list_infallible::<MtaHook>()
                .await
                .into_iter()
                .filter_map(|hook| {
                    let id = hook.id;
                    let hook = hook.object;

                    Some(MTAHook {
                        enable: bp.compile_expr(id, &hook.ctx_enable()),
                        id: hook.name,
                        url: hook.url,
                        timeout: hook.timeout.into_inner(),
                        headers: hook
                            .http_auth
                            .build_headers(hook.http_headers, "application/json".into())
                            .map_err(|err| {
                                bp.build_error(id, format!("Unable to build HTTP headers: {}", err))
                            })
                            .ok()?,
                        tls_allow_invalid_certs: hook.allow_invalid_certs,
                        tempfail_on_error: hook.temp_fail_on_error,
                        run_on_stage: hook.stages.into_iter().map(Stage::from).collect(),
                        max_response_size: hook.max_response_size as usize,
                    })
                })
                .collect(),
        }
    }
}

#[derive(Default)]
pub struct Mechanism(u64);

impl ParseValue for Mechanism {
    fn parse_value(value: &str) -> Result<Self, String> {
        Ok(Mechanism(match value.to_ascii_uppercase().as_str() {
            "LOGIN" => AUTH_LOGIN,
            "PLAIN" => AUTH_PLAIN,
            "XOAUTH2" => AUTH_XOAUTH2,
            "OAUTHBEARER" => AUTH_OAUTHBEARER,
            /*"SCRAM-SHA-256-PLUS" => AUTH_SCRAM_SHA_256_PLUS,
            "SCRAM-SHA-256" => AUTH_SCRAM_SHA_256,
            "SCRAM-SHA-1-PLUS" => AUTH_SCRAM_SHA_1_PLUS,
            "SCRAM-SHA-1" => AUTH_SCRAM_SHA_1,
            "XOAUTH" => AUTH_XOAUTH,
            "9798-M-DSA-SHA1" => AUTH_9798_M_DSA_SHA1,
            "9798-M-ECDSA-SHA1" => AUTH_9798_M_ECDSA_SHA1,
            "9798-M-RSA-SHA1-ENC" => AUTH_9798_M_RSA_SHA1_ENC,
            "9798-U-DSA-SHA1" => AUTH_9798_U_DSA_SHA1,
            "9798-U-ECDSA-SHA1" => AUTH_9798_U_ECDSA_SHA1,
            "9798-U-RSA-SHA1-ENC" => AUTH_9798_U_RSA_SHA1_ENC,
            "EAP-AES128" => AUTH_EAP_AES128,
            "EAP-AES128-PLUS" => AUTH_EAP_AES128_PLUS,
            "ECDH-X25519-CHALLENGE" => AUTH_ECDH_X25519_CHALLENGE,
            "ECDSA-NIST256P-CHALLENGE" => AUTH_ECDSA_NIST256P_CHALLENGE,
            "EXTERNAL" => AUTH_EXTERNAL,
            "GS2-KRB5" => AUTH_GS2_KRB5,
            "GS2-KRB5-PLUS" => AUTH_GS2_KRB5_PLUS,
            "GSS-SPNEGO" => AUTH_GSS_SPNEGO,
            "GSSAPI" => AUTH_GSSAPI,
            "KERBEROS_V4" => AUTH_KERBEROS_V4,
            "KERBEROS_V5" => AUTH_KERBEROS_V5,
            "NMAS-SAMBA-AUTH" => AUTH_NMAS_SAMBA_AUTH,
            "NMAS_AUTHEN" => AUTH_NMAS_AUTHEN,
            "NMAS_LOGIN" => AUTH_NMAS_LOGIN,
            "NTLM" => AUTH_NTLM,
            "OAUTH10A" => AUTH_OAUTH10A,
            "OPENID20" => AUTH_OPENID20,
            "OTP" => AUTH_OTP,
            "SAML20" => AUTH_SAML20,
            "SECURID" => AUTH_SECURID,
            "SKEY" => AUTH_SKEY,
            "SPNEGO" => AUTH_SPNEGO,
            "SPNEGO-PLUS" => AUTH_SPNEGO_PLUS,
            "SXOVER-PLUS" => AUTH_SXOVER_PLUS,
            "CRAM-MD5" => AUTH_CRAM_MD5,
            "DIGEST-MD5" => AUTH_DIGEST_MD5,
            "ANONYMOUS" => AUTH_ANONYMOUS,*/
            _ => return Err(format!("Unsupported mechanism {:?}.", value)),
        }))
    }
}

impl<'x> TryFrom<Variable<'x>> for Mechanism {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Constant(value) => Mechanism::try_from(value),
            Variable::Array(items) => {
                let mut mechanism = 0;

                for item in items {
                    match item {
                        Variable::Constant(value) => mechanism |= Mechanism::try_from(value)?.0,
                        _ => return Err(()),
                    }
                }

                Ok(Mechanism(mechanism))
            }
            _ => Err(()),
        }
    }
}

impl TryFrom<ExpressionConstant> for Mechanism {
    type Error = ();

    fn try_from(value: ExpressionConstant) -> Result<Self, Self::Error> {
        match value {
            ExpressionConstant::Login => Ok(Mechanism(AUTH_LOGIN)),
            ExpressionConstant::Plain => Ok(Mechanism(AUTH_PLAIN)),
            ExpressionConstant::Xoauth2 => Ok(Mechanism(AUTH_XOAUTH2)),
            ExpressionConstant::Oauthbearer => Ok(Mechanism(AUTH_OAUTHBEARER)),
            _ => Err(()),
        }
    }
}

impl From<Mechanism> for u64 {
    fn from(value: Mechanism) -> Self {
        value.0
    }
}

impl From<u64> for Mechanism {
    fn from(value: u64) -> Self {
        Mechanism(value)
    }
}

impl<'x> TryFrom<Variable<'x>> for MtPriority {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Constant(value) => match value {
                ExpressionConstant::Mixer => Ok(MtPriority::Mixer),
                ExpressionConstant::Stanag4406 => Ok(MtPriority::Stanag4406),
                ExpressionConstant::Nsep => Ok(MtPriority::Nsep),
                _ => Err(()),
            },
            Variable::String(value) => MtPriority::parse_value(value.as_str()).map_err(|_| ()),
            _ => Err(()),
        }
    }
}

impl From<MtaStage> for Stage {
    fn from(value: MtaStage) -> Self {
        match value {
            MtaStage::Connect => Stage::Connect,
            MtaStage::Ehlo => Stage::Ehlo,
            MtaStage::Auth => Stage::Auth,
            MtaStage::Mail => Stage::Mail,
            MtaStage::Rcpt => Stage::Rcpt,
            MtaStage::Data => Stage::Data,
        }
    }
}
