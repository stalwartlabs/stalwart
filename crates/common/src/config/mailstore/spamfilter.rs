/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    expr::{Variable, functions::ResolveVariable, if_block::IfBlock},
    manager::bootstrap::Bootstrap,
};
use ahash::AHashSet;
use mail_auth::common::resolver::ToReverseName;
use nlp::classifier::model::{CcfhClassifier, FhClassifier};
use registry::schema::{
    enums::{ExpressionVariable, ModelSize},
    prelude::Object,
    structs::{
        self, SpamDnsblServer, SpamDnsblSettings, SpamFileExtension, SpamPyzor, SpamRule,
        SpamSettings, SpamTag,
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use store::registry::RegistryObject;
use tokio::net::lookup_host;
use utils::{cache::CacheItemWeight, config::utils::ParseValue, glob::GlobMap};

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default)]
pub enum SpamClassifier {
    FhClassifier {
        classifier: FhClassifier,
        last_trained_at: u64,
    },
    CcfhClassifier {
        classifier: CcfhClassifier,
        last_trained_at: u64,
    },
    #[default]
    Disabled,
}

#[derive(Debug, Clone, Default)]
pub struct SpamFilterConfig {
    pub enabled: bool,
    pub card_is_ham: bool,
    pub trusted_reply: bool,
    pub grey_list_expiry: Option<u64>,

    pub dnsbl: DnsBlConfig,
    pub rules: SpamFilterRules,
    pub lists: SpamFilterLists,
    pub pyzor: Option<PyzorConfig>,
    pub classifier: Option<ClassifierConfig>,
    pub scores: SpamFilterScoreConfig,
}

#[derive(Debug, Clone, Default)]
pub struct SpamFilterScoreConfig {
    pub reject_threshold: f32,
    pub discard_threshold: f32,
    pub spam_threshold: f32,
}

#[derive(Debug, Clone, Default)]
pub struct DnsBlConfig {
    pub max_ip_checks: usize,
    pub max_domain_checks: usize,
    pub max_email_checks: usize,
    pub max_url_checks: usize,
    pub servers: Vec<DnsBlServer>,
}

#[derive(Debug, Clone, Default)]
pub struct SpamFilterLists {
    pub file_extensions: GlobMap<FileExtension>,
    pub scores: GlobMap<SpamFilterAction<f32>>,
}

#[derive(Debug, Clone)]
pub enum SpamFilterAction<T> {
    Allow(T),
    Discard,
    Reject,
    Disabled,
}

#[derive(Debug, Clone, Default)]
pub struct ClassifierConfig {
    pub w_params: FtrlParameters,
    pub i_params: Option<FtrlParameters>,
    pub reservoir_capacity: usize,
    pub min_ham_samples: u64,
    pub min_spam_samples: u64,
    pub auto_learn_reply_ham: bool,
    pub auto_learn_card_is_ham: bool,
    pub auto_learn_spam_trap: bool,
    pub auto_learn_spam_rbl_count: u32,
    pub hold_samples_for: u64,
    pub train_frequency: Option<u64>,
    pub log_scale: bool,
    pub l2_normalize: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FtrlParameters {
    pub feature_hash_size: usize,
    pub alpha: f64,
    pub beta: f64,
    pub l1_ratio: f64,
    pub l2_ratio: f64,
}

#[derive(Debug, Clone)]
pub struct PyzorConfig {
    pub address: SocketAddr,
    pub timeout: Duration,
    pub min_count: u64,
    pub min_wl_count: u64,
    pub ratio: f64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpamFilterRules {
    pub url: Vec<IfBlock>,
    pub domain: Vec<IfBlock>,
    pub email: Vec<IfBlock>,
    pub ip: Vec<IfBlock>,
    pub header: Vec<IfBlock>,
    pub body: Vec<IfBlock>,
    pub any: Vec<IfBlock>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileExtension {
    pub known_types: AHashSet<String>,
    pub is_bad: bool,
    pub is_archive: bool,
    pub is_nz: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Element {
    Url,
    Domain,
    Email,
    Ip,
    Header,
    Body,
    #[default]
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Location {
    EnvelopeFrom,
    EnvelopeTo,
    HeaderDkimPass,
    HeaderReceived,
    HeaderFrom,
    HeaderReplyTo,
    HeaderSubject,
    HeaderTo,
    HeaderCc,
    HeaderBcc,
    HeaderMid,
    HeaderDnt,
    Ehlo,
    BodyText,
    BodyHtml,
    Attachment,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct DnsBlServer {
    pub id: String,
    pub zone: IfBlock,
    pub scope: Element,
    pub tags: IfBlock,
}

impl SpamFilterConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let spam = bp.setting_infallible::<SpamSettings>().await;

        SpamFilterConfig {
            enabled: spam.enable,
            card_is_ham: spam.trust_contacts,
            trusted_reply: spam.trust_replies,
            dnsbl: DnsBlConfig::parse(bp).await,
            rules: SpamFilterRules::parse(bp).await,
            lists: SpamFilterLists::parse(bp).await,
            pyzor: PyzorConfig::parse(bp).await,
            classifier: ClassifierConfig::parse(bp).await,
            scores: SpamFilterScoreConfig {
                reject_threshold: spam.score_reject as f32,
                discard_threshold: spam.score_discard as f32,
                spam_threshold: spam.score_spam as f32,
            },
            grey_list_expiry: spam.greylist_for.map(|d| d.into_inner().as_secs()),
        }
    }
}

impl SpamFilterRules {
    pub async fn parse(bp: &mut Bootstrap) -> SpamFilterRules {
        let mut rules = vec![];
        for rule in bp.list_infallible::<SpamRule>().await {
            if let Some(rule) = SpamFilterRule::parse(bp, rule) {
                rules.push(rule);
            }
        }
        rules.sort_by(|a, b| a.priority.cmp(&b.priority));

        let mut result = SpamFilterRules::default();

        for rule in rules {
            match rule.scope {
                Element::Url => result.url.push(rule.rule),
                Element::Domain => result.domain.push(rule.rule),
                Element::Email => result.email.push(rule.rule),
                Element::Ip => result.ip.push(rule.rule),
                Element::Header => result.header.push(rule.rule),
                Element::Body => result.body.push(rule.rule),
                Element::Any => result.any.push(rule.rule),
            }
        }

        result
    }
}

struct SpamFilterRule {
    rule: IfBlock,
    priority: i32,
    scope: Element,
}

impl SpamFilterRule {
    pub fn parse(bp: &mut Bootstrap, obj: RegistryObject<SpamRule>) -> Option<Self> {
        match obj.object {
            SpamRule::Any(rule) if rule.enable => SpamFilterRule {
                rule: bp.compile_expr(obj.id, &rule.ctx_condition()),
                scope: Element::Any,
                priority: rule.priority as i32,
            }
            .into(),
            SpamRule::Url(rule) if rule.enable => SpamFilterRule {
                rule: bp.compile_expr(obj.id, &rule.ctx_condition()),
                scope: Element::Url,
                priority: rule.priority as i32,
            }
            .into(),
            SpamRule::Domain(rule) if rule.enable => SpamFilterRule {
                rule: bp.compile_expr(obj.id, &rule.ctx_condition()),
                scope: Element::Domain,
                priority: rule.priority as i32,
            }
            .into(),
            SpamRule::Email(rule) if rule.enable => SpamFilterRule {
                rule: bp.compile_expr(obj.id, &rule.ctx_condition()),
                scope: Element::Email,
                priority: rule.priority as i32,
            }
            .into(),
            SpamRule::Ip(rule) if rule.enable => SpamFilterRule {
                rule: bp.compile_expr(obj.id, &rule.ctx_condition()),
                scope: Element::Ip,
                priority: rule.priority as i32,
            }
            .into(),
            SpamRule::Header(rule) if rule.enable => SpamFilterRule {
                rule: bp.compile_expr(obj.id, &rule.ctx_condition()),
                scope: Element::Header,
                priority: rule.priority as i32,
            }
            .into(),
            SpamRule::Body(rule) if rule.enable => SpamFilterRule {
                rule: bp.compile_expr(obj.id, &rule.ctx_condition()),
                scope: Element::Body,
                priority: rule.priority as i32,
            }
            .into(),
            _ => None,
        }
    }
}

impl DnsBlConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut servers = vec![];
        for server in bp.list_infallible::<SpamDnsblServer>().await {
            if let Some(server) = DnsBlServer::parse(bp, server) {
                servers.push(server);
            }
        }

        let dnsbl = bp.setting_infallible::<SpamDnsblSettings>().await;
        DnsBlConfig {
            max_ip_checks: dnsbl.ip_limit as usize,
            max_domain_checks: dnsbl.domain_limit as usize,
            max_email_checks: dnsbl.email_limit as usize,
            max_url_checks: dnsbl.url_limit as usize,
            servers,
        }
    }
}

impl DnsBlServer {
    pub fn parse(bp: &mut Bootstrap, obj: RegistryObject<SpamDnsblServer>) -> Option<Self> {
        match obj.object {
            SpamDnsblServer::Any(server) if server.enable => DnsBlServer {
                zone: bp.compile_expr(obj.id, &server.ctx_zone()),
                tags: bp.compile_expr(obj.id, &server.ctx_tag()),
                scope: Element::Any,
                id: server.name,
            }
            .into(),
            SpamDnsblServer::Url(server) if server.enable => DnsBlServer {
                zone: bp.compile_expr(obj.id, &server.ctx_zone()),
                tags: bp.compile_expr(obj.id, &server.ctx_tag()),
                scope: Element::Url,
                id: server.name,
            }
            .into(),
            SpamDnsblServer::Domain(server) if server.enable => DnsBlServer {
                zone: bp.compile_expr(obj.id, &server.ctx_zone()),
                tags: bp.compile_expr(obj.id, &server.ctx_tag()),
                scope: Element::Domain,
                id: server.name,
            }
            .into(),
            SpamDnsblServer::Email(server) if server.enable => DnsBlServer {
                zone: bp.compile_expr(obj.id, &server.ctx_zone()),
                tags: bp.compile_expr(obj.id, &server.ctx_tag()),
                scope: Element::Email,
                id: server.name,
            }
            .into(),
            SpamDnsblServer::Ip(server) if server.enable => DnsBlServer {
                zone: bp.compile_expr(obj.id, &server.ctx_zone()),
                tags: bp.compile_expr(obj.id, &server.ctx_tag()),
                scope: Element::Ip,
                id: server.name,
            }
            .into(),
            SpamDnsblServer::Header(server) if server.enable => DnsBlServer {
                zone: bp.compile_expr(obj.id, &server.ctx_zone()),
                tags: bp.compile_expr(obj.id, &server.ctx_tag()),
                scope: Element::Header,
                id: server.name,
            }
            .into(),
            SpamDnsblServer::Body(server) if server.enable => DnsBlServer {
                zone: bp.compile_expr(obj.id, &server.ctx_zone()),
                tags: bp.compile_expr(obj.id, &server.ctx_tag()),
                scope: Element::Body,
                id: server.name,
            }
            .into(),
            _ => None,
        }
    }
}

impl SpamFilterLists {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut lists = SpamFilterLists {
            file_extensions: GlobMap::default(),
            scores: GlobMap::default(),
        };

        for tag in bp.list_infallible::<SpamTag>().await {
            match tag.object {
                SpamTag::Score(tag) => lists
                    .scores
                    .insert(&tag.tag, SpamFilterAction::Allow(tag.score as f32)),
                SpamTag::Discard(tag) => lists.scores.insert(&tag.tag, SpamFilterAction::Discard),
                SpamTag::Reject(tag) => lists.scores.insert(&tag.tag, SpamFilterAction::Reject),
            }
        }

        for ext in bp.list_infallible::<SpamFileExtension>().await {
            let ext = ext.object;
            lists.file_extensions.insert(
                &ext.extension,
                FileExtension {
                    known_types: ext.content_types.into_iter().collect(),
                    is_bad: ext.is_bad,
                    is_archive: ext.is_archive,
                    is_nz: ext.is_nz,
                },
            );
        }

        lists
    }
}

impl PyzorConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        let pyzor = bp.setting_infallible::<SpamPyzor>().await;

        if !pyzor.enable {
            return None;
        }

        let port = pyzor.port;
        let host = pyzor.host;
        let address = match lookup_host(format!("{host}:{port}"))
            .await
            .map(|mut a| a.next())
        {
            Ok(Some(address)) => address,
            Ok(None) => {
                bp.build_error(
                    Object::SpamPyzor.singleton(),
                    "Invalid address: No addresses found.",
                );
                return None;
            }
            Err(err) => {
                bp.build_error(
                    Object::SpamPyzor.singleton(),
                    format!("Invalid address: {}", err),
                );
                return None;
            }
        };

        PyzorConfig {
            address,
            timeout: pyzor.timeout.into_inner(),
            min_count: pyzor.block_count,
            min_wl_count: pyzor.allow_count,
            ratio: pyzor.ratio,
        }
        .into()
    }
}

impl ClassifierConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        let classifier = bp.setting_infallible::<structs::SpamClassifier>().await;
        let w_params;
        let i_params;
        let log_scale;
        let l2_normalize;

        match classifier.model {
            structs::SpamClassifierModel::FtrlFh(model) => {
                log_scale = model.feature_log_scale;
                l2_normalize = model.feature_l2_normalize;
                w_params = FtrlParameters::parse(&model.parameters);
                i_params = None;
            }
            structs::SpamClassifierModel::FtrlCcfh(model) => {
                log_scale = model.feature_log_scale;
                l2_normalize = model.feature_l2_normalize;
                w_params = FtrlParameters::parse(&model.parameters);
                i_params = Some(FtrlParameters::parse(&model.indicator_parameters));
            }
            structs::SpamClassifierModel::Disabled => return None,
        }

        ClassifierConfig {
            w_params,
            i_params,
            reservoir_capacity: classifier.reservoir_capacity as usize,
            auto_learn_card_is_ham: classifier.learn_ham_from_card,
            auto_learn_reply_ham: classifier.learn_ham_from_reply,
            auto_learn_spam_trap: classifier.learn_spam_from_traps,
            auto_learn_spam_rbl_count: classifier.learn_spam_from_rbl_hits as u32,
            hold_samples_for: classifier.hold_samples_for.into_inner().as_secs(),
            min_ham_samples: classifier.min_ham_samples,
            min_spam_samples: classifier.min_spam_samples,
            train_frequency: classifier.train_frequency.map(|d| d.into_inner().as_secs()),
            log_scale,
            l2_normalize,
        }
        .into()
    }
}

impl FtrlParameters {
    pub fn parse(params: &structs::FtrlParameters) -> Self {
        let hash_size = match params.num_features {
            ModelSize::V16 => 16,
            ModelSize::V17 => 17,
            ModelSize::V18 => 18,
            ModelSize::V19 => 19,
            ModelSize::V20 => 20,
            ModelSize::V21 => 21,
            ModelSize::V22 => 22,
            ModelSize::V23 => 23,
            ModelSize::V24 => 24,
            ModelSize::V25 => 25,
            ModelSize::V26 => 26,
            ModelSize::V27 => 27,
            ModelSize::V28 => 28,
        };
        FtrlParameters {
            feature_hash_size: 1 << hash_size,
            alpha: params.alpha,
            beta: params.beta,
            l1_ratio: params.l1_ratio,
            l2_ratio: params.l2_ratio,
        }
    }
}

impl SpamClassifier {
    pub fn is_active(&self) -> bool {
        !matches!(self, SpamClassifier::Disabled)
    }
}

impl ParseValue for Element {
    fn parse_value(value: &str) -> utils::config::Result<Self> {
        match value {
            "url" => Ok(Element::Url),
            "domain" => Ok(Element::Domain),
            "email" => Ok(Element::Email),
            "ip" => Ok(Element::Ip),
            "header" => Ok(Element::Header),
            "body" => Ok(Element::Body),
            "any" | "message" => Ok(Element::Any),
            other => Err(format!("Invalid type {other:?}.",)),
        }
    }
}

impl Location {
    pub fn as_str(&self) -> &'static str {
        match self {
            Location::EnvelopeFrom => "env_from",
            Location::EnvelopeTo => "env_to",
            Location::HeaderDkimPass => "dkim_pass",
            Location::HeaderReceived => "received",
            Location::HeaderFrom => "from",
            Location::HeaderReplyTo => "reply_to",
            Location::HeaderSubject => "subject",
            Location::HeaderTo => "to",
            Location::HeaderCc => "cc",
            Location::HeaderBcc => "bcc",
            Location::HeaderMid => "message_id",
            Location::HeaderDnt => "dnt",
            Location::Ehlo => "ehlo",
            Location::BodyText => "body_text",
            Location::BodyHtml => "body_html",
            Location::Attachment => "attachment",
            Location::Tcp => "tcp",
        }
    }
}

impl Element {
    pub fn as_str(&self) -> &'static str {
        match self {
            Element::Url => "url",
            Element::Domain => "domain",
            Element::Email => "email",
            Element::Ip => "ip",
            Element::Header => "header",
            Element::Body => "body",
            Element::Any => "any",
        }
    }
}

pub struct IpResolver {
    ip: IpAddr,
    ip_string: String,
    reverse: String,
    octets: Variable<'static>,
}

impl ResolveVariable for IpResolver {
    fn resolve_variable(&self, variable: ExpressionVariable) -> Variable<'_> {
        match variable {
            ExpressionVariable::Ip | ExpressionVariable::Value => self.ip_string.as_str().into(),
            ExpressionVariable::IpReverse => self.reverse.as_str().into(),
            ExpressionVariable::Octets => self.octets.clone(),
            ExpressionVariable::IsV4 => Variable::Integer(self.ip.is_ipv4() as _),
            ExpressionVariable::IsV6 => Variable::Integer(self.ip.is_ipv6() as _),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl IpResolver {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip_string: ip.to_string(),
            reverse: ip.to_reverse_name(),
            octets: Variable::Array(match ip {
                IpAddr::V4(ipv4_addr) => ipv4_addr
                    .octets()
                    .iter()
                    .map(|o| Variable::Integer(*o as _))
                    .collect(),
                IpAddr::V6(ipv6_addr) => ipv6_addr
                    .octets()
                    .iter()
                    .map(|o| Variable::Integer(*o as _))
                    .collect(),
            }),
            ip,
        }
    }
}

impl CacheItemWeight for IpResolver {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<IpResolver>() + self.ip_string.len() + self.reverse.len()) as u64
    }
}

impl<T> SpamFilterAction<T> {
    pub fn as_score(&self) -> Option<&T> {
        match self {
            SpamFilterAction::Allow(value) => Some(value),
            _ => None,
        }
    }
}
