/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

pub mod ai;
pub mod alerts;
pub mod config;
pub mod license;
pub mod logo;

pub use crate::config::mailstore::spamfilter::AI_TAG_PREFIX;

use crate::{
    Core, LogoCache, Server, config::groupware::CalendarTemplateVariable, expr::if_block::IfBlock,
    manager::application::Resource,
};
use ai::{AiClassifier, AiModel, AiVerdict, BreakerPolicy, PreparedClassifier};
use bytes::Bytes;
use compact_str::CompactString;
use license::LicenseKey;
use logo::{LogoLoadError, LogoSource};
use mail_parser::DateTime;
use registry::{
    schema::structs::{Domain, Tenant},
    types::id::ObjectId,
};
use std::{sync::Arc, time::Duration};
use trc::{AddContext, MetricType};
use utils::{cron::SimpleCron, outbound::OutboundPolicy, template::Template};

#[derive(Clone)]
pub struct Enterprise {
    pub license: LicenseKey,
    pub logo: Option<String>,
    pub deleted_items_retention: Option<Duration>,
    pub deleted_accounts_retention: Option<Duration>,
    pub trace_retention: Option<Duration>,
    pub metrics_retention: Option<Duration>,
    pub metrics_interval: SimpleCron,
    pub metrics_alerts: Vec<MetricAlert>,
    pub ai_models: Vec<Arc<AiModel>>,
    pub spam_ai: Option<Arc<SpamAiConfig>>,
    pub template_calendar_alarm: Option<Template<CalendarTemplateVariable>>,
    pub template_scheduling_email: Option<Template<CalendarTemplateVariable>>,
    pub template_scheduling_web: Option<Arc<str>>,
}

pub struct SpamAiConfig {
    pub mode: SpamAiMode,
    pub condition: IfBlock,
    pub tiers: Box<[SpamAiTier]>,
    pub classifier: Arc<AiClassifier>,
    pub category_tags: Box<[[CompactString; 3]]>,
    pub signal_tags: Box<[CompactString]>,
    pub buckets: SpamAiBuckets,
    pub add_header: bool,
    pub input: SpamAiInput,
    pub deadline: Duration,
    pub breaker: BreakerPolicy,
    pub learn: Option<SpamAiLearn>,
    pub web_search: SpamAiWebSearch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamAiMode {
    Automatic,
    Shadow,
}

pub struct SpamAiTier {
    pub classifier: PreparedClassifier,
    pub escalate_below: f32,
    pub escalate_on: Box<[u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpamAiBuckets {
    pub high: f32,
    pub medium: f32,
    pub uncertain_below: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpamAiInput {
    pub max_input_chars: usize,
    pub max_links: usize,
    pub max_attachments: usize,
    pub trim_quotes: bool,
    pub include_auth: bool,
    pub include_links: bool,
    pub include_attachments: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpamAiLearn {
    pub min_probability: f32,
    pub sample_rate: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamAiWebSearch {
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamAiBucket {
    High,
    Medium,
    Low,
}

pub const AI_TAG_UNCERTAIN: &str = "AI_UNCERTAIN";
pub const AI_TAG_ERROR: &str = "AI_ERROR";
pub const AI_SIGNAL_THRESHOLD: f32 = 0.5;

impl SpamAiBuckets {
    pub fn bucket(&self, probability: f32) -> SpamAiBucket {
        if probability >= self.high {
            SpamAiBucket::High
        } else if probability >= self.medium {
            SpamAiBucket::Medium
        } else {
            SpamAiBucket::Low
        }
    }
}

impl SpamAiBucket {
    pub fn index(self) -> usize {
        match self {
            SpamAiBucket::High => 0,
            SpamAiBucket::Medium => 1,
            SpamAiBucket::Low => 2,
        }
    }
}

impl SpamAiConfig {
    pub fn is_uncertain(&self, verdict: &AiVerdict) -> bool {
        verdict.confidence < self.buckets.uncertain_below
    }

    pub fn should_escalate(&self, tier: &SpamAiTier, verdict: &AiVerdict) -> bool {
        self.is_uncertain(verdict)
            || verdict.confidence < tier.escalate_below
            || self.buckets.bucket(verdict.probability) == SpamAiBucket::Low
            || tier.escalate_on.contains(&verdict.category)
    }

    pub fn verdict_tags(&self, verdict: &AiVerdict, tags: &mut Vec<CompactString>) {
        if self.is_uncertain(verdict) {
            tags.push(CompactString::const_new(AI_TAG_UNCERTAIN));
        } else if let Some(tag) =
            self.category_tag(verdict.category, self.buckets.bucket(verdict.probability))
        {
            tags.push(tag.clone());
        }
        for (signal, probability) in verdict.signals.iter() {
            if *probability >= AI_SIGNAL_THRESHOLD
                && let Some(tag) = self.signal_tag(*signal)
            {
                tags.push(tag.clone());
            }
        }
    }

    pub fn category_name(&self, category: u8) -> &str {
        self.classifier
            .categories
            .get(usize::from(category))
            .map_or("unknown", |category| category.name.as_ref())
    }

    pub fn category_tag(&self, category: u8, bucket: SpamAiBucket) -> Option<&CompactString> {
        self.category_tags
            .get(usize::from(category))
            .and_then(|tags| tags.get(bucket.index()))
    }

    pub fn signal_tag(&self, signal: u8) -> Option<&CompactString> {
        self.signal_tags.get(usize::from(signal))
    }
}

#[derive(Clone, Debug)]
pub struct MetricAlert {
    pub id: ObjectId,
    pub condition: IfBlock,
    pub method: Vec<AlertMethod>,
}

#[derive(Clone, Debug)]
pub enum AlertMethod {
    Email {
        from_name: Option<String>,
        from_addr: String,
        to: Vec<String>,
        subject: AlertContent,
        body: AlertContent,
    },
    Event {
        message: Option<AlertContent>,
    },
}

#[derive(Clone, Debug)]
pub struct AlertContent(pub Vec<AlertContentToken>);

#[derive(Clone, Debug)]
pub enum AlertContentToken {
    Text(String),
    Metric(MetricType),
}

impl Enterprise {
    pub fn ai_model(&self, name: &str) -> Option<&Arc<AiModel>> {
        if name.is_empty() && self.ai_models.len() == 1 {
            self.ai_models.first()
        } else {
            self.ai_models.iter().find(|model| &*model.name == name)
        }
    }

    pub fn ai_model_by_id(&self, id: u64) -> Option<&Arc<AiModel>> {
        self.ai_models.iter().find(|model| model.id == id)
    }
}

impl Core {
    pub fn is_enterprise_edition(&self) -> bool {
        self.enterprise
            .as_ref()
            .is_some_and(|e| !e.license.is_expired())
    }
}

impl Server {
    // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
    // Any attempt to modify, bypass, or disable this license validation mechanism
    // constitutes a severe violation of the Stalwart Enterprise License Agreement.
    // Such actions may result in immediate termination of your license, legal action,
    // and substantial financial penalties. Stalwart Labs LLC actively monitors for
    // unauthorized modifications and will pursue all available legal remedies against
    // violators to the fullest extent of the law, including but not limited to claims
    // for copyright infringement, breach of contract, and fraud.

    #[inline]
    pub fn is_enterprise_edition(&self) -> bool {
        self.core.is_enterprise_edition()
    }

    pub fn licensed_accounts(&self) -> u32 {
        self.core
            .enterprise
            .as_ref()
            .map_or(0, |e| e.license.accounts)
    }

    pub fn log_license_details(&self) {
        if let Some(enterprise) = &self.core.enterprise {
            trc::event!(
                Server(trc::ServerEvent::Licensing),
                Details = "Stalwart Enterprise Edition license key is valid",
                Domain = enterprise.license.domain.clone(),
                Limit = enterprise.license.accounts,
                ValidFrom =
                    DateTime::from_timestamp(enterprise.license.valid_from as i64).to_rfc3339(),
                ValidTo = DateTime::from_timestamp(enterprise.license.valid_to as i64).to_rfc3339(),
            );
        }
    }

    pub async fn can_create_account(&self) -> trc::Result<bool> {
        if let Some(enterprise) = &self.core.enterprise {
            let total_accounts = self.total_accounts().await.caused_by(trc::location!())?;

            if total_accounts + 1 > enterprise.license.accounts as usize {
                trc::event!(
                    Server(trc::ServerEvent::Licensing),
                    Details = "Account creation not possible: license key account limit reached",
                    Domain = enterprise.license.domain.clone(),
                    Used = total_accounts,
                    Limit = enterprise.license.accounts,
                );

                return Ok(false);
            }
        }

        Ok(true)
    }

    pub async fn logo_resource(&self, domain: &str) -> trc::Result<Option<Resource<Bytes>>> {
        if !self.is_enterprise_edition() {
            return Ok(None);
        }

        let mut domain = psl::domain_str(domain).unwrap_or(domain);
        let logo_cache = { self.inner.data.logos.lock().get(domain).cloned() };
        if let Some(logo) = logo_cache {
            return Ok(logo.data);
        }

        let mut logo_source = None;
        let mut logo_policy = OutboundPolicy::Trusted;
        let mut domain_id = u32::MAX;
        let mut tenant_id = None;
        if let Some((d_id, t_id)) = self.domain(domain).await?.map(|d| (d.id, d.id_tenant))
            && let Some(domain_record) = self.registry().object::<Domain>(d_id.into()).await?
        {
            if domain_record.logo.is_some() {
                logo_policy = OutboundPolicy::for_tenant(domain_record.member_tenant_id);
            }
            logo_source = domain_record.logo;
            domain_id = d_id;
            tenant_id = t_id;

            if logo_source.is_none()
                && let Some(tenant_id) = tenant_id
                && let Some(tenant_logo) = self
                    .registry()
                    .object::<Tenant>(tenant_id.into())
                    .await?
                    .and_then(|t| t.logo)
            {
                logo_policy = OutboundPolicy::PublicOnly;
                logo_source = Some(tenant_logo);
            }
        } else {
            domain = "*";
        }

        if logo_source.is_none()
            && let Some(default_logo) = self.default_logo()
        {
            let logo = {
                self.inner
                    .data
                    .logos
                    .lock()
                    .get("*")
                    .map(|logo| logo.data.clone())
            };
            if let Some(logo) = logo {
                if domain != "*" {
                    self.inner.data.logos.lock().insert(
                        domain.into(),
                        LogoCache {
                            domain_id,
                            tenant_id,
                            data: logo.clone(),
                        },
                    );
                }
                return Ok(logo);
            }
            logo_source = Some(default_logo);
        }

        let logo = match logo_source {
            Some(logo_source) => match LogoSource::parse(&logo_source, logo_policy) {
                Ok(source) => source.load(logo_policy).await.map(Some),
                Err(err) => Err(LogoLoadError::Rejected(err)),
            },
            None => Ok(None),
        };
        let logo = match logo {
            Ok(logo) => logo,
            Err(err) => {
                let is_transient = err.is_transient();
                trc::error!(trc::Error::from(err).ctx(trc::Key::Domain, domain.to_string()));
                if is_transient {
                    return Ok(None);
                }
                None
            }
        };

        self.inner.data.logos.lock().insert(
            domain.into(),
            LogoCache {
                domain_id,
                tenant_id,
                data: logo.clone(),
            },
        );

        Ok(logo)
    }

    fn default_logo(&self) -> Option<String> {
        self.core.enterprise.as_ref().and_then(|e| e.logo.clone())
    }
}
