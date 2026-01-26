/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::expr::{Variable, if_block::IfBlock};
use registry::schema::{
    enums::ExpressionConstant,
    prelude::Object,
    structs::{
        DataRetention, DkimReportSettings, DmarcReportSettings, ReportSettings, SpfReportSettings,
        TlsReportSettings,
    },
};
use std::time::Duration;
use utils::config::utils::ParseValue;

#[derive(Clone)]
pub struct ReportConfig {
    pub submitter: IfBlock,
    pub analysis: ReportAnalysis,

    pub dkim: Report,
    pub spf: Report,
    pub dmarc: Report,
    pub dmarc_aggregate: AggregateReport,
    pub tls: AggregateReport,
}

#[derive(Clone)]
pub struct ReportAnalysis {
    pub addresses: Vec<AddressMatch>,
    pub forward: bool,
    pub store: Option<Duration>,
}

#[derive(Clone)]
pub enum AddressMatch {
    StartsWith(String),
    EndsWith(String),
    Equals(String),
}

#[derive(Clone)]
pub struct AggregateReport {
    pub name: IfBlock,
    pub address: IfBlock,
    pub org_name: IfBlock,
    pub contact_info: IfBlock,
    pub send: IfBlock,
    pub sign: IfBlock,
    pub max_size: IfBlock,
}

#[derive(Clone)]
pub struct Report {
    pub name: IfBlock,
    pub address: IfBlock,
    pub subject: IfBlock,
    pub sign: IfBlock,
    pub send: IfBlock,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AggregateFrequency {
    Hourly,
    Daily,
    Weekly,
    #[default]
    Never,
}

impl ReportConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let report = bp.setting_infallible::<ReportSettings>().await;
        let dkim = bp.setting_infallible::<DkimReportSettings>().await;
        let spf = bp.setting_infallible::<SpfReportSettings>().await;
        let dmarc = bp.setting_infallible::<DmarcReportSettings>().await;
        let tls = bp.setting_infallible::<TlsReportSettings>().await;
        let dr = bp.setting_infallible::<DataRetention>().await;

        ReportConfig {
            submitter: bp.compile_expr(
                Object::ReportSettings.singleton(),
                &report.ctx_outbound_report_submitter(),
            ),
            analysis: ReportAnalysis {
                addresses: report
                    .inbound_report_addresses
                    .iter()
                    .filter_map(|addr| AddressMatch::parse_value(addr).ok())
                    .collect(),
                forward: report.inbound_report_forwarding,
                store: dr.hold_mta_reports_for.map(|d| d.into_inner()),
            },
            dkim: Report {
                name: bp.compile_expr(
                    Object::DkimReportSettings.singleton(),
                    &dkim.ctx_from_name(),
                ),
                address: bp.compile_expr(
                    Object::DkimReportSettings.singleton(),
                    &dkim.ctx_from_address(),
                ),
                subject: bp
                    .compile_expr(Object::DkimReportSettings.singleton(), &dkim.ctx_subject()),
                sign: bp.compile_expr(
                    Object::DkimReportSettings.singleton(),
                    &dkim.ctx_dkim_sign_domain(),
                ),
                send: bp.compile_expr(
                    Object::DkimReportSettings.singleton(),
                    &dkim.ctx_send_frequency(),
                ),
            },
            spf: Report {
                name: bp.compile_expr(Object::SpfReportSettings.singleton(), &spf.ctx_from_name()),
                address: bp.compile_expr(
                    Object::SpfReportSettings.singleton(),
                    &spf.ctx_from_address(),
                ),
                subject: bp.compile_expr(Object::SpfReportSettings.singleton(), &spf.ctx_subject()),
                sign: bp.compile_expr(
                    Object::SpfReportSettings.singleton(),
                    &spf.ctx_dkim_sign_domain(),
                ),
                send: bp.compile_expr(
                    Object::SpfReportSettings.singleton(),
                    &spf.ctx_send_frequency(),
                ),
            },
            dmarc: Report {
                name: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_failure_from_name(),
                ),
                address: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_failure_from_address(),
                ),
                subject: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_failure_subject(),
                ),
                sign: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_failure_dkim_sign_domain(),
                ),
                send: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_failure_send_frequency(),
                ),
            },
            dmarc_aggregate: AggregateReport {
                name: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_aggregate_from_name(),
                ),
                address: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_aggregate_from_address(),
                ),
                org_name: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_aggregate_org_name(),
                ),
                contact_info: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_aggregate_contact_info(),
                ),
                send: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_aggregate_send_frequency(),
                ),
                sign: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_aggregate_dkim_sign_domain(),
                ),
                max_size: bp.compile_expr(
                    Object::DmarcReportSettings.singleton(),
                    &dmarc.ctx_aggregate_max_report_size(),
                ),
            },
            tls: AggregateReport {
                name: bp.compile_expr(Object::TlsReportSettings.singleton(), &tls.ctx_from_name()),
                address: bp.compile_expr(
                    Object::TlsReportSettings.singleton(),
                    &tls.ctx_from_address(),
                ),
                org_name: bp
                    .compile_expr(Object::TlsReportSettings.singleton(), &tls.ctx_org_name()),
                contact_info: bp.compile_expr(
                    Object::TlsReportSettings.singleton(),
                    &tls.ctx_contact_info(),
                ),
                send: bp.compile_expr(
                    Object::TlsReportSettings.singleton(),
                    &tls.ctx_send_frequency(),
                ),
                sign: bp.compile_expr(
                    Object::TlsReportSettings.singleton(),
                    &tls.ctx_dkim_sign_domain(),
                ),
                max_size: bp.compile_expr(
                    Object::TlsReportSettings.singleton(),
                    &tls.ctx_max_report_size(),
                ),
            },
        }
    }
}

impl ParseValue for AggregateFrequency {
    fn parse_value(value: &str) -> Result<Self, String> {
        match value {
            "daily" | "day" => Ok(AggregateFrequency::Daily),
            "hourly" | "hour" => Ok(AggregateFrequency::Hourly),
            "weekly" | "week" => Ok(AggregateFrequency::Weekly),
            "never" | "disable" | "false" => Ok(AggregateFrequency::Never),
            _ => Err(format!("Invalid aggregate frequency value {:?}.", value,)),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for AggregateFrequency {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Constant(ExpressionConstant::Disable) => Ok(AggregateFrequency::Never),
            Variable::Constant(ExpressionConstant::Hourly) => Ok(AggregateFrequency::Hourly),
            Variable::Constant(ExpressionConstant::Daily) => Ok(AggregateFrequency::Daily),
            Variable::Constant(ExpressionConstant::Weekly) => Ok(AggregateFrequency::Weekly),
            _ => Err(()),
        }
    }
}

impl ParseValue for AddressMatch {
    fn parse_value(value: &str) -> Result<Self, String> {
        if let Some(value) = value.strip_prefix('*').map(|v| v.trim()) {
            if !value.is_empty() {
                return Ok(AddressMatch::EndsWith(value.to_lowercase()));
            }
        } else if let Some(value) = value.strip_suffix('*').map(|v| v.trim()) {
            if !value.is_empty() {
                return Ok(AddressMatch::StartsWith(value.to_lowercase()));
            }
        } else if value.contains('@') {
            return Ok(AddressMatch::Equals(value.trim().to_lowercase()));
        }
        Err(format!("Invalid address match value {:?}.", value,))
    }
}
