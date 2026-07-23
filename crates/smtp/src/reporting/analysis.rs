/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use common::{Server, psl};
use mail_auth::{
    flate2::read::GzDecoder,
    report::{Feedback, Report, tlsrpt::TlsReport},
    zip,
};
use mail_parser::{Message, MimeHeaders, PartType};
use registry::{
    schema::structs::{ArfExternalReport, DmarcExternalReport, TlsExternalReport},
    types::datetime::UTCDateTime,
};
use std::{
    borrow::Cow,
    io::{Cursor, Read},
};
use store::write::{BatchBuilder, now};
use trc::IncomingReportEvent;
use types::id::Id;

use crate::reporting::{inbound::LogReport, index::ExternalReportIndex};

enum Compression {
    None,
    Gzip,
    Zip,
}

enum Format<D, T, A> {
    Dmarc(D),
    Tls(T),
    Arf(A),
}

struct ReportData<'x> {
    compression: Compression,
    format: Format<(), (), ()>,
    data: &'x [u8],
}

pub trait AnalyzeReport: Sync + Send {
    fn analyze_report(&self, message: Message<'static>, session_id: u64);
}

impl AnalyzeReport for Server {
    fn analyze_report(&self, message: Message<'static>, session_id: u64) {
        let core = self.clone();
        tokio::spawn(async move {
            let from: String = message
                .from()
                .and_then(|a| a.last())
                .and_then(|a| a.address())
                .unwrap_or_default()
                .into();
            let to: Vec<String> = message.to().map_or_else(Vec::new, |a| {
                a.iter()
                    .filter_map(|a| a.address())
                    .map(|a| a.into())
                    .collect()
            });
            let subject: String = message.subject().unwrap_or_default().into();
            let mut reports = Vec::new();

            for part in &message.parts {
                match &part.body {
                    PartType::Text(report) => {
                        if part
                            .content_type()
                            .and_then(|ct| ct.subtype())
                            .is_some_and(|t| t.eq_ignore_ascii_case("xml"))
                            || part
                                .attachment_name()
                                .and_then(|n| n.rsplit_once('.'))
                                .is_some_and(|(_, e)| e.eq_ignore_ascii_case("xml"))
                        {
                            reports.push(ReportData {
                                compression: Compression::None,
                                format: Format::Dmarc(()),
                                data: report.as_bytes(),
                            });
                        } else if part.is_content_type("message", "feedback-report") {
                            reports.push(ReportData {
                                compression: Compression::None,
                                format: Format::Arf(()),
                                data: report.as_bytes(),
                            });
                        }
                    }
                    PartType::Binary(report) | PartType::InlineBinary(report) => {
                        if part.is_content_type("message", "feedback-report") {
                            reports.push(ReportData {
                                compression: Compression::None,
                                format: Format::Arf(()),
                                data: report.as_ref(),
                            });
                            continue;
                        }

                        let subtype = part
                            .content_type()
                            .and_then(|ct| ct.subtype())
                            .unwrap_or("");
                        let attachment_name = part.attachment_name();
                        let ext = attachment_name
                            .and_then(|f| f.rsplit_once('.'))
                            .map_or("", |(_, e)| e);
                        let tls_parts = subtype.rsplit_once('+');
                        let compression = match (tls_parts.map(|(_, c)| c).unwrap_or(subtype), ext)
                        {
                            ("gzip", _) => Compression::Gzip,
                            ("zip", _) => Compression::Zip,
                            (_, "gz") => Compression::Gzip,
                            (_, "zip") => Compression::Zip,
                            _ => Compression::None,
                        };
                        let format = match (tls_parts.map(|(c, _)| c).unwrap_or(subtype), ext) {
                            ("xml", _) => Format::Dmarc(()),
                            ("tlsrpt", _) | (_, "json") => Format::Tls(()),
                            _ => {
                                if attachment_name
                                    .is_some_and(|n| n.contains(".xml") || n.contains('!'))
                                {
                                    Format::Dmarc(())
                                } else {
                                    continue;
                                }
                            }
                        };

                        reports.push(ReportData {
                            compression,
                            format,
                            data: report.as_ref(),
                        });
                    }
                    _ => (),
                }
            }

            for report in reports {
                let data = match report.compression {
                    Compression::None => Cow::Borrowed(report.data),
                    Compression::Gzip => {
                        let mut file = GzDecoder::new(report.data);
                        let mut buf = Vec::new();
                        if let Err(err) = file.read_to_end(&mut buf) {
                            trc::event!(
                                IncomingReport(IncomingReportEvent::DecompressError),
                                SpanId = session_id,
                                From = from.to_string(),
                                Reason = err.to_string(),
                                CausedBy = trc::location!()
                            );

                            continue;
                        }
                        Cow::Owned(buf)
                    }
                    Compression::Zip => {
                        let data = report.data.to_vec();
                        let result = tokio::task::spawn_blocking(
                            move || -> Result<Vec<u8>, std::io::Error> {
                                let mut archive = zip::ZipArchive::new(Cursor::new(data))
                                    .map_err(std::io::Error::other)?;
                                let mut buf = Vec::new();
                                if !archive.is_empty() {
                                    let mut file =
                                        archive.by_index(0).map_err(std::io::Error::other)?;
                                    buf.reserve(file.compressed_size() as usize);
                                    file.read_to_end(&mut buf)?;
                                }
                                Ok(buf)
                            },
                        )
                        .await;
                        match result {
                            Ok(Ok(buf)) => Cow::Owned(buf),
                            Ok(Err(err)) => {
                                trc::event!(
                                    IncomingReport(IncomingReportEvent::DecompressError),
                                    SpanId = session_id,
                                    From = from.to_string(),
                                    Reason = err.to_string(),
                                    CausedBy = trc::location!()
                                );
                                continue;
                            }
                            Err(err) => {
                                trc::event!(
                                    IncomingReport(IncomingReportEvent::DecompressError),
                                    SpanId = session_id,
                                    From = from.to_string(),
                                    Reason = err.to_string(),
                                    CausedBy = trc::location!()
                                );
                                continue;
                            }
                        }
                    }
                };

                let report = match report.format {
                    Format::Dmarc(_) => match Report::parse_xml(&data) {
                        Ok(report) => {
                            // Log
                            report.log();
                            Format::Dmarc(report)
                        }
                        Err(err) => {
                            trc::event!(
                                IncomingReport(IncomingReportEvent::DmarcParseFailed),
                                SpanId = session_id,
                                From = from.to_string(),
                                Reason = err,
                                CausedBy = trc::location!()
                            );

                            continue;
                        }
                    },
                    Format::Tls(_) => match TlsReport::parse_json(&data) {
                        Ok(report) => {
                            // Log
                            report.log();
                            Format::Tls(report)
                        }
                        Err(err) => {
                            trc::event!(
                                IncomingReport(IncomingReportEvent::TlsRpcParseFailed),
                                SpanId = session_id,
                                From = from.to_string(),
                                Reason = format!("{err:?}"),
                                CausedBy = trc::location!()
                            );

                            continue;
                        }
                    },
                    Format::Arf(_) => match Feedback::parse_arf(&data) {
                        Some(report) => {
                            // Log
                            report.log();
                            Format::Arf(report.into_owned())
                        }
                        None => {
                            trc::event!(
                                IncomingReport(IncomingReportEvent::ArfParseFailed),
                                SpanId = session_id,
                                From = from.to_string(),
                                CausedBy = trc::location!()
                            );

                            continue;
                        }
                    },
                };

                // Store report
                if let Some(expires_in) = &core.core.smtp.report.analysis.store {
                    let expires = now() + expires_in.as_secs();
                    let item_id = core.inner.data.queue_id_gen.generate();
                    let mut batch = BatchBuilder::new();

                    match report {
                        Format::Dmarc(report) => {
                            let mut report = DmarcExternalReport {
                                from,
                                to: to.into(),
                                subject,
                                member_tenant_id: None,
                                expires_at: UTCDateTime::from_timestamp(expires as i64),
                                received_at: UTCDateTime::now(),
                                report: report.into(),
                            };
                            report.member_tenant_id = tenant_ids(
                                &core,
                                report
                                    .domains()
                                    .filter_map(psl::domain_str)
                                    .collect::<AHashSet<_>>(),
                            )
                            .await;
                            report.write_ops(&mut batch, item_id, true);
                        }
                        Format::Tls(report) => {
                            let mut report = TlsExternalReport {
                                from,
                                to: to.into(),
                                subject,
                                member_tenant_id: None,
                                expires_at: UTCDateTime::from_timestamp(expires as i64),
                                received_at: UTCDateTime::now(),
                                report: report.into(),
                            };
                            report.member_tenant_id = tenant_ids(
                                &core,
                                report
                                    .domains()
                                    .filter_map(psl::domain_str)
                                    .collect::<AHashSet<_>>(),
                            )
                            .await;
                            report.write_ops(&mut batch, item_id, true);
                        }
                        Format::Arf(report) => {
                            let mut report = ArfExternalReport {
                                from,
                                to: to.into(),
                                subject,
                                member_tenant_id: None,
                                expires_at: UTCDateTime::from_timestamp(expires as i64),
                                received_at: UTCDateTime::now(),
                                report: report.into(),
                            };
                            report.member_tenant_id = tenant_ids(
                                &core,
                                report
                                    .domains()
                                    .filter_map(psl::domain_str)
                                    .collect::<AHashSet<_>>(),
                            )
                            .await;
                            report.write_ops(&mut batch, item_id, true);
                        }
                    }

                    if let Err(err) = core.core.storage.data.write(batch.build_all()).await {
                        trc::error!(
                            err.span_id(session_id)
                                .caused_by(trc::location!())
                                .details("Failed to write report")
                        );
                    }
                }
                return;
            }
        });
    }
}

async fn tenant_ids(server: &Server, domains: AHashSet<&str>) -> Option<Id> {
    let mut tenant_ids = Vec::with_capacity(domains.len());
    for domain in domains {
        if let Some(tenant_id) = server
            .domain(domain)
            .await
            .map_err(|err| {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to lookup domain")
                );
            })
            .unwrap_or_default()
            .and_then(|domain| domain.id_tenant)
            .map(Id::from)
            && !tenant_ids.contains(&tenant_id)
        {
            tenant_ids.push(tenant_id);
        }
    }

    if tenant_ids.len() == 1 {
        tenant_ids.into_iter().next()
    } else {
        None
    }
}
