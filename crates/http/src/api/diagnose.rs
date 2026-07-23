/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    config::smtp::{
        queue::{HostOrIp, MxConfig},
        resolver::{Policy, Tlsa},
    },
};
use hyper::body::{Bytes, Frame};
use mail_auth::{IpLookupStrategy, mta_sts::TlsRpt};
use serde::{Deserialize, Serialize};
use smtp::outbound::{
    client::{SmtpClient, StartTlsResult},
    dane::{
        dnssec::{TlsaLookup, TlsaResult},
        verify::TlsaVerify,
    },
    error::ClientError,
    lookup::{DnsLookup, SourceIp, ToNextHop},
    mta_sts::{lookup::MtaStsLookup, verify::VerifyPolicy},
};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, sync::mpsc};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub(crate) enum DeliveryStage {
    MxLookupStart {
        domain: String,
    },
    MxLookupSuccess {
        mxs: Vec<MX>,
        elapsed: u64,
    },
    MxLookupError {
        reason: String,
        elapsed: u64,
    },
    MtaStsFetchStart,
    MtaStsFetchSuccess {
        policy: Policy,
        elapsed: u64,
    },
    MtaStsFetchError {
        reason: String,
        elapsed: u64,
    },
    MtaStsNotFound {
        elapsed: u64,
    },
    TlsRptLookupStart,
    TlsRptLookupSuccess {
        rua: Vec<ReportUri>,
        elapsed: u64,
    },
    TlsRptLookupError {
        reason: String,
        elapsed: u64,
    },
    TlsRptNotFound {
        elapsed: u64,
    },
    DeliveryAttemptStart {
        hostname: String,
    },
    MtaStsVerifySuccess,
    MtaStsVerifyError {
        reason: String,
    },
    TlsaLookupStart,
    TlsaLookupSuccess {
        record: Tlsa,
        elapsed: u64,
    },
    TlsaNotFound {
        elapsed: u64,
        reason: String,
    },
    TlsaLookupError {
        elapsed: u64,
        reason: String,
    },
    IpLookupStart,
    #[serde(rename_all = "camelCase")]
    IpLookupSuccess {
        remote_ips: Vec<IpAddr>,
        elapsed: u64,
    },
    IpLookupError {
        reason: String,
        elapsed: u64,
    },
    #[serde(rename_all = "camelCase")]
    ConnectionStart {
        remote_ip: IpAddr,
    },
    ConnectionSuccess {
        elapsed: u64,
    },
    ConnectionError {
        elapsed: u64,
        reason: String,
    },
    ReadGreetingStart,
    ReadGreetingSuccess {
        elapsed: u64,
    },
    ReadGreetingError {
        elapsed: u64,
        reason: String,
    },
    EhloStart,
    EhloSuccess {
        elapsed: u64,
    },
    EhloError {
        elapsed: u64,
        reason: String,
    },
    StartTlsStart,
    StartTlsSuccess {
        elapsed: u64,
    },
    StartTlsError {
        elapsed: u64,
        reason: String,
    },
    DaneVerifySuccess,
    DaneVerifyError {
        reason: String,
    },
    MailFromStart,
    MailFromSuccess {
        elapsed: u64,
    },
    MailFromError {
        reason: String,
        elapsed: u64,
    },
    RcptToStart,
    RcptToSuccess {
        elapsed: u64,
    },
    RcptToError {
        reason: String,
        elapsed: u64,
    },
    QuitStart,
    QuitCompleted {
        elapsed: u64,
    },
    Completed,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MX {
    pub exchanges: Vec<String>,
    pub preference: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum ReportUri {
    Mail { email: String },
    Http { url: String },
}

impl DeliveryStage {
    pub fn to_frame(&self) -> Frame<Bytes> {
        let payload = format!(
            "event: event\ndata: [{}]\n\n",
            serde_json::to_string(self).unwrap_or_default()
        );
        Frame::data(Bytes::from(payload))
    }
}

trait ElapsedMs {
    fn elapsed_ms(&self) -> u64;
}

impl ElapsedMs for Instant {
    fn elapsed_ms(&self) -> u64 {
        self.elapsed().as_millis() as u64
    }
}
pub(crate) fn spawn_delivery_diagnose(
    server: Server,
    domain_or_email: String,
    timeout: Duration,
) -> mpsc::Receiver<DeliveryStage> {
    let (tx, rx) = mpsc::channel(10);

    tokio::spawn(async move {
        let _ = delivery_diagnose(tx, server, domain_or_email, timeout).await;
    });

    rx
}

async fn delivery_diagnose(
    tx: mpsc::Sender<DeliveryStage>,
    server: Server,
    domain_or_email: String,
    timeout: Duration,
) -> Result<(), mpsc::error::SendError<DeliveryStage>> {
    let (domain, email) = if let Some((_, domain)) = domain_or_email.rsplit_once('@') {
        (domain.to_string(), Some(domain_or_email))
    } else {
        (domain_or_email, None)
    };

    let local_host = &server.core.network.server_name;
    let conn_strategy = server.get_connection_or_default("default", 0);

    tx.send(DeliveryStage::MxLookupStart {
        domain: domain.to_string(),
    })
    .await?;

    // Lookup MX
    let now = Instant::now();
    let mxs = match server
        .core
        .smtp
        .resolvers
        .dns
        .mx_lookup(&domain, Some(&server.inner.cache.dns_mx))
        .await
    {
        Ok(mxs) => mxs,
        Err(err) => {
            tx.send(DeliveryStage::MxLookupError {
                reason: err.to_string(),
                elapsed: now.elapsed_ms(),
            })
            .await?;

            return Ok(());
        }
    };

    // Obtain remote host list
    let mx_config = MxConfig {
        max_mx: mxs.rrset.len(),
        max_multi_homed: 10,
        ip_lookup_strategy: IpLookupStrategy::Ipv4thenIpv6,
    };
    let hosts = if let Some(hosts) = mxs.to_remote_hosts(&domain, &mx_config) {
        tx.send(DeliveryStage::MxLookupSuccess {
            mxs: mxs
                .rrset
                .iter()
                .map(|mx| MX {
                    exchanges: mx.exchanges.iter().map(|e| e.to_string()).collect(),
                    preference: mx.preference,
                })
                .collect(),
            elapsed: now.elapsed_ms(),
        })
        .await?;

        hosts
    } else {
        tx.send(DeliveryStage::MxLookupError {
            reason: "Null MX record".to_string(),
            elapsed: now.elapsed_ms(),
        })
        .await?;

        return Ok(());
    };

    // Fetch MTA-STS policy
    let now = Instant::now();
    tx.send(DeliveryStage::MtaStsFetchStart).await?;
    let mta_sts_policy = match server.lookup_mta_sts_policy(&domain, timeout).await {
        Ok(policy) => {
            tx.send(DeliveryStage::MtaStsFetchSuccess {
                policy: policy.as_ref().clone(),
                elapsed: now.elapsed_ms(),
            })
            .await?;
            Some(policy)
        }
        Err(err) => {
            if matches!(
                &err,
                smtp::outbound::mta_sts::Error::Dns(mail_auth::Error::Dns(
                    mail_auth::DnsError::RecordNotFound(_)
                ))
            ) {
                tx.send(DeliveryStage::MtaStsNotFound {
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            } else {
                tx.send(DeliveryStage::MtaStsFetchError {
                    reason: err.to_string(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            }
            None
        }
    };

    // Fetch TLS-RPT settings
    let now = Instant::now();
    tx.send(DeliveryStage::TlsRptLookupStart).await?;
    match server
        .core
        .smtp
        .resolvers
        .dns
        .txt_lookup::<TlsRpt>(
            format!("_smtp._tls.{domain}."),
            Some(&server.inner.cache.dns_txt),
        )
        .await
    {
        Ok(record) => {
            tx.send(DeliveryStage::TlsRptLookupSuccess {
                rua: record
                    .rua
                    .iter()
                    .map(|r| match r {
                        mail_auth::mta_sts::ReportUri::Mail(email) => ReportUri::Mail {
                            email: email.clone(),
                        },
                        mail_auth::mta_sts::ReportUri::Http(url) => {
                            ReportUri::Http { url: url.clone() }
                        }
                    })
                    .collect(),
                elapsed: now.elapsed_ms(),
            })
            .await?;
        }
        Err(err) => {
            if matches!(
                &err,
                mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(_))
            ) {
                tx.send(DeliveryStage::TlsRptNotFound {
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            } else {
                tx.send(DeliveryStage::TlsRptLookupError {
                    reason: err.to_string(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            }
        }
    }

    // Try with each host
    'outer: for host in hosts {
        let hostname = host.hostname();

        tx.send(DeliveryStage::DeliveryAttemptStart {
            hostname: hostname.to_string(),
        })
        .await?;

        // Verify MTA-STS policy
        if let Some(mta_sts_policy) = &mta_sts_policy {
            if mta_sts_policy.verify(hostname) {
                tx.send(DeliveryStage::MtaStsVerifySuccess).await?;
            } else {
                tx.send(DeliveryStage::MtaStsVerifyError {
                    reason: "Not authorized by policy".to_string(),
                })
                .await?;

                continue;
            }
        }

        // Fetch TLSA record
        tx.send(DeliveryStage::TlsaLookupStart).await?;

        let now = Instant::now();
        let dane_policy = match server.tlsa_lookup(format!("_25._tcp.{hostname}.")).await {
            Ok(TlsaResult::Secure(tlsa)) if tlsa.has_end_entities => {
                tx.send(DeliveryStage::TlsaLookupSuccess {
                    record: tlsa.as_ref().clone(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;

                Some(tlsa)
            }
            Ok(TlsaResult::Secure(_)) => {
                tx.send(DeliveryStage::TlsaLookupError {
                    elapsed: now.elapsed_ms(),
                    reason: "TLSA record does not have end entities".to_string(),
                })
                .await?;

                None
            }
            Ok(TlsaResult::Bogus) => {
                tx.send(DeliveryStage::TlsaLookupError {
                    elapsed: now.elapsed_ms(),
                    reason: "Bogus TLSA record".to_string(),
                })
                .await?;

                None
            }
            Ok(TlsaResult::Missing) => {
                tx.send(DeliveryStage::TlsaNotFound {
                    elapsed: now.elapsed_ms(),
                    reason: "No TLSA DNSSEC records found".to_string(),
                })
                .await?;

                None
            }
            Err(err) => {
                if matches!(
                    &err,
                    mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(_))
                ) {
                    tx.send(DeliveryStage::TlsaNotFound {
                        elapsed: now.elapsed_ms(),
                        reason: "No TLSA records found for MX".to_string(),
                    })
                    .await?;
                } else {
                    tx.send(DeliveryStage::TlsaLookupError {
                        elapsed: now.elapsed_ms(),
                        reason: err.to_string(),
                    })
                    .await?;
                }
                None
            }
        };

        tx.send(DeliveryStage::IpLookupStart).await?;

        let now = Instant::now();
        let remote_ips = match host.fqdn_hostname() {
            HostOrIp::Host(hostname) => {
                match server
                    .ip_lookup(&hostname, IpLookupStrategy::Ipv4thenIpv6, usize::MAX)
                    .await
                {
                    Ok(remote_ips) if !remote_ips.is_empty() => remote_ips,
                    Ok(_) => {
                        tx.send(DeliveryStage::IpLookupError {
                            reason: "No IP addresses found for host".to_string(),
                            elapsed: now.elapsed_ms(),
                        })
                        .await?;
                        continue;
                    }
                    Err(err) => {
                        tx.send(DeliveryStage::IpLookupError {
                            reason: err.to_string(),
                            elapsed: now.elapsed_ms(),
                        })
                        .await?;
                        continue;
                    }
                }
            }
            HostOrIp::Ip(ip) => vec![ip],
        };

        tx.send(DeliveryStage::IpLookupSuccess {
            remote_ips: remote_ips.clone(),
            elapsed: now.elapsed_ms(),
        })
        .await?;

        for remote_ip in remote_ips {
            // Start connection
            tx.send(DeliveryStage::ConnectionStart { remote_ip })
                .await?;

            let now = Instant::now();
            let connect = if let Some(ip_host) = conn_strategy.source_ip(remote_ip.is_ipv4()) {
                SmtpClient::connect_using(ip_host.ip, SocketAddr::new(remote_ip, 25), timeout, 0)
                    .await
            } else {
                SmtpClient::connect(SocketAddr::new(remote_ip, 25), timeout, 0).await
            };
            match connect {
                Ok(mut client) => {
                    tx.send(DeliveryStage::ConnectionSuccess {
                        elapsed: now.elapsed_ms(),
                    })
                    .await?;

                    // Read greeting
                    tx.send(DeliveryStage::ReadGreetingStart).await?;

                    let now = Instant::now();
                    if let Err(status) = client.read_greeting(hostname).await {
                        tx.send(DeliveryStage::ReadGreetingError {
                            elapsed: now.elapsed_ms(),
                            reason: status.to_string(),
                        })
                        .await?;

                        continue;
                    }
                    tx.send(DeliveryStage::ReadGreetingSuccess {
                        elapsed: now.elapsed_ms(),
                    })
                    .await?;

                    // Say EHLO
                    tx.send(DeliveryStage::EhloStart).await?;

                    let now = Instant::now();
                    let capabilities = match tokio::time::timeout(timeout, async {
                        client
                            .stream
                            .write_all(format!("EHLO {local_host}\r\n",).as_bytes())
                            .await?;
                        client.stream.flush().await?;
                        client.read_ehlo().await
                    })
                    .await
                    {
                        Ok(Ok(capabilities)) => {
                            tx.send(DeliveryStage::EhloSuccess {
                                elapsed: now.elapsed_ms(),
                            })
                            .await?;

                            capabilities
                        }
                        Ok(Err(err)) => {
                            tx.send(DeliveryStage::EhloError {
                                elapsed: now.elapsed_ms(),
                                reason: err.to_string(),
                            })
                            .await?;

                            continue;
                        }
                        Err(_) => {
                            tx.send(DeliveryStage::EhloError {
                                elapsed: now.elapsed_ms(),
                                reason: "Timed out reading response".to_string(),
                            })
                            .await?;

                            continue;
                        }
                    };

                    // Start TLS
                    tx.send(DeliveryStage::StartTlsStart).await?;

                    let now = Instant::now();
                    let mut client = match client
                        .try_start_tls(
                            &server.inner.data.smtp_connectors.pki_verify,
                            hostname,
                            &capabilities,
                        )
                        .await
                    {
                        StartTlsResult::Success { smtp_client } => {
                            tx.send(DeliveryStage::StartTlsSuccess {
                                elapsed: now.elapsed_ms(),
                            })
                            .await?;

                            smtp_client
                        }
                        StartTlsResult::Error { error } => {
                            tx.send(DeliveryStage::StartTlsError {
                                elapsed: now.elapsed_ms(),
                                reason: error.to_string(),
                            })
                            .await?;

                            continue;
                        }
                        StartTlsResult::Unavailable { response, .. } => {
                            tx.send(DeliveryStage::StartTlsError {
                                elapsed: now.elapsed_ms(),
                                reason: response.map(|r| r.to_string()).unwrap_or_else(|| {
                                    "STARTTLS not advertised by host".to_string()
                                }),
                            })
                            .await?;

                            continue;
                        }
                    };

                    // Verify DANE policy
                    if let Some(dane_policy) = &dane_policy {
                        if let Err(err) = dane_policy.verify(
                            0,
                            hostname,
                            &[hostname],
                            client.tls_connection().peer_certificates(),
                        ) {
                            tx.send(DeliveryStage::DaneVerifyError {
                                reason: err.to_string(),
                            })
                            .await?;
                        } else {
                            tx.send(DeliveryStage::DaneVerifySuccess).await?;
                        }
                    }

                    // Say EHLO again (some SMTP servers require this)
                    tx.send(DeliveryStage::EhloStart).await?;

                    let now = Instant::now();
                    match tokio::time::timeout(timeout, async {
                        client
                            .stream
                            .write_all(format!("EHLO {local_host}\r\n",).as_bytes())
                            .await?;
                        client.stream.flush().await?;
                        client.read_ehlo().await
                    })
                    .await
                    {
                        Ok(Ok(_)) => {
                            tx.send(DeliveryStage::EhloSuccess {
                                elapsed: now.elapsed_ms(),
                            })
                            .await?;
                        }
                        Ok(Err(err)) => {
                            tx.send(DeliveryStage::EhloError {
                                elapsed: now.elapsed_ms(),
                                reason: err.to_string(),
                            })
                            .await?;

                            continue;
                        }
                        Err(_) => {
                            tx.send(DeliveryStage::EhloError {
                                elapsed: now.elapsed_ms(),
                                reason: "Timed out reading response".to_string(),
                            })
                            .await?;

                            continue;
                        }
                    }

                    // Verify recipient
                    let mut is_success = email.is_none();
                    if let Some(email) = &email {
                        // MAIL FROM
                        tx.send(DeliveryStage::MailFromStart).await?;

                        let now = Instant::now();

                        match client.cmd(b"MAIL FROM:<>\r\n").await.and_then(|r| {
                            if r.is_positive_completion() {
                                Ok(r)
                            } else {
                                Err(ClientError::UnexpectedReply(Box::new(r)))
                            }
                        }) {
                            Ok(_) => {
                                tx.send(DeliveryStage::MailFromSuccess {
                                    elapsed: now.elapsed_ms(),
                                })
                                .await?;

                                // RCPT TO
                                tx.send(DeliveryStage::RcptToStart).await?;

                                let now = Instant::now();
                                match client
                                    .cmd(format!("RCPT TO:<{email}>\r\n").as_bytes())
                                    .await
                                    .and_then(|r| {
                                        if r.is_positive_completion() {
                                            Ok(r)
                                        } else {
                                            Err(ClientError::UnexpectedReply(Box::new(r)))
                                        }
                                    }) {
                                    Ok(_) => {
                                        is_success = true;
                                        tx.send(DeliveryStage::RcptToSuccess {
                                            elapsed: now.elapsed_ms(),
                                        })
                                        .await?;
                                    }
                                    Err(err) => {
                                        tx.send(DeliveryStage::RcptToError {
                                            reason: err.to_string(),
                                            elapsed: now.elapsed_ms(),
                                        })
                                        .await?;
                                    }
                                }
                            }
                            Err(err) => {
                                tx.send(DeliveryStage::MailFromError {
                                    reason: err.to_string(),
                                    elapsed: now.elapsed_ms(),
                                })
                                .await?;
                            }
                        }
                    }

                    // QUIT
                    tx.send(DeliveryStage::QuitStart).await?;

                    let now = Instant::now();
                    client.quit().await;
                    tx.send(DeliveryStage::QuitCompleted {
                        elapsed: now.elapsed_ms(),
                    })
                    .await?;

                    if is_success {
                        break 'outer;
                    }
                }
                Err(err) => {
                    tx.send(DeliveryStage::ConnectionError {
                        elapsed: now.elapsed_ms(),
                        reason: err.to_string(),
                    })
                    .await?;
                }
            }
        }
    }

    Ok(())
}
