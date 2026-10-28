/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::TransportError;
use http::{HeaderValue, Uri, uri::Scheme};

const HTTP_DEFAULT_PORT: u16 = 80;
const HTTPS_DEFAULT_PORT: u16 = 443;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Http,
    Grpc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Traces,
    Logs,
    Metrics,
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    tls: bool,
    host: Box<str>,
    port: u16,
    authority: Box<str>,
    base_path: Box<str>,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub origin_form: Uri,
    pub absolute_form: Uri,
    pub host: HeaderValue,
}

impl Signal {
    const ALL: [Signal; 3] = [Signal::Traces, Signal::Logs, Signal::Metrics];

    fn http_path(self) -> &'static str {
        match self {
            Signal::Traces => "/v1/traces",
            Signal::Logs => "/v1/logs",
            Signal::Metrics => "/v1/metrics",
        }
    }

    fn grpc_path(self) -> &'static str {
        match self {
            Signal::Traces => "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
            Signal::Logs => "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
            Signal::Metrics => "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
        }
    }
}

impl Endpoint {
    pub fn parse(url: &str) -> Result<Self, TransportError> {
        let uri = url
            .parse::<Uri>()
            .map_err(|err| TransportError::InvalidEndpoint(format!("{url}: {err}").into()))?;
        let tls = match uri.scheme() {
            Some(scheme) if *scheme == Scheme::HTTPS => true,
            Some(scheme) if *scheme == Scheme::HTTP => false,
            _ => {
                return Err(TransportError::InvalidEndpoint(
                    format!("{url}: scheme must be http or https").into(),
                ));
            }
        };
        let authority = uri.authority().ok_or_else(|| {
            TransportError::InvalidEndpoint(format!("{url}: missing host").into())
        })?;
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = authority.port_u16().unwrap_or(if tls {
            HTTPS_DEFAULT_PORT
        } else {
            HTTP_DEFAULT_PORT
        });
        Ok(Self {
            tls,
            host: host.into(),
            port,
            authority: authority
                .as_str()
                .rsplit_once('@')
                .map_or(authority.as_str(), |(_, host_port)| host_port)
                .into(),
            base_path: base_path(uri.path()).into(),
        })
    }

    pub fn is_tls(&self) -> bool {
        self.tls
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn target(&self, transport: Transport, signal: Signal) -> Result<Target, TransportError> {
        let path = match transport {
            Transport::Http => format!("{}{}", self.base_path, signal.http_path()),
            Transport::Grpc => signal.grpc_path().to_string(),
        };
        let scheme = if self.tls { "https" } else { "http" };
        let invalid = |err: &dyn std::fmt::Display| {
            TransportError::InvalidEndpoint(format!("{}: {err}", self.authority).into())
        };
        Ok(Target {
            origin_form: path.parse().map_err(|err| invalid(&err))?,
            absolute_form: format!("{scheme}://{}{path}", self.authority)
                .parse()
                .map_err(|err| invalid(&err))?,
            host: HeaderValue::from_str(&self.authority).map_err(|err| invalid(&err))?,
        })
    }
}

fn base_path(path: &str) -> &str {
    let path = path.trim_end_matches('/');
    Signal::ALL
        .into_iter()
        .find_map(|signal| path.strip_suffix(signal.http_path()))
        .unwrap_or(path)
}
