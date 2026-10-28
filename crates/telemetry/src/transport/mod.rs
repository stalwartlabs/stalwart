/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod conn;
pub mod endpoint;
pub mod response;
pub mod retry;
pub mod sender;

use std::fmt::Display;

#[derive(Debug)]
pub enum TransportError {
    InvalidEndpoint(Box<str>),
    InvalidHeader(Box<str>),
    Connect(std::io::Error),
    Tls(std::io::Error),
    Handshake(hyper::Error),
    Request(hyper::Error),
    ResponseTooLarge,
}

impl TransportError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            TransportError::Connect(_)
                | TransportError::Tls(_)
                | TransportError::Handshake(_)
                | TransportError::Request(_)
        )
    }
}

impl Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::InvalidEndpoint(err) => write!(f, "Invalid endpoint: {err}"),
            TransportError::InvalidHeader(err) => write!(f, "Invalid header: {err}"),
            TransportError::Connect(err) => write!(f, "Connection failed: {err}"),
            TransportError::Tls(err) => write!(f, "TLS handshake failed: {err}"),
            TransportError::Handshake(err) => write!(f, "HTTP handshake failed: {err}"),
            TransportError::Request(err) => write!(f, "Request failed: {err}"),
            TransportError::ResponseTooLarge => f.write_str("Response exceeds the size limit"),
        }
    }
}
