/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use smtp_proto::{Response, Severity};

#[derive(Debug)]
pub enum ClientError {
    /// I/O error
    Io(std::io::Error),

    /// TLS error
    Tls(Box<rustls::Error>),

    /// Base64 decode error
    Base64(base64::DecodeError),

    // SMTP authentication error.
    InvalidChallenge,

    /// Failure parsing SMTP reply
    UnparseableReply,

    /// Unexpected SMTP reply.
    UnexpectedReply(Box<smtp_proto::Response<String>>),

    /// SMTP authentication failure.
    AuthenticationFailed(Box<smtp_proto::Response<String>>),

    /// Invalid TLS name provided.
    InvalidTLSName,

    /// Missing authentication credentials.
    MissingCredentials,

    /// Missing message sender.
    MissingMailFrom,

    /// Missing message recipients.
    MissingRcptTo,

    /// The server does no support any of the available authentication methods.
    UnsupportedAuthMechanism,

    /// Connection timeout.
    Timeout,

    /// STARTTLS not available
    MissingStartTls,
}

pub trait AssertReply: Sized {
    fn is_positive_completion(&self) -> bool;
    fn assert_positive_completion(self) -> ClientResult<()>;
    fn assert_severity(self, severity: Severity) -> ClientResult<()>;
    fn assert_code(self, code: u16) -> ClientResult<()>;
}

impl AssertReply for Response<String> {
    /// Returns `true` if the reply is a positive completion.
    #[inline(always)]
    fn is_positive_completion(&self) -> bool {
        (200..=299).contains(&self.code)
    }

    /// Returns Ok if the reply has the specified severity.
    #[inline(always)]
    fn assert_severity(self, severity: Severity) -> ClientResult<()> {
        if self.severity() == severity {
            Ok(())
        } else {
            Err(ClientError::UnexpectedReply(Box::new(self)))
        }
    }

    /// Returns Ok if the reply returned a 2xx code.
    #[inline(always)]
    fn assert_positive_completion(self) -> ClientResult<()> {
        if (200..=299).contains(&self.code) {
            Ok(())
        } else {
            Err(ClientError::UnexpectedReply(Box::new(self)))
        }
    }

    /// Returns Ok if the reply has the specified status code.
    #[inline(always)]
    fn assert_code(self, code: u16) -> ClientResult<()> {
        if self.code() == code {
            Ok(())
        } else {
            Err(ClientError::UnexpectedReply(Box::new(self)))
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Io(err) => err.source(),
            ClientError::Tls(err) => err.source(),
            ClientError::Base64(err) => err.source(),
            _ => None,
        }
    }
}

pub type ClientResult<T> = std::result::Result<T, ClientError>;

impl Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "I/O error: {e}"),
            ClientError::Tls(e) => write!(f, "TLS error: {e}"),
            ClientError::Base64(e) => write!(f, "Base64 decode error: {e}"),
            ClientError::InvalidChallenge => {
                write!(f, "SMTP authentication error: Invalid challenge")
            }
            ClientError::UnparseableReply => write!(f, "Unparseable SMTP reply"),
            ClientError::UnexpectedReply(e) => write!(f, "Unexpected reply: {e}"),
            ClientError::AuthenticationFailed(e) => write!(f, "Authentication failed: {e}"),
            ClientError::InvalidTLSName => write!(f, "Invalid TLS name provided"),
            ClientError::MissingCredentials => write!(f, "Missing authentication credentials"),
            ClientError::MissingMailFrom => write!(f, "Missing message sender"),
            ClientError::MissingRcptTo => write!(f, "Missing message recipients"),
            ClientError::UnsupportedAuthMechanism => write!(
                f,
                "The server does no support any of the available authentication methods"
            ),
            ClientError::Timeout => write!(f, "Connection timeout"),
            ClientError::MissingStartTls => write!(f, "STARTTLS extension unavailable"),
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        ClientError::Io(err)
    }
}

impl From<base64::DecodeError> for ClientError {
    fn from(err: base64::DecodeError) -> Self {
        ClientError::Base64(err)
    }
}
