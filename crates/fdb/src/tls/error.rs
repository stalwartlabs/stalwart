/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt, io, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Material {
    Certificate,
    Key,
    Ca,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsError {
    Read {
        material: Material,
        path: Box<Path>,
        kind: io::ErrorKind,
    },
    TooLarge {
        material: Material,
        path: Box<Path>,
    },
    Pem {
        material: Material,
    },
    NoCertificate {
        material: Material,
    },
    InvalidCa,
    Unpaired {
        missing: Material,
    },
    KeyPassword,
    Key,
    VerifyPeers {
        rule: Box<str>,
    },
    Config(rustls::Error),
}

impl fmt::Display for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Certificate => "certificate",
            Self::Key => "key",
            Self::Ca => "CA",
        })
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read {
                material,
                path,
                kind,
            } => write!(
                f,
                "cannot read TLS {material} file {}: {kind}",
                path.display()
            ),
            Self::TooLarge { material, path } => {
                write!(f, "TLS {material} file {} is too large", path.display())
            }
            Self::Pem { material } => write!(f, "invalid PEM in TLS {material}"),
            Self::NoCertificate { material } => {
                write!(f, "no certificate found in TLS {material}")
            }
            Self::InvalidCa => f.write_str("TLS CA certificate cannot be used as a trust anchor"),
            Self::Unpaired { missing } => write!(
                f,
                "TLS {missing} missing while its certificate or key counterpart is configured"
            ),
            Self::KeyPassword => f.write_str("TLS key password contains a NUL byte"),
            Self::Key => {
                f.write_str("no usable TLS private key (missing, unsupported or wrong password)")
            }
            Self::VerifyPeers { rule } => write!(f, "invalid TLS verify peers rule {rule:?}"),
            Self::Config(err) => write!(f, "invalid TLS configuration: {err}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<rustls::Error> for TlsError {
    fn from(err: rustls::Error) -> Self {
        Self::Config(err)
    }
}
