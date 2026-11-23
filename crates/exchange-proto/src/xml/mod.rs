/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod tokenizer;
pub mod value;
pub mod writer;

pub use tokenizer::{Attr, Attrs, Token, Tokenizer, line_column};
pub use value::XmlValue;
pub use writer::{Base64Sink, XmlWrite, XmlWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ns {
    Soap11,
    Soap12,
    Messages,
    Types,
    Errors,
    Xsi,
    AdRequestOutlook,
    AdResponseOutlook,
    AdResponseOuter,
    AdRequestMobile,
    AdResponseMobile,
    AdSoap,
    WsAddressing,
    None,
    Other,
}

impl Ns {
    pub fn from_uri(uri: &[u8]) -> Self {
        hashify::map!(
            uri,
            Ns,
            "http://schemas.xmlsoap.org/soap/envelope/" => Ns::Soap11,
            "http://www.w3.org/2003/05/soap-envelope" => Ns::Soap12,
            "http://schemas.microsoft.com/exchange/services/2006/messages" => Ns::Messages,
            "http://schemas.microsoft.com/exchange/services/2006/types" => Ns::Types,
            "http://schemas.microsoft.com/exchange/services/2006/errors" => Ns::Errors,
            "http://www.w3.org/2001/XMLSchema-instance" => Ns::Xsi,
            "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006" => Ns::AdRequestOutlook,
            "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a" => Ns::AdResponseOutlook,
            "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006" => Ns::AdResponseOuter,
            "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006" => Ns::AdRequestMobile,
            "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006" => Ns::AdResponseMobile,
            "http://schemas.microsoft.com/exchange/2010/Autodiscover" => Ns::AdSoap,
            "http://www.w3.org/2005/08/addressing" => Ns::WsAddressing,
            "" => Ns::None,
        )
        .copied()
        .unwrap_or(Ns::Other)
    }

    pub const fn uri(self) -> &'static str {
        match self {
            Ns::Soap11 => "http://schemas.xmlsoap.org/soap/envelope/",
            Ns::Soap12 => "http://www.w3.org/2003/05/soap-envelope",
            Ns::Messages => "http://schemas.microsoft.com/exchange/services/2006/messages",
            Ns::Types => "http://schemas.microsoft.com/exchange/services/2006/types",
            Ns::Errors => "http://schemas.microsoft.com/exchange/services/2006/errors",
            Ns::Xsi => "http://www.w3.org/2001/XMLSchema-instance",
            Ns::AdRequestOutlook => {
                "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"
            }
            Ns::AdResponseOutlook => {
                "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
            }
            Ns::AdResponseOuter => {
                "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006"
            }
            Ns::AdRequestMobile => {
                "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006"
            }
            Ns::AdResponseMobile => {
                "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006"
            }
            Ns::AdSoap => "http://schemas.microsoft.com/exchange/2010/Autodiscover",
            Ns::WsAddressing => "http://www.w3.org/2005/08/addressing",
            Ns::None | Ns::Other => "",
        }
    }
}

pub trait XmlName: Copy + Sized {
    fn parse(ns: Ns, local: &[u8]) -> Option<Self>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    pub max_depth: u8,
    pub max_ns_bindings: u8,
}

impl XmlLimits {
    pub const DEFAULT: Self = XmlLimits {
        max_depth: 64,
        max_ns_bindings: 32,
    };
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlErrorKind {
    Syntax,
    Utf8,
    InvalidChar,
    DocType,
    UnsupportedEncoding,
    UnknownEntity,
    UnboundPrefix,
    TooDeep,
    TooManyNamespaces,
    UnexpectedEof,
    UnexpectedElement,
    InvalidAttribute,
    InvalidValue,
    MissingValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlError {
    pub kind: XmlErrorKind,
    pub offset: u32,
}

const _: () = assert!(std::mem::size_of::<XmlError>() <= 8);

impl XmlError {
    pub const fn new(kind: XmlErrorKind, offset: u32) -> Self {
        XmlError { kind, offset }
    }
}

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}

impl std::error::Error for XmlError {}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/xml/tests.rs"]
mod tests;
