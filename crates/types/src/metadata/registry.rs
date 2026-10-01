/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::MetadataScope;
use crate::type_state::DataType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceScope {
    Metadata,
    PrivateMetadata,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceUsage {
    Common,
    Reserved,
    Obsolete,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct RegisteredNamespace {
    pub id: u16,
    pub name: &'static str,
    pub scope: NamespaceScope,
    pub data_types: &'static [DataType],
    pub usage: NamespaceUsage,
}

macro_rules! registered_namespaces {
    ($($id:literal => $name:literal {
        scope: $scope:ident,
        data_types: [$($data_type:ident),* $(,)?],
        usage: $usage:ident $(,)?
    }),* $(,)?) => {
        pub const REGISTERED_NAMESPACES: &[RegisteredNamespace] = &[$(
            RegisteredNamespace {
                id: $id,
                name: $name,
                scope: NamespaceScope::$scope,
                data_types: &[$(DataType::$data_type),*],
                usage: NamespaceUsage::$usage,
            },
        )*];

        impl RegisteredNamespace {
            pub fn by_name(name: &str) -> Option<&'static RegisteredNamespace> {
                let id: Option<&'static u16> = hashify::map!(name.as_bytes(), u16, $($name => $id,)*);
                id.and_then(|id| RegisteredNamespace::by_id(*id))
            }
        }
    };
}

registered_namespaces!();

impl RegisteredNamespace {
    pub fn by_id(id: u16) -> Option<&'static RegisteredNamespace> {
        REGISTERED_NAMESPACES
            .binary_search_by_key(&id, |namespace| namespace.id)
            .ok()
            .and_then(|position| REGISTERED_NAMESPACES.get(position))
    }

    pub fn is_advertised(&self) -> bool {
        self.usage == NamespaceUsage::Common
    }

    pub fn is_writable(&self) -> bool {
        self.usage == NamespaceUsage::Common
    }

    pub fn supports(&self, data_type: DataType, scope: MetadataScope) -> bool {
        self.data_types.contains(&data_type)
            && matches!(
                (self.scope, scope),
                (NamespaceScope::Both, _)
                    | (NamespaceScope::Metadata, MetadataScope::Shared)
                    | (NamespaceScope::PrivateMetadata, MetadataScope::Private)
            )
    }
}

macro_rules! known_xml_namespaces {
    ($($id:literal => $uri:literal),* $(,)?) => {
        const KNOWN_XML_NAMESPACES: &[&str] = &[$($uri),*];

        pub(crate) fn known_xml_namespace_id(uri: &str) -> Option<u8> {
            hashify::map!(uri.as_bytes(), u8, $($uri => $id,)*).copied()
        }
    };
}

known_xml_namespaces!(
    1 => "DAV:",
    2 => "urn:ietf:params:xml:ns:caldav",
    3 => "urn:ietf:params:xml:ns:carddav",
    4 => "http://calendarserver.org/ns/",
    5 => "http://calendarserver.org/ns",
    6 => "http://apple.com/ns/ical/",
    7 => "http://www.apple.com/webdav_fs/props/",
    8 => "http://me.com/_namespace/",
    9 => "urn:schemas-microsoft-com:",
    10 => "http://owncloud.org/ns",
    11 => "http://nextcloud.org/ns",
    12 => "http://sabredav.org/ns",
    13 => "http://www.w3.org/XML/1998/namespace",
    14 => "http://www.w3.org/1999/xhtml",
);

pub(crate) const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
pub(crate) const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

pub(crate) fn known_xml_namespace(id: u8) -> Option<&'static str> {
    KNOWN_XML_NAMESPACES
        .get(usize::from(id).checked_sub(1)?)
        .copied()
}

#[cfg(test)]
pub(crate) fn known_xml_namespace_count() -> usize {
    KNOWN_XML_NAMESPACES.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace<'x> {
    Registered(&'static RegisteredNamespace),
    Vendor(&'x str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamespaceError {
    Invalid,
    Unregistered,
}

const MAX_REGISTERED_NAME: usize = 64;
const MAX_DOMAIN_NAME: usize = 253;
const MAX_DOMAIN_LABEL: usize = 63;

impl<'x> Namespace<'x> {
    pub fn parse(name: &'x str) -> Result<Self, NamespaceError> {
        if name.as_bytes().contains(&b'.') {
            if is_vendor_name(name) {
                Ok(Namespace::Vendor(name))
            } else {
                Err(NamespaceError::Invalid)
            }
        } else if is_registered_name(name) {
            RegisteredNamespace::by_name(name)
                .map(Namespace::Registered)
                .ok_or(NamespaceError::Unregistered)
        } else {
            Err(NamespaceError::Invalid)
        }
    }

    pub fn name(&self) -> &'x str {
        match self {
            Namespace::Registered(namespace) => namespace.name,
            Namespace::Vendor(name) => name,
        }
    }
}

fn is_registered_name(name: &str) -> bool {
    (1..=MAX_REGISTERED_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn is_vendor_name(name: &str) -> bool {
    name.len() <= MAX_DOMAIN_NAME
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            (1..=MAX_DOMAIN_LABEL).contains(&bytes.len())
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
                && bytes.first() != Some(&b'-')
                && bytes.last() != Some(&b'-')
        })
}
