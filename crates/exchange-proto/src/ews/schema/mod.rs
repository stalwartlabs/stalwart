/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

macro_rules! name_enum {
    ($name:ident { $($variant:ident = $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn parse(value: &[u8]) -> Option<Self> {
                hashify::map!(value, $name, $($text => $name::$variant),+).copied()
            }

            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text),+
                }
            }
        }

        impl<'x> $crate::ews::types::value::EwsValue<'x> for $name {
            fn parse(
                p: &mut $crate::ews::parser::Parser<'x>,
                _: &$crate::xml::Attrs<'x>,
            ) -> $crate::ews::parser::Result<Self> {
                p.text_enum(stringify!($name), $name::parse)
            }

            fn write(&self, w: &mut $crate::xml::XmlWriter<'_>, local: &str) {
                w.leaf($crate::ews::types::value::T, local, self.as_str());
            }
        }

        impl $crate::ews::schema::NameEnum for $name {
            fn parse_name(value: &[u8]) -> Option<Self> {
                Self::parse(value)
            }

            fn name(self) -> &'static str {
                self.as_str()
            }
        }
    };
    ($name:ident : $data:ty { $($variant:ident = $text:literal => $value:expr),+ $(,)? }) => {
        name_enum!($name { $($variant = $text),+ });

        impl $name {
            pub const fn data(self) -> $data {
                match self {
                    $($name::$variant => $value),+
                }
            }
        }
    };
}

pub trait NameEnum: Copy + Sized {
    fn parse_name(value: &[u8]) -> Option<Self>;
    fn name(self) -> &'static str;
}

pub mod enums;
pub mod field_uri;
pub mod folder_name;
pub mod prop_set;
pub mod prop_type;
pub mod response_code;
pub mod version;

pub use enums::*;
pub use field_uri::{DictionaryField, ExceptionField, UnindexedField};
pub use folder_name::DistinguishedFolderName;
pub use prop_set::DistinguishedPropertySet;
pub use prop_type::MapiPropertyTypeName;
pub use response_code::ResponseCode;
pub use version::ExchangeVersion;
