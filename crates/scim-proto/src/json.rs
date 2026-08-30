/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{borrow::Cow, fmt};

use serde::de::{Deserialize, Deserializer, Error, Visitor};

pub(crate) struct Str<'a>(pub Cow<'a, str>);

impl<'de: 'a, 'a> Deserialize<'de> for Str<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrVisitor;

        impl<'de> Visitor<'de> for StrVisitor {
            type Value = Str<'de>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(Str(Cow::Borrowed(v)))
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Str(Cow::Owned(v.to_string())))
            }

            fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(Str(Cow::Owned(v)))
            }
        }

        deserializer.deserialize_str(StrVisitor).map(|v| Str(v.0))
    }
}

pub(crate) fn duplicate_attribute(name: &str) -> String {
    format!("Duplicate attribute '{name}'")
}

pub(crate) fn missing_schemas(urn: &str) -> String {
    format!("Missing 'schemas' attribute, expected '{urn}'")
}

pub(crate) fn unknown_attribute(name: &str) -> String {
    if name.contains(':') {
        format!("Unsupported schema URI '{name}'")
    } else {
        format!("Unknown attribute '{name}'")
    }
}

macro_rules! scim_value {
    (str, $lt:lifetime, $map:ident) => {
        $map.next_value::<Option<$crate::json::Str<$lt>>>()?
            .map(|v| v.0)
    };
    (input, $lt:lifetime, $map:ident) => {
        $map.next_value::<Option<$crate::json::Str<$lt>>>()?
            .map(|v| v.0)
    };
    (strs, $lt:lifetime, $map:ident) => {
        $map.next_value::<Option<Vec<$crate::json::Str<$lt>>>>()?
            .map(|v| v.into_iter().map(|v| v.0).collect())
    };
    (any, $lt:lifetime, $map:ident) => {
        $map.next_value()?
    };
}

macro_rules! scim_serialize_field {
    (input, $map:ident, $key:literal, $value:expr) => {};
    ($kind:tt, $map:ident, $key:literal, $value:expr) => {
        if let Some(value) = $value {
            $map.serialize_entry($key, value)?;
        }
    };
}

macro_rules! scim_object {
    ($vis:vis $name:ident<$lt:lifetime>, $urn:expr, { $($key:literal => $kind:tt $field:ident : $ty:ty),* $(,)? }) => {
        $crate::json::scim_object!($vis $name<$lt>, $urn, &[], &[], { $($key => $kind $field: $ty),* });
    };
    ($vis:vis $name:ident<$lt:lifetime>, $urn:expr, $tolerated:expr, $tolerated_schemas:expr, { $($key:literal => $kind:tt $field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, Default, PartialEq)]
        $vis struct $name<$lt> {
            $(pub $field: $ty,)*
        }

        impl<$lt> serde::Serialize for $name<$lt> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeMap;

                let mut map = serializer.serialize_map(None)?;
                if let Some(urn) = $urn {
                    map.serialize_entry("schemas", &[urn])?;
                }
                $($crate::json::scim_serialize_field!($kind, map, $key, self.$field.as_ref());)*
                map.end()
            }
        }

        impl<'de: $lt, $lt> serde::Deserialize<'de> for $name<$lt> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __schemas,
                    $($field,)*
                }

                struct __Visitor<$lt>(std::marker::PhantomData<&$lt ()>);

                impl<'de: $lt, $lt> serde::de::Visitor<'de> for __Visitor<$lt> {
                    type Value = $name<$lt>;

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str(stringify!($name))
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: serde::de::MapAccess<'de>,
                    {
                        let mut result = $name::default();
                        let mut has_schemas = false;

                        while let Some(key) = map.next_key::<$crate::json::Str<$lt>>()? {
                            let field = hashify::tiny_map_ignore_case!(key.0.as_bytes(),
                                "schemas" => __Field::__schemas,
                                $($key => __Field::$field,)*
                            );

                            match field {
                                Some(__Field::__schemas) => {
                                    let expected: Option<&'static str> = $urn;
                                    match expected {
                                        Some(expected) => {
                                            let tolerated: &[&str] = $tolerated_schemas;
                                            for value in map
                                                .next_value::<Vec<$crate::json::Str<$lt>>>()?
                                            {
                                                if value.0.eq_ignore_ascii_case(expected) {
                                                    has_schemas = true;
                                                } else if !tolerated.iter().any(|urn| {
                                                    value.0.eq_ignore_ascii_case(urn)
                                                }) {
                                                    return Err(serde::de::Error::custom(
                                                        $crate::json::unknown_attribute(&value.0),
                                                    ));
                                                }
                                            }
                                        }
                                        None => {
                                            return Err(serde::de::Error::custom(
                                                $crate::json::unknown_attribute(&key.0),
                                            ));
                                        }
                                    }
                                }
                                $(Some(__Field::$field) => {
                                    if result.$field.is_some() {
                                        return Err(serde::de::Error::custom(
                                            $crate::json::duplicate_attribute($key),
                                        ));
                                    }

                                    result.$field = $crate::json::scim_value!($kind, $lt, map);
                                })*
                                None => {
                                    let tolerated: &[&str] = $tolerated;
                                    if tolerated
                                        .iter()
                                        .any(|name| key.0.eq_ignore_ascii_case(name))
                                    {
                                        map.next_value::<serde::de::IgnoredAny>()?;
                                    } else {
                                        return Err(serde::de::Error::custom(
                                            $crate::json::unknown_attribute(&key.0),
                                        ));
                                    }
                                }
                            }
                        }

                        match $urn {
                            Some(urn) if !has_schemas => {
                                Err(serde::de::Error::custom($crate::json::missing_schemas(urn)))
                            }
                            _ => Ok(result),
                        }
                    }
                }

                deserializer.deserialize_map(__Visitor(std::marker::PhantomData))
            }
        }
    };
}

pub(crate) use {scim_object, scim_serialize_field, scim_value};
