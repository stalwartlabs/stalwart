/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt, marker::PhantomData};

use serde::{
    Deserializer,
    de::{self, MapAccess, Visitor},
};

pub trait DeserializeArguments<'de> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>;
}

impl<'de> DeserializeArguments<'de> for () {
    fn deserialize_argument<A>(&mut self, _key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let _: de::IgnoredAny = map.next_value()?;
        Ok(())
    }
}

pub(crate) fn deserialize_request<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeArguments<'de> + Default,
    D: Deserializer<'de>,
{
    struct DirectArgumentsVisitor<T> {
        _phantom: PhantomData<T>,
    }

    impl<T> DirectArgumentsVisitor<T> {
        fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
    }

    impl<'de, T> Visitor<'de> for DirectArgumentsVisitor<T>
    where
        T: DeserializeArguments<'de> + Default,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a JMAP request object")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut target = T::default();

            while let Some(key) = map.next_key::<&str>()? {
                target
                    .deserialize_argument(key, &mut map)
                    .map_err(de::Error::custom)?;
            }

            Ok(target)
        }
    }

    deserializer.deserialize_map(DirectArgumentsVisitor::<T>::new())
}
