/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod catalogue;

use catalogue::{BY_NAME, MEDIA_TYPES};
use std::borrow::Cow;

const MAX_RESTRICTED_NAME: usize = 127;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct MediaTypeId(u16);

impl MediaTypeId {
    pub const NONE: Self = Self(0);
    pub const UNCATALOGUED: Self = Self((1 << Self::BITS) - 1);
    pub const BITS: u32 = 12;

    #[inline(always)]
    pub fn from_raw(raw: u16) -> Self {
        Self(raw & Self::UNCATALOGUED.0)
    }

    #[inline(always)]
    pub fn raw(self) -> u16 {
        self.0
    }

    #[inline(always)]
    pub fn is_none(self) -> bool {
        self == Self::NONE
    }

    #[inline(always)]
    pub fn is_uncatalogued(self) -> bool {
        self == Self::UNCATALOGUED
    }

    pub fn lookup(essence: &str) -> Self {
        BY_NAME
            .binary_search_by(|&idx| {
                MEDIA_TYPES
                    .get(idx as usize)
                    .copied()
                    .unwrap_or_default()
                    .cmp(essence)
            })
            .ok()
            .and_then(|pos| BY_NAME.get(pos))
            .map_or(Self::UNCATALOGUED, |&idx| Self(idx + 1))
    }

    pub fn as_str(self) -> Option<&'static str> {
        self.0
            .checked_sub(1)
            .and_then(|idx| MEDIA_TYPES.get(idx as usize))
            .copied()
    }

    pub fn catalogue() -> impl Iterator<Item = (MediaTypeId, &'static str)> {
        MEDIA_TYPES
            .iter()
            .zip(1u16..)
            .map(|(name, id)| (MediaTypeId(id), *name))
    }
}

pub fn is_valid_media_type(value: &str) -> bool {
    value
        .split_once('/')
        .is_some_and(|(top, sub)| is_restricted_name(top) && is_restricted_name(sub))
}

pub fn media_type_essence(value: &str) -> Option<Cow<'_, str>> {
    let essence = value
        .split_once(';')
        .map_or(value, |(essence, _)| essence)
        .trim_matches(|c: char| c.is_ascii_whitespace());
    if !is_valid_media_type(essence) {
        None
    } else if essence.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(Cow::Owned(essence.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(essence))
    }
}

fn is_restricted_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b) if b.is_ascii_alphanumeric())
        && bytes.len() <= MAX_RESTRICTED_NAME
        && bytes.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_sorted_unique_and_fits() {
        assert!(MEDIA_TYPES.len() < MediaTypeId::UNCATALOGUED.raw() as usize);
        assert_eq!(BY_NAME.len(), MEDIA_TYPES.len());
        let sorted = BY_NAME
            .iter()
            .map(|&idx| MEDIA_TYPES[idx as usize])
            .collect::<Vec<_>>();
        assert!(sorted.windows(2).all(|w| w[0] < w[1]));
        assert!(MEDIA_TYPES.iter().all(|name| is_valid_media_type(name)));
    }

    #[test]
    fn lookup_round_trips() {
        for (id, name) in MediaTypeId::catalogue() {
            assert_eq!(MediaTypeId::lookup(name), id);
            assert_eq!(id.as_str(), Some(name));
        }
        assert_eq!(
            MediaTypeId::lookup("application/x-stalwart-unknown"),
            MediaTypeId::UNCATALOGUED
        );
        assert_eq!(MediaTypeId::NONE.as_str(), None);
        assert_eq!(MediaTypeId::UNCATALOGUED.as_str(), None);
        assert_eq!(
            MediaTypeId::lookup("application/1d-interleaved-parityfec").raw(),
            1
        );
        for common in [
            "text/plain",
            "application/pdf",
            "image/png",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/x-7z-compressed",
        ] {
            assert!(!MediaTypeId::lookup(common).is_uncatalogued(), "{common}");
        }
    }

    #[test]
    fn essence_normalisation() {
        assert_eq!(
            media_type_essence("Text/Plain; charset=utf-8").as_deref(),
            Some("text/plain")
        );
        assert!(matches!(
            media_type_essence("image/png"),
            Some(Cow::Borrowed("image/png"))
        ));
        assert_eq!(
            media_type_essence(" text/html ").as_deref(),
            Some("text/html")
        );
        for invalid in [
            "",
            "text",
            "text/",
            "/plain",
            "te xt/plain",
            "-a/b",
            "a/b/c",
        ] {
            assert_eq!(media_type_essence(invalid), None, "{invalid:?}");
        }
        assert!(is_valid_media_type("application/vnd.api+json"));
        assert!(!is_valid_media_type("text/plain; charset=utf-8"));
        assert!(!is_valid_media_type(&format!("a/{}", "b".repeat(128))));
    }
}
