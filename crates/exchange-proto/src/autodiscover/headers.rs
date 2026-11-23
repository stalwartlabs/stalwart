/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::num::NonZeroU32;

const OFFICE_PRODUCT: &[u8] = b"Microsoft Office/";
const MAPI_HTTP_MIN_OFFICE_MAJOR: u32 = 16;
const MAX_DECIMAL_DIGITS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapiHttpCapability(pub NonZeroU32);

impl MapiHttpCapability {
    pub fn parse(value: Option<&[u8]>) -> Option<Self> {
        parse_decimal(value?.trim_ascii())
            .and_then(NonZeroU32::new)
            .map(MapiHttpCapability)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientCanHandle {
    pub negotiate: bool,
    pub ex_http_info: bool,
}

impl ClientCanHandle {
    pub fn parse(value: Option<&[u8]>) -> Self {
        let mut result = ClientCanHandle::default();
        for item in value.unwrap_or_default().split(|&ch| ch == b',') {
            hashify::fnc_map_ignore_case!(item.trim_ascii(),
                "Negotiate" => { result.negotiate = true; },
                "ExHttpInfo" => { result.ex_http_info = true; },
                _ => {}
            );
        }
        result
    }
}

pub fn user_agent_is_mapi_http_outlook(ua: &[u8]) -> bool {
    memchr::memmem::find(ua, OFFICE_PRODUCT)
        .and_then(|pos| ua.get(pos + OFFICE_PRODUCT.len()..))
        .and_then(|version| {
            let digits = version.iter().take_while(|ch| ch.is_ascii_digit()).count();
            version.get(..digits)
        })
        .and_then(parse_decimal)
        .is_some_and(|major| major >= MAPI_HTTP_MIN_OFFICE_MAJOR)
}

fn parse_decimal(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > MAX_DECIMAL_DIGITS {
        return None;
    }
    digits.iter().try_fold(0u32, |acc, &ch| {
        if ch.is_ascii_digit() {
            acc.checked_mul(10)?.checked_add(u32::from(ch - b'0'))
        } else {
            None
        }
    })
}
