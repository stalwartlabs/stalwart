/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::PromFormat;

const MAX_MEDIA_RANGES: usize = 32;
const MAX_PARAMETERS: usize = 8;
const MAX_QUALITY: u16 = 1000;

#[derive(Clone, Copy)]
enum MediaKind {
    OpenMetrics,
    Text,
    Any,
}

#[derive(Clone, Copy)]
enum Parameter {
    Version,
    Quality,
}

#[derive(Clone, Copy)]
enum Version {
    V001,
    V004,
    V100,
}

pub fn negotiate(accept: Option<&[u8]>) -> PromFormat {
    let mut best: Option<(u16, PromFormat)> = None;
    for range in accept
        .unwrap_or_default()
        .split(|byte| *byte == b',')
        .take(MAX_MEDIA_RANGES)
    {
        if let Some((quality, format)) = parse_range(range)
            && quality > 0
            && best.is_none_or(|(best_quality, _)| quality > best_quality)
        {
            best = Some((quality, format));
        }
    }
    best.map_or(PromFormat::Text004, |(_, format)| format)
}

fn parse_range(range: &[u8]) -> Option<(u16, PromFormat)> {
    let mut parts = range.split(|byte| *byte == b';');
    let kind = *hashify::map_ignore_case!(
        parts.next()?.trim_ascii(),
        MediaKind,
        "application/openmetrics-text" => MediaKind::OpenMetrics,
        "text/plain" => MediaKind::Text,
        "text/*" => MediaKind::Any,
        "*/*" => MediaKind::Any,
    )?;

    let mut version = None;
    let mut quality = MAX_QUALITY;
    for parameter in parts.take(MAX_PARAMETERS) {
        let mut pair = parameter.splitn(2, |byte| *byte == b'=');
        let name = pair.next().unwrap_or_default().trim_ascii();
        let value = pair.next().unwrap_or_default().trim_ascii();
        let value = value
            .strip_prefix(b"\"")
            .and_then(|value| value.strip_suffix(b"\""))
            .unwrap_or(value);
        match hashify::map_ignore_case!(
            name,
            Parameter,
            "version" => Parameter::Version,
            "q" => Parameter::Quality,
        ) {
            Some(Parameter::Version) => {
                version = Some(*hashify::map!(
                    value,
                    Version,
                    "0.0.1" => Version::V001,
                    "0.0.4" => Version::V004,
                    "1.0.0" => Version::V100,
                )?);
            }
            Some(Parameter::Quality) => quality = parse_quality(value)?,
            None => {}
        }
    }

    let format = match (kind, version) {
        (MediaKind::OpenMetrics, None | Some(Version::V100)) => PromFormat::OpenMetrics100,
        (MediaKind::Text, None | Some(Version::V004)) | (MediaKind::Any, _) => PromFormat::Text004,
        (MediaKind::Text, Some(Version::V100)) => PromFormat::Text100,
        _ => return None,
    };
    Some((quality, format))
}

fn parse_quality(value: &[u8]) -> Option<u16> {
    let (first, rest) = value.split_first()?;
    let fraction = match rest {
        [] => &[][..],
        [b'.', fraction @ ..] if fraction.len() <= 3 => fraction,
        _ => return None,
    };
    let mut quality = match first {
        b'0' => 0u16,
        b'1' => MAX_QUALITY,
        _ => return None,
    };
    let mut scale = 100u16;
    for digit in fraction {
        if !digit.is_ascii_digit() || (quality == MAX_QUALITY && *digit != b'0') {
            return None;
        }
        quality += (digit - b'0') as u16 * scale;
        scale /= 10;
    }
    Some(quality)
}
