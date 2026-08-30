/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub fn weak_etag(revision: u64) -> String {
    format!("W/\"{revision:016x}\"")
}

pub fn opaque_value(etag: &str) -> &str {
    etag.strip_prefix("W/")
        .unwrap_or(etag)
        .trim()
        .trim_matches('"')
}

pub fn is_weak(etag: &str) -> bool {
    etag.starts_with("W/")
}

pub fn matches(header: &str, version: &str) -> bool {
    let version = opaque_value(version);

    split_list(header).any(|candidate| candidate == "*" || opaque_value(candidate) == version)
}

fn split_list(header: &str) -> impl Iterator<Item = &str> {
    let mut quoted = false;

    header
        .split(move |ch| {
            match ch {
                '"' => quoted = !quoted,
                ',' if !quoted => return true,
                _ => {}
            }

            false
        })
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_weak_etag() {
        assert_eq!(weak_etag(0x3694e05e9dff590), "W/\"03694e05e9dff590\"");
        assert!(is_weak(&weak_etag(1)));
    }

    #[test]
    fn extract_opaque_value() {
        assert_eq!(opaque_value("W/\"abc\""), "abc");
        assert_eq!(opaque_value("\"abc\""), "abc");
        assert_eq!(opaque_value("abc"), "abc");
    }

    #[test]
    fn compare_conditional_headers() {
        let version = weak_etag(0xdeadbeef);

        assert!(matches(&version, &version));
        assert!(matches("*", &version));
        assert!(matches("\"00000000deadbeef\"", &version));
        assert!(matches("W/\"other\", W/\"00000000deadbeef\"", &version));
        assert!(!matches("W/\"other\"", &version));
        assert!(!matches("", &version));
        assert!(matches("W/\"a,b\"", "W/\"a,b\""));
        assert!(!matches("W/\"a,b\"", "W/\"a\""));
    }
}
