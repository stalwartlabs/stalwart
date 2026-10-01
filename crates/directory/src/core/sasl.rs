/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Credentials;
use encodify::base64::URL_SAFE_NO_PAD;

impl Credentials {
    pub fn decode_sasl_challenge_plain(challenge: &[u8]) -> Option<Self> {
        let mut args = challenge.split(|&ch| ch == 0).skip(1);
        let username = args.next().filter(|username| !username.is_empty())?;
        let secret = args.next().filter(|secret| !secret.is_empty())?;

        Some(Credentials::Basic {
            username: std::str::from_utf8(username).ok()?.to_string(),
            secret: std::str::from_utf8(secret).ok()?.to_string(),
            mfa_token: None,
        })
    }

    pub fn decode_sasl_challenge_oauth(challenge: &[u8]) -> Option<Self> {
        extract_oauth_bearer(challenge)
            .map(|(token, username)| Credentials::Bearer { username, token })
    }
}

fn extract_oauth_bearer(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let mut start_pos = 0;
    let eof = bytes.len().saturating_sub(1);
    let mut iter = bytes.iter().enumerate();
    let mut a = None;

    while let Some((pos, ch)) = iter.next() {
        if *ch == b','
            && bytes
                .get(pos + 1..pos + 3)
                .is_some_and(|s| s.eq_ignore_ascii_case(b"a="))
        {
            let from_pos = pos + 3;
            let mut to_pos = from_pos;
            for (pos, ch) in iter.by_ref() {
                if *ch == b',' || *ch == 1 {
                    to_pos = pos;
                    break;
                }
            }

            if to_pos > from_pos {
                a = bytes
                    .get(from_pos..to_pos)
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .filter(|v| v.contains('@'));
            }
        } else {
            let is_separator = *ch == 1;
            if is_separator || pos == eof {
                if bytes
                    .get(start_pos..start_pos + 12)
                    .is_some_and(|s| s.eq_ignore_ascii_case(b"auth=Bearer "))
                {
                    return bytes
                        .get(start_pos + 12..if is_separator { pos } else { bytes.len() })
                        .and_then(|s| std::str::from_utf8(s).ok())
                        .map(|token| {
                            (
                                token.to_string(),
                                a.map(|s| s.to_string())
                                    .or_else(|| extract_email_from_jwt(token)),
                            )
                        });
                }

                start_pos = pos + 1;
            }
        }
    }

    None
}

#[derive(Debug, serde::Deserialize)]
struct JwtClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    #[serde(default)]
    unique_name: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

fn extract_email_from_jwt(token: &str) -> Option<String> {
    let claims: JwtClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?).ok()?;
    [
        claims.email,
        claims.preferred_username,
        claims.upn,
        claims.unique_name,
        claims.sub,
    ]
    .into_iter()
    .flatten()
    .find(|v| v.contains('@'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_sasl_plain(challenge: &[u8]) -> Option<(String, String)> {
        let mut username = Vec::new();
        let mut secret = Vec::new();
        let mut arg_num = 0;
        for &ch in challenge {
            if ch != 0 {
                if arg_num == 1 {
                    username.push(ch);
                } else if arg_num == 2 {
                    secret.push(ch);
                }
            } else {
                arg_num += 1;
            }
        }
        match (String::from_utf8(username), String::from_utf8(secret)) {
            (Ok(username), Ok(secret)) if !username.is_empty() && !secret.is_empty() => {
                Some((username, secret))
            }
            _ => None,
        }
    }

    #[test]
    fn sasl_plain_matches_reference() {
        let cases: &[&[u8]] = &[
            b"",
            b"\0",
            b"\0\0",
            b"user",
            b"\0user",
            b"\0user\0",
            b"\0user\0pass",
            b"authz\0user\0pass",
            b"authz\0user\0pass\0extra",
            b"authz\0user\0pass\0\0extra\0",
            b"\0\0pass",
            b"\0user\0\0pass",
            b"\0us\xffer\0pass",
            b"\0user\0pa\xc3\xa9ss",
            b"\0user\0pa\xc3ss",
            b"\xff\0user\0pass",
            b"\0user\0pass\0\xff",
        ];
        for case in cases {
            let decoded = Credentials::decode_sasl_challenge_plain(case).map(|c| match c {
                Credentials::Basic {
                    username, secret, ..
                } => (username, secret),
                Credentials::Bearer { .. } => unreachable!(),
            });
            assert_eq!(decoded, reference_sasl_plain(case), "{case:?}");
        }
    }

    #[test]
    fn test_extract_oauth_bearer() {
        let input = b"auth=Bearer validtoken";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some(("validtoken".to_string(), None)));

        let input = b"auth=Invalid validtoken";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, None);

        let input = b"auth=Bearer";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, None);

        let input = b"";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, None);

        let input = b"auth=Bearer token1\x01auth=Bearer token2";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some(("token1".to_string(), None)));

        let input = b"auth=Bearer VALIDTOKEN";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some(("VALIDTOKEN".to_string(), None)));

        let input = b"auth=Bearer token with spaces";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some(("token with spaces".to_string(), None)));

        let input = b"auth=Bearer token_with_special_chars!@#";
        let result = extract_oauth_bearer(input);
        assert_eq!(
            result,
            Some(("token_with_special_chars!@#".to_string(), None))
        );

        let input = "n,a=user@example.com,\x01host=server.example.com\x01port=143\x01auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\x01\x01";
        let result = extract_oauth_bearer(input.as_bytes());
        assert_eq!(
            result,
            Some((
                "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==".to_string(),
                Some("user@example.com".to_string())
            ))
        );
    }
}
