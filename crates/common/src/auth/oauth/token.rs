/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{GrantType, crypto::SymmetricEncrypt};
use crate::Server;
use base64::{Engine, engine::general_purpose};
use std::time::SystemTime;
use store::rand::{Rng, rng};
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

pub const FAILED_TO_DECODE_TOKEN: &str = concat!(
    "Failed to decode token. If you are using an ",
    "external OIDC provider, make sure it is configured as the default directory under ",
    "the Authentication object."
);

const TOKEN_HEADER: &str = "sw1.";
const TOKEN_KEY_CONTEXT: &str = "stalwart-oauth-token-sw1";
const OAUTH_EPOCH: u64 = 946684800; // Jan 1, 2000

pub struct TokenInfo {
    pub grant_type: GrantType,
    pub account_id: u32,
    pub claims: Option<String>,
    pub expiry: u64,
    pub issued_at: u64,
    pub expires_in: u64,
}

struct RawToken {
    grant_type: GrantType,
    account_id: u32,
    claims: Option<String>,
    issued_at: u64,
    expiry: u64,
    credential_version: u64,
}

impl Server {
    pub async fn encode_access_token(
        &self,
        grant_type: GrantType,
        account_id: u32,
        account_name: &str,
        expiry_in: u64,
        claims: Option<&str>,
        credential_version: Option<u64>,
    ) -> trc::Result<String> {
        let issued_at = seconds_since_oauth_epoch();
        let raw = RawToken {
            grant_type,
            account_id,
            claims: claims.map(|claims| claims.to_string()),
            issued_at,
            expiry: issued_at + expiry_in,
            credential_version: credential_version
                .filter(|_| !matches!(grant_type, GrantType::Rsvp))
                .unwrap_or_default(),
        };

        seal_token(
            self.core.oauth.oauth_key.as_bytes(),
            &raw,
            account_name.as_bytes(),
        )
        .map_err(|err| {
            trc::AuthEvent::Error
                .into_err()
                .ctx(trc::Key::Reason, "Failed to encrypt token")
                .reason(err)
                .caused_by(trc::location!())
        })
    }

    pub async fn validate_access_token(
        &self,
        expected_grant_type: Option<GrantType>,
        token_: &str,
    ) -> trc::Result<TokenInfo> {
        let token = open_token(self.core.oauth.oauth_key.as_bytes(), token_).map_err(|_| {
            trc::AuthEvent::Error
                .into_err()
                .ctx(trc::Key::Reason, FAILED_TO_DECODE_TOKEN)
                .caused_by(trc::location!())
                .details(token_.to_string())
        })?;

        // Validate expiration
        let now = seconds_since_oauth_epoch();
        if token.expiry <= now || token.issued_at > now {
            return Err(trc::AuthEvent::TokenExpired.into_err());
        }

        // Validate grant type
        if expected_grant_type.is_some_and(|g| g != token.grant_type) {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Invalid grant type"));
        }

        // Enforce credential revocation for long lived tokens
        if token.credential_version != 0 {
            let current = self
                .access_token(token.account_id)
                .await
                .map_err(|err| trc::AuthEvent::Error.into_err().ctx(trc::Key::Details, err))?
                .credential_version();
            if current != token.credential_version {
                return Err(trc::AuthEvent::TokenExpired
                    .into_err()
                    .details("Token revoked"));
            }
        }

        Ok(TokenInfo {
            grant_type: token.grant_type,
            account_id: token.account_id,
            claims: token.claims,
            expiry: token.expiry + OAUTH_EPOCH,
            issued_at: token.issued_at + OAUTH_EPOCH,
            expires_in: token.expiry - now,
        })
    }
}

fn seal_token(key: &[u8], token: &RawToken, footer: &[u8]) -> Result<String, String> {
    let mut payload = Vec::with_capacity(32);
    payload.push_leb128(token.account_id);
    payload.push(token.grant_type.id());
    payload.push_leb128(token.issued_at);
    payload.push_leb128(token.expiry);
    payload.push_leb128(token.credential_version);
    if let Some(claims) = token.claims.as_deref().filter(|claims| !claims.is_empty()) {
        payload.extend_from_slice(claims.as_bytes());
    }

    let nonce = rng().random::<[u8; SymmetricEncrypt::NONCE_LEN]>();
    let ciphertext =
        SymmetricEncrypt::new(key, TOKEN_KEY_CONTEXT).encrypt_with_aad(&payload, &nonce, footer)?;

    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);

    let mut out = String::with_capacity(TOKEN_HEADER.len() + (body.len() + footer.len()) * 2);
    out.push_str(TOKEN_HEADER);
    general_purpose::URL_SAFE_NO_PAD.encode_string(&body, &mut out);
    if !footer.is_empty() {
        out.push('.');
        general_purpose::URL_SAFE_NO_PAD.encode_string(footer, &mut out);
    }

    Ok(out)
}

fn open_token(key: &[u8], token: &str) -> Result<RawToken, ()> {
    let rest = token.strip_prefix(TOKEN_HEADER).ok_or(())?;
    let (body, footer) = match rest.split_once('.') {
        Some((body, footer)) => (
            body,
            general_purpose::URL_SAFE_NO_PAD
                .decode(footer.as_bytes())
                .map_err(|_| ())?,
        ),
        None => (rest, Vec::new()),
    };
    let body = general_purpose::URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|_| ())?;
    if body.len() < SymmetricEncrypt::NONCE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN {
        return Err(());
    }
    let (nonce, ciphertext) = body.split_at(SymmetricEncrypt::NONCE_LEN);

    let payload = SymmetricEncrypt::new(key, TOKEN_KEY_CONTEXT)
        .decrypt_with_aad(ciphertext, nonce, &footer)
        .map_err(|_| ())?;

    let mut bytes = payload.iter();
    let account_id: u32 = bytes.next_leb128().ok_or(())?;
    let grant_type = GrantType::from_id(bytes.next().copied().ok_or(())?).ok_or(())?;
    let issued_at: u64 = bytes.next_leb128().ok_or(())?;
    let expiry: u64 = bytes.next_leb128().ok_or(())?;
    let credential_version: u64 = bytes.next_leb128().ok_or(())?;
    let bytes = bytes.as_slice();
    let claims = if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8(bytes.to_vec()).map_err(|_| ())?)
    };

    Ok(RawToken {
        grant_type,
        account_id,
        claims,
        issued_at,
        expiry,
        credential_version,
    })
}

#[inline(always)]
fn seconds_since_oauth_epoch() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .saturating_sub(OAUTH_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-test-encryption-key-of-some-length";
    const NAME: &[u8] = b"user@example.org";

    fn sample(grant_type: GrantType, claims: Option<&str>, cv: u64) -> RawToken {
        RawToken {
            grant_type,
            account_id: 42,
            claims: claims.map(|c| c.to_string()),
            issued_at: 1_000,
            expiry: 2_000,
            credential_version: cv,
        }
    }

    fn assert_eq_fields(a: &RawToken, b: &RawToken) {
        assert_eq!(a.account_id, b.account_id);
        assert_eq!(a.grant_type, b.grant_type);
        assert_eq!(a.claims, b.claims);
        assert_eq!(a.issued_at, b.issued_at);
        assert_eq!(a.expiry, b.expiry);
        assert_eq!(a.credential_version, b.credential_version);
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        for (raw, footer) in [
            (sample(GrantType::AccessToken, None, 0), NAME),
            (
                sample(GrantType::RefreshToken, None, 0xdead_beef_cafe),
                NAME,
            ),
            (
                sample(GrantType::Rsvp, Some("attendee@x.org;7"), 0),
                b"owner@example.org",
            ),
            (sample(GrantType::AccessToken, None, 0), b""),
            (
                RawToken {
                    account_id: u32::MAX,
                    credential_version: u64::MAX,
                    ..sample(GrantType::AccessToken, Some("名前;1"), 1)
                },
                "名字@example.org".as_bytes(),
            ),
        ] {
            let token = seal_token(KEY, &raw, footer).unwrap();
            assert!(token.starts_with(TOKEN_HEADER));
            let opened = open_token(KEY, &token).unwrap();
            assert_eq_fields(&raw, &opened);

            // The footer (account name) round-trips in clear text for proxies
            if footer.is_empty() {
                assert!(!token[TOKEN_HEADER.len()..].contains('.'));
            } else {
                let segment = token.rsplit_once('.').unwrap().1;
                assert_eq!(
                    general_purpose::URL_SAFE_NO_PAD.decode(segment).unwrap(),
                    footer
                );
            }
        }
    }

    #[test]
    fn account_name_is_readable_in_clear_text_footer() {
        let token = seal_token(
            KEY,
            &sample(GrantType::AccessToken, None, 0),
            b"route-me@example.org",
        )
        .unwrap();
        let footer = token.rsplit_once('.').unwrap().1;
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(footer).unwrap();
        assert_eq!(decoded, b"route-me@example.org");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let token = seal_token(KEY, &sample(GrantType::AccessToken, None, 0), NAME).unwrap();
        assert!(open_token(b"a-different-encryption-key-entirely!", &token).is_err());
    }

    #[test]
    fn tampering_with_ciphertext_is_rejected() {
        let raw = sample(GrantType::AccessToken, None, 0);
        let token = seal_token(KEY, &raw, NAME).unwrap();
        let (header, rest) = token.split_at(TOKEN_HEADER.len());
        let (body_b64, footer) = match rest.split_once('.') {
            Some((b, f)) => (b.to_string(), Some(f.to_string())),
            None => (rest.to_string(), None),
        };
        let mut body = general_purpose::URL_SAFE_NO_PAD.decode(&body_b64).unwrap();

        for idx in 0..body.len() {
            let mut tampered = body.clone();
            tampered[idx] ^= 0x01;
            let mut rebuilt = String::from(header);
            rebuilt.push_str(&general_purpose::URL_SAFE_NO_PAD.encode(&tampered));
            if let Some(footer) = &footer {
                rebuilt.push('.');
                rebuilt.push_str(footer);
            }
            assert!(
                open_token(KEY, &rebuilt).is_err(),
                "flipping byte {idx} of the body must invalidate the token"
            );
        }

        // Sanity: the untampered token still opens
        body[0] ^= 0x00;
        assert!(open_token(KEY, &token).is_ok());
    }

    #[test]
    fn tampering_with_clear_text_footer_is_rejected() {
        let raw = sample(GrantType::AccessToken, None, 0);
        let token = seal_token(KEY, &raw, b"victim@example.org").unwrap();
        let (body, _) = token.rsplit_once('.').unwrap();

        // An attacker rewrites the clear-text account name to impersonate another account
        let forged_footer = general_purpose::URL_SAFE_NO_PAD.encode(b"attacker@example.org");
        let forged = format!("{body}.{forged_footer}");
        assert!(
            open_token(KEY, &forged).is_err(),
            "the footer is bound through the associated data and must be authenticated"
        );
    }

    #[test]
    fn swapping_footers_between_tokens_is_rejected() {
        let a = seal_token(
            KEY,
            &sample(GrantType::AccessToken, None, 0),
            b"alice@example.org",
        )
        .unwrap();
        let b = seal_token(
            KEY,
            &sample(GrantType::AccessToken, None, 0),
            b"bob@example.org",
        )
        .unwrap();
        let a_body = a.rsplit_once('.').unwrap().0;
        let b_footer = b.rsplit_once('.').unwrap().1;
        let frankentoken = format!("{a_body}.{b_footer}");
        assert!(open_token(KEY, &frankentoken).is_err());
    }

    #[test]
    fn malformed_input_never_panics_and_is_rejected() {
        let valid = seal_token(KEY, &sample(GrantType::AccessToken, None, 0), NAME).unwrap();
        let cases = [
            String::new(),
            "sw1.".to_string(),
            "sw1.!!!not-base64!!!".to_string(),
            "sw1...".to_string(),
            "wrong-prefix.".to_string(),
            "sw1.AAAA".to_string(),
            "sw1.AAAA.BBBB".to_string(),
            valid.replace("sw1.", "sw2."),
            valid[..valid.len() / 2].to_string(),
            format!("sw1.{}", "A".repeat(10_000)),
            "\u{0}\u{0}\u{0}".to_string(),
        ];
        for case in cases {
            assert!(open_token(KEY, &case).is_err(), "must reject {case:?}");
        }
    }

    #[test]
    fn truncating_the_body_is_rejected() {
        let token = seal_token(KEY, &sample(GrantType::AccessToken, None, 0), NAME).unwrap();
        let (header, rest) = token.split_at(TOKEN_HEADER.len());
        let body_b64 = rest.split_once('.').map(|(b, _)| b).unwrap_or(rest);
        let body = general_purpose::URL_SAFE_NO_PAD.decode(body_b64).unwrap();
        for len in 0..body.len() {
            let mut rebuilt = String::from(header);
            rebuilt.push_str(&general_purpose::URL_SAFE_NO_PAD.encode(&body[..len]));
            assert!(
                open_token(KEY, &rebuilt).is_err(),
                "truncation to {len} must be rejected"
            );
        }
    }

    #[test]
    fn identical_input_produces_distinct_tokens() {
        let raw = sample(GrantType::AccessToken, None, 7);
        let a = seal_token(KEY, &raw, NAME).unwrap();
        let b = seal_token(KEY, &raw, NAME).unwrap();
        assert_ne!(a, b, "a random nonce must make each token unique");
        assert_eq_fields(&open_token(KEY, &a).unwrap(), &open_token(KEY, &b).unwrap());
    }

    #[test]
    fn claims_with_separators_round_trip_exactly() {
        let raw = sample(GrantType::Rsvp, Some("a;b;c;d@e.org;999"), 0);
        let token = seal_token(KEY, &raw, b"owner@example.org").unwrap();
        let opened = open_token(KEY, &token).unwrap();
        assert_eq!(opened.claims.as_deref(), Some("a;b;c;d@e.org;999"));
    }
}
