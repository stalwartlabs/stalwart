/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    SCOPE_CALENDARS, SCOPE_CONTACTS, SCOPE_MAIL, SCOPE_OFFLINE_ACCESS, SCOPE_OPENID,
    crypto::SymmetricEncrypt,
};
use base64::{Engine, engine::general_purpose};
use store::blake3;
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

const CLIENT_ID_HEADER: &str = "swc1.";
const CLIENT_ID_KEY_CONTEXT: &str = "stalwart-oauth-client-id-sw1";
const CLIENT_ID_VERSION: u8 = 1;

const SCOPE_BITS: &[&str] = &[
    SCOPE_OPENID,
    SCOPE_OFFLINE_ACCESS,
    SCOPE_MAIL,
    SCOPE_CONTACTS,
    SCOPE_CALENDARS,
];

pub fn scopes_to_mask(scope: &str) -> u64 {
    let mut mask = 0u64;
    for scope in scope.split_ascii_whitespace() {
        if let Some(bit) = SCOPE_BITS.iter().position(|known| *known == scope) {
            mask |= 1 << bit;
        }
    }
    mask
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientMeta {
    pub redirect_uris: Vec<String>,
    pub scope_mask: u64,
    pub client_name: Option<String>,
}

pub fn encode_client_id(key: &[u8], meta: &ClientMeta) -> Result<String, String> {
    let client_name = meta.client_name.as_deref().unwrap_or_default();

    let mut payload = Vec::with_capacity(
        24 + meta
            .redirect_uris
            .iter()
            .map(|u| u.len() + 2)
            .sum::<usize>()
            + client_name.len(),
    );
    payload.push(CLIENT_ID_VERSION);
    payload.push_leb128(meta.redirect_uris.len());
    for uri in &meta.redirect_uris {
        payload.push_leb128(uri.len());
        payload.extend_from_slice(uri.as_bytes());
    }
    payload.push_leb128(meta.scope_mask);
    payload.push_leb128(client_name.len());
    payload.extend_from_slice(client_name.as_bytes());

    let digest = blake3::hash(&payload);
    let nonce = &digest.as_bytes()[..SymmetricEncrypt::NONCE_LEN];
    let ciphertext =
        SymmetricEncrypt::new(key, CLIENT_ID_KEY_CONTEXT).encrypt_with_aad(&payload, nonce, &[])?;

    let mut body = Vec::with_capacity(nonce.len() + ciphertext.len());
    body.extend_from_slice(nonce);
    body.extend_from_slice(&ciphertext);

    let mut out = String::with_capacity(CLIENT_ID_HEADER.len() + body.len().div_ceil(3) * 4);
    out.push_str(CLIENT_ID_HEADER);
    general_purpose::URL_SAFE_NO_PAD.encode_string(&body, &mut out);

    Ok(out)
}

pub fn decode_client_id(key: &[u8], client_id: &str) -> Option<ClientMeta> {
    let body = general_purpose::URL_SAFE_NO_PAD
        .decode(client_id.strip_prefix(CLIENT_ID_HEADER)?.as_bytes())
        .ok()?;
    if body.len() < SymmetricEncrypt::NONCE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN {
        return None;
    }
    let (nonce, ciphertext) = body.split_at(SymmetricEncrypt::NONCE_LEN);
    let payload = SymmetricEncrypt::new(key, CLIENT_ID_KEY_CONTEXT)
        .decrypt_with_aad(ciphertext, nonce, &[])
        .ok()?;

    let mut bytes = payload.iter();
    if bytes.next().copied()? != CLIENT_ID_VERSION {
        return None;
    }

    let uri_count: usize = bytes.next_leb128()?;
    if uri_count > u8::MAX as usize {
        return None;
    }
    let mut redirect_uris = Vec::with_capacity(uri_count);
    for _ in 0..uri_count {
        redirect_uris.push(take_string(&mut bytes)?);
    }
    let scope_mask: u64 = bytes.next_leb128()?;
    let client_name = take_string(&mut bytes)?;

    Some(ClientMeta {
        redirect_uris,
        scope_mask,
        client_name: (!client_name.is_empty()).then_some(client_name),
    })
}

fn take_string(bytes: &mut std::slice::Iter<'_, u8>) -> Option<String> {
    let len: usize = bytes.next_leb128()?;
    let slice = bytes.as_slice();
    if slice.len() < len {
        return None;
    }
    let value = String::from_utf8(slice[..len].to_vec()).ok()?;
    if len > 0 {
        bytes.nth(len - 1)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-test-encryption-key-of-some-length";

    fn sample() -> ClientMeta {
        ClientMeta {
            redirect_uris: vec![
                "http://127.0.0.1/cb".to_string(),
                "com.example.app:/oauth".to_string(),
            ],
            scope_mask: scopes_to_mask(&format!("{SCOPE_OFFLINE_ACCESS} {SCOPE_MAIL}")),
            client_name: Some("Example Client".to_string()),
        }
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        for meta in [
            sample(),
            ClientMeta {
                redirect_uris: vec!["http://[::1]/".to_string()],
                scope_mask: 0,
                client_name: None,
            },
            ClientMeta::default(),
        ] {
            let client_id = encode_client_id(KEY, &meta).unwrap();
            assert!(client_id.starts_with(CLIENT_ID_HEADER));
            assert_eq!(decode_client_id(KEY, &client_id), Some(meta));
        }
    }

    #[test]
    fn scope_mask_is_order_independent_and_drops_unknown() {
        assert_eq!(
            scopes_to_mask(&format!("{SCOPE_MAIL} {SCOPE_OFFLINE_ACCESS}")),
            scopes_to_mask(&format!("{SCOPE_OFFLINE_ACCESS} {SCOPE_MAIL}"))
        );
        assert_eq!(
            scopes_to_mask(&format!("{SCOPE_MAIL} custom:unknown")),
            scopes_to_mask(SCOPE_MAIL)
        );
        assert_eq!(scopes_to_mask("totally unknown"), 0);
    }

    #[test]
    fn identical_input_is_deterministic() {
        let meta = sample();
        assert_eq!(
            encode_client_id(KEY, &meta).unwrap(),
            encode_client_id(KEY, &meta).unwrap()
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let client_id = encode_client_id(KEY, &sample()).unwrap();
        assert_eq!(
            decode_client_id(b"a-completely-different-key-value!", &client_id),
            None
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let client_id = encode_client_id(KEY, &sample()).unwrap();
        let (header, body_b64) = client_id.split_at(CLIENT_ID_HEADER.len());
        let mut body = general_purpose::URL_SAFE_NO_PAD.decode(body_b64).unwrap();
        for idx in 0..body.len() {
            let mut tampered = body.clone();
            tampered[idx] ^= 0x01;
            let forged = format!(
                "{header}{}",
                general_purpose::URL_SAFE_NO_PAD.encode(&tampered)
            );
            assert_eq!(decode_client_id(KEY, &forged), None, "byte {idx}");
        }
        body[0] ^= 0x00;
        assert!(decode_client_id(KEY, &client_id).is_some());
    }

    #[test]
    fn malformed_input_never_panics() {
        for case in [
            "",
            "swc1.",
            "swc1.!!!",
            "swc1.AAAA",
            "wrong.AAAA",
            "swc1.AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(decode_client_id(KEY, case), None, "{case:?}");
        }
    }
}
