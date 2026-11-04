/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{crypto::SymmetricEncrypt, scope::OAuthScopes};
use encodify::base64::URL_SAFE_NO_PAD;
use store::blake3;
use utils::codec::leb128::{Leb128Reader, Leb128Writer};

pub const CLIENT_ID_HEADER: &str = "swc1.";
const CLIENT_ID_KEY_CONTEXT: &str = "stalwart-oauth-client-id-sw1";
const CLIENT_ID_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientMeta {
    pub redirect_uris: Vec<String>,
    pub scopes: OAuthScopes,
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
    payload.push_leb128(u64::from(meta.scopes.bits()));
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
    URL_SAFE_NO_PAD.encode_append(&body, &mut out);

    Ok(out)
}

pub fn decode_client_id(key: &[u8], client_id: &str) -> Option<ClientMeta> {
    let body = URL_SAFE_NO_PAD
        .decode(client_id.strip_prefix(CLIENT_ID_HEADER)?.as_bytes())
        .ok()?;
    if body.len() < SymmetricEncrypt::NONCE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN {
        return None;
    }
    let (nonce, ciphertext) = body.split_at(SymmetricEncrypt::NONCE_LEN);
    let payload = SymmetricEncrypt::new(key, CLIENT_ID_KEY_CONTEXT)
        .decrypt_with_aad(ciphertext, nonce, &[])
        .ok()?;

    let (&version, mut bytes) = payload.split_first()?;
    if version != CLIENT_ID_VERSION {
        return None;
    }

    let uri_count: usize = bytes.read_leb128()?;
    if uri_count > u8::MAX as usize {
        return None;
    }
    let mut redirect_uris = Vec::with_capacity(uri_count);
    for _ in 0..uri_count {
        redirect_uris.push(take_string(&mut bytes)?);
    }
    let scopes = OAuthScopes::from_bits(u16::try_from(bytes.read_leb128::<u64>()?).ok()?);
    let client_name = take_string(&mut bytes)?;

    Some(ClientMeta {
        redirect_uris,
        scopes,
        client_name: (!client_name.is_empty()).then_some(client_name),
    })
}

fn take_string(bytes: &mut &[u8]) -> Option<String> {
    let len: usize = bytes.read_leb128()?;
    let (value, rest) = bytes.split_at_checked(len)?;
    let value = String::from_utf8(value.to_vec()).ok()?;
    *bytes = rest;
    Some(value)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/client_id/tests.rs"]
mod tests;
