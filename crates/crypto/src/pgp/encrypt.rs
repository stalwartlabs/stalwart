/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use zeroize::Zeroizing;

use crate::{
    backend::{
        PrimitiveError,
        aes::{AesCipher, AesKeySize, BLOCK_LEN, cfb_encrypt_zero_iv},
        agree::Curve,
        base64::ARMOR,
        hash::HashAlgorithm,
        kdf::{HkdfHash, openpgp_ecdh},
        kem::MlKem,
        ocb::OcbKey,
        rng::Rng,
        symmetric::GcmKey,
    },
    error::{EncryptError, ProfileError},
    mime::{BOUNDARY_LEN, CRLF, Sink, boundary, entity::Entity},
    pgp::{
        armor::{BEGIN_MESSAGE, END_MESSAGE, checksum_line},
        cert::{EncryptionKey, PgpCert, PgpKey},
        key::{EcdhCurve, KeyVersion, SYM_AES128, SYM_AES256, aes_key_id},
        packet::{
            TAG_LITERAL, TAG_PADDING, TAG_PKESK, TAG_SEIPD, header_bytes, header_len, mpi_header,
            write_header,
        },
        signature::SymPrefs,
    },
    types::{EncryptOptions, HeaderProtection, Profile, RecipientIds},
};

pub(crate) const AEAD_OCB: u8 = 2;
pub(crate) const AEAD_GCM: u8 = 3;
const TAG_LEN: usize = 16;
const SALT_LEN: usize = 32;
const SINGLE_CHUNK_OCTET: u8 = 16;
pub(crate) const MULTI_CHUNK_OCTET: u8 = 12;
const LITERAL_FIELDS: [u8; 6] = [b'b', 0, 0, 0, 0, 0];
const LITERAL_OVERHEAD: usize = LITERAL_FIELDS.len();
const MDC_LEN: usize = 22;
const MDC_HEADER: [u8; 2] = [0xD3, 0x14];
const PREFIX_LEN: usize = BLOCK_LEN + 2;
const PADDING_GRANULE: usize = 512;
const MAX_FIELDS: usize = 2048;
const MAX_SESSION_KEY: usize = 32;
const X25519_INFO: &[u8] = b"OpenPGP X25519";
const X448_INFO: &[u8] = b"OpenPGP X448";
const COMBINER_DOMAIN: &[u8] = b"OpenPGPCompositeKDFv1";
const PKESK_V3: u8 = 3;
const PKESK_V6: u8 = 6;
const SEIPD_V1: u8 = 1;
const SEIPD_V2: u8 = 2;
const MAX_MESSAGE_LEN: usize = u32::MAX as usize - (1 << 20);

const MIME_HEADER_START: &[u8] =
    b"Content-Type: multipart/encrypted;\r\n\tprotocol=\"application/pgp-encrypted\";\r\n\tboundary=\"";
const MIME_HEADER_END: &[u8] =
    b"\"\r\n\r\nOpenPGP/MIME message (Automatically encrypted by Stalwart)\r\n\r\n";
const VERSION_PART: &[u8] =
    b"\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n";
const DATA_PART: &[u8] = b"\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\nContent-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n";
const DASHES: &[u8] = b"--";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Row {
    V1 { cipher: AesKeySize },
    V2 { cipher: AesKeySize, aead: u8 },
}

pub(crate) fn selected_keys(
    certs: &[PgpCert],
    profile: Profile,
) -> impl Iterator<Item = &PgpKey> + Clone {
    certs.iter().flat_map(move |cert| {
        let has_classical = cert.keys.iter().any(|k| !k.is_post_quantum());
        cert.keys.iter().filter(move |key| match profile {
            Profile::Compatible => !key.is_post_quantum() || !has_classical,
            Profile::Modern => true,
            Profile::PostQuantum => key.is_post_quantum(),
        })
    })
}

pub(crate) fn check_profile(certs: &[PgpCert], profile: Profile) -> Result<(), ProfileError> {
    if profile == Profile::PostQuantum
        && certs
            .iter()
            .any(|cert| !cert.keys.iter().any(PgpKey::is_post_quantum))
    {
        return Err(ProfileError::NoPostQuantumKey);
    }
    Ok(())
}

fn accepts_pair(key: &PgpKey, pair: (u8, u8)) -> bool {
    pair == (SYM_AES128, AEAD_OCB)
        || (key.is_post_quantum() && pair == (SYM_AES256, AEAD_OCB))
        || key.aead_prefs.as_slice().contains(&pair)
}

fn accepts_aes256_v1(key: &PgpKey) -> bool {
    key.is_post_quantum() || key.sym_prefs.is_some_and(|p| p.contains(SymPrefs::AES256))
}

fn aes_size(id: u8) -> AesKeySize {
    match id {
        SYM_AES256 => AesKeySize::Aes256,
        SYM_AES128 => AesKeySize::Aes128,
        _ => AesKeySize::Aes192,
    }
}

pub(crate) fn select_row<'x>(
    keys: impl Iterator<Item = &'x PgpKey> + Clone,
    profile: Profile,
) -> Result<Row, EncryptError> {
    let mut iter = keys.clone();
    let first = iter.next().ok_or(EncryptError::NoRecipients)?;
    if !keys.clone().all(|k| k.seipd_v2) {
        return Ok(Row::V1 {
            cipher: if keys.clone().all(accepts_aes256_v1) {
                AesKeySize::Aes256
            } else {
                AesKeySize::Aes128
            },
        });
    }
    let all_accept = |pair: (u8, u8)| keys.clone().all(|k| accepts_pair(k, pair));
    let (cipher, aead) =
        if profile == Profile::PostQuantum || keys.clone().any(PgpKey::is_post_quantum) {
            [(SYM_AES256, AEAD_OCB), (SYM_AES256, AEAD_GCM)]
                .into_iter()
                .find(|pair| all_accept(*pair))
                .unwrap_or((SYM_AES256, AEAD_OCB))
        } else {
            let chosen = first
                .aead_prefs
                .as_slice()
                .iter()
                .copied()
                .chain([(SYM_AES128, AEAD_OCB)])
                .find(|pair| all_accept(*pair))
                .unwrap_or((SYM_AES128, AEAD_OCB));
            if profile == Profile::Modern
                && chosen.0 != SYM_AES256
                && all_accept((SYM_AES256, chosen.1))
            {
                (SYM_AES256, chosen.1)
            } else {
                chosen
            }
        };
    Ok(Row::V2 {
        cipher: aes_size(cipher),
        aead,
    })
}

struct Fields {
    buf: [u8; MAX_FIELDS],
    len: usize,
}

impl Fields {
    fn new() -> Self {
        Fields {
            buf: [0u8; MAX_FIELDS],
            len: 0,
        }
    }

    fn put(&mut self, data: &[u8]) -> Result<(), PrimitiveError> {
        let end = self.len + data.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(PrimitiveError::InvalidLength)?
            .copy_from_slice(data);
        self.len = end;
        Ok(())
    }

    fn reserve(&mut self, len: usize) -> Result<&mut [u8], PrimitiveError> {
        let end = self.len + len;
        let slot = self
            .buf
            .get_mut(self.len..end)
            .ok_or(PrimitiveError::InvalidLength)?;
        self.len = end;
        Ok(slot)
    }

    fn put_mpi(&mut self, value: &[u8]) -> Result<(), PrimitiveError> {
        let (bits, value) = mpi_header(value);
        self.put(&bits)?;
        self.put(value)
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

fn checksum(key: &[u8]) -> [u8; 2] {
    (key.iter().map(|b| u32::from(*b)).sum::<u32>() as u16).to_be_bytes()
}

pub(crate) fn mlkem_kek(
    mlkem_shared: &[u8],
    ecdh_shared: &[u8],
    ecdh_ciphertext: &[u8],
    ecdh_public: &[u8],
    algorithm: u8,
) -> Zeroizing<[u8; 32]> {
    let mut hasher = HashAlgorithm::Sha3_256.hasher();
    for part in [mlkem_shared, ecdh_shared, ecdh_ciphertext, ecdh_public] {
        hasher.update(part);
    }
    hasher.update(&[algorithm]);
    hasher.update(COMBINER_DOMAIN);
    hasher.update(&[COMBINER_DOMAIN.len() as u8]);
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(hasher.finish().as_ref());
    kek
}

fn wrap_into(
    fields: &mut Fields,
    kek: &[u8],
    sym: Option<u8>,
    session_key: &[u8],
    with_length: bool,
) -> Result<(), PrimitiveError> {
    let wrapped_len = AesCipher::wrap_len(session_key.len());
    if with_length {
        fields.put(&[(wrapped_len + usize::from(sym.is_some())) as u8])?;
    }
    if let Some(sym) = sym {
        fields.put(&[sym])?;
    }
    let slot = fields.reserve(wrapped_len)?;
    AesCipher::new(kek)?.wrap(session_key, slot)
}

fn pkesk_fields(
    key: &PgpKey,
    sym: Option<u8>,
    session_key: &[u8],
    rng: &mut impl Rng,
    fields: &mut Fields,
) -> Result<(), PrimitiveError> {
    match &key.key {
        EncryptionKey::Rsa(rsa) => {
            let mut m = Zeroizing::new([0u8; MAX_SESSION_KEY + 3]);
            let mut len = 0;
            if let Some(sym) = sym {
                m[0] = sym;
                len = 1;
            }
            m[len..len + session_key.len()].copy_from_slice(session_key);
            len += session_key.len();
            m[len..len + 2].copy_from_slice(&checksum(session_key));
            len += 2;
            let mut ct = [0u8; 1024];
            let ct = ct
                .get_mut(..rsa.ciphertext_len())
                .ok_or(PrimitiveError::InvalidLength)?;
            rsa.encrypt_pkcs1(&m[..len], ct)?;
            fields.put_mpi(ct)
        }
        EncryptionKey::Ecdh {
            curve,
            point,
            kdf_hash,
            kek,
            param,
        } => {
            let agreement = curve.curve().ephemeral_agree(point, rng)?;
            let mut kek_bytes = Zeroizing::new([0u8; 32]);
            let kek_bytes = &mut kek_bytes[..kek.key_len()];
            openpgp_ecdh(
                *kdf_hash,
                agreement.shared(),
                &[param.as_slice()],
                kek_bytes,
            )?;
            let mut m = Zeroizing::new([0u8; 48]);
            let mut len = 0;
            if let Some(sym) = sym {
                m[0] = sym;
                len = 1;
            }
            m[len..len + session_key.len()].copy_from_slice(session_key);
            len += session_key.len();
            m[len..len + 2].copy_from_slice(&checksum(session_key));
            len += 2;
            let pad = 8 - len % 8;
            m[len..len + pad].fill(pad as u8);
            len += pad;
            match curve {
                EcdhCurve::Curve25519Legacy => {
                    let mut native = [0u8; 33];
                    native[0] = 0x40;
                    native[1..].copy_from_slice(agreement.public());
                    fields.put(&263u16.to_be_bytes())?;
                    fields.put(&native)?;
                }
                EcdhCurve::Nist(_) => fields.put_mpi(agreement.public())?,
            }
            fields.put(&[AesCipher::wrap_len(len) as u8])?;
            let slot = fields.reserve(AesCipher::wrap_len(len))?;
            AesCipher::new(kek_bytes)?.wrap(&m[..len], slot)
        }
        EncryptionKey::X25519(recipient) => {
            let agreement = Curve::X25519.ephemeral_agree(recipient, rng)?;
            let mut kek = Zeroizing::new([0u8; 16]);
            HkdfHash::Sha256.derive(
                &[],
                &[agreement.public(), recipient, agreement.shared()],
                &[X25519_INFO],
                kek.as_mut(),
            )?;
            fields.put(agreement.public())?;
            wrap_into(fields, kek.as_ref(), sym, session_key, true)
        }
        EncryptionKey::X448(recipient) => {
            let agreement = Curve::X448.ephemeral_agree(recipient, rng)?;
            let mut kek = Zeroizing::new([0u8; 32]);
            HkdfHash::Sha512.derive(
                &[],
                &[agreement.public(), recipient, agreement.shared()],
                &[X448_INFO],
                kek.as_mut(),
            )?;
            fields.put(agreement.public())?;
            wrap_into(fields, kek.as_ref(), sym, session_key, true)
        }
        EncryptionKey::MlKem { ecdh, kem } => {
            let curve = match kem.kem() {
                MlKem::MlKem1024 => Curve::X448,
                _ => Curve::X25519,
            };
            let agreement = curve.ephemeral_agree(ecdh, rng)?;
            let encapsulation = kem.encapsulate()?;
            let kek = mlkem_kek(
                encapsulation.shared(),
                agreement.shared(),
                agreement.public(),
                ecdh,
                key.algorithm,
            );
            fields.put(agreement.public())?;
            fields.put(encapsulation.ciphertext())?;
            wrap_into(fields, kek.as_ref(), sym, session_key, true)
        }
    }
}

pub(crate) fn write_pkesk(
    out: &mut Vec<u8>,
    key: &PgpKey,
    row: Row,
    ids: RecipientIds,
    session_key: &[u8],
    rng: &mut impl Rng,
) -> Result<(), EncryptError> {
    let mut fields = Fields::new();
    let fp = key.fingerprint.as_bytes();
    match (row, ids) {
        (Row::V1 { cipher }, _) => {
            fields.put(&[PKESK_V3])?;
            fields.put(match ids {
                RecipientIds::Real => &key.key_id,
                RecipientIds::Anonymous => &[0u8; 8],
            })?;
            fields.put(&[key.algorithm])?;
            pkesk_fields(key, Some(aes_key_id(cipher)), session_key, rng, &mut fields)?;
        }
        (Row::V2 { .. }, RecipientIds::Real) => {
            let version = match key.version {
                KeyVersion::V4 => 4,
                KeyVersion::V6 => 6,
            };
            fields.put(&[PKESK_V6, (fp.len() + 1) as u8, version])?;
            fields.put(fp)?;
            fields.put(&[key.algorithm])?;
            pkesk_fields(key, None, session_key, rng, &mut fields)?;
        }
        (Row::V2 { .. }, RecipientIds::Anonymous) => {
            fields.put(&[PKESK_V6, 0, key.algorithm])?;
            pkesk_fields(key, None, session_key, rng, &mut fields)?;
        }
    }
    write_header(out, TAG_PKESK, fields.len);
    out.extend_from_slice(fields.as_slice());
    Ok(())
}

pub(crate) const fn pkesk_upper_bound(key: &PgpKey) -> usize {
    let fields = match &key.key {
        EncryptionKey::Rsa(_) => 1026,
        EncryptionKey::Ecdh { .. } => 2 + 133 + 1 + 48,
        EncryptionKey::X25519(_) => 32 + 2 + 40,
        EncryptionKey::X448(_) => 56 + 2 + 40,
        EncryptionKey::MlKem { .. } => 56 + 1568 + 2 + 40,
    };
    6 + 1 + 1 + 1 + 32 + 1 + fields
}

pub(crate) struct ChunkWriter<'a> {
    pub out: &'a mut Vec<u8>,
    pub chunk: usize,
    pub filled: usize,
}

impl Sink for ChunkWriter<'_> {
    fn put(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.filled == self.chunk {
                self.out.extend_from_slice(&[0u8; TAG_LEN]);
                self.filled = 0;
            }
            let (head, rest) = data.split_at((self.chunk - self.filled).min(data.len()));
            self.out.extend_from_slice(head);
            self.filled += head.len();
            data = rest;
        }
    }
}

fn padding_len(plain_len: usize) -> usize {
    let body = PADDING_GRANULE - (plain_len + 2) % PADDING_GRANULE;
    body.max(1)
}

pub(crate) fn encrypt(
    message: &Entity<'_>,
    certs: &[PgpCert],
    options: &EncryptOptions,
    rng: &mut impl Rng,
) -> Result<Vec<u8>, EncryptError> {
    check_profile(certs, options.profile)?;
    let keys = selected_keys(certs, options.profile);
    let row = select_row(keys.clone(), options.profile)?;
    let inner_len = message.inner_len();
    if inner_len > MAX_MESSAGE_LEN {
        return Err(EncryptError::MessageTooLarge);
    }
    let literal_body = LITERAL_OVERHEAD + inner_len;
    let literal_total = header_len(literal_body) + literal_body;

    let (cipher, plain_len, padding_body, chunk_octet) = match row {
        Row::V1 { cipher } => (cipher, literal_total, 0, 0),
        Row::V2 { cipher, .. } => {
            let padding_body = if options.header_protection == HeaderProtection::Baseline {
                padding_len(literal_total)
            } else {
                0
            };
            let plain = literal_total
                + if padding_body > 0 {
                    header_len(padding_body) + padding_body
                } else {
                    0
                };
            let octet = if plain <= 1 << (u32::from(SINGLE_CHUNK_OCTET) + 6) {
                SINGLE_CHUNK_OCTET
            } else {
                MULTI_CHUNK_OCTET
            };
            (cipher, plain, padding_body, octet)
        }
    };
    let seipd_body = match row {
        Row::V1 { .. } => 1 + PREFIX_LEN + plain_len + MDC_LEN,
        Row::V2 { .. } => {
            let chunk = 1usize << (u32::from(chunk_octet) + 6);
            4 + SALT_LEN + plain_len + plain_len.div_ceil(chunk) * TAG_LEN + TAG_LEN
        }
    };
    let pkesk_bound: usize = keys.clone().map(pkesk_upper_bound).sum();
    let mut scratch = Vec::with_capacity(pkesk_bound + header_len(seipd_body) + seipd_body);

    let mut session_key = Zeroizing::new([0u8; MAX_SESSION_KEY]);
    let session_key = &mut session_key[..cipher.key_len()];
    rng.fill(session_key)?;
    for key in keys {
        write_pkesk(
            &mut scratch,
            key,
            row,
            options.recipient_ids,
            session_key,
            rng,
        )?;
    }
    write_header(&mut scratch, TAG_SEIPD, seipd_body);
    match row {
        Row::V1 { .. } => {
            scratch.push(SEIPD_V1);
            let start = scratch.len();
            let mut prefix = [0u8; PREFIX_LEN];
            rng.fill(&mut prefix[..BLOCK_LEN])?;
            prefix[BLOCK_LEN] = prefix[BLOCK_LEN - 2];
            prefix[BLOCK_LEN + 1] = prefix[BLOCK_LEN - 1];
            scratch.extend_from_slice(&prefix);
            write_header(&mut scratch, TAG_LITERAL, literal_body);
            scratch.extend_from_slice(&LITERAL_FIELDS);
            message.write_inner(&mut scratch);
            scratch.extend_from_slice(&MDC_HEADER);
            let mdc = HashAlgorithm::Sha1.digest(&scratch[start..]);
            scratch.extend_from_slice(mdc.as_ref());
            cfb_encrypt_zero_iv(session_key, &mut scratch[start..])?;
        }
        Row::V2 { cipher, aead } => {
            let info = [0xD2, SEIPD_V2, aes_key_id(cipher), aead, chunk_octet];
            scratch.extend_from_slice(&info[1..]);
            let mut salt = [0u8; SALT_LEN];
            rng.fill(&mut salt)?;
            scratch.extend_from_slice(&salt);
            let start = scratch.len();
            let chunk = 1usize << (u32::from(chunk_octet) + 6);
            let mut writer = ChunkWriter {
                out: &mut scratch,
                chunk,
                filled: 0,
            };
            let (header, header_size) = header_bytes(TAG_LITERAL, literal_body);
            writer.put(&header[..header_size]);
            writer.put(&LITERAL_FIELDS);
            message.write_inner(&mut writer);
            if padding_body > 0 {
                let (header, header_size) = header_bytes(TAG_PADDING, padding_body);
                writer.put(&header[..header_size]);
                let mut random = [0u8; PADDING_GRANULE];
                rng.fill(&mut random[..padding_body])?;
                writer.put(&random[..padding_body]);
            }
            if writer.filled > 0 {
                writer.out.extend_from_slice(&[0u8; TAG_LEN]);
            }
            scratch.extend_from_slice(&[0u8; TAG_LEN]);
            seal_v2(
                &mut scratch[start..],
                session_key,
                &salt,
                &info,
                aead,
                chunk,
                plain_len,
            )?;
        }
    }
    session_key.fill(0);

    let checksum = match row {
        Row::V1 { .. } => Some(checksum_line(&scratch)),
        Row::V2 { .. } => None,
    };
    let armored = ARMOR.encoded_len(scratch.len()) + checksum.as_ref().map_or(0, |line| line.len());
    let total = message.outer_len()
        + MIME_HEADER_START.len()
        + BOUNDARY_LEN
        + MIME_HEADER_END.len()
        + 2 * (DASHES.len() + BOUNDARY_LEN)
        + VERSION_PART.len()
        + DATA_PART.len()
        + BEGIN_MESSAGE.len()
        + armored
        + END_MESSAGE.len()
        + CRLF.len()
        + DASHES.len()
        + BOUNDARY_LEN
        + DASHES.len()
        + CRLF.len();
    let mut random = [0u8; 16];
    rng.fill(&mut random)?;
    let boundary = boundary(&random);
    let mut out = Vec::with_capacity(total);
    message.write_outer(&mut out);
    for part in [
        MIME_HEADER_START,
        &boundary,
        MIME_HEADER_END,
        DASHES,
        &boundary,
        VERSION_PART,
        DASHES,
        &boundary,
        DATA_PART,
        BEGIN_MESSAGE,
    ] {
        out.extend_from_slice(part);
    }
    ARMOR.encode_append(&scratch, &mut out);
    if let Some(line) = &checksum {
        out.extend_from_slice(line);
    }
    for part in [END_MESSAGE, CRLF, DASHES, &boundary, DASHES, CRLF] {
        out.extend_from_slice(part);
    }
    Ok(out)
}

pub(crate) fn seal_v2(
    data: &mut [u8],
    session_key: &[u8],
    salt: &[u8; SALT_LEN],
    info: &[u8; 5],
    aead: u8,
    chunk: usize,
    plain_len: usize,
) -> Result<(), EncryptError> {
    let key_len = session_key.len();
    let nonce_len = if aead == AEAD_OCB { 15 } else { 12 };
    let iv_len = nonce_len - 8;
    let mut okm = Zeroizing::new([0u8; MAX_SESSION_KEY + 8]);
    let okm = &mut okm[..key_len + iv_len];
    HkdfHash::Sha256.derive(salt, &[session_key], &[info], okm)?;
    let (message_key, iv) = okm.split_at(key_len);
    let mut nonce = [0u8; 15];
    nonce[..iv_len].copy_from_slice(iv);
    let mut final_ad = [0u8; 13];
    final_ad[..5].copy_from_slice(info);
    final_ad[5..].copy_from_slice(&(plain_len as u64).to_be_bytes());

    let (body, final_tag) = data
        .split_last_chunk_mut::<TAG_LEN>()
        .ok_or(EncryptError::MalformedMessage)?;
    let chunk_count = plain_len.div_ceil(chunk) as u64;
    match aead {
        AEAD_OCB => {
            let key = OcbKey::new(message_key)?;
            let ad_hash = key.hash(info);
            for (index, segment) in (0u64..).zip(body.chunks_mut(chunk + TAG_LEN)) {
                nonce[iv_len..nonce_len].copy_from_slice(&index.to_be_bytes());
                let (plain, tag) = segment
                    .split_last_chunk_mut::<TAG_LEN>()
                    .ok_or(EncryptError::MalformedMessage)?;
                *tag = key.seal_in_place(&nonce[..nonce_len], ad_hash, plain)?;
            }
            nonce[iv_len..nonce_len].copy_from_slice(&chunk_count.to_be_bytes());
            *final_tag = key.seal_in_place(&nonce[..nonce_len], key.hash(&final_ad), &mut [])?;
        }
        _ => {
            let key = GcmKey::new(message_key)?;
            let mut gcm_nonce = [0u8; 12];
            gcm_nonce[..iv_len].copy_from_slice(&nonce[..iv_len]);
            for (index, segment) in (0u64..).zip(body.chunks_mut(chunk + TAG_LEN)) {
                gcm_nonce[iv_len..].copy_from_slice(&index.to_be_bytes());
                let (plain, tag) = segment
                    .split_last_chunk_mut::<TAG_LEN>()
                    .ok_or(EncryptError::MalformedMessage)?;
                *tag = key.seal_in_place(gcm_nonce, info, plain)?;
            }
            gcm_nonce[iv_len..].copy_from_slice(&chunk_count.to_be_bytes());
            *final_tag = key.seal_in_place(gcm_nonce, &final_ad, &mut [])?;
        }
    }
    Ok(())
}
