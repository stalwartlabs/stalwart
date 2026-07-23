/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use chacha20poly1305::ChaCha20Poly1305;
use common::auth::{
    ACCOUNT_FLAG_ENCRYPT_ALGO_AES256, ACCOUNT_FLAG_ENCRYPT_ALGO_AES256_GCM,
    ACCOUNT_FLAG_ENCRYPT_ALGO_CHACHA20_POLY1305, ACCOUNT_FLAG_ENCRYPT_METHOD_PGP,
    ACCOUNT_FLAG_ENCRYPT_TRAIN_SPAM_FILTER, EncryptionKeys,
};
use mail_builder::{encoders::base64::base64_encode_mime, mime::make_boundary};
use mail_parser::{Message, MimeHeaders, PartType};
use openpgp::{
    parse::Parse,
    serialize::stream,
    types::{KeyFlags, SymmetricAlgorithm},
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rasn::Encoder;
use rasn::types::{OctetString, Oid, SetOf};
use rasn_cms::{
    AlgorithmIdentifier, AuthEnvelopedData, CONTENT_DATA, CONTENT_ENVELOPED_DATA, EncryptedContent,
    EncryptedContentInfo, EncryptedKey, EnvelopedData, IssuerAndSerialNumber,
    KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo,
    algorithms::{AES128_CBC, AES256_CBC, RSA},
    pkcs7_compat::EncapsulatedContentInfo,
};
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPublicKey, pkcs1::DecodeRsaPublicKey, sha2::Sha256};
use sequoia_openpgp as openpgp;
use std::io::Cursor;

const AES256_GCM: &Oid =
    Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_AES256_GCM;
const CHACHA20_POLY1305: &Oid = Oid::const_new(&[1, 2, 840, 113549, 1, 9, 16, 3, 18]);
const CONTENT_AUTH_ENVELOPED_DATA: &Oid =
    Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_AUTH_ENVELOPED_DATA;
const SHA256: &Oid =
    Oid::JOINT_ISO_ITU_T_COUNTRY_US_ORGANIZATION_GOV_CSOR_NIST_ALGORITHMS_HASH_SHA256;
const MGF1: &Oid = Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS1_MGF1;
const RSAES_OAEP: &Oid = Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS1_RSAES_OAEP;

#[derive(Debug)]
pub enum EncryptMessageError {
    AlreadyEncrypted,
    Error(String),
}

#[allow(async_fn_in_trait)]
pub trait EncryptMessage {
    async fn encrypt(
        &self,
        keys: &EncryptionKeys,
        flags: u64,
    ) -> Result<Vec<u8>, EncryptMessageError>;
    fn is_encrypted(&self) -> bool;
}

impl EncryptMessage for Message<'_> {
    async fn encrypt(
        &self,
        keys: &EncryptionKeys,
        flags: u64,
    ) -> Result<Vec<u8>, EncryptMessageError> {
        if flags & ACCOUNT_FLAG_ENCRYPT_METHOD_PGP != 0 && flags.cipher().is_aead() {
            return Err(EncryptMessageError::Error(
                "AES-256-GCM and ChaCha20-Poly1305 are only supported for S/MIME encryption."
                    .into(),
            ));
        }

        let root = self.root_part();
        let raw_message = self.raw_message();
        let mut outer_message = Vec::with_capacity((raw_message.len() as f64 * 1.5) as usize);
        let mut inner_message = Vec::with_capacity(raw_message.len());

        // Move MIME headers and body to inner message
        for header in root.headers() {
            (if header.name.is_mime_header() {
                &mut inner_message
            } else {
                &mut outer_message
            })
            .extend_from_slice(
                &raw_message[header.offset_field() as usize..header.offset_end() as usize],
            );
        }
        inner_message.extend_from_slice(b"\r\n");
        inner_message.extend_from_slice(&raw_message[root.raw_body_offset() as usize..]);

        // Encrypt inner message
        if flags & ACCOUNT_FLAG_ENCRYPT_METHOD_PGP != 0 {
            // Prepare encrypted message
            let boundary = make_boundary("_");
            outer_message.extend_from_slice(
                concat!(
                    "Content-Type: multipart/encrypted;\r\n\t",
                    "protocol=\"application/pgp-encrypted\";\r\n\t",
                    "boundary=\""
                )
                .as_bytes(),
            );
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(
                concat!(
                    "\"\r\n\r\n",
                    "OpenPGP/MIME message (Automatically encrypted by Stalwart)\r\n\r\n",
                    "--"
                )
                .as_bytes(),
            );
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(
                concat!(
                    "\r\nContent-Type: application/pgp-encrypted\r\n\r\n",
                    "Version: 1\r\n\r\n--"
                )
                .as_bytes(),
            );
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(
                concat!(
                    "\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n",
                    "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n"
                )
                .as_bytes(),
            );

            let certs = keys
                .iter()
                .map(openpgp::Cert::from_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| {
                    EncryptMessageError::Error(format!(
                        "Failed to parse OpenPGP public key: {}",
                        err
                    ))
                })?;

            // Encrypt contents (TODO: use rayon)
            let encrypted_contents = tokio::task::spawn_blocking(move || {
                // Parse public key
                let mut keys = Vec::with_capacity(certs.len());
                let policy = openpgp::policy::StandardPolicy::new();

                for cert in &certs {
                    for key in cert
                        .keys()
                        .with_policy(&policy, None)
                        .supported()
                        .alive()
                        .revoked(false)
                        .key_flags(KeyFlags::empty().set_transport_encryption())
                    {
                        keys.push(key);
                    }
                }

                // Compose a writer stack corresponding to the output format and
                // packet structure we want.
                let mut sink = Vec::with_capacity(inner_message.len());

                // Stream an OpenPGP message.
                let message = stream::Armorer::new(stream::Message::new(&mut sink))
                    .build()
                    .map_err(|err| {
                        EncryptMessageError::Error(format!("Failed to create armorer: {}", err))
                    })?;
                let message = stream::Encryptor::for_recipients(message, keys)
                    .symmetric_algo(flags.algo())
                    .build()
                    .map_err(|err| {
                        EncryptMessageError::Error(format!("Failed to build encryptor: {}", err))
                    })?;
                let mut message = stream::LiteralWriter::new(message).build().map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to create literal writer: {}", err))
                })?;
                std::io::copy(&mut Cursor::new(inner_message), &mut message).map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
                })?;
                message.finalize().map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to finalize message: {}", err))
                })?;

                String::from_utf8(sink).map_err(|err| {
                    EncryptMessageError::Error(format!(
                        "Failed to convert encrypted message to UTF-8: {}",
                        err
                    ))
                })
            })
            .await
            .map_err(|err| {
                EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
            })??;
            outer_message.extend_from_slice(encrypted_contents.as_bytes());
            outer_message.extend_from_slice(b"\r\n--");
            outer_message.extend_from_slice(boundary.as_bytes());
            outer_message.extend_from_slice(b"--\r\n");
        } else {
            let cipher = flags.cipher();

            // Generate random nonce
            let mut rng = StdRng::from_entropy();
            let mut nonce = vec![0u8; cipher.nonce_size()];
            rng.fill_bytes(&mut nonce);

            // Generate random key
            let mut key = vec![0u8; cipher.key_size()];
            rng.fill_bytes(&mut key);

            // Encrypt contents (TODO: use rayon)
            let (encrypted_contents, mac, key, nonce) = tokio::task::spawn_blocking(move || {
                let (encrypted_contents, mac) = cipher.encrypt(&key, &nonce, &inner_message);
                (encrypted_contents, mac, key, nonce)
            })
            .await
            .map_err(|err| {
                EncryptMessageError::Error(format!("Failed to encrypt message: {}", err))
            })?;

            // Encrypt key using public keys
            let key_encryption_algorithm = cipher.key_encryption_algorithm()?;
            let mut recipient_infos = SetOf::new();
            for cert in keys.iter() {
                let cert = rasn::der::decode::<rasn_pkix::Certificate>(cert).map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to parse certificate: {}", err))
                })?;

                let public_key = RsaPublicKey::from_pkcs1_der(
                    cert.tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .as_raw_slice(),
                )
                .map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to parse public key: {}", err))
                })?;
                let encrypted_key = if cipher.is_aead() {
                    public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), &key[..])
                } else {
                    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key[..])
                }
                .map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to encrypt key: {}", err))
                })?;

                recipient_infos.insert(RecipientInfo::KeyTransRecipientInfo(
                    KeyTransRecipientInfo {
                        version: 0.into(),
                        rid: RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                            issuer: cert.tbs_certificate.issuer,
                            serial_number: cert.tbs_certificate.serial_number,
                        }),
                        key_encryption_algorithm: key_encryption_algorithm.clone(),
                        encrypted_key: EncryptedKey::from(encrypted_key),
                    },
                ));
            }

            let encrypted_content_info = EncryptedContentInfo {
                content_type: CONTENT_DATA.into(),
                content_encryption_algorithm: cipher.content_encryption_algorithm(&nonce)?,
                encrypted_content: Some(EncryptedContent::from(encrypted_contents)),
            };

            let (content_type, content) = if let Some(mac) = mac {
                (
                    CONTENT_AUTH_ENVELOPED_DATA,
                    rasn::der::encode(&AuthEnvelopedData {
                        version: 0.into(),
                        originator_info: None,
                        recipient_infos,
                        auth_encrypted_content_info: encrypted_content_info,
                        auth_attrs: None,
                        mac: OctetString::from(mac),
                        unauth_attrs: None,
                    })
                    .map_err(|err| {
                        EncryptMessageError::Error(format!(
                            "Failed to encode AuthEnvelopedData: {}",
                            err
                        ))
                    })?,
                )
            } else {
                (
                    CONTENT_ENVELOPED_DATA,
                    rasn::der::encode(&EnvelopedData {
                        version: 0.into(),
                        originator_info: None,
                        recipient_infos,
                        encrypted_content_info,
                        unprotected_attrs: None,
                    })
                    .map_err(|err| {
                        EncryptMessageError::Error(format!(
                            "Failed to encode EnvelopedData: {}",
                            err
                        ))
                    })?,
                )
            };

            let pkcs7 = rasn::der::encode(&EncapsulatedContentInfo {
                content_type: content_type.into(),
                content: Some(content.into()),
            })
            .map_err(|err| {
                EncryptMessageError::Error(format!("Failed to encode ContentInfo: {}", err))
            })?;

            // Generate message
            outer_message.extend_from_slice(b"Content-Type: application/pkcs7-mime;\r\n");
            outer_message.extend_from_slice(b"\tname=\"smime.p7m\";\r\n\tsmime-type=");
            outer_message.extend_from_slice(if cipher.is_aead() {
                b"authenticated-enveloped-data\r\n"
            } else {
                b"enveloped-data\r\n"
            });
            outer_message.extend_from_slice(
                concat!(
                    "Content-Disposition: attachment;\r\n",
                    "\tfilename=\"smime.p7m\"\r\n",
                    "Content-Transfer-Encoding: base64\r\n\r\n"
                )
                .as_bytes(),
            );
            base64_encode_mime(&pkcs7, &mut outer_message, false).map_err(|err| {
                EncryptMessageError::Error(format!("Failed to base64 encode PKCS7: {}", err))
            })?;
        }

        Ok(outer_message)
    }

    fn is_encrypted(&self) -> bool {
        if self.content_type().is_some_and(|ct| {
            let main_type = ct.c_type.as_ref();
            let sub_type = ct
                .c_subtype
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or_default();

            (main_type.eq_ignore_ascii_case("application")
                && (sub_type.eq_ignore_ascii_case("pkcs7-mime")
                    || sub_type.eq_ignore_ascii_case("pkcs7-signature")
                    || (sub_type.eq_ignore_ascii_case("octet-stream")
                        && self.attachment_name().is_some_and(|name| {
                            name.rsplit_once('.')
                                .is_some_and(|(_, ext)| ["p7m", "p7s", "p7c", "p7z"].contains(&ext))
                        }))))
                || (main_type.eq_ignore_ascii_case("multipart")
                    && sub_type.eq_ignore_ascii_case("encrypted"))
        }) {
            return true;
        }

        if self.parts.len() <= 2 {
            let mut text_part = None;
            let mut is_multipart = false;

            for part in &self.parts {
                match &part.body {
                    PartType::Text(text) => {
                        text_part = Some(text.as_ref());
                    }
                    PartType::Multipart(_) => {
                        is_multipart = true;
                    }
                    _ => (),
                }
            }

            match text_part {
                Some(text)
                    if (self.parts.len() == 1 || is_multipart)
                        && text.trim_start().starts_with("-----BEGIN PGP MESSAGE-----") =>
                {
                    return true;
                }
                _ => (),
            }
        }

        false
    }
}

pub trait EncryptionFlags {
    fn cipher(&self) -> SymmetricCipher;
    fn can_train_spam_filter(&self) -> bool;
    fn algo(&self) -> SymmetricAlgorithm;
}

impl EncryptionFlags for u64 {
    fn cipher(&self) -> SymmetricCipher {
        if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_AES256_GCM != 0 {
            SymmetricCipher::Aes256Gcm
        } else if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_CHACHA20_POLY1305 != 0 {
            SymmetricCipher::ChaCha20Poly1305
        } else if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_AES256 != 0 {
            SymmetricCipher::Aes256Cbc
        } else {
            SymmetricCipher::Aes128Cbc
        }
    }

    fn can_train_spam_filter(&self) -> bool {
        *self & ACCOUNT_FLAG_ENCRYPT_TRAIN_SPAM_FILTER != 0
    }

    fn algo(&self) -> SymmetricAlgorithm {
        if *self & ACCOUNT_FLAG_ENCRYPT_ALGO_AES256 != 0 {
            SymmetricAlgorithm::AES256
        } else {
            SymmetricAlgorithm::AES128
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymmetricCipher {
    Aes128Cbc,
    Aes256Cbc,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SymmetricCipher {
    fn key_size(self) -> usize {
        match self {
            SymmetricCipher::Aes128Cbc => 16,
            SymmetricCipher::Aes256Cbc
            | SymmetricCipher::Aes256Gcm
            | SymmetricCipher::ChaCha20Poly1305 => 32,
        }
    }

    fn nonce_size(self) -> usize {
        match self {
            SymmetricCipher::Aes128Cbc | SymmetricCipher::Aes256Cbc => 16,
            SymmetricCipher::Aes256Gcm | SymmetricCipher::ChaCha20Poly1305 => 12,
        }
    }

    fn is_aead(self) -> bool {
        matches!(
            self,
            SymmetricCipher::Aes256Gcm | SymmetricCipher::ChaCha20Poly1305
        )
    }

    fn encrypt(self, key: &[u8], nonce: &[u8], contents: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        match self {
            SymmetricCipher::Aes128Cbc => (
                cbc::Encryptor::<aes::Aes128>::new_from_slices(key, nonce)
                    .expect("invalid key or iv length")
                    .encrypt_padded_vec::<Pkcs7>(contents),
                None,
            ),
            SymmetricCipher::Aes256Cbc => (
                cbc::Encryptor::<aes::Aes256>::new_from_slices(key, nonce)
                    .expect("invalid key or iv length")
                    .encrypt_padded_vec::<Pkcs7>(contents),
                None,
            ),
            SymmetricCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key).expect("invalid key length");
                let mut buffer = contents.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(nonce), b"", &mut buffer)
                    .expect("AES-GCM encryption failed");
                (buffer, Some(tag.to_vec()))
            }
            SymmetricCipher::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key).expect("invalid key length");
                let mut buffer = contents.to_vec();
                let tag = cipher
                    .encrypt_in_place_detached(GenericArray::from_slice(nonce), b"", &mut buffer)
                    .expect("ChaCha20-Poly1305 encryption failed");
                (buffer, Some(tag.to_vec()))
            }
        }
    }

    fn content_encryption_algorithm(
        self,
        nonce: &[u8],
    ) -> Result<AlgorithmIdentifier, EncryptMessageError> {
        let (algorithm, parameters) = match self {
            SymmetricCipher::Aes128Cbc => (AES128_CBC, encode_octet_string(nonce)?),
            SymmetricCipher::Aes256Cbc => (AES256_CBC, encode_octet_string(nonce)?),
            SymmetricCipher::ChaCha20Poly1305 => (CHACHA20_POLY1305, encode_octet_string(nonce)?),
            SymmetricCipher::Aes256Gcm => (
                AES256_GCM,
                rasn::der::encode(&GcmParameters {
                    nonce: OctetString::from_slice(nonce),
                    icv_len: 16,
                })
                .map_err(|err| {
                    EncryptMessageError::Error(format!("Failed to encode GCM parameters: {}", err))
                })?,
            ),
        };

        Ok(AlgorithmIdentifier {
            algorithm: algorithm.into(),
            parameters: Some(parameters.into()),
        })
    }

    fn key_encryption_algorithm(self) -> Result<AlgorithmIdentifier, EncryptMessageError> {
        if self.is_aead() {
            let sha256 = AlgorithmIdentifier {
                algorithm: SHA256.into(),
                parameters: Some(encode_null()?.into()),
            };
            let parameters = rasn::der::encode(&OaepParameters {
                hash_algorithm: sha256.clone(),
                mask_gen_algorithm: AlgorithmIdentifier {
                    algorithm: MGF1.into(),
                    parameters: Some(
                        rasn::der::encode(&sha256)
                            .map_err(|err| {
                                EncryptMessageError::Error(format!(
                                    "Failed to encode MGF1 parameters: {}",
                                    err
                                ))
                            })?
                            .into(),
                    ),
                },
            })
            .map_err(|err| {
                EncryptMessageError::Error(format!("Failed to encode OAEP parameters: {}", err))
            })?;

            Ok(AlgorithmIdentifier {
                algorithm: RSAES_OAEP.into(),
                parameters: Some(parameters.into()),
            })
        } else {
            Ok(AlgorithmIdentifier {
                algorithm: RSA.into(),
                parameters: Some(encode_null()?.into()),
            })
        }
    }
}

#[derive(rasn::AsnType, rasn::Encode)]
struct GcmParameters {
    nonce: OctetString,
    icv_len: u8,
}

#[derive(rasn::AsnType, rasn::Encode)]
struct OaepParameters {
    #[rasn(tag(explicit(0)))]
    hash_algorithm: AlgorithmIdentifier,
    #[rasn(tag(explicit(1)))]
    mask_gen_algorithm: AlgorithmIdentifier,
}

fn encode_octet_string(value: &[u8]) -> Result<Vec<u8>, EncryptMessageError> {
    rasn::der::encode(&OctetString::from_slice(value))
        .map_err(|err| EncryptMessageError::Error(format!("Failed to encode nonce: {}", err)))
}

fn encode_null() -> Result<Vec<u8>, EncryptMessageError> {
    rasn::der::encode(&()).map_err(|err| {
        EncryptMessageError::Error(format!("Failed to encode NULL parameters: {}", err))
    })
}
