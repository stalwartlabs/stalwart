/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::expr::{
    self,
    if_block::{BootstrapExprExt, IfBlock},
};
use compact_str::ToCompactString;
use encodify::{Error as CodecError, base64::LENIENT, pem};
use mail_auth::{
    crypto::{DkimKey, Ed25519Key, HashAlgorithm, MlDsa44Key, RsaKey, Sha256, SigningKey},
    dkim::Canonicalization,
    dkim2::{Dkim2Hash, Dkim2Signer, Flag},
    signer::Ready,
};
use registry::{
    schema::{
        enums::{self, Dkim2Flag, Dkim2HashAlgorithm, ExpressionConstant},
        prelude::ObjectType,
        structs::{
            Dkim1Signature, Dkim2Signature, DkimSignature, MtaStageData, SecretText, SenderAuth,
        },
    },
    types::ObjectImpl,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use std::borrow::Cow;
use store::registry::bootstrap::Bootstrap;
use utils::cache::CacheItemWeight;

#[derive(Clone)]
pub struct MailAuthConfig {
    pub dkim: DkimAuthConfig,
    pub arc: ArcAuthConfig,
    pub spf: SpfAuthConfig,
    pub dmarc: DmarcAuthConfig,
    pub iprev: IpRevAuthConfig,
}

#[derive(Clone)]
pub struct DkimAuthConfig {
    pub verify: IfBlock,
    pub sign: IfBlock,
    pub strict: bool,
}

#[derive(Clone)]
pub struct ArcAuthConfig {
    pub verify: IfBlock,
}

#[derive(Clone)]
pub struct SpfAuthConfig {
    pub verify_ehlo: IfBlock,
    pub verify_mail_from: IfBlock,
}

#[derive(Clone)]
pub struct DmarcAuthConfig {
    pub verify: IfBlock,
}

#[derive(Clone)]
pub struct IpRevAuthConfig {
    pub verify: IfBlock,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum VerifyStrategy {
    #[default]
    Relaxed,
    Strict,
    Disable,
}

pub enum Dkim1Signer {
    RsaSha256(mail_auth::dkim::DkimSigner<RsaKey<Sha256>, Ready>),
    Ed25519Sha256(mail_auth::dkim::DkimSigner<Ed25519Key, Ready>),
}

pub struct Dkim2Signers {
    pub signer: Dkim2Signer<Ready>,
    pub hashes: Vec<Dkim2Hash>,
}

#[derive(Default)]
pub struct DkimSigners {
    pub dkim1: Vec<Dkim1Signer>,
    pub dkim2: Option<Dkim2Signers>,
}

impl MailAuthConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let auth = bp.setting_infallible::<SenderAuth>().await;
        let data = bp.setting_infallible::<MtaStageData>().await;

        MailAuthConfig {
            dkim: DkimAuthConfig {
                verify: bp
                    .compile_expr(ObjectType::SenderAuth.singleton(), &auth.ctx_dkim_verify()),
                sign: bp.compile_expr(
                    ObjectType::MtaStageData.singleton(),
                    &data.ctx_dkim_sign_domain(),
                ),
                strict: auth.dkim_strict,
            },
            arc: ArcAuthConfig {
                verify: bp.compile_expr(ObjectType::SenderAuth.singleton(), &auth.ctx_arc_verify()),
            },
            spf: SpfAuthConfig {
                verify_ehlo: bp.compile_expr(
                    ObjectType::SenderAuth.singleton(),
                    &auth.ctx_spf_ehlo_verify(),
                ),
                verify_mail_from: bp.compile_expr(
                    ObjectType::SenderAuth.singleton(),
                    &auth.ctx_spf_from_verify(),
                ),
            },
            dmarc: DmarcAuthConfig {
                verify: bp
                    .compile_expr(ObjectType::SenderAuth.singleton(), &auth.ctx_dmarc_verify()),
            },
            iprev: IpRevAuthConfig {
                verify: bp.compile_expr(
                    ObjectType::SenderAuth.singleton(),
                    &auth.ctx_reverse_ip_verify(),
                ),
            },
        }
    }
}

impl DkimSigners {
    pub async fn insert(&mut self, domain: String, signature: DkimSignature) -> trc::Result<()> {
        let mut errors = vec![];
        if !signature.validate(&mut errors) {
            return Err(trc::DkimEvent::BuildError
                .reason("DKIM signature validation failed")
                .details(
                    errors
                        .into_iter()
                        .map(|v| trc::Value::from(v.to_compact_string()))
                        .collect::<Vec<_>>(),
                ));
        }

        match signature {
            DkimSignature::Dkim1Ed25519Sha256(signature) => {
                let key = ed25519_key_parse(&private_key(&signature.private_key).await?)?;
                self.dkim1
                    .push(Dkim1Signer::Ed25519Sha256(build_dkim1_signer(
                        domain, signature, key,
                    )));
            }
            DkimSignature::Dkim1RsaSha256(signature) => {
                let key = rsa_key_parse(private_key(&signature.private_key).await?.as_bytes())?;
                self.dkim1.push(Dkim1Signer::RsaSha256(build_dkim1_signer(
                    domain, signature, key,
                )));
            }
            DkimSignature::Dkim2Ed25519Sha256(signature) => {
                self.insert_dkim2(domain, signature, |pem| {
                    ed25519_key_parse(pem).map(DkimKey::from)
                })
                .await?;
            }
            DkimSignature::Dkim2RsaSha256(signature) => {
                self.insert_dkim2(domain, signature, |pem| {
                    rsa_key_parse(pem.as_bytes()).map(DkimKey::from)
                })
                .await?;
            }
            DkimSignature::Dkim2MlDsa44(signature) => {
                self.insert_dkim2(domain, signature, |pem| {
                    mldsa44_key_parse(pem).map(DkimKey::from)
                })
                .await?;
            }
        }

        Ok(())
    }

    async fn insert_dkim2(
        &mut self,
        domain: String,
        signature: Dkim2Signature,
        parse_key: fn(&str) -> trc::Result<DkimKey>,
    ) -> trc::Result<()> {
        let key = parse_key(&private_key(&signature.private_key).await?)?;
        let flags = signature
            .flags
            .into_inner()
            .into_iter()
            .map(|flag| match flag {
                Dkim2Flag::Feedback => Flag::Feedback,
            });
        let hashes = signature
            .instance_hashes
            .into_inner()
            .into_iter()
            .map(|hash| match hash {
                Dkim2HashAlgorithm::Sha256 => Dkim2Hash::Sha256,
                Dkim2HashAlgorithm::Sha512 => Dkim2Hash::Sha512,
            });

        let (signer, mut all_hashes) = match self.dkim2.take() {
            None => (
                Dkim2Signer::from_key(key)
                    .domain(domain)
                    .selector(signature.selector),
                Vec::with_capacity(2),
            ),
            Some(signers) => (
                signers.signer.additional_key(key, signature.selector),
                signers.hashes,
            ),
        };
        for hash in hashes {
            if !all_hashes.contains(&hash) {
                all_hashes.push(hash);
            }
        }
        if all_hashes.is_empty() {
            all_hashes.push(Dkim2Hash::Sha256);
        }

        self.dkim2 = Some(Dkim2Signers {
            signer: signer.flags(flags).hashes(all_hashes.iter().copied()),
            hashes: all_hashes,
        });

        Ok(())
    }
}

async fn private_key(secret: &SecretText) -> trc::Result<Cow<'_, str>> {
    secret
        .secret()
        .await
        .map_err(|err| trc::DkimEvent::BuildError.reason(err))
}

fn ed25519_key_parse(pem: &str) -> trc::Result<Ed25519Key> {
    let der = pem_or_base64_decode(pem).map_err(|_| {
        trc::DkimEvent::BuildError
            .reason("Failed to parse ED25519 private key PEM")
            .details("Invalid PEM format")
    })?;
    Ed25519Key::from_pkcs8_maybe_unchecked_der(&der).map_err(|err| {
        trc::DkimEvent::BuildError
            .reason(err)
            .details("Failed to build ED25519 key")
    })
}

fn mldsa44_key_parse(pem: &str) -> trc::Result<MlDsa44Key> {
    let der = pem_or_base64_decode(pem).map_err(|_| {
        trc::DkimEvent::BuildError
            .reason("Failed to parse ML-DSA-44 private key PEM")
            .details("Invalid PEM format")
    })?;
    MlDsa44Key::from_pkcs8_der(&der).map_err(|err| {
        trc::DkimEvent::BuildError
            .reason(err)
            .details("Failed to build ML-DSA-44 key")
    })
}

pub fn rsa_key_parse(private_key: &[u8]) -> trc::Result<RsaKey<Sha256>> {
    PrivatePkcs1KeyDer::from_pem_slice(private_key)
        .map(PrivateKeyDer::Pkcs1)
        .or_else(|_| PrivatePkcs8KeyDer::from_pem_slice(private_key).map(PrivateKeyDer::Pkcs8))
        .map_err(|err| {
            trc::DkimEvent::BuildError
                .reason(err)
                .details("Failed to build RSA key")
        })
        .and_then(|key| {
            RsaKey::<Sha256>::from_key_der(key).map_err(|err| {
                trc::DkimEvent::BuildError
                    .reason(err)
                    .details("Failed to build RSA key")
            })
        })
}

pub fn pem_or_base64_decode(contents: &str) -> Result<Vec<u8>, CodecError> {
    match pem::STANDARD.decode(contents.as_bytes()) {
        Ok(block) => Ok(block.contents),
        Err(CodecError::NotFound) => LENIENT.decode(contents),
        Err(err) => Err(err),
    }
}

fn build_dkim1_signer<T: SigningKey>(
    domain: String,
    signature: Dkim1Signature,
    key: T,
) -> mail_auth::dkim::DkimSigner<T, Ready> {
    let mut signer = mail_auth::dkim::DkimSigner::from_key(key)
        .domain(domain)
        .selector(signature.selector)
        .headers(signature.headers)
        .reporting(signature.report);

    match signature.canonicalization {
        enums::DkimCanonicalization::RelaxedRelaxed => {
            signer = signer
                .body_canonicalization(Canonicalization::Relaxed)
                .header_canonicalization(Canonicalization::Relaxed);
        }
        enums::DkimCanonicalization::SimpleSimple => {
            signer = signer
                .body_canonicalization(Canonicalization::Simple)
                .header_canonicalization(Canonicalization::Simple);
        }
        enums::DkimCanonicalization::RelaxedSimple => {
            signer = signer
                .body_canonicalization(Canonicalization::Simple)
                .header_canonicalization(Canonicalization::Relaxed);
        }
        enums::DkimCanonicalization::SimpleRelaxed => {
            signer = signer
                .body_canonicalization(Canonicalization::Relaxed)
                .header_canonicalization(Canonicalization::Simple);
        }
    }

    if let Some(expire) = signature.expire {
        signer = signer.expiration(expire.into_inner());
    }

    if let Some(auid) = signature.auid {
        signer = signer.identity(auid);
    }

    if let Some(atps) = signature.third_party {
        signer = signer.atps(atps);
    }

    if let Some(atpsh) = signature.third_party_hash {
        signer = signer.atps_hash(match atpsh {
            enums::DkimHash::Sha256 => HashAlgorithm::Sha256,
            enums::DkimHash::Sha1 => HashAlgorithm::Sha1,
        });
    }
    signer
}

impl<'x> TryFrom<expr::Variable<'x>> for VerifyStrategy {
    type Error = ();

    fn try_from(value: expr::Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            expr::Variable::Constant(c) => match c {
                ExpressionConstant::Relaxed => Ok(VerifyStrategy::Relaxed),
                ExpressionConstant::Strict => Ok(VerifyStrategy::Strict),
                ExpressionConstant::Disable => Ok(VerifyStrategy::Disable),
                _ => Err(()),
            },
            _ => Err(()),
        }
    }
}

impl VerifyStrategy {
    #[inline(always)]
    pub fn verify(&self) -> bool {
        matches!(self, VerifyStrategy::Strict | VerifyStrategy::Relaxed)
    }

    #[inline(always)]
    pub fn is_strict(&self) -> bool {
        matches!(self, VerifyStrategy::Strict)
    }
}

impl Dkim1Signer {
    fn heap_size(&self) -> usize {
        match self {
            Dkim1Signer::RsaSha256(signer) => signer.heap_size(),
            Dkim1Signer::Ed25519Sha256(signer) => signer.heap_size(),
        }
    }
}

impl CacheItemWeight for Dkim1Signer {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<Self>() + self.heap_size()) as u64
    }
}

impl CacheItemWeight for DkimSigners {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<Self>()
            + self.dkim1.capacity() * std::mem::size_of::<Dkim1Signer>()
            + self.dkim1.iter().map(Dkim1Signer::heap_size).sum::<usize>()
            + self.dkim2.as_ref().map_or(0, |dkim2| {
                dkim2.signer.heap_size()
                    + dkim2.hashes.capacity() * std::mem::size_of::<Dkim2Hash>()
            })) as u64
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/config/smtp/auth/tests.rs"]
mod tests;
