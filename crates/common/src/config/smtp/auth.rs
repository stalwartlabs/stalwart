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
use mail_auth::{
    common::crypto::{Ed25519Key, HashAlgorithm, RsaKey, Sha256, SigningKey},
    dkim::{Canonicalization, Done},
    dkim2::{Dkim2Signer, Done as Dkim2Done, Flag},
};
use encodify::{Error as CodecError, base64::LENIENT, pem};
use registry::{
    schema::{
        enums::{self, Dkim2Flag, ExpressionConstant},
        prelude::ObjectType,
        structs::{Dkim1Signature, DkimSignature, SenderAuth},
    },
    types::{ObjectImpl, map::Map},
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, pem::PemObject};
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
    //pub seal: IfBlock,
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
    RsaSha256(mail_auth::dkim::DkimSigner<RsaKey<Sha256>, Done>),
    Ed25519Sha256(mail_auth::dkim::DkimSigner<Ed25519Key, Done>),
}

#[derive(Default)]
pub struct DkimSigners {
    pub dkim1: Vec<Dkim1Signer>,
    pub dkim2: Option<Dkim2Signer<Dkim2Done>>,
}

impl MailAuthConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let auth = bp.setting_infallible::<SenderAuth>().await;

        MailAuthConfig {
            dkim: DkimAuthConfig {
                verify: bp
                    .compile_expr(ObjectType::SenderAuth.singleton(), &auth.ctx_dkim_verify()),
                sign: bp.compile_expr(
                    ObjectType::SenderAuth.singleton(),
                    &auth.ctx_dkim_sign_domain(),
                ),
                strict: auth.dkim_strict,
            },
            arc: ArcAuthConfig {
                verify: bp.compile_expr(ObjectType::SenderAuth.singleton(), &auth.ctx_arc_verify()),
                //seal: bp.compile_expr(ObjectType::SenderAuth.singleton(), &auth.ctx_arc_seal_domain()),
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
                let private_key = signature
                    .private_key
                    .secret()
                    .await
                    .map_err(|err| trc::DkimEvent::BuildError.reason(err))?;
                let private_key = pem_or_base64_decode(&private_key).map_err(|_| {
                    trc::DkimEvent::BuildError
                        .reason("Failed to parse ED25519 private key PEM")
                        .details("Invalid PEM format")
                })?;
                let key =
                    Ed25519Key::from_pkcs8_maybe_unchecked_der(&private_key).map_err(|err| {
                        trc::DkimEvent::BuildError
                            .reason(err)
                            .details("Failed to build ED25519 key")
                    })?;

                self.dkim1
                    .push(Dkim1Signer::Ed25519Sha256(build_dkim1_signer(
                        domain, signature, key,
                    )));
            }
            DkimSignature::Dkim1RsaSha256(signature) => {
                let private_key = signature
                    .private_key
                    .secret()
                    .await
                    .map_err(|err| trc::DkimEvent::BuildError.reason(err))?;
                let key = rsa_key_parse(private_key.as_bytes())?;

                self.dkim1.push(Dkim1Signer::RsaSha256(build_dkim1_signer(
                    domain, signature, key,
                )));
            }
            DkimSignature::Dkim2Ed25519Sha256(signature) => {
                let private_key = signature
                    .private_key
                    .secret()
                    .await
                    .map_err(|err| trc::DkimEvent::BuildError.reason(err))?;
                let private_key = pem_or_base64_decode(&private_key).map_err(|_| {
                    trc::DkimEvent::BuildError
                        .reason("Failed to parse ED25519 private key PEM")
                        .details("Invalid PEM format")
                })?;
                let key =
                    Ed25519Key::from_pkcs8_maybe_unchecked_der(&private_key).map_err(|err| {
                        trc::DkimEvent::BuildError
                            .reason(err)
                            .details("Failed to build ED25519 key")
                    })?;

                self.dkim2 = Some(match self.dkim2.take() {
                    None => Dkim2Signer::from_key(key)
                        .domain(domain)
                        .selector(signature.selector)
                        .flags(map_dkim2_flags(signature.flags)),
                    Some(signer) => signer
                        .additional_key(key, signature.selector)
                        .flags(map_dkim2_flags(signature.flags)),
                });
            }
            DkimSignature::Dkim2RsaSha256(signature) => {
                let private_key = signature
                    .private_key
                    .secret()
                    .await
                    .map_err(|err| trc::DkimEvent::BuildError.reason(err))?;
                let key = rsa_key_parse(private_key.as_bytes())?;

                self.dkim2 = Some(match self.dkim2.take() {
                    None => Dkim2Signer::from_key(key)
                        .domain(domain)
                        .selector(signature.selector)
                        .flags(map_dkim2_flags(signature.flags)),
                    Some(signer) => signer
                        .additional_key(key, signature.selector)
                        .flags(map_dkim2_flags(signature.flags)),
                });
            }
        }

        Ok(())
    }
}

fn map_dkim2_flags(flags: Map<enums::Dkim2Flag>) -> impl Iterator<Item = Flag> {
    flags.into_inner().into_iter().map(|flag| match flag {
        Dkim2Flag::Donotmodify => Flag::DoNotModify,
        Dkim2Flag::Donotexplode => Flag::DoNotExplode,
        Dkim2Flag::Feedback => Flag::Feedback,
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
) -> mail_auth::dkim::DkimSigner<T, Done> {
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
        signer = signer.expiration(expire.into_inner().as_secs());
    }

    if let Some(auid) = signature.auid {
        signer = signer.agent_user_identifier(auid);
    }

    if let Some(atps) = signature.third_party {
        signer = signer.atps(atps);
    }

    if let Some(atpsh) = signature.third_party_hash {
        signer = signer.atpsh(match atpsh {
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

impl CacheItemWeight for Dkim1Signer {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Self>() as u64
    }
}

impl CacheItemWeight for DkimSigners {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<Self>()
            + self.dkim1.len() * std::mem::size_of::<Dkim1Signer>()
            + std::mem::size_of::<Dkim2Signer<Dkim2Done>>()) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::pem_or_base64_decode;
    use mail_auth::{common::crypto::Ed25519Key, dkim::generate::DkimKeyPair};
    use encodify::{
        base64::{LineEnding, MIME, STANDARD},
        pem,
    };

    #[test]
    fn ed25519_keys_decode_from_pem_or_bare_base64() {
        let key_pair = DkimKeyPair::generate_ed25519().unwrap();
        let der = key_pair.private_key();
        let bare = STANDARD.encode(der);

        for text in [
            pem::STANDARD.encode("PRIVATE KEY", der),
            pem::STANDARD
                .with_ending(LineEnding::CrLf)
                .encode("PRIVATE KEY", der),
            bare.clone(),
            format!("\n  {bare}\n"),
            MIME.encode(der),
        ] {
            let decoded = pem_or_base64_decode(&text).unwrap();
            assert_eq!(decoded, der, "{text:?}");
            assert!(Ed25519Key::from_pkcs8_maybe_unchecked_der(&decoded).is_ok());
        }

        for text in [
            "",
            "not base64!",
            "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(
                pem_or_base64_decode(text)
                    .ok()
                    .and_then(|der| Ed25519Key::from_pkcs8_maybe_unchecked_der(&der).ok())
                    .is_none(),
                "{text:?}"
            );
        }
    }
}
