/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::{
    digest::Digest,
    signature::{
        ECDSA_P256_SHA1_ASN1, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA384_ASN1,
        ECDSA_P256_SHA512_ASN1, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
        ECDSA_P384_SHA512_ASN1, ECDSA_P521_SHA1_ASN1, ECDSA_P521_SHA224_ASN1,
        ECDSA_P521_SHA256_ASN1, ECDSA_P521_SHA384_ASN1, ECDSA_P521_SHA512_ASN1, ED25519, ML_DSA_44,
        ML_DSA_65, ML_DSA_87, RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
        UnparsedPublicKey, VerificationAlgorithm,
    },
};

use super::{PrimitiveError, hash::HashAlgorithm};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MlDsa {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    RsaPkcs1(HashAlgorithm),
    RsaPss(HashAlgorithm),
    Ecdsa(EcCurve, HashAlgorithm),
    Ed25519,
    Ed448,
    MlDsa(MlDsa),
}

impl SignatureScheme {
    fn algorithm(self) -> Result<&'static dyn VerificationAlgorithm, PrimitiveError> {
        use EcCurve::*;
        use HashAlgorithm::*;
        Ok(match self {
            SignatureScheme::RsaPkcs1(Sha1) => &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            SignatureScheme::RsaPkcs1(Sha256) => &RSA_PKCS1_2048_8192_SHA256,
            SignatureScheme::RsaPkcs1(Sha384) => &RSA_PKCS1_2048_8192_SHA384,
            SignatureScheme::RsaPkcs1(Sha512) => &RSA_PKCS1_2048_8192_SHA512,
            SignatureScheme::RsaPss(Sha256) => &RSA_PSS_2048_8192_SHA256,
            SignatureScheme::RsaPss(Sha384) => &RSA_PSS_2048_8192_SHA384,
            SignatureScheme::RsaPss(Sha512) => &RSA_PSS_2048_8192_SHA512,
            SignatureScheme::Ecdsa(P256, Sha1) => &ECDSA_P256_SHA1_ASN1,
            SignatureScheme::Ecdsa(P256, Sha256) => &ECDSA_P256_SHA256_ASN1,
            SignatureScheme::Ecdsa(P256, Sha384) => &ECDSA_P256_SHA384_ASN1,
            SignatureScheme::Ecdsa(P256, Sha512) => &ECDSA_P256_SHA512_ASN1,
            SignatureScheme::Ecdsa(P384, Sha256) => &ECDSA_P384_SHA256_ASN1,
            SignatureScheme::Ecdsa(P384, Sha384) => &ECDSA_P384_SHA384_ASN1,
            SignatureScheme::Ecdsa(P384, Sha512) => &ECDSA_P384_SHA512_ASN1,
            SignatureScheme::Ecdsa(P521, Sha1) => &ECDSA_P521_SHA1_ASN1,
            SignatureScheme::Ecdsa(P521, Sha224) => &ECDSA_P521_SHA224_ASN1,
            SignatureScheme::Ecdsa(P521, Sha256) => &ECDSA_P521_SHA256_ASN1,
            SignatureScheme::Ecdsa(P521, Sha384) => &ECDSA_P521_SHA384_ASN1,
            SignatureScheme::Ecdsa(P521, Sha512) => &ECDSA_P521_SHA512_ASN1,
            SignatureScheme::Ed25519 => &ED25519,
            SignatureScheme::MlDsa(MlDsa::MlDsa44) => &ML_DSA_44,
            SignatureScheme::MlDsa(MlDsa::MlDsa65) => &ML_DSA_65,
            SignatureScheme::MlDsa(MlDsa::MlDsa87) => &ML_DSA_87,
            _ => return Err(PrimitiveError::UnsupportedAlgorithm),
        })
    }

    pub(crate) fn verify(
        self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), PrimitiveError> {
        if self == SignatureScheme::Ed448 {
            return super::ed448::verify(public_key, message, signature);
        }
        UnparsedPublicKey::new(self.algorithm()?, public_key)
            .verify(message, signature)
            .map_err(|_| PrimitiveError::BadSignature)
    }

    pub(crate) fn verify_digest(
        self,
        public_key: &[u8],
        digest: &Digest,
        signature: &[u8],
    ) -> Result<(), PrimitiveError> {
        match self {
            SignatureScheme::Ed25519 | SignatureScheme::Ed448 | SignatureScheme::MlDsa(_) => {
                self.verify(public_key, digest.as_ref(), signature)
            }
            _ => UnparsedPublicKey::new(self.algorithm()?, public_key)
                .verify_digest(digest, signature)
                .map_err(|_| PrimitiveError::BadSignature),
        }
    }
}
