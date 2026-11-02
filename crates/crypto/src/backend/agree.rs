/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::agreement::{
    self, ECDH_P256, ECDH_P384, ECDH_P521, ParsedPublicKey, PrivateKey, UnparsedPublicKey, X25519,
};
use ed448_goldilocks::{Scalar, curve::MontgomeryPoint};
use zeroize::Zeroizing;

use super::{PrimitiveError, rng::Rng};

pub(crate) const MAX_PUBLIC_LEN: usize = 133;
pub(crate) const MAX_SHARED_LEN: usize = 66;
const X448_LEN: usize = 56;
const MAX_SCALAR_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    P256,
    P384,
    P521,
    X25519,
    X448,
}

impl Curve {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
            Curve::X25519 => "X25519",
            Curve::X448 => "X448",
        }
    }
}

impl Curve {
    pub const fn shared_len(self) -> usize {
        match self {
            Curve::P256 | Curve::X25519 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
            Curve::X448 => X448_LEN,
        }
    }

    pub const fn public_len(self) -> usize {
        match self {
            Curve::P256 => 65,
            Curve::P384 => 97,
            Curve::P521 => 133,
            Curve::X25519 => 32,
            Curve::X448 => X448_LEN,
        }
    }

    const fn scalar_len(self) -> usize {
        match self {
            Curve::P521 => 66,
            _ => self.shared_len(),
        }
    }

    fn aws_algorithm(self) -> Option<&'static agreement::Algorithm> {
        match self {
            Curve::P256 => Some(&ECDH_P256),
            Curve::P384 => Some(&ECDH_P384),
            Curve::P521 => Some(&ECDH_P521),
            Curve::X25519 => Some(&X25519),
            Curve::X448 => None,
        }
    }

    pub(crate) fn validate_public(self, public: &[u8]) -> Result<(), PrimitiveError> {
        if public.len() != self.public_len() {
            return Err(PrimitiveError::InvalidPublicKey);
        }
        match self.aws_algorithm() {
            Some(alg) => ParsedPublicKey::try_from(UnparsedPublicKey::new(alg, public))
                .map(|_| ())
                .map_err(|_| PrimitiveError::InvalidPublicKey),
            None => Ok(()),
        }
    }

    pub(crate) fn ephemeral_agree(
        self,
        peer_public: &[u8],
        rng: &mut impl Rng,
    ) -> Result<Agreement, PrimitiveError> {
        let mut agreement = Agreement {
            curve: self,
            public: [0u8; MAX_PUBLIC_LEN],
            shared: Zeroizing::new([0u8; MAX_SHARED_LEN]),
        };
        match self.aws_algorithm() {
            Some(alg) => {
                let private = self.random_private_key(alg, rng)?;
                let public = private
                    .compute_public_key()
                    .map_err(|_| PrimitiveError::KeyAgreement)?;
                agreement
                    .public
                    .get_mut(..self.public_len())
                    .filter(|_| public.as_ref().len() == self.public_len())
                    .ok_or(PrimitiveError::KeyAgreement)?
                    .copy_from_slice(public.as_ref());
                let shared = agreement
                    .shared
                    .get_mut(..self.shared_len())
                    .ok_or(PrimitiveError::KeyAgreement)?;
                agreement::agree(
                    &private,
                    UnparsedPublicKey::new(alg, peer_public),
                    PrimitiveError::KeyAgreement,
                    |z| {
                        if z.len() == shared.len() {
                            shared.copy_from_slice(z);
                            Ok(())
                        } else {
                            Err(PrimitiveError::KeyAgreement)
                        }
                    },
                )?;
            }
            None => {
                let peer: [u8; X448_LEN] = peer_public
                    .try_into()
                    .map_err(|_| PrimitiveError::InvalidPublicKey)?;
                let mut secret = Zeroizing::new([0u8; X448_LEN]);
                rng.fill(secret.as_mut())?;
                secret[0] &= 252;
                secret[X448_LEN - 1] |= 128;
                let scalar = Scalar::from_bytes(*secret);
                let public = &MontgomeryPoint::generator() * &scalar;
                let shared = &MontgomeryPoint(peer) * &scalar;
                if shared.0.iter().all(|b| *b == 0) {
                    return Err(PrimitiveError::KeyAgreement);
                }
                agreement.public[..X448_LEN].copy_from_slice(&public.0);
                agreement.shared[..X448_LEN].copy_from_slice(&shared.0);
            }
        }
        Ok(agreement)
    }

    fn random_private_key(
        self,
        alg: &'static agreement::Algorithm,
        rng: &mut impl Rng,
    ) -> Result<PrivateKey, PrimitiveError> {
        let mut scalar = Zeroizing::new([0u8; MAX_SHARED_LEN]);
        let scalar = scalar
            .get_mut(..self.scalar_len())
            .ok_or(PrimitiveError::KeyAgreement)?;
        for _ in 0..MAX_SCALAR_ATTEMPTS {
            rng.fill(scalar)?;
            if self == Curve::P521
                && let Some(first) = scalar.first_mut()
            {
                *first &= 0x01;
            }
            if let Ok(key) = PrivateKey::from_private_key(alg, scalar) {
                return Ok(key);
            }
        }
        Err(PrimitiveError::KeyAgreement)
    }
}

pub(crate) struct Agreement {
    curve: Curve,
    public: [u8; MAX_PUBLIC_LEN],
    shared: Zeroizing<[u8; MAX_SHARED_LEN]>,
}

impl Agreement {
    pub(crate) fn public(&self) -> &[u8] {
        &self.public[..self.curve.public_len()]
    }

    pub(crate) fn shared(&self) -> &[u8] {
        &self.shared[..self.curve.shared_len()]
    }
}
