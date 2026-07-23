/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::{
    enums::{DkimRotationStage, DkimSignatureType},
    prelude::{DkimSignature, UTCDateTime},
};
use types::id::Id;

impl DkimSignature {
    pub fn rotation_due(&self) -> Option<DkimRotationStage> {
        let (stage, next_transition) = match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => (sign.stage, sign.next_transition_at),
            DkimSignature::Dkim1RsaSha256(sign) => (sign.stage, sign.next_transition_at),
            DkimSignature::Dkim2Ed25519Sha256(sign) => (sign.stage, sign.next_transition_at),
            DkimSignature::Dkim2RsaSha256(sign) => (sign.stage, sign.next_transition_at),
        };
        next_transition.and_then(|next_transition| {
            if next_transition <= UTCDateTime::now() {
                Some(stage)
            } else {
                None
            }
        })
    }

    pub fn next_transition(&self) -> Option<UTCDateTime> {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => sign.next_transition_at,
            DkimSignature::Dkim1RsaSha256(sign) => sign.next_transition_at,
            DkimSignature::Dkim2Ed25519Sha256(sign) => sign.next_transition_at,
            DkimSignature::Dkim2RsaSha256(sign) => sign.next_transition_at,
        }
    }

    pub fn set_next_transition(&mut self, next_transition: UTCDateTime) {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => {
                sign.next_transition_at = Some(next_transition)
            }
            DkimSignature::Dkim1RsaSha256(sign) => sign.next_transition_at = Some(next_transition),
            DkimSignature::Dkim2Ed25519Sha256(sign) => {
                sign.next_transition_at = Some(next_transition)
            }
            DkimSignature::Dkim2RsaSha256(sign) => sign.next_transition_at = Some(next_transition),
        }
    }

    pub fn stage(&self) -> DkimRotationStage {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => sign.stage,
            DkimSignature::Dkim1RsaSha256(sign) => sign.stage,
            DkimSignature::Dkim2Ed25519Sha256(sign) => sign.stage,
            DkimSignature::Dkim2RsaSha256(sign) => sign.stage,
        }
    }

    pub fn set_stage(&mut self, stage: DkimRotationStage) {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => sign.stage = stage,
            DkimSignature::Dkim1RsaSha256(sign) => sign.stage = stage,
            DkimSignature::Dkim2Ed25519Sha256(sign) => sign.stage = stage,
            DkimSignature::Dkim2RsaSha256(sign) => sign.stage = stage,
        }
    }

    pub fn is_active(&self) -> bool {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => sign.stage == DkimRotationStage::Active,
            DkimSignature::Dkim1RsaSha256(sign) => sign.stage == DkimRotationStage::Active,
            DkimSignature::Dkim2Ed25519Sha256(sign) => sign.stage == DkimRotationStage::Active,
            DkimSignature::Dkim2RsaSha256(sign) => sign.stage == DkimRotationStage::Active,
        }
    }

    pub fn selector(&self) -> &str {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => &sign.selector,
            DkimSignature::Dkim1RsaSha256(sign) => &sign.selector,
            DkimSignature::Dkim2Ed25519Sha256(sign) => &sign.selector,
            DkimSignature::Dkim2RsaSha256(sign) => &sign.selector,
        }
    }

    pub fn domain_id(&self) -> Id {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(sign) => sign.domain_id,
            DkimSignature::Dkim1RsaSha256(sign) => sign.domain_id,
            DkimSignature::Dkim2Ed25519Sha256(sign) => sign.domain_id,
            DkimSignature::Dkim2RsaSha256(sign) => sign.domain_id,
        }
    }
}

impl DkimSignatureType {
    pub const fn algorithm(self) -> &'static str {
        match self {
            Self::Dkim1Ed25519Sha256 | Self::Dkim2Ed25519Sha256 => "ed25519",
            Self::Dkim1RsaSha256 | Self::Dkim2RsaSha256 => "rsa",
        }
    }

    pub const fn hash(self) -> &'static str {
        "sha256"
    }

    pub const fn version(self) -> &'static str {
        match self {
            Self::Dkim1Ed25519Sha256 | Self::Dkim1RsaSha256 => "1",
            Self::Dkim2Ed25519Sha256 | Self::Dkim2RsaSha256 => "2",
        }
    }
}
