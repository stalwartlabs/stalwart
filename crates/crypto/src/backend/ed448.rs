/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ed448_goldilocks::{
    Scalar,
    curve::edwards::{CompressedEdwardsY, ExtendedPoint},
};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

use super::PrimitiveError;

pub(crate) const ED448_PUBLIC_LEN: usize = 57;
pub(crate) const ED448_SIGNATURE_LEN: usize = 114;
const DOM4_PREFIX: &[u8] = b"SigEd448\x00\x00";
const SIGN_BIT_MASK: u8 = 0x7F;

fn decode_point(bytes: &[u8; ED448_PUBLIC_LEN]) -> Option<ExtendedPoint> {
    if bytes[ED448_PUBLIC_LEN - 1] & SIGN_BIT_MASK != 0 {
        return None;
    }
    let point = CompressedEdwardsY(*bytes).decompress()?;
    (point.compress().0 == *bytes).then_some(point)
}

pub(crate) fn verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PrimitiveError> {
    let public_key: &[u8; ED448_PUBLIC_LEN] = public_key
        .try_into()
        .map_err(|_| PrimitiveError::InvalidPublicKey)?;
    let (r_bytes, s_bytes) = signature
        .split_first_chunk::<ED448_PUBLIC_LEN>()
        .ok_or(PrimitiveError::BadSignature)?;
    let s_bytes: [u8; ED448_PUBLIC_LEN] = s_bytes
        .try_into()
        .map_err(|_| PrimitiveError::BadSignature)?;
    let a = decode_point(public_key).ok_or(PrimitiveError::InvalidPublicKey)?;
    let r = decode_point(r_bytes).ok_or(PrimitiveError::BadSignature)?;
    let s = Scalar::from_canonical_bytes(s_bytes).ok_or(PrimitiveError::BadSignature)?;

    let mut shake = Shake256::default();
    shake.update(DOM4_PREFIX);
    shake.update(r_bytes);
    shake.update(public_key);
    shake.update(message);
    let mut wide = [0u8; ED448_SIGNATURE_LEN];
    shake.finalize_xof().read(&mut wide);
    let k = Scalar::from_bytes_mod_order_wide(&wide);

    let lhs = ExtendedPoint::generator().scalar_mul(&s);
    let rhs = r.add(&a.scalar_mul(&k));
    if lhs.add(&rhs.negate()).double().double() == ExtendedPoint::identity() {
        Ok(())
    } else {
        Err(PrimitiveError::BadSignature)
    }
}
