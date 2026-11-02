/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::hmac::{self, Context, Key};

use super::{PrimitiveError, hash::HashAlgorithm};

const MAX_HASH_LEN: usize = 64;
const MAX_HKDF_BLOCKS: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HkdfHash {
    Sha256,
    Sha512,
}

impl HkdfHash {
    fn algorithm(self) -> hmac::Algorithm {
        match self {
            HkdfHash::Sha256 => hmac::HMAC_SHA256,
            HkdfHash::Sha512 => hmac::HMAC_SHA512,
        }
    }

    pub(crate) fn derive(
        self,
        salt: &[u8],
        ikm: &[&[u8]],
        info: &[&[u8]],
        out: &mut [u8],
    ) -> Result<(), PrimitiveError> {
        let algorithm = self.algorithm();
        let hash_len = algorithm.digest_algorithm().output_len();
        if out.len() > MAX_HKDF_BLOCKS * hash_len {
            return Err(PrimitiveError::InvalidLength);
        }
        let zero_salt = [0u8; MAX_HASH_LEN];
        let salt = if salt.is_empty() {
            zero_salt
                .get(..hash_len)
                .ok_or(PrimitiveError::InvalidLength)?
        } else {
            salt
        };
        let mut extract = Context::with_key(&Key::new(algorithm, salt));
        for part in ikm {
            extract.update(part);
        }
        let prk = Key::new(algorithm, extract.sign().as_ref());
        let mut previous = None;
        for (counter, block) in (1u8..).zip(out.chunks_mut(hash_len)) {
            let mut expand = Context::with_key(&prk);
            if let Some(previous) = &previous {
                expand.update(AsRef::<[u8]>::as_ref(previous));
            }
            for part in info {
                expand.update(part);
            }
            expand.update(&[counter]);
            let tag = expand.sign();
            block.copy_from_slice(
                tag.as_ref()
                    .get(..block.len())
                    .ok_or(PrimitiveError::InvalidLength)?,
            );
            previous = Some(tag);
        }
        Ok(())
    }
}

pub(crate) fn x963(
    hash: HashAlgorithm,
    z: &[u8],
    shared_info: &[u8],
    out: &mut [u8],
) -> Result<(), PrimitiveError> {
    for (counter, block) in (1u32..).zip(out.chunks_mut(hash.output_len())) {
        let mut hasher = hash.hasher();
        hasher.update(z);
        hasher.update(&counter.to_be_bytes());
        hasher.update(shared_info);
        let digest = hasher.finish();
        let digest = digest
            .as_ref()
            .get(..block.len())
            .ok_or(PrimitiveError::InvalidLength)?;
        block.copy_from_slice(digest);
    }
    Ok(())
}

pub(crate) fn openpgp_ecdh(
    hash: HashAlgorithm,
    z: &[u8],
    param: &[&[u8]],
    out: &mut [u8],
) -> Result<(), PrimitiveError> {
    let mut hasher = hash.hasher();
    hasher.update(&1u32.to_be_bytes());
    hasher.update(z);
    for part in param {
        hasher.update(part);
    }
    let digest = hasher.finish();
    out.copy_from_slice(
        digest
            .as_ref()
            .get(..out.len())
            .ok_or(PrimitiveError::InvalidLength)?,
    );
    Ok(())
}
