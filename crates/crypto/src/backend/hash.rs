/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aws_lc_rs::digest::{self, Context, Digest};

use crate::mime::Sink;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl HashAlgorithm {
    pub(crate) fn algorithm(self) -> &'static digest::Algorithm {
        match self {
            HashAlgorithm::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            HashAlgorithm::Sha224 => &digest::SHA224,
            HashAlgorithm::Sha256 => &digest::SHA256,
            HashAlgorithm::Sha384 => &digest::SHA384,
            HashAlgorithm::Sha512 => &digest::SHA512,
            HashAlgorithm::Sha3_256 => &digest::SHA3_256,
            HashAlgorithm::Sha3_512 => &digest::SHA3_512,
        }
    }

    pub const fn output_len(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha224 => 28,
            HashAlgorithm::Sha256 | HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 | HashAlgorithm::Sha3_512 => 64,
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Digest {
        digest::digest(self.algorithm(), data)
    }

    pub(crate) fn hasher(self) -> Hasher {
        Hasher(Context::new(self.algorithm()))
    }
}

#[derive(Clone)]
pub(crate) struct Hasher(Context);

impl Hasher {
    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub(crate) fn finish(self) -> Digest {
        self.0.finish()
    }
}

impl Sink for Hasher {
    #[inline]
    fn put(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
