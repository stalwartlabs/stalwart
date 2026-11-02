/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    PrimitiveError,
    aes::{AesCipher, BLOCK_LEN},
};

pub(crate) const OCB_TAG_LEN: usize = 16;
pub(crate) const OCB_MAX_NONCE_LEN: usize = 15;
const L_TABLE_LEN: usize = 32;
const PAD_MARKER: u8 = 0x80;

pub(crate) struct OcbKey {
    cipher: AesCipher,
    l_star: u128,
    l_dollar: u128,
    l: [u128; L_TABLE_LEN],
}

#[inline(always)]
fn load(block: &[u8; BLOCK_LEN]) -> u128 {
    u128::from_ne_bytes(*block)
}

fn double(value: u128) -> u128 {
    let v = u128::from_be_bytes(value.to_ne_bytes());
    let doubled = (v << 1) ^ ((v >> 127) * 0x87);
    u128::from_ne_bytes(doubled.to_be_bytes())
}

impl OcbKey {
    pub(crate) fn new(key: &[u8]) -> Result<Self, PrimitiveError> {
        let mut ocb = OcbKey {
            cipher: AesCipher::new(key)?,
            l_star: 0,
            l_dollar: 0,
            l: [0u128; L_TABLE_LEN],
        };
        ocb.l_star = ocb.encipher(0);
        ocb.l_dollar = double(ocb.l_star);
        let mut acc = ocb.l_dollar;
        for entry in ocb.l.iter_mut() {
            acc = double(acc);
            *entry = acc;
        }
        Ok(ocb)
    }

    fn encipher(&self, value: u128) -> u128 {
        let mut block = value.to_ne_bytes();
        self.cipher.encrypt_block(&mut block);
        load(&block)
    }

    #[inline(always)]
    fn l_at(&self, index: u64) -> u128 {
        self.l[index.trailing_zeros() as usize & (L_TABLE_LEN - 1)]
    }

    fn initial_offset(&self, nonce: &[u8]) -> Result<u128, PrimitiveError> {
        if nonce.is_empty() || nonce.len() > OCB_MAX_NONCE_LEN {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut block = [0u8; BLOCK_LEN];
        let (head, tail) = block.split_at_mut(BLOCK_LEN - nonce.len());
        tail.copy_from_slice(nonce);
        if let Some(marker) = head.last_mut() {
            *marker |= 1;
        }
        let bottom = u32::from(block[BLOCK_LEN - 1] & 0x3F);
        block[BLOCK_LEN - 1] &= 0xC0;
        self.cipher.encrypt_block(&mut block);
        let ktop = u128::from_be_bytes(block);
        let stretch = ((ktop >> 64) as u64) ^ ((ktop >> 56) as u64);
        let offset = if bottom == 0 {
            ktop
        } else {
            (ktop << bottom) | (u128::from(stretch) >> (64 - bottom))
        };
        Ok(u128::from_ne_bytes(offset.to_be_bytes()))
    }

    pub(crate) fn hash(&self, ad: &[u8]) -> u128 {
        let (blocks, tail) = ad.as_chunks::<BLOCK_LEN>();
        let mut offset = 0u128;
        let mut sum = 0u128;
        for (i, block) in (1u64..).zip(blocks) {
            offset ^= self.l_at(i);
            sum ^= self.encipher(load(block) ^ offset);
        }
        if !tail.is_empty() {
            offset ^= self.l_star;
            sum ^= self.encipher(load(&padded(tail)) ^ offset);
        }
        sum
    }

    pub(crate) fn seal_in_place(
        &self,
        nonce: &[u8],
        ad_hash: u128,
        data: &mut [u8],
    ) -> Result<[u8; OCB_TAG_LEN], PrimitiveError> {
        let initial = self.initial_offset(nonce)?;
        let (blocks, tail) = data.as_chunks_mut::<BLOCK_LEN>();
        let mut checksum = 0u128;
        let mut offset = initial;
        for (i, block) in (1u64..).zip(blocks.iter_mut()) {
            offset ^= self.l_at(i);
            let plain = load(block);
            checksum ^= plain;
            *block = (plain ^ offset).to_ne_bytes();
        }
        self.cipher.encrypt_blocks(blocks.as_flattened_mut());
        let mut offset = initial;
        for (i, block) in (1u64..).zip(blocks.iter_mut()) {
            offset ^= self.l_at(i);
            *block = (load(block) ^ offset).to_ne_bytes();
        }
        if !tail.is_empty() {
            offset ^= self.l_star;
            let pad = self.encipher(offset).to_ne_bytes();
            checksum ^= load(&padded(tail));
            for (byte, pad) in tail.iter_mut().zip(pad) {
                *byte ^= pad;
            }
        }
        Ok((self.encipher(checksum ^ offset ^ self.l_dollar) ^ ad_hash).to_ne_bytes())
    }
}

fn padded(tail: &[u8]) -> [u8; BLOCK_LEN] {
    let mut block = [0u8; BLOCK_LEN];
    let (head, rest) = block.split_at_mut(tail.len().min(BLOCK_LEN - 1));
    head.copy_from_slice(&tail[..head.len()]);
    if let Some(marker) = rest.first_mut() {
        *marker = PAD_MARKER;
    }
    block
}
