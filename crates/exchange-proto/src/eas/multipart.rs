/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const COUNT_LEN: u32 = 4;
const ENTRY_LEN: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartTooLarge;

pub fn header_len(parts: usize) -> Option<u32> {
    u32::try_from(parts)
        .ok()?
        .checked_mul(ENTRY_LEN)?
        .checked_add(COUNT_LEN)
}

pub fn write_multipart_header(
    out: &mut Vec<u8>,
    part_lens: &[u32],
) -> Result<(), MultipartTooLarge> {
    let count = u32::try_from(part_lens.len()).map_err(|_| MultipartTooLarge)?;
    let mut offset = header_len(part_lens.len()).ok_or(MultipartTooLarge)?;
    part_lens
        .iter()
        .try_fold(offset, |total, &len| total.checked_add(len))
        .ok_or(MultipartTooLarge)?;
    out.reserve(usize::try_from(offset).map_err(|_| MultipartTooLarge)?);
    out.extend_from_slice(&count.to_le_bytes());
    for &len in part_lens {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        offset = offset.wrapping_add(len);
    }
    Ok(())
}
