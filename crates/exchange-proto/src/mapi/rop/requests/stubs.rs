/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::framed;
use super::too_many;
use crate::common::LeReader;
use crate::mapi::rop::{buffer::DecodeContext, error::RopDecodeError};

pub(super) fn skip_abort_submit(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(8)?;
    r.skip(8)?;
    Ok(())
}

pub(super) fn skip_clone_stream(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(1)?;
    Ok(())
}

pub(super) fn skip_get_owning_servers(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(8)?;
    Ok(())
}

pub(super) fn skip_spooler_lock_message(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(8)?;
    r.skip(1)?;
    Ok(())
}

pub(super) fn skip_progress(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(1)?;
    Ok(())
}

pub(super) fn skip_transport_new_mail(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(8)?;
    r.skip(8)?;
    r.ascii_z()?;
    r.skip(4)?;
    Ok(())
}

pub(super) fn skip_update_deferred_action_messages(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    let server_entry_id_size = r.u16()?;
    r.skip(usize::from(server_entry_id_size))?;
    let client_entry_id_size = r.u16()?;
    r.skip(usize::from(client_entry_id_size))?;
    Ok(())
}

pub(super) fn skip_lock_region_stream(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(8)?;
    r.skip(8)?;
    r.skip(4)?;
    Ok(())
}

pub(super) fn skip_unlock_region_stream(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(8)?;
    r.skip(8)?;
    r.skip(4)?;
    Ok(())
}

pub(super) fn skip_get_per_user_long_term_ids(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(16)?;
    Ok(())
}

pub(super) fn skip_get_per_user_guid(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(24)?;
    Ok(())
}

pub(super) fn skip_read_per_user_information(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.skip(24)?;
    r.skip(1)?;
    r.skip(4)?;
    r.skip(2)?;
    Ok(())
}

pub(super) fn skip_options_data(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    r.ascii_z()?;
    r.skip(1)?;
    Ok(())
}

pub(super) fn skip_write_and_commit_stream(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    let data_size = r.u16()?;
    r.skip(usize::from(data_size))?;
    Ok(())
}

pub(super) fn skip_set_local_replica_midset_deleted(
    r: &mut LeReader<'_>,
    _ctx: &DecodeContext<'_>,
) -> Result<(), RopDecodeError> {
    let data_size = r.u16()?;
    let frame = r.offset();
    let long_term_id_range_count = r.u32()?;
    r.skip(
        usize::try_from(long_term_id_range_count)
            .map_err(|_| too_many(r))?
            .checked_mul(48)
            .ok_or_else(|| too_many(r))?,
    )?;
    framed(r, frame, usize::from(data_size))?;
    Ok(())
}
