/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ConfigName;
use crate::store::folder::{FaiFolder, FolderStore};
use common::Server;
use store::write::{Archive, ArchiveBytes};
use trc::AddContext;

pub(super) async fn find_config_id(
    server: &Server,
    account_id: u32,
    folder: FaiFolder,
    name: ConfigName<'_>,
) -> trc::Result<Option<u32>> {
    let mut found = None;
    server
        .fai_messages(account_id, folder, |id, message| {
            if name.matches(message.message_class.as_str()) {
                found = Some(id);
                Ok(false)
            } else {
                Ok(true)
            }
        })
        .await
        .caused_by(trc::location!())?;
    Ok(found)
}

pub(super) async fn find_config(
    server: &Server,
    account_id: u32,
    folder: FaiFolder,
    name: ConfigName<'_>,
) -> trc::Result<Option<(u32, Archive<ArchiveBytes>)>> {
    let Some(id) = find_config_id(server, account_id, folder, name).await? else {
        return Ok(None);
    };
    Ok(server
        .fai_message(account_id, folder, id)
        .await
        .caused_by(trc::location!())?
        .map(|row| (id, row)))
}
