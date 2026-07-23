/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{
    Store, U64_LEN,
    write::{AnyKey, key::KeySerializer},
};
use trc::AddContext;

pub async fn destroy_subspace(store: &Store, subspace: u8) -> trc::Result<()> {
    store
        .delete_range(
            AnyKey {
                subspace,
                key: KeySerializer::new(U64_LEN).write(0u8).finalize(),
            },
            AnyKey {
                subspace,
                key: KeySerializer::new(U64_LEN)
                    .write(&[u8::MAX; 64][..])
                    .finalize(),
            },
        )
        .await
        .caused_by(trc::location!())
}
