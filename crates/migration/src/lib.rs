/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use crate::v016::migrate_v0_16;
use common::{DATABASE_SCHEMA_VERSION, Server};
use store::{
    IterateParams, SUBSPACE_PROPERTY, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SerializeInfallible,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass},
};
use trc::AddContext;

pub mod destroy;
pub mod v016;

pub async fn try_migrate(server: &Server) -> trc::Result<()> {
    match server
        .store()
        .get_value::<u32>(AnyKey {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        })
        .await
        .caused_by(trc::location!())?
    {
        Some(DATABASE_SCHEMA_VERSION) => {
            if !std::env::var("DANGER_FORCE_MIGRATE").is_ok_and(|v| v == "1") {
                return Ok(());
            }
        }
        Some(0..=4) => {
            abort(concat!(
                "You must first upgrade to version 0.15, please read ",
                "https://github.com/stalwartlabs/stalwart/blob/main/UPGRADING/v0_16.md"
            ));
        }
        Some(5) => {
            if !server.registry().is_recovery_mode() {
                abort(concat!(
                    "Upgrading to version 0.16 is a multi-step process, please read ",
                    "https://github.com/stalwartlabs/stalwart/blob/main/UPGRADING/v0_16.md"
                ));
            }
        }

        Some(version) => {
            panic!(
                "Unknown database schema version, expected {} or below, found {}",
                DATABASE_SCHEMA_VERSION, version
            );
        }
        _ => {
            if is_new_install(server).await.caused_by(trc::location!())? {
                write_schema_version(server).await?;
                return Ok(());
            } else {
                abort(concat!(
                    "You must first upgrade to version 0.15, please read ",
                    "https://github.com/stalwartlabs/stalwart/blob/main/UPGRADING/v0_16.md"
                ));
            }
        }
    }

    migrate_v0_16(server).await?;
    write_schema_version(server).await
}

async fn write_schema_version(server: &Server) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        }),
        DATABASE_SCHEMA_VERSION.serialize(),
    );

    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

fn abort(message: &str) -> ! {
    eprintln!("Migration aborted: {message}");
    panic!("Migration aborted: {message}");
}

async fn is_new_install(server: &Server) -> trc::Result<bool> {
    for subspace in [
        SUBSPACE_QUEUE_MESSAGE,
        SUBSPACE_REPORT_IN,
        SUBSPACE_REPORT_OUT,
        SUBSPACE_PROPERTY,
    ] {
        let mut has_data = false;

        server
            .store()
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: vec![0u8],
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; 16],
                    },
                )
                .no_values(),
                |_, _| {
                    has_data = true;

                    Ok(false)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if has_data {
            return Ok(false);
        }
    }

    Ok(true)
}
