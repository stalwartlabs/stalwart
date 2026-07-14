/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]
#![warn(clippy::cast_possible_truncation)]
#![warn(clippy::cast_possible_wrap)]
#![warn(clippy::cast_sign_loss)]

use common::{BuildServer, config::server::ServerProtocol, manager::boot::BootManager};
use http::HttpSessionManager;
use imap::core::ImapSessionManager;
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use services::{StartServices, broadcast::subscriber::spawn_broadcast_subscriber};
use smtp::{StartQueueManager, core::SmtpSessionManager};
use std::time::Duration;
use trc::Collector;
use utils::wait_for_shutdown;

#[cfg(feature = "dev_mode")]
pub mod test_data;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
use jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Install AWS-LC-RS as the default Rustls crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install aws-lc-rs as the default rustls crypto provider");

    // Load config and apply macros
    let mut init = Box::pin(BootManager::init()).await;

    // Migrate database
    if let Err(err) = migration::try_migrate(&init.inner.build_server()).await {
        trc::event!(
            Server(trc::ServerEvent::StartupError),
            Details = "Failed to migrate database, aborting startup.",
            Reason = err,
        );
        return Ok(());
    }

    // Init services
    init.start_services().await;
    init.start_queue_manager();

    // Log configuration errors
    init.bootstrap.log_errors();
    init.bootstrap.log_warnings();

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    // Log licensing information
    #[cfg(feature = "enterprise")]
    init.inner.build_server().log_license_details();
    // SPDX-SnippetEnd

    #[cfg(feature = "dev_mode")]
    if std::env::var("INSERT_TEST_DATA").is_ok() {
        let server = init.inner.build_server();
        test_data::insert_test_data(&server).await;
        server.insert_test_metrics().await;
    }

    // Spawn servers
    let (shutdown_tx, shutdown_rx) = init.servers.spawn(|server, acceptor, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                SmtpSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Http => server.spawn(
                HttpSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Imap => server.spawn(
                ImapSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Pop3 => server.spawn(
                Pop3SessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::ManageSieve => server.spawn(
                ManageSieveSessionManager::new(init.inner.clone()),
                init.inner.clone(),
                acceptor,
                shutdown_rx,
            ),
        };
    });

    // Start broadcast subscriber
    spawn_broadcast_subscriber(init.inner, shutdown_rx);

    // Wait for shutdown signal
    wait_for_shutdown().await;

    // Shutdown collector
    Collector::shutdown();

    // Stop services
    let _ = shutdown_tx.send(true);

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}
