/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{backup::BackupParams, console::store_console};
use crate::{
    BuildServer, Caches, Core, Data, IPC_CHANNEL_BUFFER, Inner, Ipc,
    config::{
        network::AsnGeoLookupConfig, server::Listeners, storage::Storage, telemetry::Telemetry,
    },
    ipc::{BroadcastEvent, PushEvent, QueueEvent, ReportingEvent, TrainTaskController},
    manager::defaults::BootstrapDefaults,
};
use arc_swap::ArcSwap;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
};
use store::{RegistryStore, registry::bootstrap::Bootstrap};
use tokio::sync::{Notify, mpsc};
use utils::{UnwrapFailure, failed};

pub struct BootManager {
    pub bootstrap: Bootstrap,
    pub inner: Arc<Inner>,
    pub servers: Listeners,
    pub ipc_rxs: IpcReceivers,
}

pub struct IpcReceivers {
    pub push_rx: Option<mpsc::Receiver<PushEvent>>,
    pub queue_rx: Option<mpsc::Receiver<QueueEvent>>,
    pub report_rx: Option<mpsc::Receiver<ReportingEvent>>,
    pub broadcast_rx: Option<mpsc::Receiver<BroadcastEvent>>,
}

const HELP: &str = concat!(
    "Stalwart Server v",
    env!("CARGO_PKG_VERSION"),
    r#"

Usage: stalwart [OPTIONS]

Options:
  -c, --config <PATH>              Start server with the specified configuration file
  -e, --export <PATH>              Export all store data to a specific path
  -i, --import <PATH>              Import store data from a specific path
  -o, --console                    Open the store console
  -h, --help                       Print help
  -V, --version                    Print version
"#
);

#[derive(PartialEq, Eq)]
enum StoreOp {
    Export(BackupParams),
    Import(PathBuf),
    Console,
    None,
}

impl BootManager {
    pub async fn init() -> Self {
        let mut config_path = std::env::var("CONFIG_PATH").ok();
        let mut import_export = StoreOp::None;

        if config_path.is_none() {
            let mut args = std::env::args().skip(1);

            while let Some(arg) = args.next().and_then(|arg| {
                arg.strip_prefix("--")
                    .or_else(|| arg.strip_prefix('-'))
                    .map(|arg| arg.to_string())
            }) {
                let (key, value) = if let Some((key, value)) = arg.split_once('=') {
                    (key.to_string(), Some(value.trim().to_string()))
                } else {
                    (arg, args.next())
                };

                match (key.as_str(), value) {
                    ("help" | "h", _) => {
                        eprintln!("{HELP}");
                        std::process::exit(0);
                    }
                    ("version" | "V", _) => {
                        println!("{}", env!("CARGO_PKG_VERSION"));
                        std::process::exit(0);
                    }
                    ("config" | "c", Some(value)) => {
                        config_path = Some(value);
                    }
                    ("export" | "e", Some(value)) => {
                        import_export = StoreOp::Export(BackupParams::new(value.into()));
                    }
                    ("import" | "i", Some(value)) => {
                        import_export = StoreOp::Import(value.into());
                    }
                    ("console" | "o", None) => {
                        import_export = StoreOp::Console;
                    }
                    (_, None) => {
                        failed(&format!("Unrecognized command '{key}', try '--help'."));
                    }
                    (_, Some(_)) => failed(&format!(
                        "Missing value for argument '{key}', try '--help'."
                    )),
                }
            }

            if config_path.is_none() {
                if import_export == StoreOp::None {
                    eprintln!("{HELP}");
                } else {
                    eprintln!("Missing '--config' argument for import/export.")
                }
                std::process::exit(0);
            }
        }

        // Initialize registry
        let registry = RegistryStore::init(PathBuf::from(config_path.unwrap()))
            .await
            .failed("⚠️ Startup failed");
        let mut bootstrap = Bootstrap::new(registry).await;

        // Add safe defaults if missing
        if import_export == StoreOp::None {
            bootstrap.insert_safe_defaults().await;
        }

        // Start listeners
        let mut servers = Listeners::parse(&mut bootstrap).await;
        servers.bind_and_drop_priv(&mut bootstrap);

        // Parse storage
        let storage = Storage::parse(&mut bootstrap).await;

        // Parse telemetry
        let telemetry = Telemetry::parse(&mut bootstrap, &storage).await;

        match import_export {
            StoreOp::None => {
                // Parse components
                let core: Box<Core> =
                    Box::new(Box::pin(Core::parse(&mut bootstrap, storage)).await);
                let data = Data::parse(&mut bootstrap).await;
                let cache = Caches::parse(&mut bootstrap).await;

                // Enable telemetry

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                telemetry.enable(core.is_enterprise_edition());
                // SPDX-SnippetEnd

                #[cfg(not(feature = "enterprise"))]
                telemetry.enable(false);

                if bootstrap.registry.is_bootstrap_mode() {
                    trc::event!(
                        Server(trc::ServerEvent::BootstrapMode),
                        Hostname = bootstrap.registry.local_hostname().to_string(),
                        Details =
                            "No configuration file was found. Port 8080 is open for initial setup.",
                        Version = env!("CARGO_PKG_VERSION"),
                    );
                } else if bootstrap.registry.is_recovery_mode() {
                    trc::event!(
                        Server(trc::ServerEvent::RecoveryMode),
                        Details = "Port 8080 is open for troubleshooting and recovery.",
                        Hostname = bootstrap.registry.local_hostname().to_string(),
                        Version = env!("CARGO_PKG_VERSION"),
                    );
                } else {
                    trc::event!(
                        Server(trc::ServerEvent::Startup),
                        Hostname = bootstrap.registry.local_hostname().to_string(),
                        Version = env!("CARGO_PKG_VERSION"),
                    );
                }

                if core.storage.coordinator.is_enabled() {
                    trc::event!(
                        Cluster(trc::ClusterEvent::Startup),
                        Id = bootstrap.registry.node_id(),
                        Type = bootstrap
                            .registry
                            .cluster_role()
                            .unwrap_or("[default]")
                            .to_string(),
                        Details = bootstrap.registry.cluster_push_shard()
                    );
                }

                // Build shared inner
                let has_remote_asn = matches!(
                    core.network.asn_geo_lookup,
                    AsnGeoLookupConfig::Resource { .. }
                );
                let (ipc, ipc_rxs) = build_ipc(!core.storage.coordinator.is_none());
                let inner = Arc::new(Inner {
                    shared_core: ArcSwap::new(Arc::from(core)),
                    data,
                    ipc,
                    cache,
                });

                if !bootstrap.registry.is_recovery_mode() {
                    // Load spam model
                    if let Err(err) = inner.build_server().spam_model_reload().await {
                        trc::error!(
                            err.details("Failed to load spam filter model")
                                .caused_by(trc::location!())
                        );
                    }

                    // Fetch ASN database
                    if has_remote_asn {
                        inner
                            .build_server()
                            .lookup_asn_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                            .await;
                    }
                }

                // Parse TCP acceptors
                servers
                    .parse_tcp_acceptors(&mut bootstrap, inner.clone())
                    .await;

                BootManager {
                    inner,
                    bootstrap,
                    servers,
                    ipc_rxs,
                }
            }
            StoreOp::Export(path) => {
                // Enable telemetry
                telemetry.enable(false);

                // Parse settings and backup
                Box::pin(Core::parse(&mut bootstrap, storage))
                    .await
                    .backup(path)
                    .await;
                std::process::exit(0);
            }
            StoreOp::Import(path) => {
                // Enable telemetry
                telemetry.enable(false);

                // Parse settings and restore
                Box::pin(Core::parse(&mut bootstrap, storage))
                    .await
                    .restore(path)
                    .await;
                std::process::exit(0);
            }
            StoreOp::Console => {
                // Store console
                store_console(
                    Box::pin(Core::parse(&mut bootstrap, storage))
                        .await
                        .storage
                        .data,
                )
                .await;
                std::process::exit(0);
            }
        }
    }
}

pub fn build_ipc(has_pubsub: bool) -> (Ipc, IpcReceivers) {
    // Build ipc receivers
    let (push_tx, push_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (queue_tx, queue_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (report_tx, report_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (broadcast_tx, broadcast_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    (
        Ipc {
            push_tx,
            queue_tx,
            report_tx,
            broadcast_tx: has_pubsub.then_some(broadcast_tx),
            task_tx: Arc::new(Notify::new()),
            train_task_controller: Arc::new(TrainTaskController::default()),
        },
        IpcReceivers {
            push_rx: Some(push_rx),
            queue_rx: Some(queue_rx),
            report_rx: Some(report_rx),
            broadcast_rx: has_pubsub.then_some(broadcast_rx),
        },
    )
}
