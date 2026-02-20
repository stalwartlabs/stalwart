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
    ipc::{
        BroadcastEvent, HousekeeperEvent, PushEvent, QueueEvent, ReportingEvent,
        TrainTaskController,
    },
};
use arc_swap::ArcSwap;
use pwhash::sha512_crypt;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
};
use store::{
    RegistryStore,
    rand::{Rng, distr::Alphanumeric, rng},
    registry::bootstrap::Bootstrap,
};
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
    pub housekeeper_rx: Option<mpsc::Receiver<HousekeeperEvent>>,
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
  -I, --init <PATH>                Initialize a new server at a specific path
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

pub const DEFAULT_SETTINGS: &[(&str, &str)] = &[
    ("oauth.key", "abc"),
    ("queue.quota.size.messages", "100000"),
    ("queue.quota.size.size", "10737418240"),
    ("queue.quota.size.enable", "true"),
    ("queue.limiter.inbound.ip.key", "remote_ip"),
    ("queue.limiter.inbound.ip.rate", "5/1s"),
    ("queue.limiter.inbound.ip.enable", "true"),
    ("queue.limiter.inbound.sender.key.0", "sender_domain"),
    ("queue.limiter.inbound.sender.key.1", "rcpt"),
    ("queue.limiter.inbound.sender.rate", "25/1h"),
    ("queue.limiter.inbound.sender.enable", "true"),
    ("report.analysis.addresses", "postmaster@*"),
    ("queue.virtual.local.threads-per-node", "25"),
    ("queue.virtual.local.description", "Local delivery queue"),
    ("queue.virtual.remote.threads-per-node", "50"),
    ("queue.virtual.remote.description", "Remote delivery queue"),
    ("queue.virtual.dsn.threads-per-node", "5"),
    (
        "queue.virtual.dsn.description",
        "Delivery Status Notification delivery queue",
    ),
    ("queue.virtual.report.threads-per-node", "5"),
    (
        "queue.virtual.report.description",
        "DMARC and TLS report delivery queue",
    ),
    ("queue.schedule.local.queue-name", "local"),
    ("queue.schedule.local.retry.0", "2m"),
    ("queue.schedule.local.retry.1", "5m"),
    ("queue.schedule.local.retry.2", "10m"),
    ("queue.schedule.local.retry.3", "15m"),
    ("queue.schedule.local.retry.4", "30m"),
    ("queue.schedule.local.retry.5", "1h"),
    ("queue.schedule.local.retry.6", "2h"),
    ("queue.schedule.local.notify.0", "1d"),
    ("queue.schedule.local.notify.1", "3d"),
    ("queue.schedule.local.expire-type", "ttl"),
    ("queue.schedule.local.expire", "3d"),
    (
        "queue.schedule.local.description",
        "Local delivery schedule",
    ),
    ("queue.schedule.remote.queue-name", "remote"),
    ("queue.schedule.remote.retry.0", "2m"),
    ("queue.schedule.remote.retry.1", "5m"),
    ("queue.schedule.remote.retry.2", "10m"),
    ("queue.schedule.remote.retry.3", "15m"),
    ("queue.schedule.remote.retry.4", "30m"),
    ("queue.schedule.remote.retry.5", "1h"),
    ("queue.schedule.remote.retry.6", "2h"),
    ("queue.schedule.remote.notify.0", "1d"),
    ("queue.schedule.remote.notify.1", "3d"),
    ("queue.schedule.remote.expire-type", "ttl"),
    ("queue.schedule.remote.expire", "3d"),
    (
        "queue.schedule.remote.description",
        "Remote delivery schedule",
    ),
    ("queue.schedule.dsn.queue-name", "dsn"),
    ("queue.schedule.dsn.retry.0", "15m"),
    ("queue.schedule.dsn.retry.1", "30m"),
    ("queue.schedule.dsn.retry.2", "1h"),
    ("queue.schedule.dsn.retry.3", "2h"),
    ("queue.schedule.dsn.expire-type", "attempts"),
    ("queue.schedule.dsn.max-attempts", "10"),
    (
        "queue.schedule.dsn.description",
        "Delivery Status Notification delivery schedule",
    ),
    ("queue.schedule.report.queue-name", "report"),
    ("queue.schedule.report.retry.0", "30m"),
    ("queue.schedule.report.retry.1", "1h"),
    ("queue.schedule.report.retry.2", "2h"),
    ("queue.schedule.report.expire-type", "attempts"),
    ("queue.schedule.report.max-attempts", "8"),
    (
        "queue.schedule.report.description",
        "DMARC and TLS report delivery schedule",
    ),
    ("queue.tls.invalid-tls.allow-invalid-certs", "true"),
    (
        "queue.tls.invalid-tls.description",
        "Allow invalid TLS certificates",
    ),
    ("queue.tls.default.allow-invalid-certs", "false"),
    ("queue.tls.default.description", "Default TLS settings"),
    ("queue.route.local.type", "local"),
    ("queue.route.local.description", "Local delivery route"),
    ("queue.route.mx.type", "mx"),
    ("queue.route.mx.limits.multihomed", "2"),
    ("queue.route.mx.limits.mx", "5"),
    ("queue.route.mx.ip-lookup", "ipv4_then_ipv6"),
    ("queue.route.mx.description", "MX delivery route"),
    ("queue.connection.default.timeout.connect", "5m"),
    (
        "queue.connection.default.description",
        "Default connection settings",
    ),
];

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
                    ("init" | "I", Some(value)) => {
                        quickstart(value);
                        std::process::exit(0);
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
        let mut bootstrap = Bootstrap::init(registry).await;

        // Start listeners
        let mut servers = Listeners::parse(&mut bootstrap).await;
        servers.bind_and_drop_priv(&mut bootstrap);

        // Parse storage
        let storage = Storage::parse(&mut bootstrap).await;

        // Parse telemetry
        let telemetry = Telemetry::parse(&mut bootstrap, &storage).await;

        match import_export {
            StoreOp::None => {
                let todo = "add default settings, hostname, download filter rules, webadmin";

                // Parse components
                let core = Box::pin(Core::parse(&mut bootstrap, storage)).await;
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

                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Version = env!("CARGO_PKG_VERSION"),
                );

                // Build shared inner
                let has_remote_asn = matches!(
                    core.network.asn_geo_lookup,
                    AsnGeoLookupConfig::Resource { .. }
                );
                let (ipc, ipc_rxs) = build_ipc(!core.storage.coordinator.is_none());
                let inner = Arc::new(Inner {
                    shared_core: ArcSwap::from_pointee(core),
                    data,
                    ipc,
                    cache,
                });

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
    let (housekeeper_tx, housekeeper_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (queue_tx, queue_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (report_tx, report_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (broadcast_tx, broadcast_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    (
        Ipc {
            push_tx,
            housekeeper_tx,
            queue_tx,
            report_tx,
            broadcast_tx: has_pubsub.then_some(broadcast_tx),
            task_tx: Arc::new(Notify::new()),
            train_task_controller: Arc::new(TrainTaskController::default()),
        },
        IpcReceivers {
            push_rx: Some(push_rx),
            housekeeper_rx: Some(housekeeper_rx),
            queue_rx: Some(queue_rx),
            report_rx: Some(report_rx),
            broadcast_rx: has_pubsub.then_some(broadcast_rx),
        },
    )
}

fn quickstart(path: impl Into<PathBuf>) {
    let path = path.into();

    if !path.exists() {
        std::fs::create_dir_all(&path).failed("Failed to create directory");
    }

    for dir in &["etc", "data", "logs"] {
        let sub_path = path.join(dir);
        if !sub_path.exists() {
            std::fs::create_dir(sub_path).failed(&format!("Failed to create {dir} directory"));
        }
    }

    let admin_pass = std::env::var("STALWART_ADMIN_PASSWORD").unwrap_or_else(|_| {
        rng()
            .sample_iter(Alphanumeric)
            .take(10)
            .map(char::from)
            .collect::<String>()
    });

    std::fs::write(
        path.join("etc").join("registry.json"),
        QUICKSTART_CONFIG
            .replace("_P_", &path.to_string_lossy())
            .replace("_S_", &sha512_crypt::hash(&admin_pass).unwrap()),
    )
    .failed("Failed to write configuration file");

    eprintln!(
        "✅ Local registry initialized at {}/etc/registry.json",
        path.to_string_lossy()
    );
    eprintln!("🔑 Your administrator account is 'admin' with password '{admin_pass}'.");
}

#[cfg(not(feature = "foundation"))]
const QUICKSTART_CONFIG: &str = r#"[server.listener.smtp]
bind = "[::]:25"
protocol = "smtp"

[server.listener.submission]
bind = "[::]:587"
protocol = "smtp"

[server.listener.submissions]
bind = "[::]:465"
protocol = "smtp"
tls.implicit = true

[server.listener.imap]
bind = "[::]:143"
protocol = "imap"

[server.listener.imaptls]
bind = "[::]:993"
protocol = "imap"
tls.implicit = true

[server.listener.pop3]
bind = "[::]:110"
protocol = "pop3"

[server.listener.pop3s]
bind = "[::]:995"
protocol = "pop3"
tls.implicit = true

[server.listener.sieve]
bind = "[::]:4190"
protocol = "managesieve"

[server.listener.https]
protocol = "http"
bind = "[::]:443"
tls.implicit = true

[server.listener.http]
protocol = "http"
bind = "[::]:8080"

[storage]
data = "rocksdb"
fts = "rocksdb"
blob = "rocksdb"
lookup = "rocksdb"
directory = "internal"

[store.rocksdb]
type = "rocksdb"
path = "_P_/data"
compression = "lz4"

[directory.internal]
type = "internal"
store = "rocksdb"

[tracer.log]
type = "log"
level = "info"
path = "_P_/logs"
prefix = "stalwart.log"
rotate = "daily"
ansi = false
enable = true

[authentication.fallback-admin]
user = "admin"
secret = "_S_"
"#;

#[cfg(feature = "foundation")]
const QUICKSTART_CONFIG: &str = r#"[server.listener.smtp]
bind = "[::]:25"
protocol = "smtp"

[server.listener.submission]
bind = "[::]:587"
protocol = "smtp"

[server.listener.submissions]
bind = "[::]:465"
protocol = "smtp"
tls.implicit = true

[server.listener.imap]
bind = "[::]:143"
protocol = "imap"

[server.listener.imaptls]
bind = "[::]:993"
protocol = "imap"
tls.implicit = true

[server.listener.pop3]
bind = "[::]:110"
protocol = "pop3"

[server.listener.pop3s]
bind = "[::]:995"
protocol = "pop3"
tls.implicit = true

[server.listener.sieve]
bind = "[::]:4190"
protocol = "managesieve"

[server.listener.https]
protocol = "http"
bind = "[::]:443"
tls.implicit = true

[server.listener.http]
protocol = "http"
bind = "[::]:8080"

[storage]
data = "foundation-db"
fts = "foundation-db"
blob = "foundation-db"
lookup = "foundation-db"
directory = "internal"

[store.foundation-db]
type = "foundationdb"
compression = "lz4"

[directory.internal]
type = "internal"
store = "foundation-db"

[tracer.log]
type = "log"
level = "info"
path = "_P_/logs"
prefix = "stalwart.log"
rotate = "daily"
ansi = false
enable = true

[authentication.fallback-admin]
user = "admin"
secret = "_S_"
"#;
