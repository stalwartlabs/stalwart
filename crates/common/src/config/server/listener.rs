/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Listener, Listeners, ServerProtocol, TcpListener,
    tls::{TLS12_VERSION, TLS13_VERSION},
};
use crate::{
    Inner,
    network::{TcpAcceptor, tls::CertificateResolver},
};
use registry::schema::{
    enums::{NetworkListenerProtocol, TlsCipherSuite, TlsVersion},
    structs::NetworkListener,
};
use rustls::{
    ALL_VERSIONS, ServerConfig, SupportedCipherSuite,
    crypto::ring::{ALL_CIPHER_SUITES, cipher_suite::*, default_provider},
};
use std::sync::Arc;
use store::registry::{RegistryObject, bootstrap::Bootstrap};
use tokio::net::TcpSocket;
use tokio_rustls::TlsAcceptor;
use utils::snowflake::SnowflakeIdGenerator;

impl Listeners {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        // Parse ACME managers
        let mut servers = Listeners {
            span_id_gen: Arc::new(SnowflakeIdGenerator::with_node_id(bp.node_id())),
            ..Default::default()
        };

        // Parse servers
        let node_id = bp.node_id();
        for listener in bp.list_infallible::<NetworkListener>().await {
            if listener.object.enable_for_nodes.is_empty()
                || listener
                    .object
                    .enable_for_nodes
                    .iter()
                    .any(|n| n.contains(node_id))
            {
                servers.parse_server(bp, listener);
            }
        }
        servers
    }

    fn parse_server(&mut self, bp: &mut Bootstrap, listener: RegistryObject<NetworkListener>) {
        let id = listener.id;
        let listener = listener.object;

        // Parse protocol
        let protocol = match listener.protocol {
            NetworkListenerProtocol::Smtp => ServerProtocol::Smtp,
            NetworkListenerProtocol::Lmtp => ServerProtocol::Lmtp,
            NetworkListenerProtocol::Http => ServerProtocol::Http,
            NetworkListenerProtocol::Imap => ServerProtocol::Imap,
            NetworkListenerProtocol::Pop3 => ServerProtocol::Pop3,
            NetworkListenerProtocol::ManageSieve => ServerProtocol::ManageSieve,
        };

        // Build listeners
        let mut listeners = Vec::new();
        for addr in &listener.bind {
            // Parse bind address and build socket
            let addr = addr.0;
            let socket = match if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            } {
                Ok(socket) => socket,
                Err(err) => {
                    bp.build_error(id, format!("Failed to create socket: {err}"));
                    return;
                }
            };

            if let Err(err) = socket.set_reuseaddr(listener.socket_reuse_address) {
                bp.build_error(id, format!("Failed to set SO_REUSEADDR: {err}"));
                return;
            }

            #[cfg(not(target_env = "msvc"))]
            if let Err(err) = socket.set_reuseport(listener.socket_reuse_port) {
                bp.build_error(id, format!("Failed to set SO_REUSEPORT: {err}"));
                return;
            }

            if let Some(send_size) = listener.socket_send_buffer_size
                && let Err(err) = socket.set_send_buffer_size(send_size as u32)
            {
                bp.build_error(id, format!("Failed to set SO_SNDBUF: {err}"));
                return;
            }

            if let Some(recv_size) = listener.socket_receive_buffer_size
                && let Err(err) = socket.set_recv_buffer_size(recv_size as u32)
            {
                bp.build_error(id, format!("Failed to set SO_RCVBUF: {err}"));
                return;
            }

            if let Some(tos) = listener.socket_tos_v4
                && let Err(err) = socket.set_tos_v4(tos as u32)
            {
                bp.build_error(id, format!("Failed to set IP_TOS: {err}"));
                return;
            }

            listeners.push(TcpListener {
                socket,
                addr,
                ttl: listener.socket_ttl.map(|v| v as u32),
                backlog: listener.socket_backlog.map(|v| v as u32),
                nodelay: listener.socket_no_delay,
            });
        }

        let span_id_gen = self.span_id_gen.clone();
        self.servers.push(Listener {
            max_connections: listener.max_connections.unwrap_or(bp.node.max_connections),
            id: listener.name.clone(),
            registry_id: id,
            protocol,
            listeners,
            proxy_networks: if !listener.override_proxy_trusted_networks.is_empty() {
                listener.override_proxy_trusted_networks.clone()
            } else {
                bp.node.proxy_trusted_networks.clone()
            },
            span_id_gen,
        });
        self.parsed_listeners.push(RegistryObject {
            id,
            object: listener,
        });
    }

    pub async fn parse_tcp_acceptors(&mut self, bp: &mut Bootstrap, inner: Arc<Inner>) {
        let resolver = Arc::new(CertificateResolver::new(inner.clone()));

        for listener in std::mem::take(&mut self.parsed_listeners) {
            let id = listener.id;
            let listener = listener.object;

            // Build TLS config
            let acceptor = if listener.use_tls {
                // Parse protocol versions
                let mut tls_v2 = true;
                let mut tls_v3 = true;

                for disabled in listener.tls_disable_protocols {
                    match disabled {
                        TlsVersion::Tls12 => {
                            tls_v2 = false;
                        }
                        TlsVersion::Tls13 => {
                            tls_v3 = false;
                        }
                    }
                }

                // Parse cipher suites
                let mut disabled_ciphers: Vec<SupportedCipherSuite> = Vec::new();
                for disabled in listener.tls_disable_cipher_suites {
                    disabled_ciphers.push(match disabled {
                        TlsCipherSuite::Tls13Aes256GcmSha384 => {
                            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                        }
                        TlsCipherSuite::Tls13Aes128GcmSha256 => {
                            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                        }
                        TlsCipherSuite::Tls13Chacha20Poly1305Sha256 => {
                            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                        }
                        TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384 => {
                            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                        }
                        TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256 => {
                            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                        }
                        TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
                            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                        }
                        TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        }
                        TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256 => {
                            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                        }
                        TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
                            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                        }
                    });
                }

                // Build cert provider
                let mut provider = default_provider();
                if !disabled_ciphers.is_empty() {
                    provider.cipher_suites = ALL_CIPHER_SUITES
                        .iter()
                        .filter(|suite| !disabled_ciphers.contains(suite))
                        .copied()
                        .collect();
                }

                // Build server config
                let mut server_config = match ServerConfig::builder_with_provider(provider.into())
                    .with_protocol_versions(if tls_v3 == tls_v2 {
                        ALL_VERSIONS
                    } else if tls_v3 {
                        TLS13_VERSION
                    } else {
                        TLS12_VERSION
                    }) {
                    Ok(server_config) => server_config
                        .with_no_client_auth()
                        .with_cert_resolver(resolver.clone()),
                    Err(err) => {
                        bp.build_error(id, format!("Failed to build TLS server config: {err}"));
                        return;
                    }
                };

                server_config.ignore_client_order = listener.tls_ignore_client_order;

                // Build acceptor
                let default_config = Arc::new(server_config);
                TcpAcceptor::Tls {
                    acceptor: TlsAcceptor::from(default_config.clone()),
                    config: default_config,
                    implicit: listener.tls_implicit,
                }
            } else {
                TcpAcceptor::Plain
            };

            self.tcp_acceptors.insert(listener.name, acceptor);
        }
    }
}
