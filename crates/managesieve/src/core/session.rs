/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ManageSieveSessionManager, Session, State};
use crate::SERVER_GREETING;
use common::{
    BuildServer,
    network::{SessionData, SessionManager, SessionResult, SessionStream},
};
use imap_proto::receiver::{self, MAX_UNAUTHENTICATED_REQUEST_SIZE, Receiver};
use tokio_rustls::server::TlsStream;

impl SessionManager for ManageSieveSessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            // Create session
            let server = self.inner.build_server();
            let mut session = Session {
                receiver: Receiver::with_max_request_size(MAX_UNAUTHENTICATED_REQUEST_SIZE)
                    .with_start_state(receiver::State::Command { is_uid: false }),
                server,
                instance: session.instance,
                state: State::NotAuthenticated {
                    auth_failures: 0,
                    sasl_failure: None,
                },
                session_id: session.session_id,
                stream: session.stream,
                in_flight: session.in_flight,
                remote_addr: session.remote_ip,
            };

            if session
                .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                .await
                .is_ok()
                && session.handle_conn().await
                && session.instance.acceptor.is_tls()
                && let Ok(mut session) = session.into_tls().await
            {
                let _ = session
                    .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                    .await;
                session.handle_conn().await;
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn handle_conn(&mut self) -> bool {
        let mut buf = vec![0; 8192];
        let mut shutdown_rx = self.instance.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    self.timeout(),
                    self.read(&mut buf)) => {
                        match result {
                            Ok(Ok(bytes_read)) => {
                                if bytes_read > 0 {
                                    match self.ingest(&buf[..bytes_read]).await {
                                        SessionResult::Continue => (),
                                        SessionResult::UpgradeTls => {
                                            return true;
                                        }
                                        SessionResult::Close => {
                                            break;
                                        }
                                    }
                                } else {
                                    trc::event!(
                                        Network(trc::NetworkEvent::Closed),
                                        SpanId = self.session_id,
                                        CausedBy = trc::location!()
                                    );
                                    break;
                                }
                            }
                            Ok(Err(err)) => {
                                trc::event!(
                                    Network(trc::NetworkEvent::ReadError),
                                    SpanId = self.session_id,
                                    Reason = err,
                                    CausedBy = trc::location!()
                                );
                                break;
                            }
                            Err(_) => {
                                trc::event!(
                                    Network(trc::NetworkEvent::Timeout),
                                    SpanId = self.session_id,
                                    CausedBy = trc::location!()
                                );
                                self
                                    .write(b"BYE \"Connection timed out.\"\r\n")
                                    .await
                                    .ok();
                                break;
                            }
                        }
                },
                _ = shutdown_rx.changed() => {
                    trc::event!(
                        Network(trc::NetworkEvent::Closed),
                        SpanId = self.session_id,
                        Reason = "Server shutting down",
                        CausedBy = trc::location!()
                    );
                    self.write(b"BYE \"Server shutting down.\"\r\n").await.ok();
                    break;
                }
            };
        }

        false
    }

    pub async fn into_tls(mut self) -> Result<Session<TlsStream<T>>, ()> {
        self.state.take_sasl_failure();
        let receiver = Receiver::with_max_request_size(self.receiver.max_request_size)
            .with_start_state(receiver::State::Command { is_uid: false });

        Ok(Session {
            stream: self
                .instance
                .tls_accept(self.stream, self.session_id)
                .await?,
            state: self.state,
            instance: self.instance,
            in_flight: self.in_flight,
            session_id: self.session_id,
            server: self.server,
            receiver,
            remote_addr: self.remote_addr,
        })
    }
}
