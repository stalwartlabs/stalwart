/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{into_error, tls::MakeRustlsConnect};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    task::JoinHandle,
    time::{Instant, Sleep},
};
use tokio_postgres::{Client, Config, Connection, NoTls, config::Host, tls::MakeTlsConnect};

const DEFAULT_PORT: u16 = 5432;

pub(crate) struct PgConnect {
    pub(crate) config: Config,
    pub(crate) tls: Option<MakeRustlsConnect>,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) response_timeout: Option<Duration>,
    pub(crate) unresponsive: Arc<AtomicBool>,
}

pub(crate) struct ResponseDeadline {
    socket: PgSocket,
    timeout: Option<Duration>,
    sent_at: Option<Instant>,
    timer: Pin<Box<Sleep>>,
    unresponsive: Arc<AtomicBool>,
}

enum PgSocket {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl PgConnect {
    pub(crate) async fn connect(&self) -> trc::Result<(Client, JoinHandle<()>)> {
        match self.connect_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, self.connect_inner()).await {
                Ok(result) => result,
                Err(_) => {
                    self.unresponsive.store(true, Ordering::Relaxed);
                    Err(trc::StoreEvent::PostgresqlError
                        .reason("Timed out connecting to the PostgreSQL server"))
                }
            },
            None => self.connect_inner().await,
        }
    }

    async fn connect_inner(&self) -> trc::Result<(Client, JoinHandle<()>)> {
        let (socket, hostname) = self.open_socket().await.map_err(|err| {
            trc::StoreEvent::PostgresqlError
                .reason(err)
                .details("Failed to connect to the PostgreSQL server")
        })?;
        let stream = ResponseDeadline {
            socket,
            timeout: self.response_timeout,
            sent_at: None,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
            unresponsive: self.unresponsive.clone(),
        };
        match &self.tls {
            Some(tls) => {
                let tls = MakeTlsConnect::<ResponseDeadline>::make_tls_connect(
                    &mut tls.clone(),
                    hostname,
                )
                .map_err(|err| trc::StoreEvent::PostgresqlError.reason(err))?;
                spawn_connection(self.config.connect_raw(stream, tls).await)
            }
            None => spawn_connection(self.config.connect_raw(stream, NoTls).await),
        }
    }

    async fn open_socket(&self) -> io::Result<(PgSocket, &str)> {
        let ports = self.config.get_ports();
        let fallback_port = ports.first().copied().unwrap_or(DEFAULT_PORT);
        let mut last_error = None;
        for (host, port) in self.config.get_hosts().iter().zip(
            ports
                .iter()
                .copied()
                .chain(std::iter::repeat(fallback_port)),
        ) {
            let result = match host {
                Host::Tcp(name) => match TcpStream::connect((name.as_str(), port)).await {
                    Ok(stream) => stream
                        .set_nodelay(true)
                        .map(|_| (PgSocket::Tcp(stream), name.as_str())),
                    Err(err) => Err(err),
                },
                #[cfg(unix)]
                Host::Unix(dir) => {
                    tokio::net::UnixStream::connect(dir.join(format!(".s.PGSQL.{port}")))
                        .await
                        .map(|stream| (PgSocket::Unix(stream), ""))
                }
            };
            match result {
                Ok(socket) => return Ok(socket),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No host configured")))
    }

    pub(crate) fn is_unresponsive(&self) -> bool {
        self.unresponsive.load(Ordering::Relaxed)
    }
}

fn spawn_connection<T>(
    result: Result<(Client, Connection<ResponseDeadline, T>), tokio_postgres::Error>,
) -> trc::Result<(Client, JoinHandle<()>)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, connection) = result.map_err(into_error)?;
    let task = tokio::spawn(async move {
        if let Err(err) = connection.await {
            trc::error!(into_error(err).details("PostgreSQL connection closed"));
        }
    });
    Ok((client, task))
}

impl ResponseDeadline {
    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (Some(sent_at), Some(timeout)) = (self.sent_at, self.timeout) else {
            return Poll::Pending;
        };
        let deadline = sent_at + timeout;
        while self.timer.as_mut().poll(cx).is_ready() {
            if self.timer.deadline() >= deadline {
                self.unresponsive.store(true, Ordering::Relaxed);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PostgreSQL server did not respond in time",
                )));
            }
            self.timer.as_mut().reset(deadline);
        }
        Poll::Pending
    }
}

impl AsyncRead for ResponseDeadline {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let filled = buf.filled().len();
        let result = match &mut this.socket {
            PgSocket::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(unix)]
            PgSocket::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        };
        match result {
            Poll::Pending => this.poll_deadline(cx),
            Poll::Ready(Ok(())) if buf.filled().len() > filled => {
                this.sent_at = None;
                if this.unresponsive.load(Ordering::Relaxed) {
                    this.unresponsive.store(false, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for ResponseDeadline {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let result = match &mut this.socket {
            PgSocket::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(unix)]
            PgSocket::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        };
        if this.sent_at.is_none() && matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            this.sent_at = Some(Instant::now());
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.socket {
            PgSocket::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            PgSocket::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.socket {
            PgSocket::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            PgSocket::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/store/src/backend/postgres/connect/tests.rs"]
mod tests;
