/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::session::SessionParams;
use crate::{
    outbound::error::{AssertReply, ClientError, ClientResult},
    queue::{Error, ErrorDetails, HostResponse, MessageWrapper, Status},
};
use base64::{Engine, engine::general_purpose};
use directory::Credentials;
use rustls::ClientConnection;
use rustls_pki_types::ServerName;
use smtp_proto::{
    AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2, EXT_START_TLS, EhloResponse, Response,
    response::{
        generate::BitToString,
        parser::{MAX_RESPONSE_LENGTH, ResponseReceiver},
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use trc::DeliveryEvent;

pub struct SmtpClient<T: AsyncRead + AsyncWrite> {
    pub stream: T,
    pub timeout: Duration,
    pub session_id: u64,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    pub async fn authenticate(
        &mut self,
        credentials: &Credentials,
        capabilities: impl AsRef<EhloResponse<String>>,
    ) -> ClientResult<&mut Self> {
        let capabilities = capabilities.as_ref();
        let mut available_mechanisms = match &credentials {
            Credentials::Basic { .. } => AUTH_LOGIN | AUTH_PLAIN,
            Credentials::Bearer { .. } => AUTH_OAUTHBEARER | AUTH_XOAUTH2,
        } & capabilities.auth_mechanisms;

        // Try authenticating from most secure to least secure
        let mut has_err = None;
        let mut has_failed = false;

        while available_mechanisms != 0 && !has_failed {
            let mechanism = 1 << ((63 - available_mechanisms.leading_zeros()) as u64);
            available_mechanisms ^= mechanism;
            match self.auth(mechanism, credentials).await {
                Ok(_) => {
                    return Ok(self);
                }
                Err(err) => match err {
                    ClientError::UnexpectedReply(reply) => {
                        has_failed = reply.code() == 535;
                        has_err = reply.into();
                    }
                    ClientError::UnsupportedAuthMechanism => (),
                    _ => return Err(err),
                },
            }
        }

        if let Some(has_err) = has_err {
            Err(ClientError::AuthenticationFailed(has_err))
        } else {
            Err(ClientError::UnsupportedAuthMechanism)
        }
    }

    pub(crate) async fn auth(
        &mut self,
        mechanism: u64,
        credentials: &Credentials,
    ) -> ClientResult<()> {
        let mut reply = if (mechanism & (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER)) != 0 {
            self.cmd(
                format!(
                    "AUTH {} {}\r\n",
                    mechanism.to_mechanism(),
                    encode_credentials(credentials, mechanism, "")?,
                )
                .as_bytes(),
            )
            .await?
        } else {
            self.cmd(format!("AUTH {}\r\n", mechanism.to_mechanism()).as_bytes())
                .await?
        };

        for _ in 0..3 {
            match reply.code() {
                334 => {
                    reply = self
                        .cmd(
                            format!(
                                "{}\r\n",
                                encode_credentials(credentials, mechanism, reply.message())?
                            )
                            .as_bytes(),
                        )
                        .await?;
                }
                235 => {
                    return Ok(());
                }
                _ => {
                    return Err(ClientError::UnexpectedReply(Box::new(reply)));
                }
            }
        }

        Err(ClientError::UnexpectedReply(Box::new(reply)))
    }

    pub async fn read_greeting(
        &mut self,
        hostname: &str,
    ) -> Result<(), Status<HostResponse<Box<str>>, ErrorDetails>> {
        tokio::time::timeout(self.timeout, self.read())
            .await
            .map_err(|_| Status::timeout(hostname, "reading greeting"))?
            .and_then(|r| r.assert_code(220))
            .map_err(|err| Status::from_smtp_error(hostname, "", err))
    }

    pub async fn read_smtp_data_response(
        &mut self,
        hostname: &str,
        bdat_cmd: &Option<String>,
    ) -> Result<Response<String>, Status<HostResponse<Box<str>>, ErrorDetails>> {
        tokio::time::timeout(self.timeout, self.read())
            .await
            .map_err(|_| Status::timeout(hostname, "reading SMTP DATA response"))?
            .map_err(|err| {
                Status::from_smtp_error(hostname, bdat_cmd.as_deref().unwrap_or("DATA"), err)
            })
    }

    pub async fn read_lmtp_data_response(
        &mut self,
        hostname: &str,
        num_responses: usize,
    ) -> Result<Vec<Response<Box<str>>>, Status<HostResponse<Box<str>>, ErrorDetails>> {
        tokio::time::timeout(self.timeout, async { self.read_many(num_responses).await })
            .await
            .map_err(|_| Status::timeout(hostname, "reading LMTP DATA responses"))?
            .map_err(|err| Status::from_smtp_error(hostname, "", err))
    }

    pub async fn write_chunks(&mut self, chunks: &[&[u8]]) -> Result<(), ClientError> {
        for chunk in chunks {
            self.stream
                .write_all(chunk)
                .await
                .map_err(ClientError::from)?;
        }
        self.stream.flush().await.map_err(ClientError::from)
    }

    pub async fn send_message(
        &mut self,
        message: &MessageWrapper,
        rcpt_headers: Option<&[u8]>,
        bdat_cmd: &mut Option<String>,
        params: &SessionParams<'_>,
    ) -> Result<(), Status<HostResponse<Box<str>>, ErrorDetails>> {
        match params
            .server
            .blob_store()
            .get_blob(message.message.blob_hash.as_slice(), 0..usize::MAX)
            .await
        {
            Ok(Some(raw_message)) => {
                tokio::time::timeout(params.conn_strategy.timeout_data, async {
                    if let Some(bdat_cmd) = bdat_cmd {
                        *bdat_cmd = format!(
                            "BDAT {} LAST\r\n",
                            raw_message.len() + rcpt_headers.map(|h| h.len()).unwrap_or(0)
                        );

                        trc::event!(
                            Delivery(DeliveryEvent::RawOutput),
                            SpanId = self.session_id,
                            Contents = bdat_cmd.clone(),
                            Size = bdat_cmd.len()
                        );

                        let chunks = if let Some(rcpt_headers) = rcpt_headers {
                            &[bdat_cmd.as_bytes(), rcpt_headers, &raw_message][..]
                        } else {
                            &[bdat_cmd.as_bytes(), &raw_message][..]
                        };

                        self.write_chunks(chunks).await
                    } else {
                        trc::event!(
                            Delivery(DeliveryEvent::RawOutput),
                            SpanId = self.session_id,
                            Contents = "DATA\r\n",
                            Size = 6
                        );

                        self.write_chunks(&[b"DATA\r\n"]).await?;
                        self.read().await?.assert_code(354)?;
                        if let Some(rcpt_headers) = rcpt_headers
                            && let Err(err) = self.write_chunks(&[rcpt_headers]).await
                        {
                            Err(err)
                        } else {
                            self.write_message(&raw_message)
                                .await
                                .map_err(ClientError::from)
                        }
                    }
                })
                .await
                .map_err(|_| Status::timeout(params.hostname, "sending message"))?
                .map_err(|err| {
                    Status::from_smtp_error(
                        params.hostname,
                        bdat_cmd.as_deref().unwrap_or("DATA"),
                        err,
                    )
                })
            }
            Ok(None) => {
                trc::event!(
                    Queue(trc::QueueEvent::BlobNotFound),
                    SpanId = message.span_id,
                    BlobId = message.message.blob_hash.to_hex(),
                    CausedBy = trc::location!()
                );
                Err(Status::TemporaryFailure(ErrorDetails {
                    entity: "localhost".into(),
                    details: Error::Io("Queue system error.".into()),
                }))
            }
            Err(err) => {
                trc::error!(
                    err.span_id(message.span_id)
                        .details("Failed to fetch blobId")
                        .caused_by(trc::location!())
                );

                Err(Status::TemporaryFailure(ErrorDetails {
                    entity: "localhost".into(),
                    details: Error::Io("Queue system error.".into()),
                }))
            }
        }
    }

    pub async fn say_helo(
        &mut self,
        params: &SessionParams<'_>,
    ) -> Result<EhloResponse<String>, Status<HostResponse<Box<str>>, ErrorDetails>> {
        let cmd = if params.is_smtp {
            format!("EHLO {}\r\n", params.local_hostname)
        } else {
            format!("LHLO {}\r\n", params.local_hostname)
        };

        trc::event!(
            Delivery(DeliveryEvent::RawOutput),
            SpanId = self.session_id,
            Contents = cmd.clone(),
            Size = cmd.len()
        );

        tokio::time::timeout(params.conn_strategy.timeout_ehlo, async {
            self.stream.write_all(cmd.as_bytes()).await?;
            self.stream.flush().await?;
            self.read_ehlo().await
        })
        .await
        .map_err(|_| Status::timeout(params.hostname, "reading EHLO response"))?
        .map_err(|err| Status::from_smtp_error(params.hostname, &cmd, err))
    }

    pub async fn quit(mut self: SmtpClient<T>) {
        trc::event!(
            Delivery(DeliveryEvent::RawOutput),
            SpanId = self.session_id,
            Contents = "QUIT\r\n",
            Size = 6
        );

        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            if self.stream.write_all(b"QUIT\r\n").await.is_ok() && self.stream.flush().await.is_ok()
            {
                let mut buf = [0u8; 128];
                let _ = self.stream.read(&mut buf).await;
            }
        })
        .await;
    }

    pub async fn read_ehlo(&mut self) -> ClientResult<EhloResponse<String>> {
        let mut buf = vec![0u8; 8192];
        let mut buf_concat = Vec::with_capacity(0);

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br == 0 {
                return Err(ClientError::UnparseableReply);
            }

            trc::event!(
                Delivery(DeliveryEvent::RawInput),
                SpanId = self.session_id,
                Contents = trc::Value::from_maybe_string(&buf[..br]),
                Size = br,
            );

            let mut iter = if buf_concat.is_empty() {
                buf[..br].iter()
            } else if br + buf_concat.len() < MAX_RESPONSE_LENGTH {
                buf_concat.extend_from_slice(&buf[..br]);
                buf_concat.iter()
            } else {
                return Err(ClientError::UnparseableReply);
            };

            match EhloResponse::parse(&mut iter) {
                Ok(reply) => return Ok(reply),
                Err(err) => match err {
                    smtp_proto::Error::NeedsMoreData { .. } => {
                        if buf_concat.is_empty() {
                            buf_concat = buf[..br].to_vec();
                        }
                    }
                    smtp_proto::Error::InvalidResponse { code } => {
                        match ResponseReceiver::from_code(code).parse(&mut iter) {
                            Ok(response) => {
                                return Err(ClientError::UnexpectedReply(Box::new(response)));
                            }
                            Err(smtp_proto::Error::NeedsMoreData { .. }) => {
                                if buf_concat.is_empty() {
                                    buf_concat = buf[..br].to_vec();
                                }
                            }
                            Err(_) => return Err(ClientError::UnparseableReply),
                        }
                    }
                    _ => {
                        return Err(ClientError::UnparseableReply);
                    }
                },
            }
        }
    }

    pub async fn read(&mut self) -> ClientResult<Response<String>> {
        let mut buf = vec![0u8; 8192];
        let mut parser = ResponseReceiver::default();

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                trc::event!(
                    Delivery(DeliveryEvent::RawInput),
                    SpanId = self.session_id,
                    Contents = trc::Value::from_maybe_string(&buf[..br]),
                    Size = br
                );

                match parser.parse(&mut buf[..br].iter()) {
                    Ok(reply) => return Ok(reply),
                    Err(err) => match err {
                        smtp_proto::Error::NeedsMoreData { .. } => (),
                        _ => {
                            return Err(ClientError::UnparseableReply);
                        }
                    },
                }
            } else {
                return Err(ClientError::UnparseableReply);
            }
        }
    }

    pub async fn read_many(&mut self, num: usize) -> ClientResult<Vec<Response<Box<str>>>> {
        let mut buf = vec![0u8; 1024];
        let mut response = Vec::with_capacity(num);
        let mut parser = ResponseReceiver::default();

        'outer: loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                let mut iter = buf[..br].iter();

                trc::event!(
                    Delivery(DeliveryEvent::RawInput),
                    SpanId = self.session_id,
                    Contents = trc::Value::from_maybe_string(&buf[..br]),
                    Size = br
                );

                loop {
                    match parser.parse(&mut iter) {
                        Ok(reply) => {
                            response.push(reply.into_box());
                            if response.len() != num {
                                parser.reset();
                            } else {
                                break 'outer;
                            }
                        }
                        Err(err) => match err {
                            smtp_proto::Error::NeedsMoreData { .. } => break,
                            _ => {
                                return Err(ClientError::UnparseableReply);
                            }
                        },
                    }
                }
            } else {
                return Err(ClientError::UnparseableReply);
            }
        }

        Ok(response)
    }

    /// Sends a command to the SMTP server and waits for a reply.
    pub async fn cmd(&mut self, cmd: impl AsRef<[u8]>) -> ClientResult<Response<String>> {
        tokio::time::timeout(self.timeout, async {
            let cmd = cmd.as_ref();

            trc::event!(
                Delivery(DeliveryEvent::RawOutput),
                SpanId = self.session_id,
                Contents = trc::Value::from_maybe_string(cmd),
                Size = cmd.len()
            );

            self.stream.write_all(cmd).await?;
            self.stream.flush().await?;
            self.read().await
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    pub async fn write_message(&mut self, message: &[u8]) -> tokio::io::Result<()> {
        // Transparency procedure
        let mut is_cr_or_lf = false;

        // As per RFC 5322bis, section 2.3:
        // CR and LF MUST only occur together as CRLF; they MUST NOT appear
        // independently in the body.
        // For this reason, we apply the transparency procedure when there is
        // a CR or LF followed by a dot.

        trc::event!(
            Delivery(DeliveryEvent::RawOutput),
            SpanId = self.session_id,
            Contents = "[message]",
            Size = message.len() + 5
        );

        let mut last_pos = 0;
        for (pos, byte) in message.iter().enumerate() {
            if *byte == b'.' && is_cr_or_lf {
                if let Some(bytes) = message.get(last_pos..pos) {
                    self.stream.write_all(bytes).await?;
                    self.stream.write_all(b".").await?;
                    last_pos = pos;
                }
                is_cr_or_lf = false;
            } else {
                is_cr_or_lf = *byte == b'\n' || *byte == b'\r';
            }
        }
        if let Some(bytes) = message.get(last_pos..) {
            self.stream.write_all(bytes).await?;
        }
        self.stream.write_all("\r\n.\r\n".as_bytes()).await?;
        self.stream.flush().await
    }
}

impl SmtpClient<TcpStream> {
    /// Upgrade the connection to TLS.
    pub async fn start_tls(
        mut self,
        tls_connector: &TlsConnector,
        hostname: &str,
    ) -> ClientResult<SmtpClient<TlsStream<TcpStream>>> {
        // Send STARTTLS command
        self.cmd(b"STARTTLS\r\n")
            .await?
            .assert_positive_completion()?;

        self.into_tls(tls_connector, hostname).await
    }

    pub async fn into_tls(
        self,
        tls_connector: &TlsConnector,
        hostname: &str,
    ) -> ClientResult<SmtpClient<TlsStream<TcpStream>>> {
        tokio::time::timeout(self.timeout, async {
            Ok(SmtpClient {
                stream: tls_connector
                    .connect(
                        ServerName::try_from(hostname)
                            .map_err(|_| ClientError::InvalidTLSName)?
                            .to_owned(),
                        self.stream,
                    )
                    .await
                    .map_err(|err| {
                        let kind = err.kind();
                        if let Some(inner) = err.into_inner() {
                            match inner.downcast::<rustls::Error>() {
                                Ok(error) => ClientError::Tls(error),
                                Err(error) => ClientError::Io(std::io::Error::new(kind, error)),
                            }
                        } else {
                            ClientError::Io(std::io::Error::new(kind, "Unspecified"))
                        }
                    })?,
                timeout: self.timeout,
                session_id: self.session_id,
            })
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }
}

impl SmtpClient<TcpStream> {
    /// Connects to a remote host address
    pub async fn connect(
        remote_addr: SocketAddr,
        timeout: Duration,
        session_id: u64,
    ) -> ClientResult<Self> {
        tokio::time::timeout(timeout, async {
            Ok(SmtpClient {
                stream: TcpStream::connect(remote_addr).await?,
                timeout,
                session_id,
            })
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    /// Connects to a remote host address using the provided local IP
    pub async fn connect_using(
        local_ip: IpAddr,
        remote_addr: SocketAddr,
        timeout: Duration,
        session_id: u64,
    ) -> ClientResult<Self> {
        tokio::time::timeout(timeout, async {
            let socket = if local_ip.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(local_ip, 0))?;

            Ok(SmtpClient {
                stream: socket.connect(remote_addr).await?,
                timeout,
                session_id,
            })
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    pub async fn try_start_tls(
        mut self,
        tls_connector: &TlsConnector,
        hostname: &str,
        capabilities: &EhloResponse<String>,
    ) -> StartTlsResult {
        if capabilities.has_capability(EXT_START_TLS) {
            match self.cmd("STARTTLS\r\n").await {
                Ok(response) => {
                    if response.code() == 220 {
                        match self.into_tls(tls_connector, hostname).await {
                            Ok(smtp_client) => StartTlsResult::Success { smtp_client },
                            Err(error) => StartTlsResult::Error { error },
                        }
                    } else {
                        StartTlsResult::Unavailable {
                            response: response.into_box().into(),
                            smtp_client: self,
                        }
                    }
                }
                Err(error) => StartTlsResult::Error { error },
            }
        } else {
            StartTlsResult::Unavailable {
                smtp_client: self,
                response: None,
            }
        }
    }
}

fn encode_credentials(
    credentials: &Credentials,
    mechanism: u64,
    challenge: &str,
) -> ClientResult<String> {
    Ok(general_purpose::STANDARD.encode(
        match (mechanism, credentials) {
            (
                AUTH_PLAIN,
                Credentials::Basic {
                    username, secret, ..
                },
            ) => {
                format!("\u{0}{}\u{0}{}", username, secret)
            }
            (
                AUTH_LOGIN,
                Credentials::Basic {
                    username, secret, ..
                },
            ) => {
                let challenge = general_purpose::STANDARD.decode(challenge)?;

                if b"user name"
                    .eq_ignore_ascii_case(challenge.get(0..9).ok_or(ClientError::InvalidChallenge)?)
                    || b"username".eq_ignore_ascii_case(
                        // Because Google makes its own standards
                        challenge.get(0..8).ok_or(ClientError::InvalidChallenge)?,
                    )
                {
                    &username
                } else if b"password"
                    .eq_ignore_ascii_case(challenge.get(0..8).ok_or(ClientError::InvalidChallenge)?)
                {
                    &secret
                } else {
                    return Err(ClientError::InvalidChallenge);
                }
                .to_string()
            }

            (AUTH_XOAUTH2, Credentials::Bearer { token, username }) => format!(
                "user={}\x01auth=Bearer {}\x01\x01",
                username.as_deref().unwrap_or_default(),
                token
            ),
            (AUTH_OAUTHBEARER, Credentials::Bearer { token, .. }) => token.to_string(),
            _ => return Err(ClientError::UnsupportedAuthMechanism),
        }
        .as_bytes(),
    ))
}

impl SmtpClient<TlsStream<TcpStream>> {
    pub fn tls_connection(&self) -> &ClientConnection {
        self.stream.get_ref().1
    }
}

#[allow(clippy::large_enum_variant)]
pub enum StartTlsResult {
    Success {
        smtp_client: SmtpClient<TlsStream<TcpStream>>,
    },
    Error {
        error: ClientError,
    },
    Unavailable {
        response: Option<Response<Box<str>>>,
        smtp_client: SmtpClient<TcpStream>,
    },
}

pub(crate) trait BoxResponse {
    fn into_box(self) -> Response<Box<str>>;
}

impl BoxResponse for Response<String> {
    fn into_box(self) -> Response<Box<str>> {
        Response {
            code: self.code,
            esc: self.esc,
            message: self.message.into_boxed_str(),
        }
    }
}

pub(crate) fn from_mail_send_error(error: &ClientError) -> trc::Error {
    let event = trc::EventType::Smtp(trc::SmtpEvent::Error).into_err();
    match error {
        ClientError::Io(err) => event.details("I/O Error").reason(err),
        ClientError::Tls(err) => event.details("TLS Error").reason(err),
        ClientError::Base64(err) => event.details("Base64 Error").reason(err),
        ClientError::InvalidChallenge => event
            .details("SMTP Authentication Error")
            .reason("Invalid Challenge"),
        ClientError::UnparseableReply => event.details("Unparseable SMTP Reply"),
        ClientError::UnexpectedReply(reply) => event
            .details("Unexpected SMTP Response")
            .ctx(trc::Key::Code, reply.code)
            .ctx(trc::Key::Reason, reply.message.clone()),
        ClientError::AuthenticationFailed(reply) => event
            .details("SMTP Authentication Failed")
            .ctx(trc::Key::Code, reply.code)
            .ctx(trc::Key::Reason, reply.message.clone()),
        ClientError::InvalidTLSName => event.details("Invalid TLS Name"),
        ClientError::MissingCredentials => event.details("Missing Authentication Credentials"),
        ClientError::MissingMailFrom => event.details("Missing Message Sender"),
        ClientError::MissingRcptTo => event.details("Missing Message Recipients"),
        ClientError::UnsupportedAuthMechanism => {
            event.details("Unsupported Authentication Mechanism")
        }
        ClientError::Timeout => event.details("Connection Timeout"),
        ClientError::MissingStartTls => event.details("STARTTLS not available"),
    }
}

pub(crate) fn from_error_status(err: &Status<HostResponse<Box<str>>, ErrorDetails>) -> trc::Error {
    match err {
        Status::Scheduled | Status::Completed(_) => {
            trc::EventType::Smtp(trc::SmtpEvent::Error).into_err()
        }
        Status::TemporaryFailure(err) | Status::PermanentFailure(err) => {
            from_error_details(&err.details)
        }
    }
}

pub(crate) fn from_error_details(err: &Error) -> trc::Error {
    let event = trc::EventType::Smtp(trc::SmtpEvent::Error).into_err();
    match err {
        Error::DnsError(err) => event.details("DNS Error").reason(err),
        Error::UnexpectedResponse(reply) => event
            .details("Unexpected SMTP Response")
            .ctx(trc::Key::Code, reply.response.code)
            .ctx(trc::Key::Details, reply.command.clone())
            .ctx(trc::Key::Reason, reply.response.message.clone()),
        Error::ConnectionError(err) => event
            .details("Connection Error")
            .ctx(trc::Key::Reason, err.clone()),
        Error::TlsError(err) => event
            .details("TLS Error")
            .ctx(trc::Key::Reason, err.clone()),
        Error::DaneError(err) => event
            .details("DANE Error")
            .ctx(trc::Key::Reason, err.clone()),
        Error::MtaStsError(err) => event.details("MTA-STS Error").reason(err),
        Error::RateLimited => event.details("Rate Limited"),
        Error::ConcurrencyLimited => event.details("Concurrency Limited"),
        Error::Io(err) => event.details("I/O Error").reason(err),
    }
}
