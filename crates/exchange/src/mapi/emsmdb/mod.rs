/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod access;
pub mod cache;
pub mod copy;
pub mod execute;
pub mod folder;
pub mod folder_permissions;
pub mod folder_store;
pub mod folder_write;
pub mod ics;
pub mod logon;
pub mod message;
pub mod named;
pub mod notify;
pub mod props;
pub mod read_flags;
pub mod resolve;
pub mod rules;
pub mod search;
pub mod staged;
pub mod state;
pub mod store;
pub mod stream;
pub mod stream_write;
pub mod table;

use super::{
    http::{CookieSet, Envelope, Expiration, Reply},
    session::{
        LockOutcome, SessionKey, SessionKind, SessionLock, connect_allowed, delete_session,
        load_archive, load_session, refresh_session, save_session,
    },
};
use crate::{
    cache::{ExchangeCacheFetch, last_change_ids},
    identity::principal_from_dn,
    push::{ExchangePush, ExchangeReceiver},
};
use access::LogonAccess;
use cache::forget_session_content;
use common::{
    Server,
    auth::AccessToken,
    ipc::{PushNotification, ViewerStateChange},
    network::ServerInstance,
};
use exchange_proto::mapi::{
    BodyError, ErrorCode, MapiLimits, ResponseCode, StatusCode,
    aux_buffer::AuxOut,
    emsmdb::{
        ConnectRequest, ConnectResponse, begin_execute_response, finish_execute_response,
        parse_connect, parse_disconnect, parse_execute, parse_notification_wait,
        write_connect_response, write_disconnect_response, write_failure_body,
        write_notification_wait_response,
    },
};
use smallvec::SmallVec;
use staged::forget_staged_content;
use state::{ArchivedServerObject, EmsmdbState, MAX_LOGON_MAILBOXES, MailboxCursor};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use types::{collection::SyncCollection, type_state::DataType};
use utils::map::bitmap::Bitmap;

const WATCHED_TYPES: [DataType; 6] = [
    DataType::Email,
    DataType::Mailbox,
    DataType::Calendar,
    DataType::CalendarEvent,
    DataType::AddressBook,
    DataType::ContactCard,
];

pub struct EmsmdbRequest<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub instance: &'x Arc<ServerInstance>,
    pub envelope: &'x Envelope,
    pub body: &'x [u8],
}

enum BodyOutcome {
    ResponseCode(ResponseCode),
    Status(StatusCode),
    Error(ErrorCode),
}

impl From<BodyError> for BodyOutcome {
    fn from(err: BodyError) -> Self {
        let code = err.response_code();
        if code != ResponseCode::Success {
            BodyOutcome::ResponseCode(code)
        } else if err.status_code() != StatusCode::OK {
            BodyOutcome::Status(err.status_code())
        } else {
            BodyOutcome::Error(err.error_code())
        }
    }
}

fn response_code(code: ResponseCode) -> Reply {
    Reply {
        body: Vec::new(),
        response_code: Some(code),
        cookies: None,
        expiration: None,
    }
}

fn failure(status: StatusCode, cookies: Option<CookieSet>) -> Reply {
    let mut body = Vec::with_capacity(8);
    write_failure_body(&mut body, status);
    Reply {
        body,
        response_code: None,
        cookies,
        expiration: Some(Expiration::Session),
    }
}

impl EmsmdbRequest<'_> {
    fn session_key(&self) -> Result<SessionKey, ResponseCode> {
        self.envelope
            .context_key(SessionKind::Emsmdb, self.access_token.account_id())
    }

    pub async fn connect(&self) -> trc::Result<Reply> {
        let request = match parse_connect(self.body) {
            Ok(request) => request,
            Err(err) => {
                return Ok(match BodyOutcome::from(err) {
                    BodyOutcome::ResponseCode(code) => response_code(code),
                    BodyOutcome::Status(status) => failure(status, None),
                    BodyOutcome::Error(error) => self.connect_reply(error, None, ""),
                });
            }
        };
        if let Ok(previous) = self.session_key()
            && let LockOutcome::Acquired(lock) = SessionLock::acquire(self.server, previous).await?
        {
            delete_session(&lock).await?;
            lock.release().await?;
        }
        let account_id = self.access_token.account_id();
        if request.flags & ConnectRequest::FLAG_ADMIN != 0 {
            return Ok(self.connect_reply(ErrorCode::LOGIN_PERM, None, ""));
        }
        match principal_from_dn(request.user_dn) {
            Some(principal) if principal == account_id => {}
            Some(_) => return Ok(self.connect_reply(ErrorCode::ACCESS_DENIED, None, "")),
            None if request.user_dn.is_empty() => {
                return Ok(self.connect_reply(ErrorCode::ACCESS_DENIED, None, ""));
            }
            None => return Ok(self.connect_reply(ErrorCode::UNKNOWN_USER, None, "")),
        }
        if !connect_allowed(self.server, account_id).await? {
            return Ok(failure(StatusCode::SERVER_TOO_BUSY, None));
        }
        let account = self.server.account(account_id).await?;
        let display_name = account
            .description
            .as_deref()
            .unwrap_or(account.name.as_ref());
        let key = SessionKey::generate(SessionKind::Emsmdb, account_id);
        let mut state = EmsmdbState::new(
            account_id,
            request.code_page,
            request.lcid_sort,
            request.lcid_string,
        );
        let sequence = new_sequence();
        state.sequence = sequence;
        save_session(self.server, key, state).await?;
        Ok(self.connect_reply(
            ErrorCode::SUCCESS,
            Some(CookieSet {
                context: key,
                sequence: Some(sequence),
                expired: false,
            }),
            display_name,
        ))
    }

    fn connect_reply(
        &self,
        error: ErrorCode,
        cookies: Option<CookieSet>,
        display_name: &str,
    ) -> Reply {
        let aux = AuxOut::connect_default();
        let mut body = Vec::with_capacity(64 + display_name.len() * 2);
        write_connect_response(
            &mut body,
            &ConnectResponse {
                error,
                polls_max: ConnectResponse::POLLS_MAX_MS,
                retry_count: ConnectResponse::RETRY_COUNT,
                retry_delay: ConnectResponse::RETRY_DELAY_MS,
                dn_prefix: b"",
                display_name,
                aux: &aux,
            },
        );
        Reply {
            body,
            response_code: None,
            cookies,
            expiration: Some(Expiration::Connect),
        }
    }

    pub async fn disconnect(&self) -> trc::Result<Reply> {
        if let Err(err) = parse_disconnect(self.body) {
            return Ok(match BodyOutcome::from(err) {
                BodyOutcome::ResponseCode(code) => response_code(code),
                BodyOutcome::Status(status) => failure(status, None),
                BodyOutcome::Error(_) => self.disconnect_reply(None),
            });
        }
        let key = match self.session_key() {
            Ok(key) => key,
            Err(code) => return Ok(response_code(code)),
        };
        match SessionLock::acquire(self.server, key).await? {
            LockOutcome::Acquired(lock) => {
                delete_session(&lock).await?;
                forget_session_content(self.server, key.account_id, key.id);
                forget_staged_content(self.server, key.account_id, key.id);
                lock.release().await?;
            }
            LockOutcome::Busy => return Ok(response_code(ResponseCode::InvalidSequence)),
        }
        Ok(self.disconnect_reply(Some(key)))
    }

    fn disconnect_reply(&self, key: Option<SessionKey>) -> Reply {
        let mut body = Vec::with_capacity(12);
        write_disconnect_response(&mut body, ErrorCode::SUCCESS);
        Reply {
            body,
            response_code: None,
            cookies: key.map(|context| CookieSet {
                context,
                sequence: None,
                expired: false,
            }),
            expiration: Some(Expiration::Session),
        }
    }

    pub async fn ping(&self) -> trc::Result<Reply> {
        let mut reply = Reply {
            body: Vec::new(),
            response_code: None,
            cookies: None,
            expiration: None,
        };
        if let Ok(key) = self.session_key() {
            let alive = match SessionLock::acquire(self.server, key).await? {
                LockOutcome::Acquired(lock) => {
                    let alive = refresh_session(self.server, key).await?;
                    lock.release().await?;
                    alive
                }
                LockOutcome::Busy => true,
            };
            if alive {
                reply.expiration = Some(Expiration::Session);
                reply.cookies = Some(CookieSet {
                    context: key,
                    sequence: None,
                    expired: false,
                });
            } else {
                reply.response_code = Some(ResponseCode::ContextNotFound);
            }
        }
        Ok(reply)
    }

    pub async fn execute(&self) -> trc::Result<Reply> {
        let key = match self.session_key() {
            Ok(key) => key,
            Err(code) => return Ok(response_code(code)),
        };
        let LockOutcome::Acquired(lock) = SessionLock::acquire_patiently(self.server, key).await?
        else {
            return Ok(response_code(ResponseCode::InvalidSequence));
        };
        let reply = self.execute_locked(key).await?;
        lock.release().await?;
        Ok(reply)
    }

    async fn execute_locked(&self, key: SessionKey) -> trc::Result<Reply> {
        let Some(mut state) = load_session::<EmsmdbState>(self.server, key).await? else {
            return Ok(response_code(ResponseCode::ContextNotFound));
        };
        if state.account_id != self.access_token.account_id() {
            return Ok(response_code(ResponseCode::ContextNotFound));
        }
        if state.sequence != 0 && self.envelope.sequence_value() != Some(state.sequence) {
            return Ok(response_code(ResponseCode::InvalidSequence));
        }
        let limits = MapiLimits::DEFAULT;
        let parsed = parse_execute(self.body, &limits).map_err(BodyOutcome::from);
        if let Err(BodyOutcome::ResponseCode(code)) = parsed {
            return Ok(Reply {
                cookies: Some(CookieSet {
                    context: key,
                    sequence: Some(state.sequence),
                    expired: false,
                }),
                ..response_code(code)
            });
        }
        state.sequence = new_sequence();
        let cookies = CookieSet {
            context: key,
            sequence: Some(state.sequence),
            expired: false,
        };
        let reply = match parsed {
            Ok(request) => {
                let mut body = Vec::with_capacity(4096);
                let mut mark = begin_execute_response(&mut body);
                match execute::run(self, key.id, &mut state, &request, &mut body, &mut mark).await?
                {
                    execute::Outcome::Done => {
                        finish_execute_response(&mut body, mark, ErrorCode::SUCCESS);
                        Reply {
                            body,
                            response_code: None,
                            cookies: Some(cookies),
                            expiration: Some(Expiration::Session),
                        }
                    }
                    execute::Outcome::Error(error) => execute_error(error, cookies),
                    execute::Outcome::Status(status) => failure(status, Some(cookies)),
                }
            }
            Err(BodyOutcome::Status(status)) => failure(status, Some(cookies)),
            Err(BodyOutcome::Error(error)) => execute_error(error, cookies),
            Err(BodyOutcome::ResponseCode(code)) => response_code(code),
        };
        save_session(self.server, key, state).await?;
        Ok(reply)
    }

    pub async fn notification_wait(&self) -> trc::Result<WaitOutcome> {
        if let Err(err) = parse_notification_wait(self.body) {
            return Ok(WaitOutcome::Reply(match BodyOutcome::from(err) {
                BodyOutcome::ResponseCode(code) => response_code(code),
                BodyOutcome::Status(status) => failure(status, None),
                BodyOutcome::Error(error) => notification_reply(error, false),
            }));
        }
        let key = match self.session_key() {
            Ok(key) => key,
            Err(code) => return Ok(WaitOutcome::Reply(response_code(code))),
        };
        let account_id = self.access_token.account_id();
        let mut types = Bitmap::from_iter(WATCHED_TYPES);
        self.access_token.restrict_data_types(&mut types);
        let mut cursors: SmallVec<[MailboxCursor; MAX_LOGON_MAILBOXES]> = SmallVec::new();
        let mut mailboxes: SmallVec<[u32; MAX_LOGON_MAILBOXES]> = SmallVec::new();
        match load_archive(self.server, key).await? {
            Some(archive) => {
                let state = archive.unarchive_untrusted::<EmsmdbState>()?;
                if state.account_id.to_native() == account_id {
                    cursors.extend(
                        state
                            .seen
                            .iter()
                            .map(|cursor| MailboxCursor {
                                mailbox_id: cursor.mailbox_id.to_native(),
                                heads: cursor.heads.map(|id| id.to_native()),
                                exchange_change: cursor.exchange_change.to_native(),
                            })
                            .filter(|cursor| {
                                LogonAccess::of(self.access_token, cursor.mailbox_id).is_some()
                            })
                            .take(MAX_LOGON_MAILBOXES),
                    );
                    mailboxes.extend(cursors.iter().map(|cursor| cursor.mailbox_id));
                    for slot in state.objects.iter() {
                        if mailboxes.len() == MAX_LOGON_MAILBOXES {
                            break;
                        }
                        if let Some(ArchivedServerObject::Logon(logon)) = slot.object.as_ref() {
                            let mailbox_id = logon.mailbox_id.to_native();
                            if !mailboxes.contains(&mailbox_id)
                                && LogonAccess::of(self.access_token, mailbox_id).is_some()
                            {
                                mailboxes.push(mailbox_id);
                            }
                        }
                    }
                }
            }
            None => {
                return Ok(WaitOutcome::Reply(response_code(
                    ResponseCode::ContextNotFound,
                )));
            }
        }
        if mailboxes.is_empty() {
            mailboxes.push(account_id);
        }
        let receiver = self.server.subscribe_exchange_accounts(&mailboxes, types);
        let mut watch = Watch::Changes(receiver);
        for cursor in &cursors {
            if notify::behind(
                &cursor.heads,
                &last_change_ids(self.server, cursor.mailbox_id).await?,
                types,
            ) {
                watch = Watch::Pending(cursor.mailbox_id);
                break;
            }
        }
        Ok(WaitOutcome::Wait(NotificationWait {
            server: self.server.clone(),
            key,
            mailboxes,
            watch,
            wait: self
                .server
                .core
                .exchange
                .max_heartbeat
                .min(Duration::from_millis(u64::from(
                    exchange_proto::mapi::http::NOTIFICATION_WAIT_MS,
                ))),
        }))
    }
}

pub enum WaitOutcome {
    Reply(Reply),
    Wait(NotificationWait),
}

pub struct NotificationWait {
    server: Server,
    key: SessionKey,
    mailboxes: SmallVec<[u32; MAX_LOGON_MAILBOXES]>,
    watch: Watch,
    wait: Duration,
}

enum Watch {
    Pending(u32),
    Changes(ExchangeReceiver),
}

impl NotificationWait {
    pub fn cookies(&self) -> CookieSet {
        CookieSet {
            context: self.key,
            sequence: None,
            expired: false,
        }
    }

    pub async fn run(self) -> Vec<u8> {
        let deadline = Instant::now() + self.wait;
        let mut woken: SmallVec<[u32; MAX_LOGON_MAILBOXES]> = SmallVec::new();
        match self.watch {
            Watch::Pending(mailbox_id) => woken.push(mailbox_id),
            Watch::Changes(mut receiver) => {
                let mut notifications = Vec::new();
                while woken.is_empty()
                    && matches!(
                        tokio::time::timeout_at(deadline, receiver.recv(&mut notifications)).await,
                        Ok(true)
                    )
                {
                    for notification in &notifications {
                        if let PushNotification::StateChange(change)
                        | PushNotification::ViewerStateChange(ViewerStateChange {
                            change, ..
                        }) = notification
                            && self.mailboxes.contains(&change.account_id)
                            && !woken.contains(&change.account_id)
                        {
                            woken.push(change.account_id);
                        }
                    }
                    notifications.clear();
                }
            }
        }
        let pending = !woken.is_empty();
        for account_id in woken {
            self.server.mark_exchange_stale(account_id);
            self.server
                .inner
                .mark_cache_stale(account_id, SyncCollection::Email);
        }
        let server = self.server;
        let key = self.key;
        let refresh = tokio::spawn(async move {
            if let Err(err) = refresh_unlocked(&server, key).await {
                trc::error!(err.details("Failed to refresh MAPI session"));
            }
        });
        if let Err(err) = refresh.await {
            trc::error!(
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .details("MAPI session refresh task failed")
            );
        }
        let mut body = Vec::with_capacity(16);
        write_notification_wait_response(&mut body, ErrorCode::SUCCESS, pending);
        body
    }
}

async fn refresh_unlocked(server: &Server, key: SessionKey) -> trc::Result<()> {
    if let LockOutcome::Acquired(lock) = SessionLock::acquire(server, key).await? {
        let refreshed = refresh_session(server, key).await;
        lock.release().await?;
        refreshed?;
    }
    Ok(())
}

fn notification_reply(error: ErrorCode, pending: bool) -> Reply {
    let mut body = Vec::with_capacity(16);
    write_notification_wait_response(&mut body, error, pending);
    Reply {
        body,
        response_code: None,
        cookies: None,
        expiration: Some(Expiration::Session),
    }
}

fn execute_error(error: ErrorCode, cookies: CookieSet) -> Reply {
    let mut body = Vec::with_capacity(24);
    let mark = begin_execute_response(&mut body);
    finish_execute_response(&mut body, mark, error);
    Reply {
        body,
        response_code: None,
        cookies: Some(cookies),
        expiration: Some(Expiration::Session),
    }
}

fn new_sequence() -> u64 {
    ::store::rand::random::<u64>() | 1
}
