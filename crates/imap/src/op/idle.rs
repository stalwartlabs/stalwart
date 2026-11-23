/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::{AccountCaches, SelectedAccess, SelectedMailbox, Session, SessionData, State},
    op::ImapContext,
};
use common::{
    auth::AccessToken,
    ipc::{
        PushNotification,
        subscribers::{PushReceiver, PushSubscribers},
    },
    network::SessionStream,
};
use compact_str::CompactString;
use email::cache::MessageCacheFetch;
use imap_proto::{
    Command, StatusResponse,
    protocol::{
        Sequence, fetch,
        list::{Attribute, ListItem},
        status::Status,
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{
    future::pending,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, sync::OwnedSemaphorePermit};
use trc::AddContext;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

const SHARED_STATUS_INTERVAL: Duration = Duration::from_secs(1);

impl<T: SessionStream> Session<T> {
    pub async fn handle_idle(
        &mut self,
        request: Request<Command>,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapIdle)?;

        let op_start = Instant::now();
        let (data, mailbox, types) = match &self.state {
            State::Authenticated { data, .. } => {
                (data.clone(), None, Bitmap::from_iter([DataType::Mailbox]))
            }
            State::Selected { data, mailbox, .. } => (
                data.clone(),
                mailbox.clone().into(),
                Bitmap::from_iter([DataType::Email, DataType::Mailbox, DataType::EmailDelivery]),
            ),
            _ => unreachable!(),
        };
        let is_rev2 = self.version.is_rev2();
        let is_utf8 = self.is_utf8;
        let is_uidonly = self.is_uidonly;
        let is_objectid = self.is_objectid;
        let use_vanished = self.is_qresync || is_uidonly;
        let is_condstore =
            self.is_condstore || mailbox.as_ref().is_some_and(|mailbox| mailbox.is_condstore);

        // Register with push manager
        let primary_id = mailbox
            .as_ref()
            .map_or(data.account_id, |mailbox| mailbox.id.account_id);
        let view_sync = if data.is_acl_shared(primary_id) {
            ViewSync::SyncIfReadable
        } else {
            ViewSync::Sync
        };
        let (mut primary_rx, mut shared_rx) = subscribe_idle(
            &self.server.inner.ipc.push_subscribers,
            &data.access_token,
            primary_id,
            types,
        );

        data.seed_mailbox_counters()
            .await
            .imap_ctx(&request.tag, trc::location!())?;

        // Send continuation response
        self.write_bytes(b"+ Idling, send 'DONE' to stop.\r\n".to_vec())
            .await?;
        if let Some(mailbox) = &mailbox {
            data.flush_view(mailbox, use_vanished)
                .await
                .imap_ctx(&request.tag, trc::location!())?;
        }

        trc::event!(
            Imap(trc::ImapEvent::IdleStart),
            SpanId = self.session_id,
            Elapsed = op_start.elapsed()
        );

        let op_start = Instant::now();
        let timeout_idle = self.server.core.imap.timeout_idle;
        let mut window = [0u8; 4];
        let mut byte = [0u8; 1];
        let mut notifications = Vec::new();
        let mut shared_notifications = Vec::new();
        let mut schedule = PassSchedule::Paced(op_start);
        loop {
            let wait = schedule.wait(timeout_idle);
            let wake = tokio::select! {
                result = tokio::time::timeout(wait, self.stream_rx.read(&mut byte)) => {
                    match result {
                        Ok(Ok(0)) => {
                            return Err(trc::NetworkEvent::Closed.into_err().details("IMAP connection closed by client.").id(request.tag));
                        }
                        Ok(Ok(_)) => {
                            window.rotate_left(1);
                            window[3] = byte[0];
                            if &window == b"DONE" {
                                if schedule.is_deferred()
                                    && let Err(err) = data.write_changes(mailbox.as_ref(), true, ViewSync::Skip, use_vanished, is_condstore, is_uidonly, is_rev2, is_utf8, is_objectid).await
                                {
                                    trc::error!(err.span_id(self.session_id));
                                }
                                trc::event!(Imap(trc::ImapEvent::IdleStop), SpanId = self.session_id, Elapsed = op_start.elapsed());
                                return self.write_bytes(StatusResponse::completed(Command::Idle)
                                                                .with_tag(request.tag)
                                                                .into_bytes()).await;
                            }
                            continue;
                        },
                        Ok(Err(err)) => {
                            return Err(trc::NetworkEvent::ReadError.into_err().reason(err).details("IMAP connection error.").id(request.tag));
                        },
                        Err(_) if wait < timeout_idle => Wake::Due,
                        Err(_) => {
                            self.write_bytes(&b"* BYE IDLE timed out.\r\n"[..]).await.ok();
                            return Err(trc::NetworkEvent::Timeout.into_err().details("IMAP IDLE timed out.").id(request.tag));
                        }
                    }
                }
                received = primary_rx.recv(&mut notifications) => Wake::received(received),
                received = recv_shared(&mut shared_rx, &mut shared_notifications), if !schedule.is_deferred() => Wake::received(received),
            };

            let mut check_mailboxes = match wake {
                Wake::Notified => false,
                Wake::Due => true,
                Wake::Closed => return Err(self.idle_closed(request.tag).await),
            };
            data.assert_session_access()
                .await
                .map_err(|err| err.id(request.tag.clone()))?;
            let mut changes = IdleChanges::default();
            for notification in notifications.drain(..) {
                changes.add(&notification);
            }
            let mut shared = IdleChanges::default();
            for notification in shared_notifications.drain(..) {
                shared.add(&notification);
            }
            check_mailboxes |=
                changes.mailboxes || (shared.mailboxes && schedule.admits_shared(Instant::now()));
            if check_mailboxes && let Some(shared_rx) = &mut shared_rx {
                if !take_pending(shared_rx, &mut shared_notifications) {
                    return Err(self.idle_closed(request.tag).await);
                }
                shared_notifications.clear();
            }

            let view = changes.view_sync(view_sync);
            if check_mailboxes || view != ViewSync::Skip {
                data.write_changes(
                    mailbox.as_ref(),
                    check_mailboxes,
                    view,
                    use_vanished,
                    is_condstore,
                    is_uidonly,
                    is_rev2,
                    is_utf8,
                    is_objectid,
                )
                .await?;
            }
            if check_mailboxes && shared_rx.is_some() {
                schedule.passed(Instant::now());
            }
        }
    }

    async fn idle_closed(&self, tag: CompactString) -> trc::Error {
        self.write_bytes(&b"* BYE Server shutting down.\r\n"[..])
            .await
            .ok();
        trc::NetworkEvent::Closed
            .into_err()
            .details("IDLE channel closed.")
            .id(tag)
    }
}

fn subscribe_idle(
    subscribers: &Arc<PushSubscribers>,
    access_token: &AccessToken,
    primary_id: u32,
    types: Bitmap<DataType>,
) -> (PushReceiver, Option<PushReceiver>) {
    let shared_rx = access_token
        .member_ids()
        .any(|account_id| account_id != primary_id)
        .then(|| {
            subscribers.subscribe(
                access_token
                    .member_ids()
                    .filter(|account_id| *account_id != primary_id),
                Bitmap::from_iter([DataType::Mailbox]),
            )
        });
    (subscribers.subscribe([primary_id], types), shared_rx)
}

async fn recv_shared(
    shared_rx: &mut Option<PushReceiver>,
    notifications: &mut Vec<PushNotification>,
) -> bool {
    match shared_rx {
        Some(shared_rx) => shared_rx.recv(notifications).await,
        None => pending().await,
    }
}

fn take_pending(rx: &mut PushReceiver, notifications: &mut Vec<PushNotification>) -> bool {
    match pin!(rx.recv(notifications)).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(is_open) => is_open,
        Poll::Pending => true,
    }
}

enum Wake {
    Notified,
    Due,
    Closed,
}

impl Wake {
    fn received(received: bool) -> Self {
        if received {
            Wake::Notified
        } else {
            Wake::Closed
        }
    }
}

#[derive(Default)]
struct IdleChanges {
    mailboxes: bool,
    emails: bool,
}

impl IdleChanges {
    fn add(&mut self, notification: &PushNotification) {
        match notification {
            PushNotification::StateChange(state_change) => {
                for type_state in state_change.types {
                    match type_state {
                        DataType::Email | DataType::EmailDelivery => self.emails = true,
                        DataType::Mailbox => self.mailboxes = true,
                        _ => {}
                    }
                }
            }
            PushNotification::EmailPush(_) => {
                self.emails = true;
                self.mailboxes = true;
            }
            PushNotification::ViewerStateChange(_) | PushNotification::CalendarAlert(_) => {}
        }
    }

    fn view_sync(&self, sync: ViewSync) -> ViewSync {
        match sync {
            ViewSync::Sync if self.emails => sync,
            ViewSync::SyncIfReadable if self.emails || self.mailboxes => sync,
            _ => ViewSync::Skip,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewSync {
    Skip,
    Sync,
    SyncIfReadable,
}

enum PassSchedule {
    Paced(Instant),
    Deferred(Instant),
}

impl PassSchedule {
    fn is_deferred(&self) -> bool {
        matches!(self, PassSchedule::Deferred(_))
    }

    fn wait(&self, timeout: Duration) -> Duration {
        match self {
            PassSchedule::Deferred(due) => {
                due.saturating_duration_since(Instant::now()).min(timeout)
            }
            PassSchedule::Paced(_) => timeout,
        }
    }

    fn admits_shared(&mut self, now: Instant) -> bool {
        match *self {
            PassSchedule::Paced(due) | PassSchedule::Deferred(due) if due > now => {
                *self = PassSchedule::Deferred(due);
                false
            }
            _ => true,
        }
    }

    fn passed(&mut self, now: Instant) {
        *self = PassSchedule::Paced(now + SHARED_STATUS_INTERVAL);
    }
}

impl<T: SessionStream> SessionData<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn write_changes(
        &self,
        mailbox: Option<&Arc<SelectedMailbox>>,
        check_mailboxes: bool,
        view: ViewSync,
        use_vanished: bool,
        is_condstore: bool,
        is_uidonly: bool,
        is_rev2: bool,
        is_utf8: bool,
        is_objectid: bool,
    ) -> trc::Result<()> {
        // Synchronize the selected mailbox first so the account counters are current
        let mut changed_uids = Vec::new();
        let mut access_token = None;
        let cache = match (mailbox, view) {
            (Some(mailbox), ViewSync::Sync) => Some(
                self.server
                    .get_cached_messages(mailbox.id.account_id)
                    .await
                    .caused_by(trc::location!())?,
            ),
            (Some(mailbox), ViewSync::SyncIfReadable) => {
                match self
                    .selected_access(&mailbox.id)
                    .await
                    .caused_by(trc::location!())?
                {
                    SelectedAccess::Readable {
                        access_token: token,
                        cache,
                    } => {
                        access_token = Some(token);
                        Some(cache)
                    }
                    SelectedAccess::Revoked => return Err(self.close_revoked().await),
                }
            }
            _ => None,
        };
        if let (Some(mailbox), Some(cache)) = (mailbox, &cache) {
            self.sync_view(mailbox, cache, Some(&mut changed_uids))
                .await
                .caused_by(trc::location!())?;
        }

        // Fetch all changed mailboxes
        if check_mailboxes {
            let caches = match (mailbox, &cache) {
                (Some(mailbox), Some(cache)) => {
                    AccountCaches::with(mailbox.id.account_id, cache.clone())
                }
                _ => AccountCaches::default(),
            };
            let refresh = match access_token {
                Some(access_token) => {
                    self.synchronize_mailboxes_as(access_token, true, caches)
                        .await
                }
                None => self.synchronize_mailboxes_using(true, caches).await,
            }
            .caused_by(trc::location!())?;
            let changes = refresh.changes.unwrap_or_default();
            let mut caches = refresh.caches;
            let access_token = refresh.access_token;

            let mut buf = Vec::with_capacity(64);

            // List deleted mailboxes
            for change in changes.deleted {
                ListItem {
                    mailbox_name: change.name.into(),
                    attributes: vec![Attribute::NonExistent],
                    tags: vec![],
                    objectid: is_objectid.then_some(change.objectid),
                    metadata: None,
                }
                .serialize(&mut buf, is_rev2, is_utf8, false);
            }

            // List added mailboxes
            for change in changes.added {
                ListItem {
                    mailbox_name: change.name.into(),
                    attributes: vec![],
                    tags: vec![],
                    objectid: is_objectid.then_some(change.objectid),
                    metadata: None,
                }
                .serialize(&mut buf, is_rev2, is_utf8, false);
            }
            // Obtain status of changed mailboxes
            let status_items: &[Status] = if is_condstore {
                &[
                    Status::Messages,
                    Status::Unseen,
                    Status::UidNext,
                    Status::UidValidity,
                    Status::HighestModSeq,
                ]
            } else {
                &[
                    Status::Messages,
                    Status::Unseen,
                    Status::UidNext,
                    Status::UidValidity,
                ]
            };
            for mailbox_name in changes.changed {
                if let Ok(status) = self
                    .status(
                        &mut caches,
                        &access_token,
                        mailbox_name.into(),
                        status_items,
                    )
                    .await
                {
                    status.serialize(&mut buf, is_utf8);
                }
            }

            if !buf.is_empty() {
                self.write_bytes(buf).await?;
            }
        }

        // Fetch selected mailbox changes
        if let (Some(mailbox), Some(cache)) = (mailbox, cache) {
            self.flush_view(mailbox, use_vanished)
                .await
                .caused_by(trc::location!())?;

            if !changed_uids.is_empty() {
                changed_uids.sort_unstable();
                changed_uids.dedup();
                let op_start = Instant::now();
                return self
                    .fetch(
                        fetch::Arguments {
                            tag: "".into(),
                            sequence_set: Sequence::List {
                                items: changed_uids
                                    .into_iter()
                                    .map(|uid| Sequence::Number { value: uid })
                                    .collect(),
                            },
                            attributes: vec![fetch::Attribute::Flags, fetch::Attribute::Uid],
                            changed_since: None,
                            include_vanished: false,
                        },
                        mailbox.clone(),
                        Some(cache),
                        true,
                        use_vanished,
                        is_uidonly,
                        false,
                        is_utf8,
                        u32::MAX,
                        op_start,
                    )
                    .await
                    .caused_by(trc::location!())
                    .map(|_| ());
            }
        }

        Ok(())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap/src/op/idle/tests.rs"]
mod tests;
