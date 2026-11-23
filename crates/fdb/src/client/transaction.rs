/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Cluster, Retry,
    commit_buffer::{CommitBuffer, Lookup, PendingOps},
    expiry::{Deadlines, Timer, deadline_after, is_expired, timed_out},
    grv::Waiter,
};
use crate::api::{
    KEYSPACE_END, MAX_KEY_SIZE,
    config::TransactionDefaults,
    error::{Error, ErrorCode, Result},
    read::Priority,
    transaction::{Causality, TransactionOptions},
    version::{ReadVersionPolicy, Version},
};
use bytes::Bytes;
use pin_project_lite::pin_project;
use std::{
    pin::{Pin, pin},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::{Notify, futures::Notified},
    time::Instant,
};

pub(crate) struct TransactionState {
    options: TransactionOptions,
    pub(crate) buffer: CommitBuffer,
    attempt: Option<Arc<Attempt>>,
    retry: Retry,
    deadline: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct Attempt {
    version: OnceLock<Result<Version>>,
    requested: AtomicBool,
    filled: Notify,
    cancellation: Cancellation,
}

pin_project! {
    pub(crate) struct Race<'a, F> {
        #[pin]
        future: F,
        #[pin]
        cancelled: Notified<'a>,
        cancellation: &'a Cancellation,
        timer: Timer<'a>,
    }
}

#[derive(Default)]
pub(crate) struct Cancellation {
    code: AtomicU16,
    cancelled: Notify,
    deadline: Option<Instant>,
}

impl Cancellation {
    pub(crate) fn check(&self) -> Result<()> {
        self.check_code()?;
        match self.deadline {
            Some(deadline) if is_expired(deadline) => {
                self.cancel(ErrorCode::TRANSACTION_TIMED_OUT);
                self.check_code()
            }
            _ => Ok(()),
        }
    }

    fn check_code(&self) -> Result<()> {
        match self.code.load(Ordering::Relaxed) {
            0 => Ok(()),
            code => Err(Error::new(ErrorCode::new(code))),
        }
    }

    pub(crate) fn race<'a, F: Future>(
        &'a self,
        deadlines: &'a Deadlines,
        future: F,
    ) -> Race<'a, F> {
        Race {
            future,
            cancelled: self.cancelled.notified(),
            cancellation: self,
            timer: Timer::new(deadlines),
        }
    }

    fn cancel(&self, code: ErrorCode) {
        if self
            .code
            .compare_exchange(0, code.get(), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.cancelled.notify_waiters();
        }
    }
}

impl<F: Future> Future for Race<'_, F> {
    type Output = Result<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        if this.timer.is_armed() {
            this.cancellation.check_code()?;
        } else {
            this.cancellation.check()?;
        }
        if let Poll::Ready(output) = this.future.poll(cx) {
            return Poll::Ready(Ok(output));
        }
        if let Some(deadline) = this.cancellation.deadline
            && this.timer.poll_expired(deadline, cx).is_ready()
        {
            this.cancellation.cancel(ErrorCode::TRANSACTION_TIMED_OUT);
        }
        loop {
            this.cancellation.check_code()?;
            if this.cancelled.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.cancelled.set(this.cancellation.cancelled.notified());
        }
    }
}

impl Attempt {
    fn new(deadline: Option<Instant>) -> Self {
        Attempt {
            cancellation: Cancellation {
                deadline,
                ..Cancellation::default()
            },
            ..Attempt::default()
        }
    }

    pub(crate) fn check(&self) -> Result<()> {
        self.cancellation.check()
    }

    pub(crate) fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }

    pub(crate) async fn version(
        self: &Arc<Self>,
        cluster: &Cluster,
        policy: ReadVersionPolicy,
        priority: Priority,
        causality: Causality,
    ) -> Result<Version> {
        if let Some(version) = self.version.get() {
            return *version;
        }
        match policy {
            ReadVersionPolicy::Fresh => {
                if !self.requested.swap(true, Ordering::Relaxed) {
                    cluster.request_read_version(
                        Waiter::Attempt(self.clone()),
                        priority,
                        causality,
                    );
                }
                self.wait_for_version().await
            }
            policy => {
                let fetched = cluster.read_version(policy, priority).await;
                *self.version.get_or_init(|| fetched)
            }
        }
    }

    async fn wait_for_version(&self) -> Result<Version> {
        loop {
            let mut filled = pin!(self.filled.notified());
            filled.as_mut().enable();
            if let Some(version) = self.version.get() {
                return *version;
            }
            self.check()?;
            filled.await;
        }
    }

    pub(crate) fn fill(&self, result: Result<Version>) {
        let _ = self.version.set(result);
        self.filled.notify_waiters();
    }

    fn cancel(&self, code: ErrorCode) {
        self.cancellation.cancel(code);
        self.filled.notify_waiters();
    }

    fn known_version(&self) -> Option<Version> {
        self.version.get().and_then(|version| version.ok())
    }
}

impl TransactionState {
    pub(crate) fn new(options: TransactionOptions, defaults: TransactionDefaults) -> Self {
        TransactionState {
            options,
            buffer: CommitBuffer::default(),
            attempt: None,
            retry: Retry::new(),
            deadline: deadline_after(defaults.timeout),
        }
    }

    pub(crate) fn options(&self) -> &TransactionOptions {
        &self.options
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub(crate) fn attempt(&mut self) -> Arc<Attempt> {
        self.current().clone()
    }

    fn current(&mut self) -> &Arc<Attempt> {
        let deadline = self.deadline;
        self.attempt
            .get_or_insert_with(|| Arc::new(Attempt::new(deadline)))
    }

    pub(crate) fn commit_attempt(&mut self) -> (Arc<Attempt>, Causality) {
        match &self.attempt {
            Some(attempt) => (attempt.clone(), self.options.causality),
            None => (self.attempt(), Causality::ReadRisky),
        }
    }

    pub(crate) fn begin_read(&mut self, key: &[u8]) -> Result<Read> {
        self.buffer.check()?;
        let readable = readable(key);
        if !matches!(readable, Ok(true)) {
            self.check_expired()?;
        }
        if !readable? {
            return Ok(Read::Done(None));
        }
        let ops = match self.buffer.lookup(key) {
            Lookup::Unmodified => None,
            Lookup::Dependent(ops) => Some(ops),
            Lookup::Known(value) => {
                self.check_expired()?;
                return Ok(Read::Done(value));
            }
        };
        self.buffer.read_key(key);
        Ok(Read::Storage(self.attempt(), ops))
    }

    pub(crate) fn known_version(&self) -> Option<Version> {
        self.attempt.as_deref().and_then(Attempt::known_version)
    }

    pub(crate) fn next_delay(
        &mut self,
        error: Error,
        defaults: &TransactionDefaults,
    ) -> Result<Duration> {
        self.check_expired()?;
        if matches!(self.options.read_version, ReadVersionPolicy::At(_))
            && error.error_code() == ErrorCode::TRANSACTION_TOO_OLD
        {
            self.cancel();
            return Err(error);
        }
        self.retry
            .next_delay(error, defaults)
            .inspect_err(|_| self.cancel())
    }

    fn check_expired(&self) -> Result<()> {
        match self.attempt.as_deref() {
            Some(attempt) => attempt.check(),
            None if self.deadline.is_some_and(is_expired) => Err(timed_out()),
            None => Ok(()),
        }
    }

    pub(crate) fn next_attempt(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            attempt.cancel(ErrorCode::TRANSACTION_CANCELLED);
        }
        self.buffer.clear_all();
    }

    pub(crate) fn reset(&mut self, defaults: &TransactionDefaults) {
        self.next_attempt();
        self.retry = Retry::new();
        self.deadline = deadline_after(defaults.timeout);
    }

    fn cancel(&mut self) {
        self.current().cancel(ErrorCode::TRANSACTION_CANCELLED);
    }
}

impl Drop for TransactionState {
    fn drop(&mut self) {
        if let Some(attempt) = &self.attempt {
            attempt.cancel(ErrorCode::TRANSACTION_CANCELLED);
        }
    }
}

pub(crate) enum Read {
    Done(Option<Bytes>),
    Storage(Arc<Attempt>, Option<PendingOps>),
}

pub(crate) fn readable(key: &[u8]) -> Result<bool> {
    if key >= KEYSPACE_END {
        Err(Error::new(ErrorCode::KEY_OUTSIDE_LEGAL_RANGE))
    } else {
        Ok(key.len() <= MAX_KEY_SIZE)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/transaction/tests.rs"]
mod tests;
