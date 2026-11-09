/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{connect::PgConnect, into_error};
use deadpool::managed::{self, Metrics, RecycleError, RecycleResult};
use deadpool_postgres::{ClientWrapper, Manager};
use futures::{FutureExt, StreamExt};
use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};
use tokio_postgres::SimpleQueryStream;

const ROLLBACK: &str = "ROLLBACK";

pub type PgPool = managed::Pool<PgManager>;
pub type PgObject = managed::Object<PgManager>;

pub struct PgManager {
    manager: Manager,
    connect: PgConnect,
}

pub struct PgConn {
    client: ClientWrapper,
    rollback: Option<Pin<Box<SimpleQueryStream>>>,
}

pub(crate) enum RollbackOutcome {
    Succeeded,
    Failed,
    Pending,
}

impl PgManager {
    pub(crate) fn new(manager: Manager, connect: PgConnect) -> Self {
        PgManager { manager, connect }
    }

    pub(crate) fn is_unresponsive(&self) -> bool {
        self.connect.is_unresponsive()
    }
}

impl managed::Manager for PgManager {
    type Type = PgConn;
    type Error = trc::Error;

    async fn create(&self) -> trc::Result<PgConn> {
        let (client, connection) = Box::pin(self.connect.connect()).await?;
        Ok(PgConn {
            client: ClientWrapper::new(client, connection),
            rollback: None,
        })
    }

    async fn recycle(&self, conn: &mut PgConn, metrics: &Metrics) -> RecycleResult<trc::Error> {
        conn.check_deferred_rollback()?;
        self.manager
            .recycle(&mut conn.client, metrics)
            .await
            .map_err(|err| match err {
                RecycleError::Message(message) => RecycleError::Message(message),
                RecycleError::Backend(err) => RecycleError::Backend(into_error(err)),
            })?;
        conn.check_deferred_rollback()
    }

    fn detach(&self, conn: &mut PgConn) {
        self.manager.detach(&mut conn.client);
    }
}

impl PgConn {
    pub(crate) fn defer_rollback(&mut self) -> bool {
        if !matches!(self.rollback_outcome(), RollbackOutcome::Succeeded) {
            return false;
        }
        #[cfg(stalwart_tests)]
        let statement = if crate::backend::sql_fault::fire() {
            crate::backend::sql_fault::FAILING_ROLLBACK
        } else {
            ROLLBACK
        };
        #[cfg(not(stalwart_tests))]
        let statement = ROLLBACK;
        match self.client.simple_query_raw(statement).now_or_never() {
            Some(Ok(stream)) => {
                self.rollback = Some(Box::pin(stream));
                true
            }
            _ => false,
        }
    }

    fn check_deferred_rollback(&mut self) -> RecycleResult<trc::Error> {
        if let RollbackOutcome::Failed = self.rollback_outcome() {
            #[cfg(stalwart_tests)]
            crate::backend::sql_fault::record_detection(
                crate::backend::sql_fault::Detection::Checkout,
            );
            Err(RecycleError::message("Deferred ROLLBACK failed"))
        } else {
            Ok(())
        }
    }

    pub(crate) fn rollback_outcome(&mut self) -> RollbackOutcome {
        let Some(mut stream) = self.rollback.take() else {
            return RollbackOutcome::Succeeded;
        };
        loop {
            match stream.next().now_or_never() {
                Some(Some(Ok(_))) => (),
                Some(None) => return RollbackOutcome::Succeeded,
                Some(Some(Err(_))) => return RollbackOutcome::Failed,
                None => {
                    self.rollback = Some(stream);
                    return RollbackOutcome::Pending;
                }
            }
        }
    }
}

impl Deref for PgConn {
    type Target = ClientWrapper;

    #[inline]
    fn deref(&self) -> &ClientWrapper {
        &self.client
    }
}

impl DerefMut for PgConn {
    #[inline]
    fn deref_mut(&mut self) -> &mut ClientWrapper {
        &mut self.client
    }
}
