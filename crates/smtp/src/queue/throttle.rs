/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::throttle::NewKey;
use common::{
    KV_RATE_LIMIT_SMTP, Server, config::smtp::QueueRateLimiter, expr::functions::ResolveVariable,
};
use registry::schema::prelude::Property;
use std::future::Future;
use store::write::now;

pub trait IsAllowed: Sync + Send {
    fn is_allowed<'x>(
        &'x self,
        throttle: &'x QueueRateLimiter,
        envelope: &impl ResolveVariable,
        session_id: u64,
    ) -> impl Future<Output = Result<(), u64>> + Send;
}

impl IsAllowed for Server {
    async fn is_allowed<'x>(
        &'x self,
        throttle: &'x QueueRateLimiter,
        envelope: &impl ResolveVariable,
        session_id: u64,
    ) -> Result<(), u64> {
        if throttle.expr.is_empty()
            || self
                .eval_expr(
                    &throttle.expr,
                    envelope,
                    throttle.id,
                    Property::Match,
                    session_id,
                )
                .await
                .unwrap_or(false)
        {
            let key = throttle.new_key(envelope, "outbound");

            match self
                .in_memory_store()
                .is_rate_allowed(KV_RATE_LIMIT_SMTP, key.as_ref(), &throttle.rate, false)
                .await
            {
                Ok(Some(next_refill)) => {
                    trc::event!(
                        Queue(trc::QueueEvent::RateLimitExceeded),
                        SpanId = session_id,
                        Id = throttle.id.to_string(),
                        Limit = vec![
                            trc::Value::from(throttle.rate.count),
                            trc::Value::from(throttle.rate.period.into_inner())
                        ],
                    );

                    return Err(now() + next_refill);
                }
                Err(err) => {
                    trc::error!(err.span_id(session_id).caused_by(trc::location!()));
                }
                _ => (),
            }
        }

        Ok(())
    }
}
