/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::AccessToken;
use crate::network::ip_rate_key;
use crate::network::limiter::{
    AccountLimits, AccountRate, InFlight, LimiterResult, RateCounter, RateHit,
};
use crate::{
    KV_RATE_LIMIT_HTTP_ANONYMOUS, KV_RATE_LIMIT_HTTP_AUTHENTICATED, KV_RATE_LIMIT_IMAP, Server,
};
use compact_str::format_compact;
use registry::schema::{enums::Permission, structs::Rate};
use std::{net::IpAddr, sync::Arc};
use store::{dispatch::lookup::KeyValue, write::now};
use trc::AddContext;

impl Server {
    pub async fn is_http_authenticated_request_allowed(
        &self,
        access_token: &AccessToken,
        addr: IpAddr,
    ) -> trc::Result<Option<InFlight>> {
        if let Some(rate) = &self.core.network.http.rate_authenticated
            && !access_token.has_permission(Permission::UnlimitedRequests)
            && !self.is_ip_allowed(addr)
            && let Some(reset) = self
                .is_account_rate_allowed(
                    KV_RATE_LIMIT_HTTP_AUTHENTICATED,
                    access_token.account_id(),
                    rate,
                    access_token.inner.rate_counter(AccountRate::Http),
                )
                .await
                .caused_by(trc::location!())?
        {
            return Err(trc::LimitEvent::TooManyRequests
                .into_err()
                .ctx(trc::Key::Expires, reset)
                .ctx(trc::Key::Limit, rate.count));
        }

        match access_token.is_http_request_allowed() {
            LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
            LimiterResult::Forbidden => {
                if access_token.has_permission(Permission::UnlimitedRequests) {
                    Ok(None)
                } else {
                    Err(trc::LimitEvent::ConcurrentRequest
                        .into_err()
                        .ctx(trc::Key::Limit, access_token.concurrent_http_requests()))
                }
            }
            LimiterResult::Disabled => Ok(None),
        }
    }

    pub async fn is_imap_request_allowed(&self, access_token: &AccessToken) -> trc::Result<()> {
        if let Some(rate) = &self.core.imap.rate_requests
            && !access_token.has_permission(Permission::UnlimitedRequests)
            && let Some(reset) = self
                .is_account_rate_allowed(
                    KV_RATE_LIMIT_IMAP,
                    access_token.account_id(),
                    rate,
                    access_token.inner.rate_counter(AccountRate::Imap),
                )
                .await
                .caused_by(trc::location!())?
        {
            Err(trc::LimitEvent::TooManyRequests
                .into_err()
                .ctx(trc::Key::Expires, reset)
                .ctx(trc::Key::Limit, rate.count)
                .details(format_compact!(
                    "Too many requests, retry in {reset} seconds"
                )))
        } else {
            Ok(())
        }
    }

    async fn is_account_rate_allowed(
        &self,
        prefix: u8,
        account_id: u32,
        rate: &Rate,
        counter: Option<&RateCounter>,
    ) -> trc::Result<Option<u64>> {
        let key = account_id.to_be_bytes();
        let Some(counter) = counter else {
            return self
                .core
                .storage
                .memory
                .is_rate_allowed(prefix, &key, rate)
                .await;
        };

        match counter.hit(rate, now()) {
            RateHit::Allowed => Ok(None),
            RateHit::Exceeded { reset_in } => Ok(Some(reset_in)),
            RateHit::Flush(flush) => {
                let window = flush.window();
                let total = self
                    .core
                    .storage
                    .memory
                    .key_incr(
                        KeyValue::new(window.bucket(prefix, &key), i64::from(flush.delta()))
                            .expires(window.expires_in),
                    )
                    .await?;
                Ok(flush.settle(rate, u64::try_from(total).unwrap_or_default()))
            }
        }
    }

    pub(crate) fn account_limits(&self) -> Option<Arc<AccountLimits>> {
        let is_remote = self.core.storage.memory.is_remote();
        AccountLimits::new(
            [
                self.core.jmap.request_max_concurrent,
                self.core.imap.rate_concurrent,
                self.core.jmap.upload_max_concurrent,
            ],
            [
                self.core.network.http.rate_authenticated.is_some() && is_remote,
                self.core.imap.rate_requests.is_some() && is_remote,
            ],
        )
    }

    pub async fn is_http_anonymous_request_allowed(&self, addr: IpAddr) -> trc::Result<()> {
        if let Some(rate) = &self.core.network.http.rate_anonymous
            && !self.is_ip_allowed(addr)
            && let Some(reset) = self
                .core
                .storage
                .memory
                .is_rate_allowed(KV_RATE_LIMIT_HTTP_ANONYMOUS, &ip_rate_key(&addr), rate)
                .await
                .caused_by(trc::location!())?
        {
            return Err(trc::LimitEvent::TooManyRequests
                .into_err()
                .ctx(trc::Key::Expires, reset)
                .ctx(trc::Key::Limit, rate.count));
        }
        Ok(())
    }

    pub fn is_upload_allowed(&self, access_token: &AccessToken) -> trc::Result<Option<InFlight>> {
        match access_token.is_upload_allowed() {
            LimiterResult::Allowed(in_flight) => Ok(Some(in_flight)),
            LimiterResult::Forbidden => {
                if access_token.has_permission(Permission::UnlimitedRequests) {
                    Ok(None)
                } else {
                    Err(trc::LimitEvent::ConcurrentUpload
                        .into_err()
                        .ctx(trc::Key::Limit, access_token.concurrent_uploads()))
                }
            }
            LimiterResult::Disabled => Ok(None),
        }
    }
}
