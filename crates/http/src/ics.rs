/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use groupware::calendar::{
    publish_http::{CalendarPublishStore, parse_ics_http_path},
};
use http_proto::HttpResponse;
use hyper::{header, StatusCode};
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

fn http_date(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|dt| {
            dt.format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string()
        })
        .unwrap_or_default()
}

pub trait IcsHttpHandler: Sync + Send {
    fn http_ics_handle(
        &self,
        path: &str,
        is_head: bool,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl IcsHttpHandler for Server {
    async fn http_ics_handle(&self, path: &str, is_head: bool) -> trc::Result<HttpResponse> {
        let (link_id, secret, is_public) = parse_ics_http_path(path)?;
        let (account_id, link) = self
            .verify_publish_link_access(link_id, secret.as_deref(), is_public)
            .await?;

        let ical_body = self.export_calendar_publish_feed(account_id, &link).await?;
        let etag = format!(
            "\"{}\"",
            CheekyHash::new(ical_body.as_bytes()).to_string()
        );
        let last_modified = link.last_used_at.unwrap_or(link.created_at);

        self.touch_publish_link_if_stale(account_id, &link)
            .await
            .caused_by(trc::location!())?;

        let response = HttpResponse::new(StatusCode::OK)
            .with_content_type("text/calendar; charset=utf-8")
            .with_etag(etag)
            .with_last_modified(http_date(last_modified))
            .with_header(header::CACHE_CONTROL, "private, max-age=300")
            .with_header("X-Robots-Tag", "noindex");

        if is_head {
            Ok(response.with_content_length(ical_body.len()))
        } else {
            Ok(response.with_binary_body(ical_body))
        }
    }
}
