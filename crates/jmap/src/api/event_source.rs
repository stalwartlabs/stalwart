/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::IntoPushObject;
use common::{
    BuildServer, LONG_1D_SLUMBER, Server,
    auth::AccessToken,
    cache::http_auth::RevocationEpoch,
    ipc::{PushNotification, ViewerStateChange},
};
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::*;
use hyper::{
    StatusCode,
    body::{Bytes, Frame},
};
use jmap_proto::{response::status::PushObject, types::state::State};
use std::time::{Duration, Instant};
use std::{future::Future, net::IpAddr, str::FromStr};
use sync_wrapper::SyncFuture;
use types::{id::Id, type_state::DataType};
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

struct Ping {
    interval: Duration,
    last_ping: Instant,
    payload: Bytes,
}

pub trait EventSourceHandler: Sync + Send {
    fn handle_event_source(
        &self,
        req: HttpRequest,
        access_token: AccessToken,
        epoch: RevocationEpoch,
        remote_ip: IpAddr,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl EventSourceHandler for Server {
    async fn handle_event_source(
        &self,
        req: HttpRequest,
        mut access_token: AccessToken,
        mut revocation_epoch: RevocationEpoch,
        remote_ip: IpAddr,
    ) -> trc::Result<HttpResponse> {
        // Parse query
        let mut ping = 0;
        let mut types = Bitmap::default();
        let mut close_after_state = false;

        for (key, value) in
            http_proto::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
        {
            hashify::fnc_map!(key.as_bytes(),
                "types" => {
                    for type_state in value.split(',') {
                        if type_state == "*" {
                            types = Bitmap::all();
                            break;
                        } else if let Ok(type_state) = DataType::from_str(type_state) {
                            types.insert(type_state);
                        } else {
                            return Err(trc::ResourceEvent::BadParameters.into_err());
                        }
                    }
                },
                "closeafter" => match value.as_ref() {
                    "state" => {
                        close_after_state = true;
                    }
                    "no" => {}
                    _ => return Err(trc::ResourceEvent::BadParameters.into_err()),
                },
                "ping" => match value.parse::<u32>() {
                    Ok(value) => {
                        ping = value;
                    }
                    Err(_) => return Err(trc::ResourceEvent::BadParameters.into_err()),
                },
                _ => {}
            );
        }

        let mut ping = if ping > 0 {
            #[cfg(not(stalwart_tests))]
            let interval = std::cmp::max(ping, 30);
            #[cfg(stalwart_tests)]
            let interval = ping;
            let interval_duration = Duration::from_secs(interval as u64);

            Ping {
                interval: interval_duration,
                last_ping: Instant::now() - interval_duration,
                payload: Bytes::from(format!(
                    "event: ping\ndata: {{\"interval\": {}}}\n\n",
                    interval
                )),
            }
            .into()
        } else {
            None
        };

        // Register with push manager
        let requested_types = types;
        access_token.restrict_data_types(&mut types);
        let mut push_rx = self.subscribe_push_manager(&access_token, types);
        let inner = self.inner.clone();
        let mut changed: VecMap<Id, VecMap<DataType, State>> = VecMap::new();
        let throttle = self.core.jmap.event_source_throttle;

        Ok(HttpResponse::new(StatusCode::OK)
            .with_content_type("text/event-stream")
            .with_cache_control("no-store")
            .with_stream_body(BoxBody::new(StreamBody::new(async_stream::stream! {
                let mut last_message = Instant::now() - throttle;
                let mut timeout =
                    ping.as_ref().map(|p| p.interval).unwrap_or(LONG_1D_SLUMBER);
                let mut notifications = Vec::new();

                loop {
                    let received = tokio::time::timeout(timeout, push_rx.recv(&mut notifications)).await;

                    let server = inner.build_server();
                    let renewal = match access_token
                        .grant_id()
                        .map(|_| server.inner.cache.grant_revocations.epoch())
                    {
                        Some(epoch) if epoch != revocation_epoch => {
                            SyncFuture::new(server.renew_access_token(&access_token, remote_ip))
                                .await
                                .map(|renewed| {
                                    revocation_epoch = epoch;
                                    Some(renewed)
                                })
                        }
                        _ => SyncFuture::new(server.refresh_access_token(&access_token, remote_ip)).await,
                    };
                    match renewal {
                        Ok(Some(renewed)) => {
                            let mut renewed_types = requested_types;
                            renewed.restrict_data_types(&mut renewed_types);
                            if renewed_types != types || !renewed.member_ids().eq(access_token.member_ids()) {
                                break;
                            }
                            access_token = renewed;
                        }
                        Ok(None) => (),
                        Err(_) => break,
                    }

                    match received {
                        Ok(true) => for notification in notifications.drain(..) {
                            match notification {
                                PushNotification::StateChange(state_change)
                                | PushNotification::ViewerStateChange(ViewerStateChange {
                                    change: state_change,
                                    ..
                                }) => {
                                    let states = changed.get_mut_or_insert(state_change.account_id.into());
                                    for type_state in state_change.types {
                                        states.set(type_state, State::Exact(state_change.change_id));
                                    }
                                }
                                PushNotification::CalendarAlert(calendar_alert) => {
                                    yield Ok(Frame::data(Bytes::from(format!(
                                        "event: calendarAlert\ndata: {}\n\n",
                                        serde_json::to_string(&calendar_alert.into_push_object()).unwrap()
                                    ))));
                                }
                                PushNotification::EmailPush(email_push) => {
                                    let state_change = email_push.to_state_change();
                                    let states = changed.get_mut_or_insert(state_change.account_id.into());
                                    for type_state in state_change.types {
                                        states.set(type_state, State::Exact(state_change.change_id));
                                    }
                                }
                            }
                        },
                        Ok(false) => {
                            break;
                        }
                        Err(_) => (),
                    }

                    timeout = if !changed.is_empty() {
                        let elapsed = last_message.elapsed();
                        if elapsed >= throttle {
                            last_message = Instant::now();
                            let response =
                                PushObject::StateChange { changed: std::mem::take(&mut changed) };

                            yield Ok(Frame::data(Bytes::from(format!(
                                "event: state\ndata: {}\n\n",
                                serde_json::to_string(&response).unwrap()
                            ))));

                            if close_after_state {
                                break;
                            }

                            ping.as_ref().map(|p| p.interval).unwrap_or(LONG_1D_SLUMBER)
                        } else {
                            throttle - elapsed
                        }
                    } else if let Some(ping) = &mut ping {
                        let elapsed = ping.last_ping.elapsed();
                        if elapsed >= ping.interval {
                            ping.last_ping = Instant::now();
                            yield Ok(Frame::data(ping.payload.clone()));
                            ping.interval
                        } else {
                            ping.interval - elapsed
                        }
                    } else {
                        LONG_1D_SLUMBER
                    };
                }
            }))))
    }
}
