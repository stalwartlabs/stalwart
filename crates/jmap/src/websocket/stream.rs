/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::{
    ToRequestError, notifications_into_push_objects, request::RequestHandler,
    session::allowed_capabilities,
};
use common::{
    BuildServer, Server,
    auth::AccessToken,
    cache::http_auth::RevocationEpoch,
    ipc::{PushNotification, ViewerStateChange},
    network::memory::MemoryClass,
};
use compact_str::ToCompactString;
use futures_util::{SinkExt, StreamExt};
use http_proto::HttpSessionData;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use jmap_proto::{
    error::request::RequestError,
    request::websocket::{
        WebSocketMessage, WebSocketPushObject, WebSocketRequestError, WebSocketResponse,
    },
};
use std::future::Future;
use std::time::Instant;
use tokio_tungstenite::WebSocketStream;
use trc::{JmapEvent, LimitEvent};
use tungstenite::{
    Error as WsError, Message,
    protocol::{CloseFrame, frame::coding::CloseCode},
};
use types::type_state::{DataType, StateChange};
use utils::map::bitmap::Bitmap;

pub trait WebSocketHandler: Sync + Send {
    fn handle_websocket_stream(
        &self,
        stream: WebSocketStream<TokioIo<Upgraded>>,
        access_token: AccessToken,
        epoch: RevocationEpoch,
        session: HttpSessionData,
    ) -> impl Future<Output = ()> + Send;
}

impl WebSocketHandler for Server {
    async fn handle_websocket_stream(
        &self,
        mut stream: WebSocketStream<TokioIo<Upgraded>>,
        mut access_token: AccessToken,
        epoch: RevocationEpoch,
        session: HttpSessionData,
    ) {
        trc::event!(
            Jmap(JmapEvent::WebsocketStart),
            SpanId = session.session_id,
            AccountId = access_token.account_id(),
        );

        // Set timeouts
        let throttle = self.core.jmap.web_socket_throttle;
        let timeout = self.core.jmap.web_socket_timeout;
        let heartbeat = self.core.jmap.web_socket_heartbeat;
        let mut last_request = Instant::now();
        let mut last_changes_sent = Instant::now() - throttle;
        let mut last_heartbeat = Instant::now() - heartbeat;
        let mut next_event = heartbeat;

        // Register with push manager
        let mut allowed_types = Bitmap::all();
        access_token.restrict_data_types(&mut allowed_types);
        let mut push_rx = self.subscribe_push_manager(&access_token, allowed_types);
        let mut revocation_epoch = epoch;

        let mut notifications = Vec::new();
        let mut received = Vec::new();
        let mut change_types: Bitmap<DataType> = Bitmap::new();

        loop {
            tokio::select! {
                event = tokio::time::timeout(next_event, stream.next()) => {
                    match event {
                        Ok(Some(Ok(event))) => {
                            match event {
                                Message::Text(text) => {
                                    let response = match WebSocketMessage::parse(
                                        text.as_bytes(),
                                        self.core.jmap.request_max_calls,
                                        self.core.jmap.request_max_size,
                                    ) {
                                        Ok(WebSocketMessage::Request(mut request)) => {
                                            let server = self.inner.build_server();
                                            let renewal = match access_token
                                                .grant_id()
                                                .map(|_| server.inner.cache.grant_revocations.epoch())
                                            {
                                                Some(epoch) if epoch != revocation_epoch => server
                                                    .renew_access_token(&access_token, session.remote_ip)
                                                    .await
                                                    .map(|renewed| {
                                                        revocation_epoch = epoch;
                                                        Some(renewed)
                                                    }),
                                                _ => server.refresh_access_token(&access_token, session.remote_ip).await,
                                            };
                                            let renewal = match renewal {
                                                Ok(renewed) => {
                                                    if let Some(renewed) = renewed {
                                                        access_token = renewed;
                                                    }
                                                    Ok(())
                                                }
                                                Err(err) if matches!(err.as_ref(), trc::EventType::Auth(_) | trc::EventType::Security(_)) => {
                                                    trc::event!(
                                                        Jmap(JmapEvent::WebsocketStop),
                                                        SpanId = session.session_id,
                                                        Reason = "Authorization revoked"
                                                    );
                                                    let _ = stream.close(Some(CloseFrame {
                                                        code: CloseCode::Policy,
                                                        reason: "Authorization revoked".into(),
                                                    })).await;
                                                    break;
                                                }
                                                Err(err) => Err(err),
                                            };
                                            match renewal {
                                                Ok(()) => match server
                                                    .is_http_authenticated_request_allowed(&access_token, session.remote_ip)
                                                    .await
                                                {
                                                    Ok(_in_flight) => {
                                                        request.request.using = allowed_capabilities(&access_token, request.request.using);
                                                        let mut reservation = server.memory_reservation(MemoryClass::Read);
                                                        let response = server
                                                            .handle_jmap_request(
                                                                request.request,
                                                                &access_token,
                                                                &session,
                                                                &mut reservation,
                                                            )
                                                            .await;
                                                        let response = WebSocketResponse::from_response(response, request.id);
                                                        match response.to_json() {
                                                            Ok(response) => response,
                                                            Err(err) => {
                                                                trc::event!(
                                                                    Jmap(JmapEvent::WebsocketError),
                                                                    Details = "Failed to serialize response",
                                                                    SpanId = session.session_id,
                                                                    Reason = err.to_compact_string()
                                                                );
                                                                WebSocketRequestError::from_error(RequestError::internal_server_error(), response.request_id).to_json()
                                                            }
                                                        }
                                                    }
                                                    Err(err) => {
                                                        let response = WebSocketRequestError::from_error(err.to_request_error(), request.id).to_json();
                                                        trc::error!(err.span_id(session.session_id));
                                                        response
                                                    }
                                                },
                                                Err(err) => {
                                                    trc::error!(err.details("Failed to renew WebSocket access token").span_id(session.session_id));
                                                    WebSocketRequestError::from_error(RequestError::internal_server_error(), request.id).to_json()
                                                }
                                            }
                                        }
                                        Ok(WebSocketMessage::PushEnable(push_enable)) => {
                                            change_types = if !push_enable.data_types.is_empty() {
                                                push_enable.data_types.into()
                                            } else {
                                                Bitmap::all()
                                            };
                                            change_types.intersection(&allowed_types);
                                            continue;
                                        }
                                        Ok(WebSocketMessage::PushDisable) => {
                                            change_types = Bitmap::new();
                                            continue;
                                        }
                                        Err(err) => {
                                            let response = WebSocketRequestError::from_error(err.error.to_request_error(), err.request_id).to_json();
                                            trc::error!(err.error.details("Rejected WebSocket message").span_id(session.session_id));
                                            response
                                        },
                                    };
                                    if let Err(err) = stream.send(Message::Text(response.into())).await {
                                        trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Failed to send text message",
                                                    SpanId = session.session_id,
                                                    Reason = err.to_compact_string()
                                        );
                                    }
                                }
                                Message::Ping(bytes) => {
                                    if let Err(err) = stream.send(Message::Pong(bytes)).await {
                                        trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Failed to send pong message",
                                                    SpanId = session.session_id,
                                                    Reason = err.to_compact_string()
                                        );
                                    }
                                }
                                Message::Close(frame) => {
                                    let _ = stream.close(frame).await;
                                    break;
                                }
                                _ => (),
                            }

                            last_request = Instant::now();
                            last_heartbeat = Instant::now();
                        }
                        Ok(Some(Err(WsError::Capacity(err)))) => {
                            trc::event!(
                                Limit(LimitEvent::SizeRequest),
                                SpanId = session.session_id,
                                Reason = err.to_compact_string()
                            );
                            let _ = stream.close(Some(CloseFrame {
                                code: CloseCode::Size,
                                reason: "Message too big".into(),
                            })).await;
                            break;
                        }
                        Ok(Some(Err(err))) => {
                            trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Websocket error",
                                                    SpanId = session.session_id,
                                                    Reason = err.to_compact_string()
                                        );
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            // Verify timeout
                            if last_request.elapsed() > timeout {
                                trc::event!(
                                    Jmap(JmapEvent::WebsocketStop),
                                    SpanId = session.session_id,
                                    Reason = "Idle client"
                                );

                                break;
                            }
                        }
                    }
                }
                is_open = push_rx.recv(&mut received) => {
                    if is_open {
                        for push_notification in received.drain(..) {
                            match push_notification {
                                PushNotification::StateChange(state_change)
                                | PushNotification::ViewerStateChange(ViewerStateChange {
                                    change: state_change,
                                    ..
                                }) => {
                                    let mut types = state_change.types;
                                    types.intersection(&change_types);

                                    if !types.is_empty() {
                                        notifications.push(PushNotification::StateChange(
                                            StateChange {
                                                types,
                                                ..state_change
                                            }
                                        ));
                                    }
                                },
                                PushNotification::EmailPush(email_push) => {
                                    let state_change = email_push.to_state_change();
                                    let mut types = state_change.types;
                                    types.intersection(&change_types);

                                    if !types.is_empty() {
                                        notifications.push(PushNotification::StateChange(
                                            StateChange {
                                                types,
                                                ..state_change
                                            }
                                        ));
                                    }
                                },
                                PushNotification::CalendarAlert(calendar_alert) => {
                                    if change_types.contains(DataType::CalendarAlert) {
                                        notifications.push(PushNotification::CalendarAlert(
                                            calendar_alert
                                        ));
                                    }
                                },
                            }
                        }
                    } else {
                        trc::event!(
                            Jmap(JmapEvent::WebsocketStop),
                            SpanId = session.session_id,
                            Reason = "State manager channel closed"
                        );

                        break;
                    }
                }
            }

            if !notifications.is_empty() {
                // Send any queued changes
                let elapsed = last_changes_sent.elapsed();
                if elapsed >= throttle {
                    for push in notifications_into_push_objects(std::mem::take(&mut notifications))
                    {
                        let payload = WebSocketPushObject {
                            push,
                            push_state: None,
                        };
                        if let Err(err) = stream.send(Message::Text(payload.to_json().into())).await
                        {
                            trc::event!(
                                Jmap(JmapEvent::WebsocketError),
                                Details = "Failed to send state change message.",
                                SpanId = session.session_id,
                                Reason = err.to_compact_string()
                            );
                        }
                    }
                    last_changes_sent = Instant::now();
                    last_heartbeat = Instant::now();
                    next_event = heartbeat;
                } else {
                    next_event = throttle - elapsed;
                }
            } else if last_heartbeat.elapsed() > heartbeat {
                if let Err(err) = stream.send(Message::Ping(Vec::<u8>::new().into())).await {
                    trc::event!(
                        Jmap(JmapEvent::WebsocketError),
                        Details = "Failed to send ping message.",
                        SpanId = session.session_id,
                        Reason = err.to_compact_string()
                    );
                    break;
                }
                last_heartbeat = Instant::now();
                next_event = heartbeat;
            }
        }
    }
}
