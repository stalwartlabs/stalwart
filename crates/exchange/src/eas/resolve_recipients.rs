/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EasContext,
    directory::{GalQuery, MAX_GAL_RESULTS, MatchKind, load_entries, open_directory},
    response::EasResponse,
};
use crate::{
    ews::availability::{account_merged_free_busy, rate_limited},
    mapi::nspi::{
        book::{AbEntry, Book, BookError, BookResult},
        page::{Anchor, Page, RowKey, Window},
        scan::{AbView, Detail},
    },
};
use common::Server;
use exchange_proto::{
    common::UtcSeconds,
    eas::{
        commands::resolve_recipients::{
            AvailabilityWindow, Recipient, RecipientAvailability, RecipientCertificates,
            RecipientPicture, RecipientResponse, ResolveRecipientsRequest,
            ResolveRecipientsResponse,
        },
        http::Command,
        status::{CommonStatus, PictureStatus, ResolveRecipientsStatus},
        types::EasDateTime,
        wbxml::Decoder,
    },
};
use std::{borrow::Cow, iter};
use types::type_state::DataType;

const RECIPIENT_TYPE_GAL: u8 = 1;
const CERTIFICATE_RETRIEVAL_FULL: u8 = 2;
const CERTIFICATE_RETRIEVAL_MINI: u8 = 3;
const FREE_BUSY_SLOT_SECONDS: i64 = 30 * 60;
const MILLIS_PER_SECOND: i64 = 1000;
const DEFAULT_AVAILABILITY_SECONDS: i64 = 7 * 86_400;
const MAX_AVAILABILITY_SECONDS: i64 = 42 * 86_400;

pub trait EasResolveRecipients: Sync + Send {
    fn eas_resolve_recipients(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

impl EasResolveRecipients for Server {
    async fn eas_resolve_recipients(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::ResolveRecipients,
                CommonStatus::INVALID_XML.into(),
            ));
        };
        let request = match ResolveRecipientsRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::ResolveRecipients,
                    err.status(Command::ResolveRecipients),
                ));
            }
        };
        let max_duration = self.core.groupware.max_availability_duration;
        let range = match request
            .options
            .availability
            .map(|window| AvailabilityRange::new(&window, max_duration))
        {
            Some(None) => {
                return Ok(EasResponse::status(
                    Command::ResolveRecipients,
                    ResolveRecipientsStatus::PROTOCOL_ERROR.into(),
                ));
            }
            range => range.flatten(),
        };
        let max_ambiguous = request
            .options
            .max_ambiguous_recipients
            .unwrap_or(MAX_GAL_RESULTS)
            .min(MAX_GAL_RESULTS);
        let shown_ambiguous = usize::try_from(max_ambiguous).unwrap_or(usize::MAX);
        let picture = request.options.picture.map(|_| RecipientPicture {
            status: PictureStatus::NO_PICTURE,
            data: None,
        });
        let certificates = matches!(
            request.options.certificate_retrieval,
            Some(CERTIFICATE_RETRIEVAL_FULL | CERTIFICATE_RETRIEVAL_MINI)
        )
        .then(|| RecipientCertificates {
            status: ResolveRecipientsStatus::CERTIFICATE_INVALID,
            certificate_count: None,
            recipient_count: None,
            certificates: Vec::new(),
            mini_certificate: None,
        });

        let resolutions = match open_directory(self, ctx) {
            Some(mut book) => match resolve_all(&mut book, &request.to, max_ambiguous).await {
                Ok(resolutions) => resolutions,
                Err(BookError::OutOfMemory) => {
                    return Ok(EasResponse::status(
                        Command::ResolveRecipients,
                        ResolveRecipientsStatus::SERVER_ERROR.into(),
                    ));
                }
                Err(BookError::Store(err)) => return Err(err),
            },
            None => request.to.iter().map(|_| Resolution::default()).collect(),
        };
        let availability = match range {
            Some(range) => free_busy_all(self, ctx, &resolutions, range).await?,
            None => Vec::new(),
        };

        let response = ResolveRecipientsResponse {
            status: ResolveRecipientsStatus::SUCCESS,
            responses: request
                .to
                .iter()
                .zip(&resolutions)
                .zip(
                    availability
                        .iter()
                        .map(Option::as_ref)
                        .chain(iter::repeat(None)),
                )
                .map(|((to, resolution), free_busy)| {
                    let status = resolution.status(shown_ambiguous);
                    let certificates = certificates
                        .as_ref()
                        .filter(|_| status == ResolveRecipientsStatus::SUCCESS);
                    RecipientResponse {
                        to,
                        status,
                        recipient_count: Some(resolution.count),
                        recipients: resolution
                            .entries
                            .iter()
                            .take(resolution.shown(shown_ambiguous))
                            .map(|entry| Recipient {
                                recipient_type: RECIPIENT_TYPE_GAL,
                                display_name: &entry.display_name,
                                email_address: &entry.smtp,
                                availability: free_busy.map(|free_busy| RecipientAvailability {
                                    status: free_busy.status,
                                    merged_free_busy: free_busy.merged.as_deref(),
                                }),
                                certificates: certificates.cloned(),
                                pictures: picture.iter().cloned().collect(),
                            })
                            .collect(),
                    }
                })
                .collect(),
        };
        Ok(EasResponse::encode(ctx.version, |encoder| {
            response.encode(encoder)
        }))
    }
}

async fn resolve_all(
    book: &mut Book<'_>,
    to: &[Cow<'_, str>],
    limit: u32,
) -> BookResult<Vec<Resolution>> {
    let start = Anchor::Start;
    let mut queries = to
        .iter()
        .map(|to| GalQuery::new(to).map(|query| (query, Matches::new(&start, limit))))
        .collect::<Vec<_>>();
    if queries.iter().any(Option::is_some) {
        let mut scan = book.scan().await?;
        while let Some(key) = scan.next(book.server(), Detail::Addresses).await? {
            match_row(&mut queries, &key, &scan.view(&key));
        }
    }
    let mut resolutions = Vec::with_capacity(queries.len());
    for query in queries {
        resolutions.push(match query {
            Some((_, matches)) => {
                let page = matches.finish();
                Resolution {
                    count: u32::try_from(page.total).unwrap_or(u32::MAX),
                    entries: load_entries(book, &page.rows).await?,
                }
            }
            None => Resolution::default(),
        });
    }
    Ok(resolutions)
}

fn match_row(queries: &mut [Option<(GalQuery<'_>, Matches<'_>)>], key: &RowKey, view: &AbView<'_>) {
    for (query, matches) in queries.iter_mut().flatten() {
        if let Some(kind) = query.classify(view) {
            matches.push(kind, key);
        }
    }
}

struct Matches<'a> {
    exact: Window<'a>,
    prefix: Window<'a>,
    limit: usize,
}

impl<'a> Matches<'a> {
    fn new(start: &'a Anchor, limit: u32) -> Self {
        let limit = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
        Matches {
            exact: Window::new(start, 0, limit),
            prefix: Window::new(start, 0, limit),
            limit,
        }
    }

    fn push(&mut self, kind: MatchKind, key: &RowKey) {
        match kind {
            MatchKind::Exact => self.exact.push(key.clone()),
            MatchKind::Prefix => self.prefix.push(key.clone()),
        }
    }

    fn finish(self) -> Page {
        let exact = self.exact.finish(0, self.limit);
        if exact.total > 0 {
            exact
        } else {
            self.prefix.finish(0, self.limit)
        }
    }
}

#[derive(Default)]
struct Resolution {
    count: u32,
    entries: Vec<AbEntry>,
}

impl Resolution {
    fn status(&self, shown_ambiguous: usize) -> ResolveRecipientsStatus {
        match self.count {
            0 => ResolveRecipientsStatus::NOT_RESOLVED,
            1 => ResolveRecipientsStatus::SUCCESS,
            count if usize::try_from(count).is_ok_and(|count| count > shown_ambiguous) => {
                ResolveRecipientsStatus::AMBIGUOUS_PARTIAL
            }
            _ => ResolveRecipientsStatus::AMBIGUOUS,
        }
    }

    fn shown(&self, shown_ambiguous: usize) -> usize {
        if self.count == 1 {
            self.entries.len()
        } else {
            shown_ambiguous
        }
    }
}

#[derive(Clone, Copy)]
struct AvailabilityRange {
    start: i64,
    end: i64,
}

impl AvailabilityRange {
    fn new(window: &AvailabilityWindow, max_duration: u64) -> Option<Self> {
        let to_millis = |EasDateTime(UtcSeconds(seconds), millis): EasDateTime| {
            seconds
                .checked_mul(MILLIS_PER_SECOND)?
                .checked_add(i64::from(millis))
        };
        let start = window.start_time.0.0;
        let span = match window.end_time {
            Some(end) => to_millis(end)?.checked_sub(to_millis(window.start_time)?)?,
            None => DEFAULT_AVAILABILITY_SECONDS * MILLIS_PER_SECOND,
        };
        let max = i64::try_from(max_duration)
            .unwrap_or(i64::MAX)
            .min(MAX_AVAILABILITY_SECONDS);
        if !(FREE_BUSY_SLOT_SECONDS * MILLIS_PER_SECOND..=max.saturating_mul(MILLIS_PER_SECOND))
            .contains(&span)
        {
            return None;
        }
        let seconds = (span + MILLIS_PER_SECOND - 1) / MILLIS_PER_SECOND;
        Some(AvailabilityRange {
            start,
            end: start.checked_add(seconds)?,
        })
    }
}

#[derive(Clone)]
struct FreeBusy {
    status: ResolveRecipientsStatus,
    merged: Option<String>,
}

impl FreeBusy {
    const FAILURE: Self = FreeBusy {
        status: ResolveRecipientsStatus::AVAILABILITY_FAILURE,
        merged: None,
    };
    const TRANSIENT: Self = FreeBusy {
        status: ResolveRecipientsStatus::AVAILABILITY_TRANSIENT_FAILURE,
        merged: None,
    };
}

async fn free_busy_all(
    server: &Server,
    ctx: &EasContext<'_>,
    resolutions: &[Resolution],
    range: AvailabilityRange,
) -> trc::Result<Vec<Option<FreeBusy>>> {
    let allowed = ctx.data_types.contains(DataType::CalendarEvent);
    let mut known: Vec<(u32, FreeBusy)> = Vec::new();
    let mut limited = false;
    let mut availability = Vec::with_capacity(resolutions.len());
    for resolution in resolutions {
        let entry = match resolution.entries.as_slice() {
            [entry] if resolution.count == 1 => entry,
            _ => {
                availability.push(None);
                continue;
            }
        };
        let account_id = match entry.principal.account_id() {
            Some(account_id) if allowed => account_id,
            _ => {
                availability.push(Some(FreeBusy::FAILURE));
                continue;
            }
        };
        let free_busy = if let Some((_, free_busy)) = known.iter().find(|(id, _)| *id == account_id)
        {
            free_busy.clone()
        } else {
            limited = limited || rate_limited(server, &ctx.access_token).await?;
            let free_busy = if limited {
                FreeBusy::TRANSIENT
            } else {
                account_merged_free_busy(
                    server,
                    &ctx.access_token,
                    account_id,
                    range.start,
                    range.end,
                    FREE_BUSY_SLOT_SECONDS,
                )
                .await?
                .map_or(FreeBusy::FAILURE, |merged| FreeBusy {
                    status: ResolveRecipientsStatus::SUCCESS,
                    merged: Some(merged),
                })
            };
            known.push((account_id, free_busy.clone()));
            free_busy
        };
        availability.push(Some(free_busy));
    }
    Ok(availability)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/eas/resolve_recipients/tests.rs"]
mod tests;
