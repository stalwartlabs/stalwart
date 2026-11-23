/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    contact::{
        Contacts,
        resolve::{CardMatch, CardMatches, CardQuery, resolve_address_book},
    },
    context::{EwsCaller, EwsContext},
    groupware::{GroupwareKind, items::decode_item_id},
    reply::{RESPONSE_CAPACITY, ews_response},
};
use crate::{
    eas::directory::{GalQuery, MAX_GAL_RESULTS},
    identity::directory_ref_from_dn,
    mapi::nspi::{
        book::{AbEntry, Book, BookError, BookResult, Members, directory_entry},
        page::{AbKind, Page, RowKey, RowRef},
        scan::{AbView, Detail, ScanScope, directory_ref_from_email},
    },
};
use common::Server;
use exchange_proto::{
    convert::vcard::is_contact_group,
    ews::{
        MessageResult, Operation, Status,
        envelope::MessagesWriter,
        requests::{
            availability::GetRooms,
            resolve::{ExpandDl, ResolveNames},
        },
        responses::{
            Paging, ShapeB,
            availability::{GetRoomListsBody, GetRoomsBody},
            resolve::{ExpandDlMessage, Resolution, ResolveNamesMessage},
        },
        schema::{
            ContactSource, EmailAddressKey, MailboxType, ResolveNamesSearchScope, ResponseCode,
        },
        types::{
            address::EmailAddress,
            ids::ItemId,
            item::{
                ContactItem,
                contact::{ContactFields, EmailAddressEntry},
            },
            value::List,
        },
    },
};
use http_proto::HttpResponse;
use registry::schema::{enums::ResourceKind, prelude::Permission};
use std::borrow::Cow;
use types::type_state::DataType;

pub(crate) const MAX_DL_MEMBERS: usize = 1000;
const MAX_RESOLUTIONS: usize = MAX_GAL_RESULTS as usize;
pub(crate) const ALL_DL_MEMBERS: usize = usize::MAX;
pub(crate) const ROUTING_SMTP: &str = "SMTP";
const EXACT_MARKER: char = '=';
const ADDRESS_MARKER: char = '@';
pub(super) const LEGACY_DN_MARKER: char = '/';
const CONTACT_KEYS: [EmailAddressKey; 3] = [
    EmailAddressKey::EmailAddress1,
    EmailAddressKey::EmailAddress2,
    EmailAddressKey::EmailAddress3,
];
const NO_RESULTS: &str = "No results were found.";
const MULTIPLE_RESULTS: &str = "Multiple results were found.";
const INVALID_NAME: &str = "The name is not valid for name resolution.";
const DIRECTORY_BUSY: &str = "The address book is not available.";
const NOT_A_LIST: &str = "The item is not a distribution list.";

struct Found {
    entries: Vec<AbEntry>,
    complete: bool,
}

struct Expansion {
    status: Status<'static>,
    found: Found,
    members: Members,
}

enum NameQuery<'q> {
    Prefix(GalQuery<'q>),
    Exact(GalQuery<'q>),
    Address(&'q str, Match),
    LegacyDn(&'q str),
    Unsupported,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Match {
    Prefix,
    Exact,
}

#[derive(Clone, Copy)]
enum ListKind {
    Any,
    Rooms,
}

#[derive(Clone, Copy)]
enum RoutingType {
    Smtp,
    Ex,
    Other,
}

impl RoutingType {
    fn parse(name: &str) -> Option<Self> {
        hashify::map_ignore_case!(name.as_bytes(), RoutingType,
            "smtp" => RoutingType::Smtp,
            "ex" => RoutingType::Ex,
            "sip" => RoutingType::Other,
            "x400" => RoutingType::Other,
            "x500" => RoutingType::Other,
            "eum" => RoutingType::Other,
            "spo" => RoutingType::Other,
            "fax" => RoutingType::Other,
        )
        .copied()
    }
}

impl ListKind {
    fn is_member(self, key: &RowKey) -> bool {
        match self {
            ListKind::Any => true,
            ListKind::Rooms => matches!(
                key.subject(),
                RowRef::Account(account) if account.resource_kind() == Some(ResourceKind::Room)
            ),
        }
    }
}

impl Found {
    async fn window(
        book: &mut Book<'_>,
        detail: Detail,
        limit: usize,
        mut filter: impl FnMut(&AbView<'_>) -> bool,
    ) -> BookResult<Self> {
        let page = book
            .window(detail, 0, limit, |_, view| filter(view))
            .await?;
        Found::load(book, page, limit).await
    }

    async fn load(book: &mut Book<'_>, page: Page, limit: usize) -> BookResult<Self> {
        let mut entries = Vec::with_capacity(page.rows.len());
        for key in &page.rows {
            if let Some(entry) = book.entry(key).await? {
                entries.push(entry);
            }
        }
        Ok(Found {
            entries,
            complete: page.total <= limit,
        })
    }
}

impl<'q> NameQuery<'q> {
    fn parse(entry: &'q str) -> Option<Self> {
        let entry = entry.trim();
        let (entry, mode) = match entry.strip_prefix(EXACT_MARKER) {
            Some(exact) => (exact.trim_start(), Match::Exact),
            None => (entry, Match::Prefix),
        };
        if entry
            .chars()
            .all(|c| matches!(c, ',' | ';' | '-') || c.is_whitespace())
        {
            return None;
        }
        if let Some((routing, address)) = entry.split_once(':')
            && let Some(routing) = RoutingType::parse(routing)
        {
            let address = address.trim();
            return Some(match routing {
                _ if address.is_empty() => NameQuery::Unsupported,
                RoutingType::Smtp => NameQuery::Address(address, mode),
                RoutingType::Ex => NameQuery::LegacyDn(address),
                RoutingType::Other => NameQuery::Unsupported,
            });
        }
        if mode == Match::Exact && entry.contains(ADDRESS_MARKER) {
            return Some(NameQuery::Address(entry, Match::Exact));
        }
        GalQuery::new(entry).map(match mode {
            Match::Prefix => NameQuery::Prefix,
            Match::Exact => NameQuery::Exact,
        })
    }

    fn matches(&self, view: &AbView<'_>) -> bool {
        match self {
            NameQuery::Prefix(query) => query.matches(view),
            NameQuery::Exact(query) => query.is_exact(view),
            NameQuery::Address(wanted, mode) => view.addresses().any(|address| match mode {
                Match::Exact => address.eq_ignore_ascii_case(wanted),
                Match::Prefix => address
                    .get(..wanted.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(wanted)),
            }),
            NameQuery::LegacyDn(dn) => view.dn().is_some_and(|own| own.eq_ignore_ascii_case(dn)),
            NameQuery::Unsupported => false,
        }
    }

    fn card_query(&self) -> Option<CardQuery<'_>> {
        match self {
            NameQuery::Prefix(query) => Some(CardQuery::Name {
                query: query.query(),
                folded: query.folded(),
                exact: false,
            }),
            NameQuery::Exact(query) => Some(CardQuery::Name {
                query: query.query(),
                folded: query.folded(),
                exact: true,
            }),
            NameQuery::Address(address, mode) => Some(CardQuery::Address {
                address,
                exact: *mode == Match::Exact,
            }),
            NameQuery::LegacyDn(_) | NameQuery::Unsupported => None,
        }
    }

    async fn principal(
        &self,
        server: &Server,
        caller: EwsCaller<'_>,
    ) -> trc::Result<Option<Option<AbEntry>>> {
        let principal = match self {
            NameQuery::Address(address, Match::Exact) => {
                directory_ref_from_email(server, address).await?
            }
            NameQuery::LegacyDn(dn) => directory_ref_from_dn(dn.as_bytes()),
            NameQuery::Unsupported => None,
            _ => return Ok(None),
        };
        let Some(principal) = principal else {
            return Ok(Some(None));
        };
        Ok(Some(
            directory_entry(server, caller.access_token, principal)
                .await?
                .filter(|entry| self.matches(&entry.view())),
        ))
    }
}

pub(crate) async fn resolve_names(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &ResolveNames<'_>,
) -> trc::Result<HttpResponse> {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::ResolveNames);
    let Some(query) = NameQuery::parse(&request.unresolved_entry) else {
        messages.message(&MessageResult::<ResolveNamesMessage> {
            status: Status::error(
                ResponseCode::ErrorInvalidNameForNameResolution,
                INVALID_NAME,
            ),
            body: None,
        });
        messages.finish();
        return Ok(ews_response(out));
    };
    let scope = request.search_scope;
    let card_query = match scope {
        ResolveNamesSearchScope::ActiveDirectory => None,
        _ => query.card_query(),
    };
    let personal = match card_query {
        Some(card_query) => match Personal::open(server, ctx, request).await? {
            Ok(personal) => personal.map(|personal| (personal, card_query)),
            Err(_) if scope != ResolveNamesSearchScope::Contacts => None,
            Err(status) => {
                messages.message(&MessageResult::<ResolveNamesMessage> { status, body: None });
                messages.finish();
                return Ok(ews_response(out));
            }
        },
        None => None,
    };
    let searches_directory = scope != ResolveNamesSearchScope::Contacts;
    let contacts_first = matches!(
        scope,
        ResolveNamesSearchScope::Contacts | ResolveNamesSearchScope::ContactsActiveDirectory
    );
    let mut cards = None;
    if contacts_first && let Some((personal, card_query)) = &personal {
        cards = Some(
            personal
                .matches(server, *card_query, MAX_RESOLUTIONS)
                .await?,
        );
    }
    let remaining = MAX_RESOLUTIONS - cards.as_ref().map_or(0, |cards| cards.cards.len());
    let found = if !searches_directory || remaining == 0 {
        Found {
            entries: Vec::new(),
            complete: !searches_directory,
        }
    } else {
        match directory_matches(server, ctx, caller, &query, remaining).await? {
            Ok(found) => found,
            Err(status) => {
                messages.message(&MessageResult::<ResolveNamesMessage> { status, body: None });
                messages.finish();
                return Ok(ews_response(out));
            }
        }
    };
    if !contacts_first && let Some((personal, card_query)) = &personal {
        let remaining = MAX_RESOLUTIONS.saturating_sub(found.entries.len());
        if remaining > 0 || found.complete {
            cards = Some(personal.matches(server, *card_query, remaining).await?);
        }
    }
    if let Some(cards) = &mut cards {
        cards.cards.retain(|card| {
            card.email.as_deref().is_none_or(|email| {
                !found.entries.iter().any(|entry| {
                    entry.smtp.eq_ignore_ascii_case(email)
                        || entry
                            .view()
                            .addresses()
                            .any(|address| address.eq_ignore_ascii_case(email))
                })
            })
        });
    }
    let directory = found.entries.iter().map(|entry| Resolution {
        mailbox: mailbox(entry),
        contact: request
            .return_full_contact_data
            .then(|| Box::new(contact(entry))),
    });
    let store =
        personal
            .as_ref()
            .zip(cards.as_ref())
            .into_iter()
            .flat_map(|((personal, _), cards)| {
                cards.cards.iter().map(|card| Resolution {
                    mailbox: personal.mailbox(card),
                    contact: None,
                })
            });
    let resolutions: Vec<_> = if contacts_first {
        store.chain(directory).collect()
    } else {
        directory.chain(store).collect()
    };
    let complete = found.complete && cards.as_ref().is_none_or(|cards| cards.complete);
    let status = match resolutions.len() {
        0 => Status::error(ResponseCode::ErrorNameResolutionNoResults, NO_RESULTS),
        1 => Status::SUCCESS,
        _ => Status::warning(
            ResponseCode::ErrorNameResolutionMultipleResults,
            MULTIPLE_RESULTS,
        ),
    };
    let body = (!resolutions.is_empty()).then(|| ResolveNamesMessage {
        paging: paging(resolutions.len(), complete),
        resolutions,
    });
    messages.message(&MessageResult { status, body });
    messages.finish();
    Ok(ews_response(out))
}

struct Personal {
    contacts: Contacts,
    address_book: u32,
}

impl Personal {
    async fn open(
        server: &Server,
        ctx: &EwsContext,
        request: &ResolveNames<'_>,
    ) -> trc::Result<Result<Option<Self>, Status<'static>>> {
        let Ok(contacts) = Contacts::load(server, ctx).await? else {
            return Ok(Ok(None));
        };
        Ok(resolve_address_book(
            server,
            ctx,
            request.parent_folder_ids.as_deref().unwrap_or_default(),
        )
        .await?
        .map(|address_book| {
            Some(Personal {
                contacts,
                address_book,
            })
        }))
    }

    async fn matches(
        &self,
        server: &Server,
        query: CardQuery<'_>,
        limit: usize,
    ) -> trc::Result<CardMatches> {
        self.contacts
            .match_cards(server, self.address_book, query, limit)
            .await
    }

    fn mailbox<'c>(&self, card: &'c CardMatch) -> EmailAddress<'c> {
        EmailAddress {
            name: Some(Cow::Borrowed(&card.name)),
            email_address: card.email.as_deref().map(Cow::Borrowed),
            routing_type: card.email.as_ref().map(|_| Cow::Borrowed(ROUTING_SMTP)),
            mailbox_type: Some(if card.group {
                MailboxType::PrivateDL
            } else {
                MailboxType::Contact
            }),
            item_id: Some(Box::new(self.contacts.unversioned_id(card.item))),
            ..Default::default()
        }
    }
}

async fn directory_matches(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    query: &NameQuery<'_>,
    limit: usize,
) -> trc::Result<Result<Found, Status<'static>>> {
    if !ctx.account.data_types.contains(DataType::Principal) {
        return Ok(Ok(Found {
            entries: Vec::new(),
            complete: true,
        }));
    }
    if let Some(single) = query.principal(server, caller).await? {
        return Ok(Ok(Found {
            entries: single.into_iter().collect(),
            complete: true,
        }));
    }
    let mut book = Book::new(server, caller.access_token);
    match Found::window(&mut book, Detail::Addresses, limit, |view| {
        query.matches(view)
    })
    .await
    {
        Ok(found) => Ok(Ok(found)),
        Err(BookError::OutOfMemory) => Ok(Err(Status::error(
            ResponseCode::ErrorServerBusy,
            DIRECTORY_BUSY,
        ))),
        Err(BookError::Store(err)) => Err(err),
    }
}

pub(crate) async fn expand_dl(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &ExpandDl<'_>,
) -> trc::Result<HttpResponse> {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::ExpandDL);
    if let Some(id) = request.mailbox.item_id.as_deref() {
        expand_personal(server, ctx, &mut messages, id).await?;
        messages.finish();
        return Ok(ews_response(out));
    }
    let address = request
        .mailbox
        .email_address
        .as_deref()
        .map(str::trim)
        .filter(|address| {
            !address.is_empty() && ctx.account.data_types.contains(DataType::Principal)
        });
    let expansion = match address {
        Some(address) => {
            expand(
                &mut Book::new(server, caller.access_token).with_scope(ScanScope::Lists),
                address,
                ListKind::Any,
            )
            .await
        }
        None => Ok(None),
    };
    match expansion {
        Ok(Some(expansion)) => {
            let externals = caller
                .access_token
                .has_permission(Permission::SysMailingListGet)
                .then(|| expansion.members.external())
                .into_iter()
                .flatten();
            let mailboxes = expansion
                .found
                .entries
                .iter()
                .map(mailbox)
                .chain(externals.map(one_off))
                .take(MAX_DL_MEMBERS)
                .collect::<Vec<_>>();
            let complete = expansion.found.complete && mailboxes.len() < MAX_DL_MEMBERS;
            messages.message(&MessageResult {
                status: expansion.status,
                body: Some(ExpandDlMessage {
                    paging: paging(mailboxes.len(), complete),
                    mailboxes,
                }),
            })
        }
        Ok(None) => messages.message(&no_results()),
        Err(BookError::OutOfMemory) => messages.message(&MessageResult::<ExpandDlMessage> {
            status: Status::error(ResponseCode::ErrorServerBusy, DIRECTORY_BUSY),
            body: None,
        }),
        Err(BookError::Store(err)) => return Err(err),
    }
    messages.finish();
    Ok(ews_response(out))
}

pub(crate) async fn get_rooms(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &GetRooms<'_>,
) -> trc::Result<HttpResponse> {
    let address = request
        .room_list
        .email_address
        .as_deref()
        .map(str::trim)
        .filter(|address| {
            !address.is_empty() && ctx.account.data_types.contains(DataType::Principal)
        });
    let expansion = match address {
        Some(address) => {
            expand(
                &mut Book::new(server, caller.access_token).with_scope(ScanScope::Lists),
                address,
                ListKind::Rooms,
            )
            .await
        }
        None => Ok(None),
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let envelope = ctx.envelope(&mut out);
    match expansion {
        Ok(Some(rooms)) if !rooms.found.entries.is_empty() => envelope.body(&ShapeB {
            op: Operation::GetRooms,
            status: Status::SUCCESS,
            body: Some(GetRoomsBody {
                rooms: rooms.found.entries.iter().map(mailbox).collect(),
            }),
        }),
        Ok(_) => envelope.body(&ShapeB::<GetRoomsBody> {
            op: Operation::GetRooms,
            status: Status::error(ResponseCode::ErrorNameResolutionNoResults, NO_RESULTS),
            body: None,
        }),
        Err(BookError::OutOfMemory) => envelope.body(&ShapeB::<GetRoomsBody> {
            op: Operation::GetRooms,
            status: Status::error(ResponseCode::ErrorServerBusy, DIRECTORY_BUSY),
            body: None,
        }),
        Err(BookError::Store(err)) => return Err(err),
    }
    Ok(ews_response(out))
}

pub(crate) async fn get_room_lists(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
) -> trc::Result<HttpResponse> {
    let lists = if ctx.account.data_types.contains(DataType::Principal) {
        room_lists(&mut Book::new(server, caller.access_token).with_scope(ScanScope::Rooms)).await
    } else {
        Ok(Found {
            entries: Vec::new(),
            complete: true,
        })
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let envelope = ctx.envelope(&mut out);
    match lists {
        Ok(lists) => envelope.body(&ShapeB {
            op: Operation::GetRoomLists,
            status: Status::SUCCESS,
            body: Some(GetRoomListsBody {
                room_lists: lists.entries.iter().map(mailbox).collect(),
            }),
        }),
        Err(BookError::OutOfMemory) => envelope.body(&ShapeB::<GetRoomListsBody> {
            op: Operation::GetRoomLists,
            status: Status::error(ResponseCode::ErrorServerBusy, DIRECTORY_BUSY),
            body: None,
        }),
        Err(BookError::Store(err)) => return Err(err),
    }
    Ok(ews_response(out))
}

async fn room_lists(book: &mut Book<'_>) -> BookResult<Found> {
    let rooms = book.addresses().await?;
    if rooms.is_empty() {
        return Ok(Found {
            entries: Vec::new(),
            complete: true,
        });
    }
    book.set_scope(ScanScope::Lists);
    let mut folded = String::new();
    let page = book
        .window(Detail::Key, 0, MAX_DL_MEMBERS, |key, _| {
            let RowRef::List(list) = key.subject() else {
                return false;
            };
            list.recipients.iter().any(|recipient| {
                folded.clear();
                folded.extend(recipient.chars().map(|c| c.to_ascii_lowercase()));
                rooms.contains(folded.as_str())
            })
        })
        .await?;
    Found::load(book, page, MAX_DL_MEMBERS).await
}

async fn expand_personal(
    server: &Server,
    ctx: &EwsContext,
    messages: &mut MessagesWriter<'_>,
    id: &ItemId<'_>,
) -> trc::Result<()> {
    let Some((GroupwareKind::Contact, account, item)) = decode_item_id(id) else {
        messages.message(&no_results());
        return Ok(());
    };
    let contacts = match Contacts::load(server, ctx).await? {
        Ok(contacts) => contacts,
        Err(err) => {
            messages.message(&MessageResult::<ExpandDlMessage> {
                status: err.status(),
                body: None,
            });
            return Ok(());
        }
    };
    let opened = match contacts.check(account, item) {
        Ok(item) => contacts.open_card(server, item).await?,
        Err(err) => Err(err),
    };
    let card = match opened {
        Ok(opened) if is_contact_group(&opened.card) => opened.card,
        Ok(_) => {
            messages.message(&MessageResult::<ExpandDlMessage> {
                status: Status::error(
                    ResponseCode::ErrorInvalidItemForOperationExpandDL,
                    NOT_A_LIST,
                ),
                body: None,
            });
            return Ok(());
        }
        Err(_) => {
            messages.message(&no_results());
            return Ok(());
        }
    };
    let members = contacts
        .group_members(server, &card, MAX_DL_MEMBERS)
        .await?;
    let mailboxes = members
        .mailboxes(&contacts)
        .map(|(_, mailbox)| mailbox)
        .collect::<Vec<_>>();
    messages.message(&MessageResult {
        status: Status::SUCCESS,
        body: Some(ExpandDlMessage {
            paging: paging(mailboxes.len(), members.complete),
            mailboxes,
        }),
    });
    Ok(())
}

fn no_results() -> MessageResult<'static, ExpandDlMessage<'static>> {
    MessageResult {
        status: Status::error(ResponseCode::ErrorNameResolutionNoResults, NO_RESULTS),
        body: None,
    }
}

async fn expand(
    book: &mut Book<'_>,
    address: &str,
    kind: ListKind,
) -> BookResult<Option<Expansion>> {
    let (list, status) = {
        let legacy_dn = address.starts_with(LEGACY_DN_MARKER);
        let page = book
            .window(Detail::Addresses, 0, 1, |_, view| {
                view.kind == AbKind::List && names_list(view, address, legacy_dn)
            })
            .await?;
        let Some(list) = page.rows.into_iter().next() else {
            return Ok(None);
        };
        let status = if page.total > 1 {
            Status::warning(
                ResponseCode::ErrorNameResolutionMultipleResults,
                MULTIPLE_RESULTS,
            )
        } else {
            Status::SUCCESS
        };
        (list, status)
    };
    let mut members = book.members(&list, MAX_DL_MEMBERS).await?;
    members.rows.retain(|key| kind.is_member(key));
    let page = Page {
        total: members
            .rows
            .len()
            .saturating_add(usize::from(members.truncated)),
        rows: std::mem::take(&mut members.rows),
        start: 0,
        anchor: 0,
    };
    Ok(Some(Expansion {
        status,
        found: Found::load(book, page, MAX_DL_MEMBERS).await?,
        members,
    }))
}

fn names_list(view: &AbView<'_>, address: &str, legacy_dn: bool) -> bool {
    view.account.eq_ignore_ascii_case(address)
        || view.display_name.eq_ignore_ascii_case(address)
        || view
            .addresses()
            .any(|own| own.eq_ignore_ascii_case(address))
        || (legacy_dn && view.dn().is_some_and(|dn| dn.eq_ignore_ascii_case(address)))
}

fn paging(returned: usize, complete: bool) -> Paging {
    Paging {
        indexed_paging_offset: None,
        numerator_offset: None,
        absolute_denominator: None,
        includes_last_item_in_range: Some(complete),
        total_items_in_view: i32::try_from(returned).unwrap_or(i32::MAX),
    }
}

fn mailbox(entry: &AbEntry) -> EmailAddress<'_> {
    EmailAddress {
        name: Some(Cow::Borrowed(&entry.display_name)),
        email_address: Some(Cow::Borrowed(&entry.smtp)),
        routing_type: Some(Cow::Borrowed(ROUTING_SMTP)),
        mailbox_type: Some(match entry.kind {
            AbKind::List => MailboxType::PublicDL,
            AbKind::User => MailboxType::Mailbox,
        }),
        ..Default::default()
    }
}

fn one_off(address: &str) -> EmailAddress<'_> {
    EmailAddress {
        email_address: Some(Cow::Borrowed(address)),
        routing_type: Some(Cow::Borrowed(ROUTING_SMTP)),
        mailbox_type: Some(MailboxType::OneOff),
        ..Default::default()
    }
}

fn contact(entry: &AbEntry) -> ContactItem<'_> {
    ContactItem {
        contact: ContactFields {
            display_name: Some(Cow::Borrowed(&entry.display_name)),
            email_addresses: Some(List(
                CONTACT_KEYS
                    .into_iter()
                    .zip(entry.proxies.iter())
                    .map(|(key, proxy)| EmailAddressEntry {
                        key,
                        name: None,
                        routing_type: None,
                        mailbox_type: None,
                        address: Cow::Borrowed(proxy),
                    })
                    .collect(),
            )),
            contact_source: Some(ContactSource::ActiveDirectory),
            ..Default::default()
        },
        ..Default::default()
    }
}
