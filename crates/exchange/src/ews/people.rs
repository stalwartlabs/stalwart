/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    contact::{Contacts, address_book_of, find::ContactProp},
    context::{EwsCaller, EwsContext},
    directory::LEGACY_DN_MARKER,
    filter::{Filter, FilterProp},
    folder::{
        FolderSelector,
        get::{Window, max_entries},
        resolve_folder,
    },
    groupware::{FindPlan, GroupwareFields, items::GroupwareRef},
    item::ItemError,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use crate::{
    eas::directory::{GalQuery, MAX_GAL_RESULTS},
    identity::principal_from_dn,
    mapi::nspi::{
        book::{AbEntry, Book, BookError, principal_entry},
        page::{AbKind, fold},
        scan::{AbView, Detail, ScanScope},
        table::name_anr,
    },
};
use common::Server;
use exchange_proto::{
    ews::{
        Operation, Status,
        contact::{ContactFieldSet, ContactProps, ContactText},
        persona::{PersonaEntry, PersonaFieldSet, PersonaKind, persona_text},
        requests::people::{FindPeople, GetPersona},
        responses::{
            ShapeB,
            people::{FindPeopleBody, GetPersonaBody},
        },
        schema::{
            DistinguishedFolderName, EmailAddressKey, IndexBasePoint, ResponseCode, SortDirection,
            UnindexedField,
        },
        types::{
            ids::{DistinguishedFolderId, EwsIdStr, ItemId, TargetFolderId},
            path::Path,
            view::{FieldOrder, FolderView, IndexedView},
        },
    },
    ids::ews::EwsPersonaId,
};
use http_proto::HttpResponse;
use std::borrow::Cow;
use types::type_state::DataType;

const MAX_DIRECTORY_MATCHES: usize = 1000;
const PEOPLE_PAGE: usize = MAX_GAL_RESULTS as usize;
const NOT_CONTACTS: &str = "FindPeople requires a contacts folder or the directory.";
const DIRECTORY_BUSY: &str = "The address book is not available.";
const PERSONA_NOT_FOUND: &str = "The persona was not found.";
const PERSONA_MALFORMED: &str = "The persona id is malformed.";
const PERSONA_REQUIRED: &str = "A PersonaId or an EmailAddress is required.";
const CONTACT_QUERY_FIELDS: [ContactText; 7] = [
    ContactText::DisplayName,
    ContactText::GivenName,
    ContactText::Surname,
    ContactText::CompanyName,
    ContactText::Email(EmailAddressKey::EmailAddress1),
    ContactText::Email(EmailAddressKey::EmailAddress2),
    ContactText::Email(EmailAddressKey::EmailAddress3),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersonaProp(ContactProp);

impl FilterProp for PersonaProp {
    fn of_path(path: &Path<'_>) -> Option<Self> {
        persona_text(path)
            .map(ContactProp::Text)
            .or_else(|| ContactProp::of_path(path))
            .map(PersonaProp)
    }
}

enum PeopleSource {
    AddressBook(u32),
    Directory,
}

pub(crate) async fn find_people(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &FindPeople<'_>,
) -> trc::Result<HttpResponse> {
    let fields = PersonaFieldSet::from_shape(request.shape.as_ref());
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let status = match source(server, ctx, request.parent_folder_id.as_ref()).await? {
        Ok(PeopleSource::AddressBook(address_book)) => {
            find_contacts(server, ctx, request, address_book, fields, &mut out).await?
        }
        Ok(PeopleSource::Directory) => {
            find_directory(server, ctx, caller, request, fields, &mut out).await?
        }
        Err(status) => Err(status),
    };
    if let Err(status) = status {
        ctx.envelope(&mut out).body(&ShapeB::<FindPeopleBody> {
            op: Operation::FindPeople,
            status,
            body: None,
        });
    }
    Ok(ews_response(out))
}

async fn source(
    server: &Server,
    ctx: &EwsContext,
    parent: Option<&TargetFolderId<'_>>,
) -> trc::Result<Result<PeopleSource, Status<'static>>> {
    let contacts = DistinguishedFolderId {
        name: DistinguishedFolderName::Contacts,
        change_key: None,
        mailbox: None,
    };
    let selector = match parent {
        Some(TargetFolderId::Distinguished(id))
            if id.name == DistinguishedFolderName::Directory =>
        {
            return Ok(Ok(PeopleSource::Directory));
        }
        Some(TargetFolderId::AddressList(_)) => return Ok(Ok(PeopleSource::Directory)),
        Some(parent) => FolderSelector::from(parent),
        None => FolderSelector::Distinguished(&contacts),
    };
    let tree = ctx.folder_tree(server).await?;
    Ok(match resolve_folder(server, ctx, &tree, selector).await? {
        Ok(entry) if !ctx.access.of(entry.node).reads_items() => Err(ItemError::Forbidden.status()),
        Ok(entry) => address_book_of(entry.node)
            .map(PeopleSource::AddressBook)
            .ok_or_else(|| {
                Status::error(
                    ResponseCode::ErrorInvalidFolderTypeForOperation,
                    NOT_CONTACTS,
                )
            }),
        Err(status) => Err(status),
    })
}

async fn find_contacts(
    server: &Server,
    ctx: &EwsContext,
    request: &FindPeople<'_>,
    address_book: u32,
    fields: PersonaFieldSet,
    out: &mut Vec<u8>,
) -> trc::Result<Result<(), Status<'static>>> {
    let contacts = match Contacts::load(server, ctx).await? {
        Ok(contacts) => contacts,
        Err(err) => return Ok(Err(err.status())),
    };
    let by_name = [FieldOrder {
        path: Path::Field(UnindexedField::PersonaDisplayName),
        order: SortDirection::Ascending,
    }];
    let sort = request
        .sort_order
        .as_deref()
        .filter(|sort| !sort.is_empty())
        .unwrap_or(&by_name);
    let plan = match FindPlan::<PersonaProp>::new(request.restriction.as_ref(), Some(sort)) {
        Ok(plan) => plan,
        Err(unsupported) => return Ok(Err(unsupported.status())),
    };
    let aggregation = match request
        .aggregation_restriction
        .as_ref()
        .map(Filter::<PersonaProp>::new)
        .transpose()
    {
        Ok(aggregation) => aggregation,
        Err(unsupported) => return Ok(Err(unsupported.status())),
    };
    let query = request
        .query_string
        .as_deref()
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(fold);
    let mut candidates = Vec::new();
    contacts
        .scan(server, address_book, |item, props| {
            let value = |prop: PersonaProp| {
                ContactFieldSet::value(&contacts, item.document_id, prop.0, props)
            };
            if query
                .as_deref()
                .is_some_and(|query| !contact_matches(ContactProps::new(props), query))
                || aggregation
                    .as_ref()
                    .is_some_and(|aggregation| !aggregation.matches(&value))
            {
                return;
            }
            candidates.extend(plan.candidate(item, item.document_id, value));
        })
        .await?;
    plan.sort(&mut candidates);
    let view = FolderView::Indexed(request.indexed_page_item_view);
    let window = Window::new(Some(&view), candidates.len());
    let page = window
        .slice(&candidates)
        .iter()
        .map(|candidate| candidate.item)
        .collect::<Vec<GroupwareRef>>();
    let loaded = contacts
        .load_many(server, &page, ContactFieldSet::all().for_list())
        .await?;
    let people = loaded
        .iter()
        .filter_map(|loaded| {
            let content = loaded.content.as_ref()?;
            let id = persona_id(EwsPersonaId::Contact {
                account: contacts.account_id,
                container: loaded.item.container,
                id: loaded.item.document_id,
            });
            Some(ContactProps::new(&content.props).persona(fields, id))
        })
        .collect();
    write_people(ctx, out, people, candidates.len(), window.offset);
    Ok(Ok(()))
}

async fn find_directory(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &FindPeople<'_>,
    fields: PersonaFieldSet,
    out: &mut Vec<u8>,
) -> trc::Result<Result<(), Status<'static>>> {
    if let Err(unsupported) =
        FindPlan::<PersonaProp>::new(request.restriction.as_ref(), request.sort_order.as_deref())
    {
        return Ok(Err(unsupported.status()));
    }
    if let Some(Err(unsupported)) = request
        .aggregation_restriction
        .as_ref()
        .map(Filter::<PersonaProp>::new)
    {
        return Ok(Err(unsupported.status()));
    }
    let query = request.query_string.as_deref().and_then(GalQuery::new);
    let (Some(query), true) = (query, ctx.account.data_types.contains(DataType::Principal)) else {
        write_people(ctx, out, Vec::new(), 0, 0);
        return Ok(Ok(()));
    };
    let mut book = Book::new(server, caller.access_token).with_scope(ScanScope::Accounts);
    let entries = match directory_page(&mut book, &query, request.indexed_page_item_view).await {
        Ok(entries) => entries,
        Err(BookError::OutOfMemory) => {
            return Ok(Err(Status::error(
                ResponseCode::ErrorServerBusy,
                DIRECTORY_BUSY,
            )));
        }
        Err(BookError::Store(err)) => return Err(err),
    };
    let people = entries
        .entries
        .iter()
        .filter_map(|entry| directory_persona(entry, fields))
        .collect();
    write_people(ctx, out, people, entries.total, entries.offset);
    Ok(Ok(()))
}

pub(crate) struct DirectoryPage {
    pub entries: Vec<AbEntry>,
    total: usize,
    offset: usize,
}

pub(crate) async fn directory_page(
    book: &mut Book<'_>,
    query: &GalQuery<'_>,
    view: IndexedView,
) -> Result<DirectoryPage, BookError> {
    let requested = usize::try_from(view.offset).unwrap_or_default();
    let mut count = max_entries(view.max_entries).min(PEOPLE_PAGE);
    let first = match view.base_point {
        IndexBasePoint::Beginning => requested,
        IndexBasePoint::End => {
            let total = book
                .window(Detail::Addresses, 0, 0, |_, entry| person(query, entry))
                .await?
                .total;
            let end = total.saturating_sub(requested);
            count = count.min(end);
            end - count
        }
    }
    .min(MAX_DIRECTORY_MATCHES);
    let count = count.min(MAX_DIRECTORY_MATCHES - first);
    let page = book
        .window(Detail::Addresses, first, count, |_, entry| {
            person(query, entry)
        })
        .await?;
    let mut entries = Vec::with_capacity(page.rows.len());
    for key in &page.rows {
        if let Some(entry) = book.entry(key).await? {
            entries.push(entry);
        }
    }
    Ok(DirectoryPage {
        entries,
        total: page.total,
        offset: page.start,
    })
}

fn write_people(
    ctx: &EwsContext,
    out: &mut Vec<u8>,
    people: Vec<PersonaEntry<'_>>,
    total: usize,
    offset: usize,
) {
    let offset = i32::try_from(offset).unwrap_or(i32::MAX);
    ctx.envelope(out).body(&ShapeB {
        op: Operation::FindPeople,
        status: Status::SUCCESS,
        body: Some(FindPeopleBody {
            people,
            total_number_of_people_in_view: Some(i32::try_from(total).unwrap_or(i32::MAX)),
            first_matching_row_index: Some(offset),
            first_loaded_row_index: Some(offset),
            transaction_id: None,
        }),
    });
}

pub(crate) fn contact_matches(props: ContactProps<'_>, query: &str) -> bool {
    CONTACT_QUERY_FIELDS
        .into_iter()
        .filter_map(|field| props.field_text(field))
        .any(|text| name_anr(text, query))
}

fn persona_id(id: EwsPersonaId) -> ItemId<'static> {
    ItemId {
        id: EwsIdStr::Minted(id.encode()),
        change_key: None,
    }
}

fn person(query: &GalQuery<'_>, entry: &AbView<'_>) -> bool {
    entry.kind != AbKind::List && query.matches(entry)
}

fn directory_persona(entry: &AbEntry, fields: PersonaFieldSet) -> Option<PersonaEntry<'_>> {
    let principal = entry.principal.account_id()?;
    let id = persona_id(EwsPersonaId::Directory { principal });
    let mut persona = PersonaEntry::new(fields, id, PersonaKind::Person);
    persona.display_name = Some(Cow::Borrowed(&entry.display_name));
    if persona.wants_addresses() {
        let name = Some(&*entry.display_name);
        persona.email_addresses.extend(
            entry
                .view()
                .addresses()
                .map(|address| PersonaEntry::smtp_address(name, address)),
        );
    }
    Some(persona)
}

pub(crate) async fn get_persona(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &GetPersona<'_>,
) -> trc::Result<HttpResponse> {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let fields = PersonaFieldSet::all();
    let directory = ctx.account.data_types.contains(DataType::Principal);
    let target = match (&request.persona_id, &request.email_address) {
        (Some(id), _) => match EwsPersonaId::decode(id.id.as_str()) {
            Some(id) => Ok(id),
            None => Err(Status::error(
                ResponseCode::ErrorInvalidIdMalformed,
                PERSONA_MALFORMED,
            )),
        },
        (None, Some(address)) => {
            let principal = match address
                .email_address
                .as_deref()
                .map(str::trim)
                .filter(|address| directory && !address.is_empty())
            {
                Some(address) if address.starts_with(LEGACY_DN_MARKER) => {
                    principal_from_dn(address.as_bytes())
                }
                Some(address) => server.account_id_from_email(address, false).await?,
                None => None,
            };
            principal
                .map(|principal| EwsPersonaId::Directory { principal })
                .ok_or_else(not_found)
        }
        (None, None) => Err(Status::error(
            ResponseCode::ErrorInvalidArgument,
            PERSONA_REQUIRED,
        )),
    };
    match target {
        Ok(EwsPersonaId::Contact {
            account,
            container,
            id,
        }) => {
            let item = GroupwareRef {
                container,
                document_id: id,
            };
            let contacts = match Contacts::load(server, ctx).await? {
                Ok(contacts) => contacts,
                Err(err) => return Ok(persona_error(ctx, out, err.status())),
            };
            let loaded = match contacts.check(account, item) {
                Ok(item) => {
                    contacts
                        .load_item(server, item, ContactFieldSet::all().for_list())
                        .await?
                }
                Err(err) => Err(err),
            };
            let Some(content) = loaded.ok().and_then(|loaded| loaded.content) else {
                return Ok(persona_error(ctx, out, not_found()));
            };
            let id = persona_id(EwsPersonaId::Contact {
                account,
                container,
                id,
            });
            write_persona(
                ctx,
                &mut out,
                ContactProps::new(&content.props).persona(fields, id),
            );
        }
        Ok(EwsPersonaId::Directory { principal }) => {
            let entry = if directory {
                principal_entry(server, caller.access_token, principal).await?
            } else {
                None
            };
            let Some(persona) = entry
                .as_ref()
                .and_then(|entry| directory_persona(entry, fields))
            else {
                return Ok(persona_error(ctx, out, not_found()));
            };
            write_persona(ctx, &mut out, persona);
        }
        Err(status) => return Ok(persona_error(ctx, out, status)),
    }
    Ok(ews_response(out))
}

fn write_persona(ctx: &EwsContext, out: &mut Vec<u8>, persona: PersonaEntry<'_>) {
    ctx.envelope(out).body(&ShapeB {
        op: Operation::GetPersona,
        status: Status::SUCCESS,
        body: Some(GetPersonaBody { persona }),
    });
}

fn persona_error(ctx: &EwsContext, mut out: Vec<u8>, status: Status<'static>) -> HttpResponse {
    ctx.envelope(&mut out).body(&ShapeB::<GetPersonaBody> {
        op: Operation::GetPersona,
        status,
        body: None,
    });
    ews_response(out)
}

fn not_found() -> Status<'static> {
    Status::error(ResponseCode::ErrorItemNotFound, PERSONA_NOT_FOUND)
}
