/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod book;
pub mod page;
pub mod props;
pub mod scan;
pub mod table;
pub mod templates;

use super::{
    http::{CookieSet, Envelope, Expiration, Reply, endpoint_path},
    session::{
        LockOutcome, SESSION_TTL_SECS, SessionKey, SessionKind, SessionLock, SessionState,
        connect_allowed, delete_session, load_session, save_session,
    },
    text::decode_text,
};
use crate::{
    autodiscover::Endpoints,
    identity::{deployment_guid, directory_ref_from_dn},
};
use book::{AbEntry, Book, BookError, ResourceDetail};
use common::{Server, auth::AccessToken};
use exchange_proto::{
    common::Guid,
    ids::{
        entryid::{AddressBookEntryId, EntryId},
        essdn::GAL_DN,
    },
    mapi::{
        RequestType, ResponseCode, StatusCode,
        emsmdb::write_failure_body,
        http::Endpoint,
        nspi::{
            AbkCell, AbkListWriter, AbkRowWriter, MinimalId, NspiLimits, NspiRequest, NspiStatus,
            PropTagList, Stat,
            tags::{
                AB_RECIPIENTS, AB_ROOMS, AB_UNMODIFIABLE, CONTAINER_CONTENTS, CONTAINER_FLAGS,
                CONTAINER_ID, DT_CONTAINER, IS_MASTER,
            },
            verbs::{
                BIND_ANONYMOUS, Bind, CompareMinIds, DnToMinId, EPH_ID, GetMatches, GetPropList,
                GetProps, GetSpecialTable, GetTemplateInfo, ModLinkAtt, ModProps,
                QUERY_COLUMNS_UNICODE, QueryRows, ResolveNames, ResortRestriction, SKIP_OBJECTS,
                SPECIAL_ADDRESS_CREATION_TEMPLATES, SPECIAL_UNICODE_STRINGS, SeekEntries,
                UpdateStat, parse_nspi, write_has, write_mids, write_nspi_success, write_prop_tags,
                write_server_guid, write_state, write_u32_opt, write_url,
            },
        },
        prop::{CodePage, PropTag, PropType, PropValue, tags, value::CountWidth},
        restriction::{Restriction, RestrictionBytes},
    },
};
use page::{AbKind, Anchor, Page, RowKey, RowRef, Seek, fold};
use props::{
    AbValue, DEFAULT_COLUMNS, EntryIdForm, all_tags, as_string8, entry_tags, resource_detail,
};
use scan::{Detail, directory_ref_from_email};
use std::{borrow::Cow, cmp::Ordering};
use store::{
    Serialize,
    write::{Archive, ArchiveBytes, ArchiveCompression, Archiver, now},
};
use table::{
    Matcher, NameKind, PendingName, ROOMS_CONTAINER, ROOMS_CONTAINER_DN, Resolution,
    container_scope, set_position,
};
use templates::Template;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

const MAX_ROWS: usize = 4096;
const MAX_MATCHES: usize = MAX_ROWS;
const MAX_COLUMNS: usize = 512;
const MAX_RESOLVE_NAMES: usize = 256;
const MAX_RESPONSE_BYTES: usize = 4 << 20;
const SEEK_ROWS: usize = 50;
const GAL_DISPLAY_NAME: &str = "Global Address List";
const ROOMS_DISPLAY_NAME: &str = "All Rooms";
const MEMBER_PROP_ID: u16 = 0x8009;
const PUBLIC_DELEGATES_PROP_ID: u16 = 0x8015;
const GAL_MID: MinimalId = MinimalId(0);
const HIERARCHY_TABLE_VERSION: u32 = 1;

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone)]
pub struct NspiState {
    pub account_id: u32,
    pub code_page: u32,
    pub refreshed_at: u64,
}

impl ArchiveCompression for NspiState {}

impl SessionState for NspiState {
    fn encode(self) -> trc::Result<Vec<u8>> {
        Archiver::new(self).untrusted().serialize()
    }

    fn decode(archive: &Archive<ArchiveBytes>) -> trc::Result<Self> {
        archive.deserialize_untrusted::<NspiState>()
    }
}

pub struct NspiRequestHandler<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub envelope: &'x Envelope,
    pub body: &'x [u8],
}

#[derive(Debug)]
enum Failure {
    Status(NspiStatus),
    Store(trc::Error),
}

impl From<NspiStatus> for Failure {
    fn from(status: NspiStatus) -> Self {
        Failure::Status(status)
    }
}

impl From<trc::Error> for Failure {
    fn from(err: trc::Error) -> Self {
        Failure::Store(err)
    }
}

impl From<BookError> for Failure {
    fn from(err: BookError) -> Self {
        match err {
            BookError::OutOfMemory => Failure::Status(NspiStatus::OUT_OF_RESOURCES),
            BookError::Store(err) => Failure::Store(err),
        }
    }
}

type NspiResult = Result<(), Failure>;

impl NspiRequestHandler<'_> {
    fn session_key(&self) -> Result<SessionKey, ResponseCode> {
        self.envelope
            .context_key(SessionKind::Nspi, self.access_token.account_id())
    }

    fn server_guid(&self) -> Guid {
        deployment_guid(&self.server.core.network.server_name)
    }

    pub async fn handle(&self) -> trc::Result<Reply> {
        let request_type = self.envelope.request_type;
        if request_type == RequestType::Ping {
            return self.ping().await;
        }
        let request = match parse_nspi(request_type, self.body, &NspiLimits::DEFAULT) {
            Ok(parsed) => parsed.request,
            Err(err) => {
                let code = err.response_code();
                if code != ResponseCode::Success {
                    return Ok(Reply::response_code(code));
                }
                let mut body = Vec::with_capacity(32);
                self.error_body(&mut body, err.status());
                return Ok(self.reply(body, self.session_key().ok(), false));
            }
        };
        match request {
            NspiRequest::Bind(bind) => self.bind(&bind).await,
            NspiRequest::Unbind => self.unbind().await,
            request => {
                let key = match self.session_key() {
                    Ok(key) => key,
                    Err(code) => return Ok(Reply::response_code(code)),
                };
                if !self.touch(key).await? {
                    return Ok(Reply::response_code(ResponseCode::ContextNotFound));
                }
                let mut body = Vec::with_capacity(512);
                let result = match request {
                    NspiRequest::GetMailboxUrl(_) => self.endpoint_url(Endpoint::Emsmdb, &mut body),
                    NspiRequest::GetAddressBookUrl(_) => {
                        self.endpoint_url(Endpoint::Nspi, &mut body)
                    }
                    request => self.dispatch(request, &mut body).await,
                };
                match result {
                    Ok(()) => {}
                    Err(Failure::Status(status)) => {
                        body.clear();
                        self.error_body(&mut body, status);
                    }
                    Err(Failure::Store(err)) => return Err(err),
                }
                Ok(self.reply(body, Some(key), false))
            }
        }
    }

    fn reply(&self, body: Vec<u8>, key: Option<SessionKey>, expired: bool) -> Reply {
        Reply {
            body,
            response_code: None,
            cookies: key.map(|context| CookieSet {
                context,
                sequence: None,
                expired,
            }),
            expiration: Some(Expiration::Session),
        }
    }

    async fn bind(&self, bind: &Bind) -> trc::Result<Reply> {
        let server_guid = self.server_guid();
        let mut body = Vec::with_capacity(32);
        if bind.flags & BIND_ANONYMOUS != 0 {
            self.error_body(&mut body, NspiStatus::NOT_SUPPORTED);
            return Ok(self.reply(body, None, false));
        }
        let state = bind.state.as_ref();
        if state.is_some_and(|state| {
            state.code_page == Stat::CP_WINUNICODE || code_page(state.code_page).is_err()
        }) {
            write_nspi_success(&mut body, NspiStatus::INVALID_CODEPAGE, |out| {
                write_server_guid(out, &server_guid)
            });
            return Ok(self.reply(body, None, false));
        }
        if let Ok(previous) = self.session_key() {
            self.end_session(previous).await?;
        }
        let mut types = Bitmap::<DataType>::all();
        self.access_token.restrict_data_types(&mut types);
        if !types.contains(DataType::Principal) {
            self.error_body(&mut body, NspiStatus::LOGON_FAILED);
            return Ok(self.reply(body, None, false));
        }
        let account_id = self.access_token.account_id();
        if !connect_allowed(self.server, account_id).await? {
            write_failure_body(&mut body, StatusCode::SERVER_TOO_BUSY);
            return Ok(self.reply(body, None, false));
        }
        let key = SessionKey::generate(SessionKind::Nspi, account_id);
        save_session(
            self.server,
            key,
            NspiState {
                account_id,
                code_page: state.map_or(0, |state| state.code_page),
                refreshed_at: now(),
            },
        )
        .await?;
        write_nspi_success(&mut body, NspiStatus::SUCCESS, |out| {
            write_server_guid(out, &server_guid)
        });
        Ok(self.reply(body, Some(key), false))
    }

    async fn unbind(&self) -> trc::Result<Reply> {
        let key = self.session_key().ok();
        if let Some(key) = key {
            self.end_session(key).await?;
        }
        let mut body = Vec::with_capacity(12);
        write_nspi_success(&mut body, NspiStatus::UNBIND_SUCCESS, |_| {});
        Ok(self.reply(body, key, true))
    }

    fn endpoint_url(&self, endpoint: Endpoint, out: &mut Vec<u8>) -> NspiResult {
        let mut url = Endpoints::new(self.server).url(endpoint_path(endpoint));
        url.push('/');
        write_nspi_success(out, NspiStatus::SUCCESS, |out| write_url(out, &url));
        Ok(())
    }

    async fn end_session(&self, key: SessionKey) -> trc::Result<()> {
        match SessionLock::acquire_patiently(self.server, key).await? {
            LockOutcome::Acquired(lock) => {
                delete_session(&lock).await?;
                lock.release().await
            }
            LockOutcome::Busy => Ok(()),
        }
    }

    async fn touch(&self, key: SessionKey) -> trc::Result<bool> {
        let Some(state) = load_session::<NspiState>(self.server, key).await? else {
            return Ok(false);
        };
        let now = now();
        if now.saturating_sub(state.refreshed_at) < SESSION_TTL_SECS / 2 {
            return Ok(true);
        }
        let LockOutcome::Acquired(lock) = SessionLock::acquire(self.server, key).await? else {
            return Ok(true);
        };
        let alive = match load_session::<NspiState>(self.server, key).await? {
            Some(state) => {
                save_session(
                    self.server,
                    key,
                    NspiState {
                        refreshed_at: now,
                        ..state
                    },
                )
                .await?;
                true
            }
            None => false,
        };
        lock.release().await?;
        Ok(alive)
    }

    async fn ping(&self) -> trc::Result<Reply> {
        let key = match self.session_key() {
            Ok(key) => key,
            Err(code) => return Ok(Reply::response_code(code)),
        };
        if self.touch(key).await? {
            Ok(self.reply(Vec::new(), Some(key), false))
        } else {
            Ok(Reply::response_code(ResponseCode::ContextNotFound))
        }
    }

    async fn dispatch(&self, request: NspiRequest<'_>, out: &mut Vec<u8>) -> NspiResult {
        let mut book = Book::new(self.server, self.access_token);
        match request {
            NspiRequest::GetSpecialTable(request) => get_special_table(&request, out),
            NspiRequest::UpdateStat(request) => update_stat(&mut book, &request, out).await,
            NspiRequest::QueryColumns(request) => {
                query_columns(request.flags & QUERY_COLUMNS_UNICODE != 0, out)
            }
            NspiRequest::GetPropList(request) => get_prop_list(&mut book, &request, out).await,
            NspiRequest::GetProps(request) => get_props(&mut book, &request, out).await,
            NspiRequest::QueryRows(request) => query_rows(&mut book, &request, out).await,
            NspiRequest::SeekEntries(request) => seek_entries(&mut book, &request, out).await,
            NspiRequest::GetMatches(request) => get_matches(&mut book, &request, out).await,
            NspiRequest::ResortRestriction(request) => {
                resort_restriction(&mut book, &request, out).await
            }
            NspiRequest::CompareMinIds(request) => compare_min_ids(&book, &request, out).await,
            NspiRequest::DnToMinId(request) => dn_to_min_id(&book, &request, out).await,
            NspiRequest::ResolveNames(request) => resolve_names(&mut book, &request, out).await,
            NspiRequest::GetTemplateInfo(request) => get_template_info(&request, out),
            NspiRequest::ModProps(request) => mod_props(&book, &request).await,
            NspiRequest::ModLinkAtt(request) => {
                mod_link_att(&book, &request, self.access_token.account_id(), out).await
            }
            NspiRequest::Bind(_)
            | NspiRequest::Unbind
            | NspiRequest::GetMailboxUrl(_)
            | NspiRequest::GetAddressBookUrl(_) => Err(NspiStatus::GENERAL_FAILURE.into()),
        }
    }

    fn error_body(&self, out: &mut Vec<u8>, status: NspiStatus) {
        let request_type = self.envelope.request_type;
        let server_guid = (request_type == RequestType::Bind).then(|| self.server_guid());
        write_nspi_success(out, status, |out| {
            if let Some(guid) = &server_guid {
                write_server_guid(out, guid);
            }
            let (fixed, flags) = error_layout(request_type);
            out.extend(std::iter::repeat_n(0u8, fixed));
            out.extend(std::iter::repeat_n(0u8, flags));
        });
    }
}

fn error_layout(request_type: RequestType) -> (usize, usize) {
    match request_type {
        RequestType::CompareMinIds => (4, 0),
        RequestType::GetSpecialTable => (4, 2),
        RequestType::GetProps | RequestType::GetTemplateInfo => (4, 1),
        RequestType::ResolveNames => (4, 2),
        RequestType::GetMailboxUrl | RequestType::GetAddressBookUrl => (2, 0),
        RequestType::GetMatches => (0, 3),
        RequestType::QueryRows
        | RequestType::SeekEntries
        | RequestType::ResortRestriction
        | RequestType::UpdateStat => (0, 2),
        RequestType::GetPropList | RequestType::QueryColumns | RequestType::DnToMinId => (0, 1),
        _ => (0, 0),
    }
}

fn code_page(value: u32) -> Result<CodePage, NspiStatus> {
    if value == 0 || value == Stat::CP_WINUNICODE {
        Ok(CodePage::WINDOWS_1252)
    } else {
        CodePage::from_identifier(value).ok_or(NspiStatus::INVALID_CODEPAGE)
    }
}

fn get_template_info(request: &GetTemplateInfo<'_>, out: &mut Vec<u8>) -> NspiResult {
    if request.code_page == Stat::CP_WINUNICODE {
        return Err(NspiStatus::INVALID_CODEPAGE.into());
    }
    code_page(request.code_page)?;
    let template = match request.template_dn {
        Some(dn) => Template::from_dn(dn),
        None if request.locale_id == templates::NO_LOCALE => None,
        None => Template::for_display_type(request.display_type),
    }
    .ok_or(NspiStatus::INVALID_LOCALE)?;
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        out.extend_from_slice(&request.code_page.to_le_bytes());
        write_has(out, true);
        let mut list = AbkListWriter::begin(out);
        template.write_info(request.flags, &mut list);
        list.finish();
    });
    Ok(())
}

fn entry_id_form(flags: u32) -> EntryIdForm {
    if flags & EPH_ID != 0 {
        EntryIdForm::Ephemeral
    } else {
        EntryIdForm::Permanent
    }
}

fn get_special_table(request: &GetSpecialTable, out: &mut Vec<u8>) -> NspiResult {
    let stat = request.state.unwrap_or_default();
    let templates = request.flags & SPECIAL_ADDRESS_CREATION_TEMPLATES != 0;
    let unicode = !templates && request.flags & SPECIAL_UNICODE_STRINGS != 0;
    let (used_code_page, name_code_page) = if unicode {
        (Stat::CP_WINUNICODE, CodePage::WINDOWS_1252)
    } else if templates {
        (stat.code_page, CodePage::WINDOWS_1252)
    } else {
        (stat.code_page, code_page(stat.code_page)?)
    };
    let mut creation_table = Vec::new();
    if templates {
        Template::write_creation_table(stat.template_locale, &mut creation_table)
            .map_err(|_| NspiStatus::GENERAL_FAILURE)?;
    }
    let gal_id = container_entry_id(GAL_DN)?;
    let rooms_id = container_entry_id(ROOMS_CONTAINER_DN)?;
    let name_tag = if unicode {
        tags::DISPLAY_NAME
    } else {
        as_string8(tags::DISPLAY_NAME)
    };
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        out.extend_from_slice(&used_code_page.to_le_bytes());
        write_u32_opt(
            out,
            if templates {
                request.version
            } else {
                request.version.map(|_| HIERARCHY_TABLE_VERSION)
            },
        );
        write_has(out, true);
        if templates {
            out.extend_from_slice(&creation_table);
            return;
        }
        out.extend_from_slice(&2u32.to_le_bytes());
        for (entry_id, flags, container_id, name) in [
            (
                &gal_id,
                AB_RECIPIENTS | AB_UNMODIFIABLE,
                0,
                GAL_DISPLAY_NAME,
            ),
            (
                &rooms_id,
                AB_RECIPIENTS | AB_UNMODIFIABLE | AB_ROOMS,
                ROOMS_CONTAINER,
                ROOMS_DISPLAY_NAME,
            ),
        ] {
            let mut row = AbkListWriter::begin(out);
            row.value(tags::ENTRY_ID, &PropValue::Binary(entry_id));
            row.value(
                CONTAINER_FLAGS,
                &PropValue::I32(i32::from_le_bytes(flags.to_le_bytes())),
            );
            row.value(tags::DEPTH, &PropValue::I32(0));
            row.value(
                CONTAINER_ID,
                &PropValue::I32(i32::from_le_bytes(container_id.to_le_bytes())),
            );
            row.text(name_tag, name, name_code_page);
            row.value(IS_MASTER, &PropValue::Bool(false));
            row.finish();
        }
    });
    Ok(())
}

fn container_entry_id(dn: &str) -> Result<Vec<u8>, NspiStatus> {
    let mut entry_id = Vec::with_capacity(32 + dn.len());
    EntryId::AddressBook(AddressBookEntryId {
        flags: 0,
        display_type: DT_CONTAINER,
        dn: Cow::Borrowed(dn.as_bytes()),
    })
    .encode(&mut entry_id)
    .map_err(|_| NspiStatus::GENERAL_FAILURE)?;
    Ok(entry_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingRow {
    NotFound,
    Approximate,
}

async fn seek(book: &Book<'_>, stat: &Stat, missing: MissingRow) -> Result<Seek, Failure> {
    let by_fraction = Seek::Fraction {
        num_pos: stat.num_pos,
        total_recs: stat.total_recs,
    };
    Ok(match MinimalId(stat.current_rec) {
        MinimalId::CURRENT => by_fraction,
        MinimalId::BEGINNING_OF_TABLE => Seek::At(Anchor::Start),
        MinimalId::END_OF_TABLE => Seek::At(Anchor::End),
        mid => match (book.key_of(mid).await?, missing) {
            (Some(key), _) => Seek::At(Anchor::Row(key)),
            (None, MissingRow::Approximate) => by_fraction,
            (None, MissingRow::NotFound) => return Err(NspiStatus::NOT_FOUND.into()),
        },
    })
}

async fn update_stat(book: &mut Book<'_>, request: &UpdateStat, out: &mut Vec<u8>) -> NspiResult {
    let mut stat = request.state.ok_or(NspiStatus::INVALID_PARAMETER)?;
    book.set_scope(container_scope(&stat)?);
    let seek = seek(book, &stat, MissingRow::NotFound).await?;
    let page = book.page(seek, stat.delta, 1).await?;
    set_position(&mut stat, &page, page.start);
    write_update_stat(out, &stat, &page, request.delta_requested);
    Ok(())
}

fn write_update_stat(out: &mut Vec<u8>, stat: &Stat, page: &Page, delta_requested: bool) {
    let delta =
        i64::try_from(page.start).unwrap_or(i64::MAX) - i64::try_from(page.anchor).unwrap_or(0);
    let delta = i32::try_from(delta).unwrap_or(0);
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        write_state(out, Some(stat));
        write_u32_opt(
            out,
            delta_requested.then(|| u32::from_le_bytes(delta.to_le_bytes())),
        );
    });
}

fn query_columns(unicode: bool, out: &mut Vec<u8>) -> NspiResult {
    let mut columns = Vec::with_capacity(32);
    columns.extend(all_tags().map(|tag| if unicode { tag } else { as_string8(tag) }));
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        write_prop_tags(out, Some(&columns))
    });
    Ok(())
}

async fn get_prop_list(
    book: &mut Book<'_>,
    request: &GetPropList,
    out: &mut Vec<u8>,
) -> NspiResult {
    if request.mid == GAL_MID {
        write_prop_list(out, request.flags, all_tags());
        return Ok(());
    }
    book.set_resource_detail(ResourceDetail::Full);
    let entry = match book.key_of(request.mid).await? {
        Some(key) => book.entry(&key).await?,
        None => None,
    };
    write_prop_list(out, request.flags, entry.iter().flat_map(entry_tags));
    Ok(())
}

fn write_prop_list(out: &mut Vec<u8>, flags: u32, tags: impl Iterator<Item = PropTag>) {
    let mut columns = Vec::with_capacity(32);
    columns.extend(
        tags.filter(|tag| flags & SKIP_OBJECTS == 0 || tag.ptype() != PropType::Object)
            .map(as_string8),
    );
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        write_prop_tags(out, Some(&columns))
    });
}

async fn get_props(book: &mut Book<'_>, request: &GetProps<'_>, out: &mut Vec<u8>) -> NspiResult {
    let stat = request.state.ok_or(NspiStatus::INVALID_PARAMETER)?;
    let columns = request.tags.as_ref().map(capped).transpose()?;
    book.set_resource_detail(resource_detail(columns.as_deref()));
    let entry = match book.key_of(MinimalId(stat.current_rec)).await? {
        Some(key) => book.entry(&key).await?,
        None => None,
    };
    write_props(out, &stat, columns, request.flags, entry.as_ref()).map_err(Failure::from)
}

fn write_props(
    out: &mut Vec<u8>,
    stat: &Stat,
    columns: Option<Vec<PropTag>>,
    flags: u32,
    entry: Option<&AbEntry>,
) -> Result<(), NspiStatus> {
    let code_page = code_page(stat.code_page)?;
    let form = entry_id_form(flags);
    let columns = columns.unwrap_or_else(|| {
        entry
            .into_iter()
            .flat_map(entry_tags)
            .filter(|tag| flags & SKIP_OBJECTS == 0 || tag.ptype() != PropType::Object)
            .map(as_string8)
            .collect()
    });
    let values = |tag: PropTag| entry.and_then(|entry| AbValue::of(entry, tag, form));
    let status = if columns.iter().all(|tag| values(*tag).is_some()) {
        NspiStatus::SUCCESS
    } else {
        NspiStatus::ERRORS_RETURNED
    };
    write_nspi_success(out, status, |out| {
        out.extend_from_slice(&stat.code_page.to_le_bytes());
        write_has(out, true);
        let mut list = AbkListWriter::begin(out);
        for tag in &columns {
            match values(*tag) {
                Some(value) => value.write(&mut list, *tag, code_page),
                None => props::write_missing(&mut list, *tag),
            }
        }
        list.finish();
    });
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowLimit {
    Truncate,
    Complete,
}

fn write_rows<'e>(
    out: &mut Vec<u8>,
    columns: &[PropTag],
    stat: &Stat,
    form: EntryIdForm,
    limit: RowLimit,
    rows: impl Iterator<Item = Option<&'e AbEntry>> + Clone,
) -> Result<usize, NspiStatus> {
    let code_page = code_page(stat.code_page)?;
    let has_rows = rows.clone().next().is_some();
    let columns = columns
        .iter()
        .map(|tag| {
            let valueless = has_rows
                && tag.ptype() != PropType::Unspecified
                && rows.clone().take(MAX_ROWS).all(|entry| {
                    entry
                        .and_then(|entry| AbValue::of(entry, *tag, form))
                        .is_none()
                });
            if valueless {
                tag.with_type(PropType::Error)
            } else {
                *tag
            }
        })
        .collect::<Vec<_>>();
    let budget = out.len().saturating_add(MAX_RESPONSE_BYTES);
    let mut writer = AbkRowWriter::begin(out, &columns, u32::MAX).with_code_page(code_page);
    let mut cells: Vec<AbkCell<'e>> = Vec::with_capacity(columns.len());
    let mut written = 0;
    for entry in rows {
        if written >= MAX_ROWS || (written > 0 && writer.output_len() > budget) {
            match limit {
                RowLimit::Truncate => break,
                RowLimit::Complete => return Err(NspiStatus::TABLE_TOO_BIG),
            }
        }
        cells.clear();
        cells.extend(columns.iter().map(|tag| props::cell(entry, *tag, form)));
        writer.row(&cells);
        written += 1;
    }
    writer.finish();
    Ok(written)
}

fn capped(list: &PropTagList<'_>) -> Result<Vec<PropTag>, NspiStatus> {
    if list.len() > MAX_COLUMNS {
        Err(NspiStatus::TABLE_TOO_BIG)
    } else {
        Ok(list.iter().collect())
    }
}

fn columns_of(list: Option<&PropTagList<'_>>) -> Result<Vec<PropTag>, NspiStatus> {
    list.map_or_else(|| Ok(DEFAULT_COLUMNS.to_vec()), capped)
}

fn patch_state(out: &mut [u8], at: usize, stat: &Stat) {
    let mut encoded = Vec::with_capacity(Stat::LEN);
    stat.encode(&mut encoded);
    if let Some(slot) = out.get_mut(at..at.saturating_add(Stat::LEN)) {
        slot.copy_from_slice(&encoded);
    }
}

fn row_count(requested: u32) -> usize {
    usize::try_from(requested)
        .unwrap_or(usize::MAX)
        .min(MAX_ROWS)
}

async fn query_rows(book: &mut Book<'_>, request: &QueryRows<'_>, out: &mut Vec<u8>) -> NspiResult {
    let columns = columns_of(request.columns.as_ref())?;
    book.set_resource_detail(resource_detail(Some(&columns)));
    let form = entry_id_form(request.flags);
    let count = row_count(request.row_count);
    if !request.explicit_table.is_empty() {
        let keys = book
            .keys_of(request.explicit_table.iter().take(count))
            .await?;
        let entries = book.entries(keys.iter().map(Option::as_ref)).await?;
        let stat = request.state.unwrap_or_default();
        let mut result = Ok(0);
        write_nspi_success(out, NspiStatus::SUCCESS, |out| {
            write_state(out, request.state.as_ref());
            result = write_rows(
                out,
                &columns,
                &stat,
                form,
                RowLimit::Truncate,
                entries.iter().map(Option::as_ref),
            );
        });
        return result.map(|_| ()).map_err(Failure::from);
    }
    let stat = request.state.ok_or(NspiStatus::INVALID_PARAMETER)?;
    book.set_scope(container_scope(&stat)?);
    let seek = seek(book, &stat, MissingRow::Approximate).await?;
    let page = book.page(seek, stat.delta, count.saturating_add(1)).await?;
    let entries = book.entries(page.rows.iter().take(count).map(Some)).await?;
    write_query_rows(out, &columns, stat, form, &page, &entries).map_err(Failure::from)
}

fn write_query_rows(
    out: &mut Vec<u8>,
    columns: &[PropTag],
    mut stat: Stat,
    form: EntryIdForm,
    page: &Page,
    entries: &[Option<AbEntry>],
) -> Result<(), NspiStatus> {
    let mut result = Ok(0);
    let mut state_at = 0;
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        state_at = out.len().saturating_add(1);
        write_state(out, Some(&stat));
        result = write_rows(
            out,
            columns,
            &stat,
            form,
            RowLimit::Truncate,
            entries.iter().map(Option::as_ref),
        );
    });
    set_position(&mut stat, page, page.start.saturating_add(result?));
    patch_state(out, state_at, &stat);
    Ok(())
}

async fn seek_entries(
    book: &mut Book<'_>,
    request: &SeekEntries<'_>,
    out: &mut Vec<u8>,
) -> NspiResult {
    let mut stat = request.state.ok_or(NspiStatus::INVALID_PARAMETER)?;
    book.set_scope(container_scope(&stat)?);
    if stat.sort_type != Stat::SORT_DISPLAY_NAME {
        return Err(NspiStatus::GENERAL_FAILURE.into());
    }
    let Some((tag, value)) = &request.target else {
        return Err(NspiStatus::INVALID_PARAMETER.into());
    };
    let mut target = String::new();
    if tag.id() != tags::DISPLAY_NAME.id()
        || !decode_text(value, code_page(stat.code_page)?, &mut target)
    {
        return Err(NspiStatus::GENERAL_FAILURE.into());
    }
    let anchor = Anchor::Prefix(fold(&target).into_boxed_str());
    let columns = request.columns.as_ref().map(capped).transpose()?;
    book.set_resource_detail(resource_detail(columns.as_deref()));
    let entries = match request
        .explicit_table
        .as_ref()
        .filter(|table| !table.is_empty())
    {
        Some(table) => {
            let keys = book.keys_of(table.iter()).await?;
            let position = keys
                .iter()
                .position(|key| key.as_ref().is_some_and(|key| !anchor.is_below(key)))
                .ok_or(NspiStatus::NOT_FOUND)?;
            let rest = keys.get(position..).unwrap_or_default();
            stat.current_rec = rest
                .first()
                .and_then(Option::as_ref)
                .map_or(0, |key| key.mid().0);
            stat.num_pos = u32::try_from(position).unwrap_or(u32::MAX);
            stat.total_recs = u32::try_from(keys.len()).unwrap_or(u32::MAX);
            match columns {
                Some(_) => {
                    book.entries(rest.iter().take(MAX_ROWS).map(Option::as_ref))
                        .await?
                }
                None => Vec::new(),
            }
        }
        None => {
            let page = book.page(Seek::At(anchor), 0, SEEK_ROWS).await?;
            if page.anchor >= page.total {
                return Err(NspiStatus::NOT_FOUND.into());
            }
            set_position(&mut stat, &page, page.anchor);
            stat.delta = request.state.map_or(0, |state| state.delta);
            match columns {
                Some(_) => book.entries(page.rows.iter().map(Some)).await?,
                None => Vec::new(),
            }
        }
    };
    write_seek_entries(out, &stat, columns.as_deref(), &entries).map_err(Failure::from)
}

fn write_seek_entries(
    out: &mut Vec<u8>,
    stat: &Stat,
    columns: Option<&[PropTag]>,
    entries: &[Option<AbEntry>],
) -> Result<(), NspiStatus> {
    let mut result = Ok(0);
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        write_state(out, Some(stat));
        match columns {
            Some(columns) => {
                result = write_rows(
                    out,
                    columns,
                    stat,
                    EntryIdForm::Ephemeral,
                    RowLimit::Truncate,
                    entries.iter().map(Option::as_ref),
                );
            }
            None => AbkRowWriter::absent(out),
        }
    });
    result.map(|_| ())
}

async fn get_matches(
    book: &mut Book<'_>,
    request: &GetMatches<'_>,
    out: &mut Vec<u8>,
) -> NspiResult {
    let input = request.state.ok_or(NspiStatus::INVALID_PARAMETER)?;
    let limit = usize::try_from(request.row_count)
        .unwrap_or(usize::MAX)
        .min(MAX_MATCHES);
    let columns = request.columns.as_ref().map(capped).transpose()?;
    book.set_resource_detail(resource_detail(columns.as_deref()));
    let matches = match &request.filter {
        Some(filter) => {
            book.set_scope(container_scope(&input)?);
            if request.mids.is_some() {
                return Err(NspiStatus::TOO_COMPLEX.into());
            }
            let restriction = decode_filter(filter)?;
            let matcher = Matcher::new(&restriction, code_page(input.code_page)?)?;
            book.matches(Detail::Addresses, limit, |_, view| matcher.matches(view))
                .await?
        }
        None => {
            let object = book
                .key_of(MinimalId(input.current_rec))
                .await?
                .ok_or(NspiStatus::GENERAL_FAILURE)?;
            let property = PropTag(input.container_id);
            if request.property_name.is_some() {
                return Err(NspiStatus::NOT_SUPPORTED.into());
            } else if property.id().0 == MEMBER_PROP_ID {
                match object.subject() {
                    RowRef::List(_) => {
                        let members = book.members(&object, limit).await?;
                        book::Matches {
                            rows: members.rows,
                            truncated: members.truncated,
                        }
                    }
                    RowRef::Account(_) => book::Matches::default(),
                }
            } else if property.id().0 == PUBLIC_DELEGATES_PROP_ID
                || (property.id() == CONTAINER_CONTENTS.id() && object.kind() == AbKind::List)
            {
                book::Matches::default()
            } else if property.ptype() == PropType::Object {
                return Err(NspiStatus::NOT_SUPPORTED.into());
            } else {
                book::Matches {
                    truncated: limit == 0,
                    rows: vec![object],
                }
            }
        }
    };
    if matches.truncated {
        return Err(NspiStatus::TABLE_TOO_BIG.into());
    }
    let entries = match columns {
        Some(_) => book.entries(matches.rows.iter().map(Some)).await?,
        None => Vec::new(),
    };
    let mids = matches.rows.iter().map(RowKey::mid).collect::<Vec<_>>();
    write_matches(out, &input, &mids, columns.as_deref(), &entries).map_err(Failure::from)
}

fn write_matches(
    out: &mut Vec<u8>,
    stat: &Stat,
    mids: &[MinimalId],
    columns: Option<&[PropTag]>,
    entries: &[Option<AbEntry>],
) -> Result<(), NspiStatus> {
    let mut result = Ok(0);
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        write_state(out, Some(stat));
        write_mids(out, Some(mids));
        match columns {
            Some(columns) => {
                result = write_rows(
                    out,
                    columns,
                    stat,
                    EntryIdForm::Ephemeral,
                    RowLimit::Complete,
                    entries.iter().map(Option::as_ref),
                );
            }
            None => AbkRowWriter::absent(out),
        }
    });
    result.map(|_| ())
}

fn decode_filter<'a>(filter: &RestrictionBytes<'a>) -> Result<Restriction<'a>, NspiStatus> {
    filter
        .decode(
            CountWidth::Wide,
            true,
            NspiLimits::DEFAULT.restriction_depth,
        )
        .map_err(|_| NspiStatus::TOO_COMPLEX)?
        .ok_or(NspiStatus::INVALID_PARAMETER)
}

async fn resort_restriction(
    book: &mut Book<'_>,
    request: &ResortRestriction<'_>,
    out: &mut Vec<u8>,
) -> NspiResult {
    let mut stat = request.state.ok_or(NspiStatus::INVALID_PARAMETER)?;
    let mut keys = book
        .keys_of(request.mids.iter().flat_map(|mids| mids.iter()))
        .await?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup_by_key(|key| key.mid());
    let mids = keys.iter().map(RowKey::mid).collect::<Vec<_>>();
    write_resort(out, &mut stat, &mids);
    Ok(())
}

fn write_resort(out: &mut Vec<u8>, stat: &mut Stat, mids: &[MinimalId]) {
    stat.total_recs = u32::try_from(mids.len()).unwrap_or(u32::MAX);
    if !mids.contains(&MinimalId(stat.current_rec)) {
        stat.current_rec = MinimalId::BEGINNING_OF_TABLE.0;
        stat.num_pos = 0;
    }
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        write_state(out, Some(stat));
        write_mids(out, Some(mids));
    });
}

async fn compare_min_ids(
    book: &Book<'_>,
    request: &CompareMinIds,
    out: &mut Vec<u8>,
) -> NspiResult {
    let stat = request.state.unwrap_or_default();
    container_scope(&stat)?;
    let (Some(first), Some(second)) = (
        book.key_of(request.mid1).await?,
        book.key_of(request.mid2).await?,
    ) else {
        return Err(NspiStatus::GENERAL_FAILURE.into());
    };
    let result: i32 = match first.cmp(&second) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    };
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        out.extend_from_slice(&result.to_le_bytes())
    });
    Ok(())
}

async fn mod_props(book: &Book<'_>, request: &ModProps<'_>) -> NspiResult {
    let current = request.state.map(|stat| MinimalId(stat.current_rec));
    let located = match current {
        Some(mid) if request.tags.is_some() => book.key_of(mid).await?.is_some(),
        _ => false,
    };
    Err(if located {
        NspiStatus::ACCESS_DENIED
    } else {
        NspiStatus::INVALID_PARAMETER
    }
    .into())
}

async fn mod_link_att(
    book: &Book<'_>,
    request: &ModLinkAtt<'_>,
    account_id: u32,
    out: &mut Vec<u8>,
) -> NspiResult {
    match request.tag.id().0 {
        PUBLIC_DELEGATES_PROP_ID
            if request.mid.principal() == Some((MinimalId::KIND_ADDRESS, account_id)) =>
        {
            write_nspi_success(out, NspiStatus::SUCCESS, |_| {});
            Ok(())
        }
        MEMBER_PROP_ID | PUBLIC_DELEGATES_PROP_ID => {
            Err(if book.key_of(request.mid).await?.is_some() {
                NspiStatus::ACCESS_DENIED
            } else {
                NspiStatus::INVALID_PARAMETER
            }
            .into())
        }
        _ => Err(NspiStatus::NOT_FOUND.into()),
    }
}

async fn dn_to_min_id(book: &Book<'_>, request: &DnToMinId<'_>, out: &mut Vec<u8>) -> NspiResult {
    let mut mids = Vec::with_capacity(request.names.map_or(0, |names| names.iter().size_hint().0));
    for dn in request.names.iter().flat_map(|names| names.iter()) {
        let key = match directory_ref_from_dn(dn) {
            Some(principal) => book.principal_key(principal).await?,
            None => None,
        };
        mids.push(key.map_or(MinimalId(0), |key| key.mid()));
    }
    write_nspi_success(out, NspiStatus::SUCCESS, |out| write_mids(out, Some(&mids)));
    Ok(())
}

async fn resolve_names(
    book: &mut Book<'_>,
    request: &ResolveNames<'_>,
    out: &mut Vec<u8>,
) -> NspiResult {
    let stat = request.state.unwrap_or_default();
    book.set_scope(container_scope(&stat)?);
    let columns = columns_of(request.tags.as_ref())?;
    book.set_resource_detail(resource_detail(Some(&columns)));
    let Some(names) = request.names else {
        write_resolved(out, &stat, &columns, None, &[])?;
        return Ok(());
    };
    if usize::try_from(names.len()).unwrap_or(usize::MAX) > MAX_RESOLVE_NAMES {
        return Err(NspiStatus::OUT_OF_RESOURCES.into());
    }
    let mut resolutions = Vec::with_capacity(MAX_RESOLVE_NAMES.min(names.iter().size_hint().0));
    let mut pending = Vec::new();
    let mut name = String::new();
    for value in names.iter() {
        name.clear();
        value.to_string_lossy(&mut name);
        resolutions.push(match NameKind::of(&name) {
            NameKind::Empty => Resolution::Unresolved,
            NameKind::Principal(principal) => book.principal_key(principal).await?.into(),
            NameKind::Smtp(address) => {
                match directory_ref_from_email(book.server(), address).await? {
                    Some(principal) => book.principal_key(principal).await?.into(),
                    None => Resolution::Unresolved,
                }
            }
            NameKind::Text(text) => {
                pending.push((resolutions.len(), PendingName::new(text)));
                Resolution::Unresolved
            }
        });
    }
    if !pending.is_empty() {
        book.matches(Detail::Addresses, 0, |key, view| {
            for (_, name) in pending.iter_mut() {
                name.test(view, key);
            }
            false
        })
        .await?;
        for (index, name) in pending {
            if let Some(slot) = resolutions.get_mut(index) {
                *slot = name.finish();
            }
        }
    }
    let mids = resolutions
        .iter()
        .map(|resolution| match resolution {
            Resolution::Unresolved => MinimalId::UNRESOLVED,
            Resolution::Ambiguous => MinimalId::AMBIGUOUS,
            Resolution::Resolved(_) => MinimalId::RESOLVED,
        })
        .collect::<Vec<_>>();
    let entries = book
        .entries(
            resolutions
                .iter()
                .filter_map(|resolution| match resolution {
                    Resolution::Resolved(key) => Some(Some(key)),
                    _ => None,
                }),
        )
        .await?;
    write_resolved(out, &stat, &columns, Some(&mids), &entries).map_err(Failure::from)
}

fn write_resolved(
    out: &mut Vec<u8>,
    stat: &Stat,
    columns: &[PropTag],
    mids: Option<&[MinimalId]>,
    entries: &[Option<AbEntry>],
) -> Result<(), NspiStatus> {
    let mut result = Ok(0);
    write_nspi_success(out, NspiStatus::SUCCESS, |out| {
        out.extend_from_slice(&stat.code_page.to_le_bytes());
        write_mids(out, mids);
        if mids.is_some() {
            result = write_rows(
                out,
                columns,
                stat,
                EntryIdForm::Permanent,
                RowLimit::Complete,
                entries.iter().map(Option::as_ref),
            );
        } else {
            AbkRowWriter::absent(out);
        }
    });
    result.map(|_| ())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/nspi/tests.rs"]
mod tests;
