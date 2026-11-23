/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmsmdbRequest,
    access::DelegateRights,
    folder::{FolderActivity, FolderCounters, stored_mailbox},
    ics::destination::PutBufferForm,
    message::load::LoadedContent,
    notify::activates_view,
    staged::StagedSlot,
    state::{EmsmdbState, Handle, MAX_LOGON_MAILBOXES, ServerObject},
    stream_write::WriteForm,
    table::RowCache,
};
use crate::{
    cache::ExchangeCacheFetch,
    ews::delegate::Representing,
    folders::{ExchangeFolders, FolderNode, FolderTree},
    mapi::ids::{IdSpace, MapiId},
    store::{FolderKind, FolderRef, alias::GroupwareKind},
};
use ahash::AHashMap;
use common::{MessageStoreCache, auth::AccountInfo, cache::exchange::ExchangeAccountCache};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use exchange_proto::convert::model::PropBag as ContentBag;
use exchange_proto::ids::Eid;
use exchange_proto::mapi::{
    ErrorCode, MapiLimits, StatusCode,
    emsmdb::{ExecuteFlags, ExecuteRequest, ExecuteResponseMark},
    rop::{
        BUFFER_TOO_SMALL_LEN, DecodedRop, FailureBody, Mark, Overflow, ResponseHeader, RopBuffer,
        RopId, RopRequest, RopResponse, RopWriter,
        header::{HandleRole, Tier},
        requests::{CopyProperties, CopyTo, QueryRows, ReadStream},
        responses::OptionsDataResponse,
    },
    rpc_ext::decode_single_buffer,
};
use smallvec::SmallVec;
use std::sync::Arc;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

pub enum Outcome {
    Done,
    Error(ErrorCode),
    Status(StatusCode),
}

pub enum RopError {
    Code(ErrorCode),
    Overflow,
    Internal(trc::Error),
}

pub type RopResult = Result<(), RopError>;

impl From<ErrorCode> for RopError {
    fn from(code: ErrorCode) -> Self {
        RopError::Code(code)
    }
}

impl From<Overflow> for RopError {
    fn from(_: Overflow) -> Self {
        RopError::Overflow
    }
}

impl From<trc::Error> for RopError {
    fn from(err: trc::Error) -> Self {
        RopError::Internal(err)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packing {
    Rows(u16),
    Bytes(u32),
    Buffer,
}

impl Packing {
    const ROWS_RESIDUAL_MIN: usize = 0x8000;
    const STREAM_RESIDUAL_MIN: usize = 0x2000;

    fn residual_min(self) -> usize {
        match self {
            Packing::Rows(_) => Self::ROWS_RESIDUAL_MIN,
            Packing::Bytes(_) | Packing::Buffer => Self::STREAM_RESIDUAL_MIN,
        }
    }

    fn remaining<'a>(self, request: &RopRequest<'a>) -> Option<RopRequest<'a>> {
        match (self, request) {
            (Packing::Rows(returned), RopRequest::QueryRows(r)) => r
                .row_count
                .checked_sub(returned)
                .filter(|count| *count > 0)
                .map(|row_count| RopRequest::QueryRows(QueryRows { row_count, ..*r })),
            (Packing::Bytes(read), RopRequest::ReadStream(r)) => match r.maximum_byte_count {
                Some(maximum) => {
                    maximum
                        .checked_sub(read)
                        .filter(|count| *count > 0)
                        .map(|maximum| {
                            RopRequest::ReadStream(ReadStream {
                                maximum_byte_count: Some(maximum),
                                ..*r
                            })
                        })
                }
                None => u16::try_from(read)
                    .ok()
                    .and_then(|read| r.byte_count.checked_sub(read))
                    .filter(|count| *count > 0)
                    .map(|byte_count| RopRequest::ReadStream(ReadStream { byte_count, ..*r })),
            },
            (Packing::Buffer, RopRequest::FastTransferSourceGetBuffer(r)) => {
                Some(RopRequest::FastTransferSourceGetBuffer(*r))
            }
            _ => None,
        }
    }
}

const UNASSIGNED: u32 = u32::MAX;
const SIZE_NEEDED_MAX: u16 = 0x8000;
const WRITTEN_SIZE_LEN: u8 = 2;
const WRITTEN_SIZE_EXTENDED_LEN: u8 = 4;
const DATA_SIZE_LEN: u8 = 2;
const COPY_TO_STREAM_COUNTS_LEN: u8 = 16;
const PUT_BUFFER_EXTENDED_FAILURE_LEN: u8 = 13;

pub struct RopContext<'x, 'o> {
    pub request: &'x EmsmdbRequest<'x>,
    pub state: &'x mut EmsmdbState,
    pub writer: RopWriter<'o>,
    pub types: Bitmap<DataType>,
    pub session: u128,
    handles: SmallVec<[u32; 16]>,
    mailboxes: SmallVec<[MailboxView; 2]>,
    pub loaded: Option<LoadedContent>,
    pub envelopes: AHashMap<(u32, u64), ContentBag>,
    pub rows: Option<RowCache>,
    pub staged: StagedSlot<'x>,
    pack: Option<Packing>,
    account_info: Option<AccountInfo>,
    pub(crate) representing: Representing,
    pub completed_searches: SmallVec<[(u32, MapiId); 1]>,
}

#[derive(Clone)]
pub struct MailboxView {
    pub id: u32,
    pub exchange: Arc<ExchangeAccountCache>,
    pub messages: Option<Arc<MessageStoreCache>>,
    tree: Option<Arc<FolderTree>>,
    counters: Option<Arc<FolderCounters>>,
    activity: Option<Arc<FolderActivity>>,
    rights: Option<Arc<DelegateRights>>,
}

impl MailboxView {
    pub fn email_document(&self, container: u32, item: u32) -> u32 {
        self.exchange.email_document(container, item)
    }

    pub fn email_item(&self, container: u32, document_id: u32) -> u32 {
        self.exchange.email_item(container, document_id)
    }

    pub fn client_document(&self, container: u32, item: u32) -> Option<u32> {
        let document_id = self.email_document(container, item);
        (self.email_item(container, document_id) == item).then_some(document_id)
    }

    pub fn stored_id(&self, container: Option<u32>, id: MapiId) -> MapiId {
        match container {
            Some(container) if id.space == IdSpace::Email => {
                MapiId::new(IdSpace::Email, self.email_document(container, id.id))
            }
            _ => id,
        }
    }

    pub fn stored_item(&self, folder: u64, id: MapiId) -> Option<MapiId> {
        if id.space != IdSpace::Email {
            return Some(id);
        }
        let Some(FolderNode::Stored(FolderRef {
            kind,
            id: container,
        })) = MapiId::from_counter(folder).and_then(MapiId::to_node)
        else {
            return Some(id);
        };
        match GroupwareKind::from_folder(kind) {
            Some(groupware) => self
                .exchange
                .groupware_document(groupware.folder(container), id.id)
                .map(|document_id| MapiId::new(IdSpace::of_groupware(groupware), document_id)),
            None if kind == FolderKind::Mailbox => Some(MapiId::new(
                IdSpace::Email,
                self.email_document(container, id.id),
            )),
            None => Some(id),
        }
    }

    pub fn client_item(&self, folder: FolderRef, document_id: u32) -> MapiId {
        match GroupwareKind::from_folder(folder.kind) {
            Some(groupware) => self
                .exchange
                .groupware_item(groupware.folder(folder.id), document_id)
                .map_or(
                    MapiId::new(IdSpace::of_groupware(groupware), document_id),
                    |item| MapiId::new(IdSpace::Email, item),
                ),
            None => MapiId::new(IdSpace::Email, self.email_item(folder.id, document_id)),
        }
    }
}

impl<'o> RopContext<'_, 'o> {
    fn view(&self, id: u32) -> Option<&MailboxView> {
        self.mailboxes.iter().find(|view| view.id == id)
    }

    fn view_mut(&mut self, id: u32) -> Option<&mut MailboxView> {
        self.mailboxes.iter_mut().find(|view| view.id == id)
    }

    pub fn cached_rights(&self, id: u32) -> Option<Arc<DelegateRights>> {
        self.view(id).and_then(|view| view.rights.clone())
    }

    pub fn cache_rights(&mut self, id: u32, rights: Arc<DelegateRights>) {
        if let Some(view) = self.view_mut(id) {
            view.rights = Some(rights);
        }
    }

    pub async fn mailbox(&mut self, id: u32) -> trc::Result<MailboxView> {
        if let Some(view) = self.view(id) {
            return Ok(view.clone());
        }
        let server = self.request.server;
        let exchange = server.get_cached_exchange(id).await?;
        let messages = if self.types.contains(DataType::Email) {
            Some(server.get_cached_messages(id).await?)
        } else {
            None
        };
        let view = MailboxView {
            id,
            exchange,
            messages,
            tree: None,
            counters: None,
            activity: None,
            rights: None,
        };
        if self.mailboxes.len() >= MAX_LOGON_MAILBOXES {
            self.mailboxes.remove(0);
        }
        self.mailboxes.push(view.clone());
        Ok(view)
    }

    pub async fn cached_account_info(&mut self, account_id: u32) -> trc::Result<&AccountInfo> {
        let info = match self.account_info.take() {
            Some(info) if info.account_id == account_id => info,
            _ => self.request.server.account_info(account_id).await?,
        };
        Ok(self.account_info.insert(info))
    }

    pub async fn folder_id(&mut self, mailbox_id: u32, eid: Eid) -> Result<MapiId, RopError> {
        let id = MapiId::from_eid(eid).ok_or(ErrorCode::NOT_FOUND)?;
        if id.space.is_folder() {
            return Ok(id);
        }
        if id.space == IdSpace::Email
            && let Some(node) = id.to_folder(&self.mailbox(mailbox_id).await?.exchange)
        {
            return Ok(MapiId::from_node(node));
        }
        Err(RopError::Code(ErrorCode::NOT_FOUND))
    }

    pub async fn folder_tree(&mut self, id: u32) -> trc::Result<Arc<FolderTree>> {
        if let Some(tree) = self.view(id).and_then(|view| view.tree.clone()) {
            return Ok(tree);
        }
        self.mailbox(id).await?;
        let tree = Arc::new(
            self.request
                .server
                .exchange_folder_tree(id, self.types)
                .await?,
        );
        if let Some(view) = self.view_mut(id) {
            view.tree = Some(tree.clone());
        }
        Ok(tree)
    }

    pub async fn folder_counters(&mut self, id: u32) -> trc::Result<Arc<FolderCounters>> {
        if let Some(counters) = self.view(id).and_then(|view| view.counters.clone()) {
            return Ok(counters);
        }
        let tree = self.folder_tree(id).await?;
        let counters = Arc::new(
            self.mailbox(id)
                .await?
                .messages
                .as_ref()
                .map(|messages| {
                    messages.mailbox_counters(
                        tree.iter().filter_map(|entry| stored_mailbox(entry.node)),
                        false,
                    )
                })
                .unwrap_or_default(),
        );
        if let Some(view) = self.view_mut(id) {
            view.counters = Some(counters.clone());
        }
        Ok(counters)
    }

    pub async fn folder_activity(&mut self, id: u32) -> trc::Result<Arc<FolderActivity>> {
        if let Some(activity) = self.view(id).and_then(|view| view.activity.clone()) {
            return Ok(activity);
        }
        let tree = self.folder_tree(id).await?;
        let mailbox = self.mailbox(id).await?;
        let activity = Arc::new(self.scan_folder_activity(&mailbox, &tree).await?);
        if let Some(view) = self.view_mut(id) {
            view.activity = Some(activity.clone());
        }
        Ok(activity)
    }

    pub fn invalidate_mailbox(&mut self) {
        self.mailboxes.clear();
        self.loaded = None;
        self.envelopes.clear();
        self.rows = None;
    }

    pub fn input(&self, index: u8) -> Result<Handle, RopError> {
        self.handles
            .get(usize::from(index))
            .copied()
            .filter(|handle| *handle != UNASSIGNED)
            .map(Handle)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))
    }

    pub fn set_output(&mut self, index: u8, handle: Handle) -> Result<(), RopError> {
        let slot = self
            .handles
            .get_mut(usize::from(index))
            .ok_or(RopError::Code(ErrorCode::INVALID_PARAM))?;
        *slot = handle.0;
        self.writer.set_handle(index, handle.0);
        Ok(())
    }

    pub fn respond<R: RopResponse>(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        body: &R,
    ) -> RopResult {
        self.writer
            .response(
                ResponseHeader::new(rop.header.id.response_id(), index, ErrorCode::SUCCESS),
                body,
            )
            .map_err(RopError::from)
    }

    pub fn respond_most<R: RopResponse>(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        len: usize,
        body: impl Fn(usize) -> R,
    ) -> Result<usize, RopError> {
        match self.respond(rop, index, &body(len)) {
            Err(RopError::Overflow) => {}
            other => return other.map(|()| len),
        }
        let (mut fits, mut over) = (0, len);
        while over.saturating_sub(fits) > 1 {
            let mid = fits + (over - fits) / 2;
            let mark = self.writer.mark();
            match self.respond(rop, index, &body(mid)) {
                Ok(()) => {
                    self.writer.rollback(mark);
                    fits = mid;
                }
                Err(RopError::Overflow) => over = mid,
                Err(err) => return Err(err),
            }
        }
        self.respond(rop, index, &body(fits))?;
        Ok(fits)
    }

    pub fn respond_empty(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        self.writer
            .failure(
                ResponseHeader::new(rop.header.id.response_id(), index, ErrorCode::SUCCESS),
                &FailureBody::HeaderOnly,
            )
            .map_err(RopError::from)
    }
}

fn response_index(rop: &DecodedRop<'_>) -> u8 {
    match &rop.request {
        RopRequest::Logon(r) => r.output_handle_index,
        RopRequest::OpenFolder(r) => r.output_handle_index,
        RopRequest::CreateFolder(r) => r.output_handle_index,
        RopRequest::OpenMessage(r) => r.output_handle_index,
        RopRequest::CreateMessage(r) => r.output_handle_index,
        RopRequest::GetHierarchyTable(r) => r.output_handle_index,
        RopRequest::GetContentsTable(r) => r.output_handle_index,
        RopRequest::GetAttachmentTable(r) => r.output_handle_index,
        RopRequest::OpenAttachment(r) => r.output_handle_index,
        RopRequest::CreateAttachment(r) => r.output_handle_index,
        RopRequest::OpenEmbeddedMessage(r) => r.output_handle_index,
        RopRequest::OpenStream(r) => r.output_handle_index,
        RopRequest::GetPermissionsTable(r) => r.output_handle_index,
        RopRequest::GetRulesTable(r) => r.output_handle_index,
        RopRequest::FastTransferDestinationConfigure(r) => r.output_handle_index,
        RopRequest::FastTransferSourceCopyMessages(r) => r.output_handle_index,
        RopRequest::FastTransferSourceCopyFolder(r) => r.output_handle_index,
        RopRequest::FastTransferSourceCopyTo(r) => r.output_handle_index,
        RopRequest::FastTransferSourceCopyProperties(r) => r.output_handle_index,
        RopRequest::SynchronizationConfigure(r) => r.output_handle_index,
        RopRequest::SynchronizationImportMessageChange(r) => r.output_handle_index,
        RopRequest::SynchronizationOpenCollector(r) => r.output_handle_index,
        RopRequest::SynchronizationGetTransferState(r) => r.output_handle_index,
        RopRequest::RegisterNotification(r) => r.output_handle_index,
        RopRequest::Stub(id, body) if id.handles() == Some(HandleRole::Output) => {
            body.first().copied().unwrap_or(rop.header.handle_index)
        }
        _ => rop.header.handle_index,
    }
}

pub async fn run(
    request: &EmsmdbRequest<'_>,
    session: u128,
    state: &mut EmsmdbState,
    execute: &ExecuteRequest<'_>,
    out: &mut Vec<u8>,
    response: &mut ExecuteResponseMark,
) -> trc::Result<Outcome> {
    let limits = MapiLimits::DEFAULT;
    let mut scratch = Vec::new();
    let payload = if execute.rop_buffer.is_empty() {
        execute.rop_buffer
    } else {
        match decode_single_buffer(execute.rop_buffer, &mut scratch, limits.decompressed_max) {
            Ok(payload) => payload,
            Err(err) => {
                return Ok(if err.status_code() != StatusCode::OK {
                    Outcome::Status(err.status_code())
                } else {
                    Outcome::Error(err.error_code())
                });
            }
        }
    };
    let buffer = match RopBuffer::parse(payload, &limits) {
        Ok(buffer) => buffer,
        Err(err) => return Ok(Outcome::Error(err.error_code())),
    };
    let mut types = Bitmap::<DataType>::all();
    request.access_token.restrict_data_types(&mut types);
    let at_max = execute.max_rop_out >= limits.output_budget_max;
    let account_id = state.account_id;
    let mut ctx = RopContext {
        request,
        state,
        writer: RopWriter::new(out, execute.max_rop_out, &buffer.handles),
        types,
        session,
        handles: buffer.handles.iter().collect(),
        mailboxes: SmallVec::new(),
        loaded: None,
        envelopes: AHashMap::new(),
        rows: None,
        staged: StagedSlot::new(request.server, account_id, session),
        pack: None,
        account_info: None,
        representing: Representing::default(),
        completed_searches: SmallVec::new(),
    };
    let mut logons = ctx.state.logon_kinds();
    let mut rops = buffer.rops();
    let mut answered = false;
    let mut packable = None;
    let empty = ctx.writer.remaining();
    while let Some(decoded) = rops.next_rop(&logons) {
        let rop = match decoded {
            Ok(rop) => rop,
            Err(err) => return Ok(Outcome::Error(err.error_code())),
        };
        let guarded =
            ctx.writer.remaining() >= BUFFER_TOO_SMALL_LEN.saturating_add(rop.raw_from_here.len());
        if guarded {
            ctx.writer
                .reserve_tail(BUFFER_TOO_SMALL_LEN.saturating_add(rops.remaining_len()));
        }
        let index = response_index(&rop);
        let previous = ctx.handle_at(index);
        let mark = ctx.writer.mark();
        ctx.pack = None;
        let result = dispatch(&mut ctx, &rop, index).await;
        let code = match result {
            Ok(()) => {
                if activates_view(&rop.request) {
                    ctx.activate_table(&rop);
                }
                None
            }
            Err(RopError::Code(code)) => Some(code),
            Err(RopError::Internal(err)) => {
                trc::error!(err.details("MAPI ROP failed"));
                Some(ErrorCode::ERROR)
            }
            Err(RopError::Overflow) => {
                ctx.undo(mark, index, previous);
                ctx.writer.reserve_tail(0);
                return Ok(ctx.buffer_too_small(rop.raw_from_here, answered, at_max));
            }
        };
        if let Some(code) = code {
            ctx.undo(mark, index, previous);
            let header = ResponseHeader::new(rop.header.id.response_id(), index, code);
            if ctx
                .writer
                .failure(header, &failure_body(&rop.request, code))
                .is_err()
            {
                return Ok(ctx.buffer_too_small(rop.raw_from_here, answered, at_max));
            }
        }
        ctx.writer.reserve_tail(0);
        answered = true;
        if matches!(rop.request, RopRequest::Logon(_) | RopRequest::Release) {
            logons = ctx.state.logon_kinds();
        }
        packable = ctx
            .pack
            .take()
            .filter(|_| code.is_none())
            .map(|packing| (rop, index, packing));
    }
    if let Err(err) = ctx.emit_notifications(empty).await {
        trc::error!(err.details("MAPI notifications failed"));
    }
    if execute.flags.contains(ExecuteFlags::CHAIN)
        && let Some((rop, index, packing)) = packable
    {
        ctx.pack_payloads(response, execute.max_rop_out, rop, index, packing)
            .await;
    }
    ctx.writer.finish();
    Ok(Outcome::Done)
}

impl RopContext<'_, '_> {
    pub(super) fn packable(&mut self, packing: Packing) {
        self.pack = Some(packing);
    }

    async fn pack_payloads(
        &mut self,
        response: &mut ExecuteResponseMark,
        max_rop_out: u32,
        mut rop: DecodedRop<'_>,
        index: u8,
        mut packing: Packing,
    ) {
        while let Some(request) = packing.remaining(&rop.request)
            && let Some(saved) =
                self.writer
                    .next_payload(response, max_rop_out, packing.residual_min())
        {
            rop.request = request;
            self.pack = None;
            match dispatch(self, &rop, index).await {
                Ok(()) => match self.pack.take() {
                    Some(next) => packing = next,
                    None => return,
                },
                Err(err) => {
                    if let RopError::Internal(err) = err {
                        trc::error!(err.details("MAPI ROP failed"));
                    }
                    self.writer.drop_payload(response, saved);
                    return;
                }
            }
        }
    }

    fn is_item(&self, rop: &DecodedRop<'_>) -> Result<bool, RopError> {
        Ok(matches!(
            self.state.get(self.input(rop.header.input_handle)?),
            Some(ServerObject::Message(_) | ServerObject::Attachment(_))
        ))
    }

    fn is_store(&self, rop: &DecodedRop<'_>) -> Result<bool, RopError> {
        Ok(matches!(
            self.state.get(self.input(rop.header.input_handle)?),
            Some(ServerObject::Logon(_))
        ))
    }

    fn handle_at(&self, index: u8) -> u32 {
        self.handles
            .get(usize::from(index))
            .copied()
            .unwrap_or(UNASSIGNED)
    }

    fn undo(&mut self, mark: Mark, index: u8, previous: u32) {
        self.writer.rollback(mark);
        let current = self.handle_at(index);
        if current != previous {
            if current != UNASSIGNED {
                self.state.release(Handle(current));
            }
            if let Some(slot) = self.handles.get_mut(usize::from(index)) {
                *slot = previous;
            }
            self.writer.reset_handle(index, previous);
        }
    }

    fn buffer_too_small(self, unprocessed: &[u8], answered: bool, at_max: bool) -> Outcome {
        let mut writer = self.writer;
        if (!answered && at_max)
            || writer
                .buffer_too_small(SIZE_NEEDED_MAX, unprocessed)
                .is_err()
        {
            return Outcome::Status(StatusCode::BUFFER_TOO_SMALL);
        }
        writer.finish();
        Outcome::Done
    }
}

fn failure_body(request: &RopRequest<'_>, code: ErrorCode) -> FailureBody {
    let dest_handle = match request {
        RopRequest::MoveFolder(r) => Some(r.dest_handle_index),
        RopRequest::CopyFolder(r) => Some(r.dest_handle_index),
        RopRequest::MoveCopyMessages(r) => Some(r.dest_handle_index),
        RopRequest::DeleteFolder(_)
        | RopRequest::DeleteMessages(_)
        | RopRequest::EmptyFolder(_)
        | RopRequest::HardDeleteMessages(_)
        | RopRequest::HardDeleteMessagesAndSubfolders(_)
        | RopRequest::SetReadFlags(_) => None,
        RopRequest::FastTransferSourceGetBuffer(_)
        | RopRequest::FastTransferDestinationPutBuffer(_) => return FailureBody::Transfer,
        RopRequest::FastTransferDestinationPutBufferExtended(_) => {
            return FailureBody::Zeroed(PUT_BUFFER_EXTENDED_FAILURE_LEN);
        }
        RopRequest::WriteStream(_) => return FailureBody::Zeroed(WRITTEN_SIZE_LEN),
        RopRequest::ReadStream(_) => return FailureBody::Zeroed(DATA_SIZE_LEN),
        RopRequest::CopyProperties(CopyProperties {
            dest_handle_index, ..
        })
        | RopRequest::CopyTo(CopyTo {
            dest_handle_index, ..
        }) if code == ErrorCode::DST_NULL_OBJECT => {
            return FailureBody::NullDestination(u32::from(*dest_handle_index));
        }
        RopRequest::CopyToStream(request) => {
            return if code == ErrorCode::DST_NULL_OBJECT {
                FailureBody::NullDestinationStream(u32::from(request.dest_handle_index))
            } else {
                FailureBody::Zeroed(COPY_TO_STREAM_COUNTS_LEN)
            };
        }
        RopRequest::WriteStreamExtended(_) => {
            return FailureBody::Zeroed(WRITTEN_SIZE_EXTENDED_LEN);
        }
        RopRequest::Stub(id, _) if *id == RopId::WRITE_AND_COMMIT_STREAM => {
            return FailureBody::Zeroed(WRITTEN_SIZE_LEN);
        }
        _ => return FailureBody::HeaderOnly,
    };
    match dest_handle {
        Some(dest_handle) if code == ErrorCode::DST_NULL_OBJECT => {
            FailureBody::NullDestinationPartial {
                dest_handle: u32::from(dest_handle),
                partial_completion: false,
            }
        }
        _ => FailureBody::PartialCompletion(false),
    }
}

async fn dispatch(ctx: &mut RopContext<'_, '_>, rop: &DecodedRop<'_>, index: u8) -> RopResult {
    ctx.may_write(&rop.request, rop.header.input_handle)?;
    match &rop.request {
        RopRequest::Release => {
            if let Ok(handle) = ctx.input(rop.header.input_handle) {
                if matches!(ctx.state.get(handle), Some(ServerObject::Logon(_))) {
                    ctx.forget_content();
                } else {
                    ctx.release_stream(handle).await;
                    ctx.release_attachment(handle);
                    ctx.release_embedded(handle);
                }
                let staged = ctx.holds_staged_object(handle);
                ctx.state.release(handle);
                if staged {
                    ctx.prune_staged();
                }
            }
            Ok(())
        }
        RopRequest::Logon(request) => ctx.logon(rop, request).await,
        RopRequest::RegisterNotification(request) => ctx.register_notification(rop, request).await,
        RopRequest::SetReceiveFolder(request) => ctx.set_receive_folder(rop, index, request).await,
        RopRequest::GetReceiveFolder(request) => ctx.get_receive_folder(rop, index, request).await,
        RopRequest::GetTransportFolder => ctx.get_transport_folder(rop, index),
        RopRequest::PublicFolderIsGhosted(_) => ctx.public_folder_is_ghosted(rop, index),
        RopRequest::LongTermIdFromId(request) => {
            ctx.long_term_id_from_id(rop, index, request).await
        }
        RopRequest::IdFromLongTermId(request) => {
            ctx.id_from_long_term_id(rop, index, request).await
        }
        RopRequest::OpenFolder(request) => ctx.open_folder(rop, request).await,
        RopRequest::CreateFolder(request) => ctx.create_folder(rop, request).await,
        RopRequest::DeleteFolder(request) => ctx.delete_folder(rop, index, request).await,
        RopRequest::MoveFolder(request) => ctx.move_folder(rop, index, request).await,
        RopRequest::CopyFolder(request) => ctx.copy_folder(rop, index, request).await,
        RopRequest::SetProperties(request) if ctx.is_item(rop)? => {
            ctx.set_item_properties(rop, index, request).await
        }
        RopRequest::SetProperties(request) if ctx.is_store(rop)? => {
            ctx.set_store_properties(rop, index, request).await
        }
        RopRequest::SetProperties(request) => ctx.set_properties(rop, index, request).await,
        RopRequest::DeleteProperties(request) if ctx.is_item(rop)? => {
            ctx.delete_item_properties(rop, index, request).await
        }
        RopRequest::DeleteProperties(request) if ctx.is_store(rop)? => {
            ctx.delete_store_properties(rop, index, request)
        }
        RopRequest::DeleteProperties(request) => ctx.delete_properties(rop, index, request).await,
        RopRequest::CreateMessage(request) => ctx.create_message(rop, request).await,
        RopRequest::SaveChangesMessage(request) => {
            ctx.save_changes_message(rop, index, request).await
        }
        RopRequest::DeleteMessages(request) => {
            ctx.delete_messages(rop, index, &request.message_ids).await
        }
        RopRequest::HardDeleteMessages(request) => {
            ctx.hard_delete_messages(rop, index, &request.message_ids)
                .await
        }
        RopRequest::MoveCopyMessages(request) => ctx.move_copy_messages(rop, index, request).await,
        RopRequest::SubmitMessage(request) => ctx.submit_message(rop, index, request).await,
        RopRequest::EmptyFolder(request) => {
            ctx.empty_folder(rop, index, request.want_delete_associated)
                .await
        }
        RopRequest::HardDeleteMessagesAndSubfolders(request) => {
            ctx.hard_delete_messages_and_subfolders(rop, index, request.want_delete_associated)
                .await
        }
        RopRequest::ModifyRecipients(request) => ctx.modify_recipients(rop, index, request).await,
        RopRequest::RemoveAllRecipients(_) => ctx.remove_all_recipients(rop, index).await,
        RopRequest::CreateAttachment(request) => ctx.create_attachment(rop, request).await,
        RopRequest::SaveChangesAttachment(request) => {
            ctx.save_changes_attachment(rop, index, request)
        }
        RopRequest::DeleteAttachment(request) => ctx.delete_attachment(rop, index, request).await,
        RopRequest::WriteStream(request) => {
            ctx.write_stream(rop, index, request, WriteForm::Standard)
        }
        RopRequest::WriteStreamExtended(request) => {
            ctx.write_stream(rop, index, request, WriteForm::Extended)
        }
        RopRequest::SetStreamSize(request) => ctx.set_stream_size(rop, index, request),
        RopRequest::CommitStream => ctx.commit_stream(rop, index).await,
        RopRequest::GetHierarchyTable(request) => ctx.get_hierarchy_table(rop, request).await,
        RopRequest::GetContentsTable(request) => ctx.get_contents_table(rop, request).await,
        RopRequest::GetAttachmentTable(request) => ctx.get_attachment_table(rop, request),
        RopRequest::SetReadFlags(request) => ctx.set_read_flags(rop, index, request).await,
        RopRequest::SetMessageReadFlag(request) => {
            ctx.set_message_read_flag(rop, index, request).await
        }
        RopRequest::OpenStream(request) => ctx.open_stream(rop, request).await,
        RopRequest::ReadStream(request) => ctx.read_stream(rop, index, request).await,
        RopRequest::SeekStream(request) => ctx.seek_stream(rop, index, request),
        RopRequest::GetStreamSize => ctx.get_stream_size(rop, index),
        RopRequest::OpenMessage(request) => ctx.open_message(rop, request).await,
        RopRequest::OpenAttachment(request) => ctx.open_attachment(rop, request).await,
        RopRequest::OpenEmbeddedMessage(request) => ctx.open_embedded_message(rop, request).await,
        RopRequest::GetMessageStatus(request) => ctx.get_message_status(rop, index, request).await,
        RopRequest::SetMessageStatus(request) => ctx.set_message_status(rop, index, request).await,
        RopRequest::ReloadCachedInformation => ctx.reload_cached_information(rop, index).await,
        RopRequest::GetAddressTypes => ctx.get_address_types(rop, index),
        RopRequest::CopyProperties(request) => ctx.copy_properties(rop, index, request).await,
        RopRequest::CopyTo(request) => ctx.copy_to(rop, index, request).await,
        RopRequest::CopyToStream(request) => ctx.copy_to_stream(rop, index, request).await,
        RopRequest::QueryNamedProperties(request) => {
            ctx.query_named_properties(rop, index, request).await
        }
        RopRequest::ReadRecipients(request) => ctx.read_recipients(rop, index, request).await,
        RopRequest::SetColumns(request) => ctx.set_columns(rop, index, request),
        RopRequest::SortTable(request) => ctx.sort_table(rop, index, request),
        RopRequest::Restrict(request) => ctx.restrict(rop, index, request),
        RopRequest::QueryRows(request) => ctx.query_rows(rop, index, request).await,
        RopRequest::QueryPosition => ctx.query_position(rop, index).await,
        RopRequest::SeekRow(request) => ctx.seek_row(rop, index, request).await,
        RopRequest::SeekRowBookmark(request) => ctx.seek_row_bookmark(rop, index, request).await,
        RopRequest::SeekRowFractional(request) => {
            ctx.seek_row_fractional(rop, index, request).await
        }
        RopRequest::CreateBookmark => ctx.create_bookmark(rop, index).await,
        RopRequest::FreeBookmark(request) => ctx.free_bookmark(rop, index, request),
        RopRequest::FindRow(request) => ctx.find_row(rop, index, request).await,
        RopRequest::ExpandRow(request) => ctx.expand_row(rop, index, request).await,
        RopRequest::CollapseRow(request) => ctx.collapse_row(rop, index, request).await,
        RopRequest::GetPropertyIdsFromNames(request) => {
            ctx.get_property_ids_from_names(rop, index, request).await
        }
        RopRequest::GetNamesFromPropertyIds(request) => {
            ctx.get_names_from_property_ids(rop, index, request).await
        }
        RopRequest::GetReceiveFolderTable => ctx.get_receive_folder_table(rop, index).await,
        RopRequest::GetPropertiesSpecific(request) => {
            ctx.get_properties_specific(rop, index, request).await
        }
        RopRequest::GetPropertiesAll(request) => ctx.get_properties_all(rop, index, request).await,
        RopRequest::GetPropertiesList => ctx.get_properties_list(rop, index).await,
        RopRequest::SynchronizationConfigure(request) => {
            ctx.synchronization_configure(rop, request).await
        }
        RopRequest::SynchronizationUploadStateStreamBegin(request) => {
            ctx.upload_state_stream_begin(rop, request)
        }
        RopRequest::SynchronizationUploadStateStreamContinue(request) => {
            ctx.upload_state_stream_continue(rop, request)
        }
        RopRequest::SynchronizationUploadStateStreamEnd => ctx.upload_state_stream_end(rop),
        RopRequest::SynchronizationImportMessageChange(request) => {
            ctx.synchronization_import_message_change(rop, request)
                .await
        }
        RopRequest::SynchronizationImportHierarchyChange(request) => {
            ctx.synchronization_import_hierarchy_change(rop, index, request)
                .await
        }
        RopRequest::SynchronizationImportMessageMove(request) => {
            ctx.synchronization_import_message_move(rop, index, request)
                .await
        }
        RopRequest::SynchronizationOpenCollector(request) => {
            ctx.synchronization_open_collector(rop, request)
        }
        RopRequest::GetLocalReplicaIds(request) => {
            ctx.get_local_replica_ids(rop, index, request).await
        }
        RopRequest::SynchronizationImportReadStateChanges(request) => {
            ctx.synchronization_import_read_state_changes(rop, index, request)
                .await
        }
        RopRequest::SynchronizationImportDeletes(request) => {
            ctx.synchronization_import_deletes(rop, index, request)
                .await
        }
        RopRequest::SynchronizationGetTransferState(request) => {
            ctx.synchronization_get_transfer_state(rop, request)
        }
        RopRequest::FastTransferSourceGetBuffer(request) => {
            ctx.fast_transfer_source_get_buffer(rop, request).await
        }
        RopRequest::FastTransferSourceCopyMessages(request) => {
            ctx.fast_transfer_source_copy_messages(rop, request).await
        }
        RopRequest::FastTransferSourceCopyFolder(request) => {
            ctx.fast_transfer_source_copy_folder(rop, request).await
        }
        RopRequest::FastTransferSourceCopyTo(request) => {
            ctx.fast_transfer_source_copy_to(rop, request).await
        }
        RopRequest::FastTransferSourceCopyProperties(request) => {
            ctx.fast_transfer_source_copy_properties(rop, request).await
        }
        RopRequest::TellVersion(_) => ctx.tell_version(rop, index),
        RopRequest::FastTransferDestinationConfigure(request) => {
            ctx.fast_transfer_destination_configure(rop, request).await
        }
        RopRequest::FastTransferDestinationPutBuffer(request) => {
            ctx.fast_transfer_destination_put_buffer(rop, request, PutBufferForm::Standard)
                .await
        }
        RopRequest::FastTransferDestinationPutBufferExtended(request) => {
            ctx.fast_transfer_destination_put_buffer(rop, request, PutBufferForm::Extended)
                .await
        }
        RopRequest::GetPermissionsTable(request) => ctx.get_permissions_table(rop, request),
        RopRequest::ModifyPermissions(request) => ctx.modify_permissions(rop, index, request).await,
        RopRequest::GetRulesTable(request) => ctx.get_rules_table(rop, request),
        RopRequest::ModifyRules(request) => ctx.modify_rules(rop, index, request).await,
        RopRequest::SetSearchCriteria(request) => {
            ctx.set_search_criteria(rop, index, request).await
        }
        RopRequest::GetSearchCriteria(request) => {
            ctx.get_search_criteria(rop, index, request).await
        }
        RopRequest::GetCollapseState(request) => ctx.get_collapse_state(rop, index, request),
        RopRequest::SetCollapseState(request) => ctx.set_collapse_state(rop, index, request).await,
        RopRequest::Stub(id, _) => match *id {
            RopId::GET_PER_USER_LONG_TERM_IDS => ctx.get_per_user_long_term_ids(rop, index),
            RopId::QUERY_COLUMNS_ALL => ctx.query_columns_all(rop, index),
            RopId::RESET_TABLE => ctx.reset_table(rop, index),
            RopId::SET_LOCAL_REPLICA_MIDSET_DELETED => ctx.respond_empty(rop, index),
            RopId::TRANSPORT_SEND => ctx.transport_send(rop, index).await,
            RopId::SET_SPOOLER => {
                ctx.input(rop.header.input_handle)?;
                ctx.respond_empty(rop, index)
            }
            RopId::OPTIONS_DATA => {
                ctx.input(rop.header.input_handle)?;
                ctx.respond(rop, index, &OptionsDataResponse)
            }
            id if id.tier() == Some(Tier::D) => {
                if id.handles() == Some(HandleRole::Input) {
                    ctx.input(rop.header.input_handle)?;
                }
                Err(RopError::Code(ErrorCode::NOT_IMPLEMENTED))
            }
            _ => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
        },
    }
}
