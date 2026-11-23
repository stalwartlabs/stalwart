/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod content;
pub mod destination;
pub mod hierarchy;
pub mod import;
pub mod import_fai;
pub mod import_groupware;
pub mod plan;
pub mod source;
pub mod stream;
pub mod upload;

use super::{
    execute::{Packing, RopContext, RopError, RopResult},
    staged::StagedObject,
    state::{FolderObject, Handle, ServerObject, TransferKind, TransferObject},
    table::{decode_restriction, filter::RowFilter},
};
use crate::mapi::ids::MapiId;
use destination::UploadContext;
use exchange_proto::{
    ics::{
        IcsLimits, IcsState, StateUpload, SyncKind,
        flags::{
            SendOptions, SynchronizationExtraFlags, SynchronizationFlags, SynchronizationType,
            TransferStatus,
        },
        fx::{FxEncoder, StringMode},
    },
    mapi::{
        ErrorCode,
        prop::{CodePage, PropId, PropTag},
        rop::{
            DecodedRop,
            requests::{
                FastTransferSourceGetBuffer, SynchronizationConfigure,
                SynchronizationGetTransferState, SynchronizationUploadStateStreamBegin,
                SynchronizationUploadStateStreamContinue,
            },
            responses::{FastTransferSourceGetBufferResponse, TransferBody},
        },
    },
};
use plan::DownloadPlan;
use source::CopySource;
use upload::Imported;

const CONTEXT_BASE_CHARGE: u64 = 4096;
const MAX_RESTRICTION_LEN: usize = 64 * 1024;
const RANGE_CHARGE: u64 = 16;

pub enum TransferContext {
    Sync(Box<SyncContext>),
    Buffer(FxEncoder),
    Upload(Box<UploadContext>),
    Copy(Box<CopySource>),
}

pub struct SyncContext {
    pub config: SyncConfig,
    pub upload: StateUpload,
    pub phase: SyncPhase,
}

pub enum SyncPhase {
    Configured,
    Streaming(Box<Download>),
    Done(Box<IcsState>),
    Collecting(Box<Imported>),
    Failed(ErrorCode),
}

pub struct Download {
    pub plan: DownloadPlan,
    pub cursor: usize,
    pub encoder: FxEncoder,
    pub tail: TailStep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailStep {
    Changes,
    Written,
}

pub struct SyncConfig {
    pub kind: SyncKind,
    pub flags: SynchronizationFlags,
    pub extra: SynchronizationExtraFlags,
    pub mode: StringMode,
    pub tags: TagFilter,
    pub restriction: Box<[u8]>,
}

pub enum TagFilter {
    Exclude(Box<[PropId]>),
    Include(Box<[PropId]>),
}

impl TagFilter {
    fn new(tags: impl Iterator<Item = PropTag>, include: bool) -> Self {
        let mut ids = tags.map(PropTag::id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        let ids = ids.into_boxed_slice();
        if include {
            TagFilter::Include(ids)
        } else {
            TagFilter::Exclude(ids)
        }
    }

    pub fn allows(&self, tag: PropTag) -> bool {
        self.allows_id(tag.id())
    }

    pub fn allows_body(&self, tag: PropTag, native: Option<PropId>) -> bool {
        match self {
            TagFilter::Exclude(_) if native == Some(tag.id()) => true,
            _ => self.allows(tag),
        }
    }

    pub fn allows_id(&self, id: PropId) -> bool {
        match self {
            TagFilter::Exclude(ids) => ids.binary_search(&id).is_err(),
            TagFilter::Include(ids) => ids.binary_search(&id).is_ok(),
        }
    }
}

impl SyncConfig {
    fn new(request: &SynchronizationConfigure<'_>, code_page: CodePage) -> Result<Self, ErrorCode> {
        let flags = request.synchronization_flags;
        let send = request.send_options;
        let kind = match request.synchronization_type {
            Some(SynchronizationType::Contents) => SyncKind::Contents,
            Some(SynchronizationType::Hierarchy) => SyncKind::Hierarchy,
            None => return Err(ErrorCode::INVALID_PARAM),
        };
        if send.has_unknown()
            || (flags.contains(SynchronizationFlags::UNICODE)
                && !send.contains(SendOptions::UNICODE))
            || (kind == SyncKind::Hierarchy && !request.restriction_data.0.is_empty())
            || request.restriction_data.0.len() > MAX_RESTRICTION_LEN
        {
            return Err(ErrorCode::INVALID_PARAM);
        }
        Ok(SyncConfig {
            kind,
            flags,
            extra: request.synchronization_extra_flags,
            mode: string_mode(send, code_page),
            tags: TagFilter::new(
                request.property_tags.iter(),
                flags.contains(SynchronizationFlags::ONLY_SPECIFIED_PROPERTIES),
            ),
            restriction: request.restriction_data.0.into(),
        })
    }

    pub fn wants_normal(&self) -> bool {
        self.kind == SyncKind::Hierarchy || self.flags.contains(SynchronizationFlags::NORMAL)
    }

    pub fn wants_fai(&self) -> bool {
        self.kind == SyncKind::Contents && self.flags.contains(SynchronizationFlags::FAI)
    }

    pub fn reports_deletions(&self) -> bool {
        !self.flags.contains(SynchronizationFlags::NO_DELETIONS)
    }
}

fn string_mode(send: SendOptions, code_page: CodePage) -> StringMode {
    if send.contains(SendOptions::USE_CPID) {
        StringMode::CodePageTagged
    } else if send.contains(SendOptions::UNICODE) || send.contains(SendOptions::FORCE_UNICODE) {
        StringMode::Unicode
    } else {
        StringMode::String8 {
            code_page: code_page.0,
        }
    }
}

pub(super) fn state_charge(state: &IcsState) -> u64 {
    let ranges = state
        .given
        .total_ranges()
        .saturating_add(state.seen.total_ranges())
        .saturating_add(state.seen_fai.total_ranges())
        .saturating_add(state.read.total_ranges());
    CONTEXT_BASE_CHARGE.saturating_add(
        u64::try_from(ranges)
            .unwrap_or(u64::MAX)
            .saturating_mul(RANGE_CHARGE),
    )
}

impl RopContext<'_, '_> {
    pub async fn synchronization_configure(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &SynchronizationConfigure<'_>,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let folder = match self.state.get(parent) {
            Some(ServerObject::Folder(folder)) => *folder,
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let config = SyncConfig::new(request, self.code_page())?;
        if !self.request.access_token.is_account_id(folder.mailbox_id) {
            let node = folder
                .id()
                .and_then(MapiId::to_node)
                .ok_or(ErrorCode::NOT_FOUND)?;
            match config.kind {
                SyncKind::Hierarchy => self.require_visible(folder.mailbox_id, node).await?,
                SyncKind::Contents => self.require_items(folder.mailbox_id, node).await?,
            }
        }
        if let Some(restriction) = decode_restriction(&config.restriction)? {
            RowFilter::new(&restriction, self.code_page())
                .ok_or(RopError::Code(ErrorCode::TOO_COMPLEX))?;
        }
        let kind = match config.kind {
            SyncKind::Contents => TransferKind::Contents,
            SyncKind::Hierarchy => TransferKind::Hierarchy,
        };
        let context = TransferContext::Sync(Box::new(SyncContext {
            config,
            upload: StateUpload::new(&IcsLimits::DEFAULT),
            phase: SyncPhase::Configured,
        }));
        self.open_transfer(
            rop,
            parent,
            request.output_handle_index,
            folder,
            kind,
            context,
        )
    }

    fn open_transfer(
        &mut self,
        rop: &DecodedRop<'_>,
        parent: Handle,
        index: u8,
        folder: FolderObject,
        kind: TransferKind,
        context: TransferContext,
    ) -> RopResult {
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let staged = self.state.allocate_staged();
        let charge = context.charge();
        self.staged()
            .insert(staged, StagedObject::Transfer(Box::new(context)), charge)?;
        let handle = self.state.insert(
            logon_id,
            ServerObject::Transfer(TransferObject {
                folder,
                kind,
                staged,
            }),
        )?;
        self.set_output(index, handle)?;
        self.respond_empty(rop, index)
    }

    fn transfer_object(&self, rop: &DecodedRop<'_>) -> Result<TransferObject, RopError> {
        let handle = self.input(rop.header.input_handle)?;
        match self.state.get(handle) {
            Some(ServerObject::Transfer(transfer)) => Ok(*transfer),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    fn sync_context(&mut self, staged: u32) -> Result<&mut SyncContext, RopError> {
        match self.staged().transfer(staged) {
            Some(TransferContext::Sync(context)) => Ok(context),
            Some(
                TransferContext::Buffer(_) | TransferContext::Upload(_) | TransferContext::Copy(_),
            ) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    fn uploading_context(
        &mut self,
        rop: &DecodedRop<'_>,
    ) -> Result<(u32, &mut SyncContext), RopError> {
        let transfer = self.transfer_object(rop)?;
        let context = self.sync_context(transfer.staged)?;
        if !matches!(
            context.phase,
            SyncPhase::Configured | SyncPhase::Collecting(_)
        ) {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        Ok((transfer.staged, context))
    }

    pub fn upload_state_stream_begin(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &SynchronizationUploadStateStreamBegin,
    ) -> RopResult {
        let (_, context) = self.uploading_context(rop)?;
        context
            .upload
            .begin(request.state_property, request.transfer_buffer_size)
            .map_err(|err| RopError::Code(err.error_code()))?;
        self.respond_empty(rop, rop.header.handle_index)
    }

    pub fn upload_state_stream_continue(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &SynchronizationUploadStateStreamContinue<'_>,
    ) -> RopResult {
        let (staged, context) = self.uploading_context(rop)?;
        context
            .upload
            .append(request.stream_data)
            .map_err(|err| RopError::Code(err.error_code()))?;
        let added = u64::try_from(request.stream_data.len()).unwrap_or(u64::MAX);
        self.staged().charge(staged, added)?;
        self.respond_empty(rop, rop.header.handle_index)
    }

    pub fn upload_state_stream_end(&mut self, rop: &DecodedRop<'_>) -> RopResult {
        let (staged, context) = self.uploading_context(rop)?;
        context
            .upload
            .end()
            .map_err(|err| RopError::Code(err.error_code()))?;
        let charge = state_charge(context.upload.state());
        self.staged().set_charge(staged, charge)?;
        self.respond_empty(rop, rop.header.handle_index)
    }

    pub fn synchronization_get_transfer_state(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &SynchronizationGetTransferState,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let transfer = self.transfer_object(rop)?;
        let context = self.sync_context(transfer.staged)?;
        if context.upload.is_streaming() {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let merged;
        let state = match &context.phase {
            SyncPhase::Done(state) => state.as_ref(),
            SyncPhase::Collecting(imported) => {
                merged = imported.merged(context.upload.state());
                &merged
            }
            SyncPhase::Failed(code) => return Err(RopError::Code(*code)),
            SyncPhase::Configured | SyncPhase::Streaming(_) => context.upload.state(),
        };
        let mut encoder = FxEncoder::new(context.config.mode);
        encoder
            .state(state, context.config.kind)
            .map_err(|err| RopError::Code(err.error_code()))?;
        self.open_transfer(
            rop,
            parent,
            request.output_handle_index,
            transfer.folder,
            TransferKind::StateStream,
            TransferContext::Buffer(encoder),
        )
    }

    pub async fn fast_transfer_source_get_buffer(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &FastTransferSourceGetBuffer,
    ) -> RopResult {
        let transfer = self.transfer_object(rop)?;
        let budget = stream::buffer_budget(self.writer.remaining(), request)?;
        let Some(StagedObject::Transfer(mut context)) = self.staged().remove(transfer.staged)
        else {
            return Err(RopError::Code(ErrorCode::NULL_OBJECT));
        };
        let produced = self.produce(&transfer, &mut context, budget).await;
        let held = context.charge();
        let outcome = match (produced, self.staged().reserve_for(held)) {
            (Ok(fill), Ok(())) => {
                self.respond_transfer(rop, &mut context, fill, budget, BufferMode::of(request))
            }
            (Ok(_), Err(code)) => {
                context.fail(code);
                Err(RopError::Code(code))
            }
            (Err(err), _) => Err(err),
        };
        let charge = context.charge();
        self.staged()
            .insert(transfer.staged, StagedObject::Transfer(context), charge)?;
        outcome
    }

    fn respond_transfer(
        &mut self,
        rop: &DecodedRop<'_>,
        context: &mut TransferContext,
        fill: stream::Fill,
        budget: usize,
        mode: BufferMode,
    ) -> RopResult {
        let encoder = match context {
            TransferContext::Buffer(encoder) => encoder,
            TransferContext::Copy(source) => &mut source.encoder,
            TransferContext::Upload(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            TransferContext::Sync(sync) => match &mut sync.phase {
                SyncPhase::Streaming(download) => &mut download.encoder,
                SyncPhase::Failed(code) => return Err(RopError::Code(*code)),
                SyncPhase::Collecting(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
                SyncPhase::Configured | SyncPhase::Done(_) => {
                    return self.respond_buffer(rop, &[], TransferStatus::Done, fill);
                }
            },
        };
        let pending = encoder.buffered();
        let (bytes, taken) = encoder.take(budget);
        if taken == 0 && pending > 0 {
            if let BufferMode::Adaptive { ceiling } = mode
                && encoder.min_progress() <= ceiling
            {
                return self.respond_buffer(rop, &[], TransferStatus::Partial, fill);
            }
            context.fail(ErrorCode::BUFFER_TOO_SMALL);
            return Err(RopError::Code(ErrorCode::BUFFER_TOO_SMALL));
        }
        let done = fill.finished && pending == taken;
        let status = if done {
            TransferStatus::Done
        } else {
            TransferStatus::Partial
        };
        self.respond_buffer(rop, bytes, status, fill)?;
        encoder.compact();
        if !done && taken > 0 {
            self.packable(Packing::Buffer);
        }
        if done
            && let TransferContext::Sync(sync) = context
            && let SyncPhase::Streaming(download) = &mut sync.phase
        {
            let next = std::mem::take(&mut download.plan.next);
            sync.phase = SyncPhase::Done(Box::new(next));
        }
        Ok(())
    }

    fn respond_buffer(
        &mut self,
        rop: &DecodedRop<'_>,
        bytes: &[u8],
        status: TransferStatus,
        fill: stream::Fill,
    ) -> RopResult {
        self.respond(
            rop,
            rop.header.handle_index,
            &FastTransferSourceGetBufferResponse {
                transfer_status: status,
                in_progress_count: fill.in_progress,
                total_step_count: fill.total,
                body: TransferBody::Buffer(bytes),
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferMode {
    Fixed,
    Adaptive { ceiling: usize },
}

impl BufferMode {
    fn of(request: &FastTransferSourceGetBuffer) -> Self {
        match request.maximum_buffer_size {
            Some(max) => BufferMode::Adaptive {
                ceiling: usize::from(max).min(stream::TRANSFER_BUFFER_MAX),
            },
            None => BufferMode::Fixed,
        }
    }
}

impl TransferContext {
    fn fail(&mut self, code: ErrorCode) {
        match self {
            TransferContext::Sync(sync) => sync.phase = SyncPhase::Failed(code),
            TransferContext::Upload(upload) => upload.fail(code),
            TransferContext::Copy(source) => source.fail(code),
            TransferContext::Buffer(_) => {}
        }
    }

    fn charge(&self) -> u64 {
        match self {
            TransferContext::Buffer(encoder) => {
                CONTEXT_BASE_CHARGE.saturating_add(stream::encoder_charge(encoder))
            }
            TransferContext::Upload(upload) => upload.charge(),
            TransferContext::Copy(source) => source.charge(),
            TransferContext::Sync(context) => match &context.phase {
                SyncPhase::Configured => state_charge(context.upload.state()),
                SyncPhase::Streaming(download) => state_charge(context.upload.state())
                    .saturating_add(download.plan.footprint())
                    .saturating_add(stream::encoder_charge(&download.encoder)),
                SyncPhase::Done(state) => {
                    state_charge(state).saturating_add(state_charge(context.upload.state()))
                }
                SyncPhase::Collecting(imported) => {
                    state_charge(context.upload.state()).saturating_add(imported.charge())
                }
                SyncPhase::Failed(_) => CONTEXT_BASE_CHARGE,
            },
        }
    }
}
