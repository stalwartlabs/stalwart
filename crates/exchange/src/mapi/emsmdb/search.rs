/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::{RopContext, RopError, RopResult},
    folder_write::OpenFolder,
    table::validate_restriction,
};
use crate::{
    folders::{FolderNode, FolderWriteError, FolderWrites},
    mapi::ids::MapiId,
    store::folder::SearchDefinition,
};
use exchange_proto::{
    ids::Eid,
    mapi::{
        ErrorCode,
        rop::{
            DecodedRop,
            requests::{GetSearchCriteria, SetSearchCriteria},
            responses::{EmptyResponse, GetSearchCriteriaResponse},
        },
    },
};
use types::type_state::DataType;

const STOP_SEARCH: u32 = 0x0000_0001;
const RESTART_SEARCH: u32 = 0x0000_0002;
const RECURSIVE_SEARCH: u32 = 0x0000_0004;
const SHALLOW_SEARCH: u32 = 0x0000_0008;
const FOREGROUND_SEARCH: u32 = 0x0000_0010;
const BACKGROUND_SEARCH: u32 = 0x0000_0020;
const CONTENT_INDEXED_SEARCH: u32 = 0x0001_0000;
const NON_CONTENT_INDEXED_SEARCH: u32 = 0x0002_0000;
const STATIC_SEARCH: u32 = 0x0004_0000;
const VALID_SEARCH_FLAGS: u32 = STOP_SEARCH
    | RESTART_SEARCH
    | RECURSIVE_SEARCH
    | SHALLOW_SEARCH
    | FOREGROUND_SEARCH
    | BACKGROUND_SEARCH
    | CONTENT_INDEXED_SEARCH
    | NON_CONTENT_INDEXED_SEARCH
    | STATIC_SEARCH;
const EXCLUSIVE_SEARCH_FLAGS: [u32; 4] = [
    STOP_SEARCH | RESTART_SEARCH,
    RECURSIVE_SEARCH | SHALLOW_SEARCH,
    FOREGROUND_SEARCH | BACKGROUND_SEARCH,
    CONTENT_INDEXED_SEARCH | NON_CONTENT_INDEXED_SEARCH,
];

const SEARCH_RECURSIVE: u32 = 0x0000_0004;
const SEARCH_COMPLETE: u32 = 0x0000_1000;
const SEARCH_STATIC: u32 = 0x0001_0000;
const TWIR_TOTALLY: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SearchFlags(pub(super) u32);

impl SearchFlags {
    pub(super) fn recursive(self) -> bool {
        let SearchFlags(stored) = self;
        stored & RECURSIVE_SEARCH != 0
    }

    pub(super) fn completes(self) -> bool {
        let SearchFlags(stored) = self;
        stored != 0 && stored & STOP_SEARCH == 0
    }

    fn parse(flags: u32) -> Result<Self, ErrorCode> {
        if flags & !VALID_SEARCH_FLAGS != 0 {
            return Err(ErrorCode::NOT_SUPPORTED);
        }
        if EXCLUSIVE_SEARCH_FLAGS
            .iter()
            .any(|pair| flags & pair == *pair)
        {
            return Err(ErrorCode::INVALID_PARAM);
        }
        let mut flags = flags & !(FOREGROUND_SEARCH | BACKGROUND_SEARCH);
        if flags & (STOP_SEARCH | RESTART_SEARCH) == 0 {
            flags |= RESTART_SEARCH;
        }
        if flags & (RECURSIVE_SEARCH | SHALLOW_SEARCH) == 0 {
            flags |= SHALLOW_SEARCH;
        }
        Ok(SearchFlags(flags))
    }

    fn status(self) -> u32 {
        let SearchFlags(stored) = self;
        if stored == 0 {
            return 0;
        }
        let mut status = SEARCH_COMPLETE | TWIR_TOTALLY;
        if stored & RECURSIVE_SEARCH != 0 {
            status |= SEARCH_RECURSIVE;
        }
        if stored & STATIC_SEARCH != 0 {
            status |= SEARCH_STATIC;
        }
        status
    }
}

impl RopContext<'_, '_> {
    async fn current_search(&self, folder: OpenFolder) -> Result<SearchDefinition, RopError> {
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let request = self.request;
        match request
            .server
            .folder_search(request.access_token, folder.mailbox_id, folder.node)
            .await?
        {
            Ok(search) => Ok(search),
            Err(
                FolderWriteError::Unsupported
                | FolderWriteError::Protected
                | FolderWriteError::InvalidSearch,
            ) => Err(RopError::Code(ErrorCode::NOT_SEARCH_FOLDER)),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn set_search_criteria(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetSearchCriteria<'_>,
    ) -> RopResult {
        let folder = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let flags = SearchFlags::parse(request.search_flags)?;
        let restriction = request.restriction_data.0;
        validate_restriction(restriction, self.code_page())?;
        let mut search = self.current_search(folder).await?;
        if !restriction.is_empty() {
            search.restriction.clear();
            search.restriction.extend_from_slice(restriction);
        }
        if !request.folder_ids.is_empty() {
            search.scope.clear();
            search.scope.reserve(request.folder_ids.len());
            for eid in request.folder_ids.iter() {
                let node = self
                    .folder_id(folder.mailbox_id, eid)
                    .await?
                    .to_node()
                    .ok_or(ErrorCode::NOT_FOUND)?;
                if node == folder.node {
                    return Err(RopError::Code(ErrorCode::SEARCH_FOLDER_SCOPE_VIOLATION));
                }
                search.scope.push(node.to_stored());
            }
        } else {
            let tree = self.folder_tree(folder.mailbox_id).await?;
            search.scope.retain(|stored| {
                FolderNode::from_stored(stored.kind, stored.id)
                    .is_some_and(|node| tree.get(node).is_some())
            });
            if search.scope.is_empty() {
                return Err(RopError::Code(ErrorCode::NOT_INITIALIZED));
            }
        }
        search.flags = flags.0;
        let ctx = self.request;
        ctx.server
            .folder_set_search(ctx.access_token, folder.mailbox_id, folder.node, &search)
            .await??;
        if flags.completes() {
            self.completed_searches
                .push((folder.mailbox_id, MapiId::from_node(folder.node)));
        }
        self.invalidate_mailbox();
        self.respond(rop, index, &EmptyResponse)
    }

    pub async fn get_search_criteria(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetSearchCriteria,
    ) -> RopResult {
        let folder = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let search = self.current_search(folder).await?;
        let folder_ids = if request.include_folders {
            let exchange = self.mailbox(folder.mailbox_id).await?.exchange;
            search
                .scope
                .iter()
                .filter_map(|folder| FolderNode::from_stored(folder.kind, folder.id))
                .map(|node| MapiId::from_folder(&exchange, node).to_eid())
                .collect()
        } else {
            Vec::<Eid>::new()
        };
        let restriction_data = if request.include_restriction {
            search.restriction.as_slice()
        } else {
            &[]
        };
        self.respond(
            rop,
            index,
            &GetSearchCriteriaResponse {
                restriction_data,
                logon_id: rop.header.logon_id,
                folder_ids: &folder_ids,
                search_flags: SearchFlags(search.flags).status(),
            },
        )
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/search/tests.rs"]
mod tests;
