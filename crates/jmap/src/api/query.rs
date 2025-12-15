/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    method::query::{QueryRequest, QueryResponse},
    object::JmapObject,
    types::state::State,
};
use types::id::Id;

pub struct QueryResponseBuilder {
    requested_position: i32,
    position: i32,
    pub limit: usize,
    anchor: u32,
    anchor_offset: i32,
    has_anchor: bool,
    anchor_found: bool,

    pub response: QueryResponse,
}

impl QueryResponseBuilder {
    pub fn new<T: JmapObject + Sync + Send>(
        total_results: usize,
        max_results: usize,
        query_state: State,
        request: &QueryRequest<T>,
    ) -> Self {
        let (limit_total, limit) = if let Some(limit) = request.limit {
            if limit > 0 {
                let limit = std::cmp::min(limit, max_results);
                (std::cmp::min(limit, total_results), limit)
            } else {
                (0, 0)
            }
        } else {
            (std::cmp::min(max_results, total_results), max_results)
        };

        let (has_anchor, anchor) = request
            .anchor
            .map(|anchor| (true, anchor.document_id()))
            .unwrap_or((false, 0));

        QueryResponseBuilder {
            requested_position: request.position.unwrap_or(0),
            position: request.position.unwrap_or(0),
            limit: limit_total,
            anchor,
            anchor_offset: request.anchor_offset.unwrap_or(0),
            has_anchor,
            anchor_found: false,
            response: QueryResponse {
                account_id: request.account_id,
                query_state,
                can_calculate_changes: true,
                position: 0,
                ids: vec![],
                total: if request.calculate_total.unwrap_or(false) {
                    Some(total_results)
                } else {
                    None
                },
                limit: if total_results > limit {
                    Some(limit)
                } else {
                    None
                },
            },
        }
    }

    #[inline(always)]
    pub fn add(&mut self, prefix_id: u32, document_id: u32) -> bool {
        self.add_id(Id::from_parts(prefix_id, document_id))
    }

    pub fn add_id(&mut self, id: Id) -> bool {
        let document_id = id.document_id();

        // Pagination
        if !self.has_anchor {
            if self.position >= 0 {
                if self.position > 0 {
                    self.position -= 1;
                } else {
                    self.response.ids.push(id);
                    if self.response.ids.len() == self.limit {
                        return false;
                    }
                }
            } else {
                self.response.ids.push(id);
            }
        } else if self.anchor_offset >= 0 {
            if !self.anchor_found {
                if document_id != self.anchor {
                    return true;
                }
                self.anchor_found = true;
            }

            if self.anchor_offset > 0 {
                self.anchor_offset -= 1;
            } else {
                self.response.ids.push(id);
                if self.response.ids.len() == self.limit {
                    return false;
                }
            }
        } else {
            self.anchor_found = document_id == self.anchor;
            self.response.ids.push(id);

            if self.anchor_found {
                self.position = self.anchor_offset;
                return false;
            }
        }

        true
    }

    pub fn is_full(&self) -> bool {
        self.response.ids.len() == self.limit
    }

    pub fn build(mut self) -> trc::Result<QueryResponse> {
        if !self.has_anchor || self.anchor_found {
            if !self.has_anchor && self.requested_position >= 0 {
                self.response.position = if self.position == 0 {
                    self.requested_position
                } else {
                    0
                };
            } else if self.position >= 0 {
                self.response.position = self.position;
            } else {
                let position = self.position.unsigned_abs() as usize;
                let start_offset = if position < self.response.ids.len() {
                    self.response.ids.len() - position
                } else {
                    0
                };
                self.response.position = start_offset as i32;
                let end_offset = if self.limit > 0 {
                    std::cmp::min(start_offset + self.limit, self.response.ids.len())
                } else {
                    self.response.ids.len()
                };

                self.response.ids = self.response.ids[start_offset..end_offset].to_vec()
            }

            Ok(self.response)
        } else {
            Err(trc::JmapEvent::AnchorNotFound.into_err())
        }
    }
}
