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
    anchor: u64,
    anchor_offset: i32,
    pub has_anchor: bool,
    pub anchor_found: bool,
    index: i32,

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

        QueryResponseBuilder {
            requested_position: request.position.unwrap_or(0),
            position: request.position.unwrap_or(0),
            limit: limit_total,
            has_anchor: request.anchor.is_some(),
            anchor: request.anchor.map(|anchor| anchor.id()).unwrap_or(0),
            anchor_offset: request.anchor_offset.unwrap_or(0),
            anchor_found: false,
            index: 0,
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
        let id_u64 = id.id();

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
        } else {
            let current_index = self.index;
            self.index += 1;

            if id_u64 == self.anchor {
                self.anchor_found = true;
                self.position = (current_index + self.anchor_offset).max(0);
            }

            if self.anchor_offset >= 0 {
                if self.anchor_found && current_index >= self.position {
                    self.response.ids.push(id);
                    if self.limit > 0 && self.response.ids.len() == self.limit {
                        return false;
                    }
                }
            } else {
                self.response.ids.push(id);
                if self.anchor_found
                    && self.limit > 0
                    && self.response.ids.len() >= self.position as usize + self.limit
                {
                    return false;
                }
            }
        }

        true
    }

    pub fn is_full(&self) -> bool {
        self.response.ids.len() == self.limit
    }

    pub fn build(mut self) -> trc::Result<QueryResponse> {
        if self.has_anchor {
            if !self.anchor_found {
                return Err(trc::JmapEvent::AnchorNotFound.into_err());
            }

            let start = self.position.max(0) as usize;
            if self.anchor_offset < 0 {
                let start = start.min(self.response.ids.len());
                let end = if self.limit > 0 {
                    std::cmp::min(start + self.limit, self.response.ids.len())
                } else {
                    self.response.ids.len()
                };
                self.response.ids = self.response.ids[start..end].to_vec();
            }
            self.response.position = start as i32;

            return Ok(self.response);
        }

        if self.requested_position >= 0 {
            self.response.position = if self.position == 0 {
                self.requested_position
            } else {
                0
            };
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

            self.response.ids = self.response.ids[start_offset..end_offset].to_vec();
        }

        Ok(self.response)
    }
}
