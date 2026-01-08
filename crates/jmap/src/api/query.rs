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

#[cfg(test)]
mod tests {
    use super::*;
    use jmap_proto::types::state::State;
    use types::id::Id;

    // Helper to create a QueryResponseBuilder with specific pagination settings
    fn create_builder(
        limit: usize,
        position: i32,
        anchor: Option<u32>,
        anchor_offset: i32,
    ) -> QueryResponseBuilder {
        let (has_anchor, anchor_val) = anchor.map(|a| (true, a)).unwrap_or((false, 0));

        QueryResponseBuilder {
            requested_position: position,
            position,
            limit,
            anchor: anchor_val,
            anchor_offset,
            has_anchor,
            anchor_found: false,
            response: jmap_proto::method::query::QueryResponse {
                account_id: types::id::Id::default(),
                query_state: State::Initial,
                can_calculate_changes: true,
                position: 0,
                ids: vec![],
                total: None,
                limit: None,
            },
        }
    }

    #[test]
    fn test_pagination_position_with_1_anchor_offset() {
        let mut builder = create_builder(3, 0, Some(3), 1);

        for i in 0..10 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 4, "First item should be 4");
        assert_eq!(result.ids[1].document_id(), 5, "Second item should be 5");
        assert_eq!(result.ids[2].document_id(), 6, "Third item should be 6");
        assert_eq!(
            result.position, 5,
            "Position should be 5 (where we started collecting)"
        );
    }

    #[test]
    fn test_pagination_position_with_positive_anchor_offset() {
        let mut builder = create_builder(3, 0, Some(3), 2);

        for i in 0..10 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 5, "First item should be 5");
        assert_eq!(result.ids[1].document_id(), 6, "Second item should be 6");
        assert_eq!(result.ids[2].document_id(), 7, "Third item should be 7");
        assert_eq!(
            result.position, 6,
            "Position should be 6 (where we started collecting)"
        );
    }

    #[test]
    fn test_pagination_position_with_zero_anchor_offset() {
        let mut builder = create_builder(3, 0, Some(5), 0);

        for i in 0..10 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 5, "First item should be 5");
        assert_eq!(result.ids[1].document_id(), 6, "Second item should be 6");
        assert_eq!(result.ids[2].document_id(), 7, "Third item should be 7");
        assert_eq!(result.position, 6, "Position should be 6 (anchor position)");
    }

    #[test]
    fn test_pagination_without_anchor_from_start() {
        let mut builder = create_builder(3, 0, None, 0);

        for i in 0..10 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 0, "First item should be 0");
        assert_eq!(result.ids[1].document_id(), 1, "Second item should be 1");
        assert_eq!(result.ids[2].document_id(), 2, "Third item should be 2");
        assert_eq!(result.position, 0, "Position should be 0");
    }

    #[test]
    fn test_pagination_without_anchor_with_offset() {
        let mut builder = create_builder(3, 5, None, 0);

        for i in 0..10 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 5, "First item should be 5");
        assert_eq!(result.ids[1].document_id(), 6, "Second item should be 6");
        assert_eq!(result.ids[2].document_id(), 7, "Third item should be 7");
        assert_eq!(result.position, 5, "Position should be 5");
    }

    #[test]
    fn test_pagination_without_anchor_partial_results() {
        let mut builder = create_builder(5, 3, None, 0);

        for i in 0..5 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(
            result.ids.len(),
            2,
            "Should collect 2 items (not full limit)"
        );
        assert_eq!(result.ids[0].document_id(), 3, "First item should be 3");
        assert_eq!(result.ids[1].document_id(), 4, "Second item should be 4");
        assert_eq!(result.position, 3, " be 3");
    }

    #[test]
    fn test_pagination_with_large_anchor_offset() {
        let mut builder = create_builder(5, 0, Some(3), 10);

        for i in 0..30 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 5, "Should collect 5 items");
        assert_eq!(result.ids[0].document_id(), 13, "First item should be 13");
        assert_eq!(result.ids[1].document_id(), 14, "Second item should be 14");
        assert_eq!(result.ids[2].document_id(), 15, "Third item should be 15");
        assert_eq!(result.ids[3].document_id(), 16, "Fourth item should be 16");
        assert_eq!(result.ids[4].document_id(), 17, "Fifth item should be 17");
        assert_eq!(
            result.position, 14,
            "Position should be 14 (where we started collecting)"
        );
    }

    #[test]
    fn test_pagination_anchor_offset_10_expects_items_starting_at_anchor_plus_10() {
        let mut builder = create_builder(10, 0, Some(5), 10);

        for i in 0..30 {
            let should_continue = builder.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 10, "Should collect 10 items");
        // Anchor at index 5, offset 10 means: skip to position 5+10=15
        assert_eq!(result.ids[0].document_id(), 15, "First item should be 15 (anchor_pos + offset)");
        assert_eq!(result.ids[9].document_id(), 24, "Last item should be 24");
        assert_eq!(
            result.position, 16,
            "Position should be 16"
        );
    }
}
