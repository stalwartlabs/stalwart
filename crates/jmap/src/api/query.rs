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
            // by position
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
            // by anchor
            if document_id == self.anchor {
                self.anchor_found = true;
            } else if !self.anchor_found {
                self.position += 1;
            }

            if self.anchor_found && self.anchor_offset == 0 {
                // once we're in a stable state (anchor found and offset zero), we'll keep pushing ids until we reach the limit
                self.response.ids.push(id);
                if self.response.ids.len() == self.limit {
                    return false;
                }
            } else if self.anchor_offset < 0 {
                // if the offset is negative, we need to "remember" the last -offset items we've seen
                self.response.ids.push(id);
                if self.anchor_found {
                    // once we find the anchor, trim the list to keep those we need to include in the returned list
                    self.position += self.anchor_offset;
                    self.anchor_offset = 0;
                    if self.response.ids.len() > self.limit {
                        self.response.ids = self.response.ids[0..self.limit].to_vec();
                        return false;
                    }
                    if self.response.ids.len() == self.limit {
                        return false;
                    }
                } else if self.response.ids.len() > self.anchor_offset.unsigned_abs() as usize {
                    // limit remembered items to -offset length
                    self.response.ids.remove(0);
                }
            } else if self.anchor_found && self.anchor_offset > 0 {
                // if the offset is positive, we don't start pushing ids until we've skipped offset items after finding the anchor
                self.anchor_offset -= 1;
                self.position += 1;
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
    use jmap_tools::Null;
    use types::id::Id;

    #[derive(Debug, Clone, Copy)]
    struct TestJMAPObject;

    impl JmapObject for TestJMAPObject {
        type Property = Null;
        type Element = Null;
        type Id = Null;

        type Filter = ();
        type Comparator = ();

        type GetArguments = ();
        type SetArguments<'de> = ();
        type QueryArguments = ();
        type CopyArguments = ();
        type ParseArguments = ();

        const ID_PROPERTY: Self::Property = Null;
    }

    #[test]
    fn test_pagination_with_zero_position() {
        let range: std::ops::Range<u32> = 0..10;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                position: Some(0),
                limit: Some(3),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
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
    fn test_pagination_with_positive_position() {
        let range: std::ops::Range<u32> = 0..10;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                position: Some(5),
                limit: Some(3),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
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
    fn test_pagination_negative_position() {
        let range: std::ops::Range<u32> = 0..30;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                position: Some(-6),
                limit: Some(3),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 10 items");
        assert_eq!(result.ids[0].document_id(), 24, "First item should be 24");
        assert_eq!(result.ids[1].document_id(), 25, "Second item should be 25");
        assert_eq!(result.ids[2].document_id(), 26, "Third item should be 26");
        assert_eq!(result.position, 24);
    }

    #[test]
    fn test_pagination_with_position_partial_results() {
        let range: std::ops::Range<u32> = 0..5;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                position: Some(3),
                limit: Some(5),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
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
    fn test_pagination_with_zero_anchor_offset() {
        let range: std::ops::Range<u32> = 0..10;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                limit: Some(3),
                anchor: Some(Id::from_parts(0, 5)),
                anchor_offset: Some(0),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
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
    fn test_pagination_with_negative_anchor_offset() {
        let range: std::ops::Range<u32> = 0..10;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                limit: Some(3),
                anchor: Some(Id::from_parts(0, 5)),
                anchor_offset: Some(-2),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 3, "First item should be 3");
        assert_eq!(result.ids[1].document_id(), 4, "Second item should be 4");
        assert_eq!(result.ids[2].document_id(), 5, "Third item should be 5");
        assert_eq!(result.position, 3, "Position should be 3");
    }

    #[test]
    fn test_pagination_with_negative_anchor_offset_more_than_limit() {
        let range: std::ops::Range<u32> = 0..10;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                limit: Some(3),
                anchor: Some(Id::from_parts(0, 9)),
                anchor_offset: Some(-6),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 3, "First item should be 3");
        assert_eq!(result.ids[1].document_id(), 4, "Second item should be 4");
        assert_eq!(result.ids[2].document_id(), 5, "Third item should be 5");
        assert_eq!(result.position, 3, "Position should be 3");
    }

    #[test]
    fn test_pagination_with_anchor_offset_1() {
        let range: std::ops::Range<u32> = 0..10;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                limit: Some(3),
                anchor: Some(Id::from_parts(0, 3)),
                anchor_offset: Some(1),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
                break;
            }
        }

        let result = builder.build().unwrap();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 4, "First item should be 4");
        assert_eq!(result.ids[1].document_id(), 5, "Second item should be 5");
        assert_eq!(result.ids[2].document_id(), 6, "Third item should be 6");
        assert_eq!(result.position, 4, "Position should be 4");
    }

    #[test]
    fn test_pagination_with_anchor_offset_2() {
        let range: std::ops::Range<u32> = 0..10;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                limit: Some(3),
                anchor: Some(Id::from_parts(0, 3)),
                anchor_offset: Some(2),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
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
    fn test_pagination_with_anchor_offset_10() {
        let range: std::ops::Range<u32> = 0..30;
        let mut builder = QueryResponseBuilder::new(
            range.len(),
            100,
            State::Initial,
            &QueryRequest::<TestJMAPObject> {
                limit: Some(5),
                anchor: Some(Id::from_parts(0, 3)),
                anchor_offset: Some(10),
                ..Default::default()
            },
        );

        for i in range {
            if !builder.add_id(Id::from_parts(0, i)) {
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
        assert_eq!(result.position, 13, "Position should be 13");
    }
}
