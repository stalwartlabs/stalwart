/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Comparator, ResultSet, SortedResultSet};
use crate::{IndexKeyPrefix, IterateParams, Store, U32_LEN, write::key::DeserializeBigEndian};
use ahash::{AHashMap, AHashSet};
use std::cmp::Ordering;
use trc::AddContext;
use types::id::Id;

#[derive(Debug)]
pub struct Pagination<'x> {
    requested_position: i32,
    position: i32,
    pub limit: usize,
    anchor: u32,
    anchor_offset: i32,
    has_anchor: bool,
    anchor_found: bool,
    pub ids: Vec<Id>,
    prefix_map: Option<&'x AHashMap<u32, u32>>,
    prefix_unique: bool,
}

impl Store {
    pub async fn sort(
        &self,
        result_set: ResultSet,
        mut comparators: Vec<Comparator>,
        mut paginate: Pagination<'_>,
    ) -> trc::Result<SortedResultSet> {
        paginate.limit = match (result_set.results.len(), paginate.limit) {
            (0, _) => {
                return Ok(SortedResultSet {
                    position: paginate.position,
                    ids: vec![],
                    found_anchor: true,
                });
            }
            (_, 0) => result_set.results.len() as usize,
            (a, b) => std::cmp::min(a as usize, b),
        };

        if comparators.len() == 1 && !paginate.prefix_unique {
            match comparators.pop().unwrap() {
                Comparator::Field { field, ascending } => {
                    let mut results = result_set.results;
                    let collection = u8::from(result_set.collection);

                    self.iterate(
                        IterateParams::new(
                            IndexKeyPrefix {
                                account_id: result_set.account_id,
                                collection,
                                field,
                            },
                            IndexKeyPrefix {
                                account_id: result_set.account_id,
                                collection,
                                field: field + 1,
                            },
                        )
                        .no_values()
                        .set_ascending(ascending),
                        |key, _| {
                            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;

                            Ok(!results.remove(document_id) || paginate.add(0, document_id))
                        },
                    )
                    .await
                    .caused_by(trc::location!())?;

                    // Add remaining items not present in the index
                    if !results.is_empty() && !paginate.is_full() {
                        for document_id in results {
                            if !paginate.add(0, document_id) {
                                break;
                            }
                        }
                    }
                }
                Comparator::DocumentSet { set, ascending } => {
                    let in_set = &result_set.results & &set;
                    let not_in_set = &result_set.results ^ &in_set;
                    let sets = if ascending {
                        [in_set, not_in_set]
                    } else {
                        [not_in_set, in_set]
                    };
                    'outer: for set in sets {
                        for document_id in set {
                            if !paginate.add(0, document_id) {
                                break 'outer;
                            }
                        }
                    }
                }
                Comparator::SortedList { list, ascending } => {
                    if ascending {
                        for document_id in list {
                            if result_set.results.contains(document_id)
                                && !paginate.add(0, document_id)
                            {
                                break;
                            }
                        }
                    } else {
                        for document_id in list.into_iter().rev() {
                            if result_set.results.contains(document_id)
                                && !paginate.add(0, document_id)
                            {
                                break;
                            }
                        }
                    }
                }
            }

            // Obtain prefixes
            let prefix_map = paginate.prefix_map.take();
            let mut sorted_results = paginate.build();
            if let Some(prefix_map) = prefix_map {
                for id in sorted_results.ids.iter_mut() {
                    let document_id = id.document_id();
                    if let Some(prefix_id) = prefix_map.get(&document_id) {
                        *id = Id::from_parts(*prefix_id, document_id);
                    }
                }
            }

            Ok(sorted_results)
        } else if comparators.len() > 1 {
            //TODO improve this algorithm, avoid re-sorting in memory.
            let mut sorted_ids = AHashMap::with_capacity(paginate.limit);

            for (pos, comparator) in comparators.into_iter().take(4).enumerate() {
                match comparator {
                    Comparator::Field { field, ascending } => {
                        let mut results = result_set.results.clone();
                        let mut prev_data = vec![];
                        let mut has_grouped_ids = false;
                        let mut idx = 0;
                        let collection = u8::from(result_set.collection);

                        self.iterate(
                            IterateParams::new(
                                IndexKeyPrefix {
                                    account_id: result_set.account_id,
                                    collection,
                                    field,
                                },
                                IndexKeyPrefix {
                                    account_id: result_set.account_id,
                                    collection,
                                    field: field + 1,
                                },
                            )
                            .no_values()
                            .set_ascending(ascending),
                            |key, _| {
                                let id_pos = key.len() - U32_LEN;
                                let document_id = key.deserialize_be_u32(id_pos)?;

                                Ok(if results.remove(document_id) {
                                    let data = key.get(IndexKeyPrefix::len()..id_pos).ok_or_else(
                                        || trc::Error::corrupted_key(key, None, trc::location!()),
                                    )?;
                                    debug_assert!(!data.is_empty());

                                    if data != prev_data {
                                        idx += 1;
                                        prev_data = data.to_vec();
                                    } else {
                                        has_grouped_ids = true;
                                    }

                                    sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] = idx;

                                    !results.is_empty()
                                } else {
                                    true
                                })
                            },
                        )
                        .await
                        .caused_by(trc::location!())?;

                        // Add remaining items not present in the index
                        if !results.is_empty() {
                            idx += 1;
                            for document_id in results {
                                sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] = idx;
                            }
                        } else if !has_grouped_ids {
                            // If we are sorting by multiple fields and we don't have grouped ids, we can
                            // stop here
                            break;
                        }
                    }
                    Comparator::DocumentSet { set, ascending } => {
                        let in_set = &result_set.results & &set;
                        let not_in_set = &result_set.results ^ &in_set;
                        let sets = if ascending {
                            [(in_set, 0), (not_in_set, 1)]
                        } else {
                            [(not_in_set, 0), (in_set, 1)]
                        };

                        for (document_ids, idx) in sets {
                            for document_id in document_ids {
                                sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] = idx;
                            }
                        }
                    }
                    Comparator::SortedList { list, ascending } => {
                        if ascending {
                            for (idx, document_id) in list.into_iter().enumerate() {
                                if result_set.results.contains(document_id) {
                                    sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] =
                                        idx as u32;
                                }
                            }
                        } else {
                            for (idx, document_id) in list.into_iter().rev().enumerate() {
                                if result_set.results.contains(document_id) {
                                    sorted_ids.entry(document_id).or_insert([0u32; 4])[pos] =
                                        idx as u32;
                                }
                            }
                        }
                    }
                }
            }

            let mut seen_prefixes = AHashSet::new();
            let mut sorted_ids = sorted_ids.into_iter().collect::<Vec<_>>();
            sorted_ids.sort_by(|a, b| match a.1.cmp(&b.1) {
                Ordering::Equal => a.0.cmp(&b.0),
                other => other,
            });
            for (document_id, _) in sorted_ids {
                // Obtain document prefixId
                let prefix_id = if let Some(prefix_map) = paginate.prefix_map {
                    if let Some(prefix_id) = prefix_map.get(&document_id) {
                        if paginate.prefix_unique && !seen_prefixes.insert(*prefix_id) {
                            continue;
                        }
                        *prefix_id
                    } else {
                        // Document no longer exists?
                        continue;
                    }
                } else {
                    0
                };

                // Add document to results
                if !paginate.add(prefix_id, document_id) {
                    break;
                }
            }

            Ok(paginate.build())
        } else {
            let mut seen_prefixes = AHashSet::new();
            for document_id in result_set.results {
                // Obtain document prefixId
                let prefix_id = if let Some(prefix_map) = paginate.prefix_map {
                    if let Some(prefix_id) = prefix_map.get(&document_id) {
                        if paginate.prefix_unique && !seen_prefixes.insert(*prefix_id) {
                            continue;
                        }
                        *prefix_id
                    } else {
                        // Document no longer exists?
                        continue;
                    }
                } else {
                    0
                };

                // Add document to results
                if !paginate.add(prefix_id, document_id) {
                    break;
                }
            }
            Ok(paginate.build())
        }
    }
}

impl<'x> Pagination<'x> {
    pub fn new(limit: usize, position: i32, anchor: Option<u32>, anchor_offset: i32) -> Self {
        let (has_anchor, anchor) = anchor.map(|anchor| (true, anchor)).unwrap_or((false, 0));

        Self {
            requested_position: position,
            position,
            limit,
            anchor,
            anchor_offset,
            has_anchor,
            anchor_found: false,
            ids: Vec::with_capacity(limit),
            prefix_map: None,
            prefix_unique: false,
        }
    }

    pub fn with_prefix_map(mut self, prefix_map: &'x AHashMap<u32, u32>) -> Self {
        self.prefix_map = Some(prefix_map);
        self
    }

    pub fn with_prefix_unique(mut self, prefix_unique: bool) -> Self {
        self.prefix_unique = prefix_unique;
        self
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
                    self.ids.push(id);
                    if self.ids.len() == self.limit {
                        return false;
                    }
                }
            } else {
                self.ids.push(id);
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
                self.ids.push(id);
                if self.ids.len() == self.limit {
                    return false;
                }
            }
        } else {
            self.anchor_found = document_id == self.anchor;
            self.ids.push(id);

            if self.anchor_found {
                self.position = self.anchor_offset;
                return false;
            }
        }

        true
    }

    pub fn is_full(&self) -> bool {
        self.ids.len() == self.limit
    }

    pub fn build(self) -> SortedResultSet {
        let mut result = SortedResultSet {
            ids: self.ids,
            position: 0,
            found_anchor: !self.has_anchor || self.anchor_found,
        };

        if result.found_anchor {
            if !self.has_anchor && self.requested_position >= 0 {
                result.position = if self.position == 0 {
                    self.requested_position
                } else {
                    0
                };
            } else if self.position >= 0 {
                result.position = self.position;
            } else {
                let position = self.position.unsigned_abs() as usize;
                let start_offset = if position < result.ids.len() {
                    result.ids.len() - position
                } else {
                    0
                };
                result.position = start_offset as i32;
                let end_offset = if self.limit > 0 {
                    std::cmp::min(start_offset + self.limit, result.ids.len())
                } else {
                    result.ids.len()
                };

                result.ids = result.ids[start_offset..end_offset].to_vec()
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::id::Id;

    #[test]
    fn test_pagination_position_with_1_anchor_offset() {
        let mut pagination = Pagination::new(3, 0, Some(3), 1);

        for i in 0..10 {
            let should_continue = pagination.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = pagination.build();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 5, "First item should be 5");
        assert_eq!(result.ids[1].document_id(), 6, "Second item should be 6");
        assert_eq!(result.ids[2].document_id(), 7, "Third item should be 7");
        assert!(result.found_anchor, "Should have found anchor");
        assert_eq!(
            result.position, 5,
            "Position should be 5 (where we started collecting)"
        );
    }

    #[test]
    fn test_pagination_position_with_positive_anchor_offset() {
        let mut pagination = Pagination::new(3, 0, Some(3), 2);

        for i in 0..10 {
            let should_continue = pagination.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = pagination.build();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 6, "First item should be 6");
        assert_eq!(result.ids[1].document_id(), 7, "Second item should be 7");
        assert_eq!(result.ids[2].document_id(), 8, "Third item should be 8");
        assert!(result.found_anchor, "Should have found anchor");
        assert_eq!(
            result.position, 6,
            "Position should be 6 (where we started collecting)"
        );
    }

    #[test]
    fn test_pagination_position_with_zero_anchor_offset() {
        let mut pagination = Pagination::new(3, 0, Some(5), 0);

        for i in 0..10 {
            let should_continue = pagination.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = pagination.build();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 5, "First item should be 5");
        assert_eq!(result.ids[1].document_id(), 6, "Second item should be 6");
        assert_eq!(result.ids[2].document_id(), 7, "Third item should be 7");
        assert!(result.found_anchor, "Should have found anchor");
        assert_eq!(result.position, 5, "Position should be 5 (anchor position)");
    }

    #[test]
    fn test_pagination_without_anchor_from_start() {
        let mut pagination = Pagination::new(3, 0, None, 0);

        for i in 0..10 {
            let should_continue = pagination.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = pagination.build();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 0, "First item should be 0");
        assert_eq!(result.ids[1].document_id(), 1, "Second item should be 1");
        assert_eq!(result.ids[2].document_id(), 2, "Third item should be 2");
        assert_eq!(result.position, 0, "Position should be 0");
    }

    #[test]
    fn test_pagination_without_anchor_with_offset() {
        let mut pagination = Pagination::new(3, 5, None, 0);

        for i in 0..10 {
            let should_continue = pagination.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = pagination.build();

        assert_eq!(result.ids.len(), 3, "Should collect 3 items");
        assert_eq!(result.ids[0].document_id(), 5, "First item should be 5");
        assert_eq!(result.ids[1].document_id(), 6, "Second item should be 6");
        assert_eq!(result.ids[2].document_id(), 7, "Third item should be 7");
        assert_eq!(result.position, 5, "Position should be 5");
    }

    #[test]
    fn test_pagination_without_anchor_partial_results() {
        let mut pagination = Pagination::new(5, 3, None, 0);

        for i in 0..5 {
            let should_continue = pagination.add_id(Id::from_parts(0, i));
            if !should_continue {
                break;
            }
        }

        let result = pagination.build();

        assert_eq!(
            result.ids.len(),
            2,
            "Should collect 2 items (not full limit)"
        );
        assert_eq!(result.ids[0].document_id(), 3, "First item should be 3");
        assert_eq!(result.ids[1].document_id(), 4, "Second item should be 4");
        assert_eq!(result.position, 3, "Position should be 3");
    }
}
