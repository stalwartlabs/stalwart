/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::*;
use roaring::RoaringBitmap;

struct State {
    pub op: SearchFilter,
    pub bm: Option<RoaringBitmap>,
}

impl SearchQuery {
    pub fn new(index: SearchIndex) -> Self {
        Self {
            index,
            filters: Vec::new(),
            comparators: Vec::new(),
            mask: RoaringBitmap::new(),
        }
    }

    pub fn with_filters(mut self, filters: Vec<SearchFilter>) -> Self {
        if self.filters.is_empty() {
            self.filters = filters;
        } else {
            self.filters.extend(filters);
        }
        self
    }

    pub fn with_comparators(mut self, comparators: Vec<SearchComparator>) -> Self {
        if self.comparators.is_empty() {
            self.comparators = comparators;
        } else {
            self.comparators.extend(comparators);
        }
        self
    }

    pub fn with_filter(mut self, filter: SearchFilter) -> Self {
        self.filters.push(filter);
        self
    }

    pub fn add_filter(&mut self, filter: SearchFilter) -> &mut Self {
        self.filters.push(filter);
        self
    }

    pub fn with_comparator(mut self, comparator: SearchComparator) -> Self {
        self.comparators.push(comparator);
        self
    }

    pub fn with_mask(mut self, mask: RoaringBitmap) -> Self {
        self.mask = mask;
        self
    }

    pub fn with_account_id(mut self, account_id: u32) -> Self {
        self.filters.push(SearchFilter::cond(
            SearchField::AccountId,
            SearchOperator::Equal,
            SearchValue::Uint(account_id as u64),
        ));
        self
    }

    pub fn filter(self) -> QueryResults {
        if self.filters.is_empty() {
            return QueryResults {
                results: self.mask,
                comparators: self.comparators,
            };
        }
        let mut state: State = State {
            op: SearchFilter::And,
            bm: None,
        };
        let mut stack = Vec::new();
        let mut filters = self.filters.into_iter().peekable();
        let mask = self.mask;

        while let Some(filter) = filters.next() {
            let mut result = match filter {
                SearchFilter::DocumentSet(set) => Some(set),
                op @ (SearchFilter::And | SearchFilter::Or | SearchFilter::Not) => {
                    stack.push(state);
                    state = State { op, bm: None };
                    continue;
                }
                SearchFilter::End => {
                    if let Some(prev_state) = stack.pop() {
                        let bm = state.bm;
                        state = prev_state;
                        bm
                    } else {
                        break;
                    }
                }
                SearchFilter::Operator { .. } => {
                    continue;
                }
            };

            // Apply logical operation
            if let Some(dest) = &mut state.bm {
                match state.op {
                    SearchFilter::And => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    SearchFilter::Or => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    SearchFilter::Not => {
                        if let Some(mut result) = result {
                            result.bitxor_assign(&mask);
                            dest.bitand_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if let Some(ref mut result_) = result {
                if let SearchFilter::Not = state.op {
                    result_.bitxor_assign(&mask);
                }
                state.bm = result;
            } else if let SearchFilter::Not = state.op {
                state.bm = Some(mask.clone());
            } else {
                state.bm = Some(RoaringBitmap::new());
            }

            // And short-circuit
            if matches!(state.op, SearchFilter::And) && state.bm.as_ref().unwrap().is_empty() {
                while let Some(filter) = filters.peek() {
                    if matches!(filter, SearchFilter::End) {
                        break;
                    } else {
                        filters.next();
                    }
                }
            }
        }

        // AND with mask
        let mut results = state.bm.unwrap_or_default();
        results.bitand_assign(&mask);
        QueryResults {
            results,
            comparators: self.comparators,
        }
    }
}

impl QueryResults {
    pub fn new(results: RoaringBitmap, comparators: Vec<SearchComparator>) -> Self {
        Self {
            results,
            comparators,
        }
    }

    pub fn with_comparators(mut self, comparators: Vec<SearchComparator>) -> Self {
        if self.comparators.is_empty() {
            self.comparators = comparators;
        } else {
            self.comparators.extend(comparators);
        }
        self
    }

    pub fn results(&self) -> &RoaringBitmap {
        &self.results
    }

    pub fn update_results(&mut self, results: RoaringBitmap) {
        self.results = results;
    }

    pub fn into_bitmap(self) -> RoaringBitmap {
        self.results
    }

    pub fn into_sorted(self) -> Vec<u32> {
        let comparators = self.comparators;
        let mut results = self.results.into_iter().collect::<Vec<u32>>();

        if !results.is_empty() && !comparators.is_empty() {
            results.sort_by(|a, b| {
                for comparator in &comparators {
                    let (a, b, is_ascending) = match comparator {
                        SearchComparator::DocumentSet { set, ascending } => (
                            !set.contains(*a) as u32,
                            !set.contains(*b) as u32,
                            *ascending,
                        ),
                        SearchComparator::SortedSet { set, ascending } => (
                            *set.get(a).unwrap_or(&u32::MAX),
                            *set.get(b).unwrap_or(&u32::MAX),
                            *ascending,
                        ),
                        SearchComparator::Field { .. } => continue,
                    };

                    let ordering = if is_ascending { a.cmp(&b) } else { b.cmp(&a) };

                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
                Ordering::Equal
            });
        }

        results
    }
}
