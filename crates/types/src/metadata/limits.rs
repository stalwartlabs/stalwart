/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::builder::EncodedMetadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataScope {
    Shared,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MetadataLimits {
    pub max_depth: Option<u32>,
    pub max_entry_size: usize,
    pub max_size: usize,
    pub max_private_size: usize,
    pub max_entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitViolation {
    Depth { depth: u32, max: u32 },
    EntrySize { size: usize, max: usize },
    ContainerSize { size: usize, max: usize },
    Entries { count: usize, max: usize },
}

#[derive(Debug, Clone, Copy)]
pub struct EntryBound {
    bound: usize,
    max_entries: usize,
}

impl Default for MetadataLimits {
    fn default() -> Self {
        MetadataLimits {
            max_depth: Some(8),
            max_entry_size: 8 * 1024,
            max_size: 64 * 1024,
            max_private_size: 16 * 1024,
            max_entries: 128,
        }
    }
}

impl MetadataLimits {
    pub fn max_container_size(&self, scope: MetadataScope) -> usize {
        match scope {
            MetadataScope::Shared => self.max_size,
            MetadataScope::Private => self.max_private_size,
        }
    }

    pub fn check_depth(&self, depth: u32) -> Result<(), LimitViolation> {
        match self.max_depth {
            Some(max) if depth > max => Err(LimitViolation::Depth { depth, max }),
            _ => Ok(()),
        }
    }

    pub fn check_entry_size(&self, size: usize) -> Result<(), LimitViolation> {
        if size > self.max_entry_size {
            Err(LimitViolation::EntrySize {
                size,
                max: self.max_entry_size,
            })
        } else {
            Ok(())
        }
    }

    pub fn entry_bound(&self, previous_entries: usize) -> EntryBound {
        EntryBound {
            bound: self.max_entries.max(previous_entries),
            max_entries: self.max_entries,
        }
    }

    pub fn check_edit(
        &self,
        scope: MetadataScope,
        previous_len: usize,
        previous_entries: usize,
        next: &EncodedMetadata,
    ) -> Result<(), LimitViolation> {
        let count = next.entries();
        if count > self.max_entries && count > previous_entries {
            return Err(LimitViolation::Entries {
                count,
                max: self.max_entries,
            });
        }
        let size = next.len();
        let max = self.max_container_size(scope);
        if size > max && size > previous_len {
            Err(LimitViolation::ContainerSize { size, max })
        } else {
            Ok(())
        }
    }
}

impl EntryBound {
    pub fn check(self, entries: usize, pending_removals: usize) -> Result<(), LimitViolation> {
        let count = entries.saturating_sub(pending_removals);
        if count > self.bound {
            Err(LimitViolation::Entries {
                count,
                max: self.max_entries,
            })
        } else {
            Ok(())
        }
    }
}
