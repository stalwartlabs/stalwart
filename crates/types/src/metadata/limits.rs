/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{builder::EncodedMetadata, json::EncodedJson};

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

    pub fn check_json(&self, value: &EncodedJson) -> Result<(), LimitViolation> {
        self.check_depth(value.depth())?;
        self.check_entry_size(value.len())
    }

    pub fn check_container(
        &self,
        scope: MetadataScope,
        container: &EncodedMetadata,
    ) -> Result<(), LimitViolation> {
        if container.entries() > self.max_entries {
            return Err(LimitViolation::Entries {
                count: container.entries(),
                max: self.max_entries,
            });
        }
        let max = self.max_container_size(scope);
        if container.len() > max {
            Err(LimitViolation::ContainerSize {
                size: container.len(),
                max,
            })
        } else {
            Ok(())
        }
    }
}
