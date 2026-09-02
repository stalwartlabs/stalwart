/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod build;
pub mod object;
pub mod split;
pub mod value;

pub use object::*;
pub use split::*;
pub use value::*;

use crate::auth::AccountTenantIds;
use build::{build_index, merge_index};
use store::write::{BatchBuilder, IntoOperations, Slot};

#[derive(Debug)]
pub struct ObjectIndexBuilder<C, N> {
    changed_by: u32,
    tenant_id: Option<u32>,
    current: Option<C>,
    changes: Option<N>,
    pending_id: Option<Slot>,
}

impl<C, N> Default for ObjectIndexBuilder<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C, N> ObjectIndexBuilder<C, N> {
    pub fn new() -> Self {
        Self {
            current: None,
            changes: None,
            tenant_id: None,
            changed_by: u32::MAX,
            pending_id: None,
        }
    }

    pub fn with_current(mut self, current: C) -> Self {
        self.current = Some(current);
        self
    }

    pub fn with_changes(mut self, changes: N) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_pending_id(mut self, slot: Slot) -> Self {
        self.pending_id = Some(slot);
        self
    }

    pub fn with_pending_id_opt(mut self, slot: Option<Slot>) -> Self {
        self.pending_id = slot;
        self
    }

    pub fn with_current_opt(mut self, current: Option<C>) -> Self {
        self.current = current;
        self
    }

    pub fn changes(&self) -> Option<&N> {
        self.changes.as_ref()
    }

    pub fn changes_mut(&mut self) -> Option<&mut N> {
        self.changes.as_mut()
    }

    pub fn current(&self) -> Option<&C> {
        self.current.as_ref()
    }

    pub fn with_changed_by(mut self, ids: AccountTenantIds) -> Self {
        self.tenant_id = ids.tenant_id;
        self.changed_by = ids.account_id;
        self
    }

    pub fn with_tenant_id(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant_id = tenant_id;
        self
    }
}

impl<C: CurrentObject, N: SerializableObject> IntoOperations for ObjectIndexBuilder<C, N> {
    fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        match (self.current, self.changes) {
            (None, Some(changes)) => {
                // Insertion
                for item in changes.index_values() {
                    build_index(batch, item, self.changed_by, self.tenant_id, true);
                }
                changes.serialize_into(batch, self.pending_id)?;
            }
            (Some(current), Some(changes)) => {
                // Update
                current.assert(batch);
                for (current, change) in current.index_values().zip(changes.index_values()) {
                    if current != change {
                        merge_index(batch, current, change, self.changed_by, self.tenant_id)?;
                    } else {
                        match current {
                            IndexValue::LogContainer { sync_collection } => {
                                batch.log_container_update(sync_collection);
                            }
                            IndexValue::LogItem {
                                sync_collection,
                                prefix,
                            } => {
                                batch.log_item_update(sync_collection, prefix);
                            }
                            _ => (),
                        }
                    }
                }
                changes.serialize_into(batch, self.pending_id)?;
            }
            (Some(current), None) => {
                // Deletion
                current.assert(batch);
                for item in current.index_values() {
                    build_index(batch, item, self.changed_by, self.tenant_id, false);
                }
                current.clear(batch);
            }
            (None, None) => unreachable!(),
        }

        Ok(())
    }
}
