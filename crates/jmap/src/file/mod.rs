/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{GroupwareResources, Server, auth::AccountCache, storage::quota::ObjectQuotaUsage};
use jmap_proto::{error::set::SetError, object::file_node::FileNodeProperty};
use registry::schema::enums::StorageQuota;

pub mod copy;
pub mod get;
pub mod node;
pub mod query;
pub mod set;
pub mod writer;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ObjectCounts {
    pub files: usize,
    pub folders: usize,
}

pub(crate) struct FileNodeQuota {
    files: ObjectQuotaUsage,
    folders: ObjectQuotaUsage,
}

impl FileNodeQuota {
    pub(crate) fn new(server: &Server, account: &AccountCache, cache: &GroupwareResources) -> Self {
        let files_limit = server.object_quota_limit(account, StorageQuota::MaxFiles);
        let folders_limit = server.object_quota_limit(account, StorageQuota::MaxFolders);
        if files_limit.is_none() && folders_limit.is_none() {
            return Self::unlimited();
        }

        let folders = cache.resources.count(true);
        let files = cache.resources.len().saturating_sub(folders);
        let usage = |limit: Option<usize>, used| {
            limit.map_or_else(ObjectQuotaUsage::unlimited, |limit| ObjectQuotaUsage {
                used,
                limit,
            })
        };
        Self {
            files: usage(files_limit, files),
            folders: usage(folders_limit, folders),
        }
    }

    pub(crate) fn unlimited() -> Self {
        Self {
            files: ObjectQuotaUsage::unlimited(),
            folders: ObjectQuotaUsage::unlimited(),
        }
    }

    pub(crate) fn validate(
        &self,
        is_folder: bool,
        created: ObjectCounts,
        destroyed: ObjectCounts,
    ) -> Result<(), SetError<FileNodeProperty>> {
        let (usage, pending, released, description) = if is_folder {
            (
                &self.folders,
                created.folders,
                destroyed.folders,
                "There are too many folders, please delete some before adding a new one.",
            )
        } else {
            (
                &self.files,
                created.files,
                destroyed.files,
                "There are too many files, please delete some before adding a new one.",
            )
        };
        if (ObjectQuotaUsage {
            used: usage.used.saturating_sub(released),
            limit: usage.limit,
        })
        .has_room(pending)
        {
            Ok(())
        } else {
            Err(SetError::over_quota().with_description(description))
        }
    }
}
