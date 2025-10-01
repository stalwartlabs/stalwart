/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod blob;
pub mod blob_hash;
pub mod collection;
pub mod field;
pub mod id;
pub mod keyword;
pub mod semver;
pub mod special_use;
pub mod type_state;

pub type DocumentId = u32;
pub type ChangeId = u64;
