/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::{ArchivedItem, UTCDateTime};
use types::{blob::BlobId, id::Id};

impl ArchivedItem {
    pub fn account_id(&self) -> Id {
        match self {
            ArchivedItem::Email(i) => i.account_id,
            ArchivedItem::FileNode(i) => i.account_id,
            ArchivedItem::CalendarEvent(i) => i.account_id,
            ArchivedItem::ContactCard(i) => i.account_id,
            ArchivedItem::SieveScript(i) => i.account_id,
        }
    }

    pub fn blob_id(&self) -> &BlobId {
        match self {
            ArchivedItem::Email(i) => &i.blob_id,
            ArchivedItem::FileNode(i) => &i.blob_id,
            ArchivedItem::CalendarEvent(i) => &i.blob_id,
            ArchivedItem::ContactCard(i) => &i.blob_id,
            ArchivedItem::SieveScript(i) => &i.blob_id,
        }
    }

    pub fn archived_until(&self) -> UTCDateTime {
        match self {
            ArchivedItem::Email(i) => i.archived_until,
            ArchivedItem::FileNode(i) => i.archived_until,
            ArchivedItem::CalendarEvent(i) => i.archived_until,
            ArchivedItem::ContactCard(i) => i.archived_until,
            ArchivedItem::SieveScript(i) => i.archived_until,
        }
    }

    pub fn created_at(&self) -> UTCDateTime {
        match self {
            ArchivedItem::Email(i) => i.received_at,
            ArchivedItem::FileNode(i) => i.created_at,
            ArchivedItem::CalendarEvent(i) => i.created_at,
            ArchivedItem::ContactCard(i) => i.created_at,
            ArchivedItem::SieveScript(i) => i.created_at,
        }
    }

    pub fn set_account_id(&mut self, value: Id) {
        match self {
            ArchivedItem::Email(i) => i.account_id = value,
            ArchivedItem::FileNode(i) => i.account_id = value,
            ArchivedItem::CalendarEvent(i) => i.account_id = value,
            ArchivedItem::ContactCard(i) => i.account_id = value,
            ArchivedItem::SieveScript(i) => i.account_id = value,
        }
    }

    pub fn set_blob_id(&mut self, value: BlobId) {
        match self {
            ArchivedItem::Email(i) => i.blob_id = value,
            ArchivedItem::FileNode(i) => i.blob_id = value,
            ArchivedItem::CalendarEvent(i) => i.blob_id = value,
            ArchivedItem::ContactCard(i) => i.blob_id = value,
            ArchivedItem::SieveScript(i) => i.blob_id = value,
        }
    }

    pub fn set_archived_until(&mut self, value: UTCDateTime) {
        match self {
            ArchivedItem::Email(i) => i.archived_until = value,
            ArchivedItem::FileNode(i) => i.archived_until = value,
            ArchivedItem::CalendarEvent(i) => i.archived_until = value,
            ArchivedItem::ContactCard(i) => i.archived_until = value,
            ArchivedItem::SieveScript(i) => i.archived_until = value,
        }
    }

    pub fn account_id_mut(&mut self) -> &mut Id {
        match self {
            ArchivedItem::Email(i) => &mut i.account_id,
            ArchivedItem::FileNode(i) => &mut i.account_id,
            ArchivedItem::CalendarEvent(i) => &mut i.account_id,
            ArchivedItem::ContactCard(i) => &mut i.account_id,
            ArchivedItem::SieveScript(i) => &mut i.account_id,
        }
    }

    pub fn blob_id_mut(&mut self) -> &mut BlobId {
        match self {
            ArchivedItem::Email(i) => &mut i.blob_id,
            ArchivedItem::FileNode(i) => &mut i.blob_id,
            ArchivedItem::CalendarEvent(i) => &mut i.blob_id,
            ArchivedItem::ContactCard(i) => &mut i.blob_id,
            ArchivedItem::SieveScript(i) => &mut i.blob_id,
        }
    }

    pub fn archived_until_mut(&mut self) -> &mut UTCDateTime {
        match self {
            ArchivedItem::Email(i) => &mut i.archived_until,
            ArchivedItem::FileNode(i) => &mut i.archived_until,
            ArchivedItem::CalendarEvent(i) => &mut i.archived_until,
            ArchivedItem::ContactCard(i) => &mut i.archived_until,
            ArchivedItem::SieveScript(i) => &mut i.archived_until,
        }
    }

    pub fn into_blob_id(self) -> BlobId {
        match self {
            ArchivedItem::Email(i) => i.blob_id,
            ArchivedItem::FileNode(i) => i.blob_id,
            ArchivedItem::CalendarEvent(i) => i.blob_id,
            ArchivedItem::ContactCard(i) => i.blob_id,
            ArchivedItem::SieveScript(i) => i.blob_id,
        }
    }
}
