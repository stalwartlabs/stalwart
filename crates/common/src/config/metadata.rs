/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::{enums::MetadataDataType, structs::Metadata};
use store::registry::bootstrap::Bootstrap;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

#[derive(Default, Clone)]
pub struct MetadataConfig {
    pub data_types: Bitmap<DataType>,
    pub vendor_namespaces: bool,
    pub private_metadata: bool,
    pub max_depth: Option<u32>,
    pub max_entry_size: usize,
    pub max_size: usize,
    pub max_private_size: usize,
    pub max_entries: usize,
    pub query_max_scan: usize,
    pub imap_server_comment: Option<String>,
    pub imap_server_admin: Option<String>,
}

impl MetadataConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let metadata = bp.setting_infallible::<Metadata>().await;

        MetadataConfig {
            data_types: metadata
                .data_types
                .iter()
                .map(|data_type| match data_type {
                    MetadataDataType::Email => DataType::Email,
                    MetadataDataType::Mailbox => DataType::Mailbox,
                    MetadataDataType::SieveScript => DataType::SieveScript,
                    MetadataDataType::Calendar => DataType::Calendar,
                    MetadataDataType::CalendarEvent => DataType::CalendarEvent,
                    MetadataDataType::AddressBook => DataType::AddressBook,
                    MetadataDataType::ContactCard => DataType::ContactCard,
                    MetadataDataType::FileNode => DataType::FileNode,
                })
                .collect(),
            vendor_namespaces: metadata.vendor_namespaces,
            private_metadata: metadata.private_metadata,
            max_depth: metadata
                .max_depth
                .map(|depth| depth.min(u32::MAX as u64) as u32),
            max_entry_size: metadata.max_entry_size as usize,
            max_size: metadata.max_size as usize,
            max_private_size: metadata.max_private_size as usize,
            max_entries: metadata.max_entries as usize,
            query_max_scan: metadata.query_max_scan as usize,
            imap_server_comment: metadata.imap_server_comment,
            imap_server_admin: metadata.imap_server_admin,
        }
    }
}
