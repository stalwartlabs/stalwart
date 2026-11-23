/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::time::EasDateForm;
use crate::eas::commands::appdata::ApplicationData;
use crate::eas::status::SyncStatus;
use crate::eas::tokens::Tag;
use crate::eas::tokens::tag::{airsync as sync, airsyncbase as asb};
use crate::eas::types::{Class, EasDateTime};
use crate::eas::wbxml::Encoder;

#[derive(Debug, Clone, PartialEq)]
pub struct SyncResponse<'x> {
    pub status: Option<SyncStatus>,
    pub body: SyncResponseBody<'x>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncResponseBody<'x> {
    Limit(u32),
    Collections(Vec<SyncResponseCollection<'x>>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SyncResponseCollection<'x> {
    pub sync_key: &'x str,
    pub collection_id: &'x str,
    pub status: SyncStatus,
    pub responses: Vec<SyncItemResponse<'x>>,
    pub more_available: bool,
    pub commands: Vec<ServerCommand<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncItemResponse<'x> {
    Add {
        class: Option<Class>,
        client_id: &'x str,
        server_id: Option<&'x str>,
        status: SyncStatus,
        data: Option<ApplicationData<'x>>,
    },
    Change {
        server_id: &'x str,
        instance_id: Option<EasDateTime>,
        status: SyncStatus,
    },
    Delete {
        server_id: &'x str,
        instance_id: Option<EasDateTime>,
        status: SyncStatus,
    },
    Fetch {
        server_id: Option<&'x str>,
        status: SyncStatus,
        data: Option<ApplicationData<'x>>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServerCommand<'x> {
    Add {
        server_id: &'x str,
        data: ApplicationData<'x>,
    },
    Change {
        server_id: &'x str,
        data: ApplicationData<'x>,
    },
    Delete {
        server_id: &'x str,
    },
    SoftDelete {
        server_id: &'x str,
    },
}

impl SyncResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(sync::SYNC);
        if let Some(status) = self.status {
            enc.text_u64(sync::STATUS, u64::from(status.0));
        }
        match &self.body {
            SyncResponseBody::Limit(limit) => {
                enc.text_u64(sync::LIMIT, u64::from(*limit));
            }
            SyncResponseBody::Collections(collections) if !collections.is_empty() => {
                enc.start(sync::COLLECTIONS);
                for collection in collections {
                    collection.encode(enc);
                }
                enc.end();
            }
            SyncResponseBody::Collections(_) => {}
        }
        enc.end();
    }
}

impl SyncItemResponse<'_> {
    const RANKS: u8 = 4;

    fn rank(&self) -> u8 {
        match self {
            SyncItemResponse::Change { .. } => 0,
            SyncItemResponse::Add { .. } => 1,
            SyncItemResponse::Delete { .. } => 2,
            SyncItemResponse::Fetch { .. } => 3,
        }
    }
}

impl SyncResponseCollection<'_> {
    fn encode(&self, enc: &mut Encoder) {
        enc.start(sync::COLLECTION)
            .text_str(sync::SYNC_KEY, self.sync_key)
            .text_str(sync::COLLECTION_ID, self.collection_id)
            .text_u64(sync::STATUS, u64::from(self.status.0));
        if !self.responses.is_empty() {
            enc.start(sync::RESPONSES);
            for rank in 0..SyncItemResponse::RANKS {
                for response in self.responses.iter().filter(|r| r.rank() == rank) {
                    response.encode(enc);
                }
            }
            enc.end();
        }
        if self.more_available {
            enc.empty(sync::MORE_AVAILABLE);
        }
        if !self.commands.is_empty() {
            enc.start(sync::COMMANDS);
            for command in &self.commands {
                command.encode(enc);
            }
            enc.end();
        }
        enc.end();
    }
}

fn encode_instance_id(enc: &mut Encoder, instance_id: Option<EasDateTime>) {
    if let Some(instance_id) = instance_id
        && enc.allows(asb::INSTANCE_ID)
    {
        enc.text_with(asb::INSTANCE_ID, |out| {
            instance_id.write(out, EasDateForm::Punctuated)
        });
    }
}

fn encode_data(enc: &mut Encoder, data: &ApplicationData<'_>) {
    enc.start(sync::APPLICATION_DATA);
    data.encode_fields(enc);
    enc.end();
}

impl SyncItemResponse<'_> {
    fn encode(&self, enc: &mut Encoder) {
        match self {
            SyncItemResponse::Add {
                class,
                client_id,
                server_id,
                status,
                data,
            } => {
                enc.start(sync::ADD);
                if let Some(class) = class {
                    enc.text_str(sync::CLASS, class.as_str());
                }
                enc.text_str(sync::CLIENT_ID, client_id);
                if let Some(server_id) = server_id {
                    enc.text_str(sync::SERVER_ID, server_id);
                }
                enc.text_u64(sync::STATUS, u64::from(status.0));
                if let Some(data) = data {
                    encode_data(enc, data);
                }
                enc.end();
            }
            SyncItemResponse::Change {
                server_id,
                instance_id,
                status,
            } => encode_item_status(enc, sync::CHANGE, server_id, *instance_id, *status),
            SyncItemResponse::Delete {
                server_id,
                instance_id,
                status,
            } => encode_item_status(enc, sync::DELETE, server_id, *instance_id, *status),
            SyncItemResponse::Fetch {
                server_id,
                status,
                data,
            } => {
                enc.start(sync::FETCH);
                if let Some(server_id) = server_id {
                    enc.text_str(sync::SERVER_ID, server_id);
                }
                enc.text_u64(sync::STATUS, u64::from(status.0));
                if let Some(data) = data {
                    encode_data(enc, data);
                }
                enc.end();
            }
        }
    }
}

fn encode_item_status(
    enc: &mut Encoder,
    tag: Tag,
    server_id: &str,
    instance_id: Option<EasDateTime>,
    status: SyncStatus,
) {
    enc.start(tag).text_str(sync::SERVER_ID, server_id);
    encode_instance_id(enc, instance_id);
    enc.text_u64(sync::STATUS, u64::from(status.0)).end();
}

impl ServerCommand<'_> {
    fn encode(&self, enc: &mut Encoder) {
        match self {
            ServerCommand::Add { server_id, data } => {
                enc.start(sync::ADD).text_str(sync::SERVER_ID, server_id);
                encode_data(enc, data);
                enc.end();
            }
            ServerCommand::Change { server_id, data } => {
                enc.start(sync::CHANGE).text_str(sync::SERVER_ID, server_id);
                encode_data(enc, data);
                enc.end();
            }
            ServerCommand::Delete { server_id } => {
                enc.start(sync::DELETE)
                    .text_str(sync::SERVER_ID, server_id)
                    .end();
            }
            ServerCommand::SoftDelete { server_id } => {
                enc.start(sync::SOFT_DELETE)
                    .text_str(sync::SERVER_ID, server_id)
                    .end();
            }
        }
    }
}
