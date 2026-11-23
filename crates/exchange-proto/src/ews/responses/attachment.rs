/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::types::{ids::ItemId, item::attachment::Attachment, value::M},
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttachmentInfoMessage<'x> {
    pub attachments: Vec<Attachment<'x>>,
}

impl ResponseMessage for AttachmentInfoMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "Attachments");
        for attachment in &self.attachments {
            attachment.write(w);
        }
        w.end(M, "Attachments");
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        w.start(M, "Attachments");
        w.end(M, "Attachments");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeleteAttachmentMessage<'x> {
    pub root_item_id: Option<ItemId<'x>>,
}

impl ResponseMessage for DeleteAttachmentMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(root) = &self.root_item_id {
            w.start(M, "RootItemId")
                .attr("RootItemId", root.id.as_str());
            if let Some(change_key) = &root.change_key {
                w.attr("RootItemChangeKey", change_key.as_str());
            }
            w.empty();
        }
    }
}
