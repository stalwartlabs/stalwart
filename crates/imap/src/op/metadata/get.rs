/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    READ_RIGHTS, SERVER_DOCUMENT_ID, SPECIAL_USE_ENTRY, reads_private_container,
    select::{EntrySource, PrivateEntries, SelectOptions, select_entries},
    special_use_value,
};
use crate::{core::SessionData, op::ImapContext};
use common::network::SessionStream;
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::metadata::{GetArguments, MetadataCode, Response, Scope},
};
use registry::schema::enums::Permission;
use std::time::Instant;
use types::{collection::Collection, metadata::MetadataKinds, special_use::SpecialUse};

const ADMIN_ENTRY: &str = "/admin";
const COMMENT_ENTRY: &str = "/comment";

impl<T: SessionStream> SessionData<T> {
    pub async fn get_metadata(
        &self,
        arguments: GetArguments,
        is_utf8: bool,
        op_start: Instant,
    ) -> trc::Result<()> {
        let tag = arguments.tag.as_str();
        self.assert_metadata_request(tag, arguments.entries.len())?;

        let access_token = self
            .refresh_access_token()
            .await
            .imap_ctx(tag, trc::location!())?;
        let viewer = self
            .server
            .metadata_viewer(&access_token, Permission::ImapMetadataPrivate);
        let has_shared = arguments
            .entries
            .iter()
            .any(|entry| entry.scope == Scope::Shared);
        let has_private = viewer.is_some()
            && arguments
                .entries
                .iter()
                .any(|entry| entry.scope == Scope::Private);

        let (shared, private, role, mailbox_id) = if arguments.mailbox_name.is_empty() {
            let private = match viewer {
                Some(viewer) if has_private => self
                    .server
                    .metadata_container(
                        viewer.account_id(),
                        Collection::Principal,
                        SERVER_DOCUMENT_ID,
                    )
                    .await
                    .imap_ctx(tag, trc::location!())?,
                _ => None,
            };
            (None, private, SpecialUse::None, None)
        } else {
            let mailbox = self
                .metadata_mailbox(tag, &arguments.mailbox_name, &access_token)
                .await?;
            mailbox.assert_rights(tag, &READ_RIGHTS)?;

            let shared = if has_shared && mailbox.kinds.contains(MetadataKinds::IMAP) {
                self.server
                    .metadata_container(mailbox.account_id, Collection::Mailbox, mailbox.mailbox_id)
                    .await
                    .imap_ctx(tag, trc::location!())?
            } else {
                None
            };
            let private = match viewer {
                Some(viewer)
                    if reads_private_container(&arguments.entries, arguments.depth)
                        && self
                            .server
                            .metadata_viewer_state(viewer, mailbox.account_id, Collection::Mailbox)
                            .await
                            .imap_ctx(tag, trc::location!())?
                            .containers
                            > 0 =>
                {
                    self.server
                        .private_metadata_container(
                            mailbox.account_id,
                            viewer.account_id(),
                            Collection::Mailbox,
                            mailbox.mailbox_id,
                        )
                        .await
                        .imap_ctx(tag, trc::location!())?
                }
                _ => None,
            };
            (shared, private, mailbox.role, Some(mailbox.id()))
        };

        let shared_source = match &shared {
            Some(container) => EntrySource::new(container.view().imap()),
            None if arguments.mailbox_name.is_empty() => {
                let metadata = &self.server.core.metadata;
                EntrySource::new(
                    [
                        (ADMIN_ENTRY, metadata.imap_server_admin.as_deref()),
                        (COMMENT_ENTRY, metadata.imap_server_comment.as_deref()),
                    ]
                    .into_iter()
                    .filter_map(|(name, value)| value.map(|value| (name, value.as_bytes()))),
                )
            }
            None => EntrySource::default(),
        };
        let mut private_source = private
            .as_ref()
            .map(|container| EntrySource::new(container.view().imap()))
            .unwrap_or_default();
        if let Some(value) = special_use_value(role) {
            private_source.insert(SPECIAL_USE_ENTRY, value);
        }
        let private_entries = match viewer {
            Some(_) => PrivateEntries::All(&private_source),
            None if arguments.mailbox_name.is_empty() => PrivateEntries::Hidden,
            None => PrivateEntries::SpecialUse(&private_source),
        };

        let selection = select_entries(
            &arguments.entries,
            SelectOptions {
                depth: arguments.depth,
                max_size: arguments.max_size,
            },
            &shared_source,
            private_entries,
        );

        let total = selection.entries.len();
        let mut buf = Vec::with_capacity(128);
        if !selection.entries.is_empty() {
            Response {
                mailbox_name: &arguments.mailbox_name,
                entries: selection.entries,
            }
            .serialize(&mut buf, is_utf8);
        }
        let response = StatusResponse::completed(Command::GetMetadata).with_tag(tag);
        let response = match selection.longest {
            Some(longest) => {
                response.with_code(ResponseCode::Metadata(MetadataCode::LongEntries(longest)))
            }
            None => response,
        };

        trc::event!(
            Imap(trc::ImapEvent::GetMetadata),
            SpanId = self.session_id,
            MailboxName = arguments.mailbox_name,
            AccountId = mailbox_id.map(|id| id.account_id),
            MailboxId = mailbox_id.map(|id| id.mailbox_id),
            Total = total,
            Elapsed = op_start.elapsed()
        );

        self.write_bytes(response.serialize(buf)).await
    }
}
