/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MetadataMailbox, READ_RIGHTS, SERVER_DOCUMENT_ID, SPECIAL_USE_ENTRY,
    edit::{ContainerUpdate, edit_container},
    mailbox_not_found, metadata_error, special_use_value,
};
use crate::{
    core::{MailboxId, SessionData},
    op::{ImapContext, create::attr_to_role},
};
use common::{
    auth::{AccessToken, AccountCache},
    network::SessionStream,
    storage::{
        index::ObjectIndexBuilder,
        metadata::{
            MetadataLog, MetadataPresence, MetadataViewer, MetadataWrite, PrivateMetadataCommit,
            PrivateMetadataWrite, StoredContainer,
        },
    },
};
use compact_str::CompactString;
use email::{
    mailbox::{Mailbox, role::RoleChange},
    presence::update_mailbox_presence,
};
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::{
        list::Attribute,
        metadata::{EntryValue, MetadataCode, Scope, SetArguments},
    },
};
use registry::schema::enums::Permission;
use std::time::Instant;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, metadata::MetadataBuf},
};
use types::{
    acl::Acl,
    collection::Collection,
    metadata::{EncodedMetadata, MetadataEdit, MetadataScope},
    special_use::SpecialUse,
};

const SHARED_WRITE_RIGHTS: [Acl; 1] = [Acl::ModifyItems];
const ROLE_RIGHTS: [Acl; 1] = [Acl::Modify];

struct ContainerWrite {
    previous: Option<StoredContainer>,
    next: Option<EncodedMetadata>,
    edit: MetadataEdit,
}

impl<T: SessionStream> SessionData<T> {
    pub async fn set_metadata(
        &self,
        arguments: SetArguments,
        op_start: Instant,
    ) -> trc::Result<StatusResponse> {
        let SetArguments {
            tag,
            mailbox_name,
            entries,
        } = arguments;
        let access_token = self
            .refresh_access_token()
            .await
            .imap_ctx(&tag, trc::location!())?;

        let has_shared = entries
            .iter()
            .any(|entry| entry.entry.scope == Scope::Shared);
        if has_shared {
            access_token
                .enforce_permission(Permission::ImapMetadataSet)
                .map_err(|err| err.id(tag.clone()))?;
        }
        let viewer = if needs_viewer(&mailbox_name, &entries) {
            Some(
                self.server
                    .imap_metadata_viewer(&access_token)
                    .ok_or_else(|| metadata_error(&tag, MetadataCode::NoPrivate))?,
            )
        } else {
            None
        };

        let mailbox_id = if mailbox_name.is_empty() {
            self.set_server_metadata(&tag, &entries, has_shared, viewer)
                .await?;
            None
        } else {
            Some(
                self.set_mailbox_metadata(&tag, &mailbox_name, &entries, viewer, &access_token)
                    .await?,
            )
        };

        trc::event!(
            Imap(trc::ImapEvent::SetMetadata),
            SpanId = self.session_id,
            MailboxName = mailbox_name,
            AccountId = mailbox_id.map(|id| id.account_id),
            MailboxId = mailbox_id.map(|id| id.mailbox_id),
            Total = entries.len(),
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::completed(Command::SetMetadata).with_tag(tag))
    }

    async fn set_server_metadata(
        &self,
        tag: &str,
        entries: &[EntryValue<'_>],
        has_shared: bool,
        viewer: Option<MetadataViewer>,
    ) -> trc::Result<()> {
        if has_shared {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("Shared server annotations are read-only.")
                .code(ResponseCode::NoPerm)
                .id(CompactString::from(tag)));
        }
        let Some(viewer) = viewer else {
            return Ok(());
        };

        let account_id = viewer.account_id();
        let previous = self
            .server
            .metadata_container(account_id, Collection::Principal, SERVER_DOCUMENT_ID)
            .await
            .imap_ctx(tag, trc::location!())?;
        let Some(write) = self.container_write(
            tag,
            previous.as_ref(),
            entries.iter().map(entry_value),
            MetadataScope::Private,
        )?
        else {
            return Ok(());
        };

        let account = self
            .server
            .account(account_id)
            .await
            .imap_ctx(tag, trc::location!())?;
        self.assert_metadata_quota(tag, &account, &write).await?;

        let mut batch = BatchBuilder::new();
        MetadataWrite {
            account_id,
            tenant_id: account.id_tenant,
            collection: Collection::Principal,
            document_id: SERVER_DOCUMENT_ID.into(),
            previous: write.previous,
            next: write.next,
            log: MetadataLog::None,
        }
        .build(&mut batch)
        .imap_ctx(tag, trc::location!())?;
        self.server
            .commit_batch(batch)
            .await
            .imap_ctx(tag, trc::location!())
            .map(|_| ())
    }

    async fn set_mailbox_metadata(
        &self,
        tag: &str,
        mailbox_name: &str,
        entries: &[EntryValue<'_>],
        viewer: Option<MetadataViewer>,
        access_token: &AccessToken,
    ) -> trc::Result<MailboxId> {
        let mailbox = self
            .metadata_mailbox(tag, mailbox_name, access_token)
            .await?;
        let shared_entries = entries
            .iter()
            .filter(|entry| entry.entry.scope == Scope::Shared)
            .map(entry_value);
        let private_entries = entries
            .iter()
            .filter(|entry| {
                entry.entry.scope == Scope::Private && entry.entry.path != SPECIAL_USE_ENTRY
            })
            .map(entry_value);
        let has_shared = shared_entries.clone().next().is_some();
        let has_private = private_entries.clone().next().is_some();

        if has_shared {
            mailbox.assert_rights(tag, &SHARED_WRITE_RIGHTS)?;
        }
        if has_private {
            mailbox.assert_rights(tag, &READ_RIGHTS)?;
        }
        let role = match entries.iter().find(|entry| {
            entry.entry.scope == Scope::Private && entry.entry.path == SPECIAL_USE_ENTRY
        }) {
            Some(entry) => self.special_use_change(tag, &mailbox, entry.value.as_deref())?,
            None => None,
        };

        let shared = if has_shared {
            let previous = if !mailbox.kinds.is_empty() {
                self.server
                    .metadata_container(mailbox.account_id, Collection::Mailbox, mailbox.mailbox_id)
                    .await
                    .imap_ctx(tag, trc::location!())?
            } else {
                None
            };
            self.container_write(
                tag,
                previous.as_ref(),
                shared_entries,
                MetadataScope::Shared,
            )?
        } else {
            None
        };
        let private = match viewer {
            Some(viewer) if has_private => {
                let previous = if self
                    .server
                    .metadata_viewer_state(viewer, mailbox.account_id, Collection::Mailbox)
                    .await
                    .imap_ctx(tag, trc::location!())?
                    .containers
                    > 0
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
                } else {
                    None
                };
                self.container_write(
                    tag,
                    previous.as_ref(),
                    private_entries,
                    MetadataScope::Private,
                )?
                .map(|write| (viewer, write))
            }
            _ => None,
        };

        let mut batch = BatchBuilder::new();
        let mut commit = PrivateMetadataCommit::default();
        let mut presence = None;
        if let Some(write) = shared {
            let owner = self
                .server
                .account(mailbox.account_id)
                .await
                .imap_ctx(tag, trc::location!())?;
            self.assert_metadata_quota(tag, &owner, &write).await?;
            presence = Some(
                MetadataWrite {
                    account_id: mailbox.account_id,
                    tenant_id: owner.id_tenant,
                    collection: Collection::Mailbox,
                    document_id: mailbox.mailbox_id.into(),
                    previous: write.previous,
                    next: write.next,
                    log: MetadataLog::Container,
                }
                .build(&mut batch)
                .imap_ctx(tag, trc::location!())?,
            );
        }
        if let Some((viewer, write)) = private {
            let account = self
                .server
                .account(viewer.account_id())
                .await
                .imap_ctx(tag, trc::location!())?;
            self.assert_metadata_quota(tag, &account, &write).await?;
            PrivateMetadataWrite {
                owner_id: mailbox.account_id,
                viewer_id: viewer.account_id(),
                viewer_tenant_id: account.id_tenant,
                collection: Collection::Mailbox,
                previous: write.previous,
                next: write.next,
                log: MetadataLog::Container,
            }
            .build(mailbox.mailbox_id.into(), &mut batch, &mut commit)
            .imap_ctx(tag, trc::location!())?;
        }

        let presence =
            presence.filter(|presence| presence.has_changed_for(Mailbox::TRACKED_METADATA));
        if role.is_some() || presence.is_some() {
            self.update_mailbox_archive(tag, &mailbox, role, presence, &mut batch)
                .await?;
        }

        if !batch.is_empty() {
            let assigned_ids = self
                .server
                .commit_batch(batch)
                .await
                .imap_ctx(tag, trc::location!())?;
            self.server
                .private_metadata_committed(commit, &assigned_ids)
                .await;
        }

        Ok(mailbox.id())
    }

    fn special_use_change(
        &self,
        tag: &str,
        mailbox: &MetadataMailbox,
        value: Option<&[u8]>,
    ) -> trc::Result<Option<SpecialUse>> {
        mailbox.assert_rights(tag, &ROLE_RIGHTS)?;
        let role = parse_special_use(value)
            .ok_or_else(|| use_attr_error(tag, "Unsupported special-use attribute.".to_string()))?;
        if role == SpecialUse::None && special_use_value(mailbox.role).is_none() {
            return Ok(None);
        }
        RoleChange::Update {
            document_id: mailbox.mailbox_id,
            current: mailbox.role,
            role,
        }
        .validate(&mailbox.cache)
        .map_err(|err| use_attr_error(tag, err.to_string()))?;
        Ok((role != mailbox.role).then_some(role))
    }

    fn container_write<'x>(
        &self,
        tag: &str,
        previous: Option<&'x MetadataBuf>,
        entries: impl Iterator<Item = (&'x str, Option<&'x [u8]>)> + Clone,
        scope: MetadataScope,
    ) -> trc::Result<Option<ContainerWrite>> {
        let (next, edit) = match edit_container(
            previous,
            entries,
            scope,
            &self.server.core.metadata.limits(),
        )
        .map_err(|code| metadata_error(tag, code))?
        {
            ContainerUpdate::Unchanged => return Ok(None),
            ContainerUpdate::Clear => (None, MetadataEdit::RemovalOnly),
            ContainerUpdate::Replace(container, edit) => (Some(container), edit),
        };
        Ok(Some(ContainerWrite {
            previous: previous.map(StoredContainer::from),
            next,
            edit,
        }))
    }

    async fn assert_metadata_quota(
        &self,
        tag: &str,
        account: &AccountCache,
        write: &ContainerWrite,
    ) -> trc::Result<()> {
        match &write.next {
            Some(next)
                if !self
                    .server
                    .has_metadata_quota(account, write.edit, write.previous.as_ref(), next)
                    .await
                    .imap_ctx(tag, trc::location!())? =>
            {
                Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Quota exceeded.")
                    .code(ResponseCode::OverQuota)
                    .id(CompactString::from(tag)))
            }
            _ => Ok(()),
        }
    }

    async fn update_mailbox_archive(
        &self,
        tag: &str,
        mailbox: &MetadataMailbox,
        role: Option<SpecialUse>,
        presence: Option<MetadataPresence>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let archive = self
            .server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                mailbox.account_id,
                Collection::Mailbox,
                mailbox.mailbox_id,
            ))
            .await
            .imap_ctx(tag, trc::location!())?
            .ok_or_else(|| mailbox_not_found(tag))?;
        let current = archive
            .to_unarchived::<Mailbox>()
            .imap_ctx(tag, trc::location!())?;

        match (role, presence) {
            (Some(role), presence) => {
                let mut changes = current
                    .deserialize::<Mailbox>()
                    .imap_ctx(tag, trc::location!())?;
                changes.role = role;
                if let Some(presence) = presence {
                    changes.set_metadata_kinds(presence.after);
                }
                batch
                    .with_account_id(mailbox.account_id)
                    .with_collection(Collection::Mailbox)
                    .with_document(mailbox.mailbox_id)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_current(current)
                            .with_changes(changes),
                    )
                    .imap_ctx(tag, trc::location!())?;
            }
            (None, Some(presence)) => {
                update_mailbox_presence(
                    batch,
                    mailbox.account_id,
                    mailbox.mailbox_id,
                    &current,
                    presence,
                )
                .imap_ctx(tag, trc::location!())?;
            }
            (None, None) => {}
        }

        Ok(())
    }
}

fn needs_viewer(mailbox_name: &str, entries: &[EntryValue<'_>]) -> bool {
    entries.iter().any(|entry| {
        entry.entry.scope == Scope::Private
            && (mailbox_name.is_empty() || entry.entry.path != SPECIAL_USE_ENTRY)
    })
}

fn entry_value<'x>(entry: &'x EntryValue<'_>) -> (&'x str, Option<&'x [u8]>) {
    (entry.entry.path.as_ref(), entry.value.as_deref())
}

fn use_attr_error(tag: &str, details: String) -> trc::Error {
    trc::ImapEvent::Error
        .into_err()
        .details(details)
        .code(ResponseCode::UseAttr)
        .id(CompactString::from(tag))
}

fn parse_special_use(value: Option<&[u8]>) -> Option<SpecialUse> {
    let mut role = SpecialUse::None;
    for attribute in value
        .unwrap_or_default()
        .split(u8::is_ascii_whitespace)
        .filter(|attribute| !attribute.is_empty())
    {
        let next = match Attribute::parse_special_use(attribute)? {
            Attribute::All => return None,
            attribute => attr_to_role(attribute),
        };
        if role != SpecialUse::None && role != next {
            return None;
        }
        role = next;
    }
    Some(role)
}

#[cfg(test)]
mod tests {
    use super::{needs_viewer, parse_special_use};
    use imap_proto::protocol::metadata::{Entry, EntryValue, Scope};
    use std::borrow::Cow;
    use types::special_use::SpecialUse;

    #[test]
    fn only_stored_private_entries_need_private_support() {
        let entries = |paths: &[(Scope, &'static str)]| {
            paths
                .iter()
                .map(|(scope, path)| EntryValue {
                    entry: Entry {
                        scope: *scope,
                        path: Cow::Borrowed(*path),
                    },
                    value: None,
                })
                .collect::<Vec<_>>()
        };
        let special_use = entries(&[(Scope::Shared, "/comment"), (Scope::Private, "/specialuse")]);
        let comment = entries(&[
            (Scope::Private, "/comment"),
            (Scope::Private, "/specialuse"),
        ]);
        let shared = entries(&[(Scope::Shared, "/comment")]);

        assert!(!needs_viewer("INBOX", &special_use));
        assert!(needs_viewer("", &special_use));
        assert!(needs_viewer("INBOX", &comment));
        assert!(needs_viewer("", &comment));
        assert!(!needs_viewer("INBOX", &shared));
        assert!(!needs_viewer("", &shared));
    }

    #[test]
    fn special_use_values_parse_into_one_role() {
        for (value, expected) in [
            (None, Some(SpecialUse::None)),
            (Some(&b""[..]), Some(SpecialUse::None)),
            (Some(b"  "), Some(SpecialUse::None)),
            (Some(b"\\Drafts"), Some(SpecialUse::Drafts)),
            (Some(b"\\sent"), Some(SpecialUse::Sent)),
            (Some(b" \\Trash \\Trash "), Some(SpecialUse::Trash)),
            (Some(b"\\Snoozed"), Some(SpecialUse::Snoozed)),
            (Some(b"\\Drafts \\Sent"), None),
            (Some(b"\\All"), None),
            (Some(b"\\Flagged"), None),
            (Some(b"Drafts"), None),
        ] {
            assert_eq!(parse_special_use(value), expected, "{value:?}");
        }
    }
}
