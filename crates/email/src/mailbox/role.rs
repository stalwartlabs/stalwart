/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{INBOX_ID, JUNK_ID, TRASH_ID};
use crate::cache::mailbox::MailboxCacheAccess;
use common::MessageStoreCache;
use std::fmt::{self, Display};
use types::special_use::SpecialUse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleChange {
    Create {
        role: SpecialUse,
    },
    Update {
        document_id: u32,
        current: SpecialUse,
        role: SpecialUse,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleChangeError {
    InUse(SpecialUse),
    Protected,
}

impl RoleChange {
    pub fn validate(self, cache: &MessageStoreCache) -> Result<(), RoleChangeError> {
        let role = match self {
            RoleChange::Update { current, role, .. } if current == role => return Ok(()),
            RoleChange::Create { role } | RoleChange::Update { role, .. } => role,
        };

        if role != SpecialUse::None && cache.mailbox_by_role(&role).is_some() {
            Err(RoleChangeError::InUse(role))
        } else if let RoleChange::Update {
            document_id: INBOX_ID | TRASH_ID | JUNK_ID,
            ..
        } = self
        {
            Err(RoleChangeError::Protected)
        } else {
            Ok(())
        }
    }
}

impl Display for RoleChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleChangeError::InUse(role) => write!(
                f,
                "A mailbox with role '{}' already exists.",
                role.as_str().unwrap_or_default()
            ),
            RoleChangeError::Protected => f.write_str(
                "You are not allowed to change the role of Inbox, Junk or Trash folders.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RoleChange, RoleChangeError};
    use crate::mailbox::{DRAFTS_ID, INBOX_ID, JUNK_ID, SENT_ID, TRASH_ID};
    use common::{MailboxCache, MailboxesCache, MessageStoreCache, MessagesCache, UpdateLock};
    use std::sync::Arc;
    use types::{metadata::MetadataKinds, special_use::SpecialUse};

    fn cache(roles: &[(u32, SpecialUse)]) -> MessageStoreCache {
        MessageStoreCache {
            emails: Arc::new(MessagesCache::new(1, Vec::new(), Vec::new())),
            mailboxes: Arc::new(MailboxesCache {
                change_id: 1,
                index: roles
                    .iter()
                    .zip(0u32..)
                    .map(|((document_id, _), position)| (*document_id, position))
                    .collect(),
                items: roles
                    .iter()
                    .map(|(document_id, role)| MailboxCache {
                        document_id: *document_id,
                        name: format!("mailbox {document_id}"),
                        path: format!("mailbox {document_id}"),
                        role: *role,
                        parent_id: 0,
                        sort_order: 0,
                        subscribers: Default::default(),
                        uid_validity: 0,
                        acls: Default::default(),
                        metadata_kinds: MetadataKinds::NONE,
                    })
                    .collect(),
                size: 0,
            }),
            update_lock: Arc::new(UpdateLock::new()),
            last_change_id: 1,
            size: 0,
            verification: Default::default(),
        }
    }

    #[test]
    fn roles_are_unique_and_system_roles_are_fixed() {
        let cache = cache(&[
            (INBOX_ID, SpecialUse::Inbox),
            (TRASH_ID, SpecialUse::Trash),
            (JUNK_ID, SpecialUse::Junk),
            (DRAFTS_ID, SpecialUse::Drafts),
            (SENT_ID, SpecialUse::None),
        ]);
        let update = |document_id, current, role| RoleChange::Update {
            document_id,
            current,
            role,
        };

        for (change, expected) in [
            (
                RoleChange::Create {
                    role: SpecialUse::Sent,
                },
                Ok(()),
            ),
            (
                RoleChange::Create {
                    role: SpecialUse::None,
                },
                Ok(()),
            ),
            (
                RoleChange::Create {
                    role: SpecialUse::Drafts,
                },
                Err(RoleChangeError::InUse(SpecialUse::Drafts)),
            ),
            (update(SENT_ID, SpecialUse::None, SpecialUse::Sent), Ok(())),
            (
                update(DRAFTS_ID, SpecialUse::Drafts, SpecialUse::Drafts),
                Ok(()),
            ),
            (
                update(DRAFTS_ID, SpecialUse::Drafts, SpecialUse::None),
                Ok(()),
            ),
            (
                update(SENT_ID, SpecialUse::None, SpecialUse::Drafts),
                Err(RoleChangeError::InUse(SpecialUse::Drafts)),
            ),
            (
                update(TRASH_ID, SpecialUse::Trash, SpecialUse::None),
                Err(RoleChangeError::Protected),
            ),
            (
                update(INBOX_ID, SpecialUse::Inbox, SpecialUse::Archive),
                Err(RoleChangeError::Protected),
            ),
            (update(JUNK_ID, SpecialUse::Junk, SpecialUse::Junk), Ok(())),
        ] {
            assert_eq!(change.validate(&cache), expected, "{change:?}");
        }

        assert_eq!(
            RoleChangeError::InUse(SpecialUse::Drafts).to_string(),
            "A mailbox with role 'drafts' already exists."
        );
    }
}
