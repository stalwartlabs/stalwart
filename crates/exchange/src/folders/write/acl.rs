/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderWriteError, FolderWritten, WritableFolder, WriteOutcome, commit,
    groupware::read_container,
};
use common::{
    Server,
    auth::AccessToken,
    sharing::{
        EffectiveAcl,
        grants::{AclGrantLookup, ShareUpdate, ShareViolation},
    },
    storage::index::ObjectIndexBuilder,
};
use email::mailbox::Mailbox;
use groupware::{calendar::Calendar, contact::AddressBook};
use store::write::BatchBuilder;
use trc::AddContext;
use types::acl::{Acl, AclGrant};
use utils::map::bitmap::Bitmap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclWriteError {
    Folder(FolderWriteError),
    TooManyShares,
    InvalidGrantee(u32),
}

pub type AclWriteResult = trc::Result<Result<FolderWritten, AclWriteError>>;

pub type AclEdit<'x> = &'x (dyn Fn(&[AclGrant]) -> Vec<AclGrant> + Sync);

impl From<FolderWriteError> for AclWriteError {
    fn from(err: FolderWriteError) -> Self {
        AclWriteError::Folder(err)
    }
}

fn share_actor(
    access_token: &AccessToken,
    account_id: u32,
    acl: impl FnOnce() -> Bitmap<Acl>,
) -> Result<Option<Bitmap<Acl>>, AclWriteError> {
    match (!access_token.is_member(account_id)).then(acl) {
        Some(actor) if !actor.contains(Acl::Share) => Err(FolderWriteError::Forbidden.into()),
        actor => Ok(actor),
    }
}

pub(super) async fn set_acl(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    kind: WritableFolder,
    document_id: u32,
    edit: AclEdit<'_>,
) -> AclWriteResult {
    let unchanged = Ok(Ok(FolderWritten {
        folder: kind.folder_ref(document_id),
        change_id: None,
        outcome: WriteOutcome::Written,
    }));
    let Some(archive) = read_container(server, account_id, kind, document_id).await? else {
        return Ok(Err(FolderWriteError::NotFound.into()));
    };
    let changed_by = access_token.changed_by();
    let mut batch = BatchBuilder::new();
    match kind {
        WritableFolder::Mailbox => {
            let current = archive
                .into_deserialized::<Mailbox>()
                .caused_by(trc::location!())?;
            let current_acls = current.inner.acls.as_slice();
            let actor = match share_actor(access_token, account_id, || {
                current_acls.effective_acl(access_token)
            }) {
                Ok(actor) => actor,
                Err(err) => return Ok(Err(err)),
            };
            let acls = edit(current_acls);
            if acls == current_acls {
                return unchanged;
            }
            if let Err(err) = validate_grants(
                server,
                access_token,
                kind,
                account_id,
                actor,
                &acls,
                current_acls,
            )
            .await?
            {
                return Ok(Err(err));
            }
            let mut changes = current.inner.clone();
            changes.acls = acls;
            batch
                .with_account_id(account_id)
                .with_collection(kind.collection())
                .with_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_changes(changes)
                        .with_current(current)
                        .with_changed_by(changed_by),
                )
                .caused_by(trc::location!())?;
        }
        WritableFolder::Calendar => {
            let calendar = archive
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;
            let actor = match share_actor(access_token, account_id, || {
                calendar.inner.acls.effective_acl(access_token)
            }) {
                Ok(actor) => actor,
                Err(err) => return Ok(Err(err)),
            };
            let mut new_calendar = calendar
                .deserialize::<Calendar>()
                .caused_by(trc::location!())?;
            let acls = edit(&new_calendar.acls);
            if acls == new_calendar.acls {
                return unchanged;
            }
            if let Err(err) = validate_grants(
                server,
                access_token,
                kind,
                account_id,
                actor,
                &acls,
                &new_calendar.acls,
            )
            .await?
            {
                return Ok(Err(err));
            }
            new_calendar.acls = acls;
            new_calendar
                .update(changed_by, calendar, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
        }
        WritableFolder::AddressBook => {
            let book = archive
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;
            let actor = match share_actor(access_token, account_id, || {
                book.inner.acls.effective_acl(access_token)
            }) {
                Ok(actor) => actor,
                Err(err) => return Ok(Err(err)),
            };
            let mut new_book = book
                .deserialize::<AddressBook>()
                .caused_by(trc::location!())?;
            let acls = edit(&new_book.acls);
            if acls == new_book.acls {
                return unchanged;
            }
            if let Err(err) = validate_grants(
                server,
                access_token,
                kind,
                account_id,
                actor,
                &acls,
                &new_book.acls,
            )
            .await?
            {
                return Ok(Err(err));
            }
            new_book.acls = acls;
            new_book
                .update(changed_by, book, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
        }
        WritableFolder::Virtual => return Ok(Err(FolderWriteError::Unsupported.into())),
    }
    Ok(commit(server, account_id, kind, batch, |_| document_id)
        .await?
        .map_err(AclWriteError::from))
}

#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
async fn validate_grants(
    server: &Server,
    access_token: &AccessToken,
    kind: WritableFolder,
    owner_id: u32,
    actor: Option<Bitmap<Acl>>,
    grants: &[AclGrant],
    current: &[AclGrant],
) -> trc::Result<Result<(), AclWriteError>> {
    let update = ShareUpdate {
        collection: kind.collection(),
        owner_id,
        actor,
        current,
        max_shares: server.core.groupware.max_shares_per_item,
    };
    if let Err(violation) = update.validate(grants) {
        return Ok(Err(match violation {
            ShareViolation::TooManyShares(_) => AclWriteError::TooManyShares,
            ShareViolation::OwnerShared => AclWriteError::InvalidGrantee(owner_id),
            ShareViolation::RightNotHeld => FolderWriteError::Forbidden.into(),
        }));
    }
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let mut owner_tenant_id = None;
    // SPDX-SnippetEnd
    for grant in grants {
        if !current.grants_of(grant.account_id).is_empty() {
            continue;
        }
        #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
        let Some(grantee) = server
            .try_account(grant.account_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(AclWriteError::InvalidGrantee(grant.account_id)));
        };
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        {
            let owner_tenant_id = match owner_tenant_id {
                Some(tenant_id) => tenant_id,
                None if access_token.is_account_id(owner_id) => {
                    *owner_tenant_id.insert(access_token.tenant_id())
                }
                None => *owner_tenant_id.insert(
                    server
                        .account(owner_id)
                        .await
                        .caused_by(trc::location!())?
                        .tenant_id(),
                ),
            };
            if grantee.tenant_id() != owner_tenant_id {
                return Ok(Err(AclWriteError::InvalidGrantee(grant.account_id)));
            }
        }
        // SPDX-SnippetEnd
    }
    Ok(Ok(()))
}
