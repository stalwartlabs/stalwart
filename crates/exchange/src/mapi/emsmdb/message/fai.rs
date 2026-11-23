/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    import::ImportSave,
    load::ClientVersion,
    object_row::{
        carry_creation_time, fai_properties, merge_properties, recipient_properties,
        stamp_creation_time,
    },
    save::{SaveMode, SaveTarget},
};
use crate::{
    cache::ExchangeCacheFetch,
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    folders::{FolderEntry, FolderNode, SpecialFolder},
    junk::{apply_junk_rule, junk_baseline, junk_rule},
    mapi::{
        emsmdb::{
            access::LogonAccess,
            execute::{RopContext, RopError},
            ics::import::MoveVersion,
            rules::is_rules_folder,
            state::MessageObject,
            store::extended_rule_size_limit,
        },
        ids::{ChangeSpace, IdSpace, MapiId},
    },
    store::{
        FolderKind, QuotaOwner,
        account::{ExchangeAccountStore, ExchangeCounter},
        folder::{
            ArchivedFaiMessage, FaiChange, FaiClientKey, FaiCommit, FaiFolder, FaiKind, FaiMessage,
            FaiNext, FaiRecipient, FaiWrite, FolderStore,
        },
        object::ObjectVersion,
    },
};
use exchange_proto::{
    common::{FileTime, UtcSeconds},
    convert::{
        model::{MessageContent, PropBag as ContentBag},
        tags::message_flags,
    },
    ids::ReplGuid,
    mapi::{
        ErrorCode,
        junk_rule::JunkLists,
        prop::{OwnedPropValue, PropKey, PropKeyRef, tags},
    },
};
use store::write::{Archive, ArchiveBytes, BatchBuilder, now};
use trc::{AddContext, EventType, LimitEvent};
use types::type_state::DataType;

pub const MSGFLAG_ASSOCIATED: i32 = 0x40;
const DEFAULT_FAI_CLASS: &str = "IPM";
const MAX_FAI_DELETES: usize = 256;

struct FaiSave {
    account_id: u32,
    owner: QuotaOwner,
    folder: FaiFolder,
    version: ObjectVersion,
    record: FaiMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FaiRowFilter {
    All,
    Normal,
}

impl FaiRowFilter {
    fn matches(self, kind: FaiKind) -> bool {
        self == FaiRowFilter::All || kind == FaiKind::Normal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaiRecordError {
    Attachments,
    RuleTooLarge,
    InvalidClass,
}

impl From<FaiRecordError> for RopError {
    fn from(err: FaiRecordError) -> Self {
        RopError::Code(match err {
            FaiRecordError::Attachments => ErrorCode::NOT_SUPPORTED,
            FaiRecordError::RuleTooLarge => ErrorCode::NOT_ENOUGH_MEMORY,
            FaiRecordError::InvalidClass => ErrorCode::INVALID_PARAM,
        })
    }
}

pub(crate) fn creation_stamp() -> FileTime {
    FileTime::from_utc(UtcSeconds(i64::try_from(now()).unwrap_or(i64::MAX)), 0)
}

pub(crate) fn fai_record(
    content: &MessageContent,
    rule_size_limit: Option<u64>,
    kind: FaiKind,
) -> Result<FaiMessage, FaiRecordError> {
    if !content.attachments.is_empty() {
        return Err(FaiRecordError::Attachments);
    }
    if let Some(limit) = rule_size_limit
        && let Some(OwnedPropValue::Binary(condition)) = content
            .props
            .get_any(PropKeyRef::Tag(tags::EXTENDED_RULE_MESSAGE_CONDITION.id()))
        && u64::try_from(condition.len()).unwrap_or(u64::MAX) > limit
    {
        return Err(FaiRecordError::RuleTooLarge);
    }
    let message_class = match content
        .props
        .get_any(PropKeyRef::Tag(tags::MESSAGE_CLASS.id()))
    {
        Some(OwnedPropValue::Unicode(class)) if !class.is_empty() => class.to_string(),
        Some(OwnedPropValue::String8(class)) if !class.is_empty() => str::from_utf8(class)
            .ok()
            .filter(|class| class.is_ascii())
            .ok_or(FaiRecordError::InvalidClass)?
            .to_string(),
        _ => DEFAULT_FAI_CLASS.to_string(),
    };
    Ok(FaiMessage {
        change: 0,
        message_class,
        properties: fai_properties(&content.props),
        recipients: content
            .recipients
            .iter()
            .map(|recipient| FaiRecipient {
                properties: recipient_properties(recipient),
            })
            .collect(),
        conflict: None,
        kind,
    })
}

pub fn holds_normal_fai_rows(entry: &FolderEntry) -> bool {
    !entry.search
        && match entry.node {
            FolderNode::Stored(folder) => folder.kind == FolderKind::Virtual,
            FolderNode::Special(special) => special.holds_fai() && special != SpecialFolder::Outbox,
        }
}

pub fn fai_data_type(kind: FolderKind) -> DataType {
    match kind {
        FolderKind::Calendar => DataType::CalendarEvent,
        FolderKind::AddressBook => DataType::ContactCard,
        FolderKind::FileNode => DataType::FileNode,
        FolderKind::Mailbox | FolderKind::Virtual => DataType::Email,
    }
}

pub fn fai_props(fai: &ArchivedFaiMessage) -> MessageContent {
    let mut content = MessageContent::default();
    merge_properties(fai.properties.iter(), &mut content.props);
    push_fai_state(
        &mut content,
        fai.message_class.as_str(),
        FaiKind::from(&fai.kind),
    );
    content
}

pub fn fai_content(fai: &ArchivedFaiMessage) -> MessageContent {
    let mut content = fai_props(fai);
    content.recipients = fai
        .recipients
        .iter()
        .map(|recipient| {
            let mut bag = ContentBag::default();
            merge_properties(recipient.properties.iter(), &mut bag);
            bag
        })
        .collect();
    content
}

pub(in crate::mapi::emsmdb) fn fai_client(fai: &ArchivedFaiMessage) -> Option<ClientVersion> {
    fai.conflict
        .as_ref()
        .map(|conflict| ClientVersion::from_conflict(conflict, true))
}

fn push_fai_state(content: &mut MessageContent, message_class: &str, kind: FaiKind) {
    let (associated, flags) = match kind {
        FaiKind::Associated => (true, message_flags::READ | MSGFLAG_ASSOCIATED),
        FaiKind::Normal => (false, message_flags::READ),
    };
    content.props.set(
        PropKey::tag(tags::MESSAGE_CLASS.id()),
        OwnedPropValue::Unicode(message_class.into()),
    );
    content.props.set(
        PropKey::tag(tags::ASSOCIATED.id()),
        OwnedPropValue::Bool(associated),
    );
    content.props.set(
        PropKey::tag(tags::MESSAGE_FLAGS.id()),
        OwnedPropValue::I32(flags),
    );
}

impl RopContext<'_, '_> {
    pub fn fai_folder(&self, mailbox_id: u32, node: FolderNode) -> Result<FaiFolder, ErrorCode> {
        let owner = LogonAccess::reads_all(self.logon_access(mailbox_id));
        let data_type = match node {
            FolderNode::Stored(folder) => fai_data_type(folder.kind),
            FolderNode::Special(_) if owner => DataType::Email,
            FolderNode::Special(_) => return Err(ErrorCode::NOT_FOUND),
        };
        if !self.types.contains(data_type) {
            return Err(if owner {
                ErrorCode::ACCESS_DENIED
            } else {
                ErrorCode::NOT_FOUND
            });
        }
        FaiFolder::new(node).ok_or(ErrorCode::NOT_FOUND)
    }

    pub(in crate::mapi::emsmdb) async fn fai_target(
        &mut self,
        mailbox_id: u32,
        folder: u64,
    ) -> Result<FaiFolder, RopError> {
        let node = MapiId::from_counter(folder)
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::NOT_FOUND)?;
        if self.folder_tree(mailbox_id).await?.get(node).is_none() {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        Ok(self.fai_folder(mailbox_id, node)?)
    }

    pub async fn load_fai(
        &mut self,
        message: &MessageObject,
        id: u32,
    ) -> Result<(u64, MessageContent, Option<ClientVersion>), RopError> {
        let row = self
            .fai_row(message, id)
            .await?
            .ok_or(ErrorCode::NOT_FOUND)?;
        let fai = row.unarchive::<FaiMessage>()?;
        Ok((fai.change.to_native(), fai_content(fai), fai_client(fai)))
    }

    pub(super) async fn normal_fai_content(
        &mut self,
        mailbox_id: u32,
        folder: FaiFolder,
        id: u32,
    ) -> Result<Option<MessageContent>, RopError> {
        let Some(row) = self
            .request
            .server
            .fai_message(mailbox_id, folder, id)
            .await?
        else {
            return Ok(None);
        };
        let fai = row.unarchive::<FaiMessage>()?;
        Ok((FaiKind::from(&fai.kind) == FaiKind::Normal).then(|| fai_content(fai)))
    }

    pub(in crate::mapi::emsmdb) async fn fai_version(
        &mut self,
        message: &MessageObject,
        id: u32,
    ) -> Result<Option<(u64, Option<ClientVersion>)>, RopError> {
        let Some(row) = self.fai_row(message, id).await? else {
            return Ok(None);
        };
        let fai = row.unarchive::<FaiMessage>()?;
        Ok(Some((fai.change.to_native(), fai_client(fai))))
    }

    async fn fai_row(
        &mut self,
        message: &MessageObject,
        id: u32,
    ) -> Result<Option<Archive<ArchiveBytes>>, RopError> {
        let folder = self.fai_target(message.mailbox_id, message.folder).await?;
        Ok(self
            .request
            .server
            .fai_message(message.mailbox_id, folder, id)
            .await?)
    }

    pub(super) async fn save_fai(
        &mut self,
        message: &MessageObject,
        target: SaveTarget,
        import: Option<&ImportSave>,
    ) -> Result<(MapiId, Option<u64>), RopError> {
        let folder = self.fai_target(message.mailbox_id, message.folder).await?;
        let rule_size_limit = extended_rule_size_limit(self.request.server);
        let staged = self.staged_message(message)?;
        let kind = if staged.associated {
            FaiKind::Associated
        } else {
            FaiKind::Normal
        };
        let record = fai_record(&staged.content, rule_size_limit, kind)?;
        let junk = (kind == FaiKind::Associated && is_rules_folder(message.folder))
            .then(|| junk_rule(&staged.content.props, message.mailbox_id))
            .flatten();
        let base = target.base.map(|id| id.id);
        let server = self.request.server;
        let access_token = self.request.access_token;
        let account_id = message.mailbox_id;
        let owner = server
            .exchange_quota_owner(access_token, account_id)
            .await?;
        let version = import.map_or(ObjectVersion::Server, |import| {
            ObjectVersion::Client(import.version.clone())
        });
        if let (None, Some(key)) = (base, import.and_then(|import| import.item)) {
            let key = FaiClientKey::new(key).ok_or(ErrorCode::INVALID_PARAM)?;
            let mut record = record;
            stamp_creation_time(&mut record.properties, creation_stamp());
            for _ in 0..MAX_STATE_ATTEMPTS {
                let change = FaiChange::Import {
                    key,
                    message: record.clone(),
                    version: version.clone(),
                };
                match server.commit_fai(owner, folder, change).await {
                    Ok(FaiCommit::Written { id, change }) => {
                        apply_junk_rule(
                            server,
                            access_token,
                            account_id,
                            junk,
                            JunkLists::default(),
                        )
                        .await;
                        return Ok((MapiId::new(IdSpace::Fai, id), Some(change)));
                    }
                    Ok(FaiCommit::Conflict) => {
                        if server
                            .fai_message(account_id, folder, key.id())
                            .await?
                            .is_some()
                        {
                            return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
                        }
                    }
                    Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
                        return Err(RopError::Code(ErrorCode::TOO_BIG));
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
        }
        let checked = match target.mode {
            SaveMode::Checked => target.origin,
            SaveMode::Force => None,
        };
        let mut baseline = JunkLists::default();
        let (id, change) = self
            .write_fai(
                FaiSave {
                    account_id,
                    owner,
                    folder,
                    version,
                    record,
                },
                base,
                checked,
                junk.is_some().then_some(&mut baseline),
            )
            .await?;
        apply_junk_rule(server, access_token, account_id, junk, baseline).await;
        Ok((MapiId::new(IdSpace::Fai, id), Some(change)))
    }

    pub(in crate::mapi::emsmdb) async fn move_fai(
        &mut self,
        account_id: u32,
        (from, id): (FaiFolder, u32),
        to: FaiFolder,
        key: Option<FaiClientKey>,
        row: Archive<ArchiveBytes>,
        (version, replica): (&MoveVersion, ReplGuid),
    ) -> Result<(u32, u64), RopError> {
        let server = self.request.server;
        let owner = server
            .exchange_quota_owner(self.request.access_token, account_id)
            .await?;
        let max_size = server.core.exchange.max_object_size;
        let source_change = row.unarchive::<FaiMessage>()?.change.to_native();
        for _ in 0..MAX_STATE_ATTEMPTS {
            let mut batch = BatchBuilder::new();
            let (moved, change) = match key {
                Some(key) => {
                    let reservation = server
                        .reserve_exchange_ids(account_id, [(ExchangeCounter::Change, 2)])
                        .await?;
                    let [change] = reservation.ids();
                    reservation.seal(&mut batch);
                    (key.id(), change)
                }
                None => {
                    let reservation = server
                        .reserve_exchange_ids(
                            account_id,
                            [(ExchangeCounter::Fai, 1), (ExchangeCounter::Change, 2)],
                        )
                        .await?;
                    let [moved, change] = reservation.ids();
                    let moved = u32::try_from(moved).map_err(|_| ErrorCode::TOO_BIG)?;
                    reservation.seal(&mut batch);
                    (moved, change)
                }
            };
            let conflict = version
                .stamped(ChangeSpace::Exchange.cn(change), replica)
                .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
            let write = FaiWrite {
                owner,
                folder: to,
                id: moved,
                version: ObjectVersion::Client(conflict),
                previous: None,
                next: FaiNext::Live(FaiMessage {
                    change,
                    ..row.deserialize::<FaiMessage>()?
                }),
                max_size,
            };
            match write.build(&mut batch) {
                Ok(()) => {}
                Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
                    return Err(RopError::Code(ErrorCode::TOO_BIG));
                }
                Err(err) => return Err(err.into()),
            }
            FaiWrite {
                owner,
                folder: from,
                id,
                version: ObjectVersion::Server,
                previous: Some(&row),
                next: FaiNext::Deleted { change: change + 1 },
                max_size,
            }
            .build(&mut batch)?;
            match server.commit_batch(batch).await {
                Ok(_) => {
                    server.mark_exchange_stale(account_id);
                    self.invalidate_mailbox();
                    return Ok((moved, change));
                }
                Err(err) if err.is_assertion_failure() => {}
                Err(err) => return Err(err.caused_by(trc::location!()).into()),
            }
            if key.is_some() && server.fai_message(account_id, to, moved).await?.is_some() {
                return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
            }
            let current = server
                .fai_message(account_id, from, id)
                .await?
                .ok_or(ErrorCode::SYNC_OBJECT_DELETED)?;
            if current.unarchive::<FaiMessage>()?.change.to_native() != source_change {
                return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    pub(in crate::mapi::emsmdb) async fn create_fai_content(
        &mut self,
        account_id: u32,
        folder: FaiFolder,
        content: &MessageContent,
    ) -> Result<u32, RopError> {
        let record = fai_record(
            content,
            extended_rule_size_limit(self.request.server),
            FaiKind::Associated,
        )?;
        let owner = self
            .request
            .server
            .exchange_quota_owner(self.request.access_token, account_id)
            .await?;
        self.write_fai(
            FaiSave {
                account_id,
                owner,
                folder,
                version: ObjectVersion::Server,
                record,
            },
            None,
            None,
            None,
        )
        .await
        .map(|(id, _)| id)
    }

    async fn write_fai(
        &self,
        save: FaiSave,
        base: Option<u32>,
        checked: Option<u64>,
        mut baseline: Option<&mut JunkLists>,
    ) -> Result<(u32, u64), RopError> {
        let FaiSave {
            account_id,
            owner,
            folder,
            version,
            mut record,
        } = save;
        if base.is_none() {
            stamp_creation_time(&mut record.properties, creation_stamp());
        }
        let server = self.request.server;
        let max_size = server.core.exchange.max_object_size;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let previous = match base {
                Some(id) => Some(
                    server
                        .fai_message(account_id, folder, id)
                        .await?
                        .ok_or(ErrorCode::OBJECT_DELETED)?,
                ),
                None => None,
            };
            if let (Some(origin), Some(previous)) = (checked, &previous)
                && previous.unarchive::<FaiMessage>()?.change.to_native() != origin
            {
                return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
            }
            let mut batch = BatchBuilder::new();
            let (id, change) = match base {
                Some(id) => {
                    let reservation = server
                        .reserve_exchange_ids(account_id, [(ExchangeCounter::Change, 1)])
                        .await?;
                    let [change] = reservation.ids();
                    reservation.seal(&mut batch);
                    (id, change)
                }
                None => {
                    let reservation = server
                        .reserve_exchange_ids(
                            account_id,
                            [(ExchangeCounter::Fai, 1), (ExchangeCounter::Change, 1)],
                        )
                        .await?;
                    let [id, change] = reservation.ids();
                    let id = u32::try_from(id).map_err(|_| ErrorCode::TOO_BIG)?;
                    reservation.seal(&mut batch);
                    (id, change)
                }
            };
            let mut message = FaiMessage {
                change,
                ..record.clone()
            };
            if let Some(previous) = &previous {
                let previous = previous.unarchive::<FaiMessage>()?;
                carry_creation_time(&mut message.properties, previous.properties.iter());
                if let Some(baseline) = baseline.as_deref_mut() {
                    *baseline = junk_baseline(&fai_props(previous).props);
                }
            }
            let write = FaiWrite {
                owner,
                folder,
                id,
                version: version.clone(),
                previous: previous.as_ref(),
                next: FaiNext::Live(message),
                max_size,
            };
            match write.build(&mut batch) {
                Ok(()) => {}
                Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
                    return Err(RopError::Code(ErrorCode::TOO_BIG));
                }
                Err(err) => return Err(err.into()),
            }
            match server.commit_batch(batch).await {
                Ok(_) => {
                    server.mark_exchange_stale(account_id);
                    return Ok((id, change));
                }
                Err(err) if err.is_assertion_failure() => {}
                Err(err) => return Err(err.caused_by(trc::location!()).into()),
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    pub(super) async fn delete_fai_ids(
        &mut self,
        mailbox_id: u32,
        counter: u64,
        ids: &mut Vec<u32>,
    ) -> Result<bool, RopError> {
        if ids.is_empty() {
            return Ok(false);
        }
        ids.sort_unstable();
        ids.dedup();
        let folder = self.fai_target(mailbox_id, counter).await?;
        let mut partial = false;
        for chunk in ids.chunks(MAX_FAI_DELETES) {
            partial |= self.delete_fai(mailbox_id, folder, chunk).await?;
        }
        self.invalidate_mailbox();
        Ok(partial)
    }

    pub(super) async fn clear_fai(
        &mut self,
        mailbox_id: u32,
        counter: u64,
        filter: FaiRowFilter,
    ) -> Result<bool, RopError> {
        let folder = self.fai_target(mailbox_id, counter).await?;
        let mut ids = Vec::new();
        self.request
            .server
            .fai_messages(mailbox_id, folder, |id, fai| {
                if filter.matches(FaiKind::from(&fai.kind)) {
                    ids.push(id);
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        self.delete_fai_ids(mailbox_id, counter, &mut ids).await
    }

    async fn delete_fai(
        &mut self,
        account_id: u32,
        folder: FaiFolder,
        ids: &[u32],
    ) -> Result<bool, RopError> {
        let server = self.request.server;
        let owner = server
            .exchange_quota_owner(self.request.access_token, account_id)
            .await?;
        let max_size = server.core.exchange.max_object_size;
        let mut rows = Vec::<(u32, Archive<ArchiveBytes>)>::with_capacity(ids.len());
        for _ in 0..MAX_STATE_ATTEMPTS {
            rows.clear();
            for id in ids {
                if let Some(row) = server
                    .fai_message(account_id, folder, *id)
                    .await
                    .caused_by(trc::location!())?
                {
                    rows.push((*id, row));
                }
            }
            let missing = rows.len() != ids.len();
            let Ok(count) = u32::try_from(rows.len()) else {
                return Err(RopError::Code(ErrorCode::TOO_BIG));
            };
            if count == 0 {
                return Ok(missing);
            }
            let reservation = server
                .reserve_exchange_ids(account_id, [(ExchangeCounter::Change, count)])
                .await?;
            let [first] = reservation.ids();
            let mut batch = BatchBuilder::new();
            reservation.seal(&mut batch);
            for ((id, row), change) in rows.iter().zip(first..) {
                FaiWrite {
                    owner,
                    folder,
                    id: *id,
                    version: ObjectVersion::Server,
                    previous: Some(row),
                    next: FaiNext::Deleted { change },
                    max_size,
                }
                .build(&mut batch)?;
            }
            match server.commit_batch(batch).await {
                Ok(_) => {
                    server.mark_exchange_stale(account_id);
                    return Ok(missing);
                }
                Err(err) if err.is_assertion_failure() => {}
                Err(err) => return Err(err.caused_by(trc::location!()).into()),
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }
}
