/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ExchangeProperty, FolderRef, QuotaOwner,
    account::{ExchangeAccountStore, ExchangeCounter},
    account_key,
    eas::StoredFolder,
    key_tail,
    object::{ConflictState, ExchangeObject, ObjectVersion},
    properties_size,
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::{FolderNode, SpecialFolder},
};
use common::Server;
use store::{
    Deserialize, IterateParams, Serialize, U64_LEN,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, Archiver, BatchBuilder,
        assert::AssertValue,
        metadata::{ExchangeClass, ExchangeFolder},
        now,
    },
};
use trc::AddContext;
use types::collection::Collection;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct FaiMessage {
    pub change: u64,
    pub message_class: String,
    pub properties: Vec<ExchangeProperty>,
    pub recipients: Vec<FaiRecipient>,
    pub conflict: Option<ConflictState>,
    pub kind: FaiKind,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, Copy, PartialEq, Eq,
)]
pub enum FaiKind {
    #[default]
    Associated,
    Normal,
}

impl From<&ArchivedFaiKind> for FaiKind {
    fn from(kind: &ArchivedFaiKind) -> Self {
        match kind {
            ArchivedFaiKind::Associated => FaiKind::Associated,
            ArchivedFaiKind::Normal => FaiKind::Normal,
        }
    }
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct FaiRecipient {
    pub properties: Vec<ExchangeProperty>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct VirtualFolder {
    pub change: u64,
    pub modified: u64,
    pub parent: StoredFolder,
    pub name: String,
    pub container_class: String,
    pub search: Option<SearchDefinition>,
    pub properties: Vec<ExchangeProperty>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone)]
pub struct SearchDefinition {
    pub restriction: Vec<u8>,
    pub scope: Vec<StoredFolder>,
    pub flags: u32,
    pub started: u64,
}

impl PartialEq for SearchDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.restriction == other.restriction
            && self.scope == other.scope
            && self.flags == other.flags
    }
}

impl Eq for SearchDefinition {}

impl ArchiveCompression for FaiMessage {}
impl ArchiveCompression for VirtualFolder {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaiFolder(ExchangeFolder);

pub struct FaiWrite<'x> {
    pub owner: QuotaOwner,
    pub folder: FaiFolder,
    pub id: u32,
    pub version: ObjectVersion,
    pub previous: Option<&'x Archive<ArchiveBytes>>,
    pub next: FaiNext,
    pub max_size: usize,
}

pub enum FaiNext {
    Live(FaiMessage),
    Deleted { change: u64 },
}

pub enum FaiChange<'x> {
    Create {
        message: FaiMessage,
        version: ObjectVersion,
    },
    Update {
        id: u32,
        previous: &'x Archive<ArchiveBytes>,
        message: FaiMessage,
        version: ObjectVersion,
    },
    Import {
        key: FaiClientKey,
        message: FaiMessage,
        version: ObjectVersion,
    },
    Delete {
        id: u32,
        previous: &'x Archive<ArchiveBytes>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaiKey {
    Server(u32),
    Client(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaiClientKey(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaiCommit {
    Written { id: u32, change: u64 },
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaiTombstone {
    Deleted { id: u32, change: u64 },
    Horizon { change: u64 },
}

pub struct VirtualFolderWrite<'x> {
    pub owner: QuotaOwner,
    pub id: u32,
    pub previous: Option<&'x Archive<ArchiveBytes>>,
    pub next: VirtualFolderNext,
    pub max_size: usize,
}

pub struct SpecialFolderWrite<'x> {
    pub owner: QuotaOwner,
    pub folder: SpecialFolder,
    pub previous: Option<&'x Archive<ArchiveBytes>>,
    pub next: Option<ExchangeObject>,
    pub max_size: usize,
}

pub enum VirtualFolderNext {
    Live(VirtualFolder),
    Deleted { change: u64 },
}

pub enum VirtualFolderRow<'x> {
    Live(&'x ArchivedVirtualFolder),
    Deleted { change: u64 },
    Horizon { change: u64 },
}

pub const TOMBSTONE_HORIZON_ID: u32 = 0;
pub(crate) const FAI_CLIENT_KEY: u32 = 1 << 31;

const STORED_FOLDER_SIZE: usize = size_of::<u8>() + size_of::<u32>();

impl FaiFolder {
    pub const fn new(node: FolderNode) -> Option<Self> {
        match node {
            FolderNode::Special(special) if !special.holds_fai() => None,
            node => Some(FaiFolder(node.exchange_folder())),
        }
    }

    pub const fn exchange_folder(self) -> ExchangeFolder {
        self.0
    }
}

impl From<FolderRef> for FaiFolder {
    fn from(folder: FolderRef) -> Self {
        FaiFolder(folder.stored())
    }
}

impl FaiMessage {
    pub fn quota_size(&self) -> i64 {
        properties_size(
            self.properties
                .iter()
                .chain(
                    self.recipients
                        .iter()
                        .flat_map(|recipient| recipient.properties.iter()),
                )
                .map(|property| (property.key.as_slice(), property.value.as_slice())),
        ) + self.message_class.len() as i64
    }
}

impl ArchivedFaiMessage {
    pub fn quota_size(&self) -> i64 {
        properties_size(
            self.properties
                .iter()
                .chain(
                    self.recipients
                        .iter()
                        .flat_map(|recipient| recipient.properties.iter()),
                )
                .map(|property| (property.key.as_slice(), property.value.as_slice())),
        ) + self.message_class.len() as i64
    }
}

impl VirtualFolder {
    pub fn stamp(&mut self, change: u64) {
        self.change = change;
        self.modified = now();
    }

    pub fn quota_size(&self) -> i64 {
        properties_size(
            self.properties
                .iter()
                .map(|property| (property.key.as_slice(), property.value.as_slice())),
        ) + (self.name.len()
            + self.container_class.len()
            + self.search.as_ref().map_or(0, |search| {
                search.restriction.len() + search.scope.len() * STORED_FOLDER_SIZE
            })) as i64
    }
}

impl ArchivedVirtualFolder {
    pub fn quota_size(&self) -> i64 {
        properties_size(
            self.properties
                .iter()
                .map(|property| (property.key.as_slice(), property.value.as_slice())),
        ) + (self.name.len()
            + self.container_class.len()
            + self.search.as_ref().map_or(0, |search| {
                search.restriction.len() + search.scope.len() * STORED_FOLDER_SIZE
            })) as i64
    }
}

impl FaiKey {
    pub const fn from_id(id: u32) -> Self {
        if id & FAI_CLIENT_KEY != 0 {
            FaiKey::Client(id & !FAI_CLIENT_KEY)
        } else {
            FaiKey::Server(id)
        }
    }

    pub const fn id(self) -> Option<u32> {
        match self {
            FaiKey::Server(id) if id != TOMBSTONE_HORIZON_ID && id < FAI_CLIENT_KEY => Some(id),
            FaiKey::Client(key) if key < FAI_CLIENT_KEY => Some(key | FAI_CLIENT_KEY),
            _ => None,
        }
    }
}

impl FaiClientKey {
    pub const fn new(key: u32) -> Option<Self> {
        if key < FAI_CLIENT_KEY {
            Some(FaiClientKey(key))
        } else {
            None
        }
    }

    pub const fn id(self) -> u32 {
        self.0 | FAI_CLIENT_KEY
    }
}

impl FaiWrite<'_> {
    pub fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        if self.id == TOMBSTONE_HORIZON_ID
            || (self.previous.is_none() && matches!(self.next, FaiNext::Deleted { .. }))
        {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Invalid FAI message write.")
                .ctx(trc::Key::Id, self.id)
                .caused_by(trc::location!()));
        }
        let previous = match self.previous {
            Some(previous) => Some(previous.unarchive::<FaiMessage>()?),
            None => None,
        };
        let previous_size = previous.map_or(0, ArchivedFaiMessage::quota_size);
        let folder = self.folder.0;
        let class = ExchangeClass::Fai {
            folder,
            id: self.id,
        };
        let tombstone = ExchangeClass::FaiTombstone {
            folder,
            id: self.id,
        };
        let sizes = |next_size| (previous_size, next_size, self.max_size);
        match self.next {
            FaiNext::Live(mut message) => {
                if let Some(previous) = previous {
                    message.kind = FaiKind::from(&previous.kind);
                }
                message.conflict = match self.version {
                    ObjectVersion::Server => None,
                    ObjectVersion::Client(conflict) => Some(conflict),
                    ObjectVersion::ClientAt { .. } | ObjectVersion::Kept => {
                        return Err(trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details("Kept versions are only written to mail Object rows.")
                            .ctx(trc::Key::Id, self.id)
                            .caused_by(trc::location!()));
                    }
                };
                let next_size = message.quota_size();
                write_row(
                    batch,
                    self.owner,
                    class,
                    self.previous,
                    Some(Archiver::new(message)),
                    sizes(next_size),
                )?;
                if self.previous.is_none() {
                    batch.clear(tombstone);
                }
            }
            FaiNext::Deleted { change } => {
                write_row::<Archiver<FaiMessage>>(
                    batch,
                    self.owner,
                    class,
                    self.previous,
                    None,
                    sizes(0),
                )?;
                batch.set(tombstone, change.to_be_bytes().to_vec());
            }
        }
        Ok(())
    }
}

impl VirtualFolderWrite<'_> {
    pub fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        let previous_size = match self.previous {
            Some(previous) => previous.unarchive::<VirtualFolder>()?.quota_size(),
            None => 0,
        };
        let class = ExchangeClass::Folder { id: self.id };
        let sizes = |next_size| (previous_size, next_size, self.max_size);
        match self.next {
            VirtualFolderNext::Live(folder) => {
                let next_size = folder.quota_size();
                write_row(
                    batch,
                    self.owner,
                    class,
                    self.previous,
                    Some(Archiver::new(folder)),
                    sizes(next_size),
                )
            }
            VirtualFolderNext::Deleted { change } => {
                if self.previous.is_none() || self.id == TOMBSTONE_HORIZON_ID {
                    return Err(trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details("Deleting a virtual folder that does not exist.")
                        .ctx(trc::Key::Id, self.id)
                        .caused_by(trc::location!()));
                }
                write_row::<Archiver<VirtualFolder>>(
                    batch,
                    self.owner,
                    class,
                    self.previous,
                    None,
                    sizes(0),
                )?;
                batch.set(
                    ExchangeClass::FolderTombstone { id: self.id },
                    change.to_be_bytes().to_vec(),
                );
                Ok(())
            }
        }
    }
}

impl SpecialFolderWrite<'_> {
    pub fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        let previous_size = match self.previous {
            Some(previous) => previous.unarchive::<ExchangeObject>()?.quota_size(),
            None => 0,
        };
        let next_size = self.next.as_ref().map_or(0, ExchangeObject::quota_size);
        write_row(
            batch,
            self.owner,
            special_folder_class(self.folder),
            self.previous,
            self.next.map(Archiver::new),
            (previous_size, next_size, self.max_size),
        )
    }
}

pub(crate) const fn special_folder_class(folder: SpecialFolder) -> ExchangeClass {
    ExchangeClass::SpecialFolder {
        code: folder.code(),
    }
}

fn write_row<T: Serialize>(
    batch: &mut BatchBuilder,
    owner: QuotaOwner,
    class: ExchangeClass,
    previous: Option<&Archive<ArchiveBytes>>,
    next: Option<T>,
    (previous_size, next_size, max_size): (i64, i64, usize),
) -> trc::Result<()> {
    if usize::try_from(next_size).unwrap_or(usize::MAX) > max_size {
        return Err(trc::LimitEvent::SizeRequest
            .into_err()
            .details("Exchange folder data exceeds the configured maximum size.")
            .ctx(trc::Key::Size, max_size));
    }
    batch
        .with_account_id(owner.account_id)
        .with_collection(Collection::Principal)
        .with_document(0);
    match previous {
        Some(previous) => batch.assert_value(class, previous),
        None => batch.assert_value(class, AssertValue::None),
    };
    match next {
        Some(next) => batch.set(class, next.serialize().caused_by(trc::location!())?),
        None => batch.clear(class),
    };
    owner.add(batch, next_size - previous_size);
    Ok(())
}

pub trait FolderStore: Sync + Send {
    fn fai_messages<CB>(
        &self,
        account_id: u32,
        folder: FaiFolder,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        CB: FnMut(u32, &ArchivedFaiMessage) -> trc::Result<bool> + Send + Sync;

    fn fai_message(
        &self,
        account_id: u32,
        folder: FaiFolder,
        id: u32,
    ) -> impl Future<Output = trc::Result<Option<Archive<ArchiveBytes>>>> + Send;

    fn fai_tombstones<CB>(
        &self,
        account_id: u32,
        folder: FaiFolder,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        CB: FnMut(FaiTombstone) -> trc::Result<bool> + Send + Sync;

    fn virtual_folders<CB>(
        &self,
        account_id: u32,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        CB: FnMut(u32, &ArchivedVirtualFolder) -> trc::Result<bool> + Send + Sync;

    fn virtual_folder_rows<CB>(
        &self,
        account_id: u32,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        CB: FnMut(u32, VirtualFolderRow<'_>) -> trc::Result<bool> + Send + Sync;

    fn commit_fai(
        &self,
        owner: QuotaOwner,
        folder: FaiFolder,
        change: FaiChange<'_>,
    ) -> impl Future<Output = trc::Result<FaiCommit>> + Send;
}

impl FolderStore for Server {
    async fn fai_messages<CB>(
        &self,
        account_id: u32,
        folder: FaiFolder,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        CB: FnMut(u32, &ArchivedFaiMessage) -> trc::Result<bool> + Send + Sync,
    {
        let folder = folder.0;
        self.store()
            .iterate(
                IterateParams::new(
                    account_key(account_id, ExchangeClass::Fai { folder, id: 0 }),
                    account_key(
                        account_id,
                        ExchangeClass::Fai {
                            folder,
                            id: u32::MAX,
                        },
                    ),
                ),
                |key, value| {
                    let (_, id) = key_tail(key)?;
                    let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                    cb(id, archive.unarchive::<FaiMessage>()?)
                },
            )
            .await
            .caused_by(trc::location!())
    }

    async fn fai_message(
        &self,
        account_id: u32,
        folder: FaiFolder,
        id: u32,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.store()
            .get_value::<Archive<ArchiveBytes>>(account_key(
                account_id,
                ExchangeClass::Fai {
                    folder: folder.0,
                    id,
                },
            ))
            .await
            .caused_by(trc::location!())
    }

    async fn fai_tombstones<CB>(
        &self,
        account_id: u32,
        folder: FaiFolder,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        CB: FnMut(FaiTombstone) -> trc::Result<bool> + Send + Sync,
    {
        let folder = folder.0;
        self.store()
            .iterate(
                IterateParams::new(
                    account_key(
                        account_id,
                        ExchangeClass::FaiTombstone {
                            folder,
                            id: TOMBSTONE_HORIZON_ID,
                        },
                    ),
                    account_key(
                        account_id,
                        ExchangeClass::FaiTombstone {
                            folder,
                            id: u32::MAX,
                        },
                    ),
                ),
                |key, value| {
                    let (_, id) = key_tail(key)?;
                    let change = tombstone_change(key, value)?;
                    if id == TOMBSTONE_HORIZON_ID {
                        cb(FaiTombstone::Horizon { change })
                    } else {
                        cb(FaiTombstone::Deleted { id, change })
                    }
                },
            )
            .await
            .caused_by(trc::location!())
    }

    async fn virtual_folders<CB>(&self, account_id: u32, mut cb: CB) -> trc::Result<()>
    where
        CB: FnMut(u32, &ArchivedVirtualFolder) -> trc::Result<bool> + Send + Sync,
    {
        self.store()
            .iterate(
                IterateParams::new(
                    account_key(account_id, ExchangeClass::Folder { id: 0 }),
                    account_key(account_id, ExchangeClass::Folder { id: u32::MAX }),
                ),
                |key, value| {
                    let (_, id) = key_tail(key)?;
                    let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                    cb(id, archive.unarchive::<VirtualFolder>()?)
                },
            )
            .await
            .caused_by(trc::location!())
    }

    async fn virtual_folder_rows<CB>(&self, account_id: u32, mut cb: CB) -> trc::Result<()>
    where
        CB: FnMut(u32, VirtualFolderRow<'_>) -> trc::Result<bool> + Send + Sync,
    {
        const FOLDER: u8 = ExchangeClass::Folder { id: 0 }.code();
        const TOMBSTONE: u8 = ExchangeClass::FolderTombstone { id: 0 }.code();
        self.store()
            .iterate(
                IterateParams::new(
                    account_key(account_id, ExchangeClass::Folder { id: 0 }),
                    account_key(account_id, ExchangeClass::FolderTombstone { id: u32::MAX }),
                ),
                |key, value| match key_tail(key)? {
                    (FOLDER, id) => {
                        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                        cb(
                            id,
                            VirtualFolderRow::Live(archive.unarchive::<VirtualFolder>()?),
                        )
                    }
                    (TOMBSTONE, id) => {
                        let change = tombstone_change(key, value)?;
                        if id == TOMBSTONE_HORIZON_ID {
                            cb(id, VirtualFolderRow::Horizon { change })
                        } else {
                            cb(id, VirtualFolderRow::Deleted { change })
                        }
                    }
                    _ => Err(trc::Error::corrupted_key(key, None, trc::location!())),
                },
            )
            .await
            .caused_by(trc::location!())
    }

    async fn commit_fai(
        &self,
        owner: QuotaOwner,
        folder: FaiFolder,
        change: FaiChange<'_>,
    ) -> trc::Result<FaiCommit> {
        let account_id = owner.account_id;
        let mut batch = BatchBuilder::new();
        let (id, version, previous, next) = match change {
            FaiChange::Create {
                mut message,
                version,
            } => {
                let reservation = self
                    .reserve_exchange_ids(
                        account_id,
                        [(ExchangeCounter::Fai, 1), (ExchangeCounter::Change, 1)],
                    )
                    .await?;
                let [id, change] = reservation.ids();
                let id = u32::try_from(id).map_err(|_| {
                    trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details("FAI id space exhausted.")
                        .caused_by(trc::location!())
                })?;
                reservation.seal(&mut batch);
                message.change = change;
                (id, version, None, FaiNext::Live(message))
            }
            FaiChange::Update {
                id,
                previous,
                mut message,
                version,
            } => {
                message.change = reserve_change(self, account_id, &mut batch).await?;
                (id, version, Some(previous), FaiNext::Live(message))
            }
            FaiChange::Import {
                key,
                mut message,
                version,
            } => {
                let id = key.id();
                message.change = reserve_change(self, account_id, &mut batch).await?;
                (id, version, None, FaiNext::Live(message))
            }
            FaiChange::Delete { id, previous } => {
                let change = reserve_change(self, account_id, &mut batch).await?;
                (
                    id,
                    ObjectVersion::Server,
                    Some(previous),
                    FaiNext::Deleted { change },
                )
            }
        };
        let change = match &next {
            FaiNext::Live(message) => message.change,
            FaiNext::Deleted { change } => *change,
        };
        FaiWrite {
            owner,
            folder,
            id,
            version,
            previous,
            next,
            max_size: self.core.exchange.max_object_size,
        }
        .build(&mut batch)?;
        match self.commit_batch(batch).await {
            Ok(_) => {
                self.mark_exchange_stale(account_id);
                Ok(FaiCommit::Written { id, change })
            }
            Err(err) if err.is_assertion_failure() => Ok(FaiCommit::Conflict),
            Err(err) => Err(err.caused_by(trc::location!())),
        }
    }
}

async fn reserve_change(
    server: &Server,
    account_id: u32,
    batch: &mut BatchBuilder,
) -> trc::Result<u64> {
    let reservation = server
        .reserve_exchange_ids(account_id, [(ExchangeCounter::Change, 1)])
        .await?;
    let [change] = reservation.ids();
    reservation.seal(batch);
    Ok(change)
}

pub(super) fn tombstone_change(key: &[u8], value: &[u8]) -> trc::Result<u64> {
    value
        .first_chunk::<U64_LEN>()
        .map(|change| u64::from_be_bytes(*change))
        .ok_or_else(|| trc::Error::corrupted_key(key, Some(value), trc::location!()))
}

pub(crate) async fn purge_virtual_tombstones(server: &Server, account_id: u32) -> trc::Result<()> {
    let Some(max_history) = server.core.email.changes_max_history else {
        return Ok(());
    };
    let mut horizon = 0;
    let mut tombstones = Vec::new();
    server
        .store()
        .iterate(
            IterateParams::new(
                account_key(account_id, ExchangeClass::FolderTombstone { id: 0 }),
                account_key(account_id, ExchangeClass::FolderTombstone { id: u32::MAX }),
            ),
            |key, value| {
                let (_, id) = key_tail(key)?;
                let change = tombstone_change(key, value)?;
                if id == TOMBSTONE_HORIZON_ID {
                    horizon = change;
                } else {
                    tombstones.push((change, id));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    let Some(excess) = tombstones
        .len()
        .checked_sub(max_history)
        .filter(|excess| *excess > 0)
    else {
        return Ok(());
    };
    tombstones.select_nth_unstable(excess - 1);
    let purged = tombstones.get(..excess).unwrap_or_default();
    let horizon = purged
        .iter()
        .fold(horizon, |horizon, (change, _)| horizon.max(*change));
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Principal)
        .with_document(0)
        .set(
            ExchangeClass::FolderTombstone {
                id: TOMBSTONE_HORIZON_ID,
            },
            horizon.to_be_bytes().to_vec(),
        )
        .commit_point();
    for &(_, id) in purged {
        batch
            .clear(ExchangeClass::FolderTombstone { id })
            .commit_point();
    }
    server
        .store()
        .write_batch(&mut batch)
        .await
        .map(|_| ())
        .caused_by(trc::location!())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/store/folder/tests.rs"]
mod tests;
