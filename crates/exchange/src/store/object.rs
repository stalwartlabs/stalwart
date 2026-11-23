/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedExchangeProperty, ExchangeProperty, QuotaOwner, account::bump_objects_epoch,
    category::SpellingChanges, exchange_key, properties_size,
};
use crate::cache::ExchangeCacheFetch;
use common::{
    Server,
    auth::ChangedBy,
    cache::exchange::{ExchangeAccountCache, Placement},
    storage::index::CurrentObject,
};
use email::message::{
    delete::EmailDeletion,
    ingest::{
        EmailIngest, IngestEmail, IngestSource, IngestedEmail, PendingIngest,
        recheck::ThreadRecheck,
    },
    messagedata::{KEYWORD_BITS, MessageData, SERVER_SET_KEYWORDS},
};
use store::{
    Deserialize, IterateParams, Serialize, U32_LEN,
    roaring::RoaringBitmap,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, ArchiveVersion, Archiver, BatchBuilder,
        MergeResult, Patch, PatchSource, PendingId,
        assert::{AssertValue, ToAssertValue},
        metadata::ExchangeClass,
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::Field,
    keyword::Keyword,
};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ExchangeObject {
    pub properties: Vec<ExchangeProperty>,
    pub conflict: Option<ConflictState>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ConflictState {
    pub change_key: Vec<u8>,
    pub pcl: Vec<u8>,
}

impl ArchiveCompression for ExchangeObject {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredPlacement {
    pub container: u32,
    pub item: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ObjectVersion {
    #[default]
    Server,
    Client(ConflictState),
    ClientAt {
        conflict: ConflictState,
        change_id: u64,
    },
    Kept,
}

#[derive(Debug, Clone, Default)]
pub struct CreatedEmail {
    pub carried: Option<ExchangeObject>,
    pub version: ObjectVersion,
    pub alias: Option<u32>,
    pub spellings: SpellingChanges,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerStamp {
    Email { thread_id: u32 },
    Versioned,
    Container,
    Logged,
}

pub struct ReplacedEmail<'x> {
    pub document_id: u32,
    pub data: &'x MessageData,
    pub identity: StoredPlacement,
    pub alias: Option<StoredPlacement>,
    pub object: Option<&'x Archive<ArchiveBytes>>,
    pub added_keywords: u32,
    pub removed_keywords: u32,
    pub keywords_extra: Option<&'x [Keyword]>,
}

pub struct ExchangeObjectWrite<'x> {
    pub owner: QuotaOwner,
    pub collection: Collection,
    pub document_id: PendingId,
    pub stamp: OwnerStamp,
    pub version: ObjectVersion,
    pub previous: Option<&'x Archive<ArchiveBytes>>,
    pub next: Option<ExchangeObject>,
    pub max_size: usize,
}

impl ExchangeObject {
    pub fn property(&self, key: &[u8]) -> Option<&[u8]> {
        self.properties
            .binary_search_by(|property| property.key.as_slice().cmp(key))
            .ok()
            .and_then(|idx| self.properties.get(idx))
            .map(|property| property.value.as_slice())
    }

    pub fn set_property(&mut self, key: Vec<u8>, value: Vec<u8>) {
        match self
            .properties
            .binary_search_by(|property| property.key.as_slice().cmp(&key))
        {
            Ok(idx) => {
                if let Some(property) = self.properties.get_mut(idx) {
                    property.value = value;
                }
            }
            Err(idx) => self.properties.insert(idx, ExchangeProperty { key, value }),
        }
    }

    pub fn remove_property(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.properties
            .binary_search_by(|property| property.key.as_slice().cmp(key))
            .ok()
            .map(|idx| self.properties.remove(idx).value)
    }

    pub fn is_empty(&self) -> bool {
        self.properties.is_empty() && self.conflict.is_none()
    }

    pub fn quota_size(&self) -> i64 {
        properties_size(
            self.properties
                .iter()
                .map(|property| (property.key.as_slice(), property.value.as_slice())),
        ) + self.conflict.as_ref().map_or(0, |conflict| {
            (conflict.change_key.len() + conflict.pcl.len()) as i64
        })
    }

    pub fn sized_within(&self, max_size: usize) -> trc::Result<i64> {
        let size = self.quota_size();
        if usize::try_from(size).unwrap_or(usize::MAX) > max_size {
            Err(trc::LimitEvent::SizeRequest
                .into_err()
                .details("Exchange object properties exceed the configured maximum size.")
                .ctx(trc::Key::Size, max_size))
        } else {
            Ok(size)
        }
    }

    pub fn exceeds(&self, max_size: usize) -> bool {
        usize::try_from(self.quota_size()).unwrap_or(usize::MAX) > max_size
    }

    pub fn client_conflict(
        archive: &Archive<ArchiveBytes>,
        change_id: u64,
    ) -> trc::Result<Option<&ArchivedConflictState>> {
        if archive.version.change_id() == Some(change_id) {
            archive
                .unarchive::<ExchangeObject>()
                .map(|object| object.conflict.as_ref())
        } else {
            Ok(None)
        }
    }
}

impl ArchivedExchangeObject {
    pub fn property(&self, key: &[u8]) -> Option<&[u8]> {
        self.properties
            .binary_search_by(|property| property.key.as_slice().cmp(key))
            .ok()
            .and_then(|idx| self.properties.get(idx))
            .map(|property| property.value.as_slice())
    }

    pub fn properties_in_set<'x>(
        &'x self,
        prefix: &'x [u8],
    ) -> impl Iterator<Item = &'x ArchivedExchangeProperty> + 'x {
        let start = self
            .properties
            .partition_point(|property| property.key.as_slice() < prefix);
        self.properties
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(move |property| property.key.as_slice().starts_with(prefix))
    }

    pub fn quota_size(&self) -> i64 {
        properties_size(
            self.properties
                .iter()
                .map(|property| (property.key.as_slice(), property.value.as_slice())),
        ) + self.conflict.as_ref().map_or(0, |conflict| {
            (conflict.change_key.len() + conflict.pcl.len()) as i64
        })
    }
}

impl From<Placement> for StoredPlacement {
    fn from(placement: Placement) -> Self {
        StoredPlacement {
            container: placement.container,
            item: placement.item,
        }
    }
}

impl ToAssertValue for StoredPlacement {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::U64((u64::from(self.container) << u32::BITS) | u64::from(self.item))
    }
}

impl StoredPlacement {
    pub const fn folder(client_key: u32) -> Self {
        StoredPlacement {
            container: 0,
            item: client_key,
        }
    }

    pub fn serialize(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(U32_LEN * 2);
        bytes.extend_from_slice(&self.container.to_be_bytes());
        bytes.extend_from_slice(&self.item.to_be_bytes());
        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (container, item) = bytes.split_first_chunk::<U32_LEN>()?;
        let item = item.first_chunk::<U32_LEN>()?;
        Some(StoredPlacement {
            container: u32::from_be_bytes(*container),
            item: u32::from_be_bytes(*item),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RowBaseline {
    #[default]
    Untracked,
    Absent,
    Hashed(u32),
}

impl RowBaseline {
    pub fn of(version: Option<&ArchiveVersion>) -> Self {
        match version {
            None => RowBaseline::Absent,
            Some(version) => version
                .hash()
                .map_or(RowBaseline::Untracked, RowBaseline::Hashed),
        }
    }

    fn of_written(bytes: &[u8]) -> Self {
        Archive::<ArchiveBytes>::extract_hash(bytes)
            .map_or(RowBaseline::Untracked, RowBaseline::Hashed)
    }

    pub fn is_current(self, version: Option<&ArchiveVersion>) -> bool {
        self == RowBaseline::Untracked || self == RowBaseline::of(version)
    }
}

impl ExchangeObjectWrite<'_> {
    pub fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        self.build_tracked(batch).map(drop)
    }

    pub fn build_tracked(self, batch: &mut BatchBuilder) -> trc::Result<RowBaseline> {
        let mut next = self.next;
        let kept_change_id = match self.version {
            ObjectVersion::Server => {
                if let Some(next) = &mut next {
                    next.conflict = None;
                }
                None
            }
            ObjectVersion::Client(conflict)
                if self.collection == Collection::Email
                    && match self.stamp {
                        OwnerStamp::Email { .. } => true,
                        OwnerStamp::Logged => self.document_id.is_pending(),
                        OwnerStamp::Versioned | OwnerStamp::Container => false,
                    } =>
            {
                if let Some(next) = &mut next {
                    next.conflict = Some(conflict);
                }
                None
            }
            ObjectVersion::Client(_) => {
                return Err(trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details(
                        "Client versions are only stored on mail Object rows with a logged change.",
                    )
                    .caused_by(trc::location!()));
            }
            ObjectVersion::ClientAt {
                conflict,
                change_id,
            } if matches!(
                self.collection,
                Collection::ContactCard | Collection::CalendarEvent
            ) && self.stamp == OwnerStamp::Logged
                && !self.document_id.is_pending() =>
            {
                if let Some(next) = &mut next {
                    next.conflict = Some(conflict);
                }
                Some(change_id)
            }
            ObjectVersion::ClientAt { .. } => {
                return Err(trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details(
                        "Pinned client versions are only stored on existing groupware Object rows.",
                    )
                    .caused_by(trc::location!()));
            }
            ObjectVersion::Kept
                if matches!(
                    self.collection,
                    Collection::Email | Collection::ContactCard | Collection::CalendarEvent
                ) && self.stamp == OwnerStamp::Logged
                    && !self.document_id.is_pending() =>
            {
                let change_id = self
                    .previous
                    .and_then(|previous| previous.version.change_id());
                if change_id.is_none()
                    && let Some(next) = &mut next
                {
                    next.conflict = None;
                }
                change_id
            }
            ObjectVersion::Kept => {
                return Err(trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("Kept versions are only written to existing logged Object rows.")
                    .caused_by(trc::location!()));
            }
        };
        let previous_size = match self.previous {
            Some(previous) => previous.unarchive::<ExchangeObject>()?.quota_size(),
            None => 0,
        };
        let next = next.filter(|next| !next.is_empty());
        let next_size = match &next {
            Some(next) => next.sized_within(self.max_size)?,
            None => 0,
        };
        let account_id = self.owner.account_id;
        batch
            .with_account_id(account_id)
            .with_collection(self.collection)
            .with_pending_document(self.document_id);
        match self.previous {
            Some(previous) => batch.assert_value(ExchangeClass::Object, previous),
            None => batch.assert_value(ExchangeClass::Object, AssertValue::None),
        };
        let has_next = next.is_some();
        let written = match next {
            Some(next) if next.conflict.is_some() => {
                let (offset, mut bytes) = Archiver::new(next)
                    .serialize_versioned()
                    .caused_by(trc::location!())?;
                let written = RowBaseline::of_written(&bytes);
                match kept_change_id {
                    Some(change_id) => {
                        if !Archive::<ArchiveBytes>::restamp_change_id(&mut bytes, change_id) {
                            return Err(trc::StoreEvent::UnexpectedError
                                .into_err()
                                .details("Versioned Exchange object has no change id slot.")
                                .caused_by(trc::location!()));
                        }
                        batch.set(ExchangeClass::Object, bytes);
                    }
                    None => {
                        let offset = u32::try_from(offset).map_err(|_| {
                            trc::StoreEvent::UnexpectedError
                                .into_err()
                                .details("Versioned Exchange object is too large.")
                                .caused_by(trc::location!())
                        })?;
                        batch.set(
                            ExchangeClass::Object,
                            (
                                bytes,
                                vec![Patch {
                                    offset,
                                    source: PatchSource::ChangeIdBe,
                                }],
                            ),
                        );
                    }
                }
                written
            }
            Some(next) => {
                let bytes = Archiver::new(next)
                    .serialize()
                    .caused_by(trc::location!())?;
                let written = RowBaseline::of_written(&bytes);
                batch.set(ExchangeClass::Object, bytes);
                written
            }
            None => {
                batch.clear(ExchangeClass::Object);
                RowBaseline::Absent
            }
        };
        self.owner.add(batch, next_size - previous_size);
        if self.previous.is_some() != has_next {
            bump_objects_epoch(batch, account_id);
        }
        match self.stamp {
            OwnerStamp::Email { thread_id } => {
                touch_email(batch, account_id, self.document_id, thread_id);
            }
            OwnerStamp::Versioned => {
                touch_versioned(batch, account_id, self.collection, self.document_id);
            }
            OwnerStamp::Container => {
                batch
                    .with_account_id(account_id)
                    .with_collection(self.collection)
                    .log_container_property_change(
                        SyncCollection::from(self.collection),
                        self.document_id,
                    );
            }
            OwnerStamp::Logged => {}
        }
        Ok(written)
    }
}

pub fn touch_email(
    batch: &mut BatchBuilder,
    account_id: u32,
    document_id: PendingId,
    thread_id: u32,
) {
    let group = SyncCollection::Email.change_group();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Email)
        .with_pending_document(document_id)
        .merge_fnc(Field::ARCHIVE, move |ids, bytes| {
            let change_id = ids.change_id(account_id, group).ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("No change id was allocated for the Exchange update.")
                    .caused_by(trc::location!())
            })?;
            let bytes = bytes.ok_or_else(|| {
                trc::StoreEvent::AssertValueFailed
                    .into_err()
                    .details("Message no longer exists.")
                    .caused_by(trc::location!())
            })?;
            MessageData::deserialize(bytes)?
                .serialize_with_change_id(change_id)
                .map(MergeResult::Update)
        })
        .log_item_update(SyncCollection::Email, Some(PendingId::Assigned(thread_id)));
}

pub fn touch_versioned(
    batch: &mut BatchBuilder,
    account_id: u32,
    collection: Collection,
    document_id: PendingId,
) {
    let sync_collection = SyncCollection::from(collection);
    let group = sync_collection.change_group();
    batch
        .with_account_id(account_id)
        .with_collection(collection)
        .with_pending_document(document_id)
        .merge_fnc(Field::ARCHIVE, move |ids, bytes| {
            let change_id = ids.change_id(account_id, group).ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("No change id was allocated for the Exchange update.")
                    .caused_by(trc::location!())
            })?;
            let mut bytes = bytes
                .ok_or_else(|| {
                    trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .details("Object no longer exists.")
                        .caused_by(trc::location!())
                })?
                .to_vec();
            if !Archive::<ArchiveBytes>::restamp_change_id(&mut bytes, change_id) {
                return Err(trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Object archive is not versioned.")
                    .caused_by(trc::location!()));
            }
            Ok(MergeResult::Update(bytes))
        })
        .log_item_update(sync_collection, None);
}

pub trait ExchangeObjectStore: Sync + Send {
    fn exchange_object(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> impl Future<Output = trc::Result<Option<Archive<ArchiveBytes>>>> + Send;

    fn exchange_objects<CB>(
        &self,
        cache: &ExchangeAccountCache,
        account_id: u32,
        collection: Collection,
        documents: &RoaringBitmap,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        CB: FnMut(u32, &ArchivedExchangeObject) -> trc::Result<bool> + Send + Sync;

    fn create_email(
        &self,
        params: IngestEmail<'_>,
        owner: QuotaOwner,
        created: CreatedEmail,
        max_size: usize,
    ) -> impl Future<Output = trc::Result<IngestedEmail>> + Send;

    fn create_email_tracked(
        &self,
        params: IngestEmail<'_>,
        owner: QuotaOwner,
        created: CreatedEmail,
        max_size: usize,
    ) -> impl Future<Output = trc::Result<(IngestedEmail, RowBaseline)>> + Send;

    fn replace_email(
        &self,
        params: IngestEmail<'_>,
        changed_by: ChangedBy,
        owner: QuotaOwner,
        replaced: ReplacedEmail<'_>,
        carried: Option<ExchangeObject>,
        max_size: usize,
    ) -> impl Future<Output = trc::Result<IngestedEmail>> + Send;

    fn replace_email_tracked(
        &self,
        params: IngestEmail<'_>,
        changed_by: ChangedBy,
        owner: QuotaOwner,
        replaced: ReplacedEmail<'_>,
        carried: Option<ExchangeObject>,
        max_size: usize,
    ) -> impl Future<Output = trc::Result<(IngestedEmail, RowBaseline)>> + Send;
}

impl ExchangeObjectStore for Server {
    async fn exchange_object(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.store()
            .get_value::<Archive<ArchiveBytes>>(exchange_key(
                account_id,
                collection,
                document_id,
                ExchangeClass::Object,
            ))
            .await
            .caused_by(trc::location!())
    }

    async fn exchange_objects<CB>(
        &self,
        cache: &ExchangeAccountCache,
        account_id: u32,
        collection: Collection,
        documents: &RoaringBitmap,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        CB: FnMut(u32, &ArchivedExchangeObject) -> trc::Result<bool> + Send + Sync,
    {
        let Some(stored) = cache.objects(collection) else {
            return Ok(());
        };
        let ranges = (documents & stored)
            .iter()
            .map(|document_id| {
                let key = exchange_key(account_id, collection, document_id, ExchangeClass::Object);
                IterateParams::new(key.clone(), key)
            })
            .collect::<Vec<_>>();
        if ranges.is_empty() {
            return Ok(());
        }
        self.store()
            .iterate_many(ranges, |key, value| {
                let document_id = key
                    .last_chunk::<U32_LEN>()
                    .map(|id| u32::from_be_bytes(*id))
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                cb(document_id, archive.unarchive::<ExchangeObject>()?)
            })
            .await
            .caused_by(trc::location!())
    }

    async fn create_email(
        &self,
        params: IngestEmail<'_>,
        owner: QuotaOwner,
        created: CreatedEmail,
        max_size: usize,
    ) -> trc::Result<IngestedEmail> {
        self.create_email_tracked(params, owner, created, max_size)
            .await
            .map(|(email, _)| email)
    }

    async fn create_email_tracked(
        &self,
        params: IngestEmail<'_>,
        owner: QuotaOwner,
        created: CreatedEmail,
        max_size: usize,
    ) -> trc::Result<(IngestedEmail, RowBaseline)> {
        ingest_email(self, params, owner, created, max_size, None).await
    }

    async fn replace_email(
        &self,
        params: IngestEmail<'_>,
        changed_by: ChangedBy,
        owner: QuotaOwner,
        replaced: ReplacedEmail<'_>,
        carried: Option<ExchangeObject>,
        max_size: usize,
    ) -> trc::Result<IngestedEmail> {
        self.replace_email_tracked(params, changed_by, owner, replaced, carried, max_size)
            .await
            .map(|(email, _)| email)
    }

    async fn replace_email_tracked(
        &self,
        params: IngestEmail<'_>,
        changed_by: ChangedBy,
        owner: QuotaOwner,
        replaced: ReplacedEmail<'_>,
        carried: Option<ExchangeObject>,
        max_size: usize,
    ) -> trc::Result<(IngestedEmail, RowBaseline)> {
        ingest_email(
            self,
            params,
            owner,
            CreatedEmail {
                carried,
                ..Default::default()
            },
            max_size,
            Some((changed_by, replaced)),
        )
        .await
    }
}

async fn ingest_email(
    server: &Server,
    mut params: IngestEmail<'_>,
    owner: QuotaOwner,
    created: CreatedEmail,
    max_size: usize,
    replaced: Option<(ChangedBy, ReplacedEmail<'_>)>,
) -> trc::Result<(IngestedEmail, RowBaseline)> {
    if matches!(params.source, IngestSource::Smtp { .. }) {
        return Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Exchange ingest does not accept an SMTP source.")
            .caused_by(trc::location!()));
    }
    let CreatedEmail {
        carried,
        version,
        alias,
        spellings,
    } = created;
    let carried = match version {
        ObjectVersion::Server => carried.filter(|carried| !carried.is_empty()),
        ObjectVersion::Client(_) => Some(carried.unwrap_or_default()),
        ObjectVersion::ClientAt { .. } | ObjectVersion::Kept => {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Kept versions are only written to existing mail Object rows.")
                .caused_by(trc::location!()));
        }
    };
    if let Some((_, replaced)) = &replaced {
        let data = replaced.data;
        let keywords = ((data.keywords | replaced.added_keywords) & !replaced.removed_keywords)
            & KEYWORD_BITS
            & !SERVER_SET_KEYWORDS;
        params.mailbox_ids.clear();
        params
            .mailbox_ids
            .extend(data.mailboxes.iter().map(|mailbox| mailbox.mailbox_id));
        params.keywords.clear();
        params.keywords.extend(
            (0..u32::BITS)
                .filter(|bit| keywords & (1 << bit) != 0)
                .filter_map(|bit| Keyword::try_from_id(bit as usize).ok()),
        );
        match replaced.keywords_extra {
            Some(extra) => params.keywords.extend_from_slice(extra),
            None => params
                .keywords
                .extend(data.keywords_extra.iter().cloned().map(Keyword::Other)),
        }
    }
    let alias = match (alias, params.mailbox_ids.as_slice()) {
        (None, _) => None,
        (Some(item), &[container]) => Some(StoredPlacement { container, item }),
        (Some(_), _) => {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("A client item alias needs exactly one mailbox.")
                .caused_by(trc::location!()));
        }
    };
    let account_id = params.access_token.account_id();
    let session_id = params.session_id;
    let mut batch = BatchBuilder::new();
    let pending = match server
        .email_ingest_into(&mut params, &mut batch, None)
        .await?
    {
        PendingIngest::Queued(pending) => pending,
        PendingIngest::Duplicate(email) => return Ok((email, RowBaseline::Untracked)),
    };
    let document_id = pending.document_id();
    let exchange_rows =
        carried.is_some() || alias.is_some() || replaced.is_some() || !spellings.is_empty();
    let row = match carried {
        Some(carried) => ExchangeObjectWrite {
            owner,
            collection: Collection::Email,
            document_id,
            stamp: OwnerStamp::Logged,
            version,
            previous: None,
            next: Some(carried),
            max_size,
        }
        .build_tracked(&mut batch)?,
        None => RowBaseline::Absent,
    };
    if let Some(alias) = alias {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_pending_document(document_id)
            .set(ExchangeClass::Alias, alias.serialize());
        bump_objects_epoch(&mut batch, account_id);
    }
    if let Some((changed_by, replaced)) = replaced {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_pending_document(document_id)
            .set(ExchangeClass::Alias, replaced.identity.serialize());
        if replaced.object.is_some() {
            ExchangeObjectWrite {
                owner,
                collection: Collection::Email,
                document_id: PendingId::Assigned(replaced.document_id),
                stamp: OwnerStamp::Logged,
                version: ObjectVersion::Server,
                previous: replaced.object,
                next: None,
                max_size,
            }
            .build(&mut batch)?;
        }
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_document(replaced.document_id);
        replaced.data.assert(&mut batch);
        match replaced.alias {
            Some(alias) => batch.assert_value(ExchangeClass::Alias, alias),
            None => batch.assert_value(ExchangeClass::Alias, AssertValue::None),
        };
        batch.clear(ExchangeClass::Alias);
        bump_objects_epoch(&mut batch, account_id);
        server
            .emails_delete(
                account_id,
                changed_by,
                &mut batch,
                RoaringBitmap::from_iter([replaced.document_id]),
            )
            .await
            .caused_by(trc::location!())?;
    }
    spellings.queue(&mut batch, account_id);
    let assigned_ids = match server.commit_batch(batch).await {
        Ok(assigned_ids) => assigned_ids,
        Err(err) => {
            if err.is_assertion_failure() {
                server
                    .inner
                    .mark_cache_stale(account_id, SyncCollection::Email);
                if exchange_rows {
                    server.mark_exchange_stale(account_id);
                }
            }
            return Err(err.caused_by(trc::location!()));
        }
    };
    if exchange_rows {
        server.mark_exchange_stale(account_id);
    }
    let mut email = server.email_ingest_finish(pending, &assigned_ids).await;
    let mut recheck = ThreadRecheck::default();
    recheck.push(account_id, &mut email);
    recheck.finish(server, session_id).await;
    Ok((email, row))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/store/object/tests.rs"]
mod tests;
