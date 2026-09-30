/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Archive, ArchiveBytes, ValueClass};
use crate::{Deserialize, SerializeInfallible, U32_LEN, U64_LEN};
use types::metadata::{EncodedMetadata, MetadataKinds, MetadataView, STORAGE_TRAILER_CAPACITY};

pub const METADATA_COMPRESS_WATERMARK: usize = 1024;

const TRAILER_LEN: usize = U32_LEN + 1;
const _: () = assert!(TRAILER_LEN == STORAGE_TRAILER_CAPACITY);

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum MetadataClass {
    Shared,
    Private { viewer: u32 },
    Viewer { viewer: u32 },
    Owner { owner: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMetadata {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataBuf {
    bytes: Box<[u8]>,
    stored_len: u32,
    hash: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ViewerState {
    pub change_id: u64,
    pub containers: u32,
}

const VIEWER_STATE_LEN: usize = U64_LEN + U32_LEN;

impl MetadataClass {
    pub(crate) const SHARED: u8 = 0;
    pub(crate) const PRIVATE: u8 = 1;
    pub(crate) const VIEWER: u8 = 2;
    pub(crate) const OWNER: u8 = 3;
}

impl From<MetadataClass> for ValueClass {
    fn from(class: MetadataClass) -> Self {
        ValueClass::Metadata(class)
    }
}

impl StoredMetadata {
    pub fn new(container: EncodedMetadata) -> trc::Result<Self> {
        Archive::serialize_raw(container.into_bytes(), METADATA_COMPRESS_WATERMARK)
            .map(|bytes| StoredMetadata { bytes })
    }

    pub fn trailer_hash(stored: &[u8]) -> trc::Result<u32> {
        stored
            .split_last()
            .and_then(|(_, contents)| contents.last_chunk::<U32_LEN>())
            .map(|hash| u32::from_be_bytes(*hash))
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Metadata container carries no trailer")
                    .ctx(trc::Key::Value, stored)
                    .caused_by(trc::location!())
            })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn view<'x>(stored: &'x [u8], scratch: &'x mut Vec<u8>) -> trc::Result<MetadataView<'x>> {
        let contents = Archive::<ArchiveBytes>::deserialize_raw(stored, scratch)?;
        unsafe { MetadataView::from_trusted(contents) }.ok_or_else(|| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid metadata container header")
                .ctx(trc::Key::Value, contents)
                .caused_by(trc::location!())
        })
    }
}

impl MetadataBuf {
    pub fn from_view(view: &MetadataView<'_>, stored_len: u32, hash: u32) -> Self {
        MetadataBuf {
            bytes: view.as_bytes().into(),
            stored_len,
            hash,
        }
    }

    pub fn read(stored: &[u8]) -> trc::Result<Self> {
        let hash = StoredMetadata::trailer_hash(stored)?;
        let stored_len = u32::try_from(stored.len()).unwrap_or(u32::MAX);
        let mut scratch = Vec::new();
        StoredMetadata::view(stored, &mut scratch)
            .map(|view| Self::from_view(&view, stored_len, hash))
    }

    pub fn view(&self) -> MetadataView<'_> {
        unsafe { MetadataView::from_trusted(&self.bytes) }.unwrap_or_else(MetadataView::empty)
    }

    pub fn kinds(&self) -> MetadataKinds {
        self.view().kinds()
    }

    pub fn stored_len(&self) -> u32 {
        self.stored_len
    }

    pub fn hash(&self) -> u32 {
        self.hash
    }
}

impl Deserialize for MetadataBuf {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Self::read(bytes)
    }
}

impl SerializeInfallible for ViewerState {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(VIEWER_STATE_LEN);
        bytes.extend_from_slice(&self.change_id.to_be_bytes());
        bytes.extend_from_slice(&self.containers.to_be_bytes());
        bytes
    }
}

impl Deserialize for ViewerState {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes
            .split_first_chunk::<U64_LEN>()
            .and_then(|(change_id, containers)| {
                Some(ViewerState {
                    change_id: u64::from_be_bytes(*change_id),
                    containers: u32::from_be_bytes(containers.try_into().ok()?),
                })
            })
            .ok_or_else(|| {
                trc::StoreEvent::DataCorruption
                    .into_err()
                    .details("Invalid metadata viewer state")
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Key, ValueKey,
        write::{
            ArchiveVersion, AssertValue, BatchBuilder, ChangeCounter, LogCollection, Operation,
            PRIVATE_LOG, PendingId,
        },
    };
    use std::borrow::Cow;
    use types::{
        collection::{Collection, SyncCollection},
        metadata::MetadataBuilder,
    };

    fn container(repeat: usize) -> EncodedMetadata {
        let mut builder = MetadataBuilder::new();
        builder.set_imap(Cow::Borrowed("/comment"), "abc".repeat(repeat).as_bytes());
        builder.encode().expect("non-empty")
    }

    #[test]
    fn stored_metadata_roundtrip() {
        for repeat in [1, 100, 2000] {
            let encoded = container(repeat);
            let stored = StoredMetadata::new(encoded.clone()).expect("serializable");
            if encoded.len() < METADATA_COMPRESS_WATERMARK {
                assert_eq!(stored.len(), encoded.len() + U32_LEN + 1);
            } else {
                assert!(
                    stored.len() < encoded.len(),
                    "large containers are compressed"
                );
            }

            let mut scratch = Vec::new();
            let view = StoredMetadata::view(stored.as_bytes(), &mut scratch).expect("readable");
            assert_eq!(view.as_bytes(), encoded.as_bytes());

            let owned = MetadataBuf::read(stored.as_bytes()).expect("readable");
            assert_eq!(owned.view().as_bytes(), encoded.as_bytes());
            assert_eq!(owned.stored_len() as usize, stored.len());
            assert_eq!(owned.kinds(), MetadataKinds::IMAP);
            assert_eq!(
                owned.hash(),
                StoredMetadata::trailer_hash(stored.as_bytes()).expect("trailer")
            );

            let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(stored.as_bytes())
                .expect("the generic archive reader accepts raw containers");
            assert_eq!(archive.as_bytes(), encoded.as_bytes());

            let mut corrupted = stored.into_bytes();
            if let Some(byte) = corrupted.first_mut() {
                *byte ^= 0xFF;
            }
            assert!(StoredMetadata::view(&corrupted, &mut scratch).is_err());
        }
    }

    #[test]
    fn uncompressed_containers_are_framed_in_place() {
        let encoded = container(1);
        let contents = encoded.as_bytes().as_ptr();
        let stored = StoredMetadata::new(encoded).expect("serializable");
        assert_eq!(stored.as_bytes().as_ptr(), contents);
    }

    #[test]
    fn trailer_hash_asserts_stored_containers() {
        for repeat in [1, 100, 2000] {
            let stored = StoredMetadata::new(container(repeat)).expect("serializable");
            let bytes = stored.as_bytes();
            let hash = StoredMetadata::trailer_hash(bytes).expect("trailer");

            let archive =
                <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes).expect("readable");
            assert_eq!(archive.version, ArchiveVersion::Hashed { hash }, "{repeat}");
            assert!(AssertValue::Archive(ArchiveVersion::Hashed { hash }).matches(bytes));
            assert!(!AssertValue::None.matches(bytes));

            let other = StoredMetadata::new(container(repeat + 1)).expect("serializable");
            assert!(
                !AssertValue::Archive(ArchiveVersion::Hashed { hash }).matches(other.as_bytes()),
                "{repeat}"
            );
            assert!(
                !AssertValue::Archive(ArchiveVersion::Hashed {
                    hash: hash.wrapping_add(1)
                })
                .matches(bytes)
            );
        }
        assert!(StoredMetadata::trailer_hash(&[0; U32_LEN]).is_err());
    }

    #[test]
    fn viewer_state_roundtrip() {
        let state = ViewerState {
            change_id: u64::MAX - 7,
            containers: 42,
        };
        assert_eq!(
            ViewerState::deserialize(&state.serialize()).expect("valid"),
            state
        );
        assert!(ViewerState::deserialize(&[0; VIEWER_STATE_LEN - 1]).is_err());
        assert!(ViewerState::deserialize(&[0; VIEWER_STATE_LEN + 1]).is_err());
    }

    #[test]
    fn metadata_keys() {
        let collection = u8::from(Collection::Email);
        let metadata = u8::from(Collection::Metadata);
        for (class, expected) in [
            (
                MetadataClass::Shared,
                [
                    &7u32.to_be_bytes()[..],
                    &[metadata, 0, collection],
                    &9u32.to_be_bytes(),
                ]
                .concat(),
            ),
            (
                MetadataClass::Private { viewer: 3 },
                [
                    &7u32.to_be_bytes()[..],
                    &[metadata, 1],
                    &3u32.to_be_bytes(),
                    &[collection],
                    &9u32.to_be_bytes(),
                ]
                .concat(),
            ),
            (
                MetadataClass::Viewer { viewer: 3 },
                [
                    &7u32.to_be_bytes()[..],
                    &[metadata, 2, collection],
                    &3u32.to_be_bytes(),
                ]
                .concat(),
            ),
            (
                MetadataClass::Owner { owner: 5 },
                [
                    &7u32.to_be_bytes()[..],
                    &[metadata, 3],
                    &5u32.to_be_bytes(),
                    &[collection],
                ]
                .concat(),
            ),
        ] {
            let key = ValueKey {
                account_id: 7,
                collection,
                document_id: 9,
                class: ValueClass::Metadata(class),
            };
            assert_eq!(key.serialize(0), expected, "{class:?}");
            assert_eq!(key.key_len_hint(), expected.len(), "{class:?}");
        }
    }

    #[test]
    fn private_log_keys() {
        let private = LogCollection::Private {
            collection: SyncCollection::Calendar,
            viewer: 5,
        };
        assert_eq!(
            u8::from(private),
            PRIVATE_LOG | u8::from(SyncCollection::Calendar)
        );
        assert_eq!(
            private.change_group(),
            SyncCollection::Calendar.change_group()
        );
        let key = private.log_key(7, 99);
        let expected = [
            &7u32.to_be_bytes()[..],
            &[PRIVATE_LOG | u8::from(SyncCollection::Calendar)],
            &5u32.to_be_bytes(),
            &99u64.to_be_bytes(),
        ]
        .concat();
        assert_eq!(key.serialize(0), expected);
        assert_eq!(key.key_len_hint(), expected.len());

        let shared = LogCollection::Sync(SyncCollection::Calendar).log_key(7, 99);
        assert_eq!(
            shared.serialize(0),
            [
                &7u32.to_be_bytes()[..],
                &[u8::from(SyncCollection::Calendar)],
                &99u64.to_be_bytes(),
            ]
            .concat()
        );
        assert!(
            LogCollection::Private {
                collection: SyncCollection::Email,
                viewer: 1,
            }
            .is_prefixed()
        );
    }

    fn logged_collections(batch: &BatchBuilder) -> Vec<LogCollection> {
        batch
            .ops
            .iter()
            .filter_map(|op| match op {
                Operation::Log { collection, .. } => Some(*collection),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn private_rows_allocate_a_change_id_without_notifying() {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(1)
            .with_collection(Collection::Email)
            .with_document(5)
            .log_private_item_metadata(SyncCollection::Email, 9, Some(PendingId::Assigned(2)));
        batch.add_commit_point();

        assert!(batch.changed_collections.is_empty());
        assert_eq!(
            batch.change_accounts,
            vec![ChangeCounter {
                account_id: 1,
                group: SyncCollection::Email.change_group(),
            }]
        );
        assert_eq!(
            logged_collections(&batch),
            vec![LogCollection::Private {
                collection: SyncCollection::Email,
                viewer: 9,
            }]
        );
    }

    #[test]
    fn shared_metadata_rows_notify_like_other_changes() {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(1)
            .with_collection(Collection::Mailbox)
            .with_document(3)
            .log_container_metadata(SyncCollection::Email)
            .with_collection(Collection::CalendarEvent)
            .with_document(4)
            .log_item_metadata(SyncCollection::Calendar, None);
        batch.add_commit_point();

        let changed = batch
            .changed_collections
            .get(&1)
            .expect("account 1 changed");
        assert!(changed.changed_containers.contains(SyncCollection::Email));
        assert!(changed.changed_items.contains(SyncCollection::Calendar));
        assert!(!changed.changed_items.contains(SyncCollection::Email));
        let mut logged = logged_collections(&batch);
        logged.sort_unstable_by_key(|collection| u8::from(*collection));
        assert_eq!(
            logged,
            vec![
                LogCollection::Sync(SyncCollection::Email),
                LogCollection::Sync(SyncCollection::Calendar),
            ]
        );
    }
}
