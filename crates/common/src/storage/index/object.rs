/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::IndexValue;
use store::{
    Serialize, U32_LEN, U64_LEN,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, Archiver, AssignedIds, BatchBuilder, Patch,
        PatchSource, SerializeWithIds, SetValue, SizedSetValue, Slot,
    },
};
use types::field::Field;

pub trait IndexableObject: Sync + Send {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>>;
}

pub trait IndexableAndSerializableObject:
    IndexableObject
    + ArchiveCompression
    + rkyv::Archive
    + for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            Vec<u8>,
            rkyv::ser::allocator::ArenaHandle<'a>,
            rkyv::rancor::Error,
        >,
    >
{
    const PENDING_ID_FIELD: Option<ArchivedIdField> = None;

    fn is_versioned() -> bool;

    fn set_pending_id(&mut self, _document_id: u32) {
        unreachable!("object carries no pending document id")
    }

    fn size_hint(&self) -> usize {
        unreachable!("object carries no pending document id")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ArchivedIdField {
    offset: usize,
    base: u32,
}

impl ArchivedIdField {
    pub const fn new(offset: usize) -> Self {
        Self { offset, base: 0 }
    }

    pub const fn one_based(self) -> Self {
        Self {
            offset: self.offset,
            base: 1,
        }
    }

    pub fn patch(&self, root_offset: usize, slot: Slot) -> Patch {
        Patch {
            offset: (root_offset + self.offset) as u32,
            source: PatchSource::SlotArchivedU32 {
                slot,
                base: self.base,
            },
        }
    }
}

pub trait CurrentObject: Send + Sync {
    fn assert(&self, batch: &mut BatchBuilder);
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>>;
    fn clear(&self, batch: &mut BatchBuilder);
}

impl<T: IndexableObject> CurrentObject for Archive<T> {
    #[inline(always)]
    fn assert(&self, batch: &mut BatchBuilder) {
        batch.assert_value(Field::ARCHIVE, self);
    }

    #[inline(always)]
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        self.inner.index_values()
    }

    #[inline(always)]
    fn clear(&self, batch: &mut BatchBuilder) {
        batch.clear(Field::ARCHIVE);
    }
}

impl CurrentObject for () {
    fn assert(&self, _: &mut BatchBuilder) {}
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        std::iter::empty()
    }
    fn clear(&self, _: &mut BatchBuilder) {}
}

pub trait SerializableObject: IndexableObject {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()>;
}

struct PendingObject<T>
where
    T: IndexableAndSerializableObject,
{
    archiver: Archiver<T>,
    slot: Slot,
    size_hint: usize,
}

impl<T: IndexableAndSerializableObject + 'static> SerializeWithIds for PendingObject<T> {
    fn serialize_with_ids(&mut self, ids: &AssignedIds) -> trc::Result<(Vec<u8>, Option<u32>)> {
        self.archiver.inner.set_pending_id(ids.slot(self.slot));

        let mut archive = self.archiver.serialize()?;
        if T::is_versioned() {
            let offset = archive.len() - U64_LEN - 1;
            archive[offset..offset + U64_LEN]
                .copy_from_slice(&ids.current_change_id().to_be_bytes());
        }
        let hash = Archive::<ArchiveBytes>::extract_hash(&archive);

        Ok((archive, hash))
    }

    fn size_hint(&self) -> usize {
        self.size_hint
    }
}

impl<T: IndexableAndSerializableObject + 'static> From<PendingObject<T>> for SizedSetValue {
    fn from(object: PendingObject<T>) -> Self {
        SetValue::serializable(object)
    }
}

pub fn serialize_object<T: IndexableAndSerializableObject + 'static>(
    object: T,
    batch: &mut BatchBuilder,
    pending_id: Option<Slot>,
) -> trc::Result<()> {
    if let Some(slot) = pending_id {
        if let Some(field) = T::PENDING_ID_FIELD {
            const {
                assert!(std::mem::align_of::<T::Archived>() == 1);
            };
            debug_assert!(
                field.offset + U32_LEN <= std::mem::size_of::<T::Archived>(),
                "pending id field is outside the archived root"
            );

            let archiver = Archiver::new(object);
            let (payload_len, archive) = if T::is_versioned() {
                archiver.with_version().serialize_patchable()?
            } else {
                archiver.serialize_patchable()?
            };
            let root_offset = payload_len as usize - std::mem::size_of::<T::Archived>();
            let mut patches = vec![field.patch(root_offset, slot)];

            if T::is_versioned() {
                patches.push(Patch {
                    offset: (archive.len() - U64_LEN - 1) as u32,
                    source: PatchSource::ChangeIdBe,
                });
            }

            batch
                .set_archive_hash(None)
                .set(Field::ARCHIVE, (archive, patches));
        } else {
            let size_hint = object.size_hint();
            let archiver = Archiver::new(object);
            let archiver = if T::is_versioned() {
                archiver.with_version()
            } else {
                archiver
            };

            batch.set_archive_hash(None).set(
                Field::ARCHIVE,
                PendingObject {
                    archiver,
                    slot,
                    size_hint,
                },
            );
        }
    } else if T::is_versioned() {
        let (offset, archive) = Archiver::new(object).serialize_versioned()?;
        batch
            .set_archive_hash(Archive::<ArchiveBytes>::extract_hash(&archive))
            .set(
                Field::ARCHIVE,
                (
                    archive,
                    vec![Patch {
                        offset: offset as u32,
                        source: PatchSource::ChangeIdBe,
                    }],
                ),
            );
    } else {
        let archive = Archiver::new(object).serialize()?;
        batch
            .set_archive_hash(Archive::<ArchiveBytes>::extract_hash(&archive))
            .set(Field::ARCHIVE, archive);
    }

    Ok(())
}

impl IndexableObject for () {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        std::iter::empty()
    }
}

impl IndexableAndSerializableObject for () {
    fn is_versioned() -> bool {
        false
    }
}

impl SerializableObject for () {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        serialize_object(self, batch, pending_id)
    }
}
