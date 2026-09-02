/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CurrentObject, IndexValue, IndexableAndSerializableObject, IndexableObject, ObjectIndexBuilder,
    SerializableObject, serialize_object,
};
use crate::auth::AccountTenantIds;
use store::{
    Serialize,
    write::{Archive, ArchiveCompression, Archiver, BatchBuilder, Slot},
};
use types::field::Field;

pub trait SerializableContent:
    ArchiveCompression
    + rkyv::Archive
    + for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            Vec<u8>,
            rkyv::ser::allocator::ArenaHandle<'a>,
            rkyv::rancor::Error,
        >,
    > + Sync
    + Send
{
}

impl<T> SerializableContent for T where
    T: ArchiveCompression
        + rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                Vec<u8>,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        > + Sync
        + Send
{
}

pub trait SplitObject: IndexableAndSerializableObject
where
    Self::Archived: ArchivedSplitObject,
{
    type Content: SerializableContent;
    type Context: Copy;

    const CONTENT_FIELD: Field;

    fn meta_hash(&self) -> u32;

    fn set_etag(&mut self, etag: u32);

    fn etag_value(&self) -> u32;

    fn refresh_from_content(&mut self, content: &Self::Content, ctx: Self::Context);

    fn full_index_values<'x>(&'x self, content: &'x Self::Content) -> Vec<IndexValue<'x>>;
}

pub trait ArchivedSplitObject: Sync + Send {
    type ArchivedContent: Sync + Send;

    const CONTENT_FIELD: Field;

    fn meta_hash(&self) -> u32;

    fn etag(&self) -> u32;

    fn meta_index_values(&self) -> Vec<IndexValue<'_>>;

    fn full_index_values<'x>(&'x self, content: &'x Self::ArchivedContent) -> Vec<IndexValue<'x>>;
}

pub enum GroupwareWrite<M: SplitObject>
where
    M::Archived: ArchivedSplitObject,
{
    Full {
        meta: M,
        content: M::Content,
        content_archive: Vec<u8>,
    },
    MetaOnly(M),
}

impl<M: SplitObject> GroupwareWrite<M>
where
    M::Archived: ArchivedSplitObject,
{
    pub fn full(mut meta: M, content: M::Content, ctx: M::Context) -> trc::Result<Self> {
        let archiver = Archiver::new(content);
        let content_archive = archiver.serialize()?;
        let content = archiver.inner;

        meta.refresh_from_content(&content, ctx);
        meta.set_etag(content_hash(&content_archive) ^ meta.meta_hash());

        Ok(GroupwareWrite::Full {
            meta,
            content,
            content_archive,
        })
    }

    pub fn meta_only(mut meta: M, current: &M::Archived) -> Self {
        let payload = current.etag() ^ current.meta_hash();
        meta.set_etag(payload ^ meta.meta_hash());

        GroupwareWrite::MetaOnly(meta)
    }

    pub fn meta(&self) -> &M {
        match self {
            GroupwareWrite::Full { meta, .. } | GroupwareWrite::MetaOnly(meta) => meta,
        }
    }
}

fn content_hash(archive: &[u8]) -> u32 {
    store::xxhash_rust::xxh3::xxh3_64(archive) as u32
}

pub struct SplitUpdate<'x, M: SplitObject>
where
    M::Archived: ArchivedSplitObject,
{
    current: SplitCurrent<'x, M::Archived>,
    changes: GroupwareWrite<M>,
}

impl<'x, M: SplitObject> SplitUpdate<'x, M>
where
    M::Archived: ArchivedSplitObject,
{
    pub fn full(
        current_meta: Archive<&'x M::Archived>,
        current_content: &'x <M::Archived as ArchivedSplitObject>::ArchivedContent,
        meta: M,
        content: M::Content,
        ctx: M::Context,
    ) -> trc::Result<Self> {
        Ok(SplitUpdate {
            current: SplitCurrent::Full {
                meta: current_meta,
                content: current_content,
            },
            changes: GroupwareWrite::full(meta, content, ctx)?,
        })
    }

    pub fn meta_only(current_meta: Archive<&'x M::Archived>, meta: M) -> Self {
        let changes = GroupwareWrite::meta_only(meta, current_meta.inner);

        SplitUpdate {
            current: SplitCurrent::MetaOnly(current_meta),
            changes,
        }
    }

    pub fn etag(&self) -> String {
        format!("\"{}\"", self.changes.meta().etag_value())
    }

    pub fn into_builder(
        self,
        changed_by: AccountTenantIds,
        pending_id: Option<Slot>,
    ) -> ObjectIndexBuilder<SplitCurrent<'x, M::Archived>, GroupwareWrite<M>> {
        ObjectIndexBuilder::new()
            .with_current(self.current)
            .with_changes(self.changes)
            .with_changed_by(changed_by)
            .with_pending_id_opt(pending_id)
    }
}

impl<M: SplitObject> IndexableObject for GroupwareWrite<M>
where
    M::Archived: ArchivedSplitObject,
{
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        match self {
            GroupwareWrite::Full { meta, content, .. } => {
                meta.full_index_values(content).into_iter()
            }
            GroupwareWrite::MetaOnly(meta) => meta.index_values().collect::<Vec<_>>().into_iter(),
        }
    }
}

impl<M: SplitObject + 'static> SerializableObject for GroupwareWrite<M>
where
    M::Archived: ArchivedSplitObject,
{
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        match self {
            GroupwareWrite::Full {
                meta,
                content_archive,
                ..
            } => {
                serialize_object(meta, batch, pending_id)?;
                batch.set(M::CONTENT_FIELD, content_archive);
            }
            GroupwareWrite::MetaOnly(meta) => serialize_object(meta, batch, pending_id)?,
        }

        batch.set_archive_hash(None);

        Ok(())
    }
}

pub enum SplitCurrent<'x, M: ArchivedSplitObject> {
    Full {
        meta: Archive<&'x M>,
        content: &'x M::ArchivedContent,
    },
    MetaOnly(Archive<&'x M>),
}

impl<'x, M: ArchivedSplitObject> SplitCurrent<'x, M> {
    pub fn meta(&self) -> &Archive<&'x M> {
        match self {
            SplitCurrent::Full { meta, .. } | SplitCurrent::MetaOnly(meta) => meta,
        }
    }
}

impl<M: ArchivedSplitObject> CurrentObject for SplitCurrent<'_, M> {
    fn assert(&self, batch: &mut BatchBuilder) {
        batch.assert_value(Field::ARCHIVE, self.meta());
    }

    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        match self {
            SplitCurrent::Full { meta, content } => {
                meta.inner.full_index_values(content).into_iter()
            }
            SplitCurrent::MetaOnly(meta) => meta.inner.meta_index_values().into_iter(),
        }
    }

    fn clear(&self, batch: &mut BatchBuilder) {
        batch.clear(Field::ARCHIVE);
        batch.clear(M::CONTENT_FIELD);
    }
}
