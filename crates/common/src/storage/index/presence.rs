/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{IndexableAndSerializableObject, IndexableObject, SerializableObject};
use rkyv::{
    api::high::{HighDeserializer, HighValidator},
    bytecheck::CheckBytes,
    rancor,
};
use store::write::{Archive, BatchBuilder};
use trc::AddContext;
use types::{collection::Collection, field::Field, metadata::MetadataKinds};

pub trait PresenceFlags: SerializableObject + IndexableAndSerializableObject {
    const COLLECTION: Collection;
    const TRACKED: MetadataKinds;

    fn set_metadata_kinds(&mut self, kinds: MetadataKinds);
}

pub trait RewritePresence: rkyv::Archive {
    fn rewrite_presence(
        current: &Archive<&Self::Archived>,
        kinds: MetadataKinds,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()>;
}

impl<T> RewritePresence for T
where
    T: PresenceFlags,
    T::Archived: for<'a> CheckBytes<HighValidator<'a, rancor::Error>>
        + rkyv::Deserialize<T, HighDeserializer<rancor::Error>>
        + Sync
        + Send,
    for<'a> &'a T::Archived: IndexableObject,
{
    fn rewrite_presence(
        current: &Archive<&T::Archived>,
        kinds: MetadataKinds,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if current.inner.metadata_kinds().bits() == kinds.bits() & T::TRACKED.bits() {
            return Ok(());
        }
        let mut object = current.deserialize::<T>().caused_by(trc::location!())?;
        object.set_metadata_kinds(kinds);
        rewrite_archive(
            current,
            object,
            T::COLLECTION,
            account_id,
            document_id,
            batch,
        )
    }
}

pub fn rewrite_archive<A>(
    current: &Archive<A>,
    changes: impl SerializableObject,
    collection: Collection,
    account_id: u32,
    document_id: u32,
    batch: &mut BatchBuilder,
) -> trc::Result<()> {
    batch
        .with_account_id(account_id)
        .with_collection(collection)
        .with_document(document_id)
        .assert_value(Field::ARCHIVE, current);
    changes.serialize_into(batch, None)
}
