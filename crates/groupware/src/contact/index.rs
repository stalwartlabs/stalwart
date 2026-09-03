/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AddressBook, ArchivedAddressBook, ArchivedContactCard, ArchivedContactCardContent,
    CARD_HAS_DEAD_PROPERTIES, ContactCard, ContactCardContent,
};
use crate::{MetaHasher, SizeWriter};
use ahash::AHashSet;
use calcard::{
    common::IanaString,
    vcard::{ArchivedVCardProperty, ArchivedVCardValue, VCardProperty, VCardVersion},
};
use common::storage::index::{
    ArchivedSplitObject, IndexItem, IndexValue, IndexableAndSerializableObject, IndexableObject,
    SEARCH_HASH_UNCHANGED, SerializableObject, SplitObject, serialize_object,
};
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use store::{
    search::{ContactSearchField, IndexDocument, SearchField},
    write::{ArchiveCompression, BatchBuilder, Compression, Dictionary, SearchIndex, Slot},
    xxhash_rust::xxh3,
};
use types::{
    acl::AclGrant,
    collection::SyncCollection,
    field::{ContactField, Field},
};
use utils::sanitize_email;

impl IndexableObject for AddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::AddressBook,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedAddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::AddressBook,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for AddressBook {
    fn is_versioned() -> bool {
        true
    }
}

impl SerializableObject for AddressBook {
    fn serialize_into(self, batch: &mut BatchBuilder, pending_id: Option<Slot>) -> trc::Result<()> {
        serialize_object(self, batch, pending_id)
    }
}

impl IndexableObject for ContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: IndexItem::None,
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: SEARCH_HASH_UNCHANGED,
            },
            IndexValue::Quota { used: self.size },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        self.meta_index_values().into_iter()
    }
}

impl IndexableAndSerializableObject for ContactCard {
    fn is_versioned() -> bool {
        true
    }

    fn set_pending_id(&mut self, document_id: u32) {
        let content_hash = self.etag ^ self.meta_hash();
        self.names
            .last_mut()
            .expect("a pending address book id requires a name")
            .parent_id = document_id;
        self.etag = content_hash ^ self.meta_hash();
    }

    fn size_hint(&self) -> usize {
        self.meta_size_hint()
    }
}

impl SplitObject for ContactCard {
    type Content = ContactCardContent;
    type Context = VCardVersion;

    const CONTENT_FIELD: Field = ContactField::Content.field();

    fn meta_hash(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        hasher.u32(self.names.len() as u32);
        for name in &self.names {
            hasher.str(&name.name).u32(name.parent_id);
        }
        hasher
            .str(&self.uid)
            .opt_str(self.display_name.as_deref())
            .i64(self.created)
            .i64(self.modified)
            .u32(self.size)
            .u16(self.flags)
            .finish()
    }

    fn set_etag(&mut self, etag: u32) {
        self.etag = etag;
    }

    fn etag_value(&self) -> u32 {
        self.etag
    }

    fn refresh_from_content(&mut self, content: &ContactCardContent, ctx: VCardVersion) {
        self.uid = content.card.uid().unwrap_or_default().to_string();
        self.size = SizeWriter::vcard(&content.card, ctx) as u32;
        if content.dead_properties.is_empty() {
            self.flags &= !CARD_HAS_DEAD_PROPERTIES;
        } else {
            self.flags |= CARD_HAS_DEAD_PROPERTIES;
        }
    }

    fn full_index_values<'x>(&'x self, content: &'x ContactCardContent) -> Vec<IndexValue<'x>> {
        vec![
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: content.emails().next().into(),
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: content.hashes().fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Quota { used: self.size },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
    }
}

impl ArchivedSplitObject for ArchivedContactCard {
    type ArchivedContent = ArchivedContactCardContent;

    const CONTENT_FIELD: Field = ContactField::Content.field();

    fn meta_hash(&self) -> u32 {
        let mut hasher = MetaHasher::new();
        hasher.u32(self.names.len() as u32);
        for name in self.names.iter() {
            hasher.str(&name.name).u32(name.parent_id.to_native());
        }
        hasher
            .str(&self.uid)
            .opt_str(self.display_name.as_deref())
            .i64(self.created.to_native())
            .i64(self.modified.to_native())
            .u32(self.size.to_native())
            .u16(self.flags.to_native())
            .finish()
    }

    fn etag(&self) -> u32 {
        self.etag.to_native()
    }

    fn meta_index_values(&self) -> Vec<IndexValue<'_>> {
        vec![
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: IndexItem::None,
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: SEARCH_HASH_UNCHANGED,
            },
            IndexValue::Quota {
                used: self.size.to_native(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
    }

    fn full_index_values<'x>(
        &'x self,
        content: &'x ArchivedContactCardContent,
    ) -> Vec<IndexValue<'x>> {
        vec![
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: content.emails().next().into(),
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: content.hashes().fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Quota {
                used: self.size.to_native(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
    }
}

impl AddressBook {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self
                .preferences
                .iter()
                .map(|p| p.name.len() + p.description.as_ref().map_or(0, |n| n.len()))
                .sum::<usize>()
            + self.name.len()
            + std::mem::size_of::<AddressBook>()
    }
}

impl ArchivedAddressBook {
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self
                .preferences
                .iter()
                .map(|p| p.name.len() + p.description.as_ref().map_or(0, |n| n.len()))
                .sum::<usize>()
            + self.name.len()
            + std::mem::size_of::<AddressBook>()
    }
}

impl ContactCard {
    pub fn meta_size_hint(&self) -> usize {
        self.uid.len()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + std::mem::size_of::<ContactCard>()
    }
}

impl ContactCardContent {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.card
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.name,
                    VCardProperty::Adr
                        | VCardProperty::N
                        | VCardProperty::Fn
                        | VCardProperty::Title
                        | VCardProperty::Org
                        | VCardProperty::Note
                        | VCardProperty::Nickname
                        | VCardProperty::Email
                        | VCardProperty::Kind
                        | VCardProperty::Uid
                        | VCardProperty::Member
                        | VCardProperty::Impp
                        | VCardProperty::Socialprofile
                        | VCardProperty::Tel
                )
            })
            .flat_map(|e| e.values.iter().filter_map(|v| v.as_text()))
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }

    pub fn emails(&self) -> impl Iterator<Item = String> {
        self.card.properties(&VCardProperty::Email).flat_map(|e| {
            e.values
                .iter()
                .filter_map(|v| v.as_text().and_then(sanitize_email))
        })
    }
}

impl ArchivedContactCard {
    pub fn meta_size_hint(&self) -> usize {
        self.uid.len()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + std::mem::size_of::<ContactCard>()
    }
}

impl ArchivedContactCardContent {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.card
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.name,
                    ArchivedVCardProperty::Adr
                        | ArchivedVCardProperty::N
                        | ArchivedVCardProperty::Fn
                        | ArchivedVCardProperty::Title
                        | ArchivedVCardProperty::Org
                        | ArchivedVCardProperty::Note
                        | ArchivedVCardProperty::Nickname
                        | ArchivedVCardProperty::Email
                        | ArchivedVCardProperty::Kind
                        | ArchivedVCardProperty::Uid
                        | ArchivedVCardProperty::Member
                        | ArchivedVCardProperty::Impp
                        | ArchivedVCardProperty::Socialprofile
                        | ArchivedVCardProperty::Tel
                )
            })
            .flat_map(|e| e.values.iter().filter_map(|v| v.as_text()))
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }

    pub fn emails(&self) -> impl Iterator<Item = String> {
        self.card.properties(&VCardProperty::Email).flat_map(|e| {
            e.values
                .iter()
                .filter_map(|v| v.as_text().and_then(sanitize_email))
        })
    }

    pub fn index_document(
        &self,
        account_id: u32,
        document_id: u32,
        index_fields: &AHashSet<SearchField>,
        default_language: Language,
    ) -> IndexDocument {
        let mut document = IndexDocument::new(SearchIndex::Contacts)
            .with_account_id(account_id)
            .with_document_id(document_id);
        let mut detector = LanguageDetector::new();

        for entry in self.card.entries.iter() {
            let (is_text, is_keyword, field) = match entry.name {
                ArchivedVCardProperty::N => (false, false, ContactSearchField::Name),
                ArchivedVCardProperty::Nickname => (false, false, ContactSearchField::Nickname),
                ArchivedVCardProperty::Org => (false, false, ContactSearchField::Organization),
                ArchivedVCardProperty::Email => (false, false, ContactSearchField::Email),
                ArchivedVCardProperty::Tel => (false, false, ContactSearchField::Phone),
                ArchivedVCardProperty::Impp | ArchivedVCardProperty::Socialprofile => {
                    (false, false, ContactSearchField::OnlineService)
                }
                ArchivedVCardProperty::Adr => (false, false, ContactSearchField::Address),
                ArchivedVCardProperty::Note => (true, false, ContactSearchField::Note),
                ArchivedVCardProperty::Kind => (false, true, ContactSearchField::Kind),
                ArchivedVCardProperty::Member => (false, false, ContactSearchField::Member),
                _ => continue,
            };
            let field = SearchField::Contact(field);

            if index_fields.is_empty() || index_fields.contains(&field) {
                for value in entry.values.iter() {
                    match value {
                        ArchivedVCardValue::Text(v) => {
                            if !is_keyword {
                                let lang = if is_text {
                                    detector.detect(v.as_str().trim(), MIN_LANGUAGE_SCORE);
                                    Language::Unknown
                                } else {
                                    Language::None
                                };

                                document.index_text(field.clone(), v, lang);
                            } else {
                                document.index_keyword(field.clone(), v.as_str());
                            }
                        }
                        ArchivedVCardValue::Kind(v) => {
                            document.index_keyword(field.clone(), v.as_str());
                        }
                        ArchivedVCardValue::Component(v) => {
                            for item in v.iter() {
                                document.index_text(field.clone(), item.trim(), Language::None);
                            }
                        }
                        _ => (),
                    }
                }

                /*for param in entry.params.iter() {
                    if let ArchivedVCardParameterValue::Text(value) = &param.value {
                        let lang = if is_text {
                            detector.detect(value.as_str(), MIN_LANGUAGE_SCORE);
                            Language::Unknown
                        } else {
                            Language::None
                        };
                        document.index_text(field.clone(), value, lang);
                    }
                }*/
            }
        }

        document.set_unknown_language(
            detector
                .most_frequent_language()
                .unwrap_or(default_language),
        );

        document
    }
}

impl ArchiveCompression for AddressBook {
    const COMPRESSION: Compression = Compression::None;
}

impl ArchiveCompression for ContactCard {
    const COMPRESSION: Compression = Compression::None;
}

impl ArchiveCompression for ContactCardContent {
    const COMPRESSION: Compression = Compression::Zstd(Some(Dictionary::Contact));
}
