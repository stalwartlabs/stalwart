/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard};
use ahash::AHashSet;
use calcard::{
    common::IanaString,
    vcard::{ArchivedVCardProperty, ArchivedVCardValue, VCardProperty},
};
use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use store::{
    search::{ContactSearchField, IndexDocument, SearchField},
    write::{IndexPropertyClass, SearchIndex, ValueClass},
    xxhash_rust::xxh3,
};
use types::{acl::AclGrant, collection::SyncCollection, field::ContactField};
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

impl IndexableObject for ContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: ContactField::Uid.into(),
                value: self.card.uid().into(),
            },
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: self.emails().next().into(),
            },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: ContactField::CreatedToUpdated.into(),
                    value: self.created as u64,
                }),
                value: self.modified.into(),
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: self.hashes().fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
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
        [
            IndexValue::Index {
                field: ContactField::Uid.into(),
                value: self.card.uid().into(),
            },
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: self.emails().next().into(),
            },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: ContactField::CreatedToUpdated.into(),
                    value: self.created.to_native() as u64,
                }),
                value: (self.modified.to_native() as u64).into(),
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: self.hashes().fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Quota {
                used: self.size() as u32,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for ContactCard {
    fn is_versioned() -> bool {
        true
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
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + self.size as usize
            + std::mem::size_of::<ContactCard>()
    }

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
    pub fn size(&self) -> usize {
        self.dead_properties.size()
            + self.display_name.as_ref().map_or(0, |n| n.len())
            + self.names.iter().map(|n| n.name.len()).sum::<usize>()
            + self.size.to_native() as usize
            + std::mem::size_of::<ContactCard>()
    }

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
                ArchivedVCardProperty::Uid => (false, true, ContactSearchField::Uid),
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
