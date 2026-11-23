/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod canonical;
pub mod code_page;
pub mod codec;
pub mod name;
pub mod owned;
pub mod row;
pub mod seed;
mod seed_table;
pub mod tag;
pub mod tagged;
pub mod tags;
pub mod value;

pub use canonical::read_canonical_borrowed;
pub use code_page::CodePage;
pub use codec::{decode_value, encode_owned, encode_value};
pub use name::{
    FIRST_NAMED_ID, MAX_NAMED_IDS, NamedPropMap, PropKey, PropKeyRef, PropertyName,
    StaticNamedPropMap, sets,
};
pub use owned::OwnedPropValue;
pub use tag::{PropId, PropTag, PropType};
pub use tagged::{TaggedIter, TaggedValues};
pub use value::{CountWidth, MvDialect, MvError, MvIter, MvType, MvView, PropValue};
