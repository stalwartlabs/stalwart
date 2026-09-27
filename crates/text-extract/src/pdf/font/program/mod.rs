/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod cff;
mod cff_data;
mod cmap;
mod post;
mod post_data;
mod read;
mod sfnt;
mod truetype;
mod type1;

#[cfg(test)]
mod tests;

pub(crate) use self::cff::Cff;
pub(crate) use self::cmap::{Cmap, CmapSubtable};
pub(crate) use self::post::Post;
pub(crate) use self::sfnt::Sfnt;
pub(crate) use self::truetype::TrueType;

const CODE_COUNT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BuiltinEncoding<'x> {
    Standard,
    Expert,
    Custom(CodeNames<'x>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeNames<'x> {
    names: Box<[Option<&'x [u8]>; CODE_COUNT]>,
}

impl<'x> CodeNames<'x> {
    fn new() -> Self {
        Self {
            names: Box::new([None; CODE_COUNT]),
        }
    }

    fn set(&mut self, code: u8, name: &'x [u8]) {
        if let Some(slot) = self.names.get_mut(usize::from(code)) {
            *slot = Some(name);
        }
    }

    pub(crate) fn get(&self, code: u8) -> Option<&'x [u8]> {
        self.names.get(usize::from(code)).copied().flatten()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u8, &'x [u8])> + '_ {
        (0..=u8::MAX)
            .zip(self.names.iter())
            .filter_map(|(code, name)| name.map(|name| (code, name)))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.names.iter().all(Option::is_none)
    }
}
