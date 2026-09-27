/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Font;
use crate::pdf::{
    document::Document,
    object::{ObjRef, Object},
};
use std::{
    cell::OnceCell,
    collections::{HashMap, VecDeque},
};

pub(crate) const MAX_FONTS: usize = 4096;
pub(crate) const MAX_FONT_HEAP: usize = 16 << 20;
const MAX_TRANSIENT: usize = 64;
const MAX_TRANSIENT_HEAP: usize = 16 << 20;
const TRANSIENT_BIT: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FontId(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FontKey {
    Ref(ObjRef),
    Direct(usize, usize),
}

struct Transient {
    serial: u32,
    key: FontKey,
    size: usize,
    font: Font,
}

pub(crate) struct FontCache {
    fonts: Vec<Font>,
    keys: HashMap<FontKey, FontId>,
    transient: VecDeque<Transient>,
    serial: u32,
    heap: usize,
    transient_heap: usize,
    standard: OnceCell<Font>,
}

impl Default for FontCache {
    fn default() -> Self {
        FontCache {
            fonts: Vec::new(),
            keys: HashMap::new(),
            transient: VecDeque::new(),
            serial: 0,
            heap: 0,
            transient_heap: 0,
            standard: OnceCell::new(),
        }
    }
}

impl FontId {
    pub(crate) const STANDARD: FontId = FontId(u32::MAX);

    #[cfg(test)]
    pub(crate) const FIRST: FontId = FontId(0);
}

impl FontCache {
    pub(crate) fn clear(&mut self) {
        self.fonts.clear();
        self.keys.clear();
        self.end_page();
        self.serial = 0;
        self.heap = 0;
    }

    pub(crate) fn shrink(&mut self) {
        self.clear();
        self.fonts.shrink_to(0);
        self.keys.shrink_to(0);
        self.transient.shrink_to(0);
    }

    pub(crate) fn load(
        &mut self,
        doc: &Document<'_>,
        value: Object<'_>,
        buf: &mut Vec<u8>,
    ) -> Option<FontId> {
        let key = match value {
            Object::Ref(id) => FontKey::Ref(id),
            Object::Dict(dict) => FontKey::Direct(dict.body().as_ptr() as usize, dict.body().len()),
            _ => return None,
        };
        if let Some(&id) = self.keys.get(&key) {
            return Some(id);
        }
        if let Some(stored) = self.transient.iter().find(|stored| stored.key == key) {
            return Some(FontId(TRANSIENT_BIT | stored.serial));
        }
        let dict = doc.resolve(value).as_dict()?;
        let font = Font::load(doc, dict, buf);
        let size = font.heap_size();
        if self.fonts.len() < MAX_FONTS && self.heap.saturating_add(size) <= MAX_FONT_HEAP {
            let id = FontId(u32::try_from(self.fonts.len()).ok()?);
            self.heap += size;
            self.fonts.push(font);
            self.keys.insert(key, id);
            return Some(id);
        }
        while !self.transient.is_empty()
            && (self.transient.len() >= MAX_TRANSIENT
                || self.transient_heap.saturating_add(size) > MAX_TRANSIENT_HEAP)
        {
            if let Some(evicted) = self.transient.pop_front() {
                self.transient_heap -= evicted.size;
            }
        }
        self.serial = self.serial.wrapping_add(1) & !TRANSIENT_BIT;
        self.transient_heap += size;
        self.transient.push_back(Transient {
            serial: self.serial,
            key,
            size,
            font,
        });
        Some(FontId(TRANSIENT_BIT | self.serial))
    }

    #[inline]
    pub(crate) fn font(&self, id: FontId) -> &Font {
        if id.0 & TRANSIENT_BIT == 0 {
            return self
                .fonts
                .get(id.0 as usize)
                .unwrap_or_else(|| self.standard());
        }
        let serial = id.0 & !TRANSIENT_BIT;
        self.transient
            .front()
            .map(|first| serial.wrapping_sub(first.serial) & !TRANSIENT_BIT)
            .and_then(|index| self.transient.get(index as usize))
            .filter(|stored| stored.serial == serial)
            .map_or_else(|| self.standard(), |stored| &stored.font)
    }

    fn standard(&self) -> &Font {
        self.standard.get_or_init(Font::standard)
    }

    pub(crate) fn end_page(&mut self) {
        self.transient.clear();
        self.transient_heap = 0;
    }
}
