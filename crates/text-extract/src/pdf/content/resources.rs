/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::pdf::{
    document::Document,
    font::{FontCache, FontId},
    object::{Dict, Name, ObjRef, Object},
};
use std::collections::{HashMap, HashSet};

const MAX_CACHED_NAME: usize = 32;
const MAX_ENTRIES: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Category {
    Font,
    XObject,
    State,
    Properties,
}

type Location = (usize, usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    resources: Location,
    category: Category,
    name: [u8; MAX_CACHED_NAME],
    len: u8,
}

#[derive(Debug, Clone, Copy)]
enum Cached {
    Reference(ObjRef),
    Font(Option<FontId>),
    XObject(Option<ObjRef>),
    State(Option<(FontId, f64)>),
    Plain,
}

pub(crate) struct Lookup<'c, 'd, 'a> {
    pub(crate) doc: &'d Document<'a>,
    pub(crate) fonts: &'c mut FontCache,
    pub(crate) buf: &'c mut Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct ResourceCache {
    map: HashMap<Key, Cached>,
    indexed: HashSet<(Location, Category)>,
}

impl Category {
    fn key(self) -> &'static [u8] {
        match self {
            Category::Font => b"Font",
            Category::XObject => b"XObject",
            Category::State => b"ExtGState",
            Category::Properties => b"Properties",
        }
    }
}

fn location(resources: Option<Dict<'_>>) -> Location {
    resources.map_or((0, 0), |dict| {
        (dict.body().as_ptr() as usize, dict.body().len())
    })
}

impl Key {
    fn new(resources: Location, category: Category, name: &[u8]) -> Option<Self> {
        let len = u8::try_from(name.len())
            .ok()
            .filter(|&len| usize::from(len) <= MAX_CACHED_NAME)?;
        let mut stored = [0u8; MAX_CACHED_NAME];
        stored.get_mut(..name.len())?.copy_from_slice(name);
        Some(Key {
            resources,
            category,
            name: stored,
            len,
        })
    }
}

impl ResourceCache {
    pub(crate) fn clear(&mut self) {
        self.map.clear();
        self.indexed.clear();
    }

    pub(crate) fn shrink(&mut self) {
        self.map = HashMap::new();
        self.indexed = HashSet::new();
    }

    fn store(&mut self, key: Option<Key>, value: Cached) {
        if let Some(key) = key {
            if self.map.len() >= MAX_ENTRIES {
                self.clear();
            }
            self.map.insert(key, value);
        }
    }

    fn index(&mut self, doc: &Document<'_>, resources: Option<Dict<'_>>, category: Category) {
        let place = location(resources);
        if !self.indexed.insert((place, category)) {
            return;
        }
        let Some(group) = resources.and_then(|resources| doc.get_dict(resources, category.key()))
        else {
            return;
        };
        for (name, value) in group.iter() {
            if self.map.len() >= MAX_ENTRIES {
                return;
            }
            if let Object::Ref(id) = value
                && let Some(key) = Key::new(place, category, &name.decoded())
            {
                self.map.insert(key, Cached::Reference(id));
            }
        }
    }

    fn find<'d>(
        &mut self,
        doc: &'d Document<'_>,
        resources: Option<Dict<'d>>,
        category: Category,
        name: &[u8],
    ) -> (Option<Key>, Option<Cached>, Option<Object<'d>>) {
        let key = Key::new(location(resources), category, name);
        if let Some(key) = key {
            if let Some(&cached) = self.map.get(&key) {
                return (Some(key), Some(cached), None);
            }
            self.index(doc, resources, category);
            if let Some(&cached) = self.map.get(&key) {
                return (Some(key), Some(cached), None);
            }
        }
        (key, None, entry(doc, resources, category.key(), name))
    }

    pub(crate) fn font(
        &mut self,
        lookup: Lookup<'_, '_, '_>,
        resources: Option<Dict<'_>>,
        name: Name<'_>,
    ) -> Option<FontId> {
        let decoded = name.decoded();
        let (key, cached, direct) = self.find(lookup.doc, resources, Category::Font, &decoded);
        let value = match cached {
            Some(Cached::Font(font)) => return font,
            Some(Cached::Reference(id)) => Some(Object::Ref(id)),
            _ => direct,
        };
        let font = value.and_then(|value| lookup.fonts.load(lookup.doc, value, lookup.buf));
        self.store(key, Cached::Font(font));
        font
    }

    pub(crate) fn xobject(
        &mut self,
        doc: &Document<'_>,
        resources: Option<Dict<'_>>,
        name: Name<'_>,
    ) -> Option<ObjRef> {
        let decoded = name.decoded();
        let (key, cached, direct) = self.find(doc, resources, Category::XObject, &decoded);
        let id = match cached {
            Some(Cached::XObject(id)) => return id,
            Some(Cached::Reference(id)) => Some(id),
            _ => direct.and_then(|value| value.as_ref()),
        };
        self.store(key, Cached::XObject(id));
        id
    }

    pub(crate) fn state_font(
        &mut self,
        lookup: Lookup<'_, '_, '_>,
        resources: Option<Dict<'_>>,
        name: Name<'_>,
    ) -> Option<(FontId, f64)> {
        let decoded = name.decoded();
        let doc = lookup.doc;
        let (key, cached, direct) = self.find(doc, resources, Category::State, &decoded);
        let value = match cached {
            Some(Cached::State(font)) => return font,
            Some(Cached::Reference(id)) => Some(Object::Ref(id)),
            _ => direct,
        };
        let font = value
            .and_then(|value| doc.resolve(value).as_dict())
            .and_then(|state| doc.get_array(state, b"Font"))
            .and_then(|pair| {
                let mut items = pair.iter();
                let (font, size) = (items.next()?, doc.resolve(items.next()?).as_f64()?);
                Some((lookup.fonts.load(doc, font, lookup.buf)?, size))
            });
        self.store(key, Cached::State(font));
        font
    }

    pub(crate) fn actual_text<'d>(
        &mut self,
        doc: &'d Document<'_>,
        resources: Option<Dict<'d>>,
        name: Name<'_>,
    ) -> Option<Object<'d>> {
        let decoded = name.decoded();
        let (key, cached, direct) = self.find(doc, resources, Category::Properties, &decoded);
        let value = match cached {
            Some(Cached::Plain) => return None,
            Some(Cached::Reference(id)) => Some(Object::Ref(id)),
            _ => direct,
        };
        let text = value
            .and_then(|value| doc.resolve(value).as_dict())
            .map(|dict| doc.dict_get(dict, b"ActualText"))
            .filter(|text| !text.is_null());
        if text.is_none() {
            self.store(key, Cached::Plain);
        }
        text
    }
}

pub(crate) fn entry<'d>(
    doc: &'d Document<'_>,
    resources: Option<Dict<'d>>,
    category: &[u8],
    name: &[u8],
) -> Option<Object<'d>> {
    let group = doc.get_dict(resources?, category)?;
    group.get(name)
}
