/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    decode::DecodeOutcome,
    document::Document,
    object::{Array, ArrayIter, Dict, MAX_OBJECT_NUMBER, ObjRef, Object},
};

pub(crate) const MAX_TREE_DEPTH: usize = 64;
const WORD_BITS: usize = u64::BITS as usize;
const CONTENT_SEPARATOR: u8 = b'\n';

#[derive(Default)]
pub(crate) struct Visited {
    words: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Page<'d> {
    pub(crate) dict: Dict<'d>,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "page identity is reported by the corpus inspection test"
        )
    )]
    pub(crate) id: Option<ObjRef>,
    pub(crate) resources: Option<Dict<'d>>,
    pub(crate) media_box: Option<Array<'d>>,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "rotation never changes content order, only the page-tree tests read it"
        )
    )]
    pub(crate) rotate: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Contents {
    pub(crate) streams: usize,
    pub(crate) failures: usize,
    pub(crate) truncated: bool,
}

#[derive(Clone, Copy)]
struct Inherited<'d> {
    resources: Option<Dict<'d>>,
    media_box: Option<Array<'d>>,
    rotate: i64,
}

enum Kids<'d> {
    Many(ArrayIter<'d>),
    One(Option<Object<'d>>),
}

struct Frame<'d> {
    kids: Kids<'d>,
    inherited: Inherited<'d>,
}

pub(crate) struct Pages<'d, 'a, 'v> {
    doc: &'d Document<'a>,
    visited: &'v mut Visited,
    root: Option<Object<'d>>,
    stack: Vec<Frame<'d>>,
    yielded: usize,
    fallback: Option<usize>,
}

impl Visited {
    pub(crate) fn clear(&mut self) {
        self.words.clear();
    }

    pub(crate) fn shrink(&mut self, max_bytes: usize) {
        self.words.clear();
        self.words.shrink_to(max_bytes / std::mem::size_of::<u64>());
    }

    pub(crate) fn insert(&mut self, num: u32) -> bool {
        if num > MAX_OBJECT_NUMBER {
            return false;
        }
        let (word, bit) = (num as usize / WORD_BITS, num as usize % WORD_BITS);
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        let Some(slot) = self.words.get_mut(word) else {
            return false;
        };
        let mask = 1u64 << bit;
        let fresh = *slot & mask == 0;
        *slot |= mask;
        fresh
    }
}

impl<'d, 'a, 'v> Pages<'d, 'a, 'v> {
    pub(crate) fn new(doc: &'d Document<'a>, visited: &'v mut Visited) -> Self {
        visited.clear();
        Pages {
            root: doc.page_tree_root(),
            doc,
            visited,
            stack: Vec::new(),
            yielded: 0,
            fallback: None,
        }
    }

    fn visit(&mut self, node: Object<'d>, inherited: Inherited<'d>) -> Option<Page<'d>> {
        let id = node.as_ref();
        if let Some(id) = id
            && !self.visited.insert(id.num)
        {
            return None;
        }
        let Object::Dict(dict) = self.doc.resolve(node) else {
            return None;
        };
        let doc = self.doc;
        let (mut resources, mut rotate, mut kids, mut kind) = (None, None, None, None);
        let mut media_box = None;
        for (key, value) in dict.iter() {
            hashify::fnc_map!(key.decoded(),
                b"Resources" => resources = Some(value),
                b"MediaBox" => media_box = Some(value),
                b"Rotate" => rotate = Some(value),
                b"Kids" => kids = Some(value),
                b"Type" => kind = Some(value),
                _ => {}
            );
        }
        let inherited = Inherited {
            resources: resources
                .and_then(|value| doc.resolve(value).as_dict())
                .or(inherited.resources),
            media_box: media_box
                .and_then(|value| doc.resolve(value).as_array())
                .or(inherited.media_box),
            rotate: rotate
                .and_then(|value| doc.resolve(value).as_int())
                .unwrap_or(inherited.rotate),
        };
        let kids = match kids.map(|value| (value, doc.resolve(value))) {
            Some((_, Object::Array(array))) => Some(Kids::Many(array.iter())),
            Some((Object::Ref(kid), Object::Dict(_))) => Some(Kids::One(Some(Object::Ref(kid)))),
            _ => None,
        };
        let kind = kind.and_then(|value| doc.resolve(value).as_name());
        let is_tree = match kind {
            Some(kind) if kind.is(b"Pages") => true,
            Some(kind) if kind.is(b"Page") => false,
            _ => kids.is_some(),
        };
        if !is_tree {
            self.yielded += 1;
            return Some(Page {
                dict,
                id,
                resources: inherited.resources,
                media_box: inherited.media_box,
                rotate: inherited.rotate,
            });
        }
        if let Some(kids) = kids
            && self.stack.len() < MAX_TREE_DEPTH
        {
            self.stack.push(Frame { kids, inherited });
        }
        None
    }

    fn next_fallback(&mut self) -> Option<Page<'d>> {
        let doc = self.doc;
        let candidates = doc.fallback_pages();
        let mut index = self.fallback.unwrap_or(0);
        while let Some(&id) = candidates.get(index) {
            index += 1;
            self.fallback = Some(index);
            if !self.visited.insert(id.num) {
                continue;
            }
            let Object::Dict(dict) = doc.get(id) else {
                continue;
            };
            let inherited = Inherited::from_ancestors(doc, dict);
            return Some(Page {
                dict,
                id: Some(id),
                resources: inherited.resources,
                media_box: inherited.media_box,
                rotate: inherited.rotate,
            });
        }
        self.fallback = Some(index);
        None
    }
}

impl<'d> Inherited<'d> {
    fn from_ancestors(doc: &'d Document<'_>, page: Dict<'d>) -> Self {
        let mut inherited = Inherited {
            resources: None,
            media_box: None,
            rotate: 0,
        };
        let mut rotate = None;
        let mut node = Some(page);
        for _ in 0..MAX_TREE_DEPTH {
            let Some(dict) = node else {
                break;
            };
            inherited.resources = inherited
                .resources
                .or_else(|| doc.get_dict(dict, b"Resources"));
            inherited.media_box = inherited
                .media_box
                .or_else(|| doc.get_array(dict, b"MediaBox"));
            rotate = rotate.or_else(|| doc.get_int(dict, b"Rotate"));
            if inherited.resources.is_some() && inherited.media_box.is_some() && rotate.is_some() {
                break;
            }
            node = doc.get_dict(dict, b"Parent");
        }
        inherited.rotate = rotate.unwrap_or(0);
        inherited
    }
}

impl<'d> Iterator for Pages<'d, '_, '_> {
    type Item = Page<'d>;

    fn next(&mut self) -> Option<Page<'d>> {
        loop {
            if self.doc.exhausted() {
                return None;
            }
            if let Some(root) = self.root.take() {
                let root_page = self.visit(
                    root,
                    Inherited {
                        resources: None,
                        media_box: None,
                        rotate: 0,
                    },
                );
                if root_page.is_some() {
                    return root_page;
                }
                continue;
            }
            if let Some(frame) = self.stack.last_mut() {
                let inherited = frame.inherited;
                let kid = match &mut frame.kids {
                    Kids::Many(kids) => kids.next(),
                    Kids::One(kid) => kid.take(),
                };
                match kid {
                    Some(kid) => {
                        if let Some(page) = self.visit(kid, inherited) {
                            return Some(page);
                        }
                    }
                    None => {
                        self.stack.pop();
                    }
                }
                continue;
            }
            if self.yielded > 0 {
                return None;
            }
            return self.next_fallback();
        }
    }
}

impl<'d> Page<'d> {
    pub(crate) fn media_box(&self, doc: &'d Document<'_>) -> Option<[f64; 4]> {
        let mut values = [0f64; 4];
        let mut count = 0;
        for (slot, value) in values.iter_mut().zip(doc.array_iter(self.media_box?)) {
            *slot = value.as_f64()?;
            count += 1;
        }
        let [x0, y0, x1, y1] = values;
        (count == values.len()).then(|| [x0.min(x1), y0.min(y1), x0.max(x1), y0.max(y1)])
    }

    pub(crate) fn annots(&self, doc: &'d Document<'_>) -> Option<Array<'d>> {
        doc.get_array(self.dict, b"Annots")
    }

    pub(crate) fn contents<'r>(
        &self,
        doc: &'d Document<'_>,
        out: &'r mut Vec<u8>,
    ) -> (&'r [u8], Contents)
    where
        'd: 'r,
    {
        out.clear();
        match doc.dict_get(self.dict, b"Contents") {
            Object::Stream(stream) => {
                let (data, outcome) = doc.stream_bytes(stream, out);
                let contents = Contents {
                    streams: 1,
                    failures: usize::from(outcome.is_failure()),
                    truncated: outcome == DecodeOutcome::Truncated,
                };
                (data, contents)
            }
            Object::Array(array) => {
                let contents = Page::concatenate(doc, array, out);
                (out, contents)
            }
            _ => (out, Contents::default()),
        }
    }

    fn concatenate(doc: &'d Document<'_>, array: Array<'d>, out: &mut Vec<u8>) -> Contents {
        let mut contents = Contents::default();
        let mut append = |object: Object<'_>, contents: &mut Contents| {
            let Some(stream) = object.as_stream() else {
                return;
            };
            if !out.is_empty() {
                out.push(CONTENT_SEPARATOR);
            }
            contents.streams += 1;
            match doc.decode_stream(stream, out) {
                DecodeOutcome::Truncated => contents.truncated = true,
                outcome if outcome.is_failure() => contents.failures += 1,
                _ => {}
            }
        };
        for item in doc.array_iter(array) {
            if doc.exhausted() {
                contents.truncated = true;
                break;
            }
            append(item, &mut contents);
        }
        contents
    }
}
