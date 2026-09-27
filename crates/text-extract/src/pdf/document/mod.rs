/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod crypt;
mod fetch;
mod recover;
mod streams;
mod table;

use self::{
    crypt::Crypt,
    recover::Recovered,
    table::{Slot, Table, assign_slots},
};
use super::{
    object::{Array, Dict, Name, ObjRef, Object, Stream},
    source::{Codec, Source},
    xref::{self, Builder, Entries},
};
use crate::xml::stream::Budget;
use std::{
    borrow::Cow,
    cell::{Cell, OnceCell},
};

pub(crate) const MAX_REFERENCE_CHAIN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenError {
    Encrypted,
    Unusable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpenFailure {
    pub(crate) error: OpenError,
    pub(crate) used_bytes: u64,
}

#[derive(Default)]
pub(crate) struct DocScratch {
    entries: Entries,
    codec: Codec,
}

pub(crate) struct Document<'a> {
    source: Source<'a>,
    primary: Table<'a>,
    trailers: Vec<Dict<'a>>,
    repaired: OnceCell<Recovered<'a>>,
    repairing: Cell<bool>,
    catalog: Cell<Option<ObjRef>>,
    page_tree: Cell<Option<ObjRef>>,
    crypt: OnceCell<Crypt>,
    retained: Cell<usize>,
    nesting: Cell<u32>,
    max_objects: usize,
}

impl DocScratch {
    pub(crate) fn shrink(&mut self, max_bytes: usize) {
        self.entries.shrink(max_bytes);
        self.codec.shrink(max_bytes);
    }
}

impl<'a> Document<'a> {
    pub(crate) fn open(
        data: &'a [u8],
        scratch: &'a mut DocScratch,
        budget: Budget,
        max_objects: usize,
    ) -> Result<Self, OpenFailure> {
        let DocScratch { entries, codec } = scratch;
        let source = Source::new(data, codec, budget);
        let sections = {
            let mut builder = Builder::new(entries, data.len(), max_objects);
            let sections = xref::read_sections(&source, &mut builder);
            builder.finish();
            sections
        };
        let slots = assign_slots(entries);
        let entries: &'a Entries = entries;
        let (trailers, bias, found) = match sections {
            Some(sections) => (sections.trailers, sections.bias, true),
            None => (Vec::new(), source.header, false),
        };
        let header = source.header;
        let document = Document {
            source,
            primary: Table::new(Cow::Borrowed(entries), Slot::many(slots), bias, header),
            trailers,
            repaired: OnceCell::new(),
            repairing: Cell::new(false),
            catalog: Cell::new(None),
            page_tree: Cell::new(None),
            crypt: OnceCell::new(),
            retained: Cell::new(0),
            nesting: Cell::new(0),
            max_objects,
        };
        if !found {
            document.repair();
        }
        let fail = |document: &Document<'_>, error| OpenFailure {
            error,
            used_bytes: document.source.used_bytes(),
        };
        if document.crypt.get().is_none()
            && let Err(error) = document.setup_crypt(document.table(), &document.trailers())
        {
            return Err(fail(&document, error));
        }
        if !document.locate_root() {
            return Err(fail(&document, OpenError::Unusable));
        }
        Ok(document)
    }

    pub(crate) fn finish(self) -> Budget {
        self.source.into_budget()
    }

    #[cfg(test)]
    pub(crate) fn used_bytes(&self) -> u64 {
        self.source.used_bytes()
    }

    #[cfg(test)]
    pub(crate) fn truncated(&self) -> bool {
        self.source.truncated()
    }

    #[cfg(test)]
    pub(crate) fn repaired(&self) -> bool {
        self.repaired.get().is_some()
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.source.budget_exhausted() || self.source.scan_exhausted()
    }

    fn table(&self) -> &Table<'a> {
        self.repaired
            .get()
            .map_or(&self.primary, |recovered| &recovered.table)
    }

    fn trailers(&self) -> Vec<Dict<'a>> {
        let mut trailers = self.trailers.clone();
        if let Some(recovered) = self.repaired.get() {
            trailers.extend_from_slice(&recovered.trailers);
        }
        trailers
    }

    pub(crate) fn get(&self, id: ObjRef) -> Object<'_> {
        match self.fetch(self.table(), id) {
            Ok(object) => object,
            Err(_) if self.repair() => self.fetch(self.table(), id).unwrap_or_default(),
            Err(_) => Object::Null,
        }
    }

    pub(crate) fn resolve<'d>(&'d self, object: Object<'d>) -> Object<'d> {
        let mut current = object;
        for _ in 0..MAX_REFERENCE_CHAIN {
            match current {
                Object::Ref(id) => current = self.get(id),
                resolved => return resolved,
            }
        }
        Object::Null
    }

    pub(crate) fn dict_get<'d>(&'d self, dict: Dict<'d>, key: &[u8]) -> Object<'d> {
        if !self.source.charge_scan(dict.body().len()) {
            return Object::Null;
        }
        dict.get(key)
            .map_or(Object::Null, |value| self.resolve(value))
    }

    pub(crate) fn get_int(&self, dict: Dict<'_>, key: &[u8]) -> Option<i64> {
        self.dict_get(dict, key).as_int()
    }

    pub(crate) fn get_f64(&self, dict: Dict<'_>, key: &[u8]) -> Option<f64> {
        self.dict_get(dict, key).as_f64()
    }

    pub(crate) fn get_name<'d>(&'d self, dict: Dict<'d>, key: &[u8]) -> Option<Name<'d>> {
        self.dict_get(dict, key).as_name()
    }

    pub(crate) fn get_dict<'d>(&'d self, dict: Dict<'d>, key: &[u8]) -> Option<Dict<'d>> {
        match self.dict_get(dict, key) {
            Object::Dict(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn get_array<'d>(&'d self, dict: Dict<'d>, key: &[u8]) -> Option<Array<'d>> {
        self.dict_get(dict, key).as_array()
    }

    pub(crate) fn get_stream<'d>(&'d self, dict: Dict<'d>, key: &[u8]) -> Option<Stream<'d>> {
        self.dict_get(dict, key).as_stream()
    }

    pub(crate) fn array_iter<'d>(
        &'d self,
        array: Array<'d>,
    ) -> impl Iterator<Item = Object<'d>> + 'd {
        let allowed = self.source.charge_scan(array.body().len());
        array
            .iter()
            .take_while(move |_| allowed)
            .map(move |item| self.resolve(item))
    }

    pub(crate) fn catalog(&self) -> Option<Dict<'_>> {
        match self.get(self.catalog.get()?) {
            Object::Dict(dict) => Some(dict),
            _ => None,
        }
    }

    pub(crate) fn page_tree_root(&self) -> Option<Object<'_>> {
        match self.catalog() {
            Some(catalog) => Some(catalog.get(b"Pages").unwrap_or_default()),
            None => self.page_tree.get().map(Object::Ref),
        }
    }

    pub(crate) fn acroform_fields(&self) -> Option<Array<'_>> {
        let form = self.get_dict(self.catalog()?, b"AcroForm")?;
        self.get_array(form, b"Fields")
    }

    fn locate_root(&self) -> bool {
        if self.root_from_trailers(&self.trailers) {
            return true;
        }
        self.repair();
        let Some(recovered) = self.repaired.get() else {
            return false;
        };
        if self.root_from_trailers(&recovered.trailers) {
            return true;
        }
        if let Some(root) = recovered
            .catalogs
            .iter()
            .copied()
            .find(|&id| self.is_catalog(id))
        {
            self.catalog.set(Some(root));
            return true;
        }
        if let Some(tree) = recovered
            .page_trees
            .iter()
            .copied()
            .find(|&id| matches!(self.get(id), Object::Dict(_)))
        {
            self.page_tree.set(Some(tree));
            return true;
        }
        !recovered.pages.is_empty()
    }

    fn root_from_trailers(&self, trailers: &[Dict<'a>]) -> bool {
        for root in trailers.iter().filter_map(|trailer| trailer.get(b"Root")) {
            match root {
                Object::Ref(id) if self.is_catalog(id) => {
                    self.catalog.set(Some(id));
                    return true;
                }
                Object::Dict(catalog) => {
                    if let Some(Object::Ref(tree)) = catalog.get(b"Pages")
                        && matches!(self.get(tree), Object::Dict(_))
                    {
                        self.page_tree.set(Some(tree));
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn is_catalog(&self, id: ObjRef) -> bool {
        match self.get(id) {
            Object::Dict(catalog) => matches!(self.dict_get(catalog, b"Pages"), Object::Dict(_)),
            _ => false,
        }
    }

    pub(crate) fn fallback_pages(&self) -> &[ObjRef] {
        self.repair();
        self.repaired
            .get()
            .map_or(&[], |recovered| recovered.pages.as_slice())
    }
}
