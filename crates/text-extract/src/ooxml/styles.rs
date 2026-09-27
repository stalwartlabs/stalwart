/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::number::NumberFormat;
use crate::{
    output::Output,
    xml::{Handler, Tag, Text, attr::decode_into, local_name},
};

const MAX_CUSTOM_FORMATS: usize = 4096;
const MAX_CELL_FORMATS: usize = 65_536;
const MAX_FORMAT_CODE: usize = 1024;

#[derive(Default)]
pub(crate) struct Styles {
    cell_formats: Vec<NumberFormat>,
    custom: Vec<(u32, NumberFormat)>,
    decoded: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Other,
    NumberFormats,
    CellFormats,
}

pub(crate) struct StylesHandler<'x> {
    styles: &'x mut Styles,
    section: Section,
    done: bool,
}

impl Styles {
    pub(crate) fn clear(&mut self) {
        self.cell_formats.clear();
        self.custom.clear();
    }

    pub(crate) fn cell_formats(&self) -> &[NumberFormat] {
        &self.cell_formats
    }

    pub(crate) fn handler(&mut self) -> StylesHandler<'_> {
        StylesHandler {
            styles: self,
            section: Section::Other,
            done: false,
        }
    }

    fn define(&mut self, tag: &Tag<'_>) {
        if self.custom.len() >= MAX_CUSTOM_FORMATS {
            return;
        }
        let (mut id, mut code) = (None, None);
        for (name, value) in tag.attributes() {
            hashify::fnc_map!(name,
                b"numFmtId" => { id = parse_index(value); },
                b"formatCode" => { code = Some(value); },
                _ => {}
            );
        }
        let (Some(id), Some(code)) = (id, code) else {
            return;
        };
        self.decoded.clear();
        decode_into(
            code.get(..MAX_FORMAT_CODE).unwrap_or(code),
            &mut self.decoded,
        );
        if let Err(index) = self.custom.binary_search_by_key(&id, |&(custom, _)| custom) {
            self.custom
                .insert(index, (id, NumberFormat::classify(&self.decoded)));
        }
    }

    fn resolve(&mut self, tag: &Tag<'_>) {
        if self.cell_formats.len() >= MAX_CELL_FORMATS {
            return;
        }
        let id = tag
            .attributes()
            .find_map(|(name, value)| hashify::set!(name, b"numFmtId").then(|| parse_index(value)))
            .flatten()
            .unwrap_or(0);
        let format = match self.custom.binary_search_by_key(&id, |&(custom, _)| custom) {
            Ok(index) => self
                .custom
                .get(index)
                .map_or(NumberFormat::General, |&(_, format)| format),
            Err(_) => NumberFormat::builtin(id),
        };
        self.cell_formats.push(format);
    }
}

impl Handler for StylesHandler<'_> {
    fn start(&mut self, tag: &Tag<'_>, _out: &mut Output<'_>) {
        let local = tag.local();
        match self.section {
            Section::NumberFormats if hashify::set!(local, b"numFmt") => self.styles.define(tag),
            Section::CellFormats if hashify::set!(local, b"xf") => self.styles.resolve(tag),
            _ => hashify::fnc_map!(local,
                b"numFmts" => { self.section = Section::NumberFormats; },
                b"cellXfs" => { self.section = Section::CellFormats; },
                _ => {}
            ),
        }
    }

    fn end(&mut self, name: &[u8], _out: &mut Output<'_>) {
        if hashify::set!(local_name(name), b"numFmts", b"cellXfs") {
            self.done |= self.section == Section::CellFormats;
            self.section = Section::Other;
        }
    }

    fn text(&mut self, _text: Text<'_>, _out: &mut Output<'_>) {}

    fn aborted(&self) -> bool {
        self.done
    }
}

pub(crate) fn parse_index(value: &[u8]) -> Option<u32> {
    let digits = value.trim_ascii();
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u32, |index, &digit| {
        index.checked_mul(10)?.checked_add(u32::from(
            digit.checked_sub(b'0').filter(|value| *value < 10)?,
        ))
    })
}
