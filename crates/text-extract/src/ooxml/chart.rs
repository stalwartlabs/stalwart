/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::number::{DateSystem, NumberFormat, ValueBuffer, push_number};
use crate::{
    output::{Output, Separator},
    xml::{Handler, Skip, Tag, Text, local_name},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChartValues {
    Strings,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChartElement {
    RichText,
    Value,
    Paragraph,
    StringData,
    NumberData,
    FormatCode,
    Level,
    Date1904,
    Category,
    Skipped,
}

impl ChartElement {
    fn parse(local: &[u8]) -> Option<ChartElement> {
        hashify::map!(local, ChartElement,
            b"t" => ChartElement::RichText,
            b"v" => ChartElement::Value,
            b"pt" => ChartElement::Value,
            b"p" => ChartElement::Paragraph,
            b"tx" => ChartElement::StringData,
            b"txData" => ChartElement::StringData,
            b"strCache" => ChartElement::StringData,
            b"strLit" => ChartElement::StringData,
            b"multiLvlStrCache" => ChartElement::StringData,
            b"strDim" => ChartElement::StringData,
            b"numCache" => ChartElement::NumberData,
            b"numLit" => ChartElement::NumberData,
            b"numDim" => ChartElement::NumberData,
            b"formatCode" => ChartElement::FormatCode,
            b"lvl" => ChartElement::Level,
            b"date1904" => ChartElement::Date1904,
            b"cat" => ChartElement::Category,
            b"xVal" => ChartElement::Category,
            b"extLst" => ChartElement::Skipped,
            b"Fallback" => ChartElement::Skipped,
        )
        .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Collect {
    Nothing,
    Text,
    Number,
    FormatCode,
}

pub(crate) struct ChartText {
    values: ChartValues,
    skip: Skip<ChartElement>,
    strings: u32,
    numbers: u32,
    collect: Collect,
    number: ValueBuffer,
    format: NumberFormat,
    dates: DateSystem,
    categories_done: bool,
}

impl ChartText {
    pub(crate) fn new(values: ChartValues) -> Self {
        ChartText {
            values,
            skip: Skip::default(),
            strings: 0,
            numbers: 0,
            collect: Collect::Nothing,
            number: ValueBuffer::default(),
            format: NumberFormat::General,
            dates: DateSystem::Epoch1900,
            categories_done: false,
        }
    }

    fn value_mode(&mut self) -> Collect {
        if self.strings > 0 {
            Collect::Text
        } else if self.numbers > 0 && self.values == ChartValues::All {
            self.number.clear();
            Collect::Number
        } else {
            Collect::Nothing
        }
    }
}

impl Handler for ChartText {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        let element = ChartElement::parse(tag.local());
        if self.skip.on_start(element) {
            return;
        }
        match element {
            Some(ChartElement::RichText) => self.collect = Collect::Text,
            Some(ChartElement::Value) => self.collect = self.value_mode(),
            Some(ChartElement::StringData) => self.strings = self.strings.saturating_add(1),
            Some(ChartElement::NumberData) => {
                self.numbers = self.numbers.saturating_add(1);
                self.format = NumberFormat::General;
            }
            Some(ChartElement::FormatCode) if self.numbers > 0 => {
                self.number.clear();
                self.collect = Collect::FormatCode;
            }
            Some(ChartElement::Level) if self.numbers > 0 => {
                if let Some(code) = tag
                    .attributes()
                    .find_map(|(name, value)| hashify::set!(name, b"formatCode").then_some(value))
                {
                    self.format = NumberFormat::classify(code);
                }
            }
            Some(ChartElement::Date1904) => self.dates = DateSystem::from_value(tag),
            Some(ChartElement::Category)
                if self.values == ChartValues::Strings || self.categories_done =>
            {
                self.skip.begin(ChartElement::Category)
            }
            Some(ChartElement::Skipped) => self.skip.begin(ChartElement::Skipped),
            Some(ChartElement::Paragraph) => out.separator(Separator::Newline),
            Some(ChartElement::FormatCode | ChartElement::Level | ChartElement::Category)
            | None => {}
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        let element = ChartElement::parse(local_name(name));
        if self.skip.on_end(element) {
            return;
        }
        match element {
            Some(ChartElement::RichText | ChartElement::Value) => {
                if self.collect == Collect::Number {
                    push_number(self.number.value(), self.format, self.dates, out);
                    self.number.clear();
                }
                self.collect = Collect::Nothing;
                out.separator(Separator::Space);
            }
            Some(ChartElement::FormatCode) if self.collect == Collect::FormatCode => {
                self.format = NumberFormat::classify(self.number.value());
                self.number.clear();
                self.collect = Collect::Nothing;
            }
            Some(ChartElement::StringData) => self.strings = self.strings.saturating_sub(1),
            Some(ChartElement::NumberData) => self.numbers = self.numbers.saturating_sub(1),
            Some(ChartElement::Paragraph) => out.separator(Separator::Newline),
            Some(ChartElement::Category) => self.categories_done = true,
            Some(
                ChartElement::FormatCode
                | ChartElement::Level
                | ChartElement::Date1904
                | ChartElement::Skipped,
            )
            | None => {}
        }
    }

    fn text(&mut self, text: Text<'_>, out: &mut Output<'_>) {
        match self.collect {
            Collect::Nothing => {}
            Collect::Text => text.push(out),
            Collect::Number => {
                if !self.number.push(text.as_bytes(), out) {
                    self.collect = Collect::Text;
                }
            }
            Collect::FormatCode => {
                if !self.number.fill(text.as_bytes()) {
                    self.collect = Collect::Nothing;
                }
            }
        }
    }
}
