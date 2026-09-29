/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedHeaderEntry, ArchivedMessageMetadata, Completeness, HeaderId, HeaderList,
    HeaderMatcher, HeaderView, PartFlags, PartSource, PartView, build::clamp,
    header_id::ArchivedHeaderId,
};
use mail_parser::{HeaderForm, ParsedValue, scan::Kernel};
use rkyv::primitive::ArchivedU32;

const CONTENT_PREFIX: &[u8] = b"content-";

#[derive(Debug, Default)]
pub struct ParsedHeaders {
    entries: Vec<ArchivedHeaderEntry>,
}

pub enum PartHeaders<'a> {
    Stored(HeaderList<'a>),
    Parsed(ParsedHeaders),
}

#[derive(Debug, Clone, Copy)]
pub enum HeaderSelection<'x> {
    All,
    Ids(&'x [HeaderId]),
    Named(&'x HeaderMatcher),
    Except(&'x HeaderMatcher),
    Content,
}

#[derive(Debug)]
pub struct ScannedHeader(ArchivedHeaderEntry);

#[derive(Debug, Clone, Copy, Default)]
struct Segment<'b> {
    block: &'b [u8],
    base: usize,
}

#[derive(Debug, Clone)]
pub struct HeaderScan<'b> {
    segments: [Segment<'b>; 2],
    segment: usize,
    line: usize,
    selection: HeaderSelection<'b>,
    kernel: Kernel,
}

#[derive(Debug, Clone, Copy)]
struct Field {
    start: usize,
    name_len: usize,
    colon: usize,
    end: usize,
}

enum Fold {
    Field(Field),
    End,
    Continue,
}

impl Completeness {
    #[inline]
    pub fn of(root_flags: PartFlags) -> Self {
        if root_flags.contains(PartFlags::TRUNCATED) {
            Completeness::Truncated
        } else {
            Completeness::Complete
        }
    }

    #[inline]
    pub fn is_truncated(self) -> bool {
        self == Completeness::Truncated
    }
}

impl ArchivedMessageMetadata {
    #[inline]
    pub fn completeness(&self) -> Completeness {
        Completeness::of(
            self.parts
                .first()
                .map_or(PartFlags::default(), |root| root.info.native().flags()),
        )
    }

    #[inline]
    pub fn extra_headers_len(&self) -> usize {
        self.headers_len().saturating_sub(self.blob_body_offset())
    }

    pub fn root_field_in<'s>(
        &self,
        headers: &'s [u8],
        id: HeaderId,
        form: HeaderForm,
    ) -> Option<ParsedValue<'s>> {
        let ids = [id];
        self.root()
            .root_part()
            .selected_headers(headers, HeaderSelection::Ids(&ids))
            .list()
            .last_parsed(id, headers, form)
    }
}

impl HeaderSelection<'_> {
    pub const ENVELOPE: HeaderSelection<'static> = HeaderSelection::Ids(&[
        HeaderId::DATE,
        HeaderId::SUBJECT,
        HeaderId::FROM,
        HeaderId::SENDER,
        HeaderId::REPLY_TO,
        HeaderId::TO,
        HeaderId::CC,
        HeaderId::BCC,
        HeaderId::IN_REPLY_TO,
        HeaderId::MESSAGE_ID,
    ]);

    #[inline]
    pub fn matches(&self, header: HeaderView<'_>, source: &[u8]) -> bool {
        self.matches_name(header.id(), || header.raw_name(source))
    }

    fn matches_name<'n>(&self, id: HeaderId, name: impl FnOnce() -> &'n [u8]) -> bool {
        match self {
            HeaderSelection::All => true,
            HeaderSelection::Ids(ids) => ids.contains(&id),
            HeaderSelection::Named(matcher) => matcher.matches_name(id, name),
            HeaderSelection::Except(matcher) => !matcher.matches_name(id, name),
            HeaderSelection::Content => name()
                .get(..CONTENT_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CONTENT_PREFIX)),
        }
    }
}

impl HeaderMatcher {
    #[inline]
    fn matches_name<'n>(&self, id: HeaderId, name: impl FnOnce() -> &'n [u8]) -> bool {
        if id.is_known() {
            self.matches_id(id)
        } else {
            self.matches_other(name())
        }
    }
}

impl ScannedHeader {
    #[inline]
    pub fn view(&self) -> HeaderView<'_> {
        HeaderView::new(&self.0)
    }

    #[inline]
    pub fn into_entry(self) -> ArchivedHeaderEntry {
        self.0
    }
}

impl<'b> HeaderScan<'b> {
    pub fn new(block: &'b [u8], base: usize, selection: HeaderSelection<'b>) -> Self {
        HeaderScan::with_segments([Segment { block, base }, Segment::default()], selection)
    }

    fn with_segments(segments: [Segment<'b>; 2], selection: HeaderSelection<'b>) -> Self {
        HeaderScan {
            segments,
            segment: 0,
            line: 0,
            selection,
            kernel: Kernel::best(),
        }
    }
}

impl Iterator for HeaderScan<'_> {
    type Item = ScannedHeader;

    fn next(&mut self) -> Option<ScannedHeader> {
        loop {
            let segment = *self.segments.get(self.segment)?;
            let Some(field) = segment.next_field(&mut self.line, self.kernel) else {
                self.segment += 1;
                self.line = 0;
                continue;
            };
            let bytes = segment
                .block
                .get(field.start..field.end)
                .unwrap_or_default();
            let id = HeaderId::parse(bytes.get(..field.name_len).unwrap_or_default());
            let name = || {
                bytes
                    .get(..field.colon)
                    .unwrap_or_default()
                    .trim_ascii_end()
            };
            if self.selection.matches_name(id, name) {
                return Some(field.entry(id, segment.base));
            }
        }
    }
}

impl Segment<'_> {
    fn next_field(&self, line: &mut usize, kernel: Kernel) -> Option<Field> {
        let src = self.block;
        loop {
            let rest = src.get(*line..).unwrap_or_default();
            let skip = rest.iter().take_while(|&&byte| is_line_space(byte)).count();
            match rest.get(skip) {
                None | Some(b'\n') => return None,
                Some(_) => {}
            }
            let start = *line + skip;
            let end = kernel
                .field_end(src, start)
                .map_or(src.len(), |newline| newline + 1);
            *line = end;
            match Field::parse(src, start, end) {
                Ok(field) => return Some(field),
                Err(next_line) => match Field::folded(src, start + next_line, end) {
                    Fold::Field(field) => return Some(field),
                    Fold::End => return None,
                    Fold::Continue => {}
                },
            }
        }
    }
}

impl Field {
    fn parse(src: &[u8], start: usize, end: usize) -> Result<Field, usize> {
        let field = src.get(start..end).unwrap_or_default();
        let lead = field.iter().take_while(|&&byte| byte == b':').count();
        let rest = field.get(lead..).unwrap_or_default();
        match rest.iter().position(|&byte| matches!(byte, b':' | b'\n')) {
            Some(colon) if rest.get(colon) == Some(&b':') => {
                let colon = lead + colon;
                let name = field.get(..colon).unwrap_or_default();
                let name_len = name
                    .iter()
                    .rposition(|&byte| !matches!(byte, b' ' | b'\t'))
                    .map_or(0, |last| last + 1);
                Ok(Field {
                    start,
                    name_len,
                    colon,
                    end,
                })
            }
            Some(newline) => Err(lead + newline + 1),
            None => Err(field.len()),
        }
    }

    fn folded(src: &[u8], mut line: usize, end: usize) -> Fold {
        while line < end {
            let rest = src.get(line..end).unwrap_or_default();
            let skip = rest.iter().take_while(|&&byte| is_line_space(byte)).count();
            match rest.get(skip) {
                None if end == src.len() => return Fold::End,
                None => return Fold::Continue,
                Some(b'\n') => return Fold::End,
                Some(_) => {}
            }
            let start = line + skip;
            match Field::parse(src, start, end) {
                Ok(field) => return Fold::Field(field),
                Err(next_line) => line = start + next_line,
            }
        }
        Fold::Continue
    }

    #[inline]
    fn entry(self, id: HeaderId, base: usize) -> ScannedHeader {
        let shift = |offset: usize| ArchivedU32::from_native(clamp(base.saturating_add(offset)));
        ScannedHeader(ArchivedHeaderEntry {
            name: ArchivedHeaderId(id.0),
            offset_field: shift(self.start),
            offset_value: shift(self.start + self.colon + 1),
            offset_end: shift(self.end),
        })
    }
}

#[inline]
fn is_line_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\x0c')
}

impl FromIterator<ScannedHeader> for ParsedHeaders {
    fn from_iter<I: IntoIterator<Item = ScannedHeader>>(headers: I) -> Self {
        ParsedHeaders {
            entries: headers.into_iter().map(ScannedHeader::into_entry).collect(),
        }
    }
}

impl ParsedHeaders {
    #[inline]
    pub fn list(&self) -> HeaderList<'_> {
        HeaderList::new(&self.entries)
    }
}

impl PartHeaders<'_> {
    #[inline]
    pub fn list(&self) -> HeaderList<'_> {
        match self {
            PartHeaders::Stored(list) => *list,
            PartHeaders::Parsed(parsed) => parsed.list(),
        }
    }

    #[inline]
    pub fn is_parsed(&self) -> bool {
        matches!(self, PartHeaders::Parsed(_))
    }
}

impl<'a> PartView<'a> {
    #[inline]
    pub fn is_headers_truncated(&self) -> bool {
        self.flags().contains(PartFlags::HEADERS_TRUNCATED)
    }

    pub fn scan_headers<'b>(
        &self,
        block: &'b [u8],
        selection: HeaderSelection<'b>,
    ) -> HeaderScan<'b> {
        let offset = self.offset_header();
        if self.id() == 0 {
            let extra = self.metadata().extra_headers_len();
            let (extra_block, message_block) =
                block.split_at_checked(extra).unwrap_or((&[], block));
            HeaderScan::with_segments(
                [
                    Segment {
                        block: extra_block,
                        base: offset,
                    },
                    Segment {
                        block: message_block,
                        base: offset.saturating_add(extra_block.len()),
                    },
                ],
                selection,
            )
        } else {
            HeaderScan::new(block, offset, selection)
        }
    }

    pub fn selected_headers(
        &self,
        block: &[u8],
        selection: HeaderSelection<'_>,
    ) -> PartHeaders<'a> {
        if self.is_headers_truncated() {
            PartHeaders::Parsed(self.scan_headers(block, selection).collect())
        } else {
            PartHeaders::Stored(self.headers())
        }
    }

    pub fn selected_headers_in(
        &self,
        source: &PartSource<'_>,
        selection: HeaderSelection<'_>,
    ) -> PartHeaders<'a> {
        if !self.is_headers_truncated() {
            return PartHeaders::Stored(self.headers());
        }
        match source.get(self.header_range()) {
            Some(block) => self.selected_headers(&block, selection),
            None => PartHeaders::Stored(self.headers()),
        }
    }
}
