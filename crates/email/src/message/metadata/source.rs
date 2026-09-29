/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedMessageMetadata, HeaderId, MAX_SOURCE_DEPTH, PartFlags, TransferEncoding,
    complete::{HeaderScan, HeaderSelection, PartHeaders},
    view::{MessageView, PartView},
};
use mail_parser::{Charset, Encoding};
use std::{borrow::Cow, ops::Range};
use utils::chained_bytes::ChainedBytes;

impl TransferEncoding {
    #[inline]
    fn parser(self) -> Encoding {
        Encoding::from(self)
    }

    #[inline]
    pub fn decode(self, bytes: &[u8]) -> Cow<'_, [u8]> {
        self.parser().decode(bytes)
    }

    #[inline]
    pub fn decode_checked(self, bytes: &[u8]) -> (Cow<'_, [u8]>, bool) {
        self.parser().decode_checked(bytes)
    }

    #[inline]
    pub fn decode_append(self, bytes: &[u8], out: &mut Vec<u8>) {
        self.parser().decode_append(bytes, out)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RawMessage<'x> {
    bytes: ChainedBytes<'x>,
    base: usize,
}

#[derive(Debug, Clone)]
pub enum PartSource<'x> {
    Raw(RawMessage<'x>),
    Decoded(Vec<u8>),
}

#[derive(Debug, Clone, Copy)]
pub struct SourceChain {
    ids: [u32; MAX_SOURCE_DEPTH],
    depth: usize,
}

#[derive(Debug, Clone)]
pub struct DecodedText<'x> {
    pub text: Cow<'x, str>,
    pub has_problems: bool,
}

impl<'x> RawMessage<'x> {
    #[inline]
    pub fn len(&self) -> usize {
        self.base + self.bytes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn has_headers(&self) -> bool {
        self.base == 0
    }

    #[inline]
    pub fn whole(&self) -> Option<ChainedBytes<'x>> {
        self.has_headers().then_some(self.bytes)
    }

    #[inline]
    pub fn view(&self, range: Range<usize>) -> Option<ChainedBytes<'x>> {
        self.bytes
            .view(range.start.checked_sub(self.base)?..range.end.checked_sub(self.base)?)
    }

    #[inline]
    pub fn get(&self, range: Range<usize>) -> Option<Cow<'x, [u8]>> {
        self.bytes
            .get(range.start.checked_sub(self.base)?..range.end.checked_sub(self.base)?)
    }

    #[inline]
    pub fn contiguous(&self, range: Range<usize>) -> Option<&'x [u8]> {
        match self.view(range)?.segments() {
            [bytes, []] | [[], bytes] => Some(bytes),
            _ => None,
        }
    }
}

impl<'x> PartSource<'x> {
    pub fn get(&self, range: Range<usize>) -> Option<Cow<'_, [u8]>> {
        match self {
            PartSource::Raw(raw) => raw.get(range),
            PartSource::Decoded(bytes) => bytes.get(range).map(Cow::Borrowed),
        }
    }

    pub fn slice(&self, range: Range<usize>) -> Option<Cow<'x, [u8]>> {
        match self {
            PartSource::Raw(raw) => raw.get(range),
            PartSource::Decoded(bytes) => bytes.get(range).map(|bytes| Cow::Owned(bytes.to_vec())),
        }
    }

    pub fn decode(&self, range: Range<usize>, encoding: TransferEncoding) -> Cow<'x, [u8]> {
        match self {
            PartSource::Raw(raw) => match raw.get(range) {
                Some(Cow::Borrowed(bytes)) => encoding.decode(bytes),
                Some(Cow::Owned(bytes)) => match encoding.decode(&bytes) {
                    Cow::Borrowed(_) => Cow::Owned(bytes),
                    Cow::Owned(decoded) => Cow::Owned(decoded),
                },
                None => Cow::Borrowed(&[]),
            },
            PartSource::Decoded(bytes) => bytes
                .get(range)
                .map(|bytes| Cow::Owned(encoding.decode(bytes).into_owned()))
                .unwrap_or_default(),
        }
    }

    fn decode_checked(
        &self,
        range: Range<usize>,
        encoding: TransferEncoding,
    ) -> (Cow<'x, [u8]>, bool) {
        let owned = |bytes: &[u8]| {
            let (decoded, malformed) = encoding.decode_checked(bytes);
            (Cow::Owned(decoded.into_owned()), malformed)
        };
        match self {
            PartSource::Raw(raw) => match raw.get(range) {
                Some(Cow::Borrowed(bytes)) => encoding.decode_checked(bytes),
                Some(Cow::Owned(bytes)) => owned(&bytes),
                None => (Cow::Borrowed(&[][..]), false),
            },
            PartSource::Decoded(bytes) => bytes
                .get(range)
                .map_or((Cow::Borrowed(&[][..]), false), owned),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            PartSource::Raw(raw) => raw.len(),
            PartSource::Decoded(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_decoded(&self) -> bool {
        matches!(self, PartSource::Decoded(_))
    }
}

impl SourceChain {
    #[inline]
    pub fn len(&self) -> usize {
        self.depth
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.depth == 0
    }

    #[inline]
    pub fn ids(&self) -> impl ExactSizeIterator<Item = u32> + use<'_> {
        self.ids
            .get(..self.depth)
            .unwrap_or_default()
            .iter()
            .rev()
            .copied()
    }
}

impl ArchivedMessageMetadata {
    pub fn raw_message<'x>(&self, headers: Option<&'x [u8]>, blob: &'x [u8]) -> RawMessage<'x> {
        let headers_len = self.headers_len();
        match headers.filter(|headers| headers.len() == headers_len) {
            Some(headers) => RawMessage {
                bytes: ChainedBytes::from_blob(headers, blob, self.blob_body_offset()),
                base: 0,
            },
            None => RawMessage {
                bytes: ChainedBytes::from_blob(&[], blob, self.blob_body_offset()),
                base: headers_len,
            },
        }
    }

    pub fn source_chain(&self, message: MessageView<'_>) -> Option<SourceChain> {
        let mut ids = [0u32; MAX_SOURCE_DEPTH];
        let mut depth = 0;
        let mut current = message;
        while let Some(part) = current.source_part() {
            *ids.get_mut(depth)? = part.id();
            depth += 1;
            current = part.message();
        }
        Some(SourceChain { ids, depth })
    }

    pub fn source<'x>(
        &self,
        message: MessageView<'_>,
        raw: RawMessage<'x>,
    ) -> Option<PartSource<'x>> {
        let chain = self.source_chain(message)?;
        if chain.is_empty() {
            return Some(PartSource::Raw(raw));
        }

        let mut buffer: Option<Vec<u8>> = None;
        for id in chain.ids() {
            let part = self.part(id)?;
            let range = part.body_range();
            let mut decoded = Vec::new();
            match &buffer {
                None => part
                    .encoding()
                    .decode_append(&raw.get(range)?, &mut decoded),
                Some(outer) => part
                    .encoding()
                    .decode_append(outer.get(range)?, &mut decoded),
            }
            buffer = Some(decoded);
        }
        buffer.map(PartSource::Decoded)
    }

    pub fn strip_root_fields<'b>(&self, blob: &'b [u8], id: HeaderId) -> Cow<'b, [u8]> {
        let root = self.root().root_part();
        let ids = [id];
        let headers = if root.is_headers_truncated() {
            PartHeaders::Parsed(
                HeaderScan::new(
                    blob.get(..self.blob_body_offset()).unwrap_or_default(),
                    self.extra_headers_len(),
                    HeaderSelection::Ids(&ids),
                )
                .collect(),
            )
        } else {
            PartHeaders::Stored(root.headers())
        };
        let mut ranges = headers
            .list()
            .all(id)
            .filter_map(|header| self.blob_range(header.field_range()))
            .filter(|range| range.end <= blob.len())
            .peekable();
        if ranges.peek().is_none() {
            return Cow::Borrowed(blob);
        }
        let mut stripped = Vec::with_capacity(blob.len());
        let mut cursor = 0;
        for range in ranges {
            if let Some(kept) = blob.get(cursor..range.start) {
                stripped.extend_from_slice(kept);
                cursor = range.end;
            }
        }
        stripped.extend_from_slice(blob.get(cursor..).unwrap_or_default());
        Cow::Owned(stripped)
    }
}

impl<'a> PartView<'a> {
    pub fn decoded<'x>(&self, source: &PartSource<'x>) -> Cow<'x, [u8]> {
        source.decode(self.body_range(), self.encoding())
    }

    pub fn text<'x>(&self, source: &PartSource<'x>) -> Option<DecodedText<'x>> {
        if !self.is_text() {
            return None;
        }
        let (decoded, mut has_problems) = source.decode_checked(self.body_range(), self.encoding());
        if self.flags().contains(PartFlags::UNKNOWN_TRANSFER_ENCODING) {
            has_problems = true;
        }
        let charset = match self.charset() {
            None => Charset::default(),
            Some(label) => Charset::from_label(label.as_bytes()).unwrap_or_else(|| {
                has_problems = true;
                Charset::default()
            }),
        };
        let (text, malformed) = match decoded {
            Cow::Borrowed(bytes) => charset.decode_checked(bytes),
            Cow::Owned(bytes) if charset == Charset::Utf8 => match String::from_utf8(bytes) {
                Ok(text) => (Cow::Owned(text), false),
                Err(err) => {
                    let (text, malformed) = charset.decode_checked(err.as_bytes());
                    (Cow::Owned(text.into_owned()), malformed)
                }
            },
            Cow::Owned(bytes) => {
                let (text, malformed) = charset.decode_checked(&bytes);
                (Cow::Owned(text.into_owned()), malformed)
            }
        };
        Some(DecodedText {
            text,
            has_problems: has_problems || malformed,
        })
    }
}
