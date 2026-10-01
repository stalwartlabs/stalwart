/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::metadata::{
    MAX_SOURCE_DEPTH, MessageView, PartView, RawMessage, TransferEncoding,
};
use std::{borrow::Cow, ops::Range};
use utils::chained_bytes::ChainedBytes;

#[derive(Debug, Default)]
pub struct DecodedSources {
    source: Option<Decoded>,
    leaf: Option<Decoded>,
}

#[derive(Debug)]
struct Decoded {
    part_id: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SourceView<'x> {
    Raw(RawMessage<'x>),
    Bytes(&'x [u8]),
}

impl DecodedSources {
    pub(super) fn source<'x>(
        &'x mut self,
        message: MessageView<'_>,
        raw: RawMessage<'x>,
    ) -> Option<SourceView<'x>> {
        Decoded::source(&mut self.source, message, raw)
    }

    pub(super) fn leaf<'x>(
        &'x mut self,
        part: PartView<'_>,
        raw: RawMessage<'x>,
    ) -> Option<ChainedBytes<'x>> {
        let DecodedSources { source, leaf } = self;
        if leaf.as_ref().is_some_and(|leaf| leaf.part_id == part.id()) {
            return leaf.as_ref().map(|leaf| ChainedBytes::new(&leaf.bytes));
        }
        match Decoded::source(source, part.message(), raw)?
            .decode(part.body_range(), part.encoding())
        {
            Cow::Borrowed(bytes) => Some(ChainedBytes::new(bytes)),
            Cow::Owned(bytes) => Some(ChainedBytes::new(
                &leaf
                    .insert(Decoded {
                        part_id: part.id(),
                        bytes,
                    })
                    .bytes,
            )),
        }
    }

    pub fn len(&self) -> usize {
        usize::from(self.source.is_some()) + usize::from(self.leaf.is_some())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub(super) fn bytes_held(&self) -> usize {
        [&self.source, &self.leaf]
            .into_iter()
            .flatten()
            .map(|decoded| decoded.bytes.len())
            .sum()
    }
}

impl Decoded {
    fn source<'x>(
        slot: &'x mut Option<Decoded>,
        message: MessageView<'_>,
        raw: RawMessage<'x>,
    ) -> Option<SourceView<'x>> {
        let mut chain = [0u32; MAX_SOURCE_DEPTH];
        let mut depth = 0;
        let mut is_cached = false;
        let mut current = message;
        while let Some(part) = current.source_part() {
            if slot
                .as_ref()
                .is_some_and(|decoded| decoded.part_id == part.id())
            {
                is_cached = true;
                break;
            }
            *chain.get_mut(depth)? = part.id();
            depth += 1;
            current = part.message();
        }

        if !is_cached {
            if depth == 0 {
                return Some(SourceView::Raw(raw));
            }
            *slot = None;
        }

        let meta = message.metadata();
        for part_id in chain.get(..depth)?.iter().rev() {
            let part = meta.part(*part_id)?;
            let range = part.body_range();
            let mut bytes = Vec::new();
            match slot.as_ref() {
                None => part.encoding().decode_append(&raw.get(range)?, &mut bytes),
                Some(base) => part
                    .encoding()
                    .decode_append(base.bytes.get(range)?, &mut bytes),
            }
            *slot = Some(Decoded {
                part_id: *part_id,
                bytes,
            });
        }

        slot.as_ref()
            .map(|decoded| SourceView::Bytes(&decoded.bytes))
    }
}

impl<'x> SourceView<'x> {
    pub(super) fn view(&self, range: Range<usize>) -> Option<ChainedBytes<'x>> {
        match self {
            SourceView::Raw(raw) => raw.view(range),
            SourceView::Bytes(bytes) => bytes.get(range).map(ChainedBytes::new),
        }
    }

    pub(super) fn get(&self, range: Range<usize>) -> Option<Cow<'x, [u8]>> {
        match self {
            SourceView::Raw(raw) => raw.get(range),
            SourceView::Bytes(bytes) => bytes.get(range).map(Cow::Borrowed),
        }
    }

    pub(super) fn view_without(
        &self,
        range: Range<usize>,
        gap: Range<usize>,
    ) -> Option<ChainedBytes<'x>> {
        if !gap.is_empty()
            && let (Some(head), Some(tail)) = (
                self.contiguous(range.start..gap.start),
                self.contiguous(gap.end..range.end),
            )
        {
            return Some(ChainedBytes::chain(head, tail));
        }
        self.view(range)
    }

    pub(super) fn len(&self) -> usize {
        match self {
            SourceView::Raw(raw) => raw.len(),
            SourceView::Bytes(bytes) => bytes.len(),
        }
    }

    fn contiguous(&self, range: Range<usize>) -> Option<&'x [u8]> {
        match self {
            SourceView::Raw(raw) => raw.contiguous(range),
            SourceView::Bytes(bytes) => bytes.get(range),
        }
    }

    fn decode(&self, range: Range<usize>, encoding: TransferEncoding) -> Cow<'x, [u8]> {
        match self.get(range) {
            Some(Cow::Borrowed(bytes)) => encoding.decode(bytes),
            Some(Cow::Owned(bytes)) => match encoding.decode(&bytes) {
                Cow::Borrowed(_) => Cow::Owned(bytes),
                Cow::Owned(decoded) => Cow::Owned(decoded),
            },
            None => Cow::Borrowed(&[]),
        }
    }
}
