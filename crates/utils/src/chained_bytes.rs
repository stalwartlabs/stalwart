/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::memchr_iter;
use std::{borrow::Cow, ops::Range};

#[derive(Debug, Clone, Copy, Default)]
pub struct ChainedBytes<'x> {
    head: &'x [u8],
    tail: &'x [u8],
}

impl<'x> ChainedBytes<'x> {
    pub const fn new(bytes: &'x [u8]) -> Self {
        Self {
            head: bytes,
            tail: &[],
        }
    }

    pub const fn chain(head: &'x [u8], tail: &'x [u8]) -> Self {
        Self { head, tail }
    }

    pub fn from_blob(head: &'x [u8], blob: &'x [u8], body_offset: usize) -> Self {
        Self {
            head,
            tail: blob.get(body_offset..).unwrap_or_default(),
        }
    }

    pub const fn len(&self) -> usize {
        self.head.len() + self.tail.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.head.is_empty() && self.tail.is_empty()
    }

    pub const fn segments(&self) -> [&'x [u8]; 2] {
        [self.head, self.tail]
    }

    #[inline]
    pub fn view(&self, range: Range<usize>) -> Option<Self> {
        let split = self.head.len();
        if range.end <= split {
            self.head.get(range).map(Self::new)
        } else if range.start >= split {
            self.tail
                .get(range.start - split..range.end - split)
                .map(Self::new)
        } else {
            Some(Self::chain(
                self.head.get(range.start..)?,
                self.tail.get(..range.end - split)?,
            ))
        }
    }

    #[inline]
    pub fn get(&self, range: Range<usize>) -> Option<Cow<'x, [u8]>> {
        let split = self.head.len();
        if range.end <= split {
            self.head.get(range).map(Cow::Borrowed)
        } else if range.start >= split {
            self.tail
                .get(range.start - split..range.end - split)
                .map(Cow::Borrowed)
        } else {
            self.concat(range)
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.segments().concat()
    }

    #[inline]
    pub fn extend_into(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.len());
        buf.extend_from_slice(self.head);
        buf.extend_from_slice(self.tail);
    }

    pub fn line_prefix_len(&self, lines: usize) -> usize {
        let Some(nth) = lines.checked_sub(1) else {
            return 0;
        };
        let [head, tail] = self.segments();
        memchr_iter(b'\n', head)
            .chain(memchr_iter(b'\n', tail).map(|pos| pos + head.len()))
            .nth(nth)
            .map_or(self.len(), |pos| pos + 1)
    }

    #[cold]
    fn concat(&self, range: Range<usize>) -> Option<Cow<'x, [u8]>> {
        self.view(range).map(|bytes| Cow::Owned(bytes.to_vec()))
    }
}

impl PartialEq for ChainedBytes<'_> {
    fn eq(&self, other: &Self) -> bool {
        let (short, long) = if self.head.len() <= other.head.len() {
            (self, other)
        } else {
            (other, self)
        };
        if short.len() != long.len() {
            return false;
        }
        let Some((long_head, long_middle)) = long.head.split_at_checked(short.head.len()) else {
            return false;
        };
        let Some((short_middle, short_tail)) = short.tail.split_at_checked(long_middle.len())
        else {
            return false;
        };
        short.head == long_head && short_middle == long_middle && short_tail == long.tail
    }
}

impl Eq for ChainedBytes<'_> {}

#[cfg(test)]
mod tests {
    use super::ChainedBytes;
    use std::borrow::Cow;

    const MAX_LEN: usize = 24;
    const LINES_ALPHABET: &[u8] = b"a\n";
    const LINES_MAX_LEN: usize = 10;

    fn buffer(len: usize) -> Vec<u8> {
        (0..len).map(|i| b'a' + (i % 26) as u8).collect()
    }

    fn strings_over(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut current = vec![Vec::new()];
        for _ in 0..max_len {
            current = current
                .iter()
                .flat_map(|prefix: &Vec<u8>| {
                    alphabet.iter().map(move |byte| {
                        let mut next = prefix.clone();
                        next.push(*byte);
                        next
                    })
                })
                .collect();
            all.extend(current.iter().cloned());
        }
        all
    }

    fn naive_line_prefix_len(bytes: &[u8], lines: usize) -> usize {
        if lines == 0 {
            return 0;
        }
        bytes
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'\n')
            .nth(lines - 1)
            .map_or(bytes.len(), |(pos, _)| pos + 1)
    }

    #[test]
    fn view_and_get_match_naive_slicing_at_every_split() {
        for len in 0..=MAX_LEN {
            let buf = buffer(len);
            for split in 0..=len {
                let (head, tail) = buf.split_at(split);
                let chain = ChainedBytes::chain(head, tail);
                assert_eq!(chain.len(), len);
                assert_eq!(chain.to_vec(), buf);
                for start in 0..=len + 2 {
                    for end in 0..=len + 2 {
                        let expected = buf.get(start..end);
                        let view = chain.view(start..end);
                        assert_eq!(
                            view.map(|view| view.to_vec()),
                            expected.map(<[u8]>::to_vec),
                            "view {start}..{end} split {split} len {len}"
                        );
                        let get = chain.get(start..end);
                        assert_eq!(
                            get.as_deref(),
                            expected,
                            "get {start}..{end} split {split} len {len}"
                        );
                        if let Some(get) = &get {
                            let spans = start < split && end > split;
                            assert_eq!(
                                matches!(get, Cow::Owned(_)),
                                spans,
                                "borrowing {start}..{end} split {split}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn hostile_ranges_return_none_without_panicking() {
        let buf = buffer(MAX_LEN);
        for split in [0, 1, MAX_LEN / 2, MAX_LEN - 1, MAX_LEN] {
            let (head, tail) = buf.split_at(split);
            let chain = ChainedBytes::chain(head, tail);
            for (start, end) in [
                (usize::MAX, usize::MAX),
                (0, usize::MAX),
                (usize::MAX, 0),
                (split, usize::MAX),
                (usize::MAX, split),
                (split + 1, split.saturating_sub(1)),
                (MAX_LEN, 0),
                (MAX_LEN + 1, MAX_LEN),
                (split.saturating_sub(1), usize::MAX - 1),
            ] {
                if start <= end && end <= MAX_LEN {
                    continue;
                }
                assert!(
                    chain.view(start..end).is_none(),
                    "{start}..{end} split {split}"
                );
                assert!(
                    chain.get(start..end).is_none(),
                    "{start}..{end} split {split}"
                );
            }
        }
    }

    #[test]
    fn segments_extend_into_and_equality_ignore_the_split() {
        for len in 0..=MAX_LEN {
            let buf = buffer(len);
            let mut changed = buf.clone();
            if let Some(last) = changed.last_mut() {
                *last = b'#';
            }
            for split in 0..=len {
                let (head, tail) = buf.split_at(split);
                let chain = ChainedBytes::chain(head, tail);
                assert_eq!(chain.segments().concat(), buf);
                let mut extended = b"prefix".to_vec();
                chain.extend_into(&mut extended);
                assert_eq!(extended.get(6..), Some(buf.as_slice()));
                assert_eq!(chain.is_empty(), len == 0);
                for other_split in 0..=len {
                    let (other_head, other_tail) = buf.split_at(other_split);
                    assert_eq!(chain, ChainedBytes::chain(other_head, other_tail));
                    let (changed_head, changed_tail) = changed.split_at(other_split);
                    assert_eq!(
                        chain == ChainedBytes::chain(changed_head, changed_tail),
                        len == 0
                    );
                }
                assert_ne!(chain, ChainedBytes::new(b"-"));
            }
        }
    }

    #[test]
    fn from_blob_clamps_the_tail() {
        let blob = b"header\r\n\r\nbody";
        assert_eq!(
            ChainedBytes::from_blob(b"H", blob, 10).to_vec(),
            b"Hbody".to_vec()
        );
        assert_eq!(
            ChainedBytes::from_blob(b"H", blob, 14).to_vec(),
            b"H".to_vec()
        );
        assert_eq!(
            ChainedBytes::from_blob(b"H", blob, 99).to_vec(),
            b"H".to_vec()
        );
        assert_eq!(
            ChainedBytes::from_blob(b"H", blob, usize::MAX).to_vec(),
            b"H".to_vec()
        );
    }

    #[test]
    fn line_prefix_len_matches_naive_count() {
        for message in strings_over(LINES_ALPHABET, LINES_MAX_LEN) {
            for split in 0..=message.len() {
                let (head, tail) = message.split_at(split);
                let chain = ChainedBytes::chain(head, tail);
                for lines in 0..=6 {
                    assert_eq!(
                        chain.line_prefix_len(lines),
                        naive_line_prefix_len(&message, lines),
                        "{message:?} split {split} lines {lines}"
                    );
                }
                assert_eq!(chain.line_prefix_len(usize::MAX), message.len());
            }
        }
    }
}
