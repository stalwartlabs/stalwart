/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::memchr_iter;

const DENSE_LINE_LEN: usize = 8;
const DENSE_STREAK: u32 = 8;
const SPARSE_LINE_LEN: usize = 64;

pub struct DotStuffer {
    last: u8,
}

impl Default for DotStuffer {
    fn default() -> Self {
        Self { last: b'\n' }
    }
}

impl DotStuffer {
    pub fn push(&mut self, buf: &mut Vec<u8>, bytes: &[u8]) {
        let mut offset = 0;
        while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
            offset += self.copy_sparse(buf, rest);
            offset += self.copy_dense(buf, bytes.get(offset..).unwrap_or_default());
        }
    }

    pub fn finish(self, buf: &mut Vec<u8>) {
        if self.last != b'\n' {
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b".\r\n");
    }

    fn copy_sparse(&mut self, buf: &mut Vec<u8>, bytes: &[u8]) -> usize {
        if self.last == b'\n' && bytes.first() == Some(&b'.') {
            buf.push(b'.');
        }
        let mut run_start = 0;
        let mut short_lines = 0;
        for pos in memchr_iter(b'\n', bytes) {
            let prev = pos
                .checked_sub(1)
                .and_then(|prev| bytes.get(prev))
                .copied()
                .unwrap_or(self.last);
            let is_bare = prev != b'\r';
            let is_dot = bytes.get(pos + 1) == Some(&b'.');
            if is_bare || is_dot {
                buf.extend_from_slice(bytes.get(run_start..pos).unwrap_or_default());
                if pos - run_start < DENSE_LINE_LEN {
                    short_lines += 1;
                    if short_lines == DENSE_STREAK {
                        self.last = prev;
                        return pos;
                    }
                } else {
                    short_lines = 0;
                }
                if is_bare {
                    buf.push(b'\r');
                }
                buf.push(b'\n');
                if is_dot {
                    buf.push(b'.');
                }
                run_start = pos + 1;
            }
        }
        buf.extend_from_slice(bytes.get(run_start..).unwrap_or_default());
        if let Some(&last) = bytes.last() {
            self.last = last;
        }
        bytes.len()
    }

    fn copy_dense(&mut self, buf: &mut Vec<u8>, bytes: &[u8]) -> usize {
        let mut line_start = 0;
        for (pos, &byte) in bytes.iter().enumerate() {
            if byte == b'\n' {
                if self.last != b'\r' {
                    buf.push(b'\r');
                }
                buf.push(b'\n');
                self.last = b'\n';
                if pos - line_start >= SPARSE_LINE_LEN {
                    return pos + 1;
                }
                line_start = pos + 1;
            } else {
                if byte == b'.' && self.last == b'\n' {
                    buf.push(b'.');
                }
                buf.push(byte);
                self.last = byte;
            }
        }
        bytes.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::DotStuffer;
    use crate::protocol::response::Response;
    use utils::chained_bytes::ChainedBytes;

    const STUFFING_ALPHABET: &[u8] = b"a.\r\n";
    const STUFFING_MAX_LEN: usize = 7;
    const KIB: usize = 1024;
    const ADVERSARIAL_LEN: usize = 64 * KIB;

    pub(crate) fn strings_over(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
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

    pub(crate) fn reference_pop3(message: &[u8]) -> Vec<u8> {
        let mut out = format!("+OK {} octets\r\n", message.len()).into_bytes();
        let mut prev = b'\n';
        for &byte in message {
            if byte == b'\n' && prev != b'\r' {
                out.push(b'\r');
            }
            if byte == b'.' && prev == b'\n' {
                out.push(b'.');
            }
            out.push(byte);
            prev = byte;
        }
        if prev != b'\n' {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
        out
    }

    #[test]
    fn dot_stuffing_matches_reference_at_every_split() {
        let serialize = |bytes: ChainedBytes<'_>| Response::<u32>::Message(bytes).serialize();
        for message in strings_over(STUFFING_ALPHABET, STUFFING_MAX_LEN) {
            let expected = reference_pop3(&message);
            for split in 0..=message.len() {
                let (head, tail) = message.split_at(split);
                assert_eq!(
                    serialize(ChainedBytes::chain(head, tail)),
                    expected,
                    "{message:?} split {split}"
                );
            }
        }
    }

    #[test]
    fn dot_stuffer_handles_many_segments() {
        for message in strings_over(STUFFING_ALPHABET, 5) {
            let expected = reference_pop3(&message);
            let mut buf = format!("+OK {} octets\r\n", message.len()).into_bytes();
            let mut stuffer = DotStuffer::default();
            for byte in message.chunks(1) {
                stuffer.push(&mut buf, &[]);
                stuffer.push(&mut buf, byte);
            }
            stuffer.finish(&mut buf);
            assert_eq!(buf, expected, "{message:?}");
        }
    }

    #[test]
    fn leading_dot_is_stuffed() {
        let serialize = |bytes: ChainedBytes<'_>| Response::<u32>::Message(bytes).serialize();
        assert_eq!(
            serialize(ChainedBytes::new(b".first\r\n")),
            b"+OK 8 octets\r\n..first\r\n.\r\n".to_vec()
        );
        assert_eq!(
            serialize(ChainedBytes::chain(b"", b".\r\n")),
            b"+OK 3 octets\r\n..\r\n.\r\n".to_vec()
        );
        assert_eq!(
            serialize(ChainedBytes::chain(b"a\r\n", b".b")),
            b"+OK 5 octets\r\na\r\n..b\r\n.\r\n".to_vec()
        );
    }

    #[test]
    fn empty_message_has_no_spurious_crlf() {
        let serialize = |bytes: ChainedBytes<'_>| Response::<u32>::Message(bytes).serialize();
        assert_eq!(
            serialize(ChainedBytes::default()),
            b"+OK 0 octets\r\n.\r\n".to_vec()
        );
        assert_eq!(
            serialize(ChainedBytes::chain(b"", b"")),
            b"+OK 0 octets\r\n.\r\n".to_vec()
        );
    }

    #[test]
    fn dot_stuffer_matches_reference_on_mixed_and_adversarial_input() {
        let serialize = |bytes: ChainedBytes<'_>| Response::<u32>::Message(bytes).serialize();
        let crlf_split_tail = [
            b"\n.second\r\n".as_slice(),
            &b"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789ab\r\n"
                .repeat(ADVERSARIAL_LEN / 76),
        ]
        .concat();
        let adversarial: [(&str, &[u8], Vec<u8>); 6] = [
            (
                "short-lines",
                b"Subject: short lines\r\n\r\n",
                b"a\r\n".repeat(ADVERSARIAL_LEN / 3),
            ),
            (
                "dot-lines",
                b"Subject: dot lines\r\n\r\n",
                b".a\r\n".repeat(ADVERSARIAL_LEN / 4),
            ),
            (
                "bare-lf",
                b"Subject: bare lf\n\n",
                b"a\n".repeat(ADVERSARIAL_LEN / 2),
            ),
            (
                "dot-bare-lf",
                b"Subject: dot bare lf\n\n",
                b".\n".repeat(ADVERSARIAL_LEN / 2),
            ),
            (
                "crlf-split",
                b"Subject: split at the boundary\r\n\r\n.first\r",
                crlf_split_tail,
            ),
            (
                "one-line",
                b"Subject: one line\r\n\r\n",
                vec![b'x'; 16 * ADVERSARIAL_LEN],
            ),
        ];
        for (name, head, tail) in &adversarial {
            let bytes = [*head, tail.as_slice()].concat();
            assert_eq!(
                serialize(ChainedBytes::chain(head, tail)),
                reference_pop3(&bytes),
                "{name}"
            );
        }
        let mixed: Vec<u8> = (0..20_000u32)
            .flat_map(|i| {
                let line: &[u8] = match i % 7 {
                    0 => b".dot\n",
                    1 => b"a\r\n",
                    2 => b"a much longer line that exceeds the sparse threshold of sixty-four bytes, surely\n",
                    3 => b"..\r\n",
                    4 => b"x\n",
                    5 => b"medium length line\r\n",
                    _ => b"\n",
                };
                line.iter().copied()
            })
            .collect();
        let expected = reference_pop3(&mixed);
        for split in [0, 1, 5, 100, 4097, mixed.len() / 2, mixed.len()] {
            let (head, tail) = mixed.split_at(split);
            assert_eq!(
                serialize(ChainedBytes::chain(head, tail)),
                expected,
                "split {split}"
            );
        }
    }

    #[test]
    fn dot_stuffer_switches_between_dense_and_sparse_at_every_split() {
        let serialize = |bytes: ChainedBytes<'_>| Response::<u32>::Message(bytes).serialize();
        let long_lf = [vec![b'b'; 70], b"\n".to_vec()].concat();
        let long_crlf = [vec![b'c'; 70], b"\r\n".to_vec()].concat();
        let block = [
            b"a\n".repeat(12),
            long_lf,
            b".\n".repeat(10),
            long_crlf,
            b"\r\n".repeat(3),
            b".x\r\n".repeat(9),
            b"\n".repeat(9),
        ]
        .concat();
        let message = block.repeat(3);
        let expected = reference_pop3(&message);
        for split in 0..=message.len() {
            let (head, tail) = message.split_at(split);
            assert_eq!(
                serialize(ChainedBytes::chain(head, tail)),
                expected,
                "split {split}"
            );
        }
    }
}
