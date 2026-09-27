/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Builder, Entry, NO_SLOT};
use crate::pdf::{
    lexer::{Lexer, Token},
    object::{Dict, Object},
};

const MIN_ENTRY_BYTES: usize = 18;
const FREE_HEAD_GEN: i64 = 65535;

enum Flag {
    Used,
    Free,
}

pub(super) fn read_table<'a>(
    data: &'a [u8],
    pos: usize,
    builder: &mut Builder<'_>,
    section: u16,
) -> Option<Dict<'a>> {
    let mut lexer = Lexer::at(data, pos);
    let mut current = 0u64;
    let mut first_subsection = true;
    loop {
        let before = lexer.pos();
        match lexer.next()? {
            Token::Keyword(b"trailer") => {
                return Object::read(&mut lexer, None).and_then(|object| object.as_dict());
            }
            Token::Int(first) => {
                let Token::Int(second) = lexer.next()? else {
                    return None;
                };
                if let Some(flag) = flag(&lexer) {
                    lexer.next();
                    emit(builder, current, first, second, flag, section);
                    current = current.saturating_add(1);
                    continue;
                }
                let Ok(start) = u64::try_from(first) else {
                    return None;
                };
                let room = data.len().saturating_sub(lexer.pos()) / MIN_ENTRY_BYTES + 1;
                let count = usize::try_from(second).unwrap_or(0).min(room);
                current = start;
                for index in 0..count {
                    let mut probe = lexer;
                    let (Some(Token::Int(offset)), Some(Token::Int(generation))) =
                        (probe.next(), probe.next())
                    else {
                        break;
                    };
                    lexer = probe;
                    let flag = match flag(&lexer) {
                        Some(flag) => {
                            lexer.next();
                            flag
                        }
                        None => Flag::Free,
                    };
                    if first_subsection
                        && index == 0
                        && start == 1
                        && offset == 0
                        && generation == FREE_HEAD_GEN
                        && matches!(flag, Flag::Free)
                    {
                        current = 0;
                    }
                    emit(builder, current, offset, generation, flag, section);
                    current = current.saturating_add(1);
                }
                first_subsection = false;
            }
            _ => {
                lexer.set_pos(before);
                return None;
            }
        }
    }
}

fn flag(lexer: &Lexer<'_>) -> Option<Flag> {
    match lexer.peek()? {
        Token::Keyword(b"n" | b"N") => Some(Flag::Used),
        Token::Keyword(b"f" | b"F") => Some(Flag::Free),
        Token::Keyword(word) if word.len() == 1 => Some(Flag::Free),
        _ => None,
    }
}

fn emit(
    builder: &mut Builder<'_>,
    num: u64,
    offset: i64,
    generation: i64,
    flag: Flag,
    section: u16,
) {
    let offset = u32::try_from(offset).ok().filter(|&offset| offset > 0);
    let entry = match (flag, offset) {
        (Flag::Used, Some(offset)) => Entry::Offset {
            offset,
            generation: u16::try_from(generation.clamp(0, i64::from(u16::MAX))).unwrap_or(u16::MAX),
            slot: NO_SLOT,
        },
        _ => Entry::Free { section },
    };
    builder.merge(num, entry, section);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::xref::Entries;

    fn read(table: &[u8]) -> (Vec<Entry>, bool) {
        let mut entries = Entries::default();
        let mut builder = Builder::new(&mut entries, 1 << 16, 1 << 20);
        let trailer = read_table(table, 0, &mut builder, 0).is_some();
        builder.finish();
        (entries.iter().map(|(_, entry)| entry).collect(), trailer)
    }

    #[test]
    fn tolerant_tables() {
        let (entries, trailer) = read(
            b"\n0 3\r\n0000000000 65535 f\r\n0000000017 00000 n\r\n0000000081 00000 n\ntrailer\n<< /Size 3 >>",
        );
        assert!(trailer);
        assert_eq!(
            entries,
            vec![
                Entry::Free { section: 0 },
                Entry::Offset {
                    offset: 17,
                    generation: 0,
                    slot: NO_SLOT
                },
                Entry::Offset {
                    offset: 81,
                    generation: 0,
                    slot: NO_SLOT
                },
            ]
        );
        let (entries, _) = read(b"1 2\n0000000000 65535 f\n0000000009 00000 n\ntrailer<<>>");
        assert!(matches!(
            entries.get(1),
            Some(Entry::Offset { offset: 9, .. })
        ));
        let (entries, trailer) = read(b"0 5\n0000000000 65535 f\n0000000009 00000 n\ntrailer<<>>");
        assert!(trailer);
        assert_eq!(entries.len(), 2);
        let (entries, trailer) =
            read(b"0 1\n0000000000 65535 f\n0000000009 00000 n\n0000000000 00000 n\n0000000010 00000 x\ntrailer<<>>");
        assert!(trailer);
        assert!(matches!(
            entries.get(1),
            Some(Entry::Offset { offset: 9, .. })
        ));
        assert_eq!(entries.get(2), Some(&Entry::Free { section: 0 }));
        assert_eq!(entries.get(3), Some(&Entry::Free { section: 0 }));
        let (_, trailer) = read(b"0 1\ngarbage");
        assert!(!trailer);
        let (entries, _) = read(b"4294967296 1\n0000000009 00000 n\ntrailer<<>>");
        assert!(entries.is_empty());
    }
}
