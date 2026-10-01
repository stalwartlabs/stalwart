/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Language;
use std::collections::VecDeque;

fn escape_char(c: char, string: &mut String) {
    match c {
        '&' => string.push_str("&amp;"),
        '<' => string.push_str("&lt;"),
        '>' => string.push_str("&gt;"),
        '"' => string.push_str("&quot;"),
        '\n' | '\r' => string.push(' '),
        _ => string.push(c),
    }
}

fn escape_char_len(c: char) -> usize {
    match c {
        '&' => "&amp;".len(),
        '<' => "&lt;".len(),
        '>' => "&gt;".len(),
        '"' => "&quot;".len(),
        '\r' | '\n' => 1,
        _ => c.len_utf8(),
    }
}

const MAX_SNIPPET_LEN: usize = 255;
const MARK_LEN: usize = "<mark>".len() * 2;
const LEADING_CONTEXT_THRESHOLD: usize = 240;
const LEADING_CONTEXT_CHARS: usize = 40;
const LEADING_CONTEXT_WORDS: usize = 3;
const MAX_TOKEN_LEN: usize = 200;
const MAX_WINDOW_CAPACITY: usize = 64;

struct Term {
    offset: usize,
    len: usize,
}

struct SnippetWriter<'x> {
    text: &'x str,
    snippet: String,
    last_end: Option<usize>,
    stop_offset: usize,
}

enum Flow {
    Continue,
    Full,
}

pub fn generate_snippet(
    text: &str,
    needles: &[impl AsRef<str>],
    language: Language,
    is_exact: bool,
) -> Option<String> {
    let mut writer = SnippetWriter {
        text,
        snippet: String::new(),
        last_end: None,
        stop_offset: usize::MAX,
    };
    let tokens = language.tokenize_text(text, MAX_TOKEN_LEN);

    if is_exact {
        if needles.is_empty() {
            return None;
        }
        let mut window = VecDeque::with_capacity(needles.len().min(MAX_WINDOW_CAPACITY));
        for token in tokens {
            if window.len() == needles.len() {
                window.pop_front();
            }
            window.push_back(token);
            if window.len() < needles.len() {
                continue;
            }
            if window
                .front()
                .is_some_and(|first| first.from >= writer.stop_offset)
            {
                break;
            }
            if needles
                .iter()
                .zip(&window)
                .all(|(needle, token)| needle.as_ref() == token.word.as_ref())
            {
                for token in &window {
                    if let Flow::Full = writer.push(Term {
                        offset: token.from,
                        len: token.to - token.from,
                    })? {
                        return Some(writer.snippet);
                    }
                }
            }
        }
    } else {
        for token in tokens {
            if token.from >= writer.stop_offset {
                break;
            }
            if needles.iter().any(|needle| {
                let needle = needle.as_ref();
                needle == token.word.as_ref() || needle.len() > 2 && token.word.contains(needle)
            }) && let Flow::Full = writer.push(Term {
                offset: token.from,
                len: token.to - token.from,
            })? {
                return Some(writer.snippet);
            }
        }
    }

    writer.finish()
}

impl SnippetWriter<'_> {
    fn push(&mut self, term: Term) -> Option<Flow> {
        match self.last_end {
            Some(end) => {
                if let Flow::Full = self.write_gap(end, term.offset)? {
                    return Some(Flow::Full);
                }
            }
            None => self.write_leading_context(term.offset)?,
        }

        if self.snippet.len() + MARK_LEN + term.len + 1 > MAX_SNIPPET_LEN {
            return Some(Flow::Full);
        }

        let end = term.offset + term.len;
        self.snippet.push_str("<mark>");
        self.snippet.push_str(self.text.get(term.offset..end)?);
        self.snippet.push_str("</mark>");
        self.last_end = Some(end);
        self.stop_offset = self.overflow_offset(end);

        Some(Flow::Continue)
    }

    fn finish(mut self) -> Option<String> {
        let end = self.last_end?;
        self.write_gap(end, self.text.len())?;
        Some(self.snippet)
    }

    fn write_leading_context(&mut self, start_offset: usize) -> Option<()> {
        self.snippet
            .reserve(self.text.len().min(MAX_SNIPPET_LEN + 1));

        if start_offset > 0 {
            let mut word_count = 0;
            let mut from_offset = 0;
            let mut last_is_space = false;

            if self.text.len() > LEADING_CONTEXT_THRESHOLD {
                for (pos, char) in self.text.get(0..start_offset)?.char_indices().rev() {
                    if char.is_whitespace() {
                        if !last_is_space {
                            word_count += 1;
                            if word_count == LEADING_CONTEXT_WORDS {
                                break;
                            }
                            last_is_space = true;
                        }
                    } else {
                        last_is_space = false;
                    }
                    from_offset = pos;
                    if start_offset - from_offset >= LEADING_CONTEXT_CHARS {
                        break;
                    }
                }
            }

            last_is_space = false;
            for char in self.text.get(from_offset..start_offset)?.chars() {
                if !char.is_whitespace() {
                    last_is_space = false;
                } else {
                    if last_is_space {
                        continue;
                    }
                    last_is_space = true;
                }
                escape_char(char, &mut self.snippet);
            }
        }

        Some(())
    }

    fn write_gap(&mut self, from: usize, to: usize) -> Option<Flow> {
        let mut last_is_space = false;
        for char in self.text.get(from..to)?.chars() {
            if !char.is_whitespace() {
                last_is_space = false;
            } else {
                if last_is_space {
                    continue;
                }
                last_is_space = true;
            }

            if self.snippet.len() + escape_char_len(char) <= MAX_SNIPPET_LEN {
                escape_char(char, &mut self.snippet);
            } else {
                return Some(Flow::Full);
            }
        }

        Some(Flow::Continue)
    }

    fn overflow_offset(&self, from: usize) -> usize {
        let Some(rest) = self.text.get(from..) else {
            return usize::MAX;
        };
        let mut len = self.snippet.len();
        let mut last_is_space = false;
        for (pos, char) in rest.char_indices() {
            if !char.is_whitespace() {
                last_is_space = false;
            } else {
                if last_is_space {
                    continue;
                }
                last_is_space = true;
            }
            len += escape_char_len(char);
            if len > MAX_SNIPPET_LEN {
                return from + pos;
            }
        }
        usize::MAX
    }
}

#[cfg(test)]
mod tests {
    use crate::language::{
        Language,
        search_snippet::{escape_char, escape_char_len, generate_snippet},
    };

    struct ReferenceTerm {
        offset: usize,
        len: usize,
    }

    fn reference_snippet(
        text: &str,
        needles: &[impl AsRef<str>],
        language: Language,
        is_exact: bool,
    ) -> Option<String> {
        let mut terms = Vec::new();
        if is_exact {
            let tokens = language.tokenize_text(text, 200).collect::<Vec<_>>();
            for tokens in tokens.windows(needles.len()) {
                if needles
                    .iter()
                    .zip(tokens)
                    .all(|(needle, token)| needle.as_ref() == token.word.as_ref())
                {
                    for token in tokens {
                        terms.push(ReferenceTerm {
                            offset: token.from,
                            len: token.to - token.from,
                        });
                    }
                }
            }
        } else {
            for token in language.tokenize_text(text, 200) {
                if needles.iter().any(|needle| {
                    let needle = needle.as_ref();
                    needle == token.word.as_ref() || needle.len() > 2 && token.word.contains(needle)
                }) {
                    terms.push(ReferenceTerm {
                        offset: token.from,
                        len: token.to - token.from,
                    });
                }
            }
        }
        if terms.is_empty() {
            return None;
        }

        let mut snippet = String::with_capacity(text.len());
        let start_offset = terms.first()?.offset;

        if start_offset > 0 {
            let mut word_count = 0;
            let mut from_offset = 0;
            let mut last_is_space = false;

            if text.len() > 240 {
                for (pos, char) in text.get(0..start_offset)?.char_indices().rev() {
                    if char.is_whitespace() {
                        if !last_is_space {
                            word_count += 1;
                            if word_count == 3 {
                                break;
                            }
                            last_is_space = true;
                        }
                    } else {
                        last_is_space = false;
                    }
                    from_offset = pos;
                    if start_offset - from_offset >= 40 {
                        break;
                    }
                }
            }

            last_is_space = false;
            for char in text.get(from_offset..start_offset)?.chars() {
                if !char.is_whitespace() {
                    last_is_space = false;
                } else {
                    if last_is_space {
                        continue;
                    }
                    last_is_space = true;
                }
                escape_char(char, &mut snippet);
            }
        }

        let mut terms = terms.iter().peekable();

        'outer: while let Some(term) = terms.next() {
            if snippet.len() + ("<mark>".len() * 2) + term.len + 1 > 255 {
                break;
            }

            snippet.push_str("<mark>");
            snippet.push_str(text.get(term.offset..term.offset + term.len)?);
            snippet.push_str("</mark>");

            let next_offset = if let Some(next_term) = terms.peek() {
                next_term.offset
            } else {
                text.len()
            };

            let mut last_is_space = false;
            for char in text.get(term.offset + term.len..next_offset)?.chars() {
                if !char.is_whitespace() {
                    last_is_space = false;
                } else {
                    if last_is_space {
                        continue;
                    }
                    last_is_space = true;
                }

                if snippet.len() + escape_char_len(char) <= 255 {
                    escape_char(char, &mut snippet);
                } else {
                    break 'outer;
                }
            }
        }

        Some(snippet)
    }

    #[test]
    fn snippets_match_reference() {
        const WORDS: [&str; 12] = [
            "alpha", "Beta", "gamma", "delta", "<tag>", "a&b", "\"q\"", "côte", "x", "alphabet",
            "beta", "gam",
        ];
        const GAPS: [&str; 6] = [" ", "  ", "\n", " \r\n ", "\t\t", "    \n\n    "];
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % bound as u64) as usize
        };

        for _ in 0..4000 {
            let mut text = String::new();
            for _ in 0..next(400) {
                text.push_str(WORDS[next(WORDS.len())]);
                text.push_str(GAPS[next(GAPS.len())]);
            }
            let needles: Vec<&str> = (0..next(4)).map(|_| WORDS[next(WORDS.len())]).collect();
            let needles: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();
            for is_exact in [false, true] {
                if is_exact && needles.is_empty() {
                    assert_eq!(
                        generate_snippet(&text, &needles, Language::English, true),
                        None
                    );
                    continue;
                }
                assert_eq!(
                    generate_snippet(&text, &needles, Language::English, is_exact),
                    reference_snippet(&text, &needles, Language::English, is_exact),
                    "{text:?} {needles:?} {is_exact}"
                );
            }
        }
    }

    #[test]
    fn search_snippets() {
        let inputs = [
            (
                vec![
                    "Help a friend from Abidjan Côte d'Ivoire",
                    concat!(
                        "When my mother died when she was given birth to me, my father took me so ",
                        "special because I am motherless. Before the death of my late father on 22nd June ",
                        "2013 in a private hospital here in Abidjan Côte d'Ivoire. He secretly called me on his ",
                        "bedside and told me that he has a sum of $7.5M (Seven Million five Hundred ",
                        "Thousand Dollars) left in a suspense account in a local bank here in Abidjan Côte ",
                        "d'Ivoire, that he used my name as his only daughter for the next of kin in deposit of ",
                        "the fund. ",
                        "I am 24year old. Dear I am honorably seeking your assistance in the following ways. ",
                        "1) To provide any bank account where this money would be transferred into. ",
                        "2) To serve as the guardian of this fund. ",
                        "3) To make arrangement for me to come over to your country to further my ",
                        "education and to secure a residential permit for me in your country. ",
                        "Moreover, I am willing to offer you 30 percent of the total sum as compensation for ",
                        "your effort input after the successful transfer of this fund to your nominated ",
                        "account overseas."
                    ),
                ],
                vec![
                    (
                        vec!["côte"],
                        vec![
                            "Help a friend from Abidjan <mark>Côte</mark> d'Ivoire",
                            concat!(
                                "in Abidjan <mark>Côte</mark> d'Ivoire. He secretly called me on his bedside ",
                                "and told me that he has a sum of $7.5M (Seven Million five Hundred Thousand ",
                                "Dollars) left in a suspense account in a local bank here in Abidjan ",
                                "<mark>Côte</mark> d'Ivoire, that "
                            ),
                        ],
                    ),
                    (
                        vec!["your", "country"],
                        vec![concat!(
                            "honorably seeking <mark>your</mark> assistance in the following ways. ",
                            "1) To provide any bank account where this money would be transferred into. 2) ",
                            "To serve as the guardian of this fund. 3) To make arrangement for me to come ",
                            "over to <mark>your</mark> "
                        )],
                    ),
                    (
                        vec!["overseas"],
                        vec!["nominated account <mark>overseas</mark>."],
                    ),
                ],
            ),
            (
                vec![
                    "孫子兵法",
                    concat!(
                        "<\"孫子兵法：\">",
                        "孫子曰：兵者，國之大事，死生之地，存亡之道，不可不察也。",
                        "孫子曰：凡用兵之法，馳車千駟，革車千乘，帶甲十萬；千里饋糧，則內外之費賓客之用，膠漆之材，",
                        "車甲之奉，日費千金，然後十萬之師舉矣。",
                        "孫子曰：凡用兵之法，全國為上，破國次之；全旅為上，破旅次之；全卒為上，破卒次之；全伍為上，破伍次之。",
                        "是故百戰百勝，非善之善者也；不戰而屈人之兵，善之善者也。",
                        "孫子曰：昔之善戰者，先為不可勝，以待敵之可勝，不可勝在己，可勝在敵。故善戰者，能為不可勝，不能使敵必可勝。",
                        "故曰：勝可知，而不可為。",
                        "兵者，詭道也。故能而示之不能，用而示之不用，近而示之遠，遠而示之近。利而誘之，亂而取之，實而備之，強而避之，",
                        "怒而撓之，卑而驕之，佚而勞之，親而離之。攻其無備，出其不意，此兵家之勝，不可先傳也。",
                        "夫未戰而廟算勝者，得算多也；未戰而廟算不勝者，得算少也；多算勝，少算不勝，而況於無算乎？吾以此觀之，勝負見矣。",
                        "孫子曰：凡治眾如治寡，分數是也。鬥眾如鬥寡，形名是也。三軍之眾，可使必受敵而無敗者，奇正是也。兵之所加，",
                        "如以碬投卵者，虛實是也。",
                    ),
                ],
                vec![
                    (
                        vec!["孫子兵法"],
                        vec![
                            "<mark>孫子兵法</mark>",
                            concat!(
                                "&lt;&quot;<mark>孫子兵法</mark>：&quot;&gt;孫子曰：兵者，國之大事，死生之地，存亡之道，",
                                "不可不察也。孫子曰：凡用兵之法，馳車千駟，革車千乘，帶甲十萬；千里饋糧，則內外之費賓客之用，膠"
                            ),
                        ],
                    ),
                    (
                        vec!["孫子曰"],
                        vec![concat!(
                            "&lt;&quot;孫子兵法：&quot;&gt;<mark>孫子曰</mark>：兵者，國之大事，死生之地，存亡之道，",
                            "不可不察也。<mark>孫子曰</mark>：凡用兵之法，馳車千駟，革車千乘，帶甲十萬；千里饋糧，則內外之費賓",
                        )],
                    ),
                ],
            ),
        ];

        for (parts, tests) in inputs {
            for (needles, snippets) in tests {
                let mut results = Vec::new();

                for part in &parts {
                    if let Some(matched) =
                        generate_snippet(part, &needles, Language::English, false)
                    {
                        results.push(matched);
                    }
                }

                assert_eq!(snippets, results);
            }
        }
    }
}
