/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    language::{
        Language,
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
        stemmer::STEMMER_MAP,
        stopwords::{STOP_WORDS, StopwordFnc},
    },
    tokenizers::{chinese::JIEBA, japanese},
};
use std::borrow::Cow;

pub struct WordStemTokenizer {
    stemmer: Stemmer,
    stop_words: Option<StopwordFnc>,
}

enum Stemmer {
    IndoEuropean(rust_stemmers::Stemmer),
    Mandarin,
    Japanese,
    None,
}

impl WordStemTokenizer {
    pub fn new(text: &str) -> Self {
        // Detect language
        let (mut language, score) =
            LanguageDetector::detect_single(text).unwrap_or((Language::English, 1.0));
        if score < MIN_LANGUAGE_SCORE {
            language = Language::English;
        }

        Self {
            stemmer: match language {
                Language::Mandarin => Stemmer::Mandarin,
                Language::Japanese => Stemmer::Japanese,
                _ => STEMMER_MAP[language as usize]
                    .map(|algo| Stemmer::IndoEuropean(rust_stemmers::Stemmer::create(algo)))
                    .unwrap_or(Stemmer::None),
            },
            stop_words: STOP_WORDS[language as usize],
        }
    }

    pub fn tokenize<'x>(&self, word: &'x str, mut cb: impl FnMut(Cow<'x, str>)) {
        if self.stop_words.is_some_and(|sw| sw(word)) {
            return;
        }
        match &self.stemmer {
            Stemmer::IndoEuropean(stemmer) => {
                cb(stemmer.stem(word));
            }
            Stemmer::Mandarin => {
                for token in JIEBA.cut(word, false) {
                    cb(Cow::from(token.word));
                }
            }
            Stemmer::Japanese => {
                for word in japanese::tokenize(word) {
                    cb(Cow::from(word));
                }
            }
            Stemmer::None => {
                cb(Cow::from(word));
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::tokenizers::{
        stream::WordStemTokenizer,
        types::{TokenType, TypesTokenizer},
    };

    #[test]
    fn stream_tokenizer() {
        let inputs = [
            (
                "The quick brown fox jumps over the lazy dog",
                vec!["quick", "brown", "fox", "jump", "lazi", "dog"],
            ),
            (
                "Jovencillo emponzoñado de whisky: ¡qué figurota exhibe!",
                vec!["jovencill", "emponzoñ", "whisky", "figurot", "exhib"],
            ),
            (
                "Ma la volpe col suo balzo ha raggiunto il quieto Fido",
                vec!["volp", "balz", "raggiunt", "quiet", "fid"],
            ),
            (
                "Jaz em prisão bota que vexa dez cegonhas felizes",
                vec!["jaz", "prisã", "bot", "vex", "dez", "cegonh", "feliz"],
            ),
            (
                "Zwölf Boxkämpfer jagten Victor quer über den großen Sylter Deich",
                vec![
                    "zwolf", "boxkampf", "jagt", "victor", "quer", "gross", "sylt", "deich",
                ],
            ),
            (
                "עטלף אבק נס דרך מזגן שהתפוצץ כי חם",
                vec!["עטלף", "אבק", "נס", "דרך", "מזגן", "שהתפוצץ", "כי", "חם"],
            ),
            (
                "Съешь ещё этих мягких французских булок, да выпей же чаю",
                vec![
                    "съеш",
                    "ещё",
                    "эт",
                    "мягк",
                    "французск",
                    "булок",
                    "вып",
                    "ча",
                ],
            ),
            (
                "Чуєш їх, доцю, га? Кумедна ж ти, прощайся без ґольфів!",
                vec![
                    "чуєш",
                    "їх",
                    "доцю",
                    "га",
                    "кумедна",
                    "ж",
                    "ти",
                    "прощайся",
                    "без",
                    "ґольфів",
                ],
            ),
            (
                "Љубазни фењерџија чађавог лица хоће да ми покаже штос",
                vec![
                    "љубазни",
                    "фењерџија",
                    "чађавог",
                    "лица",
                    "хоће",
                    "да",
                    "ми",
                    "покаже",
                    "штос",
                ],
            ),
            (
                "Pijamalı hasta yağız şoföre çabucak güvendi",
                vec!["pijamalı", "hasta", "yağız", "şoför", "çabucak", "güvendi"],
            ),
            ("己所不欲,勿施于人。", vec!["己所不欲", "勿施于人"]),
            (
                "井の中の蛙大海を知らず",
                vec!["井", "の", "中", "の", "蛙大", "海", "を", "知ら", "ず"],
            ),
            ("시작이 반이다", vec!["시작이", "반이다"]),
        ];

        for (input, expect) in inputs.iter() {
            let tokenizer = WordStemTokenizer::new(input);
            let mut result = Vec::new();
            for token in TypesTokenizer::new(&input.to_lowercase()) {
                if let TokenType::Alphabetic(word) = token.word {
                    tokenizer.tokenize(word, |t| {
                        result.push(t.into_owned());
                    });
                }
            }

            assert_eq!(&result, expect,);
        }
    }
}
