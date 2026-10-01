/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod case;
mod encode;

#[cfg(test)]
mod tests;

pub use case::{to_lowercase, to_uppercase};
pub use encode::{hex_encode, utf8_lossy};
pub use utils::text::{
    ConstNeedle, ConstSet, IgnoreCaseNeedle, SplitWords, contains_ignore_case, count_chars,
    count_lowercase, count_uppercase, count_whitespace, has_digits, is_lowercase, is_uppercase,
    split_words, substring,
};
