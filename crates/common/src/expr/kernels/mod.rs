/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod case;
mod count;
mod encode;
mod ignore_case;
mod needle;
mod rank;
mod segments;
mod set;
mod text;

#[cfg(test)]
mod tests;

pub use case::{to_lowercase, to_uppercase};
pub use count::{
    count_chars, count_lowercase, count_uppercase, count_whitespace, has_digits, is_lowercase,
    is_uppercase,
};
pub use encode::{hex_encode, utf8_lossy};
pub use ignore_case::{IgnoreCaseNeedle, contains_ignore_case};
pub use needle::ConstNeedle;
pub use set::ConstSet;
pub use text::{SplitWords, split_words, substring};
