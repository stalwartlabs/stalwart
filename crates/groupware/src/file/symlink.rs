/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub const MAX_SYMLINK_TARGET_LEN: usize = 4096;
const SEPARATOR: char = '/';
const ROOT: &str = "/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkTargetError {
    Empty,
    EmptyElement,
    InvalidCharacter,
    TooLong,
}

#[derive(Default)]
pub struct SymlinkTargetBuilder {
    target: String,
    elements: usize,
}

impl SymlinkTargetBuilder {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            target: String::with_capacity(capacity),
            elements: 0,
        }
    }

    pub fn push(&mut self, element: &str) -> Result<(), SymlinkTargetError> {
        if element.contains([SEPARATOR, '\0']) {
            return Err(SymlinkTargetError::InvalidCharacter);
        } else if element.is_empty() && self.elements > 0 {
            return Err(SymlinkTargetError::EmptyElement);
        }
        if self.elements > 0 {
            self.target.push(SEPARATOR);
        }
        self.target.push_str(element);
        self.elements += 1;
        if self.target.len() > MAX_SYMLINK_TARGET_LEN {
            Err(SymlinkTargetError::TooLong)
        } else {
            Ok(())
        }
    }

    pub fn build(mut self) -> Result<String, SymlinkTargetError> {
        match self.elements {
            0 => Err(SymlinkTargetError::Empty),
            1 if self.target.is_empty() => {
                self.target.push(SEPARATOR);
                Ok(self.target)
            }
            _ => Ok(self.target),
        }
    }
}

pub fn symlink_target_elements(target: &str) -> impl Iterator<Item = &str> {
    let (root, rest) = if target == ROOT {
        (Some(""), None)
    } else {
        (None, Some(target.split(SEPARATOR)))
    };
    root.into_iter().chain(rest.into_iter().flatten())
}

impl SymlinkTargetError {
    pub fn description(&self) -> &'static str {
        match self {
            SymlinkTargetError::Empty => "target must contain at least one element.",
            SymlinkTargetError::EmptyElement => "only the first target element may be empty.",
            SymlinkTargetError::InvalidCharacter => {
                "target elements must not contain '/' or U+0000."
            }
            SymlinkTargetError::TooLong => "target is too long.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(elements: &[&str]) -> Result<String, SymlinkTargetError> {
        let mut builder = SymlinkTargetBuilder::default();
        for element in elements {
            builder.push(element)?;
        }
        builder.build()
    }

    #[test]
    fn targets_round_trip() {
        for (elements, stored) in [
            (&["", "docs", "a.txt"][..], "/docs/a.txt"),
            (&[""][..], "/"),
            (&["..", "x"][..], "../x"),
            (&["a", "b"][..], "a/b"),
            (&["."][..], "."),
            (&["name with spaces", "ü"][..], "name with spaces/ü"),
        ] {
            assert_eq!(encode(elements).as_deref(), Ok(stored));
            assert_eq!(
                symlink_target_elements(stored).collect::<Vec<_>>(),
                elements,
                "{stored}"
            );
        }
    }

    #[test]
    fn invalid_targets_are_rejected() {
        assert_eq!(encode(&[]), Err(SymlinkTargetError::Empty));
        assert_eq!(encode(&["a", ""]), Err(SymlinkTargetError::EmptyElement));
        assert_eq!(encode(&["", ""]), Err(SymlinkTargetError::EmptyElement));
        assert_eq!(encode(&["a/b"]), Err(SymlinkTargetError::InvalidCharacter));
        assert_eq!(encode(&["a\0"]), Err(SymlinkTargetError::InvalidCharacter));
        let long = "x".repeat(MAX_SYMLINK_TARGET_LEN);
        assert_eq!(encode(&[&long, "y"]), Err(SymlinkTargetError::TooLong));
    }
}
