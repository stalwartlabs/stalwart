/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::set::{SetError, SetErrorType},
    object::email::EmailProperty,
};
use std::fmt::Display;
use types::keyword::Keyword;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailLimits {
    pub mailboxes_per_email: usize,
    pub keywords_per_email: usize,
    pub keyword_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailLimitError {
    TooManyMailboxes { max: usize },
    TooManyKeywords { max: usize },
    KeywordTooLong { max: usize },
}

impl EmailLimits {
    pub fn validate_mailbox_count(&self, count: usize) -> Result<(), EmailLimitError> {
        if count <= self.mailboxes_per_email {
            Ok(())
        } else {
            Err(EmailLimitError::TooManyMailboxes {
                max: self.mailboxes_per_email,
            })
        }
    }

    pub fn validate_mailbox_change(
        &self,
        prev_count: usize,
        count: usize,
    ) -> Result<(), EmailLimitError> {
        if count <= prev_count {
            Ok(())
        } else {
            self.validate_mailbox_count(count)
        }
    }

    pub fn validate_keyword_count(&self, count: usize) -> Result<(), EmailLimitError> {
        if count <= self.keywords_per_email {
            Ok(())
        } else {
            Err(EmailLimitError::TooManyKeywords {
                max: self.keywords_per_email,
            })
        }
    }

    pub fn validate_keyword_change(
        &self,
        prev_count: usize,
        count: usize,
    ) -> Result<(), EmailLimitError> {
        if count <= prev_count {
            Ok(())
        } else {
            self.validate_keyword_count(count)
        }
    }

    pub fn validate_keyword_names<'x>(
        &self,
        names: impl IntoIterator<Item = &'x str>,
    ) -> Result<(), EmailLimitError> {
        if names
            .into_iter()
            .all(|name| name.len() <= self.keyword_length)
        {
            Ok(())
        } else {
            Err(EmailLimitError::KeywordTooLong {
                max: self.keyword_length,
            })
        }
    }

    pub fn validate_keywords<'x>(
        &self,
        count: usize,
        names: impl IntoIterator<Item = &'x str>,
    ) -> Result<(), EmailLimitError> {
        self.validate_keyword_count(count)?;
        self.validate_keyword_names(names)
    }

    pub fn validate_email(
        &self,
        mailbox_count: usize,
        keywords: &[Keyword],
    ) -> Result<(), EmailLimitError> {
        self.validate_mailbox_count(mailbox_count)?;
        self.validate_keywords(
            keywords.len(),
            keywords.iter().filter_map(|keyword| keyword.id().err()),
        )
    }

    pub fn is_keyword_allowed(&self, keyword: &Keyword) -> bool {
        keyword
            .id()
            .map_or_else(|name| name.len() <= self.keyword_length, |_| true)
    }
}

impl From<EmailLimitError> for SetError<EmailProperty> {
    fn from(err: EmailLimitError) -> Self {
        match err {
            EmailLimitError::TooManyMailboxes { .. } => {
                SetError::new(SetErrorType::TooManyMailboxes)
                    .with_property(EmailProperty::MailboxIds)
            }
            EmailLimitError::TooManyKeywords { .. } => {
                SetError::new(SetErrorType::TooManyKeywords).with_property(EmailProperty::Keywords)
            }
            EmailLimitError::KeywordTooLong { .. } => {
                SetError::invalid_properties().with_property(EmailProperty::Keywords)
            }
        }
        .with_description(err.to_string())
    }
}

impl Display for EmailLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailLimitError::TooManyMailboxes { max } => {
                write!(f, "An email cannot belong to more than {max} mailboxes.")
            }
            EmailLimitError::TooManyKeywords { max } => {
                write!(f, "An email cannot have more than {max} keywords.")
            }
            EmailLimitError::KeywordTooLong { max } => {
                write!(f, "Keywords cannot be longer than {max} bytes.")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: EmailLimits = EmailLimits {
        mailboxes_per_email: 2,
        keywords_per_email: 3,
        keyword_length: 5,
    };

    fn keywords(names: &[&str]) -> Vec<Keyword> {
        names.iter().map(|name| Keyword::parse(name)).collect()
    }

    #[test]
    fn mailbox_count() {
        assert_eq!(LIMITS.validate_mailbox_count(2), Ok(()));
        assert_eq!(
            LIMITS.validate_mailbox_count(3),
            Err(EmailLimitError::TooManyMailboxes { max: 2 })
        );
    }

    #[test]
    fn mailbox_change_allows_shrinking_over_limit() {
        assert_eq!(LIMITS.validate_mailbox_change(5, 4), Ok(()));
        assert_eq!(LIMITS.validate_mailbox_change(5, 5), Ok(()));
        assert_eq!(LIMITS.validate_mailbox_change(1, 2), Ok(()));
        assert_eq!(
            LIMITS.validate_mailbox_change(2, 3),
            Err(EmailLimitError::TooManyMailboxes { max: 2 })
        );
    }

    #[test]
    fn keyword_change_allows_shrinking_over_limit() {
        assert_eq!(LIMITS.validate_keyword_change(6, 4), Ok(()));
        assert_eq!(
            LIMITS.validate_keyword_change(3, 4),
            Err(EmailLimitError::TooManyKeywords { max: 3 })
        );
    }

    #[test]
    fn email_keywords() {
        assert_eq!(
            LIMITS.validate_email(1, &keywords(&["$seen", "abcde", "$flagged"])),
            Ok(())
        );
        assert_eq!(
            LIMITS.validate_email(1, &keywords(&["$seen", "a", "b", "c"])),
            Err(EmailLimitError::TooManyKeywords { max: 3 })
        );
        assert_eq!(
            LIMITS.validate_email(1, &keywords(&["abcdef"])),
            Err(EmailLimitError::KeywordTooLong { max: 5 })
        );
        assert_eq!(
            LIMITS.validate_email(3, &keywords(&["abcdef"])),
            Err(EmailLimitError::TooManyMailboxes { max: 2 })
        );
    }

    #[test]
    fn system_keywords_ignore_length() {
        assert!(LIMITS.is_keyword_allowed(&Keyword::parse("$hasattachment")));
        assert!(LIMITS.is_keyword_allowed(&Keyword::parse("abcde")));
        assert!(!LIMITS.is_keyword_allowed(&Keyword::parse("abcdef")));
    }

    #[test]
    fn set_error_mapping() {
        let err: SetError<EmailProperty> = EmailLimitError::TooManyMailboxes { max: 2 }.into();
        assert_eq!(err.error_type(), &SetErrorType::TooManyMailboxes);
        let err: SetError<EmailProperty> = EmailLimitError::TooManyKeywords { max: 3 }.into();
        assert_eq!(err.error_type(), &SetErrorType::TooManyKeywords);
        let err: SetError<EmailProperty> = EmailLimitError::KeywordTooLong { max: 5 }.into();
        assert_eq!(err.error_type(), &SetErrorType::InvalidProperties);
        assert_eq!(
            err.description(),
            Some("Keywords cannot be longer than 5 bytes.")
        );
    }
}
