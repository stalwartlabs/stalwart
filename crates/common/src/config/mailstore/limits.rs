/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::set::{SetError, SetErrorType},
    object::email::EmailProperty,
};
use mail_parser::Message;
use std::fmt::Display;
use types::keyword::Keyword;

pub const MAX_HEADER_ENTRIES: usize = 65_534;
const HEADER_TERMINATOR_LEN: usize = b"\r\n".len();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailLimits {
    pub mailboxes_per_email: usize,
    pub keywords_per_email: usize,
    pub keyword_length: usize,
    pub header_count: usize,
    pub header_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailLimitError {
    TooManyMailboxes { max: usize },
    TooManyKeywords { max: usize },
    KeywordTooLong { max: usize },
    TooManyHeaders { max: usize },
    TooManyMessageHeaders { max: usize },
    HeaderTooLarge { max: usize },
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

    pub fn header_fields_size(&self) -> usize {
        self.header_size.saturating_sub(HEADER_TERMINATOR_LEN)
    }

    pub fn validate_header_section(&self, message: &Message<'_>) -> Result<(), EmailLimitError> {
        let root = message.root_part();
        if root.headers().len() > self.header_count {
            Err(EmailLimitError::TooManyHeaders {
                max: self.header_count,
            })
        } else if message.header_count() > MAX_HEADER_ENTRIES {
            Err(EmailLimitError::TooManyMessageHeaders {
                max: MAX_HEADER_ENTRIES,
            })
        } else if root.offset_body().saturating_sub(root.offset_header()) as usize
            > self.header_size
        {
            Err(EmailLimitError::HeaderTooLarge {
                max: self.header_size,
            })
        } else {
            Ok(())
        }
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
            EmailLimitError::TooManyHeaders { .. }
            | EmailLimitError::TooManyMessageHeaders { .. }
            | EmailLimitError::HeaderTooLarge { .. } => SetError::too_large(),
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
            EmailLimitError::TooManyHeaders { max } => {
                write!(f, "An email header cannot have more than {max} fields.")
            }
            EmailLimitError::TooManyMessageHeaders { max } => {
                write!(
                    f,
                    "An email cannot have more than {max} header fields across all its parts."
                )
            }
            EmailLimitError::HeaderTooLarge { max } => {
                write!(f, "An email header cannot exceed {max} bytes.")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::MessageParser;

    const LIMITS: EmailLimits = EmailLimits {
        mailboxes_per_email: 2,
        keywords_per_email: 3,
        keyword_length: 5,
        header_count: 3,
        header_size: 38,
    };
    const HEADER_FIELD: &str = "Subject: x\r\n";
    const NESTED_ROOT_HEADER: &str = concat!(
        "Subject: nested\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n"
    );

    fn keywords(names: &[&str]) -> Vec<Keyword> {
        names.iter().map(|name| Keyword::parse(name)).collect()
    }

    fn header_fields(count: usize) -> String {
        format!("{}\r\nbody\r\n", HEADER_FIELD.repeat(count))
    }

    fn validate_raw(limits: &EmailLimits, raw: &str) -> Result<(), EmailLimitError> {
        let message = MessageParser::new()
            .parse(raw.as_bytes())
            .expect("test message parses");
        limits.validate_header_section(&message)
    }

    fn nested_message() -> String {
        let nested_fields = HEADER_FIELD.repeat(50);
        format!(
            concat!(
                "{root}",
                "--b\r\n",
                "{nested_fields}",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "part\r\n",
                "--b\r\n",
                "Content-Type: message/rfc822\r\n",
                "\r\n",
                "{nested_fields}",
                "\r\n",
                "attached\r\n",
                "--b--\r\n"
            ),
            root = NESTED_ROOT_HEADER,
            nested_fields = nested_fields,
        )
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
    fn header_section_at_limit() {
        assert_eq!(validate_raw(&LIMITS, &header_fields(3)), Ok(()));
    }

    #[test]
    fn header_fields_size_excludes_terminator() {
        assert_eq!(LIMITS.header_fields_size(), 36);
    }

    #[test]
    fn header_count_over_limit() {
        let limits = EmailLimits {
            header_size: usize::MAX,
            ..LIMITS
        };
        assert_eq!(
            validate_raw(&limits, &header_fields(4)),
            Err(EmailLimitError::TooManyHeaders { max: 3 })
        );
    }

    #[test]
    fn header_size_over_limit() {
        let limits = EmailLimits {
            header_size: LIMITS.header_size - 1,
            ..LIMITS
        };
        assert_eq!(
            validate_raw(&limits, &header_fields(3)),
            Err(EmailLimitError::HeaderTooLarge { max: 37 })
        );
    }

    #[test]
    fn nested_headers_not_counted() {
        let raw = nested_message();
        let limits = EmailLimits {
            header_count: 2,
            header_size: NESTED_ROOT_HEADER.len(),
            ..LIMITS
        };
        assert_eq!(validate_raw(&limits, &raw), Ok(()));
        assert_eq!(
            validate_raw(
                &EmailLimits {
                    header_count: 1,
                    ..limits
                },
                &raw
            ),
            Err(EmailLimitError::TooManyHeaders { max: 1 })
        );
        assert_eq!(
            validate_raw(
                &EmailLimits {
                    header_size: NESTED_ROOT_HEADER.len() - 1,
                    ..limits
                },
                &raw
            ),
            Err(EmailLimitError::HeaderTooLarge {
                max: NESTED_ROOT_HEADER.len() - 1
            })
        );
    }

    #[test]
    fn message_header_count_spans_every_part() {
        let raw = |part_fields: usize| {
            format!(
                concat!(
                    "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                    "\r\n",
                    "--b\r\n",
                    "{fields}",
                    "\r\n",
                    "part\r\n",
                    "--b--\r\n"
                ),
                fields = HEADER_FIELD.repeat(part_fields)
            )
        };
        let limits = EmailLimits {
            header_count: 1,
            header_size: usize::MAX,
            ..LIMITS
        };
        assert_eq!(validate_raw(&limits, &raw(MAX_HEADER_ENTRIES - 1)), Ok(()));
        assert_eq!(
            validate_raw(&limits, &raw(MAX_HEADER_ENTRIES)),
            Err(EmailLimitError::TooManyMessageHeaders {
                max: MAX_HEADER_ENTRIES
            })
        );
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
        let err: SetError<EmailProperty> = EmailLimitError::TooManyHeaders { max: 100 }.into();
        assert_eq!(err.error_type(), &SetErrorType::TooLarge);
        assert_eq!(
            err.description(),
            Some("An email header cannot have more than 100 fields.")
        );
        let err: SetError<EmailProperty> =
            EmailLimitError::TooManyMessageHeaders { max: 100 }.into();
        assert_eq!(err.error_type(), &SetErrorType::TooLarge);
        assert_eq!(
            err.description(),
            Some("An email cannot have more than 100 header fields across all its parts.")
        );
        let err: SetError<EmailProperty> = EmailLimitError::HeaderTooLarge { max: 1024 }.into();
        assert_eq!(err.error_type(), &SetErrorType::TooLarge);
        assert_eq!(
            err.description(),
            Some("An email header cannot exceed 1024 bytes.")
        );
    }
}
