/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::resolver::{Mode, MxPattern, Policy};
use utils::DomainPart;

fn to_a_label(domain: &str) -> String {
    domain
        .to_ascii_domain()
        .map(|domain| domain.to_lowercase())
        .unwrap_or_else(|| domain.to_lowercase())
}

pub trait ParsePolicy {
    fn parse(data: &str, id: String) -> Result<Self, String>
    where
        Self: Sized;
}

impl ParsePolicy for Policy {
    fn parse(mut data: &str, id: String) -> Result<Policy, String> {
        let mut mode = Mode::None;
        let mut max_age: u64 = 86400;
        let mut mx = Vec::new();

        while !data.is_empty() {
            if let Some((key, next_data)) = data.split_once(':') {
                let value = if let Some((value, next_data)) = next_data.split_once('\n') {
                    data = next_data;
                    value.trim()
                } else {
                    data = "";
                    next_data.trim()
                };
                hashify::fnc_map!(key.trim().as_bytes(),
                    b"mx" => {
                        if let Some(suffix) = value.strip_prefix("*.") {
                            if !suffix.is_empty() {
                                mx.push(MxPattern::StartsWith(to_a_label(suffix)));
                            }
                        } else if !value.is_empty() {
                            mx.push(MxPattern::Equals(to_a_label(value)));
                        }
                    },
                    b"max_age" => {
                        if let Ok(value) = value.parse() {
                            max_age = value;
                        }
                    },
                    b"mode" => {
                        mode = match value {
                            "enforce" => Mode::Enforce,
                            "testing" => Mode::Testing,
                            "none" => Mode::None,
                            _ => return Err(format!("Unsupported mode {value:?}.")),
                        };
                    },
                    b"version" => {
                        if !value.eq_ignore_ascii_case("STSv1") {
                            return Err(format!("Unsupported version {value:?}."));
                        }
                    },
                    _ => {}
                );
            } else {
                break;
            }
        }

        if !mx.is_empty() {
            Ok(Policy {
                id,
                mode,
                mx: mx.into_boxed_slice(),
                max_age,
            })
        } else {
            Err("No 'mx' entries found.".to_string())
        }
    }
}

#[cfg(test)]
mod test {
    use super::ParsePolicy;
    use crate::outbound::mta_sts::verify::VerifyPolicy;
    use common::config::smtp::resolver::Policy;

    #[test]
    fn mx_patterns_are_a_labels() {
        let policy = Policy::parse(
            concat!(
                "version: STSv1\n",
                "mode: enforce\n",
                "mx: *.\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}\n",
                "mx: MAIL.\u{5de}\u{5d9}\u{5d9}\u{5dc}.\u{5e7}\u{5d5}\u{5dd}\n",
                "max_age: 604800\n"
            ),
            "test".to_string(),
        )
        .unwrap();

        assert!(policy.verify("mx.xn--eebajf.xn--9dbq2a"));
        assert!(policy.verify("mail.xn--eebajf.xn--9dbq2a"));
        assert!(!policy.verify("mx.example.org"));
    }
}
