/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::uidbatches,
    receiver::{Request, bad},
};
use compact_str::ToCompactString;

use super::parse_number;

impl Request<Command> {
    pub fn parse_uidbatches(self) -> trc::Result<uidbatches::Arguments> {
        let mut tokens = self.tokens.into_iter();
        let batch_size = parse_number::<u32>(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.to_compact_string(), "Missing batch size."))?
                .unwrap_bytes(),
        )
        .map_err(|v| bad(self.tag.to_compact_string(), v))?;

        if batch_size == 0 {
            return Err(bad(
                self.tag.to_compact_string(),
                "Batch size cannot be zero.",
            ));
        }

        let batch_range = match tokens.next() {
            Some(token) => {
                let token = token
                    .unwrap_string()
                    .map_err(|v| bad(self.tag.to_compact_string(), v))?;
                let (from, to) = token.split_once(':').ok_or_else(|| {
                    bad(
                        self.tag.to_compact_string(),
                        "Expected a batch range in the form 'from:to'.",
                    )
                })?;
                let from = parse_number::<u32>(from.trim().as_bytes())
                    .map_err(|v| bad(self.tag.to_compact_string(), v))?;
                let to = parse_number::<u32>(to.trim().as_bytes())
                    .map_err(|v| bad(self.tag.to_compact_string(), v))?;

                if from == 0 || to == 0 {
                    return Err(bad(
                        self.tag.to_compact_string(),
                        "Batch numbers start at one.",
                    ));
                }

                Some((from, to))
            }
            None => None,
        };

        if tokens.next().is_some() {
            return Err(bad(
                self.tag.to_compact_string(),
                "Too many arguments for UIDBATCHES.",
            ));
        }

        Ok(uidbatches::Arguments {
            tag: self.tag,
            batch_size,
            batch_range,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{protocol::uidbatches, receiver::Receiver};

    #[test]
    fn parse_uidbatches() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A143 UIDBATCHES 2000\r\n",
                uidbatches::Arguments {
                    tag: "A143".into(),
                    batch_size: 2000,
                    batch_range: None,
                },
            ),
            (
                "A302 UIDBATCHES 2000 10:20\r\n",
                uidbatches::Arguments {
                    tag: "A302".into(),
                    batch_size: 2000,
                    batch_range: Some((10, 20)),
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_uidbatches()
                    .unwrap(),
                arguments,
                "Failed to parse {command}"
            );
        }

        for command in [
            "A1 UIDBATCHES\r\n",
            "A2 UIDBATCHES abc\r\n",
            "A3 UIDBATCHES 2000 10\r\n",
            "A4 UIDBATCHES 0\r\n",
            "A5 UIDBATCHES 2000 0:20\r\n",
            "A6 UIDBATCHES 2000 1:2 junk\r\n",
        ] {
            assert!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_uidbatches()
                    .is_err(),
                "Expected an error for {command}"
            );
        }
    }
}
