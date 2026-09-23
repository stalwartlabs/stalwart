/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Command,
    protocol::authenticate::{self, Mechanism},
    receiver::{Request, bad},
};

impl Request<Command> {
    pub fn parse_authenticate(self) -> trc::Result<authenticate::Arguments> {
        if !self.tokens.is_empty() {
            let mut tokens = self.tokens.into_iter();
            Ok(authenticate::Arguments {
                mechanism: Mechanism::parse(&tokens.next().unwrap().unwrap_bytes())
                    .map_err(|v| bad(self.tag.clone(), v))?,
                params: tokens
                    .filter_map(|token| token.unwrap_string().ok())
                    .collect(),
                tag: self.tag,
            })
        } else {
            Err(self.into_error("Authentication mechanism missing."))
        }
    }
}

impl Mechanism {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        hashify::fnc_map_ignore_case!(value,
            "PLAIN" => Some(Self::Plain),
            "CRAM-MD5" => Some(Self::CramMd5),
            "DIGEST-MD5" => Some(Self::DigestMd5),
            "SCRAM-SHA-1" => Some(Self::ScramSha1),
            "SCRAM-SHA-256" => Some(Self::ScramSha256),
            "APOP" => Some(Self::Apop),
            "NTLM" => Some(Self::Ntlm),
            "GSSAPI" => Some(Self::Gssapi),
            "ANONYMOUS" => Some(Self::Anonymous),
            "EXTERNAL" => Some(Self::External),
            "OAUTHBEARER" => Some(Self::OAuthBearer),
            "XOAUTH2" => Some(Self::XOauth2),
            _ => None,
        )
        .ok_or_else(|| {
            format!(
                "Unsupported mechanism '{}'.",
                String::from_utf8_lossy(value)
            )
            .into()
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::authenticate::{self, Mechanism},
        receiver::Receiver,
    };

    #[test]
    fn parse_authenticate() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "a002 AUTHENTICATE \"EXTERNAL\" {16+}\r\nfred@example.com\r\n",
                authenticate::Arguments {
                    tag: "a002".into(),
                    mechanism: Mechanism::External,
                    params: vec!["fred@example.com".into()],
                },
            ),
            (
                "A01 AUTHENTICATE PLAIN\r\n",
                authenticate::Arguments {
                    tag: "A01".into(),
                    mechanism: Mechanism::Plain,
                    params: vec![],
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_authenticate()
                    .unwrap(),
                arguments
            );
        }
    }
}
