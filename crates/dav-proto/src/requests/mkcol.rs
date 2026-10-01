/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{DavParser, Token, tokenizer::Tokenizer, value::InheritedLang},
    schema::{Element, NamedElement, Namespace, request::MkCol},
};

impl DavParser for MkCol {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut mkcol = MkCol {
            is_mkcalendar: false,
            props: Vec::new(),
        };
        let request = match stream.token()? {
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Mkcol,
                    },
                raw,
            } => raw,
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Mkcalendar,
                    },
                raw,
            } => {
                mkcol.is_mkcalendar = true;
                raw
            }
            Token::Eof => {
                return Ok(mkcol);
            }
            other => return Err(other.into_unexpected()),
        };

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Set,
                        },
                    raw,
                } => {
                    let prop = stream.expect_named_element_raw(NamedElement::dav(Element::Prop))?;
                    stream.collect_property_values(
                        |value| mkcol.props.push(value),
                        &mut InheritedLang::new(&prop, &raw, &request),
                    )?;
                    stream.expect_element_end()?;
                }
                Token::ElementEnd | Token::Eof => {
                    break;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(mkcol)
    }
}
