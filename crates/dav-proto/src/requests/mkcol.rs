/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{DavParser, Token, tokenizer::Tokenizer},
    schema::{Element, NamedElement, Namespace, request::MkCol},
};

impl DavParser for MkCol {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut mkcol = MkCol {
            is_mkcalendar: false,
            props: Vec::new(),
        };
        let mkcol_lang = match stream.token()? {
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Mkcol,
                    },
                raw,
            } => raw.xml_lang()?,
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Mkcalendar,
                    },
                raw,
            } => {
                mkcol.is_mkcalendar = true;
                raw.xml_lang()?
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
                    let set_lang = raw.xml_lang()?;
                    let prop_lang = stream
                        .expect_named_element_raw(NamedElement::dav(Element::Prop))?
                        .xml_lang()?;
                    let lang = prop_lang
                        .as_deref()
                        .or(set_lang.as_deref())
                        .or(mkcol_lang.as_deref());
                    stream.collect_property_values(&mut mkcol.props, lang)?;
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
