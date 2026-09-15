/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{DavParser, Token, tokenizer::Tokenizer},
    schema::{Element, NamedElement, Namespace, request::PropFind},
};

impl DavParser for PropFind {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        if !stream.expect_named_element_or_eof(NamedElement::dav(Element::Propfind))? {
            return Ok(PropFind::AllProp(vec![]));
        }

        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Propname,
                        },
                    ..
                } => return Ok(PropFind::PropName),
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Allprop,
                        },
                    ..
                } => {
                    stream.expect_element_end()?;
                    return PropFind::parse_allprop_include(stream);
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Prop,
                        },
                    ..
                } => return stream.collect_properties(Vec::new()).map(PropFind::Prop),
                Token::ElementStart { .. } | Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                Token::ElementEnd | Token::Eof => return Ok(PropFind::AllProp(vec![])),
                token => return Err(token.into_unexpected()),
            }
        }
    }
}

impl PropFind {
    fn parse_allprop_include(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        loop {
            match stream.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Include,
                        },
                    ..
                } => return stream.collect_properties(Vec::new()).map(PropFind::AllProp),
                Token::ElementStart { .. } | Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                _ => return Ok(PropFind::AllProp(vec![])),
            }
        }
    }
}
