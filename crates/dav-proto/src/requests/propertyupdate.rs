/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{DavParser, Token, tokenizer::Tokenizer, value::InheritedLang},
    schema::{
        Element, NamedElement, Namespace,
        request::{PropertyUpdate, PropertyUpdateOp},
    },
};

impl DavParser for PropertyUpdate {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let request =
            stream.expect_named_element_raw(NamedElement::dav(Element::Propertyupdate))?;
        let mut update = PropertyUpdate {
            ops: Vec::with_capacity(4),
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
                        |value| update.ops.push(PropertyUpdateOp::Set(value)),
                        &mut InheritedLang::new(&prop, &raw, &request),
                    )?;
                    stream.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::Dav,
                            element: Element::Remove,
                        },
                    ..
                } => {
                    stream.expect_named_element(NamedElement::dav(Element::Prop))?;
                    update.ops.extend(
                        stream
                            .collect_properties(Vec::new())?
                            .into_iter()
                            .map(PropertyUpdateOp::Remove),
                    );
                    stream.expect_element_end()?;
                }
                Token::ElementEnd | Token::Eof => {
                    break;
                }
                Token::UnknownElement(_) => {
                    // Ignore unknown elements
                    stream.seek_element_end()?;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(update)
    }
}
