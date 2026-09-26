/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Depth,
    parser::{DavParser, Token, XmlValueParser, property::TimeRangeFromRaw, tokenizer::Tokenizer},
    schema::{
        Attribute, Element, NamedElement, Namespace,
        property::DavProperty,
        request::{
            AclPrincipalPropSet, AddressbookQuery, CalendarQuery, CardFilter, CompFilter,
            ExpandProperty, ExpandPropertyItem, FreeBusyQuery, MultiGet, PrincipalMatch,
            PrincipalPropertySearch, PropFind, Report, SyncCollection, Timezone,
        },
    },
};
use types::{TimeRange, dead_property::DeadElementTag};

impl DavParser for Report {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let (name, principal_search_test) = match stream.token()? {
            Token::ElementStart { name, raw } => (name, raw.principal_search_test()?),
            token => return Err(token.into_unexpected()),
        };
        match name {
            NamedElement {
                ns: Namespace::CalDav,
                element: Element::CalendarQuery,
            } => CalendarQuery::parse(stream).map(Report::CalendarQuery),
            NamedElement {
                ns: Namespace::CalDav,
                element: Element::FreeBusyQuery,
            } => FreeBusyQuery::parse(stream).map(Report::FreeBusyQuery),
            NamedElement {
                ns: Namespace::CalDav,
                element: Element::CalendarMultiget,
            } => MultiGet::parse(stream).map(Report::CalendarMultiGet),
            NamedElement {
                ns: Namespace::CardDav,
                element: Element::AddressbookQuery,
            } => AddressbookQuery::parse(stream).map(Report::AddressbookQuery),
            NamedElement {
                ns: Namespace::CardDav,
                element: Element::AddressbookMultiget,
            } => MultiGet::parse(stream).map(Report::AddressbookMultiGet),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::SyncCollection,
            } => SyncCollection::parse(stream).map(Report::SyncCollection),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::AclPrincipalPropSet,
            } => AclPrincipalPropSet::parse(stream).map(Report::AclPrincipalPropSet),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::PrincipalMatch,
            } => PrincipalMatch::parse(stream).map(Report::PrincipalMatch),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::PrincipalPropertySearch,
            } => PrincipalPropertySearch::parse(stream).map(|mut search| {
                search.test = principal_search_test;
                Report::PrincipalPropertySearch(search)
            }),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::PrincipalSearchPropertySet,
            } => stream
                .expect_element_end()
                .map(|_| Report::PrincipalSearchPropertySet),
            NamedElement {
                ns: Namespace::Dav,
                element: Element::ExpandProperty,
            } => ExpandProperty::parse(stream).map(Report::ExpandProperty),
            other => Err(other.into_unexpected()),
        }
    }
}

impl DavParser for CalendarQuery {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut cq = CalendarQuery {
            properties: PropFind::AllProp(vec![]),
            filter: None,
            timezone: Timezone::None,
        };

        loop {
            match stream.token()? {
                Token::ElementStart { name, .. } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Propname,
                    } => {
                        cq.properties = PropFind::PropName;
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Allprop,
                    } => {
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } => {
                        cq.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Filter,
                    } if cq.filter.is_none() => {
                        cq.filter = CompFilter::parse_filter(stream)?;
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::Timezone,
                    } => {
                        cq.timezone =
                            Timezone::Name(stream.collect_string_value()?.unwrap_or_default());
                    }
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::TimezoneId,
                    } => {
                        cq.timezone =
                            Timezone::Id(stream.collect_string_value()?.unwrap_or_default());
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(cq)
    }
}

impl DavParser for AddressbookQuery {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut aq = AddressbookQuery {
            properties: PropFind::AllProp(vec![]),
            filter: CardFilter::default(),
            limit: None,
        };
        let mut has_filter = false;

        loop {
            match stream.token()? {
                Token::ElementStart { name, raw } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Propname,
                    } => {
                        aq.properties = PropFind::PropName;
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Allprop,
                    } => {
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } => {
                        aq.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Filter,
                    } if !has_filter => {
                        let test = raw.filter_test()?;
                        aq.filter = CardFilter::parse_filter(test, stream)?;
                        has_filter = true;
                    }
                    NamedElement {
                        ns: Namespace::CardDav,
                        element: Element::Limit,
                    } => {
                        stream.expect_named_element(NamedElement::carddav(Element::Nresults))?;
                        if let Some(Ok(limit)) = stream.parse_value::<u32>()? {
                            aq.limit = limit.into();
                        }
                        stream.expect_element_end()?;
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(aq)
    }
}

impl DavParser for FreeBusyQuery {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        match stream.token()? {
            Token::ElementStart {
                name:
                    NamedElement {
                        ns: Namespace::CalDav,
                        element: Element::TimeRange,
                    },
                raw,
            } => TimeRange::from_raw(&raw).map(|range| FreeBusyQuery { range }),
            other => Err(other.into_unexpected()),
        }
    }
}

impl DavParser for MultiGet {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut mg = MultiGet {
            properties: PropFind::AllProp(vec![]),
            hrefs: vec![],
        };

        loop {
            match stream.token()? {
                Token::ElementStart { name, .. } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Propname,
                    } => {
                        mg.properties = PropFind::PropName;
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Allprop,
                    } => {
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } => {
                        mg.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Href,
                    } => {
                        if let Some(href) = stream.collect_string_value()? {
                            mg.hrefs.push(href);
                        }
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    break;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(mg)
    }
}

impl DavParser for SyncCollection {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut sc = SyncCollection {
            properties: PropFind::AllProp(vec![]),
            limit: None,
            sync_token: None,
            depth: Depth::None,
        };

        loop {
            match stream.token()? {
                Token::ElementStart { name, .. } => match name {
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Prop,
                    } => {
                        sc.properties = PropFind::Prop(stream.collect_properties(Vec::new())?);
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::Limit,
                    } => {
                        stream.expect_named_element(NamedElement::dav(Element::Nresults))?;
                        if let Some(Ok(limit)) = stream.parse_value::<u32>()? {
                            sc.limit = limit.into();
                        }
                        stream.expect_element_end()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::SyncToken,
                    } => {
                        sc.sync_token = stream.collect_string_value()?;
                    }
                    NamedElement {
                        ns: Namespace::Dav,
                        element: Element::SyncLevel,
                    } => {
                        if let Some(Ok(depth)) = stream.parse_value::<Depth>()? {
                            sc.depth = depth;
                        }
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(sc)
    }
}

impl DavParser for ExpandProperty {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut ep = ExpandProperty { properties: vec![] };
        let mut depth = 1;

        loop {
            match stream.token()? {
                Token::ElementStart { name, raw } => match name {
                    NamedElement {
                        ns,
                        element: Element::Property,
                    } => {
                        for attribute in raw.attributes::<String>() {
                            if let Attribute::Name(name) = attribute? {
                                if let Some(property) = Element::try_parse(name.as_bytes())
                                    .copied()
                                    .and_then(|element| {
                                        DavProperty::from_element(NamedElement { ns, element })
                                    })
                                {
                                    ep.properties.push(ExpandPropertyItem {
                                        property,
                                        depth: depth - 1,
                                    });
                                } else {
                                    let attrs = raw.element.attributes_raw().trim_ascii();
                                    ep.properties.push(ExpandPropertyItem {
                                        property: DavProperty::DeadProperty(DeadElementTag {
                                            name,
                                            attrs: (!attrs.is_empty()).then(|| {
                                                String::from_utf8_lossy(attrs).into_owned()
                                            }),
                                        }),
                                        depth: depth - 1,
                                    });
                                }
                                break;
                            }
                        }
                        depth += 1;
                    }
                    name => return Err(name.into_unexpected()),
                },
                Token::ElementEnd => {
                    depth -= 1;

                    if depth == 0 {
                        break;
                    }
                }
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                element => return Err(element.into_unexpected()),
            }
        }

        Ok(ep)
    }
}

impl XmlValueParser for Depth {
    fn parse_bytes(bytes: &[u8]) -> Option<Self> {
        Depth::parse(bytes)
    }

    fn parse_str(text: &str) -> Option<Self> {
        Depth::parse(text.as_bytes())
    }
}
