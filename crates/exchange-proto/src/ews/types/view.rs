/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{path::Path, restriction::Restriction};
use crate::{
    common::XsDateTime,
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        schema::{Aggregate, IndexBasePoint, SortDirection, StandardGroupBy},
    },
    xml::Attrs,
};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedView {
    pub max_entries: Option<u32>,
    pub offset: i32,
    pub base_point: IndexBasePoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FractionalView {
    pub max_entries: Option<u32>,
    pub numerator: i32,
    pub denominator: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemView<'a> {
    Indexed(IndexedView),
    Fractional(FractionalView),
    SeekToCondition {
        max_entries: Option<u32>,
        base_point: IndexBasePoint,
        condition: Restriction<'a>,
    },
    Calendar {
        max_entries: Option<u32>,
        start: XsDateTime,
        end: XsDateTime,
    },
    Contacts {
        max_entries: Option<u32>,
        initial_name: Option<Cow<'a, str>>,
        final_name: Option<Cow<'a, str>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderView {
    Indexed(IndexedView),
    Fractional(FractionalView),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldOrder<'a> {
    pub path: Path<'a>,
    pub order: SortDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateOn<'a> {
    pub aggregate: Aggregate,
    pub path: Path<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupBy<'a> {
    Field {
        order: SortDirection,
        path: Path<'a>,
        aggregate: AggregateOn<'a>,
        use_collapsible_groups: Option<bool>,
        items_per_group: Option<u32>,
        max_items_per_group: Option<u32>,
    },
    Distinguished {
        order: SortDirection,
        standard: StandardGroupBy,
    },
}

#[derive(Clone, Copy)]
enum ViewKind {
    Indexed,
    Fractional,
    Seek,
    Calendar,
    Contacts,
}

fn max_entries<'a>(p: &Parser<'a>, attrs: &Attrs<'a>) -> Result<Option<u32>> {
    p.attr_value(attrs, "MaxEntriesReturned")
}

fn base_point<'a>(p: &Parser<'a>, attrs: &Attrs<'a>) -> Result<IndexBasePoint> {
    Ok(p.attr_enum(attrs, "BasePoint", IndexBasePoint::parse)?
        .unwrap_or(IndexBasePoint::Beginning))
}

impl IndexedView {
    pub fn parse<'a>(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        let view = IndexedView {
            max_entries: max_entries(p, attrs)?,
            offset: p.attr_value(attrs, "Offset")?.unwrap_or(0),
            base_point: base_point(p, attrs)?,
        };
        p.skip_rest()?;
        Ok(view)
    }
}

impl FractionalView {
    fn parse<'a>(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        let view = FractionalView {
            max_entries: max_entries(p, attrs)?,
            numerator: p
                .attr_value(attrs, "Numerator")?
                .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("Numerator")))?,
            denominator: p
                .attr_value(attrs, "Denominator")?
                .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("Denominator")))?,
        };
        p.skip_rest()?;
        Ok(view)
    }
}

impl<'a> ItemView<'a> {
    pub fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let Some(kind) = hashify::map!(child.local.as_bytes(), ViewKind,
            "IndexedPageItemView" => ViewKind::Indexed,
            "FractionalPageItemView" => ViewKind::Fractional,
            "SeekToConditionPageItemView" => ViewKind::Seek,
            "CalendarView" => ViewKind::Calendar,
            "ContactsView" => ViewKind::Contacts,
        )
        .copied() else {
            return Ok(None);
        };
        p.expect_messages(child)?;
        let attrs = &child.attrs;
        let view = match kind {
            ViewKind::Indexed => ItemView::Indexed(IndexedView::parse(p, attrs)?),
            ViewKind::Fractional => ItemView::Fractional(FractionalView::parse(p, attrs)?),
            ViewKind::Seek => {
                let max_entries = max_entries(p, attrs)?;
                let base_point = base_point(p, attrs)?;
                let mut condition = None;
                while let Some(child) = p.child()? {
                    if child.local == "Condition" {
                        p.expect_types(&child)?;
                        condition = Some(Restriction::parse(p)?);
                    } else {
                        p.skip()?;
                    }
                }
                ItemView::SeekToCondition {
                    max_entries,
                    base_point,
                    condition: condition
                        .ok_or_else(|| p.error(ParseErrorKind::MissingElement("Condition")))?,
                }
            }
            ViewKind::Calendar => {
                let view = ItemView::Calendar {
                    max_entries: max_entries(p, attrs)?,
                    start: p
                        .attr_value(attrs, "StartDate")?
                        .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("StartDate")))?,
                    end: p
                        .attr_value(attrs, "EndDate")?
                        .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("EndDate")))?,
                };
                p.skip_rest()?;
                view
            }
            ViewKind::Contacts => {
                let view = ItemView::Contacts {
                    max_entries: max_entries(p, attrs)?,
                    initial_name: p.attr(attrs, "InitialName")?,
                    final_name: p.attr(attrs, "FinalName")?,
                };
                p.skip_rest()?;
                view
            }
        };
        Ok(Some(view))
    }
}

impl FolderView {
    pub fn parse_child<'a>(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let view = hashify::fnc_map!(child.local.as_bytes(),
            "IndexedPageFolderView" => {
                p.expect_messages(child)?;
                FolderView::Indexed(IndexedView::parse(p, &child.attrs)?)
            },
            "FractionalPageFolderView" => {
                p.expect_messages(child)?;
                FolderView::Fractional(FractionalView::parse(p, &child.attrs)?)
            },
            _ => {
                return Ok(None);
            }
        );
        Ok(Some(view))
    }
}

fn sort_direction<'a>(p: &Parser<'a>, attrs: &Attrs<'a>) -> Result<SortDirection> {
    Ok(p.attr_enum(attrs, "Order", SortDirection::parse)?
        .unwrap_or(SortDirection::Ascending))
}

impl<'a> FieldOrder<'a> {
    pub fn parse_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            if child.local != "FieldOrder" {
                p.skip()?;
                continue;
            }
            p.expect_types(&child)?;
            let order = sort_direction(p, &child.attrs)?;
            list.push(FieldOrder {
                path: Path::parse_one(p)?,
                order,
            });
        }
        Ok(list)
    }
}

impl<'a> GroupBy<'a> {
    pub fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let distinguished = hashify::fnc_map!(child.local.as_bytes(),
            "GroupBy" => { false },
            "DistinguishedGroupBy" => { true },
            _ => {
                return Ok(None);
            }
        );
        p.expect_messages(child)?;
        let order = sort_direction(p, &child.attrs)?;
        if distinguished {
            let mut standard = None;
            while let Some(child) = p.child()? {
                if child.local == "StandardGroupBy" {
                    p.expect_types(&child)?;
                    standard = Some(p.text_enum("StandardGroupBy", StandardGroupBy::parse)?);
                } else {
                    p.skip()?;
                }
            }
            return Ok(Some(GroupBy::Distinguished {
                order,
                standard: standard
                    .ok_or_else(|| p.error(ParseErrorKind::MissingElement("StandardGroupBy")))?,
            }));
        }

        let mut path = None;
        let mut aggregate = None;
        let mut use_collapsible_groups = None;
        let mut items_per_group = None;
        let mut max_items_per_group = None;
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "AggregateOn" => {
                    p.expect_types(&child)?;
                    let kind = p
                        .attr_enum(&child.attrs, "Aggregate", Aggregate::parse)?
                        .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("Aggregate")))?;
                    aggregate = Some(AggregateOn { aggregate: kind, path: Path::parse_one(p)? });
                },
                "UseCollapsibleGroups" => {
                    p.expect_types(&child)?;
                    use_collapsible_groups = Some(p.value("UseCollapsibleGroups")?);
                },
                "ItemsPerGroup" => {
                    p.expect_types(&child)?;
                    items_per_group = Some(p.value("ItemsPerGroup")?);
                },
                "MaxItemsPerGroup" => {
                    p.expect_types(&child)?;
                    max_items_per_group = Some(p.value("MaxItemsPerGroup")?);
                },
                _ => {
                    match Path::parse_child(p, &child)? {
                        Some(found) => path = Some(found),
                        None => p.skip()?,
                    }
                }
            );
        }
        Ok(Some(GroupBy::Field {
            order,
            path: path.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Path")))?,
            aggregate: aggregate
                .ok_or_else(|| p.error(ParseErrorKind::MissingElement("AggregateOn")))?,
            use_collapsible_groups,
            items_per_group,
            max_items_per_group,
        }))
    }
}
