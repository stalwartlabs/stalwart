/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::{EwsValue, T, ews_struct};
use crate::{
    ews::{
        parser::{Parser, Result},
        schema::LegacyFreeBusy,
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

ews_struct! {
    pub struct IndividualConflict {
        busy_type: req "BusyType" => LegacyFreeBusy,
    }
}

ews_struct! {
    pub struct GroupConflict {
        number_of_members: req "NumberOfMembers" => i32,
        number_of_members_available: req "NumberOfMembersAvailable" => i32,
        number_of_members_with_conflict: req "NumberOfMembersWithConflict" => i32,
        number_of_members_with_no_data: req "NumberOfMembersWithNoData" => i32,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AttendeeConflict {
    Unknown,
    TooBigGroup,
    Individual(IndividualConflict),
    Group(GroupConflict),
}

#[derive(Debug, Clone, Copy)]
enum ConflictKind {
    Unknown,
    TooBigGroup,
    Individual,
    Group,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttendeeConflicts(pub Vec<AttendeeConflict>);

impl<'x> EwsValue<'x> for AttendeeConflicts {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            let Some(kind) = hashify::map!(child.local.as_bytes(), ConflictKind,
                "UnknownAttendeeConflictData" => ConflictKind::Unknown,
                "TooBigGroupAttendeeConflictData" => ConflictKind::TooBigGroup,
                "IndividualAttendeeConflictData" => ConflictKind::Individual,
                "GroupAttendeeConflictData" => ConflictKind::Group,
            )
            .copied() else {
                p.skip()?;
                continue;
            };
            p.expect_types(&child)?;
            p.count_id()?;
            list.push(match kind {
                ConflictKind::Unknown => {
                    p.skip_rest()?;
                    AttendeeConflict::Unknown
                }
                ConflictKind::TooBigGroup => {
                    p.skip_rest()?;
                    AttendeeConflict::TooBigGroup
                }
                ConflictKind::Individual => {
                    AttendeeConflict::Individual(IndividualConflict::parse(p, &child.attrs)?)
                }
                ConflictKind::Group => {
                    AttendeeConflict::Group(GroupConflict::parse(p, &child.attrs)?)
                }
            });
        }
        Ok(AttendeeConflicts(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for conflict in &self.0 {
            match conflict {
                AttendeeConflict::Unknown => w.empty_leaf(T, "UnknownAttendeeConflictData"),
                AttendeeConflict::TooBigGroup => w.empty_leaf(T, "TooBigGroupAttendeeConflictData"),
                AttendeeConflict::Individual(data) => {
                    data.write(w, "IndividualAttendeeConflictData")
                }
                AttendeeConflict::Group(data) => data.write(w, "GroupAttendeeConflictData"),
            }
        }
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpDomain<'x> {
    pub name: Cow<'x, str>,
    pub include_subdomains: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmtpDomains<'x>(pub Vec<SmtpDomain<'x>>);

impl<'x> EwsValue<'x> for SmtpDomains<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            if child.local == "Domain" {
                p.expect_types(&child)?;
                p.count_id()?;
                list.push(SmtpDomain {
                    name: p.attr_required(&child.attrs, "Name")?,
                    include_subdomains: p.attr_value(&child.attrs, "IncludeSubdomains")?,
                });
            }
            p.skip()?;
        }
        Ok(SmtpDomains(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for domain in &self.0 {
            w.start(T, "Domain").attr("Name", &domain.name);
            if let Some(include) = domain.include_subdomains {
                w.attr_bool("IncludeSubdomains", include);
            }
            w.empty();
        }
        w.end(T, local);
    }
}
