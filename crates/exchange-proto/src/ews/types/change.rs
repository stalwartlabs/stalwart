/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    folder::Folder,
    ids::{BaseFolderId, BaseItemId},
    item::Item,
    path::Path,
};
use crate::ews::{
    parser::{ParseErrorKind, Parser, Result},
    schema::UnindexedField,
};

#[derive(Debug, Clone, PartialEq)]
pub enum ItemChange<'a> {
    Set { path: Path<'a>, value: Item<'a> },
    Append { path: Path<'a>, value: Item<'a> },
    Delete(Path<'a>),
}

impl UnindexedField {
    pub fn is_unstored_groupware_field(self) -> bool {
        matches!(
            self,
            UnindexedField::ItemReminderIsSet
                | UnindexedField::ItemReminderMinutesBeforeStart
                | UnindexedField::ItemReminderDueBy
                | UnindexedField::ItemInReplyTo
                | UnindexedField::ItemCulture
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ItemUpdate<'a> {
    pub id: BaseItemId<'a>,
    pub changes: Vec<ItemChange<'a>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FolderChange<'a> {
    Set { path: Path<'a>, value: Folder<'a> },
    Append { path: Path<'a>, value: Folder<'a> },
    Delete(Path<'a>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FolderUpdate<'a> {
    pub id: BaseFolderId<'a>,
    pub changes: Vec<FolderChange<'a>>,
}

#[derive(Clone, Copy)]
enum ChangeKind {
    Set,
    Append,
    Delete,
}

macro_rules! change_parser {
    ($update:ident, $change:ident, $id:ident, $value:ident, $element:literal,
     $set:literal, $append:literal, $delete:literal $(, skip $skip:literal)?) => {
        impl<'a> $update<'a> {
            pub fn parse_list(p: &mut Parser<'a>) -> Result<Vec<Self>> {
                let mut list = Vec::new();
                while let Some(child) = p.child()? {
                    if child.local == $element {
                        p.expect_types(&child)?;
                        list.push(Self::parse(p)?);
                    } else {
                        p.skip()?;
                    }
                }
                Ok(list)
            }

            fn parse(p: &mut Parser<'a>) -> Result<Self> {
                let mut id = None;
                let mut changes = Vec::new();
                while let Some(child) = p.child()? {
                    if let Some(parsed) = $id::parse_child(p, &child)? {
                        id = Some(parsed);
                    } else if child.local == "Updates" {
                        p.expect_types(&child)?;
                        $change::parse_updates(p, &mut changes)?;
                    } $(else if child.local == $skip {
                        p.expect_types(&child)?;
                        p.skip()?;
                    })? else {
                        p.skip()?;
                    }
                }
                let id = id.ok_or_else(|| p.error(ParseErrorKind::MissingElement(stringify!($id))))?;
                if changes.is_empty() {
                    return Err(p.error(ParseErrorKind::MissingElement("Updates")));
                }
                Ok($update { id, changes })
            }
        }

        impl<'a> $change<'a> {
            fn parse_updates(p: &mut Parser<'a>, changes: &mut Vec<Self>) -> Result<()> {
                while let Some(child) = p.child()? {
                    let kind = hashify::fnc_map!(child.local.as_bytes(),
                        $set => { ChangeKind::Set },
                        $append => { ChangeKind::Append },
                        $delete => { ChangeKind::Delete },
                        _ => {
                            p.skip()?;
                            continue;
                        }
                    );
                    p.expect_types(&child)?;
                    changes.push(Self::parse_change(p, kind)?);
                }
                Ok(())
            }

            fn parse_change(p: &mut Parser<'a>, kind: ChangeKind) -> Result<Self> {
                let mut path = None;
                let mut value = None;
                while let Some(child) = p.child()? {
                    if let Some(parsed) = Path::parse_child(p, &child)? {
                        path = Some(parsed);
                    } else if let Some(parsed) = $value::parse_child(p, &child)? {
                        value = Some(parsed);
                    } else {
                        p.skip()?;
                    }
                }
                let path = path.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Path")))?;
                let value = || value.ok_or_else(|| p.error(ParseErrorKind::MissingElement($element)));
                Ok(match kind {
                    ChangeKind::Set => $change::Set { path, value: value()? },
                    ChangeKind::Append => $change::Append { path, value: value()? },
                    ChangeKind::Delete => $change::Delete(path),
                })
            }
        }
    };
}

change_parser!(
    ItemUpdate, ItemChange, BaseItemId, Item, "ItemChange",
    "SetItemField", "AppendToItemField", "DeleteItemField", skip "CalendarActivityData"
);
change_parser!(
    FolderUpdate,
    FolderChange,
    BaseFolderId,
    Folder,
    "FolderChange",
    "SetFolderField",
    "AppendToFolderField",
    "DeleteFolderField"
);
