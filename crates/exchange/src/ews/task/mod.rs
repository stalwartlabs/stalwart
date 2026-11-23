/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod find;
pub mod write;

use super::{
    filter::PropValue,
    groupware::{
        GroupwareFields, GroupwareKind,
        items::{GroupwareItems, LoadedItem},
    },
};
use crate::{
    folders::{ContainerClass, FolderEntry, FolderNode},
    store::{FolderKind, FolderRef},
};
use exchange_proto::{
    convert::model::PropBag,
    ews::{
        task::{TaskFieldSet, TaskProps},
        types::{item::Item, shape::ItemShape},
    },
};
use find::TaskProp;

pub(crate) type Tasks = GroupwareItems<TaskFieldSet>;

impl GroupwareFields for TaskFieldSet {
    const KIND: GroupwareKind = GroupwareKind::Task;
    type Prop = TaskProp;

    fn from_shape(shape: &ItemShape<'_>) -> Self {
        TaskFieldSet::from_shape(shape)
    }

    fn for_list(self) -> Self {
        TaskFieldSet::for_list(self)
    }

    fn needs_content(self) -> bool {
        TaskFieldSet::needs_content(self)
    }

    fn value<'p>(_: &Tasks, _: u32, prop: TaskProp, props: &'p PropBag) -> Option<PropValue<'p>> {
        prop.value(TaskProps::new(props))
    }

    fn render<'c>(self, tasks: &Tasks, loaded: &'c LoadedItem) -> Item<'c> {
        let mut item = match &loaded.content {
            Some(content) => TaskProps::new(&content.props).render(self),
            None => Default::default(),
        };
        if self.has(TaskFieldSet::ID) {
            item.item.item_id = Some(tasks.item_id(loaded.item, loaded.change_id));
        }
        if self.has(TaskFieldSet::PARENT) {
            item.item.parent_folder_id = Some(tasks.parent_id(loaded));
        }
        Item::Task(Box::new(item))
    }
}

pub(crate) fn task_list_of(entry: &FolderEntry) -> Option<u32> {
    match (entry.node, &entry.class) {
        (
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar,
                id,
            }),
            ContainerClass::Task,
        ) => Some(id),
        _ => None,
    }
}
