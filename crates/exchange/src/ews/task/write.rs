/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::task_list_of;
use crate::{
    ews::{
        context::{EwsCaller, EwsContext},
        folder::{
            FolderSelector, folder_not_found, resolve_folder, saved_folder_status,
            write::{FolderOp, write_status},
        },
        groupware::{items::GroupwareRef, write::CalendarWriter},
        item::ItemError,
    },
    folders::{FolderNode, FolderWrites, SpecialFolder},
    groupware_write::{new_todo, new_uid},
};
use common::Server;
use exchange_proto::{
    convert::ical::{
        Advance, advance_recurring_todo, completed_copy, is_open_recurring_todo, todo_completed_at,
    },
    ews::{
        Status,
        task::{TaskEdit, TaskEditError, TaskFieldSet},
        types::{
            change::ItemChange,
            ids::{ItemId, TargetFolderId},
            item::{Item, ItemFields, TaskItem},
        },
    },
};
use groupware::calendar::write::ItipMode;
use jiff::Timestamp;

pub(crate) type TaskWriter<'x> = CalendarWriter<'x, TaskFieldSet>;

impl CalendarWriter<'_, TaskFieldSet> {
    pub async fn create(
        &mut self,
        task_list: u32,
        item: &TaskItem<'_>,
    ) -> trc::Result<Result<ItemId<'static>, ItemError>> {
        let edit = match TaskEdit::from_item(item) {
            Ok(edit) => edit,
            Err(err) => return Ok(Err(edit_error(err))),
        };
        let uid = new_uid();
        let mut ical = new_todo(&uid, Timestamp::now());
        if let Err(err) = edit.apply(&mut ical, &self.items.options()) {
            return Ok(Err(edit_error(err)));
        }
        Ok(self
            .create_ical(task_list, &uid, ical, ItipMode::Suppress)
            .await?
            .map(|(id, _)| id))
    }

    pub async fn update(
        &mut self,
        task: GroupwareRef,
        expected_change: Option<u64>,
        changes: &[ItemChange<'_>],
    ) -> trc::Result<Result<ItemId<'static>, ItemError>> {
        let mut edit = TaskEdit::default();
        for change in changes {
            if let Err(err) = edit.change(change) {
                return Ok(Err(edit_error(err)));
            }
        }
        let options = self.items.options();
        let mut split = None;
        let committed = self
            .commit_ical(task, expected_change, ItipMode::Suppress, |ical| {
                let recurring = is_open_recurring_todo(ical);
                edit.apply(ical, &options).map_err(edit_error)?;
                split = None;
                if let Some(at) = recurring.then(|| todo_completed_at(ical)).flatten() {
                    let uid = new_uid();
                    let copy = completed_copy(ical, at, &uid);
                    if let Advance::Next(_) = advance_recurring_todo(ical, at) {
                        if !self.may_create(task.container, &copy) {
                            return Err(ItemError::AccessDenied);
                        }
                        split = Some((uid, copy));
                    }
                }
                Ok(())
            })
            .await?;
        if let Err(err) = committed {
            return Ok(Err(err));
        }
        match split {
            Some((uid, copy)) => Ok(self
                .create_ical(task.container, &uid, copy, ItipMode::Suppress)
                .await?
                .map(|(id, _)| id)),
            None => {
                let change_id = self.current_change(task).await?;
                Ok(Ok(self.items.item_id(task, change_id)))
            }
        }
    }
}

pub(crate) async fn task_destination(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    id: Option<&TargetFolderId<'_>>,
) -> trc::Result<Result<u32, Status<'static>>> {
    let tree = ctx.folder_tree(server).await?;
    let entry = match id {
        Some(id) => match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => return Ok(Err(saved_folder_status(ctx, status))),
        },
        None => match tree.special(SpecialFolder::Tasks) {
            Some(entry) => entry,
            None => return Ok(Err(folder_not_found())),
        },
    };
    if entry.node != FolderNode::Special(SpecialFolder::Tasks) {
        return Ok(task_list_of(entry).ok_or_else(|| ItemError::TaskFolder.status()));
    }
    virtual_task_list(server, ctx, caller).await
}

pub(crate) async fn virtual_task_list(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
) -> trc::Result<Result<u32, Status<'static>>> {
    Ok(
        match server
            .folder_task_list(caller.access_token, ctx.account.account_id)
            .await?
        {
            Ok(folder) => {
                ctx.folders_changed();
                Ok(folder.id)
            }
            Err(err) => Err(write_status(err, FolderOp::Place)),
        },
    )
}

pub(crate) fn task_id_only(id: ItemId<'static>) -> Item<'static> {
    Item::Task(Box::new(TaskItem {
        item: ItemFields {
            item_id: Some(id),
            ..Default::default()
        },
        ..Default::default()
    }))
}

fn edit_error(err: TaskEditError) -> ItemError {
    match err {
        TaskEditError::NotATask | TaskEditError::InvalidPropertySet => {
            ItemError::InvalidPropertySet
        }
        TaskEditError::InvalidPropertyAppend => ItemError::InvalidPropertyAppend,
        TaskEditError::InvalidRecurrence => ItemError::InvalidRecurrence,
        TaskEditError::NoOccurrence => ItemError::NoOccurrence,
        TaskEditError::UnsupportedRecurrence => ItemError::UnsupportedRecurrence,
        TaskEditError::Conversion => ItemError::ItemSave,
    }
}
