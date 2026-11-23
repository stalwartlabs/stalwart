/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem, MailWrite,
    attach::rewrite_draft,
    content::{ChangeKind, ContentEdit, DraftEdit},
    create::{SentFolder, carried_property},
    edit::{CarriedEdit, EditRound, Edited, commit_edits, write_carried},
    id_only,
    props::{ItemProp, is_carried, is_ignored_tag},
    writable_mail,
};
use crate::{
    eas::convert::flag::{
        FLAG_FOLLOW_UP, FLAG_STATUS_ACTIVE, FLAG_STATUS_COMPLETE, FlagKeys, LastVerb,
    },
    ews::{
        calendar::{
            Events,
            instance::EventTarget,
            write::{EventScope, event_id_only, update_send},
        },
        contact::{Contacts, write::ContactWriter},
        context::{EwsCaller, EwsContext},
        groupware::{
            GroupwareKind,
            items::{GroupwareRef, decode_item},
            write::CalendarWriter,
        },
        reply::{RESPONSE_CAPACITY, ews_response},
        task::{
            Tasks,
            write::{TaskWriter, task_id_only},
        },
    },
    mail::{AccountCategories, CategoryOutcome, FlagEdit, FlagOutcome},
    mapi::emsmdb::message::object_row::encode_key,
};
use ahash::AHashSet;
use common::{Server, config::mailstore::limits::EmailLimits};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    common::time::UtcSeconds,
    eas::{commands::appdata::email::EmailFlag, types::EasDateTime},
    ews::{
        MessageResult, Operation, Status,
        requests::item::UpdateItem,
        responses::item::UpdateItemMessage,
        schema::{ConflictResolution, FlagStatus, MessageDisposition, UnindexedField},
        types::{
            change::ItemChange,
            common::Flag,
            ids::BaseItemId,
            item::Item,
            path::Path,
            value::DateTime,
            xprop::{ExtendedFieldUri, ExtendedProperty, XPropValue},
        },
    },
    ids::ews::EwsChangeKey,
    mapi::prop::OwnedPropValue,
};
use http_proto::HttpResponse;
use smallvec::SmallVec;
use std::{borrow::Cow, slice};
use store::{roaring::RoaringBitmap, write::now};
use types::collection::Collection;

pub(super) const VERB_REPLY_TO_SENDER: i64 = 102;
pub(super) const VERB_REPLY_TO_ALL: i64 = 103;
pub(super) const VERB_FORWARD: i64 = 104;
pub(super) const FLAG_STATUS_FLAGGED: i64 = 2;
pub(super) const FLAG_STATUS_COMPLETED: i64 = 1;
const SECONDS_PER_MINUTE: i64 = 60;

pub(super) type CategoryNames<'x> = SmallVec<[&'x str; 8]>;

#[derive(Debug, Default)]
pub(crate) enum CategoryEdit<'x> {
    #[default]
    Keep,
    Replace(CategoryNames<'x>),
    Append(CategoryNames<'x>),
}

struct FlagPlan {
    item: MailItem,
    flags: FlagEdit,
    expected_change: Option<u64>,
    carried: Vec<CarriedEdit>,
}

struct GroupwarePlan<'x> {
    account: u32,
    target: GroupwareRef,
    expected_change: Option<u64>,
    changes: &'x [ItemChange<'x>],
}

enum Planned<'x> {
    Flags(FlagPlan, CategoryEdit<'x>),
    Draft(MailItem, DraftEdit<'x>, CategoryEdit<'x>),
    Contact(GroupwarePlan<'x>),
    Task(GroupwarePlan<'x>),
    Event(GroupwarePlan<'x>, EventScope),
    Failed(ItemError),
}

pub(crate) async fn update_item(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UpdateItem<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let save_only = request
        .message_disposition
        .is_none_or(|disposition| disposition == MessageDisposition::SaveOnly);
    let never_overwrite = request.conflict_resolution == ConflictResolution::NeverOverwrite;
    let limits = &server.core.email.limits;
    let max_object_size = server.core.exchange.max_object_size;
    let ids = EmailIds::load(server, ctx).await?;
    let mut seen = RoaringBitmap::new();
    let mut seen_contacts = RoaringBitmap::new();
    let mut seen_tasks = RoaringBitmap::new();
    let mut seen_events = AHashSet::new();
    let planned = request
        .item_changes
        .iter()
        .map(|update| {
            let groupware = match EventTarget::decode(&update.id) {
                Some(EventTarget::Master(account, event)) => {
                    Some((GroupwareKind::Event, account, event, EventScope::Master))
                }
                Some(EventTarget::Instance(account, event, instance)) => Some((
                    GroupwareKind::Event,
                    account,
                    event,
                    EventScope::Instance(instance),
                )),
                Some(EventTarget::Indexed(account, event, index)) => Some((
                    GroupwareKind::Event,
                    account,
                    event,
                    EventScope::Indexed(index),
                )),
                None => decode_item(&update.id)
                    .map(|(kind, account, target)| (kind, account, target, EventScope::Master)),
            };
            if let Some((kind, account, target, scope)) = groupware {
                let first = match kind {
                    GroupwareKind::Contact => seen_contacts.insert(target.document_id),
                    GroupwareKind::Task => seen_tasks.insert(target.document_id),
                    GroupwareKind::Event => seen_events.insert((target.document_id, scope)),
                };
                if !first {
                    return Planned::Failed(ItemError::Duplicate);
                }
                let plan = GroupwarePlan {
                    account,
                    target,
                    expected_change: never_overwrite
                        .then(|| expected_change(&update.id))
                        .flatten(),
                    changes: &update.changes,
                };
                return match kind {
                    GroupwareKind::Contact => Planned::Contact(plan),
                    GroupwareKind::Task => Planned::Task(plan),
                    GroupwareKind::Event => Planned::Event(plan, scope),
                };
            }
            let item = match ids.decode(ctx, &update.id) {
                Ok(item) => item,
                Err(err) => return Planned::Failed(err),
            };
            let (flags, categories, content, mut carried) = match item_edit(&update.changes) {
                Ok(_) if !save_only => return Planned::Failed(ItemError::Unsupported),
                Ok(edit) => edit,
                Err(err) => return Planned::Failed(err),
            };
            if carried.iter().all(|edit| edit.value.is_none())
                && !ids
                    .exchange()
                    .has_object(Collection::Email, item.document_id)
            {
                carried.clear();
            }
            if !seen.insert(item.document_id) {
                return Planned::Failed(ItemError::Duplicate);
            }
            if carried.iter().any(|edit| {
                edit.key.len() + edit.value.as_ref().map_or(0, Vec::len) > max_object_size
            }) {
                return Planned::Failed(ItemError::TooLarge);
            }
            let expected_change = never_overwrite
                .then(|| expected_change(&update.id))
                .flatten();
            match (content.is_empty(), categories) {
                (true, categories) => Planned::Flags(
                    FlagPlan {
                        item,
                        flags,
                        expected_change,
                        carried,
                    },
                    categories,
                ),
                (false, categories) => Planned::Draft(
                    item,
                    DraftEdit {
                        content,
                        flags,
                        expected_change,
                        carried,
                    },
                    categories,
                ),
            }
        })
        .collect::<Vec<_>>();

    let categories = AccountCategories::new(ids.exchange());
    let committed = if planned
        .iter()
        .any(|entry| matches!(entry, Planned::Flags(..)))
    {
        Some(
            commit_edits(
                server,
                caller,
                account_id,
                &planned,
                |round, entry| match entry {
                    Planned::Flags(plan, edit) => {
                        plan_flags(round, ctx, limits, categories, plan, edit)
                    }
                    Planned::Draft(..)
                    | Planned::Contact(_)
                    | Planned::Task(_)
                    | Planned::Event(..)
                    | Planned::Failed(_) => Ok(Ok(Edited::Done)),
                },
            )
            .await?,
        )
    } else {
        None
    };

    let contacts = if planned
        .iter()
        .any(|entry| matches!(entry, Planned::Contact(_)))
    {
        Some(Contacts::load(server, ctx).await?)
    } else {
        None
    };
    let contact_writer = match &contacts {
        Some(Ok(contacts)) => Some((contacts, ContactWriter::new(server, caller, contacts))),
        _ => None,
    };
    let tasks = if planned
        .iter()
        .any(|entry| matches!(entry, Planned::Task(_)))
    {
        Some(Tasks::load(server, ctx).await?)
    } else {
        None
    };
    let mut task_writer = match &tasks {
        Some(Ok(tasks)) => Some((tasks, TaskWriter::new(server, caller, tasks))),
        _ => None,
    };
    let events = if planned
        .iter()
        .any(|entry| matches!(entry, Planned::Event(..)))
    {
        Some(Events::load(server, ctx).await?)
    } else {
        None
    };
    let event_writer = match &events {
        Some(Ok(events)) => Some((events, CalendarWriter::new(server, caller, events))),
        _ => None,
    };
    let send = update_send(request.send_meeting_invitations_or_cancellations);

    let flag_outcomes = committed
        .as_ref()
        .map_or(&[][..], |committed| committed.outcomes.as_slice());
    let mut results = Vec::with_capacity(planned.len());
    let mut sent = SentFolder::new(None);
    for (position, entry) in planned.iter().enumerate() {
        results.push(match entry {
            Planned::Flags(plan, _) => match (&committed, flag_outcomes.get(position)) {
                (Some(committed), Some(outcome)) => {
                    match outcome.map(|edited| committed.change_id_of(edited)) {
                        Ok(placed) if !plan.carried.is_empty() => {
                            let expected = placed
                                .filter(|_| never_overwrite)
                                .map(|(_, change_id)| change_id);
                            match write_carried(
                                server,
                                caller,
                                account_id,
                                plan.item,
                                expected,
                                &plan.carried,
                            )
                            .await?
                            {
                                Ok(Some(change_id)) => {
                                    Ok(Some(id_only(ids.item_id(plan.item, change_id))))
                                }
                                Ok(None) => Ok(placed.map(|(item, change_id)| {
                                    id_only(ids.item_id(item, change_id))
                                })),
                                Err(err) => Err(err),
                            }
                        }
                        placed => placed.map(|placed| {
                            placed.map(|(item, change_id)| id_only(ids.item_id(item, change_id)))
                        }),
                    }
                }
                _ => Err(ItemError::Conflict),
            },
            Planned::Draft(item, edit, category_edit) => {
                match rewrite_draft(server, ctx, caller, *item, &[], &[], edit).await? {
                    Ok(rewritten) if matches!(category_edit, CategoryEdit::Keep) => {
                        Ok(Some(id_only(rewritten.root_id(&ids))))
                    }
                    Ok(rewritten) => {
                        let plan = FlagPlan {
                            item: rewritten.item(),
                            flags: FlagEdit::default(),
                            expected_change: None,
                            carried: Vec::new(),
                        };
                        let committed = commit_edits(
                            server,
                            caller,
                            account_id,
                            slice::from_ref(&plan),
                            |round, plan| {
                                plan_flags(round, ctx, limits, categories, plan, category_edit)
                            },
                        )
                        .await?;
                        match committed.outcomes.first().copied() {
                            Some(Ok(edited)) => Ok(Some(id_only(
                                match committed.change_id_of(edited) {
                                    Some((_, change_id)) => rewritten.with_change_id(change_id),
                                    None => rewritten,
                                }
                                .root_id(&ids),
                            ))),
                            Some(Err(err)) => Err(err),
                            None => Err(ItemError::Conflict),
                        }
                    }
                    Err(ItemError::NotADraft) => Err(ItemError::ContentNotDraft),
                    Err(err) => Err(err),
                }
            }
            Planned::Contact(plan) => match (&contacts, &contact_writer) {
                (Some(Err(err)), _) => Err(*err),
                (_, Some((contacts, writer))) => match contacts.check(plan.account, plan.target) {
                    Ok(contact) => writer
                        .update(contact, plan.expected_change, plan.changes)
                        .await?
                        .map(Some),
                    Err(err) => Err(err),
                },
                _ => Err(ItemError::NotFound),
            },
            Planned::Task(plan) => match (&tasks, &mut task_writer) {
                (Some(Err(err)), _) => Err(*err),
                (_, Some((tasks, writer))) => match tasks.check(plan.account, plan.target) {
                    Ok(task) => writer
                        .update(task, plan.expected_change, plan.changes)
                        .await?
                        .map(|id| Some(task_id_only(id))),
                    Err(err) => Err(err),
                },
                _ => Err(ItemError::NotFound),
            },
            Planned::Event(plan, scope) => match (&events, &event_writer, send) {
                (_, _, Err(err)) => Err(err),
                (Some(Err(err)), _, _) => Err(*err),
                (_, Some((events, writer)), Ok(send)) => {
                    match events.check(plan.account, plan.target) {
                        Ok(event) => match writer
                            .update(event, *scope, plan.expected_change, plan.changes, send)
                            .await?
                        {
                            Ok((id, copies)) => {
                                sent.save(server, ctx, caller, copies).await;
                                Ok(Some(event_id_only(id)))
                            }
                            Err(err) => Err(err),
                        },
                        Err(err) => Err(err),
                    }
                }
                _ => Err(ItemError::NotFound),
            },
            Planned::Failed(err) => Err(*err),
        });
    }

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::UpdateItem);
    for result in results {
        match result {
            Ok(id) => messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(UpdateItemMessage {
                    items: id.into_iter().collect(),
                    conflict_count: Some(0),
                }),
            }),
            Err(err) => messages.message(&MessageResult::<UpdateItemMessage> {
                status: err.status(),
                body: None,
            }),
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

fn plan_flags(
    round: &mut EditRound<'_>,
    ctx: &EwsContext,
    limits: &EmailLimits,
    categories: AccountCategories<'_>,
    plan: &FlagPlan,
    edit: &CategoryEdit<'_>,
) -> trc::Result<Result<Edited, ItemError>> {
    let write = if plan.carried.is_empty()
        && matches!(edit, CategoryEdit::Keep)
        && plan.flags
            == (FlagEdit {
                read: plan.flags.read,
                ..Default::default()
            }) {
        MailWrite::ReadState
    } else {
        MailWrite::Edit
    };
    let item = match writable_mail(ctx, round.cache, plan.item, write) {
        Ok(item) => item,
        Err(err) => return Ok(Err(err)),
    };
    let Some(data) = round
        .cache
        .message_data(item.document_id)
        .filter(|data| data.has_mailbox_id(item.mailbox_id))
    else {
        return Ok(Err(ItemError::NotFound));
    };
    let stale = plan
        .expected_change
        .is_some_and(|change_id| change_id != data.change_id);
    if stale && !round.planned_before(item.document_id) {
        return Ok(Err(ItemError::Stale));
    }
    let current;
    let merged;
    let names: &[&str] = match edit {
        CategoryEdit::Replace(names) => names,
        CategoryEdit::Append(added) => {
            current = categories
                .resolve(&data.keywords_extra)
                .collect::<SmallVec<[_; 8]>>();
            merged = current
                .iter()
                .map(AsRef::as_ref)
                .chain(added.iter().copied())
                .collect::<CategoryNames<'_>>();
            &merged
        }
        CategoryEdit::Keep => {
            if stale && plan.flags.diff(data.keywords) != (0, 0) {
                return Ok(Err(ItemError::Stale));
            }
            if let Err(err) = round.claim(item.document_id) {
                return Ok(Err(err));
            }
            return Ok(
                match round
                    .edits
                    .set_flags(limits, item.document_id, &data, plan.flags)?
                {
                    FlagOutcome::Changed => Ok(Edited::Written(item)),
                    FlagOutcome::Unchanged => Ok(Edited::Unchanged(item, data.change_id)),
                    FlagOutcome::KeywordLimit => Err(ItemError::KeywordLimit),
                },
            );
        }
    };
    if stale
        && !matches!(
            round.scratch_edits().set_categories(
                limits,
                item.document_id,
                &data,
                plan.flags,
                names,
                categories,
            )?,
            CategoryOutcome::Unchanged | CategoryOutcome::Renamed
        )
    {
        return Ok(Err(ItemError::Stale));
    }
    if let Err(err) = round.claim(item.document_id) {
        return Ok(Err(err));
    }
    Ok(
        match round.edits.set_categories(
            limits,
            item.document_id,
            &data,
            plan.flags,
            names,
            categories,
        )? {
            CategoryOutcome::Changed => Ok(Edited::Written(item)),
            CategoryOutcome::Renamed | CategoryOutcome::Unchanged => {
                Ok(Edited::Unchanged(item, data.change_id))
            }
            CategoryOutcome::KeywordLimit => Err(ItemError::KeywordLimit),
            CategoryOutcome::InvalidName => Err(ItemError::CategoryInvalid),
        },
    )
}

impl<'x> CategoryEdit<'x> {
    fn apply(&mut self, kind: ChangeKind, names: CategoryNames<'x>) {
        match (kind, self) {
            (
                ChangeKind::Append,
                CategoryEdit::Replace(current) | CategoryEdit::Append(current),
            ) => current.extend(names),
            (ChangeKind::Append, edit) => *edit = CategoryEdit::Append(names),
            (ChangeKind::Set | ChangeKind::Delete, edit) => *edit = CategoryEdit::Replace(names),
        }
    }
}

fn category_names<'x>(
    path: &Path<'x>,
    value: Option<&'x Item<'x>>,
) -> Option<Result<CategoryNames<'x>, ItemError>> {
    let names = match path {
        Path::Field(UnindexedField::ItemCategories) => value.map(|value| {
            value
                .fields()
                .categories
                .as_ref()
                .map(|names| names.0.iter().map(AsRef::as_ref).collect())
        }),
        Path::Extended(uri)
            if matches!(ItemProp::of_extended(uri), Some((_, ItemProp::Keywords))) =>
        {
            value.map(|value| {
                value
                    .fields()
                    .extended_property
                    .as_ref()?
                    .0
                    .iter()
                    .find(|property| property.uri == *uri)
                    .and_then(|property| match &property.value {
                        XPropValue::Multi(names) => Some(names.iter().map(AsRef::as_ref).collect()),
                        XPropValue::Single(_) => None,
                    })
            })
        }
        _ => return None,
    };
    Some(match names {
        None => Ok(CategoryNames::new()),
        Some(names) => names.ok_or(ItemError::InvalidPropertySet),
    })
}

pub(crate) fn item_edit<'x>(
    changes: &'x [ItemChange<'x>],
) -> Result<
    (
        FlagEdit,
        CategoryEdit<'x>,
        ContentEdit<'x>,
        Vec<CarriedEdit>,
    ),
    ItemError,
> {
    let mut edit = FlagEdit::default();
    let mut carried = Vec::new();
    let mut keys = None;
    let mut categories = CategoryEdit::default();
    let mut content = ContentEdit::default();
    for change in changes {
        let (path, value, kind) = match change {
            ItemChange::Set { path, value } => (path, Some(value), ChangeKind::Set),
            ItemChange::Append { path, value } => (path, Some(value), ChangeKind::Append),
            ItemChange::Delete(path) => (path, None, ChangeKind::Delete),
        };
        if let Path::Field(field) = path
            && content.apply(*field, kind, value)?
        {
            continue;
        }
        if let Some(names) = category_names(path, value) {
            categories.apply(kind, names?);
            continue;
        }
        if matches!(kind, ChangeKind::Append) {
            return Err(ItemError::InvalidPropertyAppend);
        }
        match path {
            Path::Field(UnindexedField::MessageIsRead) => {
                edit.read = Some(
                    value
                        .and_then(is_read)
                        .ok_or(ItemError::InvalidPropertySet)?,
                );
            }
            Path::Field(UnindexedField::MessageIsResponseRequested) => {
                let requested = match value {
                    Some(value) => Some(
                        value
                            .message_fields()
                            .and_then(|fields| fields.is_response_requested)
                            .ok_or(ItemError::InvalidPropertySet)?,
                    ),
                    None => None,
                };
                keys.get_or_insert_with(FlagKeys::new)
                    .response_requested_edit(requested, row_edit(&mut carried));
            }
            Path::Field(UnindexedField::ItemFlag) => {
                let flag = stored_flag(value.and_then(|value| value.fields().flag.as_ref()))?;
                edit.flagged = Some(flag.status == Some(FLAG_STATUS_ACTIVE));
                keys.get_or_insert_with(FlagKeys::new)
                    .ews_edits(&flag, row_edit(&mut carried));
            }
            Path::Extended(uri) => extended_edit(&mut edit, &mut carried, &mut keys, uri, value)?,
            _ => return Err(ItemError::InvalidPropertySet),
        }
    }
    Ok((edit, categories, content, carried))
}

pub(super) fn stored_flag(flag: Option<&Flag>) -> Result<EmailFlag<'static>, ItemError> {
    let Some(flag) = flag else {
        return Ok(EmailFlag::default());
    };
    let start = flag.start_date.as_ref().map(flag_time).transpose()?;
    let due = flag.due_date.as_ref().map(flag_time).transpose()?;
    let completed = flag.complete_date.as_ref().map(flag_time).transpose()?;
    match (flag.flag_status, start, due, completed) {
        (Some(FlagStatus::Flagged), start, due, None) if start.is_some() == due.is_some() => {
            Ok(EmailFlag {
                status: Some(FLAG_STATUS_ACTIVE),
                start_date: start,
                utc_start_date: start,
                due_date: due,
                utc_due_date: due,
                ..Default::default()
            })
        }
        (Some(FlagStatus::Complete), None, None, completed) => {
            let completed = completed.unwrap_or_else(completion_now);
            Ok(EmailFlag {
                status: Some(FLAG_STATUS_COMPLETE),
                flag_type: Some(Cow::Borrowed(FLAG_FOLLOW_UP)),
                date_completed: Some(completed),
                complete_time: Some(completed),
                ..Default::default()
            })
        }
        (Some(FlagStatus::NotFlagged) | None, None, None, None) => Ok(EmailFlag::default()),
        _ => Err(ItemError::InvalidFlag),
    }
}

fn completion_now() -> EasDateTime {
    let now = i64::try_from(now()).unwrap_or(i64::MAX);
    EasDateTime(UtcSeconds(now - now.rem_euclid(SECONDS_PER_MINUTE)), 0)
}

fn flag_time(time: &DateTime) -> Result<EasDateTime, ItemError> {
    time.to_utc()
        .map(|seconds| EasDateTime(seconds, 0))
        .ok_or(ItemError::InvalidFlag)
}

fn row_edit(carried: &mut Vec<CarriedEdit>) -> impl FnMut(&[u8], Option<OwnedPropValue>) + '_ {
    move |key, value| {
        carried.push(CarriedEdit {
            key: key.to_vec(),
            value: value.map(|value| {
                let mut encoded = Vec::new();
                value.write_canonical(&mut encoded);
                encoded
            }),
        })
    }
}

fn extended_edit(
    edit: &mut FlagEdit,
    carried: &mut Vec<CarriedEdit>,
    keys: &mut Option<FlagKeys>,
    uri: &ExtendedFieldUri<'_>,
    value: Option<&Item<'_>>,
) -> Result<(), ItemError> {
    let prop = match ItemProp::of_extended(uri) {
        Some((_, prop)) => prop,
        None if is_ignored_tag(&uri.target) => return Ok(()),
        None => {
            carried.push(carried_edit(uri, value)?);
            return Ok(());
        }
    };
    let number = match value {
        Some(value) => Some(integer(uri, value).ok_or(ItemError::InvalidPropertySet)?),
        None => None,
    };
    match prop {
        ItemProp::FlagStatus => {
            edit.flagged = Some(number == Some(FLAG_STATUS_FLAGGED));
            keys.get_or_insert_with(FlagKeys::new)
                .status_edit(number == Some(FLAG_STATUS_COMPLETED), row_edit(carried));
        }
        ItemProp::LastVerb => {
            let verb = match number {
                None => {
                    edit.answered = Some(false);
                    edit.forwarded = Some(false);
                    None
                }
                Some(number) => {
                    let verb = i32::try_from(number)
                        .ok()
                        .and_then(LastVerb::from_mapi)
                        .ok_or(ItemError::InvalidPropertySet)?;
                    match verb {
                        LastVerb::ReplyToSender | LastVerb::ReplyToAll => {
                            edit.answered = Some(true)
                        }
                        LastVerb::Forward => edit.forwarded = Some(true),
                    }
                    Some(verb)
                }
            };
            keys.get_or_insert_with(FlagKeys::new)
                .verb_edit(verb, row_edit(carried));
        }
        ItemProp::ImapDeleted => edit.deleted = Some(number.is_some_and(|n| n != 0)),
        ItemProp::MessageFlags => {}
        _ => return Err(ItemError::InvalidPropertySet),
    }
    Ok(())
}

fn carried_edit(
    uri: &ExtendedFieldUri<'_>,
    value: Option<&Item<'_>>,
) -> Result<CarriedEdit, ItemError> {
    let Some(value) = value else {
        let (key, _) = uri.to_prop().map_err(|_| ItemError::InvalidPropertySet)?;
        return if is_carried(uri, key.as_ref()) {
            Ok(CarriedEdit {
                key: encode_key(key.as_ref()),
                value: None,
            })
        } else {
            Err(ItemError::InvalidPropertySet)
        };
    };
    let property =
        carried_property(extended_property(uri, value).ok_or(ItemError::InvalidPropertySet)?)?;
    Ok(CarriedEdit {
        key: property.key,
        value: Some(property.value),
    })
}

fn extended_property<'v, 'x>(
    uri: &ExtendedFieldUri<'_>,
    value: &'v Item<'x>,
) -> Option<&'v ExtendedProperty<'x>> {
    value
        .fields()
        .extended_property
        .as_ref()?
        .0
        .iter()
        .find(|property| property.uri == *uri)
}

fn is_read(value: &Item<'_>) -> Option<bool> {
    value.message_fields()?.is_read
}

fn integer(uri: &ExtendedFieldUri<'_>, value: &Item<'_>) -> Option<i64> {
    xprop_int(&extended_property(uri, value)?.value)
}

pub(super) fn xprop_int(value: &XPropValue<'_>) -> Option<i64> {
    match value {
        XPropValue::Single(text) => text.trim().parse().ok(),
        XPropValue::Multi(_) => None,
    }
}

fn expected_change(id: &BaseItemId<'_>) -> Option<u64> {
    let change_key = match id {
        BaseItemId::Item(id) => id.change_key.as_ref(),
        BaseItemId::Occurrence { change_key, .. }
        | BaseItemId::RecurringMaster { change_key, .. } => change_key.as_ref(),
        BaseItemId::MasterRanges(_) => None,
    }?;
    EwsChangeKey::decode(change_key.as_str()).map(|key| key.change_id)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/item/update/tests.rs"]
mod tests;
