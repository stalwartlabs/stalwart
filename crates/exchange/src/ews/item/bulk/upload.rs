/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Parsed, RecordLimits,
    associated::{associated_content, fai_message, write_associated},
    email::{EmailRecord, create_email, update_email},
    native::{create_calendar, create_contact, native_content, update_calendar, update_contact},
    organization, record_limit,
};
use crate::{
    ews::{
        calendar::{Events, write::calendar_destination},
        contact::{
            Contacts,
            write::{ContactWriter, contact_destination},
        },
        context::{EwsCaller, EwsContext},
        folder::{FolderSelector, resolve_folder, saved_folder_status},
        groupware::{GroupwareKind, items::convert_options, write::CalendarWriter},
        item::{
            EmailIds, ItemError,
            create::decoded,
            write::{destination, saved_destination},
        },
        reply::{RESPONSE_CAPACITY, ews_response},
        task::{Tasks, write::task_destination},
    },
    folders::FolderNode,
    mapi::emsmdb::store::extended_rule_size_limit,
};
use ahash::AHashSet;
use calcard::icalendar::ICalendarComponentType;
use common::Server;
use exchange_proto::{
    ews::{
        MessageResult, Operation, Status,
        bulk::{BulkRecord, RecordKind},
        calendar::CalendarFieldSet,
        requests::bulk::UploadItems,
        responses::item::UploadItemsMessage,
        schema::CreateAction,
        task::TaskFieldSet,
        types::{
            bulk::UploadItem,
            ids::{FolderId, ItemId, TargetFolderId},
        },
    },
    ids::essdn::OrgDn,
};
use http_proto::HttpResponse;
use tokio::sync::OnceCell;

type Uploaded = Result<ItemId<'static>, Status<'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Destination {
    MailSave,
    Mail,
    Calendar,
    Tasks,
    Contacts,
    Associated,
}

impl Destination {
    pub(super) fn for_create(is_associated: bool, kind: RecordKind) -> Result<Self, ItemError> {
        if is_associated {
            return Ok(Destination::Associated);
        }
        match kind {
            RecordKind::Email => Ok(Destination::MailSave),
            RecordKind::Event => Ok(Destination::Calendar),
            RecordKind::Task => Ok(Destination::Tasks),
            RecordKind::Contact => Ok(Destination::Contacts),
            RecordKind::Associated => Err(ItemError::AssociatedRecord),
        }
    }

    pub(super) fn for_update(
        is_associated: bool,
        parsed: Parsed,
        kind: RecordKind,
    ) -> Option<Self> {
        match (is_associated, parsed, kind) {
            (true, Parsed::Associated(_), _) => Some(Destination::Associated),
            (false, Parsed::Mail, RecordKind::Email) => Some(Destination::Mail),
            (false, Parsed::Groupware(GroupwareKind::Event, ..), RecordKind::Event) => {
                Some(Destination::Calendar)
            }
            (false, Parsed::Groupware(GroupwareKind::Task, ..), RecordKind::Task) => {
                Some(Destination::Tasks)
            }
            (false, Parsed::Groupware(GroupwareKind::Contact, ..), RecordKind::Contact) => {
                Some(Destination::Contacts)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolved {
    Container(u32),
    Node(FolderNode),
}

enum Failure {
    Missing,
    Status(Status<'static>),
}

impl From<ItemError> for Failure {
    fn from(err: ItemError) -> Self {
        match err {
            ItemError::NotFound => Failure::Missing,
            err => Failure::Status(err.status()),
        }
    }
}

#[derive(Default)]
struct Sides {
    ids: OnceCell<EmailIds>,
    events: OnceCell<Result<Events, ItemError>>,
    tasks: OnceCell<Result<Tasks, ItemError>>,
    contacts: OnceCell<Result<Contacts, ItemError>>,
    org: OnceCell<OrgDn>,
}

struct Uploader<'x> {
    server: &'x Server,
    ctx: &'x EwsContext,
    caller: EwsCaller<'x>,
    sides: &'x Sides,
    events: Option<CalendarWriter<'x, CalendarFieldSet>>,
    tasks: Option<CalendarWriter<'x, TaskFieldSet>>,
    contacts: Option<(&'x Contacts, ContactWriter<'x>)>,
    parents: Vec<(Box<str>, Destination, Result<Resolved, Status<'static>>)>,
    limits: RecordLimits,
}

pub(crate) async fn upload_items(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UploadItems<'_>,
) -> trc::Result<HttpResponse> {
    let limit = record_limit(server);
    let sides = Sides::default();
    let mut uploader = Uploader {
        server,
        ctx,
        caller,
        sides: &sides,
        events: None,
        tasks: None,
        contacts: None,
        parents: Vec::new(),
        limits: RecordLimits::new(server),
    };
    let mut claimed = AHashSet::with_capacity(request.items.len());
    let mut results = Vec::with_capacity(request.items.len());
    for item in &request.items {
        let target = match (&item.item_id, item.create_action) {
            (Some(id), CreateAction::Update | CreateAction::UpdateOrCreate) => {
                Some(Parsed::of(id).and_then(|parsed| {
                    if claimed.insert(id.id.as_str()) {
                        Ok((id, parsed))
                    } else {
                        Err(ItemError::Duplicate)
                    }
                }))
            }
            _ => None,
        };
        results.push(match target.transpose() {
            Ok(target) => uploader.upload(item, target, limit).await?,
            Err(err) => Err(err.status()),
        });
    }
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::UploadItems);
    for result in results {
        match result {
            Ok(item_id) => messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(UploadItemsMessage {
                    item_id: Some(item_id),
                }),
            }),
            Err(status) => {
                messages.message(&MessageResult::<UploadItemsMessage> { status, body: None })
            }
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

impl<'x> Uploader<'x> {
    async fn upload(
        &mut self,
        item: &UploadItem<'_>,
        target: Option<(&ItemId<'_>, Parsed)>,
        limit: usize,
    ) -> trc::Result<Uploaded> {
        let data = match decoded(&item.data, limit, ItemError::CorruptData) {
            Ok(data) => data,
            Err(err) => return Ok(Err(err.status())),
        };
        let Ok(record) = BulkRecord::decode(&data) else {
            return Ok(Err(ItemError::CorruptData.status()));
        };
        if let Err(err) = self.limits.check(&record) {
            return Ok(Err(err.status()));
        }
        if !item.is_associated && record.kind() == RecordKind::Associated {
            return Ok(Err(ItemError::AssociatedRecord.status()));
        }
        let Some((id, parsed)) = target else {
            return self.create(item, &record).await;
        };
        match self.update(item, &record, id, parsed).await? {
            Ok(item_id) => Ok(Ok(item_id)),
            Err(Failure::Missing) if item.create_action == CreateAction::UpdateOrCreate => {
                self.create(item, &record).await
            }
            Err(Failure::Missing) => Ok(Err(ItemError::NotFound.status())),
            Err(Failure::Status(status)) => Ok(Err(status)),
        }
    }

    async fn create(
        &mut self,
        item: &UploadItem<'_>,
        record: &BulkRecord<'_>,
    ) -> trc::Result<Uploaded> {
        let destination = match Destination::for_create(item.is_associated, record.kind()) {
            Ok(destination) => destination,
            Err(err) => return Ok(Err(err.status())),
        };
        let container = match self.parent(&item.parent_folder_id, destination).await? {
            Ok(Resolved::Container(container)) => container,
            Ok(Resolved::Node(node)) => {
                return Ok(self
                    .associated(node, None, record)
                    .await?
                    .map_err(ItemError::status));
            }
            Err(status) => return Ok(Err(status)),
        };
        let created = match record {
            BulkRecord::Email {
                raw,
                received_at,
                keywords,
                properties,
            } => match EmailRecord::new(raw, *received_at, keywords, properties) {
                Ok(email) => {
                    let ids = self.ids().await?;
                    create_email(self.server, self.ctx, self.caller, ids, container, email).await?
                }
                Err(err) => Err(err),
            },
            BulkRecord::Event { ical } => match self.events().await? {
                Ok(writer) => {
                    create_calendar(writer, container, ical, &ICalendarComponentType::VEvent)
                        .await?
                }
                Err(err) => Err(err),
            },
            BulkRecord::Task { ical } => match self.tasks().await? {
                Ok(writer) => {
                    create_calendar(writer, container, ical, &ICalendarComponentType::VTodo).await?
                }
                Err(err) => Err(err),
            },
            BulkRecord::Contact { vcard } => match self.contacts().await? {
                Ok((_, writer)) => create_contact(writer, container, vcard).await?,
                Err(err) => Err(err),
            },
            BulkRecord::Associated { .. } => Err(ItemError::AssociatedRecord),
        };
        Ok(created.map_err(ItemError::status))
    }

    async fn update(
        &mut self,
        item: &UploadItem<'_>,
        record: &BulkRecord<'_>,
        id: &ItemId<'_>,
        parsed: Parsed,
    ) -> trc::Result<Result<ItemId<'static>, Failure>> {
        let type_changed = Err(Failure::Status(ItemError::ObjectTypeChanged.status()));
        let Some(destination) = Destination::for_update(item.is_associated, parsed, record.kind())
        else {
            return Ok(type_changed);
        };
        let Ok(resolved) = self.parent(&item.parent_folder_id, destination).await? else {
            return Ok(Err(Failure::Missing));
        };
        let updated = match (parsed, resolved, record) {
            (Parsed::Associated(target), Resolved::Node(node), _) => {
                if target.node != node || target.account != self.ctx.account.account_id {
                    Err(ItemError::NotFound)
                } else {
                    self.associated(node, Some(target.id), record).await?
                }
            }
            (
                Parsed::Mail,
                Resolved::Container(mailbox_id),
                BulkRecord::Email {
                    raw,
                    received_at,
                    keywords,
                    properties,
                },
            ) => match EmailRecord::new(raw, *received_at, keywords, properties) {
                Ok(email) => {
                    let ids = self.ids().await?;
                    update_email(
                        self.server,
                        self.ctx,
                        self.caller,
                        ids,
                        id,
                        mailbox_id,
                        &email,
                    )
                    .await?
                }
                Err(err) => Err(err),
            },
            (
                Parsed::Groupware(GroupwareKind::Event, account, target),
                Resolved::Container(container),
                BulkRecord::Event { ical },
            ) => match self.events().await? {
                Ok(writer) => {
                    update_calendar(
                        writer,
                        account,
                        target,
                        container,
                        ical,
                        &ICalendarComponentType::VEvent,
                    )
                    .await?
                }
                Err(err) => Err(err),
            },
            (
                Parsed::Groupware(GroupwareKind::Task, account, target),
                Resolved::Container(container),
                BulkRecord::Task { ical },
            ) => match self.tasks().await? {
                Ok(writer) => {
                    update_calendar(
                        writer,
                        account,
                        target,
                        container,
                        ical,
                        &ICalendarComponentType::VTodo,
                    )
                    .await?
                }
                Err(err) => Err(err),
            },
            (
                Parsed::Groupware(GroupwareKind::Contact, account, target),
                Resolved::Container(container),
                BulkRecord::Contact { vcard },
            ) => match self.contacts().await? {
                Ok((contacts, writer)) => {
                    update_contact(contacts, writer, account, target, container, vcard).await?
                }
                Err(err) => Err(err),
            },
            _ => return Ok(type_changed),
        };
        Ok(updated.map_err(Failure::from))
    }

    async fn associated(
        &self,
        node: FolderNode,
        existing: Option<u32>,
        record: &BulkRecord<'_>,
    ) -> trc::Result<Result<ItemId<'static>, ItemError>> {
        let content = match record {
            BulkRecord::Associated {
                message_class,
                properties,
                recipients,
            } => associated_content(message_class, properties, recipients),
            record => {
                let sides = self.sides;
                let org = sides
                    .org
                    .get_or_try_init(|| async { organization() })
                    .await?;
                native_content(record, &convert_options(org))
            }
        };
        let message = match content
            .and_then(|content| fai_message(&content, extended_rule_size_limit(self.server)))
        {
            Ok(message) => message,
            Err(err) => return Ok(Err(err)),
        };
        write_associated(self.server, self.ctx, self.caller, node, existing, message).await
    }

    async fn parent(
        &mut self,
        parent: &FolderId<'_>,
        destination: Destination,
    ) -> trc::Result<Result<Resolved, Status<'static>>> {
        if let Some((_, _, resolved)) = self
            .parents
            .iter()
            .find(|(id, used, _)| *used == destination && **id == *parent.id.as_str())
        {
            return Ok(resolved.clone());
        }
        let (server, ctx, caller) = (self.server, self.ctx, self.caller);
        let folder = TargetFolderId::Folder(parent.clone());
        let resolved = match destination {
            Destination::MailSave => saved_destination(server, ctx, &folder)
                .await?
                .map(Resolved::Container),
            Destination::Mail => destination_mailbox(server, ctx, &folder).await?,
            Destination::Calendar => calendar_destination(server, ctx, caller, Some(&folder))
                .await?
                .map(Resolved::Container),
            Destination::Tasks => task_destination(server, ctx, caller, Some(&folder))
                .await?
                .map(Resolved::Container),
            Destination::Contacts => contact_destination(server, ctx, Some(&folder))
                .await?
                .map(Resolved::Container),
            Destination::Associated => {
                let tree = ctx.folder_tree(server).await?;
                resolve_folder(server, ctx, &tree, FolderSelector::from(&folder))
                    .await?
                    .map(|entry| Resolved::Node(entry.node))
                    .map_err(|status| saved_folder_status(ctx, status))
            }
        };
        self.parents
            .push((parent.id.as_str().into(), destination, resolved.clone()));
        Ok(resolved)
    }

    async fn ids(&self) -> trc::Result<&'x EmailIds> {
        let sides = self.sides;
        sides
            .ids
            .get_or_try_init(|| EmailIds::load(self.server, self.ctx))
            .await
    }

    async fn events(
        &mut self,
    ) -> trc::Result<Result<&mut CalendarWriter<'x, CalendarFieldSet>, ItemError>> {
        if self.events.is_none() {
            let sides = self.sides;
            match sides
                .events
                .get_or_try_init(|| Events::load(self.server, self.ctx))
                .await?
            {
                Ok(events) => {
                    self.events = Some(CalendarWriter::new(self.server, self.caller, events))
                }
                Err(err) => return Ok(Err(*err)),
            }
        }
        Ok(self.events.as_mut().ok_or(ItemError::NotFound))
    }

    async fn tasks(
        &mut self,
    ) -> trc::Result<Result<&mut CalendarWriter<'x, TaskFieldSet>, ItemError>> {
        if self.tasks.is_none() {
            let sides = self.sides;
            match sides
                .tasks
                .get_or_try_init(|| Tasks::load(self.server, self.ctx))
                .await?
            {
                Ok(tasks) => {
                    self.tasks = Some(CalendarWriter::new(self.server, self.caller, tasks))
                }
                Err(err) => return Ok(Err(*err)),
            }
        }
        Ok(self.tasks.as_mut().ok_or(ItemError::NotFound))
    }

    async fn contacts(
        &mut self,
    ) -> trc::Result<Result<(&'x Contacts, &mut ContactWriter<'x>), ItemError>> {
        if self.contacts.is_none() {
            let sides = self.sides;
            match sides
                .contacts
                .get_or_try_init(|| Contacts::load(self.server, self.ctx))
                .await?
            {
                Ok(contacts) => {
                    self.contacts = Some((
                        contacts,
                        ContactWriter::new(self.server, self.caller, contacts),
                    ))
                }
                Err(err) => return Ok(Err(*err)),
            }
        }
        Ok(self
            .contacts
            .as_mut()
            .map(|(contacts, writer)| (*contacts, writer))
            .ok_or(ItemError::NotFound))
    }
}

async fn destination_mailbox(
    server: &Server,
    ctx: &EwsContext,
    folder: &TargetFolderId<'_>,
) -> trc::Result<Result<Resolved, Status<'static>>> {
    Ok(destination(server, ctx, folder)
        .await?
        .map(Resolved::Container)
        .map_err(|status| saved_folder_status(ctx, status)))
}
