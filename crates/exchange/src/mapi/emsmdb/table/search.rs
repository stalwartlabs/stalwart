/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    TableRow,
    body::EmailRows,
    contents::{RowFill, envelope_column, mail_envelope_column, push_row_instance},
    decode_restriction,
    filter::RowFilter,
    references,
};
use crate::{
    folders::{FolderNode, FolderTree, FolderWrites, access::ViewRights},
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError},
            message::{
                MessageParent, object_row::is_category, push_categories, push_email_state,
                push_message_ids,
            },
            props::{PropBag, PropOut},
            search::SearchFlags,
            state::TableObject,
            store::StoreGuids,
        },
        ids::{IdSpace, MapiId},
        text::decode_text,
    },
    store::{FolderKind, FolderRef, alias::GroupwareKind, named::AccountNamedProps},
};
use email::{
    cache::email::{MessageAccess, MessageCacheAccess},
    message::query::{MailCondition, MailFilter, MailTextField, QueryFilter},
};
use exchange_proto::mapi::{
    prop::{CodePage, FIRST_NAMED_ID, NamedPropMap, PropTag, PropType, PropValue, tags},
    restriction::{RelOp, Restriction, RestrictionNode},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{EVENT_HAS_ALARMS, EVENT_USES_DEFAULT_ALERTS},
};
use std::{iter, mem, ops::Range};
use store::{ahash::AHashSet, roaring::RoaringBitmap, search::SearchQuery, write::SearchIndex};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    type_state::DataType,
};

const EVENT_ALERTS: u16 = EVENT_HAS_ALARMS | EVENT_USES_DEFAULT_ALERTS;
const MAIL_CLASS: &str = "ipm.note";
const PARENT_SERVER_ID: PropTag = PropTag::new(tags::PARENT_ENTRY_ID.id(), PropType::ServerId);

struct Prune {
    named: bool,
    mail_only: bool,
    texts: Vec<MailFilter>,
}

impl Prune {
    fn of(
        restriction: &Restriction<'_>,
        named: &AccountNamedProps<'_>,
        code_page: CodePage,
    ) -> Self {
        let mut texts = Vec::new();
        let mut text = String::new();
        collect_text(restriction, restriction.root, code_page, &mut texts);
        Prune {
            named: requires_named(restriction, restriction.root, named),
            mail_only: requires_mail_class(restriction, restriction.root, code_page, &mut text),
            texts,
        }
    }
}

fn children<'r>(restriction: &'r Restriction<'_>, range: &Range<u16>) -> &'r [u16] {
    restriction
        .children
        .get(usize::from(range.start)..usize::from(range.end))
        .unwrap_or_default()
}

fn requires_named(
    restriction: &Restriction<'_>,
    index: u16,
    named: &AccountNamedProps<'_>,
) -> bool {
    let is_named = |tag: PropTag| {
        let id = tag.id();
        id.0 >= FIRST_NAMED_ID.0 && !named.key(id).is_some_and(is_category)
    };
    match restriction.nodes.get(usize::from(index)) {
        Some(RestrictionNode::And(range)) => children(restriction, range)
            .iter()
            .any(|child| requires_named(restriction, *child, named)),
        Some(RestrictionNode::Or(range)) => {
            let children = children(restriction, range);
            !children.is_empty()
                && children
                    .iter()
                    .all(|child| requires_named(restriction, *child, named))
        }
        Some(
            RestrictionNode::Content { tag, .. }
            | RestrictionNode::Property { tag, .. }
            | RestrictionNode::Bitmask { tag, .. }
            | RestrictionNode::Size { tag, .. }
            | RestrictionNode::Exist(tag),
        ) => is_named(*tag),
        Some(RestrictionNode::CompareProps { a, b, .. }) => is_named(*a) || is_named(*b),
        Some(RestrictionNode::Comment {
            child: Some(child), ..
        })
        | Some(RestrictionNode::Count { child, .. }) => requires_named(restriction, *child, named),
        Some(
            RestrictionNode::Not(_)
            | RestrictionNode::Sub { .. }
            | RestrictionNode::Comment { child: None, .. },
        )
        | None => false,
    }
}

fn requires_mail_class(
    restriction: &Restriction<'_>,
    index: u16,
    code_page: CodePage,
    text: &mut String,
) -> bool {
    match restriction.nodes.get(usize::from(index)) {
        Some(RestrictionNode::And(range)) => children(restriction, range)
            .iter()
            .any(|child| requires_mail_class(restriction, *child, code_page, text)),
        Some(RestrictionNode::Or(range)) => {
            let children = children(restriction, range);
            !children.is_empty()
                && children
                    .iter()
                    .all(|child| requires_mail_class(restriction, *child, code_page, text))
        }
        Some(
            RestrictionNode::Content { tag, value, .. }
            | RestrictionNode::Property {
                op: RelOp::Eq,
                tag,
                value,
            },
        ) if tag.id() == tags::MESSAGE_CLASS.id() => {
            decode_text(value, code_page, text) && {
                text.make_ascii_lowercase();
                text.contains(MAIL_CLASS)
            }
        }
        Some(RestrictionNode::Comment {
            child: Some(child), ..
        })
        | Some(RestrictionNode::Count { child, .. }) => {
            requires_mail_class(restriction, *child, code_page, text)
        }
        _ => false,
    }
}

fn collect_text(
    restriction: &Restriction<'_>,
    index: u16,
    code_page: CodePage,
    texts: &mut Vec<MailFilter>,
) {
    match restriction.nodes.get(usize::from(index)) {
        Some(RestrictionNode::And(range)) => {
            for child in children(restriction, range) {
                collect_text(restriction, *child, code_page, texts);
            }
        }
        Some(RestrictionNode::Or(range)) => match children(restriction, range) {
            [child] => collect_text(restriction, *child, code_page, texts),
            children => {
                if let Some(conditions) = children
                    .iter()
                    .map(|child| {
                        text_condition(restriction.nodes.get(usize::from(*child)), code_page)
                    })
                    .collect::<Option<Vec<_>>>()
                    && !conditions.is_empty()
                {
                    texts.reserve(conditions.len() + 2);
                    texts.push(MailFilter::Or);
                    texts.extend(conditions);
                    texts.push(MailFilter::Close);
                }
            }
        },
        Some(RestrictionNode::Comment {
            child: Some(child), ..
        })
        | Some(RestrictionNode::Count { child, .. }) => {
            collect_text(restriction, *child, code_page, texts)
        }
        node => texts.extend(text_condition(node, code_page)),
    }
}

fn text_condition(node: Option<&RestrictionNode<'_>>, code_page: CodePage) -> Option<MailFilter> {
    let Some(RestrictionNode::Content { tag, value, .. }) = node else {
        return None;
    };
    let field = if tag.id() == tags::SUBJECT.id() || tag.id() == tags::NORMALIZED_SUBJECT.id() {
        MailTextField::Subject
    } else if tag.id() == tags::BODY.id() {
        MailTextField::Body
    } else {
        return None;
    };
    let mut text = String::new();
    (decode_text(value, code_page, &mut text) && !text.trim().is_empty())
        .then(|| MailFilter::Condition(MailCondition::Text(field, text)))
}

fn push_parent_server_id(bag: &mut PropBag, server_id: &[u8]) {
    bag.push_out(
        PARENT_SERVER_ID,
        &PropOut::Value(PropValue::ServerId(server_id)),
    );
}

fn scope_containers(
    tree: &FolderTree,
    scope: impl Iterator<Item = FolderNode>,
    recursive: bool,
    rights: &ViewRights,
) -> Vec<FolderRef> {
    let mut containers = Vec::new();
    let mut seen = AHashSet::new();
    for node in scope {
        let Some(entry) = tree.get(node) else {
            continue;
        };
        let nested = recursive
            .then(|| tree.descendants(node))
            .into_iter()
            .flatten();
        for entry in iter::once(entry).chain(nested) {
            if let FolderNode::Stored(
                folder @ FolderRef {
                    kind: FolderKind::Mailbox | FolderKind::Calendar | FolderKind::AddressBook,
                    ..
                },
            ) = entry.node
                && !entry.search
                && rights.of(entry.node).reads_items()
                && seen.insert(folder)
            {
                containers.push(folder);
            }
        }
    }
    containers
}

impl RopContext<'_, '_> {
    pub(super) async fn search_rows(
        &mut self,
        table: &TableObject,
        node: FolderNode,
        envelope: bool,
    ) -> Result<Vec<TableRow>, RopError> {
        let mailbox_id = table.folder.mailbox_id;
        let request = self.request;
        let Ok(search) = request
            .server
            .folder_search(request.access_token, mailbox_id, node)
            .await?
        else {
            return Ok(Vec::new());
        };
        let Ok(Some(restriction)) = decode_restriction(&search.restriction) else {
            return Ok(Vec::new());
        };
        let code_page = self.code_page();
        let Some(mut filter) = RowFilter::new(&restriction, code_page) else {
            return Ok(Vec::new());
        };
        let tree = self.folder_tree(mailbox_id).await?;
        let scope = search
            .scope
            .iter()
            .filter_map(|folder| FolderNode::from_stored(folder.kind, folder.id));
        let rights = self.view_rights(mailbox_id).await?;
        let containers =
            scope_containers(&tree, scope, SearchFlags(search.flags).recursive(), &rights);
        if containers.is_empty() {
            return Ok(Vec::new());
        }

        let mailbox = self.mailbox(mailbox_id).await?;
        let mut prune = Prune::of(
            &restriction,
            &AccountNamedProps::new(&mailbox.exchange),
            code_page,
        );
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let mut rows = Vec::new();

        if let Some(messages) = mailbox.messages.as_ref()
            && self.types.contains(DataType::Email)
        {
            let mut seen = RoaringBitmap::new();
            let mut candidates = Vec::new();
            for container in containers
                .iter()
                .filter(|folder| folder.kind == FolderKind::Mailbox)
            {
                for item in messages.in_mailbox(container.id) {
                    let document_id = item.document_id();
                    if (!prune.named || mailbox.exchange.has_object(Collection::Email, document_id))
                        && seen.insert(document_id)
                    {
                        candidates.push((container.id, item));
                    }
                }
            }
            if !prune.texts.is_empty()
                && !candidates.is_empty()
                && let Some(mut query) = QueryFilter::parse(
                    mem::take(&mut prune.texts),
                    messages,
                    MessageAccess::All,
                    request.server.core.email.default_language,
                )
            {
                let matches = request
                    .server
                    .search_store()
                    .filter_account(
                        SearchQuery::new(SearchIndex::Email)
                            .with_filters(query.residual_filters())
                            .with_account_id(mailbox_id)
                            .with_mask(seen),
                    )
                    .await
                    .caused_by(trc::location!())?;
                candidates.retain(|(_, item)| matches.contains(item.document_id()));
            }
            rows.reserve(candidates.len());
            let mut current: Option<(u32, MessageParent, Vec<u8>)> = None;
            for (container, item) in candidates {
                let document_id = item.document_id();
                let (parent, server_id) = match current {
                    Some((folder, ref parent, ref server_id)) if folder == container => {
                        (parent, server_id.as_slice())
                    }
                    _ => {
                        let folder = MapiId::from_node(FolderNode::Stored(FolderRef {
                            kind: FolderKind::Mailbox,
                            id: container,
                        }));
                        let parent = MessageParent::new(&guids, &mailbox.exchange, folder);
                        let server_id = parent.server_id();
                        let (_, parent, server_id) = current.insert((container, parent, server_id));
                        (&*parent, server_id.as_slice())
                    }
                };
                let id = MapiId::new(IdSpace::Email, mailbox.email_item(container, document_id));
                let mut bag = PropBag::default();
                push_message_ids(&mut bag, &guids, parent, id);
                push_parent_server_id(&mut bag, server_id);
                push_row_instance(&mut bag, id);
                push_email_state(&mut bag, item, &mailbox.exchange);
                push_categories(&mut bag, &mailbox, item);
                rows.push(TableRow {
                    key: MapiId::new(IdSpace::Email, document_id).counter(),
                    bag,
                });
            }
        }

        let mail_rows = rows.len();
        for (kind, groupware, collection, data_type) in [
            (
                FolderKind::Calendar,
                GroupwareKind::Event,
                SyncCollection::Calendar,
                DataType::CalendarEvent,
            ),
            (
                FolderKind::AddressBook,
                GroupwareKind::Contact,
                SyncCollection::AddressBook,
                DataType::ContactCard,
            ),
        ] {
            if prune.mail_only
                || !self.types.contains(data_type)
                || !containers.iter().any(|folder| folder.kind == kind)
            {
                continue;
            }
            let resources = request
                .server
                .fetch_groupware_resources(mailbox_id, mailbox_id, collection)
                .await
                .caused_by(trc::location!())?;
            let alerts_only = prune.named && groupware == GroupwareKind::Event;
            let mut seen = RoaringBitmap::new();
            for folder in containers.iter().filter(|folder| folder.kind == kind) {
                let parent = MessageParent::new(
                    &guids,
                    &mailbox.exchange,
                    MapiId::from_node(FolderNode::Stored(*folder)),
                );
                let server_id = parent.server_id();
                for document_id in resources.children_ids(folder.id) {
                    if rights.hides(&resources, document_id)
                        || (alerts_only
                            && resources
                                .item_by_id(document_id)
                                .and_then(|item| item.event_flags())
                                .is_none_or(|flags| flags & EVENT_ALERTS == 0))
                        || !seen.insert(document_id)
                    {
                        continue;
                    }
                    let id = mailbox.client_item(*folder, document_id);
                    let mut bag = PropBag::default();
                    push_message_ids(&mut bag, &guids, &parent, id);
                    push_parent_server_id(&mut bag, &server_id);
                    push_row_instance(&mut bag, id);
                    rows.push(TableRow {
                        key: MapiId::new(IdSpace::of_groupware(groupware), document_id).counter(),
                        bag,
                    });
                }
            }
        }

        let envelope_column = if rows.len() == mail_rows {
            mail_envelope_column
        } else {
            envelope_column
        };
        if envelope || references(&restriction, envelope_column) {
            self.complete_rows(table, &mut rows, RowFill::Envelope)
                .await?;
        }
        let documents = self
            .resolve_body_terms(mailbox_id, EmailRows::Search, &mut filter, &rows)
            .await?;
        rows.retain(|row| {
            filter.matches_document(
                &|tag| row.get(tag),
                documents
                    .as_ref()
                    .and_then(|documents| documents.document(row.key)),
            )
        });
        Ok(rows)
    }
}
