/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{EventView, GroupwareFields, GroupwareKind, VersionedArchives, change_id_of};
use crate::{
    ews::{context::EwsContext, folder::folder_id, item::ItemError},
    folders::{FolderNode, access::ViewRights},
    identity::org_dn,
    store::FolderRef,
};
use bytes::Bytes;
use common::{GroupwareResources, Server, auth::AccountInfo};
use exchange_proto::{
    convert::{
        context::{BodyPreference, ConvertOptions, TnefPolicy},
        ical::{EventOccurrences, EventParts},
        model::{MessageContent, PropBag},
    },
    ews::types::{
        ids::{BaseItemId, EwsIdStr, FolderId, ItemId},
        item::Item,
    },
    ids::{
        essdn::OrgDn,
        ews::{EwsChangeKey, EwsObjectId},
    },
};
use groupware::{cache::GroupwareCache, calendar::CalendarEventContent};
use std::{marker::PhantomData, sync::Arc};
use store::{
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes},
};
use tokio::sync::OnceCell;
use trc::AddContext;

const MAX_DECODED: u32 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GroupwareRef {
    pub container: u32,
    pub document_id: u32,
}

pub(crate) struct LoadedItem {
    pub item: GroupwareRef,
    pub change_id: u64,
    pub content: Option<MessageContent>,
    pub occurrences: Option<Box<EventOccurrences>>,
    pub mime: Option<Bytes>,
}

pub(crate) struct GroupwareItems<F> {
    pub account_id: u32,
    pub resources: Arc<GroupwareResources>,
    view: ViewRights,
    account_info: OnceCell<AccountInfo>,
    org: OrgDn,
    fields: PhantomData<F>,
}

impl<F: GroupwareFields> GroupwareItems<F> {
    pub async fn load(server: &Server, ctx: &EwsContext) -> trc::Result<Result<Self, ItemError>> {
        if !F::KIND
            .data_types()
            .into_iter()
            .all(|data_type| ctx.account.data_types.contains(data_type))
        {
            return Ok(Err(ItemError::AccessDenied));
        }
        let account_id = ctx.account.account_id;
        let org = org_dn().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Exchange organization DN is invalid.")
                .caused_by(trc::location!())
        })?;
        Ok(Ok(GroupwareItems {
            account_id,
            resources: server
                .fetch_groupware_resources(account_id, account_id, F::KIND.sync_collection())
                .await?,
            view: ctx.access.clone(),
            account_info: OnceCell::new(),
            org,
            fields: PhantomData,
        }))
    }

    pub fn check(&self, account: u32, item: GroupwareRef) -> Result<GroupwareRef, ItemError> {
        if account != self.account_id
            || !self
                .resources
                .item_by_id(item.document_id)
                .is_some_and(|cached| {
                    cached
                        .child_names()
                        .iter()
                        .any(|name| name.parent_id == item.container)
                })
            || self.hides(item.document_id)
        {
            return Err(ItemError::NotFound);
        }
        let rights = self.view.of(FolderNode::Stored(FolderRef {
            kind: F::KIND.folder_kind(),
            id: item.container,
        }));
        if rights.reads_items() {
            Ok(item)
        } else if rights.is_visible() {
            Err(ItemError::Forbidden)
        } else {
            Err(ItemError::NotFound)
        }
    }

    pub fn members(&self, container: u32) -> impl Iterator<Item = GroupwareRef> + '_ {
        self.resources
            .children(container)
            .filter(|path| !path.is_container() && !self.hides(path.document_id()))
            .map(move |path| GroupwareRef {
                container,
                document_id: path.document_id(),
            })
    }

    pub fn view(&self) -> &ViewRights {
        &self.view
    }

    fn hides(&self, document_id: u32) -> bool {
        !matches!(F::KIND, GroupwareKind::Contact) && self.view.hides(&self.resources, document_id)
    }

    pub fn event_view(&self, document_id: u32) -> EventView {
        match F::KIND {
            GroupwareKind::Contact => EventView::Full,
            GroupwareKind::Task | GroupwareKind::Event => {
                EventView::of(self.view.privacy(&self.resources, document_id))
            }
        }
    }

    pub async fn listed(
        &self,
        server: &Server,
        container: u32,
        known: &RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        let mut listed = self
            .members(container)
            .map(|item| item.document_id)
            .collect::<RoaringBitmap>();
        if !matches!(F::KIND, GroupwareKind::Event) {
            return Ok(listed);
        }
        let unknown = &listed - known;
        if unknown.is_empty() {
            return Ok(listed);
        }
        listed -= &unknown;
        server
            .archives(
                self.account_id,
                F::KIND.collection(),
                F::KIND.content(),
                &unknown,
                |document_id, archive| {
                    if archive
                        .unarchive::<CalendarEventContent>()?
                        .data
                        .event
                        .components
                        .iter()
                        .any(|component| component.component_type.is_event())
                    {
                        listed.insert(document_id);
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        Ok(listed)
    }

    pub async fn account_info(&self, server: &Server) -> trc::Result<&AccountInfo> {
        self.account_info
            .get_or_try_init(|| server.account_info(self.account_id))
            .await
            .caused_by(trc::location!())
    }

    pub async fn prepare(&self, server: &Server, fields: F) -> trc::Result<()> {
        if fields.needs_owner() {
            self.account_info(server).await?;
        }
        Ok(())
    }

    pub fn owner(&self) -> &[String] {
        self.account_info
            .get()
            .map_or(&[], |info| info.addresses.as_slice())
    }

    pub async fn load_item(
        &self,
        server: &Server,
        item: GroupwareRef,
        fields: F,
    ) -> trc::Result<Result<LoadedItem, ItemError>> {
        self.prepare(server, fields).await?;
        if !fields.needs_content() {
            return Ok(self
                .load_many(server, &[item], fields)
                .await?
                .pop()
                .ok_or(ItemError::NotFound));
        }
        let (archive, content) = server
            .archive_and_field(
                self.account_id,
                F::KIND.collection(),
                item.document_id,
                F::KIND.content(),
            )
            .await
            .caused_by(trc::location!())?;
        let (Some(archive), Some(content)) = (archive, content) else {
            return Ok(Err(ItemError::NotFound));
        };
        Ok(
            match F::KIND.convert(
                &content,
                self.event_view(item.document_id),
                fields.event_parts(),
                &self.options(),
            ) {
                Some(converted) => Ok(LoadedItem {
                    item,
                    change_id: change_id_of(archive.version),
                    content: Some(converted.content),
                    occurrences: converted.occurrences,
                    mime: converted.mime,
                }),
                None => Err(ItemError::Unparsable),
            },
        )
    }

    pub async fn load_many(
        &self,
        server: &Server,
        items: &[GroupwareRef],
        fields: F,
    ) -> trc::Result<Vec<LoadedItem>> {
        self.prepare(server, fields).await?;
        let documents = items
            .iter()
            .map(|item| item.document_id)
            .collect::<RoaringBitmap>();
        let archives = VersionedArchives::read(
            server,
            self.account_id,
            F::KIND.collection(),
            F::KIND.content(),
            &documents,
            fields.needs_content() || fields.needs_kind(),
        )
        .await?;
        let options = self.options();
        let mut loaded = Vec::with_capacity(items.len());
        for item in items {
            let Some(change_id) = archives.change_id(item.document_id) else {
                continue;
            };
            let (content, occurrences, mime) = if fields.needs_content() {
                let Some(converted) = archives.content(item.document_id).and_then(|content| {
                    F::KIND.convert(
                        content,
                        self.event_view(item.document_id),
                        fields.event_parts(),
                        &options,
                    )
                }) else {
                    continue;
                };
                (
                    Some(converted.content),
                    converted.occurrences,
                    converted.mime,
                )
            } else if fields.needs_kind() {
                (
                    archives
                        .content(item.document_id)
                        .and_then(|content| F::KIND.kind_only(content)),
                    None,
                    None,
                )
            } else {
                (None, None, None)
            };
            loaded.push(LoadedItem {
                item: *item,
                change_id,
                content,
                occurrences,
                mime,
            });
        }
        Ok(loaded)
    }

    pub async fn scan(
        &self,
        server: &Server,
        container: u32,
        mut visit: impl FnMut(GroupwareRef, &PropBag) + Send + Sync,
    ) -> trc::Result<()> {
        let documents = self
            .members(container)
            .map(|item| item.document_id)
            .collect::<RoaringBitmap>();
        let options = self.options();
        server
            .archives(
                self.account_id,
                F::KIND.collection(),
                F::KIND.content(),
                &documents,
                |document_id, archive| {
                    if let Some(converted) = F::KIND.convert(
                        &archive,
                        self.event_view(document_id),
                        EventParts::NO_DATA,
                        &options,
                    ) {
                        visit(
                            GroupwareRef {
                                container,
                                document_id,
                            },
                            &converted.content.props,
                        );
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
    }

    pub fn options(&self) -> ConvertOptions<'_> {
        convert_options(&self.org)
    }

    pub async fn load_archive(
        &self,
        server: &Server,
        item: GroupwareRef,
    ) -> trc::Result<Result<(u64, Archive<ArchiveBytes>), ItemError>> {
        let (archive, content) = server
            .archive_and_field(
                self.account_id,
                F::KIND.collection(),
                item.document_id,
                F::KIND.content(),
            )
            .await
            .caused_by(trc::location!())?;
        Ok(match (archive, content) {
            (Some(archive), Some(content)) => Ok((change_id_of(archive.version), content)),
            _ => Err(ItemError::NotFound),
        })
    }

    pub fn unversioned_id(&self, item: GroupwareRef) -> ItemId<'static> {
        ItemId {
            id: self.encode(item),
            change_key: None,
        }
    }

    fn encode(&self, item: GroupwareRef) -> EwsIdStr<'static> {
        EwsIdStr::Minted(
            EwsObjectId::Item {
                account: self.account_id,
                kind: F::KIND.object_kind(),
                container: item.container,
                id: item.document_id,
            }
            .encode(),
        )
    }

    pub fn item_id(&self, item: GroupwareRef, change_id: u64) -> ItemId<'static> {
        ItemId {
            id: self.encode(item),
            change_key: Some(EwsIdStr::Minted(
                EwsChangeKey {
                    kind: F::KIND.object_kind(),
                    change_id,
                }
                .encode(),
            )),
        }
    }

    pub fn parent_id(&self, loaded: &LoadedItem) -> FolderId<'static> {
        folder_id(
            self.account_id,
            FolderNode::Stored(FolderRef {
                kind: F::KIND.folder_kind(),
                id: loaded.item.container,
            }),
            loaded.change_id,
        )
    }

    pub fn render<'c>(&self, loaded: &'c LoadedItem, fields: F) -> Item<'c> {
        fields.render(self, loaded)
    }
}

pub(crate) fn convert_options(org: &OrgDn) -> ConvertOptions<'_> {
    ConvertOptions {
        org_dn: org,
        store: None,
        body_preference: BodyPreference::Native,
        tnef: TnefPolicy::Decode,
        max_decoded: MAX_DECODED,
    }
}

pub(crate) fn decode_item(id: &BaseItemId<'_>) -> Option<(GroupwareKind, u32, GroupwareRef)> {
    match id {
        BaseItemId::Item(id) => decode_item_id(id),
        _ => None,
    }
}

pub(crate) fn decode_item_id(id: &ItemId<'_>) -> Option<(GroupwareKind, u32, GroupwareRef)> {
    match EwsObjectId::decode(id.id.as_str())? {
        EwsObjectId::Item {
            account,
            kind,
            container,
            id,
        } => Some((
            GroupwareKind::of_object(kind)?,
            account,
            GroupwareRef {
                container,
                document_id: id,
            },
        )),
        _ => None,
    }
}
