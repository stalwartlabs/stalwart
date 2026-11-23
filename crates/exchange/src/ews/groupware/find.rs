/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    GroupwareFields, Selection,
    items::{GroupwareItems, GroupwareRef},
};
use crate::ews::{folder::get::Window, item::ItemError};
use common::Server;
use exchange_proto::ews::{
    MessageResult, Status,
    envelope::MessagesWriter,
    requests::find::FindItem,
    responses::item::FindItemMessage,
    types::{
        value::{M, T},
        view::FolderView,
    },
};
use store::roaring::RoaringBitmap;

pub(crate) async fn find_items<F: GroupwareFields>(
    server: &Server,
    items: &Result<GroupwareItems<F>, ItemError>,
    request: &FindItem<'_>,
    container: u32,
    view: Option<&FolderView>,
    messages: &mut MessagesWriter<'_>,
) -> trc::Result<()> {
    let items = match items {
        Ok(items) => items,
        Err(err) => {
            messages.message(&MessageResult::<FindItemMessage> {
                status: err.status(),
                body: None,
            });
            return Ok(());
        }
    };
    let candidates = match select(server, items, request, container).await? {
        Ok(candidates) => candidates,
        Err(status) => {
            messages.message(&MessageResult::<FindItemMessage> { status, body: None });
            return Ok(());
        }
    };
    let fields = F::from_shape(&request.shape).for_list();
    let window = Window::new(view, candidates.len());
    let loaded = items
        .load_many(server, window.slice(&candidates), fields)
        .await?;
    let mut body = messages.begin_message(&Status::SUCCESS);
    let w = body.writer();
    w.start(M, "RootFolder");
    window.paging.write_attrs(w);
    w.start(T, "Items");
    for loaded in &loaded {
        items.render(loaded, fields).write(w);
    }
    w.end(T, "Items");
    w.end(M, "RootFolder");
    body.finish();
    Ok(())
}

async fn select<F: GroupwareFields>(
    server: &Server,
    items: &GroupwareItems<F>,
    request: &FindItem<'_>,
    container: u32,
) -> trc::Result<Result<Vec<GroupwareRef>, Status<'static>>> {
    let plan = match Selection::<F::Prop>::new(request) {
        Selection::Empty => return Ok(Ok(Vec::new())),
        Selection::Members => {
            return Ok(Ok(items
                .listed(server, container, &RoaringBitmap::new())
                .await?
                .iter()
                .map(|document_id| GroupwareRef {
                    container,
                    document_id,
                })
                .collect()));
        }
        Selection::Scan(plan) => plan,
        Selection::Invalid(status) => return Ok(Err(status)),
    };
    let mut candidates = Vec::new();
    items
        .scan(server, container, |item, props| {
            candidates.extend(plan.candidate(item, item.document_id, |prop| {
                F::value(items, item.document_id, prop, props)
            }));
        })
        .await?;
    plan.sort(&mut candidates);
    Ok(Ok(candidates
        .into_iter()
        .map(|candidate| candidate.item)
        .collect()))
}
