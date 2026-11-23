/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderCounts, FolderFieldSet, FolderRenderer, FolderSelector, props::FolderProp,
    removed_folder_status, resolve_folder,
};
use crate::{
    ews::{
        context::EwsContext,
        filter::Filter,
        reply::{RESPONSE_CAPACITY, ews_response},
    },
    folders::{FolderEntry, FolderTree},
};
use common::Server;
use exchange_proto::ews::{
    MessageResult, Operation, Paging, Status,
    requests::{find::FindFolder, folder::GetFolder},
    responses::folder::{FindFolderMessage, FindFolderRoot, FolderInfoMessage},
    schema::{FolderQueryTraversal, IndexBasePoint},
    types::view::FolderView,
};
use http_proto::HttpResponse;

const MAX_PAGE: usize = 1000;

pub(crate) async fn get_folder(
    server: &Server,
    ctx: &EwsContext,
    request: &GetFolder<'_>,
) -> trc::Result<HttpResponse> {
    let tree = ctx.folder_tree(server).await?;
    let mut resolved = Vec::with_capacity(request.folder_ids.len());
    for id in &request.folder_ids {
        resolved.push(
            match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
                Err(status) => Err(removed_folder_status(ctx, &tree, id).unwrap_or(status)),
                found => found,
            },
        );
    }
    let fields = FolderFieldSet::from_shape(&request.shape);
    let renderer = FolderRenderer {
        tree: &tree,
        access: &ctx.access,
        account_id: ctx.account.account_id,
        fields,
        counts: FolderCounts::load(
            server,
            ctx,
            fields,
            resolved
                .iter()
                .filter_map(|entry| entry.as_ref().ok().copied()),
        )
        .await?,
    };

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::GetFolder);
    for entry in resolved {
        messages.message(&match entry {
            Ok(entry) => MessageResult {
                status: Status::SUCCESS,
                body: Some(FolderInfoMessage {
                    folders: vec![renderer.render(entry)],
                }),
            },
            Err(status) => MessageResult { status, body: None },
        });
    }
    messages.finish();
    Ok(ews_response(out))
}

pub(crate) async fn find_folder(
    server: &Server,
    ctx: &EwsContext,
    request: &FindFolder<'_>,
) -> trc::Result<HttpResponse> {
    let tree = ctx.folder_tree(server).await?;
    let mut parents = Vec::with_capacity(request.parent_folder_ids.len());
    for id in &request.parent_folder_ids {
        parents.push(resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await?);
    }
    let filter = request
        .restriction
        .as_ref()
        .map(Filter::<FolderProp>::new)
        .transpose();
    let filter = match filter {
        Ok(filter) => filter,
        Err(unsupported) => {
            let status = unsupported.status();
            for parent in &mut parents {
                if parent.is_ok() {
                    *parent = Err(status.clone());
                }
            }
            None
        }
    };
    let fields = FolderFieldSet::from_shape(&request.shape);
    let traversal = request.traversal;
    let filter_counts = filter
        .as_ref()
        .is_some_and(|filter| filter.props().any(FolderProp::needs_counts));
    let mut renderer = FolderRenderer {
        tree: &tree,
        access: &ctx.access,
        account_id: ctx.account.account_id,
        fields,
        counts: if filter_counts {
            FolderCounts::load(
                server,
                ctx,
                fields.with_counts(),
                parents
                    .iter()
                    .filter_map(|parent| parent.as_ref().ok().copied())
                    .flat_map(|parent| scope(&tree, parent, traversal)),
            )
            .await?
        } else {
            FolderCounts::default()
        },
    };
    let matches = parents
        .iter()
        .map(|parent| match parent {
            Ok(parent) => scope(&tree, parent, traversal)
                .filter(|entry| {
                    filter
                        .as_ref()
                        .is_none_or(|filter| filter.matches(&|prop| renderer.value(entry, prop)))
                })
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        })
        .collect::<Vec<_>>();
    let windows = parents
        .iter()
        .zip(&matches)
        .map(|(parent, matches)| match parent {
            Ok(_) => Window::new(request.view.as_ref(), matches.len()),
            Err(_) => Window::new(None, 0),
        })
        .collect::<Vec<_>>();
    if !filter_counts {
        let mut visible = Vec::with_capacity(windows.iter().map(|window| window.count).sum());
        for (matches, window) in matches.iter().zip(&windows) {
            visible.extend_from_slice(window.slice(matches));
        }
        renderer.counts = FolderCounts::load(server, ctx, fields, visible.iter().copied()).await?;
    }

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::FindFolder);
    for ((parent, window), matches) in parents.into_iter().zip(windows).zip(&matches) {
        let result = match parent {
            Ok(_) => MessageResult {
                status: Status::SUCCESS,
                body: Some(FindFolderMessage {
                    root: Some(FindFolderRoot {
                        folders: window
                            .slice(matches)
                            .iter()
                            .map(|entry| renderer.render(entry))
                            .collect(),
                        paging: window.paging,
                    }),
                }),
            },
            Err(status) => MessageResult { status, body: None },
        };
        messages.message(&result);
    }
    messages.finish();
    Ok(ews_response(out))
}

fn scope<'t>(
    tree: &'t FolderTree,
    parent: &FolderEntry,
    traversal: FolderQueryTraversal,
) -> impl Iterator<Item = &'t FolderEntry> + Clone + 't {
    let node = parent.node;
    tree.descendants(node).filter(move |entry| match traversal {
        FolderQueryTraversal::Shallow => entry.parent == Some(node),
        FolderQueryTraversal::Deep => true,
        FolderQueryTraversal::SoftDeleted => false,
    })
}

pub(crate) struct Window {
    pub offset: usize,
    pub count: usize,
    pub paging: Paging,
}

impl Window {
    pub fn slice<'e, T>(&self, items: &'e [T]) -> &'e [T] {
        items
            .get(self.offset..)
            .and_then(|items| items.get(..self.count))
            .unwrap_or_default()
    }

    pub fn new(view: Option<&FolderView>, total: usize) -> Self {
        let total_i32 = i32::try_from(total).unwrap_or(i32::MAX);
        match view {
            None => {
                let count = total.min(MAX_PAGE);
                Window {
                    offset: 0,
                    count,
                    paging: Paging {
                        indexed_paging_offset: Some(i32::try_from(count).unwrap_or(i32::MAX)),
                        includes_last_item_in_range: Some(count == total),
                        total_items_in_view: total_i32,
                        numerator_offset: None,
                        absolute_denominator: None,
                    },
                }
            }
            Some(FolderView::Indexed(view)) => {
                let requested = usize::try_from(view.offset.max(0)).unwrap_or_default();
                let max = max_entries(view.max_entries);
                let (offset, count) = match view.base_point {
                    IndexBasePoint::Beginning => {
                        let offset = requested.min(total);
                        (offset, max.min(total - offset))
                    }
                    IndexBasePoint::End => {
                        let end = total.saturating_sub(requested);
                        let count = max.min(end);
                        (end - count, count)
                    }
                };
                Window {
                    offset,
                    count,
                    paging: Paging {
                        indexed_paging_offset: Some(
                            i32::try_from(offset + count).unwrap_or(i32::MAX),
                        ),
                        includes_last_item_in_range: Some(offset + count >= total),
                        total_items_in_view: total_i32,
                        numerator_offset: None,
                        absolute_denominator: None,
                    },
                }
            }
            Some(FolderView::Fractional(view)) => {
                let numerator = u64::try_from(view.numerator.max(0)).unwrap_or_default();
                let denominator = u64::try_from(view.denominator.max(1)).unwrap_or(1);
                let offset = usize::try_from(
                    (total as u64)
                        .saturating_mul(numerator)
                        .checked_div(denominator)
                        .unwrap_or_default(),
                )
                .unwrap_or(total)
                .min(total);
                let count = max_entries(view.max_entries).min(total - offset);
                Window {
                    offset,
                    count,
                    paging: Paging {
                        numerator_offset: Some(i32::try_from(offset + count).unwrap_or(i32::MAX)),
                        absolute_denominator: Some(total_i32),
                        includes_last_item_in_range: Some(offset + count >= total),
                        total_items_in_view: total_i32,
                        indexed_paging_offset: None,
                    },
                }
            }
        }
    }
}

pub(crate) fn max_entries(requested: Option<u32>) -> usize {
    requested.map_or(MAX_PAGE, |max| {
        usize::try_from(max).unwrap_or(MAX_PAGE).min(MAX_PAGE)
    })
}
