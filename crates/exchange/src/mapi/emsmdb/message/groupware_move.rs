/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::edit::GroupwareContainer;
use crate::{
    groupware_move::{GroupwareMover, Transfer},
    groupware_write::WriteFailure,
    mapi::emsmdb::execute::{RopContext, RopError},
};

pub(in crate::mapi::emsmdb) use crate::groupware_move::{GroupwareMove, GroupwareRoute};

impl GroupwareRoute {
    pub(in crate::mapi::emsmdb) fn between(
        from: GroupwareContainer,
        to: GroupwareContainer,
    ) -> Option<Self> {
        match (from, to) {
            (GroupwareContainer::AddressBook(from), GroupwareContainer::AddressBook(to))
                if from != to =>
            {
                Some(GroupwareRoute::Cards { from, to })
            }
            (GroupwareContainer::Calendar(from), GroupwareContainer::Calendar(to))
                if from != to =>
            {
                Some(GroupwareRoute::Events { from, to })
            }
            _ => None,
        }
    }
}

impl RopContext<'_, '_> {
    pub(in crate::mapi::emsmdb) async fn move_groupware(
        &mut self,
        account_id: u32,
        route: GroupwareRoute,
        documents: &[u32],
    ) -> Result<Vec<GroupwareMove>, RopError> {
        let refused = || vec![GroupwareMove::Refused(WriteFailure::Forbidden); documents.len()];
        if !self.types.contains(route.data_type()) {
            return Ok(refused());
        }
        let Some(mover) = GroupwareMover::open(
            self.request.server,
            self.request.access_token,
            account_id,
            route,
            Transfer::Move,
        )
        .await?
        else {
            return Ok(refused());
        };
        let mut outcomes = Vec::with_capacity(documents.len());
        let result: trc::Result<()> = async {
            for &document_id in documents {
                outcomes.push(mover.move_item(document_id).await?);
            }
            Ok(())
        }
        .await;
        self.invalidate_mailbox();
        result?;
        Ok(outcomes)
    }
}
