/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::{ArchivedMessage, FROM_UNAUTHENTICATED, FROM_UNAUTHENTICATED_DMARC, Message};
use common::Server;
use utils::DomainPart;

impl Message {
    pub fn has_tenant(&self, tenant_id: u32) -> bool {
        self.tenant_ids.binary_search(&tenant_id).is_ok()
    }

    pub(crate) async fn assign_tenants(&mut self, server: &Server, span_id: u64) {
        if !server.is_enterprise_edition() {
            return;
        }

        self.tenant_ids = match self.owner_tenant(server).await {
            Ok(tenant_id) => tenant_id.into_iter().collect(),
            Err(err) => {
                trc::error!(
                    err.span_id(span_id)
                        .caused_by(trc::location!())
                        .details("Failed to resolve the tenant of a queued message")
                );
                Box::default()
            }
        };
    }

    async fn owner_tenant(&self, server: &Server) -> trc::Result<Option<u32>> {
        if self.flags & (FROM_UNAUTHENTICATED | FROM_UNAUTHENTICATED_DMARC) == 0 {
            let domain = self.return_path.domain_part();
            if !domain.is_empty()
                && let Some(tenant_id) = server
                    .domain(domain)
                    .await?
                    .and_then(|domain| domain.id_tenant)
            {
                return Ok(Some(tenant_id));
            }
        }

        let mut owner = None;
        let mut last_domain = None;
        for domain in self.recipients.iter().map(|rcpt| rcpt.domain_part()) {
            if last_domain.replace(domain) == Some(domain) {
                continue;
            }
            let tenant_id = server
                .domain(domain)
                .await?
                .and_then(|domain| domain.id_tenant);
            match (owner, tenant_id) {
                (_, None) => {}
                (None, tenant_id) => owner = tenant_id,
                (Some(owner_id), Some(tenant_id)) if owner_id == tenant_id => {}
                (Some(_), Some(_)) => return Ok(None),
            }
        }
        Ok(owner)
    }
}

impl ArchivedMessage {
    pub fn has_tenant(&self, tenant_id: u32) -> bool {
        self.tenant_ids.iter().any(|id| id.to_native() == tenant_id)
    }
}
