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

        let return_path = (self.flags & (FROM_UNAUTHENTICATED | FROM_UNAUTHENTICATED_DMARC) == 0)
            .then(|| self.return_path.domain_part())
            .filter(|domain| !domain.is_empty());
        let mut tenant_ids = Vec::new();
        let mut last_domain = None;
        for domain in return_path
            .into_iter()
            .chain(self.recipients.iter().map(|rcpt| rcpt.domain_part()))
        {
            if last_domain == Some(domain) {
                continue;
            }
            last_domain = Some(domain);
            match server.domain(domain).await {
                Ok(Some(domain)) => {
                    if let Some(tenant_id) = domain.id_tenant
                        && !tenant_ids.contains(&tenant_id)
                    {
                        tenant_ids.push(tenant_id);
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    trc::error!(
                        err.span_id(span_id)
                            .caused_by(trc::location!())
                            .details("Failed to resolve the tenant of a queued message")
                    );
                }
            }
        }
        tenant_ids.sort_unstable();
        self.tenant_ids = tenant_ids.into_boxed_slice();
    }
}

impl ArchivedMessage {
    pub fn has_tenant(&self, tenant_id: u32) -> bool {
        self.tenant_ids.iter().any(|id| id.to_native() == tenant_id)
    }
}
