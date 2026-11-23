/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{fields::ItemFieldSet, render::MailView};
use crate::mapi::nspi::{
    page::AbKind,
    scan::{directory_ref_from_email, visible_ref},
};
use common::{Server, auth::AccessToken};
use email::message::metadata::{AddressHeader, Addresses};
use exchange_proto::ews::{
    schema::MailboxType,
    types::{address::EmailAddress, item::Item},
};
use std::borrow::Cow;

const MAX_RESOLVED: usize = 64;
const MAX_DOMAINS: usize = 16;

#[derive(Default)]
pub(crate) struct RecipientNames {
    addresses: Vec<(Box<str>, Option<Resolved>)>,
    domains: Domains,
}

#[derive(Default)]
struct Domains(Vec<(Box<str>, bool)>);

struct Resolved {
    name: Box<str>,
    mailbox_type: MailboxType,
}

impl RecipientNames {
    pub(crate) async fn apply(
        &mut self,
        server: &Server,
        caller: &AccessToken,
        item: &mut Item<'_>,
        view: &MailView<'_>,
        requested: ItemFieldSet,
    ) -> trc::Result<()> {
        if let Some(message) = item.message_fields_mut() {
            for recipient in [&mut message.sender, &mut message.from]
                .into_iter()
                .flatten()
            {
                self.resolve(server, caller, &mut recipient.0).await?;
            }
            for list in [
                &mut message.to_recipients,
                &mut message.cc_recipients,
                &mut message.bcc_recipients,
                &mut message.reply_to,
            ]
            .into_iter()
            .flatten()
            {
                for recipient in &mut list.0 {
                    self.resolve(server, caller, recipient).await?;
                }
            }
        }
        if requested.has(ItemFieldSet::DISPLAY_TO)
            && let Some(addresses) = view.addresses(AddressHeader::To)
        {
            let names = self.display_names(server, caller, addresses).await?;
            item.fields_mut().display_to = Some(names);
        }
        if requested.has(ItemFieldSet::DISPLAY_CC)
            && let Some(addresses) = view.addresses(AddressHeader::Cc)
        {
            let names = self.display_names(server, caller, addresses).await?;
            item.fields_mut().display_cc = Some(names);
        }
        Ok(())
    }

    async fn resolve(
        &mut self,
        server: &Server,
        caller: &AccessToken,
        recipient: &mut EmailAddress<'_>,
    ) -> trc::Result<()> {
        let Some(address) = recipient.email_address.as_deref() else {
            return Ok(());
        };
        let Some(resolved) = self.lookup(server, caller, address).await? else {
            return Ok(());
        };
        if is_unnamed(recipient.name.as_deref(), address) {
            recipient.name = Some(Cow::Owned(resolved.name.to_string()));
        }
        recipient.mailbox_type = Some(resolved.mailbox_type);
        Ok(())
    }

    async fn display_names(
        &mut self,
        server: &Server,
        caller: &AccessToken,
        addresses: Addresses<'_>,
    ) -> trc::Result<Cow<'static, str>> {
        let mut out = String::new();
        for mailbox in addresses.mailboxes() {
            let header_name = match mailbox.address {
                Some(address) if is_unnamed(mailbox.name, address) => None,
                _ => mailbox.name.filter(|name| !name.is_empty()),
            };
            let resolved = match (header_name, mailbox.address) {
                (None, Some(address)) => self
                    .lookup(server, caller, address)
                    .await?
                    .map(|resolved| &*resolved.name),
                _ => None,
            };
            let Some(name) = header_name.or(resolved).or(mailbox.address) else {
                continue;
            };
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(name);
        }
        Ok(Cow::Owned(out))
    }

    async fn lookup(
        &mut self,
        server: &Server,
        caller: &AccessToken,
        address: &str,
    ) -> trc::Result<Option<&Resolved>> {
        let known = self
            .addresses
            .iter()
            .position(|(known, _)| known.eq_ignore_ascii_case(address));
        let index = match known {
            Some(index) => index,
            None if self.addresses.len() < MAX_RESOLVED => {
                let Some((_, domain)) = address.rsplit_once('@') else {
                    return Ok(None);
                };
                if !self.domains.is_local(server, domain).await? {
                    return Ok(None);
                }
                let resolved = match directory_ref_from_email(server, address).await? {
                    Some(principal) => {
                        visible_ref(server, caller, principal)
                            .await?
                            .map(|key| Resolved {
                                name: Box::from(key.display_name()),
                                mailbox_type: match key.kind() {
                                    AbKind::List => MailboxType::PublicDL,
                                    AbKind::User => MailboxType::Mailbox,
                                },
                            })
                    }
                    None => None,
                };
                self.addresses.push((Box::from(address), resolved));
                self.addresses.len() - 1
            }
            None => return Ok(None),
        };
        Ok(self
            .addresses
            .get(index)
            .and_then(|(_, resolved)| resolved.as_ref()))
    }
}

impl Domains {
    async fn is_local(&mut self, server: &Server, domain: &str) -> trc::Result<bool> {
        if let Some(local) = self.known(domain) {
            return Ok(local);
        }
        let local = server.domain(domain).await?.is_some();
        self.0.push((Box::from(domain), local));
        Ok(local)
    }

    fn known(&self, domain: &str) -> Option<bool> {
        self.0
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(domain))
            .map(|(_, local)| *local)
            .or_else(|| (self.0.len() >= MAX_DOMAINS).then_some(false))
    }
}

fn is_unnamed(name: Option<&str>, address: &str) -> bool {
    name.is_none_or(|name| name.is_empty() || name.eq_ignore_ascii_case(address))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/item/recipients/tests.rs"]
mod tests;
