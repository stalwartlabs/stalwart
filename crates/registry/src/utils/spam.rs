/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::{SpamDnsblServer, SpamRule};

impl SpamRule {
    pub fn enable(&self) -> bool {
        match self {
            SpamRule::Any(rule) => rule.enable,
            SpamRule::Url(rule) => rule.enable,
            SpamRule::Domain(rule) => rule.enable,
            SpamRule::Email(rule) => rule.enable,
            SpamRule::Ip(rule) => rule.enable,
            SpamRule::Header(rule) => rule.enable,
            SpamRule::Body(rule) => rule.enable,
        }
    }

    pub fn set_enable(&mut self, enable: bool) {
        match self {
            SpamRule::Any(rule) => rule.enable = enable,
            SpamRule::Url(rule) => rule.enable = enable,
            SpamRule::Domain(rule) => rule.enable = enable,
            SpamRule::Email(rule) => rule.enable = enable,
            SpamRule::Ip(rule) => rule.enable = enable,
            SpamRule::Header(rule) => rule.enable = enable,
            SpamRule::Body(rule) => rule.enable = enable,
        }
    }
}

impl SpamDnsblServer {
    pub fn enable(&self) -> bool {
        match self {
            SpamDnsblServer::Any(server) => server.enable,
            SpamDnsblServer::Url(server) => server.enable,
            SpamDnsblServer::Domain(server) => server.enable,
            SpamDnsblServer::Email(server) => server.enable,
            SpamDnsblServer::Ip(server) => server.enable,
            SpamDnsblServer::Header(server) => server.enable,
            SpamDnsblServer::Body(server) => server.enable,
        }
    }

    pub fn set_enable(&mut self, enable: bool) {
        match self {
            SpamDnsblServer::Any(server) => server.enable = enable,
            SpamDnsblServer::Url(server) => server.enable = enable,
            SpamDnsblServer::Domain(server) => server.enable = enable,
            SpamDnsblServer::Email(server) => server.enable = enable,
            SpamDnsblServer::Ip(server) => server.enable = enable,
            SpamDnsblServer::Header(server) => server.enable = enable,
            SpamDnsblServer::Body(server) => server.enable = enable,
        }
    }
}
