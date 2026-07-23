/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    config::{mailstore::spamfilter::IpResolver, smtp::resolver::Tlsa},
};
use mail_auth::{DnssecStatus, MX, RecordSet, Txt, common::resolver::ToFqdn};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub trait DnsCache {
    fn txt_add(&self, name: impl ToFqdn, value: impl Into<Txt>, valid_until: std::time::Instant);
    fn ipv4_add(&self, name: impl ToFqdn, value: Vec<Ipv4Addr>, valid_until: std::time::Instant);
    fn ipv6_add(&self, name: impl ToFqdn, value: Vec<Ipv6Addr>, valid_until: std::time::Instant);
    fn dnsbl_add(&self, name: &str, value: Vec<Ipv4Addr>, valid_until: std::time::Instant);
    fn ptr_add(&self, name: IpAddr, value: Vec<String>, valid_until: std::time::Instant);
    fn mx_add(
        &self,
        name: impl ToFqdn,
        value: Vec<MX>,
        dnssec_status: DnssecStatus,
        valid_until: std::time::Instant,
    );
    fn tlsa_add(&self, name: impl ToFqdn, value: Arc<Tlsa>, valid_until: std::time::Instant);
}

impl DnsCache for Server {
    fn txt_add(&self, name: impl ToFqdn, value: impl Into<Txt>, valid_until: std::time::Instant) {
        self.inner
            .cache
            .dns_txt
            .insert_with_expiry(name.to_fqdn(), value.into(), valid_until);
    }

    fn ipv4_add(&self, name: impl ToFqdn, value: Vec<Ipv4Addr>, valid_until: std::time::Instant) {
        self.inner.cache.dns_ipv4.insert_with_expiry(
            name.to_fqdn(),
            RecordSet {
                rrset: Arc::from(value),
                dnssec_status: DnssecStatus::Indeterminate,
            },
            valid_until,
        );
    }

    fn dnsbl_add(&self, name: &str, value: Vec<Ipv4Addr>, valid_until: std::time::Instant) {
        self.inner.cache.dns_rbl.insert_with_expiry(
            name.into(),
            Some(Arc::new(IpResolver::new(
                value
                    .iter()
                    .copied()
                    .next()
                    .unwrap_or(Ipv4Addr::BROADCAST)
                    .into(),
            ))),
            valid_until,
        );
    }

    fn ipv6_add(&self, name: impl ToFqdn, value: Vec<Ipv6Addr>, valid_until: std::time::Instant) {
        self.inner.cache.dns_ipv6.insert_with_expiry(
            name.to_fqdn(),
            RecordSet {
                rrset: Arc::from(value),
                dnssec_status: DnssecStatus::Indeterminate,
            },
            valid_until,
        );
    }

    fn ptr_add(&self, name: IpAddr, value: Vec<String>, valid_until: std::time::Instant) {
        self.inner.cache.dns_ptr.insert_with_expiry(
            name,
            RecordSet {
                rrset: Arc::from(value.into_iter().map(Into::into).collect::<Vec<_>>()),
                dnssec_status: DnssecStatus::Indeterminate,
            },
            valid_until,
        );
    }

    fn mx_add(
        &self,
        name: impl ToFqdn,
        value: Vec<MX>,
        dnssec_status: DnssecStatus,
        valid_until: std::time::Instant,
    ) {
        self.inner.cache.dns_mx.insert_with_expiry(
            name.to_fqdn(),
            RecordSet {
                rrset: Arc::from(value),
                dnssec_status,
            },
            valid_until,
        );
    }

    fn tlsa_add(&self, name: impl ToFqdn, value: Arc<Tlsa>, valid_until: std::time::Instant) {
        self.inner
            .cache
            .dns_tlsa
            .insert_with_expiry(name.to_fqdn(), value, valid_until);
    }
}
