/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::expr::{
    Constant, ExpressionItem, Variable,
    if_block::{BootstrapExprExt, IfBlock},
};
use crypto::{HeaderProtection, KeyKind};
use registry::schema::{
    enums::{
        ExpressionConstant, HeaderProtection as RegistryHeaderProtection, KeyTrust, PublicKeyKind,
    },
    prelude::{ObjectType, Property},
    structs::Encryption,
};
use reqwest::Proxy;
use std::{sync::Arc, time::Duration};
use store::registry::bootstrap::Bootstrap;
use utils::{
    http::http_client_builder,
    outbound::{OutboundClient, OutboundPolicy, Redirects},
};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PKI_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_MAX_REDIRECTS: usize = 3;

pub struct GatewayConfig {
    pub outbound: IfBlock,
    pub min_trust: IfBlock,
    pub outbound_enabled: bool,
    pub harvest: IfBlock,
    pub harvest_enabled: bool,
    pub methods: Box<[KeyKind]>,
    pub header_protection: HeaderProtection,
    pub encrypt_signed: bool,
    pub hkp_servers: Box<[Box<str>]>,
    pub source_timeout: Duration,
    pub key_refresh_interval: Duration,
    pub negative_ttl: Duration,
    pub use_bundled_roots: bool,
    pub max_crl_size: usize,
    pub http: OutboundClient,
    pub pki_http: OutboundClient,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GatewayMode {
    Disable,
    Opportunistic,
    Required,
}

pub trait GatewayHeaderProtection {
    fn to_gateway(self) -> HeaderProtection;
}

pub trait KeyTrustRank {
    fn rank(self) -> u8;
}

trait ConstantBlock {
    fn is_constant(&self, constant: ExpressionConstant) -> bool;

    fn is_false(&self) -> bool;
}

impl GatewayConfig {
    pub fn parse(bp: &mut Bootstrap, encryption: &Encryption) -> Option<Arc<Self>> {
        if !encryption.gateway_enable {
            return None;
        }
        let id = ObjectType::Encryption.singleton();
        let mut outbound = bp.compile_expr(id, &encryption.ctx_gateway_outbound());
        if outbound.is_empty() {
            bp.invalid_property(
                id,
                Property::GatewayOutbound,
                "Empty outbound policy: recipients are rejected until it is fixed",
            );
            outbound = IfBlock::empty(id, Property::GatewayOutbound);
        }
        let outbound_enabled = !outbound.is_constant(ExpressionConstant::Disable);
        let harvest = bp.compile_expr(id, &encryption.ctx_harvest_keys());
        let harvest_enabled = !harvest.is_false();
        let proxy = encryption.discovery_proxy.as_deref().map(Proxy::all);
        let proxy_is_valid = proxy.as_ref().is_none_or(Result::is_ok);
        if let Some(Err(err)) = &proxy {
            bp.invalid_property(id, Property::DiscoveryProxy, err.to_string());
        }
        let proxy = proxy.and_then(Result::ok);
        if let Some(server) = encryption
            .hkp_servers
            .iter()
            .find(|url| !url.trim().starts_with("https://") && !url.trim().starts_with("hkps://"))
        {
            bp.invalid_property(
                id,
                Property::HkpServers,
                format!("Keyserver {server} must use https or hkps."),
            );
        }

        Some(Arc::new(GatewayConfig {
            min_trust: bp.compile_expr(id, &encryption.ctx_gateway_min_trust()),
            outbound,
            outbound_enabled,
            harvest,
            harvest_enabled,
            methods: encryption
                .gateway_methods
                .iter()
                .map(|kind| match kind {
                    PublicKeyKind::OpenPgp => KeyKind::OpenPgp,
                    PublicKeyKind::Smime => KeyKind::Smime,
                })
                .collect(),
            header_protection: encryption.gateway_header_protection.to_gateway(),
            encrypt_signed: encryption.gateway_encrypt_signed,
            hkp_servers: encryption
                .hkp_servers
                .iter()
                .map(|url| Box::from(url.trim()))
                .collect(),
            source_timeout: encryption.source_timeout.into_inner(),
            key_refresh_interval: encryption.key_refresh_interval.into_inner(),
            negative_ttl: encryption.negative_cache_ttl.into_inner(),
            use_bundled_roots: encryption.use_bundled_roots,
            max_crl_size: encryption.max_crl_size as usize,
            http: Self::http_client(
                encryption.source_timeout.into_inner(),
                OutboundPolicy::PublicOnly,
                proxy.as_ref(),
                proxy_is_valid,
            ),
            pki_http: Self::http_client(
                PKI_FETCH_TIMEOUT,
                OutboundPolicy::PublicSignedData,
                proxy.as_ref(),
                proxy_is_valid,
            ),
        }))
    }

    fn http_client(
        timeout: Duration,
        policy: OutboundPolicy,
        proxy: Option<&Proxy>,
        proxy_is_valid: bool,
    ) -> OutboundClient {
        if !proxy_is_valid {
            return OutboundClient::default();
        }
        let builder = http_client_builder(cfg!(stalwart_tests))
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(timeout);
        let redirects = Redirects::Limited(HTTP_MAX_REDIRECTS);
        match proxy {
            Some(proxy) => OutboundClient::with_proxy(builder, policy, redirects, proxy.clone()),
            None => OutboundClient::new(builder, policy, redirects),
        }
    }
}

impl ConstantBlock for IfBlock {
    fn is_constant(&self, constant: ExpressionConstant) -> bool {
        self.if_then.is_empty()
            && matches!(
                &*self.default.items,
                [ExpressionItem::Constant(Constant::Static(value))] if *value == constant
            )
    }

    fn is_false(&self) -> bool {
        self.if_then.is_empty()
            && (self.default.items.is_empty()
                || matches!(
                    &*self.default.items,
                    [ExpressionItem::Constant(Constant::Integer(0))]
                ))
    }
}

impl GatewayHeaderProtection for RegistryHeaderProtection {
    fn to_gateway(self) -> HeaderProtection {
        match self {
            RegistryHeaderProtection::None => HeaderProtection::None,
            RegistryHeaderProtection::NoConfidentiality => HeaderProtection::Full,
            RegistryHeaderProtection::Baseline => HeaderProtection::Baseline,
        }
    }
}

impl KeyTrustRank for KeyTrust {
    fn rank(self) -> u8 {
        match self {
            KeyTrust::Manual => 4,
            KeyTrust::Verified => 3,
            KeyTrust::Discovered => 2,
            KeyTrust::Harvested => 1,
            KeyTrust::Unverified => 0,
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for GatewayMode {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, ()> {
        match value {
            Variable::Constant(ExpressionConstant::Disable) => Ok(GatewayMode::Disable),
            Variable::Constant(ExpressionConstant::Opportunistic) => Ok(GatewayMode::Opportunistic),
            Variable::Constant(ExpressionConstant::Required) => Ok(GatewayMode::Required),
            _ => Err(()),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for GatewayMinTrust {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, ()> {
        match value {
            Variable::Constant(ExpressionConstant::Manual) => Ok(GatewayMinTrust(KeyTrust::Manual)),
            Variable::Constant(ExpressionConstant::Verified) => {
                Ok(GatewayMinTrust(KeyTrust::Verified))
            }
            Variable::Constant(ExpressionConstant::Discovered) => {
                Ok(GatewayMinTrust(KeyTrust::Discovered))
            }
            Variable::Constant(ExpressionConstant::Harvested) => {
                Ok(GatewayMinTrust(KeyTrust::Harvested))
            }
            Variable::Constant(ExpressionConstant::Unverified) => {
                Ok(GatewayMinTrust(KeyTrust::Unverified))
            }
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy)]
pub struct GatewayMinTrust(pub KeyTrust);
