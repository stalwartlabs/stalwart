/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use reqwest::{
    Client, ClientBuilder, Method, Proxy, RequestBuilder, Url,
    dns::{Addrs, Name, Resolve, Resolving},
    redirect::{Action, Attempt, Policy},
};
use std::{
    fmt::{self, Display},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
};
use url::Host;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundPolicy {
    Trusted,
    PublicOnly,
    PublicSignedData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirects {
    None,
    Limited(usize),
    SameOrganization(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundError {
    InvalidUrl,
    InsecureScheme,
    Credentials,
    MissingHost,
    NonPublicHost,
    NonPublicAddress,
    TooManyRedirects,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectDecision {
    Follow,
    Stop,
    Reject(OutboundError),
}

#[derive(Debug, Clone)]
pub struct OutboundClient {
    client: Option<Client>,
    policy: OutboundPolicy,
}

impl Default for OutboundClient {
    fn default() -> Self {
        OutboundClient {
            client: None,
            policy: OutboundPolicy::PublicOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PublicResolver;

#[cfg(all(stalwart_tests, not(test)))]
pub static TEST_HTTPS_ORIGIN: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

impl OutboundPolicy {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn for_tenant<T>(tenant_id: Option<T>) -> Self {
        if tenant_id.is_some() {
            OutboundPolicy::PublicOnly
        } else {
            OutboundPolicy::Trusted
        }
    }
    // SPDX-SnippetEnd

    pub fn parse_url(self, url: &str) -> Result<Url, OutboundError> {
        let url = Url::parse(url).map_err(|_| OutboundError::InvalidUrl)?;
        self.check_url(&url).map(|_| url)
    }

    pub fn check_url(self, url: &Url) -> Result<(), OutboundError> {
        if self == OutboundPolicy::Trusted {
            Ok(())
        } else if !self.permits_scheme(url.scheme()) {
            Err(OutboundError::InsecureScheme)
        } else if !url.username().is_empty() || url.password().is_some() {
            Err(OutboundError::Credentials)
        } else {
            match url.host() {
                Some(Host::Domain(domain)) => self.check_domain(domain),
                Some(Host::Ipv4(ip)) => self.check_ip(IpAddr::V4(ip)),
                Some(Host::Ipv6(ip)) => self.check_ip(IpAddr::V6(ip)),
                None => Err(OutboundError::MissingHost),
            }
        }
    }

    fn permits_scheme(self, scheme: &str) -> bool {
        match self {
            OutboundPolicy::Trusted => true,
            OutboundPolicy::PublicOnly => scheme == "https",
            OutboundPolicy::PublicSignedData => matches!(scheme, "https" | "http"),
        }
    }

    pub fn check_domain(self, domain: &str) -> Result<(), OutboundError> {
        if self == OutboundPolicy::Trusted || is_public_domain(domain) {
            Ok(())
        } else {
            Err(OutboundError::NonPublicHost)
        }
    }

    pub fn check_ip(self, ip: IpAddr) -> Result<(), OutboundError> {
        if self == OutboundPolicy::Trusted || is_permitted_ip(ip) {
            Ok(())
        } else {
            Err(OutboundError::NonPublicAddress)
        }
    }
}

impl Redirects {
    pub fn decide(self, policy: OutboundPolicy, next: &Url, previous: &[Url]) -> RedirectDecision {
        let (max_redirects, same_organization) = match self {
            Redirects::None => return RedirectDecision::Stop,
            Redirects::Limited(max_redirects) => (max_redirects, false),
            Redirects::SameOrganization(max_redirects) => (max_redirects, true),
        };

        if same_organization
            && !previous
                .last()
                .is_some_and(|previous| is_same_organization(previous, next))
        {
            RedirectDecision::Stop
        } else if previous.len() > max_redirects {
            RedirectDecision::Reject(OutboundError::TooManyRedirects)
        } else if let Err(err) = policy.check_url(next) {
            RedirectDecision::Reject(err)
        } else {
            RedirectDecision::Follow
        }
    }

    fn into_policy(self, policy: OutboundPolicy) -> Policy {
        match (self, policy) {
            (Redirects::None, _) => Policy::none(),
            (Redirects::Limited(max_redirects), OutboundPolicy::Trusted) => {
                Policy::limited(max_redirects)
            }
            (redirects, policy) => {
                Policy::custom(move |attempt| redirects.attempt(policy, attempt))
            }
        }
    }

    fn attempt(self, policy: OutboundPolicy, attempt: Attempt<'_>) -> Action {
        match self.decide(policy, attempt.url(), attempt.previous()) {
            RedirectDecision::Follow => attempt.follow(),
            RedirectDecision::Stop => attempt.stop(),
            RedirectDecision::Reject(err) => attempt.error(err),
        }
    }
}

impl OutboundClient {
    pub fn new(builder: ClientBuilder, policy: OutboundPolicy, redirects: Redirects) -> Self {
        let builder = builder.redirect(redirects.into_policy(policy));
        let builder = match policy {
            OutboundPolicy::Trusted => builder,
            OutboundPolicy::PublicOnly | OutboundPolicy::PublicSignedData => {
                builder.no_proxy().dns_resolver(PublicResolver)
            }
        };
        Self::build(builder, policy)
    }

    pub fn with_proxy(
        builder: ClientBuilder,
        policy: OutboundPolicy,
        redirects: Redirects,
        proxy: Proxy,
    ) -> Self {
        Self::build(
            builder
                .redirect(redirects.into_policy(policy))
                .no_proxy()
                .proxy(proxy),
            policy,
        )
    }

    fn build(builder: ClientBuilder, policy: OutboundPolicy) -> Self {
        let client = builder
            .build()
            .map_err(|err| {
                trc::event!(
                    Http(trc::HttpEvent::Error),
                    Details = "Failed to build outbound HTTP client",
                    Reason = err.to_string(),
                );
            })
            .ok();

        OutboundClient { client, policy }
    }

    pub fn request(&self, method: Method, url: &str) -> Result<RequestBuilder, OutboundError> {
        #[cfg(all(stalwart_tests, not(test)))]
        if let Ok(origin) = TEST_HTTPS_ORIGIN.read()
            && let Some(origin) = origin.as_deref()
            && self
                .policy
                .parse_url(url)
                .is_ok_and(|url| url.host_str() != Some("localhost"))
            && let Some(path) = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
        {
            return self.request_url(method, Url::parse(&format!("{origin}/{path}")).unwrap());
        }

        self.request_url(method, self.policy.parse_url(url)?)
    }

    pub fn request_url(&self, method: Method, url: Url) -> Result<RequestBuilder, OutboundError> {
        self.policy.check_url(&url)?;
        self.client
            .as_ref()
            .map(|client| client.request(method, url))
            .ok_or(OutboundError::Unavailable)
    }

    pub fn policy(&self) -> OutboundPolicy {
        self.policy
    }
}

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let mut addrs =
                tokio::task::spawn_blocking(move || (name.as_str(), 0).to_socket_addrs())
                    .await??
                    .filter(|addr| is_permitted_ip(addr.ip()))
                    .peekable();

            if addrs.peek().is_some() {
                Ok(Box::new(addrs) as Addrs)
            } else {
                Err(OutboundError::NonPublicAddress.into())
            }
        })
    }
}

impl OutboundError {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutboundError::InvalidUrl => "Invalid URL",
            OutboundError::InsecureScheme => "URL scheme is not permitted",
            OutboundError::Credentials => "URL must not contain credentials",
            OutboundError::MissingHost => "URL must contain a host",
            OutboundError::NonPublicHost => "Host is not a public domain name",
            OutboundError::NonPublicAddress => "Destination is a local or reserved IP address",
            OutboundError::TooManyRedirects => "Too many redirects",
            OutboundError::Unavailable => "HTTP client unavailable",
        }
    }
}

impl Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for OutboundError {}

fn is_public_domain(domain: &str) -> bool {
    #[cfg(all(stalwart_tests, not(test)))]
    if domain.eq_ignore_ascii_case("localhost") {
        return true;
    }

    psl::domain(domain.as_bytes()).is_some_and(|domain| {
        let suffix = domain.suffix();
        suffix.is_known() && !is_special_use_suffix(suffix.as_bytes())
    })
}

fn is_special_use_suffix(suffix: &[u8]) -> bool {
    hashify::set_ignore_case!(
        suffix,
        "arpa",
        "home.arpa",
        "in-addr.arpa",
        "ip6.arpa",
        "onion",
    )
}

fn is_permitted_ip(ip: IpAddr) -> bool {
    #[cfg(all(stalwart_tests, not(test)))]
    if ip.is_loopback() {
        return true;
    }

    is_global_ip(&ip)
}

pub fn is_same_organization(previous: &Url, next: &Url) -> bool {
    if previous.scheme() != next.scheme() {
        return false;
    }

    match (previous.host(), next.host()) {
        (Some(Host::Domain(previous)), Some(Host::Domain(next))) => {
            match (psl::domain_str(previous), psl::domain_str(next)) {
                (Some(previous), Some(next)) => previous == next,
                _ => previous == next,
            }
        }
        (Some(previous), Some(next)) => previous == next,
        _ => false,
    }
}

pub fn is_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_ipv4(ip),
        IpAddr::V6(ip) => is_global_ipv6(ip),
    }
}

fn is_global_ipv4(ip: &Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let is_this_network = a == 0;
    let is_shared = a == 100 && (64..128).contains(&b);
    let is_protocol_assignment = a == 192 && b == 0 && c == 0;
    let is_benchmarking = a == 198 && (b & 0xfe) == 18;
    let is_relay_6to4 = a == 192 && b == 88 && c == 99;
    let is_reserved = a >= 240;

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || is_this_network
        || is_shared
        || is_protocol_assignment
        || is_benchmarking
        || is_relay_6to4
        || is_reserved)
}

fn is_global_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }

    if let Some(ip) = ip.to_ipv4() {
        return is_global_ipv4(&ip);
    }

    let segments = ip.segments();

    if let [0, 0, 0, 0, 0xffff, 0, high, low] = segments {
        return is_global_ipv4(&Ipv4Addr::from(((high as u32) << 16) | low as u32));
    }

    if segments[0] == 0x2002 {
        return is_global_ipv4(&Ipv4Addr::from(
            ((segments[1] as u32) << 16) | segments[2] as u32,
        ));
    }

    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        let is_well_known_prefix =
            segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0;

        return is_well_known_prefix
            && is_global_ipv4(&Ipv4Addr::from(
                ((segments[6] as u32) << 16) | segments[7] as u32,
            ));
    }

    let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
    let is_site_local = (segments[0] & 0xffc0) == 0xfec0;
    let is_discard_only =
        segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_teredo = segments[0] == 0x2001 && segments[1] == 0;
    let is_orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020;
    let is_benchmarking = segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0;
    let is_documentation_v2 = segments[0] == 0x3fff && (segments[1] & 0xf000) == 0;
    let is_srv6_sid = segments[0] == 0x5f00;

    !(is_unique_local
        || is_benchmarking
        || is_documentation_v2
        || is_srv6_sid
        || is_link_local
        || is_site_local
        || is_discard_only
        || is_documentation
        || is_teredo
        || is_orchid)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/utils/src/outbound/tests.rs"]
mod tests;
