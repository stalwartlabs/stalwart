/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ErrorType, PkceCodeChallenge};
use common::{
    Server,
    auth::oauth::{
        client::{RequestOrigin, ResolveContext, ResolvedClient},
        registration::redirect_display_host,
        scope::OAuthScopes,
    },
    manager::app_client::is_safe_authority,
};
use http_proto::form_urlencoded;
use registry::schema::enums::OAuthGrantType;
use std::borrow::Cow;

const MAX_QUERY_LEN: usize = 8 * 1024;
const MAX_RESOURCES: usize = 16;
const PKCE_S256_CHALLENGE_LEN: usize = 43;
const LABEL_FULL_ACCESS: &str = "Full access to your account";
pub const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";

#[derive(Debug)]
pub struct Authorization {
    pub client: ResolvedClient,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: Option<String>,
    pub scope: Option<String>,
    pub code_challenge: PkceCodeChallenge,
    pub prompt_consent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    Invalid {
        error: ErrorType,
        description: &'static str,
    },
    Redirect {
        location: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Param {
    ClientId,
    RedirectUri,
    ResponseType,
    State,
    Scope,
    Nonce,
    CodeChallenge,
    CodeChallengeMethod,
    Resource,
    Prompt,
}

#[derive(Default)]
struct AuthorizationQuery<'x> {
    client_id: Option<Cow<'x, str>>,
    redirect_uri: Option<Cow<'x, str>>,
    response_type: Option<Cow<'x, str>>,
    state: Option<Cow<'x, str>>,
    scope: Option<Cow<'x, str>>,
    nonce: Option<Cow<'x, str>>,
    code_challenge: Option<Cow<'x, str>>,
    code_challenge_method: Option<Cow<'x, str>>,
    prompt: Option<Cow<'x, str>>,
    resources: Vec<Cow<'x, str>>,
    duplicates: u16,
    too_many_resources: bool,
}

impl Param {
    fn parse(name: &str) -> Option<Self> {
        hashify::map!(
            name.as_bytes(),
            Param,
            "client_id" => Param::ClientId,
            "redirect_uri" => Param::RedirectUri,
            "response_type" => Param::ResponseType,
            "state" => Param::State,
            "scope" => Param::Scope,
            "nonce" => Param::Nonce,
            "code_challenge" => Param::CodeChallenge,
            "code_challenge_method" => Param::CodeChallengeMethod,
            "resource" => Param::Resource,
            "prompt" => Param::Prompt,
        )
        .copied()
    }

    fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

impl<'x> AuthorizationQuery<'x> {
    fn parse(query: &'x str) -> Self {
        let mut parsed = AuthorizationQuery::default();
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            let Some(param) = Param::parse(&name) else {
                continue;
            };
            let slot = match param {
                Param::Resource => {
                    if parsed.resources.len() < MAX_RESOURCES {
                        parsed.resources.push(value);
                    } else {
                        parsed.too_many_resources = true;
                    }
                    continue;
                }
                Param::ClientId => &mut parsed.client_id,
                Param::RedirectUri => &mut parsed.redirect_uri,
                Param::ResponseType => &mut parsed.response_type,
                Param::State => &mut parsed.state,
                Param::Scope => &mut parsed.scope,
                Param::Nonce => &mut parsed.nonce,
                Param::CodeChallenge => &mut parsed.code_challenge,
                Param::CodeChallengeMethod => &mut parsed.code_challenge_method,
                Param::Prompt => &mut parsed.prompt,
            };
            if slot.is_some() {
                parsed.duplicates |= param.bit();
            } else {
                *slot = Some(value);
            }
        }
        parsed
    }

    fn is_duplicate(&self, param: Param) -> bool {
        self.duplicates & param.bit() != 0
    }
}

pub async fn validate_authorization(
    server: &Server,
    query: &str,
    ctx: &ResolveContext<'_>,
    issuer: &str,
) -> trc::Result<Result<Authorization, AuthorizationError>> {
    if query.len() > MAX_QUERY_LEN {
        return Ok(Err(AuthorizationError::invalid(
            ErrorType::InvalidRequest,
            "The authorization request is too large.",
        )));
    }

    let query = AuthorizationQuery::parse(query);
    if query.is_duplicate(Param::ClientId) || query.is_duplicate(Param::RedirectUri) {
        return Ok(Err(AuthorizationError::invalid(
            ErrorType::InvalidRequest,
            "The client_id and redirect_uri parameters must not be repeated.",
        )));
    }
    let Some(client_id) = query.client_id.as_deref().filter(|id| !id.is_empty()) else {
        return Ok(Err(AuthorizationError::invalid(
            ErrorType::InvalidRequest,
            "The client_id parameter is missing.",
        )));
    };
    let client = match server.resolve_oauth_client(client_id, ctx).await? {
        Ok(client) => client,
        Err(rejection) => {
            return Ok(Err(AuthorizationError::invalid(
                ErrorType::InvalidClient,
                rejection.as_str(),
            )));
        }
    };
    let Some(redirect_uri) = query
        .redirect_uri
        .as_deref()
        .filter(|uri| client.redirect_uri_matches(uri))
    else {
        return Ok(Err(AuthorizationError::invalid(
            ErrorType::InvalidRequest,
            "The redirect_uri parameter is missing or does not match the client registration.",
        )));
    };

    let state = query
        .state
        .as_deref()
        .filter(|state| !state.is_empty() && !query.is_duplicate(Param::State));
    let redirect = |error: ErrorType, description: &str| {
        Ok(Err(AuthorizationError::Redirect {
            location: error_location(redirect_uri, error, Some(description), state, issuer),
        }))
    };

    if query.duplicates != 0 {
        return redirect(
            ErrorType::InvalidRequest,
            "Request parameters must not be repeated.",
        );
    } else if query.too_many_resources {
        return redirect(
            ErrorType::InvalidTarget,
            "Too many resource parameters were requested.",
        );
    }
    match query.response_type.as_deref() {
        Some("code") => {}
        Some(_) => {
            return redirect(
                ErrorType::UnsupportedResponseType,
                "Only the code response type is supported.",
            );
        }
        None => {
            return redirect(
                ErrorType::InvalidRequest,
                "The response_type parameter is missing.",
            );
        }
    }
    let Some(state) = state else {
        return redirect(ErrorType::InvalidRequest, "The state parameter is missing.");
    };
    if !client.allows_grant(OAuthGrantType::AuthorizationCode) {
        return redirect(
            ErrorType::UnauthorizedClient,
            "The client is not allowed to use the authorization code grant.",
        );
    }

    let code_challenge = match (
        query.code_challenge.as_deref(),
        query.code_challenge_method.as_deref(),
    ) {
        (Some(challenge), Some("S256")) if is_s256_challenge(challenge) => {
            PkceCodeChallenge::S256(challenge.to_string())
        }
        (Some(_), Some("S256")) => {
            return redirect(
                ErrorType::InvalidRequest,
                "The code_challenge parameter is not a valid S256 challenge.",
            );
        }
        (None, None) if client.is_confidential() => PkceCodeChallenge::None,
        (None, None) => {
            return redirect(
                ErrorType::InvalidRequest,
                "A PKCE code_challenge is required.",
            );
        }
        _ => {
            return redirect(
                ErrorType::InvalidRequest,
                "The code_challenge_method must be S256.",
            );
        }
    };

    let scope = match granted_scope(query.scope.as_deref(), client.allowed_scopes()) {
        Ok(scope) => scope,
        Err(error) => {
            return redirect(error, "The requested scope is not allowed for this client.");
        }
    };

    for resource in &query.resources {
        if !is_permitted_resource(server, ctx.origin, resource) {
            return redirect(
                ErrorType::InvalidTarget,
                "The requested resource is not served by this server.",
            );
        }
    }

    Ok(Ok(Authorization {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        state: state.to_string(),
        nonce: query.nonce.map(Cow::into_owned),
        scope,
        code_challenge,
        prompt_consent: query.prompt.as_deref().is_some_and(|prompt| {
            prompt
                .split_ascii_whitespace()
                .any(|value| value == "consent")
        }),
        client,
    }))
}

impl Authorization {
    pub fn error_location(&self, error: ErrorType, issuer: &str) -> String {
        error_location(&self.redirect_uri, error, None, Some(&self.state), issuer)
    }

    pub fn code_location(&self, code: &str, issuer: &str) -> String {
        redirect_location(
            &self.redirect_uri,
            [("code", code), ("state", &self.state), ("iss", issuer)],
        )
    }

    pub fn consent_scopes(&self) -> OAuthScopes {
        if self.client.allowed_scopes().is_some() {
            OAuthScopes::parse(self.scope.as_deref().unwrap_or_default()).interoperable()
        } else {
            OAuthScopes::NONE
        }
    }

    pub fn scope_labels(&self) -> Vec<&'static str> {
        scope_labels(&self.client, self.scope.as_deref())
    }

    pub fn redirect_host(&self) -> Option<String> {
        redirect_display_host(&self.redirect_uri)
    }
}

impl AuthorizationError {
    fn invalid(error: ErrorType, description: &'static str) -> Self {
        AuthorizationError::Invalid { error, description }
    }
}

pub fn granted_scope(
    requested: Option<&str>,
    allowed: Option<OAuthScopes>,
) -> Result<Option<String>, ErrorType> {
    let mut scope = String::new();
    for item in requested.unwrap_or_default().split_ascii_whitespace() {
        if let Some(allowed) = allowed {
            let scope = OAuthScopes::from_name(item);
            if scope.is_empty() || !allowed.contains(scope) {
                return Err(ErrorType::InvalidScope);
            }
        }
        if !scope.is_empty() {
            scope.push(' ');
        }
        scope.push_str(item);
    }
    Ok((!scope.is_empty()).then_some(scope))
}

pub fn scope_labels(client: &ResolvedClient, scope: Option<&str>) -> Vec<&'static str> {
    if client.allowed_scopes().is_none() {
        return vec![LABEL_FULL_ACCESS];
    }

    let mut seen = OAuthScopes::NONE;
    let mut labels = Vec::new();
    for item in scope.unwrap_or_default().split_ascii_whitespace() {
        let bit = OAuthScopes::from_name(item);
        if !seen.intersects(bit)
            && let Some(label) = scope_label(item)
        {
            seen |= bit;
            labels.push(label);
        }
    }
    labels
}

fn scope_label(scope: &str) -> Option<&'static str> {
    hashify::map!(
        scope.as_bytes(),
        &'static str,
        "openid" => "See your account name and email address",
        "offline_access" => "Stay connected when you are not using it",
        "urn:ietf:params:oauth:scope:mail" => "Read, send and manage your email",
        "urn:ietf:params:oauth:scope:contacts" => "Read and manage your contacts",
        "urn:ietf:params:oauth:scope:calendars" => "Read and manage your calendars",
        "urn:ietf:params:oauth:scope:files" => "Read and manage your files",
    )
    .copied()
}

pub fn issuer<'x>(server: &'x Server, origin: RequestOrigin<'_>) -> Cow<'x, str> {
    issuer_for(&server.core.network.http.url_https, origin)
}

fn issuer_for<'x>(url_https: &'x str, origin: RequestOrigin<'_>) -> Cow<'x, str> {
    if !url_https.is_empty() && (origin.is_tls || !cfg!(feature = "dev_mode")) {
        Cow::Borrowed(url_https)
    } else {
        Cow::Owned(format!("{}://{}", origin.scheme(), origin.authority))
    }
}

pub fn resource_origin(server: &Server, origin: RequestOrigin<'_>) -> Option<String> {
    if !is_safe_authority(origin.authority) {
        None
    } else if server.registry().is_bootstrap_mode() || server.registry().is_recovery_mode() {
        Some(format!("{}://{}", origin.scheme(), origin.authority))
    } else if server
        .core
        .network
        .resources
        .is_trusted_host(origin.authority)
    {
        Some(format!("https://{}", origin.authority))
    } else {
        None
    }
}

pub fn resource_metadata_url(server: &Server, origin: RequestOrigin<'_>, path: &str) -> String {
    let mut url = resource_origin(server, origin)
        .unwrap_or_else(|| server.core.network.http.url_https.clone());
    url.push_str(PROTECTED_RESOURCE_PATH);
    if path != "/" && is_resource_path(path) {
        url.push_str(path);
    }
    url
}

pub fn is_resource_path(path: &str) -> bool {
    path.is_empty()
        || (path.starts_with('/')
            && path.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'-' | b'.'
                            | b'_'
                            | b'~'
                            | b'/'
                            | b'%'
                            | b'!'
                            | b'$'
                            | b'&'
                            | b'\''
                            | b'('
                            | b')'
                            | b'*'
                            | b'+'
                            | b','
                            | b';'
                            | b'='
                            | b':'
                            | b'@'
                    )
            }))
}

fn is_permitted_resource(
    server: &Server,
    origin: Option<RequestOrigin<'_>>,
    resource: &str,
) -> bool {
    server.core.network.resources.is_known_resource(resource)
        || ((server.registry().is_bootstrap_mode() || server.registry().is_recovery_mode())
            && origin.is_some_and(|origin| {
                resource
                    .strip_prefix(origin.scheme())
                    .and_then(|rest| rest.strip_prefix("://"))
                    .and_then(|rest| rest.strip_prefix(origin.authority))
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                    && !resource.contains('#')
            }))
}

fn is_s256_challenge(challenge: &str) -> bool {
    challenge.len() == PKCE_S256_CHALLENGE_LEN
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn error_location(
    redirect_uri: &str,
    error: ErrorType,
    description: Option<&str>,
    state: Option<&str>,
    issuer: &str,
) -> String {
    let mut params = [
        ("error", error.as_str()),
        ("", ""),
        ("", ""),
        ("iss", issuer),
    ];
    if let Some(description) = description {
        params[1] = ("error_description", description);
    }
    if let Some(state) = state {
        params[2] = ("state", state);
    }
    redirect_location(
        redirect_uri,
        params.into_iter().filter(|(name, _)| !name.is_empty()),
    )
}

pub(super) fn redirect_location<'x>(
    redirect_uri: &str,
    params: impl IntoIterator<Item = (&'x str, &'x str)>,
) -> String {
    let mut location = String::with_capacity(redirect_uri.len() + 192);
    location.push_str(redirect_uri);
    if !redirect_uri.contains('?') {
        location.push('?');
    } else if !redirect_uri.ends_with(['?', '&']) {
        location.push('&');
    }
    let start = location.len();
    form_urlencoded::Serializer::for_suffix(location, start)
        .extend_pairs(params)
        .finish()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/http/src/auth/oauth/authorize/tests.rs"]
mod tests;
