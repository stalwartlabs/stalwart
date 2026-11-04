/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::CLIENT_ID_MAX_LEN;
use registry::schema::{
    enums::{OAuthGrantType, OAuthScope},
    prelude::Property,
    structs::OAuthClient,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub struct ClientRegistrationRequest {
    pub redirect_uris: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<ApplicationType>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>, // Using serde_json::Value for flexibility

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<SubjectType>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub default_acr_values: Vec<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub request_uris: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub struct ClientRegistrationResponse {
    // Required fields
    pub client_id: String,

    // Optional fields specific to the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,

    // Echo back the request
    #[serde(flatten)]
    pub request: ClientRegistrationRequest,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    Web,
    Native,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Pairwise,
    Public,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    ClientSecretPost,
    ClientSecretBasic,
    ClientSecretJwt,
    PrivateKeyJwt,
    None,
}

#[derive(Serialize, Debug)]
pub struct ClientRegistrationError {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<&'static str>,
}

impl ClientRegistrationError {
    pub fn invalid_redirect_uri(description: &'static str) -> Self {
        ClientRegistrationError {
            error: "invalid_redirect_uri",
            error_description: Some(description),
        }
    }

    pub fn invalid_client_metadata(description: &'static str) -> Self {
        ClientRegistrationError {
            error: "invalid_client_metadata",
            error_description: Some(description),
        }
    }

    pub fn for_post_logout_redirect_uri(self) -> Self {
        ClientRegistrationError {
            error: "invalid_client_metadata",
            error_description: self.error_description,
        }
    }
}

pub const GRANT_TYPE_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const CLIENT_NAME_MAX_LEN: usize = 256;
const HTTPS_PREFIX: &str = "https://";

pub fn loopback_redirect_parts(uri: &str) -> Option<(&str, &str)> {
    let uri = uri.strip_prefix("http://")?;

    for host in ["127.0.0.1", "[::1]"] {
        if let Some(rest) = uri.strip_prefix(host) {
            if let Some(path) = rest.strip_prefix('/') {
                return Some((host, path));
            } else if let Some(after_colon) = rest.strip_prefix(':')
                && let Some((port, path)) = after_colon.split_once('/')
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok()
            {
                return Some((host, path));
            }
        }
    }
    None
}

pub fn post_logout_redirect_uri_matches<'x>(
    registered: impl IntoIterator<Item = &'x String>,
    presented: &str,
) -> bool {
    is_safe_redirect_target(presented)
        && registered
            .into_iter()
            .any(|registered| registered == presented)
}

pub fn redirect_uri_matches(registered: &str, presented: &str) -> bool {
    registered == presented
        || matches!(
            (
                loopback_redirect_parts(registered),
                loopback_redirect_parts(presented),
            ),
            (Some(reg), Some(pres)) if reg == pres
        )
}

fn uri_scheme(uri: &str) -> Option<&str> {
    uri.split_once(':')
        .map(|(scheme, _)| scheme)
        .filter(|scheme| {
            scheme
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
        })
}

fn is_private_use_redirect(uri: &str) -> bool {
    uri_scheme(uri).is_some_and(|scheme| scheme.contains('.'))
}

fn is_dangerous_scheme(scheme: &str) -> bool {
    hashify::set_ignore_case!(
        scheme.as_bytes(),
        "javascript",
        "data",
        "vbscript",
        "file",
        "blob",
        "about",
    )
}

pub fn is_safe_redirect_target(uri: &str) -> bool {
    !uri.bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
        && uri_scheme(uri).is_some_and(|scheme| !is_dangerous_scheme(scheme))
}

pub fn check_client_name(name: &str) -> Result<(), &'static str> {
    if name.len() > CLIENT_NAME_MAX_LEN {
        Err("client_name must not exceed 256 bytes.")
    } else if name.chars().any(|ch| {
        ch.is_control() || matches!(ch, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
    }) {
        Err("client_name must not contain control or bidirectional formatting characters.")
    } else {
        Ok(())
    }
}

fn check_redirect_uri_syntax(uri: &str) -> Result<(), ClientRegistrationError> {
    if uri.contains('#') {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must not contain a fragment.",
        ))
    } else if uri.contains("..") {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must not contain consecutive dots.",
        ))
    } else if uri.contains('\\') {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must not contain a backslash.",
        ))
    } else if uri_scheme(uri).is_some_and(is_dangerous_scheme) {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI uses a forbidden scheme.",
        ))
    } else {
        Ok(())
    }
}

pub fn validate_public_redirect_uri(uri: &str) -> Result<(), ClientRegistrationError> {
    check_redirect_uri_syntax(uri)?;
    if loopback_redirect_parts(uri).is_some() || is_private_use_redirect(uri) {
        Ok(())
    } else {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must be a loopback (http://127.0.0.1/, http://[::1]/) or a private-use scheme containing a dot.",
        ))
    }
}

pub fn validate_redirect_uri(uri: &str) -> Result<(), ClientRegistrationError> {
    check_redirect_uri_syntax(uri)?;
    if uri.starts_with("https://")
        || loopback_redirect_parts(uri).is_some()
        || is_private_use_redirect(uri)
    {
        Ok(())
    } else {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must be an https URL, a loopback (http://127.0.0.1/, http://[::1]/) or a private-use scheme URI.",
        ))
    }
}

pub fn validate_registered_redirect_uri(uri: &str) -> Result<(), ClientRegistrationError> {
    if uri.len() > CLIENT_ID_MAX_LEN
        || uri
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
    {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI is too long or contains invalid characters.",
        ))
    } else if uri.contains('#') {
        Err(ClientRegistrationError::invalid_redirect_uri(
            "Redirect URI must not contain a fragment.",
        ))
    } else {
        match uri_scheme(uri) {
            Some(scheme) if is_dangerous_scheme(scheme) => {
                Err(ClientRegistrationError::invalid_redirect_uri(
                    "Redirect URI uses a forbidden scheme.",
                ))
            }
            Some(_) => Ok(()),
            None => Err(ClientRegistrationError::invalid_redirect_uri(
                "Redirect URI must be an absolute URI.",
            )),
        }
    }
}

pub fn validate_public_client_metadata(
    request: &ClientRegistrationRequest,
) -> Result<(), ClientRegistrationError> {
    for uri in &request.redirect_uris {
        validate_public_redirect_uri(uri)?;
    }
    if !matches!(
        request.token_endpoint_auth_method,
        None | Some(TokenEndpointAuthMethod::None)
    ) {
        return Err(ClientRegistrationError::invalid_client_metadata(
            "token_endpoint_auth_method must be \"none\".",
        ));
    }
    for uri in [
        &request.client_uri,
        &request.logo_uri,
        &request.tos_uri,
        &request.policy_uri,
    ]
    .into_iter()
    .flatten()
    {
        if !is_https_url(uri) {
            return Err(ClientRegistrationError::invalid_client_metadata(
                "client_uri, logo_uri, tos_uri and policy_uri must use https.",
            ));
        }
    }
    if request
        .grant_types
        .iter()
        .any(|grant| grant == GRANT_TYPE_DEVICE_CODE)
    {
        return Err(ClientRegistrationError::invalid_client_metadata(
            "The device_code grant is not available to dynamically registered clients.",
        ));
    }

    Ok(())
}

pub fn redirect_display_host(redirect_uri: &str) -> Option<String> {
    let url = Url::parse(redirect_uri).ok()?;
    match url.scheme() {
        "http" | "https" => {
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        }
        scheme => Some(scheme.to_string()),
    }
}

pub fn is_https_url(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some_and(|host| !host.is_empty())
            && url.username().is_empty()
            && url.password().is_none()
    })
}

pub fn parse_grant_type(grant_type: &str) -> Option<OAuthGrantType> {
    hashify::map!(
        grant_type.as_bytes(),
        OAuthGrantType,
        "authorization_code" => OAuthGrantType::AuthorizationCode,
        "refresh_token" => OAuthGrantType::RefreshToken,
        "urn:ietf:params:oauth:grant-type:device_code" => OAuthGrantType::DeviceCode,
    )
    .copied()
}

pub fn parse_oauth_scope(scope: &str) -> Option<OAuthScope> {
    hashify::map!(
        scope.as_bytes(),
        OAuthScope,
        "urn:ietf:params:oauth:scope:mail" => OAuthScope::Mail,
        "urn:ietf:params:oauth:scope:contacts" => OAuthScope::Contacts,
        "urn:ietf:params:oauth:scope:calendars" => OAuthScope::Calendars,
        "urn:ietf:params:oauth:scope:files" => OAuthScope::Files,
        "urn:stalwart:oauth:scope:security" => OAuthScope::Security,
        "urn:stalwart:oauth:scope:settings" => OAuthScope::Settings,
        "urn:stalwart:oauth:scope:full" => OAuthScope::Full,
    )
    .copied()
}

pub fn validate_client_name(
    request: &ClientRegistrationRequest,
) -> Result<(), ClientRegistrationError> {
    match request.client_name.as_deref().map(check_client_name) {
        Some(Err(description)) => Err(ClientRegistrationError::invalid_client_metadata(
            description,
        )),
        _ => Ok(()),
    }
}

pub fn validate_oauth_client(
    client: &OAuthClient,
    is_superuser: bool,
) -> Result<(), (Property, ClientRegistrationError)> {
    for uri in client.redirect_uris.iter() {
        validate_registered_redirect_uri(uri).map_err(|err| (Property::RedirectUris, err))?;
    }
    for uri in client.post_logout_redirect_uris.iter() {
        validate_registered_redirect_uri(uri).map_err(|err| {
            (
                Property::PostLogoutRedirectUris,
                err.for_post_logout_redirect_uri(),
            )
        })?;
    }
    if !is_superuser
        && client
            .client_id
            .get(..HTTPS_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(HTTPS_PREFIX))
    {
        return Err((
            Property::ClientId,
            ClientRegistrationError::invalid_client_metadata(
                "Only a superuser can register a client metadata document URL as a client id.",
            ),
        ));
    }
    if !is_superuser && client.scopes.contains(&OAuthScope::Full) {
        return Err((
            Property::Scopes,
            ClientRegistrationError::invalid_client_metadata(
                "Only a superuser can register a client with full access.",
            ),
        ));
    }
    Ok(())
}

pub fn validate_grant_metadata(
    request: &ClientRegistrationRequest,
) -> Result<(), ClientRegistrationError> {
    if !request.response_types.is_empty() && !request.response_types.iter().any(|t| t == "code") {
        return Err(ClientRegistrationError::invalid_client_metadata(
            "response_types must include \"code\".",
        ));
    }
    if !request.grant_types.is_empty() {
        if !request
            .grant_types
            .iter()
            .any(|t| t == "authorization_code")
        {
            return Err(ClientRegistrationError::invalid_client_metadata(
                "grant_types must include \"authorization_code\".",
            ));
        }
        if !request.grant_types.iter().any(|t| t == "refresh_token") {
            return Err(ClientRegistrationError::invalid_client_metadata(
                "grant_types must include \"refresh_token\".",
            ));
        }
    }

    Ok(())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/common/src/auth/oauth/registration/tests.rs"]
mod tests;
