/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};

/// Top-level configuration document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Configuration {
    /// Supported protocols and their server endpoints.
    pub protocols: Protocols,

    /// Authentication mechanisms the provider supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,

    /// Informational metadata about the provider.
    pub info: Info,
}

/// The `protocols` object listing available protocol endpoints.
///
/// HTTP-based protocols (JMAP, CalDAV, CardDAV, WebDAV) use [`HttpServer`].
/// Text-based protocols (IMAP, POP3, SMTP, ManageSieve) use [`TextServer`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Protocols {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmap: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub imap: Option<TextServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3: Option<TextServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<TextServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub caldav: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub carddav: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub webdav: Option<HttpServer>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub managesieve: Option<TextServer>,
}

/// An HTTP-based protocol endpoint (JMAP, CalDAV, CardDAV, WebDAV).
///
/// The `url` MUST use the `https` scheme and the default port 443.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpServer {
    /// HTTPS URL of the protocol endpoint.
    pub url: String,
}

/// A text-based protocol endpoint (IMAP, POP3, SMTP, ManageSieve).
///
/// Connections use TLS on the protocol's default port
/// (993 IMAP, 995 POP3, 465 SMTP).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TextServer {
    /// Hostname of the server.
    pub host: String,
}

/// Authentication mechanisms supported by the provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Authentication {
    /// OAuth Profile for Open Public Clients configuration.
    #[serde(rename = "oauth-public", skip_serializing_if = "Option::is_none")]
    pub oauth_public: Option<OAuthPublic>,

    /// Whether the provider supports username/password authentication.
    pub password: bool,
}

/// OAuth Profile for Open Public Clients parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthPublic {
    /// The authorization server's issuer identifier (RFC 8414).
    /// Must be an `https` URL with no query or fragment components.
    pub issuer: String,
}

/// Informational metadata presented to users and developers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Info {
    /// Provider identity information (required).
    pub provider: Provider,

    /// Help links for users and developers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<Help>,
}

/// Provider identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Provider {
    /// Display name of the provider (≤ 60 characters, SHOULD ≤ 30).
    pub name: String,

    /// Short name (≤ 20 characters, SHOULD ≤ 12).
    #[serde(rename = "shortName", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,

    /// Logo image variants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Vec<Logo>>,
}

/// A single logo variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Logo {
    /// URL where the logo can be retrieved.
    pub url: String,

    /// Media type of the logo image (e.g. `image/svg+xml`, `image/png`).
    #[serde(rename = "content-type")]
    pub content_type: String,

    /// Image width in pixels. Omitted for SVG.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,

    /// Image height in pixels. Omitted for SVG.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
}

/// Help links for users and developers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Help {
    /// URL with user-facing documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,

    /// URL with developer-facing documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer: Option<String>,

    /// Contact URIs (e.g. `mailto:` URLs). NOT for end-user display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full example from Section 4.1 of the draft.
    const EXAMPLE_JSON: &str = r#"{
    "protocols": {
        "jmap": {
            "url": "https://jmap.example.com/session"
        },
        "imap": {
            "host": "imap.example.com"
        },
        "pop3": {
            "host": "pop3.example.com"
        },
        "smtp": {
            "host": "smtp.example.com"
        },
        "caldav": {
            "url": "https://sync.example.com/calendar/"
        },
        "carddav": {
            "url": "https://sync.example.com/contacts/"
        }
    },
    "authentication": {
        "oauth-public": {
            "issuer": "https://auth.example.com/"
        },
        "password": true
    },
    "info": {
        "provider": {
            "name": "Example Provider Name",
            "shortName": "Example",
            "logo": [
                {
                    "url": "https://www.example.net/logo.svg",
                    "content-type": "image/svg+xml"
                }
            ]
        },
        "help": {
            "documentation": "https://help.example.net/howto/set-up-your-mail-app.html",
            "developer": "https://developer.example.net/client-apps/",
            "contact": ["mailto:it@team.example.net"]
        }
    }
}"#;

    #[test]
    fn deserialize_full_example() {
        let config: Configuration =
            serde_json::from_str(EXAMPLE_JSON).expect("failed to deserialize");

        // Protocols
        assert_eq!(
            config.protocols.jmap.as_ref().unwrap().url,
            "https://jmap.example.com/session"
        );
        assert_eq!(
            config.protocols.imap.as_ref().unwrap().host,
            "imap.example.com"
        );
        assert_eq!(
            config.protocols.smtp.as_ref().unwrap().host,
            "smtp.example.com"
        );
        assert_eq!(
            config.protocols.pop3.as_ref().unwrap().host,
            "pop3.example.com"
        );
        assert_eq!(
            config.protocols.caldav.as_ref().unwrap().url,
            "https://sync.example.com/calendar/"
        );
        assert_eq!(
            config.protocols.carddav.as_ref().unwrap().url,
            "https://sync.example.com/contacts/"
        );
        assert!(config.protocols.webdav.is_none());
        assert!(config.protocols.managesieve.is_none());

        // Authentication
        let auth = config.authentication.as_ref().unwrap();
        assert!(auth.password);
        assert_eq!(
            auth.oauth_public.as_ref().unwrap().issuer,
            "https://auth.example.com/"
        );

        // Info
        assert_eq!(config.info.provider.name, "Example Provider Name");
        assert_eq!(config.info.provider.short_name.as_deref(), Some("Example"));

        let logos = config.info.provider.logo.as_ref().unwrap();
        assert_eq!(logos.len(), 1);
        assert_eq!(logos[0].content_type, "image/svg+xml");
        assert!(logos[0].width.is_none());

        let help = config.info.help.as_ref().unwrap();
        assert_eq!(
            help.documentation.as_deref(),
            Some("https://help.example.net/howto/set-up-your-mail-app.html")
        );
        assert_eq!(
            help.contact.as_ref().unwrap(),
            &["mailto:it@team.example.net"]
        );
    }

    #[test]
    fn roundtrip() {
        let config: Configuration =
            serde_json::from_str(EXAMPLE_JSON).expect("failed to deserialize");
        let serialized = serde_json::to_string_pretty(&config).expect("failed to serialize");
        let roundtripped: Configuration =
            serde_json::from_str(&serialized).expect("failed to re-deserialize");
        assert_eq!(config, roundtripped);
    }

    #[test]
    fn minimal_config() {
        let json = r#"{
            "protocols": {},
            "info": {
                "provider": {
                    "name": "Minimal"
                }
            }
        }"#;
        let config: Configuration = serde_json::from_str(json).expect("failed to deserialize");
        assert_eq!(config.info.provider.name, "Minimal");
        assert!(config.authentication.is_none());
        assert!(config.protocols.jmap.is_none());
    }

    #[test]
    fn ignores_unknown_properties() {
        let json = r#"{
            "protocols": {
                "imap": { "host": "imap.example.com" },
                "future-protocol": { "endpoint": "wss://example.com" }
            },
            "info": {
                "provider": { "name": "Test" }
            },
            "futureField": 42
        }"#;
        let config: Configuration = serde_json::from_str(json).expect("should ignore unknowns");
        assert_eq!(
            config.protocols.imap.as_ref().unwrap().host,
            "imap.example.com"
        );
    }

    #[test]
    fn logo_with_dimensions() {
        let json = r#"{
            "protocols": {},
            "info": {
                "provider": {
                    "name": "Test",
                    "logo": [
                        {
                            "url": "https://example.com/logo.svg",
                            "content-type": "image/svg+xml"
                        },
                        {
                            "url": "https://example.com/logo-128.png",
                            "content-type": "image/png",
                            "width": 128,
                            "height": 128
                        },
                        {
                            "url": "https://example.com/logo-512.png",
                            "content-type": "image/png",
                            "width": 512,
                            "height": 512
                        }
                    ]
                }
            }
        }"#;
        let config: Configuration = serde_json::from_str(json).unwrap();
        let logos = config.info.provider.logo.as_ref().unwrap();
        assert_eq!(logos.len(), 3);
        assert!(logos[0].width.is_none());
        assert_eq!(logos[1].width, Some(128));
        assert_eq!(logos[2].height, Some(512));
    }

    #[test]
    fn password_only_auth() {
        let json = r#"{
            "protocols": { "imap": { "host": "mail.example.com" } },
            "authentication": { "password": true },
            "info": { "provider": { "name": "PW Only" } }
        }"#;
        let config: Configuration = serde_json::from_str(json).unwrap();
        let auth = config.authentication.unwrap();
        assert!(auth.password);
        assert!(auth.oauth_public.is_none());
    }
}
