/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, manager::application::Resource};
use http_proto::*;
use quick_xml::Reader;
use quick_xml::events::Event;
use registry::schema::enums::NetworkListenerProtocol;
use registry::schema::structs::NetworkListener;
use std::fmt::Write;
use std::future::Future;
use utils::url_params::UrlParams;

pub trait Autoconfig: Sync + Send {
    fn handle_autoconfig_request(
        &self,
        req: &HttpRequest,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
    fn handle_autodiscover_request(
        &self,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl Autoconfig for Server {
    async fn handle_autoconfig_request(&self, req: &HttpRequest) -> trc::Result<HttpResponse> {
        // Obtain parameters
        let params = UrlParams::new(req.uri().query());
        let emailaddress = params
            .get("emailaddress")
            .unwrap_or_default()
            .to_lowercase();
        let Some((_, domain)) = emailaddress.rsplit_once('@') else {
            return Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("Missing domain in email address"));
        };
        let listeners = self.registry().list::<NetworkListener>().await?;
        let server_name = &self.core.network.server_name;

        // Build XML response
        let mut config = String::with_capacity(1024);
        config.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        config.push_str("<clientConfig version=\"1.1\">\n");
        let _ = writeln!(&mut config, "\t<emailProvider id=\"{domain}\">");
        let _ = writeln!(&mut config, "\t\t<domain>{domain}</domain>");
        let _ = writeln!(&mut config, "\t\t<displayName>{emailaddress}</displayName>");
        let _ = writeln!(
            &mut config,
            "\t\t<displayShortName>{domain}</displayShortName>"
        );
        for listener in listeners {
            let listener = listener.object;
            let Some(port) = listener.bind.first().map(|l| l.0.port()) else {
                continue;
            };
            let (protocol, tag) = match listener.protocol {
                NetworkListenerProtocol::Smtp if port != 25 => ("smtp", "outgoingServer"),
                NetworkListenerProtocol::Imap => ("imap", "incomingServer"),
                NetworkListenerProtocol::Pop3 => ("pop3", "incomingServer"),
                _ => continue,
            };
            let _ = writeln!(&mut config, "\t\t<{tag} type=\"{protocol}\">");
            let _ = writeln!(&mut config, "\t\t\t<hostname>{server_name}</hostname>");
            let _ = writeln!(&mut config, "\t\t\t<port>{port}</port>");
            let _ = writeln!(
                &mut config,
                "\t\t\t<socketType>{}</socketType>",
                if listener.tls_implicit {
                    "SSL"
                } else {
                    "STARTTLS"
                }
            );
            let _ = writeln!(&mut config, "\t\t\t<username>{emailaddress}</username>");
            let _ = writeln!(
                &mut config,
                "\t\t\t<authentication>password-cleartext</authentication>"
            );
            let _ = writeln!(&mut config, "\t\t</{tag}>");
        }

        config.push_str("\t</emailProvider>\n");

        for (tag, protocol, url) in [
            ("addressBook", "carddav", "card"),
            ("calendar", "caldav", "cal"),
            ("fileShare", "webdav", "file"),
        ] {
            let _ = writeln!(&mut config, "\t<{tag} type=\"{protocol}\">");
            let _ = writeln!(&mut config, "\t\t<username>{emailaddress}</username>");
            let _ = writeln!(
                &mut config,
                "\t\t<authentication>http-basic</authentication>"
            );
            let _ = writeln!(
                &mut config,
                "\t\t<serverURL>https://{server_name}/dav/{url}</serverURL>"
            );
            let _ = writeln!(&mut config, "\t</{tag}>");
        }

        let _ = writeln!(
            &mut config,
            "\t<clientConfigUpdate url=\"https://autoconfig.{domain}/mail/config-v1.1.xml\"></clientConfigUpdate>"
        );
        config.push_str("</clientConfig>\n");

        Ok(
            Resource::new("application/xml; charset=utf-8", config.into_bytes())
                .into_http_response(),
        )
    }

    async fn handle_autodiscover_request(
        &self,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        // Obtain parameters
        let emailaddress = parse_autodiscover_request(body.as_deref().unwrap_or_default())
            .map_err(|err| {
                trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("Failed to parse autodiscover request")
                    .ctx(trc::Key::Reason, err)
            })?;
        let listeners = self.registry().list::<NetworkListener>().await?;
        let server_name = &self.core.network.server_name;

        // Build XML response
        let mut config = String::with_capacity(1024);
        let _ = writeln!(&mut config, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        let _ = writeln!(
            &mut config,
            "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">"
        );
        let _ = writeln!(
            &mut config,
            "\t<Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">"
        );
        let _ = writeln!(&mut config, "\t\t<User>");
        let _ = writeln!(
            &mut config,
            "\t\t\t<DisplayName>{emailaddress}</DisplayName>"
        );
        let _ = writeln!(
            &mut config,
            "\t\t\t<AutoDiscoverSMTPAddress>{emailaddress}</AutoDiscoverSMTPAddress>"
        );
        // DeploymentId is a required field of User but we are not a MS Exchange server so use a random value
        let _ = writeln!(
            &mut config,
            "\t\t\t<DeploymentId>644560b8-a1ce-429c-8ace-23395843f701</DeploymentId>"
        );
        let _ = writeln!(&mut config, "\t\t</User>");
        let _ = writeln!(&mut config, "\t\t<Account>");
        let _ = writeln!(&mut config, "\t\t\t<AccountType>email</AccountType>");
        let _ = writeln!(&mut config, "\t\t\t<Action>settings</Action>");
        for listener in listeners {
            let listener = listener.object;
            let Some(port) = listener.bind.first().map(|l| l.0.port()) else {
                continue;
            };

            let protocol = match listener.protocol {
                NetworkListenerProtocol::Imap => "IMAP",
                NetworkListenerProtocol::Pop3 => "POP3",
                NetworkListenerProtocol::Smtp if port != 25 => "SMTP",
                _ => continue,
            };

            let _ = writeln!(&mut config, "\t\t\t<Protocol>");
            let _ = writeln!(&mut config, "\t\t\t\t<Type>{protocol}</Type>",);
            let _ = writeln!(&mut config, "\t\t\t\t<Server>{server_name}</Server>");
            let _ = writeln!(&mut config, "\t\t\t\t<Port>{port}</Port>");
            let _ = writeln!(&mut config, "\t\t\t\t<LoginName>{emailaddress}</LoginName>");
            let _ = writeln!(&mut config, "\t\t\t\t<AuthRequired>on</AuthRequired>");
            let _ = writeln!(&mut config, "\t\t\t\t<DirectoryPort>0</DirectoryPort>");
            let _ = writeln!(&mut config, "\t\t\t\t<ReferralPort>0</ReferralPort>");
            let _ = writeln!(
                &mut config,
                "\t\t\t\t<SSL>{}</SSL>",
                if listener.tls_implicit { "on" } else { "off" }
            );
            if listener.tls_implicit {
                let _ = writeln!(&mut config, "\t\t\t\t<Encryption>TLS</Encryption>");
            }
            let _ = writeln!(&mut config, "\t\t\t\t<SPA>off</SPA>");
            let _ = writeln!(&mut config, "\t\t\t</Protocol>");
        }

        let _ = writeln!(&mut config, "\t\t</Account>");
        let _ = writeln!(&mut config, "\t</Response>");
        let _ = writeln!(&mut config, "</Autodiscover>");

        Ok(
            Resource::new("application/xml; charset=utf-8", config.into_bytes())
                .into_http_response(),
        )
    }
}

fn parse_autodiscover_request(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("Empty request body".to_string());
    }

    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::with_capacity(128);

    'outer: for tag_name in ["Autodiscover", "Request", "EMailAddress"] {
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let found_tag_name = e.name();
                    if tag_name
                        .as_bytes()
                        .eq_ignore_ascii_case(found_tag_name.as_ref())
                    {
                        continue 'outer;
                    } else if tag_name == "EMailAddress" {
                        // Skip unsupported tags under Request, such as AcceptableResponseSchema
                        let mut tag_count = 0;
                        loop {
                            match reader.read_event_into(&mut buf) {
                                Ok(Event::End(_)) => {
                                    if tag_count == 0 {
                                        break;
                                    } else {
                                        tag_count -= 1;
                                    }
                                }
                                Ok(Event::Start(_)) => {
                                    tag_count += 1;
                                }
                                Ok(Event::Eof) => {
                                    return Err(format!(
                                        "Expected value, found unexpected EOF at position {}.",
                                        reader.buffer_position()
                                    ));
                                }
                                _ => (),
                            }
                        }
                    } else {
                        return Err(format!(
                            "Expected tag {}, found unexpected tag {} at position {}.",
                            tag_name,
                            String::from_utf8_lossy(found_tag_name.as_ref()),
                            reader.buffer_position()
                        ));
                    }
                }
                Ok(Event::Decl(_) | Event::Text(_)) => (),
                Err(e) => {
                    return Err(format!(
                        "Error at position {}: {:?}",
                        reader.buffer_position(),
                        e
                    ));
                }
                Ok(event) => {
                    return Err(format!(
                        "Expected tag {}, found unexpected event {event:?} at position {}.",
                        tag_name,
                        reader.buffer_position()
                    ));
                }
            }
        }
    }

    if let Ok(Event::Text(text)) = reader.read_event_into(&mut buf)
        && let Ok(text) = text.xml_content()
        && text.contains('@')
    {
        return Ok(text.trim().to_lowercase());
    }

    Err(format!(
        "Expected email address, found unexpected value at position {}.",
        reader.buffer_position()
    ))
}

#[cfg(test)]
mod tests {

    #[test]
    fn parse_autodiscover() {
        let r = r#"<?xml version="1.0" encoding="utf-8"?>
            <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                <Request>
                        <EMailAddress>email@example.com</EMailAddress>
                        <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
                </Request>
            </Autodiscover>"#;

        assert_eq!(
            super::parse_autodiscover_request(r.as_bytes()).unwrap(),
            "email@example.com"
        );
    }
}
