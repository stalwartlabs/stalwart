/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, manager::application::Resource};
use registry::schema::enums::ServiceProtocol;
use std::fmt::Write;
use utils::url_params::UrlParams;

impl Server {
    pub async fn handle_autoconfig_request(
        &self,
        uri: Option<&str>,
    ) -> trc::Result<Resource<Vec<u8>>> {
        // Obtain parameters
        let params = UrlParams::new(uri);
        let emailaddress_param = params
            .get("emailaddress")
            .unwrap_or_default()
            .to_lowercase();
        let default_host = &self.core.network.server_name;
        let (emailaddress, domain) =
            if let Some((_, domain)) = emailaddress_param.rsplit_once('@') {
                (emailaddress_param.as_str(), domain)
            } else {
                ("%EMAILADDRESS%", default_host.as_str())
            };

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
        for (protocol, service) in &self.core.network.info.services {
            let (protocol, tag, ports) = match protocol {
                ServiceProtocol::Smtp => ("smtp", "outgoingServer", [587, 465]),
                ServiceProtocol::Imap => ("imap", "incomingServer", [143, 993]),
                ServiceProtocol::Pop3 => ("pop3", "incomingServer", [110, 995]),
                _ => continue,
            };
            for (is_tls, port) in ports.into_iter().enumerate() {
                if is_tls == 1 || service.cleartext {
                    let server_name = service.hostname.as_deref().unwrap_or(default_host);
                    let _ = writeln!(&mut config, "\t\t<{tag} type=\"{protocol}\">");
                    let _ = writeln!(&mut config, "\t\t\t<hostname>{server_name}</hostname>");
                    let _ = writeln!(&mut config, "\t\t\t<port>{port}</port>");
                    let _ = writeln!(
                        &mut config,
                        "\t\t\t<socketType>{}</socketType>",
                        if is_tls == 1 { "SSL" } else { "STARTTLS" }
                    );
                    let _ = writeln!(&mut config, "\t\t\t<username>{emailaddress}</username>");
                    let _ = writeln!(
                        &mut config,
                        "\t\t\t<authentication>password-cleartext</authentication>"
                    );
                    let _ = writeln!(&mut config, "\t\t</{tag}>");
                }
            }
        }

        config.push_str("\t</emailProvider>\n");

        for (protocol, service) in &self.core.network.info.services {
            let (tag, protocol, url) = match protocol {
                ServiceProtocol::Carddav => ("addressBook", "carddav", "card"),
                ServiceProtocol::Caldav => ("calendar", "caldav", "cal"),
                ServiceProtocol::Webdav => ("fileShare", "webdav", "file"),
                _ => continue,
            };
            let server_name = service.hostname.as_deref().unwrap_or(default_host);

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

        Ok(Resource::new(
            "application/xml; charset=utf-8",
            config.into_bytes(),
        ))
    }
}
