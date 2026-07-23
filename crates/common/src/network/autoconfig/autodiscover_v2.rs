/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, manager::application::Resource};
use utils::url_params::UrlParams;

impl Server {
    pub async fn handle_autodiscover_v2_request(
        &self,
        query: Option<&str>,
        path_email: Option<&str>,
    ) -> trc::Result<Result<Resource<Vec<u8>>, String>> {
        // Parse query parameters
        let params = UrlParams::new(query);
        let emailaddress = path_email
            .filter(|email| !email.is_empty())
            .or_else(|| params.get("Email"))
            .unwrap_or_default()
            .to_lowercase();
        let protocol = params.get("Protocol").unwrap_or_default();

        // Validate email address
        let Some((_, domain)) = emailaddress.rsplit_once('@') else {
            return Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("Missing domain in email address"));
        };

        if domain.is_empty() {
            return Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("Missing domain in email address"));
        }

        if protocol.eq_ignore_ascii_case("autodiscoverv1") {
            let server_name = &self.core.network.server_name;
            let body = format!(
                "{{\"Protocol\":\"AutodiscoverV1\",\
                     \"Url\":\"https://{server_name}/autodiscover/autodiscover.xml\"}}"
            );
            Ok(Ok(Resource::new(
                "application/json; charset=utf-8",
                body.into_bytes(),
            )))
        } else {
            let safe_protocol: String = protocol
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            let err = format!(
                "{{\"ErrorCode\":\"InvalidProtocol\",\
                     \"ErrorMessage\":\"The given protocol value \
                     '{safe_protocol}' is invalid. \
                     Supported values are 'AutodiscoverV1'\"}}"
            );
            Ok(Err(err))
        }
    }
}
