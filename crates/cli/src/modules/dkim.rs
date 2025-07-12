/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::cli::{Client, DkimCommands};
use clap::ValueEnum;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum Algorithm {
    /// RSA
    #[default]
    Rsa,
    /// ED25519
    Ed25519,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
struct DkimSignature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    pub algorithm: Algorithm,

    pub domain: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
}

impl DkimCommands {
    pub async fn exec(self, client: Client) {
        match self {
            DkimCommands::Create {
                signature_id,
                algorithm,
                domain,
                selector,
            } => {
                let signature_req = DkimSignature {
                    id: signature_id,
                    algorithm,
                    domain: domain.clone(),
                    selector,
                };
                client
                    .http_request::<Value, _>(Method::POST, "/api/dkim", Some(signature_req))
                    .await;
                eprintln!("Successfully created {algorithm:?} signature for domain {domain:?}");
            }
            DkimCommands::GetPublicKey { signature_id } => {
                let response = client
                    .http_request::<Value, String>(
                        Method::GET,
                        &format!("/api/dkim/{signature_id}"),
                        None,
                    )
                    .await;

                eprintln!();
                eprintln!("Public DKIM key for signature {signature_id}: {response}");
                eprintln!();
            }
        }
    }
}
