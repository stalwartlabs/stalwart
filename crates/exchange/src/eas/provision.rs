/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EasContext,
    device::{PolicyKey, WipeState, stored_eas_device},
    response::EasResponse,
};
use crate::store::eas::EasStore;
use common::Server;
use exchange_proto::eas::{
    commands::{
        appdata::{List, OrEmpty},
        provision::{
            POLICY_TYPE_WBXML, PolicyDoc, PolicyRequest, PolicyResponse, ProvisionRequest,
            ProvisionResponse,
        },
    },
    http::Command,
    status::{PolicyStatus, ProvisionStatus, SettingsStatus},
    wbxml::Decoder,
};

const WIPE_ACK_SUCCESS: u8 = 1;
const POLICY_DOC_COMPLEX_CHARACTERS: u8 = 1;
const POLICY_DOC_ALLOW_BLUETOOTH: u8 = 2;
const POLICY_DOC_ALGORITHM_NEGOTIATION: i32 = 2;
const POLICY_DOC_NO_TRUNCATION: i32 = -1;

pub trait EasProvision: Sync + Send {
    fn eas_provision(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

impl EasProvision for Server {
    async fn eas_provision(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::Provision,
                ProvisionStatus::PROTOCOL_ERROR.into(),
            ));
        };
        let request = match ProvisionRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::Provision,
                    err.status(Command::Provision),
                ));
            }
        };

        let mut response = ProvisionResponse {
            device_information: request
                .device_information
                .is_some()
                .then_some(SettingsStatus::SUCCESS),
            status: ProvisionStatus::SUCCESS,
            policy: None,
            remote_wipe: false,
            account_only_remote_wipe: false,
        };

        let wipe = WipeState::from_code(ctx.device.wipe);
        if wipe.is_pending() {
            let acknowledged = request.remote_wipe.or(request.account_only_remote_wipe);
            match acknowledged {
                Some(WIPE_ACK_SUCCESS) => {
                    self.update_eas_device(ctx.account_id, ctx.device.slot, |device| {
                        device.wipe = WipeState::Wiped.code();
                    })
                    .await?;
                }
                acknowledged => {
                    if acknowledged.is_some() {
                        response.status = ProvisionStatus::PROTOCOL_ERROR;
                    }
                    if wipe == WipeState::AccountOnly && ctx.version.is_16() {
                        response.account_only_remote_wipe = true;
                    } else {
                        response.remote_wipe = true;
                    }
                }
            }
            return Ok(encode(ctx, &response));
        }

        if let Some(policy) = &request.policy {
            response.policy = Some(eas_policy(self, ctx, policy).await?);
        }

        Ok(encode(ctx, &response))
    }
}

async fn eas_policy(
    server: &Server,
    ctx: &EasContext<'_>,
    policy: &PolicyRequest<'_>,
) -> trc::Result<PolicyResponse<'static>> {
    if policy.policy_type != POLICY_TYPE_WBXML {
        return Ok(PolicyResponse {
            policy_type: "",
            status: PolicyStatus::UNKNOWN_POLICY_TYPE,
            policy_key: None,
            document: None,
        });
    }

    if policy.status.is_none() {
        let key = PolicyKey::new_temporary();
        server
            .update_eas_device(ctx.account_id, ctx.device.slot, |device| {
                device.policy_key = key;
            })
            .await?;
        return Ok(PolicyResponse {
            policy_type: POLICY_TYPE_WBXML,
            status: PolicyStatus::SUCCESS,
            policy_key: Some(key),
            document: Some(permissive_policy()),
        });
    }

    let stored = stored_eas_device(server, ctx.account_id, ctx.device.slot)
        .await?
        .map(|device| PolicyKey::from_stored(device.policy_key));
    match (stored, policy.policy_key) {
        (Some(PolicyKey::Temporary(issued)), Some(sent)) if issued == sent => {
            let key = PolicyKey::new_permanent();
            server
                .update_eas_device(ctx.account_id, ctx.device.slot, |device| {
                    device.policy_key = key;
                })
                .await?;
            Ok(PolicyResponse {
                policy_type: POLICY_TYPE_WBXML,
                status: PolicyStatus::SUCCESS,
                policy_key: Some(key),
                document: None,
            })
        }
        _ => Ok(PolicyResponse {
            policy_type: POLICY_TYPE_WBXML,
            status: PolicyStatus::WRONG_POLICY_KEY,
            policy_key: None,
            document: None,
        }),
    }
}

fn encode(ctx: &EasContext<'_>, response: &ProvisionResponse<'_>) -> EasResponse {
    EasResponse::encode(ctx.version, |encoder| response.encode(encoder))
}

fn permissive_policy() -> PolicyDoc<'static> {
    PolicyDoc {
        device_password_enabled: Some(false),
        alphanumeric_device_password_required: Some(false),
        password_recovery_enabled: Some(false),
        require_storage_card_encryption: Some(false),
        attachments_enabled: Some(true),
        min_device_password_length: Some(OrEmpty(None)),
        max_inactivity_time_device_lock: Some(OrEmpty(None)),
        max_device_password_failed_attempts: Some(OrEmpty(None)),
        max_attachment_size: Some(OrEmpty(None)),
        allow_simple_device_password: Some(true),
        device_password_expiration: Some(OrEmpty(None)),
        device_password_history: Some(0),
        allow_storage_card: Some(true),
        allow_camera: Some(true),
        require_device_encryption: Some(false),
        allow_unsigned_applications: Some(true),
        allow_unsigned_installation_packages: Some(true),
        min_device_password_complex_characters: Some(POLICY_DOC_COMPLEX_CHARACTERS),
        allow_wi_fi: Some(true),
        allow_text_messaging: Some(true),
        allow_popimap_email: Some(true),
        allow_bluetooth: Some(POLICY_DOC_ALLOW_BLUETOOTH),
        allow_ir_da: Some(true),
        require_manual_sync_when_roaming: Some(false),
        allow_desktop_sync: Some(true),
        max_calendar_age_filter: Some(0),
        allow_html_email: Some(true),
        max_email_age_filter: Some(0),
        max_email_body_truncation_size: Some(POLICY_DOC_NO_TRUNCATION),
        max_email_html_body_truncation_size: Some(POLICY_DOC_NO_TRUNCATION),
        require_signed_smime_messages: Some(false),
        require_encrypted_smime_messages: Some(false),
        require_signed_smime_algorithm: Some(0),
        require_encryption_smime_algorithm: Some(0),
        allow_smime_encryption_algorithm_negotiation: Some(POLICY_DOC_ALGORITHM_NEGOTIATION),
        allow_smime_soft_certs: Some(true),
        allow_browser: Some(true),
        allow_consumer_email: Some(true),
        allow_remote_desktop: Some(true),
        allow_internet_sharing: Some(true),
        unapproved_in_rom_application_list: Some(List(Vec::new())),
        approved_application_list: Some(List(Vec::new())),
    }
}
