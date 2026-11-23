/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EasContext,
    oof::{oof_get, oof_set},
    response::EasResponse,
};
use common::Server;
use exchange_proto::eas::{
    commands::{
        appdata::List,
        settings::{
            Account, EmailAddresses, SettingsAction, SettingsRequest, SettingsResponse,
            SettingsResult,
        },
    },
    http::Command,
    status::SettingsStatus,
    wbxml::Decoder,
};
use std::borrow::Cow;
use types::type_state::DataType;

pub trait EasSettings: Sync + Send {
    fn eas_settings(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

impl EasSettings for Server {
    async fn eas_settings(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::Settings,
                SettingsStatus::PROTOCOL_ERROR.into(),
            ));
        };
        let request = match SettingsRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::Settings,
                    err.status(Command::Settings),
                ));
            }
        };

        let mut results = Vec::with_capacity(request.actions.len());
        for action in &request.actions {
            results.push(match action {
                SettingsAction::OofGet { body_type } => {
                    if ctx.allows_type(DataType::VacationResponse) {
                        SettingsResult::Oof {
                            status: SettingsStatus::SUCCESS,
                            get: Some(Box::new(oof_get(self, ctx.account_id, body_type).await?)),
                        }
                    } else {
                        SettingsResult::Oof {
                            status: SettingsStatus::ACCESS_DENIED,
                            get: None,
                        }
                    }
                }
                SettingsAction::OofSet(oof) => SettingsResult::Oof {
                    status: if ctx.allows_type(DataType::VacationResponse) {
                        oof_set(self, ctx, oof).await?
                    } else {
                        SettingsStatus::ACCESS_DENIED
                    },
                    get: None,
                },
                SettingsAction::DevicePasswordSet { .. } => SettingsResult::DevicePassword {
                    status: SettingsStatus::SUCCESS,
                },
                SettingsAction::DevicePasswordTooLong => SettingsResult::DevicePassword {
                    status: SettingsStatus::INVALID_ARGUMENTS,
                },
                SettingsAction::DeviceInformationSet(_) => SettingsResult::DeviceInformation {
                    status: SettingsStatus::SUCCESS,
                },
                SettingsAction::UserInformationGet => {
                    let account = self.account_info(ctx.account_id).await?;
                    let addresses: Vec<Cow<'static, str>> = account
                        .addresses()
                        .iter()
                        .map(|address| Cow::Owned(address.clone()))
                        .collect();
                    let primary = addresses.first().cloned();
                    let display_name = account
                        .description()
                        .unwrap_or_else(|| account.name())
                        .to_string();
                    SettingsResult::UserInformation {
                        status: SettingsStatus::SUCCESS,
                        email_addresses: Some(EmailAddresses {
                            smtp_addresses: addresses.clone(),
                            primary_smtp_address: None,
                        }),
                        accounts: Some(List(vec![Account {
                            user_display_name: Some(Cow::Owned(display_name)),
                            email_addresses: Some(EmailAddresses {
                                smtp_addresses: addresses,
                                primary_smtp_address: primary,
                            }),
                            ..Default::default()
                        }])),
                    }
                }
                SettingsAction::RightsManagementInformationGet => {
                    SettingsResult::RightsManagementInformation {
                        status: SettingsStatus::SUCCESS,
                        templates: None,
                    }
                }
            });
        }

        let response = SettingsResponse {
            status: SettingsStatus::SUCCESS,
            results,
        };
        Ok(EasResponse::encode(ctx.version, |encoder| {
            response.encode(encoder)
        }))
    }
}
