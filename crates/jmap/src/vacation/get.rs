/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::Server;
use email::sieve::{SieveScript, ingest::SieveScriptIngest};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::vacation_response::{
        VacationResponse, VacationResponseProperty, VacationResponseValue,
    },
    request::reference::MaybeResultReference,
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use std::future::Future;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::SieveField,
    id::Id,
};

pub trait VacationResponseGet: Sync + Send {
    fn vacation_response_get(
        &self,
        request: GetRequest<VacationResponse>,
    ) -> impl Future<Output = trc::Result<GetResponse<VacationResponse>>> + Send;

    fn get_vacation_sieve_script_id(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;
}

impl VacationResponseGet for Server {
    async fn vacation_response_get(
        &self,
        mut request: GetRequest<VacationResponse>,
    ) -> trc::Result<GetResponse<VacationResponse>> {
        let account_id = request.account_id.document_id();
        let properties = request.unwrap_properties(&[
            VacationResponseProperty::Id,
            VacationResponseProperty::IsEnabled,
            VacationResponseProperty::FromDate,
            VacationResponseProperty::ToDate,
            VacationResponseProperty::Subject,
            VacationResponseProperty::TextBody,
            VacationResponseProperty::HtmlBody,
        ]);
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::SieveScript)
                .await?
                .into(),
            list: Vec::with_capacity(1),
            not_found: vec![],
        };

        let do_get = if let Some(MaybeResultReference::Value(ids)) = request.ids {
            let mut do_get = false;
            for id in ids {
                match id.try_unwrap() {
                    Some(id) if id.is_singleton() => {
                        do_get = true;
                    }
                    Some(id) => {
                        response.not_found.push(id);
                    }
                    _ => {}
                }
            }
            do_get
        } else {
            true
        };
        if do_get {
            if let Some(document_id) = self.get_vacation_sieve_script_id(account_id).await? {
                if let Some(sieve_) = self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account_id,
                        Collection::SieveScript,
                        document_id,
                    ))
                    .await?
                {
                    let active_script_id = self.sieve_script_get_active_id(account_id).await?;
                    let sieve = sieve_
                        .unarchive::<SieveScript>()
                        .caused_by(trc::location!())?;
                    let vacation = sieve.vacation_response.as_ref();
                    let mut result = Map::with_capacity(properties.len());
                    for property in &properties {
                        match property {
                            VacationResponseProperty::Id => {
                                result.insert_unchecked(
                                    VacationResponseProperty::Id,
                                    Id::singleton(),
                                );
                            }
                            VacationResponseProperty::IsEnabled => {
                                result.insert_unchecked(
                                    VacationResponseProperty::IsEnabled,
                                    active_script_id == Some(document_id),
                                );
                            }
                            VacationResponseProperty::FromDate => {
                                result.insert_unchecked(
                                    VacationResponseProperty::FromDate,
                                    vacation.and_then(|r| {
                                        r.from_date
                                            .as_ref()
                                            .map(u64::from)
                                            .map(UTCDate::from)
                                            .map(|v| Value::Element(VacationResponseValue::Date(v)))
                                    }),
                                );
                            }
                            VacationResponseProperty::ToDate => {
                                result.insert_unchecked(
                                    VacationResponseProperty::ToDate,
                                    vacation.and_then(|r| {
                                        r.to_date
                                            .as_ref()
                                            .map(u64::from)
                                            .map(UTCDate::from)
                                            .map(|v| Value::Element(VacationResponseValue::Date(v)))
                                    }),
                                );
                            }
                            VacationResponseProperty::Subject => {
                                result.insert_unchecked(
                                    VacationResponseProperty::Subject,
                                    vacation.and_then(|r| r.subject.as_ref()),
                                );
                            }
                            VacationResponseProperty::TextBody => {
                                result.insert_unchecked(
                                    VacationResponseProperty::TextBody,
                                    vacation.and_then(|r| r.text_body.as_ref()),
                                );
                            }
                            VacationResponseProperty::HtmlBody => {
                                result.insert_unchecked(
                                    VacationResponseProperty::HtmlBody,
                                    vacation.and_then(|r| r.html_body.as_ref()),
                                );
                            }
                        }
                    }
                    response.list.push(result.into());
                } else {
                    response.not_found.push(Id::singleton());
                }
            } else {
                response.not_found.push(Id::singleton());
            }
        }

        Ok(response)
    }

    async fn get_vacation_sieve_script_id(&self, account_id: u32) -> trc::Result<Option<u32>> {
        self.document_ids_matching(
            account_id,
            Collection::SieveScript,
            SieveField::Name,
            "vacation".as_bytes(),
        )
        .await
        .map(|r| r.min())
    }
}
