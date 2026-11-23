/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::Server;
use email::sieve::rules::managed::ManagedSieveScript;
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::vacation_response::{
        VacationResponse, VacationResponseProperty, VacationResponseValue,
    },
    request::{
        MaybeInvalid,
        reference::{MaybeIdReference, MaybeResultReference},
    },
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use std::future::Future;
use types::{collection::SyncCollection, id::Id};

pub trait VacationResponseGet: Sync + Send {
    fn vacation_response_get(
        &self,
        request: GetRequest<VacationResponse>,
    ) -> impl Future<Output = trc::Result<GetResponse<VacationResponse>>> + Send;
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
                match id {
                    MaybeIdReference::Id(id) if id.is_singleton() => {
                        do_get = true;
                    }
                    MaybeIdReference::Id(id) => {
                        response.push_not_found(id);
                    }
                    MaybeIdReference::Invalid(s) | MaybeIdReference::Reference(s) => {
                        response.not_found.push(MaybeInvalid::Invalid(s));
                    }
                }
            }
            do_get
        } else {
            true
        };
        if do_get {
            let vacation = self.managed_vacation_read(account_id).await?;
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    VacationResponseProperty::Id => {
                        result.insert_unchecked(VacationResponseProperty::Id, Id::singleton());
                    }
                    VacationResponseProperty::IsEnabled => {
                        result.insert_unchecked(
                            VacationResponseProperty::IsEnabled,
                            vacation.as_ref().is_some_and(|v| v.is_enabled),
                        );
                    }
                    VacationResponseProperty::FromDate | VacationResponseProperty::ToDate => {
                        let date = vacation.as_ref().and_then(|v| {
                            if *property == VacationResponseProperty::FromDate {
                                v.from_date
                            } else {
                                v.to_date
                            }
                        });
                        result.insert_unchecked(
                            property.clone(),
                            date.map_or(Value::Null, |date| {
                                Value::Element(VacationResponseValue::Date(UTCDate::from(date)))
                            }),
                        );
                    }
                    VacationResponseProperty::Subject => {
                        result.insert_unchecked(
                            VacationResponseProperty::Subject,
                            vacation.as_ref().and_then(|v| v.subject.clone()),
                        );
                    }
                    VacationResponseProperty::TextBody => {
                        result.insert_unchecked(
                            VacationResponseProperty::TextBody,
                            vacation.as_ref().and_then(|v| v.text_body.clone()),
                        );
                    }
                    VacationResponseProperty::HtmlBody => {
                        result.insert_unchecked(
                            VacationResponseProperty::HtmlBody,
                            vacation.as_ref().and_then(|v| v.html_body.clone()),
                        );
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
