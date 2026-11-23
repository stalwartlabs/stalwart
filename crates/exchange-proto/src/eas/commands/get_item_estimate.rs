/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use smallvec::SmallVec;

use super::sync::{SyncOptions, options::FilterFit};
use super::{
    Children, CommandError, Counter, MAX_GET_ITEM_ESTIMATE_COLLECTIONS, MAX_ID_LEN, SyncKeyStr,
    read_bool, read_id, required,
};
use crate::eas::status::GetItemEstimateStatus;
use crate::eas::tokens::ProtocolVersion;
use crate::eas::tokens::tag::{airsync as sync, get_item_estimate as gie};
use crate::eas::types::Class;
use crate::eas::wbxml::{Decoder, Encoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstimateCollection<'a> {
    pub sync_key: Option<SyncKeyStr<'a>>,
    pub collection_id: Cow<'a, str>,
    pub conversation_mode: Option<bool>,
    pub options: SmallVec<[SyncOptions; 2]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetItemEstimateRequest<'a> {
    pub collections: Vec<EstimateCollection<'a>>,
}

impl<'a> GetItemEstimateRequest<'a> {
    pub fn parse(dec: &mut Decoder<'a>, _version: ProtocolVersion) -> Result<Self, CommandError> {
        let mut request = GetItemEstimateRequest::default();
        let mut counter = Counter::new(MAX_GET_ITEM_ESTIMATE_COLLECTIONS);
        let mut children = Children::root(dec, gie::GET_ITEM_ESTIMATE)?;
        while let Some(tag) = children.next(dec)? {
            if tag != gie::COLLECTIONS {
                continue;
            }
            let mut list = Children::of(dec);
            while let Some(tag) = list.next(dec)? {
                if tag == gie::COLLECTION {
                    counter.bump(tag)?;
                    request.collections.push(EstimateCollection::parse(dec)?);
                }
            }
        }
        if request.collections.is_empty() {
            return Err(CommandError::Missing {
                tag: gie::COLLECTION,
            });
        }
        Ok(request)
    }
}

impl EstimateCollection<'_> {
    pub fn filter_fit(&self, class: Class) -> FilterFit {
        self.options
            .iter()
            .map(|options| options.filter_fit(class))
            .find(|fit| *fit != FilterFit::Fits)
            .unwrap_or(FilterFit::Fits)
    }

    pub fn mixes_classes(&self) -> bool {
        self.options.len() > 1
            && self.options.iter().any(|options| {
                options
                    .class
                    .is_some_and(|class| !matches!(class, Class::Email | Class::Sms))
            })
    }
}

impl<'a> EstimateCollection<'a> {
    fn parse(dec: &mut Decoder<'a>) -> Result<Self, CommandError> {
        let mut sync_key = None;
        let mut collection_id = None;
        let mut conversation_mode = None;
        let mut options = SmallVec::new();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                sync::SYNC_KEY => sync_key = Some(SyncKeyStr(read_id(dec, tag, MAX_ID_LEN)?)),
                gie::COLLECTION_ID => collection_id = Some(read_id(dec, tag, MAX_ID_LEN)?),
                sync::CONVERSATION_MODE => conversation_mode = Some(read_bool(dec, tag)?),
                sync::OPTIONS => {
                    if options.len() >= super::sync::MAX_OPTIONS {
                        return Err(CommandError::TooMany {
                            tag,
                            limit: super::sync::MAX_OPTIONS as u32,
                        });
                    }
                    options.push(SyncOptions::parse(dec)?);
                }
                _ => {}
            }
        }
        Ok(EstimateCollection {
            sync_key,
            collection_id: required(collection_id, gie::COLLECTION_ID)?,
            conversation_mode,
            options,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstimateResult<'x> {
    pub status: GetItemEstimateStatus,
    pub collection_id: Option<&'x str>,
    pub estimate: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetItemEstimateResponse<'x> {
    pub status: Option<GetItemEstimateStatus>,
    pub responses: Vec<EstimateResult<'x>>,
}

impl GetItemEstimateResponse<'_> {
    pub fn encode(&self, enc: &mut Encoder) {
        enc.start(gie::GET_ITEM_ESTIMATE);
        if let Some(status) = self.status {
            enc.text_u64(gie::STATUS, u64::from(status.0));
        }
        for response in &self.responses {
            enc.start(gie::RESPONSE)
                .text_u64(gie::STATUS, u64::from(response.status.0));
            if let Some(collection_id) = response.collection_id {
                enc.start(gie::COLLECTION)
                    .text_str(gie::COLLECTION_ID, collection_id);
                if let Some(estimate) = response.estimate {
                    enc.text_u64(gie::ESTIMATE, u64::from(estimate));
                }
                enc.end();
            }
            enc.end();
        }
        enc.end();
    }
}
