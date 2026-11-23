/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ews_request, prelude::*};

ews_request! {
    pub struct StartSearchSession<'a> {
        search_session_id: req M "SearchSessionId" => Cow<'a, str> = |p, a| EwsValue::parse(p, a)?,
    }
}

ews_request! {
    pub struct EndSearchSession<'a> {
        search_session_id: req M "SearchSessionId" => Cow<'a, str> = |p, a| EwsValue::parse(p, a)?,
    }
}

ews_request! {
    pub struct GetSearchSuggestions<'a> {
        search_session_id: req M "SearchSessionId" => Cow<'a, str> = |p, a| EwsValue::parse(p, a)?,
        query: opt M "Query" => Cow<'a, str> = |p, a| EwsValue::parse(p, a)?,
        suggestion_types: opt M "SuggestionTypes" => SuggestionKinds = |p, a| SuggestionKinds::parse(&<Cow<'a, str>>::parse(p, a)?),
        max_suggestions: opt M "MaxSuggestionsCountPerSuggestionType" => i64 = |p, a| EwsValue::parse(p, a)?,
    }
}

ews_request! {
    pub struct ExecuteSearch<'a> {
        search_session_id: req M "SearchSessionId" => Cow<'a, str> = |p, a| EwsValue::parse(p, a)?,
        search_scope: req M "SearchScope" => SearchScope<'a> = |p, _| SearchScope::parse(p)?,
        query: req M "Query" => Cow<'a, str> = |p, a| EwsValue::parse(p, a)?,
        result_row_count: opt M "ResultRowCount" => i64 = |p, a| EwsValue::parse(p, a)?,
        result_row_offset: opt M "ResultRowOffset" => i64 = |p, a| EwsValue::parse(p, a)?,
        id_format: opt M "IdFormat" => IdFormat = |p, a| EwsValue::parse(p, a)?,
        item_types: req M "ItemTypes" => SearchItemTypes = |p, a| SearchItemTypes::parse(&<Cow<'a, str>>::parse(p, a)?),
        include_deleted: opt M "IncludeDeleted" => bool = |p, a| EwsValue::parse(p, a)?,
    }
}
