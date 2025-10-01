/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, changes::state::StateManager};
use common::Server;
use email::submission::UndoStatus;
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::email_submission::{self, EmailSubmissionComparator, EmailSubmissionFilter},
};
use std::future::Future;
use store::{
    SerializeInfallible,
    query::{self},
};
use types::{
    collection::{Collection, SyncCollection},
    field::EmailSubmissionField,
};

pub trait EmailSubmissionQuery: Sync + Send {
    fn email_submission_query(
        &self,
        request: QueryRequest<email_submission::EmailSubmission>,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl EmailSubmissionQuery for Server {
    async fn email_submission_query(
        &self,
        mut request: QueryRequest<email_submission::EmailSubmission>,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    EmailSubmissionFilter::IdentityIds(ids) => {
                        filters.push(query::Filter::Or);
                        for id in ids {
                            filters.push(query::Filter::eq(
                                EmailSubmissionField::IdentityId,
                                id.document_id().serialize(),
                            ));
                        }
                        filters.push(query::Filter::End);
                    }
                    EmailSubmissionFilter::EmailIds(ids) => {
                        filters.push(query::Filter::Or);
                        for id in ids {
                            filters.push(query::Filter::eq(
                                EmailSubmissionField::EmailId,
                                id.id().serialize(),
                            ));
                        }
                        filters.push(query::Filter::End);
                    }
                    EmailSubmissionFilter::ThreadIds(ids) => {
                        filters.push(query::Filter::Or);
                        for id in ids {
                            filters.push(query::Filter::eq(
                                EmailSubmissionField::ThreadId,
                                id.document_id().serialize(),
                            ));
                        }
                        filters.push(query::Filter::End);
                    }
                    EmailSubmissionFilter::UndoStatus(undo_status) => {
                        filters.push(query::Filter::eq(
                            EmailSubmissionField::UndoStatus,
                            match undo_status {
                                email_submission::UndoStatus::Pending => UndoStatus::Pending,
                                email_submission::UndoStatus::Final => UndoStatus::Final,
                                email_submission::UndoStatus::Canceled => UndoStatus::Canceled,
                            }
                            .as_index()
                            .serialize(),
                        ))
                    }
                    EmailSubmissionFilter::Before(before) => filters.push(query::Filter::lt(
                        EmailSubmissionField::SendAt,
                        (before.timestamp() as u64).serialize(),
                    )),
                    EmailSubmissionFilter::After(after) => filters.push(query::Filter::gt(
                        EmailSubmissionField::SendAt,
                        (after.timestamp() as u64).serialize(),
                    )),

                    EmailSubmissionFilter::_T(other) => {
                        return Err(trc::JmapEvent::UnsupportedFilter.into_err().details(other));
                    }
                },

                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
            }
        }

        let result_set = self
            .filter(account_id, Collection::EmailSubmission, filters)
            .await?;

        let (response, paginate) = self
            .build_query_response(
                &result_set,
                self.get_state(account_id, SyncCollection::EmailSubmission)
                    .await?,
                &request,
            )
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .and_then(|s| if !s.is_empty() { s.into() } else { None })
                .unwrap_or_else(|| vec![Comparator::descending(EmailSubmissionComparator::SentAt)])
            {
                comparators.push(match comparator.property {
                    EmailSubmissionComparator::EmailId => query::Comparator::field(
                        EmailSubmissionField::EmailId,
                        comparator.is_ascending,
                    ),
                    EmailSubmissionComparator::ThreadId => query::Comparator::field(
                        EmailSubmissionField::ThreadId,
                        comparator.is_ascending,
                    ),
                    EmailSubmissionComparator::SentAt => query::Comparator::field(
                        EmailSubmissionField::SendAt,
                        comparator.is_ascending,
                    ),
                    EmailSubmissionComparator::_T(other) => {
                        return Err(trc::JmapEvent::UnsupportedSort.into_err().details(other));
                    }
                });
            }

            // Sort results
            self.sort(result_set, comparators, paginate, response).await
        } else {
            Ok(response)
        }
    }
}
