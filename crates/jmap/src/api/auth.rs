/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::AccessToken;
use directory::Permission;
use jmap_proto::request::{
    CopyRequestMethod, GetRequestMethod, QueryChangesRequestMethod, QueryRequestMethod,
    RequestMethod, SetRequestMethod, method::MethodObject,
};
use types::{collection::Collection, id::Id};

pub trait JmapAuthorization {
    fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self>;
    fn assert_has_jmap_permission(
        &self,
        request: &RequestMethod,
        object: MethodObject,
    ) -> trc::Result<()>;
    fn assert_has_access(&self, to_account_id: Id, to_collection: Collection)
    -> trc::Result<&Self>;
}

impl JmapAuthorization for AccessToken {
    fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self> {
        if self.is_member(account_id.document_id()) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details(format!("You are not an owner of account {}", account_id)))
        }
    }

    fn assert_has_access(
        &self,
        to_account_id: Id,
        to_collection: Collection,
    ) -> trc::Result<&Self> {
        if self.has_access(to_account_id.document_id(), to_collection) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden.into_err().details(format!(
                "You do not have access to account {}",
                to_account_id
            )))
        }
    }

    fn assert_has_jmap_permission(
        &self,
        request: &RequestMethod,
        object: MethodObject,
    ) -> trc::Result<()> {
        let permission = match request {
            RequestMethod::Get(m) => match &m {
                GetRequestMethod::Email(_) => Permission::JmapEmailGet,
                GetRequestMethod::Mailbox(_) => Permission::JmapMailboxGet,
                GetRequestMethod::Thread(_) => Permission::JmapThreadGet,
                GetRequestMethod::Identity(_) => Permission::JmapIdentityGet,
                GetRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionGet,
                GetRequestMethod::PushSubscription(_) => Permission::JmapPushSubscriptionGet,
                GetRequestMethod::Sieve(_) => Permission::JmapSieveScriptGet,
                GetRequestMethod::VacationResponse(_) => Permission::JmapVacationResponseGet,
                GetRequestMethod::Principal(_) => Permission::JmapPrincipalGet,
                GetRequestMethod::Quota(_) => Permission::JmapQuotaGet,
                GetRequestMethod::Blob(_) => Permission::JmapBlobGet,
            },
            RequestMethod::Set(m) => match &m {
                SetRequestMethod::Email(_) => Permission::JmapEmailSet,
                SetRequestMethod::Mailbox(_) => Permission::JmapMailboxSet,
                SetRequestMethod::Identity(_) => Permission::JmapIdentitySet,
                SetRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionSet,
                SetRequestMethod::PushSubscription(_) => Permission::JmapPushSubscriptionSet,
                SetRequestMethod::Sieve(_) => Permission::JmapSieveScriptSet,
                SetRequestMethod::VacationResponse(_) => Permission::JmapVacationResponseSet,
            },
            RequestMethod::Changes(_) => match object {
                MethodObject::Email => Permission::JmapEmailChanges,
                MethodObject::Mailbox => Permission::JmapMailboxChanges,
                MethodObject::Thread => Permission::JmapThreadChanges,
                MethodObject::Identity => Permission::JmapIdentityChanges,
                MethodObject::EmailSubmission => Permission::JmapEmailSubmissionChanges,
                MethodObject::Quota => Permission::JmapQuotaChanges,
                MethodObject::Core
                | MethodObject::Blob
                | MethodObject::PushSubscription
                | MethodObject::SearchSnippet
                | MethodObject::VacationResponse
                | MethodObject::SieveScript
                | MethodObject::Principal => Permission::JmapEmailChanges, // Unimplemented
            },
            RequestMethod::Copy(m) => match &m {
                CopyRequestMethod::Email(_) => Permission::JmapEmailCopy,
                CopyRequestMethod::Blob(_) => Permission::JmapBlobCopy,
            },
            RequestMethod::ImportEmail(_) => Permission::JmapEmailImport,
            RequestMethod::ParseEmail(_) => Permission::JmapEmailParse,
            RequestMethod::QueryChanges(m) => match m {
                QueryChangesRequestMethod::Email(_) => Permission::JmapEmailQueryChanges,
                QueryChangesRequestMethod::Mailbox(_) => Permission::JmapMailboxQueryChanges,
                QueryChangesRequestMethod::EmailSubmission(_) => {
                    Permission::JmapEmailSubmissionQueryChanges
                }
                QueryChangesRequestMethod::Sieve(_) => Permission::JmapSieveScriptQueryChanges,
                QueryChangesRequestMethod::Principal(_) => Permission::JmapPrincipalQueryChanges,
                QueryChangesRequestMethod::Quota(_) => Permission::JmapQuotaQueryChanges,
            },
            RequestMethod::Query(m) => match m {
                QueryRequestMethod::Email(_) => Permission::JmapEmailQuery,
                QueryRequestMethod::Mailbox(_) => Permission::JmapMailboxQuery,
                QueryRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionQuery,
                QueryRequestMethod::Sieve(_) => Permission::JmapSieveScriptQuery,
                QueryRequestMethod::Principal(_) => Permission::JmapPrincipalQuery,
                QueryRequestMethod::Quota(_) => Permission::JmapQuotaQuery,
            },
            RequestMethod::SearchSnippet(_) => Permission::JmapSearchSnippet,
            RequestMethod::ValidateScript(_) => Permission::JmapSieveScriptValidate,
            RequestMethod::LookupBlob(_) => Permission::JmapBlobLookup,
            RequestMethod::UploadBlob(_) => Permission::JmapBlobUpload,
            RequestMethod::Echo(_) => Permission::JmapEcho,
            RequestMethod::Error(_) => return Ok(()),
        };

        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("You are not authorized to perform this action"))
        }
    }
}
