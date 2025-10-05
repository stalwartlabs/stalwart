/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::AccessToken;
use directory::Permission;
use jmap_proto::request::{
    CopyRequestMethod, GetRequestMethod, ParseRequestMethod, QueryChangesRequestMethod,
    QueryRequestMethod, RequestMethod, SetRequestMethod, method::MethodObject,
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
                GetRequestMethod::AddressBook(_) => Permission::JmapAddressBookGet,
                GetRequestMethod::ContactCard(_) => Permission::JmapContactCardGet,
                GetRequestMethod::FileNode(_) => Permission::JmapFileNodeGet,
                GetRequestMethod::PrincipalAvailability(_) => {
                    Permission::JmapPrincipalGetAvailability
                }
                GetRequestMethod::Calendar(_) => Permission::JmapCalendarGet,
                GetRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventGet,
                GetRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationGet
                }
                GetRequestMethod::ParticipantIdentity(_) => Permission::JmapParticipantIdentityGet,
                GetRequestMethod::ShareNotification(_) => Permission::JmapShareNotificationGet,
            },
            RequestMethod::Set(m) => match &m {
                SetRequestMethod::Email(_) => Permission::JmapEmailSet,
                SetRequestMethod::Mailbox(_) => Permission::JmapMailboxSet,
                SetRequestMethod::Identity(_) => Permission::JmapIdentitySet,
                SetRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionSet,
                SetRequestMethod::PushSubscription(_) => Permission::JmapPushSubscriptionSet,
                SetRequestMethod::Sieve(_) => Permission::JmapSieveScriptSet,
                SetRequestMethod::VacationResponse(_) => Permission::JmapVacationResponseSet,
                SetRequestMethod::AddressBook(_) => Permission::JmapAddressBookSet,
                SetRequestMethod::ContactCard(_) => Permission::JmapContactCardSet,
                SetRequestMethod::FileNode(_) => Permission::JmapFileNodeSet,
                SetRequestMethod::ShareNotification(_) => Permission::JmapShareNotificationSet,
                SetRequestMethod::Calendar(_) => Permission::JmapCalendarSet,
                SetRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventSet,
                SetRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationSet
                }
                SetRequestMethod::ParticipantIdentity(_) => Permission::JmapParticipantIdentitySet,
            },
            RequestMethod::Changes(_) => match object {
                MethodObject::Email => Permission::JmapEmailChanges,
                MethodObject::Mailbox => Permission::JmapMailboxChanges,
                MethodObject::Thread => Permission::JmapThreadChanges,
                MethodObject::Identity => Permission::JmapIdentityChanges,
                MethodObject::EmailSubmission => Permission::JmapEmailSubmissionChanges,
                MethodObject::Quota => Permission::JmapQuotaChanges,
                MethodObject::ContactCard => Permission::JmapContactCardChanges,
                MethodObject::FileNode => Permission::JmapFileNodeChanges,
                MethodObject::Calendar => Permission::JmapCalendarChanges,
                MethodObject::CalendarEvent => Permission::JmapCalendarEventChanges,
                MethodObject::CalendarEventNotification => {
                    Permission::JmapCalendarEventNotificationChanges
                }
                MethodObject::ParticipantIdentity => Permission::JmapParticipantIdentityChanges,
                MethodObject::ShareNotification => Permission::JmapShareNotificationChanges,
                MethodObject::Principal => Permission::JmapPrincipalChanges,
                MethodObject::Core
                | MethodObject::Blob
                | MethodObject::PushSubscription
                | MethodObject::SearchSnippet
                | MethodObject::VacationResponse
                | MethodObject::SieveScript
                | MethodObject::AddressBook => Permission::JmapEmailChanges,
            },
            RequestMethod::Copy(m) => match &m {
                CopyRequestMethod::Email(_) => Permission::JmapEmailCopy,
                CopyRequestMethod::Blob(_) => Permission::JmapBlobCopy,
                CopyRequestMethod::ContactCard(_) => Permission::JmapContactCardCopy,
                CopyRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventCopy,
            },
            RequestMethod::ImportEmail(_) => Permission::JmapEmailImport,
            RequestMethod::Parse(m) => match &m {
                ParseRequestMethod::Email(_) => Permission::JmapEmailParse,
                ParseRequestMethod::ContactCard(_) => Permission::JmapContactCardParse,
                ParseRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventParse,
            },
            RequestMethod::QueryChanges(m) => match m {
                QueryChangesRequestMethod::Email(_) => Permission::JmapEmailQueryChanges,
                QueryChangesRequestMethod::Mailbox(_) => Permission::JmapMailboxQueryChanges,
                QueryChangesRequestMethod::EmailSubmission(_) => {
                    Permission::JmapEmailSubmissionQueryChanges
                }
                QueryChangesRequestMethod::Sieve(_) => Permission::JmapSieveScriptQueryChanges,
                QueryChangesRequestMethod::Principal(_) => Permission::JmapPrincipalQueryChanges,
                QueryChangesRequestMethod::Quota(_) => Permission::JmapQuotaQueryChanges,
                QueryChangesRequestMethod::ContactCard(_) => {
                    Permission::JmapContactCardQueryChanges
                }
                QueryChangesRequestMethod::FileNode(_) => Permission::JmapFileNodeQueryChanges,
                QueryChangesRequestMethod::CalendarEvent(_) => {
                    Permission::JmapCalendarEventQueryChanges
                }
                QueryChangesRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationQueryChanges
                }
                QueryChangesRequestMethod::ShareNotification(_) => {
                    Permission::JmapShareNotificationQueryChanges
                }
            },
            RequestMethod::Query(m) => match m {
                QueryRequestMethod::Email(_) => Permission::JmapEmailQuery,
                QueryRequestMethod::Mailbox(_) => Permission::JmapMailboxQuery,
                QueryRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionQuery,
                QueryRequestMethod::Sieve(_) => Permission::JmapSieveScriptQuery,
                QueryRequestMethod::Principal(_) => Permission::JmapPrincipalQuery,
                QueryRequestMethod::Quota(_) => Permission::JmapQuotaQuery,
                QueryRequestMethod::ContactCard(_) => Permission::JmapContactCardQuery,
                QueryRequestMethod::FileNode(_) => Permission::JmapFileNodeQuery,
                QueryRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventQuery,
                QueryRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationQuery
                }
                QueryRequestMethod::ShareNotification(_) => Permission::JmapShareNotificationQuery,
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
