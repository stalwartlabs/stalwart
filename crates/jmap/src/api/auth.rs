/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::AccessToken;
use jmap_proto::{
    method::set::SetRequest,
    object::JmapObject,
    request::{
        CopyRequestMethod, GetRequestMethod, ParseRequestMethod, QueryChangesRequestMethod,
        QueryRequestMethod, RequestMethod, SetRequestMethod, method::MethodObject,
        reference::MaybeResultReference,
    },
};
use registry::schema::enums::Permission;
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
                GetRequestMethod::Registry(_) => {
                    let MethodObject::Registry(object_type) = object else {
                        unreachable!()
                    };
                    object_type.get_permission()
                }
            },
            RequestMethod::Set(m) => {
                return match &m {
                    SetRequestMethod::Email(s) => validate_set(
                        s,
                        self,
                        Permission::JmapEmailCreate,
                        Permission::JmapEmailUpdate,
                        Permission::JmapEmailDestroy,
                    ),
                    SetRequestMethod::Mailbox(s) => validate_set(
                        s,
                        self,
                        Permission::JmapMailboxCreate,
                        Permission::JmapMailboxUpdate,
                        Permission::JmapMailboxDestroy,
                    ),
                    SetRequestMethod::Identity(s) => validate_set(
                        s,
                        self,
                        Permission::JmapIdentityCreate,
                        Permission::JmapIdentityUpdate,
                        Permission::JmapIdentityDestroy,
                    ),
                    SetRequestMethod::EmailSubmission(s) => validate_set(
                        s,
                        self,
                        Permission::JmapEmailSubmissionCreate,
                        Permission::JmapEmailSubmissionUpdate,
                        Permission::JmapEmailSubmissionDestroy,
                    ),
                    SetRequestMethod::PushSubscription(s) => validate_set(
                        s,
                        self,
                        Permission::JmapPushSubscriptionCreate,
                        Permission::JmapPushSubscriptionUpdate,
                        Permission::JmapPushSubscriptionDestroy,
                    ),
                    SetRequestMethod::Sieve(s) => validate_set(
                        s,
                        self,
                        Permission::JmapSieveScriptCreate,
                        Permission::JmapSieveScriptUpdate,
                        Permission::JmapSieveScriptDestroy,
                    ),
                    SetRequestMethod::VacationResponse(s) => validate_set(
                        s,
                        self,
                        Permission::JmapVacationResponseCreate,
                        Permission::JmapVacationResponseUpdate,
                        Permission::JmapVacationResponseDestroy,
                    ),
                    SetRequestMethod::AddressBook(s) => validate_set(
                        s,
                        self,
                        Permission::JmapAddressBookCreate,
                        Permission::JmapAddressBookUpdate,
                        Permission::JmapAddressBookDestroy,
                    ),
                    SetRequestMethod::ContactCard(s) => validate_set(
                        s,
                        self,
                        Permission::JmapContactCardCreate,
                        Permission::JmapContactCardUpdate,
                        Permission::JmapContactCardDestroy,
                    ),
                    SetRequestMethod::FileNode(s) => validate_set(
                        s,
                        self,
                        Permission::JmapFileNodeCreate,
                        Permission::JmapFileNodeUpdate,
                        Permission::JmapFileNodeDestroy,
                    ),
                    SetRequestMethod::ShareNotification(s) => validate_set(
                        s,
                        self,
                        Permission::JmapShareNotificationCreate,
                        Permission::JmapShareNotificationUpdate,
                        Permission::JmapShareNotificationDestroy,
                    ),
                    SetRequestMethod::Calendar(s) => validate_set(
                        s,
                        self,
                        Permission::JmapCalendarCreate,
                        Permission::JmapCalendarUpdate,
                        Permission::JmapCalendarDestroy,
                    ),
                    SetRequestMethod::CalendarEvent(s) => validate_set(
                        s,
                        self,
                        Permission::JmapCalendarEventCreate,
                        Permission::JmapCalendarEventUpdate,
                        Permission::JmapCalendarEventDestroy,
                    ),
                    SetRequestMethod::CalendarEventNotification(s) => validate_set(
                        s,
                        self,
                        Permission::JmapCalendarEventNotificationCreate,
                        Permission::JmapCalendarEventNotificationUpdate,
                        Permission::JmapCalendarEventNotificationDestroy,
                    ),
                    SetRequestMethod::ParticipantIdentity(s) => validate_set(
                        s,
                        self,
                        Permission::JmapParticipantIdentityCreate,
                        Permission::JmapParticipantIdentityUpdate,
                        Permission::JmapParticipantIdentityDestroy,
                    ),
                    SetRequestMethod::Registry(s) => {
                        let MethodObject::Registry(object_type) = object else {
                            unreachable!()
                        };
                        let set_permissions = object_type.set_permission();
                        validate_set(
                            s,
                            self,
                            set_permissions[0],
                            set_permissions[1],
                            set_permissions[2],
                        )
                    }
                };
            }
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
                MethodObject::AddressBook => Permission::JmapAddressBookChanges,
                MethodObject::Core
                | MethodObject::Blob
                | MethodObject::PushSubscription
                | MethodObject::SearchSnippet
                | MethodObject::VacationResponse
                | MethodObject::SieveScript
                | MethodObject::Registry(_) => Permission::JmapEmailChanges,
            },
            RequestMethod::Copy(m) => match &m {
                CopyRequestMethod::Email(_) => Permission::JmapEmailCopy,
                CopyRequestMethod::Blob(_) => Permission::JmapBlobCopy,
                CopyRequestMethod::ContactCard(_) => Permission::JmapContactCardCopy,
                CopyRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventCopy,
                CopyRequestMethod::FileNode(_) => Permission::JmapFileNodeCopy,
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
                QueryRequestMethod::AddressBook(_) => Permission::JmapAddressBookGet,
                QueryRequestMethod::ContactCard(_) => Permission::JmapContactCardQuery,
                QueryRequestMethod::FileNode(_) => Permission::JmapFileNodeQuery,
                QueryRequestMethod::Calendar(_) => Permission::JmapCalendarGet,
                QueryRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventQuery,
                QueryRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationQuery
                }
                QueryRequestMethod::ShareNotification(_) => Permission::JmapShareNotificationQuery,
                QueryRequestMethod::Registry(_) => {
                    let MethodObject::Registry(object_type) = object else {
                        unreachable!()
                    };
                    object_type.query_permission()
                }
            },
            RequestMethod::SearchSnippet(_) => Permission::JmapSearchSnippetGet,
            RequestMethod::ValidateScript(_) => Permission::JmapSieveScriptValidate,
            RequestMethod::LookupBlob(_) => Permission::JmapBlobLookup,
            RequestMethod::UploadBlob(_) => Permission::JmapBlobUpload,
            RequestMethod::Echo(_) => Permission::JmapCoreEcho,
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

fn validate_set<T: JmapObject>(
    set: &SetRequest<'_, T>,
    access_token: &AccessToken,
    create_permission: Permission,
    update_permission: Permission,
    destroy_permission: Permission,
) -> trc::Result<()> {
    let can_create = access_token.has_permission(create_permission);
    let can_update = access_token.has_permission(update_permission);
    let can_destroy = access_token.has_permission(destroy_permission);

    if can_create && can_update && can_destroy {
        Ok(())
    } else if !can_create && !can_update && !can_destroy {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to create, update or destroy objects of this type"))
    } else if !can_create && set.create.as_ref().is_some_and(|objs| !objs.is_empty()) {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to create objects of this type"))
    } else if !can_update && set.update.as_ref().is_some_and(|objs| !objs.is_empty()) {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to update objects of this type"))
    } else if !can_destroy
        && set.destroy.as_ref().is_some_and(|objs| match objs {
            MaybeResultReference::Value(v) => !v.is_empty(),
            MaybeResultReference::Reference(_) => true,
        })
    {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to destroy objects of this type"))
    } else {
        Ok(())
    }
}
