/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub use super::{parse_connection_timeout, parse_max_changes, parse_max_items, repeated};
pub use crate::{
    ews::{
        schema::{
            AffectedTaskOccurrences, BaseShape, ConflictResolution, ConversationNodeSortOrder,
            ConversationQueryTraversal, DeliverMeetingRequests, DisposalType, FolderQueryTraversal,
            IdFormat, ItemQueryTraversal, MailboxSearchLocation, MessageDisposition, ReminderKind,
            ResolveNamesSearchScope, SendMeetingInvitations, SendMeetingInvitationsOrCancellations,
            ServiceConfigurationName, SyncFolderItemsScope, UserPhotoSize, UserPhotoType,
            ViewFilter,
        },
        types::{
            address::EmailAddress,
            availability::{
                AvailabilityAddress, FreeBusyViewOptions, MailboxData, SerializableTimeZone,
                SuggestionsViewOptions,
            },
            bulk::UploadItem,
            change::{FolderUpdate, ItemUpdate},
            config::{UserConfiguration, UserConfigurationName, UserConfigurationProperties},
            conversation::ConversationRequest,
            delegate::DelegateUser,
            folder::{Folder, UserId},
            ids::{
                AlternateId, AttachmentId, BaseFolderId, BaseItemId, ItemId, SubscriptionId,
                TargetFolderId, Watermark,
            },
            item::{
                Item,
                attachment::{Attachment, Attachments},
            },
            mailtip::MailTipSet,
            oof::UserOofSettings,
            path::{Path, Paths},
            persona::{ContextProperty, PersonaShape, QueryString},
            reminder::ReminderItemAction,
            restriction::Restriction,
            rule::RuleOperation,
            search::{SearchItemTypes, SearchScope, SuggestionKinds},
            shape::{AttachmentShape, FolderShape, ItemShape},
            subscription::SubscriptionRequest,
            value::{DateTime, EwsValue},
            view::{FieldOrder, FolderView, GroupBy, IndexedView, ItemView},
        },
    },
    xml::Ns,
};
pub use std::borrow::Cow;
