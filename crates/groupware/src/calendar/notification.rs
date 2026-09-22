/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEventNotification, CALENDAR_SUBSCRIBED, CalendarEventNotification,
    EVENT_HIDE_ATTENDEES, EVENT_NOTIFICATION_OWNER_ONLY, default_preference_flags,
    privacy::EventPrivacy,
};
use crate::{DestroyArchive, cache::GroupwareCache};
use common::{
    GroupwareResources, Server,
    auth::{AccessToken, AccountCache},
    storage::dav::resource::NotificationRef,
};
use std::sync::Arc;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
};

pub struct NotificationViewer {
    viewer_id: u32,
    is_member: bool,
    calendar_ids: RoaringBitmap,
    known_calendar_ids: RoaringBitmap,
}

impl NotificationViewer {
    pub fn new(
        calendars: &GroupwareResources,
        access_token: &AccessToken,
        account_id: u32,
    ) -> Self {
        let viewer_id = access_token.account_id();
        let is_member = access_token.is_member(account_id);
        let mut calendar_ids = RoaringBitmap::new();
        let mut known_calendar_ids = RoaringBitmap::new();

        for calendar in calendars.resources.iter().filter(|r| r.is_container()) {
            known_calendar_ids.insert(calendar.document_id());
            let flags = calendar
                .personal_calendar_preferences(viewer_id)
                .map_or_else(|| default_preference_flags(is_member), |prefs| prefs.flags);
            if flags & CALENDAR_SUBSCRIBED != 0
                && (is_member || has_read_access(access_token, calendar.acls()))
            {
                calendar_ids.insert(calendar.document_id());
            }
        }

        NotificationViewer {
            viewer_id,
            is_member,
            calendar_ids,
            known_calendar_ids,
        }
    }

    pub fn without_calendars(access_token: &AccessToken, account_id: u32) -> Self {
        NotificationViewer {
            viewer_id: access_token.account_id(),
            is_member: access_token.is_member(account_id),
            calendar_ids: RoaringBitmap::new(),
            known_calendar_ids: RoaringBitmap::new(),
        }
    }

    pub fn is_member(&self) -> bool {
        self.is_member
    }

    pub fn can_view(&self, notification: &NotificationRef<'_>) -> bool {
        notification.changed_by != self.viewer_id
            && !notification.dismissed_by.contains(&self.viewer_id)
            && (self.is_member || notification.flags & EVENT_NOTIFICATION_OWNER_ONLY == 0)
            && if notification
                .calendar_ids
                .iter()
                .any(|calendar_id| self.known_calendar_ids.contains(*calendar_id))
            {
                notification
                    .calendar_ids
                    .iter()
                    .any(|calendar_id| self.calendar_ids.contains(*calendar_id))
            } else {
                self.is_member
            }
    }

    pub fn visible_notifications(&self, notifications: &GroupwareResources) -> RoaringBitmap {
        notifications
            .resources
            .iter()
            .filter(|resource| {
                !resource.is_container()
                    && resource
                        .notification()
                        .is_some_and(|notification| self.can_view(&notification))
            })
            .map(|resource| resource.document_id())
            .collect()
    }
}

pub fn hides_details(event_flags: u16) -> bool {
    event_flags & EVENT_HIDE_ATTENDEES != 0 || !EventPrivacy::from_flags(event_flags).is_public()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountViewers {
    Owner,
    Members,
}

impl AccountViewers {
    pub fn of(account: &AccountCache) -> Self {
        if account.is_user_account() {
            AccountViewers::Owner
        } else {
            AccountViewers::Members
        }
    }
}

pub fn may_have_viewers(
    access_token: &AccessToken,
    account_id: u32,
    calendars: &GroupwareResources,
    calendar_ids: &[u32],
    is_owner_only: bool,
) -> bool {
    has_viewers(
        access_token,
        account_id,
        calendars,
        calendar_ids,
        is_owner_only,
        AccountViewers::Members,
    )
}

pub fn has_viewers(
    access_token: &AccessToken,
    account_id: u32,
    calendars: &GroupwareResources,
    calendar_ids: &[u32],
    is_owner_only: bool,
    account_viewers: AccountViewers,
) -> bool {
    if calendar_ids.is_empty() {
        return !access_token.is_account_id(account_id);
    } else if !access_token.is_account_id(account_id)
        && match account_viewers {
            AccountViewers::Owner => is_subscribed(calendars, calendar_ids, account_id),
            AccountViewers::Members => true,
        }
    {
        return true;
    }

    !is_owner_only
        && subscribed_readers(calendars, calendar_ids)
            .any(|reader_id| !is_actor(access_token, reader_id))
}

fn is_actor(access_token: &AccessToken, account_id: u32) -> bool {
    access_token
        .member_ids()
        .any(|member_id| member_id == account_id)
}

fn is_subscribed(calendars: &GroupwareResources, calendar_ids: &[u32], account_id: u32) -> bool {
    calendar_ids
        .iter()
        .filter_map(|calendar_id| calendars.resources.find(*calendar_id, true))
        .any(|calendar| {
            calendar
                .personal_calendar_preferences(account_id)
                .is_some_and(|preferences| preferences.flags & CALENDAR_SUBSCRIBED != 0)
        })
}

fn subscribed_readers<'x>(
    calendars: &'x GroupwareResources,
    calendar_ids: &'x [u32],
) -> impl Iterator<Item = u32> + 'x {
    calendar_ids
        .iter()
        .filter_map(|calendar_id| calendars.resources.find(*calendar_id, true))
        .flat_map(|calendar| {
            let preferences = calendar.all_calendar_preferences();
            calendar
                .acls()
                .iter()
                .filter(|acl| acl.grants.contains(Acl::ReadItems))
                .map(|acl| acl.account_id)
                .filter(move |account_id| {
                    preferences.iter().any(|preferences| {
                        preferences.account_id == *account_id
                            && preferences.flags & CALENDAR_SUBSCRIBED != 0
                    })
                })
        })
}

fn has_read_access(access_token: &AccessToken, acls: &[AclGrant]) -> bool {
    acls.iter()
        .any(|acl| acl.grants.contains(Acl::ReadItems) && access_token.is_member(acl.account_id))
}

pub trait CalendarNotificationViewers: Sync + Send {
    fn notification_viewer(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<NotificationViewer>> + Send;

    fn calendars_if_any(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<Arc<GroupwareResources>>>> + Send;
}

impl CalendarNotificationViewers for Server {
    async fn notification_viewer(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<NotificationViewer> {
        Ok(
            match self
                .calendars_if_any(access_token, account_id)
                .await
                .caused_by(trc::location!())?
            {
                Some(calendars) => NotificationViewer::new(&calendars, access_token, account_id),
                None => NotificationViewer::without_calendars(access_token, account_id),
            },
        )
    }

    async fn calendars_if_any(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Option<Arc<GroupwareResources>>> {
        if self
            .count_documents(account_id, Collection::Calendar, 1)
            .await
            .caused_by(trc::location!())?
            == 0
        {
            return Ok(None);
        }

        self.fetch_groupware_resources(
            access_token.account_id(),
            account_id,
            SyncCollection::Calendar,
        )
        .await
        .caused_by(trc::location!())
        .map(Some)
    }
}

pub trait CalendarNotificationReap: Sync + Send {
    fn reap_calendar_notifications(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        calendar_ids: &[u32],
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl CalendarNotificationReap for Server {
    async fn reap_calendar_notifications(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        calendar_ids: &[u32],
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let notifications = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await
            .caused_by(trc::location!())?;
        let is_member = access_token.is_member(account_id);
        let orphaned = notifications
            .resources
            .iter()
            .filter(|resource| {
                !resource.is_container()
                    && resource.notification().is_some_and(|notification| {
                        (is_member || notification.changed_by == account_id)
                            && !notification.calendar_ids.is_empty()
                            && notification
                                .calendar_ids
                                .iter()
                                .all(|calendar_id| calendar_ids.contains(calendar_id))
                    })
            })
            .map(|resource| resource.document_id())
            .collect::<Vec<_>>();

        for document_id in orphaned {
            if let Some(notification) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEventNotification,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                DestroyArchive(
                    notification
                        .to_unarchived::<CalendarEventNotification>()
                        .caused_by(trc::location!())?,
                )
                .delete(
                    access_token.account_tenant_ids(),
                    account_id,
                    document_id,
                    batch,
                )
                .caused_by(trc::location!())?;
            }
        }

        Ok(())
    }
}

pub trait CalendarNotificationDismiss: Sync + Send {
    fn dismiss_notification(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        notification: Archive<&ArchivedCalendarEventNotification>,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn has_pending_viewers(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        notification: &ArchivedCalendarEventNotification,
        dismissed_by: &[u32],
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl CalendarNotificationDismiss for Server {
    async fn dismiss_notification(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        notification: Archive<&ArchivedCalendarEventNotification>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let viewer_id = access_token.account_id();
        let is_owner_only =
            notification.inner.flags.to_native() & EVENT_NOTIFICATION_OWNER_ONLY != 0;
        let mut dismissed_by = notification.inner.dismissed_ids().collect::<Vec<_>>();
        if !dismissed_by.contains(&viewer_id) {
            dismissed_by.push(viewer_id);
        }

        if !(is_owner_only && access_token.is_member(account_id))
            && self
                .has_pending_viewers(access_token, account_id, notification.inner, &dismissed_by)
                .await
                .caused_by(trc::location!())?
        {
            let mut updated = notification
                .deserialize::<CalendarEventNotification>()
                .caused_by(trc::location!())?;
            updated.dismissed_by = dismissed_by;
            updated
                .update_meta(
                    access_token.account_tenant_ids(),
                    notification,
                    account_id,
                    document_id,
                    batch,
                )
                .caused_by(trc::location!())?;
        } else {
            DestroyArchive(notification)
                .delete(
                    access_token.account_tenant_ids(),
                    account_id,
                    document_id,
                    batch,
                )
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    async fn has_pending_viewers(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        notification: &ArchivedCalendarEventNotification,
        dismissed_by: &[u32],
    ) -> trc::Result<bool> {
        let changed_by = notification.changed_by_id();
        if changed_by != account_id && !dismissed_by.contains(&account_id) {
            return Ok(true);
        } else if notification.flags.to_native() & EVENT_NOTIFICATION_OWNER_ONLY != 0
            || notification.calendar_ids.is_empty()
        {
            return Ok(false);
        }

        let Some(calendars) = self
            .calendars_if_any(access_token, account_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(false);
        };

        let calendar_ids = notification.calendar_ids().collect::<Vec<_>>();
        Ok(subscribed_readers(&calendars, &calendar_ids)
            .any(|account_id| account_id != changed_by && !dismissed_by.contains(&account_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::{EVENT_NOTIFICATION_IS_DIRECT, EVENT_NOTIFICATION_OWNER_ONLY};
    use common::{
        DavName, GroupwareResource, GroupwareResourceMetadata, PathIndex, ResourceStore,
        TinyCalendarPreferences, UpdateLock, storage::dav::ResourceChunkBuilder,
    };
    use registry::schema::enums::Permission;
    use types::acl::AclGrant;
    use utils::map::bitmap::Bitmap;

    const OWNER: u32 = 1;
    const SHAREE: u32 = 2;
    const OTHER: u32 = 3;
    const SUBSCRIBED_CALENDAR: u32 = 10;
    const UNSUBSCRIBED_CALENDAR: u32 = 11;
    const SILENT_CALENDAR: u32 = 12;

    struct Notification {
        document_id: u32,
        changed_by: u32,
        calendar_ids: Vec<u32>,
        dismissed_by: Vec<u32>,
        flags: u16,
    }

    fn calendars() -> GroupwareResources {
        let mut containers = ResourceChunkBuilder::with_capacity(2);
        for (document_id, subscribers) in [
            (SUBSCRIBED_CALENDAR, vec![OWNER, SHAREE]),
            (UNSUBSCRIBED_CALENDAR, vec![OWNER]),
            (SILENT_CALENDAR, vec![]),
        ] {
            let name = containers.push_str("calendar");
            let acls = containers.push_acls(&[AclGrant {
                account_id: SHAREE,
                grants: Bitmap::from_iter([Acl::Read, Acl::ReadItems]),
            }]);
            let preferences = containers.push_prefs(
                &subscribers
                    .iter()
                    .map(|account_id| TinyCalendarPreferences {
                        account_id: *account_id,
                        tz: Default::default(),
                        flags: CALENDAR_SUBSCRIBED,
                    })
                    .collect::<Vec<_>>(),
            );
            containers.records.push(GroupwareResource {
                document_id,
                data: GroupwareResourceMetadata::Calendar {
                    name,
                    acls,
                    preferences,
                    etag: 0,
                },
            });
        }

        resources(ResourceStore::from_sorted(vec![containers], vec![], false))
    }

    fn notifications(notifications: Vec<Notification>) -> GroupwareResources {
        let mut items = ResourceChunkBuilder::with_capacity(notifications.len());
        for notification in notifications {
            let names = items.push_names(&[DavName {
                name: format!("{}.ics", notification.document_id),
                parent_id: u32::MAX - 3,
            }]);
            let calendar_ids_len = notification.calendar_ids.len() as u16;
            let principals = items.push_principals(
                notification
                    .calendar_ids
                    .into_iter()
                    .chain(notification.dismissed_by),
            );
            items.records.push(GroupwareResource {
                document_id: notification.document_id,
                data: GroupwareResourceMetadata::CalendarEventNotification {
                    names,
                    created_at: 0,
                    event_id: u32::MAX,
                    etag: 0,
                    changed_by: notification.changed_by,
                    principals,
                    calendar_ids_len,
                    flags: notification.flags | EVENT_NOTIFICATION_IS_DIRECT,
                },
            });
        }

        resources(ResourceStore::from_sorted(vec![], vec![items], false))
    }

    fn resources(resources: ResourceStore) -> GroupwareResources {
        GroupwareResources {
            base_path: "/dav/cal/owner/".to_string(),
            paths: Arc::new(PathIndex::pack(vec![])),
            resources,
            item_change_id: 0,
            container_change_id: 0,
            highest_change_id: 0,
            size: 0,
            update_lock: Arc::new(UpdateLock::new()),
            verification: Default::default(),
        }
    }

    fn visible_to(account_id: u32, notifications: &GroupwareResources) -> Vec<u32> {
        NotificationViewer::new(
            &calendars(),
            &AccessToken::from_id_maybe_invalid(account_id),
            OWNER,
        )
        .visible_notifications(notifications)
        .into_iter()
        .collect()
    }

    #[test]
    fn sharees_see_changes_in_calendars_they_are_subscribed_to() {
        let notifications = notifications(vec![
            Notification {
                document_id: 1,
                changed_by: OWNER,
                calendar_ids: vec![SUBSCRIBED_CALENDAR],
                dismissed_by: vec![],
                flags: 0,
            },
            Notification {
                document_id: 2,
                changed_by: OWNER,
                calendar_ids: vec![UNSUBSCRIBED_CALENDAR],
                dismissed_by: vec![],
                flags: 0,
            },
        ]);

        assert_eq!(visible_to(SHAREE, &notifications), vec![1]);
        assert!(visible_to(OWNER, &notifications).is_empty());
        assert!(visible_to(OTHER, &notifications).is_empty());
    }

    #[test]
    fn owners_see_changes_made_by_others_unless_unsubscribed() {
        let notifications = notifications(vec![
            Notification {
                document_id: 1,
                changed_by: SHAREE,
                calendar_ids: vec![SUBSCRIBED_CALENDAR],
                dismissed_by: vec![],
                flags: 0,
            },
            Notification {
                document_id: 2,
                changed_by: SHAREE,
                calendar_ids: vec![UNSUBSCRIBED_CALENDAR],
                dismissed_by: vec![],
                flags: 0,
            },
        ]);

        assert_eq!(visible_to(OWNER, &notifications), vec![1, 2]);
        assert!(visible_to(SHAREE, &notifications).is_empty());
    }

    #[test]
    fn owner_only_notifications_are_hidden_from_sharees() {
        let notifications = notifications(vec![Notification {
            document_id: 1,
            changed_by: OTHER,
            calendar_ids: vec![SUBSCRIBED_CALENDAR],
            dismissed_by: vec![],
            flags: EVENT_NOTIFICATION_OWNER_ONLY,
        }]);

        assert_eq!(visible_to(OWNER, &notifications), vec![1]);
        assert!(visible_to(SHAREE, &notifications).is_empty());
    }

    #[test]
    fn a_dismissal_only_hides_the_notification_from_that_principal() {
        let notifications = notifications(vec![Notification {
            document_id: 1,
            changed_by: OTHER,
            calendar_ids: vec![SUBSCRIBED_CALENDAR],
            dismissed_by: vec![SHAREE],
            flags: 0,
        }]);

        assert_eq!(visible_to(OWNER, &notifications), vec![1]);
        assert!(visible_to(SHAREE, &notifications).is_empty());
    }

    #[test]
    fn members_with_no_preferences_are_subscribed_by_default() {
        let notifications = notifications(vec![Notification {
            document_id: 1,
            changed_by: OTHER,
            calendar_ids: vec![SUBSCRIBED_CALENDAR, UNSUBSCRIBED_CALENDAR],
            dismissed_by: vec![],
            flags: 0,
        }]);
        let mut containers = ResourceChunkBuilder::with_capacity(1);
        let name = containers.push_str("calendar");
        let acls = containers.push_acls(&[]);
        let preferences = containers.push_prefs(&[]);
        containers.records.push(GroupwareResource {
            document_id: SUBSCRIBED_CALENDAR,
            data: GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag: 0,
            },
        });
        let calendars = resources(ResourceStore::from_sorted(vec![containers], vec![], false));

        let member = NotificationViewer::new(
            &calendars,
            &AccessToken::from_id_maybe_invalid(OWNER),
            OWNER,
        );
        assert!(member.is_member());
        assert_eq!(
            member
                .visible_notifications(&notifications)
                .into_iter()
                .collect::<Vec<_>>(),
            vec![1]
        );

        let sharee = NotificationViewer::new(
            &calendars,
            &AccessToken::from_id_maybe_invalid(SHAREE),
            OWNER,
        );
        assert!(sharee.visible_notifications(&notifications).is_empty());
    }

    #[test]
    fn notifications_without_calendars_reach_members_only() {
        let notifications = notifications(vec![Notification {
            document_id: 1,
            changed_by: OTHER,
            calendar_ids: vec![],
            dismissed_by: vec![],
            flags: 0,
        }]);

        assert_eq!(visible_to(OWNER, &notifications), vec![1]);
        assert!(visible_to(SHAREE, &notifications).is_empty());
    }

    #[test]
    fn notifications_for_deleted_calendars_reach_members_only() {
        let notifications = notifications(vec![Notification {
            document_id: 1,
            changed_by: OTHER,
            calendar_ids: vec![SUBSCRIBED_CALENDAR + 100],
            dismissed_by: vec![],
            flags: 0,
        }]);

        assert_eq!(visible_to(OWNER, &notifications), vec![1]);
        assert!(visible_to(SHAREE, &notifications).is_empty());
    }

    #[test]
    fn a_change_by_the_owner_needs_a_subscribed_reader() {
        let calendars = calendars();
        let owner = AccessToken::from_id_maybe_invalid(OWNER);

        assert!(may_have_viewers(
            &owner,
            OWNER,
            &calendars,
            &[SUBSCRIBED_CALENDAR],
            false
        ));
        assert!(!may_have_viewers(
            &owner,
            OWNER,
            &calendars,
            &[UNSUBSCRIBED_CALENDAR],
            false
        ));
        assert!(!has_viewers(
            &owner,
            OWNER,
            &calendars,
            &[UNSUBSCRIBED_CALENDAR],
            false,
            AccountViewers::Owner
        ));
        assert!(!may_have_viewers(
            &owner,
            OWNER,
            &calendars,
            &[SUBSCRIBED_CALENDAR],
            true
        ));
    }

    #[test]
    fn a_change_nobody_is_subscribed_to_is_never_stored() {
        let calendars = calendars();
        let sharee = AccessToken::from_id_maybe_invalid(SHAREE);

        assert!(!has_viewers(
            &sharee,
            OWNER,
            &calendars,
            &[SILENT_CALENDAR],
            false,
            AccountViewers::Owner
        ));
        assert!(has_viewers(
            &sharee,
            OWNER,
            &calendars,
            &[UNSUBSCRIBED_CALENDAR],
            false,
            AccountViewers::Owner
        ));
    }

    #[test]
    fn a_change_in_a_group_account_reaches_the_members() {
        let calendars = calendars();
        let member = AccessToken::from_id_maybe_invalid(OTHER);

        // A member's own preferences row must not decide for the other members
        assert!(has_viewers(
            &member,
            OWNER,
            &calendars,
            &[SILENT_CALENDAR],
            false,
            AccountViewers::Members
        ));
        assert!(has_viewers(
            &member,
            OWNER,
            &calendars,
            &[SILENT_CALENDAR],
            true,
            AccountViewers::Members
        ));

        // The account principal acting on itself still needs a subscribed reader
        assert!(!has_viewers(
            &AccessToken::from_id_maybe_invalid(OWNER),
            OWNER,
            &calendars,
            &[SILENT_CALENDAR],
            false,
            AccountViewers::Members
        ));
    }

    #[test]
    fn an_impersonating_token_still_notifies_the_owner() {
        let admin = AccessToken::from_permissions(OTHER, [Permission::Impersonate]);
        assert!(admin.is_member(OWNER));

        assert!(may_have_viewers(
            &admin,
            OWNER,
            &calendars(),
            &[SUBSCRIBED_CALENDAR],
            false
        ));
    }

    #[test]
    fn the_principal_that_made_the_change_is_never_notified() {
        let notifications = notifications(vec![Notification {
            document_id: 1,
            changed_by: SHAREE,
            calendar_ids: vec![SUBSCRIBED_CALENDAR],
            dismissed_by: vec![],
            flags: 0,
        }]);

        assert!(visible_to(SHAREE, &notifications).is_empty());
    }
}
