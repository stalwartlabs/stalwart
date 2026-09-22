/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::AccessToken,
    sharing::{
        EffectiveAcl,
        grants::{AclGrantLookup, ShareUpdate, ShareViolation},
    },
};
use jmap_proto::{
    error::set::SetError,
    object::{JmapRight, JmapSharedObject},
};
use jmap_tools::{JsonPointerIter, Key, Map, Property, Value};
use registry::schema::prelude::ObjectType;
use store::{registry::RegistryQuery, roaring::RoaringBitmap};
use types::{
    acl::{Acl, AclGrant},
    id::Id,
};
use utils::map::bitmap::Bitmap;

pub struct JmapRights;

impl JmapRights {
    pub fn acl_set<T: JmapSharedObject>(
        value: Value<'_, T::Property, T::Element>,
    ) -> Result<Vec<AclGrant>, SetError<T::Property>>
    where
        Id: TryFrom<T::Property>,
        T::Right: TryFrom<T::Property>,
    {
        let mut grants = Vec::new();

        for (key, value) in value.into_expanded_object() {
            let account_id = key
                .try_into_property()
                .and_then(|p| Id::try_from(p).ok())
                .ok_or_else(|| {
                    SetError::invalid_properties()
                        .with_property(T::SHARE_WITH_PROPERTY)
                        .with_description("Invalid account id.")
                })?
                .document_id();

            if !grants
                .iter()
                .any(|item: &AclGrant| item.account_id == account_id)
            {
                let acls = Self::map_acls::<T>(value)?;
                if !acls.is_empty() {
                    grants.push(AclGrant {
                        account_id,
                        grants: acls,
                    });
                }
            }
        }

        Ok(grants)
    }

    pub fn acl_patch<T: JmapSharedObject>(
        mut grants: Vec<AclGrant>,
        mut path: JsonPointerIter<'_, T::Property>,
        value: Value<'_, T::Property, T::Element>,
    ) -> Result<Vec<AclGrant>, SetError<T::Property>>
    where
        Id: TryFrom<T::Property>,
        T::Right: TryFrom<T::Property>,
    {
        let account_id = path
            .next()
            .and_then(|item| item.as_property_key())
            .cloned()
            .and_then(|p| Id::try_from(p).ok())
            .ok_or_else(|| {
                SetError::invalid_properties()
                    .with_property(T::SHARE_WITH_PROPERTY)
                    .with_description("Invalid account id.")
            })?
            .document_id();

        if let Some(right) = path.next() {
            if path.next().is_some() {
                return Err(SetError::invalid_properties()
                    .with_property(T::SHARE_WITH_PROPERTY)
                    .with_description("Invalid path for ACL patch."));
            }

            let is_set = match value {
                Value::Bool(is_set) => is_set,
                Value::Null => false,
                _ => {
                    return Err(SetError::invalid_properties()
                        .with_property(T::SHARE_WITH_PROPERTY)
                        .with_description("Invalid ACL value."));
                }
            };

            let right = right
                .as_property_key()
                .cloned()
                .and_then(|p| T::Right::try_from(p).ok())
                .ok_or_else(|| {
                    SetError::invalid_properties()
                        .with_property(T::SHARE_WITH_PROPERTY)
                        .with_description(format!(
                            "Invalid permission {:?}.",
                            right.to_cow().unwrap_or_default()
                        ))
                })?;
            let acl = right.to_acl().iter().copied();

            if let Some(acl_item) = grants.iter_mut().find(|item| item.account_id == account_id) {
                if is_set {
                    acl_item.grants.insert_many(acl);
                } else {
                    acl_item.grants.remove_many(acl);
                    if right.is_implied_by(&acl_item.grants) {
                        return Err(implied_right::<T>(right));
                    }
                    if acl_item.grants.is_empty() {
                        grants.retain(|item| item.account_id != account_id);
                    }
                }
            } else if is_set {
                grants.push(AclGrant {
                    account_id,
                    grants: Bitmap::from_iter(acl),
                });
            }
        } else {
            let acls = Self::map_acls::<T>(value)?;
            if !acls.is_empty() {
                if let Some(acl_item) = grants.iter_mut().find(|item| item.account_id == account_id)
                {
                    acl_item.grants = acls;
                } else {
                    grants.push(AclGrant {
                        account_id,
                        grants: acls,
                    });
                }
            } else {
                grants.retain(|item| item.account_id != account_id);
            }
        }

        Ok(grants)
    }

    fn map_acls<T: JmapSharedObject>(
        value: Value<'_, T::Property, T::Element>,
    ) -> Result<Bitmap<Acl>, SetError<T::Property>>
    where
        Id: TryFrom<T::Property>,
        T::Right: TryFrom<T::Property>,
    {
        let mut acls = Bitmap::new();
        let mut denied = Vec::new();

        for (key, value) in value.into_expanded_object() {
            let right = key
                .as_property()
                .and_then(|p| T::Right::try_from(p.clone()).ok());
            match (value.as_bool(), right) {
                (Some(true), Some(right)) => {
                    acls.insert_many(right.to_acl().iter().copied());
                }
                (Some(false), Some(right)) => {
                    if !right.implied_by_acl().is_empty() {
                        denied.push(right);
                    }
                }
                (Some(_), None) => {
                    return Err(SetError::invalid_properties()
                        .with_property(T::SHARE_WITH_PROPERTY)
                        .with_description(format!("Invalid permission {:?}.", key.to_string())));
                }
                (None, _) => {
                    return Err(SetError::invalid_properties()
                        .with_property(T::SHARE_WITH_PROPERTY)
                        .with_description(format!(
                            "Permission {:?} must be a boolean.",
                            key.to_string()
                        )));
                }
            }
        }

        match denied.into_iter().find(|right| right.is_implied_by(&acls)) {
            Some(right) => Err(implied_right::<T>(right)),
            None => Ok(acls),
        }
    }

    pub fn validate_shares<T: JmapSharedObject, G: AclGrantLookup + ?Sized>(
        update: ShareUpdate<'_, G>,
        grants: &[AclGrant],
    ) -> Result<(), SetError<T::Property>> {
        update
            .validate(grants)
            .map_err(|violation| match violation {
                ShareViolation::TooManyShares(max) => SetError::invalid_properties()
                    .with_property(T::SHARE_WITH_PROPERTY)
                    .with_description(format!(
                        "Maximum number of shares per item exceeded (max: {max})"
                    )),
                ShareViolation::OwnerShared => SetError::invalid_properties()
                    .with_property(T::SHARE_WITH_PROPERTY)
                    .with_description(
                        "An object cannot be shared with the principal that owns it.",
                    ),
                ShareViolation::RightNotHeld => SetError::forbidden()
                    .with_description("You cannot grant rights that you do not have yourself."),
            })
    }

    pub fn all_rights<T: JmapSharedObject>() -> Value<'static, T::Property, T::Element> {
        let rights = T::Right::all_rights();
        let mut obj = Map::with_capacity(rights.len());

        for right in rights {
            obj.insert_unchecked(Key::Property((*right).into()), Value::Bool(true));
        }

        Value::Object(obj)
    }

    pub fn rights<T: JmapSharedObject>(
        acls: Bitmap<Acl>,
    ) -> Value<'static, T::Property, T::Element> {
        let mut obj = Map::with_capacity(3);

        for right in T::Right::all_rights() {
            obj.insert_unchecked(
                Key::Property((*right).into()),
                Value::Bool(right.is_granted(&acls)),
            );
        }

        Value::Object(obj)
    }

    pub fn share_with<T: JmapSharedObject>(
        account_id: u32,
        access_token: &AccessToken,
        grants: &[AclGrant],
    ) -> Value<'static, T::Property, T::Element>
    where
        T::Property: From<Id>,
    {
        if access_token.is_member(account_id)
            || grants.effective_acl(access_token).contains(Acl::Share)
        {
            Self::grants_value::<T>(grants)
        } else {
            Value::Null
        }
    }

    pub fn grants_value<T: JmapSharedObject>(
        grants: &[AclGrant],
    ) -> Value<'static, T::Property, T::Element>
    where
        T::Property: From<Id>,
    {
        let mut share_with = Map::with_capacity(grants.len());
        for grant in grants {
            share_with.insert_unchecked(
                Key::Property(Id::from(grant.account_id).into()),
                Self::rights::<T>(grant.grants),
            );
        }
        Value::Object(share_with)
    }
}

pub trait JmapAcl {
    fn acl_validate(
        &self,
        grants: &[AclGrant],
    ) -> impl Future<Output = Result<(), ShareValidationError>> + Send;
}

pub enum ShareValidationError {
    MaxSharesExceeded(usize),
    InvalidAccountId(Id),
}

impl JmapAcl for Server {
    async fn acl_validate(&self, grants: &[AclGrant]) -> Result<(), ShareValidationError> {
        if grants.len() > self.core.groupware.max_shares_per_item {
            return Err(ShareValidationError::MaxSharesExceeded(
                self.core.groupware.max_shares_per_item,
            ));
        }

        let principal_ids = self
            .registry()
            .query::<RoaringBitmap>(RegistryQuery::new(ObjectType::Account))
            .await
            .unwrap_or_default();

        for grant in grants {
            if !principal_ids.contains(grant.account_id) {
                return Err(ShareValidationError::InvalidAccountId(Id::from(
                    grant.account_id,
                )));
            }
        }

        Ok(())
    }
}

trait ImpliedRight {
    fn is_implied_by(&self, acls: &Bitmap<Acl>) -> bool;
}

impl<R: JmapRight> ImpliedRight for R {
    fn is_implied_by(&self, acls: &Bitmap<Acl>) -> bool {
        let implied_by = self.implied_by_acl();
        !implied_by.is_empty() && implied_by.iter().all(|acl| acls.contains(*acl))
    }
}

fn implied_right<T: JmapSharedObject>(right: T::Right) -> SetError<T::Property> {
    SetError::invalid_properties()
        .with_property(T::SHARE_WITH_PROPERTY)
        .with_description(format!(
            "Permission {} cannot be removed while other permissions imply it.",
            Key::Property(right.into()).to_string()
        ))
}

impl<T: Property> From<ShareValidationError> for SetError<T> {
    fn from(err: ShareValidationError) -> Self {
        match err {
            ShareValidationError::MaxSharesExceeded(max) => SetError::invalid_properties()
                .with_description(format!(
                    "Maximum number of shares per item exceeded (max: {max})"
                )),
            ShareValidationError::InvalidAccountId(id) => SetError::invalid_properties()
                .with_description(format!("Account id {id} is invalid.")),
        }
    }
}
