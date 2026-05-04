/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapSetError, JmapUtils},
};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{
            Action, Expression, MtaExtensions, MtaStageAuth, MtaStageData, MtaStageEhlo,
            MtaStageRcpt, SpamSettings,
        },
    },
    types::{EnumImpl, ObjectImpl},
};
use serde_json::{Value, json};
use std::fmt::Display;
use store::registry::write::RegistryWriteResult;
use types::id::Id;

impl Account {
    pub async fn registry_create<T: ObjectImpl>(
        &self,
        items: impl IntoIterator<Item = T>,
    ) -> JmapResponse {
        let typ = T::OBJECT;
        let name = typ.as_str();

        self.jmap_create_account(
            self,
            format!("x:{name}"),
            items.into_iter().map(|item| {
                let mut item =
                    serde_json::to_value(item).expect("Failed to serialize item to JSON");
                remove_server_set_props(typ, &mut item);
                item
            }),
            Vec::<(&str, &str)>::new(),
        )
        .await
    }

    pub async fn registry_create_many(
        &self,
        object_type: ObjectType,
        items: impl IntoIterator<Item = Value>,
    ) -> JmapResponse {
        let name = object_type.as_str();
        self.jmap_create_account(self, format!("x:{name}"), items, Vec::<(&str, &str)>::new())
            .await
    }

    pub async fn registry_get<T: ObjectImpl>(&self, id: Id) -> T {
        let name = T::OBJECT.as_str();

        let value = self
            .jmap_get_account(self, format!("x:{name}"), Vec::<&str>::new(), vec![id])
            .await
            .list()[0]
            .to_string();
        serde_json::from_str(&value).unwrap_or_else(|_| {
            panic!("Failed to deserialize {value}");
        })
    }

    pub async fn registry_get_all<T: ObjectImpl>(&self) -> Vec<(Id, T)> {
        let name = T::OBJECT.as_str();

        let response = self
            .jmap_get_account(
                self,
                format!("x:{name}"),
                Vec::<&str>::new(),
                Vec::<Id>::new(),
            )
            .await;
        let mut items = Vec::with_capacity(response.list().len());
        for item in response.list() {
            let id = item.object_id();
            let item = serde_json::from_str(&item.to_string()).unwrap_or_else(|err| {
                panic!("Failed to deserialize {item} : {err}");
            });
            items.push((id, item));
        }
        items
    }

    pub async fn registry_get_many(
        &self,
        object_type: ObjectType,
        ids: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        self.jmap_get_account(
            self,
            format!("x:{}", object_type.as_str()),
            Vec::<&str>::new(),
            ids,
        )
        .await
    }

    pub async fn registry_update(
        &self,
        object: ObjectType,
        items: impl IntoIterator<Item = (impl Display, Value)>,
    ) -> JmapResponse {
        let name = object.as_str();

        self.jmap_update_account(self, format!("x:{name}"), items, Vec::<(&str, &str)>::new())
            .await
    }

    pub async fn registry_query_ids(
        &self,
        object: ObjectType,
        filter: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
        sort_by: impl IntoIterator<Item = impl Display>,
    ) -> Vec<Id> {
        self.registry_query(object, filter, sort_by)
            .await
            .object_ids()
            .collect()
    }

    pub async fn registry_query(
        &self,
        object: ObjectType,
        filter: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
        sort_by: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        let name = object.as_str();

        self.jmap_query(
            format!("x:{name}"),
            filter,
            sort_by,
            Vec::<(&str, &str)>::new(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn registry_query_paginated(
        &self,
        object: ObjectType,
        sort_property: &str,
        sort_ascending: bool,
        position: Option<i32>,
        limit: Option<usize>,
        anchor: Option<Id>,
        anchor_offset: Option<i32>,
        calculate_total: bool,
    ) -> JmapResponse {
        let name = object.as_str();
        let mut args = serde_json::Map::new();
        args.insert("filter".into(), json!({}));
        args.insert(
            "sort".into(),
            json!([{ "property": sort_property, "isAscending": sort_ascending }]),
        );
        if let Some(p) = position {
            args.insert("position".into(), json!(p));
        }
        if let Some(l) = limit {
            args.insert("limit".into(), json!(l));
        }
        if let Some(a) = anchor {
            args.insert("anchor".into(), json!(a.to_string()));
        }
        if let Some(ao) = anchor_offset {
            args.insert("anchorOffset".into(), json!(ao));
        }
        if calculate_total {
            args.insert("calculateTotal".into(), json!(true));
        }

        self.jmap_method_calls(json!([[
            format!("x:{name}/query"),
            Value::Object(args),
            "0"
        ]]))
        .await
    }

    pub async fn registry_destroy(
        &self,
        object: ObjectType,
        items: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        let name = object.as_str();

        self.jmap_destroy_account(self, format!("x:{name}"), items, Vec::<(&str, &str)>::new())
            .await
    }

    pub async fn registry_destroy_all(&self, object: ObjectType) {
        let name = object.as_str();
        self.jmap_method_calls(json!([[
            format!("x:{name}/get"),
            {
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            format!("x:{name}/set"),
            {
              "#destroy" : {
                    "resultOf": "R1",
                    "name": format!("x:{name}/get"),
                    "path": "/list/*/id"
                },
            },
            "R2"
          ]
        ]))
        .await;
    }

    pub async fn registry_create_object<T: ObjectImpl>(&self, item: T) -> Id {
        self.registry_create([item]).await.created_id(0)
    }

    pub async fn registry_create_object_expect_err<T: ObjectImpl>(&self, item: T) -> JmapSetError {
        self.registry_create([item])
            .await
            .not_created(0)
            .to_set_error()
    }

    pub async fn registry_update_object(&self, object: ObjectType, id: Id, item: Value) {
        self.registry_update(object, [(id, item)])
            .await
            .updated_id(id);
    }

    pub async fn registry_update_setting<T: ObjectImpl>(
        &self,
        setting: T,
        properties: &[Property],
    ) {
        let mut item = serde_json::to_value(setting).expect("Failed to serialize setting to JSON");

        if !properties.is_empty() {
            // Only include the specified properties in the update
            if let Value::Object(obj) = &mut item {
                obj.retain(|k, _| properties.iter().any(|p| p.as_str() == k));
            }
        }

        self.registry_update(T::OBJECT, [(Id::singleton(), item)])
            .await
            .updated_id(Id::singleton());
    }

    pub async fn reload_settings(&self) {
        self.registry_create_object(Action::ReloadSettings).await;
    }

    pub async fn reload_lookup_stores(&self) {
        self.registry_create_object(Action::ReloadLookupStores)
            .await;
    }

    pub async fn registry_update_object_expect_err(
        &self,
        object: ObjectType,
        id: Id,
        item: Value,
    ) -> JmapSetError {
        self.registry_update(object, [(id, item)])
            .await
            .not_updated(&id.to_string())
            .to_set_error()
    }

    pub async fn registry_destroy_object_expect_err(
        &self,
        object: ObjectType,
        id: Id,
    ) -> JmapSetError {
        self.registry_destroy(object, [id])
            .await
            .not_destroyed(&id.to_string())
            .to_set_error()
    }

    pub async fn destroy_account(&self, account: Account) {
        let account_id = account.id();
        self.registry_destroy(ObjectType::Account, [account_id])
            .await
            .assert_destroyed(&[account_id]);
    }

    pub async fn mta_allow_relaying(&self) {
        self.registry_create_object(MtaStageRcpt {
            allow_relaying: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    }

    pub async fn mta_disable_spam_filter(&self) {
        self.registry_create_object(SpamSettings {
            enable: false,
            ..Default::default()
        })
        .await;
    }

    pub async fn mta_no_auth(&self) {
        self.registry_create_object(MtaStageAuth {
            require: Expression {
                else_: "false".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    }

    pub async fn mta_all_extensions(&self) {
        self.registry_create_object(MtaExtensions {
            chunking: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            deliver_by: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            dsn: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            expn: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            future_release: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            mt_priority: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            no_soliciting: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            pipelining: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            require_tls: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            vrfy: Expression {
                else_: "true".into(),
                ..Default::default()
            },
        })
        .await;
    }

    pub async fn mta_allow_non_fqdn(&self) {
        self.registry_create_object(MtaStageEhlo {
            reject_non_fqdn: Expression {
                else_: "false".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    }

    pub async fn mta_add_all_headers(&self) {
        self.registry_create_object(MtaStageData {
            add_date_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_message_id_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_received_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_received_spf_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_auth_results_header: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            add_return_path_header: Expression {
                else_: "false".into(),
                ..Default::default()
            },
            enable_spam_filter: Expression {
                else_: "false".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    }
}

impl JmapResponse {
    pub fn objects<T: ObjectImpl>(&self) -> impl Iterator<Item = T> {
        self.list()
            .iter()
            .map(|item| serde_json::from_value(item.clone()).expect("Failed to deserialize item"))
    }
}

pub trait UnwrapRegistryId {
    fn unwrap_id(self, location: &str) -> Id;
}

impl UnwrapRegistryId for RegistryWriteResult {
    fn unwrap_id(self, location: &str) -> Id {
        match self {
            RegistryWriteResult::Success(id) => id,
            err => panic!("Expected success at {location} but got {err}"),
        }
    }
}

fn remove_server_set_props(typ: ObjectType, value: &mut serde_json::Value) {
    if let Value::Object(obj) = value {
        let is_app_pass = matches!(typ, ObjectType::AppPassword | ObjectType::ApiKey)
            || obj
                .get("@type")
                .and_then(|v| v.as_str())
                .is_some_and(|t| ["AppPassword", "ApiKey"].contains(&t));
        obj.retain(|k, v| {
            !([
                "createdAt",
                "credentialId",
                "retireAt",
                "accountKey",
                "accountUri",
            ]
            .contains(&k.as_str())
                || (is_app_pass && k == "secret")
                || (k == "memberTenantId" && v.is_null()))
        });
        for v in obj.values_mut() {
            remove_server_set_props(typ, v);
        }
    }
}
