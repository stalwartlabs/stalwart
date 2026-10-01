/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Access, Ctx, METADATA_CAPABILITY, MetaType, Using, method_error};
use crate::utils::{account::Account, server::TestServer};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{MetadataDataType, Permission},
        prelude::Property,
        structs::{self, Credential, Metadata, PasswordCredential, PermissionsList, UserAccount},
    },
    types::{list::List, map::Map},
};
use serde_json::{Value, json};

const DATA_TYPES: [&str; 8] = [
    "AddressBook",
    "Calendar",
    "CalendarEvent",
    "ContactCard",
    "Email",
    "FileNode",
    "Mailbox",
    "SieveScript",
];

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata capability tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let sharee = ctx.account("jane.smith@example.com");

    let expected_info = json!({
        "namespaces": [],
        "supportsVendorNamespaces": true,
        "supportsPrivate": true,
        "maxDepth": test.server.core.metadata.max_depth
    });
    let session = owner.jmap_session_object().await;
    assert_eq!(
        session.pointer(&format!("/capabilities/{METADATA_CAPABILITY}")),
        Some(&json!({})),
        "session capability must be an empty object: {session:?}"
    );
    let data_types = account_data_types(owner, owner).await;
    assert_eq!(data_type_names(&data_types), DATA_TYPES);
    for name in DATA_TYPES {
        assert_eq!(
            data_types.get(name),
            Some(&expected_info),
            "{name} capability: {data_types}"
        );
    }

    let parents = ctx.parents(owner).await;
    ctx.share(
        owner,
        MetaType::Mailbox,
        &parents.mailboxes[0],
        sharee,
        Some(Access::Read),
    )
    .await;
    let shared_types = account_data_types(sharee, owner).await;
    assert!(
        shared_types.get("Mailbox").is_some() && shared_types.get("Email").is_some(),
        "shared accounts must list the metadata capability: {shared_types}"
    );

    disabled_type(&ctx, owner).await;
    private_disabled(&ctx, owner, &parents).await;
    vendor_disabled(&ctx, owner).await;
    unbounded_depth(&ctx, owner).await;
    permissions(&ctx, owner, &parents).await;

    ctx.cleanup(&[owner, sharee]).await;
}

async fn disabled_type(ctx: &Ctx<'_>, owner: &Account) {
    configure(
        ctx,
        Metadata {
            data_types: Map::new(vec![
                MetadataDataType::Email,
                MetadataDataType::Mailbox,
                MetadataDataType::SieveScript,
                MetadataDataType::Calendar,
                MetadataDataType::CalendarEvent,
                MetadataDataType::AddressBook,
                MetadataDataType::ContactCard,
            ]),
            ..Default::default()
        },
        &[Property::DataTypes],
    )
    .await;

    let data_types = account_data_types(owner, owner).await;
    assert!(
        data_types.get("FileNode").is_none(),
        "FileNode is disabled but advertised: {data_types}"
    );
    assert_eq!(data_types.as_object().map(|types| types.len()), Some(7));

    let parents = ctx.parents(owner).await;
    let folder = ctx
        .create(
            owner,
            owner,
            MetaType::FileNode,
            &parents,
            0,
            json!({}),
            Using::Metadata,
        )
        .await
        .created(0)
        .get("id")
        .and_then(Value::as_str)
        .expect("folder id")
        .to_string();
    let object = ctx
        .get_one(
            owner,
            owner,
            MetaType::FileNode,
            &folder,
            None,
            Using::Metadata,
        )
        .await;
    assert!(
        object.get("metadata").is_none() && object.get("privateMetadata").is_none(),
        "a disabled type must not gain the metadata properties: {object}"
    );

    restore(ctx).await;
}

async fn private_disabled(ctx: &Ctx<'_>, owner: &Account, parents: &super::fixture::Parents) {
    configure(
        ctx,
        Metadata {
            private_metadata: false,
            ..Default::default()
        },
        &[Property::PrivateMetadata],
    )
    .await;

    let data_types = account_data_types(owner, owner).await;
    for name in DATA_TYPES {
        assert_eq!(
            data_types.pointer(&format!("/{name}/supportsPrivate")),
            Some(&Value::Bool(false)),
            "{name}: {data_types}"
        );
    }

    for ty in MetaType::ALL {
        let id = ctx
            .create_ok(
                owner,
                ty,
                parents,
                0,
                json!({"metadata": {"x.example": {"a": 1}}}),
            )
            .await;
        let object = ctx
            .get_one(owner, owner, ty, &id, None, Using::Metadata)
            .await;
        assert_eq!(
            object.get("metadata"),
            (ty != MetaType::Email)
                .then(|| json!({"x.example": {"a": 1}}))
                .as_ref(),
            "{}: {object}",
            ty.name()
        );
        assert!(
            object.get("privateMetadata").is_none(),
            "{}: privateMetadata must be absent when unsupported: {object}",
            ty.name()
        );

        let error = ctx
            .update_err(
                owner,
                owner,
                ty,
                &id,
                json!({"privateMetadata/x.example": {"a": 1}}),
            )
            .await;
        error.assert_type(SetErrorType::InvalidProperties);

        ctx.create_err(
            owner,
            ty,
            parents,
            json!({"privateMetadata": {"x.example": {"a": 1}}}),
        )
        .await
        .assert_type(SetErrorType::InvalidProperties);

        if let Some(scope) = parents.filter(ty, 0) {
            for condition in [
                json!({"privateMetadataExists": "x.example"}),
                json!({"privateMetadataTextContains": {"path": "x.example/a", "value": "1"}}),
                json!({"privateMetadataTextEquals": {"path": "x.example/a", "value": "1"}}),
            ] {
                let response = ctx
                    .query(
                        owner,
                        owner,
                        ty,
                        json!({"operator": "AND", "conditions": [scope.clone(), condition]}),
                        Using::Metadata,
                    )
                    .await;
                assert_eq!(
                    method_error(&response),
                    Some("unsupportedFilter"),
                    "{}: private filter accepted while unsupported: {response:?}",
                    ty.name()
                );
            }
        }

        ctx.destroy(owner, ty, &[&id]).await;
    }

    restore(ctx).await;
}

async fn vendor_disabled(ctx: &Ctx<'_>, owner: &Account) {
    configure(
        ctx,
        Metadata {
            vendor_namespaces: false,
            ..Default::default()
        },
        &[Property::VendorNamespaces],
    )
    .await;

    let session = owner.jmap_session_object().await;
    assert!(
        session
            .pointer(&format!("/capabilities/{METADATA_CAPABILITY}"))
            .is_none(),
        "a capability without any supported namespace must not be advertised: {session:?}"
    );
    assert!(
        session
            .pointer(&format!(
                "/accounts/{}/accountCapabilities/{METADATA_CAPABILITY}",
                owner.id_string()
            ))
            .is_none(),
        "account capability advertised without supported namespaces: {session:?}"
    );

    restore(ctx).await;
}

async fn unbounded_depth(ctx: &Ctx<'_>, owner: &Account) {
    configure(
        ctx,
        Metadata {
            max_depth: None,
            ..Default::default()
        },
        &[Property::MaxDepth],
    )
    .await;

    let data_types = account_data_types(owner, owner).await;
    for name in DATA_TYPES {
        assert_eq!(
            data_types.pointer(&format!("/{name}/maxDepth")),
            Some(&Value::Null),
            "{name}: {data_types}"
        );
    }

    restore(ctx).await;
}

async fn permissions(ctx: &Ctx<'_>, owner: &Account, parents: &super::fixture::Parents) {
    let admin = ctx.account("admin");
    let domain_id = admin.find_or_create_domain("example.com").await;

    let mut accounts = Vec::new();
    for (name, secret, disabled) in [
        (
            "meta-noget@example.com",
            "meta noget secret with extra safety",
            Permission::JmapMetadataGet,
        ),
        (
            "meta-noset@example.com",
            "meta noset secret with extra safety",
            Permission::JmapMetadataSet,
        ),
        (
            "meta-noprivate@example.com",
            "meta noprivate secret with extra safety",
            Permission::JmapMetadataPrivate,
        ),
    ] {
        let local = name.split_once('@').map_or(name, |(local, _)| local);
        let id = admin
            .registry_create_object(structs::Account::User(UserAccount {
                name: local.to_string(),
                domain_id,
                credentials: List::from_iter([Credential::Password(PasswordCredential {
                    secret: secret.to_string(),
                    ..Default::default()
                })]),
                permissions: structs::Permissions::Merge(PermissionsList {
                    enabled_permissions: Map::new(vec![
                        Permission::UnlimitedRequests,
                        Permission::UnlimitedUploads,
                    ]),
                    disabled_permissions: Map::new(vec![disabled]),
                }),
                ..Default::default()
            }))
            .await;
        accounts.push(Account::new(name, secret, &[], "Metadata permissions", id));
    }
    let [no_get, no_set, no_private] = &accounts[..] else {
        unreachable!()
    };

    let session = no_get.jmap_session_object().await;
    assert!(
        session
            .pointer(&format!(
                "/accounts/{}/accountCapabilities/{METADATA_CAPABILITY}",
                no_get.id_string()
            ))
            .is_none(),
        "the capability requires jmapMetadataGet: {session:?}"
    );

    let data_types = account_data_types(no_private, no_private).await;
    for name in DATA_TYPES {
        assert_eq!(
            data_types.pointer(&format!("/{name}/supportsPrivate")),
            Some(&Value::Bool(false)),
            "supportsPrivate requires jmapMetadataPrivate: {data_types}"
        );
    }

    let own_parents = ctx.parents(no_set).await;
    let mailbox = ctx
        .create_ok(no_set, MetaType::Mailbox, &own_parents, 0, json!({}))
        .await;
    ctx.update_err(
        no_set,
        no_set,
        MetaType::Mailbox,
        &mailbox,
        json!({"metadata/x.example": {"a": 1}}),
    )
    .await
    .assert_type(SetErrorType::Forbidden);
    ctx.update_ok(
        no_set,
        no_set,
        MetaType::Mailbox,
        &mailbox,
        json!({"privateMetadata/x.example": {"a": 1}}),
    )
    .await;
    ctx.assert_metadata(
        no_set,
        no_set,
        MetaType::Mailbox,
        &mailbox,
        json!({}),
        json!({"x.example": {"a": 1}}),
    )
    .await;
    ctx.create_err(
        no_set,
        MetaType::Mailbox,
        &own_parents,
        json!({"metadata": {"x.example": {"a": 1}}}),
    )
    .await
    .assert_type(SetErrorType::Forbidden);
    ctx.create_err(
        no_set,
        MetaType::Mailbox,
        &own_parents,
        json!({
            "metadata": {"x.example": {"a": 1}},
            "privateMetadata": {"x.example": {"b": 2}}
        }),
    )
    .await
    .assert_type(SetErrorType::Forbidden);
    let private_only = ctx
        .create_ok(
            no_set,
            MetaType::Mailbox,
            &own_parents,
            0,
            json!({"privateMetadata": {"x.example": {"created": true}}}),
        )
        .await;
    ctx.assert_metadata(
        no_set,
        no_set,
        MetaType::Mailbox,
        &private_only,
        json!({}),
        json!({"x.example": {"created": true}}),
    )
    .await;

    let private_parents = ctx.parents(no_private).await;
    let private_mailbox = ctx
        .create_ok(
            no_private,
            MetaType::Mailbox,
            &private_parents,
            0,
            json!({"metadata": {"x.example": {"shared": true}}}),
        )
        .await;
    ctx.update_err(
        no_private,
        no_private,
        MetaType::Mailbox,
        &private_mailbox,
        json!({"privateMetadata/x.example": {"a": 1}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);
    ctx.create_err(
        no_private,
        MetaType::Mailbox,
        &private_parents,
        json!({"privateMetadata": {"x.example": {"a": 1}}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);
    let object = ctx
        .get_one(
            no_private,
            no_private,
            MetaType::Mailbox,
            &private_mailbox,
            None,
            Using::Metadata,
        )
        .await;
    assert_eq!(
        object.get("metadata"),
        Some(&json!({"x.example": {"shared": true}}))
    );
    assert!(
        object.get("privateMetadata").is_none(),
        "privateMetadata must be absent without jmapMetadataPrivate: {object}"
    );

    let owned = ctx
        .create_ok(
            owner,
            MetaType::Mailbox,
            parents,
            0,
            json!({"metadata": {"x.example": {"visible": true}}}),
        )
        .await;
    ctx.share(
        owner,
        MetaType::Mailbox,
        &owned,
        no_set,
        Some(Access::Write),
    )
    .await;
    ctx.assert_metadata(
        no_set,
        owner,
        MetaType::Mailbox,
        &owned,
        json!({"x.example": {"visible": true}}),
        json!({}),
    )
    .await;
    ctx.update_err(
        no_set,
        owner,
        MetaType::Mailbox,
        &owned,
        json!({"metadata/x.example/visible": false}),
    )
    .await
    .assert_type(SetErrorType::Forbidden);
    ctx.update_ok(
        no_set,
        owner,
        MetaType::Mailbox,
        &owned,
        json!({"privateMetadata/x.example": {"sharee": true}}),
    )
    .await;
    ctx.assert_metadata(
        no_set,
        owner,
        MetaType::Mailbox,
        &owned,
        json!({"x.example": {"visible": true}}),
        json!({"x.example": {"sharee": true}}),
    )
    .await;
    ctx.destroy(owner, MetaType::Mailbox, &[&owned]).await;
    ctx.purge(&[owner]).await;

    for account in accounts {
        ctx.destroy_all(&account).await;
        admin.destroy_account(account).await;
    }
    ctx.test.wait_for_tasks().await;
}

async fn configure(ctx: &Ctx<'_>, metadata: Metadata, properties: &[Property]) {
    let admin = ctx.account("admin");
    admin.registry_update_setting(metadata, properties).await;
    admin.reload_settings().await;
}

async fn restore(ctx: &Ctx<'_>) {
    configure(
        ctx,
        Metadata::default(),
        &[
            Property::DataTypes,
            Property::VendorNamespaces,
            Property::PrivateMetadata,
            Property::MaxDepth,
        ],
    )
    .await;
}

async fn account_data_types(caller: &Account, account: &Account) -> Value {
    let session = caller.jmap_session_object().await;
    session
        .pointer(&format!(
            "/accounts/{}/accountCapabilities/{METADATA_CAPABILITY}/dataTypes",
            account.id_string()
        ))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "No metadata capability for {} as {}: {session:?}",
                account.name(),
                caller.name()
            )
        })
}

fn data_type_names(data_types: &Value) -> Vec<&str> {
    let mut names = data_types
        .as_object()
        .map(|types| types.keys().map(String::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    names.sort_unstable();
    names
}
