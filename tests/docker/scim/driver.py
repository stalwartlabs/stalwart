#!/usr/bin/env python3
"""Drives the third party SCIM client libraries against a Stalwart service provider."""

import argparse
import json
import sys
import traceback
import uuid

import httpx
from scim2_client.engines.httpx import SyncSCIMClient
from scim2_models import (
    Context,
    Error,
    ListResponse,
    PatchOp,
    PatchOperation,
    SearchRequest,
    ServiceProviderConfig,
)
from scim2_tester import check_server


def allow_post_rfc7643_service_provider_config_attributes():
    """RFC 9865 adds a top level `pagination` attribute to ServiceProviderConfig and
    draft-zollner-scim-interop-profile adds `interopProfileConformant`. scim2-models
    validates against RFC 7643 alone and forbids both."""
    ServiceProviderConfig.model_config["extra"] = "ignore"
    ServiceProviderConfig.model_rebuild(force=True)


def build_client(url, token):
    return SyncSCIMClient(
        httpx.Client(
            base_url=url,
            headers={"Authorization": "Bearer " + token},
            verify=False,
            timeout=120.0,
        )
    )


def conformance(client, _domain):
    results = check_server(client, raise_exceptions=False)
    return {
        "checks": [
            {
                "status": result.status.name,
                "title": result.title,
                "reason": result.reason,
                "tags": sorted(result.tags) if result.tags else [],
                "resource_type": result.resource_type,
            }
            for result in results
        ]
    }


def lifecycle(client, domain):
    steps = []

    def record(name, detail=None):
        steps.append({"step": name, "ok": True, "detail": detail})

    user_model = client.get_resource_model("User")
    group_model = client.get_resource_model("Group")
    tag = uuid.uuid4().hex[:8]
    user_name = "lifecycle-{}@{}".format(tag, domain)
    renamed = "lifecycle-{}-renamed@{}".format(tag, domain)
    alias = "lifecycle-{}-alias@{}".format(tag, domain)
    display_name = "Lifecycle Person {}".format(tag)
    group_name = "Lifecycle Team {}".format(tag)
    user_id = None
    group_id = None

    try:
        config = client.service_provider_config
        assert config.patch.supported is True
        assert config.etag.supported is True
        assert config.sort.supported is True
        assert config.change_password.supported is False
        assert config.bulk.max_operations == 1000, config.bulk
        assert config.filter.max_results == 200, config.filter
        record("discover", {
            "resource_types": sorted(
                resource_type.id for resource_type in client.resource_types
            ),
            "resource_models": sorted(
                model.__name__ for model in client.resource_models
            ),
        })

        created = client.create(
            user_model(
                user_name=user_name,
                display_name=display_name,
                external_id="lifecycle-" + tag,
                emails=[{"value": alias}],
            ),
            expected_status_codes=[201],
            raise_scim_errors=True,
        )
        user_id = created.id
        assert created.user_name == user_name, created.user_name
        assert created.display_name == display_name, created.display_name
        assert created.meta.location.endswith("/Users/" + user_id), created.meta.location
        assert created.meta.version, "the create response carried no version"
        assert "last_modified" not in type(created.meta).model_fields, "meta.lastModified was published"
        record("create_user", {"id": user_id, "version": created.meta.version})

        fetched = client.query(
            user_model, user_id, expected_status_codes=[200], raise_scim_errors=True
        )
        assert fetched.id == user_id
        assert fetched.meta.version == created.meta.version
        assert [email.value for email in fetched.emails] == [user_name, alias], fetched.emails
        record("query_user_by_id")

        response = client.client.get(
            "/Users", params={"filter": 'userName eq "{}"'.format(user_name)}
        )
        assert response.status_code == 200, response.text
        listed = ListResponse[user_model].model_validate(
            response.json(), scim_ctx=Context.RESOURCE_QUERY_RESPONSE
        )
        assert listed.total_results == 1, listed.total_results
        assert listed.resources[0].id == user_id
        record("query_user_by_filter")

        searched = client.search(
            search_request=SearchRequest(filter='userName eq "{}"'.format(user_name)),
            expected_status_codes=[200],
            raise_scim_errors=True,
        )
        assert searched.total_results == 1, searched.total_results
        record("search_endpoint")

        patched = client.modify(
            user_model,
            user_id,
            PatchOp[user_model](
                operations=[
                    PatchOperation(op="replace", path="displayName", value="Patched " + tag),
                    PatchOperation(op="replace", path="active", value=False),
                ]
            ),
            expected_status_codes=[200],
            raise_scim_errors=True,
        )
        assert patched.display_name == "Patched " + tag, patched.display_name
        assert patched.active is False, patched.active
        assert patched.meta.version != created.meta.version, "the version did not change"
        record("patch_user")

        replaced = client.replace(
            user_model(id=user_id, user_name=renamed),
            expected_status_codes=[200],
            raise_scim_errors=True,
        )
        assert replaced.user_name == renamed, replaced.user_name
        assert replaced.active is True, "a replace must reset active to its default"
        assert replaced.display_name is None, replaced.display_name
        record("replace_user")

        group = client.create(
            group_model(display_name=group_name, members=[{"value": user_id}]),
            expected_status_codes=[201],
            raise_scim_errors=True,
        )
        group_id = group.id
        assert group.display_name == group_name
        assert [member.value for member in group.members] == [user_id], group.members
        record("create_group_with_member", {"id": group_id})

        member_view = client.query(
            user_model, user_id, expected_status_codes=[200], raise_scim_errors=True
        )
        assert [entry.value for entry in member_view.groups] == [group_id], member_view.groups
        record("membership_visible_on_user")

        emptied = client.modify(
            group_model,
            group_id,
            PatchOp[group_model](
                operations=[PatchOperation(op="remove", path="members")]
            ),
            expected_status_codes=[200],
            raise_scim_errors=True,
        )
        assert not emptied.members, emptied.members
        record("patch_group_members")

        client.delete(group_model, group_id, expected_status_codes=[204], raise_scim_errors=True)
        group_id = None
        record("delete_group")

        client.delete(user_model, user_id, expected_status_codes=[204], raise_scim_errors=True)
        gone = client.query(
            user_model,
            user_id,
            expected_status_codes=[404],
            raise_scim_errors=False,
        )
        assert isinstance(gone, Error), gone
        assert gone.status == 404, gone
        user_id = None
        record("delete_user")
    except Exception as err:
        steps.append(
            {
                "step": "aborted",
                "ok": False,
                "detail": "".join(
                    traceback.format_exception(type(err), err, err.__traceback__)
                ),
            }
        )
    finally:
        for model, resource_id in ((group_model, group_id), (user_model, user_id)):
            if resource_id:
                try:
                    client.delete(model, resource_id)
                except Exception:
                    pass

    return {"steps": steps}


def clients(client, domain):
    """Replays the payload shapes that Okta and the Keycloak community extensions send."""
    steps = []
    user_model = client.get_resource_model("User")
    tag = uuid.uuid4().hex[:8]
    created = []

    def check(name, fn):
        try:
            fn()
            steps.append({"step": name, "ok": True, "detail": None})
        except Exception as err:
            steps.append(
                {
                    "step": name,
                    "ok": False,
                    "detail": "".join(
                        traceback.format_exception(type(err), err, err.__traceback__)
                    ),
                }
            )

    def post(name, payload):
        def run():
            response = client.client.post("/Users", json=payload)
            assert response.status_code == 201, "{} {}".format(
                response.status_code, response.text
            )
            body = response.json()
            created.append(body["id"])
            assert body["userName"] == payload["userName"], body
            assert "password" not in response.text, body
            if payload.get("displayName"):
                assert body["displayName"] == payload["displayName"], body
            elif payload.get("name", {}).get("givenName"):
                expected = " ".join(
                    part
                    for part in (
                        payload["name"].get("givenName"),
                        payload["name"].get("familyName"),
                    )
                    if part
                )
                assert body["displayName"] == expected, body
            user_model.model_validate(body, scim_ctx=Context.RESOURCE_QUERY_RESPONSE)

        check(name, run)

    okta_name = "okta-{}@{}".format(tag, domain)
    post(
        "okta_create_user",
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": okta_name,
            "name": {"givenName": "Barbara", "familyName": "Jensen"},
            "emails": [{"primary": True, "value": okta_name, "type": "work"}],
            "displayName": "Barbara Jensen",
            "locale": "en-US",
            "externalId": "00u" + tag,
            "groups": [],
            "password": "correct horse battery staple",
            "active": True,
            "title": "Vice President",
            "userType": "Employee",
            "phoneNumbers": [{"value": "555-0100", "type": "work"}],
        },
    )

    keycloak_name = "keycloak-{}@{}".format(tag, domain)
    post(
        "keycloak_create_user",
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": keycloak_name,
            "name": {"givenName": "Wile", "familyName": "Coyote"},
            "emails": [{"value": keycloak_name, "primary": True}],
            "active": True,
            "externalId": "kc-" + tag,
        },
    )

    entra_name = "entra-{}@{}".format(tag, domain)
    post(
        "entra_create_user",
        {
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            ],
            "userName": entra_name,
            "name": {"givenName": "Road", "familyName": "Runner"},
            "displayName": "Road Runner",
            "emails": [{"value": entra_name, "type": "work", "primary": True}],
            "active": True,
            "externalId": "entra-" + tag,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "department": "Sales",
                "employeeNumber": "42",
            },
        },
    )

    if created:
        okta_id = created[0]

        def okta_put():
            response = client.client.put(
                "/Users/" + okta_id,
                json={
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": okta_id,
                    "userName": okta_name,
                    "name": {"givenName": "Babs", "familyName": "Jensen"},
                    "emails": [{"primary": True, "value": okta_name, "type": "work"}],
                    "displayName": "Babs Jensen",
                    "active": False,
                    "password": "correct horse battery staple",
                    "title": "President",
                },
            )
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["displayName"] == "Babs Jensen", body
            assert body["active"] is False, body

        check("okta_replace_user", okta_put)

        def keycloak_patch():
            response = client.client.patch(
                "/Users/" + created[1],
                json={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{"op": "replace", "value": {"active": "false"}}],
                },
            )
            assert response.status_code == 200, response.text
            assert response.json()["active"] is False, response.text

        check("keycloak_deactivate_user", keycloak_patch)

        def entra_patch():
            response = client.client.patch(
                "/Users/" + created[2],
                json={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [
                        {"op": "replace", "path": "name.givenName", "value": "Wile"},
                        {"op": "replace", "path": "displayName", "value": "Wile Runner"},
                        {
                            "op": "add",
                            "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                            "value": "Marketing",
                        },
                    ],
                },
            )
            assert response.status_code == 200, response.text
            assert response.json()["displayName"] == "Wile Runner", response.text

        check("entra_patch_user", entra_patch)

        def okta_lookup():
            response = client.client.get(
                "/Users", params={"filter": 'userName eq "{}"'.format(okta_name)}
            )
            assert response.status_code == 200, response.text
            listed = ListResponse[user_model].model_validate(
                response.json(), scim_ctx=Context.RESOURCE_QUERY_RESPONSE
            )
            assert listed.total_results == 1, listed.total_results

        check("okta_lookup_by_username", okta_lookup)

    def rejects_typos():
        response = client.client.post(
            "/Users",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "typo-{}@{}".format(tag, domain),
                "dispalyName": "Typo",
            },
        )
        assert response.status_code == 400, response.text
        assert response.json()["scimType"] == "invalidSyntax", response.text

    check("misspelled_attributes_are_still_rejected", rejects_typos)

    for resource_id in created:
        try:
            client.client.delete("/Users/" + resource_id)
        except Exception:
            pass

    return {"steps": steps}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument(
        "--mode", required=True, choices=["conformance", "lifecycle", "clients"]
    )
    args = parser.parse_args()

    allow_post_rfc7643_service_provider_config_attributes()
    client = build_client(args.url, args.token)
    try:
        client.discover()
    except Exception as err:
        json.dump(
            {"error": "discovery failed: " + "".join(
                traceback.format_exception(type(err), err, err.__traceback__)
            )},
            sys.stdout,
        )
        sys.stdout.write("\n")
        return

    runner = {"conformance": conformance, "lifecycle": lifecycle, "clients": clients}[
        args.mode
    ]
    json.dump(runner(client, args.domain), sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
