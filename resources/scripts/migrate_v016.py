#!/usr/bin/env python3
"""
Stalwart v0.16 migration helper.

Two modes:

  dump    — pull all settings and principals from a Stalwart server via the
            management API into two JSON files.

  convert — read those two JSON files and emit:
              * config.json   — plain DataStore object (Stalwart's main config)
              * export.json   — NDJSON stream of `update`/`create` ops for
                               everything else, one op per line, in load order.

Usage:
    python migrate_v016.py dump --url https://mail.example.com \
        --username admin --password s3cret \
        --settings settings.json --principals principals.json

    python migrate_v016.py convert \
        --settings settings.json --principals principals.json \
        --config config.json --output export.json
"""

# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
from collections import defaultdict
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALL_PRINCIPAL_TYPES = [
    "individual",
    "group",
    "resource",
    "location",
    "list",
    "other",
    "domain",
    "tenant",
    "role",
    "apiKey",
    "oauthClient",
]

PAGE_SIZE = 200
REQUEST_TIMEOUT = 60

class ApiError(RuntimeError):
    pass

class ConvertError(RuntimeError):
    pass

class StalwartClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"Accept": "application/json"})
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        elif username is not None and password is not None:
            self.session.auth = (username, password)
        else:
            raise ValueError("need either a token or username/password")

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
    ) -> Any:
        resp = self.session.request(
            method,
            self.base_url + path,
            params=params,
            json=json_body,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 401:
            raise ApiError(f"401 Unauthorized for {method} {path}")
        if resp.status_code == 403:
            raise ApiError(f"403 Forbidden for {method} {path}")
        if resp.status_code == 404:
            raise ApiError(f"404 Not Found for {method} {path}")
        if not resp.ok:
            raise ApiError(
                f"{resp.status_code} {resp.reason} for {method} {path}: {resp.text[:500]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ApiError(f"Non-JSON response from {path}: {exc}")
        if isinstance(payload, dict) and "error" in payload and "data" not in payload:
            raise ApiError(f"Server error on {path}: {payload}")
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def dump_all_settings(self) -> dict[str, str]:

        merged: dict[str, str] = {}
        page = 1
        last_progress_page = 0
        while True:
            data = self.get(
                "/api/settings/list",
                params={
                    "prefix": "",
                    "page": str(page),
                    "limit": str(PAGE_SIZE),
                },
            )
            items = data.get("items", {}) or {}
            total = int(data.get("total", len(items)) or 0)

            before = len(merged)
            merged.update(items)
            gained = len(merged) - before

            if not items:
                break
            if len(merged) >= total:
                break
            if gained == 0:
                raise ApiError(
                    f"Settings pagination made no progress on page {page} "
                    f"(have {len(merged)}/{total}). Server may not support "
                    "paging /api/settings/list with page/limit."
                )
            last_progress_page = page
            page += 1

            if page - last_progress_page > 5:
                raise ApiError(
                    f"Settings pagination stalled at page {page} "
                    f"(have {len(merged)}/{total})."
                )
        return merged

    def list_principal_names(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for principal_type in ALL_PRINCIPAL_TYPES:
            try:
                self._list_principals_of_type(principal_type, out, seen)
            except ApiError as exc:
                print(
                    f"  WARN skipping principal type {principal_type!r}: {exc}",
                    file=sys.stderr,
                )
        return out

    def _list_principals_of_type(
        self,
        principal_type: str,
        out: list[tuple[str, str]],
        seen: set[tuple[str, str]],
    ) -> None:
        before = len(out)
        page = 1
        while True:
            data = self.get(
                "/api/principal",
                params={
                    "page": str(page),
                    "limit": str(PAGE_SIZE),
                    "types": principal_type,
                },
            )
            items = data.get("items", []) or []
            total = int(data.get("total", 0) or 0)
            for p in items:
                typ = p.get("type") or principal_type
                name = _principal_name(p)
                if not name:
                    continue
                key = (typ, name)
                if key in seen:
                    continue
                seen.add(key)
                out.append(key)
            if not items:
                break
            if (len(out) - before) >= total:
                break
            page += 1

    def get_principal(self, name: str) -> dict[str, Any]:
        quoted = urllib.parse.quote(name, safe="")
        return self.get(f"/api/principal/{quoted}")

def _principal_name(p: dict[str, Any]) -> str:
    v = p.get("name")
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        if isinstance(v.get("string"), str):
            return v["string"]
        sl = v.get("stringList")
        if isinstance(sl, list) and sl:
            return sl[0]
    if isinstance(v, list) and v:
        return v[0]
    return ""

def cmd_dump(args: argparse.Namespace) -> int:
    if args.token:
        client = StalwartClient(args.url, token=args.token, verify=False)
    elif args.username and args.password:
        client = StalwartClient(
            args.url,
            username=args.username,
            password=args.password,
            verify=False,
        )
    else:
        print("error: either --token or --username/--password is required",
              file=sys.stderr)
        return 2

    print("Fetching settings...", file=sys.stderr)
    settings = client.dump_all_settings()
    with open(args.settings, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, sort_keys=True, ensure_ascii=False)
    print(f"  wrote {len(settings)} settings keys to {args.settings}",
          file=sys.stderr)

    print("Listing principals...", file=sys.stderr)
    names = client.list_principal_names()
    print(f"  found {len(names)} principals across all types", file=sys.stderr)

    principals: list[dict[str, Any]] = []
    for i, (typ, name) in enumerate(names, 1):
        try:
            full = client.get_principal(name)
        except ApiError as exc:
            print(f"  [{i}/{len(names)}] WARN failed to fetch {typ} {name!r}: {exc}",
                  file=sys.stderr)
            continue
        principals.append(full)
        if i % 50 == 0 or i == len(names):
            print(f"  [{i}/{len(names)}] fetched {typ} {name}", file=sys.stderr)

    missing_id = [p for p in principals if p.get("id") is None]
    if missing_id:
        print(
            f"warning: {len(missing_id)} principal(s) returned no 'id' field",
            file=sys.stderr,
        )

    with open(args.principals, "w", encoding="utf-8") as f:
        json.dump(principals, f, indent=2, ensure_ascii=False)
    print(f"  wrote {len(principals)} principals to {args.principals}",
          file=sys.stderr)

    return 0

_DURATION_UNITS_MS = {
    "ms": 1,
    "s": 1000,
    "m": 60_000,
    "h": 3_600_000,
    "d": 86_400_000,
    "w": 604_800_000,
}

_SIZE_UNITS_BYTES = {
    "": 1,
    "b": 1,
    "kb": 1024,
    "mb": 1024 * 1024,
    "gb": 1024 * 1024 * 1024,
}

def parse_duration_ms(s: str | None) -> int | None:

    if s is None:
        return None
    s = str(s).strip().lower()
    if not s:
        return None
    m = re.fullmatch(r"(-?\d+)(ms|s|m|h|d|w)?", s)
    if not m:
        raise ConvertError(f"Could not parse duration {s!r}")
    n = int(m.group(1))
    unit = m.group(2) or "ms"
    return n * _DURATION_UNITS_MS[unit]

def parse_size_bytes(s: str | None) -> int | None:

    if s is None:
        return None
    s = str(s).strip().lower()
    if not s:
        return None
    m = re.fullmatch(r"(-?\d+)\s*(b|kb|mb|gb)?", s)
    if not m:
        raise ConvertError(f"Could not parse size {s!r}")
    return int(m.group(1)) * _SIZE_UNITS_BYTES[m.group(2) or ""]

def parse_int(s: str | None) -> int | None:
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError as exc:
        raise ConvertError(f"Could not parse integer {s!r}") from exc

def parse_bool(s: str | None) -> bool | None:
    if s is None:
        return None
    v = str(s).strip().lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off", ""):
        return False
    raise ConvertError(f"Could not parse bool {s!r}")

def pv_string(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, dict):
        if isinstance(v.get("string"), str):
            return v["string"]
        sl = v.get("stringList")
        if isinstance(sl, list) and sl:
            return str(sl[0])
        iv = v.get("integer")
        if isinstance(iv, int):
            return str(iv)
    if isinstance(v, list) and v:
        return pv_string(v[0])
    return ""

def pv_int(v: Any) -> int | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return None
    if isinstance(v, dict):
        iv = v.get("integer")
        if isinstance(iv, int):
            return iv
    return None

def pv_list(v: Any) -> list:

    if v is None:
        return []
    if isinstance(v, list):
        return list(v)
    if isinstance(v, dict):
        sl = v.get("stringList")
        if isinstance(sl, list):
            return list(sl)
        il = v.get("integerList")
        if isinstance(il, list):
            return list(il)
        if "string" in v and isinstance(v["string"], str):
            return [v["string"]]
        if "integer" in v and isinstance(v["integer"], int):
            return [v["integer"]]
        return []

    return [v]

def split_email(addr: str) -> tuple[str, str] | None:

    if "@" not in addr:
        return None
    local, _, domain = addr.rpartition("@")
    domain = domain.strip().lower()
    if not domain:
        return None
    return (local, domain)

_LABEL_RE = re.compile(r"^[^\W_](?:(?:[^\W_]|-){0,61}[^\W_])?$")
_RFC6761_RESERVED_TLDS = {"test", "local", "localhost", "invalid", "example"}

def is_valid_domain_name(name: str) -> bool:

    if not name or len(name) > 253:
        return False
    name = name.strip(".").lower()
    if not name:
        return False
    labels = name.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not _LABEL_RE.match(label):
            return False
    return True

def is_valid_local_part(local: str) -> bool:

    return bool(local) and "@" not in local

def parse_path_patch(arg: str) -> tuple[str, str]:

    if "=" not in arg:
        raise argparse.ArgumentTypeError(
            f"--patch-paths expects SOURCE=DEST, got {arg!r}"
        )
    src, _, dst = arg.partition("=")
    src = src.rstrip("/")
    dst = dst.rstrip("/")
    if not src or not dst:
        raise argparse.ArgumentTypeError(
            f"--patch-paths expects non-empty SOURCE and DEST, got {arg!r}"
        )
    return (src, dst)

def apply_path_patches(value: Any, patches: list[tuple[str, str]]) -> tuple[Any, int]:

    count = 0
    if isinstance(value, str):
        for src, dst in patches:
            if value == src or value.startswith(src + "/"):
                return (dst + value[len(src):], 1)
        return (value, 0)
    if isinstance(value, list):
        new_list: list[Any] = []
        for item in value:
            patched, n = apply_path_patches(item, patches)
            new_list.append(patched)
            count += n
        return (new_list, count)
    if isinstance(value, dict):
        new_dict: dict[Any, Any] = {}
        for k, v in value.items():
            patched, n = apply_path_patches(v, patches)
            new_dict[k] = patched
            count += n
        return (new_dict, count)
    return (value, 0)

def detect_legacy_paths(settings: dict[str, str], prefix: str = "/opt/stalwart") -> int:

    needle = prefix.rstrip("/") + "/"
    exact = prefix.rstrip("/")
    return sum(
        1
        for v in settings.values()
        if isinstance(v, str) and (needle in v or v.endswith(exact))
    )

_CONSUMED_PREFIXES: tuple[str, ...] = (
    "acme.",
    "certificate.",
    "enterprise.",
    "lookup.default.",
    "server.hostname",
    "signature.",
    "storage.",
    "store.",
    "version.",
)

def is_consumed_setting_key(key: str) -> bool:

    for prefix in _CONSUMED_PREFIXES:
        if prefix.endswith(".") and key.startswith(prefix):
            return True
        if not prefix.endswith(".") and (key == prefix or key.startswith(prefix + ".")):
            return True
    return False

def compute_unmigrated_keys(settings: dict[str, str]) -> list[str]:

    return sorted(k for k in settings if not is_consumed_setting_key(k))

def write_unmigrated_summary(unmigrated: list[str], path: str) -> None:

    counts: dict[str, int] = {}
    for k in unmigrated:
        parts = k.split(".", 2)
        prefix = ".".join(parts[:2]) if len(parts) >= 2 else parts[0]
        counts[prefix] = counts.get(prefix, 0) + 1

    width = max((len(p) for p in counts), default=0)
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            "# Unmigrated v0.15 settings\n"
            "\n"
            "These v0.15 settings were not migrated by the script and must be\n"
            "reviewed manually. The list below is grouped by the first two\n"
            "segments of the setting key. Each prefix maps to one or more v0.16\n"
            "objects; consult UPGRADING/v0_16.md and the v0.16 reference docs\n"
            "to identify the equivalent on the new schema.\n"
            "\n"
            f"Total unmigrated keys: {len(unmigrated)} across "
            f"{len(counts)} prefixes.\n"
            "\n"
        )
        for prefix in sorted(counts):
            f.write(f"  {prefix:<{width}}  {counts[prefix]:5d} keys\n")

def group_settings_by_prefix(settings: dict[str, str], prefix: str) -> dict[str, dict[str, str]]:

    raise NotImplementedError

def build_sub_trees(
    settings: dict[str, str],
    prefix: str,
    discriminator: str,
) -> dict[str, dict[str, str]]:

    record_ids: list[str] = []
    disc_suffix = "." + discriminator
    prefix_dot = prefix + "."
    for k in settings:
        if k.startswith(prefix_dot) and k.endswith(disc_suffix):
            rid = k[len(prefix_dot):-len(disc_suffix)]
            if rid:
                record_ids.append(rid)

    record_ids.sort(key=lambda s: (-len(s), s))

    trees: dict[str, dict[str, str]] = {rid: {} for rid in record_ids}
    claimed: set[str] = set()
    for rid in record_ids:
        head = prefix_dot + rid + "."
        for k, v in settings.items():
            if k in claimed:
                continue
            if k.startswith(head):
                sub = k[len(head):]
                trees[rid][sub] = v
                claimed.add(k)
    return trees

def collect_array(sub: dict[str, str], field: str) -> list[str]:

    items: list[tuple[int, str]] = []
    head = field + "."
    for k, v in sub.items():
        if k.startswith(head):
            tail = k[len(head):]
            if tail.isdigit():
                items.append((int(tail), v))
    items.sort()
    return [v for _, v in items]

_PEM_RE = re.compile(
    r"-----BEGIN (?P<kind>[A-Z][A-Z0-9 ]*?)-----"
    r"[\s\S]+?"
    r"-----END (?P=kind)-----",
    re.MULTILINE,
)


def split_pem_bundle(blob: str) -> tuple[str, str]:
    certs: list[str] = []
    key: str | None = None
    for m in _PEM_RE.finditer(blob):
        kind = m.group("kind")
        block = m.group(0) + "\n"
        if "PRIVATE KEY" in kind:
            if key is None:
                key = block
        elif kind == "CERTIFICATE":
            certs.append(block)
    return ("".join(certs), key or "")


def _make_certificate_object(cert_pem: str, key_pem: str) -> dict[str, Any]:
    return {
        "certificate": {"@type": "Text", "value": cert_pem},
        "privateKey": {"@type": "Text", "secret": key_pem},
    }


def is_app_password(secret: str) -> bool:
    return secret.startswith("$app$")

def is_otpauth(secret: str) -> bool:
    return secret.startswith("otpauth://")

def secret_key_optional(value: str | None) -> dict[str, Any]:

    if value is None or value == "":
        return {"@type": "None"}
    return {"@type": "Value", "secret": value}

def secret_key(value: str | None) -> dict[str, Any]:

    if value is None or value == "":
        return {"@type": "None"}
    return {"@type": "Value", "secret": value}

def secret_text(value: str | None) -> dict[str, Any]:

    if value is None or value == "":
        return {"@type": "None"}
    return {"@type": "Text", "secret": value}

_MACRO_RE = re.compile(r"%\{(cfg|env|file):([^}]*)\}%")

def resolve_macros(
    value: str | None,
    settings: dict[str, str],
    _seen: frozenset[str] = frozenset(),
) -> tuple[str | None, list[str]]:
    if value is None or "%{" not in value:
        return value, []
    errors: list[str] = []

    def repl(m: "re.Match[str]") -> str:
        kind = m.group(1)
        arg = m.group(2).strip()
        if kind == "cfg":
            if arg in _seen:
                errors.append(f"circular %{{cfg:{arg}}}% reference")
                return ""
            raw = settings.get(arg)
            if raw is None:
                errors.append(f"unknown setting referenced by %{{cfg:{arg}}}%")
                return ""
            nested, nested_errors = resolve_macros(
                raw, settings, _seen | {arg}
            )
            errors.extend(nested_errors)
            return nested or ""
        if kind == "env":
            env = os.environ.get(arg)
            if env is None:
                errors.append(
                    f"environment variable {arg!r} (from %{{env:{arg}}}%) "
                    f"is not set"
                )
                return ""
            return env
        try:
            with open(arg, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            errors.append(f"cannot read file {arg!r} (from %{{file:...}}%): {exc}")
            return ""

    prev = value
    for _ in range(8):
        cur = _MACRO_RE.sub(repl, prev)
        if cur == prev:
            break
        prev = cur
    return prev, errors

_REDIS_PROTOCOL_MAP = {
    "resp2": "resp2",
    "resp3": "resp3",
}

_S3_REGION_MAP = {
    "us-east-1": "UsEast1", "us-east-2": "UsEast2",
    "us-west-1": "UsWest1", "us-west-2": "UsWest2",
    "ca-central-1": "CaCentral1",
    "af-south-1": "AfSouth1",
    "ap-east-1": "ApEast1", "ap-south-1": "ApSouth1",
    "ap-northeast-1": "ApNortheast1", "ap-northeast-2": "ApNortheast2",
    "ap-northeast-3": "ApNortheast3",
    "ap-southeast-1": "ApSoutheast1", "ap-southeast-2": "ApSoutheast2",
    "cn-north-1": "CnNorth1", "cn-northwest-1": "CnNorthwest1",
    "eu-north-1": "EuNorth1",
    "eu-central-1": "EuCentral1", "eu-central-2": "EuCentral2",
    "eu-west-1": "EuWest1", "eu-west-2": "EuWest2", "eu-west-3": "EuWest3",
    "il-central-1": "IlCentral1",
    "me-south-1": "MeSouth1",
    "sa-east-1": "SaEast1",
    "do-nyc3": "DoNyc3", "do-ams3": "DoAms3",
    "do-sgp1": "DoSgp1", "do-fra1": "DoFra1",
    "yandex": "Yandex",
    "wa-us-east-1": "WaUsEast1", "wa-us-east-2": "WaUsEast2",
    "wa-us-central-1": "WaUsCentral1", "wa-us-west-1": "WaUsWest1",
    "wa-ca-central-1": "WaCaCentral1",
    "wa-eu-central-1": "WaEuCentral1", "wa-eu-central-2": "WaEuCentral2",
    "wa-eu-west-1": "WaEuWest1", "wa-eu-west-2": "WaEuWest2",
    "wa-ap-northeast-1": "WaApNortheast1", "wa-ap-northeast-2": "WaApNortheast2",
    "wa-ap-southeast-1": "WaApSoutheast1", "wa-ap-southeast-2": "WaApSoutheast2",
}

class Converter:
    def __init__(
        self,
        principals: list[dict[str, Any]],
        settings: dict[str, str],
    ):
        self.principals = principals
        self.settings = settings

        self.by_name: dict[str, dict[str, Any]] = {}
        self.by_id: dict[int, dict[str, Any]] = {}
        for p in principals:
            n = pv_string(p.get("name"))
            if n:
                self.by_name[n] = p
            pid = pv_int(p.get("id"))
            if pid is not None:
                self.by_id[pid] = p

        self.tenant_name_to_cid: dict[str, str] = {}
        self.domain_name_to_cid: dict[str, str] = {}
        self.domain_cid_to_name: dict[str, str] = {}
        self.domain_cid_to_tenant_cid: dict[str, str] = {}
        self.default_domain_cid: str | None = None
        self._create_counter = 0

    def _next_create_cid(self) -> str:
        cid = f"create-{self._create_counter}"
        self._create_counter += 1
        return cid

    @staticmethod
    def _account_cid(old_id: int) -> str:
        return f"restore-{old_id}"

    def run(self) -> dict[str, Any]:
        tenants = self._build_tenants()
        domains = self._build_domains()
        self._pick_default_domain()
        accounts = self._build_accounts()
        mailing_lists = self._build_mailing_lists()
        dkim_signatures = self._build_dkim_signatures()
        certificates = self._build_certificates()

        self._check_duplicate_emails(accounts, mailing_lists)
        self._validate_records(domains, accounts, mailing_lists, dkim_signatures)

        data_store = self._build_data_store()
        blob_store = self._build_blob_store()
        in_memory_store = self._build_in_memory_store()
        search_store = self._build_search_store()
        metrics_store = self._build_metrics_store()
        tracing_store = self._build_tracing_store()
        enterprise = self._build_enterprise()
        system_settings = self._build_system_settings()

        out: dict[str, Any] = {}
        if system_settings is not None:
            out["SystemSettings"] = system_settings
        if enterprise is not None:
            out["Enterprise"] = enterprise
        if data_store is not None:
            out["DataStore"] = data_store
        if blob_store is not None:
            out["BlobStore"] = blob_store
        if in_memory_store is not None:
            out["InMemoryStore"] = in_memory_store
        if search_store is not None:
            out["SearchStore"] = search_store
        if metrics_store is not None:
            out["MetricsStore"] = metrics_store
        if tracing_store is not None:
            out["TracingStore"] = tracing_store
        if tenants:
            out["Tenant"] = tenants
        if domains:
            out["Domain"] = domains
        if accounts:
            out["Account"] = accounts
        if mailing_lists:
            out["MailingList"] = mailing_lists
        if dkim_signatures:
            out["DkimSignature"] = dkim_signatures
        if certificates:
            out["Certificate"] = certificates
        return out

    def _build_tenants(self) -> dict[str, dict[str, Any]]:
        tenants = [p for p in self.principals if p.get("type") == "tenant"]
        tenants.sort(key=lambda p: pv_string(p.get("name")))
        out: dict[str, dict[str, Any]] = {}
        for p in tenants:
            name = pv_string(p.get("name"))
            if not name:
                continue
            cid = self._next_create_cid()
            self.tenant_name_to_cid[name] = cid
            obj: dict[str, Any] = {"name": name}
            logo = pv_string(p.get("picture"))
            if logo:
                obj["logo"] = logo
            quotas: dict[str, int] = {}
            q = pv_int(p.get("quota"))
            if q:
                quotas["maxDiskQuota"] = q
            obj["quotas"] = quotas
            out[cid] = obj
        return out

    def _collect_domain_names(self) -> set[str]:
        names: set[str] = set()

        def add(addr: str) -> None:
            parts = split_email(addr)
            if parts is None:
                return
            _, dom = parts
            if dom:
                names.add(dom)

        for p in self.principals:
            t = p.get("type")
            if t == "domain":
                n = pv_string(p.get("name")).strip().lower()
                if n:
                    names.add(n)
            elif t in ("individual", "group", "list"):

                nm = pv_string(p.get("name"))
                if "@" in nm:
                    add(nm)
                for addr in pv_list(p.get("emails")):
                    if isinstance(addr, str):
                        add(addr)

        sigs = build_sub_trees(self.settings, "signature", "algorithm")
        for _, sub in sigs.items():
            d = sub.get("domain", "").strip().lower()
            if d:
                names.add(d)

        return names

    def _build_domains(self) -> dict[str, dict[str, Any]]:
        declared: dict[str, dict[str, Any]] = {}
        for p in self.principals:
            if p.get("type") == "domain":
                n = pv_string(p.get("name")).strip().lower()
                if n:
                    declared[n] = p

        names = sorted(self._collect_domain_names())
        out: dict[str, dict[str, Any]] = {}
        for dname in names:
            cid = self._next_create_cid()
            self.domain_name_to_cid[dname] = cid
            self.domain_cid_to_name[cid] = dname
            obj: dict[str, Any] = {"name": dname}
            p = declared.get(dname)
            if p is not None:
                desc = pv_string(p.get("description"))
                if desc:
                    obj["description"] = desc
                logo = pv_string(p.get("picture"))
                if logo:
                    obj["logo"] = logo
                tname = pv_string(p.get("tenant"))
                if tname and tname in self.tenant_name_to_cid:
                    t_cid = self.tenant_name_to_cid[tname]
                    obj["memberTenantId"] = "#" + t_cid
                    self.domain_cid_to_tenant_cid[cid] = t_cid
            out[cid] = obj
        return out

    def _pick_default_domain(self) -> None:
        if not self.domain_name_to_cid:
            self.default_domain_cid = None
            return
        if len(self.domain_name_to_cid) == 1:
            self.default_domain_cid = next(iter(self.domain_name_to_cid.values()))
            return

        counts: dict[str, int] = defaultdict(int)
        for p in self.principals:
            t = p.get("type")
            if t not in ("individual", "group", "list"):
                continue
            d = self._infer_primary_domain(p)
            if d is not None:
                counts[d] += 1
        if not counts:
            first = sorted(self.domain_name_to_cid.keys())[0]
            self.default_domain_cid = self.domain_name_to_cid[first]
            return

        best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        self.default_domain_cid = self.domain_name_to_cid[best]

    def _infer_primary_domain(self, p: dict[str, Any]) -> str | None:

        nm = pv_string(p.get("name"))
        if "@" in nm:
            parts = split_email(nm)
            if parts and parts[1]:
                return parts[1]

        fallback: str | None = None
        for addr in pv_list(p.get("emails")):
            if not isinstance(addr, str):
                continue
            parts = split_email(addr)
            if parts is None:
                continue
            local, dom = parts
            if not dom:
                continue
            if local and local == nm:
                return dom
            if fallback is None:
                fallback = dom
        return fallback

    def _tenant_default_domain_cid(self, p: dict[str, Any]) -> str | None:
        tname = pv_string(p.get("tenant"))
        if not tname:
            return None
        t_cid = self.tenant_name_to_cid.get(tname)
        if t_cid is None:
            return None
        candidates = [
            (self.domain_cid_to_name.get(cid, ""), cid)
            for cid, owner in self.domain_cid_to_tenant_cid.items()
            if owner == t_cid
        ]
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][1]

    def _resolve_name_and_domain(self, p: dict[str, Any]) -> tuple[str, str]:
        nm = pv_string(p.get("name"))

        if "@" in nm:
            parts = split_email(nm)
            if parts is None or not parts[1]:
                raise ConvertError(f"principal name {nm!r} is malformed")
            local, dom = parts
            if dom not in self.domain_name_to_cid:
                raise ConvertError(f"domain {dom!r} missing from domain index")
            return (local, self.domain_name_to_cid[dom])

        dom = self._infer_primary_domain(p)
        if dom:
            if dom not in self.domain_name_to_cid:
                raise ConvertError(f"domain {dom!r} missing from domain index")
            return (nm, self.domain_name_to_cid[dom])

        tenant_default = self._tenant_default_domain_cid(p)
        if tenant_default is not None:
            return (nm, tenant_default)

        if self.default_domain_cid is None:
            raise ConvertError(
                f"principal {nm!r} has no domain and no default domain is set"
            )
        return (nm, self.default_domain_cid)

    def _build_aliases(
        self,
        p: dict[str, Any],
        primary_name: str,
        primary_domain_cid: str,
    ) -> dict[str, dict[str, Any]]:
        aliases: dict[str, dict[str, Any]] = {}
        idx = 0
        seen: set[tuple[str, str]] = set()
        for addr in pv_list(p.get("emails")):
            if not isinstance(addr, str):
                continue
            parts = split_email(addr)
            if parts is None:
                continue
            local, dom = parts
            if local == "":
                continue
            if dom not in self.domain_name_to_cid:
                continue
            d_cid = self.domain_name_to_cid[dom]
            if local == primary_name and d_cid == primary_domain_cid:
                continue
            key = (local, d_cid)
            if key in seen:
                continue
            seen.add(key)
            aliases[str(idx)] = {"name": local, "domainId": "#" + d_cid}
            idx += 1
        return aliases

    def _build_accounts(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for p in self.principals:
            t = p.get("type")
            if t == "individual":
                cid, obj = self._build_user(p)
            elif t == "group":
                cid, obj = self._build_group(p)
            else:
                continue
            if cid in out:
                raise ConvertError(f"duplicate account client-id {cid!r}")
            out[cid] = obj
        return out

    def _build_user(self, p: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        local, dom_cid = self._resolve_name_and_domain(p)
        uid = pv_int(p.get("id"))
        if uid is None:
            raise ConvertError(f"user {pv_string(p.get('name'))!r} has no id")
        body: dict[str, Any] = {
            "@type": "User",
            "name": local,
            "domainId": "#" + dom_cid,
            "aliases": self._build_aliases(p, local, dom_cid),
            "credentials": self._build_credentials(p),
            "memberGroupIds": self._build_member_group_ids(p),
            "quotas": self._build_account_quotas(p),
        }
        desc = pv_string(p.get("description"))
        if desc:
            body["description"] = desc
        tname = pv_string(p.get("tenant"))
        if tname and tname in self.tenant_name_to_cid:
            body["memberTenantId"] = "#" + self.tenant_name_to_cid[tname]
        return (self._account_cid(uid), body)

    def _build_group(self, p: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        local, dom_cid = self._resolve_name_and_domain(p)
        gid = pv_int(p.get("id"))
        if gid is None:
            raise ConvertError(f"group {pv_string(p.get('name'))!r} has no id")
        body: dict[str, Any] = {
            "@type": "Group",
            "name": local,
            "domainId": "#" + dom_cid,
            "aliases": self._build_aliases(p, local, dom_cid),
            "quotas": self._build_account_quotas(p),
        }
        desc = pv_string(p.get("description"))
        if desc:
            body["description"] = desc
        tname = pv_string(p.get("tenant"))
        if tname and tname in self.tenant_name_to_cid:
            body["memberTenantId"] = "#" + self.tenant_name_to_cid[tname]
        return (self._account_cid(gid), body)

    def _build_account_quotas(self, p: dict[str, Any]) -> dict[str, int]:
        quotas: dict[str, int] = {}
        q = pv_int(p.get("quota"))
        if q:
            quotas["maxDiskQuota"] = q
        return quotas

    def _build_credentials(self, p: dict[str, Any]) -> dict[str, dict[str, Any]]:

        secrets = [s for s in pv_list(p.get("secrets")) if isinstance(s, str)]
        password = next(
            (s for s in secrets if not is_app_password(s) and not is_otpauth(s)),
            None,
        )
        otp = next((s for s in secrets if is_otpauth(s)), None)
        if password is None:
            return {}
        cred: dict[str, Any] = {
            "@type": "Password",
            "secret": password,
        }
        if otp is not None:
            cred["otpAuth"] = otp
        return {"0": cred}

    def _build_member_group_ids(self, p: dict[str, Any]) -> dict[str, bool]:
        out: dict[str, bool] = {}
        for ref in pv_list(p.get("memberOf")):
            target = self._resolve_principal_ref(ref)
            if target is None:
                continue
            if target.get("type") != "group":
                continue
            gid = pv_int(target.get("id"))
            if gid is None:
                continue
            out["#" + self._account_cid(gid)] = True
        return out

    def _resolve_principal_ref(self, ref: Any) -> dict[str, Any] | None:
        if isinstance(ref, str):
            return self.by_name.get(ref)
        if isinstance(ref, int):
            return self.by_id.get(ref)
        if isinstance(ref, dict):
            if "string" in ref:
                return self.by_name.get(str(ref["string"]))
            if "integer" in ref:
                return self.by_id.get(int(ref["integer"]))
        return None

    def _build_mailing_lists(self) -> dict[str, dict[str, Any]]:
        lists = [p for p in self.principals if p.get("type") == "list"]
        lists.sort(key=lambda p: (pv_int(p.get("id")) or 0))
        out: dict[str, dict[str, Any]] = {}
        for p in lists:
            try:
                local, dom_cid = self._resolve_name_and_domain(p)
            except ConvertError:
                print(
                    f"warning: skipping mailing list {pv_string(p.get('name'))!r} "
                    f"(cannot resolve its domain)",
                    file=sys.stderr,
                )
                continue
            body: dict[str, Any] = {
                "name": local,
                "domainId": "#" + dom_cid,
                "aliases": self._build_aliases(p, local, dom_cid),
                "recipients": self._build_recipients(p),
            }
            desc = pv_string(p.get("description"))
            if desc:
                body["description"] = desc
            tname = pv_string(p.get("tenant"))
            if tname and tname in self.tenant_name_to_cid:
                body["memberTenantId"] = "#" + self.tenant_name_to_cid[tname]
            out[self._next_create_cid()] = body
        return out

    def _build_recipients(self, p: dict[str, Any]) -> dict[str, bool]:
        out: dict[str, bool] = {}
        for ref in pv_list(p.get("members")):
            target = self._resolve_principal_ref(ref)
            if target is None:
                continue
            if target.get("type") not in ("individual", "group"):
                continue
            try:
                local, dom_cid = self._resolve_name_and_domain(target)
            except ConvertError:
                continue
            dname = self.domain_cid_to_name.get(dom_cid)
            if dname is None:
                continue
            out[f"{local}@{dname}"] = True

        for addr in pv_list(p.get("externalMembers")):
            if isinstance(addr, str) and "@" in addr:
                out[addr] = True
        return out

    def _build_dkim_signatures(self) -> dict[str, dict[str, Any]]:
        sigs = build_sub_trees(self.settings, "signature", "algorithm")
        ids = sorted(sigs.keys())
        out: dict[str, dict[str, Any]] = {}
        for sid in ids:
            sub = sigs[sid]
            algo = sub.get("algorithm", "").strip().lower()
            if algo == "rsa-sha1":
                continue
            if algo == "ed25519-sha256":
                tag = "Dkim1Ed25519Sha256"
            elif algo == "rsa-sha256":
                tag = "Dkim1RsaSha256"
            else:
                print(f"warning: skipping DKIM signature {sid!r}: "
                      f"unknown algorithm {algo!r}", file=sys.stderr)
                continue
            selector = sub.get("selector", "").strip()
            if not selector:
                print(f"warning: skipping DKIM signature {sid!r}: no selector",
                      file=sys.stderr)
                continue
            domain = sub.get("domain", "").strip().lower()
            if domain not in self.domain_name_to_cid:
                print(f"warning: skipping DKIM signature {sid!r}: "
                      f"unknown domain {domain!r}", file=sys.stderr)
                continue
            dom_cid = self.domain_name_to_cid[domain]
            canon = sub.get("canonicalization", "relaxed/relaxed").strip().lower()
            if not canon:
                canon = "relaxed/relaxed"
            private_key, key_errors = resolve_macros(
                sub.get("private-key"), self.settings
            )
            if private_key is not None:
                private_key = private_key.strip()
            if key_errors:
                print(
                    f"warning: skipping DKIM signature {sid!r}: could not "
                    f"resolve private-key: {'; '.join(key_errors)}",
                    file=sys.stderr,
                )
                continue
            if not private_key or "%{" in private_key:
                print(
                    f"warning: skipping DKIM signature {sid!r}: private-key is "
                    f"empty or still contains an unresolved macro",
                    file=sys.stderr,
                )
                continue
            body: dict[str, Any] = {
                "@type": tag,
                "canonicalization": canon,
                "domainId": "#" + dom_cid,
                "privateKey": secret_text(private_key),
                "selector": selector,
            }
            t_cid = self.domain_cid_to_tenant_cid.get(dom_cid)
            if t_cid is not None:
                body["memberTenantId"] = "#" + t_cid
            out[self._next_create_cid()] = body
        return out

    def _stores(self) -> dict[str, dict[str, str]]:
        return build_sub_trees(self.settings, "store", "type")

    def _referenced_store_id(self, key: str) -> str | None:
        v = self.settings.get(key)
        if v is None:
            return None
        v = v.strip()
        return v or None

    def _build_data_store(self) -> dict[str, Any] | None:
        sid = self._referenced_store_id("storage.data")
        if sid is None:
            return None
        stores = self._stores()
        if sid not in stores:
            raise ConvertError(
                f"storage.data = {sid!r} but no store.{sid}.type is defined"
            )
        sub = stores[sid]
        stype = sub.get("type", "").strip().lower()
        if stype == "rocksdb":
            return self._build_rocksdb(sub)
        if stype == "sqlite":
            return self._build_sqlite(sub)
        if stype == "foundationdb":
            return self._build_foundationdb(sub)
        if stype == "postgresql":
            return self._build_postgresql(sub)
        if stype == "mysql":
            return self._build_mysql(sub)
        raise ConvertError(
            f"storage.data points at store {sid!r} of unsupported type {stype!r} "
            f"(DataStore requires rocksdb/sqlite/foundationdb/postgresql/mysql)"
        )

    def _is_same_kv_store_as_data(self, sub: dict[str, str]) -> bool:
        data_sid = self._referenced_store_id("storage.data")
        if data_sid is None:
            return False
        data_sub = self._stores().get(data_sid)
        if data_sub is None:
            return False
        if data_sub.get("type", "").strip().lower() != sub.get("type", "").strip().lower():
            return False
        data_path = data_sub.get("path", "").strip()
        sub_path = sub.get("path", "").strip()
        return bool(data_path) and data_path == sub_path

    def _build_blob_store(self) -> dict[str, Any] | None:
        sid = self._referenced_store_id("storage.blob")
        if sid is None:
            return {"@type": "Default"}
        data_sid = self._referenced_store_id("storage.data")
        if sid == data_sid:
            return {"@type": "Default"}
        stores = self._stores()
        if sid not in stores:
            raise ConvertError(
                f"storage.blob = {sid!r} but no store.{sid}.type is defined"
            )
        sub = stores[sid]
        stype = sub.get("type", "").strip().lower()
        if stype == "s3":
            return self._build_s3(sub)
        if stype == "azure":
            return self._build_azure(sub)
        if stype == "fs":
            return self._build_fs(sub)
        if stype == "foundationdb":
            return self._build_foundationdb(sub, for_blob=True)
        if stype == "postgresql":
            return self._build_postgresql(sub, for_blob=True)
        if stype == "mysql":
            return self._build_mysql(sub, for_blob=True)
        if stype in ("rocksdb", "sqlite"):
            if self._is_same_kv_store_as_data(sub):
                return {"@type": "Default"}
            raise ConvertError(
                f"storage.blob points at store {sid!r} of type {stype!r}, "
                f"but v0.16 does not support a separate {stype} blob store. "
                "Consolidate blob data into the data store, or configure a "
                "filesystem/s3/azure/foundationdb/postgresql/mysql blob "
                "store and migrate the blobs before running this script."
            )
        raise ConvertError(
            f"storage.blob points at store {sid!r} of unsupported type "
            f"{stype!r} (BlobStore requires s3/azure/fs/foundationdb/"
            "postgresql/mysql, or rocksdb/sqlite sharing the data store path)"
        )

    def _build_in_memory_store(self) -> dict[str, Any] | None:
        sid = self._referenced_store_id("storage.lookup")
        if sid is None:
            return {"@type": "Default"}
        data_sid = self._referenced_store_id("storage.data")
        if sid == data_sid:
            return {"@type": "Default"}
        stores = self._stores()
        if sid not in stores:
            raise ConvertError(
                f"storage.lookup = {sid!r} but no store.{sid}.type is defined"
            )
        sub = stores[sid]
        stype = sub.get("type", "").strip().lower()
        if stype == "redis":
            redis_type = sub.get("redis-type", "single").strip().lower()
            if redis_type == "cluster":
                return self._build_redis_cluster(sub)
            return self._build_redis_single(sub)
        return {"@type": "Default"}

    def _build_search_store(self) -> dict[str, Any] | None:
        sid = self._referenced_store_id("storage.fts")
        if sid is None:
            return {"@type": "Default"}
        data_sid = self._referenced_store_id("storage.data")
        if sid == data_sid:
            return {"@type": "Default"}
        stores = self._stores()
        if sid not in stores:
            raise ConvertError(
                f"storage.fts = {sid!r} but no store.{sid}.type is defined"
            )
        sub = stores[sid]
        stype = sub.get("type", "").strip().lower()
        if stype == "elasticsearch":
            return self._build_elasticsearch(sub)
        if stype == "meilisearch":
            return self._build_meilisearch(sub)
        if stype == "foundationdb":
            return self._build_foundationdb(sub, for_search=True)
        if stype == "postgresql":
            return self._build_postgresql(sub, for_search=True)
        if stype == "mysql":
            return self._build_mysql(sub, for_search=True)
        if stype in ("rocksdb", "sqlite"):
            if self._is_same_kv_store_as_data(sub):
                return {"@type": "Default"}
            raise ConvertError(
                f"storage.fts points at store {sid!r} of type {stype!r}, "
                f"but v0.16 does not support a separate {stype} search "
                "store. Consolidate the full-text index into the data store, "
                "or configure an elasticsearch/meilisearch/foundationdb/"
                "postgresql/mysql search store before running this script."
            )
        raise ConvertError(
            f"storage.fts points at store {sid!r} of unsupported type "
            f"{stype!r} (SearchStore requires elasticsearch/meilisearch/"
            "foundationdb/postgresql/mysql, or rocksdb/sqlite sharing the "
            "data store path)"
        )

    def _build_history_store(
        self, store_key: str, enable_key: str, role: str
    ) -> dict[str, Any] | None:
        enable = parse_bool(self.settings.get(enable_key))
        sid = self._referenced_store_id(store_key)
        if enable is False:
            return {"@type": "Disabled"}
        if sid is None:
            if enable is True:
                return {"@type": "Default"}
            return None
        data_sid = self._referenced_store_id("storage.data")
        if sid == data_sid:
            return {"@type": "Default"}
        stores = self._stores()
        if sid not in stores:
            raise ConvertError(
                f"{store_key} = {sid!r} but no store.{sid}.type is defined"
            )
        sub = stores[sid]
        stype = sub.get("type", "").strip().lower()
        if stype == "foundationdb":
            return self._build_foundationdb(sub)
        if stype == "postgresql":
            return self._build_postgresql(sub)
        if stype == "mysql":
            return self._build_mysql(sub)
        if stype in ("rocksdb", "sqlite"):
            if self._is_same_kv_store_as_data(sub):
                return {"@type": "Default"}
            raise ConvertError(
                f"{store_key} points at store {sid!r} of type {stype!r}, "
                f"but v0.16 does not support a separate {stype} {role} "
                "store. Point this setting at the data store, or configure "
                "a foundationdb/postgresql/mysql store."
            )
        raise ConvertError(
            f"{store_key} points at store {sid!r} of unsupported type "
            f"{stype!r} ({role} store requires foundationdb/postgresql/"
            "mysql, or rocksdb/sqlite sharing the data store path)"
        )

    def _build_metrics_store(self) -> dict[str, Any] | None:
        return self._build_history_store(
            "metrics.history.store", "metrics.history.enable", "metrics"
        )

    def _build_tracing_store(self) -> dict[str, Any] | None:
        return self._build_history_store(
            "tracing.history.store", "tracing.history.enable", "tracing"
        )

    def _build_rocksdb(self, sub: dict[str, str]) -> dict[str, Any]:
        path = sub.get("path", "").strip()
        if not path:
            raise ConvertError("rocksdb store missing required 'path'")
        body: dict[str, Any] = {"@type": "RocksDb", "path": path}
        bs = parse_size_bytes(sub.get("settings.min-blob-size"))
        if bs is not None:
            body["blobSize"] = bs
        wb = parse_size_bytes(sub.get("settings.write-buffer-size"))
        if wb is not None:
            body["bufferSize"] = wb
        pw = parse_int(sub.get("pool.workers"))
        if pw is not None:
            body["poolWorkers"] = pw
        return body

    def _build_sqlite(self, sub: dict[str, str]) -> dict[str, Any]:
        path = sub.get("path", "").strip()
        if not path:
            raise ConvertError("sqlite store missing required 'path'")
        body: dict[str, Any] = {"@type": "Sqlite", "path": path}
        pmc = parse_int(sub.get("pool.max-connections"))
        if pmc is not None:
            body["poolMaxConnections"] = pmc
        pw = parse_int(sub.get("pool.workers"))
        if pw is not None:
            body["poolWorkers"] = pw
        return body

    def _build_foundationdb(
        self,
        sub: dict[str, str],
        *,
        for_blob: bool = False,
        for_search: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"@type": "FoundationDb"}
        cf = sub.get("cluster-file", "").strip()
        if cf:
            body["clusterFile"] = cf
        dc = sub.get("ids.datacenter", "").strip()
        if dc:
            body["datacenterId"] = dc
        mid = sub.get("ids.machine", "").strip()
        if mid:
            body["machineId"] = mid
        trd = parse_duration_ms(sub.get("transaction.max-retry-delay"))
        if trd is not None:
            body["transactionRetryDelay"] = trd
        trl = parse_int(sub.get("transaction.retry-limit"))
        if trl is not None:
            body["transactionRetryLimit"] = trl
        tt = parse_duration_ms(sub.get("transaction.timeout"))
        if tt is not None:
            body["transactionTimeout"] = tt
        return body

    def _build_sql_common(self, sub: dict[str, str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        host = sub.get("host", "").strip()
        if not host:
            raise ConvertError("SQL store missing required 'host'")
        out["host"] = host
        db = sub.get("database", "").strip()
        if not db:
            raise ConvertError("SQL store missing required 'database'")
        out["database"] = db
        port = parse_int(sub.get("port"))
        if port is not None:
            out["port"] = port
        user = sub.get("user", "").strip()
        if user:
            out["authUsername"] = user
        out["authSecret"] = secret_key_optional(sub.get("password"))
        tls_enable = parse_bool(sub.get("tls.enable"))
        if tls_enable is not None:
            out["useTls"] = tls_enable
        tls_invalid = parse_bool(sub.get("tls.allow-invalid-certs"))
        if tls_invalid is not None:
            out["allowInvalidCerts"] = tls_invalid
        tout = parse_duration_ms(sub.get("timeout"))
        if tout is not None:
            out["timeout"] = tout
        pmc = parse_int(sub.get("pool.max-connections"))
        if pmc is not None:
            out["poolMaxConnections"] = pmc
        return out

    def _build_postgresql(
        self,
        sub: dict[str, str],
        *,
        for_blob: bool = False,
        for_search: bool = False,
    ) -> dict[str, Any]:
        body = {"@type": "PostgreSql"}
        body.update(self._build_sql_common(sub))
        return body

    def _build_mysql(
        self,
        sub: dict[str, str],
        *,
        for_blob: bool = False,
        for_search: bool = False,
    ) -> dict[str, Any]:
        body = {"@type": "MySql"}
        body.update(self._build_sql_common(sub))
        map_ = parse_size_bytes(sub.get("max-allowed-packet"))
        if map_ is not None:
            body["maxAllowedPacket"] = map_
        pmin = parse_int(sub.get("pool.min-connections"))
        if pmin is not None:
            body["poolMinConnections"] = pmin
        return body

    def _build_s3(self, sub: dict[str, str]) -> dict[str, Any]:
        body: dict[str, Any] = {"@type": "S3"}
        bucket = sub.get("bucket", "").strip()
        if not bucket:
            raise ConvertError("s3 store missing required 'bucket'")
        body["bucket"] = bucket
        ak = sub.get("access-key", "").strip()
        if ak:
            body["accessKey"] = ak
        body["secretKey"] = secret_key_optional(sub.get("secret-key"))
        body["securityToken"] = secret_key_optional(sub.get("security-token"))
        profile = sub.get("profile", "").strip()
        if profile:
            body["profile"] = profile
        kp = sub.get("key-prefix", "").strip()
        if kp:
            body["keyPrefix"] = kp
        mr = parse_int(sub.get("max-retries"))
        if mr is not None:
            body["maxRetries"] = mr
        to = parse_duration_ms(sub.get("timeout"))
        if to is not None:
            body["timeout"] = to
        region_raw = sub.get("region", "").strip().lower()
        endpoint = sub.get("endpoint", "").strip()
        if endpoint:
            body["region"] = {
                "@type": "Custom",
                "customEndpoint": endpoint,
                "customRegion": region_raw or "custom",
            }
        elif region_raw in _S3_REGION_MAP:
            body["region"] = {"@type": _S3_REGION_MAP[region_raw]}
        elif region_raw:

            body["region"] = {
                "@type": "Custom",
                "customEndpoint": "",
                "customRegion": region_raw,
            }
        return body

    def _build_azure(self, sub: dict[str, str]) -> dict[str, Any]:
        body: dict[str, Any] = {"@type": "Azure"}
        sa = sub.get("storage-account", "").strip()
        if not sa:
            raise ConvertError("azure store missing required 'storage-account'")
        body["storageAccount"] = sa
        cont = sub.get("container", "").strip()
        if not cont:
            raise ConvertError("azure store missing required 'container'")
        body["container"] = cont
        body["accessKey"] = secret_key_optional(sub.get("azure-access-key"))
        body["sasToken"] = secret_key_optional(sub.get("sas-token"))
        kp = sub.get("key-prefix", "").strip()
        if kp:
            body["keyPrefix"] = kp
        mr = parse_int(sub.get("max-retries"))
        if mr is not None:
            body["maxRetries"] = mr
        to = parse_duration_ms(sub.get("timeout"))
        if to is not None:
            body["timeout"] = to
        return body

    def _build_fs(self, sub: dict[str, str]) -> dict[str, Any]:
        path = sub.get("path", "").strip()
        if not path:
            raise ConvertError("fs store missing required 'path'")
        body: dict[str, Any] = {"@type": "FileSystem", "path": path}
        depth = parse_int(sub.get("depth"))
        if depth is not None:
            body["depth"] = depth
        return body

    def _build_redis_single(self, sub: dict[str, str]) -> dict[str, Any]:
        urls = collect_array(sub, "urls")
        if not urls:
            raise ConvertError("redis store missing required 'urls'")
        body: dict[str, Any] = {"@type": "Redis", "url": urls[0]}
        to = parse_duration_ms(sub.get("timeout"))
        if to is not None:
            body["timeout"] = to
        return body

    def _build_redis_cluster(self, sub: dict[str, str]) -> dict[str, Any]:
        urls = collect_array(sub, "urls")
        if not urls:
            raise ConvertError("redis-cluster store missing required 'urls'")
        body: dict[str, Any] = {
            "@type": "RedisCluster",
            "urls": {u: True for u in urls},
        }
        body["authSecret"] = secret_key_optional(sub.get("password"))
        user = sub.get("user", "").strip()
        if user:
            body["authUsername"] = user
        mr = parse_int(sub.get("retry.total"))
        if mr is not None:
            body["maxRetries"] = mr
        mxw = parse_duration_ms(sub.get("retry.max-wait"))
        if mxw is not None:
            body["maxRetryWait"] = mxw
        mnw = parse_duration_ms(sub.get("retry.min-wait"))
        if mnw is not None:
            body["minRetryWait"] = mnw
        rfr = parse_bool(sub.get("read-from-replicas"))
        if rfr is not None:
            body["readFromReplicas"] = rfr
        pv = sub.get("protocol-version", "").strip().lower()
        if pv in _REDIS_PROTOCOL_MAP:
            body["protocolVersion"] = _REDIS_PROTOCOL_MAP[pv]
        to = parse_duration_ms(sub.get("timeout"))
        if to is not None:
            body["timeout"] = to
        return body

    def _build_http_auth(self, sub: dict[str, str]) -> dict[str, Any]:
        token = sub.get("auth.token", "").strip()
        if token:
            return {"@type": "Bearer", "bearerToken": secret_key(token)}
        username = sub.get("auth.username", "").strip()
        secret = sub.get("auth.secret", "")
        if username:
            return {"@type": "Basic", "username": username,
                    "secret": secret_key(secret)}
        return {"@type": "Unauthenticated"}

    def _build_elasticsearch(self, sub: dict[str, str]) -> dict[str, Any]:
        url = sub.get("url", "").strip()
        if not url:
            raise ConvertError("elasticsearch store missing required 'url'")
        body: dict[str, Any] = {
            "@type": "ElasticSearch",
            "url": url,
            "httpAuth": self._build_http_auth(sub),
        }
        aic = parse_bool(sub.get("tls.allow-invalid-certs"))
        if aic is not None:
            body["allowInvalidCerts"] = aic
        nr = parse_int(sub.get("index.replicas"))
        if nr is not None:
            body["numReplicas"] = nr
        ns = parse_int(sub.get("index.shards"))
        if ns is not None:
            body["numShards"] = ns
        return body

    def _build_meilisearch(self, sub: dict[str, str]) -> dict[str, Any]:
        url = sub.get("url", "").strip()
        if not url:
            raise ConvertError("meilisearch store missing required 'url'")
        body: dict[str, Any] = {
            "@type": "Meilisearch",
            "url": url,
            "httpAuth": self._build_http_auth(sub),
        }
        aic = parse_bool(sub.get("tls.allow-invalid-certs"))
        if aic is not None:
            body["allowInvalidCerts"] = aic
        pi = parse_duration_ms(sub.get("task.poll-interval"))
        if pi is not None:
            body["pollInterval"] = pi
        return body

    def _build_enterprise(self) -> dict[str, Any] | None:
        lk = self.settings.get("enterprise.license-key", "").strip()
        ak = self.settings.get("enterprise.api-key", "").strip()
        lu = self.settings.get("enterprise.logo-url", "").strip()
        if not (lk or ak or lu):
            return None
        body: dict[str, Any] = {
            "licenseKey": secret_key_optional(lk),
            "apiKey": secret_key_optional(ak),
        }
        if lu:
            body["logoUrl"] = lu
        return body

    def _build_system_settings(self) -> dict[str, Any] | None:
        if self.default_domain_cid is None:
            return None
        hostname = self.settings.get("server.hostname", "").strip()
        body: dict[str, Any] = {
            "defaultDomainId": "#" + self.default_domain_cid,
            "defaultHostname": hostname,
        }
        return body

    def _build_certificates(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}

        for sid, sub in sorted(
            build_sub_trees(self.settings, "certificate", "cert").items()
        ):
            cert, cert_errors = resolve_macros(
                sub.get("cert", ""), self.settings
            )
            key, key_errors = resolve_macros(
                sub.get("private-key", ""), self.settings
            )
            cert = (cert or "").strip()
            key = (key or "").strip()
            if cert_errors or key_errors:
                print(
                    f"warning: skipping certificate.{sid}: could not resolve "
                    f"value: {'; '.join(cert_errors + key_errors)}",
                    file=sys.stderr,
                )
                continue
            if not cert or not key:
                print(
                    f"warning: skipping certificate.{sid}: "
                    "missing cert or private-key",
                    file=sys.stderr,
                )
                continue
            if "-----BEGIN " not in cert or "-----BEGIN " not in key:
                print(
                    f"warning: skipping certificate.{sid}: value is not PEM "
                    "(likely a file or env placeholder)",
                    file=sys.stderr,
                )
                continue
            out[self._next_create_cid()] = _make_certificate_object(cert, key)

        for sid, sub in sorted(
            build_sub_trees(self.settings, "acme", "cert").items()
        ):
            blob_b64 = sub.get("cert", "").strip()
            if not blob_b64:
                continue
            padded = blob_b64 + "=" * (-len(blob_b64) % 4)
            blob = None
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    blob = decoder(padded).decode("latin-1")
                    break
                except Exception as exc:
                    last_err = exc
            if blob is None:
                print(
                    f"warning: skipping acme.{sid}: base64 decode failed: {last_err}",
                    file=sys.stderr,
                )
                continue
            cert_pem, key_pem = split_pem_bundle(blob)
            if not cert_pem or not key_pem:
                print(
                    f"warning: skipping acme.{sid}: decoded bundle lacks "
                    "cert or private key",
                    file=sys.stderr,
                )
                continue
            out[self._next_create_cid()] = _make_certificate_object(
                cert_pem, key_pem
            )

        return out

    def _check_duplicate_emails(
        self,
        accounts: dict[str, dict[str, Any]],
        mailing_lists: dict[str, dict[str, Any]],
    ) -> None:
        owners: dict[tuple[str, str], str] = {}

        def claim(local: str, domain_ref: str, owner: str) -> None:
            d_cid = domain_ref[1:] if domain_ref.startswith("#") else domain_ref
            key = (local, d_cid)
            if key in owners:
                dname = self.domain_cid_to_name.get(d_cid, d_cid)
                raise ConvertError(
                    f"duplicate email address {local}@{dname!s} — "
                    f"claimed by both {owners[key]} and {owner}"
                )
            owners[key] = owner

        for cid, obj in accounts.items():
            kind = obj.get("@type", "Account")
            claim(obj["name"], obj["domainId"], f"{kind} {cid} ({obj['name']})")
            for alias in obj.get("aliases", {}).values():
                claim(alias["name"], alias["domainId"],
                      f"alias of {kind} {cid} ({obj['name']})")

        for cid, obj in mailing_lists.items():
            claim(obj["name"], obj["domainId"],
                  f"MailingList {cid} ({obj['name']})")
            for alias in obj.get("aliases", {}).values():
                claim(alias["name"], alias["domainId"],
                      f"alias of MailingList {cid} ({obj['name']})")

    def _validate_records(
        self,
        domains: dict[str, dict[str, Any]],
        accounts: dict[str, dict[str, Any]],
        mailing_lists: dict[str, dict[str, Any]],
        dkim_signatures: dict[str, dict[str, Any]],
    ) -> None:
        bad_domain_cids: set[str] = set()
        rejected_domains = 0
        for cid in list(domains.keys()):
            name = domains[cid].get("name", "")
            if not is_valid_domain_name(name):
                print(
                    f"warning: dropping domain {name!r}: not a valid v0.16 hostname "
                    f"(must have at least two labels, valid characters)",
                    file=sys.stderr,
                )
                bad_domain_cids.add(cid)
                rejected_domains += 1
                del domains[cid]

        renamed_accounts = 0
        dropped_accounts: list[str] = []
        for cid in list(accounts.keys()):
            obj = accounts[cid]
            name = obj.get("name", "")
            kind = obj.get("@type", "Account")
            domain_ref = obj.get("domainId", "")
            d_cid = domain_ref[1:] if domain_ref.startswith("#") else domain_ref
            if d_cid in bad_domain_cids:
                print(
                    f"warning: dropping {kind} {name!r}: its domain was rejected",
                    file=sys.stderr,
                )
                dropped_accounts.append(cid)
                del accounts[cid]
                continue
            if "@" in name:
                trimmed = name.replace("@", "").strip()
                if trimmed and is_valid_local_part(trimmed):
                    print(
                        f"warning: renaming {kind} {name!r} to {trimmed!r} "
                        f"(local-part must not contain '@')",
                        file=sys.stderr,
                    )
                    obj["name"] = trimmed
                    renamed_accounts += 1
                else:
                    print(
                        f"warning: dropping {kind} {name!r}: invalid local-part, "
                        f"rename in v0.15 before retrying",
                        file=sys.stderr,
                    )
                    dropped_accounts.append(cid)
                    del accounts[cid]
                    continue
            new_aliases: dict[str, dict[str, Any]] = {}
            for idx, alias in obj.get("aliases", {}).items():
                a_dom = alias.get("domainId", "")
                a_dcid = a_dom[1:] if a_dom.startswith("#") else a_dom
                if a_dcid in bad_domain_cids:
                    print(
                        f"warning: dropping alias of {kind} {name!r}: domain rejected",
                        file=sys.stderr,
                    )
                    continue
                if "@" in alias.get("name", ""):
                    print(
                        f"warning: dropping alias {alias.get('name')!r} of "
                        f"{kind} {name!r}: invalid local-part",
                        file=sys.stderr,
                    )
                    continue
                new_aliases[idx] = alias
            obj["aliases"] = new_aliases

        for cid in list(mailing_lists.keys()):
            obj = mailing_lists[cid]
            domain_ref = obj.get("domainId", "")
            d_cid = domain_ref[1:] if domain_ref.startswith("#") else domain_ref
            if d_cid in bad_domain_cids:
                print(
                    f"warning: dropping MailingList {obj.get('name')!r}: domain rejected",
                    file=sys.stderr,
                )
                del mailing_lists[cid]

        dropped_dkim = 0
        for cid in list(dkim_signatures.keys()):
            obj = dkim_signatures[cid]
            domain_ref = obj.get("domainId", "")
            d_cid = domain_ref[1:] if domain_ref.startswith("#") else domain_ref
            if d_cid and d_cid in bad_domain_cids:
                print(
                    f"warning: dropping DkimSignature for rejected domain",
                    file=sys.stderr,
                )
                del dkim_signatures[cid]
                dropped_dkim += 1

        if rejected_domains or renamed_accounts or dropped_accounts or dropped_dkim:
            print(
                f"validation summary: {rejected_domains} domain(s) rejected, "
                f"{renamed_accounts} account(s) renamed, "
                f"{len(dropped_accounts)} account(s) dropped, "
                f"{dropped_dkim} DKIM signature(s) dropped",
                file=sys.stderr,
            )
            print(
                "review the warnings above; fix them in the source v0.15 deployment "
                "and rerun if any of the rejections are unintentional.",
                file=sys.stderr,
            )

SINGLETON_ORDER = [
    "SystemSettings",
    "Enterprise",
    "BlobStore",
    "InMemoryStore",
    "SearchStore",
    "MetricsStore",
    "TracingStore",
]

COLLECTION_ORDER = [
    "Tenant",
    "Domain",
    "Account",
    "MailingList",
    "DkimSignature",
    "Certificate",
]

def build_export_ops(result: dict[str, Any]) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    for name in COLLECTION_ORDER:
        if name not in result:
            continue
        records: dict[str, dict[str, Any]] = result[name]
        if not records:
            continue
        if name == "Account":
            groups = {c: r for c, r in records.items() if r.get("@type") == "Group"}
            users = {c: r for c, r in records.items() if r.get("@type") == "User"}
            if groups:
                ops.append({"@type": "create", "object": name, "value": groups})
            if users:
                ops.append({"@type": "create", "object": name, "value": users})
        else:
            ops.append({"@type": "create", "object": name, "value": records})
    for name in SINGLETON_ORDER:
        if name in result:
            ops.append({
                "@type": "update",
                "object": name,
                "value": result[name],
            })
    return ops

def cmd_convert(args: argparse.Namespace) -> int:
    with open(args.settings, "r", encoding="utf-8") as f:
        settings = json.load(f)
    if not isinstance(settings, dict):
        print(f"error: {args.settings} is not a JSON object", file=sys.stderr)
        return 2
    settings = {str(k): ("" if v is None else str(v)) for k, v in settings.items()}

    with open(args.principals, "r", encoding="utf-8") as f:
        principals = json.load(f)
    if not isinstance(principals, list):
        print(f"error: {args.principals} is not a JSON array", file=sys.stderr)
        return 2

    conv = Converter(principals, settings)
    result = conv.run()

    data_store = result.pop("DataStore", None)
    if data_store is None:
        raise ConvertError(
            "DataStore could not be built (storage.data missing or invalid)"
        )

    patches: list[tuple[str, str]] = list(args.patch_paths or [])
    if not patches and not args.keep_paths:
        legacy = detect_legacy_paths(settings, "/opt/stalwart")
        if legacy:
            print(
                f"notice: detected legacy Docker paths under /opt/stalwart in "
                f"{legacy} settings.\n"
                f"        the v0.16 Docker image mounts persistent data at "
                f"/var/lib/stalwart.\n"
                f"        rerun with --patch-paths /opt/stalwart=/var/lib/stalwart "
                f"to rewrite,\n"
                f"        or pass --keep-paths to suppress this notice "
                f"(e.g. for binary deployments).",
                file=sys.stderr,
            )

    if patches:
        data_store, n_cfg = apply_path_patches(data_store, patches)
        print(f"  patched {n_cfg} path(s) in {args.config}", file=sys.stderr)

    with open(args.config, "w", encoding="utf-8") as f:
        json.dump(data_store, f, indent=2, ensure_ascii=False)
    print(f"wrote {args.config} (DataStore: @type={data_store.get('@type')!r})",
          file=sys.stderr)

    ops = build_export_ops(result)
    if patches:
        ops, n_ops = apply_path_patches(ops, patches)
        print(f"  patched {n_ops} path(s) in {args.output}", file=sys.stderr)
    with open(args.output, "w", encoding="utf-8") as f:
        for op in ops:
            f.write(json.dumps(op, ensure_ascii=False))
            f.write("\n")
    print(f"wrote {args.output} ({len(ops)} ops, NDJSON)", file=sys.stderr)
    for op in ops:
        kind = op["@type"]
        name = op["object"]
        if kind == "update":
            print(f"  update {name}", file=sys.stderr)
        else:
            print(f"  create {name}: {len(op['value'])} records",
                  file=sys.stderr)

    if args.unmigrated_output:
        unmigrated = compute_unmigrated_keys(settings)
        if unmigrated:
            write_unmigrated_summary(unmigrated, args.unmigrated_output)
            print(
                f"wrote {args.unmigrated_output} ({len(unmigrated)} v0.15 "
                f"settings keys not migrated; review and recreate manually)",
                file=sys.stderr,
            )
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Dump / migrate a Stalwart server via its management API.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("dump", help="Dump settings and principals to JSON files.")
    d.add_argument("--url", required=True,
                   help="Base URL of the Stalwart server, e.g. https://mail.example.com")
    d.add_argument("--token", help="Bearer token.")
    d.add_argument("--username", help="Admin username for HTTP Basic auth.")
    d.add_argument("--password", help="Admin password for HTTP Basic auth.")
    d.add_argument("--settings", default="settings.json",
                   help="Output file for settings (default: settings.json).")
    d.add_argument("--principals", default="principals.json",
                   help="Output file for principals (default: principals.json).")
    d.set_defaults(func=cmd_dump)

    c = sub.add_parser("convert",
                       help="Convert dumped JSON into the new JMAP-object format.")
    c.add_argument("--settings", default="settings.json",
                   help="Input settings JSON (default: settings.json).")
    c.add_argument("--principals", default="principals.json",
                   help="Input principals JSON (default: principals.json).")
    c.add_argument("--config", default="config.json",
                   help="Output file for the DataStore object "
                        "(default: config.json).")
    c.add_argument("--output", default="export.json",
                   help="Output NDJSON file with one operation per line "
                        "(default: export.json).")
    c.add_argument("--patch-paths", action="append", type=parse_path_patch,
                   metavar="SOURCE=DEST",
                   help="Rewrite paths beginning with SOURCE to DEST in both "
                        "config.json and export.json. May be passed multiple "
                        "times. Use to migrate Docker deployments from "
                        "/opt/stalwart to /var/lib/stalwart.")
    c.add_argument("--keep-paths", action="store_true",
                   help="Suppress the legacy-path detection notice. Use when "
                        "the on-disk paths in the v0.15 deployment are also "
                        "valid for the v0.16 deployment (typical for binary "
                        "installs).")
    c.add_argument("--unmigrated-output", default="unmigrated.txt",
                   help="Output file listing v0.15 setting prefixes that the "
                        "script did not migrate (default: unmigrated.txt). "
                        "Pass an empty string to skip writing this file.")
    c.set_defaults(func=cmd_convert)

    return p

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ApiError, ConvertError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

if __name__ == "__main__":
    sys.exit(main())
