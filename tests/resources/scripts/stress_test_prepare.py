import argparse
import base64
import json
import random
import ssl
import string
import urllib.error
import urllib.request

CORE = "urn:ietf:params:jmap:core"
STALWART = "urn:stalwart:jmap"
USING = [CORE, STALWART]

DEFAULT_BASE_URL = "https://127.0.0.1"
DEFAULT_NUM_USERS = 1000
DEFAULT_OUTPUT = "users.txt"
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_PREFIX = "test"

CREATE_RETRIES = 5


class AccountError(Exception):
    pass


def generate_password(length):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def primary_account(session):
    accounts = session.get("primaryAccounts") or {}
    if "urn:ietf:params:jmap:mail" in accounts:
        return accounts["urn:ietf:params:jmap:mail"]
    all_accounts = session.get("accounts") or {}
    return next(iter(all_accounts), None)


def build_opener(verify):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    handler = urllib.request.HTTPSHandler(context=context)
    return urllib.request.build_opener(handler)


class JmapClient:
    def __init__(self, base_url, auth_header, verify):
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.opener = build_opener(verify)
        self.api_url = None
        self.account_id = None
        self._discover()

    def _http(self, url, method, body=None):
        headers = {"Authorization": self.auth_header}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except urllib.error.URLError as e:
            raise SystemExit(f"Request to {url} failed: {e.reason}")

    def _discover(self):
        if "/.well-known/jmap" in self.base_url:
            candidates = [self.base_url]
        else:
            candidates = [self.base_url, f"{self.base_url}/.well-known/jmap"]
        last = ""
        for url in candidates:
            status, text = self._http(url, "GET")
            if status == 200:
                try:
                    data = json.loads(text)
                except ValueError:
                    last = f"{url}: invalid JSON"
                    continue
                if data.get("apiUrl") and data.get("accounts"):
                    self.api_url = data["apiUrl"]
                    self.account_id = primary_account(data)
                    if not self.account_id:
                        raise SystemExit(f"JMAP session at {url} has no accounts.")
                    return
            last = f"{url}: status {status}"
        raise SystemExit(f"Could not discover JMAP session ({last}).")

    def request(self, method_calls):
        body = {"using": USING, "methodCalls": method_calls}
        status, text = self._http(self.api_url, "POST", body)
        if status != 200:
            raise SystemExit(f"JMAP request failed: status {status}: {text}")
        return json.loads(text)

    def call(self, method, args):
        args = dict(args)
        args["accountId"] = self.account_id
        parsed = self.request([[method, args, "c0"]])
        responses = parsed.get("methodResponses") or []
        if not responses:
            raise SystemExit(f"{method}: empty methodResponses")
        name, payload = responses[0][0], responses[0][1]
        if name == "error":
            raise SystemExit(f"{method} error: {payload}")
        return payload

    def domain_id(self, name):
        calls = [
            [
                "x:Domain/query",
                {"accountId": self.account_id, "filter": {"name": name}},
                "q",
            ],
            [
                "x:Domain/get",
                {
                    "accountId": self.account_id,
                    "#ids": {
                        "resultOf": "q",
                        "name": "x:Domain/query",
                        "path": "/ids",
                    },
                    "properties": ["id", "name"],
                },
                "g",
            ],
        ]
        parsed = self.request(calls)
        responses = parsed.get("methodResponses") or []
        if len(responses) < 2:
            raise SystemExit(f"Domain lookup failed: {parsed}")
        get = responses[1][1]
        for entry in get.get("list") or []:
            if entry.get("name") == name:
                return entry.get("id")
        return None

    def create_account(self, localpart, domain_id, password):
        create = {
            "a": {
                "@type": "User",
                "name": localpart,
                "domainId": domain_id,
                "credentials": {"0": {"@type": "Password", "secret": password}},
                "encryptionAtRest": {"@type": "Disabled"},
                "permissions": {"@type": "Inherit"},
                "roles": {"@type": "User"},
                "locale": "en_US",
            }
        }
        response = self.call("x:Account/set", {"create": create})
        not_created = response.get("notCreated") or {}
        if not_created:
            raise AccountError(f"{not_created.get('a', not_created)}")
        created = (response.get("created") or {}).get("a") or {}
        return created.get("id")

    def invalidate_caches(self):
        self.call(
            "x:Action/set",
            {"create": {"c": {"@type": "InvalidateCaches"}}},
        )


def build_auth_header(args):
    if args.token:
        return f"Bearer {args.token}"
    raw = f"{args.user}:{args.password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Provision test accounts for the stress test using the JMAP API."
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument(
        "--domain",
        required=True,
        help="Existing domain name; resolved to a domain id via JMAP.",
    )
    parser.add_argument("--token", help="OAuth bearer token for the JMAP API.")
    parser.add_argument("--user", help="Basic auth username for the JMAP API.")
    parser.add_argument("--password", help="Basic auth password for the JMAP API.")
    parser.add_argument("--num-users", type=int, default=DEFAULT_NUM_USERS)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--password-length", type=int, default=DEFAULT_PASSWORD_LENGTH)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify TLS certificates (disabled by default for self-signed servers).",
    )
    args = parser.parse_args()
    if not args.token and not (args.user and args.password):
        parser.error("provide either --token or both --user and --password")
    return args


def main():
    args = parse_args()
    client = JmapClient(args.base_url, build_auth_header(args), args.verify)
    domain_id = client.domain_id(args.domain)
    if not domain_id:
        raise SystemExit(f"Domain '{args.domain}' not found via JMAP.")

    created = 0
    failed = 0
    with open(args.output, "w") as file:
        for i in range(1, args.num_users + 1):
            localpart = f"{args.prefix}{i}"
            email = f"{localpart}@{args.domain}"
            password = None
            last_error = None
            for _ in range(CREATE_RETRIES):
                password = generate_password(args.password_length)
                try:
                    client.create_account(localpart, domain_id, password)
                    last_error = None
                    break
                except AccountError as e:
                    last_error = e
            if last_error is not None:
                failed += 1
                print(f"FAIL {email}: {last_error}")
                continue
            file.write(f"{email}:{password}\n")
            file.flush()
            created += 1
            print(f"OK   {email}")

    client.invalidate_caches()
    print(f"\nCreated {created} accounts ({failed} failed). Written to {args.output}.")


if __name__ == "__main__":
    main()
