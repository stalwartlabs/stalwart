# Stalwart – Test Infrastructure

Ephemeral Docker Compose stack for testing Stalwart against external services.
All data is lost on `docker compose down` – every restart is a clean slate.

## Quick Start

```bash
cd stalwart-test
docker compose up -d
```

Wait ~30 seconds for all services to initialize (Keycloak takes the longest).

## Connection Reference

| Service        | Host              | Port(s)         | Credentials / Notes                        |
|----------------|-------------------|-----------------|--------------------------------------------|
| PostgreSQL     | localhost         | 5432            | `stalwart` / `stalwart`, db: `stalwart`    |
| MySQL          | localhost         | 3306            | `stalwart` / `stalwart`, db: `stalwart`    |
| FoundationDB   | localhost         | 4500            | Cluster file from container                |
| Redis          | localhost         | 6379            | No auth                                    |
| OpenSearch     | localhost         | 9200            | No auth, security plugin disabled          |
| Meilisearch    | localhost         | 7700            | Master key: `stalwart-master-key`          |
| MinIO (S3)     | localhost         | 9000 / 9001     | `minioadmin` / `minioadmin`, bucket: `stalwart` |
| Keycloak (OIDC)| localhost         | 9080            | Admin: `admin` / `admin`                   |
| OpenLDAP       | localhost         | 389 / 636 (TLS) | Admin DN: `cn=admin,dc=stalwart,dc=test`, pw: `admin` |
| Pebble (ACME)  | localhost         | 14000 / 15000   | Self-signed TLS, uses challtestsrv         |
| Challtestsrv   | localhost         | 8055            | ACME challenge test server (management API)|
| PowerDNS       | localhost         | 5300 / 8081     | API key: `stalwart-api-key`                |
| NATS           | localhost         | 4222 / 8222     | No auth                                    |

## OIDC (Keycloak) Details

- **OIDC Discovery**: `http://localhost:9080/realms/stalwart/.well-known/openid-configuration`
- **Token Endpoint**: `http://localhost:9080/realms/stalwart/protocol/openid-connect/token`
- **Client ID**: `stalwart`
- **Client Secret**: `stalwart-secret`
- **Realm**: `stalwart`

### Test Users

| Username                  | Password                 | Groups                                 |
|---------------------------|--------------------------|----------------------------------------|
| john.doe@example.org      | this is an OIDC password | sales@example.org                      |
| jane.smith@example.org    | this is an OIDC password | sales@example.org, corporate@example.org |
| bill.foobar@example.org   | this is an OIDC password | corporate@example.org                  |

### Example: Get a Token

```bash
curl -X POST http://localhost:9080/realms/stalwart/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=stalwart" \
  -d "client_secret=stalwart-secret" \
  -d "username=john.doe@example.org" \
  -d "password=this is an OIDC password"
```

## LDAP Details

- **Base DN**: `dc=stalwart,dc=test`
- **Admin DN**: `cn=admin,dc=stalwart,dc=test`
- **Admin Password**: `admin`
- **Read-only DN**: `cn=readonly,dc=stalwart,dc=test`
- **Read-only Password**: `readonly`
- **User DN pattern**: `uid={username},ou=users,dc=stalwart,dc=test`

### Test Users

| DN                                             | Mail                     | Password                 |
|------------------------------------------------|--------------------------|--------------------------|
| uid=john.doe,ou=users,dc=stalwart,dc=test      | john.doe@example.org     | this is an LDAP password |
| uid=jane.smith,ou=users,dc=stalwart,dc=test     | jane.smith@example.org   | this is an LDAP password |
| uid=bill.foobar,ou=users,dc=stalwart,dc=test    | bill.foobar@example.org  | this is an LDAP password |

### Groups

| DN                                          | Mail                    | Members          |
|---------------------------------------------|-------------------------|------------------|
| cn=sales,ou=groups,dc=stalwart,dc=test      | sales@example.org       | john.doe, jane.smith |
| cn=corporate,ou=groups,dc=stalwart,dc=test  | corporate@example.org   | bill.foobar, jane.smith |

### Example: Search by Email

```bash
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=stalwart,dc=test" -w admin \
  -b "dc=stalwart,dc=test" "(mail=john.doe@example.org)"
```

## S3 (MinIO) Details

- **Endpoint**: `http://localhost:9000`
- **Access Key**: `minioadmin`
- **Secret Key**: `minioadmin`
- **Bucket**: `stalwart`
- **Console**: `http://localhost:9001`
- **Region**: `us-east-1` (MinIO default)

## DNS (PowerDNS) Details

- **DNS port**: 5300 (TCP+UDP)
- **API**: `http://localhost:8081` (API key: `stalwart-api-key`)
- **Zone**: `stalwart.test`
- **TSIG key name**: `stalwart-update-key`
- **TSIG algorithm**: `hmac-sha256`
- **TSIG secret (base64)**: `c3RhbHdhcnQtdGVzdC10c2lnLXNlY3JldC1rZXkxMjM0NTY3ODkw`

> **Note on SIG(0):** PowerDNS does not support SIG(0) authentication for RFC2136
> updates. Only BIND has (limited) SIG(0) support. If you need to test SIG(0),
> a separate BIND instance would be required.

### Example: Query TLSA Record

```bash
dig @localhost -p 5300 _25._tcp.mail.stalwart.test TLSA
```

### Example: RFC2136 Dynamic Update

```bash
nsupdate -y hmac-sha256:stalwart-update-key:c3RhbHdhcnQtdGVzdC10c2lnLXNlY3JldC1rZXkxMjM0NTY3ODkw <<EOF
server 127.0.0.1 5300
zone stalwart.test
update add test.stalwart.test 300 A 192.168.1.100
send
EOF
```

## ACME (Pebble + Challenge Test Server) Details

- **Directory URL**: `https://localhost:14000/dir`
- **Pebble Management URL**: `https://localhost:15000`
- **Challenge Test Server API**: `http://localhost:8055`
- **TLS**: Self-signed — Stalwart must trust the Pebble CA or skip TLS verification
- Pebble uses the challenge test server (`pebble-challtestsrv`) as its DNS resolver,
  so challenge validation goes through controllable DNS/HTTP/TLS-ALPN responders.

### Challenge Test Server (challtestsrv)

The challenge test server provides a management API on port 8055 to programmatically
control DNS records and challenge responses used during ACME validation.

**Default behavior**: All A/AAAA queries resolve to `host.docker.internal` (the Docker
host), so Pebble can reach your test server on localhost automatically. Tests only need
to add challenge-specific records (TXT for DNS-01, HTTP tokens, etc.).

### How Pebble Reaches Your Test Server

When Pebble validates an HTTP-01 or TLS-ALPN-01 challenge, it:

1. Resolves the domain via challtestsrv — by default all domains resolve to the Docker host
2. Connects to the resolved IP on port **5002** (HTTP-01) or **5001** (TLS-ALPN-01)

These ports are configured in `pebble/pebble-config.json` (`httpPort` / `tlsPort`).
Change them to match whatever port your test Stalwart instance listens on.

#### Management API Examples

```bash
# Add a DNS-01 TXT challenge response
curl -s -X POST http://localhost:8055/add-dns \
  -d '{"host": "_acme-challenge.mail.stalwart.test.", "value": "dns-challenge-token"}'

# Remove a DNS-01 TXT challenge response
curl -s -X POST http://localhost:8055/del-dns \
  -d '{"host": "_acme-challenge.mail.stalwart.test."}'

# Add an HTTP-01 challenge response (served by challtestsrv itself)
curl -s -X POST http://localhost:8055/add-http \
  -d '{"token": "challenge-token", "content": "challenge-key-authorization"}'

# Remove an HTTP-01 challenge response
curl -s -X POST http://localhost:8055/del-http \
  -d '{"token": "challenge-token"}'

# Add a TLS-ALPN-01 challenge response (served by challtestsrv itself)
curl -s -X POST http://localhost:8055/add-tlsalpn \
  -d '{"host": "mail.stalwart.test", "content": "base64-encoded-key-authz"}'

# Remove a TLS-ALPN-01 challenge response
curl -s -X POST http://localhost:8055/del-tlsalpn \
  -d '{"host": "mail.stalwart.test"}'

# Clear all mock DNS/challenge data
curl -s -X POST http://localhost:8055/clear-request-count
```

## Self-Signed TLS Certificate

A shared self-signed certificate is generated at startup and mounted into services
that need it. The cert is valid for:
- `localhost`, `keycloak`, `openldap`, `pebble`, `*.stalwart.test`, `127.0.0.1`

To extract the cert for use with Stalwart:

```bash
docker compose cp cert-init:/certs/cert.pem ./test-cert.pem
docker compose cp cert-init:/certs/key.pem ./test-key.pem
```

## Troubleshooting

```bash
# Check all services are running
docker compose ps

# View logs for a specific service
docker compose logs -f keycloak

# Restart everything fresh
docker compose down && docker compose up -d

# Check FoundationDB status
docker compose exec foundationdb fdbcli --exec "status"

# Verify TSIG key is loaded
docker compose exec powerdns pdnsutil list-tsig-keys
```
