/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use testcontainers::{
    ContainerAsync, GenericBuildableImage, GenericImage, ImageExt, ReuseDirective,
    core::{CmdWaitFor, ExecCommand, Host, IntoContainerPort, WaitFor},
    runners::{AsyncBuilder, AsyncRunner},
};
use tokio::{net::TcpStream, sync::OnceCell};

const ACME_NETWORK: &str = "stalwart-test-acme";

const READY_TIMEOUT: Duration = Duration::from_secs(180);

static FOUNDATIONDB: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static POSTGRES: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static MYSQL: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static REDIS: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static NATS: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static MINIO: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static OPENSEARCH: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static MEILISEARCH: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static KEYCLOAK: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static OPENLDAP: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static CHALLTESTSRV: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static PEBBLE: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();
static POWERDNS: OnceCell<ContainerAsync<GenericImage>> = OnceCell::const_new();

const POWERDNS_ZONE_INIT: &str = r#"set -e
for i in $(seq 1 60); do
    pdnsutil list-all-zones >/dev/null 2>&1 && break
    sleep 1
done
if pdnsutil list-zone stalwart.test >/dev/null 2>&1; then
    exit 0
fi
pdnsutil create-zone stalwart.test ns1.stalwart.test
pdnsutil set-kind stalwart.test native
pdnsutil replace-rrset stalwart.test '' SOA 'ns1.stalwart.test. admin.stalwart.test. 2024010101 3600 900 604800 86400'
pdnsutil add-record stalwart.test 'ns1' A '127.0.0.1'
pdnsutil add-record stalwart.test '' A '127.0.0.1'
pdnsutil add-record stalwart.test '' MX '10 mail.stalwart.test.'
pdnsutil add-record stalwart.test 'mail' A '127.0.0.1'
pdnsutil import-tsig-key stalwart-update-key hmac-sha256 'c3RhbHdhcnQtdGVzdC10c2lnLXNlY3JldC1rZXkxMjM0NTY3ODkw'
pdnsutil activate-tsig-key stalwart.test stalwart-update-key primary
pdnsutil set-meta stalwart.test TSIG-ALLOW-DNSUPDATE stalwart-update-key
pdnsutil set-meta stalwart.test ALLOW-DNSUPDATE-FROM '0.0.0.0/0'
"#;

pub async fn ensure_foundationdb() {
    let container = FOUNDATIONDB
        .get_or_init(|| async {
            GenericImage::new("foundationdb/foundationdb", "7.4.6")
                .with_env_var("FDB_NETWORKING_MODE", "container")
                .with_mapped_port(4500, 4500.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-foundationdb")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start FoundationDB container")
        })
        .await;

    let start = Instant::now();
    loop {
        if fdbcli(container, "status minimal")
            .await
            .contains("The database is available")
        {
            return;
        }
        let created = fdbcli(container, "configure new single memory").await;
        if created.contains("Database created") || created.contains("Already exists") {
            continue;
        }
        if start.elapsed() > READY_TIMEOUT {
            panic!("Timed out configuring FoundationDB: {created}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn fdbcli(container: &ContainerAsync<GenericImage>, command: &str) -> String {
    let mut result = container
        .exec(
            ExecCommand::new(["fdbcli", "--exec", command, "--timeout", "5"])
                .with_cmd_ready_condition(CmdWaitFor::exit()),
        )
        .await
        .expect("Failed to exec fdbcli");
    let stdout = result.stdout_to_vec().await.unwrap_or_default();
    let stderr = result.stderr_to_vec().await.unwrap_or_default();
    format!(
        "{}{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    )
}

pub async fn ensure_postgres() {
    POSTGRES
        .get_or_init(|| async {
            GenericImage::new("postgres", "16-alpine")
                .with_wait_for(WaitFor::message_on_stderr(
                    "database system is ready to accept connections",
                ))
                .with_wait_for(WaitFor::message_on_stderr(
                    "database system is ready to accept connections",
                ))
                .with_env_var("POSTGRES_USER", "stalwart")
                .with_env_var("POSTGRES_PASSWORD", "stalwart")
                .with_env_var("POSTGRES_DB", "stalwart")
                .with_mapped_port(5432, 5432.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-postgres")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start PostgreSQL container")
        })
        .await;
    wait_for_tcp(5432).await;
}

pub async fn ensure_mysql() {
    MYSQL
        .get_or_init(|| async {
            GenericImage::new("mysql", "8.0")
                .with_wait_for(WaitFor::message_on_stderr("port: 3306  MySQL"))
                .with_env_var("MYSQL_ROOT_PASSWORD", "password")
                .with_env_var("MYSQL_DATABASE", "stalwart")
                .with_cmd(["--default-authentication-plugin=mysql_native_password"])
                .with_mapped_port(3307, 3306.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-mysql")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start MySQL container")
        })
        .await;
    wait_for_tcp(3307).await;
}

pub async fn ensure_redis() {
    REDIS
        .get_or_init(|| async {
            GenericImage::new("redis", "7-alpine")
                .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
                .with_cmd(["redis-server", "--save", "", "--appendonly", "no"])
                .with_mapped_port(6379, 6379.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-redis")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start Redis container")
        })
        .await;
    wait_for_tcp(6379).await;
}

pub async fn ensure_nats() {
    NATS.get_or_init(|| async {
        GenericImage::new("nats", "latest")
            .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
            .with_cmd(["--addr", "0.0.0.0", "--port", "4222", "--http_port", "8222"])
            .with_mapped_port(4222, 4222.tcp())
            .with_mapped_port(8222, 8222.tcp())
            .with_startup_timeout(READY_TIMEOUT)
            .with_container_name("stalwart-test-nats")
            .with_reuse(ReuseDirective::Always)
            .start()
            .await
            .expect("Failed to start NATS container")
    })
    .await;
    wait_for_tcp(4222).await;
}

pub async fn ensure_minio() {
    MINIO
        .get_or_init(|| async {
            GenericImage::new("minio/minio", "latest")
                .with_env_var("MINIO_ROOT_USER", "minioadmin")
                .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
                .with_cmd(["server", "/data", "--console-address", ":9001"])
                .with_mapped_port(9000, 9000.tcp())
                .with_mapped_port(9001, 9001.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-minio")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start MinIO container")
        })
        .await;
    wait_for_http("http://localhost:9000/minio/health/live").await;
    create_minio_bucket().await;
}

pub async fn ensure_opensearch() {
    OPENSEARCH
        .get_or_init(|| async {
            GenericImage::new("opensearchproject/opensearch", "2")
                .with_env_var("discovery.type", "single-node")
                .with_env_var("DISABLE_SECURITY_PLUGIN", "true")
                .with_env_var("OPENSEARCH_JAVA_OPTS", "-Xms1g -Xmx1g")
                .with_env_var("DISABLE_INSTALL_DEMO_CONFIG", "true")
                .with_mapped_port(9200, 9200.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-opensearch")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start OpenSearch container")
        })
        .await;
    wait_for_http("http://localhost:9200").await;
}

pub async fn ensure_meilisearch() {
    MEILISEARCH
        .get_or_init(|| async {
            GenericImage::new("getmeili/meilisearch", "latest")
                .with_env_var("MEILI_ENV", "development")
                .with_env_var("MEILI_NO_ANALYTICS", "true")
                .with_env_var("MEILI_MASTER_KEY", "stalwart-master-key")
                .with_mapped_port(7700, 7700.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-meilisearch")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start Meilisearch container")
        })
        .await;
    wait_for_http("http://localhost:7700/health").await;
}

pub async fn ensure_keycloak() {
    KEYCLOAK
        .get_or_init(|| async {
            GenericImage::new("quay.io/keycloak/keycloak", "latest")
                .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
                .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
                .with_env_var("KC_HTTP_PORT", "9080")
                .with_env_var("KC_HEALTH_ENABLED", "true")
                .with_cmd(["start-dev", "--import-realm"])
                .with_copy_to(
                    "/opt/keycloak/data/import/stalwart-realm.json",
                    include_bytes!("../../docker/keycloak/stalwart-realm.json").to_vec(),
                )
                .with_mapped_port(9080, 9080.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-keycloak")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start Keycloak container")
        })
        .await;
    wait_for_http("http://localhost:9080/realms/stalwart/.well-known/openid-configuration").await;
}

pub async fn ensure_acme() {
    ensure_challtestsrv().await;
    ensure_pebble().await;
}

async fn ensure_challtestsrv() {
    CHALLTESTSRV
        .get_or_init(|| async {
            let image = GenericBuildableImage::new("stalwart-test-challtestsrv", "local")
                .with_dockerfile_string(include_str!("../../docker/pebble/Dockerfile.challtestsrv"))
                .build_image()
                .await
                .expect("Failed to build challtestsrv image");
            image
                .with_network(ACME_NETWORK)
                .with_host("host.docker.internal", Host::HostGateway)
                .with_mapped_port(8055, 8055.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-challtestsrv")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start challtestsrv container")
        })
        .await;
    wait_for_tcp(8055).await;
}

async fn ensure_pebble() {
    PEBBLE
        .get_or_init(|| async {
            GenericImage::new("ghcr.io/letsencrypt/pebble", "latest")
                .with_env_var("PEBBLE_VA_NOSLEEP", "1")
                .with_env_var("PEBBLE_WFE_NONCEREJECT", "0")
                .with_env_var("PEBBLE_ALTERNATE_ROOTS", "2")
                .with_cmd([
                    "-config",
                    "/test/config/pebble-config.json",
                    "-dnsserver",
                    "stalwart-test-challtestsrv:8053",
                ])
                .with_copy_to(
                    "/test/config/pebble-config.json",
                    include_bytes!("../../docker/pebble/pebble-config.json").to_vec(),
                )
                .with_network(ACME_NETWORK)
                .with_host("host.docker.internal", Host::HostGateway)
                .with_mapped_port(14000, 14000.tcp())
                .with_mapped_port(15000, 15000.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-pebble")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start Pebble container")
        })
        .await;
    wait_for_tcp(14000).await;
}

pub async fn ensure_powerdns() {
    let container = POWERDNS
        .get_or_init(|| async {
            GenericImage::new("powerdns/pdns-auth-49", "latest")
                .with_wait_for(WaitFor::message_on_stderr("Creating backend connection"))
                .with_env_var("PDNS_AUTH_API_KEY", "stalwart-api-key")
                .with_copy_to(
                    "/etc/powerdns/pdns.d/stalwart.conf",
                    include_bytes!("../../docker/powerdns/pdns.conf").to_vec(),
                )
                .with_mapped_port(5300, 53.tcp())
                .with_mapped_port(5300, 53.udp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-powerdns")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start PowerDNS container")
        })
        .await;

    let mut result = container
        .exec(
            ExecCommand::new(["bash", "-c", POWERDNS_ZONE_INIT])
                .with_cmd_ready_condition(CmdWaitFor::exit()),
        )
        .await
        .expect("Failed to exec PowerDNS zone init");
    if result.exit_code().await.ok().flatten() != Some(0) {
        let stdout =
            String::from_utf8_lossy(&result.stdout_to_vec().await.unwrap_or_default()).into_owned();
        let stderr =
            String::from_utf8_lossy(&result.stderr_to_vec().await.unwrap_or_default()).into_owned();
        panic!("PowerDNS zone init failed:\n{stdout}\n{stderr}");
    }
    wait_for_tcp(5300).await;
}

pub async fn ensure_openldap() {
    const BOOTSTRAP_DIR: &str = "/container/service/slapd/assets/config/bootstrap/ldif/custom";
    OPENLDAP
        .get_or_init(|| async {
            GenericImage::new("osixia/openldap", "1.5.0")
                .with_wait_for(WaitFor::message_on_stderr("slapd starting"))
                .with_env_var("LDAP_ORGANISATION", "Stalwart Test")
                .with_env_var("LDAP_DOMAIN", "stalwart.test")
                .with_env_var("LDAP_BASE_DN", "dc=stalwart,dc=test")
                .with_env_var("LDAP_ADMIN_PASSWORD", "admin")
                .with_env_var("LDAP_TLS", "false")
                .with_copy_to(
                    format!("{BOOTSTRAP_DIR}/50-users.ldif"),
                    include_bytes!("../../docker/ldap/50-users.ldif").to_vec(),
                )
                .with_copy_to(
                    format!("{BOOTSTRAP_DIR}/60-groups.ldif"),
                    include_bytes!("../../docker/ldap/60-groups.ldif").to_vec(),
                )
                .with_mapped_port(389, 389.tcp())
                .with_startup_timeout(READY_TIMEOUT)
                .with_container_name("stalwart-test-openldap")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("Failed to start OpenLDAP container")
        })
        .await;
    wait_for_tcp(389).await;
}

async fn create_minio_bucket() {
    use s3::{Bucket, BucketConfiguration, Region, creds::Credentials};

    let region = Region::Custom {
        region: "eu-central-1".to_string(),
        endpoint: "http://localhost:9000".to_string(),
    };
    let credentials = Credentials::new(Some("minioadmin"), Some("minioadmin"), None, None, None)
        .expect("Failed to build MinIO credentials");

    match Bucket::create_with_path_style(
        "stalwart",
        region,
        credentials,
        BucketConfiguration::default(),
    )
    .await
    {
        Ok(response) if response.success() => {}
        Ok(_) => {}
        Err(s3::error::S3Error::HttpFailWithBody(409, _)) => {}
        Err(err) => panic!("Failed to create MinIO bucket: {err:?}"),
    }
}

async fn wait_for_tcp(port: u16) {
    let start = Instant::now();
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        if start.elapsed() > READY_TIMEOUT {
            panic!("Timed out waiting for TCP port {port}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_http(url: &str) {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to build HTTP client");
    let start = Instant::now();
    loop {
        if let Ok(response) = client.get(url).send().await
            && response.status().is_success()
        {
            return;
        }
        if start.elapsed() > READY_TIMEOUT {
            panic!("Timed out waiting for {url}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
