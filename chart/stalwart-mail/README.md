---
title: "stalwart-mail"

description: "Helm Chart for Stalwart Mail Server - Secure & Modern All-in-One Mail Server (IMAP, JMAP, SMTP)"

---

# stalwart-mail

![Version: 0.4.3](https://img.shields.io/badge/Version-0.4.3-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.14.1](https://img.shields.io/badge/AppVersion-0.14.1-informational?style=flat-square)

Helm Chart for Stalwart Mail Server - Secure & Modern All-in-One Mail Server (IMAP, JMAP, SMTP)

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| WrenIX |  | <https://wrenix.eu> |

## Alpha
{{< callout type="warning" >}}
Current stalwart is not stable and we are also not stable.

We have current known issues:
* cluster setup is not fully supported (so please keep replicas=1), see more in [issue for cluster](https://codeberg.org/wrenix/helm-charts/issues/294)
* toml interpreter of stalwart and golang (helm) are different, so we remove all `.0` in the rendering to be compatible with stalwart-toml
{{< /callout >}}

## Usage

Helm must be installed and setup to your kubernetes cluster to use the charts.
Refer to Helm's [documentation](https://helm.sh/docs) to get started.
Once Helm has been set up correctly, fetch the charts as follows:

```bash
helm pull oci://codeberg.org/wrenix/helm-charts/stalwart-mail
```

You can install a chart release using the following command:

```bash
helm install stalwart-mail-release oci://codeberg.org/wrenix/helm-charts/stalwart-mail --values values.yaml
```

To uninstall a chart release use `helm`'s delete command:

```bash
helm uninstall stalwart-mail-release
```

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://nats-io.github.io/k8s/helm/charts/ | nats | 2.12.2 |

## Values

### Backup

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| backup.enabled | bool | `true` | enable a init of statefulset to create a backup on /data |

### DKIM

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| config.auth.dkim.sign | list | `[{"if":"listener != 'smtp' && is_local_domain('', sender_domain)","then":"['rsa-' + sender_domain, 'ed25519-' + sender_domain]"},{"else":false}]` | auth rule for signing with dkim |
| config.auth.dkim.verify | string | `"relaxed"` | verify of dkim signature (relaxed, strict, disable) |

### Authentification

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| config.authentication.fallback-admin.secret | string | `"%{env:FALLBACK_ADMIN_SECRET}%"` | password for fallback authentfication (use env for store in secrets of kubernetes) |
| config.authentication.fallback-admin.user | string | `"admin"` | username for fallback authentfication |
| secrets.env.FALLBACK_ADMIN_SECRET | string | `"supersecret"` | password for fallback authentfication (env) |

### Cluster

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| config.cluster.node-id | string | `"%{env:POD_INDEX}%"` | configure stalwart to set correct node-id based on statefulset id |
| nats.config | object | `{}` | NATS configure |
| nats.enabled | bool | `false` | deploy a NATS and configure stalwart to use it as coordinator |
| replicaCount | int | `1` | replicas |
| updateStrategy | object | `{}` | updateStrategy |

### Observability

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| config.metrics.prometheus.auth.secret | string | `"%{env:METRICS_SECRET}%"` | basic auth metrics password in stalwart-mail |
| config.metrics.prometheus.auth.username | string | `"%{env:METRICS_USERNAME}%"` | basic auth metrics username in stalwart-mail |
| config.metrics.prometheus.enable | bool | `true` | enable prometheus in stalwart-mail |
| grafana.dashboards.annotations | object | `{}` | label of configmap |
| grafana.dashboards.enabled | bool | `false` | deploy grafana dashboard in configmap |
| grafana.dashboards.labels | object | `{"grafana_dashboard":"1"}` | label of configmap |
| nats.promExporter.enabled | bool | `false` | deploy prometheus exporter to NATS (in coordinator setup) |
| nats.promExporter.podMonitor.enabled | bool | `false` | deploy pod monitor for NATS prometheus exporter (in coordinator setup) |
| prometheus.servicemonitor.enabled | bool | `false` | deploy servicemonitor |
| prometheus.servicemonitor.labels | object | `{}` | label of servicemonitor |
| secrets.env.METRICS_SECRET | string | `"scrape_metrics_password"` | basic auth metrics password in secret for stalwart-mail |
| secrets.env.METRICS_USERNAME | string | `"scrape_metrics_user"` | basic auth metrics username in secret for stalwart-mail |

### Twake Webmail Client

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| twake.enabled | bool | `false` | deploy a |
| twake.image.pullPolicy | string | `"IfNotPresent"` | This sets the pull policy for images. (could be overwritten by global.image.pullPolicy) |
| twake.image.registry | string | `"ghcr.io"` | image registry (could be overwritten by global.image.registry) |
| twake.image.repository | string | `"linagora/tmail-web"` | image repository |
| twake.image.tag | string | `"v0.22.0"` | image tag |
| twake.volumeMounts | list | `[]` | Additional volumeMounts on the output Deployment definition. |
| twake.volumes | list | `[]` | Additional volumes on the output Deployment definition. |

### Other Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| autoscaling.enabled | bool | `false` |  |
| autoscaling.maxReplicas | int | `100` |  |
| autoscaling.minReplicas | int | `1` |  |
| autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| certificate.certmanager.dnsNames[0] | string | `"chart-example.local"` |  |
| certificate.certmanager.enabled | bool | `true` |  |
| certificate.certmanager.issuerRef.group | string | `"cert-manager.io"` |  |
| certificate.certmanager.issuerRef.kind | string | `"ClusterIssuer"` |  |
| certificate.certmanager.issuerRef.name | string | `"letsencrypt-prod"` |  |
| certificate.secretName | string | `nil` | not needed if certmanager is used |
| config.certificate.default.cert | string | `"%{file:/opt/stalwart/etc/certs/tls.crt}%"` |  |
| config.certificate.default.default | bool | `true` |  |
| config.certificate.default.private-key | string | `"%{file:/opt/stalwart/etc/certs/tls.key}%"` |  |
| config.config.local-keys | list | `["store.*","directory.*","tracer.*","!server.blocked-ip.*","server.*","authentication.fallback-admin.*","cluster.*","config.local-keys.*","storage.data","storage.blob","storage.lookup","storage.fts","storage.directory","certificate.*","server.allowed-ip.*","metrics.prometheus.*","auth.dkim.sign.*","auth.dkim.verify","http.use-x-forwarded","report.domain"]` | values configure here (and not per database) |
| config.directory.internal.store | string | `"rocksdb"` |  |
| config.directory.internal.type | string | `"internal"` |  |
| config.http.use-x-forwarded | bool | `true` |  |
| config.server.allowed-ip."10.42.0.1/16" | string | `""` |  |
| config.server.listener.http.bind[0] | string | `"[::]:80"` |  |
| config.server.listener.http.protocol | string | `"http"` |  |
| config.server.listener.https.bind[0] | string | `"[::]:443"` |  |
| config.server.listener.https.protocol | string | `"http"` |  |
| config.server.listener.https.tls.implicit | bool | `true` |  |
| config.server.listener.imap.bind[0] | string | `"[::]:143"` |  |
| config.server.listener.imap.protocol | string | `"imap"` |  |
| config.server.listener.imaptls.bind[0] | string | `"[::]:993"` |  |
| config.server.listener.imaptls.protocol | string | `"imap"` |  |
| config.server.listener.imaptls.tls.implicit | bool | `true` |  |
| config.server.listener.pop3.bind[0] | string | `"[::]:110"` |  |
| config.server.listener.pop3.protocol | string | `"pop3"` |  |
| config.server.listener.pop3s.bind[0] | string | `"[::]:995"` |  |
| config.server.listener.pop3s.protocol | string | `"pop3"` |  |
| config.server.listener.pop3s.tls.implicit | bool | `true` |  |
| config.server.listener.sieve.bind[0] | string | `"[::]:4190"` |  |
| config.server.listener.sieve.protocol | string | `"managesieve"` |  |
| config.server.listener.smtp.bind[0] | string | `"[::]:25"` |  |
| config.server.listener.smtp.protocol | string | `"smtp"` |  |
| config.server.listener.submission.bind[0] | string | `"[::]:587"` |  |
| config.server.listener.submission.protocol | string | `"smtp"` |  |
| config.server.listener.submissions.bind[0] | string | `"[::]:465"` |  |
| config.server.listener.submissions.protocol | string | `"smtp"` |  |
| config.server.listener.submissions.tls.implicit | bool | `true` |  |
| config.storage.blob | string | `"rocksdb"` |  |
| config.storage.data | string | `"rocksdb"` |  |
| config.storage.directory | string | `"internal"` |  |
| config.storage.fts | string | `"rocksdb"` |  |
| config.storage.lookup | string | `"rocksdb"` |  |
| config.store.rocksdb.compression | string | `"lz4"` |  |
| config.store.rocksdb.path | string | `"/data"` |  |
| config.store.rocksdb.type | string | `"rocksdb"` |  |
| config.tracer.otel.enable | bool | `false` |  |
| config.tracer.otel.endpoint | string | `"https://127.0.0.1/otel"` |  |
| config.tracer.otel.headers | list | `[]` | headers for usage with http (e.g. 'Authorization: <place_auth_here>') |
| config.tracer.otel.level | string | `"info"` |  |
| config.tracer.otel.transport | string | `"grpc"` | grpc or http |
| config.tracer.otel.type | string | `"open-telemetry"` |  |
| config.tracer.stdout.ansi | bool | `false` |  |
| config.tracer.stdout.enable | bool | `true` |  |
| config.tracer.stdout.level | string | `"info"` |  |
| config.tracer.stdout.type | string | `"stdout"` |  |
| env | list | `[]` |  |
| envFrom | list | `[]` |  |
| fullnameOverride | string | `""` |  |
| global.image.pullPolicy | string | `nil` | if set it will overwrite all pullPolicy |
| global.image.registry | string | `nil` | if set it will overwrite all registry entries |
| image.pullPolicy | string | `"IfNotPresent"` | This sets the pull policy for images. (could be overwritten by global.image.pullPolicy) |
| image.registry | string | `"ghcr.io"` | image registry (could be overwritten by global.image.registry) |
| image.repository | string | `"stalwartlabs/stalwart"` | image repository |
| image.tag | string | `""` | image tag - Overrides the image tag whose default is the chart appVersion. |
| imagePullSecrets | list | `[]` |  |
| ingress.annotations | object | `{}` |  |
| ingress.className | string | `""` |  |
| ingress.enabled | bool | `false` |  |
| ingress.hosts[0].host | string | `"admin.chart-example.local"` |  |
| ingress.hosts[0].paths[0].path | string | `"/"` |  |
| ingress.hosts[0].paths[0].pathType | string | `"ImplementationSpecific"` |  |
| ingress.hosts[1].host | string | `"chart-example.local"` |  |
| ingress.hosts[1].paths[0].path | string | `"/"` |  |
| ingress.hosts[1].paths[0].pathType | string | `"ImplementationSpecific"` |  |
| ingress.tls | list | `[]` |  |
| livenessProbe.httpGet.httpHeaders[0] | object | `{"name":"X-Forwarded-For","value":"127.0.0.1"}` | send fake X-Forwarded-For for not generate warnings |
| livenessProbe.httpGet.path | string | `"/healthz/live"` |  |
| livenessProbe.httpGet.port | string | `"http"` |  |
| livenessProbe.initialDelaySeconds | int | `5` |  |
| livenessProbe.periodSeconds | int | `10` |  |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| persistence.accessMode | string | `"ReadWriteOnce"` | accessMode |
| persistence.annotations | object | `{}` |  |
| persistence.enabled | bool | `true` | Enable persistence using Persistent Volume Claims ref: http://kubernetes.io/docs/user-guide/persistent-volumes/ |
| persistence.existingClaim | string | `nil` | A manually managed Persistent Volume and Claim Requires persistence.enabled: true If defined, PVC must be created manually before volume will be bound |
| persistence.hostPath | string | `nil` | Do not create an PVC, direct use hostPath in Pod |
| persistence.size | string | `"10Gi"` | size |
| persistence.storageClass | string | `nil` | Persistent Volume Storage Class If defined, storageClassName: <storageClass> If set to "-", storageClassName: "", which disables dynamic provisioning If undefined (the default) or set to null, no storageClassName spec is   set, choosing the default provisioner.  (gp2 on AWS, standard on   GKE, AWS & OpenStack) |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| readinessProbe.httpGet.httpHeaders[0] | object | `{"name":"X-Forwarded-For","value":"127.0.0.1"}` | send fake X-Forwarded-For for not generate warnings |
| readinessProbe.httpGet.path | string | `"/healthz/ready"` |  |
| readinessProbe.httpGet.port | string | `"http"` |  |
| readinessProbe.initialDelaySeconds | int | `30` |  |
| readinessProbe.periodSeconds | int | `10` |  |
| resources | object | `{}` |  |
| secrets.create | bool | `true` | enables env secret creation from secrets.env values    NOTE: The env variables below should be manually    passed in the pod if disabled. |
| securityContext | object | `{}` |  |
| service.annotations | object | `{}` |  |
| service.externalTrafficPolicy | string | `nil` |  |
| service.ipFamilies[0] | string | `"IPv4"` |  |
| service.ipFamilyPolicy | string | `"SingleStack"` | other option is RequireDualStack |
| service.ports.http | int | `80` |  |
| service.ports.https | int | `443` |  |
| service.ports.imap | int | `143` |  |
| service.ports.imaptls | int | `993` |  |
| service.ports.pop3 | int | `110` |  |
| service.ports.pop3s | int | `995` |  |
| service.ports.sieve | int | `4190` |  |
| service.ports.smtp | int | `25` |  |
| service.ports.submission | int | `587` |  |
| service.ports.submissions | int | `465` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.annotations | object | `{}` | Annotations to add to the service account |
| serviceAccount.automount | bool | `true` | Automatically mount a ServiceAccount's API credentials? |
| serviceAccount.create | bool | `false` | Specifies whether a service account should be created |
| serviceAccount.name | string | `""` | The name of the service account to use. If not set and create is true, a name is generated using the fullname template |
| tolerations | list | `[]` |  |
| traefik.enabled | bool | `false` |  |
| traefik.ports.https.entrypoint | string | `"websecure"` |  |
| traefik.ports.https.match | string | `nil` |  |
| traefik.ports.https.passthroughTLS | bool | `true` |  |
| traefik.ports.https.proxyProtocol | bool | `true` |  |
| traefik.ports.imaptls.entrypoint | string | `"imaps"` |  |
| traefik.ports.imaptls.match | string | `nil` |  |
| traefik.ports.imaptls.passthroughTLS | bool | `true` |  |
| traefik.ports.imaptls.proxyProtocol | bool | `true` |  |
| traefik.ports.pop3s.entrypoint | string | `"pop3s"` |  |
| traefik.ports.pop3s.match | string | `nil` |  |
| traefik.ports.pop3s.passthroughTLS | bool | `true` |  |
| traefik.ports.pop3s.proxyProtocol | bool | `true` |  |
| traefik.ports.sieve.entrypoint | string | `"sieve"` |  |
| traefik.ports.sieve.match | string | `nil` |  |
| traefik.ports.sieve.passthroughTLS | bool | `true` |  |
| traefik.ports.sieve.proxyProtocol | bool | `true` |  |
| traefik.ports.smtp.entrypoint | string | `"smtp"` |  |
| traefik.ports.smtp.match | string | `nil` |  |
| traefik.ports.smtp.proxyProtocol | bool | `true` |  |
| traefik.ports.submissions.entrypoint | string | `"smtps"` |  |
| traefik.ports.submissions.match | string | `nil` |  |
| traefik.ports.submissions.passthroughTLS | bool | `true` |  |
| traefik.ports.submissions.proxyProtocol | bool | `true` |  |
| twake.affinity | object | `{}` |  |
| twake.config.dashboard.apps[0].appLink | string | `"https://{{ (.Values.ingress.hosts | first).host }}"` |  |
| twake.config.dashboard.apps[0].name | string | `"Administration"` |  |
| twake.config.dashboard.apps[0].publicIconUri | string | `"https://{{ (.Values.ingress.hosts | first).host }}/apple-touch-icon.png"` |  |
| twake.config.env.APP_GRID_AVAILABLE | string | `"supported"` |  |
| twake.config.env.DOMAIN_REDIRECT_URL | string | `"https://{{ (.Values.twake.ingress.hosts | first).host }}"` |  |
| twake.config.env.FORWARD_WARNING_MESSAGE | string | `""` |  |
| twake.config.env.OIDC_SCOPES[0] | string | `"openid"` |  |
| twake.config.env.OIDC_SCOPES[1] | string | `"profile"` |  |
| twake.config.env.OIDC_SCOPES[2] | string | `"email"` |  |
| twake.config.env.OIDC_SCOPES[3] | string | `"offline_access"` |  |
| twake.config.env.PLATFORM | string | `"other"` |  |
| twake.config.env.SERVER_URL | string | `"https://{{ (.Values.ingress.hosts | first).host }}/"` |  |
| twake.config.env.WEB_OIDC_CLIENT_ID | string | `"teammail-web"` |  |
| twake.config.env.WS_ECHO_PING | bool | `true` |  |
| twake.ingress.annotations | object | `{}` |  |
| twake.ingress.className | string | `""` |  |
| twake.ingress.enabled | bool | `false` |  |
| twake.ingress.hosts[0].host | string | `"chart-example.local"` |  |
| twake.ingress.hosts[0].paths[0].path | string | `"/"` |  |
| twake.ingress.hosts[0].paths[0].pathType | string | `"ImplementationSpecific"` |  |
| twake.ingress.tls | list | `[]` |  |
| twake.livenessProbe.httpGet.path | string | `"/"` |  |
| twake.livenessProbe.httpGet.port | string | `"http"` |  |
| twake.livenessProbe.initialDelaySeconds | int | `5` |  |
| twake.livenessProbe.periodSeconds | int | `10` |  |
| twake.nodeSelector | object | `{}` |  |
| twake.podAnnotations | object | `{}` |  |
| twake.podLabels | object | `{}` |  |
| twake.podSecurityContext | object | `{}` |  |
| twake.readinessProbe.httpGet.path | string | `"/"` |  |
| twake.readinessProbe.httpGet.port | string | `"http"` |  |
| twake.readinessProbe.initialDelaySeconds | int | `30` |  |
| twake.readinessProbe.periodSeconds | int | `10` |  |
| twake.resources | object | `{}` |  |
| twake.securityContext | object | `{}` |  |
| twake.service.annotations | object | `{}` |  |
| twake.service.ipFamilies[0] | string | `"IPv4"` |  |
| twake.service.ipFamilyPolicy | string | `"SingleStack"` | other option is RequireDualStack |
| twake.service.type | string | `"ClusterIP"` |  |
| twake.tolerations | list | `[]` |  |
| volumeMounts | list | `[]` | Additional volumeMounts on the output Deployment definition. |
| volumes | list | `[]` | Additional volumes on the output Deployment definition. |

Autogenerated from chart metadata using [helm-docs](https://github.com/norwoodj/helm-docs)

