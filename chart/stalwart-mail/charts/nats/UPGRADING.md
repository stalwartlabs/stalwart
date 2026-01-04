# Upgrading from 0.x to 1.x

Instructions for upgrading an existing `nats` 0.x release to 1.x.

## Rename Immutable Fields

There are a number of immutable fields in the NATS Stateful Set and NATS Box deployment.  All 1.x `values.yaml` files targeting an existing 0.x release will require some or all of these settings:

```yaml
config:
  # required if using JetStream file storage
  jetstream:
    # uncomment the next line if using JetStream file storage
    # enabled: true
    fileStore:
      pvc:
        name:
          $tplYaml: >-
            {{ include "nats.fullname" . }}-js-pvc
        # set other PVC options here to make it match 0.x, refer to values.yaml for schema

  # required if using a full or cache resolver
  resolver:
    # uncomment the next line if using a full or cache resolver
    # enabled: true
    pvc:
      name: nats-jwt-pvc
    # set other PVC options here to make it match 0.x, refer to values.yaml for schema

# required
statefulSet:
  patch:
  - op: remove
    path: /spec/selector/matchLabels/app.kubernetes.io~1component
  - $tplYamlSpread: |-
      {{- if and 
        .Values.config.jetstream.enabled
        .Values.config.jetstream.fileStore.enabled
        .Values.config.jetstream.fileStore.pvc.enabled
        .Values.config.resolver.enabled
        .Values.config.resolver.pvc.enabled
      }}
      - op: move
        from: /spec/volumeClaimTemplates/0
        path: /spec/volumeClaimTemplates/1
      {{- else}}
      []
      {{- end }}

# required
headlessService:
  name:
    $tplYaml: >-
      {{ include "nats.fullname" . }}

# required unless 0.x values explicitly set nats.serviceAccount.create=false
serviceAccount:
  enabled: true

# required to use new ClusterIP service for Clients accessing NATS
# if using TLS, this may require adding another SAN
service:
  # uncomment the next line to disable the new ClusterIP service
  # enabled: false
  name:
    $tplYaml: >-
      {{ include "nats.fullname" . }}-svc

# required if using NatsBox
natsBox:
  deployment:
    patch:
    - op: replace
      path: /spec/selector/matchLabels
      value:
        app: nats-box
    - op: add
      path: /spec/template/metadata/labels/app
      value: nats-box
```

## Update NATS Config to new values.yaml schema

Most values that control the NATS Config have changed and moved under the `config` key.  Refer to the 1.x Chart's [values.yaml](values.yaml) for the complete schema.

After migrating to the new values schema, ensure that changes you expect in the NATS Config files match by templating the old and new config files.

Template your old 0.x Config Map, this example uses a file called `values-old.yaml`:

```sh
helm template \
  --version "0.x" \
  -f values-old.yaml \
  -s templates/configmap.yaml \
  nats \
  nats/nats
```

Template your new 1.x Config Map, this example uses a file called `values.yaml`:

```sh
helm template \
  --version "^1-beta" \
  -f values.yaml \
  -s templates/config-map.yaml \
  nats \
  nats/nats
```

## Update Kubernetes Resources to new values.yaml schema

Most values that control Kubernetes Resources have been changed.  Refer to the 1.x Chart's [values.yaml](values.yaml) for the complete schema.

After migrating to the new values schema, ensure that changes you expect in resources match by templating the old and new resources.

| Resource                | 0.x Template File               | 1.x Template File                         |
|-------------------------|---------------------------------|-------------------------------------------|
| Config Map              | `templates/configmap.yaml`      | `templates/config-map.yaml`               |
| Stateful Set            | `templates/statefulset.yaml`    | `templates/stateful-set.yaml`             |
| Headless Service        | `templates/service.yaml`        | `templates/headless-service.yaml`         |
| ClusterIP Service       | N/A                             | `templates/service.yaml`                  |
| Network Policy          | `templates/networkpolicy.yaml`  | N/A                                       |
| Pod Disruption Budget   | `templates/pdb.yaml`            | `templates/pod-disruption-budget.yaml`    |
| Service Account         | `templates/rbac.yaml`           | `templates/service-account.yaml`          |
| Resource                | `templates/`                    | `templates/`                              |
| Resource                | `templates/`                    | `templates/`                              |
| Prometheus Monitor      | `templates/serviceMonitor.yaml` | `templates/pod-monitor.yaml`              |
| NatsBox Deployment      | `templates/nats-box.yaml`       | `templates/nats-box/deployment.yaml`      |
| NatsBox Service Account | N/A                             | `templates/nats-box/service-account.yaml` |
| NatsBox Contents Secret | N/A                             | `templates/nats-box/contents-secret.yaml` |
| NatsBox Contexts Secret | N/A                             | `templates/nats-box/contexts-secret.yaml` |

For example, to check that the Stateful Set matches:

Template your old 0.x Stateful Set, this example uses a file called `values-old.yaml`:

```sh
helm template \
  --version "0.x" \
  -f values-old.yaml \
  -s templates/statefulset.yaml \
  nats \
  nats/nats
```

Template your new 1.x Stateful Set, this example uses a file called `values.yaml`:

```sh
helm template \
  --version "^1-beta" \
  -f values.yaml \
  -s templates/stateful-set.yaml \
  nats \
  nats/nats
```
