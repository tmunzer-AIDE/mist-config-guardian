# Mist Config Guardian

Standalone configuration history, point-in-time recovery, and post-change impact
monitoring for Juniper Mist.

The application stores only a read-only Mist service token for unattended
backup and monitoring. Every Mist write requires a freshly authenticated
administrator's delegated Mist super-user credential.

## Repository layout

```text
backend/                       FastAPI API and Celery workers
frontend/                      Angular application
helm/mist-config-guardian/     Kubernetes Helm chart
docs/product-specification.md  Approved product and technical baseline
docker-compose.yml             Local and single-node deployment
```

## Local development

Requirements: Python 3.13, uv, Node.js, and npm.

```bash
cp .env.example .env
make install
make check
make backend
make frontend
```

The API runs at `http://localhost:8000` and the Angular development server at
`http://localhost:4200`.

## Docker Compose

Replace every development secret in `.env`, then run:

```bash
docker compose up --build
```

The application is served at `http://localhost:8080`.

## Helm

The chart includes `questions.yaml` for guided installation in Rancher-compatible
catalog UIs. Configure the container images, the datastores, networking, and
application secrets through the form.

MongoDB, Redis, and InfluxDB are deployed with the release by default. Set
`mongodb.enabled`, `redis.enabled`, or `influxdb.enabled` to `false` to point
the application at an existing service through `config` instead.

By default, the chart reads sensitive settings from the Secret named by
`existingSecret`. It must contain `SECRET_KEY`, `BOOTSTRAP_ADMIN_TOKEN`,
`CREDENTIAL_ENCRYPTION_KEY`, and `INFLUXDB_TOKEN`, plus the datastore
credentials for whichever datastores are bundled:

| Key | Required when |
|---|---|
| `MONGODB_ROOT_USERNAME` | `mongodb.enabled` |
| `MONGODB_ROOT_PASSWORD` | `mongodb.enabled` |
| `REDIS_PASSWORD` | `redis.enabled` |

Each bundled datastore refuses unauthenticated connections. Both passwords are
placed in a connection URI, so keep them to characters that need no
percent-encoding: letters, digits, and any of `-._~`. The URIs are assembled
inside the pod from the Secret, so no password is written to a ConfigMap or
into the rendered manifest.

#### Rotating the MongoDB credentials

**`MONGODB_ROOT_USERNAME` and `MONGODB_ROOT_PASSWORD` are set at first install
only.** MongoDB creates the account when its data directory is empty and then
keeps it there. On a release that already has a volume, changing them in the
Secret changes what the application presents and not what the database expects:
the probes stop authenticating, and the pod restarts until it is put back.

The chart cannot rotate the password for you — doing so needs the *old* one,
which the Secret no longer holds once you have edited it. Rotate in this order
instead:

```bash
kubectl exec -it deploy/<release>-mist-config-guardian-mongodb --   mongosh --quiet -u <username> -p <old password> --authenticationDatabase admin   --eval 'db.getSiblingDB("admin").changeUserPassword("<username>", "<new password>")'
```

Then update `MONGODB_ROOT_PASSWORD` in the Secret and restart the application:

```bash
kubectl rollout restart deploy -l app.kubernetes.io/instance=<release>
```

#### Rotating the Redis password

`REDIS_PASSWORD` has no such constraint — Redis reads it when the container
starts — but a changed Secret does not restart anything on its own.

When the chart manages the Secret (`secrets.create`), it does: every pod that
reads the Secret carries a digest of it, so `helm upgrade` rolls Redis and the
application together. Expect connection errors for the few seconds the two
sides are on different passwords.

When the Secret is managed elsewhere the chart cannot see its contents and that
digest never changes, so the restart is yours to do:

```bash
kubectl rollout restart deploy -l app.kubernetes.io/instance=<release>
```

The same digest is on the MongoDB and InfluxDB pods. For MongoDB that is
deliberate: a password changed in the Secret without the rotation above is a
mistake, and rolling the pod turns it into an authentication failure you can
see in the logs straight away rather than one that surfaces at some unrelated
restart weeks later.

For evaluation environments, the form can create this Secret by enabling
`secrets.create`. External secret management is recommended for production
because chart-managed secret values are retained in Helm release data.

### Network policy

`networkPolicy.enabled` (on by default) denies every connection to every pod in
the release, then allows only the ones the application needs: the API, workers,
and scheduler reach the three datastores, and the browser reaches the frontend
and the API. Nothing else in the cluster can open a connection to MongoDB,
Redis, or InfluxDB.

Narrow the browser-facing rule to your ingress controller with
`networkPolicy.webIngressFrom`, which takes a list of `NetworkPolicyPeer`. It is
empty by default, meaning any source, because a controller's namespace and
labels differ between clusters.

Outbound traffic is unrestricted unless `networkPolicy.egress.enabled` is set.
It is off by default because the API and workers call the Mist cloud and, when
configured, an AI provider, and this chart cannot know what those resolve to.
When it is on, the pods may resolve DNS, reach their own datastores, and open
connections to `networkPolicy.egress.allowedDestinations` — by default the
public internet with the private ranges excluded.

**These objects require a CNI that enforces NetworkPolicy.** On a cluster
without one they are accepted and ignored, and the datastore passwords are then
the only thing standing between an unrelated pod and the data.

AI-assisted impact analysis is configured after deployment from the
Administration page. Its provider API key is encrypted before it is stored.

## Publishing a release

Authenticate to Docker Hub and configure a GitHub `origin` remote once. A
release is then published with one command:

```bash
docker login
make publish VERSION=0.2.0
```

The command:

1. Requires a clean Git working tree and a new semantic version.
2. Synchronizes the backend, frontend, environment example, Docker image tags,
   and Helm chart versions.
3. Runs the application checks and Helm validation.
4. Creates a release commit.
5. Publishes versioned and `latest` multi-architecture backend and frontend
   images to Docker Hub.
6. Creates an annotated `v<version>` tag and pushes the commit and tag to
   GitHub.

The default destination is `docker.io/tmunzer`. Override
`DOCKERHUB_NAMESPACE`, `DOCKER_REGISTRY`, `PLATFORMS`, `PUBLISH_LATEST`, or
`GIT_REMOTE` when needed:

```bash
make publish VERSION=0.2.0 DOCKERHUB_NAMESPACE=example PUBLISH_LATEST=false
```

To publish images without changing versions or Git history, use
`make publish-images`.
