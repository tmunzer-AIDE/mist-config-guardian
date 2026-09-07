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
catalog UIs. Configure the container images, external MongoDB, Redis, and
InfluxDB services, networking, and application secrets through the form.

By default, the chart reads sensitive settings from the Secret named by
`existingSecret`. It must contain `SECRET_KEY`, `BOOTSTRAP_ADMIN_TOKEN`,
`CREDENTIAL_ENCRYPTION_KEY`, and `INFLUXDB_TOKEN`.

For evaluation environments, the form can create this Secret by enabling
`secrets.create`. External secret management is recommended for production
because chart-managed secret values are retained in Helm release data.

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
