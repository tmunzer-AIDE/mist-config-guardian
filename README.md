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
`CREDENTIAL_ENCRYPTION_KEY`, and `INFLUXDB_TOKEN`. If AI-assisted analysis is
enabled, it must also contain `IMPACT_AI_API_KEY`.

For evaluation environments, the form can create this Secret by enabling
`secrets.create`. External secret management is recommended for production
because chart-managed secret values are retained in Helm release data.

## Publishing a release

Authenticate to Docker Hub once, then publish the backend and frontend images
for the application version declared in `backend/pyproject.toml`:

```bash
docker login
make publish-images
```

The default destination is `docker.io/tmunzer`. Override
`DOCKERHUB_NAMESPACE`, `DOCKER_REGISTRY`, `PLATFORMS`, or `PUBLISH_LATEST` when
needed. For example:

```bash
make publish-images DOCKERHUB_NAMESPACE=example PUBLISH_LATEST=false
```

To validate the application, publish both images, and create the annotated Git
tag in one command, first commit all release changes and run:

```bash
make release
git push origin HEAD --follow-tags
```

`make release` refuses to run from a dirty working tree or overwrite an
existing `v<version>` tag.
