DOCKER_REGISTRY ?= docker.io
DOCKERHUB_NAMESPACE ?= tmunzer
VERSION ?= $(shell sed -n 's/^version = "\(.*\)"/\1/p' backend/pyproject.toml | head -n 1)
PLATFORMS ?= linux/amd64,linux/arm64
PUBLISH_LATEST ?= true

BACKEND_IMAGE ?= $(DOCKER_REGISTRY)/$(DOCKERHUB_NAMESPACE)/mist-config-guardian
FRONTEND_IMAGE ?= $(DOCKER_REGISTRY)/$(DOCKERHUB_NAMESPACE)/mist-config-guardian-frontend

BACKEND_TAGS = --tag $(BACKEND_IMAGE):$(VERSION)
FRONTEND_TAGS = --tag $(FRONTEND_IMAGE):$(VERSION)
ifeq ($(PUBLISH_LATEST),true)
BACKEND_TAGS += --tag $(BACKEND_IMAGE):latest
FRONTEND_TAGS += --tag $(FRONTEND_IMAGE):latest
endif

.PHONY: install check backend frontend compose publish-images release release-preflight version-check

install:
	cd backend && uv sync
	cd frontend && npm ci

check:
	cd backend && uv run ruff format --check . && uv run ruff check . && uv run ty check src && uv run pytest
	cd frontend && npm test -- --watch=false && npm run build

backend:
	cd backend && uv run mist-config-guardian

frontend:
	cd frontend && npm start

compose:
	docker compose up --build

version-check:
	@test -n "$(VERSION)" || (echo "VERSION could not be determined" >&2; exit 1)
	@test "$(VERSION)" = "$$(node -p "require('./frontend/package.json').version")" || \
		(echo "VERSION does not match frontend/package.json" >&2; exit 1)
	@test "$(VERSION)" = "$$(sed -n 's/^appVersion: "\(.*\)"/\1/p' helm/mist-config-guardian/Chart.yaml)" || \
		(echo "VERSION does not match the Helm appVersion" >&2; exit 1)
	@test "$(VERSION)" = "$$(awk '/^  tag:/ {gsub(/"/, "", $$2); print $$2; exit}' helm/mist-config-guardian/values.yaml)" || \
		(echo "VERSION does not match the Helm backend image tag" >&2; exit 1)
	@test "$(VERSION)" = "$$(awk '/^  tag:/ {count++; if (count == 2) {gsub(/"/, "", $$2); print $$2; exit}}' helm/mist-config-guardian/values.yaml)" || \
		(echo "VERSION does not match the Helm frontend image tag" >&2; exit 1)

publish-images: version-check
	@docker info >/dev/null
	@docker buildx version >/dev/null
	docker buildx build --platform "$(PLATFORMS)" $(BACKEND_TAGS) --push backend
	docker buildx build --platform "$(PLATFORMS)" $(FRONTEND_TAGS) --push frontend
	@echo "Published $(BACKEND_IMAGE):$(VERSION) and $(FRONTEND_IMAGE):$(VERSION)"

release-preflight: version-check
	@git rev-parse --is-inside-work-tree >/dev/null
	@git rev-parse --verify HEAD >/dev/null
	@test -z "$$(git status --porcelain)" || \
		(echo "The Git working tree must be clean before releasing" >&2; exit 1)
	@! git rev-parse --verify "refs/tags/v$(VERSION)" >/dev/null 2>&1 || \
		(echo "Git tag v$(VERSION) already exists" >&2; exit 1)

release: release-preflight
	$(MAKE) check
	$(MAKE) publish-images VERSION="$(VERSION)" PUBLISH_LATEST="$(PUBLISH_LATEST)"
	git tag -a "v$(VERSION)" -m "Mist Config Guardian $(VERSION)"
	@echo "Created v$(VERSION). Push the commit and tag with: git push origin HEAD --follow-tags"
