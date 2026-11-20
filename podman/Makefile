# Contained JavaScript Solid Server, run with Podman.
# Usage: make up [PROFILE=local|lan|internet]

PROFILE ?= local
IMAGE   := localhost/jss:latest
CONTAINER := jss-server
CADDY_IMAGE := docker.io/library/caddy:2

# A gitignored profiles/<profile>.local.yaml, if present, overrides the
# committed profile (e.g. to set your real hostname or LAN IP).
CONFIG := $(firstword $(wildcard profiles/$(PROFILE).local.yaml) profiles/$(PROFILE).yaml)

ifeq ($(PROFILE),lan)
BIND := 0.0.0.0:4443:4443
else
BIND := 127.0.0.1:4443:4443
endif

.PHONY: build up down restart logs status shell reset rebuild caddy-validate grant-webid create-pod

build:
	podman build -t $(IMAGE) jss

up: build
	@echo "Using $(CONFIG), publishing $(BIND)"
	podman kube play --replace \
		--configmap $(CONFIG) \
		--publish $(BIND) \
		jss.yaml

down:
	podman kube down jss.yaml

restart: down up

logs:
	podman logs -f $(CONTAINER)

status:
	podman pod ps --filter name=jss
	podman ps --all --filter pod=jss
	podman volume ls --filter name=jss-

shell:
	podman exec -it $(CONTAINER) sh

reset:
	-podman kube down jss.yaml
	@printf 'This permanently deletes volumes jss-data and jss-secrets (all pods, users, and logins). Type "yes" to continue: '; \
	read answer; [ "$$answer" = "yes" ] || { echo "Aborted."; exit 1; }
	podman volume rm jss-data jss-secrets

rebuild:
	podman build --no-cache -t $(IMAGE) jss
	$(MAKE) restart PROFILE=$(PROFILE)

# Check proxy/Caddyfile syntax in a throwaway Caddy container (nothing is
# installed on the host).
caddy-validate:
	podman run --rm -v ./proxy/Caddyfile:/etc/caddy/Caddyfile:ro,Z $(CADDY_IMAGE) \
		caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile

# Create a pod with a generated password, saved to ~/.config/jss-dev/<name>-account.txt.
# Usage: make create-pod NAME=billy [EMAIL=billy@example.com]
create-pod:
	scripts/create-pod.sh "$(NAME)" $(EMAIL)

# Grant a WebID Read/Write/Control on a container, keeping existing rules.
# Usage: make grant-webid POD=test CONTAINER=private WEBID=https://... [EMAIL=... PASSWORD=...]
grant-webid:
	scripts/grant-webid.sh "$(POD)" "$(CONTAINER)" "$(WEBID)"

