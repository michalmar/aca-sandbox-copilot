FROM node:22.22.0-bookworm-slim@sha256:7cc56ef285a8568121537d17b05e72128f01b89c54607b51acf084a50ef483f3 AS node
FROM ghcr.io/astral-sh/uv:0.11.1@sha256:b6ca5767729b57719f1edf206123c8cb474a4b3a198cc28e1fd92eee3d3898fe AS uv
FROM ubuntu:24.04@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4 AS python-dependencies

ARG TARGETARCH
RUN test "$TARGETARCH" = amd64
ENV DEBIAN_FRONTEND=noninteractive \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    ca-certificates curl git tini tzdata python3.12 python3.12-venv python3.12-dev \
    build-essential pkg-config libffi-dev libssl-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /opt/hermes
RUN git init -q . && \
    git remote add origin https://github.com/NousResearch/hermes-agent.git && \
    git fetch -q --depth=1 origin 645da6561c724b7ca163d4af9c21de3a6397c9f2 && \
    git checkout -q --detach FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = 645da6561c724b7ca163d4af9c21de3a6397c9f2
COPY build_dependencies.py /opt/hermes-sandbox/build_dependencies.py
ARG PYPI_INDEX_URL=https://pypi.org/simple
RUN python3.12 /opt/hermes-sandbox/build_dependencies.py python-lock-exception "$PYPI_INDEX_URL" && \
    uv venv --python /usr/bin/python3.12 .venv && \
    uv --no-config pip install --python .venv/bin/python --index-url "$PYPI_INDEX_URL" \
    --require-hashes -r /opt/hermes-sandbox/runtime-requirements.txt && \
    .venv/bin/python /opt/hermes-sandbox/build_dependencies.py runtime-constraints > /tmp/runtime-constraints.txt && \
    uv --no-config pip install --python .venv/bin/python --index-url "$PYPI_INDEX_URL" \
    --constraint /tmp/runtime-constraints.txt --no-build-isolation -e . && \
    uv --no-config pip check --python .venv/bin/python && \
    rm /tmp/runtime-constraints.txt

FROM python-dependencies AS dependencies
ARG NPM_REGISTRY=https://registry.npmjs.org/
RUN .venv/bin/python /opt/hermes-sandbox/build_dependencies.py frontend-lock-exception "$NPM_REGISTRY" && \
    npm ci --registry "$NPM_REGISTRY" --ignore-scripts --no-audit --no-fund \
    --workspace web --workspace ui-tui --workspace ui-tui/packages/hermes-ink \
    --workspace apps/shared --include-workspace-root && \
    npm rebuild esbuild && \
    npm run build --workspace ui-tui && \
    npm run build --workspace web
RUN cd scripts/whatsapp-bridge && npm ci --registry "$NPM_REGISTRY" --ignore-scripts --no-audit --no-fund && \
    node -e "const f=require('fs'),c=require('crypto');f.writeFileSync('node_modules/.hermes-pkg-hash',c.createHash('sha256').update(f.readFileSync('package.json')).digest('hex').slice(0,16))"
RUN .venv/bin/python /opt/hermes-sandbox/build_dependencies.py verify

FROM dependencies AS runtime
WORKDIR /opt/hermes
COPY . /opt/hermes-sandbox/
RUN test -f /opt/hermes-sandbox/access_proxy.py && \
    test -f /opt/hermes-sandbox/google/server.py && \
    .venv/bin/python /opt/hermes-sandbox/patch_upstream.py /opt/hermes && \
    npm run build --workspace ui-tui --offline && \
    install -m 0755 /opt/hermes-sandbox/entrypoint.sh /usr/local/bin/container-entrypoint && \
    install -m 0755 /opt/hermes-sandbox/entrypoint.sh /usr/local/bin/hermes-entrypoint && \
    chmod 0755 /opt/hermes-sandbox/control.py && \
    printf '%s\n' /opt/hermes-sandbox > /opt/hermes/.venv/lib/python3.12/site-packages/hermes_sandbox.pth && \
    .venv/bin/python /opt/hermes-sandbox/build_dependencies.py registry && \
    .venv/bin/python /opt/hermes-sandbox/build_dependencies.py integration
ENV PATH="/opt/hermes/.venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    HERMES_HOME=/mnt/data/hermes \
    HERMES_TUI_DIR=/opt/hermes/ui-tui \
    HERMES_PYTHON_PATH=/opt/hermes/.venv/bin/python \
    AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential \
    TZ=Europe/Prague \
    LANG=C.UTF-8
WORKDIR /mnt/data
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "-s", "--", "/usr/local/bin/container-entrypoint"]

FROM runtime AS verification
ARG PYPI_INDEX_URL=https://pypi.org/simple
RUN /opt/hermes/.venv/bin/python /opt/hermes-sandbox/build_dependencies.py runtime-constraints \
    > /tmp/runtime-constraints.txt && \
    uv --no-config pip install --python /opt/hermes/.venv/bin/python \
    --index-url "$PYPI_INDEX_URL" --constraint /tmp/runtime-constraints.txt \
    -r /opt/hermes-sandbox/verification-requirements.txt && \
    uv --no-config pip check --python /opt/hermes/.venv/bin/python && \
    /opt/hermes/.venv/bin/python /opt/hermes-sandbox/build_dependencies.py runtime-constraints \
    > /opt/hermes-sandbox/verification-versions.txt && \
    rm /tmp/runtime-constraints.txt

FROM runtime AS final
