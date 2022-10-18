## -*- dockerfile-image-name: "bimini" -*-

ARG vault_env_exec_version=0.3.1
ARG org_opencontainers_image_created
ARG org_opencontainers_image_version
ARG org_opencontainers_image_revision


FROM rust:bullseye AS cargo-chef

RUN rustup component add rustfmt
RUN cargo install cargo-chef

WORKDIR /build


FROM cargo-chef AS planner

COPY ./Cargo.toml ./Cargo.lock ./
RUN RUST_BACKTRACE=1 cargo chef prepare --recipe-path recipe.json


FROM cargo-chef AS builder

COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
ADD . .
RUN cargo build --release --bin bimini


FROM debian:bullseye-slim AS source

COPY --from=builder --chmod=0555 /build/target/release/bimini /sbin/bimini

# COPY --from=builder --chmod=0555 /build/target/release/bimini /sbin/

# ARG org_opencontainers_image_created
# ARG org_opencontainers_image_version
# ARG org_opencontainers_image_revision
# ARG vault_env_exec_version

# ENV APOLLO_ROUTER_CONFIG_PATH=/etc/graphql-router/router.yaml
# ENV APOLLO_ROUTER_LOG=info
# ENV MANAGED_FEDERATION=true

# ADD "https://github.com/trialspark/vault-env-exec/releases/download/${vault_env_exec_version}/vault-env-exec-linux-amd64" /sbin/vault-env-exec

# RUN set -eux; \
#     \
#     export TERM='xterm'; \
#     export DEBIAN_FRONTEND='noninteractive'; \
#     \
#     useradd --home-dir /opt/graphql-router --create-home --user-group --uid 1000 apollo; \
#     \
#     apt-get update; \
#     apt-get install -y ca-certificates; \
#     \
#     chmod +x /sbin/vault-env-exec

# ADD container/root /

# COPY --from=builder /build/target/release/graphql-router /usr/local/bin

# WORKDIR /opt/graphql-router

# ENTRYPOINT ["/usr/local/bin/graphql-router"]

# LABEL \
#     org.opencontainers.image.vendor="TrialSpark Inc." \
#     org.opencontainers.image.url="https://github.com/trialspark/graphql-router" \
#     org.opencontainers.image.title="GraphQL Router" \
#     org.opencontainers.image.description="Apollo Gateway Router for GraphQL" \
#     org.opencontainers.image.documentation="https://github.com/trialspark/graphql-router/blob/master/README.md" \
#     org.opencontainers.image.source="https://github.com/trialspark/graphql-gateway.git" \
#     org.opencontainers.image.created="${org_opencontainers_image_created}" \
#     org.opencontainers.image.version="${org_opencontainers_image_version}" \
#     org.opencontainers.image.revision="${org_opencontainers_image_revision}"
