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


FROM scratch AS source

COPY --from=builder --chmod=0555 /build/target/release/bimini /sbin/bimini
