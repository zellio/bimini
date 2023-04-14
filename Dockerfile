## -*- dockerfile-image-name: "bimini" -*-


FROM rust:bullseye AS cargo-chef

ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

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


FROM debian:bullseye-slim AS image

COPY --from=builder --chmod=0555 /build/target/release/bimini /sbin/bimini

ENTRYPOINT ["/sbin/bimini"]
