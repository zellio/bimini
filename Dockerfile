## -*- dockerfile-image-name: "bimini" -*-

ARG vault_env_exec_version=0.3.1
ARG org_opencontainers_image_created
ARG org_opencontainers_image_version
ARG org_opencontainers_image_revision


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


FROM builder AS source

ADD LICENSE /image-root/

ARG source_files="\
    /etc/host.conf\n\
    /etc/hosts\n\
    /etc/ld.so.cache\n\
    /etc/nsswitch.conf\n\
    /etc/resolv.conf\n\
    /lib/aarch64-linux-gnu/libc.so.6\n\
    /lib/aarch64-linux-gnu/libdl.so.2\n\
    /lib/aarch64-linux-gnu/libgcc_s.so.1\n\
    /lib/aarch64-linux-gnu/libm.so.6\n\
    /lib/aarch64-linux-gnu/libnss_dns.so.2\n\
    /lib/aarch64-linux-gnu/libnss_files.so.2\n\
    /lib/aarch64-linux-gnu/libpthread.so.0\n\
    /lib/aarch64-linux-gnu/libresolv.so.2\n\
    /lib/aarch64-linux-gnu/librt.so.1\n\
    /lib/ld-linux-aarch64.so.1\n\
    /usr/bin/env\n\
    "

RUN echo "${source_files}" | xargs -I'{}' -- install --mode=0555 --verbose -D '{}' '/image-root{}'
RUN install --mode=0555 --verbose -D /build/target/release/bimini /image-root/sbin/bimini

FROM scratch AS image

COPY --from=source /image-root /

ENTRYPOINT ["/sbin/bimini"]
