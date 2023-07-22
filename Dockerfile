FROM rust:alpine3.17 as builder

ARG RELEASE_BUILD=true

# update packages
RUN apk update
RUN apk add build-base openssl-dev ca-certificates

# create root application folder
WORKDIR /app

COPY ./ /app/src

# Install rust toolchains
RUN rustup toolchain install stable
RUN rustup default stable

WORKDIR /app/src

# Build dependencies only. Separate these for caches
RUN cargo install cargo-build-deps
RUN sh -c "cargo build-deps ${RELEASE_BUILD:+ --release}"

# Build the release executable.
RUN sh -c "cargo build ${RELEASE_BUILD:+ --release}"

# Runner stage. I tried using distroless (gcr.io/distroless/static-debian11), but the image was only ~3MBs smaller than
# alpine. I chose to use alpine since it makes it easier to exec into the container to debug things.
FROM alpine:3.17

ARG UNAME=orca-registry
ARG UID=1000
ARG GID=1000

# Add user and copy the executable from the build stage.
RUN adduser --disabled-password --gecos "" $UNAME -s -G $GID -u $UID
COPY --from=builder --chown=$UID:$GID /app/src/target/release/orca-registry /app/orca-registry

# Chown everything
RUN mkdir /data && \
    chown -R $UID:$GID /data && \
    chown -R $UID:$GID /app

USER $UNAME

WORKDIR /app/

EXPOSE 3000

ENTRYPOINT [ "/app/orca-registry" ]