FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

# sqlx-cli for running migrations, postgresql-client for psql access to the db container
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends postgresql-client \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

RUN cargo install sqlx-cli --version ^0.8 --no-default-features --features rustls,postgres

# cargo install above ran as root, leaving root-owned files in the cargo registry.
# Hand ownership to vscode so it can write there at runtime (downloads, index updates).
RUN chown -R vscode:vscode /usr/local/cargo/registry
