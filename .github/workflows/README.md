# GitHub Workflows

This directory contains CI/CD workflows for the Rust workspace.

## `ci.yml`

Runs on pushes/PRs to `main` and `master`.

- **test**: workspace unit tests (non-root)
- **integration-test**: ignored/root-required tests via `sudo`
- **build**: release workspace build + artifact/checksum upload
- **lint**: `cargo fmt --check --all` + `cargo clippy --workspace -- -D warnings`
- **benchmark**: `cargo bench --workspace` + benchmark artifact upload

## `release.yml`

Runs on tag pushes matching `v*`.

- **test** gate first
- **build** matrix for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`
- **package-deb-rpm** creates DEB/RPM via `fpm`
- **docker** builds and pushes multi-arch images to `ghcr.io`
- **release** creates GitHub Release with binaries, checksums, and packages
