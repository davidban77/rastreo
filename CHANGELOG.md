# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.0.3](https://github.com/davidban77/rastreo/compare/v0.0.2...v0.0.3) (2026-06-20)


### Documentation

* backfill Resolver entry to 0.0.2 changelog ([#9](https://github.com/davidban77/rastreo/issues/9)) ([194ad5f](https://github.com/davidban77/rastreo/commit/194ad5f759f84569577de439f513e51c2f0e8ca7))


### CI/CD

* bump actions/checkout from 4 to 7 ([#4](https://github.com/davidban77/rastreo/issues/4)) ([3e71a87](https://github.com/davidban77/rastreo/commit/3e71a87de061fbcddb51ae65bd7d659872d63d30))
* bump apache/kafka from 3.9.0 to 4.2.0 ([#6](https://github.com/davidban77/rastreo/issues/6)) ([d9ba520](https://github.com/davidban77/rastreo/commit/d9ba520466c9d3984a076094e88506b38a6a3f76))
* bump nginx from 1.27-alpine to 1.31-alpine ([#5](https://github.com/davidban77/rastreo/issues/5)) ([a87f1f2](https://github.com/davidban77/rastreo/commit/a87f1f2054bc34bf9fe83a3e056cb5bbe8b9bcd2))

## [0.0.2](https://github.com/davidban77/rastreo/compare/v0.0.1...v0.0.2) (2026-06-20)


### Features

* **core:** add `Resolver` trait with `HickoryResolver` default implementation for CIDR expansion, IP range expansion, and DNS resolution. Configurable per-resolver host limit (default 65,536) caps expansion size. `Target::Cidr` now wraps `ipnet::IpNet` instead of `String`. New `ResolverError` sub-enum under `RastreoError`. MSRV raised to 1.88 to take `hickory-resolver` 0.26.1, which clears two open RUSTSEC advisories on the 0.25.x line. ([#2](https://github.com/davidban77/rastreo/issues/2)) ([21f56d9](https://github.com/davidban77/rastreo/commit/21f56d97e7b95810f23867a6ed1b8c8a5b0fd05b))


### Bug Fixes

* **ci:** drop per-crate package.version paths from release-please ([#7](https://github.com/davidban77/rastreo/issues/7)) ([f9a064b](https://github.com/davidban77/rastreo/commit/f9a064b2d08f3e6f9da6a4a9cd96a7d83e25aaa9))


### CI/CD

* add release-please, commitlint, and dependabot ([#3](https://github.com/davidban77/rastreo/issues/3)) ([1724fba](https://github.com/davidban77/rastreo/commit/1724fba9fa11cb059798b97b238baa7165595486))

## [Unreleased]
