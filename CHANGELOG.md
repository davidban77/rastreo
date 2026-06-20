# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.0.2](https://github.com/davidban77/rastreo/compare/v0.0.1...v0.0.2) (2026-06-20)


### Features

* **core:** add `Resolver` trait with `HickoryResolver` default implementation for CIDR expansion, IP range expansion, and DNS resolution. Configurable per-resolver host limit (default 65,536) caps expansion size. `Target::Cidr` now wraps `ipnet::IpNet` instead of `String`. New `ResolverError` sub-enum under `RastreoError`. MSRV raised to 1.88 to take `hickory-resolver` 0.26.1, which clears two open RUSTSEC advisories on the 0.25.x line. ([#2](https://github.com/davidban77/rastreo/issues/2)) ([21f56d9](https://github.com/davidban77/rastreo/commit/21f56d97e7b95810f23867a6ed1b8c8a5b0fd05b))


### Bug Fixes

* **ci:** drop per-crate package.version paths from release-please ([#7](https://github.com/davidban77/rastreo/issues/7)) ([f9a064b](https://github.com/davidban77/rastreo/commit/f9a064b2d08f3e6f9da6a4a9cd96a7d83e25aaa9))


### CI/CD

* add release-please, commitlint, and dependabot ([#3](https://github.com/davidban77/rastreo/issues/3)) ([1724fba](https://github.com/davidban77/rastreo/commit/1724fba9fa11cb059798b97b238baa7165595486))

## [Unreleased]
