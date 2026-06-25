# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0](https://github.com/davidban77/rastreo/compare/v0.1.0...v0.2.0) (2026-06-25)


### Features

* **ci:** add crates.io publish workflow ([#32](https://github.com/davidban77/rastreo/issues/32)) ([f7da1b8](https://github.com/davidban77/rastreo/commit/f7da1b8c8c5655dd71a7ea52171fdcc24510e326))
* **ci:** add live-infra UAT gate against the compose stack ([#33](https://github.com/davidban77/rastreo/issues/33)) ([238a1df](https://github.com/davidban77/rastreo/commit/238a1dfe9536fd787aba58f5fc4f27393dadeb23))
* **ci:** add multi-arch release workflow ([#30](https://github.com/davidban77/rastreo/issues/30)) ([4bb6306](https://github.com/davidban77/rastreo/commit/4bb6306677324ce93895be4c839b3715383cbe79))


### Documentation

* add brand assets, README badges, and docs home hero ([#34](https://github.com/davidban77/rastreo/issues/34)) ([d36cbf7](https://github.com/davidban77/rastreo/commit/d36cbf740eb339d179f6c3c9de937792c8c75ae4))


### Miscellaneous

* add community scaffolding and editorconfig ([#35](https://github.com/davidban77/rastreo/issues/35)) ([a93c92a](https://github.com/davidban77/rastreo/commit/a93c92af9d9a9f416044eff8783e0237528bbc97))

## [0.1.0](https://github.com/davidban77/rastreo/compare/v0.0.3...v0.1.0) (2026-06-23)


### Features

* add CLI discover subcommand driving the discovery pipeline ([#19](https://github.com/davidban77/rastreo/issues/19)) ([580a8e6](https://github.com/davidban77/rastreo/commit/580a8e6c8db673707a57508aa10987d636cd5f1a))
* add POST /scans endpoint to rastreo-server ([#21](https://github.com/davidban77/rastreo/issues/21)) ([12553c5](https://github.com/davidban77/rastreo/commit/12553c5a903446695484301405d439d08e4313c2))
* **core:** add Fuser trait with DirectFuser default impl ([#16](https://github.com/davidban77/rastreo/issues/16)) ([0e0d57e](https://github.com/davidban77/rastreo/commit/0e0d57eb48e365825a626a973b52ac025f07419a))
* **core:** add KafkaSink behind the kafka feature ([#18](https://github.com/davidban77/rastreo/issues/18)) ([609d2b4](https://github.com/davidban77/rastreo/commit/609d2b4692c3377f1b8a01753338189749d1764b))
* **core:** add NdjsonEncoder, StdoutSink, and FileSink ([#15](https://github.com/davidban77/rastreo/issues/15)) ([d6fceea](https://github.com/davidban77/rastreo/commit/d6fceea22ea009bd9ad6b365fa41d6e60b5a1ed2))
* **core:** add Scheduler trait with bounded-concurrency probe driver ([#11](https://github.com/davidban77/rastreo/issues/11)) ([d0b0ab5](https://github.com/davidban77/rastreo/commit/d0b0ab56d2f9999bb79407a1342848ca20616246))
* **core:** add TcpConnectProber as first concrete prober + docs/architecture.md ([#13](https://github.com/davidban77/rastreo/issues/13)) ([5c559c2](https://github.com/davidban77/rastreo/commit/5c559c235f7d2338bd2e787174391819f1f3176b))
* **kafka:** introduce KafkaFlushMode (PerRecord or Batched) ([#26](https://github.com/davidban77/rastreo/issues/26)) ([f1b0707](https://github.com/davidban77/rastreo/commit/f1b07072a41e73ef144edc7c096871640dfc2216))


### Bug Fixes

* **core:** validate fuser confidence knobs; derive PartialEq on Signal ([#17](https://github.com/davidban77/rastreo/issues/17)) ([b9e7624](https://github.com/davidban77/rastreo/commit/b9e762494b92dd48d72615327822c830f765021c))
* PR [#19](https://github.com/davidban77/rastreo/issues/19) follow-ups — MemorySink, CLI input validation, zero-records hint ([#20](https://github.com/davidban77/rastreo/issues/20)) ([cdbefd4](https://github.com/davidban77/rastreo/commit/cdbefd42aa59199513e1c4019c1aabb0af841fb4))
* **server:** redact 5xx error response bodies ([#22](https://github.com/davidban77/rastreo/issues/22)) ([12b732c](https://github.com/davidban77/rastreo/commit/12b732cd1a509e8ed8fa9ec2d69ef7bc41fda1cc))


### Documentation

* add CI guard, favicon, and subtle theme polish ([#29](https://github.com/davidban77/rastreo/issues/29)) ([9bfc527](https://github.com/davidban77/rastreo/commit/9bfc527e41459354368b4c1a63ce26bb4bc93431))
* add Get started and Discover content pages ([#25](https://github.com/davidban77/rastreo/issues/25)) ([bdca47e](https://github.com/davidban77/rastreo/commit/bdca47e83379a4cabec54d7e0e0b6acc8bcd378b))
* add Integrate and Deploy content pages ([#27](https://github.com/davidban77/rastreo/issues/27)) ([388ede5](https://github.com/davidban77/rastreo/commit/388ede5c26f79f2a25ef4d420e61ff8bdf1610ce))
* add Reference content pages and populate abbreviations ([#28](https://github.com/davidban77/rastreo/issues/28)) ([a974af5](https://github.com/davidban77/rastreo/commit/a974af55790fa3c9541ccb566ed0e6bb10f7992e))
* add the six-section information architecture ([#24](https://github.com/davidban77/rastreo/issues/24)) ([ea9db86](https://github.com/davidban77/rastreo/commit/ea9db86cdd5e1d4a9e9f19ee2f1b03ca8a79c93c))
* stand up the MkDocs Material site skeleton ([#23](https://github.com/davidban77/rastreo/issues/23)) ([e125a09](https://github.com/davidban77/rastreo/commit/e125a09dae5bd190108bae5d36f93efe82429eea))


### Miscellaneous

* stop tracking docs/architecture.md ([#14](https://github.com/davidban77/rastreo/issues/14)) ([88944ab](https://github.com/davidban77/rastreo/commit/88944ab8271651a327c7d566629f994af73d558d))

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
