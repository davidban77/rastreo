# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- DNS, CIDR, and IP-range resolution via a new `Resolver` trait and `HickoryResolver` default implementation. CIDR and range expansion enforce a configurable host limit (default 65,536) to avoid accidental large sweeps.

### Changed

- `Target::Cidr` now wraps `ipnet::IpNet` instead of `String`. CIDR strings are parsed at config load time, not at probe time.
- MSRV raised from 1.75 to 1.88 to take `hickory-resolver` 0.26.1, which clears the two open RUSTSEC advisories carried by the 0.25.x line.
