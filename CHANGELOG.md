# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.8.0](https://github.com/davidban77/rastreo/compare/v0.7.0...v0.8.0) (2026-07-19)


### Features

* **observability:** OTLP trace export over the scan pipeline ([#172](https://github.com/davidban77/rastreo/issues/172)) ([daa97e9](https://github.com/davidban77/rastreo/commit/daa97e933466eaee5d86702df60c0441ca52ed4f))
* **prober:** gNMI prober for gRPC device fingerprinting ([#174](https://github.com/davidban77/rastreo/issues/174)) ([03b4e57](https://github.com/davidban77/rastreo/commit/03b4e57a13023f455c722f1766b01b5f7c88e31c))
* **prober:** richer gNMI capture — encoding negotiation, path origin/keys, model org ([#175](https://github.com/davidban77/rastreo/issues/175)) ([0b7ac6e](https://github.com/davidban77/rastreo/commit/0b7ac6ea0bad389a99ad8dd4ef36ea747bf030a5))


### Bug Fixes

* **cli:** rastreo validate rejects invalid fuser config offline ([#161](https://github.com/davidban77/rastreo/issues/161)) ([88a98c8](https://github.com/davidban77/rastreo/commit/88a98c84d2f260abb524e832f1d3176963a81ea7))
* **container:** run under a hardened securityContext (permitted-only CAP_NET_RAW) ([#173](https://github.com/davidban77/rastreo/issues/173)) ([4dc5878](https://github.com/davidban77/rastreo/commit/4dc587847049b1853abb04b92ad8f21d834cdda8))


### CI/CD

* bump astral-sh/setup-uv from 5 to 7 ([#166](https://github.com/davidban77/rastreo/issues/166)) ([e122bce](https://github.com/davidban77/rastreo/commit/e122bceeebbe8ed2573d82927d366ffc70992fbd))


### Refactoring

* **fuser:** streaming-native ingest/finish Fuser contract ([#157](https://github.com/davidban77/rastreo/issues/157)) ([2b1747b](https://github.com/davidban77/rastreo/commit/2b1747b115e729a5cd7bf2b2689fb5c77392ba29))
* **scheduler:** run probers target-outer instead of prober-outer ([#159](https://github.com/davidban77/rastreo/issues/159)) ([397fabe](https://github.com/davidban77/rastreo/commit/397fabef9e4b5bfd876241ee08f3a95f22060ea9))

## [0.7.0](https://github.com/davidban77/rastreo/compare/v0.6.0...v0.7.0) (2026-07-16)


### Features

* **cli,server:** kind-derived probe-fault hints ([#122](https://github.com/davidban77/rastreo/issues/122)) ([425f468](https://github.com/davidban77/rastreo/commit/425f468af499d2e47b75c321f281487636c233ac))
* **cli:** add `catalog list` and `--dry-run-format json` ([#137](https://github.com/davidban77/rastreo/issues/137)) ([ffe3332](https://github.com/davidban77/rastreo/commit/ffe3332b700fddd017832be3e4b89904bcc2f47d))
* **cli:** offline `rastreo validate` + pure SinkConfig::validate ([#150](https://github.com/davidban77/rastreo/issues/150)) ([8986182](https://github.com/davidban77/rastreo/commit/8986182e59e892eb71ccc17c081a4090ec7df4cf))
* **core:** add DiscoveryPlan, the structured dry-run scan plan ([#132](https://github.com/davidban77/rastreo/issues/132)) ([56abc93](https://github.com/davidban77/rastreo/commit/56abc9376d51bfa53d087d02fcb522db365df27a))
* **prober:** capture TLS version, cipher suite, and ALPN signals ([#153](https://github.com/davidban77/rastreo/issues/153)) ([d2aa830](https://github.com/davidban77/rastreo/commit/d2aa8302d17986eccd775051f953737cbfcbcaf3))
* **prober:** opt-in retransmit (retries) for connectionless probers ([#128](https://github.com/davidban77/rastreo/issues/128)) ([af806cd](https://github.com/davidban77/rastreo/commit/af806cd6f18b92aa65bff4b67ce4501d950b162e))
* **prober:** typed probe faults carried as data on the outcome ([#121](https://github.com/davidban77/rastreo/issues/121)) ([c0bd10c](https://github.com/davidban77/rastreo/commit/c0bd10cb50c84c3950a19f66bc260323ed3acb7a))
* **scheduler:** probes-per-second pacing and honest concurrency naming ([#125](https://github.com/davidban77/rastreo/issues/125)) ([b958eda](https://github.com/davidban77/rastreo/commit/b958eda0be0c564b79b4b12745b4eedf35f03f72))
* **server:** 429 admission at the inflight cap, shutdown hard-timeout, env trims ([#134](https://github.com/davidban77/rastreo/issues/134)) ([5ac715e](https://github.com/davidban77/rastreo/commit/5ac715ecfc41b63a9c56bb98175f8a34c80cde71))
* **server:** bearer-token auth on POST /scans, secure by default ([#126](https://github.com/davidban77/rastreo/issues/126)) ([0c0d810](https://github.com/davidban77/rastreo/commit/0c0d8101e299eb899bc2dc9b86c51af5d4db6fc0))
* **server:** bound the POST /scans response size to prevent OOM ([#136](https://github.com/davidban77/rastreo/issues/136)) ([71d0d3a](https://github.com/davidban77/rastreo/commit/71d0d3a7f9e8be92bb3e77771ac69e68ca4247f1))
* **server:** POST /scans?dry_run=true returns the discovery plan ([#133](https://github.com/davidban77/rastreo/issues/133)) ([ecc4dcd](https://github.com/davidban77/rastreo/commit/ecc4dcde3d62c59ee74ef509657a3eab861f855c))
* **server:** target allow-list, aggregate host cap, and body limit on POST /scans ([#127](https://github.com/davidban77/rastreo/issues/127)) ([eca1153](https://github.com/davidban77/rastreo/commit/eca115374fe8c572dcac9174fe0e4d36d1efa02a))
* **sink:** Kafka TLS + SASL authentication ([#148](https://github.com/davidban77/rastreo/issues/148)) ([fa5a55f](https://github.com/davidban77/rastreo/commit/fa5a55fd133ae83242450687d08e9b3f0b80dac7))
* **sink:** retry the primary produce/publish before the DLQ ([#149](https://github.com/davidban77/rastreo/issues/149)) ([57fd32d](https://github.com/davidban77/rastreo/commit/57fd32d9f71ae83d7dbdf4f89f19cb59c07fbbfd))
* **sink:** typed sink errors carried at the failure site ([#124](https://github.com/davidban77/rastreo/issues/124)) ([97ad02a](https://github.com/davidban77/rastreo/commit/97ad02a559ceeb468a66bac0d965cdd33915e721))


### Bug Fixes

* **cli:** exit non-zero when any --file scenario fails ([#138](https://github.com/davidban77/rastreo/issues/138)) ([f3eca52](https://github.com/davidban77/rastreo/commit/f3eca524f4623793e66ee486c031ab2b7ce11343))
* **prober:** SSH prober offers legacy crypto to fingerprint legacy gear ([#152](https://github.com/davidban77/rastreo/issues/152)) ([12ca76c](https://github.com/davidban77/rastreo/commit/12ca76c33b790e5937123461285517cdffebb006))
* **prober:** unify the reachability contract across the prober fleet ([#119](https://github.com/davidban77/rastreo/issues/119)) ([5a04bba](https://github.com/davidban77/rastreo/commit/5a04bba24e44c630681788f47711cbeaedeb6bfd))
* **server:** abort in-flight probes when a scan is dropped, record timed-out scans ([#135](https://github.com/davidban77/rastreo/issues/135)) ([3d6b2e2](https://github.com/davidban77/rastreo/commit/3d6b2e24027c3addd9b510a7c1c81b5a809fa87c))
* **sink:** bound the Kafka broker connect + real-broker integration tests ([#151](https://github.com/davidban77/rastreo/issues/151)) ([5268def](https://github.com/davidban77/rastreo/commit/5268def246974f21acc2d431679caa77499c75eb))
* **sink:** one transport message per DeviceRecord ([#123](https://github.com/davidban77/rastreo/issues/123)) ([616c165](https://github.com/davidban77/rastreo/commit/616c165e8f0297377076ac7afd1ee25064fafb9c))


### Documentation

* **deploy:** de-pin stale chart/image versions, auto-bump one reference ([#140](https://github.com/davidban77/rastreo/issues/140)) ([d0fe897](https://github.com/davidban77/rastreo/commit/d0fe897d81272cc6fb711d9f531be7a517f78a22))
* **reference:** add a consolidated configuration reference page ([#143](https://github.com/davidban77/rastreo/issues/143)) ([55c6928](https://github.com/davidban77/rastreo/commit/55c6928f77d0f10b8e52b5bb4dbfe476a44a2819))


### Miscellaneous

* **deps:** adopt schemars 1.x; published schemas move to draft 2020-12 ([#145](https://github.com/davidban77/rastreo/issues/145)) ([19ad98d](https://github.com/davidban77/rastreo/commit/19ad98d4d98e6aa0dfca9e677935b0e4afb39f3f))
* drop false CSV claim, coerce Helm numeric env, doc catalog search order ([#129](https://github.com/davidban77/rastreo/issues/129)) ([5bbd26f](https://github.com/davidban77/rastreo/commit/5bbd26fbd5fa1cc5bd4bc5eaa6faa3d74a80dac7))
* **schema:** put dlq-envelope on draft 2020-12 for a consistent published set ([#146](https://github.com/davidban77/rastreo/issues/146)) ([bc24658](https://github.com/davidban77/rastreo/commit/bc24658cbf96aae7eb9ad886d4f6b38cb7eb488f))


### CI/CD

* bump actions/checkout from 4 to 7 ([#71](https://github.com/davidban77/rastreo/issues/71)) ([2b20158](https://github.com/davidban77/rastreo/commit/2b20158396ee4b35bdafa3d2a80e8d545db57faf))
* bump nats from 2.11-alpine to 2.14-alpine ([#113](https://github.com/davidban77/rastreo/issues/113)) ([ebc77f3](https://github.com/davidban77/rastreo/commit/ebc77f3d3c7ec0fef840da673999d0e7f3ad335b))
* bump peter-evans/create-pull-request from 7 to 8 ([#72](https://github.com/davidban77/rastreo/issues/72)) ([92a4c06](https://github.com/davidban77/rastreo/commit/92a4c069fe1c81a617c97b276e9ec7e37a7a7fad))
* **consumers:** run the reference consumers in CI and validate the published schema ([#147](https://github.com/davidban77/rastreo/issues/147)) ([3286837](https://github.com/davidban77/rastreo/commit/32868378ab73aa2c8e3ec6711d3aba26f5643dea))
* enforce feature isolation and a real MSRV ([#144](https://github.com/davidban77/rastreo/issues/144)) ([e62b77d](https://github.com/davidban77/rastreo/commit/e62b77d2781e90e27bfc579057d34eb6d5ad54fd))


### Refactoring

* **core:** share OTLP/tracing bootstrap behind a core `otlp` feature ([#141](https://github.com/davidban77/rastreo/issues/141)) ([d0527b0](https://github.com/davidban77/rastreo/commit/d0527b02a67fa49742b32bc26df27bf80b6f965e))
* **core:** share ScanMetadata across a scan's records via Arc ([#131](https://github.com/davidban77/rastreo/issues/131)) ([9f028ff](https://github.com/davidban77/rastreo/commit/9f028ffaf33324966c61990f343668b251a94682))
* **prober:** share one link-layer engine between ARP and NDP ([#156](https://github.com/davidban77/rastreo/issues/156)) ([5877c96](https://github.com/davidban77/rastreo/commit/5877c9696c9d3697edd73521dcc0f87110198d20))
* **server:** generate metrics from a single descriptor table ([#142](https://github.com/davidban77/rastreo/issues/142)) ([6b2ea24](https://github.com/davidban77/rastreo/commit/6b2ea24c63b99014c67c3199d6679323d8efd811))
* **sink:** rename NATS sink config to mirror the Kafka sink ([#130](https://github.com/davidban77/rastreo/issues/130)) ([b331e08](https://github.com/davidban77/rastreo/commit/b331e0875e6cc888beabf191fcf8c662bfc7d171))

## [0.6.0](https://github.com/davidban77/rastreo/compare/v0.5.0...v0.6.0) (2026-07-11)


### Features

* **classifier:** role rules classifier + 5 baked port heuristics ([#89](https://github.com/davidban77/rastreo/issues/89)) ([b5ea57f](https://github.com/davidban77/rastreo/commit/b5ea57f19011502febfa2a3b4ecb90803ee1f4a1))
* **classifier:** rules-based platform classifier + os_version field ([#88](https://github.com/davidban77/rastreo/issues/88)) ([7dbe50b](https://github.com/davidban77/rastreo/commit/7dbe50b53a7514324443f8f2c94306225d4ce956))
* **classifier:** three-dimensional platform / server / SSH split ([#94](https://github.com/davidban77/rastreo/issues/94)) ([fd26c12](https://github.com/davidban77/rastreo/commit/fd26c1259d387d2467d02edcafc0d1c99ab37387))
* **cli:** add --dry-run flag to rastreo discover ([#106](https://github.com/davidban77/rastreo/issues/106)) ([ab79332](https://github.com/davidban77/rastreo/commit/ab79332d13bcde6dd701408506c3e5f42db94267))
* **cli:** catalog references ([@name](https://github.com/name)) for reusable scenarios ([#110](https://github.com/davidban77/rastreo/issues/110)) ([e1f767f](https://github.com/davidban77/rastreo/commit/e1f767fab0776f9f68aaceae48b77af2571cd3ae))
* **cli:** runtime probe-error hints for common failure modes ([#108](https://github.com/davidban77/rastreo/issues/108)) ([8e5a7bd](https://github.com/davidban77/rastreo/commit/8e5a7bd9649f68a1e45ff0e1b31d3884fcc51052))
* **config:** env-var and file-tag secret expansion at scenario load ([#95](https://github.com/davidban77/rastreo/issues/95)) ([b350a68](https://github.com/davidban77/rastreo/commit/b350a685a26f0f9aa4c5984db565d0264cef352c))
* **core:** add versioned schema surface to DeviceRecord ([#74](https://github.com/davidban77/rastreo/issues/74)) ([095833a](https://github.com/davidban77/rastreo/commit/095833a601e3cc095ea2f6c68820d84a272ad809))
* **examples:** Infrahub reference consumer for DeviceRecord ingest ([#93](https://github.com/davidban77/rastreo/issues/93)) ([d22a67d](https://github.com/davidban77/rastreo/commit/d22a67d1c9800bcaf8a208201e5bd82e0748a78b))
* **examples:** Nautobot reference consumer for DeviceRecord ingest ([#92](https://github.com/davidban77/rastreo/issues/92)) ([a8aa95d](https://github.com/davidban77/rastreo/commit/a8aa95d3f15ee0d90606976f9b72366c4cbedcfd))
* **examples:** NetBox reference consumer for DeviceRecord ingest ([#91](https://github.com/davidban77/rastreo/issues/91)) ([26c99b6](https://github.com/davidban77/rastreo/commit/26c99b65d75a98e3c1112d6fddd4bd7a56af83e7))
* **fuser:** consume SshHostKey as third identity signal + cli_ssh UAT ([#81](https://github.com/davidban77/rastreo/issues/81)) ([7656387](https://github.com/davidban77/rastreo/commit/765638707a8718dfc2130eb36b364c35244f2c12))
* **fuser:** correlate multi-IP devices via shared identity signals ([#75](https://github.com/davidban77/rastreo/issues/75)) ([29453c9](https://github.com/davidban77/rastreo/commit/29453c973b12b327733cb46e86ee86bce9f88984))
* **helm:** Grafana dashboard + PrometheusRule alerts ([#100](https://github.com/davidban77/rastreo/issues/100)) ([2b82869](https://github.com/davidban77/rastreo/commit/2b828698be03a965cdf975caa0bfe8687e1a159c))
* **lab:** Phase 5 — real network validation harness (SR Linux + 3 SoT stacks) ([#118](https://github.com/davidban77/rastreo/issues/118)) ([1ed3884](https://github.com/davidban77/rastreo/commit/1ed38845eb2c4782d73755c91b5bb2c1d4a08135))
* **logging:** --log-format text|json flag on both binaries ([#97](https://github.com/davidban77/rastreo/issues/97)) ([ff358c9](https://github.com/davidban77/rastreo/commit/ff358c9c6a7af07a6d93a7f04e6077f669f901cc))
* **observability:** enrich metric labels + fill dashboard and alert gaps ([#103](https://github.com/davidban77/rastreo/issues/103)) ([eac6ef6](https://github.com/davidban77/rastreo/commit/eac6ef6aed171dc66286726ae76f3c9820c80053))
* **otlp:** opt-in OTLP export for metrics + logs behind `otlp` feature ([#101](https://github.com/davidban77/rastreo/issues/101)) ([af6d5ec](https://github.com/davidban77/rastreo/commit/af6d5ec91884fd201b10bc0f7502b611712f2a0f))
* **phase2-prep:** Classifier stage + IdentityFuser pair_weight iterator ([#87](https://github.com/davidban77/rastreo/issues/87)) ([4355213](https://github.com/davidban77/rastreo/commit/435521335d64817deae5c8a68b651b8a27308115))
* **prober:** add ICMP echo prober behind the icmp feature ([#83](https://github.com/davidban77/rastreo/issues/83)) ([56669c3](https://github.com/davidban77/rastreo/commit/56669c396690cef323162f38816d43db23730d14))
* **prober:** add reverse DNS prober ([#85](https://github.com/davidban77/rastreo/issues/85)) ([f3ded80](https://github.com/davidban77/rastreo/commit/f3ded80aadafd9a30814a038b268703a0f267601))
* **prober:** add SSH prober behind the ssh feature ([#80](https://github.com/davidban77/rastreo/issues/80)) ([5b5e70e](https://github.com/davidban77/rastreo/commit/5b5e70e0b3eaef3f4d19fd78b0549e1394bf6483))
* **prober:** add TLS handshake prober behind the tls feature ([#84](https://github.com/davidban77/rastreo/issues/84)) ([a6c6210](https://github.com/davidban77/rastreo/commit/a6c6210c32bf9cf5a89eb489988f6dc4d60f3400))
* **schema:** render v1 JSON Schemas to docs pages and ship AsyncAPI spec ([#76](https://github.com/davidban77/rastreo/issues/76)) ([c04904e](https://github.com/davidban77/rastreo/commit/c04904e5250a5b301909c543faec5a020b0251d8))
* **schemas:** publish JSON Schemas at davidban77.github.io/rastreo/schemas/ ([#107](https://github.com/davidban77/rastreo/issues/107)) ([3b58f0e](https://github.com/davidban77/rastreo/commit/3b58f0e6a686ae3396f343b3fc81f8972004a380))
* **server:** dual-write records to server-configured sink ([#105](https://github.com/davidban77/rastreo/issues/105)) ([e9e1e2e](https://github.com/davidban77/rastreo/commit/e9e1e2ed3069c561fbab5fa8c819972245bf7c67))
* **server:** real /readyz sink reachability probe ([#104](https://github.com/davidban77/rastreo/issues/104)) ([2f4e8ad](https://github.com/davidban77/rastreo/commit/2f4e8ad0452ca4bf37121f27c441ff3027e2f202))
* **server:** split /health into /healthz + /readyz ([#96](https://github.com/davidban77/rastreo/issues/96)) ([ba6fc45](https://github.com/davidban77/rastreo/commit/ba6fc455b80eb08d4ac928162813b30e4c58dd2f))
* **sink/kafka:** dead-letter queue on primary produce failure ([#98](https://github.com/davidban77/rastreo/issues/98)) ([a2f1284](https://github.com/davidban77/rastreo/commit/a2f1284a0c73840374c3d30cdb08f149193edb6a))
* **sink/nats:** dead-letter queue on publish + ack failure surfaces ([#99](https://github.com/davidban77/rastreo/issues/99)) ([c011112](https://github.com/davidban77/rastreo/commit/c01111232da671ecf9048f03d0ef7437b1333958))
* **sink:** add NATS JetStream sink ([#77](https://github.com/davidban77/rastreo/issues/77)) ([e6cc69d](https://github.com/davidban77/rastreo/commit/e6cc69d6aaed8fd1da51b64fdf9a804ae7bb12d5))


### Bug Fixes

* **schema:** stabilize http.user_agent schema default across release bumps ([#90](https://github.com/davidban77/rastreo/issues/90)) ([e5f46cb](https://github.com/davidban77/rastreo/commit/e5f46cb4b4c70b1a77052774118c370fbeb35789))
* **server:** graceful probe-task shutdown + sink-config-path trim ([#111](https://github.com/davidban77/rastreo/issues/111)) ([b06d52a](https://github.com/davidban77/rastreo/commit/b06d52af3d9e21c1280b0b6b3f4913b764068445))
* **server:** sink_type="unknown" surfaces broken sink config to alerts ([#112](https://github.com/davidban77/rastreo/issues/112)) ([7a0f3b7](https://github.com/davidban77/rastreo/commit/7a0f3b7b54dc8c8d2a5cbef51a12bfa2496949fb))
* **sink/kafka:** probe covers dead-letter partition when configured ([#109](https://github.com/davidban77/rastreo/issues/109)) ([c5dadd9](https://github.com/davidban77/rastreo/commit/c5dadd90978cb6ec54b9d793eeda8d1d106bee04))


### Documentation

* **claude:** refresh rastreo-core module tree + features table ([#82](https://github.com/davidban77/rastreo/issues/82)) ([3fbe847](https://github.com/davidban77/rastreo/commit/3fbe8472ada161496b86f84e3c621200884c5742))


### Miscellaneous

* **ci:** expand dependabot ignore list for coupled deps ([#69](https://github.com/davidban77/rastreo/issues/69)) ([3d2b51a](https://github.com/davidban77/rastreo/commit/3d2b51ad6aa41d7c41a47bde68ac001c4fe36ec2))
* **phase-1-close:** CLI hints + CI matrix + docs freshness ([#86](https://github.com/davidban77/rastreo/issues/86)) ([fa60276](https://github.com/davidban77/rastreo/commit/fa602767ffbad0c232b747a90bdc603f39fc6679))
* **phase-3-close:** docs reconciliation, OTLP config dedup, distroless fix ([#102](https://github.com/davidban77/rastreo/issues/102)) ([7886bfc](https://github.com/davidban77/rastreo/commit/7886bfc7ea332067fe199aac2f3adf985ab004de))


### Refactoring

* **fuser:** rename CorrelationFuser to IdentityFuser ([#78](https://github.com/davidban77/rastreo/issues/78)) ([4834e72](https://github.com/davidban77/rastreo/commit/4834e723c6f248af776ef82cb4f233c0616b24e9))
* **model:** AltIp object for DeviceRecord.alt_ips ([#79](https://github.com/davidban77/rastreo/issues/79)) ([c92863f](https://github.com/davidban77/rastreo/commit/c92863fc05ffc308fda76fab4269391d06de7944))

## [0.5.0](https://github.com/davidban77/rastreo/compare/v0.4.0...v0.5.0) (2026-07-05)


### Features

* **cli:** load scenarios from YAML files via --file ([#64](https://github.com/davidban77/rastreo/issues/64)) ([1835527](https://github.com/davidban77/rastreo/commit/183552744e75020dd6ea32ff6bf3509bf3c02304))


### Documentation

* **readme:** add link to hosted documentation site ([#56](https://github.com/davidban77/rastreo/issues/56)) ([db79d01](https://github.com/davidban77/rastreo/commit/db79d01b17e9edc0c310bfdcfc78a565d37de0fc))


### Miscellaneous

* **ci:** monthly cron to refresh bundled OUI snapshot ([#67](https://github.com/davidban77/rastreo/issues/67)) ([31ce8aa](https://github.com/davidban77/rastreo/commit/31ce8aa18d337b3435d5befdb80964cbefbfe9a3))


### CI/CD

* bump azure/setup-helm from 4 to 5 ([#58](https://github.com/davidban77/rastreo/issues/58)) ([56f735c](https://github.com/davidban77/rastreo/commit/56f735cc4e1c83af5612ee3edf442cda6f0a804d))


### Refactoring

* **cli:** address follow-ups from PR [#64](https://github.com/davidban77/rastreo/issues/64) review ([#65](https://github.com/davidban77/rastreo/issues/65)) ([99e4c32](https://github.com/davidban77/rastreo/commit/99e4c3239e46b72b30cef409565105b71055f15b))
* **fuser:** tighten OUI enrichment internals ([#66](https://github.com/davidban77/rastreo/issues/66)) ([0e0f7aa](https://github.com/davidban77/rastreo/commit/0e0f7aa5cdf38672f51650bbd9b6315eb5854434))

## [0.4.0](https://github.com/davidban77/rastreo/compare/v0.3.0...v0.4.0) (2026-07-04)


### Features

* **fuser:** add OUI vendor enrichment behind oui feature ([#55](https://github.com/davidban77/rastreo/issues/55)) ([ebca82f](https://github.com/davidban77/rastreo/commit/ebca82f105a9a7fd86a87199ee3449e80eec7c5b))
* **prober:** add ARP and NDP link-layer neighbor probers ([#54](https://github.com/davidban77/rastreo/issues/54)) ([cb47293](https://github.com/davidban77/rastreo/commit/cb472937702641603eac3557ac30c4034927aa7a))
* **prober:** add DNS prober against target-as-DNS-server ([#50](https://github.com/davidban77/rastreo/issues/50)) ([3433db0](https://github.com/davidban77/rastreo/commit/3433db0f69d1aa34448d5696484f1f40f532c00c))
* **prober:** add HTTP prober behind the http Cargo feature ([#47](https://github.com/davidban77/rastreo/issues/47)) ([19af93e](https://github.com/davidban77/rastreo/commit/19af93e72062254d4ace847a7ba73c73a51fde18))
* **prober:** add SNMP prober for v1 and v2c behind snmp feature ([#52](https://github.com/davidban77/rastreo/issues/52)) ([f02a4e1](https://github.com/davidban77/rastreo/commit/f02a4e1537b0a453849768c259a945d88938e3fe))
* **prober:** add SNMPv3 with USM authentication and privacy ([#53](https://github.com/davidban77/rastreo/issues/53)) ([56c4ad7](https://github.com/davidban77/rastreo/commit/56c4ad7d167b9edeac852dea021e0fd894635340))
* **prober:** add UDP prober with NTP, SIP, memcached, and STUN protocols ([#51](https://github.com/davidban77/rastreo/issues/51)) ([fa33729](https://github.com/davidban77/rastreo/commit/fa337295e1c6f2829304f870b8b84e47bd62b04c))


### Refactoring

* **prober:** drop Option wrappers on HTTP config, document conventions ([#49](https://github.com/davidban77/rastreo/issues/49)) ([ab1cc85](https://github.com/davidban77/rastreo/commit/ab1cc85629891cdaec3e57f451cb9274eb837cdd))

## [0.3.0](https://github.com/davidban77/rastreo/compare/v0.2.0...v0.3.0) (2026-07-01)


### Features

* **ci:** publish the Helm chart to ghcr.io on tag push ([#45](https://github.com/davidban77/rastreo/issues/45)) ([0853689](https://github.com/davidban77/rastreo/commit/08536894511a219198620014a0dd8ef2c02d97fc))
* **install:** add install.sh curl-pipe installer ([#46](https://github.com/davidban77/rastreo/issues/46)) ([1d458bb](https://github.com/davidban77/rastreo/commit/1d458bb99bbb40d684962e74b2fe5c44cbd4472a))
* **pipeline:** graceful sink flush on SIGINT/SIGTERM ([#42](https://github.com/davidban77/rastreo/issues/42)) ([0666d30](https://github.com/davidban77/rastreo/commit/0666d30df7c8ec5ed74b1b2bdf8b63c431458e8b))
* **server:** expose Prometheus metrics at GET /metrics ([#44](https://github.com/davidban77/rastreo/issues/44)) ([639fbd4](https://github.com/davidban77/rastreo/commit/639fbd43f8bb8d0e34065909853235cada63937f))

## [0.2.0](https://github.com/davidban77/rastreo/compare/v0.1.0...v0.2.0) (2026-06-28)


### Features

* **ci:** add crates.io publish workflow ([#32](https://github.com/davidban77/rastreo/issues/32)) ([f7da1b8](https://github.com/davidban77/rastreo/commit/f7da1b8c8c5655dd71a7ea52171fdcc24510e326))
* **ci:** add live-infra UAT gate against the compose stack ([#33](https://github.com/davidban77/rastreo/issues/33)) ([238a1df](https://github.com/davidban77/rastreo/commit/238a1dfe9536fd787aba58f5fc4f27393dadeb23))
* **ci:** add multi-arch release workflow ([#30](https://github.com/davidban77/rastreo/issues/30)) ([4bb6306](https://github.com/davidban77/rastreo/commit/4bb6306677324ce93895be4c839b3715383cbe79))


### Documentation

* add brand assets, README badges, and docs home hero ([#34](https://github.com/davidban77/rastreo/issues/34)) ([d36cbf7](https://github.com/davidban77/rastreo/commit/d36cbf740eb339d179f6c3c9de937792c8c75ae4))


### Miscellaneous

* add community scaffolding and editorconfig ([#35](https://github.com/davidban77/rastreo/issues/35)) ([a93c92a](https://github.com/davidban77/rastreo/commit/a93c92af9d9a9f416044eff8783e0237528bbc97))


### CI/CD

* bump actions/cache from 5 to 6 ([#38](https://github.com/davidban77/rastreo/issues/38)) ([20753f1](https://github.com/davidban77/rastreo/commit/20753f1216e895c71af7821ea7045f5555e229cf))
* bump actions/checkout from 6 to 7 ([#39](https://github.com/davidban77/rastreo/issues/39)) ([7f1af73](https://github.com/davidban77/rastreo/commit/7f1af7358738d9b51e51772a9cb1a37bd462be65))
* bump actions/upload-artifact from 4 to 7 ([#36](https://github.com/davidban77/rastreo/issues/36)) ([6ff35ab](https://github.com/davidban77/rastreo/commit/6ff35abea545f162e951e015da880a3dd9146fb5))
* bump apache/kafka from 4.2.0 to 4.3.1 ([#37](https://github.com/davidban77/rastreo/issues/37)) ([0a9f652](https://github.com/davidban77/rastreo/commit/0a9f6529791e1b953f89be38530f8e13d67a480f))

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
