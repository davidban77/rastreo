---
description: Common failures when running rastreo discover or rastreo-server — unreachable targets, DNS issues, Kafka connectivity, low confidence scores, and Kafka batching surprises.
---

# Troubleshooting

The page below covers the failures that come up most often when records do not land where you expect. Each section names the symptom, the likely cause, and what to check.

## Zero records emitted

The end-of-run summary on stderr reads `records_emitted=0`, even though `probe_attempts` is non-zero. The CLI also prints a hint that no probe reached an open port.

Common causes:

- The target is unreachable from the host running `rastreo discover` (no route, firewall blocks the connect, or the host is offline).
- The port is closed on a reachable target. A host that answers ICMP `echo` can still refuse TCP on the port you probed.
- A `--target` CIDR or range expanded to addresses that are not used in the segment. Most of a `/24` is normally unused.

Verify the target answers TCP from the host running the scan: `nc -vz <ip> <port>` or `curl -v telnet://<ip>:<port>`. If `nc` succeeds and rastreo still emits zero records, increase verbosity with `-v` or `-vv` to see per-probe outcomes.

## DNS resolution failures

A scan against a hostname fails with `ResolverError::DnsNoRecords` (the name resolved but returned no `A` / `AAAA` records) or `ResolverError::DnsLookupFailed` (the lookup itself failed — system resolver unreachable, timeout, or refused). `rastreo-server` maps these to `400 Bad Request` and `503 Service Unavailable` respectively.

Check `/etc/resolv.conf` on the host running the scan. When the scan runs inside a container, the resolver inside the container is rarely the host's resolver — Docker rewrites `resolv.conf` to point at the embedded resolver. If the embedded resolver can not reach your internal DNS, hostnames will not resolve. The fix is to add the right upstreams to the container's resolver config (`--dns` flag on `docker run`, or `dns:` in `docker-compose.yml`).

## Kafka broker unreachable

The Kafka sink fails to start with `failed to connect to broker(s)` or a partition-client error. The most common cause is a `--brokers` value that does not resolve from the host running rastreo.

The bundled compose stack uses a dual-listener Kafka config: from the host, brokers advertise as `localhost:9092`; from inside the `rastreo-net` Docker network, they advertise as `kafka:29092`. A CLI running inside a container on the same network must point at `kafka:29092`; a CLI on the host points at `localhost:9092`. Mixing the two is the usual cause of "broker not reachable" failures.

```bash
# from the host:
rastreo discover --sink kafka --brokers localhost:9092 --topic rastreo.devices ...

# from a container on rastreo-net:
rastreo discover --sink kafka --brokers kafka:29092 --topic rastreo.devices ...
```

## Unexpected low confidence scores

Every record arrives with `confidence: 0.2`, no matter how many probes ran against it. This is expected output from the default `DirectFuser`: `confidence = confidence_baseline + (signals_observed * confidence_per_signal)`, where the defaults are `confidence_baseline = 0.1` and `confidence_per_signal = 0.1`. One TCP-connect signal yields `0.2`.

To tune the curve, set `fuser.confidence_baseline` and `fuser.confidence_per_signal` on the scenario JSON sent to `rastreo-server`'s `POST /scans`. The CLI does not expose these directly today.

```json
{
  "fuser": {
    "type": "direct",
    "confidence_baseline": 0.3,
    "confidence_per_signal": 0.2
  }
}
```

## Records do not appear on the Kafka topic

You expect records on the topic during a scan, but the topic shows none until the scan ends. This is the default behaviour of `Batched` mode: the sink buffers NDJSON bytes until the threshold (default 64 KiB) is reached, then produces one Kafka message. For short scans where the buffer never fills, every record lands in the single final message produced at `flush()` when the scan ends.

The fix is `--kafka-flush-per-record`, which produces one Kafka message per record. Records appear on the topic in real time, at the cost of higher per-record broker overhead. See [Kafka](kafka.md#choosing-a-mode) for the trade-off.

## See also

- [Kafka](kafka.md) — the wire contract and flush-mode reference.
- [CLI](../discover/cli.md) — every flag and its default.
