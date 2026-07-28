# Lab validation — Nokia SR Linux

Real-network validation harness for rastreo. Deploys a Nokia SR Linux topology in [containerlab](https://containerlab.dev/), runs rastreo scans against it, and (in later slices) reconciles the emitted DeviceRecords into a real SoT (Nautobot / NetBox / Infrahub).

Unlike the compose-based Live Infra UAT — which validates TCP-connect against nginx targets — this harness exercises the full prober matrix (SNMP, SSH, HTTPS, NETCONF, LLDP, BGP peer-count) against a real network OS image.

## Prerequisites

- macOS on Apple Silicon (arm64) with [OrbStack](https://orbstack.dev/) installed, OR a Linux host with Docker
- On macOS, an OrbStack Linux VM: `orb create ubuntu clab`
- Inside the VM: containerlab and Docker
  ```
  orb -m clab bash -c "curl -sL https://containerlab.dev/setup | sudo -E bash -s all"
  orb -m clab sudo apt-get install -y docker.io
  ```
- SR Linux image (arm64-native, no emulation): `sudo docker pull ghcr.io/nokia/srlinux:latest`

## Topology

Two SR Linux nodes on the `rastreo-lab` bridge network (`198.51.100.0/24`):

```
                 rastreo-lab (198.51.100.0/24)
                            │
               ┌────────────┴────────────┐
               │                         │
        ┌──────┴──────┐           ┌──────┴──────┐
        │   srl-01    │           │   srl-02    │
        │ .11         │◄─e1-1─────┤ .12         │
        └─────────────┘           └─────────────┘
```

Single point-to-point link between `e1-1` on both nodes for LLDP + BGP.

## Deploy

From your Mac (files auto-mount into the VM at the same path):

```
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux && sudo containerlab deploy -t lab.clab.yml"
```

Boot takes ~60s. Verify SSH is listening:

```
orb -m clab bash -c "nc -zv 198.51.100.11 22 && nc -zv 198.51.100.12 22"
```

## Rastreo image

Two images available on `ghcr.io/davidban77/rastreo`:

- `:latest` (or `:v0.5.0`, `:v0.6.0`, …) — pinned to the most recent tagged release.
- `:main` — rolling build that tracks the `main` branch. Best for lab iteration when you need features that haven't been tagged yet (e.g. the SSH prober before v0.6.0).

Both variants have an `-otlp` sibling with OpenTelemetry export enabled (`:main-otlp`, `:latest-otlp`). All variants ship the same prober set: `kafka`, `http`, `snmp`, `arp`, `ndp`, `oui`, `nats`, `ssh`, `icmp`, `tls`, `gnmi`.

For fully local iteration against uncommitted changes, build inside the VM:

```
orb -m clab bash -c "cd /Users/$USER/projects/rastreo && sudo docker build \
  --build-arg TARGETARCH=arm64 \
  --build-arg FEATURES=kafka,http,snmp,arp,ndp,oui,nats,ssh,icmp,tls,gnmi \
  -t rastreo:lab ."
```

## Run a scan

Rastreo runs as a container on the same `rastreo-lab` bridge network (so it can reach the mgmt IPs directly):

```
orb -m clab bash -c "sudo docker run --rm --entrypoint /rastreo --network rastreo-lab \
  ghcr.io/davidban77/rastreo:main \
  discover --target 198.51.100.11 --target 198.51.100.12 -p 22 --sink stdout"
```

Expected output (one `DeviceRecord` per node):

```
{"identity_key":"ip:198.51.100.11","mgmt_ip":"198.51.100.11","signals":[{"OpenPort":22}], ...}
{"identity_key":"ip:198.51.100.12","mgmt_ip":"198.51.100.12","signals":[{"OpenPort":22}], ...}
■ discover  completed in 8ms | hosts: 2 | records: 2 | probes: 2 | faults: 0 | sink: stdout
```

## Teardown

```
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux && sudo containerlab destroy -t lab.clab.yml"
```

## SR Linux SNMP surface

Per-platform reality: SR Linux 26.3 exposes a **narrower SNMP MIB set** than a Cisco/Juniper platform. Available (from `sysORTable`, 1.3.6.1.2.1.1.9):

- `SNMPv2-MIB` (sysDescr, sysObjectId, sysName, sysUpTime, sysLocation, sysContact)
- `IF-MIB` + IF-MIB extension (1.3.6.1.2.1.2.2, 31.1.1, 31.1.2)
- `IP-MIB` (1.3.6.1.2.1.4.35)
- `Ethernet-like MIB` (1.3.6.1.2.1.10.7.10)
- `HOST-RESOURCES-MIB` (1.3.6.1.2.1.25.2.3)
- `LLDP-MIB` (0.8802.1.1.2.1.3.7 and 0.8802.1.1.2.1.4.1)
- Nokia enterprise MIB tree (1.3.6.1.4.1.6527.*)

Not exposed: `BGP4-MIB` (1.3.6.1.2.1.15). BGP peer signals for SR Linux need to come from gNMI or SSH command-parse — not SNMP. This is a real-world data point the harness surfaces that a synthetic-target test cannot.

## Scope

**Slice 1** — 2-node topology, default boot, TCP-connect verified. Baseline `OpenPort` signal.

**Slice 2a** — SNMP community rename to `rastreo-lab`. TCP + SNMP scenarios. First real Nokia vendor fingerprint (`SnmpSysObjectId: 1.3.6.1.4.1.6527.1.20.26`).

**Slice 2b** — HTTP scenario against JSON-RPC (fingerprints gunicorn banner). SSH scenario shipped but blocked pending full-features image.

**Slice 2c** — Per-node startup configs with e-BGP (65001 ↔ 65002) over point-to-point 10.1.1.0/30, LLDP on `e1-1`. BGP session establishes; interface + LLDP + IF-MIB signals now available to the SNMP prober.

**Slice 2d (this commit)** — Rolling `:main` docker tag published by `.github/workflows/docker-main.yml` on every push to `main`, unblocking use of features that haven't been tagged yet. SSH prober now captures OpenSSH banner + ED25519 host key from real SR Linux nodes.

**Slice 3a** — `scripts/lab_validation.py` harness + golden NDJSON snapshots for all six stdout scenarios. Regression pass on `rastreo:lab`.

**Slice 3b** — Three SoT stacks + shared Kafka broker + per-SoT bootstrap scripts + `--sot` flag on the harness. `kafka-scan.yml` publishes to Kafka; the target SoT's consumer reconciles; the harness polls the SoT API and asserts 2 devices reconciled.

## SoT reconciliation

Three SoT stacks are shipped as sibling compose files. All three can run simultaneously against the same containerlab topology — they only conflict on host ports (Nautobot 8080, NetBox 8081, Infrahub 8082).

| SoT | Host port | Compose path | Bootstrap |
|-----|-----------|--------------|-----------|
| Nautobot | 8080 | `nautobot/docker-compose.yml` | `nautobot/bootstrap.sh` |
| NetBox   | 8081 | `netbox/docker-compose.yml`   | `netbox/bootstrap.sh`   |
| Infrahub | 8082 | `infrahub/docker-compose.yml` | `infrahub/bootstrap.sh` |

Order of operations (per SoT):

```
# from containerlab/lab-srlinux/
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux && sudo containerlab deploy -t lab.clab.yml"
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux/kafka && sudo docker compose up -d"

# Nautobot flow
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux/nautobot && sudo docker compose up -d"
# wait for `docker ps` to show nautobot healthy (~5 min first boot)
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux/nautobot && ./bootstrap.sh"
python3 scripts/lab_validation.py --sot nautobot --image rastreo:lab

# NetBox flow (parallel-safe with Nautobot)
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux/netbox && sudo docker compose up -d"
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux/netbox && ./bootstrap.sh"
python3 scripts/lab_validation.py --sot netbox --image rastreo:lab

# Infrahub flow
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux/infrahub && sudo docker compose up -d"
orb -m clab bash -c "cd /Users/$USER/projects/rastreo/containerlab/lab-srlinux/infrahub && ./bootstrap.sh"
python3 scripts/lab_validation.py --sot infrahub --image rastreo:lab
```

Each `--sot <name>` run:
1. Executes `scenarios/kafka-scan.yml` (full prober matrix, sink=kafka)
2. Publishes 2 DeviceRecords to `rastreo.devices` on the shared broker
3. The per-SoT consumer picks them up, applies field mapping, writes to the SoT API
4. The harness polls the SoT for both expected identity keys (`ip:198.51.100.11`, `ip:198.51.100.12`) with a 60s timeout
5. Reports pass/fail

Nautobot and NetBox consumers key on the `rastreo_identity_key` custom field. Infrahub uses branch-based writes — records land on a `rastreo-updates` branch and (with `INFRAHUB_AUTO_MERGE=true`) merge onto `main`.
