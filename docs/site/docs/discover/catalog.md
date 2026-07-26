---
description: Catalog references — reuse named scenarios stored in `~/.config/rastreo/catalog/` or `/etc/rastreo/catalog/` via `rastreo discover --file @name`.
---

# Catalog

Catalog references let you run a saved scenario by name instead of pointing `--file` at a full path. Drop a `office-network.yml` in `~/.config/rastreo/catalog/`, then run `rastreo discover --file @office-network`. Everything else about the YAML scenario shape and CLI override rules stays the same as [YAML-driven mode](cli.md#yaml-driven-mode).

## When to use it

Use the catalog when you rerun the same scenario often — an office subnet sweep, a datacenter TCP baseline, a lab HTTP + DNS probe — and you'd rather type `@office` than `~/scripts/scans/office-network.yml`. The catalog is a convenience layer for humans at the terminal; automation and CI should keep passing explicit paths.

## Trigger

Any value passed to `--file` (or `-f`) that starts with `@` is treated as a catalog name. Everything else is a plain path:

```bash
rastreo discover --file @office-network      # catalog lookup
rastreo discover --file /etc/scans/office.yml # plain path (unchanged)
```

## Search order

rastreo looks for `<name>.yml` first, then `<name>.yaml`, in these directories, in order — first hit wins:

1. Every directory listed in `RASTREO_CATALOG_DIR` (colon-separated, PATH-style). When this env var is set, **only** these directories are searched — the user and system directories below are skipped.
2. The user directory: `$XDG_CONFIG_HOME/rastreo/catalog/` when `XDG_CONFIG_HOME` is set, otherwise `$HOME/.config/rastreo/catalog/`.
3. The system directory: `/etc/rastreo/catalog/`.

Both extensions are tried in the same directory before moving to the next directory, so `@office` finds `office.yml` in the user directory even if a `office.yaml` also exists in `/etc/rastreo/catalog/`.

You can pass the extension explicitly (`@office.yml` or `@office.yaml`) — rastreo strips it before searching, so `@office`, `@office.yml`, and `@office.yaml` all resolve to the same file when only one is present.

## Setting up the user directory

Create the directory and drop scenario files in it:

```bash
mkdir -p ~/.config/rastreo/catalog
cat > ~/.config/rastreo/catalog/office-network.yml <<'EOF'
# yaml-language-server: $schema=https://davidban77.github.io/rastreo/schemas/scenario-v1.json
version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: office-tcp
    timeout_ms: 500
    sink:
      type: stdout
    targets:
      - Cidr: "10.10.0.0/24"
    probers:
      - type: tcp_connect
        ports: [22, 80, 443]
EOF
```

Then run it by name:

```bash
rastreo discover --file @office-network
```

## Overriding the search path

`RASTREO_CATALOG_DIR` lets you point at scenario collections outside the default locations — useful for a shared team drive, a git checkout, or hermetic CI:

```bash
export RASTREO_CATALOG_DIR=/opt/team-scans:/opt/lab-scans
rastreo discover --file @lab-tcp
```

When `RASTREO_CATALOG_DIR` is set, the user and system directories are **not** consulted — only the paths listed in the variable. Empty entries in the list (`::`) are skipped.

The separator is `:` (Unix `PATH` convention); rastreo ships musl Linux and macOS binaries only, so Windows-style `;` is not supported.

## Listing catalog scenarios

`rastreo catalog list` prints every `@name` you can pass to `--file`, one per line, next to the exact file a run would load. Use it to see what names are available before you type one. It also confirms which file a name resolves to when several directories hold scenarios.

```bash
rastreo catalog list
```

```text
@datacenter-hosts  ->  /home/dave/.config/rastreo/catalog/datacenter-hosts.yml
@lab               ->  /opt/team-scans/lab.yml
@office-network    ->  /home/dave/.config/rastreo/catalog/office-network.yml
```

The command searches the same directories in the same order as an `@name` reference — see [Search order](#search-order) above. Names are deduplicated and sorted. When one name exists in more than one directory, the listed path is the file a run would pick: first directory wins, `.yml` before `.yaml`.

When the search path holds no scenarios (every directory is missing or empty), the command prints a note to stderr and exits `0`. An empty catalog is not an error:

```text
no catalog scenarios found (searched: /home/dave/.config/rastreo/catalog, /etc/rastreo/catalog)
```

## Restrictions

- **No path separators** in the name. `@subdir/foo` and `@..\/foo` are rejected. Files must live directly inside a catalog directory; no subdirectory navigation.
- **No empty name.** `@` on its own is rejected.
- **Terminal files.** A catalog file is parsed as a normal scenario YAML. It cannot reference another `@name` — expansion is one level deep.

## Interaction with other flags

Catalog references compose with every other `--file` behavior:

- `--dry-run` resolves the catalog reference first, then prints the plan for the resolved file — no probes run.
- `--sink`, `--concurrency`, `--timeout-ms`, and other overrides apply to the resolved scenario exactly as they would for a plain-path `--file`.
- `--file @name` and every flag-driven scan argument (`--target`, `--probe`, `--port`, `--probe-ports`, and the per-prober parameters) remain mutually exclusive.

## Error output

When the name does not resolve, rastreo prints the searched directories and, when possible, a list of catalog names available in each existing directory:

```text
Error: catalog scenario '@office-net' not found
searched directories:
  - /home/dave/.config/rastreo/catalog
  - /etc/rastreo/catalog (missing)
available in /home/dave/.config/rastreo/catalog:
  - @datacenter-hosts
  - @office-network
  - @lab-tcp
```

If none of the searched directories exist, rastreo suggests creating one:

```text
Error: catalog scenario '@office' not found
searched directories:
  - /home/dave/.config/rastreo/catalog (missing)
  - /etc/rastreo/catalog (missing)
no catalog directories exist; create `~/.config/rastreo/catalog/` and add scenario YAML files there
```

## See also

- [CLI](cli.md) — every `rastreo discover` flag, including `--file`.
- [Scenario schema](../reference/scenario.md) — the YAML shape of a catalog file.
