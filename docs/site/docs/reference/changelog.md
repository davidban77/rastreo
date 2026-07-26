---
description: Release history for rastreo, taken straight from the project changelog. Every version, feature, and fix in one place.
---

!!! warning "Upgrade note for 0.10.0 — records now arrive classified"
    Scans classify by default. A scenario that does not set `classifier` runs the `rules` classifier with the tables rastreo ships, so `platform`, `os_version`, `ssh_version`, `http_server`, `http_version`, and `role` are populated wherever a probe collected a signal one of those rules matches. All six fields were previously `null` on every record, on every surface — `rastreo discover`, `rastreo discover --file`, and `POST /scans`.

    **A reconciler will overwrite, not just fill in.** The reference consumers for NetBox, Nautobot, and Infrahub compare each field against the object in the source of truth and write it whenever the values differ — so a `platform` derived from a banner, or a `role: router` derived from SSH + BGP being open, replaces whatever an operator set by hand on that device. Check what your consumer does with `platform` and `role` before the first run of an upgraded scan.

    The shipped role table needs multi-port evidence and assigns nothing from a single open port, so a plain TCP-connect sweep still emits `"role": null` and touches no roles downstream. The single-port heuristics (`443`/`80` → `web_server`, `22` → `host`) ship but are opt-in.

    To keep records unclassified, ask for the pass-through classifier explicitly:

    ```yaml
    classifier:
      type: noop
    ```

    That is a scenario-file setting and there is no equivalent CLI flag, so a flag-mode scan (`rastreo discover --target ... --port ...`) always classifies — move the scan into a YAML file and run it with `--file` to turn classification off.

    See [Classification](../discover/classification.md) for the shipped rule tables, how to extend them, and how to replace them outright.

--8<-- "CHANGELOG.md"
