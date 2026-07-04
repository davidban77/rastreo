# Bundled data

## manuf.gz

Wireshark `manuf` snapshot — the canonical mapping from IEEE MAC address blocks
(MA-L /24, MA-M /28, MA-S /36) to vendor names. Consumed by the `oui`
Cargo feature via `include_bytes!` and decompressed at startup by
`OuiTable::from_bundled()`.

- Source: <https://www.wireshark.org/download/automated/data/manuf>
- Snapshot Last-Modified: `Fri, 03 Jul 2026 10:35:04 GMT`
- Uncompressed line count: 57523 (57510 entries + 13 header comments)
- gz SHA-256: `60edd49be893b0bdfbed5d2e05a677633d52729a599a219cb56135b849a9119e`
- License of the data: CC0-1.0 (see the file's own comment header).

Refresh with `scripts/refresh-oui.sh`. The upstream file is regenerated once
a week; do not refresh more often than that.
