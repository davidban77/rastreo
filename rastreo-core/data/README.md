# Bundled data

## mib_identity.gz

A small seed mapping SNMP `sysObjectID` (dotted-decimal, no leading dot) to a
vendor identity (`manufacturer`, `model`, `product_family`). Consumed by the
`mib_enrichment` Cargo feature via `include_bytes!` and decompressed at startup
by `MibTable::from_bundled()`.

- Format: 4-column TSV — `sys_object_id <TAB> manufacturer <TAB> model <TAB> product_family`.
  Any column except `sys_object_id` may be empty; a row must carry at least one identity column.
- Entry count: 9 (plus 7 header comments).
- gz SHA-256: `9fdaf261d4371ae3d93fbea2784c61ce2d974ac186cda8e3a5925abc9f21815a`
- Provenance: the OID → vendor facts are derived from public vendor product MIBs
  and `NET-SNMP-TC` enterprise assignments; the Nokia SR Linux OID
  (`1.3.6.1.4.1.6527.1.20.26`) is a real capture from the containerlab SR Linux
  node. The `manufacturer` / `model` / `product_family` strings are hand-authored
  (not copied from MIB `DESCRIPTION` text). The `NET-SNMP-TC` rows leave
  `manufacturer` and `model` blank — Net-SNMP is a software agent, not a hardware
  vendor — and keep only the OS token in `product_family`. Compiled and bundled
  under the crate's MIT/Apache-2.0 license.

This is a deliberate STUB. It is not a comprehensive database — supply your fleet's
own OIDs via the fuser's `data_path` overlay, which merges on top of this seed with
user entries winning on key collision. Rebuild with `gzip -n -9`.
