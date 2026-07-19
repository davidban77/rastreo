# Vendored gNMI protos

`gnmi.proto` and `gnmi_ext.proto` are vendored verbatim from
[openconfig/gnmi](https://github.com/openconfig/gnmi), tag **v0.14.1**
(commit `8b7dd494c4f6ff517431965d662621d8884bad0f`), under their original
Apache-2.0 license.

The directory layout preserves the proto import path — `gnmi.proto` imports
`github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto`, so the files live under
`github.com/openconfig/gnmi/proto/{gnmi,gnmi_ext}/` with `proto/` as the include root.

## Regenerating the Rust bindings

The checked-in bindings at `rastreo-core/src/prober/gnmi/generated.rs` are produced by:

```
cargo run -p xtask -- gen-gnmi
```

This requires `protoc` on `PATH` (`brew install protobuf`). The well-known types
(`google/protobuf/any.proto`, `duration.proto`, `descriptor.proto`) resolve from protoc's
bundled include path and are referenced as `::prost_types::*` in the output. A normal
`cargo build --workspace` never runs protoc — it compiles the committed `generated.rs`.
