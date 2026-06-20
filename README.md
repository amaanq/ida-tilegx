# ida-tilegx

A native **Tilera TILE-Gx** processor module for **IDA Pro 9.x**.

TILE-Gx is the 64-bit VLIW architecture behind, among other things, MikroTik's
Cloud Core Routers. IDA ships no TILE-Gx support, so this module adds it.

- **Native decoder.** Bundles are decoded straight from their bit encodings
- **Rust core + thin IDA glue.** All instruction logic lives in a Rust
  `staticlib`; `processor.cpp` owns the unavoidable IDA SDK glue
  (the `processor_t` descriptor and the `outctx_t`/`insn_t` calls).
- **Generated from one spec.** The decode tables are generated from
  `isa/tilegx.nuon`, the ISA source of truth.

## Building

```
nix build
```

produces `result/procs/tilegx.so` and `result/loaders/tilegx_raw.so`.

## Installing

IDA scans `procs/` under the per-user IDA directory (`$IDAUSR`, typically
`~/.idapro` or `~/.local/share/idapro`). A Nix-installed IDA lives in a
read-only store path, so install into your user directory:

```
mkdir -p ~/.idapro/procs
cp result/procs/tilegx.so ~/.idapro/procs/
mkdir -p ~/.idapro/loaders
cp result/loaders/tilegx_raw.so ~/.idapro/loaders/
```

The flake exposes `packages.<system>.default`, so you can wire it into your Nix
config. Add it as a flake input:

```nix
inputs.ida-tilegx.url = "github:amaanq/ida-tilegx";
```

or with [tack](https://github.com/manic-systems/tack):

```sh
tack add ida-tilegx github:amaanq/ida-tilegx
```

## Usage

Open a TILE-Gx ELF file, and IDA should be able to auto-detect the machine.
The optional firmware/flat-binary loader also recognizes dense little-endian
TILE-Gx firmware blobs, such as RouterBOOT images, and preselects the
processor. Otherwise, pick **Tilera Tile-GX** in the processor dropdown.

## Developing

- **Regenerate tables** after editing `isa/tilegx.nuon`: `nix run .#gen` (or
  `nu isa/tilegx-gen.nu`). The generated `.rs`/`.h` are committed for
  reproducible builds.
- **Test the decoder** with `cargo test`.

## Layout

| Path   | What                                        |
| ------ | ------------------------------------------- |
| `isa/` | ISA specs, comments, and table generator    |
| `src/` | Rust decoder and small C++ IDA module glue  |

## License

MPL-2.0 (see [`LICENSE`](./LICENSE))
