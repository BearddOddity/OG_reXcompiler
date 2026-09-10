# Automation

Part 1 (recompile) and Part 2 (build + boot the recompiled title) are driven
the same way ReXGlue drives its projects: **scaffold once, then `cmake`.**

```
ogxbox init <game.xbe>            # scaffold titles/<name>/
cmake  --preset <name>            # configure -> runs Part 1 (emit)
cmake  --build --preset <name>    # Part 2 -> compiles the recompiled title
ctest  --preset <name>            # smoke: boot it, assert progress
```

## One-time: build the recompiler

```
cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=clang-cl
cmake --build build --target ogxbox
```

`cmake --preset <name>` finds `ogxbox` under `build/` automatically. Run
everything from a VS dev shell (or `scripts/ogx.ps1`, which sets the
environment) so `clang-cl` sees the Windows SDK.

## `ogxbox init`

```
ogxbox init <game.xbe> [--name <name>] [--config <recomp.toml>]
           [-o <titles-dir>] [--min-calls <N>] [--timeout <S>] [--force]
```

Writes `titles/<name>/`:

| file | purpose |
|---|---|
| `manifest.toml` | `[project]` + `[smoke]`, and `includes = [<recomp.toml>]` — the recompiler reads this |
| `CMakeLists.txt` | the superbuild: emit at configure time, then `add_subdirectory` the generated tree, then a `ctest` smoke test |
| `CMakePresets.json` | one configure / build / test preset named `<name>` |
| `.gitignore` | ignores `build/` |

`--name` defaults to a sanitised form of the XBE's parent directory.
`--config` points at the real per-title config (functions list, `manual_file`,
seeds, switch tables — e.g. `configs/xmen-legends.toml`); without it, a stub is
written next to the manifest for you to fill in.

Edit the **recompiler config**, not the manifest — the manifest just references
it and adds the two project/smoke blocks.

## What `cmake --preset` does

1. **find `ogxbox`** (fatal error with instructions if the SDK isn't built).
2. **emit** (`ogxbox emit <xbe> -o build/gen --config manifest.toml`) — run at
   configure time, skipped when nothing under `runtime/`, the XBE, the manifest
   or the tool is newer than `build/gen/.emit.stamp`. `emit`'s exit 3
   (analysis-validation warnings) is non-fatal — the tree still compiles.
3. **`add_subdirectory(build/gen)`** — the emitter's own generated
   `CMakeLists.txt` builds `recomp.exe`, honours `-DREX_TRACE`, and copies
   `recomp_image.bin` next to the executable.
4. **`add_test(<name>-smoke)`**.

No `CMAKE_BUILD_TYPE` by default: `-O2` exposes latent UB in a mid-bringup
recompilation, which is debugged unoptimised. Add `-DCMAKE_BUILD_TYPE=Release`
once a title boots clean.

## The smoke test (`templates/title/smoke.cmake`)

Boots the recompiled title under a timeout and asserts the highest
`guest calls N` it reports is `>= min_guest_calls` (from `[smoke]` in the
manifest) with no boot-blocking fault. Needs `OGX_TRACE=ON` (the preset
default) — the guest-call counter is compiled out otherwise.

**Raise `min_guest_calls` as the port advances** so a regression that shortens
boot is caught. A fault that appears *after* the bar is cleared — the doomed
thread spinning at the current wall being torn down at shutdown — is reported
as a note, not a failure.

### Interest: golden-output diff (not built)

A stronger check would diff the run's instrument output (`STACK:` / `ABI:` /
spin-stack frames) against a checked-in `titles/<name>/smoke.golden.txt`,
re-blessed on deliberate changes. It is deferred because the raw output is
non-deterministic (`+N.Ns` timing lines, some addresses, the call count
wobbling a few) and needs a normaliser first, or the golden fails every run.
Add it if instrument-output regressions start slipping past the progress
assertion. See the trailing comment in `smoke.cmake`.

## Lower-level: `scripts/ogx.ps1`

`ogx.ps1 tool | emit | build | run | cycle` drives the same steps against a
throwaway output directory without scaffolding a project — handy while
iterating on the recompiler itself. See the repo README.
