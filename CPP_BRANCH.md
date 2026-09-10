# `cpp` branch — ReXGlue, x86 instead of PowerPC

A third implementation of OG_reXcompiler that **reuses ReXGlue's C++ source**
rather than re-porting the design (which `csharp` and `c` already did). The
point is not the recompiler — it is the **runtime**: ReXGlue's
`system/` + `filesystem/` + `rexglue/` give a real console layer (dependency
injection, `FunctionDispatcher`, `ExportResolver`, `KernelState`, `ObjectTable`,
`XObject`, a VFS device model, the `ReXApp` per-title hook model) instead of the
hand-built starter kernel on `main`.

## Vendored

`vendor/rexglue/` — a trimmed copy of ReXGlue release/v0.10.0 (BSD-3-Clause,
`vendor/rexglue/LICENSE`; the top-level `LICENSE.rexglue` is the same text):

| kept | dropped |
|---|---|
| `src/codegen/` (minus `ppc/`, `builders/`, `instruction_dispatch.cpp`) | `src/graphics/` (16 MB — Xenos + D3D12/Vulkan + shader translators) |
| `src/system/` | `src/audio/` (XMA) |
| `src/filesystem/` | `src/ui/` (ImGui) |
| `src/core/` | `thirdparty/` (34 submodules — we vendor only what codegen needs) |
| `src/rexglue/` | `tools/binutils`, `tests/` |
| `include/rex/**`, `resources/templates/` | |

## Third-party (submodules, `third_party/`)

`fmt`, `tomlplusplus`, `json` (nlohmann), `inja` (templates), `xxHash`,
`zydis` (+ its `zycore`) for x86 decode. **Not** Vulkan/SDL3/FFmpeg/ImGui.

## Keep / rewrite / stub

| ReXGlue piece | plan |
|---|---|
| `function_graph.cpp` (1294) | **keep** — swap `ppc::Instruction*` for our `x86::Instruction*` (a `typedef` + include change) |
| `phase_{register,scan,merge,validate}.cpp` | **keep** — orchestration; the PPC bits (PDATA seed, save/restore-helper sigs) become x86 (drop PDATA, SEH prologs) |
| `phase_{discover,gapfill}.cpp` | **keep skeleton**, swap the decode calls |
| `function_scanner.cpp` (2070) | **rewrite** — block discovery + jump-table detection is PPC pattern-matching (`lwzx`/`rlwinm`/`mtctr`/`bcctr`, `mflr`/`stwu r1` prologue). Port the x86 logic from the `c` branch's `func_scanner.c`. |
| `vtable_scanner.cpp`, `sig_scanner.cpp`, `config.cpp` | **keep** — ISA-neutral (RTTI, byte patterns, TOML) |
| `codegen_writer.cpp`, `template_registry.cpp`, `manifest.cpp`, `project_recompiler.cpp` | **keep** — inja templates + file partitioning |
| `codegen/ppc/` | **replace** — `src/x86/x86_instruction.{h,cpp}` (Zydis-backed, matching the semantic interface `function_graph`/phases use: `is_return`/`is_branch`/`is_call`/`is_conditional`/`getBranchTarget`/`decode_instruction`) |
| `instruction_dispatch.cpp` + `builders/*.cpp` (~5.6 k) | **rewrite** — x86 → C++ builders. Reuse the emitter logic from the `c` branch's `emit.c`, adapted to ReXGlue's `BuilderContext` + inja output |
| `builders/context.cpp` (570) | **replace** — `RecompCtx` x86 register struct instead of `PPCContext` |
| `src/system/` XEX module loader | **replace** — XBE loader |
| `src/system/` `IGraphicsSystem`/`IAudioSystem`/`IInputSystem` | **stub** first (nop backends — the DI already allows this), then D3D8-HLE / DirectSound / OG gamepad |
| `src/kernel/xboxkrnl` (not vendored yet) | **rewrite** — OG xboxkrnl ordinals + signatures |

## Part 1 decision (2026-09-10): port, don't re-derive

The original plan was to swap ReXGlue's PPC `function_scanner.cpp` (2070 lines),
`phase_*.cpp`, and `emitCpp` for x86 equivalents in place. That is ~8k lines of
careful adaptation to re-solve block discovery, jump-table detection, the 6-phase
fixed point, and x86-to-C lowering — all of which the `c` branch already solved
for x86, compile- and boot-verified.

So Part 1 on this branch **is the `c` branch's recompiler**, brought into the
`cpp` tree verbatim (`src/*.c`, `runtime/*`, `tomlc99`) and built by this CMake as
the `ogxbox` executable. It analyses X-Men Legends to 28,266 functions / 888,874
instructions / 99.7% lowered, emits 43 C files that compile, link, and boot to the
same NULL-`PsCreateSystemThreadEx`-StartRoutine wall as the other two branches
(missing init HLE — a Part 2 concern).

`rexcodegen.lib` (ReXGlue's own `function_graph` + RTTI/sig scanners + TOML config,
compiled against a Zydis-backed `x86::Instruction`) still builds alongside it. It
is the bridge object for Part 2: the `cpp` branch's real reason to exist is
ReXGlue's `system/` + `filesystem/` + `rexglue/` runtime framework, and that
integration will lean on ReXGlue's graph model rather than the `c` port's.

## Build order (revised)

1. [DONE] `third_party/` deps + `vendor/rexglue/include` → `rexcodegen.lib`
   (`function_graph` + `vtable_scanner` + `sig_scanner` + `config` +
   `codegen_flags`) compiling against `x86::Instruction`.
2. [DONE] `c`-branch `src/*.c` + `runtime/*` + `tomlc99` in-tree → `ogxbox`
   executable: XBE → analysis → C emit, verified against X-Men Legends.
3. `src/system/` link (stub graphics/audio/input backends) → ReXGlue's runtime
   framework builds on this branch.
4. XBE loader for `src/system/` (replaces the XEX/ELF module loaders).
5. OG xboxkrnl HLE against ReXGlue's `FunctionDispatcher` / `ExportResolver` /
   `KernelState` / `ObjectTable` → a recompiled title links + boots past the
   init-HLE wall.

## Status

Part 1 done and verified end to end (see decision above). Both `rexcodegen.lib`
and `ogxbox.exe` build with clang-cl / C++23 / C11. Next: Part 2 — wire
ReXGlue's `system/` runtime (steps 3-5).
