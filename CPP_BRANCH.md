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

## Build order

1. `third_party/` deps + `vendor/rexglue/include` + `src/x86/x86_instruction`
   → get `function_graph.cpp` + `vtable_scanner` + `sig_scanner` + `config`
   compiling as a `rexcodegen` library.
2. `src/x86/function_scanner_x86.cpp` (from the `c` branch) → the phases run.
3. A CLI (`ogxbox`) → analysis pipeline against an XBE.
4. `instruction_dispatch` + `builders` x86 rewrite → codegen output.
5. `src/system/` link (stub graphics/audio) → the runtime framework builds.
6. XBE loader, OG xboxkrnl HLE → a recompiled title links + boots.

## Status

Scaffolding. Nothing builds yet.
