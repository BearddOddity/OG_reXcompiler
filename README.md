# OG Xbox Recomp SDK

Repo: `github.com/BearddOddity/OG_reXcompiler`.


A static recompiler for original Xbox (32-bit x86) titles, built in C#. The
analysis core is a port of ReXGlue's `rex::codegen` `FunctionGraph` design —
the 6-phase fixed-point function-discovery pipeline — retargeted from Xbox 360
/ PowerPC to original Xbox / x86.

## Why

The X-Men Legends recompilation (`D:\My Games\Xbox Recomp`) proved a hand-rolled
Python pipeline could boot ~41% of the way through static init but stalled: its
function discovery is one-shot, extent detection is a `max_addr` high-water walk
that truncates and overruns, and unresolved calls become silent stubs found
only at runtime. ReXGlue's `FunctionGraph` makes each of those a named,
verified phase with a build-time gate. This SDK is that design, in C#, general
across OG Xbox titles.

## Layout

| Project | Purpose |
|---|---|
| `src/OgXbox.Recomp.Codegen` | The `FunctionGraph` analysis pipeline: authority lattice, 3-state function machine, Register → Scan → Discover → GapFill → Merge → Validate. |
| `tests/OgXbox.Recomp.Codegen.Tests` | xUnit. `dotnet test`. |

## x86 vs PPC — what changed from ReXGlue

| ReXGlue (Xbox 360 / PPC) | This SDK (OG Xbox / x86) |
|---|---|
| `bctr` + CTR-loaded jump tables | `jmp [reg*4 + table]` / `jmp [reg*4 + table + base]` |
| `.pdata` `RUNTIME_FUNCTION` seeding (`PDATA` authority) | **none** — 32-bit x86 has no `.pdata`; SEH is a runtime `fs:[0]` chain. `PDATA` kept in the lattice for shape parity, unused. |
| x64 `_C_specific_handler` scope tables | x86 `_EH4` (`__except_handler4`) scope tables; C++ EH `FuncInfo` magic `0x19930522` is the same |
| `ppc::Instruction*` into a `DecodedBinary` | `DecodedInstruction` records from iced-x86 |
| `PPCContext&` per-call register struct | (planned) `RecompContext*` per-call struct |

## Instruction decoding

[iced-x86](https://github.com/icedland/iced) (`Iced` on NuGet) — a complete,
accurate x86/x64 disassembler with first-class flags and operand info, which
the deferred-EFLAGS miscompile class needs.

## Usage

```
ogxbox analyze <game.xbe> -o out [--config title.toml]   # analysis only -> functions.json etc.
ogxbox emit    <game.xbe> -o out [--config title.toml]   # + the C recompilation
```

`emit` produces a `cmake`-buildable tree: `recomp_*.c`, `recomp_decls.h`,
`recomp_dispatch.c`, `recomp_kthunks.c`, `recomp_imports.c`,
`recomp_image.{c,bin}`, `ogxbox_{runtime,kernel,main}.c`, `ogxbox_runtime.h`,
`CMakeLists.txt`. `recomp_image.bin` must sit next to the built executable.

Verified with clang-cl (LLVM 22) + VS BuildTools + Windows SDK: the full X-Men
Legends recompilation (18.7k functions, 935k instructions) compiles with 0
errors and runs.

## License

This project's own code: see `LICENSE` (TBD). Portions derived from ReXGlue
(`rex::codegen`) — BSD-3-Clause, Copyright (c) 2026 Tom Clay; itself deriving
from the Xenia project (Copyright (c) 2022 Ben Vanik and Xenia contributors).
Full text in `LICENSE.rexglue`; derived files carry a header noting it.
