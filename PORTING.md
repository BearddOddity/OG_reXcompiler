# Porting map: ReXGlue `rex::codegen` → `OgXbox.Recomp.Codegen`

Source of truth: `D:\My apps\rexglue-sdk-0.10.0`. Each row is one ReXGlue
translation unit, its C# home, and status. "x86 rewrite" means the logic is
PPC-specific and was re-derived, not transliterated.

## Status

| ReXGlue file | lines | C# target | status | notes |
|---|--:|---|---|---|
| `function_types.h` | 304 | `FunctionTypes.cs` | **done** | PPC EH structs kept; `PDATA` unused (ledger #280) |
| `function_node.h/.cpp` | 209 / ~330 | `FunctionNode.cs` | **done** | `emitCpp` deferred to the emitter |
| `function_graph.h/.cpp` | 206 / 1294 | `FunctionGraph.cs` | **done** | `emitCpp` + code-buffer emit path deferred; base index is a binary-searched `SortedList` |
| `code_region.h` | 26 | `FunctionTypes.cs` (`CodeRegion`) | **done** | |
| — | — | `DecodedInstruction.cs` | **done** | x86 flow record; iced-x86 fills it |
| `binary_view.h/.cpp` | 130 / ~200 | `Binary/BinaryView.cs` + `Binary/Xbe.cs` | **done** | XBE header + section table + kernel-thunk imports; `XboxKernelExports` 371 ordinals |
| `decoded_binary.h/.cpp` | ~60 / 201 | `Binary/DecodedBinary.cs` | **done** | iced-x86 on-demand decode, cached; `TryDecodeRaw` for operand detail |
| `sig_scanner.cpp` | 167 | `Analysis/SigScanner.cs` | **done** | byte+wildcard scan; x86 helper-sig list still empty |
| `vtable_scanner.cpp` | 227 | `Analysis/VtableScanner.cs` | **done** | MSVC RTTI COL / `vtable[-1]` / `.?AV`/`.?AU` demangle |
| `function_scanner.cpp` | 2070 | `Analysis/FunctionScanner.cs` | **done (core)** | block discovery + x86 jump-table detector (disp32, reg-base, offset-from-base). Prologue detection + more table forms: todo |
| `phase_register.cpp` | 708 | `Phases/Phases.cs` `RegisterPhase` | **done** | imports/entry/seed/config; no PPC helpers, no PDATA |
| `phase_scan.cpp` | 178 | `Phases/ScanPhase.cs` | **done** | null-run regions + `{null,handler}` skip + data regions |
| `phase_discover.cpp` | 432 | `Phases/Phases.cs` `DiscoverPhase` | **done** | fixed-point + vtable scan. `functionPointerScan` (mov reg,imm32 code addr): todo |
| `phase_gapfill.cpp` | 235 | `Phases/Phases.cs` `GapFillPhase` | **done** | terminator split, `_EH4` skip, absorb cleanup |
| `phase_merge.cpp` | 175 | `Phases/Phases.cs` `MergePhase` | **done** | reactive resolution + funclet marking + seal. Vacancy absorption: todo |
| `phase_validate.cpp` | 218 | `Phases/Phases.cs` `ValidatePhase` | **done** | build-time gate over direct call/jump targets |
| `codegen_context.h` | — | `Phases/CodegenContext.cs` + `AnalysisState` | **done** | |
| — | — | `Output/GraphExporter.cs` + `tools/ogxbox` | **done** | functions.json / labels.json / seeded_functions.json / summary; runnable CLI |
| `config.cpp` | 621 | `Phases/RecompilerConfig.cs` | **partial** | struct done; TOML loading todo |
| `instruction_dispatch.cpp` + `builders/` | 665 + ~5k | `Emit/*` | **todo** | **full x86 rewrite** — the largest remaining piece |
| `codegen_writer.cpp` | 384 | `Emit/CodegenWriter.cs` | todo | file partitioning, per-file decl headers |
| `project_recompiler.cpp` | 565 | `ProjectRecompiler.cs` | todo | top-level driver, manifest |
| runtime layer (`rex/runtime/*`) | — | `OgXbox.Recomp.Runtime` (new project) | todo | `RecompContext`, memory, kernel HLE, dispatcher |

## State on the real XBE (X-Men Legends `default.xbe`, Release build)

38,888 functions in ~5 s — 7,281 via direct calls, 3,424 via vtables, 28,052
gap-fill, 130 imports. 18,411 sealed, 20,477 pending, 244 validation errors.
For comparison the X-Men Python pipeline reached ~1,199 hand-seeded functions.

## Remaining work, in order

1. **Shrink the ~20k pending** — more x86 jump-table forms, `functionPointerScan`
   (`mov reg, imm32` that is a code address), vacancy absorption in Merge,
   cross-function internal-branch handling. Target: pending « sealed.
2. `RecompilerConfig` TOML loading (switch tables, mid-asm hooks, seeds, chunks).
3. **`Emit/` — the x86→C instruction emitter.** Dispatch table + register/EFLAGS
   model + per-mnemonic builders. Reference: the X-Men Python `tools/recomp`
   BatchTranslator (a working x86→C lifter) and ReXGlue's `builders/` shape.
4. `CodegenWriter` (partitioned .c/.h output) + `ProjectRecompiler` driver.
5. `OgXbox.Recomp.Runtime` — the execution layer (own project; vault blueprint).

## x86 jump-table patterns (for `FunctionScanner`)

- `jmp dword [idx*4 + table]`         — absolute, table as disp32   **(done)**
- `jmp dword [reg + idx*4]`, reg ← `mov/lea reg, table`            **(done)**
- `mov reg,[T2+idx*4]; add reg,T1; jmp reg` — offset-from-base     **(done)**
- `movzx eax,[bounds]; jmp [eax*4+T]` — byte-index secondary table   (todo)

Walk back from the `jmp` for `cmp reg,N` / `ja default` (the bound) and the
`mov reg,[table + idx*scale]` (the load).
