# Porting map: ReXGlue `rex::codegen` → `OgXbox.Recomp.Codegen`

Source of truth: `D:\My apps\rexglue-sdk-0.10.0`. Each row is one ReXGlue
translation unit, its C# home, and status. "x86 rewrite" means the logic is
PPC-specific and must be re-derived, not transliterated.

## Status

| ReXGlue file | lines | C# target | status | notes |
|---|--:|---|---|---|
| `function_types.h` | 304 | `FunctionTypes.cs` | **done** | PPC EH structs kept; `PDATA` unused (ledger #280) |
| `function_node.h/.cpp` | 209 / ~330 | `FunctionNode.cs` | **done** | `emitCpp` deferred to the emitter phase |
| `function_graph.h/.cpp` | 206 / 1294 | `FunctionGraph.cs` | **done** | `emitCpp` + code-buffer emit path deferred |
| `code_region.h` | 26 | `FunctionTypes.cs` (`CodeRegion`) | todo | trivial struct |
| — | — | `DecodedInstruction.cs` | **done** | x86 flow record; iced-x86 fills it |
| `binary_view.h/.cpp` | 130 / ~200 | `BinaryView.cs` + `XbeLoader.cs` | todo | **x86 rewrite** — XBE not XEX; section table, kernel-thunk imports, no `.pdata` dir |
| `decoded_binary.h/.cpp` | ~60 / 201 | `DecodedBinary.cs` | todo | wraps iced-x86 `Decoder`; caches `DecodedInstruction` per section |
| `sig_scanner.cpp` | 167 | `SigScanner.cs` | todo | byte+mask scan; x86 helper sigs (`__SEH_prolog3` etc.) |
| `vtable_scanner.cpp` | 227 | `VtableScanner.cs` | todo | MSVC RTTI COL at `vtable[-1]`, `.?AV`/`.?AU` — same on x86 |
| `function_scanner.cpp` | 2070 | `FunctionScanner.cs` | todo | **x86 rewrite** — block discovery (merge w/ the Python `_discover_blocks`), x86 jump-table patterns, prologue detection |
| `instruction_dispatch.cpp` | 665 | `Emit/InstructionDispatch.cs` | todo | **full x86 rewrite** — PPC opcode→C is nothing like x86 |
| `phase_register.cpp` | 708 | `Phases/RegisterPhase.cs` | todo | drop `.pdata`; inputs = seeds/helpers/imports/vtable |
| `phase_scan.cpp` | 178 | `Phases/ScanPhase.cs` | todo | port of the Python `tools/graph/scan.py` (null-word regions) |
| `phase_discover.cpp` | 432 | `Phases/DiscoverPhase.cs` | todo | fixed-point worklist; calls `FunctionScanner` |
| `phase_gapfill.cpp` | 235 | `Phases/GapFillPhase.cs` | todo | `{handler, rdata-ptr}` skip is x86 `_EH4` scope-table shape |
| `phase_merge.cpp` | 175 | `Phases/MergePhase.cs` | todo | reactive resolution to fixed point + vacancy absorption |
| `phase_validate.cpp` | 218 | `Phases/ValidatePhase.cs` | todo | build-time gate; `UnresolvedCall`/`MissingJumpTable`/… |
| `config.cpp` | 621 | `RecompilerConfig.cs` | todo | TOML → switch tables, mid-asm hooks, seeds |
| `codegen_writer.cpp` | 384 | `CodegenWriter.cs` | todo | file partitioning, per-file decl headers |
| `project_recompiler.cpp` | 565 | `ProjectRecompiler.cs` | todo | top-level driver, manifest |
| `codegen_context.h` | — | `CodegenContext.cs` | todo | DI bag: BinaryView + config + graph + resolver |
| runtime layer (`rex/runtime/*`) | — | `OgXbox.Recomp.Runtime` (new project) | todo | `RecompContext`, memory, kernel HLE, dispatcher — separate blueprint in the vault |

## Order of work

1. `CodeRegion` + `BinaryView`/`XbeLoader` + `DecodedBinary` (iced-x86) — the input layer.
2. `ScanPhase` (straight port of the Python scan) + `SigScanner` + `VtableScanner`.
3. `FunctionScanner` block discovery + x86 jump tables.
4. `RegisterPhase` → `DiscoverPhase` → `GapFillPhase` → `MergePhase` → `ValidatePhase`.
5. `RecompilerConfig` (TOML).
6. `Emit/InstructionDispatch` — the big x86 rewrite — + `CodegenWriter`.
7. `ProjectRecompiler` driver.
8. Runtime project (separate).

## x86 jump-table patterns (for `FunctionScanner`)

- `jmp dword [base + idx*4]`         — absolute-address table
- `jmp dword [idx*4 + table]`        — absolute, table as disp32
- `movzx eax,[bounds]; jmp [eax*4+T]`— byte-index secondary table then main
- `mov eax,[T2+ecx]; jmp [T1+eax*4]` — offset-from-base table

Walk back from the `jmp` for `cmp reg,N` / `ja default` (the bound) and the
`mov reg,[table + idx*scale]` (the load).
