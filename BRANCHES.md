# Branches

The recompiler exists in two implementations. Both read an XBE and emit the
same kind of C; the generated game code is identical in shape.

| Branch | Language | Deps | Build | Status |
|---|---|---|---|---|
| `csharp` | C# / .NET 10 | iced-x86, Tomlyn | `dotnet build` | Full — analysis + emitter + config + runtime, compile-verified, recompiled X-Men boots |
| `c` | C11 | Zydis, tomlc99 (submodules) | CMake + clang-cl | Full parity — analysis + emitter + writers; generated X-Men recompilation compiles 0 errors, links, and runs (boots + calls the kernel, same as `csharp`) |
| `main` | = `csharp` | | | The default; Part-2 runtime work continues here |

## Why two

`main` / `csharp` was written first (the user asked for "C#"; it turned out
they meant C). Rather than discard that work it was branched, and `c` is a
from-scratch C port matching ReXGlue's own language more closely. The tool's
implementation language does not affect the output — ReXGlue is C++, XenonRecomp
is C++, and the recompiled title is C regardless.

## `c` branch layout

```
CMakeLists.txt          top-level; builds Zydis + tomlc99 + ogxbox
third_party/zydis/      submodule — x86 decode
third_party/tomlc99/    submodule — TOML config
src/
  util.h                VEC() arrays, u32map, strbuf  (List<>/Dictionary<>/StringBuilder)
  xbe.c                 XBE parser              <- Binary/Xbe.cs
  kernel_exports.c      371 xboxkrnl ordinals   <- Binary/XboxKernelExports.cs
  binary_view.c         VA-addressable sections <- Binary/BinaryView.cs
  decoded.c             Zydis wrapper -> DecodedInsn  <- Binary/DecodedBinary.cs
  func_types.h          lattice / block / CallTarget  <- FunctionTypes.cs
  func_graph.c          FunctionNode + FunctionGraph  <- FunctionNode.cs + FunctionGraph.cs
  scanners.c            vtable + sig scan       <- Analysis/{VtableScanner,SigScanner}.cs
  func_scanner.c        block discovery + jump tables  <- Analysis/FunctionScanner.cs
  config.c              TOML loader             <- Phases/RecompilerConfig{,Loader}.cs
  context.c             CodegenContext          <- Phases/CodegenContext.cs + AnalysisErrors.cs
  phases.c              the 6 phases + pipeline <- Phases/Phases.cs + ScanPhase.cs + PhaseHelpers.cs
  emit_operand.c        operand -> C            <- Emit/COperand.cs
  emit.c                per-mnemonic emitter    <- Emit/CEmitter.cs
  writers.c             image + JSON + codegen tree  <- Emit/{Image,Codegen}Writer.cs + Output/GraphExporter.cs
  main.c                CLI
runtime/                the C runtime — unchanged from main (already C)
```

## Build (`c` branch)

```
git submodule update --init --recursive
cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=clang-cl
cmake --build build
build/ogxbox emit game.xbe -o out
```

## Verified (`c` branch)

`ogxbox emit` on X-Men Legends `default.xbe`: 28,266 functions analysed,
17,124 emitted, 888,874 instructions, **99.7% lowered**. The 43-file output
compiles with clang-cl (**0 errors**), links to `recomp.exe`, and runs — the
guest boots, runs CRT init, calls kernel imports, and stops at the same
NULL-StartRoutine wall the `csharp` branch hits (missing XAPI init HLE).

## Known deltas from `csharp`

The C analysis finds fewer functions (~28k vs ~39k) — its fixed-point
discovery terminates a round earlier and a few jump-table forms are less
aggressive. Same instruction-lowering coverage. Tuning to match is tracked,
not blocking.
