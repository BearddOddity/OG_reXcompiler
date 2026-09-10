# Credits

OG_reXcompiler exists because of the projects below. It is a port, not original
research — the design, the phase structure, the authority model, and most of
the analysis logic come from ReXGlue and its own upstreams.

## Ported from

### ReXGlue SDK — https://github.com/rexglue/rexglue-sdk
BSD-3-Clause. Copyright (c) 2026 Tom Clay and the ReXGlue contributors.

The entire `rex::codegen` analysis + code-generation design was ported here:
the `FunctionGraph`, the `FunctionAuthority` lattice, the 3-state function
machine, the six analysis phases (Register / Scan / Discover / GapFill / Merge /
Validate), `projectedSize` block discovery, the vtable / signature scanners, and
the TOML config model. This project retargets all of it from Xbox 360 / PowerPC
to original Xbox / 32-bit x86 and reimplements it in C#. The full upstream
license is retained in `LICENSE.rexglue`.

ReXGlue contributors (from the ReXGlue README):
Tom (crack), Loreaxe, mystixor, Graine25, Carlos Estrague (mrcmunir),
sanjay900, Toby, Roxxsen, and the wider ReXGlue community.

### Xenia — https://github.com/xenia-project/xenia
Copyright (c) 2022 Ben Vanik and the Xenia project contributors.

ReXGlue is built on Xenia's Xbox 360 emulation work, and the runtime-layer
architecture this project sketches (Runtime + dependency injection,
FunctionDispatcher, ExportResolver, object table, VFS device model) descends
from Xenia through ReXGlue. Xenia's work laid the groundwork for all of this.

### XenonRecomp — https://github.com/hedge-dev/XenonRecomp
For pioneering the modern static-recompilation approach for Xbox 360. ReXGlue
credits it for a lot of the codegen analysis logic and instruction
translations, which flow into this project.

### rexdex's recompiler — https://github.com/rexdex/recompiler
Credited by ReXGlue as an inspiration for ahead-of-time recompilation.

## Direct dependencies

- **iced-x86** — https://github.com/icedland/iced — MIT. The x86/x64 decoder and
  assembler used for instruction decoding and for building synthetic test code.
- **Tomlyn** — https://github.com/xoofx/Tomlyn — BSD-2-Clause. TOML config parsing.
- **.NET** / **xUnit** — MIT.

## Sibling project

- **X-Men Legends RE-LOADED** (BearddOddity) — the original-Xbox recompilation
  effort this SDK was built to serve. Its hand-rolled Python pipeline was the
  prototype, and its long fight with x86 deferred-EFLAGS miscompiles is why this
  port computes flags eagerly.

The list above is not exhaustive. If your work is here and uncredited, or
credited wrongly, please open an issue.
