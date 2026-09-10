# Part 2 — the runtime

The recompiler (Part 1, `rex::codegen` port) is done: it turns an XBE into C that
compiles and runs. Part 2 is the layer that C runs *on* — the original Xbox as
seen by a title: memory, the kernel API, the filesystem, the GPU, sound, input.

ReXGlue's runtime is a full Xenia-derived console stack (`src/system`,
`src/kernel`, `src/graphics`, `src/audio`, `src/filesystem`). This project does
**not** re-port that — it is Xbox-360-specific in its contents (PPC context,
Xenos GPU, XEX loader, STFS) and enormous. Instead:

- keep ReXGlue's **architecture** — the seams — as the target shape;
- fill them with **original-Xbox** contents, drawing on the C kernel that
  already exists in the X-Men Legends recomp
  (`D:\My Games\Xbox Recomp\src\kernel`, ~180 `xbox_*` `__stdcall` functions:
  ob / thread / sync / rtl / file / io / memory / pool / hal / path / crypto).

## Current state

`runtime/ogxbox_runtime.{h,c}` + `ogxbox_kernel.c` are a **starter**: 64 MB flat
guest RAM, a sorted dispatch table (`rex_dispatch`, kernel-ordinal routing on
bit 31), a bump pool allocator, Win32-backed threads/events, ~40 xboxkrnl
functions. Enough that X-Men boots and spawns its main thread; it then hits a
null indirect call because the HLE those init paths need is missing.

## The seams (from ReXGlue, mapped to OG Xbox)

| ReXGlue | OG Xbox equivalent | status |
|---|---|---|
| `memory::Memory` + `GuestPtr<T>` + `be<T>` | flat `g_guest_ram` + `MEM*` macros. **No byte-swap** (x86 is LE). 64 MB retail / 128 MB devkit. | done (flat) |
| `FunctionDispatcher` — per-module table + thunk pool | one table for the whole XBE (`g_rex_dispatch`) + a thunk pool for host→guest callbacks | table done; thunk pool: todo |
| `ExportResolver` — export tags, `.inc` multi-include tables | `recomp_kthunks.c` (ordinal → `__imp__`) + a per-function tag/log table | basic; tags: todo |
| `KernelState` + `ObjectTable` + `XObject` | handle table (thread / event / mutant / semaphore / timer / file / …), named lookup, refcount | todo — port X-Men `kernel_ob.c` |
| `VirtualFileSystem` + `Device` (DiscImageDevice/XISO, HostPathDevice, STFS) | XISO device + host-path device + **FATX** device; mounts `D:` = disc, `T:`/`U:`/`Z:` = HDD, `Y:` = dash. No STFS. | todo — X-Men `kernel_file.c` / `kernel_path.c` |
| `IGraphicsSystem` (D3D12 / Vulkan + Xenos translator) | **D3D8 HLE** — translate `IDirect3DDevice8` calls to D3D11/12 (X-Men `d3d8_shim.c`). No NV2A pushbuffer. | todo — X-Men `d3d8_shim.c` |
| `IAudioSystem` (SDL + XMA) | DirectSound HLE (+ XMA/ADPCM/WMA decode) | todo |
| `IInputSystem` (SDL/XInput) | OG gamepad (`XInputGetState` predecessor) | todo |
| `ReXApp` — per-title hook class | a per-title C file with hook functions; replaces X-Men's `recomp_manual.c` patches | todo |

## Calling convention (already in place)

The emitter lowers `call __imp__X` to a bare `__imp__X(c)` — **no pushed return
address**, so `[c->esp]` IS argument 1. An HLE shim:

```c
void __imp__NtClose(RecompCtx* c) {
    uint32_t handle = MEM32(c->esp);          /* arg 1 */
    NTSTATUS s = xbox_NtClose((HANDLE)(uintptr_t)handle);
    c->eax = (uint32_t)s;
    c->esp += 4;                               /* __stdcall: pop 1 arg */
}
```

`__cdecl` / varargs (`DbgPrint`) leave the pop to the generated caller.

## Order of work

1. **Instrumentation first.** A guest call-stack ring (every generated function
   pushes its entry addr on call, pops on return) so an unimplemented / null
   call prints *where the game wanted to go*. This is the tool that drives
   everything else. → `runtime/ogxbox_trace.c`.
2. **Object table.** Port X-Men `kernel_ob.c` → `runtime/kernel/ob.c`. Real
   handles for the sync/thread/file objects.
3. **Bridge generator.** `ogxbox emit` also writes `recomp_kbridge.c` — a
   `__imp__<Name>(RecompCtx*)` shim per referenced import, generated from a
   `{name, argc, convention}` table, calling the vendored `xbox_<Name>`.
4. **Vendor the X-Men kernel** (`src/kernel/*.c`, game-agnostic HLE — same
   author) into `runtime/kernel/`, adapted to the SDK's `MEM*` / `XBOX_PTR`.
5. **VFS** — mount the disc image, so the game can load its files.
6. **D3D8 HLE** — port `d3d8_shim.c`; first pixel.
7. Audio, input, the per-title hook file.

Each step is gated on "X-Men gets measurably further" (more functions reached,
a new subsystem initialised, a frame rendered) — the same loop the X-Men recomp
has been running by hand.
