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

---

## Phase A — execution (2026-09-10, `main`)

Locked decisions after reading the X-Men Legends recomp kernel
(`D:\My Games\Xbox Recomp\src\kernel`, same author, ~9,300 lines):

**Memory model: base + offset, kept.** The X-Men kernel already assumes
`native = guest_va + g_xbox_mem_offset` — the same shape as this SDK's
`g_guest_ram + addr`. So `g_xbox_mem_offset == (uintptr_t)g_guest_ram` and the
vendored kernel links against our memory with no marshalling. Identity mapping
(`VirtualAlloc` at the XBE base) was tested and works, but is not needed and
would lose the null-page trap for free.

**`xbox_memory_layout.c` owns guest RAM.** It is a complete subsystem — guest
allocation, the `XBOX_HEAP_BASE` bump heap, `g_xbox_mem_offset`, the page-zero
trap, `RECOMP_TLS`. It replaces `ogxbox_runtime.c`'s ad-hoc `g_guest_ram`
malloc; our `g_guest_ram` / `MEM*` macros are re-pointed at its allocation.

**Bridge: adapt X-Men's `kernel_bridge.c`, do not regenerate.** 2,068 lines,
147 per-ordinal handlers carrying months of bring-up fixes (SEH pointer
validation via `BRIDGE_PTR_OK`, a handle table for 64-bit `HANDLE`s in 32-bit
guest slots, the `PsCreateSystemThreadEx` main-thread special case). Adaptation
is mechanical:

| X-Men | this SDK |
|---|---|
| `g_esp`, `g_eax`, `g_ecx`, ... (TLS globals) | `c->esp`, `c->eax`, ... (`RecompCtx*` param) |
| `static void bridge_X(void)` | `void __imp__X(RecompCtx* c)` |
| `STACK_ARG(n)` = `BRIDGE_MEM32(g_esp + n*4)` (after the dispatcher pops the return addr) | `MEM32(c->esp + n*4)` — our emitter pushes **no** return addr, so arg0 is already at `c->esp+0` |
| dispatcher pops `argc*4` after the call | each `__imp__X` does `c->esp += argc*4` itself (`__stdcall`); `__cdecl`/varargs leave it to the caller |
| `recomp_lookup(va)` for function-pointer args | `rex_dispatch` / the dispatch table |
| `BRIDGE_MEM32` etc. | `MEM32` etc. (identical math) |

Emitter change is minimal: emit `extern void __imp__X(RecompCtx*);` for adapted
imports; the weak `__imp__` stub in `recomp_imports.c` stays as the fallback for
any import not yet adapted.

**Vendored** into `runtime/kernel/` + `runtime/platform/` (all the user's own
code from the X-Men recomp):
`kernel_{ob,thread,sync,rtl,file,io,memory,pool,hal,path,crypto,xbox}.c`,
`kernel_thunks.c`, `kernel_bridge.c` (to be adapted),
`xbox_memory_layout.{c,h}`, `xbox_page_zero_trap.{c,h}`, `xbox_watch.{c,h}`,
`kernel.h`, `platform/{xbox_winnt.h,win32_compat.{c,h}}`.

### Step status

- [x] vendor kernel + platform sources
- [x] `runtime/kernel/` compiles — all 17 files, 0 errors, clang-cl, with
      `-I runtime -I runtime/kernel` (include root is `runtime/`, so `kernel.h`'s
      `#include "platform/xbox_winnt.h"` resolves). Windows branches are clean;
      no POSIX-header trouble.
- [ ] `xbox_memory_layout.c` wired as the RAM owner; `MEM*` re-pointed
- [ ] `kernel_bridge.c` → `recomp_kbridge.c`, `__imp__*` exported (the one file
      still on the old global-register ABI; `g_esp`/`g_eax`/`recomp_lookup` are
      externs there, so it compiles standalone now, links after adaptation)
- [ ] generated recomp builds against it and runs past the NULL-StartRoutine wall

---

## Blocker found: stdcall arg cleanup + the HLE call boundary (2026-09-10)

Tracing `PsCreateSystemThreadEx` (the "NULL StartRoutine" wall) to root cause:

1. **The wall itself was a wrong stack offset.** `__imp__PsCreateSystemThreadEx`
   read `StartRoutine` from `arg(c,6)`; on OG Xbox `StartRoutine` is arg 6 and
   `SystemRoutine` is arg 10, and the kernel enters
   `SystemRoutine(StartRoutine, StartContext)`. X-Men's own logs confirm:
   `routine=0x0019F196 (SystemRoutine) ctx1=0x001A1C23 (StartRoutine) ctx2=0`.
   Both `0x0019F196` (CRT `_threadstartex`) and `0x001A1C23` (thread main) are
   **undetected by analysis** — reachable only as data values passed to the
   kernel. Seeding them (`--seed 0x19F196,0x1A1C23`) makes the emitter produce
   `sub_0019F196` / `sub_001A1C23`; both compile.

2. **The emitter drops the `ret` immediate.** `emit.c` lowers every `ret`
   (`ZYDIS_MNEMONIC_RET`) to `REX_LEAVE(); return;` — it ignores the `ret N`
   operand. Our model: `call` is a host C call (no guest return address
   pushed), so guest `esp` is only moved by explicit push/pop. A `__stdcall`
   callee's `ret N` must therefore do `c->esp += N` to clean the args the
   caller pushed; dropping `N` leaks `N` bytes of guest stack on every stdcall
   return. `__cdecl` is already correct (bare `ret` → `return;`, caller emits
   its own `add esp, N`).

   Fix: `ret imm` → `c->esp += imm; REX_LEAVE(); return;` (read
   `raw.operands[0].imm.value.u`). This is on the `c`/`cpp` emitter (`emit.c`);
   `main`'s C# emitter (`CEmitter.cs`) has the same gap.

3. **`_SEH_prolog4` (`sub_003432A8`) computes its frame from `esp` assuming a
   pushed return address.** Functions that use it (`sub_0019F196` does) then
   read args at `[ebp+8]`. With no guest return address our translation is off
   by 4 for those. Options: (a) the HLE trampoline pushes a dummy return
   address before dispatching into guest code that uses `_SEH_prolog`;
   (b) the emitter recognises `_SEH_prolog*`/`_SEH_epilog*` and models the
   frame directly. (a) is the bring-up shortcut, (b) is correct long-term.

### Consolidation

Part 2 iterates fastest on the `c` branch: self-contained C, the emitter is
`emit.c` (directly fixable), and it already produces byte-identical analysis to
`csharp`. Moving Phase A there — kernel vendor + these emitter fixes — and
leaving `csharp`/`main` as the reference and `cpp` as the ReXGlue-reuse branch.

---

## Phase A progress (2026-09-10, `c` branch, commit 7c53a7f + diag)

The calling-convention fix + thunk fixup + manual overrides get the recompiled
X-Men Legends this far:

```
boot -> thunkfix (15 data exports patched, 115 function slots kept as ordinals)
     -> XBE entry -> PsCreateSystemThreadEx(StartRoutine=0x1A1C23, SystemRoutine=0x19F196)
     -> thread: sub_0019F196 (manual CRT trampoline) -> sub_001A1C23 (manual)
     -> sub_001A237D (engine/device init, real code) -> ~10 calls deep
     -> STUCK: tight poll loop, no further function entries, frozen at 0x0019DD85's
        neighbourhood for 15 s (g_rex_enter_count flat at 10)
```

`sub_0019DD85` and `sub_001A1D5F` are thin wrappers around `NtClose` (ordinal
187) and a sibling ordinal. The spin is in a caller a few frames up — a
register/memory poll that never changes because nothing in the runtime signals
it (another thread, a timer, a hardware/interrupt flag, or a kernel object our
stub HLE doesn't actually wake).

**Diagnostic added:** `-DREX_TRACE` now exports `g_rex_last_enter` /
`g_rex_enter_count`; `ogxbox_main.c` samples them every 0.5 s so "running" vs
"stuck" is visible without a debugger.

### Next

- A **poll-loop finder**: detect a backward branch executing many times with no
  intervening `call`, dump the addresses/values it reads. (The X-Men recomp's
  "software poll" instrument does exactly this.)
- Likely fixes once located: a real object table so `NtWaitForSingleObject` /
  `KeWaitForSingleObject` block and wake correctly; a monotonic
  `KeQuerySystemTime` / interrupt-time source; the missing worker thread the
  main thread is waiting on actually being spawned and run.
- Then the CRT per-thread setup (`sub_001A3639` etc., currently skipped) needs
  a minimal TIB so `fs:[0x28]` chains resolve.

---

## Phase A — bridge wired (2026-09-10, commit aa390fe / 8953a26)

The generated recomp now compiles and links the full vendored OG Xbox kernel
(13 `kernel/*.c` + `platform/win32_compat.c`) plus `ogxbox_bridge.c` —
`kernel_bridge.c` mechanically retargeted from the X-Men recomp's
global-register ABI to `RecompCtx*` (61 handlers, ~140 ordinals). `rex_kernel_dispatch`
(in `ogxbox_kernel_glue.c`): ordinal 255 → our real-thread PsCreateSystemThreadEx,
else the bridge handler + `c->esp += 4 + stdcall_args_for_ordinal(ord)`, else the
generated per-ordinal `rex_kthunk_fallback`. Heap = one bump allocator
(`rex_pool_alloc`, 0x800000-0x2E00000) shared by the HLE and the vendored
kernel's `xbox_Heap*`. `xbox_MemoryLayoutInit` stubbed (the SDK owns RAM).

Bridge handlers execute (their trace lines appear). Also fixed: the weak
`__imp__` stub and `rex_kthunk_fallback`'s default now pop the return-address
slot (they were leaking >=4 bytes per unhandled kernel call).

### Blocker: kernel-thunk ordinal mapping

X-Men's engine init crashes in `sub_001A23F3` writing `[ebp-0x34]` with a
near-zero `ebp`. Traced to `sub_001A2DE0`, a 5-arg `ret 0x14` forwarder that
calls the import thunk `sub_001A3C8C: jmp [0x003C6C44]` with all 5 args and no
`add esp` after — implying its target is a 5-arg `__stdcall`. But
`g_rex_kthunk` records `0x003C6C44 → ordinal 24` (`ExQueryPoolBlockSize`, a
**1-arg** function), the bridge has no handler for 24, so the fallback pops only
4 bytes and the 20 bytes of leaked args corrupt `sub_001A2DE0`'s saved `ebp`.
Two other call sites to the same thunk push **4** args, not 5 — inconsistent
arg counts to one stdcall target is impossible on hardware, so **either the XBE
kernel-thunk table parse (`xbe.c`, offset 0x0158 + the u32 array) is off by an
entry, or `sub_001A2DE0` / the 4-arg sites are mis-decoded**. Verify the
ordinal→thunk-VA mapping against the raw XBE first.

Downstream, the real fix for thunk-forwarders (`sub_X: jmp [import]` called
with caller-varying arg counts, i.e. `__cdecl`): the glue must not pop args for
those — the caller's own `add esp, N` does. The emitter can mark a
`jmp [import]`-only function so the dispatch pops just the return slot.
