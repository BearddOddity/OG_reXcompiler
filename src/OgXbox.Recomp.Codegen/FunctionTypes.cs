// Types and structures used by FunctionNode and FunctionGraph.
//
// Ported to C# / x86 from rex::codegen (ReXGlue SDK, BSD-3-Clause,
// Copyright (c) 2026 Tom Clay; portions derived from the Xenia project).
// See LICENSE.rexglue. ReXGlue targets Xbox 360 / PowerPC; this port targets
// the original Xbox / 32-bit x86, so PPC-specific fields (CTR/XER/CR/FPSCR,
// bctr jump tables) become their x86 equivalents (EFLAGS, jmp [table]).

using System;
using System.Collections.Generic;

namespace OgXbox.Recomp.Codegen;

/// <summary>
/// Determines boundary mutability and merge eligibility. Only <see cref="GapFill"/>
/// can be absorbed during vacancy merging; every other level is an immutable entry
/// point. Higher value wins when two authorities land on the same address.
/// </summary>
public enum FunctionAuthority : byte
{
    /// Speculative — found in an unclaimed gap, CAN be absorbed.
    GapFill = 0,

    /// Found via a direct <c>call</c> — immutable entry point.
    Discovered = 1,

    /// Found in a vtable — immutable entry point.
    Vtable = 2,

    /// Save/restore or CRT helper — fixed, overlaps allowed.
    Helper = 3,

    /// From .pdata — PPC only, unused on x86 (32-bit x86 has no .pdata; SEH is
    /// a runtime fs:[0] chain). Kept for lattice-shape parity. See ledger #280.
    Pdata = 4,

    /// User config / seed list — exact boundaries, immutable.
    Config = 5,

    /// Import thunk — external function, immutable.
    Import = 6,
}

/// <summary>How a branch target should be treated during code generation.</summary>
public enum TargetKind
{
    /// Target is inside the caller's own function (an internal label).
    InternalLabel,

    /// Target is a function entry point.
    Function,

    /// Target is an import.
    Import,

    /// Target is not recognized.
    Unknown,
}

/// <summary>The 3-state function lifecycle.</summary>
public enum FunctionState : byte
{
    /// Entry point known, blocks/instructions not yet assigned.
    Registered,

    /// Blocks and instructions assigned, may still have unresolved branches.
    Discovered,

    /// All branches resolved, ready for code generation.
    Sealed,
}

public static class Authority
{
    public static string Name(FunctionAuthority auth) => auth switch
    {
        FunctionAuthority.GapFill => "gap_fill",
        FunctionAuthority.Discovered => "discovered",
        FunctionAuthority.Vtable => "vtable",
        FunctionAuthority.Helper => "helper",
        FunctionAuthority.Pdata => "pdata",
        FunctionAuthority.Config => "config",
        FunctionAuthority.Import => "import",
        _ => "unknown",
    };
}

//=============================================================================
// Basic block
//=============================================================================

public readonly record struct Block(uint Base, uint Size)
{
    public uint End => Base + Size;
    public bool Contains(uint addr) => addr >= Base && addr < End;
}

//=============================================================================
// Code region — a candidate-code span left by the Scan phase (End exclusive)
//=============================================================================

public readonly record struct CodeRegion(uint Start, uint End, string Section)
{
    public uint Size => End - Start;
    public bool Contains(uint addr) => addr >= Start && addr < End;
}

//=============================================================================
// Jump table (x86: jmp [reg*4 + table] / jmp [reg*4 + table + base])
//=============================================================================

public sealed class JumpTable
{
    /// Address of the indirect <c>jmp</c> instruction.
    public uint JumpAddress { get; init; }

    /// Address of the jump-table data.
    public uint TableAddress { get; init; }

    /// Register holding the switch index.
    public byte IndexRegister { get; init; }

    /// Resolved case targets (become internal labels).
    public List<uint> Targets { get; init; } = new();
}

//=============================================================================
// Call target — resolved destination of a call/jump
//=============================================================================

public abstract record CallTarget
{
    public sealed record ToFunction(FunctionNode Node) : CallTarget;

    public sealed record ToImport(uint Address, string Name) : CallTarget;

    public sealed record Unresolved(uint Address) : CallTarget;

    public bool IsResolved => this is not Unresolved;
    public bool IsFunction => this is ToFunction;
    public bool IsImport => this is ToImport;

    public FunctionNode? AsFunction => (this as ToFunction)?.Node;

    public static CallTarget Function(FunctionNode fn) => new ToFunction(fn);
    public static CallTarget ImportRef(uint addr, string name) => new ToImport(addr, name);
    public static CallTarget UnresolvedRef(uint addr) => new Unresolved(addr);
}

/// <summary>A resolved call site within a function.</summary>
public readonly record struct CallEdge(uint Site, CallTarget Target);

/// <summary>An internal branch awaiting resolution.</summary>
public readonly record struct UnresolvedJump(uint Site, uint Target, bool IsCall, bool IsConditional);

//=============================================================================
// Exception handling — x86 _EH4 SEH and C++ EH (FuncInfo, magic 0x19930522)
//=============================================================================

public readonly record struct SehScope(uint TryStart, uint TryEnd, uint Handler, uint Filter);

public sealed class SehExceptionInfo
{
    public uint HandlerThunk { get; init; }
    public uint ScopeTableAddr { get; init; }
    public List<SehScope> Scopes { get; init; } = new();
    public uint FrameSize { get; init; }
    public uint RestoreHelper { get; init; }
}

public static class CxxEh
{
    public const uint Magic = 0x19930522;
}

public readonly record struct CxxUnwindEntry(int ToState, uint Action);

public readonly record struct CxxIpStateEntry(uint Ip, int State);

public readonly record struct CxxCatchHandler(
    uint Adjectives, uint TypeDescriptor, int CatchObjDisplacement, uint HandlerAddress);

public sealed class CxxTryBlock
{
    public int TryLow { get; init; }
    public int TryHigh { get; init; }
    public int CatchHigh { get; init; }
    public List<CxxCatchHandler> Handlers { get; init; } = new();
}

public sealed class CxxExceptionInfo
{
    public uint HandlerThunk { get; init; }
    public uint FuncInfoAddr { get; init; }
    public uint MaxState { get; init; }
    public List<CxxUnwindEntry> UnwindMap { get; init; } = new();
    public List<CxxTryBlock> TryBlocks { get; init; } = new();
    public List<CxxIpStateEntry> IpToStateMap { get; init; } = new();
}

public sealed class ExceptionInfo
{
    public SehExceptionInfo? Seh { get; init; }
    public CxxExceptionInfo? Cxx { get; init; }

    public bool HasInfo => Seh is not null || Cxx is not null;
    public bool IsSeh => Seh is not null;
    public bool IsCxx => Cxx is not null;

    public uint HandlerThunk =>
        Seh?.HandlerThunk ?? Cxx?.HandlerThunk ?? 0;
}

//=============================================================================
// Function analysis (computed at seal time)
//=============================================================================

public sealed class FunctionAnalysis
{
    // x86 has EFLAGS implicit in every instruction; the interesting derived
    // facts here are which condition flags a function leaves live across calls
    // (the deferred-flag miscompile class the X-Men port fought) and whether it
    // touches x87/SSE control state. Filled in as the emitter needs it.
    public bool UsesFpuControlWord { get; set; }
    public bool UsesMxcsr { get; set; }
    public bool UsesDirectionFlag { get; set; }
}

//=============================================================================
// Code buffer — one executable section's bytes, owned by the graph
//=============================================================================

public sealed class CodeBuffer
{
    public byte[] Data { get; }
    public uint BaseAddress { get; }

    public CodeBuffer(uint baseAddress, ReadOnlySpan<byte> data)
    {
        BaseAddress = baseAddress;
        Data = data.ToArray();
    }

    public uint Size => (uint)Data.Length;
    public uint EndAddress => BaseAddress + Size;
    public bool Contains(uint addr) => addr >= BaseAddress && addr < EndAddress;

    public ReadOnlySpan<byte> Translate(uint addr) =>
        Contains(addr) ? Data.AsSpan((int)(addr - BaseAddress)) : default;
}
