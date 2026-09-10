// Recompiler configuration — user-provided overrides and analysis tuning.
//
// Ported (lean) from rex::codegen::RecompilerConfig (ReXGlue SDK, BSD-3-Clause).
// TOML loading and the full override surface come later; this is what the
// analysis phases currently read.

using System.Collections.Generic;

namespace OgXbox.Recomp.Codegen.Phases;

/// <summary>A mid-function code hook (name + register list + optional control flow).</summary>
public sealed class MidAsmHook
{
    public required string Name { get; init; }
    public List<string> Registers { get; init; } = new();
    public bool Return { get; init; }
    public bool ReturnOnTrue { get; init; }
    public bool ReturnOnFalse { get; init; }
    public uint JumpAddress { get; init; }
    public uint JumpAddressOnTrue { get; init; }
    public uint JumpAddressOnFalse { get; init; }
    public bool AfterInstruction { get; init; }
}

/// <summary>Manual function/chunk boundary override. Non-zero <see cref="Parent"/> = a chunk.</summary>
public sealed class FunctionConfig
{
    public uint Size { get; init; }
    public uint End { get; init; }
    public string? Name { get; init; }
    public uint Parent { get; init; }
    public bool ShareRegisters { get; init; }

    public bool IsChunk => Parent != 0;

    public uint EffectiveSize(uint address) =>
        Size != 0 ? Size : (End > address ? End - address : 0);
}

public sealed class RecompilerConfig
{
    public string ProjectName { get; set; } = "ogxbox";
    public string? FilePath { get; set; }
    public string? OutDirectoryPath { get; set; }

    // --- Code generation options ---
    public bool GenerateExceptionHandlers { get; set; }

    // --- Analysis tuning ---
    /// Max bytes to extend a function for jump-table targets.
    public uint MaxJumpExtension { get; set; } = 65536;

    /// A run of this many zero bytes (Scan phase) splits a code region.
    /// x86 dwords are frequently 0; 8 bytes = two aligned words, the observed
    /// inter-object gap floor (the X-Men Python prototype used the same).
    public uint MinNullRun { get; set; } = 8;

    /// Consecutive invalid dwords to mark a region as data.
    public uint DataRegionThreshold { get; set; } = 16;

    public uint LargeFunctionThreshold { get; set; } = 1 << 20;

    // --- Manual overrides ---
    public Dictionary<uint, FunctionConfig> Functions { get; } = new();
    public Dictionary<uint, JumpTable> SwitchTables { get; } = new();
    public Dictionary<uint, MidAsmHook> MidAsmHooks { get; } = new();

    /// Explicit function seed addresses (become CONFIG authority).
    public HashSet<uint> SeedFunctions { get; } = new();

    /// Additional exception-handler thunk addresses to treat as SEH handlers.
    public HashSet<uint> ExceptionHandlerHints { get; } = new();
}
