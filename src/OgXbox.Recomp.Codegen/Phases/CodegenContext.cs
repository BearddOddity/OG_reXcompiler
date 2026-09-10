// CodegenContext — single source of truth threaded through every analysis phase.
//
// Ported (lean) from rex::codegen::CodegenContext + AnalysisState (ReXGlue SDK,
// BSD-3-Clause).

using System.Collections.Generic;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Phases;

/// <summary>Binary-derived facts and analysis results accumulated across phases.</summary>
public sealed class AnalysisState
{
    /// x86 ABI/CRT helper addresses (0 = not found). Save/restore register
    /// helpers, alloca probe, SEH prolog/epilog.
    public uint SehProlog { get; set; }
    public uint SehEpilog { get; set; }
    public uint AllocaProbe { get; set; }

    /// Indirect-jump sites known to be computed calls (vtable/switch dispatch).
    public HashSet<uint> KnownIndirectCalls { get; } = new();

    /// Exception-handler thunk addresses (from EH scan + config hints).
    public HashSet<uint> ExceptionHandlerFuncs { get; } = new();

    /// Addresses discovered via exception-info parsing.
    public HashSet<uint> EhDiscoveredFuncs { get; } = new();

    /// Bytes known not to be code: addr -> size.
    public Dictionary<uint, uint> InvalidInstructions { get; } = new();
}

/// <summary>Output of the Scan phase.</summary>
public sealed class ScanResult
{
    public List<CodeRegion> CodeRegions { get; } = new();
    public List<CodeRegion> DataRegions { get; } = new();

    /// True if <paramref name="addr"/> falls in a scanned code region.
    public bool InCodeRegion(uint addr)
    {
        foreach (var r in CodeRegions)
            if (r.Contains(addr)) return true;
        return false;
    }
}

public sealed class CodegenContext
{
    public required BinaryView Binary { get; init; }
    public required DecodedBinary Decoded { get; init; }
    public required FunctionGraph Graph { get; init; }
    public required RecompilerConfig Config { get; init; }

    public AnalysisState State { get; } = new();
    public ScanResult Scan { get; } = new();

    public static CodegenContext Create(BinaryView binary, RecompilerConfig? config = null)
    {
        config ??= new RecompilerConfig();
        return new CodegenContext
        {
            Binary = binary,
            Decoded = new DecodedBinary(binary),
            Graph = new FunctionGraph(),
            Config = config,
        };
    }
}
