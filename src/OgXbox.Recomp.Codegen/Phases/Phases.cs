// The six analysis phases: Register -> Scan -> Discover -> GapFill -> Merge ->
// Validate. Ported to C# / x86 from rex::codegen phase_*.cpp (ReXGlue SDK,
// BSD-3-Clause).
//
// x86 departures: no .pdata/PDATA (ledger #280), no PPC save/restore helpers,
// jump tables instead of bctr, _EH4 scope-table shape for the GapFill skip.

using System.Collections.Generic;
using System.Linq;
using OgXbox.Recomp.Codegen.Analysis;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Phases;

//=============================================================================
// Register
//=============================================================================

public static class RegisterPhase
{
    public static void Run(CodegenContext ctx)
    {
        var g = ctx.Graph;
        var cfg = ctx.Config;

        foreach (var a in cfg.ExceptionHandlerHints) ctx.State.ExceptionHandlerFuncs.Add(a);

        // Kernel imports -> IMPORT nodes, discovered + sealed immediately.
        foreach (var sym in ctx.Binary.ImportSymbols)
        {
            var node = g.AddImportFunction(sym.Address, "__imp__" + ShortName(sym.Name));
            if (node.CanDiscover) node.DiscoverAsImport();
            if (node.CanSeal()) node.Seal();
        }

        // Entry point -> CONFIG.
        if (ctx.Binary.EntryPoint != 0)
            g.AddFunction(ctx.Binary.EntryPoint, 0, FunctionAuthority.Config, "xstart", hasXrefs: true);

        // Seed list -> CONFIG.
        foreach (uint addr in cfg.SeedFunctions)
            g.AddFunction(addr, 0, FunctionAuthority.Config, hasXrefs: true);

        // Explicit function/chunk config.
        foreach (var (addr, fc) in cfg.Functions)
        {
            uint size = fc.EffectiveSize(addr);
            var node = g.AddFunction(addr, size, FunctionAuthority.Config,
                                     fc.Name ?? $"sub_{addr:X8}", hasXrefs: true);
            if (fc.ShareRegisters) node.SharesRegisters = true;
            if (size != 0) g.RegisterChunk(addr, size);
        }
    }

    private static string ShortName(string importName)
    {
        // "xboxkrnl@42:DbgPrint" -> "DbgPrint"
        int colon = importName.LastIndexOf(':');
        return colon >= 0 ? importName[(colon + 1)..] : importName;
    }
}

//=============================================================================
// Discover
//=============================================================================

public static class DiscoverPhase
{
    public static void Run(CodegenContext ctx)
    {
        var g = ctx.Graph;
        var scanner = new FunctionScanner(ctx.Decoded, ctx.Scan.CodeRegions);

        // Iterative call-graph expansion to a fixed point.
        int lastCount = -1;
        for (int iter = 0; iter < 64; iter++)
        {
            int count = g.FunctionCount;
            if (count == lastCount && iter > 0) break;
            lastCount = count;

            var known = PhaseHelpers.BuildKnownFunctions(g);
            if (PhaseHelpers.DiscoverPendingFunctions(ctx, scanner, known) == 0) break;
        }

        // VTable scan -> VTABLE functions, then continue discovery.
        var vtables = new VTableScanner(ctx.Binary).Scan();
        int newFns = 0;
        foreach (var vt in vtables)
            foreach (uint slot in vt.Slots)
            {
                if (g.IsEntryPoint(slot)) continue;
                if (scanner.RegionContaining(slot) is null) continue;
                g.AddFunction(slot, 4, FunctionAuthority.Vtable, hasXrefs: true);
                newFns++;
            }

        if (newFns > 0)
        {
            for (int iter = 0; iter < 64; iter++)
            {
                var known = PhaseHelpers.BuildKnownFunctions(g);
                if (PhaseHelpers.DiscoverPendingFunctions(ctx, scanner, known) == 0) break;
                if (g.FunctionCount == lastCount) break;
                lastCount = g.FunctionCount;
            }
        }
    }
}

//=============================================================================
// GapFill
//=============================================================================

public static class GapFillPhase
{
    public static void Run(CodegenContext ctx)
    {
        var g = ctx.Graph;
        var scanner = new FunctionScanner(ctx.Decoded, ctx.Scan.CodeRegions);
        var knownCallables = new HashSet<uint>(g.Functions.Keys);

        foreach (var region in ctx.Scan.CodeRegions.ToList())
        {
            foreach (var seg in SplitOnTerminators(ctx, region, knownCallables))
            {
                if (g.IsEntryPoint(seg.Start)) continue;
                if (g.GetFunctionContaining(seg.Start) is not null) continue;
                if (LooksLikeExceptionData(ctx, seg.Start)) continue;
                g.AddFunction(seg.Start, seg.Size, FunctionAuthority.GapFill, hasXrefs: false);
            }
        }

        var known = PhaseHelpers.BuildKnownFunctions(g, excludeGapFill: true);
        PhaseHelpers.DiscoverPendingFunctions(ctx, scanner, known);

        CleanupAbsorbed(ctx);
    }

    private static IEnumerable<CodeRegion> SplitOnTerminators(
        CodegenContext ctx, CodeRegion region, IReadOnlySet<uint> knownCallables)
    {
        uint segStart = region.Start;
        uint addr = region.Start;
        while (addr < region.End)
        {
            var insn = ctx.Decoded.DecodeAt(addr);
            if (insn is null || insn.Flow == InsnFlow.Invalid) { addr++; continue; }

            bool split = false;
            if (insn.Flow == InsnFlow.Return) split = true;
            else if (insn.Flow == InsnFlow.UnconditionalBranch && insn.Target != 0 &&
                     insn.Target != segStart && knownCallables.Contains(insn.Target))
                split = true;

            uint next = insn.EndAddress;
            if (split)
            {
                if (next > segStart) yield return new CodeRegion(segStart, next, region.Section);
                segStart = next;
            }
            addr = next;
        }
        if (segStart < region.End)
            yield return new CodeRegion(segStart, region.End, region.Section);
    }

    // x86 _EH4: a scope-table entry sitting in .text is {handler-thunk, .rdata ptr}.
    private static bool LooksLikeExceptionData(CodegenContext ctx, uint addr)
    {
        uint? first = ctx.Binary.ReadU32(addr);
        uint? second = ctx.Binary.ReadU32(addr + 4);
        if (first is null || second is null) return false;
        if (!ctx.Graph.IsEntryPoint(first.Value)) return false;
        var rdata = ctx.Binary.FindSectionByName(".rdata");
        if (rdata is null) return false;
        return second.Value >= rdata.BaseAddress && second.Value < rdata.End;
    }

    private static void CleanupAbsorbed(CodegenContext ctx)
    {
        var g = ctx.Graph;

        // Non-GapFill extents, sorted by base for O(log f) containment lookup.
        var solid = g.Functions.Values
            .Where(n => n.Authority != FunctionAuthority.GapFill)
            .Select(n => (Start: n.Base, End: n.End))
            .OrderBy(x => x.Start).ToArray();

        bool InsideSolid(uint addr)
        {
            int lo = 0, hi = solid.Length - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                if (solid[mid].Start > addr) hi = mid - 1;
                else if (addr >= solid[mid].End) lo = mid + 1;
                else return true;
            }
            return false;
        }

        var gapFills = g.Functions.Values
            .Where(n => n.Authority == FunctionAuthority.GapFill)
            .Select(n => n.Base).OrderBy(a => a).ToArray();

        var toRemove = new List<uint>();
        foreach (uint addr in gapFills)
        {
            if (InsideSolid(addr)) { toRemove.Add(addr); continue; }
            // absorbed by an earlier GapFill that grew over it
            var container = g.GetFunctionContaining(addr);
            if (container is not null && container.Base < addr &&
                container.Authority == FunctionAuthority.GapFill)
                toRemove.Add(addr);
        }
        foreach (uint a in toRemove) g.RemoveFunction(a);
    }
}

//=============================================================================
// Merge
//=============================================================================

public static class MergePhase
{
    public static void Run(CodegenContext ctx)
    {
        var g = ctx.Graph;
        g.SetMemoryReader(addr => ctx.Binary.ReadU32(addr));

        for (int iter = 0; iter < 32; iter++)
        {
            int changed = 0;
            foreach (uint addr in g.PendingFunctions.Select(n => n.Base).ToList())
                changed += g.TryResolveFunction(addr);
            if (changed == 0) break;
        }

        // Second-chance resolution: an unresolved branch whose target lands
        // *inside* another registered function is a tail call to that function's
        // internal label (ReXGlue classifyTarget case 4). Codegen emits it as a
        // call into that function; here it just needs to stop blocking the seal.
        foreach (var node in g.PendingFunctions.ToList())
        {
            foreach (var j in node.UnresolvedJumps.ToArray())
            {
                var owner = g.GetFunctionContaining(j.Target);
                if (owner is null || ReferenceEquals(owner, node)) continue;
                node.AddTailCall(j.Site, CallTarget.Function(owner));
                node.RemoveUnresolvedJump(j.Site);
            }
        }

        g.MarkFuncletRegisterSharing();
        g.SealAllReady();
    }
}

//=============================================================================
// Validate — build-time gate
//=============================================================================

public static class ValidatePhase
{
    /// <returns>true if the graph is clean (no unresolved calls).</returns>
    public static bool Run(CodegenContext ctx)
    {
        var g = ctx.Graph;
        var errors = ctx.Errors;

        foreach (var (addr, node) in g.Functions)
        {
            if (node.IsImport) continue;
            foreach (var block in node.Blocks)
            {
                uint p = block.Base;
                while (p < block.End)
                {
                    var insn = ctx.Decoded.DecodeAt(p);
                    if (insn is null) break;

                    // Only direct calls and direct unconditional jumps carry a
                    // target that must land in a function. Conditional branches
                    // to internal labels are handled by Discover.
                    bool check = insn.Target != 0 &&
                                 insn.Flow is InsnFlow.Call or InsnFlow.UnconditionalBranch;
                    if (check)
                    {
                        uint target = insn.Target;
                        bool resolved =
                            node.ContainsAddress(target) ||
                            node.IsWithinBounds(target) ||
                            g.IsEntryPoint(target) ||
                            g.IsImport(target) ||
                            g.GetFunctionContaining(target) is not null;

                        if (!resolved)
                            errors.Add(AnalysisErrorCategory.UnresolvedCall, target, p,
                                $"{(insn.Flow == InsnFlow.Call ? "call" : "jmp")} target not in any function");
                    }

                    uint nextP = insn.EndAddress;
                    if (nextP <= p) break;
                    p = nextP;
                }
            }
        }

        return !errors.HasErrors;
    }
}

//=============================================================================
// Driver
//=============================================================================

public static class AnalysisPipeline
{
    /// <returns>true if Validate passed.</returns>
    public static bool Run(CodegenContext ctx)
    {
        RegisterPhase.Run(ctx);
        ScanPhase.Run(ctx);
        DiscoverPhase.Run(ctx);
        GapFillPhase.Run(ctx);
        MergePhase.Run(ctx);
        return ValidatePhase.Run(ctx);
    }
}
