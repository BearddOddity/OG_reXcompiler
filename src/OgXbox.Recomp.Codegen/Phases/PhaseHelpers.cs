// Shared helpers for the discovery phases.
//
// Ported from rex::codegen phase_helpers.h (ReXGlue SDK, BSD-3-Clause).

using System.Collections.Generic;
using System.Linq;
using OgXbox.Recomp.Codegen.Analysis;

namespace OgXbox.Recomp.Codegen.Phases;

internal static class PhaseHelpers
{
    public static HashSet<uint> BuildKnownFunctions(FunctionGraph graph, bool excludeGapFill = false)
    {
        var set = new HashSet<uint>();
        foreach (var (addr, node) in graph.Functions)
        {
            if (excludeGapFill && node.Authority == FunctionAuthority.GapFill) continue;
            set.Add(addr);
        }
        return set;
    }

    /// <summary>Discover blocks for every function still in the Registered state. Returns count attempted.</summary>
    public static int DiscoverPendingFunctions(
        CodegenContext ctx, FunctionScanner scanner, IReadOnlySet<uint> knownFunctions)
    {
        var pending = ctx.Graph.Functions.Values.Where(n => n.CanDiscover).Select(n => n.Base).ToList();
        foreach (var addr in pending)
            DiscoverOne(ctx, scanner, addr, knownFunctions);
        return pending.Count;
    }

    public static void DiscoverOne(
        CodegenContext ctx, FunctionScanner scanner, uint funcAddr, IReadOnlySet<uint> knownFunctions)
    {
        var node = ctx.Graph.GetFunction(funcAddr);
        if (node is null || !node.CanDiscover) return;

        if (node.IsImport)
        {
            node.DiscoverAsImport();
            if (node.CanSeal()) node.Seal();
            return;
        }

        // CONFIG functions honour their declared size as an extent cap; others
        // let discovery find the natural boundary from the code region.
        uint declaredSize = node.Authority == FunctionAuthority.Config ? node.Size : 0;

        var result = scanner.DiscoverBlocks(funcAddr, knownFunctions, ctx.Config.SwitchTables);
        if (result.Blocks.Count == 0) return;

        // Cap to the declared size for CONFIG (drop blocks past it).
        if (declaredSize != 0)
        {
            uint end = funcAddr + declaredSize;
            result.Blocks.RemoveAll(b => b.Base >= end);
            for (int i = 0; i < result.Blocks.Count; i++)
                if (result.Blocks[i].End > end)
                    result.Blocks[i] = result.Blocks[i] with { Size = end - result.Blocks[i].Base };
            if (result.Blocks.Count == 0) return;
        }

        node.Discover(result.Blocks, result.Instructions, result.Labels);

        foreach (var jt in result.JumpTables)
            ctx.Graph.AddJumpTableToFunction(funcAddr, jt);

        foreach (uint target in result.ExternalCalls)
        {
            if (ctx.Graph.IsEntryPoint(target) || ctx.Graph.IsImport(target)) continue;
            if (target == ctx.Binary.KernelThunkTableStart) continue;
            ctx.Graph.AddFunction(target, 4, FunctionAuthority.Discovered, hasXrefs: true);
        }

        foreach (var b in result.UnresolvedBranches)
            ctx.Graph.AddUnresolvedJumpToFunction(funcAddr, b.Site, b.Target, b.IsCall, b.IsConditional);
    }
}
