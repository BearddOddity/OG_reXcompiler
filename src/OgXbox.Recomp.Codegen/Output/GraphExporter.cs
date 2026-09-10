// Export the discovered FunctionGraph to JSON.
//
// Emits the schema the X-Men recomp's tools/recomp already consumes
// (functions.json + labels.json), so a fixed-point graph can drop in for the
// hand-maintained seed list.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using OgXbox.Recomp.Codegen.Phases;

namespace OgXbox.Recomp.Codegen.Output;

public static class GraphExporter
{
    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    public static void WriteAll(CodegenContext ctx, string outDir)
    {
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "functions.json"), FunctionsJson(ctx));
        File.WriteAllText(Path.Combine(outDir, "labels.json"), LabelsJson(ctx));
        File.WriteAllText(Path.Combine(outDir, "seeded_functions.json"), SeededJson(ctx));
        File.WriteAllText(Path.Combine(outDir, "analysis_summary.json"), SummaryJson(ctx));
    }

    public static string FunctionsJson(CodegenContext ctx)
    {
        var view = ctx.Binary;

        var list = ctx.Graph.Functions.Values
            .Where(n => !n.IsImport)
            .OrderBy(n => n.Base)
            .Select(n => new Dictionary<string, object?>
            {
                ["start"] = Hex(n.Base),
                ["end"] = Hex(n.End),
                ["size"] = n.Size,
                ["name"] = n.Name,
                ["section"] = view.FindSection(n.Base)?.Name ?? "",
                ["authority"] = Authority.Name(n.Authority),
                ["state"] = n.State.ToString().ToLowerInvariant(),
                ["num_instructions"] = n.Instructions.Count,
                ["blocks"] = n.Blocks.Select(b => new[] { Hex(b.Base), Hex(b.End) }).ToArray(),
                ["labels"] = n.Labels.Select(Hex).ToArray(),
                ["calls_to"] = n.Calls.Select(c => Hex(TargetAddr(c.Target))).Distinct().ToArray(),
                ["tail_calls"] = n.TailCalls.Select(c => Hex(TargetAddr(c.Target))).Distinct().ToArray(),
                ["shares_registers"] = n.SharesRegisters,
            })
            .ToList();

        return JsonSerializer.Serialize(list, Opts);
    }

    public static string LabelsJson(CodegenContext ctx)
    {
        var view = ctx.Binary;
        var labels = ctx.Graph.Functions.Values
            .Where(n => !n.IsImport)
            .OrderBy(n => n.Base)
            .Select(n => new Dictionary<string, object?>
            {
                ["address"] = Hex(n.Base),
                ["name"] = n.Name,
                ["type"] = "function",
                ["section"] = view.FindSection(n.Base)?.Name ?? "",
                ["authority"] = Authority.Name(n.Authority),
            })
            .ToList();
        return JsonSerializer.Serialize(labels, Opts);
    }

    public static string SeededJson(CodegenContext ctx)
    {
        var addrs = ctx.Graph.Functions.Values
            .Where(n => !n.IsImport)
            .Select(n => (long)n.Base)
            .OrderBy(a => a)
            .ToArray();
        return JsonSerializer.Serialize(new { count = addrs.Length, addresses = addrs }, Opts);
    }

    public static string SummaryJson(CodegenContext ctx)
    {
        var g = ctx.Graph;
        var summary = new Dictionary<string, object?>
        {
            ["base_address"] = Hex(ctx.Binary.BaseAddress),
            ["entry_point"] = Hex(ctx.Binary.EntryPoint),
            ["functions_total"] = g.FunctionCount,
            ["functions_sealed"] = g.SealedCount,
            ["functions_pending"] = g.PendingCount,
            ["imports"] = g.Functions.Values.Count(n => n.IsImport),
            ["code_regions"] = ctx.Scan.CodeRegions.Count,
            ["data_regions"] = ctx.Scan.DataRegions.Count,
            ["validation_errors"] = ctx.Errors.Count,
            ["by_authority"] = g.Functions.Values
                .GroupBy(n => Authority.Name(n.Authority))
                .ToDictionary(gr => gr.Key, gr => gr.Count()),
        };
        return JsonSerializer.Serialize(summary, Opts);
    }

    private static string Hex(uint v) => $"0x{v:X8}";

    private static uint TargetAddr(CallTarget t) => t switch
    {
        CallTarget.ToFunction f => f.Node.Base,
        CallTarget.ToImport i => i.Address,
        CallTarget.Unresolved u => u.Address,
        _ => 0,
    };
}
