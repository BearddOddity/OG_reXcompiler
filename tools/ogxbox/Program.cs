// ogxbox — CLI front end for the OG Xbox Recomp SDK.
//
//   ogxbox analyze <file.xbe> [-o <outdir>] [--seed <addr>,...]
//
// Runs the full analysis pipeline and writes functions.json / labels.json /
// seeded_functions.json / analysis_summary.json.

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using OgXbox.Recomp.Codegen.Binary;
using OgXbox.Recomp.Codegen.Emit;
using OgXbox.Recomp.Codegen.Output;
using OgXbox.Recomp.Codegen.Phases;

if (args.Length < 2 || (args[0] != "analyze" && args[0] != "emit"))
{
    Console.Error.WriteLine("usage: ogxbox <analyze|emit> <file.xbe> [-o <outdir>] [--seed <addr>,...]");
    return 2;
}
bool doEmit = args[0] == "emit";

string xbePath = args[1];
string outDir = "ogxbox-out";
var seeds = Array.Empty<uint>();

for (int i = 2; i < args.Length - 1; i++)
{
    if (args[i] == "-o") outDir = args[i + 1];
    else if (args[i] == "--seed")
        seeds = args[i + 1].Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(ParseAddr).ToArray();
}

if (!File.Exists(xbePath))
{
    Console.Error.WriteLine($"file not found: {xbePath}");
    return 1;
}

var sw = System.Diagnostics.Stopwatch.StartNew();

var xbe = Xbe.Load(xbePath);
Console.WriteLine($"XBE: base=0x{xbe.BaseAddress:X8} entry=0x{xbe.EntryPoint:X8} " +
                  $"sections={xbe.Sections.Count} kernel-imports={xbe.KernelImports.Count} " +
                  $"({(xbe.IsDebug ? "debug" : "retail")})");

var view = BinaryView.FromXbe(xbe);
var cfg = new RecompilerConfig();
foreach (var s in seeds) cfg.SeedFunctions.Add(s);

var ctx = CodegenContext.Create(view, cfg);
bool clean = AnalysisPipeline.Run(ctx);

sw.Stop();
Console.WriteLine($"functions={ctx.Graph.FunctionCount} sealed={ctx.Graph.SealedCount} " +
                  $"pending={ctx.Graph.PendingCount} " +
                  $"imports={ctx.Graph.Functions.Values.Count(n => n.IsImport)}");
Console.WriteLine($"code-regions={ctx.Scan.CodeRegions.Count} data-regions={ctx.Scan.DataRegions.Count}");
Console.WriteLine($"validation: {(clean ? "clean" : $"{ctx.Errors.Count} errors")}  ({sw.ElapsedMilliseconds} ms)");

GraphExporter.WriteAll(ctx, outDir);
Console.WriteLine($"wrote functions.json, labels.json, seeded_functions.json, analysis_summary.json -> {outDir}/");

if (doEmit)
{
    var es = CodegenWriter.WriteAll(ctx, outDir);
    double cov = es.Instructions == 0 ? 0
        : 100.0 * (es.Instructions - es.Unimplemented) / es.Instructions;
    Console.WriteLine($"emit: {es.Functions} functions, {es.Instructions} instructions, " +
                      $"{es.Unimplemented} unimplemented ({cov:F1}% lowered)");
    foreach (var (m, n) in es.UnimplementedByMnemonic.OrderByDescending(kv => kv.Value).Take(15))
        Console.WriteLine($"  {n,8}  {m}");
    Console.WriteLine($"wrote recomp_*.c, recomp_decls.h, ogxbox_runtime.h -> {outDir}/");
}

return clean ? 0 : 3;

static uint ParseAddr(string s)
{
    s = s.Trim();
    return s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? uint.Parse(s[2..], NumberStyles.HexNumber)
        : uint.Parse(s);
}
