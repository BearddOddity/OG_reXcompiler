using System;
using System.IO;
using System.Linq;
using OgXbox.Recomp.Codegen.Binary;
using OgXbox.Recomp.Codegen.Phases;
using Xunit;

namespace OgXbox.Recomp.Codegen.Tests;

/// <summary>
/// End-to-end load + scan against a real XBE. Set OGXBOX_TEST_XBE to a .xbe
/// path to run; skipped otherwise so CI needs no game data.
/// </summary>
public class RealXbeSmokeTests
{
    private static string? XbePath => Environment.GetEnvironmentVariable("OGXBOX_TEST_XBE");

    [SkippableFact]
    public void Load_Parses_Sections_Entry_Imports()
    {
        Skip.If(string.IsNullOrEmpty(XbePath) || !File.Exists(XbePath), "OGXBOX_TEST_XBE not set");

        var xbe = Xbe.Load(XbePath!);
        Assert.NotEmpty(xbe.Sections);
        Assert.True(xbe.EntryPoint >= xbe.BaseAddress &&
                    xbe.EntryPoint < xbe.BaseAddress + xbe.ImageSize);
        Assert.Contains(xbe.Sections, s => s.Name == ".text");
        Assert.NotEmpty(xbe.KernelImports);
        Assert.All(xbe.KernelImports, k => Assert.True(k.Ordinal > 0));

        var view = BinaryView.FromXbe(xbe);
        var ctx = CodegenContext.Create(view);
        ScanPhase.Run(ctx);

        Assert.NotEmpty(ctx.Scan.CodeRegions);
        // .text should be near-solid: one big region dominating its coverage.
        var textRegions = ctx.Scan.CodeRegions.Where(r => r.Section == ".text").ToList();
        Assert.NotEmpty(textRegions);
        Assert.True(textRegions.Max(r => r.Size) > 1_000_000,
            $"largest .text region only {textRegions.Max(r => r.Size)} bytes");
    }
}
