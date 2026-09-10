using System;
using System.Linq;
using OgXbox.Recomp.Codegen;
using OgXbox.Recomp.Codegen.Binary;
using OgXbox.Recomp.Codegen.Phases;
using Xunit;

namespace OgXbox.Recomp.Codegen.Tests;

public class ScanPhaseTests
{
    private const int MinNull = 8; // RecompilerConfig default

    private static SectionView Text(uint @base, byte[] data) => new()
    {
        Name = ".text",
        BaseAddress = @base,
        Size = (uint)data.Length,
        Data = data,
        Executable = true,
        Writable = false,
    };

    private static CodegenContext Ctx(params SectionView[] secs)
    {
        var view = BinaryView.FromSections(secs);
        return CodegenContext.Create(view);
    }

    private static byte[] Fill(byte b, int n) => Enumerable.Repeat(b, n).ToArray();
    private static byte[] Cat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    [Fact]
    public void SolidCode_IsOneRegion()
    {
        var ctx = Ctx(Text(0x1000, Fill(0x90, 64)));
        ScanPhase.Run(ctx);
        var r = Assert.Single(ctx.Scan.CodeRegions);
        Assert.Equal(0x1000u, r.Start);
        Assert.Equal(0x1040u, r.End);
    }

    [Fact]
    public void LongNullRun_SplitsRegion()
    {
        var data = Cat(Fill(0x90, 16), Fill(0x00, MinNull), Fill(0x90, 16));
        var ctx = Ctx(Text(0x2000, data));
        ScanPhase.Run(ctx);
        Assert.Equal(2, ctx.Scan.CodeRegions.Count);
        Assert.Equal((0x2000u, 0x2010u), (ctx.Scan.CodeRegions[0].Start, ctx.Scan.CodeRegions[0].End));
        Assert.Equal((0x2000u + 16 + MinNull, 0x2000u + (uint)data.Length),
                     (ctx.Scan.CodeRegions[1].Start, ctx.Scan.CodeRegions[1].End));
    }

    [Fact]
    public void ShortNullRun_StaysInRegion()
    {
        var data = Cat(Fill(0x90, 8), Fill(0x00, MinNull - 1), Fill(0x90, 8));
        var ctx = Ctx(Text(0x3000, data));
        ScanPhase.Run(ctx);
        var r = Assert.Single(ctx.Scan.CodeRegions);
        Assert.Equal(0x3000u + (uint)data.Length, r.End);
    }

    [Fact]
    public void LeadingAndTrailingNulls_AreTrimmed()
    {
        var data = Cat(Fill(0x00, MinNull), Fill(0x90, 8), Fill(0x00, MinNull));
        var ctx = Ctx(Text(0x4000, data));
        ScanPhase.Run(ctx);
        var r = Assert.Single(ctx.Scan.CodeRegions);
        Assert.Equal(0x4000u + MinNull, r.Start);
        Assert.Equal(0x4000u + MinNull + 8, r.End);
    }

    [Fact]
    public void AllNullSection_YieldsNoCodeRegion()
    {
        var ctx = Ctx(Text(0x5000, Fill(0x00, 128)));
        ScanPhase.Run(ctx);
        Assert.Empty(ctx.Scan.CodeRegions);
        Assert.Single(ctx.Scan.DataRegions); // 128/4 = 32 invalid words > threshold 16
    }

    [Fact]
    public void Cc_Padding_IsNotASplit()
    {
        var data = Cat(Fill(0x90, 16), Fill(0xCC, 16), Fill(0x90, 16));
        var ctx = Ctx(Text(0x6000, data));
        ScanPhase.Run(ctx);
        var r = Assert.Single(ctx.Scan.CodeRegions);
        Assert.Equal(0x6000u + (uint)data.Length, r.End);
    }

    [Fact]
    public void SehScopeTableEntry_IsSteppedOver_NotSplitOn()
    {
        // ... code ... | 00000000 | <handler-func addr> | ... code ...
        // handler 0x00011234 is registered; the {null, handler} pair must not
        // break the region.
        var ctx0 = Ctx(Text(0x7000, Fill(0x90, 4)));
        ctx0.State.ExceptionHandlerFuncs.Add(0x00011234);

        var data = Cat(
            Fill(0x90, 16),
            new byte[] { 0, 0, 0, 0 },
            new byte[] { 0x34, 0x12, 0x01, 0x00 }, // LE 0x00011234
            Fill(0x90, 16));
        var view = BinaryView.FromSections(new[] { Text(0x7000, data) });
        var ctx = CodegenContext.Create(view);
        ctx.State.ExceptionHandlerFuncs.Add(0x00011234);

        ScanPhase.Run(ctx);
        var r = Assert.Single(ctx.Scan.CodeRegions);
        Assert.Equal(0x7000u, r.Start);
        Assert.Equal(0x7000u + (uint)data.Length, r.End);
    }

    [Fact]
    public void DataSectionsByName_AreExcluded()
    {
        var rdata = new SectionView
        {
            Name = ".rdata", BaseAddress = 0x9000, Size = 64, Data = Fill(0x90, 64),
            Executable = true, Writable = false,
        };
        var ctx = Ctx(Text(0x1000, Fill(0x90, 16)), rdata);
        ScanPhase.Run(ctx);
        Assert.Single(ctx.Scan.CodeRegions);
        Assert.Equal(0x1000u, ctx.Scan.CodeRegions[0].Start);
    }
}
