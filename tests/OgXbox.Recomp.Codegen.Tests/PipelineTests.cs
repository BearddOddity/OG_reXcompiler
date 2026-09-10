using System;
using System.IO;
using System.Linq;
using Iced.Intel;
using OgXbox.Recomp.Codegen;
using OgXbox.Recomp.Codegen.Binary;
using OgXbox.Recomp.Codegen.Phases;
using Xunit;
using static Iced.Intel.AssemblerRegisters;

namespace OgXbox.Recomp.Codegen.Tests;

public class PipelineTests
{
    private const uint Base = 0x00011000;

    private static CodegenContext BuildProgram()
    {
        // Three functions:
        //   entry (0x11000): calls helper, calls leaf, ret
        //   helper:          conditional branch, ret
        //   leaf:            ret
        var a = new Assembler(32);

        var entry = a.CreateLabel("entry");
        var helper = a.CreateLabel("helper");
        var leaf = a.CreateLabel("leaf");

        a.Label(ref entry);
        a.push(ebp);
        a.mov(ebp, esp);
        a.call(helper);
        a.call(leaf);
        a.pop(ebp);
        a.ret();

        a.Label(ref helper);
        var done = a.CreateLabel();
        a.test(ecx, ecx);
        a.je(done);
        a.inc(eax);
        a.Label(ref done);
        a.ret();

        a.Label(ref leaf);
        a.xor(eax, eax);
        a.ret();

        using var ms = new MemoryStream();
        a.Assemble(new StreamCodeWriter(ms), Base);
        var code = ms.ToArray();

        var buf = new byte[code.Length + 64]; // trailing zero padding
        Array.Copy(code, buf, code.Length);

        var sec = new SectionView
        {
            Name = ".text", BaseAddress = Base, Size = (uint)buf.Length, Data = buf,
            Executable = true, Writable = false,
        };
        var view = BinaryView.FromSections(new[] { sec }, baseAddress: 0x00010000, entryPoint: Base);
        return CodegenContext.Create(view);
    }

    [Fact]
    public void FullPipeline_DiscoversAndSealsAllFunctions()
    {
        var ctx = BuildProgram();
        bool clean = AnalysisPipeline.Run(ctx);

        // entry + helper + leaf, all reached from the entry point's calls
        Assert.True(ctx.Graph.FunctionCount >= 3, $"only {ctx.Graph.FunctionCount} functions");
        Assert.Equal(0, ctx.Graph.PendingCount);
        Assert.True(clean, ctx.Errors.Report());

        var xstart = ctx.Graph.GetFunction(Base);
        Assert.NotNull(xstart);
        Assert.Equal("xstart", xstart!.Name);
        Assert.Equal(FunctionState.Sealed, xstart.State);
        Assert.Equal(2, xstart.Calls.Count); // helper + leaf
    }

    [Fact]
    public void FullPipeline_CondBranchTarget_IsInternalLabel_NotAFunction()
    {
        var ctx = BuildProgram();
        AnalysisPipeline.Run(ctx);
        // helper's `je done` target must be a label inside helper, not its own node
        var helper = ctx.Graph.Functions.Values.Single(n => n.Name != "xstart" && n.Calls.Count == 0 && n.Labels.Count > 0);
        Assert.NotEmpty(helper.Labels);
    }
}
