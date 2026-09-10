using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Iced.Intel;
using OgXbox.Recomp.Codegen;
using OgXbox.Recomp.Codegen.Binary;
using OgXbox.Recomp.Codegen.Analysis;
using Xunit;
using static Iced.Intel.AssemblerRegisters;

namespace OgXbox.Recomp.Codegen.Tests;

public class FunctionScannerTests
{
    private const uint Base = 0x00201000;

    private static (FunctionScanner scanner, uint entry) Build(
        Action<Assembler> asm, byte[]? trailingData = null, uint dataAt = 0)
    {
        var a = new Assembler(32);
        asm(a);
        using var ms = new MemoryStream();
        a.Assemble(new StreamCodeWriter(ms), Base);
        var code = ms.ToArray();

        int size = code.Length;
        if (trailingData is not null)
            size = Math.Max(size, (int)(dataAt - Base) + trailingData.Length);
        var buf = new byte[Align(size, 16) + 16];
        Array.Copy(code, buf, code.Length);
        if (trailingData is not null)
            Array.Copy(trailingData, 0, buf, (int)(dataAt - Base), trailingData.Length);

        var sec = new SectionView
        {
            Name = ".text", BaseAddress = Base, Size = (uint)buf.Length, Data = buf,
            Executable = true, Writable = false,
        };
        var view = BinaryView.FromSections(new[] { sec });
        var decoded = new DecodedBinary(view);
        var scanner = new FunctionScanner(decoded, new[] { new CodeRegion(Base, sec.End, ".text") });
        return (scanner, Base);

        static int Align(int v, int n) => (v + n - 1) / n * n;
    }

    private static readonly HashSet<uint> NoKnown = new();

    [Fact]
    public void LinearFunction_IsOneBlock_EndsAtRet()
    {
        var (s, entry) = Build(a =>
        {
            a.push(ebp);
            a.mov(ebp, esp);
            a.xor(eax, eax);
            a.pop(ebp);
            a.ret();
        });
        var r = s.DiscoverBlocks(entry, NoKnown);
        var b = Assert.Single(r.Blocks);
        Assert.Equal(entry, b.Base);
        Assert.Equal(InsnFlow.Return, r.Instructions[^1].Flow);
        Assert.Empty(r.UnresolvedBranches);
    }

    [Fact]
    public void DirectCall_RecordedAsUnresolvedCall_AndExternal()
    {
        var (s, entry) = Build(a =>
        {
            var target = a.CreateLabel();
            a.call(0x00250000);  // far-ish forward, outside function
            a.ret();
        });
        var r = s.DiscoverBlocks(entry, NoKnown);
        var ub = Assert.Single(r.UnresolvedBranches);
        Assert.True(ub.IsCall);
        Assert.Equal(0x00250000u, ub.Target);
        Assert.Contains(0x00250000u, r.ExternalCalls);
    }

    [Fact]
    public void ConditionalBranch_InternalTarget_BecomesLabel()
    {
        var (s, entry) = Build(a =>
        {
            var skip = a.CreateLabel();
            a.test(eax, eax);
            a.je(skip);
            a.inc(ecx);
            a.Label(ref skip);
            a.ret();
        });
        var r = s.DiscoverBlocks(entry, NoKnown);
        Assert.NotEmpty(r.Labels);
        Assert.Empty(r.UnresolvedBranches); // internal, not a tail call
    }

    [Fact]
    public void UnconditionalJump_ToKnownFunction_IsTailCall()
    {
        // jmp into a byte range we'll declare as a known function entry
        var (s, entry) = Build(a =>
        {
            a.mov(eax, 1);
            a.jmp(0x00201040);
        });
        var known = new HashSet<uint> { 0x00201040 };
        var r = s.DiscoverBlocks(entry, known);
        Assert.Contains(0x00201040u, r.TailCalls);
        Assert.Contains(r.UnresolvedBranches, u => !u.IsCall && u.Target == 0x00201040);
    }

    [Fact]
    public void JumpTable_AbsoluteDisp32_FourEntries_Detected()
    {
        // cmp eax, 3 ; ja default ; jmp [TABLE + eax*4] ; default: ret
        // TABLE holds 4 code addresses (all inside the region).
        uint tableAt = Base + 0x100;
        uint c0 = Base + 0x40, c1 = Base + 0x44, c2 = Base + 0x48, c3 = Base + 0x4C;
        var table = new byte[16];
        BitConverter.GetBytes(c0).CopyTo(table, 0);
        BitConverter.GetBytes(c1).CopyTo(table, 4);
        BitConverter.GetBytes(c2).CopyTo(table, 8);
        BitConverter.GetBytes(c3).CopyTo(table, 12);

        var (s, entry) = Build(a =>
        {
            var dflt = a.CreateLabel();
            a.cmp(eax, 3);
            a.ja(dflt);
            a.jmp(__dword_ptr[eax * 4 + tableAt]);
            a.Label(ref dflt);
            a.ret();
        }, table, tableAt);

        var region = new CodeRegion(Base, Base + 0x1000, ".text");
        var jmpAddr = FindFirstIndirectJump(s, entry, region);
        var jt = s.DetectJumpTable(jmpAddr, region, entry, region.End);

        Assert.NotNull(jt);
        Assert.Equal(tableAt, jt!.TableAddress);
        Assert.Equal(4, jt.Targets.Count);
        Assert.Equal(new[] { c0, c1, c2, c3 }, jt.Targets.ToArray());
    }

    private static uint FindFirstIndirectJump(FunctionScanner s, uint entry, CodeRegion region)
    {
        var r = s.DiscoverBlocks(entry, NoKnown);
        var j = r.Instructions.First(i => i.Flow == InsnFlow.IndirectBranch);
        return j.Address;
    }
}
