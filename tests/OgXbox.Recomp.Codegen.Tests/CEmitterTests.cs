using System.IO;
using System.Linq;
using Iced.Intel;
using OgXbox.Recomp.Codegen;
using OgXbox.Recomp.Codegen.Binary;
using OgXbox.Recomp.Codegen.Emit;
using OgXbox.Recomp.Codegen.Phases;
using Xunit;
using static Iced.Intel.AssemblerRegisters;

namespace OgXbox.Recomp.Codegen.Tests;

public class CEmitterTests
{
    private const uint Base = 0x00011000;

    private static (CodegenContext ctx, FunctionNode fn) Build(System.Action<Assembler> asm)
    {
        var a = new Assembler(32);
        asm(a);
        using var ms = new MemoryStream();
        a.Assemble(new StreamCodeWriter(ms), Base);
        var code = ms.ToArray();
        var buf = new byte[code.Length + 64];
        System.Array.Copy(code, buf, code.Length);

        var sec = new SectionView
        {
            Name = ".text", BaseAddress = Base, Size = (uint)buf.Length, Data = buf,
            Executable = true, Writable = false,
        };
        var view = BinaryView.FromSections(new[] { sec }, baseAddress: 0x10000, entryPoint: Base);
        var ctx = CodegenContext.Create(view);
        AnalysisPipeline.Run(ctx);
        return (ctx, ctx.Graph.GetFunction(Base)!);
    }

    private static string EmitOne(CodegenContext ctx, FunctionNode fn) =>
        new CEmitter(ctx.Decoded, a => ctx.Graph.GetFunction(a)?.Name).Emit(fn).Code;

    [Fact]
    public void MovAddRet_LowersToC()
    {
        var (ctx, fn) = Build(a =>
        {
            a.mov(eax, 1);
            a.add(eax, ecx);
            a.ret();
        });
        var c = EmitOne(ctx, fn);
        Assert.Contains("void xstart(RecompCtx* c) {", c);
        Assert.Contains("c->eax = (uint32_t)(0x1u);", c);
        Assert.Contains("rex_flags_add(c, _a, _b, _r, 32);", c);
        Assert.Contains("return;", c);
    }

    [Fact]
    public void ConditionalBranch_LowersToGoto()
    {
        var (ctx, fn) = Build(a =>
        {
            var skip = a.CreateLabel();
            a.test(eax, eax);
            a.je(skip);
            a.inc(ecx);
            a.Label(ref skip);
            a.ret();
        });
        var c = EmitOne(ctx, fn);
        Assert.Contains("rex_flags_logic(c, _r, 32);", c);
        Assert.Matches(@"if \(c->zf\) goto loc_[0-9A-F]+;", c);
        Assert.Matches(@"loc_[0-9A-F]+:;", c);
        Assert.Contains("c->cf = _cf;", c); // inc preserves CF
    }

    [Fact]
    public void DirectCall_UsesCalleeName()
    {
        var (ctx, fn) = Build(a =>
        {
            var leaf = a.CreateLabel();
            a.call(leaf);
            a.ret();
            a.Label(ref leaf);
            a.xor(eax, eax);
            a.ret();
        });
        var c = EmitOne(ctx, fn);
        Assert.Matches(@"sub_[0-9A-F]{8}\(c\);", c);
    }

    [Fact]
    public void MemoryOperand_UsesMemMacro()
    {
        var (ctx, fn) = Build(a =>
        {
            a.mov(eax, __dword_ptr[ebx + esi * 4 + 0x10]);
            a.ret();
        });
        var c = EmitOne(ctx, fn);
        Assert.Contains("MEM32((uint32_t)(c->ebx + c->esi*4 + 0x10u))", c);
    }

    [Fact]
    public void RepMovsd_LowersToLoop()
    {
        var (ctx, fn) = Build(a =>
        {
            a.cld();
            a.rep.movsd();
            a.ret();
        });
        var c = EmitOne(ctx, fn);
        Assert.Contains("c->df = 0;", c);
        Assert.Contains("while (c->ecx != 0)", c);
        Assert.Contains("MEM32(c->edi) = MEM32(c->esi);", c);
    }

    [Fact]
    public void X87_FldFaddpFstp_UsesStack()
    {
        var (ctx, fn) = Build(a =>
        {
            a.fld(__dword_ptr[esi]);
            a.fld(__dword_ptr[esi + 4]);
            a.faddp(st1, st0);
            a.fstp(__dword_ptr[edi]);
            a.ret();
        });
        var c = EmitOne(ctx, fn);
        Assert.Contains("FPU_PUSH(c,", c);
        Assert.Contains("FPU_POP(c);", c);
    }

    [Fact]
    public void UnknownInstruction_EmitsMarker_AndIsCounted()
    {
        var (ctx, fn) = Build(a =>
        {
            a.cpuid();
            a.ret();
        });
        var r = new CEmitter(ctx.Decoded, _ => null).Emit(fn);
        Assert.True(r.Unimplemented >= 1);
        Assert.Contains("REX_UNIMPLEMENTED", r.Code);
    }
}
