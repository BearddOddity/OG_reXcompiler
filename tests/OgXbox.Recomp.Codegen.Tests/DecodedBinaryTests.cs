using OgXbox.Recomp.Codegen;
using OgXbox.Recomp.Codegen.Binary;
using Xunit;

namespace OgXbox.Recomp.Codegen.Tests;

public class DecodedBinaryTests
{
    private static DecodedBinary Decode(uint @base, byte[] code)
    {
        var sec = new SectionView
        {
            Name = ".text", BaseAddress = @base, Size = (uint)code.Length,
            Data = code, Executable = true, Writable = false,
        };
        return new DecodedBinary(BinaryView.FromSections(new[] { sec }));
    }

    [Fact]
    public void Ret_IsClassifiedAsReturn()
    {
        var d = Decode(0x1000, new byte[] { 0xC3 });
        var insn = d.DecodeAt(0x1000)!;
        Assert.Equal(InsnFlow.Return, insn.Flow);
        Assert.Equal(1u, insn.Length);
    }

    [Fact]
    public void RelCall_TargetIsResolved()
    {
        // at 0x1000: E8 rel32 -> call 0x1005 + rel; rel = 0x100 -> target 0x1105
        var d = Decode(0x1000, new byte[] { 0xE8, 0x00, 0x01, 0x00, 0x00, 0xC3 });
        var call = d.DecodeAt(0x1000)!;
        Assert.Equal(InsnFlow.Call, call.Flow);
        Assert.Equal(5u, call.Length);
        Assert.Equal(0x1105u, call.Target);
    }

    [Fact]
    public void ShortConditionalJump_TargetAndFallthrough()
    {
        // 0x2000: 74 05  je 0x2007 ; 0x2002: 90*5 ; 0x2007: C3
        var d = Decode(0x2000, new byte[] { 0x74, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3 });
        var je = d.DecodeAt(0x2000)!;
        Assert.Equal(InsnFlow.ConditionalBranch, je.Flow);
        Assert.Equal(0x2007u, je.Target);
        Assert.Equal(0x2002u, je.EndAddress);
    }

    [Fact]
    public void Int3_IsClassified()
    {
        var d = Decode(0x3000, new byte[] { 0xCC });
        Assert.Equal(InsnFlow.Int3, d.DecodeAt(0x3000)!.Flow);
    }

    [Fact]
    public void IndirectJump_IsIndirectBranch()
    {
        // FF 24 85 <disp32>  jmp [eax*4 + table]
        var d = Decode(0x4000, new byte[] { 0xFF, 0x24, 0x85, 0x00, 0x20, 0x01, 0x00 });
        var jmp = d.DecodeAt(0x4000)!;
        Assert.Equal(InsnFlow.IndirectBranch, jmp.Flow);
        Assert.Equal(0u, jmp.Target);
    }

    [Fact]
    public void UnmappedAddress_ReturnsNull()
    {
        var d = Decode(0x1000, new byte[] { 0xC3 });
        Assert.Null(d.DecodeAt(0xDEAD));
    }
}
