// Render an x86 instruction operand as a C expression / assignment.
//
// Register model: a per-call `RecompCtx* c`. 32-bit regs are struct fields;
// sub-registers go through LO8/HI8/LO16 + SET_* macros (ogxbox_runtime.h).

using System;
using System.Globalization;
using Iced.Intel;

namespace OgXbox.Recomp.Codegen.Emit;

internal static class COperand
{
    /// <summary>Bit width of operand <paramref name="i"/> (8/16/32), best-effort.</summary>
    public static int Width(in Instruction insn, int i) => insn.GetOpKind(i) switch
    {
        OpKind.Register => RegWidth(insn.GetOpRegister(i)),
        OpKind.Memory => insn.MemorySize switch
        {
            MemorySize.UInt8 or MemorySize.Int8 => 8,
            MemorySize.UInt16 or MemorySize.Int16 => 16,
            _ => 32,
        },
        OpKind.Immediate8 => 8,
        OpKind.Immediate16 => 16,
        _ => 32,
    };

    /// <summary>Operand <paramref name="i"/> as a C rvalue.</summary>
    public static string Read(in Instruction insn, int i, uint addr)
    {
        switch (insn.GetOpKind(i))
        {
            case OpKind.Register:
                return RegRead(insn.GetOpRegister(i));

            case OpKind.Immediate8:
            case OpKind.Immediate16:
            case OpKind.Immediate32:
            case OpKind.Immediate8to16:
            case OpKind.Immediate8to32:
            case OpKind.Immediate32to64:
            case OpKind.Immediate8to64:
            case OpKind.Immediate64:
                return "0x" + insn.GetImmediate(i).ToString("X", CultureInfo.InvariantCulture) + "u";

            case OpKind.Memory:
                return MemAccess(insn, addr);

            case OpKind.NearBranch16:
            case OpKind.NearBranch32:
            case OpKind.NearBranch64:
                return "0x" + insn.NearBranchTarget.ToString("X", CultureInfo.InvariantCulture) + "u";

            default:
                return $"/* op{i}? */ 0";
        }
    }

    /// <summary>A statement assigning <paramref name="valueExpr"/> into operand <paramref name="i"/>.</summary>
    public static string Write(in Instruction insn, int i, string valueExpr, uint addr)
    {
        switch (insn.GetOpKind(i))
        {
            case OpKind.Register:
                return RegWrite(insn.GetOpRegister(i), valueExpr);
            case OpKind.Memory:
                return $"{MemAccess(insn, addr)} = (uint{Width(insn, i)}_t)({valueExpr});";
            default:
                return $"/* cannot write op{i} */";
        }
    }

    //=====================================================================

    private static string MemAccess(in Instruction insn, uint addr)
    {
        if (insn.SegmentPrefix == Register.FS || insn.SegmentPrefix == Register.GS)
            return $"MEM32(rex_seg({SegName(insn.SegmentPrefix)}, {AddrExpr(insn)}))";

        int w = insn.MemorySize switch
        {
            MemorySize.UInt8 or MemorySize.Int8 => 8,
            MemorySize.UInt16 or MemorySize.Int16 => 16,
            _ => 32,
        };
        bool signed = insn.MemorySize is MemorySize.Int8 or MemorySize.Int16 or MemorySize.Int32;
        string macro = (signed ? "S" : "") + "MEM" + w;
        return $"{macro}({AddrExpr(insn)})";
    }

    /// <summary>The effective address of a memory operand as a C expression (for <c>lea</c>).</summary>
    public static string LeaAddr(in Instruction insn) => AddrExpr(insn);

    private static string AddrExpr(in Instruction insn)
    {
        var parts = new System.Collections.Generic.List<string>();
        if (insn.MemoryBase != Register.None && insn.MemoryBase != Register.RIP)
            parts.Add(Reg32Field(insn.MemoryBase));
        if (insn.MemoryIndex != Register.None)
        {
            int s = insn.MemoryIndexScale == 0 ? 1 : insn.MemoryIndexScale;
            parts.Add(s == 1 ? Reg32Field(insn.MemoryIndex)
                             : $"{Reg32Field(insn.MemoryIndex)}*{s}");
        }
        ulong disp = insn.MemoryDisplacement64;
        if (disp != 0 || parts.Count == 0)
            parts.Add("0x" + disp.ToString("X", CultureInfo.InvariantCulture) + "u");
        return "(uint32_t)(" + string.Join(" + ", parts) + ")";
    }

    private static string SegName(Register r) => r == Register.FS ? "FS" : "GS";

    //=====================================================================
    // Register field / accessor mapping
    //=====================================================================

    private static readonly string[] R32 = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

    private static int R32Index(Register r) => r switch
    {
        Register.EAX or Register.AX or Register.AL or Register.AH => 0,
        Register.ECX or Register.CX or Register.CL or Register.CH => 1,
        Register.EDX or Register.DX or Register.DL or Register.DH => 2,
        Register.EBX or Register.BX or Register.BL or Register.BH => 3,
        Register.ESP or Register.SP or Register.SPL => 4,
        Register.EBP or Register.BP or Register.BPL => 5,
        Register.ESI or Register.SI or Register.SIL => 6,
        Register.EDI or Register.DI or Register.DIL => 7,
        _ => -1,
    };

    public static int RegWidth(Register r) => r switch
    {
        >= Register.AL and <= Register.R15L => 8,
        >= Register.AX and <= Register.R15W => 16,
        _ => 32,
    };

    private static bool IsHigh8(Register r) =>
        r is Register.AH or Register.CH or Register.DH or Register.BH;

    public static string Reg32Field(Register r)
    {
        int idx = R32Index(r);
        return idx >= 0 ? "c->" + R32[idx] : $"/* reg {r}? */ 0";
    }

    public static string RegRead(Register r)
    {
        int idx = R32Index(r);
        if (idx < 0) return $"/* reg {r}? */ 0";
        string f = "c->" + R32[idx];
        return RegWidth(r) switch
        {
            8 => IsHigh8(r) ? $"HI8({f})" : $"LO8({f})",
            16 => $"LO16({f})",
            _ => f,
        };
    }

    public static string RegWrite(Register r, string value)
    {
        int idx = R32Index(r);
        if (idx < 0) return $"/* write reg {r}? */";
        string f = "c->" + R32[idx];
        return RegWidth(r) switch
        {
            8 => IsHigh8(r) ? $"SET_HI8({f}, {value});" : $"SET_LO8({f}, {value});",
            16 => $"SET_LO16({f}, {value});",
            _ => $"{f} = (uint32_t)({value});",
        };
    }
}
