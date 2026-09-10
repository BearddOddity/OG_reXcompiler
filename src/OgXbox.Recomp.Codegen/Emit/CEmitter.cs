// CEmitter — lower a sealed FunctionNode to a C function body.
//
// The x86 analogue of ReXGlue's FunctionNode::emitCpp + instruction_dispatch.
// Eager EFLAGS (the deferred-flag class was the X-Men port's biggest cost).
// Unhandled mnemonics emit a REX_UNIMPLEMENTED marker and are counted, not
// silently dropped.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Iced.Intel;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Emit;

public sealed class EmitResult
{
    public required string Name { get; init; }
    public required string Code { get; init; }
    public int Instructions { get; init; }
    public int Unimplemented { get; init; }
    public List<string> UnimplementedMnemonics { get; } = new();
}

public sealed class CEmitter
{
    private readonly DecodedBinary _decoded;
    private readonly Func<uint, string?> _nameOf;

    /// <param name="nameOf">entry addr -> symbol name, for call/jump targets.</param>
    public CEmitter(DecodedBinary decoded, Func<uint, string?> nameOf)
    {
        _decoded = decoded;
        _nameOf = nameOf;
    }

    public EmitResult Emit(FunctionNode node)
    {
        var body = new StringBuilder();
        var labels = new HashSet<uint>(node.Labels);
        foreach (var jt in node.JumpTables)
            foreach (var t in jt.Targets) labels.Add(t);

        int insnCount = 0, unimpl = 0;
        var unimplMnemonics = new List<string>();

        foreach (var block in node.Blocks.OrderBy(b => b.Base))
        {
            uint addr = block.Base;
            while (addr < block.End)
            {
                if (labels.Contains(addr))
                    body.Append("loc_").Append(addr.ToString("X", CultureInfo.InvariantCulture)).Append(":;\n");

                if (!_decoded.TryDecodeRaw(addr, out var insn) || insn.Length == 0)
                {
                    body.Append("\t/* .byte @ 0x").Append(addr.ToString("X8")).Append(" */\n");
                    addr++;
                    continue;
                }

                body.Append("\t/* ").Append(insn.ToString()).Append(" */\n");
                bool ok = EmitOne(body, insn, addr, node, labels);
                insnCount++;
                if (!ok)
                {
                    unimpl++;
                    unimplMnemonics.Add(insn.Mnemonic.ToString());
                }
                addr += (uint)insn.Length;
            }
        }

        var code = new StringBuilder();
        code.Append("void ").Append(node.Name).Append("(RecompCtx* c) {\n");
        code.Append(body);
        code.Append("}\n");

        return new EmitResult
        {
            Name = node.Name,
            Code = code.ToString(),
            Instructions = insnCount,
            Unimplemented = unimpl,
        }.WithMnemonics(unimplMnemonics);
    }

    //=====================================================================

    private bool EmitOne(StringBuilder b, in Instruction insn, uint addr,
                         FunctionNode node, HashSet<uint> labels)
    {
        switch (insn.Mnemonic)
        {
            case Mnemonic.Nop:
            case Mnemonic.Pause:
            case Mnemonic.Fnop:
            case Mnemonic.Endbr32:
            case Mnemonic.Endbr64:
                return true;

            case Mnemonic.Int3:
                Line(b, "REX_UNIMPLEMENTED(\"int3\", 0x" + addr.ToString("X8") + ");");
                return true;

            case Mnemonic.Mov:
                Line(b, W(insn, 0, R(insn, 1, addr), addr));
                return true;

            case Mnemonic.Movzx:
                Line(b, W(insn, 0, $"(uint32_t)({R(insn, 1, addr)})", addr));
                return true;

            case Mnemonic.Movsx:
            case Mnemonic.Movsxd:
            {
                int w1 = COperand.Width(insn, 1);
                Line(b, W(insn, 0, $"(uint32_t)(int32_t)(int{w1}_t)({R(insn, 1, addr)})", addr));
                return true;
            }

            case Mnemonic.Lea:
                Line(b, W(insn, 0, COperand.LeaAddr(insn), addr));
                return true;

            case Mnemonic.Push:
                Line(b, $"PUSH32(c, {R(insn, 0, addr)});");
                return true;

            case Mnemonic.Pop:
                Line(b, "{ uint32_t _t; POP32(c, _t); " + W(insn, 0, "_t", addr) + " }");
                return true;

            case Mnemonic.Leave:
                Line(b, "c->esp = c->ebp; { uint32_t _t; POP32(c, _t); c->ebp = _t; }");
                return true;

            case Mnemonic.Add: return Alu(b, insn, addr, "+", "add", writeBack: true);
            case Mnemonic.Sub: return Alu(b, insn, addr, "-", "sub", writeBack: true);
            case Mnemonic.Cmp: return Alu(b, insn, addr, "-", "sub", writeBack: false);
            case Mnemonic.And: return Alu(b, insn, addr, "&", "logic", writeBack: true);
            case Mnemonic.Or: return Alu(b, insn, addr, "|", "logic", writeBack: true);
            case Mnemonic.Xor: return Alu(b, insn, addr, "^", "logic", writeBack: true);
            case Mnemonic.Test: return Alu(b, insn, addr, "&", "logic", writeBack: false);

            case Mnemonic.Inc: return IncDec(b, insn, addr, +1);
            case Mnemonic.Dec: return IncDec(b, insn, addr, -1);

            case Mnemonic.Neg:
            {
                int w = COperand.Width(insn, 0);
                Line(b, $"{{ uint64_t _a = {R(insn, 0, addr)}; uint64_t _r = (uint64_t)0 - _a; "
                        + W(insn, 0, "(uint32_t)_r", addr) + $" rex_flags_sub(c, 0, _a, _r, {w}); }}");
                return true;
            }
            case Mnemonic.Not:
                Line(b, W(insn, 0, $"~({R(insn, 0, addr)})", addr));
                return true;

            case Mnemonic.Shl or Mnemonic.Sal: return Shift(b, insn, addr, "<<");
            case Mnemonic.Shr: return Shift(b, insn, addr, ">>");
            case Mnemonic.Sar: return ShiftArith(b, insn, addr);

            case Mnemonic.Xchg:
                Line(b, $"{{ uint32_t _t = {R(insn, 0, addr)}; "
                        + W(insn, 0, R(insn, 1, addr), addr) + " " + W(insn, 1, "_t", addr) + " }");
                return true;

            case Mnemonic.Cdq:
                Line(b, "c->edx = (c->eax & 0x80000000u) ? 0xFFFFFFFFu : 0u;");
                return true;
            case Mnemonic.Cwde:
                Line(b, "c->eax = (uint32_t)(int32_t)(int16_t)LO16(c->eax);");
                return true;

            case Mnemonic.Imul: return Imul(b, insn, addr);
            case Mnemonic.Mul:
                Line(b, "{ uint64_t _p = (uint64_t)c->eax * (uint64_t)(" + R(insn, 0, addr)
                        + "); c->eax = (uint32_t)_p; c->edx = (uint32_t)(_p >> 32); "
                        + "c->cf = c->of = (c->edx != 0); }");
                return true;

            case Mnemonic.Call: return Call(b, insn, addr);
            case Mnemonic.Ret or Mnemonic.Retf:
                Line(b, "return;");
                return true;
            case Mnemonic.Jmp: return Jmp(b, insn, addr, node, labels);

            default:
                if (IsJcc(insn.Mnemonic)) return Jcc(b, insn, addr, labels);
                if (IsSetcc(insn.Mnemonic))
                {
                    Line(b, W(insn, 0, $"({Cond(insn.Mnemonic)}) ? 1u : 0u", addr));
                    return true;
                }
                Line(b, $"REX_UNIMPLEMENTED(\"{insn.Mnemonic}\", 0x{addr:X8});");
                return false;
        }
    }

    //=====================================================================
    // groups
    //=====================================================================

    private bool Alu(StringBuilder b, in Instruction insn, uint addr, string op, string flags, bool writeBack)
    {
        int w = COperand.Width(insn, 0);
        string a = R(insn, 0, addr), c1 = R(insn, 1, addr);
        var sb = new StringBuilder("{ uint64_t _a = ").Append(a).Append("; uint64_t _b = ").Append(c1)
            .Append("; uint64_t _r = _a ").Append(op).Append(" _b; ");
        if (writeBack) sb.Append(W(insn, 0, "(uint32_t)_r", addr)).Append(' ');
        sb.Append(flags switch
        {
            "add" => $"rex_flags_add(c, _a, _b, _r, {w});",
            "sub" => $"rex_flags_sub(c, _a, _b, _r, {w});",
            _ => $"rex_flags_logic(c, _r, {w});",
        });
        sb.Append(" }");
        Line(b, sb.ToString());
        return true;
    }

    private bool IncDec(StringBuilder b, in Instruction insn, uint addr, int delta)
    {
        int w = COperand.Width(insn, 0);
        string sign = delta > 0 ? "+ 1" : "- 1";
        string fn = delta > 0 ? "add" : "sub";
        Line(b, $"{{ uint8_t _cf = c->cf; uint64_t _a = {R(insn, 0, addr)}; uint64_t _r = _a {sign}; "
                + W(insn, 0, "(uint32_t)_r", addr)
                + $" rex_flags_{fn}(c, _a, 1, _r, {w}); c->cf = _cf; }}");
        return true;
    }

    private bool Shift(StringBuilder b, in Instruction insn, uint addr, string op)
    {
        int w = COperand.Width(insn, 0);
        string cnt = insn.OpCount > 1 ? R(insn, 1, addr) : "1u";
        Line(b, $"{{ uint32_t _s = ({cnt}) & 31u; uint64_t _r = (uint64_t)(uint{w}_t)({R(insn, 0, addr)}) {op} _s; "
                + W(insn, 0, "(uint32_t)_r", addr) + $" rex_flags_logic(c, _r, {w}); }}");
        return true;
    }

    private bool ShiftArith(StringBuilder b, in Instruction insn, uint addr)
    {
        int w = COperand.Width(insn, 0);
        string cnt = insn.OpCount > 1 ? R(insn, 1, addr) : "1u";
        Line(b, $"{{ uint32_t _s = ({cnt}) & 31u; int64_t _r = (int64_t)(int{w}_t)({R(insn, 0, addr)}) >> _s; "
                + W(insn, 0, "(uint32_t)_r", addr) + $" rex_flags_logic(c, (uint64_t)_r, {w}); }}");
        return true;
    }

    private bool Imul(StringBuilder b, in Instruction insn, uint addr)
    {
        if (insn.OpCount == 1)
        {
            Line(b, "{ int64_t _p = (int64_t)(int32_t)c->eax * (int64_t)(int32_t)(" + R(insn, 0, addr)
                    + "); c->eax = (uint32_t)_p; c->edx = (uint32_t)((uint64_t)_p >> 32); }");
            return true;
        }
        string dst = insn.OpCount == 3 ? R(insn, 1, addr) : R(insn, 0, addr);
        string src = insn.OpCount == 3 ? R(insn, 2, addr) : R(insn, 1, addr);
        Line(b, "{ int64_t _p = (int64_t)(int32_t)(" + dst + ") * (int64_t)(int32_t)(" + src + "); "
                + W(insn, 0, "(uint32_t)_p", addr)
                + " c->cf = c->of = ((_p >> 31) != 0 && (_p >> 31) != -1); }");
        return true;
    }

    private bool Call(StringBuilder b, in Instruction insn, uint addr)
    {
        if (insn.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
        {
            uint target = (uint)insn.NearBranchTarget;
            string name = _nameOf(target) ?? $"sub_{target:X8}";
            Line(b, $"{name}(c);");
        }
        else
        {
            Line(b, $"rex_dispatch(c, {R(insn, 0, addr)});");
        }
        return true;
    }

    private bool Jmp(StringBuilder b, in Instruction insn, uint addr, FunctionNode node, HashSet<uint> labels)
    {
        if (insn.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
        {
            uint target = (uint)insn.NearBranchTarget;
            if (labels.Contains(target) || node.ContainsAddress(target))
            {
                Line(b, $"goto loc_{target:X};");
            }
            else
            {
                string name = _nameOf(target) ?? $"sub_{target:X8}";
                Line(b, $"{name}(c); return; /* tail call */");
            }
        }
        else
        {
            Line(b, $"rex_dispatch(c, {R(insn, 0, addr)}); return;");
        }
        return true;
    }

    private bool Jcc(StringBuilder b, in Instruction insn, uint addr, HashSet<uint> labels)
    {
        uint target = (uint)insn.NearBranchTarget;
        Line(b, $"if ({Cond(insn.Mnemonic)}) goto loc_{target:X};");
        return true;
    }

    //=====================================================================
    // helpers
    //=====================================================================

    private string R(in Instruction insn, int i, uint addr) => COperand.Read(insn, i, addr);
    private string W(in Instruction insn, int i, string v, uint addr) => COperand.Write(insn, i, v, addr);

    private static void Line(StringBuilder b, string s) => b.Append('\t').Append(s).Append('\n');

    private static bool IsJcc(Mnemonic m) => m is
        Mnemonic.Ja or Mnemonic.Jae or Mnemonic.Jb or Mnemonic.Jbe or Mnemonic.Je or Mnemonic.Jne or
        Mnemonic.Jg or Mnemonic.Jge or Mnemonic.Jl or Mnemonic.Jle or Mnemonic.Jo or Mnemonic.Jno or
        Mnemonic.Js or Mnemonic.Jns or Mnemonic.Jp or Mnemonic.Jnp or Mnemonic.Jcxz or Mnemonic.Jecxz;

    private static bool IsSetcc(Mnemonic m) => m is
        Mnemonic.Seta or Mnemonic.Setae or Mnemonic.Setb or Mnemonic.Setbe or Mnemonic.Sete or
        Mnemonic.Setne or Mnemonic.Setg or Mnemonic.Setge or Mnemonic.Setl or Mnemonic.Setle or
        Mnemonic.Seto or Mnemonic.Setno or Mnemonic.Sets or Mnemonic.Setns or Mnemonic.Setp or Mnemonic.Setnp;

    private static string Cond(Mnemonic m) => m switch
    {
        Mnemonic.Je or Mnemonic.Sete => "c->zf",
        Mnemonic.Jne or Mnemonic.Setne => "!c->zf",
        Mnemonic.Jb or Mnemonic.Setb => "c->cf",
        Mnemonic.Jae or Mnemonic.Setae => "!c->cf",
        Mnemonic.Jbe or Mnemonic.Setbe => "(c->cf || c->zf)",
        Mnemonic.Ja or Mnemonic.Seta => "(!c->cf && !c->zf)",
        Mnemonic.Jl or Mnemonic.Setl => "(c->sf != c->of)",
        Mnemonic.Jge or Mnemonic.Setge => "(c->sf == c->of)",
        Mnemonic.Jle or Mnemonic.Setle => "(c->zf || c->sf != c->of)",
        Mnemonic.Jg or Mnemonic.Setg => "(!c->zf && c->sf == c->of)",
        Mnemonic.Js or Mnemonic.Sets => "c->sf",
        Mnemonic.Jns or Mnemonic.Setns => "!c->sf",
        Mnemonic.Jo or Mnemonic.Seto => "c->of",
        Mnemonic.Jno or Mnemonic.Setno => "!c->of",
        Mnemonic.Jp or Mnemonic.Setp => "c->pf",
        Mnemonic.Jnp or Mnemonic.Setnp => "!c->pf",
        Mnemonic.Jcxz => "(LO16(c->ecx) == 0)",
        Mnemonic.Jecxz => "(c->ecx == 0)",
        _ => "0",
    };
}

internal static class EmitResultExt
{
    public static EmitResult WithMnemonics(this EmitResult r, List<string> ms)
    {
        r.UnimplementedMnemonics.AddRange(ms.Distinct());
        return r;
    }
}
