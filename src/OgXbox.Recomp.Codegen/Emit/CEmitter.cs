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

        // Every instruction start inside this function's blocks — a `goto` may
        // only target one of these (label emitted at that exact address).
        var insnStarts = new HashSet<uint>();
        foreach (var block in node.Blocks)
        {
            uint a = block.Base;
            while (a < block.End)
            {
                insnStarts.Add(a);
                if (!_decoded.TryDecodeRaw(a, out var di) || di.Length == 0) { a++; continue; }
                a += (uint)di.Length;
            }
        }
        // Pre-scan for direct-branch targets that land on an instruction start;
        // those need a label even when discovery didn't record one.
        foreach (uint a in insnStarts)
        {
            var di = _decoded.DecodeAt(a);
            if (di is null || di.Target == 0) continue;
            if (di.Flow is InsnFlow.ConditionalBranch or InsnFlow.UnconditionalBranch
                && insnStarts.Contains(di.Target))
                labels.Add(di.Target);
        }

        // The set of addresses that will actually get a `loc_X:` — the only
        // legal `goto` destinations.
        var emitted = new HashSet<uint>(labels.Where(insnStarts.Contains));

        int insnCount = 0, unimpl = 0;
        var unimplMnemonics = new List<string>();

        foreach (var block in node.Blocks.OrderBy(b => b.Base))
        {
            uint addr = block.Base;
            while (addr < block.End)
            {
                if (emitted.Contains(addr))
                    body.Append("loc_").Append(addr.ToString("X", CultureInfo.InvariantCulture)).Append(":;\n");

                if (!_decoded.TryDecodeRaw(addr, out var insn) || insn.Length == 0)
                {
                    body.Append("\t/* .byte @ 0x").Append(addr.ToString("X8")).Append(" */\n");
                    addr++;
                    continue;
                }

                body.Append("\t/* ").Append(insn.ToString()).Append(" */\n");
                bool ok = EmitOne(body, insn, addr, node, emitted);
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
                         FunctionNode node, HashSet<uint> emitted)
    {
        switch (insn.Mnemonic)
        {
            case Mnemonic.Nop:
            case Mnemonic.Pause:
            case Mnemonic.Fnop:
            case Mnemonic.Wait:
            case Mnemonic.Fninit:
            case Mnemonic.Endbr32:
            case Mnemonic.Endbr64:
                return true;

            case Mnemonic.Cld: Line(b, "c->df = 0;"); return true;
            case Mnemonic.Std: Line(b, "c->df = 1;"); return true;
            case Mnemonic.Clc: Line(b, "c->cf = 0;"); return true;
            case Mnemonic.Stc: Line(b, "c->cf = 1;"); return true;
            case Mnemonic.Cmc: Line(b, "c->cf = !c->cf;"); return true;

            case Mnemonic.Div: return DivOp(b, insn, addr, signed: false);
            case Mnemonic.Idiv: return DivOp(b, insn, addr, signed: true);

            case Mnemonic.Rol or Mnemonic.Ror: return Rotate(b, insn, addr, insn.Mnemonic == Mnemonic.Rol);

            case Mnemonic.Bt or Mnemonic.Bts or Mnemonic.Btr or Mnemonic.Btc:
                return BitTest(b, insn, addr);

            case Mnemonic.Fsqrt: Line(b, "FPU_ST(c, 0) = __builtin_sqrt(FPU_ST(c, 0));"); return true;
            case Mnemonic.Fsin: Line(b, "FPU_ST(c, 0) = __builtin_sin(FPU_ST(c, 0));"); return true;
            case Mnemonic.Fcos: Line(b, "FPU_ST(c, 0) = __builtin_cos(FPU_ST(c, 0));"); return true;
            case Mnemonic.Fptan: Line(b, "FPU_ST(c, 0) = __builtin_tan(FPU_ST(c, 0)); FPU_PUSH(c, 1.0);"); return true;
            case Mnemonic.Frndint: Line(b, "FPU_ST(c, 0) = __builtin_rint(FPU_ST(c, 0));"); return true;

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
            case Mnemonic.Adc: return AddCarry(b, insn, addr, sub: false);
            case Mnemonic.Sbb: return AddCarry(b, insn, addr, sub: true);
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

            case Mnemonic.Bswap:
                Line(b, W(insn, 0, $"__builtin_bswap32({R(insn, 0, addr)})", addr));
                return true;
            case Mnemonic.Xadd:
                Line(b, $"{{ uint64_t _a = {R(insn, 0, addr)}, _b = {R(insn, 1, addr)}, _r = _a + _b; "
                        + W(insn, 1, "(uint32_t)_a", addr) + " " + W(insn, 0, "(uint32_t)_r", addr)
                        + $" rex_flags_add(c, _a, _b, _r, {COperand.Width(insn, 0)}); }}");
                return true;
            case Mnemonic.Cmpxchg:
            {
                int w = COperand.Width(insn, 0);
                string acc = w == 8 ? "LO8(c->eax)" : w == 16 ? "LO16(c->eax)" : "c->eax";
                Line(b, $"{{ uint64_t _a = {acc}, _d = {R(insn, 0, addr)}, _r = _a - _d; "
                        + $"rex_flags_sub(c, _a, _d, _r, {w}); "
                        + $"if (c->zf) {{ {W(insn, 0, R(insn, 1, addr), addr)} }} "
                        + $"else {{ c->eax = (c->eax & ~rex_mask({w})) | (uint32_t)_d; }} }}");
                return true;
            }
            case Mnemonic.Sahf:
                Line(b, "{ uint8_t _f = HI8(c->eax); c->cf=_f&1; c->pf=(_f>>2)&1; "
                        + "c->af=(_f>>4)&1; c->zf=(_f>>6)&1; c->sf=(_f>>7)&1; }");
                return true;
            case Mnemonic.Lahf:
                Line(b, "SET_HI8(c->eax, (c->cf) | 2 | (c->pf<<2) | (c->af<<4) | (c->zf<<6) | (c->sf<<7));");
                return true;
            case Mnemonic.Pushad:
                Line(b, "{ uint32_t _sp = c->esp; PUSH32(c,c->eax); PUSH32(c,c->ecx); PUSH32(c,c->edx); "
                        + "PUSH32(c,c->ebx); PUSH32(c,_sp); PUSH32(c,c->ebp); PUSH32(c,c->esi); PUSH32(c,c->edi); }");
                return true;
            case Mnemonic.Popad:
                Line(b, "{ uint32_t _t; POP32(c,c->edi); POP32(c,c->esi); POP32(c,c->ebp); POP32(c,_t); "
                        + "POP32(c,c->ebx); POP32(c,c->edx); POP32(c,c->ecx); POP32(c,c->eax); }");
                return true;
            case Mnemonic.Xlatb:
                Line(b, "SET_LO8(c->eax, MEM8((uint32_t)(c->ebx + LO8(c->eax))));");
                return true;

            case Mnemonic.Movsb or Mnemonic.Movsw or Mnemonic.Movsd
                when insn.Op0Kind != OpKind.Register:
                return StringOp(b, insn, StringKind.Movs);
            case Mnemonic.Stosb or Mnemonic.Stosw or Mnemonic.Stosd:
                return StringOp(b, insn, StringKind.Stos);
            case Mnemonic.Lodsb or Mnemonic.Lodsw or Mnemonic.Lodsd:
                return StringOp(b, insn, StringKind.Lods);
            case Mnemonic.Scasb or Mnemonic.Scasw or Mnemonic.Scasd:
                return StringOp(b, insn, StringKind.Scas);
            case Mnemonic.Cmpsb or Mnemonic.Cmpsw or Mnemonic.Cmpsd:
                return StringOp(b, insn, StringKind.Cmps);

            case Mnemonic.Fld or Mnemonic.Fst or Mnemonic.Fstp or Mnemonic.Fild or Mnemonic.Fistp
                or Mnemonic.Fadd or Mnemonic.Faddp or Mnemonic.Fsub or Mnemonic.Fsubp
                or Mnemonic.Fsubr or Mnemonic.Fsubrp or Mnemonic.Fmul or Mnemonic.Fmulp
                or Mnemonic.Fdiv or Mnemonic.Fdivp or Mnemonic.Fdivr or Mnemonic.Fdivrp
                or Mnemonic.Fchs or Mnemonic.Fabs or Mnemonic.Fxch or Mnemonic.Fld1 or Mnemonic.Fldz
                or Mnemonic.Fcom or Mnemonic.Fcomp or Mnemonic.Fcompp or Mnemonic.Fucom
                or Mnemonic.Fucomp or Mnemonic.Fucompp or Mnemonic.Fnstsw or Mnemonic.Fnstcw
                or Mnemonic.Fldcw:
                return X87(b, insn, addr);
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
            case Mnemonic.Jmp: return Jmp(b, insn, addr, node, emitted);

            default:
                if (IsJcc(insn.Mnemonic)) return Jcc(b, insn, addr, emitted);
                if (IsSetcc(insn.Mnemonic))
                {
                    Line(b, W(insn, 0, $"({Cond(insn.Mnemonic)}) ? 1u : 0u", addr));
                    return true;
                }
                if (insn.Mnemonic.ToString().StartsWith("Cmov"))
                {
                    Line(b, $"if ({CmovCond(insn.Mnemonic)}) {{ {W(insn, 0, R(insn, 1, addr), addr)} }}");
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

    private bool DivOp(StringBuilder b, in Instruction insn, uint addr, bool signed)
    {
        int w = COperand.Width(insn, 0);
        string d = R(insn, 0, addr);
        if (w == 32)
        {
            string t = signed ? "int64_t" : "uint64_t";
            string dividend = signed
                ? "(int64_t)(((uint64_t)c->edx << 32) | c->eax)"
                : "(((uint64_t)c->edx << 32) | c->eax)";
            Line(b, $"{{ {t} _n = {dividend}; {t} _d = ({(signed ? "int32_t" : "uint32_t")})({d}); "
                    + $"c->eax = (uint32_t)(_n / _d); c->edx = (uint32_t)(_n % _d); }}");
        }
        else // 16/8 fall back: treat as 32 on ax/dx:ax — good enough for most game code
        {
            Line(b, $"{{ uint32_t _n = c->eax; uint32_t _d = ({d}); "
                    + "c->eax = (c->eax & 0xFFFF0000u) | ((_n / _d) & 0xFFFFu) | (((_n % _d) & 0xFFFFu) << 16); }");
        }
        return true;
    }

    private bool Rotate(StringBuilder b, in Instruction insn, uint addr, bool left)
    {
        int w = COperand.Width(insn, 0);
        string cnt = insn.OpCount > 1 ? R(insn, 1, addr) : "1u";
        string expr = left
            ? $"(_v << _s) | (_v >> (({w} - _s) & {w - 1}))"
            : $"(_v >> _s) | (_v << (({w} - _s) & {w - 1}))";
        Line(b, $"{{ uint32_t _s = ({cnt}) & {w - 1}u; uint{w}_t _v = (uint{w}_t)({R(insn, 0, addr)}); "
                + $"uint{w}_t _r = _s ? ({expr}) : _v; " + W(insn, 0, "_r", addr) + " }");
        return true;
    }

    private bool BitTest(StringBuilder b, in Instruction insn, uint addr)
    {
        string src = R(insn, 0, addr), bit = R(insn, 1, addr);
        Line(b, $"c->cf = (({src}) >> (({bit}) & 31u)) & 1u;");
        if (insn.Mnemonic != Mnemonic.Bt)
        {
            string opv = insn.Mnemonic switch
            {
                Mnemonic.Bts => $"({src}) | (1u << (({bit}) & 31u))",
                Mnemonic.Btr => $"({src}) & ~(1u << (({bit}) & 31u))",
                _ => $"({src}) ^ (1u << (({bit}) & 31u))",
            };
            Line(b, W(insn, 0, opv, addr));
        }
        return true;
    }

    private bool AddCarry(StringBuilder b, in Instruction insn, uint addr, bool sub)
    {
        int w = COperand.Width(insn, 0);
        string op = sub ? "-" : "+";
        string fn = sub ? "sub" : "add";
        Line(b, $"{{ uint64_t _a = {R(insn, 0, addr)}; uint64_t _b = (uint64_t)({R(insn, 1, addr)}) {op} c->cf; "
                + $"uint64_t _r = _a {op} _b; " + W(insn, 0, "(uint32_t)_r", addr)
                + $" rex_flags_{fn}(c, _a, _b, _r, {w}); }}");
        return true;
    }

    private enum StringKind { Movs, Stos, Lods, Scas, Cmps }

    private bool StringOp(StringBuilder b, in Instruction insn, StringKind kind)
    {
        int w = insn.Mnemonic.ToString().EndsWith("b") ? 8
              : insn.Mnemonic.ToString().EndsWith("w") ? 16 : 32;
        int step = w / 8;
        string mem = "MEM" + w;
        string body = kind switch
        {
            StringKind.Movs => $"{mem}(c->edi) = {mem}(c->esi); c->esi += _d; c->edi += _d;",
            StringKind.Stos => $"{mem}(c->edi) = (uint{w}_t)c->eax; c->edi += _d;",
            StringKind.Lods => $"c->eax = (c->eax & ~(uint32_t)0x{((1L << w) - 1):X}u) | {mem}(c->esi); c->esi += _d;",
            StringKind.Scas =>
                $"{{ uint64_t _a=(uint{w}_t)c->eax,_b={mem}(c->edi),_r=_a-_b; rex_flags_sub(c,_a,_b,_r,{w}); }} c->edi += _d;",
            StringKind.Cmps =>
                $"{{ uint64_t _a={mem}(c->esi),_b={mem}(c->edi),_r=_a-_b; rex_flags_sub(c,_a,_b,_r,{w}); }} c->esi += _d; c->edi += _d;",
            _ => "",
        };

        string dir = $"int32_t _d = c->df ? -{step} : {step};";
        bool rep = insn.HasRepPrefix || insn.HasRepePrefix || insn.HasRepnePrefix;
        if (!rep)
        {
            Line(b, $"{{ {dir} {body} }}");
            return true;
        }

        // REP: iterate ECX times. REPE/REPNE (scas/cmps) also break on ZF.
        string extra = kind is StringKind.Scas or StringKind.Cmps
            ? (insn.HasRepnePrefix ? " if (c->zf) break;" : " if (!c->zf) break;")
            : "";
        Line(b, $"{{ {dir} while (c->ecx != 0) {{ {body} c->ecx--;{extra} }} }}");
        return true;
    }

    private bool X87(StringBuilder b, in Instruction insn, uint addr)
    {
        string M32 = insn.Op0Kind == OpKind.Memory ? MemF(insn, addr) : null!;
        switch (insn.Mnemonic)
        {
            case Mnemonic.Fld:
                Line(b, $"FPU_PUSH(c, {(insn.Op0Kind == OpKind.Memory ? MemF(insn, addr) : StI(insn, 0))});");
                return true;
            case Mnemonic.Fld1: Line(b, "FPU_PUSH(c, 1.0);"); return true;
            case Mnemonic.Fldz: Line(b, "FPU_PUSH(c, 0.0);"); return true;
            case Mnemonic.Fild:
                Line(b, $"FPU_PUSH(c, (double)(int32_t){IntMem(insn, addr)});");
                return true;
            case Mnemonic.Fst:
                Line(b, insn.Op0Kind == OpKind.Memory
                    ? $"{MemFStore(insn, addr, "FPU_ST(c, 0)")}"
                    : $"{StI(insn, 0)} = FPU_ST(c, 0);");
                return true;
            case Mnemonic.Fstp:
                Line(b, (insn.Op0Kind == OpKind.Memory
                    ? MemFStore(insn, addr, "FPU_ST(c, 0)")
                    : $"{StI(insn, 0)} = FPU_ST(c, 0);") + " FPU_POP(c);");
                return true;
            case Mnemonic.Fistp:
                Line(b, $"{IntMemStore(insn, addr, "(int32_t)FPU_ST(c, 0)")} FPU_POP(c);");
                return true;
            case Mnemonic.Fchs: Line(b, "FPU_ST(c, 0) = -FPU_ST(c, 0);"); return true;
            case Mnemonic.Fabs: Line(b, "FPU_ST(c, 0) = FPU_ST(c, 0) < 0 ? -FPU_ST(c, 0) : FPU_ST(c, 0);"); return true;
            case Mnemonic.Fxch:
                Line(b, $"{{ double _t = FPU_ST(c, 0); FPU_ST(c, 0) = {StI(insn, 0, "1")}; {StI(insn, 0, "1")} = _t; }}");
                return true;

            case Mnemonic.Fadd or Mnemonic.Fsub or Mnemonic.Fsubr or Mnemonic.Fmul
                or Mnemonic.Fdiv or Mnemonic.Fdivr:
                return X87Arith(b, insn, addr, pop: false);
            case Mnemonic.Faddp or Mnemonic.Fsubp or Mnemonic.Fsubrp or Mnemonic.Fmulp
                or Mnemonic.Fdivp or Mnemonic.Fdivrp:
                return X87Arith(b, insn, addr, pop: true);

            case Mnemonic.Fcom:
                Line(b, $"rex_fcom(c, FPU_ST(c, 0), {X87Src(insn, addr)});");
                return true;
            case Mnemonic.Fcomp or Mnemonic.Fucom or Mnemonic.Fucomp:
                Line(b, $"rex_fcom(c, FPU_ST(c, 0), {X87Src(insn, addr)}); FPU_POP(c);");
                return true;
            case Mnemonic.Fcompp or Mnemonic.Fucompp:
                Line(b, "rex_fcom(c, FPU_ST(c, 0), FPU_ST(c, 1)); FPU_POP(c); FPU_POP(c);");
                return true;

            case Mnemonic.Fnstsw:
                Line(b, insn.Op0Kind == OpKind.Register
                    ? "SET_LO16(c->eax, c->fpu_sw);"
                    : $"{MemAddr16Store(insn, addr, "c->fpu_sw")}");
                return true;
            case Mnemonic.Fnstcw:
                Line(b, $"{MemAddr16Store(insn, addr, "c->fpu_cw")}");
                return true;
            case Mnemonic.Fldcw:
                Line(b, $"c->fpu_cw = (uint16_t)MEM16({COperand.LeaAddr(insn)});");
                return true;
        }
        Line(b, $"REX_UNIMPLEMENTED(\"{insn.Mnemonic}\", 0x{addr:X8});");
        return false;
    }

    private bool X87Arith(StringBuilder b, in Instruction insn, uint addr, bool pop)
    {
        // dest/src: fadd st(i),st(0) / fadd st(0),m32 / faddp st(i),st(0)
        string opc = insn.Mnemonic.ToString();
        string cop = opc.StartsWith("Fadd") ? "+" : opc.StartsWith("Fmul") ? "*"
                   : opc.StartsWith("Fsubr") ? "R-" : opc.StartsWith("Fsub") ? "-"
                   : opc.StartsWith("Fdivr") ? "R/" : "/";

        string dst = insn.OpCount >= 2 && insn.Op0Kind == OpKind.Register ? StI(insn, 0) : "FPU_ST(c, 0)";
        string src = X87Src(insn, addr);
        string expr = cop switch
        {
            "R-" => $"{src} - {dst}",
            "R/" => $"{src} / {dst}",
            _ => $"{dst} {cop} {src}",
        };
        Line(b, $"{dst} = {expr};" + (pop ? " FPU_POP(c);" : ""));
        return true;
    }

    private static string X87Src(in Instruction insn, uint addr)
    {
        if (insn.OpCount == 0) return "FPU_ST(c, 1)";
        int srcOp = insn.OpCount - 1;
        return insn.GetOpKind(srcOp) == OpKind.Memory ? MemF(insn, addr)
             : insn.GetOpKind(srcOp) == OpKind.Register ? StIReg(insn.GetOpRegister(srcOp))
             : "FPU_ST(c, 1)";
    }

    private static string StI(in Instruction insn, int op, string? fixedIdx = null)
    {
        if (fixedIdx is not null) return $"FPU_ST(c, {fixedIdx})";
        return insn.GetOpKind(op) == OpKind.Register ? StIReg(insn.GetOpRegister(op)) : "FPU_ST(c, 0)";
    }

    private static string StIReg(Register r) =>
        r is >= Register.ST0 and <= Register.ST7 ? $"FPU_ST(c, {r - Register.ST0})" : "FPU_ST(c, 0)";

    private static string MemF(in Instruction insn, uint addr)
    {
        bool f64 = insn.MemorySize is MemorySize.Float64;
        return $"(*({(f64 ? "double" : "float")}*)XBOX_PTR({COperand.LeaAddr(insn)}))";
    }
    private static string MemFStore(in Instruction insn, uint addr, string val)
    {
        bool f64 = insn.MemorySize is MemorySize.Float64;
        return $"*({(f64 ? "double" : "float")}*)XBOX_PTR({COperand.LeaAddr(insn)}) = ({(f64 ? "double" : "float")})({val});";
    }
    private static string IntMem(in Instruction insn, uint addr)
    {
        int w = insn.MemorySize is MemorySize.Int16 or MemorySize.UInt16 ? 16 : 32;
        return $"SMEM{w}({COperand.LeaAddr(insn)})";
    }
    private static string IntMemStore(in Instruction insn, uint addr, string val)
    {
        int w = insn.MemorySize is MemorySize.Int16 or MemorySize.UInt16 ? 16 : 32;
        return $"MEM{w}({COperand.LeaAddr(insn)}) = (uint{w}_t)({val});";
    }
    private static string MemAddr16Store(in Instruction insn, uint addr, string val) =>
        $"MEM16({COperand.LeaAddr(insn)}) = (uint16_t)({val});";

    private bool Call(StringBuilder b, in Instruction insn, uint addr)
    {
        if (insn.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
        {
            uint target = (uint)insn.NearBranchTarget;
            if (_nameOf(target) is { } name)
                Line(b, $"{name}(c);");
            else
                Line(b, $"rex_dispatch(c, 0x{target:X8}u);");
        }
        else
        {
            Line(b, $"rex_dispatch(c, {R(insn, 0, addr)});");
        }
        return true;
    }

    private bool Jmp(StringBuilder b, in Instruction insn, uint addr, FunctionNode node, HashSet<uint> emitted)
    {
        if (insn.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
        {
            uint target = (uint)insn.NearBranchTarget;
            if (emitted.Contains(target))
            {
                Line(b, $"goto loc_{target:X};");
            }
            else if (_nameOf(target) is { } name)
            {
                Line(b, $"{name}(c); return; /* tail call */");
            }
            else
            {
                // jmp into another function's body / an unregistered address:
                // route through the runtime dispatcher (loud fail if unmapped).
                Line(b, $"rex_dispatch(c, 0x{target:X8}u); return; /* mid-function tail jump */");
            }
        }
        else
        {
            Line(b, $"rex_dispatch(c, {R(insn, 0, addr)}); return;");
        }
        return true;
    }

    private bool Jcc(StringBuilder b, in Instruction insn, uint addr, HashSet<uint> emitted)
    {
        uint target = (uint)insn.NearBranchTarget;
        if (emitted.Contains(target))
            Line(b, $"if ({Cond(insn.Mnemonic)}) goto loc_{target:X};");
        else
            Line(b, $"if ({Cond(insn.Mnemonic)}) {{ rex_dispatch(c, 0x{target:X8}u); return; }}");
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

    private static string CmovCond(Mnemonic m)
    {
        // Cmove -> Je, Cmovne -> Jne, ... reuse Cond by name suffix.
        string suffix = m.ToString()[4..]; // "e", "ne", "b", ...
        if (Enum.TryParse<Mnemonic>("J" + suffix, out var jm)) return Cond(jm);
        return "1";
    }

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
