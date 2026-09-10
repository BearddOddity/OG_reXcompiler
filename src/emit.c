#include "emit.h"
#include "emit_operand.h"
#include "util.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    strbuf b;
    DecodedBinary* db;
    FunctionNode* node;
    NameOfFn name_of;
    void* name_ctx;
    u32map emitted;           /* set: addrs that get a loc_X: label */
    int unimpl;
} E;

static void line(E* e, const char* s) { sb_add(&e->b, "\t"); sb_add(&e->b, s); sb_add(&e->b, "\n"); }
static void linef(E* e, const char* fmt, ...) {
    char t[1024]; va_list ap; va_start(ap, fmt); vsnprintf(t, sizeof t, fmt, ap); va_end(ap);
    line(e, t);
}

/* operand helpers bound to a decoded raw instruction */
typedef struct { ZydisDecodedInstruction ins; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]; uint32_t addr; } RI;

static void R(RI* r, int i, char* buf, size_t n) { op_read(&r->ins, r->ops, i, r->addr, buf, n); }
static void W(RI* r, int i, const char* v, char* buf, size_t n) { op_write(&r->ins, r->ops, i, r->addr, v, buf, n); }
static int  WIDTH(RI* r, int i) { return op_width(&r->ins, r->ops, i); }

/*=========================================================================
 * condition codes
 *=======================================================================*/

static const char* cond_for(ZydisMnemonic m) {
    switch (m) {
        case ZYDIS_MNEMONIC_JZ:  case ZYDIS_MNEMONIC_SETZ:  case ZYDIS_MNEMONIC_CMOVZ:  return "c->zf";
        case ZYDIS_MNEMONIC_JNZ: case ZYDIS_MNEMONIC_SETNZ: case ZYDIS_MNEMONIC_CMOVNZ: return "!c->zf";
        case ZYDIS_MNEMONIC_JB:  case ZYDIS_MNEMONIC_SETB:  case ZYDIS_MNEMONIC_CMOVB:  return "c->cf";
        case ZYDIS_MNEMONIC_JNB: case ZYDIS_MNEMONIC_SETNB: case ZYDIS_MNEMONIC_CMOVNB: return "!c->cf";
        case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_SETBE: case ZYDIS_MNEMONIC_CMOVBE: return "(c->cf || c->zf)";
        case ZYDIS_MNEMONIC_JNBE:case ZYDIS_MNEMONIC_SETNBE:case ZYDIS_MNEMONIC_CMOVNBE:return "(!c->cf && !c->zf)";
        case ZYDIS_MNEMONIC_JL:  case ZYDIS_MNEMONIC_SETL:  case ZYDIS_MNEMONIC_CMOVL:  return "(c->sf != c->of)";
        case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_SETNL: case ZYDIS_MNEMONIC_CMOVNL: return "(c->sf == c->of)";
        case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_SETLE: case ZYDIS_MNEMONIC_CMOVLE: return "(c->zf || c->sf != c->of)";
        case ZYDIS_MNEMONIC_JNLE:case ZYDIS_MNEMONIC_SETNLE:case ZYDIS_MNEMONIC_CMOVNLE:return "(!c->zf && c->sf == c->of)";
        case ZYDIS_MNEMONIC_JS:  case ZYDIS_MNEMONIC_SETS:  case ZYDIS_MNEMONIC_CMOVS:  return "c->sf";
        case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_SETNS: case ZYDIS_MNEMONIC_CMOVNS: return "!c->sf";
        case ZYDIS_MNEMONIC_JO:  case ZYDIS_MNEMONIC_SETO:  case ZYDIS_MNEMONIC_CMOVO:  return "c->of";
        case ZYDIS_MNEMONIC_JNO: case ZYDIS_MNEMONIC_SETNO: case ZYDIS_MNEMONIC_CMOVNO: return "!c->of";
        case ZYDIS_MNEMONIC_JP:  case ZYDIS_MNEMONIC_SETP:  case ZYDIS_MNEMONIC_CMOVP:  return "c->pf";
        case ZYDIS_MNEMONIC_JNP: case ZYDIS_MNEMONIC_SETNP: case ZYDIS_MNEMONIC_CMOVNP: return "!c->pf";
        case ZYDIS_MNEMONIC_JCXZ:  return "(LO16(c->ecx) == 0)";
        case ZYDIS_MNEMONIC_JECXZ: return "(c->ecx == 0)";
        default: return "0";
    }
}
static int is_setcc(ZydisMnemonic m) { return m >= ZYDIS_MNEMONIC_SETB && m <= ZYDIS_MNEMONIC_SETZ; }
static int is_cmovcc(ZydisMnemonic m) { return m >= ZYDIS_MNEMONIC_CMOVB && m <= ZYDIS_MNEMONIC_CMOVZ; }

/*=========================================================================
 * ALU groups
 *=======================================================================*/

static void alu(E* e, RI* r, const char* op, const char* flags, int write_back) {
    int w = WIDTH(r, 0);
    char a[256], b[256];
    R(r, 0, a, sizeof a); R(r, 1, b, sizeof b);
    char body[1024];
    int p = snprintf(body, sizeof body,
        "{ uint64_t _a = %s; uint64_t _b = %s; uint64_t _r = _a %s _b; ", a, b, op);
    if (write_back) { char wb[512]; W(r, 0, "(uint32_t)_r", wb, sizeof wb);
        p += snprintf(body + p, sizeof body - p, "%s ", wb); }
    if (!strcmp(flags, "add")) p += snprintf(body + p, sizeof body - p, "rex_flags_add(c, _a, _b, _r, %d);", w);
    else if (!strcmp(flags, "sub")) p += snprintf(body + p, sizeof body - p, "rex_flags_sub(c, _a, _b, _r, %d);", w);
    else p += snprintf(body + p, sizeof body - p, "rex_flags_logic(c, _r, %d);", w);
    snprintf(body + p, sizeof body - p, " }");
    line(e, body);
}

static void inc_dec(E* e, RI* r, int delta) {
    int w = WIDTH(r, 0);
    char a[256], wb[512];
    R(r, 0, a, sizeof a);
    W(r, 0, "(uint32_t)_r", wb, sizeof wb);
    linef(e, "{ uint8_t _cf = c->cf; uint64_t _a = %s; uint64_t _r = _a %s 1; %s "
             "rex_flags_%s(c, _a, 1, _r, %d); c->cf = _cf; }",
          a, delta > 0 ? "+" : "-", wb, delta > 0 ? "add" : "sub", w);
}

static void add_carry(E* e, RI* r, int sub) {
    int w = WIDTH(r, 0);
    char a[256], b[256], wb[512];
    R(r, 0, a, sizeof a); R(r, 1, b, sizeof b);
    W(r, 0, "(uint32_t)_r", wb, sizeof wb);
    const char* op = sub ? "-" : "+";
    linef(e, "{ uint64_t _a = %s; uint64_t _b = (uint64_t)(%s) %s c->cf; uint64_t _r = _a %s _b; %s "
             "rex_flags_%s(c, _a, _b, _r, %d); }",
          a, b, op, op, wb, sub ? "sub" : "add", w);
}

static void shift(E* e, RI* r, const char* op) {
    int w = WIDTH(r, 0);
    char cnt[128] = "1u", src[256], wb[512];
    if (r->ins.operand_count_visible > 1) R(r, 1, cnt, sizeof cnt);
    R(r, 0, src, sizeof src);
    W(r, 0, "(uint32_t)_r", wb, sizeof wb);
    linef(e, "{ uint32_t _s = (%s) & 31u; uint64_t _r = (uint64_t)(uint%d_t)(%s) %s _s; %s "
             "rex_flags_logic(c, _r, %d); }", cnt, w, src, op, wb, w);
}

static void shift_arith(E* e, RI* r) {
    int w = WIDTH(r, 0);
    char cnt[128] = "1u", src[256], wb[512];
    if (r->ins.operand_count_visible > 1) R(r, 1, cnt, sizeof cnt);
    R(r, 0, src, sizeof src);
    W(r, 0, "(uint32_t)_r", wb, sizeof wb);
    linef(e, "{ uint32_t _s = (%s) & 31u; int64_t _r = (int64_t)(int%d_t)(%s) >> _s; %s "
             "rex_flags_logic(c, (uint64_t)_r, %d); }", cnt, w, src, wb, w);
}

static void rotate(E* e, RI* r, int left) {
    int w = WIDTH(r, 0);
    char cnt[128] = "1u", src[256], wb[512];
    if (r->ins.operand_count_visible > 1) R(r, 1, cnt, sizeof cnt);
    R(r, 0, src, sizeof src);
    W(r, 0, "_r", wb, sizeof wb);
    linef(e, "{ uint32_t _s = (%s) & %du; uint%d_t _v = (uint%d_t)(%s); "
             "uint%d_t _r = _s ? (%s) : _v; %s }",
          cnt, w - 1, w, w, src, w,
          left ? "(_v << _s) | (_v >> ((32 - _s) & 31))"
               : "(_v >> _s) | (_v << ((32 - _s) & 31))", wb);
}

static void bit_test(E* e, RI* r) {
    char src[256], bit[256];
    R(r, 0, src, sizeof src); R(r, 1, bit, sizeof bit);
    linef(e, "c->cf = ((%s) >> ((%s) & 31u)) & 1u;", src, bit);
    if (r->ins.mnemonic != ZYDIS_MNEMONIC_BT) {
        const char* opv = r->ins.mnemonic == ZYDIS_MNEMONIC_BTS ? "|"
                        : r->ins.mnemonic == ZYDIS_MNEMONIC_BTR ? "& ~" : "^";
        char val[512], wb[600];
        snprintf(val, sizeof val, "(%s) %s (1u << ((%s) & 31u))", src, opv, bit);
        W(r, 0, val, wb, sizeof wb);
        line(e, wb);
    }
}

static void div_op(E* e, RI* r, int is_signed) {
    int w = WIDTH(r, 0);
    char d[256]; R(r, 0, d, sizeof d);
    if (w == 32) {
        const char* t = is_signed ? "int64_t" : "uint64_t";
        const char* dt = is_signed ? "int32_t" : "uint32_t";
        const char* dividend = is_signed
            ? "(int64_t)(((uint64_t)c->edx << 32) | c->eax)"
            : "(((uint64_t)c->edx << 32) | c->eax)";
        linef(e, "{ %s _n = %s; %s _d = (%s)(%s); c->eax = (uint32_t)(_n / _d); "
                 "c->edx = (uint32_t)(_n %% _d); }", t, dividend, t, dt, d);
    } else {
        linef(e, "{ uint32_t _n = c->eax; uint32_t _d = (%s); "
                 "c->eax = (c->eax & 0xFFFF0000u) | ((_n / _d) & 0xFFFFu) | (((_n %% _d) & 0xFFFFu) << 16); }", d);
    }
}

static void imul_op(E* e, RI* r) {
    char a[256], b[256], wb[512];
    if (r->ins.operand_count_visible == 1) {
        R(r, 0, a, sizeof a);
        linef(e, "{ int64_t _p = (int64_t)(int32_t)c->eax * (int64_t)(int32_t)(%s); "
                 "c->eax = (uint32_t)_p; c->edx = (uint32_t)((uint64_t)_p >> 32); }", a);
        return;
    }
    int dst = r->ins.operand_count_visible == 3 ? 1 : 0;
    int src = r->ins.operand_count_visible == 3 ? 2 : 1;
    R(r, dst, a, sizeof a); R(r, src, b, sizeof b);
    W(r, 0, "(uint32_t)_p", wb, sizeof wb);
    linef(e, "{ int64_t _p = (int64_t)(int32_t)(%s) * (int64_t)(int32_t)(%s); %s "
             "c->cf = c->of = ((_p >> 31) != 0 && (_p >> 31) != -1); }", a, b, wb);
}

/*=========================================================================
 * string ops
 *=======================================================================*/

static void string_op(E* e, RI* r) {
    ZydisMnemonic m = r->ins.mnemonic;
    int w = 32;
    if (m == ZYDIS_MNEMONIC_MOVSB || m == ZYDIS_MNEMONIC_STOSB || m == ZYDIS_MNEMONIC_LODSB ||
        m == ZYDIS_MNEMONIC_SCASB || m == ZYDIS_MNEMONIC_CMPSB) w = 8;
    else if (m == ZYDIS_MNEMONIC_MOVSW || m == ZYDIS_MNEMONIC_STOSW || m == ZYDIS_MNEMONIC_LODSW ||
             m == ZYDIS_MNEMONIC_SCASW || m == ZYDIS_MNEMONIC_CMPSW) w = 16;
    int step = w / 8;

    const char* body;
    char bb[512];
    char mem[8]; snprintf(mem, sizeof mem, "MEM%d", w);
    if (m == ZYDIS_MNEMONIC_MOVSB || m == ZYDIS_MNEMONIC_MOVSW || m == ZYDIS_MNEMONIC_MOVSD)
        snprintf(bb, sizeof bb, "%s(c->edi) = %s(c->esi); c->esi += _d; c->edi += _d;", mem, mem);
    else if (m == ZYDIS_MNEMONIC_STOSB || m == ZYDIS_MNEMONIC_STOSW || m == ZYDIS_MNEMONIC_STOSD)
        snprintf(bb, sizeof bb, "%s(c->edi) = (uint%d_t)c->eax; c->edi += _d;", mem, w);
    else if (m == ZYDIS_MNEMONIC_LODSB || m == ZYDIS_MNEMONIC_LODSW || m == ZYDIS_MNEMONIC_LODSD)
        snprintf(bb, sizeof bb, "c->eax = (c->eax & ~(uint32_t)((1ull<<%d)-1)) | %s(c->esi); c->esi += _d;", w, mem);
    else if (m == ZYDIS_MNEMONIC_SCASB || m == ZYDIS_MNEMONIC_SCASW || m == ZYDIS_MNEMONIC_SCASD)
        snprintf(bb, sizeof bb, "{ uint64_t _a=(uint%d_t)c->eax,_b=%s(c->edi),_x=_a-_b; rex_flags_sub(c,_a,_b,_x,%d); } c->edi += _d;", w, mem, w);
    else
        snprintf(bb, sizeof bb, "{ uint64_t _a=%s(c->esi),_b=%s(c->edi),_x=_a-_b; rex_flags_sub(c,_a,_b,_x,%d); } c->esi += _d; c->edi += _d;", mem, mem, w);
    body = bb;

    int rep = (r->ins.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) != 0;
    if (!rep) { linef(e, "{ int32_t _d = c->df ? -%d : %d; %s }", step, step, body); return; }
    const char* extra = "";
    if (m == ZYDIS_MNEMONIC_SCASB || m == ZYDIS_MNEMONIC_SCASW || m == ZYDIS_MNEMONIC_SCASD ||
        m == ZYDIS_MNEMONIC_CMPSB || m == ZYDIS_MNEMONIC_CMPSW || m == ZYDIS_MNEMONIC_CMPSD)
        extra = (r->ins.attributes & ZYDIS_ATTRIB_HAS_REPNE) ? " if (c->zf) break;" : " if (!c->zf) break;";
    linef(e, "{ int32_t _d = c->df ? -%d : %d; while (c->ecx != 0) { %s c->ecx--;%s } }", step, step, body, extra);
}

/*=========================================================================
 * x87
 *=======================================================================*/

static void mem_f(RI* r, int opi, char* buf, size_t n) {
    char a[288]; op_lea_addr_at(&r->ins, r->ops, opi, a, sizeof a);
    int f64 = r->ops[opi].size == 64;
    snprintf(buf, n, "(*(%s*)XBOX_PTR(%s))", f64 ? "double" : "float", a);
}

static int x87(E* e, RI* r, uint32_t addr) {
    ZydisMnemonic m = r->ins.mnemonic;
    int mem0 = r->ins.operand_count_visible > 0 && r->ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY;
    char mf[320];
    switch (m) {
        case ZYDIS_MNEMONIC_FLD:
            if (mem0) { mem_f(r, 0, mf, sizeof mf); linef(e, "FPU_PUSH(c, %s);", mf); }
            else linef(e, "FPU_PUSH(c, FPU_ST(c, 0));");
            return 1;
        case ZYDIS_MNEMONIC_FLD1: line(e, "FPU_PUSH(c, 1.0);"); return 1;
        case ZYDIS_MNEMONIC_FLDZ: line(e, "FPU_PUSH(c, 0.0);"); return 1;
        case ZYDIS_MNEMONIC_FILD: {
            char a[288]; op_lea_addr_at(&r->ins, r->ops, 0, a, sizeof a);
            int w = r->ops[0].size == 16 ? 16 : 32;
            linef(e, "FPU_PUSH(c, (double)(int32_t)SMEM%d(%s));", w, a); return 1;
        }
        case ZYDIS_MNEMONIC_FST: case ZYDIS_MNEMONIC_FSTP:
            if (mem0) { char a[288]; op_lea_addr_at(&r->ins, r->ops, 0, a, sizeof a);
                int f64 = r->ops[0].size == 64;
                linef(e, "*(%s*)XBOX_PTR(%s) = (%s)FPU_ST(c, 0);%s",
                      f64 ? "double" : "float", a, f64 ? "double" : "float",
                      m == ZYDIS_MNEMONIC_FSTP ? " FPU_POP(c);" : ""); }
            else linef(e, "FPU_ST(c, 0) = FPU_ST(c, 0);%s", m == ZYDIS_MNEMONIC_FSTP ? " FPU_POP(c);" : "");
            return 1;
        case ZYDIS_MNEMONIC_FISTP: {
            char a[288]; op_lea_addr_at(&r->ins, r->ops, 0, a, sizeof a);
            int w = r->ops[0].size == 16 ? 16 : 32;
            linef(e, "MEM%d(%s) = (uint%d_t)(int32_t)FPU_ST(c, 0); FPU_POP(c);", w, a, w); return 1;
        }
        case ZYDIS_MNEMONIC_FCHS: line(e, "FPU_ST(c, 0) = -FPU_ST(c, 0);"); return 1;
        case ZYDIS_MNEMONIC_FABS: line(e, "FPU_ST(c, 0) = FPU_ST(c, 0) < 0 ? -FPU_ST(c, 0) : FPU_ST(c, 0);"); return 1;
        case ZYDIS_MNEMONIC_FSQRT: line(e, "FPU_ST(c, 0) = __builtin_sqrt(FPU_ST(c, 0));"); return 1;
        case ZYDIS_MNEMONIC_FSIN: line(e, "FPU_ST(c, 0) = __builtin_sin(FPU_ST(c, 0));"); return 1;
        case ZYDIS_MNEMONIC_FCOS: line(e, "FPU_ST(c, 0) = __builtin_cos(FPU_ST(c, 0));"); return 1;
        case ZYDIS_MNEMONIC_FRNDINT: line(e, "FPU_ST(c, 0) = __builtin_rint(FPU_ST(c, 0));"); return 1;
        case ZYDIS_MNEMONIC_FXCH:
            line(e, "{ double _t = FPU_ST(c, 0); FPU_ST(c, 0) = FPU_ST(c, 1); FPU_ST(c, 1) = _t; }");
            return 1;
        case ZYDIS_MNEMONIC_FADD: case ZYDIS_MNEMONIC_FADDP:
        case ZYDIS_MNEMONIC_FSUB: case ZYDIS_MNEMONIC_FSUBP:
        case ZYDIS_MNEMONIC_FSUBR: case ZYDIS_MNEMONIC_FSUBRP:
        case ZYDIS_MNEMONIC_FMUL: case ZYDIS_MNEMONIC_FMULP:
        case ZYDIS_MNEMONIC_FDIV: case ZYDIS_MNEMONIC_FDIVP:
        case ZYDIS_MNEMONIC_FDIVR: case ZYDIS_MNEMONIC_FDIVRP: {
            int pop = (m == ZYDIS_MNEMONIC_FADDP || m == ZYDIS_MNEMONIC_FSUBP || m == ZYDIS_MNEMONIC_FSUBRP ||
                       m == ZYDIS_MNEMONIC_FMULP || m == ZYDIS_MNEMONIC_FDIVP || m == ZYDIS_MNEMONIC_FDIVRP);
            const char* cop = (m==ZYDIS_MNEMONIC_FADD||m==ZYDIS_MNEMONIC_FADDP) ? "+"
                            : (m==ZYDIS_MNEMONIC_FMUL||m==ZYDIS_MNEMONIC_FMULP) ? "*"
                            : (m==ZYDIS_MNEMONIC_FSUBR||m==ZYDIS_MNEMONIC_FSUBRP) ? "R-"
                            : (m==ZYDIS_MNEMONIC_FSUB||m==ZYDIS_MNEMONIC_FSUBP) ? "-"
                            : (m==ZYDIS_MNEMONIC_FDIVR||m==ZYDIS_MNEMONIC_FDIVRP) ? "R/" : "/";
            char src[320];
            if (mem0) mem_f(r, 0, src, sizeof src);
            else snprintf(src, sizeof src, "FPU_ST(c, 1)");
            const char* dst = "FPU_ST(c, 0)";
            if (!strcmp(cop, "R-")) linef(e, "%s = %s - %s;%s", dst, src, dst, pop ? " FPU_POP(c);" : "");
            else if (!strcmp(cop, "R/")) linef(e, "%s = %s / %s;%s", dst, src, dst, pop ? " FPU_POP(c);" : "");
            else linef(e, "%s = %s %s %s;%s", dst, dst, cop, src, pop ? " FPU_POP(c);" : "");
            return 1;
        }
        case ZYDIS_MNEMONIC_FCOM: linef(e, "rex_fcom(c, FPU_ST(c, 0), FPU_ST(c, 1));"); return 1;
        case ZYDIS_MNEMONIC_FCOMP: case ZYDIS_MNEMONIC_FUCOM: case ZYDIS_MNEMONIC_FUCOMP:
            linef(e, "rex_fcom(c, FPU_ST(c, 0), FPU_ST(c, 1)); FPU_POP(c);"); return 1;
        case ZYDIS_MNEMONIC_FCOMPP: case ZYDIS_MNEMONIC_FUCOMPP:
            line(e, "rex_fcom(c, FPU_ST(c, 0), FPU_ST(c, 1)); FPU_POP(c); FPU_POP(c);"); return 1;
        case ZYDIS_MNEMONIC_FNSTSW:
            if (r->ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) line(e, "SET_LO16(c->eax, c->fpu_sw);");
            else { char a[288]; op_lea_addr_at(&r->ins, r->ops, 0, a, sizeof a);
                   linef(e, "MEM16(%s) = c->fpu_sw;", a); }
            return 1;
        case ZYDIS_MNEMONIC_FNSTCW: { char a[288]; op_lea_addr_at(&r->ins, r->ops, 0, a, sizeof a);
            linef(e, "MEM16(%s) = c->fpu_cw;", a); return 1; }
        case ZYDIS_MNEMONIC_FLDCW: { char a[288]; op_lea_addr_at(&r->ins, r->ops, 0, a, sizeof a);
            linef(e, "c->fpu_cw = (uint16_t)MEM16(%s);", a); return 1; }
        case ZYDIS_MNEMONIC_FNINIT: line(e, "c->fpu_cw = 0x037F; c->fpu_sw = 0; c->fpu_top = 0;"); return 1;
        case ZYDIS_MNEMONIC_FNCLEX: line(e, "c->fpu_sw &= (uint16_t)~0x80FFu;"); return 1;  /* clear exception + busy bits */
        default: break;
    }
    linef(e, "REX_UNIMPLEMENTED(\"%s\", 0x%08X);", ZydisMnemonicGetString(m), addr);
    return 0;
}

/*=========================================================================
 * per-instruction dispatch
 *=======================================================================*/

static int emit_one(E* e, RI* r, uint32_t addr) {
    ZydisMnemonic m = r->ins.mnemonic;
    char a[512], b[512], wb[600];

    switch (m) {
        case ZYDIS_MNEMONIC_NOP: case ZYDIS_MNEMONIC_PAUSE: case ZYDIS_MNEMONIC_FNOP:
        case ZYDIS_MNEMONIC_FWAIT: case ZYDIS_MNEMONIC_ENDBR32: case ZYDIS_MNEMONIC_ENDBR64:
            return 1;
        case ZYDIS_MNEMONIC_CLD: line(e, "c->df = 0;"); return 1;
        case ZYDIS_MNEMONIC_STD: line(e, "c->df = 1;"); return 1;
        case ZYDIS_MNEMONIC_RDTSC:
            line(e, "{ uint64_t _t = rex_rdtsc(); c->eax = (uint32_t)_t; c->edx = (uint32_t)(_t >> 32); }");
            return 1;
        case ZYDIS_MNEMONIC_CPUID:
            /* enough for CRT feature detection: no SSE/CMOV advertised */
            line(e, "{ uint32_t _l = c->eax; c->eax = _l ? 0 : 1; c->ebx = 0x756E6547; c->edx = 0x49656E69; c->ecx = 0x6C65746E; }");
            return 1;
        case ZYDIS_MNEMONIC_CLC: line(e, "c->cf = 0;"); return 1;
        case ZYDIS_MNEMONIC_STC: line(e, "c->cf = 1;"); return 1;
        case ZYDIS_MNEMONIC_CMC: line(e, "c->cf = !c->cf;"); return 1;

        case ZYDIS_MNEMONIC_MOV:
            R(r, 1, b, sizeof b); W(r, 0, b, wb, sizeof wb); line(e, wb); return 1;
        case ZYDIS_MNEMONIC_MOVZX:
            R(r, 1, b, sizeof b); { char v[560]; snprintf(v, sizeof v, "(uint32_t)(%s)", b);
            W(r, 0, v, wb, sizeof wb); } line(e, wb); return 1;
        case ZYDIS_MNEMONIC_MOVSX: case ZYDIS_MNEMONIC_MOVSXD: {
            int w1 = WIDTH(r, 1); R(r, 1, b, sizeof b);
            char v[600]; snprintf(v, sizeof v, "(uint32_t)(int32_t)(int%d_t)(%s)", w1, b);
            W(r, 0, v, wb, sizeof wb); line(e, wb); return 1;
        }
        case ZYDIS_MNEMONIC_LEA:
            op_lea_addr(&r->ins, r->ops, b, sizeof b); W(r, 0, b, wb, sizeof wb); line(e, wb); return 1;
        case ZYDIS_MNEMONIC_PUSH:
            R(r, 0, a, sizeof a); linef(e, "PUSH32(c, %s);", a); return 1;
        case ZYDIS_MNEMONIC_POP:
            W(r, 0, "_t", wb, sizeof wb); linef(e, "{ uint32_t _t; POP32(c, _t); %s }", wb); return 1;
        case ZYDIS_MNEMONIC_LEAVE:
            line(e, "c->esp = c->ebp; { uint32_t _t; POP32(c, _t); c->ebp = _t; }"); return 1;

        case ZYDIS_MNEMONIC_ADD: alu(e, r, "+", "add", 1); return 1;
        case ZYDIS_MNEMONIC_SUB: alu(e, r, "-", "sub", 1); return 1;
        case ZYDIS_MNEMONIC_CMP: alu(e, r, "-", "sub", 0); return 1;
        case ZYDIS_MNEMONIC_AND: alu(e, r, "&", "logic", 1); return 1;
        case ZYDIS_MNEMONIC_OR:  alu(e, r, "|", "logic", 1); return 1;
        case ZYDIS_MNEMONIC_XOR: alu(e, r, "^", "logic", 1); return 1;
        case ZYDIS_MNEMONIC_TEST:alu(e, r, "&", "logic", 0); return 1;
        case ZYDIS_MNEMONIC_ADC: add_carry(e, r, 0); return 1;
        case ZYDIS_MNEMONIC_SBB: add_carry(e, r, 1); return 1;
        case ZYDIS_MNEMONIC_INC: inc_dec(e, r, +1); return 1;
        case ZYDIS_MNEMONIC_DEC: inc_dec(e, r, -1); return 1;
        case ZYDIS_MNEMONIC_NEG: {
            int w = WIDTH(r, 0); R(r, 0, a, sizeof a); W(r, 0, "(uint32_t)_r", wb, sizeof wb);
            linef(e, "{ uint64_t _a = %s; uint64_t _r = (uint64_t)0 - _a; %s rex_flags_sub(c, 0, _a, _r, %d); }", a, wb, w);
            return 1;
        }
        case ZYDIS_MNEMONIC_NOT:
            R(r, 0, a, sizeof a); { char v[560]; snprintf(v, sizeof v, "~(%s)", a);
            W(r, 0, v, wb, sizeof wb); } line(e, wb); return 1;
        case ZYDIS_MNEMONIC_SHL: shift(e, r, "<<"); return 1;
        case ZYDIS_MNEMONIC_SHR: shift(e, r, ">>"); return 1;
        case ZYDIS_MNEMONIC_SAR: shift_arith(e, r); return 1;
        case ZYDIS_MNEMONIC_ROL: rotate(e, r, 1); return 1;
        case ZYDIS_MNEMONIC_ROR: rotate(e, r, 0); return 1;
        case ZYDIS_MNEMONIC_BT: case ZYDIS_MNEMONIC_BTS: case ZYDIS_MNEMONIC_BTR: case ZYDIS_MNEMONIC_BTC:
            bit_test(e, r); return 1;
        case ZYDIS_MNEMONIC_XCHG:
            R(r, 1, b, sizeof b); { char w0[600], w1b[600]; W(r, 0, b, w0, sizeof w0);
            W(r, 1, "_t", w1b, sizeof w1b); R(r, 0, a, sizeof a);
            linef(e, "{ uint32_t _t = %s; %s %s }", a, w0, w1b); } return 1;
        case ZYDIS_MNEMONIC_CDQ: line(e, "c->edx = (c->eax & 0x80000000u) ? 0xFFFFFFFFu : 0u;"); return 1;
        case ZYDIS_MNEMONIC_CWDE: line(e, "c->eax = (uint32_t)(int32_t)(int16_t)LO16(c->eax);"); return 1;
        case ZYDIS_MNEMONIC_IMUL: imul_op(e, r); return 1;
        case ZYDIS_MNEMONIC_MUL:
            R(r, 0, a, sizeof a);
            linef(e, "{ uint64_t _p = (uint64_t)c->eax * (uint64_t)(%s); c->eax = (uint32_t)_p; "
                     "c->edx = (uint32_t)(_p >> 32); c->cf = c->of = (c->edx != 0); }", a);
            return 1;
        case ZYDIS_MNEMONIC_DIV: div_op(e, r, 0); return 1;
        case ZYDIS_MNEMONIC_IDIV: div_op(e, r, 1); return 1;
        case ZYDIS_MNEMONIC_BSWAP:
            R(r, 0, a, sizeof a); { char v[560]; snprintf(v, sizeof v, "__builtin_bswap32(%s)", a);
            W(r, 0, v, wb, sizeof wb); } line(e, wb); return 1;
        case ZYDIS_MNEMONIC_SAHF:
            line(e, "{ uint8_t _f = HI8(c->eax); c->cf=_f&1; c->pf=(_f>>2)&1; c->af=(_f>>4)&1; c->zf=(_f>>6)&1; c->sf=(_f>>7)&1; }");
            return 1;
        case ZYDIS_MNEMONIC_LAHF:
            line(e, "SET_HI8(c->eax, (c->cf) | 2 | (c->pf<<2) | (c->af<<4) | (c->zf<<6) | (c->sf<<7));");
            return 1;
        case ZYDIS_MNEMONIC_XLAT:
            line(e, "SET_LO8(c->eax, MEM8((uint32_t)(c->ebx + LO8(c->eax))));"); return 1;

        case ZYDIS_MNEMONIC_RET:
            /* Pop the return-address slot our `call` pushed, plus N bytes of
             * caller-pushed args for `ret N` (stdcall). Bare `ret` (cdecl)
             * leaves arg cleanup to the caller's own `add esp, N`. */
            if (r->ins.operand_count_visible >= 1 &&
                r->ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                r->ops[0].imm.value.u != 0)
                linef(e, "c->esp += %lluu; REX_LEAVE(); return;",
                      4ull + (unsigned long long)r->ops[0].imm.value.u);
            else
                line(e, "c->esp += 4u; REX_LEAVE(); return;");
            return 1;

        case ZYDIS_MNEMONIC_MOVSB: case ZYDIS_MNEMONIC_MOVSW: case ZYDIS_MNEMONIC_MOVSD:
        case ZYDIS_MNEMONIC_STOSB: case ZYDIS_MNEMONIC_STOSW: case ZYDIS_MNEMONIC_STOSD:
        case ZYDIS_MNEMONIC_LODSB: case ZYDIS_MNEMONIC_LODSW: case ZYDIS_MNEMONIC_LODSD:
        case ZYDIS_MNEMONIC_SCASB: case ZYDIS_MNEMONIC_SCASW: case ZYDIS_MNEMONIC_SCASD:
        case ZYDIS_MNEMONIC_CMPSB: case ZYDIS_MNEMONIC_CMPSW: case ZYDIS_MNEMONIC_CMPSD:
            string_op(e, r); return 1;

        default: break;
    }

    /* x87 */
    if (m >= ZYDIS_MNEMONIC_F2XM1 && m <= ZYDIS_MNEMONIC_FYL2XP1)
        return x87(e, r, addr);

    if (is_setcc(m)) {
        char v[128]; snprintf(v, sizeof v, "(%s) ? 1u : 0u", cond_for(m));
        W(r, 0, v, wb, sizeof wb); line(e, wb); return 1;
    }
    if (is_cmovcc(m)) {
        R(r, 1, b, sizeof b); W(r, 0, b, wb, sizeof wb);
        linef(e, "if (%s) { %s }", cond_for(m), wb); return 1;
    }

    linef(e, "REX_UNIMPLEMENTED(\"%s\", 0x%08X);", ZydisMnemonicGetString(m), addr);
    return 0;
}

/*=========================================================================
 * function walk
 *=======================================================================*/

static int cmp_block_e(const void* x, const void* y) {
    uint32_t a = ((const Block*)x)->base, b = ((const Block*)y)->base;
    return a < b ? -1 : a > b ? 1 : 0;
}

void emit_function(DecodedBinary* db, FunctionNode* node,
                   NameOfFn name_of, void* name_ctx, EmitResult* out) {
    E e; memset(&e, 0, sizeof e);
    e.db = db; e.node = node; e.name_of = name_of; e.name_ctx = name_ctx;
    u32map_init(&e.emitted, 256);

    /* instruction starts inside the blocks */
    u32map insn_starts; u32map_init(&insn_starts, 256);
    for (size_t i = 0; i < node->blocks.len; i++) {
        Block* blk = &node->blocks.data[i];
        uint32_t a = blk->base;
        while (a < block_end(blk)) {
            u32set_add(&insn_starts, a);
            DecodedInsn di;
            if (!db_decode_at(db, a, &di) || di.length == 0) { a++; continue; }
            a += di.length;
        }
    }
    /* labels from node + jump tables, intersected with instruction starts */
    for (size_t i = 0; i < node->labels.cap; i++)
        if (node->labels.used[i] && u32map_has(&insn_starts, node->labels.keys[i]))
            u32set_add(&e.emitted, node->labels.keys[i]);
    for (size_t i = 0; i < node->jump_tables.len; i++) {
        JumpTable* jt = node->jump_tables.data[i];
        for (size_t k = 0; k < jt->targets.len; k++)
            if (u32map_has(&insn_starts, jt->targets.data[k]))
                u32set_add(&e.emitted, jt->targets.data[k]);
    }
    /* direct branch targets landing on an instruction start */
    for (size_t i = 0; i < insn_starts.cap; i++) {
        if (!insn_starts.used[i]) continue;
        DecodedInsn di;
        if (!db_decode_at(db, insn_starts.keys[i], &di)) continue;
        if (di.target && (di.flow == FLOW_CONDITIONAL_BR || di.flow == FLOW_UNCONDITIONAL_BR) &&
            u32map_has(&insn_starts, di.target))
            u32set_add(&e.emitted, di.target);
    }

    /* sorted block copy */
    Block* blocks = malloc(node->blocks.len * sizeof(Block));
    memcpy(blocks, node->blocks.data, node->blocks.len * sizeof(Block));
    qsort(blocks, node->blocks.len, sizeof(Block), cmp_block_e);

    int insn_count = 0;
    for (size_t bi = 0; bi < node->blocks.len; bi++) {
        uint32_t addr = blocks[bi].base, end = block_end(&blocks[bi]);
        /* Bytes of `push` args feeding the next call. Only counts pushes that
         * are plausibly arguments (immediate, memory, or a scratch reg) — a
         * `push ebx/esi/edi/ebp` is a callee-saved save, not an arg. Reset on
         * anything that breaks the run. Used to unwind unresolved stdcall/
         * thiscall indirect calls without leaking their args. */
        int arg_bytes = 0;
        while (addr < end) {
            if (u32map_has(&e.emitted, addr)) {
                sb_addf(&e.b, "loc_%X:;\n", addr);
                arg_bytes = 0;
            }

            DecodedInsn di;
            RI r; r.addr = addr;
            int have_raw = db_decode_raw(db, addr, &r.ins, r.ops);
            int have_di = db_decode_at(db, addr, &di);

            if (!have_di || di.flow == FLOW_INVALID || di.length == 0) {
                sb_addf(&e.b, "\t/* .byte @ 0x%08X */\n", addr);
                addr++;
                arg_bytes = 0;
                continue;
            }

            sb_addf(&e.b, "\t/* %s */\n", di.text);
            insn_count++;

            int arg_push = 0, is_any_push = 0;
            if (have_raw && r.ins.mnemonic == ZYDIS_MNEMONIC_PUSH) {
                is_any_push = 1;
                ZydisRegister pr = r.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                                   ? r.ops[0].reg.value : ZYDIS_REGISTER_NONE;
                int callee_saved = pr == ZYDIS_REGISTER_EBX || pr == ZYDIS_REGISTER_ESI ||
                                   pr == ZYDIS_REGISTER_EDI || pr == ZYDIS_REGISTER_EBP;
                arg_push = !callee_saved;
            }

            if (di.flow == FLOW_INT3) { linef(&e, "REX_UNIMPLEMENTED(\"int3\", 0x%08X);", addr); }
            else if (di.flow == FLOW_CALL && di.target) {
                /* Real x86 `call` pushes the return address; the callee reads its
                 * stack args relative to it ([ebp+8] = arg1) and `ret N` pops it
                 * plus N arg bytes. Our `call` is a host C call, but the guest
                 * stack slot must still exist or every stack-arg read is off by
                 * one dword. HLE handlers account for the same slot. */
                const char* nm = name_of ? name_of(name_ctx, di.target) : NULL;
                line(&e, "#ifdef REX_TRACE");
                line(&e, "{ uint32_t _sp0 = c->esp, _bp0 = c->ebp;");
                linef(&e, "PUSH32(c, 0x%08Xu);", addr + di.length);
                if (nm) linef(&e, "%s(c);", nm);
                else linef(&e, "rex_dispatch(c, 0x%08Xu);", di.target);
                linef(&e, "rex_call_balance(0x%08Xu, 0x%08Xu, _sp0, c->esp, _bp0, c->ebp); }", addr, di.target);
                line(&e, "#else");
                linef(&e, "PUSH32(c, 0x%08Xu);", addr + di.length);
                if (nm) linef(&e, "%s(c);", nm);
                else linef(&e, "rex_dispatch(c, 0x%08Xu);", di.target);
                line(&e, "#endif");
            }
            else if (di.flow == FLOW_INDIRECT_CALL && have_raw) {
                char t[256]; R(&r, 0, t, sizeof t);
                /* An unresolved target must not leak the return slot or the
                 * pushed args. If a caller-side `add esp` follows, it is cdecl
                 * and the caller cleans — pop only the return slot. */
                DecodedInsn nxt;
                int caller_cleans = db_decode_at(db, addr + di.length, &nxt) &&
                    strncmp(nxt.text, "add esp,", 8) == 0;
                linef(&e, "PUSH32(c, 0x%08Xu);", addr + di.length);
                if (!caller_cleans && arg_bytes > 0)
                    linef(&e, "rex_icall_n(c, %s, %du);", t, arg_bytes);
                else
                    linef(&e, "rex_icall(c, %s);", t);
            }
            else if (di.flow == FLOW_UNCONDITIONAL_BR && di.target) {
                if (u32map_has(&e.emitted, di.target)) linef(&e, "goto loc_%X;", di.target);
                else {
                    const char* nm = name_of ? name_of(name_ctx, di.target) : NULL;
                    if (nm) linef(&e, "REX_LEAVE(); %s(c); return;", nm);
                    else linef(&e, "REX_LEAVE(); rex_dispatch(c, 0x%08Xu); return;", di.target);
                }
            }
            else if (di.flow == FLOW_INDIRECT_BR && have_raw) {
                JumpTable* jt = NULL;
                for (size_t k = 0; k < node->jump_tables.len; k++)
                    if (node->jump_tables.data[k]->jump_address == addr) { jt = node->jump_tables.data[k]; break; }
                if (jt && jt->targets.len >= 2) {
                    /* a real switch — dispatch within the function, not out of it */
                    linef(&e, "switch (%s) {", reg32_field((ZydisRegister)jt->index_register));
                    for (size_t k = 0; k < jt->targets.len; k++) {
                        uint32_t tg = jt->targets.data[k];
                        if (u32map_has(&e.emitted, tg)) linef(&e, "  case %zu: goto loc_%X;", k, tg);
                        else linef(&e, "  case %zu: REX_LEAVE(); rex_dispatch(c, 0x%08Xu); return;", k, tg);
                    }
                    line(&e, "  default: break;");
                    line(&e, "}");
                } else {
                    char t[256]; R(&r, 0, t, sizeof t);
                    linef(&e, "REX_LEAVE(); rex_dispatch(c, %s); return;", t);
                }
            }
            else if (di.flow == FLOW_CONDITIONAL_BR && di.target) {
                if (u32map_has(&e.emitted, di.target))
                    linef(&e, "if (%s) goto loc_%X;", cond_for(r.ins.mnemonic), di.target);
                else
                    linef(&e, "if (%s) { REX_LEAVE(); rex_dispatch(c, 0x%08Xu); return; }",
                          cond_for(r.ins.mnemonic), di.target);
            }
            else if (have_raw) {
                if (!emit_one(&e, &r, addr)) e.unimpl++;
            }
            else {
                linef(&e, "REX_UNIMPLEMENTED(\"decode\", 0x%08X);", addr);
                e.unimpl++;
            }

            if (arg_push) {
                arg_bytes += 4;
            } else if (!is_any_push &&
                       (di.flow != FLOW_NEXT ||
                        (have_raw && (r.ins.mnemonic == ZYDIS_MNEMONIC_POP ||
                                      (strstr(di.text, " esp,") &&
                                       (di.text[0] == 'a' || di.text[0] == 's')))))) {
                arg_bytes = 0;
            }

            addr += di.length;
        }
    }
    free(blocks);

    strbuf code = {0};
    sb_addf(&code, "void %s(RecompCtx* c) {\n", node->name);
    sb_addf(&code, "\tREX_ENTER(0x%08Xu);\n", node->base);
    if (e.b.data) sb_add(&code, e.b.data);
    sb_add(&code, "\tREX_LEAVE();\n}\n");

    out->name = strdup(node->name);
    out->code = sb_take(&code);
    out->instructions = insn_count;
    out->unimplemented = e.unimpl;

    free(sb_take(&e.b));
    u32map_free(&e.emitted);
    u32map_free(&insn_starts);
}

void emit_result_free(EmitResult* r) {
    free(r->name); free(r->code);
    r->name = r->code = NULL;
}
