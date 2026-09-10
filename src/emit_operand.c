#include "emit_operand.h"
#include <stdio.h>
#include <string.h>

int reg_index(ZydisRegister r) {
    ZydisRegister e = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LEGACY_32, r);
    if (e >= ZYDIS_REGISTER_EAX && e <= ZYDIS_REGISTER_EDI)
        return (int)(e - ZYDIS_REGISTER_EAX);   /* EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI */
    return -1;
}

int reg_width_bits(ZydisRegister r) {
    ZyanU16 w = ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LEGACY_32, r);
    return w ? (int)w : 32;
}

static int is_high8(ZydisRegister r) {
    return r == ZYDIS_REGISTER_AH || r == ZYDIS_REGISTER_CH ||
           r == ZYDIS_REGISTER_DH || r == ZYDIS_REGISTER_BH;
}

static const char* R32[8] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

const char* reg32_field(ZydisRegister r) {
    static char buf[16];
    int i = reg_index(r);
    if (i < 0) return "0";
    snprintf(buf, sizeof buf, "c->%s", R32[i]);
    return buf;
}

static void reg_read(ZydisRegister r, char* buf, size_t n) {
    int i = reg_index(r);
    if (i < 0) { snprintf(buf, n, "0 /* reg? */"); return; }
    int w = reg_width_bits(r);
    if (w == 8)  snprintf(buf, n, is_high8(r) ? "HI8(c->%s)" : "LO8(c->%s)", R32[i]);
    else if (w == 16) snprintf(buf, n, "LO16(c->%s)", R32[i]);
    else snprintf(buf, n, "c->%s", R32[i]);
}

static void reg_write(ZydisRegister r, const char* val, char* buf, size_t n) {
    int i = reg_index(r);
    if (i < 0) { snprintf(buf, n, "/* write reg? */"); return; }
    int w = reg_width_bits(r);
    if (w == 8)  snprintf(buf, n, is_high8(r) ? "SET_HI8(c->%s, %s);" : "SET_LO8(c->%s, %s);", R32[i], val);
    else if (w == 16) snprintf(buf, n, "SET_LO16(c->%s, %s);", R32[i], val);
    else snprintf(buf, n, "c->%s = (uint32_t)(%s);", R32[i], val);
}

static const char* R32name(ZydisRegister r) {
    int i = reg_index(r);
    return i >= 0 ? R32[i] : "0";
}

static void addr_expr(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* op,
                      char* buf, size_t n) {
    (void)ins;
    char parts[256]; parts[0] = 0;
    size_t len = 0;
    int any = 0;
    if (op->mem.base != ZYDIS_REGISTER_NONE && op->mem.base != ZYDIS_REGISTER_EIP &&
        op->mem.base != ZYDIS_REGISTER_RIP) {
        len += snprintf(parts + len, sizeof parts - len, "c->%s", R32name(op->mem.base));
        any = 1;
    }
    if (op->mem.index != ZYDIS_REGISTER_NONE) {
        int s = op->mem.scale ? op->mem.scale : 1;
        if (any) len += snprintf(parts + len, sizeof parts - len, " + ");
        if (s == 1) len += snprintf(parts + len, sizeof parts - len, "c->%s", R32name(op->mem.index));
        else len += snprintf(parts + len, sizeof parts - len, "c->%s*%d", R32name(op->mem.index), s);
        any = 1;
    }
    uint32_t disp = (uint32_t)op->mem.disp.value;
    if (disp != 0 || !any) {
        if (any) len += snprintf(parts + len, sizeof parts - len, " + ");
        len += snprintf(parts + len, sizeof parts - len, "0x%Xu", disp);
    }
    snprintf(buf, n, "(uint32_t)(%s)", parts);
}

int op_width(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i) {
    (void)ins;
    const ZydisDecodedOperand* op = &ops[i];
    if (op->type == ZYDIS_OPERAND_TYPE_REGISTER) return reg_width_bits(op->reg.value);
    if (op->size == 8 || op->size == 16 || op->size == 32) return op->size;
    return 32;
}

static void mem_access(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* op,
                       char* buf, size_t n) {
    char a[288]; addr_expr(ins, op, a, sizeof a);
    if (op->mem.segment == ZYDIS_REGISTER_FS || op->mem.segment == ZYDIS_REGISTER_GS) {
        snprintf(buf, n, "MEM32(rex_seg(%s, %s))",
                 op->mem.segment == ZYDIS_REGISTER_FS ? "FS" : "GS", a);
        return;
    }
    int w = (op->size == 8 || op->size == 16) ? op->size : 32;
    snprintf(buf, n, "MEM%d(%s)", w, a);
}

void op_lea_addr(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops,
                 char* buf, size_t n) {
    addr_expr(ins, &ops[1], buf, n);
}

void op_lea_addr_at(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i,
                    char* buf, size_t n) {
    addr_expr(ins, &ops[i], buf, n);
}

void op_read(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i,
             uint32_t addr, char* buf, size_t n) {
    const ZydisDecodedOperand* op = &ops[i];
    switch (op->type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            reg_read(op->reg.value, buf, n);
            return;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if (op->imm.is_relative) {
                ZyanU64 t = 0;
                ZydisCalcAbsoluteAddress(ins, op, addr, &t);
                snprintf(buf, n, "0x%08Xu", (uint32_t)t);
            } else {
                snprintf(buf, n, "0x%llXu", (unsigned long long)op->imm.value.u);
            }
            return;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            mem_access(ins, op, buf, n);
            return;
        default:
            snprintf(buf, n, "0 /* op%d? */", i);
            return;
    }
}

void op_write(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i,
              uint32_t addr, const char* value_expr, char* buf, size_t n) {
    (void)addr;
    const ZydisDecodedOperand* op = &ops[i];
    if (op->type == ZYDIS_OPERAND_TYPE_REGISTER) {
        reg_write(op->reg.value, value_expr, buf, n);
        return;
    }
    if (op->type == ZYDIS_OPERAND_TYPE_MEMORY) {
        char m[320]; mem_access(ins, op, m, sizeof m);
        int w = op_width(ins, ops, i);
        snprintf(buf, n, "%s = (uint%d_t)(%s);", m, w, value_expr);
        return;
    }
    snprintf(buf, n, "/* cannot write op%d */", i);
}
