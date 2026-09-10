/* x86 operand -> C expression / assignment. Ported from Emit/COperand.cs.
 * All writers take a caller buffer (buf,n) and NUL-terminate. */
#ifndef OGX_EMIT_OPERAND_H
#define OGX_EMIT_OPERAND_H

#include <stddef.h>
#include <stdint.h>
#include <Zydis/Zydis.h>

int  op_width(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i);
void op_read (const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i,
              uint32_t addr, char* buf, size_t n);
void op_write(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i,
              uint32_t addr, const char* value_expr, char* buf, size_t n);
void op_lea_addr(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops,
                 char* buf, size_t n);
/* effective address of memory operand `i` (for lea / x87 mem operands). */
void op_lea_addr_at(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops, int i,
                    char* buf, size_t n);

/* 32-bit field name for a register operand, e.g. "c->eax"; "0" if unknown. */
const char* reg32_field(ZydisRegister r);
int  reg_index(ZydisRegister r);   /* 0..7 for EAX..EDI family, else -1 */
int  reg_width_bits(ZydisRegister r);

#endif
