/* x86 decode over a BinaryView via Zydis, producing a reduced DecodedInsn.
 * Ported from the C# branch (DecodedInstruction.cs + Binary/DecodedBinary.cs). */
#ifndef OGX_DECODED_H
#define OGX_DECODED_H

#include <stdint.h>
#include <Zydis/Zydis.h>
#include "util.h"
#include "binary_view.h"

typedef enum {
    FLOW_NEXT,
    FLOW_CALL,               /* direct  call rel32 -> target set */
    FLOW_INDIRECT_CALL,      /* call reg / call [mem] */
    FLOW_UNCONDITIONAL_BR,   /* jmp rel -> target set */
    FLOW_CONDITIONAL_BR,     /* jcc/jecxz/loop -> target set, also falls through */
    FLOW_INDIRECT_BR,        /* jmp reg / jmp [mem] */
    FLOW_RETURN,
    FLOW_INT3,
    FLOW_INVALID,
} InsnFlow;

typedef struct {
    uint32_t address;
    uint32_t length;
    InsnFlow flow;
    uint32_t target;         /* direct branch/call target, else 0 */
    char     text[96];       /* disasm, for // comments */
} DecodedInsn;

static inline uint32_t di_end(const DecodedInsn* d) { return d->address + d->length; }
static inline int di_is_return(const DecodedInsn* d) { return d->flow == FLOW_RETURN; }
static inline int di_is_int3(const DecodedInsn* d)   { return d->flow == FLOW_INT3; }
static inline int di_is_call(const DecodedInsn* d)   { return d->flow == FLOW_CALL || d->flow == FLOW_INDIRECT_CALL; }
static inline int di_is_uncond_jmp(const DecodedInsn* d) { return d->flow == FLOW_UNCONDITIONAL_BR || d->flow == FLOW_INDIRECT_BR; }
static inline int di_is_cond_jmp(const DecodedInsn* d)   { return d->flow == FLOW_CONDITIONAL_BR; }
static inline int di_has_direct_target(const DecodedInsn* d) {
    return d->flow == FLOW_CALL || d->flow == FLOW_UNCONDITIONAL_BR || d->flow == FLOW_CONDITIONAL_BR;
}

typedef struct {
    BinaryView*   bv;
    ZydisDecoder  decoder;
    ZydisFormatter formatter;
    u32map        cache;     /* addr -> DecodedInsn* (NULL sentinel via has+NULL) */
} DecodedBinary;

void db_init(DecodedBinary* db, BinaryView* bv);
void db_free(DecodedBinary* db);

/* Decode at addr. Returns 1 and fills out on success; 0 if unmapped/undecodable. */
int  db_decode_at(DecodedBinary* db, uint32_t addr, DecodedInsn* out);

/* Raw Zydis decode for operand-level analysis (jump tables). ops must hold
 * ZYDIS_MAX_OPERAND_COUNT. Returns 1 on a valid decode. */
int  db_decode_raw(DecodedBinary* db, uint32_t addr,
                   ZydisDecodedInstruction* ins, ZydisDecodedOperand* ops);

#endif
