#include "decoded.h"
#include <string.h>

void db_init(DecodedBinary* db, BinaryView* bv) {
    db->bv = bv;
    ZydisDecoderInit(&db->decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    ZydisFormatterInit(&db->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    u32map_init(&db->cache, 4096);
}

void db_free(DecodedBinary* db) {
    for (size_t i = 0; i < db->cache.cap; i++)
        if (db->cache.used[i]) free(db->cache.vals[i]);
    u32map_free(&db->cache);
}

static InsnFlow classify(const ZydisDecodedInstruction* ins, const ZydisDecodedOperand* ops,
                         uint32_t addr, uint32_t* target_out) {
    *target_out = 0;

    switch (ins->mnemonic) {
        case ZYDIS_MNEMONIC_RET:  case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD: case ZYDIS_MNEMONIC_IRETQ:
            return FLOW_RETURN;
        case ZYDIS_MNEMONIC_INT3:
            return FLOW_INT3;
        default: break;
    }

    int op0_rel = ins->operand_count_visible > 0 &&
                  ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[0].imm.is_relative;

    ZyanU64 abs = 0;
    if (op0_rel)
        ZydisCalcAbsoluteAddress(ins, &ops[0], addr, &abs);

    switch (ins->meta.category) {
        case ZYDIS_CATEGORY_CALL:
            if (op0_rel) { *target_out = (uint32_t)abs; return FLOW_CALL; }
            return FLOW_INDIRECT_CALL;
        case ZYDIS_CATEGORY_UNCOND_BR:
            if (op0_rel) { *target_out = (uint32_t)abs; return FLOW_UNCONDITIONAL_BR; }
            return FLOW_INDIRECT_BR;
        case ZYDIS_CATEGORY_COND_BR:
            if (op0_rel) *target_out = (uint32_t)abs;
            return FLOW_CONDITIONAL_BR;
        default:
            return FLOW_NEXT;
    }
}

int db_decode_at(DecodedBinary* db, uint32_t addr, DecodedInsn* out) {
    void* cached;
    if (u32map_get(&db->cache, addr, &cached)) {
        if (!cached) return 0;
        *out = *(DecodedInsn*)cached;
        return 1;
    }

    size_t avail;
    const uint8_t* p = bv_translate(db->bv, addr, &avail);
    DecodedInsn* slot = NULL;

    if (p && avail > 0) {
        size_t take = avail < ZYDIS_MAX_INSTRUCTION_LENGTH ? avail : ZYDIS_MAX_INSTRUCTION_LENGTH;
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&db->decoder, p, take, &ins, ops))) {
            slot = calloc(1, sizeof *slot);
            slot->address = addr;
            slot->length = ins.length;
            slot->flow = classify(&ins, ops, addr, &slot->target);
            ZydisFormatterFormatInstruction(&db->formatter, &ins, ops, ins.operand_count_visible,
                                            slot->text, sizeof slot->text, addr, ZYAN_NULL);
        }
    }

    u32map_put(&db->cache, addr, slot);
    if (!slot) return 0;
    *out = *slot;
    return 1;
}

int db_decode_raw(DecodedBinary* db, uint32_t addr,
                  ZydisDecodedInstruction* ins, ZydisDecodedOperand* ops) {
    size_t avail;
    const uint8_t* p = bv_translate(db->bv, addr, &avail);
    if (!p || avail == 0) return 0;
    size_t take = avail < ZYDIS_MAX_INSTRUCTION_LENGTH ? avail : ZYDIS_MAX_INSTRUCTION_LENGTH;
    return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&db->decoder, p, take, ins, ops));
}
