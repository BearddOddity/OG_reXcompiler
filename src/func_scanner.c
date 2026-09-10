#include "func_scanner.h"
#include <string.h>
#include <stdlib.h>

#define MAX_BLOCKS        4096
#define MAX_TABLE_ENTRIES 4096
#define MAX_BACKWARD_SCAN 24

void bdr_free(BlockDiscoveryResult* r) {
    vec_free(&r->blocks);
    vec_free(&r->instructions);
    vec_free(&r->labels);
    vec_free(&r->external_calls);
    vec_free(&r->tail_calls);
    vec_free(&r->unresolved_branches);
    for (size_t i = 0; i < r->jump_tables.len; i++) { /* owned by graph after transfer */ }
    vec_free(&r->jump_tables);
}

void fs_init(FunctionScanner* fs, DecodedBinary* db, const CodeRegion* regions, size_t n) {
    memset(fs, 0, sizeof *fs);
    fs->db = db;
    fs->bv = db->bv;
    for (size_t i = 0; i < n; i++) vec_push(&fs->code_regions, regions[i]);
}
void fs_free(FunctionScanner* fs) { vec_free(&fs->code_regions); }

CodeRegion* fs_region_containing(FunctionScanner* fs, uint32_t addr) {
    for (size_t i = 0; i < fs->code_regions.len; i++)
        if (cr_contains(&fs->code_regions.data[i], addr)) return &fs->code_regions.data[i];
    return NULL;
}

/*=========================================================================
 * Block discovery
 *=======================================================================*/

typedef struct { uint32_t* data; size_t len, cap; } queue32;
static void q_push(queue32* q, uint32_t v) {
    if (q->len == q->cap) { q->cap = q->cap ? q->cap * 2 : 16; q->data = realloc(q->data, q->cap * 4); }
    q->data[q->len++] = v;
}

typedef struct {
    uint32_t entry_point, func_end;
    u32map *known, *visited, *block_starts;
    queue32* work;
    BlockDiscoveryResult* out;
} DiscCtx;

static int disc_is_internal(DiscCtx* c, uint32_t t) {
    if (t < c->entry_point || t >= c->func_end) return 0;
    if (t != c->entry_point && u32map_has(c->known, t)) return 0;
    return 1;
}
static void disc_enqueue(DiscCtx* c, uint32_t t) {
    vec_push(&c->out->labels, t);
    if (!u32map_has(c->visited, t) && !u32map_has(c->block_starts, t)) {
        u32set_add(c->block_starts, t);
        q_push(c->work, t);
    }
}

void fs_discover_blocks(FunctionScanner* fs, uint32_t entry_point,
                        u32map* known_functions, u32map* manual_tables,
                        BlockDiscoveryResult* out) {
    memset(out, 0, sizeof *out);

    CodeRegion tmp_region;
    CodeRegion* region = fs_region_containing(fs, entry_point);
    if (!region) {
        tmp_region.start = entry_point;
        tmp_region.end = entry_point + 0x100000;
        tmp_region.section[0] = 0;
        region = &tmp_region;
    }

    u32map visited, block_starts;
    u32map_init(&visited, 256);
    u32map_init(&block_starts, 256);
    queue32 work = {0};
    u32set_add(&block_starts, entry_point);
    q_push(&work, entry_point);

    DiscCtx c = { entry_point, region->end, known_functions, &visited, &block_starts, &work, out };

    size_t qi = 0;
    while (qi < work.len && out->blocks.len < MAX_BLOCKS) {
        uint32_t block_start = work.data[qi++];
        if (u32map_has(&visited, block_start)) continue;
        if (!(block_start >= entry_point && block_start < c.func_end)) continue;

        uint32_t addr = block_start, block_size = 0;
        while (addr >= entry_point && addr < c.func_end) {
            DecodedInsn insn;
            if (!db_decode_at(fs->db, addr, &insn) ||
                insn.flow == FLOW_INVALID || insn.flow == FLOW_INT3) {
                block_size = addr - block_start;
                break;
            }
            u32set_add(&visited, addr);
            vec_push(&out->instructions, insn);
            uint32_t next = di_end(&insn);

            if (insn.flow == FLOW_RETURN) { block_size = next - block_start; break; }

            if (di_is_call(&insn)) {
                if (insn.flow == FLOW_CALL && insn.target != 0) {
                    UnresolvedBranch ub = { addr, insn.target, 1, 0 };
                    vec_push(&out->unresolved_branches, ub);
                    if (insn.target != entry_point) vec_push(&out->external_calls, insn.target);
                }
                addr = next;
                continue;
            }

            if (insn.flow == FLOW_CONDITIONAL_BR) {
                if (insn.target != 0 && disc_is_internal(&c, insn.target)) disc_enqueue(&c, insn.target);
                else if (insn.target != 0) {
                    UnresolvedBranch ub = { addr, insn.target, 0, 1 };
                    vec_push(&out->unresolved_branches, ub);
                }
                if (disc_is_internal(&c, next)) disc_enqueue(&c, next);
                addr = next;
                continue;
            }

            if (insn.flow == FLOW_UNCONDITIONAL_BR) {
                if (insn.target != 0) {
                    if (disc_is_internal(&c, insn.target)) disc_enqueue(&c, insn.target);
                    else {
                        vec_push(&out->tail_calls, insn.target);
                        UnresolvedBranch ub = { addr, insn.target, 0, 0 };
                        vec_push(&out->unresolved_branches, ub);
                    }
                }
                block_size = next - block_start;
                break;
            }

            if (insn.flow == FLOW_INDIRECT_BR) {
                JumpTable* jt = NULL;
                void* m;
                if (manual_tables && u32map_get(manual_tables, addr, &m)) jt = m;
                if (!jt) jt = fs_detect_jump_table(fs, addr, region, entry_point, c.func_end);
                if (jt) {
                    vec_push(&out->jump_tables, jt);
                    for (size_t k = 0; k < jt->targets.len; k++) {
                        uint32_t t = jt->targets.data[k];
                        if (t == 0) continue;
                        if (t != entry_point && u32map_has(known_functions, t)) continue;
                        if (t >= c.func_end && t < region->end) c.func_end = t + 1;
                        disc_enqueue(&c, t);
                    }
                }
                block_size = next - block_start;
                break;
            }

            addr = next;
        }
        if (block_size == 0) block_size = addr - block_start;
        if (block_size > 0) {
            Block b = { block_start, block_size };
            vec_push(&out->blocks, b);
        }
    }

    /* sort blocks (insertion sort, small); dedup instructions by address */
    for (size_t i = 1; i < out->blocks.len; i++) {
        Block key = out->blocks.data[i];
        size_t j = i;
        while (j > 0 && out->blocks.data[j - 1].base > key.base) {
            out->blocks.data[j] = out->blocks.data[j - 1];
            j--;
        }
        out->blocks.data[j] = key;
    }
    {
        u32map seen; u32map_init(&seen, out->instructions.len + 16);
        size_t w = 0;
        for (size_t i = 0; i < out->instructions.len; i++)
            if (!u32map_has(&seen, out->instructions.data[i].address)) {
                u32set_add(&seen, out->instructions.data[i].address);
                out->instructions.data[w++] = out->instructions.data[i];
            }
        out->instructions.len = w;
        u32map_free(&seen);
    }

    free(work.data);
    u32map_free(&visited);
    u32map_free(&block_starts);
}

/*=========================================================================
 * x86 jump-table detection
 *=======================================================================*/

static ZydisRegister reg32(ZydisRegister r) {
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LEGACY_32, r);
}

/* Instructions ending just before `from_addr`, nearest-first, up to MAX_BACKWARD_SCAN. */
typedef struct {
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    uint32_t addr;
} RawInsn;

static size_t backward_insns(FunctionScanner* fs, uint32_t from_addr, uint32_t func_start,
                             RawInsn* out, size_t out_cap) {
    uint32_t window = from_addr > func_start + 64 ? from_addr - 64 : func_start;
    RawInsn chain[64];
    size_t n = 0;
    uint32_t p = window;
    while (p < from_addr) {
        if (n >= 64) { n = 0; }  /* keep only the tail that reaches from_addr */
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!db_decode_raw(fs->db, p, &ins, ops) || ins.length == 0) { p++; n = 0; continue; }
        chain[n].ins = ins;
        memcpy(chain[n].ops, ops, sizeof ops);
        chain[n].addr = p;
        n++;
        p += ins.length;
    }
    size_t take = n < out_cap ? n : out_cap;
    for (size_t i = 0; i < take; i++) out[i] = chain[n - 1 - i];  /* newest first */
    return take;
}

static int imm_is_dword(ZydisOperandType t, const ZydisDecodedOperand* op) {
    return op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
    (void)t;
}

static uint32_t trace_reg_to_address(FunctionScanner* fs, uint32_t from_addr,
                                     uint32_t func_start, ZydisRegister reg) {
    RawInsn bw[MAX_BACKWARD_SCAN];
    size_t n = backward_insns(fs, from_addr, func_start, bw, MAX_BACKWARD_SCAN);
    for (size_t i = 0; i < n; i++) {
        ZydisDecodedInstruction* ins = &bw[i].ins;
        ZydisDecodedOperand* ops = bw[i].ops;
        if (ins->operand_count_visible < 1) continue;
        if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || ops[0].reg.value != reg) continue;
        if (ins->mnemonic == ZYDIS_MNEMONIC_MOV && ins->operand_count_visible >= 2 &&
            ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            return (uint32_t)ops[1].imm.value.u;
        if (ins->mnemonic == ZYDIS_MNEMONIC_LEA && ins->operand_count_visible >= 2 &&
            ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            ops[1].mem.base == ZYDIS_REGISTER_NONE && ops[1].mem.index == ZYDIS_REGISTER_NONE)
            return (uint32_t)ops[1].mem.disp.value;
        return 0;
    }
    return 0;
}

static int trace_reg_jump_table(FunctionScanner* fs, uint32_t jmp_addr, uint32_t func_start,
                                ZydisRegister jmp_reg, uint32_t* table_addr, ZydisRegister* index_reg) {
    *table_addr = 0; *index_reg = ZYDIS_REGISTER_NONE;
    uint32_t base_offset = 0;
    RawInsn bw[MAX_BACKWARD_SCAN];
    size_t n = backward_insns(fs, jmp_addr, func_start, bw, MAX_BACKWARD_SCAN);
    for (size_t i = 0; i < n; i++) {
        ZydisDecodedInstruction* ins = &bw[i].ins;
        ZydisDecodedOperand* ops = bw[i].ops;
        if (ins->operand_count_visible < 1) continue;
        if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || ops[0].reg.value != jmp_reg) continue;
        if (ins->mnemonic == ZYDIS_MNEMONIC_ADD && ins->operand_count_visible >= 2 &&
            ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            base_offset = (uint32_t)ops[1].imm.value.u;
            continue;
        }
        if (ins->mnemonic == ZYDIS_MNEMONIC_MOV && ins->operand_count_visible >= 2 &&
            ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            *index_reg = ops[1].mem.index;
            *table_addr = (uint32_t)ops[1].mem.disp.value + base_offset;
            return *table_addr != 0;
        }
        return 0;
    }
    return 0;
}

static int scan_for_bound(FunctionScanner* fs, uint32_t jmp_addr, uint32_t func_start,
                          ZydisRegister index_reg) {
    RawInsn bw[MAX_BACKWARD_SCAN];
    size_t n = backward_insns(fs, jmp_addr, func_start, bw, MAX_BACKWARD_SCAN);
    for (size_t i = 0; i < n; i++) {
        ZydisDecodedInstruction* ins = &bw[i].ins;
        ZydisDecodedOperand* ops = bw[i].ops;
        if (ins->mnemonic != ZYDIS_MNEMONIC_CMP) continue;
        if (ins->operand_count_visible < 2 || ops[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
        if (index_reg != ZYDIS_REGISTER_NONE && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ops[0].reg.value != index_reg && reg32(ops[0].reg.value) != reg32(index_reg))
            continue;
        long v = (long)ops[1].imm.value.s;
        if (v > 0 && v < MAX_TABLE_ENTRIES) return (int)v + 1;
    }
    return 0;
}

JumpTable* fs_detect_jump_table(FunctionScanner* fs, uint32_t jmp_addr,
                                const CodeRegion* region, uint32_t func_start, uint32_t func_end) {
    (void)func_end;
    ZydisDecodedInstruction jmp;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!db_decode_raw(fs->db, jmp_addr, &jmp, ops)) return NULL;
    if (jmp.meta.category != ZYDIS_CATEGORY_UNCOND_BR) return NULL;
    if (jmp.operand_count_visible < 1) return NULL;

    uint32_t table_addr = 0;
    ZydisRegister index_reg = ZYDIS_REGISTER_NONE;

    if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        index_reg = ops[0].mem.index;
        uint32_t disp = (uint32_t)ops[0].mem.disp.value;
        if (ops[0].mem.base == ZYDIS_REGISTER_NONE) {
            table_addr = disp;
        } else {
            table_addr = trace_reg_to_address(fs, jmp_addr, func_start, ops[0].mem.base);
            if (table_addr != 0 && disp != 0) table_addr += disp;
        }
    } else if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        if (!trace_reg_jump_table(fs, jmp_addr, func_start, ops[0].reg.value, &table_addr, &index_reg))
            return NULL;
    } else {
        return NULL;
    }
    if (table_addr == 0) return NULL;
    (void)imm_is_dword;

    int bound = scan_for_bound(fs, jmp_addr, func_start, index_reg);
    int entry_count = bound > 0 ? bound : MAX_TABLE_ENTRIES;

    U32Vec targets = {0};
    for (int i = 0; i < entry_count && i < MAX_TABLE_ENTRIES; i++) {
        uint32_t entry;
        if (!bv_read_u32(fs->bv, (uint32_t)(table_addr + (long)i * 4), &entry)) break;
        if (entry < region->start || entry >= region->end) { if (bound <= 0) break; else continue; }
        if (!bv_is_executable(fs->bv, entry)) { if (bound <= 0) break; else continue; }
        /* dedup */
        int dup = 0;
        for (size_t k = 0; k < targets.len; k++) if (targets.data[k] == entry) { dup = 1; break; }
        if (!dup) vec_push(&targets, entry);
    }

    if (targets.len < 2) { vec_free(&targets); return NULL; }

    JumpTable* jt = calloc(1, sizeof *jt);
    jt->jump_address = jmp_addr;
    jt->table_address = table_addr;
    jt->index_register = (uint8_t)index_reg;
    jt->targets = targets;
    return jt;
}
