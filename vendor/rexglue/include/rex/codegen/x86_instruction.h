/* x86 instruction — the arch type the reused ReXGlue codegen stores and
 * queries in place of rex::codegen::ppc::Instruction.
 *
 * Backed by Zydis. Only the semantic surface the ISA-neutral code touches
 * (address, length, flow classification, branch target) is exposed here; the
 * emitter reads the raw Zydis fields directly.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <Zydis/Zydis.h>

namespace rex::codegen::x86 {

enum class Flow {
    Next,
    Call,             // direct call rel32
    IndirectCall,
    UncondBranch,     // jmp rel
    CondBranch,       // jcc / jecxz / loop
    IndirectBranch,   // jmp reg / jmp [mem]
    Return,
    Int3,
    Invalid,
};

struct Instruction {
    uint32_t address = 0;
    uint32_t length  = 0;
    Flow     flow    = Flow::Invalid;
    uint32_t target  = 0;                 // direct branch/call target, else 0
    std::string text;                     // disasm, for // comments

    ZydisDecodedInstruction raw{};
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};

    uint32_t end() const { return address + length; }

    bool is_return()      const { return flow == Flow::Return; }
    bool is_int3()        const { return flow == Flow::Int3; }
    bool is_call()        const { return flow == Flow::Call || flow == Flow::IndirectCall; }
    bool is_branch()      const { return flow == Flow::UncondBranch || flow == Flow::CondBranch ||
                                         flow == Flow::IndirectBranch; }
    bool is_conditional() const { return flow == Flow::CondBranch; }
    bool has_direct_target() const {
        return flow == Flow::Call || flow == Flow::UncondBranch || flow == Flow::CondBranch;
    }
};

inline std::optional<uint32_t> getBranchTarget(const Instruction& i) {
    if (i.has_direct_target() && i.target) return i.target;
    return std::nullopt;
}
inline bool isReturn(const Instruction& i)      { return i.is_return(); }
inline bool isBranch(const Instruction& i)      { return i.is_branch(); }
inline bool isCall(const Instruction& i)        { return i.is_call(); }
inline bool isConditional(const Instruction& i) { return i.is_conditional(); }

}  // namespace rex::codegen::x86
