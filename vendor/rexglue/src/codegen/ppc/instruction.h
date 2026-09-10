#pragma once
#include <rex/codegen/x86_instruction.h>
namespace rex::codegen::x86 {
  Instruction decode_instruction(uint32_t addr, const uint8_t* code, size_t max_len);
}
