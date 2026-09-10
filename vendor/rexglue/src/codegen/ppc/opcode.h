#pragma once
// x86 opcode shim — the reused codegen only names ppc::Opcode in the
// PPC-specific paths we rewrite; provide an empty enum so headers parse.
namespace rex::codegen::x86 { enum class Opcode { kUnknown }; }
