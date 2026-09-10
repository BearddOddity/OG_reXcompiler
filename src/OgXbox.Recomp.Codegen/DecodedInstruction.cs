// A single decoded x86 instruction, reduced to what the graph and phases need.
//
// ReXGlue's FunctionGraph is coupled to `ppc::Instruction*`. The x86 port keeps
// the coupling shallow: a decoder (iced-x86, wired in a later phase) produces
// these records; the graph only ever reads flow classification and targets.

namespace OgXbox.Recomp.Codegen;

/// <summary>Control-flow class of an instruction (mirrors iced-x86 FlowControl).</summary>
public enum InsnFlow
{
    /// Falls through to the next instruction.
    Next,

    /// Direct <c>call rel32</c> — <see cref="DecodedInstruction.Target"/> is the callee.
    Call,

    /// Indirect call (<c>call reg</c> / <c>call [mem]</c>) — target unknown here.
    IndirectCall,

    /// Unconditional <c>jmp rel</c> — <see cref="DecodedInstruction.Target"/> is set.
    UnconditionalBranch,

    /// Conditional jump (<c>jcc</c>, <c>jecxz</c>, <c>loop</c>) — target set, also falls through.
    ConditionalBranch,

    /// Indirect jump (<c>jmp reg</c> / <c>jmp [mem]</c>) — switch dispatch or tail call.
    IndirectBranch,

    /// <c>ret</c> / <c>retn</c> / <c>retf</c> / <c>iret</c>.
    Return,

    /// <c>int3</c> (0xCC) — inter-function padding / breakpoint.
    Int3,

    /// Bytes that did not decode.
    Invalid,
}

/// <param name="Address">Virtual address of the instruction.</param>
/// <param name="Length">Encoded length in bytes.</param>
/// <param name="Flow">Control-flow class.</param>
/// <param name="Target">
/// Branch/call target for the direct-flow classes; 0 otherwise.
/// </param>
/// <param name="Text">Disassembly text, for emitted <c>// ...</c> comments.</param>
public sealed record DecodedInstruction(
    uint Address,
    uint Length,
    InsnFlow Flow,
    uint Target,
    string Text)
{
    public uint EndAddress => Address + Length;

    public bool IsReturn => Flow == InsnFlow.Return;
    public bool IsInt3 => Flow == InsnFlow.Int3;
    public bool IsCall => Flow is InsnFlow.Call or InsnFlow.IndirectCall;
    public bool IsUnconditionalJump => Flow is InsnFlow.UnconditionalBranch or InsnFlow.IndirectBranch;
    public bool IsConditionalJump => Flow == InsnFlow.ConditionalBranch;

    /// A direct branch/call whose target address is known.
    public bool HasDirectTarget =>
        Flow is InsnFlow.Call or InsnFlow.UnconditionalBranch or InsnFlow.ConditionalBranch;
}
