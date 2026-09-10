// DecodedBinary — on-demand x86 instruction decoding over a BinaryView, cached
// by address. iced-x86 does the heavy lifting; the rest of the codegen only
// touches DecodedInstruction records.
//
// Ported in spirit from rex::codegen::DecodedBinary (which decodes fixed-width
// PPC linearly). x86 is variable-length and unaligned, so this decodes from
// arbitrary addresses on request and caches the result.

using System;
using System.Collections.Generic;
using Iced.Intel;

namespace OgXbox.Recomp.Codegen.Binary;

public sealed class DecodedBinary
{
    private readonly BinaryView _view;
    private readonly Dictionary<uint, DecodedInstruction?> _cache = new();
    private readonly Formatter _formatter;

    public DecodedBinary(BinaryView view)
    {
        _view = view;
        _formatter = new NasmFormatter(new FormatterOptions
        {
            HexPrefix = "0x",
            HexSuffix = "",
            UppercaseHex = false,
            SpaceAfterOperandSeparator = true,
        });
    }

    public BinaryView View => _view;

    /// <summary>Decode the single instruction at <paramref name="addr"/> (null if unmapped/undecodable).</summary>
    public DecodedInstruction? DecodeAt(uint addr)
    {
        if (_cache.TryGetValue(addr, out var cached))
            return cached;

        var span = _view.Translate(addr);
        DecodedInstruction? result;
        if (span.Length == 0)
        {
            result = null;
        }
        else
        {
            // Max x86 instruction length is 15 bytes.
            int take = Math.Min(span.Length, 15);
            var bytes = span.Slice(0, take).ToArray();
            var decoder = Decoder.Create(32, new ByteArrayCodeReader(bytes), addr,
                                         DecoderOptions.None);
            decoder.Decode(out var insn);
            result = Convert(insn, bytes);
        }

        _cache[addr] = result;
        return result;
    }

    /// <summary>Linear sweep of a section from its base (desyncs on data; use for a first cut only).</summary>
    public IEnumerable<DecodedInstruction> LinearSweep(SectionView sec)
    {
        var reader = new ByteArrayCodeReader(sec.Data);
        var decoder = Decoder.Create(32, reader, sec.BaseAddress, DecoderOptions.None);
        var end = sec.End;
        while (decoder.IP < end)
        {
            decoder.Decode(out var insn);
            var di = Convert(insn, null);
            _cache[di.Address] = di;
            yield return di;
        }
    }

    private DecodedInstruction Convert(in Instruction insn, byte[]? _)
    {
        var addr = (uint)insn.IP;
        uint len = (uint)insn.Length;

        InsnFlow flow;
        uint target = 0;

        if (insn.IsInvalid || len == 0)
        {
            flow = InsnFlow.Invalid;
            if (len == 0) len = 1; // always advance
        }
        else if (insn.Code == Code.Int3)
        {
            flow = InsnFlow.Int3;
        }
        else
        {
            switch (insn.FlowControl)
            {
                case FlowControl.Next:
                    flow = InsnFlow.Next;
                    break;
                case FlowControl.Call:
                    flow = InsnFlow.Call;
                    target = TryNearTarget(insn);
                    break;
                case FlowControl.IndirectCall:
                    flow = InsnFlow.IndirectCall;
                    break;
                case FlowControl.UnconditionalBranch:
                    flow = InsnFlow.UnconditionalBranch;
                    target = TryNearTarget(insn);
                    break;
                case FlowControl.ConditionalBranch:
                    flow = InsnFlow.ConditionalBranch;
                    target = TryNearTarget(insn);
                    break;
                case FlowControl.IndirectBranch:
                    flow = InsnFlow.IndirectBranch;
                    break;
                case FlowControl.Return:
                    flow = InsnFlow.Return;
                    break;
                case FlowControl.Interrupt:
                    flow = insn.Code == Code.Int3 ? InsnFlow.Int3 : InsnFlow.Next;
                    break;
                default:
                    flow = InsnFlow.Next;
                    break;
            }
        }

        var text = flow == InsnFlow.Invalid ? "(bad)" : Format(insn);
        return new DecodedInstruction(addr, len, flow, target, text);
    }

    private static uint TryNearTarget(in Instruction insn) => insn.Op0Kind switch
    {
        OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64 =>
            (uint)insn.NearBranchTarget,
        _ => 0,
    };

    private string Format(in Instruction insn)
    {
        var output = new StringOutput();
        _formatter.Format(insn, output);
        return output.ToStringAndReset();
    }
}
