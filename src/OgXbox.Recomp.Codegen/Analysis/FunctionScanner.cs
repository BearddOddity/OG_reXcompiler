// FunctionScanner — worklist basic-block discovery + x86 jump-table detection.
//
// Ported to C# / x86 from rex::codegen::discoverBlocks / detectJumpTable
// (ReXGlue SDK, BSD-3-Clause), merged with the X-Men Python prototype's
// projectedSize / tail-call heuristics.
//
// ReXGlue walks fixed +4 PPC and dispatches on `bcctr`; this walks
// variable-length x86 via iced-x86 and dispatches on `jmp reg` / `jmp [mem]`.

using System;
using System.Collections.Generic;
using System.Linq;
using Iced.Intel;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Analysis;

public readonly record struct UnresolvedBranch(uint Site, uint Target, bool IsCall, bool IsConditional);

public sealed class BlockDiscoveryResult
{
    public List<Block> Blocks { get; } = new();
    public List<DecodedInstruction> Instructions { get; } = new();
    public SortedSet<uint> Labels { get; } = new();
    public List<uint> ExternalCalls { get; } = new();
    public List<uint> TailCalls { get; } = new();
    public List<UnresolvedBranch> UnresolvedBranches { get; } = new();
    public List<JumpTable> JumpTables { get; } = new();
}

public sealed class FunctionScanner
{
    private const int MaxBlocks = 4096;
    private const int MaxTableEntries = 4096;
    private const int MaxBackwardScan = 24;

    private readonly DecodedBinary _decoded;
    private readonly BinaryView _binary;
    private readonly List<CodeRegion> _codeRegions;

    public FunctionScanner(DecodedBinary decoded, IEnumerable<CodeRegion> codeRegions)
    {
        _decoded = decoded;
        _binary = decoded.View;
        _codeRegions = codeRegions.ToList();
    }

    public CodeRegion? RegionContaining(uint addr)
    {
        foreach (var r in _codeRegions)
            if (r.Contains(addr)) return r;
        return null;
    }

    //=========================================================================
    // Block discovery
    //=========================================================================

    public BlockDiscoveryResult DiscoverBlocks(
        uint entryPoint,
        IReadOnlySet<uint> knownFunctions,
        IReadOnlyDictionary<uint, JumpTable>? manualTables = null)
    {
        var result = new BlockDiscoveryResult();

        var region = RegionContaining(entryPoint)
                     ?? new CodeRegion(entryPoint, entryPoint + 0x100000, "");
        uint funcEnd = region.End;

        var visited = new HashSet<uint>();
        var blockStarts = new HashSet<uint> { entryPoint };
        var worklist = new Queue<uint>();
        worklist.Enqueue(entryPoint);

        bool WithinFunction(uint a) => a >= entryPoint && a < funcEnd;

        bool IsInternalTarget(uint t)
        {
            if (t < entryPoint || t >= funcEnd) return false;
            if (t != entryPoint && knownFunctions.Contains(t)) return false;
            return true;
        }

        void Enqueue(uint t)
        {
            result.Labels.Add(t);
            if (!visited.Contains(t) && blockStarts.Add(t))
                worklist.Enqueue(t);
        }

        while (worklist.Count > 0 && result.Blocks.Count < MaxBlocks)
        {
            uint blockStart = worklist.Dequeue();
            if (visited.Contains(blockStart) || !WithinFunction(blockStart)) continue;

            uint addr = blockStart;
            uint blockSize = 0;

            while (WithinFunction(addr))
            {
                var insn = _decoded.DecodeAt(addr);
                if (insn is null || insn.Flow == InsnFlow.Invalid || insn.IsInt3)
                {
                    blockSize = addr - blockStart;
                    break;
                }

                visited.Add(addr);
                result.Instructions.Add(insn);
                uint next = insn.EndAddress;

                if (insn.Flow == InsnFlow.Return)
                {
                    blockSize = next - blockStart;
                    break;
                }

                if (insn.IsCall)
                {
                    if (insn.Flow == InsnFlow.Call && insn.Target != 0)
                    {
                        result.UnresolvedBranches.Add(new(addr, insn.Target, true, false));
                        // A direct `call` always denotes a callee entry point,
                        // even when the target sits inside this function's code
                        // region (regions are coarse before GapFill splits them).
                        if (insn.Target != entryPoint)
                            result.ExternalCalls.Add(insn.Target);
                    }
                    addr = next;                       // calls don't end the block
                    continue;
                }

                if (insn.Flow == InsnFlow.ConditionalBranch)
                {
                    if (insn.Target != 0 && IsInternalTarget(insn.Target))
                        Enqueue(insn.Target);
                    else if (insn.Target != 0)
                        result.UnresolvedBranches.Add(new(addr, insn.Target, false, true));

                    if (IsInternalTarget(next)) Enqueue(next);
                    addr = next;                       // fall-through continues (ReXGlue behaviour)
                    continue;
                }

                if (insn.Flow == InsnFlow.UnconditionalBranch)
                {
                    if (insn.Target != 0)
                    {
                        if (IsInternalTarget(insn.Target))
                            Enqueue(insn.Target);
                        else
                        {
                            result.TailCalls.Add(insn.Target);
                            result.UnresolvedBranches.Add(new(addr, insn.Target, false, false));
                        }
                    }
                    blockSize = next - blockStart;
                    break;
                }

                if (insn.Flow == InsnFlow.IndirectBranch)
                {
                    JumpTable? jt = null;
                    if (manualTables is not null && manualTables.TryGetValue(addr, out var manual))
                        jt = manual;
                    jt ??= DetectJumpTable(addr, region, entryPoint, funcEnd);

                    if (jt is not null)
                    {
                        result.JumpTables.Add(jt);
                        foreach (uint t in jt.Targets)
                        {
                            if (t == 0) continue;
                            if (t != entryPoint && knownFunctions.Contains(t)) continue;
                            if (t >= funcEnd && t < region.End) funcEnd = t + 1;
                            Enqueue(t);
                        }
                    }
                    blockSize = next - blockStart;
                    break;
                }

                addr = next;
            }

            if (blockSize == 0) blockSize = addr - blockStart;
            if (blockSize > 0) result.Blocks.Add(new Block(blockStart, blockSize));
        }

        result.Blocks.Sort((a, b) => a.Base.CompareTo(b.Base));
        DedupInstructions(result);
        return result;
    }

    private static void DedupInstructions(BlockDiscoveryResult r)
    {
        var seen = new HashSet<uint>();
        r.Instructions.RemoveAll(i => !seen.Add(i.Address));
        r.Instructions.Sort((a, b) => a.Address.CompareTo(b.Address));
    }

    //=========================================================================
    // x86 jump-table detection
    //=========================================================================
    //
    // Handles the two memory-operand forms:
    //   jmp dword [table + idx*4]          — absolute table, disp32 = table
    //   jmp dword [reg + idx*4]  (reg <- mov reg, table / lea reg,[table])
    // Bounds come from a `cmp idx, N` behind the jmp (entryCount = N + 1);
    // absent that, entries are read until one leaves the code region.

    public JumpTable? DetectJumpTable(uint jmpAddr, CodeRegion region, uint funcStart, uint funcEnd)
    {
        if (!_decoded.TryDecodeRaw(jmpAddr, out var jmp)) return null;
        if (jmp.FlowControl != FlowControl.IndirectBranch) return null;

        uint tableAddr = 0;
        int scale = 4;
        Register indexReg = Register.None;

        if (jmp.Op0Kind == OpKind.Memory)
        {
            scale = jmp.MemoryIndexScale == 0 ? 4 : jmp.MemoryIndexScale;
            indexReg = jmp.MemoryIndex;
            uint disp = (uint)jmp.MemoryDisplacement64;

            if (jmp.MemoryBase == Register.None)
            {
                tableAddr = disp;                                   // jmp [table + idx*s]
            }
            else
            {
                tableAddr = TraceRegisterToAddress(jmpAddr, region, funcStart, jmp.MemoryBase);
                if (tableAddr != 0 && disp != 0) tableAddr += disp; // rare base+disp
            }
        }
        else if (jmp.Op0Kind == OpKind.Register)
        {
            // jmp reg — trace reg back to `mov reg, [table + idx*s]` (+ optional add reg, base)
            if (!TraceRegisterJumpTable(jmpAddr, region, funcStart, jmp.Op0Register,
                                        out tableAddr, out scale, out indexReg))
                return null;
        }
        else
        {
            return null;
        }

        if (tableAddr == 0 || !_binary.IsExecutable(RegionAnchor(region))) { /* fallthrough */ }
        if (tableAddr == 0) return null;

        int bound = ScanForBound(jmpAddr, region, funcStart, indexReg);
        int entryCount = bound > 0 ? bound : MaxTableEntries;

        var targets = new List<uint>();
        for (int i = 0; i < entryCount && i < MaxTableEntries; i++)
        {
            uint? entry = _binary.ReadU32((uint)(tableAddr + (long)i * 4));
            if (entry is null) break;
            uint t = entry.Value;
            // A valid case target lands in code, at or after the function start,
            // and (for an in-region table) within the containing region.
            if (t < region.Start || t >= region.End) { if (bound <= 0) break; else continue; }
            if (!_binary.IsExecutable(t)) { if (bound <= 0) break; else continue; }
            targets.Add(t);
        }

        if (targets.Count < 2) return null;

        return new JumpTable
        {
            JumpAddress = jmpAddr,
            TableAddress = tableAddr,
            IndexRegister = (byte)indexReg,
            Targets = targets.Distinct().ToList(),
        };
    }

    private static uint RegionAnchor(CodeRegion r) => r.Start;

    /// <summary>Walk back from <paramref name="fromAddr"/> for <c>mov/lea reg, imm/addr</c>.</summary>
    private uint TraceRegisterToAddress(uint fromAddr, CodeRegion region, uint funcStart, Register reg)
    {
        foreach (var insn in BackwardInsns(fromAddr, region, funcStart))
        {
            if (insn.Op0Kind == OpKind.Register && insn.Op0Register == reg)
            {
                if (insn.Mnemonic == Mnemonic.Mov &&
                    (insn.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64))
                    return (uint)insn.GetImmediate(1);
                if (insn.Mnemonic == Mnemonic.Lea && insn.Op1Kind == OpKind.Memory &&
                    insn.MemoryBase == Register.None && insn.MemoryIndex == Register.None)
                    return (uint)insn.MemoryDisplacement64;
                return 0; // reg was set some other way — give up
            }
        }
        return 0;
    }

    private bool TraceRegisterJumpTable(
        uint jmpAddr, CodeRegion region, uint funcStart, Register jmpReg,
        out uint tableAddr, out int scale, out Register indexReg)
    {
        tableAddr = 0; scale = 4; indexReg = Register.None;
        uint baseOffset = 0;

        foreach (var insn in BackwardInsns(jmpAddr, region, funcStart))
        {
            if (insn.Op0Kind != OpKind.Register || insn.Op0Register != jmpReg) continue;

            if (insn.Mnemonic == Mnemonic.Add && insn.Op1Kind is OpKind.Immediate32 or OpKind.Immediate32to64)
            {
                baseOffset = (uint)insn.GetImmediate(1);
                continue;
            }
            if (insn.Mnemonic == Mnemonic.Mov && insn.Op1Kind == OpKind.Memory)
            {
                scale = insn.MemoryIndexScale == 0 ? 4 : insn.MemoryIndexScale;
                indexReg = insn.MemoryIndex;
                tableAddr = (uint)insn.MemoryDisplacement64 + baseOffset;
                return tableAddr != 0;
            }
            return false;
        }
        return false;
    }

    /// <summary>Find a <c>cmp idx, N</c> behind the jump; returns N+1 (entry count) or 0.</summary>
    private int ScanForBound(uint jmpAddr, CodeRegion region, uint funcStart, Register indexReg)
    {
        foreach (var insn in BackwardInsns(jmpAddr, region, funcStart))
        {
            if (insn.Mnemonic != Mnemonic.Cmp) continue;
            if (insn.Op1Kind is not (OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32
                or OpKind.Immediate8to32 or OpKind.Immediate32to64))
                continue;
            // accept a cmp on the index register, or (index unknown) the first cmp we see
            if (indexReg != Register.None && insn.Op0Kind == OpKind.Register &&
                insn.Op0Register != indexReg &&
                Register32(insn.Op0Register) != Register32(indexReg))
                continue;
            long n = unchecked((long)insn.GetImmediate(1));
            if (n is > 0 and < MaxTableEntries) return (int)n + 1;
        }
        return 0;
    }

    private static Register Register32(Register r) => r switch
    {
        >= Register.AL and <= Register.R15L => (Register)(Register.EAX + (r - Register.AL)),
        >= Register.AX and <= Register.R15W => (Register)(Register.EAX + (r - Register.AX)),
        _ => r,
    };

    /// <summary>Instructions immediately before <paramref name="fromAddr"/>, nearest first.</summary>
    private IEnumerable<Instruction> BackwardInsns(uint fromAddr, CodeRegion region, uint funcStart)
    {
        // x86 is unaligned — re-decode forward from a small window start and keep
        // the ones that end exactly where the next begins, walking up to fromAddr.
        uint windowStart = fromAddr > funcStart + 64 ? fromAddr - 64 : funcStart;
        var chain = new List<Instruction>();
        uint p = windowStart;
        while (p < fromAddr)
        {
            if (!_decoded.TryDecodeRaw(p, out var insn) || insn.Length == 0) { p++; chain.Clear(); continue; }
            chain.Add(insn);
            p += (uint)insn.Length;
        }
        for (int i = chain.Count - 1; i >= 0 && i >= chain.Count - MaxBackwardScan; i--)
            yield return chain[i];
    }
}
