// FunctionNode — the core object representing a function in the graph.
// Manages its own state transitions and branch resolution.
//
// Ported to C# / x86 from rex::codegen::FunctionNode (ReXGlue SDK,
// BSD-3-Clause). See LICENSE.rexglue.

using System;
using System.Collections.Generic;
using System.Linq;

namespace OgXbox.Recomp.Codegen;

/// <summary>
/// A function in the <see cref="FunctionGraph"/>. External code inspects it;
/// only the graph mutates it (the mutators are <c>internal</c>).
/// </summary>
public sealed class FunctionNode
{
    private uint _size;
    private readonly List<Block> _blocks = new();
    private readonly List<DecodedInstruction> _instructions = new();
    private readonly SortedSet<uint> _labels = new();
    private readonly List<CallEdge> _calls = new();
    private readonly List<CallEdge> _tailCalls = new();
    private readonly List<JumpTable> _jumpTables = new();
    private readonly List<UnresolvedJump> _unresolvedJumps = new();
    private FunctionAnalysis? _analysis;

    internal FunctionNode(uint @base, uint size, FunctionAuthority authority)
    {
        Base = @base;
        _size = size;
        Authority = authority;
        Name = $"sub_{@base:X8}";
        // All functions start Registered — waiting for Discover() to assign blocks.
        // Authority prevents merging via vacancy checks, not via initial state.
    }

    //=========================================================================
    // Identity
    //=========================================================================

    public uint Base { get; }
    public uint Size => _size;
    public uint End => Base + _size;
    public string Name { get; private set; }

    public FunctionAuthority Authority { get; }
    public FunctionState State { get; private set; } = FunctionState.Registered;

    public bool IsRegistered => State == FunctionState.Registered;
    public bool IsDiscovered => State == FunctionState.Discovered;
    public bool IsSealed => State == FunctionState.Sealed;

    /// Legacy alias: "pending" == not yet sealed (Registered OR Discovered).
    public bool IsPending => State != FunctionState.Sealed;

    public bool IsImport => Authority == FunctionAuthority.Import;
    public bool IsHelper => Authority == FunctionAuthority.Helper;

    public bool HasExceptionHandler { get; private set; }
    public ExceptionInfo? ExceptionInfo { get; private set; }
    public bool HasExceptionInfo => ExceptionInfo is { HasInfo: true };

    /// <summary>
    /// This is an SEH funclet: non-volatiles stay in the shared context so it
    /// sees what its owner left live, and callers sync their localized copies
    /// around the call.
    /// </summary>
    public bool SharesRegisters { get; internal set; }

    //=========================================================================
    // Read-only collections
    //=========================================================================

    public IReadOnlyList<Block> Blocks => _blocks;
    public IReadOnlyList<DecodedInstruction> Instructions => _instructions;
    public IReadOnlySet<uint> Labels => _labels;
    public IReadOnlyList<CallEdge> Calls => _calls;
    public IReadOnlyList<CallEdge> TailCalls => _tailCalls;
    public IReadOnlyList<JumpTable> JumpTables => _jumpTables;
    public IReadOnlyList<UnresolvedJump> UnresolvedJumps => _unresolvedJumps;

    public bool HasUnresolvedJumps => _unresolvedJumps.Count > 0;
    public bool IsLabel(uint addr) => _labels.Contains(addr);

    public FunctionAnalysis Analysis =>
        _analysis ?? throw new InvalidOperationException("Analysis only valid after Seal().");

    //=========================================================================
    // State machine
    //=========================================================================

    public bool CanDiscover => State == FunctionState.Registered;

    /// <summary>Registered -&gt; Discovered with blocks, instructions, labels.</summary>
    internal void Discover(
        IEnumerable<Block> blocks,
        IEnumerable<DecodedInstruction> instructions,
        IEnumerable<uint> labels)
    {
        if (!CanDiscover)
            throw new InvalidOperationException("Invalid transition: must be Registered.");

        _blocks.Clear();
        _blocks.AddRange(blocks);
        _instructions.Clear();
        _instructions.AddRange(instructions);
        _labels.Clear();
        foreach (var l in labels) _labels.Add(l);

        if (!IsImport && _blocks.Count == 0)
            throw new InvalidOperationException("Non-import function must have blocks.");

        foreach (var block in _blocks)
        {
            if (block.End > Base + _size)
                _size = block.End - Base;
        }

        State = FunctionState.Discovered;
    }

    /// <summary>Registered -&gt; Discovered for imports (no blocks).</summary>
    internal void DiscoverAsImport()
    {
        if (!CanDiscover)
            throw new InvalidOperationException("Invalid transition: must be Registered.");
        if (!IsImport)
            throw new InvalidOperationException("Only imports can use DiscoverAsImport().");
        State = FunctionState.Discovered;
    }

    public bool CanSeal()
    {
        if (State != FunctionState.Discovered) return false;
        if (IsImport) return true;                 // imports seal without blocks
        if (_blocks.Count == 0) return false;      // non-imports must have blocks
        if (_unresolvedJumps.Count > 0) return false; // all branches resolved
        return true;
    }

    /// <summary>Discovered -&gt; Sealed. Sorts and merges blocks, computes analysis.</summary>
    internal void Seal()
    {
        if (!CanSeal())
            throw new InvalidOperationException("Cannot seal: invariants not met.");

        _blocks.Sort((a, b) => a.Base.CompareTo(b.Base));

        // Merge overlapping / adjacent blocks — multiple paths can reach the
        // same code (jump-table target and a fall-through both hitting an epilogue).
        if (_blocks.Count > 1)
        {
            var merged = new List<Block> { _blocks[0] };
            for (int i = 1; i < _blocks.Count; i++)
            {
                var last = merged[^1];
                var curr = _blocks[i];
                if (curr.Base <= last.End)
                {
                    uint newEnd = Math.Max(last.End, curr.End);
                    merged[^1] = last with { Size = newEnd - last.Base };
                }
                else
                {
                    merged.Add(curr);
                }
            }
            if (merged.Count < _blocks.Count)
            {
                _blocks.Clear();
                _blocks.AddRange(merged);
            }
        }

        _analysis = new FunctionAnalysis();
        State = FunctionState.Sealed;
    }

    //=========================================================================
    // Containment
    //=========================================================================

    public bool ContainsAddress(uint addr)
    {
        if (addr < Base || addr >= Base + _size) return false;
        if (_blocks.Count == 0) return true;

        foreach (var block in _blocks)
            if (block.Contains(addr)) return true;

        // CONFIG / PDATA declare a trusted size even when blocks don't cover it
        // (out-of-line switch cases placed after the epilogue).
        if (Authority is FunctionAuthority.Config or FunctionAuthority.Pdata)
            return true;

        return false;
    }

    /// <summary>Within the overall [Base, Base+Size) bounds, ignoring block gaps.</summary>
    public bool IsWithinBounds(uint addr) => addr >= Base && addr < Base + _size;

    //=========================================================================
    // Mutators (graph-only)
    //=========================================================================

    internal void SetName(string name) => Name = name;
    internal void SetHasExceptionHandler(bool val) => HasExceptionHandler = val;
    internal void SetExceptionInfo(ExceptionInfo info) => ExceptionInfo = info;

    internal void AddBlock(Block block)
    {
        _blocks.Add(block);
        if (block.End > Base + _size)
            _size = block.End - Base;
    }

    internal void AddLabel(uint addr) => _labels.Add(addr);

    internal void AddCall(uint site, CallTarget target) => _calls.Add(new CallEdge(site, target));

    internal void AddTailCall(uint site, CallTarget target) =>
        _tailCalls.Add(new CallEdge(site, target));

    internal void AddJumpTable(JumpTable jt)
    {
        foreach (var t in jt.Targets) _labels.Add(t);
        _jumpTables.Add(jt);
    }

    internal void AddUnresolvedJump(uint site, uint target, bool isCall, bool conditional) =>
        _unresolvedJumps.Add(new UnresolvedJump(site, target, isCall, conditional));

    internal void RemoveUnresolvedJump(uint site) =>
        _unresolvedJumps.RemoveAll(j => j.Site == site);

    //=========================================================================
    // Reactive resolution (called by the graph on events)
    //=========================================================================

    /// <summary>A new function entered the graph — claim any jump that targets its entry.</summary>
    internal bool TryResolveAgainst(FunctionNode newFunction)
    {
        if (IsSealed || newFunction is null) return false;

        bool any = false;
        for (int i = _unresolvedJumps.Count - 1; i >= 0; i--)
        {
            if (_unresolvedJumps[i].Target == newFunction.Base)
            {
                AddTailCall(_unresolvedJumps[i].Site, CallTarget.Function(newFunction));
                _unresolvedJumps.RemoveAt(i);
                any = true;
            }
        }
        return any;
    }

    internal bool TryResolveAgainstImport(uint importAddr, string importName)
    {
        if (IsSealed) return false;

        bool any = false;
        for (int i = _unresolvedJumps.Count - 1; i >= 0; i--)
        {
            if (_unresolvedJumps[i].Target == importAddr)
            {
                AddTailCall(_unresolvedJumps[i].Site, CallTarget.ImportRef(importAddr, importName));
                _unresolvedJumps.RemoveAt(i);
                any = true;
            }
        }
        return any;
    }

    internal bool TryResolveAsInternalLabel(uint target)
    {
        if (!ContainsAddress(target)) return false;
        AddLabel(target);
        return true;
    }

    internal void AbsorbRegion(uint regionBase, uint regionSize)
    {
        if (State == FunctionState.Sealed)
            throw new InvalidOperationException("Cannot absorb into a Sealed function.");
        AddBlock(new Block(regionBase, regionSize));
    }
}
