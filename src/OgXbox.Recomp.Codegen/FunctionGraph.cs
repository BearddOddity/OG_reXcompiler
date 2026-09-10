// FunctionGraph — reactive container for all function nodes. Manages authority
// resolution, resolution notifications, vacancy checking for merges, and branch
// target classification.
//
// Ported to C# / x86 from rex::codegen::FunctionGraph (ReXGlue SDK,
// BSD-3-Clause). See LICENSE.rexglue.
//
// Vacancy rules — a region is vacant iff ALL hold:
//   1. No null dword at the boundary (typical inter-function padding).
//   2. No chunk claims the region.
//   3. Target is not inside a protected function:
//      - HELPER / PDATA / CONFIG / DISCOVERED / VTABLE / IMPORT: protected.
//      - GAP_FILL: absorbable.

using System;
using System.Collections.Generic;
using System.Linq;

namespace OgXbox.Recomp.Codegen;

public sealed class FunctionGraph
{
    /// <summary>Reads a guest dword; returns null if the address is unmapped.</summary>
    public delegate uint? MemoryReader(uint addr);

    private readonly List<CodeBuffer> _codeBuffers = new();
    private readonly Dictionary<uint, FunctionNode> _functions = new();
    // SortedList (not SortedDictionary) so Keys is an IList<uint> for O(log f)
    // binary search in GetFunctionContaining, which the phases hammer.
    private readonly SortedList<uint, FunctionNode> _functionsByBase = new();
    private readonly Dictionary<uint, bool> _functionHasXrefs = new();
    private readonly List<(uint Base, uint Size)> _chunks = new();
    private MemoryReader? _memoryReader;

    //=========================================================================
    // Code buffers
    //=========================================================================

    public void AddCodeBuffer(uint baseAddress, ReadOnlySpan<byte> data) =>
        _codeBuffers.Add(new CodeBuffer(baseAddress, data));

    public IReadOnlyList<CodeBuffer> CodeBuffers => _codeBuffers;

    public ReadOnlySpan<byte> TranslateCode(uint addr)
    {
        foreach (var buf in _codeBuffers)
            if (buf.Contains(addr)) return buf.Translate(addr);
        return default;
    }

    //=========================================================================
    // Function management
    //=========================================================================

    /// <summary>
    /// Add a function. If one already exists at <paramref name="base"/>, the
    /// higher authority wins (existing kept on tie). On a real add, every
    /// pending function is notified to try resolving against the new entry.
    /// </summary>
    public FunctionNode AddFunction(uint @base, uint size, FunctionAuthority authority,
                                    bool hasXrefs = false)
    {
        if (_functions.TryGetValue(@base, out var existing))
        {
            if (existing.Authority >= authority)
                return existing;
            // else: replace with the higher-authority node
        }

        var node = new FunctionNode(@base, size, authority);
        _functions[@base] = node;
        _functionsByBase[@base] = node;
        _functionHasXrefs[@base] = hasXrefs;

        NotifyFunctionAdded(node);
        return node;
    }

    public FunctionNode AddFunction(uint @base, uint size, FunctionAuthority authority,
                                    string name, bool hasXrefs = false)
    {
        var node = AddFunction(@base, size, authority, hasXrefs);
        if (!string.IsNullOrEmpty(name))
            node.SetName(name);
        return node;
    }

    /// <summary>Add a resolved import as a callable node (IMPORT authority, __imp__ name).</summary>
    public FunctionNode AddImportFunction(uint address, string resolvedName) =>
        AddFunction(address, 4, FunctionAuthority.Import, resolvedName, hasXrefs: true);

    public FunctionNode? GetFunction(uint entryPoint) =>
        _functions.TryGetValue(entryPoint, out var n) ? n : null;

    public bool RemoveFunction(uint entryPoint)
    {
        if (!_functions.Remove(entryPoint)) return false;
        _functionsByBase.Remove(entryPoint);
        _functionHasXrefs.Remove(entryPoint);
        return true;
    }

    /// <summary>Function containing <paramref name="addr"/> (O(log f) via the sorted base index).</summary>
    public FunctionNode? GetFunctionContaining(uint addr)
    {
        var keys = _functionsByBase.Keys;
        int lo = 0, hi = keys.Count - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (keys[mid] <= addr) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (found < 0) return null;
        var candidate = _functionsByBase.Values[found];
        return candidate.ContainsAddress(addr) ? candidate : null;
    }

    public bool IsEntryPoint(uint addr) => _functions.ContainsKey(addr);

    public bool IsImport(uint addr) =>
        _functions.TryGetValue(addr, out var n) && n.Authority == FunctionAuthority.Import;

    public IReadOnlyDictionary<uint, FunctionNode> Functions => _functions;

    public IEnumerable<FunctionNode> PendingFunctions => _functions.Values.Where(n => n.IsPending);
    public IEnumerable<FunctionNode> SealedFunctions => _functions.Values.Where(n => n.IsSealed);

    public int FunctionCount => _functions.Count;
    public int PendingCount => _functions.Values.Count(n => n.IsPending);
    public int SealedCount => _functions.Values.Count(n => n.IsSealed);

    public bool HasXrefs(uint entry) => _functionHasXrefs.TryGetValue(entry, out var v) && v;

    //=========================================================================
    // Function setup (Discover phase)
    //=========================================================================

    public void SetFunctionName(uint entry, string name) => GetFunction(entry)?.SetName(name);

    public void SetFunctionHasExceptionHandler(uint entry, bool val) =>
        GetFunction(entry)?.SetHasExceptionHandler(val);

    public void SetFunctionExceptionInfo(uint entry, ExceptionInfo info) =>
        GetFunction(entry)?.SetExceptionInfo(info);

    public void AddBlockToFunction(uint entry, Block block) => GetFunction(entry)?.AddBlock(block);

    public void AddLabelToFunction(uint entry, uint label) => GetFunction(entry)?.AddLabel(label);

    public void AddCallToFunction(uint entry, uint site, CallTarget target) =>
        GetFunction(entry)?.AddCall(site, target);

    public void AddTailCallToFunction(uint entry, uint site, CallTarget target) =>
        GetFunction(entry)?.AddTailCall(site, target);

    public void AddJumpTableToFunction(uint entry, JumpTable jt) =>
        GetFunction(entry)?.AddJumpTable(jt);

    /// <summary>
    /// Add a branch that leaves internal flow. Resolves immediately if the target
    /// is a known function or import; otherwise parks it as unresolved.
    /// </summary>
    public void AddUnresolvedJumpToFunction(uint entry, uint site, uint target, bool isCall,
                                            bool conditional)
    {
        var node = GetFunction(entry);
        if (node is null) return;

        if (GetFunction(target) is { } targetFn)
        {
            if (isCall) node.AddCall(site, CallTarget.Function(targetFn));
            else node.AddTailCall(site, CallTarget.Function(targetFn));
            return;
        }

        if (IsImport(target))
        {
            var importName = GetFunction(target)!.Name;
            if (isCall) node.AddCall(site, CallTarget.ImportRef(target, importName));
            else node.AddTailCall(site, CallTarget.ImportRef(target, importName));
            return;
        }

        node.AddUnresolvedJump(site, target, isCall, conditional);
    }

    //=========================================================================
    // Resolution and expansion (Merge phase)
    //=========================================================================

    /// <summary>Retry every unresolved jump of a function. Returns how many resolved.</summary>
    public int TryResolveFunction(uint entry)
    {
        var node = GetFunction(entry);
        if (node is null || node.IsSealed) return 0;

        int resolved = 0;
        foreach (var jump in node.UnresolvedJumps.ToArray())
        {
            if (node.TryResolveAsInternalLabel(jump.Target))
            {
                node.RemoveUnresolvedJump(jump.Site);
                resolved++;
                continue;
            }

            if (GetFunction(jump.Target) is { } targetFn)
            {
                if (jump.IsCall) node.AddCall(jump.Site, CallTarget.Function(targetFn));
                else node.AddTailCall(jump.Site, CallTarget.Function(targetFn));
                node.RemoveUnresolvedJump(jump.Site);
                resolved++;
                continue;
            }

            if (IsImport(jump.Target))
            {
                var importName = GetFunction(jump.Target)!.Name;
                if (jump.IsCall) node.AddCall(jump.Site, CallTarget.ImportRef(jump.Target, importName));
                else node.AddTailCall(jump.Site, CallTarget.ImportRef(jump.Target, importName));
                node.RemoveUnresolvedJump(jump.Site);
                resolved++;
            }
        }
        return resolved;
    }

    public void AbsorbRegionIntoFunction(uint entry, uint regionBase, uint regionSize) =>
        GetFunction(entry)?.AbsorbRegion(regionBase, regionSize);

    public bool TrySealFunction(uint entry)
    {
        var node = GetFunction(entry);
        if (node is null || node.IsSealed) return false;
        if (!node.CanSeal()) return false;
        node.Seal();
        return true;
    }

    public int SealAllReady()
    {
        int sealed_ = 0;
        foreach (var node in _functions.Values)
        {
            if (node.IsPending && node.CanSeal())
            {
                node.Seal();
                sealed_++;
            }
        }
        return sealed_;
    }

    /// <summary>Seal every function, throwing with a report if any cannot be sealed.</summary>
    public void SealAll()
    {
        var errors = new List<string>();
        foreach (var (@base, node) in _functions.OrderBy(kv => kv.Key))
        {
            if (node.IsSealed) continue;
            if (!node.CanSeal())
            {
                string reason = node.IsRegistered ? "still Registered (blocks not discovered)"
                    : node.Blocks.Count == 0 && !node.IsImport ? "has 0 blocks (non-import)"
                    : node.UnresolvedJumps.Count > 0 ? $"{node.UnresolvedJumps.Count} unresolved jumps"
                    : "unknown reason";
                errors.Add($"{node.Name} (0x{@base:X8}): {reason}");
                continue;
            }
            node.Seal();
        }

        if (errors.Count > 0)
            throw new InvalidOperationException(
                $"SealAll: {errors.Count} functions cannot be sealed:\n  - " +
                string.Join("\n  - ", errors));
    }

    //=========================================================================
    // Vacancy checking
    //=========================================================================

    public void SetMemoryReader(MemoryReader reader) => _memoryReader = reader;

    public void RegisterChunk(uint @base, uint size) => _chunks.Add((@base, size));

    public bool IsVacant(uint fromAddr, uint targetAddr)
    {
        // Rule 1: null dword at the boundary.
        if (_memoryReader is not null && targetAddr > fromAddr)
        {
            var val = _memoryReader(targetAddr);
            if (val is 0u) return false;
        }

        // Rule 2: a chunk claims the target region.
        foreach (var (chunkBase, chunkSize) in _chunks)
            if (targetAddr >= chunkBase && targetAddr < chunkBase + chunkSize)
                return false;

        // Rule 3: target within a protected function.
        foreach (var node in _functions.Values)
        {
            if (node.ContainsAddress(targetAddr))
            {
                if (IsMergeableEntryPoint(targetAddr)) continue; // GAP_FILL — absorbable
                return false;
            }
        }

        return true;
    }

    public bool IsMergeableEntryPoint(uint addr) =>
        _functions.TryGetValue(addr, out var n) && n.Authority == FunctionAuthority.GapFill;

    /// <summary>
    /// Flag every SEH funclet (its handler/filter/cleanup/catch bodies, plus any
    /// second node sharing a funclet's tail) as register-sharing. Run after
    /// discovery. Returns the count flagged.
    /// </summary>
    public int MarkFuncletRegisterSharing()
    {
        var ranges = new List<(uint Start, uint End)>();

        void Claim(uint addr)
        {
            if (addr != 0 && _functions.TryGetValue(addr, out var n))
                ranges.Add((n.Base, n.End));
        }

        foreach (var node in _functions.Values)
        {
            if (!node.HasExceptionInfo) continue;
            var info = node.ExceptionInfo!;
            if (info.Seh is { } seh)
            {
                foreach (var scope in seh.Scopes) { Claim(scope.Handler); Claim(scope.Filter); }
            }
            else if (info.Cxx is { } cxx)
            {
                foreach (var e in cxx.UnwindMap) Claim(e.Action);
                foreach (var tb in cxx.TryBlocks)
                    foreach (var h in tb.Handlers) Claim(h.HandlerAddress);
            }
        }

        if (ranges.Count == 0) return 0;

        ranges.Sort();
        var mergedRanges = new List<(uint Start, uint End)> { ranges[0] };
        for (int i = 1; i < ranges.Count; i++)
        {
            var last = mergedRanges[^1];
            if (ranges[i].Start <= last.End)
                mergedRanges[^1] = (last.Start, Math.Max(last.End, ranges[i].End));
            else
                mergedRanges.Add(ranges[i]);
        }

        bool InsideFunclet(uint addr)
        {
            foreach (var r in mergedRanges)
                if (addr >= r.Start && addr < r.End) return true;
            return false;
        }

        int marked = 0;
        foreach (var node in _functions.Values)
        {
            if (!node.SharesRegisters && InsideFunclet(node.Base))
            {
                node.SharesRegisters = true;
                marked++;
            }
        }
        return marked;
    }

    //=========================================================================
    // Target classification (code generation)
    //=========================================================================

    public TargetKind ClassifyTarget(uint target, uint callerAddr, bool isCallInstruction)
    {
        var callerFn = GetFunctionContaining(callerAddr);

        if (IsImport(target))
            return TargetKind.Import;

        if (callerFn is not null && target == callerFn.Base)
            return isCallInstruction ? TargetKind.Function : TargetKind.InternalLabel;

        if (IsEntryPoint(target))
            return TargetKind.Function;

        if (callerFn is not null && callerFn.ContainsAddress(target))
            return TargetKind.InternalLabel;

        return TargetKind.Unknown;
    }

    //=========================================================================
    // Internal
    //=========================================================================

    private void NotifyFunctionAdded(FunctionNode newFunction)
    {
        foreach (var node in _functions.Values)
            if (!ReferenceEquals(node, newFunction) && node.IsPending)
                node.TryResolveAgainst(newFunction);
    }
}
