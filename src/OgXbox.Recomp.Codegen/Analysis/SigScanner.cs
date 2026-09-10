// SigScanner — byte-pattern scan over executable sections for helper prologues.
//
// Ported to C# / x86 from rex::codegen::SigScanner (ReXGlue SDK, BSD-3-Clause).
// ReXGlue's is word-oriented and 4-byte-aligned (PPC); this one is byte-oriented
// and unaligned (x86), with `null` bytes as wildcards.

using System;
using System.Collections.Generic;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Analysis;

/// <param name="Name">Identifier for the match set.</param>
/// <param name="Pattern">Bytes to match; <c>null</c> entry = wildcard.</param>
/// <param name="EntryOffset">Added to a match address to get the reported entry point.</param>
public sealed record Signature(string Name, byte?[] Pattern, int EntryOffset = 0);

public sealed class SigScanner
{
    private readonly BinaryView _binary;

    public SigScanner(BinaryView binary) => _binary = binary;

    public List<uint> Scan(Signature sig)
    {
        var matches = new List<uint>();
        if (sig.Pattern.Length == 0) return matches;

        foreach (var sec in _binary.CodeSections)
            ScanSection(sec, sig, matches);
        return matches;
    }

    public Dictionary<string, List<uint>> ScanAll(IEnumerable<Signature> sigs)
    {
        var result = new Dictionary<string, List<uint>>();
        foreach (var sig in sigs)
            result[sig.Name] = Scan(sig);
        return result;
    }

    private static void ScanSection(SectionView sec, Signature sig, List<uint> matches)
    {
        var data = sec.Data;
        var pat = sig.Pattern;
        int last = data.Length - pat.Length;
        for (int i = 0; i <= last; i++)
        {
            bool ok = true;
            for (int j = 0; j < pat.Length; j++)
            {
                if (pat[j] is { } b && data[i + j] != b) { ok = false; break; }
            }
            if (ok)
                matches.Add(sec.BaseAddress + (uint)(i + sig.EntryOffset));
        }
    }

    /// <summary>
    /// x86 MSVC CRT helper prologues worth locating. Byte patterns are filled in
    /// as they're confirmed against a real binary; empty for now so callers can
    /// register their own.
    /// </summary>
    public static IReadOnlyList<Signature> HelperSignatures() => Array.Empty<Signature>();
}
