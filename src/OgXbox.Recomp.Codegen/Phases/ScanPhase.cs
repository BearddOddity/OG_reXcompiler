// Scan phase — segment executable sections into code / data regions.
//
// Ported to C# / x86 from rex::codegen phase_scan.cpp (ReXGlue SDK,
// BSD-3-Clause), merged with the X-Men Python prototype (tools/graph/scan.py).
//
// ReXGlue splits code on a single null *word* (PPC is 4-byte aligned). x86 is
// byte-variable and 0x00000000 immediates are common, so a split needs a *run*
// of >= MinNullRun zero bytes. 0xCC (int3) padding does NOT split — that is
// inter-function padding, still inside the code region. A {null, handlerFunc}
// pair (an SEH scope-table entry sitting in .text) is stepped over, not split
// on, mirroring ReXGlue's `data += 12` skip.

using System;
using System.Collections.Generic;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Phases;

public static class ScanPhase
{
    public static void Run(CodegenContext ctx)
    {
        var minNull = (int)Math.Max(1, ctx.Config.MinNullRun);
        var handlers = ctx.State.ExceptionHandlerFuncs;

        foreach (var sec in ctx.Binary.CodeSections)
        {
            SegmentCodeRegions(sec, minNull, handlers, ctx.Scan.CodeRegions);
            DetectDataRegions(sec, (int)ctx.Config.DataRegionThreshold, ctx.Scan.DataRegions);
        }
    }

    private static void SegmentCodeRegions(
        SectionView sec, int minNull, IReadOnlySet<uint> handlers, List<CodeRegion> outRegions)
    {
        var data = sec.Data;
        int n = data.Length;
        uint @base = sec.BaseAddress;
        int? regionStart = null;
        int i = 0;

        void Close(int end)
        {
            if (regionStart is { } s && end > s)
                outRegions.Add(new CodeRegion(@base + (uint)s, @base + (uint)end, sec.Name));
            regionStart = null;
        }

        while (i < n)
        {
            if (data[i] == 0)
            {
                int j = i;
                while (j < n && data[j] == 0) j++;
                int runLen = j - i;

                // {null dword, handler-func dword} SEH scope-table entry: step over.
                if (runLen >= 4 && i + 8 <= n)
                {
                    uint nextWord = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                        data.AsSpan(i + 4, 4));
                    if (handlers.Contains(nextWord))
                    {
                        if (regionStart is null) regionStart = i;
                        i += 8;
                        continue;
                    }
                }

                if (runLen >= minNull)
                {
                    Close(i);
                    i = j;
                    continue;
                }

                // short run: part of the surrounding code
                if (regionStart is null) regionStart = i;
                i = j;
                continue;
            }

            if (regionStart is null) regionStart = i;
            i++;
        }

        Close(n);
    }

    private static void DetectDataRegions(SectionView sec, int threshold, List<CodeRegion> outRegions)
    {
        var data = sec.Data;
        int n = data.Length & ~3;
        uint @base = sec.BaseAddress;
        int invalidRun = 0;
        int runStart = 0;

        for (int off = 0; off < n; off += 4)
        {
            uint word = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                data.AsSpan(off, 4));
            bool isInvalid = word is 0x00000000u or 0xFFFFFFFFu;
            if (isInvalid)
            {
                if (invalidRun == 0) runStart = off;
                invalidRun++;
            }
            else
            {
                if (invalidRun >= threshold)
                    outRegions.Add(new CodeRegion(@base + (uint)runStart, @base + (uint)off, sec.Name));
                invalidRun = 0;
            }
        }

        if (invalidRun >= threshold)
            outRegions.Add(new CodeRegion(@base + (uint)runStart, @base + (uint)n, sec.Name));
    }
}
