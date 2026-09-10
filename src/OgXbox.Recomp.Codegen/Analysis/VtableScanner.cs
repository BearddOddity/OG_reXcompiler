// VTableScanner — recover virtual function tables via MSVC RTTI.
//
// Ported to C# / x86 from rex::codegen::VTableScanner (ReXGlue SDK,
// BSD-3-Clause). ReXGlue already assumes 32-bit MSVC RTTI, so almost nothing
// changes for x86: drop the byte-swap (x86 is native LE) and the 4-byte
// vtable-slot alignment check (x86 code is not aligned).
//
// Layout (32-bit MSVC):
//   RTTICompleteObjectLocator: +0 signature(0) +4 offset +8 cdOffset
//                              +12 pTypeDescriptor +16 pClassDescriptor
//   TypeDescriptor:            +0 pVFTable +4 spare +8 name (".?AV<Class>@@")
//   The vtable pointer to its COL sits at vtable[-1].

using System;
using System.Collections.Generic;
using System.Text;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Analysis;

public sealed class VTableInfo
{
    public required uint VTableAddress { get; init; }
    public required uint ColAddress { get; init; }
    public required string ClassName { get; init; }
    public required IReadOnlyList<uint> Slots { get; init; }
}

public sealed class VTableScanner
{
    private readonly BinaryView _binary;

    public VTableScanner(BinaryView binary) => _binary = binary;

    public List<VTableInfo> Scan()
    {
        var result = new List<VTableInfo>();
        var rdata = _binary.FindSectionByName(".rdata");
        if (rdata is null) return result;

        foreach (uint colAddr in FindCompleteObjectLocators(rdata))
        {
            uint? vtableAddr = FindVTableForCol(rdata, colAddr);
            if (vtableAddr is null) continue;

            var slots = ReadVTableSlots(vtableAddr.Value);
            if (slots.Count == 0) continue;

            result.Add(new VTableInfo
            {
                VTableAddress = vtableAddr.Value,
                ColAddress = colAddr,
                ClassName = ExtractClassName(colAddr),
                Slots = slots,
            });
        }
        return result;
    }

    private IEnumerable<uint> FindCompleteObjectLocators(SectionView rdata)
    {
        var data = rdata.Data;
        for (int off = 0; off + 20 <= data.Length; off += 4)
        {
            uint signature = ReadU32(data, off);
            if (signature != 0) continue;

            uint typeDescPtr = ReadU32(data, off + 12);
            if (_binary.FindSection(typeDescPtr) is null) continue;

            string typeName = ReadString(typeDescPtr + 8, 64);
            if (!typeName.StartsWith(".?AV", StringComparison.Ordinal) &&
                !typeName.StartsWith(".?AU", StringComparison.Ordinal))
                continue;

            yield return rdata.BaseAddress + (uint)off;
        }
    }

    private uint? FindVTableForCol(SectionView rdata, uint colAddr)
    {
        var data = rdata.Data;
        for (int off = 0; off + 4 <= data.Length; off += 4)
        {
            if (ReadU32(data, off) == colAddr)
                return rdata.BaseAddress + (uint)off + 4;
        }
        return null;
    }

    private List<uint> ReadVTableSlots(uint vtableStart)
    {
        var slots = new List<uint>();
        uint slotAddr = vtableStart;
        while (true)
        {
            uint? funcAddr = _binary.ReadU32(slotAddr);
            if (funcAddr is null or 0u) break;
            if (!_binary.IsExecutable(funcAddr.Value)) break;
            slots.Add(funcAddr.Value);
            slotAddr += 4;
        }
        return slots;
    }

    private string ExtractClassName(uint colAddr)
    {
        uint? typeDescPtr = _binary.ReadU32(colAddr + 12);
        if (typeDescPtr is null) return "";

        string mangled = ReadString(typeDescPtr.Value + 8, 256);
        if (mangled.Length > 4 &&
            (mangled.StartsWith(".?AV", StringComparison.Ordinal) ||
             mangled.StartsWith(".?AU", StringComparison.Ordinal)))
        {
            int end = mangled.IndexOf("@@", StringComparison.Ordinal);
            if (end >= 0) return mangled[4..end];
        }
        return mangled;
    }

    private static uint ReadU32(byte[] data, int off) =>
        System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off, 4));

    private string ReadString(uint addr, int maxLen)
    {
        var span = _binary.Translate(addr);
        if (span.Length == 0) return "";
        int n = Math.Min(maxLen, span.Length);
        int len = 0;
        while (len < n && span[len] != 0) len++;
        return Encoding.ASCII.GetString(span[..len]);
    }
}
