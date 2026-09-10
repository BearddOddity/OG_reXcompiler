// Minimal XBE (Xbox Executable) parser — header, section table, kernel imports.
//
// Independent implementation from the XBE format (offsets cross-checked against
// the X-Men recomp's tools/xbe_parser). Only what the recompiler needs.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace OgXbox.Recomp.Codegen.Binary;

[Flags]
public enum XbeSectionFlags : uint
{
    Writable = 0x01,
    Preload = 0x02,
    Executable = 0x04,
    InsertedFile = 0x08,
    HeadPageReadOnly = 0x10,
    TailPageReadOnly = 0x20,
}

public sealed class XbeSection
{
    public required string Name { get; init; }
    public required uint VirtualAddress { get; init; }
    public required uint VirtualSize { get; init; }
    public required uint RawAddress { get; init; }
    public required uint RawSize { get; init; }
    public required XbeSectionFlags Flags { get; init; }

    public bool IsExecutable => Flags.HasFlag(XbeSectionFlags.Executable);
    public bool IsWritable => Flags.HasFlag(XbeSectionFlags.Writable);
    public uint VirtualEnd => VirtualAddress + VirtualSize;
}

public sealed class XbeKernelImport
{
    public required int Ordinal { get; init; }
    public required string Name { get; init; }
    public required uint ThunkAddress { get; init; }
}

public sealed class Xbe
{
    private const uint EntryRetailXor = 0xA8FC57AB;
    private const uint EntryDebugXor = 0x94859D4B;
    private const uint ThunkRetailXor = 0x5B6D40B6;
    private const uint ThunkDebugXor = 0xEFB1F152;

    public required byte[] RawData { get; init; }
    public required uint BaseAddress { get; init; }
    public required uint ImageSize { get; init; }
    public required uint HeadersSize { get; init; }
    public required uint EntryPoint { get; init; }
    public required uint KernelThunkAddress { get; init; }
    public required uint TlsAddress { get; init; }
    public required bool IsDebug { get; init; }
    public required IReadOnlyList<XbeSection> Sections { get; init; }
    public required IReadOnlyList<XbeKernelImport> KernelImports { get; init; }

    public static Xbe Load(string path) => Parse(File.ReadAllBytes(path));

    public static Xbe Parse(byte[] data)
    {
        if (data.Length < 0x180 || Encoding.ASCII.GetString(data, 0, 4) != "XBEH")
            throw new InvalidDataException("Not an XBE (bad 'XBEH' magic).");

        uint U32(int off) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off, 4));

        uint baseAddr = U32(0x0104);
        uint headersSize = U32(0x0108);
        uint imageSize = U32(0x010C);
        uint numSections = U32(0x011C);
        uint sectionHeadersVa = U32(0x0120);
        uint entryRaw = U32(0x0128);
        uint tlsVa = U32(0x012C);
        uint thunkRaw = U32(0x0158);

        // Header data is mapped at [baseAddr, baseAddr + headersSize) == file [0, headersSize).
        int VaToHeaderOffset(uint va) => (int)(va - baseAddr);

        uint entryRetail = entryRaw ^ EntryRetailXor;
        uint entryDebug = entryRaw ^ EntryDebugXor;
        bool isDebug;
        uint entry;
        if (entryRetail >= baseAddr && entryRetail < baseAddr + imageSize)
        {
            entry = entryRetail; isDebug = false;
        }
        else if (entryDebug >= baseAddr && entryDebug < baseAddr + imageSize)
        {
            entry = entryDebug; isDebug = true;
        }
        else
        {
            entry = entryRetail; isDebug = false;
        }

        uint thunk = isDebug ? (thunkRaw ^ ThunkDebugXor) : (thunkRaw ^ ThunkRetailXor);

        var sections = new List<XbeSection>((int)numSections);
        int secBase = VaToHeaderOffset(sectionHeadersVa);
        for (int i = 0; i < numSections; i++)
        {
            int o = secBase + i * 56;
            var flags = (XbeSectionFlags)U32(o + 0);
            uint vaddr = U32(o + 4);
            uint vsize = U32(o + 8);
            uint raddr = U32(o + 12);
            uint rsize = U32(o + 16);
            uint nameVa = U32(o + 20);

            string name = "";
            if (nameVa != 0)
            {
                int no = VaToHeaderOffset(nameVa);
                if (no >= 0 && no < data.Length)
                {
                    int end = no;
                    while (end < data.Length && end < no + 32 && data[end] != 0) end++;
                    name = Encoding.ASCII.GetString(data, no, end - no);
                }
            }

            sections.Add(new XbeSection
            {
                Name = name,
                VirtualAddress = vaddr,
                VirtualSize = vsize,
                RawAddress = raddr,
                RawSize = rsize,
                Flags = flags,
            });
        }

        var imports = ParseKernelImports(data, sections, thunk);

        return new Xbe
        {
            RawData = data,
            BaseAddress = baseAddr,
            ImageSize = imageSize,
            HeadersSize = headersSize,
            EntryPoint = entry,
            KernelThunkAddress = thunk,
            TlsAddress = tlsVa,
            IsDebug = isDebug,
            Sections = sections,
            KernelImports = imports,
        };
    }

    private static List<XbeKernelImport> ParseKernelImports(
        byte[] data, List<XbeSection> sections, uint thunkVa)
    {
        var imports = new List<XbeKernelImport>();
        if (thunkVa == 0) return imports;

        int? fileOff = null;
        foreach (var s in sections)
        {
            if (thunkVa >= s.VirtualAddress && thunkVa < s.VirtualEnd)
            {
                fileOff = (int)(s.RawAddress + (thunkVa - s.VirtualAddress));
                break;
            }
        }
        fileOff ??= (int)thunkVa; // header area fallback (base assumed 0x10000 == file 0)

        int start = fileOff.Value;
        int off = start;
        while (off + 4 <= data.Length)
        {
            uint val = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(off, 4));
            if (val == 0) break;
            if ((val & 0x80000000) != 0)
            {
                int ordinal = (int)(val & 0x7FFFFFFF);
                imports.Add(new XbeKernelImport
                {
                    Ordinal = ordinal,
                    Name = XboxKernelExports.Name(ordinal),
                    ThunkAddress = (uint)(thunkVa + (off - start)),
                });
            }
            off += 4;
        }
        return imports;
    }
}
