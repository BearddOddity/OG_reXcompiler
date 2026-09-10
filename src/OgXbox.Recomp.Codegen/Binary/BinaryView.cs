// BinaryView — self-contained, VA-addressable view of a loaded binary that owns
// its section bytes. The codegen phases only ever see this, never the raw XBE.
//
// Ported to C# / x86 from rex::codegen::BinaryView (ReXGlue SDK, BSD-3-Clause).
// ReXGlue's is built from a XEX Module; this one is built from an Xbe.

using System;
using System.Collections.Generic;
using System.Linq;

namespace OgXbox.Recomp.Codegen.Binary;

/// <summary>A VA range backed by owned bytes.</summary>
public sealed class SectionView
{
    public required string Name { get; init; }
    public required uint BaseAddress { get; init; }
    public required uint Size { get; init; }
    public required byte[] Data { get; init; }   // length == Size; zero-padded past RawSize (BSS tail)
    public required bool Executable { get; init; }
    public required bool Writable { get; init; }

    public uint End => BaseAddress + Size;
    public bool Contains(uint addr) => addr >= BaseAddress && addr < End;

    public ReadOnlySpan<byte> Translate(uint addr) =>
        Contains(addr) ? Data.AsSpan((int)(addr - BaseAddress)) : default;
}

/// <summary>An import thunk: the address a <c>call</c> targets, plus its name.</summary>
public readonly record struct ImportSymbol(uint Address, string Name);

public sealed class BinaryView
{
    // Data sections stay data even when the XBE marks them executable: Xbox
    // linkers flag almost everything executable, and disassembling zero-fill
    // produces phantom functions. XDK library sections (D3D_RD etc.) are real
    // code and are NOT excluded.
    private static readonly HashSet<string> DataSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".data", ".data1", ".rdata", ".idata", ".edata", ".reloc", ".tls",
    };

    private readonly List<SectionView> _sections;
    private readonly List<ImportSymbol> _imports;

    private BinaryView(List<SectionView> sections, List<ImportSymbol> imports,
                       uint baseAddress, uint imageSize, uint entryPoint, uint kernelThunkAddr)
    {
        _sections = sections;
        _imports = imports;
        BaseAddress = baseAddress;
        ImageSize = imageSize;
        EntryPoint = entryPoint;
        KernelThunkTableStart = kernelThunkAddr;
    }

    public uint BaseAddress { get; }
    public uint ImageSize { get; }
    public uint EntryPoint { get; }

    /// <summary>Start of the kernel import thunk table (0 if none). Not code.</summary>
    public uint KernelThunkTableStart { get; }

    public IReadOnlyList<SectionView> Sections => _sections;
    public IReadOnlyList<ImportSymbol> ImportSymbols => _imports;

    public SectionView? FindSection(uint addr) => _sections.FirstOrDefault(s => s.Contains(addr));

    public SectionView? FindSectionByName(string name) =>
        _sections.FirstOrDefault(s => string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase));

    public ReadOnlySpan<byte> Translate(uint addr)
    {
        var sec = FindSection(addr);
        return sec is null ? default : sec.Translate(addr);
    }

    public bool IsExecutable(uint addr) => FindSection(addr) is { Executable: true };

    public uint? ReadU32(uint addr)
    {
        var span = Translate(addr);
        if (span.Length < 4) return null;
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(span);
    }

    /// <summary>
    /// Sections suitable for disassembly: executable, non-empty, and not a
    /// conventional data section by name.
    /// </summary>
    public IEnumerable<SectionView> CodeSections =>
        _sections.Where(s => s.Executable && s.Size > 0 && !DataSectionNames.Contains(s.Name));

    /// <summary>Construct directly from section views (tests, synthetic inputs).</summary>
    internal static BinaryView FromSections(
        IEnumerable<SectionView> sections,
        uint baseAddress = 0x00010000, uint entryPoint = 0, uint kernelThunkAddr = 0,
        IEnumerable<ImportSymbol>? imports = null)
    {
        var secList = sections.ToList();
        uint imageSize = secList.Count == 0 ? 0
            : secList.Max(s => s.End) - baseAddress;
        return new BinaryView(secList, (imports ?? Enumerable.Empty<ImportSymbol>()).ToList(),
                              baseAddress, imageSize, entryPoint, kernelThunkAddr);
    }

    public static BinaryView FromXbe(Xbe xbe)
    {
        var sections = new List<SectionView>();
        foreach (var s in xbe.Sections)
        {
            // Own a VirtualSize buffer; copy RawSize bytes, leave the rest zero (BSS tail).
            var buf = new byte[s.VirtualSize];
            int copy = (int)Math.Min(s.RawSize, s.VirtualSize);
            if (copy > 0 && s.RawAddress + copy <= xbe.RawData.Length)
                Array.Copy(xbe.RawData, s.RawAddress, buf, 0, copy);

            sections.Add(new SectionView
            {
                Name = s.Name,
                BaseAddress = s.VirtualAddress,
                Size = s.VirtualSize,
                Data = buf,
                Executable = s.IsExecutable,
                Writable = s.IsWritable,
            });
        }

        var imports = xbe.KernelImports
            .Select(k => new ImportSymbol(k.ThunkAddress, $"xboxkrnl@{k.Ordinal}:{k.Name}"))
            .ToList();

        return new BinaryView(sections, imports, xbe.BaseAddress, xbe.ImageSize,
                              xbe.EntryPoint, xbe.KernelThunkAddress);
    }
}
