// ImageWriter — emit the XBE's loadable sections as a flat blob + a C loader.
//
// Keeps XBE parsing in one place (C#); the runtime just maps the blob into
// guest RAM at each section's VA. Analogous to ReXGlue's XEX module loader,
// minus decompression (XBE sections are stored raw).

using System;
using System.IO;
using System.Linq;
using System.Text;
using OgXbox.Recomp.Codegen.Binary;

namespace OgXbox.Recomp.Codegen.Emit;

public static class ImageWriter
{
    public static void Write(Xbe xbe, string outDir)
    {
        var loadable = xbe.Sections
            .Where(s => s.RawSize > 0 && s.RawAddress + s.RawSize <= xbe.RawData.Length)
            .OrderBy(s => s.VirtualAddress)
            .ToList();

        // Flat blob: each section's raw bytes, concatenated.
        using (var blob = File.Create(Path.Combine(outDir, "recomp_image.bin")))
        {
            foreach (var s in loadable)
                blob.Write(xbe.RawData, (int)s.RawAddress, (int)s.RawSize);
        }

        uint ramSize = RoundUp(xbe.BaseAddress + xbe.ImageSize + 0x10000, 0x1000);
        // A generous default guest stack just below 0x80000000 (OG Xbox user space).
        uint initialEsp = 0x7FFF0000;

        var sb = new StringBuilder();
        sb.AppendLine("/* generated — XBE image map. rex_load_image() fills guest RAM. */");
        sb.AppendLine("#include \"ogxbox_runtime.h\"");
        sb.AppendLine("#include <stdio.h>");
        sb.AppendLine();
        sb.AppendLine("typedef struct { unsigned int va; unsigned int file_off; unsigned int size; } RexSection;");
        sb.AppendLine("static const RexSection g_rex_sections[] = {");
        long off = 0;
        foreach (var s in loadable)
        {
            sb.AppendLine($"  {{ 0x{s.VirtualAddress:X8}u, {off}u, 0x{s.RawSize:X}u }},  /* {s.Name} */");
            off += s.RawSize;
        }
        sb.AppendLine("};");
        sb.AppendLine($"static const unsigned int g_rex_section_count = {loadable.Count};");
        sb.AppendLine();
        sb.AppendLine($"const unsigned int g_rex_image_base = 0x{xbe.BaseAddress:X8}u;");
        sb.AppendLine($"const unsigned int g_rex_ram_size  = 0x{ramSize:X8}u;");
        sb.AppendLine($"const unsigned int g_rex_entry_va  = 0x{xbe.EntryPoint:X8}u;");
        sb.AppendLine($"const unsigned int g_rex_initial_esp = 0x{initialEsp:X8}u;");
        sb.AppendLine();
        sb.AppendLine("""
            int rex_load_image(const char* bin_path) {
                FILE* f = fopen(bin_path, "rb");
                if (!f) { fprintf(stderr, "[ogxbox] cannot open %s\n", bin_path); return -1; }
                for (unsigned int i = 0; i < g_rex_section_count; i++) {
                    const RexSection* s = &g_rex_sections[i];
                    if (s->va + s->size > g_guest_ram_size) { fclose(f); return -2; }
                    if (fseek(f, s->file_off, SEEK_SET) != 0) { fclose(f); return -3; }
                    if (fread(g_guest_ram + s->va, 1, s->size, f) != s->size) { fclose(f); return -4; }
                }
                fclose(f);
                return 0;
            }
            """);
        File.WriteAllText(Path.Combine(outDir, "recomp_image.c"), sb.ToString());
    }

    private static uint RoundUp(uint v, uint a) => (v + a - 1) / a * a;
}
