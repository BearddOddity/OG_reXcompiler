// TOML config loader — ported to C# / x86 from rex::codegen config.cpp
// (ReXGlue SDK, BSD-3-Clause; itself based on XenonRecomp/UnleashedRecomp).
//
// x86 changes: no 4-byte alignment checks (x86 is unaligned), no PPC-register
// local-variable toggles, no rexcrt heap group. Added an [[seeds]] array (the
// x86 analogue of the X-Men project's seed_list.json).
//
// Supported schema:
//   project_name / file_path / out_directory_path      (string scalars)
//   generate_exception_handlers                        (bool)
//   longjmp_address / setjmp_address                    (int)
//   [analysis] max_jump_extension / data_region_threshold /
//              large_function_threshold / min_null_run /
//              exception_handler_funcs = [ ... ]
//   [functions]  "0xADDR" = { size|end, name, parent, share_registers }
//   [[switch_tables]]  address, register, labels = [ ... ]
//   [[midasm_hook]]    address, name, registers, return*, jump_address*, after_instruction
//   [[invalid_instructions]]  data, size
//   seeds = [ 0x..., ... ]
//   indirect_calls = [ 0x..., ... ]
//   includes = [ "other.toml", ... ]     (depth-first, this file's values win)

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Tomlyn.Model;

namespace OgXbox.Recomp.Codegen.Phases;

public sealed class ConfigValidation
{
    public bool Valid { get; set; } = true;
    public List<string> Errors { get; } = new();
    public List<string> Warnings { get; } = new();
}

public static class RecompilerConfigLoader
{
    private const int MaxIncludeDepth = 32;

    public static RecompilerConfig Load(string path, out ConfigValidation validation)
    {
        var cfg = new RecompilerConfig();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        LoadRecursive(Path.GetFullPath(path), cfg, visited, 0);
        validation = Validate(cfg);
        return cfg;
    }

    private static void LoadRecursive(string path, RecompilerConfig cfg,
                                      HashSet<string> visited, int depth)
    {
        if (depth > MaxIncludeDepth)
            throw new InvalidOperationException($"config include depth exceeds {MaxIncludeDepth}: {path}");

        string canonical = Path.GetFullPath(path);
        if (!visited.Add(canonical))
            throw new InvalidOperationException($"circular config include: {canonical}");
        if (!File.Exists(canonical))
            throw new FileNotFoundException($"config not found: {canonical}");

        TomlTable model = Tomlyn.Toml.ToModel(File.ReadAllText(canonical), canonical);
        string baseDir = Path.GetDirectoryName(canonical)!;

        // Depth-first includes so this file's own values win.
        if (model.TryGetValue("includes", out var inc) && inc is TomlArray incList)
            foreach (var item in incList.OfType<string>())
                LoadRecursive(Path.Combine(baseDir, item), cfg, visited, depth + 1);

        Apply(model, cfg);
    }

    private static void Apply(TomlTable t, RecompilerConfig cfg)
    {
        Str(t, "project_name", v => cfg.ProjectName = v);
        Str(t, "file_path", v => cfg.FilePath = v);
        Str(t, "out_directory_path", v => cfg.OutDirectoryPath = v);
        Bool(t, "generate_exception_handlers", v => cfg.GenerateExceptionHandlers = v);

        if (t.TryGetValue("analysis", out var a) && a is TomlTable an)
        {
            U32(an, "max_jump_extension", v => cfg.MaxJumpExtension = v);
            U32(an, "data_region_threshold", v => cfg.DataRegionThreshold = v);
            U32(an, "large_function_threshold", v => cfg.LargeFunctionThreshold = v);
            U32(an, "min_null_run", v => cfg.MinNullRun = v);
            if (an.TryGetValue("exception_handler_funcs", out var eh) && eh is TomlArray eha)
                foreach (var x in eha) cfg.ExceptionHandlerHints.Add(ToU32(x));
        }

        // seeds / indirect_calls are top-level arrays — they must appear BEFORE
        // any [section] in the TOML file or they bind to that section instead.
        foreach (var arrKey in new[] { "seeds", "indirect_calls" })
            if (t.TryGetValue(arrKey, out var av) && av is TomlArray aa)
                foreach (var x in aa)
                    (arrKey == "seeds" ? cfg.SeedFunctions : cfg.ExceptionHandlerHints).Add(ToU32(x));

        if (t.TryGetValue("functions", out var f) && f is TomlTable ft)
            foreach (var (key, val) in ft)
            {
                if (val is not TomlTable e) continue;
                uint addr = ParseHex(key);
                uint size = U32Or(e, "size", 0);
                uint end = U32Or(e, "end", 0);
                if (size != 0 && end != 0)
                    throw new InvalidOperationException($"function 0x{addr:X8}: both size and end");
                cfg.Functions[addr] = new FunctionConfig
                {
                    Size = size,
                    End = end,
                    Name = e.TryGetValue("name", out var n) ? n as string : null,
                    Parent = U32Or(e, "parent", 0),
                    ShareRegisters = BoolOr(e, "share_registers", false),
                };
            }

        ForEachArrayTable(t, "switch_tables", e =>
        {
            uint addr = U32Or(e, "address", 0);
            var jt = new JumpTable
            {
                JumpAddress = addr,
                IndexRegister = (byte)U32Or(e, "register", 0),
            };
            if (e.TryGetValue("labels", out var lbls) && lbls is TomlArray la)
                jt.Targets.AddRange(la.Select(ToU32));
            if (jt.Targets.Count > 0) cfg.SwitchTables[addr] = jt;
        });

        ForEachArrayTable(t, "midasm_hook", e =>
        {
            uint addr = U32Or(e, "address", 0);
            var hook = new MidAsmHook
            {
                Name = (e.TryGetValue("name", out var nm) ? nm as string : null) ?? $"hook_{addr:X8}",
                Return = BoolOr(e, "return", false),
                ReturnOnTrue = BoolOr(e, "return_on_true", false),
                ReturnOnFalse = BoolOr(e, "return_on_false", false),
                JumpAddress = U32Or(e, "jump_address", 0),
                JumpAddressOnTrue = U32Or(e, "jump_address_on_true", 0),
                JumpAddressOnFalse = U32Or(e, "jump_address_on_false", 0),
                AfterInstruction = BoolOr(e, "after_instruction", false),
            };
            if (e.TryGetValue("registers", out var rr) && rr is TomlArray ra)
                hook.Registers.AddRange(ra.OfType<string>());
            cfg.MidAsmHooks[addr] = hook;
        });
    }

    public static ConfigValidation Validate(RecompilerConfig cfg)
    {
        var r = new ConfigValidation();

        // Duplicate / conflicting function boundaries.
        var seen = new Dictionary<uint, uint>();
        foreach (var (addr, fc) in cfg.Functions)
        {
            uint sz = fc.EffectiveSize(addr);
            if (seen.TryGetValue(addr, out var prev))
            {
                r.Errors.Add(prev == sz
                    ? $"duplicate function boundary: 0x{addr:X8} size 0x{sz:X}"
                    : $"conflicting sizes at 0x{addr:X8}: 0x{prev:X} vs 0x{sz:X}");
                r.Valid = false;
            }
            seen[addr] = sz;
        }

        // Overlapping standalone functions.
        var sorted = cfg.Functions
            .Where(kv => !kv.Value.IsChunk)
            .Select(kv => (kv.Key, Size: kv.Value.EffectiveSize(kv.Key)))
            .OrderBy(x => x.Key).ToList();
        for (int i = 1; i < sorted.Count; i++)
        {
            uint prevEnd = sorted[i - 1].Key + sorted[i - 1].Size;
            if (sorted[i].Key < prevEnd)
            {
                r.Errors.Add($"overlapping boundaries: 0x{sorted[i - 1].Key:X8}+0x{sorted[i - 1].Size:X} " +
                             $"overlaps 0x{sorted[i].Key:X8}");
                r.Valid = false;
            }
        }

        if (string.IsNullOrEmpty(cfg.FilePath)) r.Warnings.Add("file_path is empty");
        if (string.IsNullOrEmpty(cfg.OutDirectoryPath)) r.Warnings.Add("out_directory_path is empty");
        return r;
    }

    //=====================================================================

    private static void ForEachArrayTable(TomlTable t, string key, Action<TomlTable> fn)
    {
        if (t.TryGetValue(key, out var v) && v is TomlTableArray arr)
            foreach (var e in arr) fn(e);
    }

    private static void Str(TomlTable t, string k, Action<string> set)
    {
        if (t.TryGetValue(k, out var v) && v is string s) set(s);
    }
    private static void Bool(TomlTable t, string k, Action<bool> set)
    {
        if (t.TryGetValue(k, out var v) && v is bool b) set(b);
    }
    private static void U32(TomlTable t, string k, Action<uint> set)
    {
        if (t.TryGetValue(k, out var v)) set(ToU32(v));
    }
    private static uint U32Or(TomlTable t, string k, uint dflt) =>
        t.TryGetValue(k, out var v) ? ToU32(v) : dflt;
    private static bool BoolOr(TomlTable t, string k, bool dflt) =>
        t.TryGetValue(k, out var v) && v is bool b ? b : dflt;

    private static uint ToU32(object? v) => v switch
    {
        long l => unchecked((uint)l),
        int i => unchecked((uint)i),
        string s => ParseHex(s),
        _ => 0,
    };

    private static uint ParseHex(string s)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h)
            ? h
            : uint.Parse(s, CultureInfo.InvariantCulture);
    }
}
