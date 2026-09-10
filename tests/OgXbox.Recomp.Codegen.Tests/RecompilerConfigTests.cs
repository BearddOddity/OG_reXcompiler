using System.IO;
using OgXbox.Recomp.Codegen.Phases;
using Xunit;

namespace OgXbox.Recomp.Codegen.Tests;

public class RecompilerConfigTests
{
    private static string Write(string toml)
    {
        var p = Path.Combine(Path.GetTempPath(), "ogx_" + System.Guid.NewGuid().ToString("N") + ".toml");
        File.WriteAllText(p, toml);
        return p;
    }

    [Fact]
    public void Loads_Scalars_Seeds_SwitchTables_Hooks_Functions()
    {
        var p = Write("""
            project_name = "xmen"
            file_path = "game/default.xbe"
            out_directory_path = "out"
            seeds = [ 0x00201000, 0x00202000 ]
            indirect_calls = [ 0x00203050 ]

            [analysis]
            min_null_run = 12
            data_region_threshold = 20
            exception_handler_funcs = [ 0x00343000 ]

            [functions]
            "0x00210000" = { size = 0x40, name = "sub_special", share_registers = true }
            "0x00220000" = { end = 0x00220080 }

            [[switch_tables]]
            address = 0x00230abc
            register = 0
            labels = [ 0x00230100, 0x00230120, 0x00230140 ]

            [[midasm_hook]]
            address = 0x00240000
            name = "MyHook"
            registers = [ "eax", "ecx" ]
            after_instruction = true
            """);

        var cfg = RecompilerConfigLoader.Load(p, out var v);
        Assert.True(v.Valid, string.Join("; ", v.Errors));
        Assert.Equal("xmen", cfg.ProjectName);
        Assert.Equal(12u, cfg.MinNullRun);
        Assert.Equal(20u, cfg.DataRegionThreshold);
        Assert.Contains(0x00201000u, cfg.SeedFunctions);
        Assert.Contains(0x00202000u, cfg.SeedFunctions);

        Assert.Equal(0x40u, cfg.Functions[0x00210000].Size);
        Assert.Equal("sub_special", cfg.Functions[0x00210000].Name);
        Assert.True(cfg.Functions[0x00210000].ShareRegisters);
        Assert.Equal(0x80u, cfg.Functions[0x00220000].EffectiveSize(0x00220000));

        var jt = cfg.SwitchTables[0x00230abc];
        Assert.Equal(3, jt.Targets.Count);
        Assert.Contains(0x00230120u, jt.Targets);

        Assert.Equal("MyHook", cfg.MidAsmHooks[0x00240000].Name);
        Assert.True(cfg.MidAsmHooks[0x00240000].AfterInstruction);
        Assert.Equal(new[] { "eax", "ecx" }, cfg.MidAsmHooks[0x00240000].Registers);

        File.Delete(p);
    }

    [Fact]
    public void Validate_Flags_OverlappingFunctions()
    {
        var p = Write("""
            file_path = "x"
            [functions]
            "0x1000" = { size = 0x100 }
            "0x1080" = { size = 0x40 }
            """);
        RecompilerConfigLoader.Load(p, out var v);
        Assert.False(v.Valid);
        Assert.Contains(v.Errors, e => e.Contains("verlap"));
        File.Delete(p);
    }

    [Fact]
    public void Includes_AreMerged_LocalValuesWin()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ogx_" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "base.toml"), "project_name = \"base\"\nseeds = [ 0x1000 ]\n");
        var main = Path.Combine(dir, "main.toml");
        File.WriteAllText(main, "includes = [ \"base.toml\" ]\nproject_name = \"main\"\nseeds = [ 0x2000 ]\n");

        var cfg = RecompilerConfigLoader.Load(main, out var v);
        Assert.True(v.Valid);
        Assert.Equal("main", cfg.ProjectName);           // local wins
        Assert.Contains(0x1000u, cfg.SeedFunctions);      // sets are additive
        Assert.Contains(0x2000u, cfg.SeedFunctions);

        Directory.Delete(dir, true);
    }
}
