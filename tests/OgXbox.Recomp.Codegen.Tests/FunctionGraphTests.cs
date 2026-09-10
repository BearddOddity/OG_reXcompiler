using OgXbox.Recomp.Codegen;
using Xunit;

namespace OgXbox.Recomp.Codegen.Tests;

public class FunctionGraphTests
{
    private static DecodedInstruction Ret(uint addr) =>
        new(addr, 1, InsnFlow.Return, 0, "ret");

    private static void DiscoverLinear(FunctionNode node, uint @base, uint end) =>
        node.Discover(
            new[] { new Block(@base, end - @base) },
            new[] { Ret(end - 1) },
            System.Array.Empty<uint>());

    [Fact]
    public void AddFunction_DefaultName_IsSubPrefixed()
    {
        var g = new FunctionGraph();
        var n = g.AddFunction(0x00201000, 0x10, FunctionAuthority.Discovered);
        Assert.Equal("sub_00201000", n.Name);
        Assert.Equal(FunctionState.Registered, n.State);
    }

    [Fact]
    public void AddFunction_HigherAuthorityReplaces_LowerIsIgnored()
    {
        var g = new FunctionGraph();
        var gapFill = g.AddFunction(0x1000, 4, FunctionAuthority.GapFill);
        Assert.Same(gapFill, g.GetFunction(0x1000));

        var config = g.AddFunction(0x1000, 0x40, FunctionAuthority.Config);
        Assert.Equal(FunctionAuthority.Config, g.GetFunction(0x1000)!.Authority);

        // lower authority now ignored, existing (Config) returned
        var again = g.AddFunction(0x1000, 4, FunctionAuthority.Discovered);
        Assert.Same(config, again);
        Assert.Equal(FunctionAuthority.Config, g.GetFunction(0x1000)!.Authority);
    }

    [Fact]
    public void GetFunctionContaining_UsesSortedBaseIndex()
    {
        var g = new FunctionGraph();
        var a = g.AddFunction(0x1000, 0x100, FunctionAuthority.Config);
        var b = g.AddFunction(0x1200, 0x100, FunctionAuthority.Config);

        Assert.Same(a, g.GetFunctionContaining(0x1050));
        Assert.Same(b, g.GetFunctionContaining(0x1200));
        Assert.Null(g.GetFunctionContaining(0x1150)); // gap between a and b
        Assert.Null(g.GetFunctionContaining(0x0900)); // before everything
    }

    [Fact]
    public void UnresolvedJump_ResolvesReactively_WhenTargetFunctionAdded()
    {
        var g = new FunctionGraph();
        var caller = g.AddFunction(0x1000, 0x20, FunctionAuthority.Config);
        DiscoverLinear(caller, 0x1000, 0x1020);

        g.AddUnresolvedJumpToFunction(0x1000, site: 0x1010, target: 0x2000,
                                      isCall: false, conditional: false);
        Assert.Single(caller.UnresolvedJumps);
        Assert.False(caller.CanSeal());

        // adding the target function fires notifyFunctionAdded -> reactive resolve
        g.AddFunction(0x2000, 0x10, FunctionAuthority.Discovered);

        Assert.Empty(caller.UnresolvedJumps);
        Assert.Single(caller.TailCalls);
        Assert.True(caller.CanSeal());
    }

    [Fact]
    public void AddUnresolvedJump_ResolvesImmediately_WhenTargetAlreadyKnown()
    {
        var g = new FunctionGraph();
        var callee = g.AddFunction(0x2000, 0x10, FunctionAuthority.Discovered);
        var caller = g.AddFunction(0x1000, 0x20, FunctionAuthority.Config);

        g.AddUnresolvedJumpToFunction(0x1000, 0x1008, 0x2000, isCall: true, conditional: false);

        Assert.Empty(caller.UnresolvedJumps);
        Assert.Single(caller.Calls);
        Assert.Same(callee, caller.Calls[0].Target.AsFunction);
    }

    [Fact]
    public void TryResolveFunction_ResolvesInternalLabel()
    {
        var g = new FunctionGraph();
        var fn = g.AddFunction(0x1000, 0x100, FunctionAuthority.Config);
        DiscoverLinear(fn, 0x1000, 0x1100);

        // jump inside our own bounds -> internal label
        g.AddUnresolvedJumpToFunction(0x1000, 0x1040, 0x1080, isCall: false, conditional: true);
        Assert.Single(fn.UnresolvedJumps);

        int resolved = g.TryResolveFunction(0x1000);
        Assert.Equal(1, resolved);
        Assert.Empty(fn.UnresolvedJumps);
        Assert.Contains(0x1080u, fn.Labels);
    }

    [Fact]
    public void Seal_MergesOverlappingBlocks()
    {
        var g = new FunctionGraph();
        var fn = g.AddFunction(0x1000, 0x10, FunctionAuthority.Config);
        fn.Discover(
            new[] { new Block(0x1000, 0x20), new Block(0x1010, 0x20), new Block(0x1100, 0x10) },
            new[] { Ret(0x110F) },
            System.Array.Empty<uint>());

        g.TrySealFunction(0x1000);
        Assert.Equal(FunctionState.Sealed, fn.State);
        Assert.Equal(2, fn.Blocks.Count);
        Assert.Equal(0x1000u, fn.Blocks[0].Base);
        Assert.Equal(0x1030u, fn.Blocks[0].End);   // 0x1000+0x20 merged with 0x1010+0x20
        Assert.Equal(0x1100u, fn.Blocks[1].Base);
    }

    [Fact]
    public void SealAll_Throws_WithReport_WhenUnresolved()
    {
        var g = new FunctionGraph();
        var fn = g.AddFunction(0x1000, 0x20, FunctionAuthority.Config);
        DiscoverLinear(fn, 0x1000, 0x1020);
        g.AddUnresolvedJumpToFunction(0x1000, 0x1010, 0xDEAD, isCall: false, conditional: false);

        var ex = Assert.Throws<System.InvalidOperationException>(() => g.SealAll());
        Assert.Contains("unresolved jumps", ex.Message);
    }

    [Fact]
    public void IsVacant_NullDwordAtBoundary_BlocksVacancy()
    {
        var g = new FunctionGraph();
        g.SetMemoryReader(addr => addr == 0x2000 ? 0u : 0x12345678u);

        Assert.False(g.IsVacant(fromAddr: 0x1000, targetAddr: 0x2000));
        Assert.True(g.IsVacant(fromAddr: 0x1000, targetAddr: 0x2004));
    }

    [Fact]
    public void IsVacant_ProtectedFunctionBlocks_GapFillDoesNot()
    {
        var g = new FunctionGraph();
        g.AddFunction(0x3000, 0x40, FunctionAuthority.Config);
        g.AddFunction(0x4000, 0x40, FunctionAuthority.GapFill);

        Assert.False(g.IsVacant(0x1000, 0x3010)); // inside a Config function
        Assert.True(g.IsVacant(0x1000, 0x4000));  // GAP_FILL entry is absorbable
    }

    [Fact]
    public void IsVacant_RegisteredChunkBlocks()
    {
        var g = new FunctionGraph();
        g.RegisterChunk(0x5000, 0x100);
        Assert.False(g.IsVacant(0x1000, 0x5080));
        Assert.True(g.IsVacant(0x1000, 0x5100));
    }

    [Fact]
    public void ClassifyTarget_Cases()
    {
        var g = new FunctionGraph();
        var caller = g.AddFunction(0x1000, 0x100, FunctionAuthority.Config);
        DiscoverLinear(caller, 0x1000, 0x1100);
        g.AddFunction(0x2000, 0x10, FunctionAuthority.Discovered);
        g.AddImportFunction(0x9000, "__imp__CreateFileA");

        Assert.Equal(TargetKind.Import, g.ClassifyTarget(0x9000, 0x1010, true));
        Assert.Equal(TargetKind.Function, g.ClassifyTarget(0x1000, 0x1010, isCallInstruction: true));   // recursion
        Assert.Equal(TargetKind.InternalLabel, g.ClassifyTarget(0x1000, 0x1010, isCallInstruction: false)); // loop to start
        Assert.Equal(TargetKind.Function, g.ClassifyTarget(0x2000, 0x1010, false)); // other entry
        Assert.Equal(TargetKind.InternalLabel, g.ClassifyTarget(0x1080, 0x1010, false)); // inside caller
        Assert.Equal(TargetKind.Unknown, g.ClassifyTarget(0xABCD, 0x1010, false));
    }

    [Fact]
    public void MarkFuncletRegisterSharing_FlagsSehHandlerBodies()
    {
        var g = new FunctionGraph();
        var owner = g.AddFunction(0x1000, 0x100, FunctionAuthority.Config);
        var handler = g.AddFunction(0x1200, 0x40, FunctionAuthority.Discovered);
        g.SetFunctionExceptionInfo(0x1000, new ExceptionInfo
        {
            Seh = new SehExceptionInfo
            {
                Scopes = { new SehScope(0x1010, 0x1050, Handler: 0x1200, Filter: 0) },
            },
        });

        int marked = g.MarkFuncletRegisterSharing();
        Assert.Equal(1, marked);
        Assert.True(handler.SharesRegisters);
        Assert.False(owner.SharesRegisters);
    }
}
