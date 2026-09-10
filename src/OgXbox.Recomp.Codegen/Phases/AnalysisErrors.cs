// Analysis error accumulator — the Validate phase's build-time gate.
//
// Ported from rex::codegen::AnalysisErrors (ReXGlue SDK, BSD-3-Clause).

using System.Collections.Generic;
using System.Linq;

namespace OgXbox.Recomp.Codegen.Phases;

public enum AnalysisErrorCategory
{
    UnresolvedCall,
    MissingJumpTable,
    JumpTargetOutOfBounds,
    DiscontinuousFunction,
    UnimplementedInstruction,
}

public readonly record struct AnalysisError(
    AnalysisErrorCategory Category, uint Target, uint Site, string Message);

public sealed class AnalysisErrors
{
    private readonly List<AnalysisError> _errors = new();

    public IReadOnlyList<AnalysisError> Errors => _errors;
    public bool HasErrors => _errors.Count > 0;
    public int Count => _errors.Count;
    public int CountOf(AnalysisErrorCategory c) => _errors.Count(e => e.Category == c);

    public void Add(AnalysisErrorCategory category, uint target, uint site, string message) =>
        _errors.Add(new AnalysisError(category, target, site, message));

    public string Report()
    {
        if (_errors.Count == 0) return "no analysis errors";
        var sb = new System.Text.StringBuilder();
        foreach (var g in _errors.GroupBy(e => e.Category))
        {
            sb.AppendLine($"{g.Key}: {g.Count()}");
            foreach (var e in g.Take(50))
                sb.AppendLine($"  0x{e.Site:X8} -> 0x{e.Target:X8}: {e.Message}");
        }
        return sb.ToString();
    }
}
