namespace SmartSecureArchiver.Core.Packing;

public sealed record PackingResult(
    IReadOnlyList<BlockCandidate> SelectedBlocks,
    IReadOnlyList<BlockCandidate> RemainingBlocks,
    int TotalWeight,
    int TotalValue
);
