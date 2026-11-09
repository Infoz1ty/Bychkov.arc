namespace SmartSecureArchiver.Core.Packing;

public sealed record BlockCandidate(
    int BlockId,
    int Weight,
    int Value,
    byte[]? Data = null
);
