namespace SmartSecureArchiver.Core.Optimization;

public sealed record GeneticParameters(int WindowSize, int MinMatchLength, double NoCompressionEntropyThreshold);
