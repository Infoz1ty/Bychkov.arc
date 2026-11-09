namespace SmartSecureArchiver.Core.Analysis;

public sealed record FileFeatures(
    double Entropy,
    double[] Histogram32,
    double AsciiRatio,
    double NewlineDistanceAvg,
    double[] Autocorrelation16,
    double BigramEntropy
);
