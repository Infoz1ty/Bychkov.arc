using SmartSecureArchiver.Core.Analysis;

namespace SmartSecureArchiver.Core.Optimization;

/// <summary>
/// Адаптер IFileClassifier, що перевизначає поріг ентропії відмови від стиснення
/// (no_comp_threshold) параметром хромосоми ГА без зміни інтерфейсу IFileClassifier.
/// </summary>
public sealed class ParameterizedFileClassifier : IFileClassifier
{
    private readonly IFileClassifier _inner;
    private readonly double _noCompressionEntropyThreshold;

    public ParameterizedFileClassifier(IFileClassifier inner, double noCompressionEntropyThreshold)
    {
        ArgumentNullException.ThrowIfNull(inner);

        if (double.IsNaN(noCompressionEntropyThreshold) || double.IsInfinity(noCompressionEntropyThreshold))
        {
            throw new ArgumentOutOfRangeException(nameof(noCompressionEntropyThreshold), "Threshold must be finite.");
        }

        _inner = inner;
        _noCompressionEntropyThreshold = noCompressionEntropyThreshold;
    }

    public double NoCompressionEntropyThreshold => _noCompressionEntropyThreshold;

    /// <inheritdoc />
    public byte Classify(FileFeatures features) => _inner.Classify(features);

    /// <inheritdoc />
    public bool ShouldCompress(byte fileClass, FileFeatures features, double noCompressionEntropyThreshold = 7.95)
    {
        return _inner.ShouldCompress(fileClass, features, _noCompressionEntropyThreshold);
    }
}
