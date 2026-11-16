namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Класифікатор файлів на базі навченого MLP (Issues #22–#25).
/// Клас 5 («вже стиснуте») та дані з ентропією вище порогу ніколи не стискаються.
/// </summary>
public sealed class MlpClassifier : IFileClassifier
{
    public const double DefaultNoCompressionEntropyThreshold = 7.95;
    public const byte AlreadyCompressedClass = 5;

    private readonly MlpNetwork _network;
    private readonly FeatureNormalizer _normalizer;

    public MlpClassifier(MlpNetwork network, FeatureNormalizer normalizer)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(normalizer);

        if (normalizer.Mean.Length != network.InputSize)
        {
            throw new ArgumentException("Normalizer dimension does not match network input size.", nameof(normalizer));
        }

        _network = network;
        _normalizer = normalizer;
    }

    public MlpNetwork Network => _network;

    public FeatureNormalizer Normalizer => _normalizer;

    /// <inheritdoc />
    public byte Classify(FileFeatures features)
    {
        double[] vector = FeatureVectorizer.ToVector(features);
        double[] normalized = _normalizer.Transform(vector);
        return ModelMetrics.ArgMax(_network.Forward(normalized));
    }

    /// <inheritdoc />
    public bool ShouldCompress(
        byte fileClass,
        FileFeatures features,
        double noCompressionEntropyThreshold = DefaultNoCompressionEntropyThreshold)
    {
        ArgumentNullException.ThrowIfNull(features);

        if (fileClass == AlreadyCompressedClass)
        {
            return false;
        }

        return features.Entropy < noCompressionEntropyThreshold;
    }

    public static MlpClassifier Load(string path)
    {
        (MlpNetwork network, FeatureNormalizer normalizer) = MlpModelSerializer.Load(path);
        return new MlpClassifier(network, normalizer);
    }

    public void Save(string path)
    {
        MlpModelSerializer.Save(path, _network, _normalizer);
    }
}
