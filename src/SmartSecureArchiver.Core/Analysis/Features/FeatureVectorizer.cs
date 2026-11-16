namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Перетворює <see cref="FileFeatures"/> у плоский вектор фіксованого порядку для MLP.
/// Порядок: Entropy, Histogram32[0..31], AsciiRatio, NewlineDistanceAvg,
/// Autocorrelation16[0..15], BigramEntropy. Зміна порядку вимагає перенавчання моделі.
/// </summary>
public static class FeatureVectorizer
{
    public const int Size = FeatureExtractor.FeatureCount;

    public static double[] ToVector(FileFeatures features)
    {
        ArgumentNullException.ThrowIfNull(features);

        double[] vector = new double[Size];
        int index = 0;

        vector[index++] = features.Entropy;

        foreach (double bucket in features.Histogram32)
        {
            vector[index++] = bucket;
        }

        vector[index++] = features.AsciiRatio;
        vector[index++] = features.NewlineDistanceAvg;

        foreach (double coefficient in features.Autocorrelation16)
        {
            vector[index++] = coefficient;
        }

        vector[index] = features.BigramEntropy;
        return vector;
    }
}
