using System.Buffers;

namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Обчислює фіксований вектор із 52 статистичних ознак файлу (Issue #21).
/// Порядок ознак є частиною контракту з MLP і не може змінюватися без перенавчання моделі:
/// Entropy (1), Histogram32 (32), AsciiRatio (1), NewlineDistanceAvg (1),
/// Autocorrelation16 (16), BigramEntropy (1).
/// </summary>
public sealed class FeatureExtractor : IFeatureExtractor
{
    public const int HistogramBucketCount = 32;
    public const int AutocorrelationLags = 16;
    public const int FeatureCount = 1 + HistogramBucketCount + 1 + 1 + AutocorrelationLags + 1;

    private const int ByteValueCount = 256;
    private const int BytesPerHistogramBucket = ByteValueCount / HistogramBucketCount;
    private const int BigramValueCount = ByteValueCount * ByteValueCount;
    private const double Epsilon = 1e-12;

    /// <inheritdoc />
    public FileFeatures Extract(ReadOnlySpan<byte> fileData)
    {
        if (fileData.IsEmpty)
        {
            return new FileFeatures(
                Entropy: 0,
                Histogram32: new double[HistogramBucketCount],
                AsciiRatio: 0,
                NewlineDistanceAvg: 0,
                Autocorrelation16: new double[AutocorrelationLags],
                BigramEntropy: 0);
        }

        Span<int> byteCounts = stackalloc int[ByteValueCount];
        foreach (byte value in fileData)
        {
            byteCounts[value]++;
        }

        return new FileFeatures(
            Entropy: ComputeEntropy(byteCounts, fileData.Length),
            Histogram32: ComputeHistogram32(byteCounts, fileData.Length),
            AsciiRatio: ComputeAsciiRatio(fileData),
            NewlineDistanceAvg: ComputeNewlineDistanceAvg(fileData),
            Autocorrelation16: ComputeAutocorrelation16(fileData),
            BigramEntropy: ComputeBigramEntropy(fileData));
    }

    private static double ComputeEntropy(ReadOnlySpan<int> byteCounts, int length)
    {
        double entropy = 0;
        for (int i = 0; i < ByteValueCount; i++)
        {
            int count = byteCounts[i];
            if (count == 0)
            {
                continue;
            }

            double probability = (double)count / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static double[] ComputeHistogram32(ReadOnlySpan<int> byteCounts, int length)
    {
        double[] histogram = new double[HistogramBucketCount];
        for (int bucket = 0; bucket < HistogramBucketCount; bucket++)
        {
            int start = bucket * BytesPerHistogramBucket;
            int sum = 0;
            for (int i = 0; i < BytesPerHistogramBucket; i++)
            {
                sum += byteCounts[start + i];
            }

            histogram[bucket] = (double)sum / length;
        }

        return histogram;
    }

    private static double ComputeAsciiRatio(ReadOnlySpan<byte> data)
    {
        int printable = 0;
        foreach (byte value in data)
        {
            if (value is >= 0x20 and <= 0x7E || value is 0x09 or 0x0A or 0x0D)
            {
                printable++;
            }
        }

        return (double)printable / data.Length;
    }

    private static double ComputeNewlineDistanceAvg(ReadOnlySpan<byte> data)
    {
        const byte newline = (byte)'\n';

        int previousIndex = -1;
        long totalDistance = 0;
        int gaps = 0;

        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] != newline)
            {
                continue;
            }

            if (previousIndex >= 0)
            {
                totalDistance += i - previousIndex;
                gaps++;
            }

            previousIndex = i;
        }

        return gaps == 0 ? 0 : (double)totalDistance / gaps;
    }

    /// <summary>
    /// Коефіцієнт кореляції Пірсона між байтами на відстані lag (lag = 1..16).
    /// Для постійних або занадто коротких даних повертає 0.
    /// </summary>
    private static double[] ComputeAutocorrelation16(ReadOnlySpan<byte> data)
    {
        double[] result = new double[AutocorrelationLags];

        for (int lag = 1; lag <= AutocorrelationLags; lag++)
        {
            int pairCount = data.Length - lag;
            if (pairCount < 2)
            {
                continue;
            }

            double sumX = 0;
            double sumY = 0;
            double sumXx = 0;
            double sumYy = 0;
            double sumXy = 0;

            for (int i = 0; i < pairCount; i++)
            {
                double x = data[i];
                double y = data[i + lag];
                sumX += x;
                sumY += y;
                sumXx += x * x;
                sumYy += y * y;
                sumXy += x * y;
            }

            double meanX = sumX / pairCount;
            double meanY = sumY / pairCount;
            double covariance = (sumXy / pairCount) - (meanX * meanY);
            double varianceX = (sumXx / pairCount) - (meanX * meanX);
            double varianceY = (sumYy / pairCount) - (meanY * meanY);
            double denominator = Math.Sqrt(varianceX * varianceY);

            if (denominator <= Epsilon)
            {
                continue;
            }

            result[lag - 1] = Math.Clamp(covariance / denominator, -1.0, 1.0);
        }

        return result;
    }

    private static double ComputeBigramEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return 0;
        }

        int[] bigramCounts = ArrayPool<int>.Shared.Rent(BigramValueCount);
        try
        {
            Array.Clear(bigramCounts, 0, BigramValueCount);

            for (int i = 1; i < data.Length; i++)
            {
                int bigram = (data[i - 1] << 8) | data[i];
                bigramCounts[bigram]++;
            }

            int pairCount = data.Length - 1;
            double entropy = 0;

            for (int i = 0; i < BigramValueCount; i++)
            {
                int count = bigramCounts[i];
                if (count == 0)
                {
                    continue;
                }

                double probability = (double)count / pairCount;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }
        finally
        {
            ArrayPool<int>.Shared.Return(bigramCounts);
        }
    }
}
