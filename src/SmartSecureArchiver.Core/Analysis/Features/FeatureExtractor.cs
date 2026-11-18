using System.Buffers;

namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Обчислює фіксований вектор із 52 статистичних ознак файлу (Issue #21).
/// Порядок ознак є частиною контракту з MLP і не може змінюватися без перенавчання моделі:
/// Entropy (1), Histogram32 (32), AsciiRatio (1), NewlineDistanceAvg (1),
/// Autocorrelation16 (16), BigramEntropy (1).
/// Усі ознаки збираються за один прохід по вхідних даних: гістограма, частка ASCII,
/// відстані між переводами рядка, суми байтів і квадратів байтів, лічильники біграм.
/// Для автокореляції лише сума добутків вимагає O(lag) проходів, а суми рядків/стовпців
/// та їхні квадрати відновлюються з повних сум і крайових відрізків за O(1) на лаг.
/// </summary>
public sealed class FeatureExtractor : IFeatureExtractor
{
    public const int HistogramBucketCount = 32;
    public const int AutocorrelationLags = 16;
    public const int FeatureCount = 1 + HistogramBucketCount + 1 + 1 + AutocorrelationLags + 1;

    private const int ByteValueCount = 256;
    private const int BytesPerHistogramBucket = ByteValueCount / HistogramBucketCount;
    private const int BigramValueCount = ByteValueCount * ByteValueCount;
    private const byte NewlineByte = (byte)'\n';
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
        byteCounts.Clear();

        int printableCount = 0;
        int previousNewlineIndex = -1;
        long newlineDistanceTotal = 0;
        int newlineGaps = 0;
        long totalSum = 0;
        long totalSquareSum = 0;

        int[]? bigramCounts = fileData.Length >= 2
            ? ArrayPool<int>.Shared.Rent(BigramValueCount)
            : null;

        double bigramEntropy = 0;

        try
        {
            if (bigramCounts is not null)
            {
                Array.Clear(bigramCounts, 0, BigramValueCount);
            }

            for (int i = 0; i < fileData.Length; i++)
            {
                byte value = fileData[i];
                byteCounts[value]++;
                totalSum += value;
                totalSquareSum += value * value;

                if (IsPrintableAscii(value))
                {
                    printableCount++;
                }

                if (value == NewlineByte)
                {
                    if (previousNewlineIndex >= 0)
                    {
                        newlineDistanceTotal += i - previousNewlineIndex;
                        newlineGaps++;
                    }

                    previousNewlineIndex = i;
                }

                if (bigramCounts is not null && i > 0)
                {
                    bigramCounts[(fileData[i - 1] << 8) | value]++;
                }
            }

            if (bigramCounts is not null)
            {
                bigramEntropy = ComputeBigramEntropy(bigramCounts, fileData.Length - 1);
            }
        }
        finally
        {
            if (bigramCounts is not null)
            {
                ArrayPool<int>.Shared.Return(bigramCounts);
            }
        }

        return new FileFeatures(
            Entropy: ComputeEntropy(byteCounts, fileData.Length),
            Histogram32: ComputeHistogram32(byteCounts, fileData.Length),
            AsciiRatio: (double)printableCount / fileData.Length,
            NewlineDistanceAvg: newlineGaps == 0 ? 0 : (double)newlineDistanceTotal / newlineGaps,
            Autocorrelation16: ComputeAutocorrelation16(
                fileData,
                totalSum,
                totalSquareSum),
            BigramEntropy: bigramEntropy);
    }

    private static bool IsPrintableAscii(byte value) =>
        value is >= 0x20 and <= 0x7E || value is 0x09 or 0x0A or 0x0D;

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

    /// <summary>
    /// Коефіцієнт кореляції Пірсона між байтами на відстані lag (lag = 1..16).
    /// Для постійних або занадто коротких даних повертає 0.
    /// </summary>
    private static double[] ComputeAutocorrelation16(
        ReadOnlySpan<byte> data,
        long totalSum,
        long totalSquareSum)
    {
        double[] result = new double[AutocorrelationLags];

        int lagLimit = Math.Min(AutocorrelationLags, data.Length);
        Span<long> headSum = stackalloc long[AutocorrelationLags + 1];
        Span<long> headSquareSum = stackalloc long[AutocorrelationLags + 1];
        Span<long> tailSum = stackalloc long[AutocorrelationLags + 1];
        Span<long> tailSquareSum = stackalloc long[AutocorrelationLags + 1];
        headSum.Clear();
        headSquareSum.Clear();
        tailSum.Clear();
        tailSquareSum.Clear();

        for (int lag = 1; lag <= lagLimit; lag++)
        {
            long headValue = data[lag - 1];
            long tailValue = data[data.Length - lag];
            headSum[lag] = headSum[lag - 1] + headValue;
            headSquareSum[lag] = headSquareSum[lag - 1] + headValue * headValue;
            tailSum[lag] = tailSum[lag - 1] + tailValue;
            tailSquareSum[lag] = tailSquareSum[lag - 1] + tailValue * tailValue;
        }

        for (int lag = 1; lag <= AutocorrelationLags; lag++)
        {
            int pairCount = data.Length - lag;
            if (pairCount < 2)
            {
                continue;
            }

            long sumXy = 0;
            for (int i = 0; i < pairCount; i++)
            {
                sumXy += (long)data[i] * data[i + lag];
            }

            double sumX = totalSum - tailSum[lag];
            double sumY = totalSum - headSum[lag];
            double sumXx = totalSquareSum - tailSquareSum[lag];
            double sumYy = totalSquareSum - headSquareSum[lag];

            double meanX = sumX / pairCount;
            double meanY = sumY / pairCount;
            double covariance = (sumXy / (double)pairCount) - (meanX * meanY);
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

    private static double ComputeBigramEntropy(ReadOnlySpan<int> bigramCounts, int pairCount)
    {
        if (pairCount <= 0)
        {
            return 0;
        }

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
}
