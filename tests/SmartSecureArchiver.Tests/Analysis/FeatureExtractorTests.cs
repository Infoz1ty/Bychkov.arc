using SmartSecureArchiver.Core.Analysis;

namespace SmartSecureArchiver.Tests.Analysis;

public class FeatureExtractorTests
{
    private readonly FeatureExtractor _extractor = new();

    [Fact]
    public void FeatureCount_Is52AndMatchesArraySizes()
    {
        FileFeatures features = _extractor.Extract("test data"u8);

        Assert.Equal(52, FeatureExtractor.FeatureCount);
        Assert.Equal(32, features.Histogram32.Length);
        Assert.Equal(16, features.Autocorrelation16.Length);
        Assert.Equal(
            FeatureExtractor.FeatureCount,
            1 + features.Histogram32.Length + 1 + 1 + features.Autocorrelation16.Length + 1);
    }

    [Fact]
    public void EmptyFile_ReturnsZeroVectorWithoutExceptions()
    {
        FileFeatures features = _extractor.Extract([]);

        Assert.Equal(0, features.Entropy);
        Assert.Equal(0, features.AsciiRatio);
        Assert.Equal(0, features.NewlineDistanceAvg);
        Assert.Equal(0, features.BigramEntropy);
        Assert.All(features.Histogram32, value => Assert.Equal(0, value));
        Assert.All(features.Autocorrelation16, value => Assert.Equal(0, value));
    }

    [Fact]
    public void SingleByte_ReturnsZeroEntropyAndNoExceptions()
    {
        FileFeatures features = _extractor.Extract([0x41]);

        Assert.Equal(0, features.Entropy);
        Assert.Equal(1, features.AsciiRatio);
        Assert.Equal(0, features.BigramEntropy);
        Assert.Equal(1, features.Histogram32[0x41 / 8]);
    }

    [Fact]
    public void Entropy_ConstantDataIsZero_AndAllDistinctBytesIsEight()
    {
        byte[] constant = new byte[1000];
        Array.Fill(constant, (byte)0x41);
        Assert.Equal(0, _extractor.Extract(constant).Entropy, 10);

        byte[] allValues = new byte[256];
        for (int i = 0; i < allValues.Length; i++)
        {
            allValues[i] = (byte)i;
        }

        Assert.Equal(8, _extractor.Extract(allValues).Entropy, 10);
    }

    [Fact]
    public void Histogram32_SumsToOneAndGroupsBytesByHighBits()
    {
        byte[] data = [0, 7, 8, 15, 255];
        FileFeatures features = _extractor.Extract(data);

        Assert.Equal(1.0, features.Histogram32.Sum(), 10);
        Assert.Equal(0.4, features.Histogram32[0], 10);
        Assert.Equal(0.4, features.Histogram32[1], 10);
        Assert.Equal(0.2, features.Histogram32[31], 10);
    }

    [Fact]
    public void AsciiRatio_CountsPrintableBytesAndWhitespace()
    {
        Assert.Equal(1.0, _extractor.Extract("Hello, world!\t\r\n"u8).AsciiRatio, 10);
        Assert.Equal(0.0, _extractor.Extract([0x00, 0x01, 0x80, 0xFF]).AsciiRatio, 10);
        Assert.Equal(0.5, _extractor.Extract([0x41, 0x00]).AsciiRatio, 10);
    }

    [Fact]
    public void NewlineDistanceAvg_AveragesByteGapsBetweenNewlines()
    {
        // '\n' на позиціях 2 і 5 -> середня відстань 3.
        Assert.Equal(3.0, _extractor.Extract("ab\ncd\nef"u8).NewlineDistanceAvg, 10);

        // Менше двох переводів рядка -> 0.
        Assert.Equal(0.0, _extractor.Extract("abc\ndef"u8).NewlineDistanceAvg, 10);
        Assert.Equal(0.0, _extractor.Extract("abc"u8).NewlineDistanceAvg, 10);
    }

    [Fact]
    public void Autocorrelation_AlternatingPatternHasNegativeLag1AndPositiveLag2()
    {
        byte[] alternating = new byte[512];
        for (int i = 0; i < alternating.Length; i++)
        {
            alternating[i] = i % 2 == 0 ? (byte)0 : (byte)255;
        }

        double[] autocorrelation = _extractor.Extract(alternating).Autocorrelation16;

        Assert.Equal(-1.0, autocorrelation[0], 10);
        Assert.Equal(1.0, autocorrelation[1], 10);
        Assert.Equal(-1.0, autocorrelation[2], 10);
    }

    [Fact]
    public void Autocorrelation_ConstantDataIsZero()
    {
        byte[] constant = new byte[128];
        Array.Fill(constant, (byte)42);

        Assert.All(_extractor.Extract(constant).Autocorrelation16, value => Assert.Equal(0, value));
    }

    [Fact]
    public void BigramEntropy_TwoEquallyLikelyBigramsIsOneBit()
    {
        // "ababa" дає лише пари "ab" і "ba", обидві по 2 рази.
        Assert.Equal(1.0, _extractor.Extract("ababa"u8).BigramEntropy, 10);
        Assert.Equal(0.0, _extractor.Extract("aaaa"u8).BigramEntropy, 10);
    }

    [Fact]
    public void Extract_IsDeterministicForSameInput()
    {
        byte[] data = "deterministic input for feature extraction"u8.ToArray();

        FileFeatures first = _extractor.Extract(data);
        FileFeatures second = _extractor.Extract(data);

        Assert.Equal(first.Entropy, second.Entropy);
        Assert.Equal(first.Histogram32, second.Histogram32);
        Assert.Equal(first.Autocorrelation16, second.Autocorrelation16);
        Assert.Equal(first.BigramEntropy, second.BigramEntropy);
    }
}
