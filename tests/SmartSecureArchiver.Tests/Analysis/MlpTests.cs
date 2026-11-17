using SmartSecureArchiver.Core.Analysis;

namespace SmartSecureArchiver.Tests.Analysis;

public class MlpTests
{
    [Fact]
    public void FeatureVectorizer_UsesFixedOrderAndSize()
    {
        FileFeatures features = new(
            Entropy: 1,
            Histogram32: Enumerable.Repeat(2.0, 32).ToArray(),
            AsciiRatio: 3,
            NewlineDistanceAvg: 4,
            Autocorrelation16: Enumerable.Repeat(5.0, 16).ToArray(),
            BigramEntropy: 6);

        double[] vector = FeatureVectorizer.ToVector(features);

        Assert.Equal(52, vector.Length);
        Assert.Equal(1, vector[0]);
        Assert.All(vector[1..33], value => Assert.Equal(2, value));
        Assert.Equal(3, vector[33]);
        Assert.Equal(4, vector[34]);
        Assert.All(vector[35..51], value => Assert.Equal(5, value));
        Assert.Equal(6, vector[51]);
    }

    [Fact]
    public void Softmax_SumsToOneAndDoesNotOverflow()
    {
        double[] probabilities = MlpNetwork.Softmax([1000, 1001, 999]);

        Assert.Equal(1.0, probabilities.Sum(), 10);
        Assert.All(probabilities, value => Assert.InRange(value, 0, 1));
    }

    [Fact]
    public void Network_ForwardReturnsOutputSizeAndIsDeterministic()
    {
        MlpNetwork network = MlpNetwork.CreateRandom(52, 16, 7, seed: 10);
        double[] input = Enumerable.Range(0, 52).Select(i => i * 0.01).ToArray();

        double[] first = network.Forward(input);
        double[] second = network.Forward(input);

        Assert.Equal(7, first.Length);
        Assert.Equal(first, second);
        Assert.Equal(1.0, first.Sum(), 10);
    }

    [Fact]
    public void Network_SameSeedProducesSameWeights()
    {
        MlpNetwork first = MlpNetwork.CreateRandom(4, 3, 2, seed: 42);
        MlpNetwork second = MlpNetwork.CreateRandom(4, 3, 2, seed: 42);

        AssertMatrixEqual(first.HiddenWeights, second.HiddenWeights);
        AssertMatrixEqual(first.OutputWeights, second.OutputWeights);
        Assert.Equal(first.HiddenBiases, second.HiddenBiases);
    }

    [Fact]
    public void Trainer_LearnsTwoClusters()
    {
        (FeatureNormalizer normalizer, List<LabeledSample> samples) = CreateTwoClusterSamples();
        MlpNetwork network = MlpNetwork.CreateRandom(2, 8, 2, seed: 7);
        var trainer = new MlpTrainer(new TrainingOptions(
            Epochs: 150,
            BatchSize: 16,
            LearningRate: 0.1,
            LearningRateDecay: 1.0,
            ShuffleSeed: 5));

        TrainingHistory history = trainer.Train(network, samples);
        EvaluationReport report = ModelMetrics.Evaluate(network, samples, classCount: 2);

        Assert.True(history.FinalLoss < history.InitialLoss);
        Assert.True(report.Accuracy >= 0.95, $"Accuracy was {report.Accuracy:F3}.");
        Assert.True(report.MacroF1 >= 0.95, $"Macro-F1 was {report.MacroF1:F3}.");
    }

    [Fact]
    public void Trainer_IsDeterministicForSameSeed()
    {
        (_, List<LabeledSample> samples) = CreateTwoClusterSamples();

        MlpNetwork first = MlpNetwork.CreateRandom(2, 8, 2, seed: 11);
        MlpNetwork second = MlpNetwork.CreateRandom(2, 8, 2, seed: 11);
        var trainer = new MlpTrainer(new TrainingOptions(Epochs: 20, BatchSize: 16, ShuffleSeed: 3));

        trainer.Train(first, samples);
        trainer.Train(second, samples);

        AssertMatrixEqual(first.HiddenWeights, second.HiddenWeights);
        AssertMatrixEqual(first.OutputWeights, second.OutputWeights);
    }

    [Fact]
    public void Serializer_RoundTripsWeightsAndPredictions()
    {
        MlpNetwork network = MlpNetwork.CreateRandom(6, 5, 3, seed: 99);
        var normalizer = new FeatureNormalizer(
            Enumerable.Repeat(0.5, 6).ToArray(),
            Enumerable.Repeat(2.0, 6).ToArray());
        string path = Path.Combine(Path.GetTempPath(), $"sarc-mlp-{Guid.NewGuid():N}.bin");

        try
        {
            MlpModelSerializer.Save(path, network, normalizer);
            (MlpNetwork loaded, FeatureNormalizer loadedNormalizer) = MlpModelSerializer.Load(path);

            double[] input = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6];
            Assert.Equal(normalizer.Mean, loadedNormalizer.Mean);
            Assert.Equal(normalizer.StandardDeviation, loadedNormalizer.StandardDeviation);
            Assert.Equal(network.Forward(input), loaded.Forward(input));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void Metrics_PerfectConfusionHasMacroF1One()
    {
        int[,] confusion =
        {
            { 5, 0, 0 },
            { 0, 5, 0 },
            { 0, 0, 5 }
        };

        EvaluationReport report = ModelMetrics.FromConfusionMatrix(confusion, sampleCount: 15);

        Assert.Equal(1.0, report.Accuracy, 10);
        Assert.Equal(1.0, report.MacroF1, 10);
    }

    [Fact]
    public void Metrics_ComputesMacroF1FromKnownConfusionMatrix()
    {
        int[,] confusion =
        {
            { 8, 2, 0 },
            { 0, 9, 1 },
            { 1, 0, 9 }
        };

        EvaluationReport report = ModelMetrics.FromConfusionMatrix(confusion, sampleCount: 30);

        Assert.Equal(26.0 / 30, report.Accuracy, 10);
        Assert.Equal(8.0 / 9, report.Classes[0].Precision, 10);
        Assert.Equal(8.0 / 10, report.Classes[0].Recall, 10);
        Assert.Equal(0.9, report.Classes[2].F1, 10);
        Assert.Equal(0.866416, report.MacroF1, 5);
    }

    [Fact]
    public void Classifier_ShouldCompress_RejectsCompressedClassAndHighEntropy()
    {
        MlpNetwork network = MlpNetwork.CreateRandom(52, 4, 7, seed: 1);
        FeatureNormalizer normalizer = FeatureNormalizer.Fit([new double[52]]);
        var classifier = new MlpClassifier(network, normalizer);

        FileFeatures highEntropy = CreateFeatures(entropy: 8.0);
        FileFeatures normal = CreateFeatures(entropy: 5.0);

        Assert.False(classifier.ShouldCompress(MlpClassifier.AlreadyCompressedClass, normal));
        Assert.False(classifier.ShouldCompress(fileClass: 0, highEntropy));
        Assert.True(classifier.ShouldCompress(fileClass: 0, normal));

        // Растр із високою байтовою ентропією, але сильною автокореляцією має стискатися (Методичка п. 10.28).
        double[] correlatedAc = new double[16];
        correlatedAc[0] = 0.94;
        FileFeatures highEntropyRaster = new(
            Entropy: 7.988,
            Histogram32: Enumerable.Repeat(1.0 / 32, 32).ToArray(),
            AsciiRatio: 0.3,
            NewlineDistanceAvg: 0,
            Autocorrelation16: correlatedAc,
            BigramEntropy: 8.07);
        Assert.True(classifier.ShouldCompress(fileClass: 3, highEntropyRaster));
    }

    [Fact]
    public void Classifier_ClassifyAndSaveLoadReturnSamePrediction()
    {
        MlpNetwork network = MlpNetwork.CreateRandom(52, 8, 7, seed: 7);
        FeatureNormalizer normalizer = FeatureNormalizer.Fit([new double[52], Enumerable.Repeat(1.0, 52).ToArray()]);
        var classifier = new MlpClassifier(network, normalizer);

        string path = Path.Combine(Path.GetTempPath(), $"sarc-mlp-{Guid.NewGuid():N}.bin");
        try
        {
            classifier.Save(path);
            MlpClassifier loaded = MlpClassifier.Load(path);

            FileFeatures features = CreateFeatures(entropy: 4.0);
            byte expected = classifier.Classify(features);

            Assert.InRange(expected, (byte)0, (byte)6);
            Assert.Equal(expected, loaded.Classify(features));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static void AssertMatrixEqual(double[,] expected, double[,] actual)
    {
        Assert.Equal(expected.GetLength(0), actual.GetLength(0));
        Assert.Equal(expected.GetLength(1), actual.GetLength(1));

        for (int row = 0; row < expected.GetLength(0); row++)
        {
            for (int column = 0; column < expected.GetLength(1); column++)
            {
                Assert.Equal(expected[row, column], actual[row, column]);
            }
        }
    }

    private static (FeatureNormalizer Normalizer, List<LabeledSample> Samples) CreateTwoClusterSamples()
    {
        var random = new Random(123);
        var raw = new List<(double[] Features, byte Label)>();

        for (int i = 0; i < 200; i++)
        {
            byte label = (byte)(i % 2);
            double center = label == 0 ? -2 : 2;
            raw.Add((
                [center + NextGaussian(random), center + NextGaussian(random)],
                label));
        }

        FeatureNormalizer normalizer = FeatureNormalizer.Fit(raw.Select(item => item.Features).ToList());
        List<LabeledSample> samples = raw
            .Select(item => new LabeledSample(normalizer.Transform(item.Features), item.Label))
            .ToList();

        return (normalizer, samples);
    }

    private static FileFeatures CreateFeatures(double entropy) =>
        new(
            Entropy: entropy,
            Histogram32: Enumerable.Repeat(1.0 / 32, 32).ToArray(),
            AsciiRatio: 0.5,
            NewlineDistanceAvg: 20,
            Autocorrelation16: new double[16],
            BigramEntropy: 5);

    private static double NextGaussian(Random random)
    {
        double u1 = 1.0 - random.NextDouble();
        double u2 = random.NextDouble();
        return Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Cos(2.0 * Math.PI * u2);
    }
}
