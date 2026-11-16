namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Один навчальний приклад: уже обчислений та нормалізований вектор ознак і мітка класу 0..6.
/// </summary>
public sealed record LabeledSample(double[] Features, byte Label);

public sealed record TrainingOptions(
    int Epochs = 200,
    int BatchSize = 32,
    double LearningRate = 0.1,
    double LearningRateDecay = 0.99,
    int ShuffleSeed = 1
);

public sealed record TrainingHistory(
    IReadOnlyList<double> EpochLosses,
    double InitialLoss,
    double FinalLoss
);

/// <summary>
/// Навчання MLP із нуля (Issue #23): прямий прохід, зворотне поширення помилки,
/// cross-entropy та mini-batch SGD. Жодних ML-бібліотек.
/// </summary>
public sealed class MlpTrainer
{
    private readonly TrainingOptions _options;

    public MlpTrainer(TrainingOptions? options = null)
    {
        _options = options ?? new TrainingOptions();

        if (_options.Epochs <= 0 || _options.BatchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Epochs and batch size must be positive.");
        }

        if (_options.LearningRate <= 0 || _options.LearningRateDecay <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Learning rate and decay must be positive.");
        }
    }

    public TrainingHistory Train(MlpNetwork network, IReadOnlyList<LabeledSample> samples)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(samples);

        if (samples.Count == 0)
        {
            throw new ArgumentException("At least one training sample is required.", nameof(samples));
        }

        foreach (LabeledSample sample in samples)
        {
            if (sample.Features.Length != network.InputSize)
            {
                throw new ArgumentException(
                    $"Sample has {sample.Features.Length} features, network expects {network.InputSize}.",
                    nameof(samples));
            }

            if (sample.Label >= network.OutputSize)
            {
                throw new ArgumentException(
                    $"Sample label {sample.Label} is outside network output range 0..{network.OutputSize - 1}.",
                    nameof(samples));
            }
        }

        double[] deltaOutput = new double[network.OutputSize];
        double[] deltaHidden = new double[network.HiddenSize];
        double[,] hiddenGradient = new double[network.HiddenSize, network.InputSize];
        double[] hiddenBiasGradient = new double[network.HiddenSize];
        double[,] outputGradient = new double[network.OutputSize, network.HiddenSize];
        double[] outputBiasGradient = new double[network.OutputSize];

        int[] order = Enumerable.Range(0, samples.Count).ToArray();
        var random = new Random(_options.ShuffleSeed);
        double[] losses = new double[_options.Epochs];

        for (int epoch = 0; epoch < _options.Epochs; epoch++)
        {
            Shuffle(order, random);
            double learningRate = _options.LearningRate * Math.Pow(_options.LearningRateDecay, epoch);
            double epochLoss = 0;

            for (int batchStart = 0; batchStart < order.Length; batchStart += _options.BatchSize)
            {
                int batchEnd = Math.Min(batchStart + _options.BatchSize, order.Length);
                int batchCount = batchEnd - batchStart;

                Clear(hiddenGradient);
                Clear(outputGradient);
                Array.Clear(hiddenBiasGradient);
                Array.Clear(outputBiasGradient);

                for (int position = batchStart; position < batchEnd; position++)
                {
                    LabeledSample sample = samples[order[position]];
                    double[] probabilities = network.ForwardWithHidden(sample.Features, out double[] hidden, out _);
                    epochLoss -= Math.Log(Math.Max(probabilities[sample.Label], 1e-12));

                    Array.Copy(probabilities, deltaOutput, probabilities.Length);
                    deltaOutput[sample.Label] -= 1;

                    for (int o = 0; o < network.OutputSize; o++)
                    {
                        outputBiasGradient[o] += deltaOutput[o];
                        for (int h = 0; h < network.HiddenSize; h++)
                        {
                            outputGradient[o, h] += deltaOutput[o] * hidden[h];
                        }
                    }

                    for (int h = 0; h < network.HiddenSize; h++)
                    {
                        double sum = 0;
                        for (int o = 0; o < network.OutputSize; o++)
                        {
                            sum += deltaOutput[o] * network.OutputWeights[o, h];
                        }

                        deltaHidden[h] = hidden[h] > 0 ? sum : 0;
                    }

                    for (int h = 0; h < network.HiddenSize; h++)
                    {
                        hiddenBiasGradient[h] += deltaHidden[h];
                        for (int i = 0; i < network.InputSize; i++)
                        {
                            hiddenGradient[h, i] += deltaHidden[h] * sample.Features[i];
                        }
                    }
                }

                ApplyGradients(network, hiddenGradient, hiddenBiasGradient, outputGradient, outputBiasGradient, learningRate / batchCount);
            }

            losses[epoch] = epochLoss / samples.Count;
        }

        return new TrainingHistory(losses, losses[0], losses[^1]);
    }

    private static void ApplyGradients(
        MlpNetwork network,
        double[,] hiddenGradient,
        double[] hiddenBiasGradient,
        double[,] outputGradient,
        double[] outputBiasGradient,
        double scale)
    {
        for (int h = 0; h < network.HiddenSize; h++)
        {
            for (int i = 0; i < network.InputSize; i++)
            {
                network.HiddenWeights[h, i] -= scale * hiddenGradient[h, i];
            }

            network.HiddenBiases[h] -= scale * hiddenBiasGradient[h];
        }

        for (int o = 0; o < network.OutputSize; o++)
        {
            for (int h = 0; h < network.HiddenSize; h++)
            {
                network.OutputWeights[o, h] -= scale * outputGradient[o, h];
            }

            network.OutputBiases[o] -= scale * outputBiasGradient[o];
        }
    }

    private static void Shuffle(int[] order, Random random)
    {
        for (int i = order.Length - 1; i > 0; i--)
        {
            int j = random.Next(i + 1);
            (order[i], order[j]) = (order[j], order[i]);
        }
    }

    private static void Clear(double[,] values)
    {
        Array.Clear(values);
    }
}
