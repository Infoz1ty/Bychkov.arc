namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Багатошаровий перцептрон SARC (Issue #22): повнозв'язні шари, ReLU на прихованому шарі
/// та Softmax на виході. Реалізовано з нуля на стандартній бібліотеці .NET.
/// Ваги зберігаються у форматі [вихід][вхід].
/// </summary>
public sealed class MlpNetwork
{
    public MlpNetwork(int inputSize, int hiddenSize, int outputSize)
    {
        if (inputSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(inputSize), inputSize, "Input size must be positive.");
        }

        if (hiddenSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(hiddenSize), hiddenSize, "Hidden size must be positive.");
        }

        if (outputSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputSize), outputSize, "Output size must be positive.");
        }

        InputSize = inputSize;
        HiddenSize = hiddenSize;
        OutputSize = outputSize;

        HiddenWeights = new double[hiddenSize, inputSize];
        HiddenBiases = new double[hiddenSize];
        OutputWeights = new double[outputSize, hiddenSize];
        OutputBiases = new double[outputSize];
    }

    public int InputSize { get; }

    public int HiddenSize { get; }

    public int OutputSize { get; }

    public double[,] HiddenWeights { get; }

    public double[] HiddenBiases { get; }

    public double[,] OutputWeights { get; }

    public double[] OutputBiases { get; }

    /// <summary>
    /// Створює мережу з ініціалізацією He (ReLU) та Xavier (вихід) із фіксованим seed.
    /// </summary>
    public static MlpNetwork CreateRandom(int inputSize, int hiddenSize, int outputSize, int seed)
    {
        var network = new MlpNetwork(inputSize, hiddenSize, outputSize);
        var random = new Random(seed);

        double hiddenLimit = Math.Sqrt(6.0 / inputSize);
        double outputLimit = Math.Sqrt(6.0 / (hiddenSize + outputSize));

        FillUniform(network.HiddenWeights, hiddenLimit, random);
        FillUniform(network.OutputWeights, outputLimit, random);

        return network;
    }

    /// <summary>
    /// Прямий прохід: повертає ймовірності класів (Softmax).
    /// </summary>
    public double[] Forward(ReadOnlySpan<double> input)
    {
        return ForwardWithHidden(input, out _, out _);
    }

    /// <summary>
    /// Прямий прохід із доступом до активацій прихованого шару та логітів (потрібно для backprop).
    /// </summary>
    public double[] ForwardWithHidden(ReadOnlySpan<double> input, out double[] hidden, out double[] logits)
    {
        if (input.Length != InputSize)
        {
            throw new ArgumentException($"Expected {InputSize} inputs, got {input.Length}.", nameof(input));
        }

        hidden = new double[HiddenSize];
        for (int h = 0; h < HiddenSize; h++)
        {
            double sum = HiddenBiases[h];
            for (int i = 0; i < InputSize; i++)
            {
                sum += HiddenWeights[h, i] * input[i];
            }

            hidden[h] = sum > 0 ? sum : 0;
        }

        logits = new double[OutputSize];
        for (int o = 0; o < OutputSize; o++)
        {
            double sum = OutputBiases[o];
            for (int h = 0; h < HiddenSize; h++)
            {
                sum += OutputWeights[o, h] * hidden[h];
            }

            logits[o] = sum;
        }

        return Softmax(logits);
    }

    public static double[] Softmax(ReadOnlySpan<double> logits)
    {
        double maximum = double.NegativeInfinity;
        foreach (double value in logits)
        {
            maximum = Math.Max(maximum, value);
        }

        double[] probabilities = new double[logits.Length];
        double sum = 0;
        for (int i = 0; i < logits.Length; i++)
        {
            probabilities[i] = Math.Exp(logits[i] - maximum);
            sum += probabilities[i];
        }

        for (int i = 0; i < probabilities.Length; i++)
        {
            probabilities[i] /= sum;
        }

        return probabilities;
    }

    private static void FillUniform(double[,] weights, double limit, Random random)
    {
        int rows = weights.GetLength(0);
        int columns = weights.GetLength(1);
        for (int row = 0; row < rows; row++)
        {
            for (int column = 0; column < columns; column++)
            {
                weights[row, column] = (random.NextDouble() * 2 - 1) * limit;
            }
        }
    }
}
