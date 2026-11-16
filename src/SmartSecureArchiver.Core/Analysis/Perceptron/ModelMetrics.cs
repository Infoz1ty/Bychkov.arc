namespace SmartSecureArchiver.Core.Analysis;

public sealed record ClassReport(double Precision, double Recall, double F1, int Support);

public sealed record EvaluationReport(
    double Accuracy,
    double MacroF1,
    IReadOnlyList<ClassReport> Classes,
    int[,] ConfusionMatrix
);

/// <summary>
/// Оцінювання MLP без сторонніх бібліотек (Issue #24): accuracy, macro-F1 та матриця помилок.
/// </summary>
public static class ModelMetrics
{
    /// <summary>
    /// Оцінює мережу на прикладах, ознаки яких уже нормалізовані тим самим FeatureNormalizer,
    /// що використовувався під час навчання.
    /// </summary>
    public static EvaluationReport Evaluate(
        MlpNetwork network,
        IReadOnlyList<LabeledSample> samples,
        int classCount)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(samples);

        if (classCount <= 0 || classCount > network.OutputSize)
        {
            throw new ArgumentOutOfRangeException(nameof(classCount));
        }

        int[,] confusion = new int[classCount, classCount];
        int correct = 0;

        foreach (LabeledSample sample in samples)
        {
            if (sample.Label >= classCount)
            {
                throw new ArgumentException($"Sample label {sample.Label} is outside 0..{classCount - 1}.", nameof(samples));
            }

            byte predicted = ArgMax(network.Forward(sample.Features));
            confusion[sample.Label, predicted]++;

            if (predicted == sample.Label)
            {
                correct++;
            }
        }

        return FromConfusionMatrix(confusion, samples.Count, correct);
    }

    /// <summary>
    /// Обчислює accuracy та macro-F1 безпосередньо з матриці помилок (рядок — істинний клас, стовпець — прогноз).
    /// </summary>
    public static EvaluationReport FromConfusionMatrix(int[,] confusion, int sampleCount, int correct = -1)
    {
        ArgumentNullException.ThrowIfNull(confusion);

        int classCount = confusion.GetLength(0);
        if (classCount == 0 || confusion.GetLength(1) != classCount)
        {
            throw new ArgumentException("Confusion matrix must be square and non-empty.", nameof(confusion));
        }

        if (correct < 0)
        {
            correct = 0;
            for (int i = 0; i < classCount; i++)
            {
                correct += confusion[i, i];
            }
        }

        var classes = new List<ClassReport>(classCount);
        double macroF1 = 0;

        for (int classIndex = 0; classIndex < classCount; classIndex++)
        {
            int truePositive = confusion[classIndex, classIndex];
            int predictedTotal = 0;
            int actualTotal = 0;

            for (int i = 0; i < classCount; i++)
            {
                predictedTotal += confusion[i, classIndex];
                actualTotal += confusion[classIndex, i];
            }

            double precision = predictedTotal == 0 ? 0 : (double)truePositive / predictedTotal;
            double recall = actualTotal == 0 ? 0 : (double)truePositive / actualTotal;
            double f1 = precision + recall == 0 ? 0 : 2 * precision * recall / (precision + recall);

            classes.Add(new ClassReport(precision, recall, f1, actualTotal));
            macroF1 += f1;
        }

        return new EvaluationReport(
            sampleCount == 0 ? 0 : (double)correct / sampleCount,
            macroF1 / classCount,
            classes,
            confusion);
    }

    public static byte ArgMax(ReadOnlySpan<double> values)
    {
        if (values.IsEmpty)
        {
            throw new ArgumentException("Values cannot be empty.", nameof(values));
        }

        int bestIndex = 0;
        double bestValue = values[0];

        for (int i = 1; i < values.Length; i++)
        {
            if (values[i] > bestValue)
            {
                bestValue = values[i];
                bestIndex = i;
            }
        }

        return (byte)bestIndex;
    }
}
