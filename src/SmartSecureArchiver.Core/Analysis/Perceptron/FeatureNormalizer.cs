namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Z-score нормалізація вхідного вектора ознак. Середні та стандартні відхилення
/// обчислюються на train/ і зберігаються разом із вагами моделі.
/// </summary>
public sealed class FeatureNormalizer
{
    private const double MinimumStdDev = 1e-8;

    public FeatureNormalizer(double[] mean, double[] standardDeviation)
    {
        ArgumentNullException.ThrowIfNull(mean);
        ArgumentNullException.ThrowIfNull(standardDeviation);

        if (mean.Length == 0 || mean.Length != standardDeviation.Length)
        {
            throw new ArgumentException("Mean and standard deviation arrays must have the same non-zero length.");
        }

        Mean = (double[])mean.Clone();
        StandardDeviation = (double[])standardDeviation.Clone();
    }

    public double[] Mean { get; }

    public double[] StandardDeviation { get; }

    /// <summary>
    /// Обчислює середнє та стандартне відхилення (за генеральною сукупністю) для кожного стовпця.
    /// </summary>
    public static FeatureNormalizer Fit(IReadOnlyList<double[]> samples)
    {
        ArgumentNullException.ThrowIfNull(samples);

        if (samples.Count == 0)
        {
            throw new ArgumentException("At least one sample is required.", nameof(samples));
        }

        int dimension = samples[0].Length;
        double[] mean = new double[dimension];
        double[] standardDeviation = new double[dimension];

        foreach (double[] sample in samples)
        {
            if (sample.Length != dimension)
            {
                throw new ArgumentException("All samples must have the same length.", nameof(samples));
            }

            for (int i = 0; i < dimension; i++)
            {
                mean[i] += sample[i];
            }
        }

        for (int i = 0; i < dimension; i++)
        {
            mean[i] /= samples.Count;
        }

        foreach (double[] sample in samples)
        {
            for (int i = 0; i < dimension; i++)
            {
                double difference = sample[i] - mean[i];
                standardDeviation[i] += difference * difference;
            }
        }

        for (int i = 0; i < dimension; i++)
        {
            standardDeviation[i] = Math.Sqrt(standardDeviation[i] / samples.Count);
            if (standardDeviation[i] < MinimumStdDev)
            {
                standardDeviation[i] = 1.0;
            }
        }

        return new FeatureNormalizer(mean, standardDeviation);
    }

    public double[] Transform(ReadOnlySpan<double> input)
    {
        if (input.Length != Mean.Length)
        {
            throw new ArgumentException($"Expected {Mean.Length} features, got {input.Length}.", nameof(input));
        }

        double[] output = new double[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (input[i] - Mean[i]) / StandardDeviation[i];
        }

        return output;
    }
}
