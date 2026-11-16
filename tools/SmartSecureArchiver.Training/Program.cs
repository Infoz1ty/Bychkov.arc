using System.Globalization;
using System.Text.Json;
using SmartSecureArchiver.Core.Analysis;

namespace SmartSecureArchiver.Training;

/// <summary>
/// Протокол навчання MLP (Issue #24): train/ -> 3 ініціалізації, вибір найкращої за macro-F1 на valid/,
/// збереження ваг моделі та матриці помилок для звіту. team/ відкривається лише для читання.
/// </summary>
public static class Program
{
    private const int HiddenSize = 64;
    private const int Epochs = 250;
    private const int BatchSize = 32;
    private const double LearningRate = 0.1;
    private const double LearningRateDecay = 0.99;
    private const int ClassCount = 7;

    private static readonly int[] Seeds = [2026, 2027, 2028];

    public static int Main(string[] args)
    {
        string root = FindRepositoryRoot();
        string trainDirectory = Path.Combine(root, "team", "train");
        string validDirectory = Path.Combine(root, "team", "valid");
        double f1Min = ReadF1Min(Path.Combine(root, "team", "team_config.json"));

        Console.WriteLine("Завантаження train/ ...");
        List<RawSample> trainRaw = LoadSamples(trainDirectory);
        Console.WriteLine("Завантаження valid/ ...");
        List<RawSample> validRaw = LoadSamples(validDirectory);
        Console.WriteLine($"train: {trainRaw.Count}, valid: {validRaw.Count}, F1_min: {f1Min}");

        FeatureNormalizer normalizer = FeatureNormalizer.Fit(trainRaw.Select(sample => sample.Features).ToList());
        List<LabeledSample> train = ToLabeled(trainRaw, normalizer);
        List<LabeledSample> valid = ToLabeled(validRaw, normalizer);

        var runs = new List<RunResult>();
        MlpNetwork? bestNetwork = null;
        RunResult? bestRun = null;

        foreach (int seed in Seeds)
        {
            MlpNetwork network = MlpNetwork.CreateRandom(FeatureVectorizer.Size, HiddenSize, ClassCount, seed);
            var trainer = new MlpTrainer(new TrainingOptions(
                Epochs: Epochs,
                BatchSize: BatchSize,
                LearningRate: LearningRate,
                LearningRateDecay: LearningRateDecay,
                ShuffleSeed: seed));

            TrainingHistory history = trainer.Train(network, train);
            EvaluationReport report = ModelMetrics.Evaluate(network, valid, ClassCount);
            var run = new RunResult(seed, report.MacroF1, report.Accuracy, history.InitialLoss, history.FinalLoss, report.ConfusionMatrix);
            runs.Add(run);

            Console.WriteLine(
                $"seed {seed}: valid macro-F1 = {report.MacroF1:F4}, accuracy = {report.Accuracy:F4}, " +
                $"loss {history.InitialLoss:F4} -> {history.FinalLoss:F4}");

            if (bestRun is null || run.MacroF1 > bestRun.MacroF1)
            {
                bestRun = run;
                bestNetwork = network;
            }
        }

        if (bestRun is null || bestNetwork is null)
        {
            Console.Error.WriteLine("No model was trained.");
            return 1;
        }

        string modelPath = Path.Combine(root, "models", "mlp_weights.bin");
        string reportPath = Path.Combine(root, "reports", "classifier_metrics.json");
        MlpModelSerializer.Save(modelPath, bestNetwork, normalizer);

        Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
        var payload = new
        {
            f1_min = f1Min,
            hidden_size = HiddenSize,
            epochs = Epochs,
            batch_size = BatchSize,
            learning_rate = LearningRate,
            initializations = runs.Select(run => new
            {
                seed = run.Seed,
                valid_macro_f1 = run.MacroF1,
                valid_accuracy = run.Accuracy,
                initial_loss = run.InitialLoss,
                final_loss = run.FinalLoss,
                confusion_matrix = ToJagged(run.Confusion)
            }).ToArray(),
            best_seed = bestRun.Seed,
            best_valid_macro_f1 = bestRun.MacroF1,
            best_valid_accuracy = bestRun.Accuracy,
            confusion_matrix = ToJagged(bestRun.Confusion),
            classes = new[]
            {
                "0 природний текст", "1 вихідний код", "2 структуровані дані",
                "3 растр без стиснення", "4 виконуваний файл", "5 вже стиснуте", "6 штучні дані"
            }
        };

        File.WriteAllText(reportPath, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine();
        Console.WriteLine($"Найкраща модель: seed {bestRun.Seed}, macro-F1 = {bestRun.MacroF1:F4}");
        Console.WriteLine($"Ваги: {modelPath}");
        Console.WriteLine($"Метрики: {reportPath}");
        PrintConfusion(bestRun.Confusion);

        if (bestRun.MacroF1 < f1Min)
        {
            Console.Error.WriteLine($"FAIL: macro-F1 {bestRun.MacroF1:F4} < F1_min {f1Min}.");
            return 1;
        }

        Console.WriteLine($"OK: macro-F1 {bestRun.MacroF1:F4} >= F1_min {f1Min}.");
        return 0;
    }

    private static List<RawSample> LoadSamples(string directory)
    {
        string labelsPath = Path.Combine(directory, "labels.csv");
        if (!File.Exists(labelsPath))
        {
            throw new FileNotFoundException($"Labels file not found: {labelsPath}");
        }

        var extractor = new FeatureExtractor();
        var samples = new List<RawSample>();

        foreach (string line in File.ReadLines(labelsPath).Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            string[] parts = line.Split(',');
            if (parts.Length < 2 || !byte.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out byte label))
            {
                throw new InvalidDataException($"Malformed labels line: {line}");
            }

            string path = Path.Combine(directory, parts[0]);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"Corpus file not found: {path}");
            }

            byte[] data = File.ReadAllBytes(path);
            FileFeatures features = extractor.Extract(data);
            samples.Add(new RawSample(FeatureVectorizer.ToVector(features), label));
        }

        return samples;
    }

    private static List<LabeledSample> ToLabeled(List<RawSample> raw, FeatureNormalizer normalizer) =>
        raw.Select(sample => new LabeledSample(normalizer.Transform(sample.Features), sample.Label)).ToList();

    private static double ReadF1Min(string configPath)
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(configPath));
        return document.RootElement
            .GetProperty("класифікатор")
            .GetProperty("F1_min")
            .GetDouble();
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "team", "team_config.json")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root with team/team_config.json.");
    }

    private static int[][] ToJagged(int[,] matrix)
    {
        int rows = matrix.GetLength(0);
        int columns = matrix.GetLength(1);
        int[][] result = new int[rows][];

        for (int row = 0; row < rows; row++)
        {
            result[row] = new int[columns];
            for (int column = 0; column < columns; column++)
            {
                result[row][column] = matrix[row, column];
            }
        }

        return result;
    }

    private static void PrintConfusion(int[,] matrix)
    {
        Console.WriteLine("Матриця помилок (рядок = істинний клас, стовпець = прогноз):");
        for (int row = 0; row < matrix.GetLength(0); row++)
        {
            Console.Write("  ");
            for (int column = 0; column < matrix.GetLength(1); column++)
            {
                Console.Write($"{matrix[row, column],5}");
            }

            Console.WriteLine();
        }
    }

    private sealed record RawSample(double[] Features, byte Label);

    private sealed record RunResult(
        int Seed,
        double MacroF1,
        double Accuracy,
        double InitialLoss,
        double FinalLoss,
        int[,] Confusion);
}
