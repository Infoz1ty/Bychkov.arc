using System.Globalization;
using System.Text;
using System.Text.Json;
using SmartSecureArchiver.Core.Analysis;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Optimization;
using SmartSecureArchiver.Core.Packing;

namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Результат однієї конфігурації у дослідженні впливу блоків (Ablation Study, Таблиця №2 звіту, Issue #47).
/// </summary>
public sealed record AblationVariantResult(
    string VariantId,
    string ConfigurationName,
    string DisabledOrChangedBlock,
    bool IsByteExact,
    long OriginalBytes,
    long ArchiveBytes,
    double MedianElapsedSeconds,
    double CompressionScoreS,
    double SpeedScoreT,
    double TotalScoreQ,
    double DeltaQFromBaseline
);

/// <summary>
/// Зведений результат Ablation Study на корпусі файлів.
/// </summary>
public sealed record AblationStudyReport(
    string GeneratedAtUtc,
    int FileCount,
    long OriginalBytes,
    int MaxVolumeBytes,
    int BlockSize,
    double Alpha,
    double Beta,
    double ReferenceSeconds,
    int RunsPerVariant,
    IReadOnlyList<AblationVariantResult> Variants
);

/// <summary>
/// Автоматизований генератор Таблиці №2 звіту (Ablation Study — Issue #47, розд. 12 п. 2 ТЗ):
/// вимірює метрику Q повної системи та варіантів із почергово вимкненим кожним реалізованим блоком.
/// </summary>
public static class AblationStudyRunner
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Запускає Ablation Study на заданому наборі файлів із попереднім прогрівом JIT
    /// та обчисленням медіанного часу за задану кількість прогонів.
    /// </summary>
    public static AblationStudyReport Run(
        IReadOnlyList<string> inputFiles,
        string password = "algo2026",
        int maxVolumeBytes = 65536,
        int blockSize = ArchiveOrchestrator.DefaultBlockSize,
        double alpha = QualityMetricCalculator.DefaultAlpha,
        double beta = QualityMetricCalculator.DefaultBeta,
        double referenceSeconds = QualityMetricCalculator.DefaultReferenceSeconds,
        int runsPerVariant = 3,
        GeneticParameters? gaOptimizedParameters = null)
    {
        ArgumentNullException.ThrowIfNull(inputFiles);
        ArgumentNullException.ThrowIfNull(password);

        if (inputFiles.Count == 0)
        {
            throw new ArgumentException("Input file list cannot be empty.", nameof(inputFiles));
        }

        if (runsPerVariant < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(runsPerVariant), "Runs per variant must be >= 1.");
        }

        // Прогрів JIT на повній базовій системі перед вимірюваннями (Методичка п. 6.32)
        _ = QualityMetricCalculator.EvaluateRoundTrip(
            ArchiveOrchestratorFactory.CreateDefault(blockSize),
            inputFiles,
            password,
            maxVolumeBytes,
            alpha,
            beta,
            referenceSeconds);

        var variantsSpec = new List<(string Id, string Name, string ChangedBlock, Func<ArchiveOrchestrator> Factory)>
        {
            (
                "full_baseline",
                "Повна базова система (MLP + Greedy LZ77 + Гаффман + ДП-рюкзак + AES/HMAC)",
                "— (еталонний базовий конвеєр)",
                () => ArchiveOrchestratorFactory.CreateDefault(blockSize)
            ),
            (
                "no_mlp",
                "Без ML-класифікатора (MLP вимкнено)",
                "Блок 1: FeatureExtractor + MlpClassifier",
                () => new ArchiveOrchestrator(
                    blockCompressor: new BlockCompressor(),
                    featureExtractor: null,
                    fileClassifier: null,
                    knapsackPacker: new KnapsackPacker(),
                    blockSize: blockSize)
            ),
            (
                "no_lz77",
                "Без пошуку повторів LZ77 (тільки Канонічний Гаффман)",
                "Блок 2: Lz77Parser (тільки літерали)",
                () => new ArchiveOrchestrator(
                    blockCompressor: new BlockCompressor(new LiteralsOnlyLz77Parser(), new HuffmanCodec()),
                    featureExtractor: new FeatureExtractor(),
                    fileClassifier: MlpClassifier.CreateDefault(),
                    knapsackPacker: new KnapsackPacker(),
                    blockSize: blockSize)
            ),
            (
                "no_compression",
                "Без стиснення (NO_COMPRESSION, без LZ77 і Гаффмана)",
                "Блоки 2+3: LZ77 + Канонічний Гаффман",
                () => new ArchiveOrchestrator(
                    blockCompressor: new NoCompressionBlockCompressor(),
                    featureExtractor: new FeatureExtractor(),
                    fileClassifier: MlpClassifier.CreateDefault(),
                    knapsackPacker: new KnapsackPacker(),
                    blockSize: blockSize)
            ),
            (
                "no_knapsack_sequential",
                "Без ДП-рюкзака (послідовне пакування томів)",
                "Блок 4: KnapsackPacker (вимкнено)",
                () => new ArchiveOrchestrator(
                    blockCompressor: new BlockCompressor(),
                    featureExtractor: new FeatureExtractor(),
                    fileClassifier: MlpClassifier.CreateDefault(),
                    knapsackPacker: null,
                    blockSize: blockSize)
            ),
            (
                "greedy_knapsack",
                "Жадібне пакування (v/w) замість точного ДП-рюкзака 0/1",
                "Блок 4: заміна DP 0/1 на Greedy v/w",
                () => new ArchiveOrchestrator(
                    blockCompressor: new BlockCompressor(),
                    featureExtractor: new FeatureExtractor(),
                    fileClassifier: MlpClassifier.CreateDefault(),
                    knapsackPacker: new GreedyOnlyKnapsackPacker(new KnapsackPacker()),
                    blockSize: blockSize)
            ),
            (
                "lazy_lz77",
                "Повна система із Lazy Greedy LZ77 замість Greedy LZ77",
                "Блок 2: режим Lazy Greedy LZ77",
                () => new ArchiveOrchestrator(
                    blockCompressor: new ParameterizedBlockCompressor(
                        new BlockCompressor(),
                        windowSize: Lz77Parser.DefaultWindowSize,
                        minMatchLength: Lz77Parser.MinMatchLength,
                        useLazyMatching: true),
                    featureExtractor: new FeatureExtractor(),
                    fileClassifier: MlpClassifier.CreateDefault(),
                    knapsackPacker: new KnapsackPacker(),
                    blockSize: blockSize)
            )
        };

        if (gaOptimizedParameters is not null)
        {
            variantsSpec.Add((
                "with_ga_params",
                $"Повна система з параметрами ГА [{gaOptimizedParameters.WindowSize}, {gaOptimizedParameters.MinMatchLength}, {gaOptimizedParameters.NoCompressionEntropyThreshold.ToString("F2", CultureInfo.InvariantCulture)}]",
                "Блок 6: GeneticOptimizer (підібрана хромосома)",
                () => new ArchiveOrchestrator(
                    blockCompressor: new ParameterizedBlockCompressor(
                        new BlockCompressor(),
                        windowSize: gaOptimizedParameters.WindowSize,
                        minMatchLength: gaOptimizedParameters.MinMatchLength,
                        useLazyMatching: false),
                    featureExtractor: new FeatureExtractor(),
                    fileClassifier: new ParameterizedFileClassifier(
                        MlpClassifier.CreateDefault(),
                        gaOptimizedParameters.NoCompressionEntropyThreshold),
                    knapsackPacker: new KnapsackPacker(),
                    blockSize: blockSize)));
        }

        var results = new List<AblationVariantResult>(variantsSpec.Count);
        double baselineQ = 0.0;

        for (int i = 0; i < variantsSpec.Count; i++)
        {
            (string id, string name, string changedBlock, Func<ArchiveOrchestrator> factory) = variantsSpec[i];
            var runResults = new List<QualityMetricResult>(runsPerVariant);

            for (int r = 0; r < runsPerVariant; r++)
            {
                ArchiveOrchestrator orchestrator = factory();
                QualityMetricResult single = QualityMetricCalculator.EvaluateRoundTrip(
                    orchestrator,
                    inputFiles,
                    password,
                    maxVolumeBytes,
                    alpha,
                    beta,
                    referenceSeconds);
                runResults.Add(single);
            }

            bool allExact = runResults.All(x => x.IsByteExact);
            long origBytes = runResults[0].OriginalBytes;
            long arcBytes = runResults[0].ArchiveBytes;
            double[] sortedTimes = runResults.Select(x => x.ElapsedSeconds).OrderBy(x => x).ToArray();
            double medianTime = sortedTimes.Length % 2 == 1
                ? sortedTimes[sortedTimes.Length / 2]
                : 0.5 * (sortedTimes[sortedTimes.Length / 2 - 1] + sortedTimes[sortedTimes.Length / 2]);

            QualityMetricResult aggregated = QualityMetricCalculator.Compute(
                origBytes,
                arcBytes,
                medianTime,
                allExact,
                alpha,
                beta,
                referenceSeconds);

            if (i == 0)
            {
                baselineQ = aggregated.TotalScoreQ;
            }

            double deltaQ = aggregated.TotalScoreQ - baselineQ;
            results.Add(new AblationVariantResult(
                VariantId: id,
                ConfigurationName: name,
                DisabledOrChangedBlock: changedBlock,
                IsByteExact: aggregated.IsByteExact,
                OriginalBytes: aggregated.OriginalBytes,
                ArchiveBytes: aggregated.ArchiveBytes,
                MedianElapsedSeconds: aggregated.ElapsedSeconds,
                CompressionScoreS: aggregated.CompressionScoreS,
                SpeedScoreT: aggregated.SpeedScoreT,
                TotalScoreQ: aggregated.TotalScoreQ,
                DeltaQFromBaseline: deltaQ));
        }

        long totalOrig = results[0].OriginalBytes;
        return new AblationStudyReport(
            GeneratedAtUtc: DateTime.UtcNow.ToString("O"),
            FileCount: inputFiles.Count,
            OriginalBytes: totalOrig,
            MaxVolumeBytes: maxVolumeBytes,
            BlockSize: blockSize,
            Alpha: alpha,
            Beta: beta,
            ReferenceSeconds: referenceSeconds,
            RunsPerVariant: runsPerVariant,
            Variants: results);
    }

    /// <summary>
    /// Форматує звіт Ablation Study у Markdown (Таблиця №2 для звіту).
    /// </summary>
    public static string FormatMarkdownTable(AblationStudyReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        CultureInfo inv = CultureInfo.InvariantCulture;

        var sb = new StringBuilder();
        sb.AppendLine("# Таблиця №2 — Ablation Study: вплив кожного реалізованого блоку на метрику Q");
        sb.AppendLine();
        sb.AppendLine($"- Вибірка: **{report.FileCount}** файлів (сумарний сирий розмір **{report.OriginalBytes}** байт)");
        sb.AppendLine($"- Конфігурація: `max_volume_bytes = {report.MaxVolumeBytes}`, `block_size = {report.BlockSize}`, `α = {report.Alpha.ToString("F1", inv)}`, `β = {report.Beta.ToString("F1", inv)}`, `t_ref = {report.ReferenceSeconds.ToString("F1", inv)} с`");
        sb.AppendLine($"- Методика: прогрів JIT + медіана з **{report.RunsPerVariant}** запусків повного циклу (`archive + extract + перевірка original == restored`)");
        sb.AppendLine();
        sb.AppendLine("| Конфігурація системи | Змінений / вимкнений блок | B_arc (Б) | Час t (с) | S | T | Q | ΔQ до базової | Побайтово |");
        sb.AppendLine("|---|---|---:|---:|---:|---:|---:|---:|:---:|");

        foreach (AblationVariantResult v in report.Variants)
        {
            string deltaStr = v.VariantId == "full_baseline"
                ? "0.0000"
                : string.Format(inv, "{0:+0.0000;-0.0000;0.0000}", v.DeltaQFromBaseline);

            sb.AppendLine(string.Format(
                inv,
                "| {0} | {1} | {2} | {3:F4} | {4:F4} | {5:F4} | **{6:F4}** | {7} | {8} |",
                v.ConfigurationName,
                v.DisabledOrChangedBlock,
                v.ArchiveBytes,
                v.MedianElapsedSeconds,
                v.CompressionScoreS,
                v.SpeedScoreT,
                v.TotalScoreQ,
                deltaStr,
                v.IsByteExact ? "OK" : "FAIL"));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Зберігає Markdown-таблицю та сирі JSON-результати Ablation Study на диск.
    /// </summary>
    public static void SaveReport(string markdownPath, string jsonPath, AblationStudyReport report)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(markdownPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(jsonPath);
        ArgumentNullException.ThrowIfNull(report);

        EnsureParentDir(markdownPath);
        EnsureParentDir(jsonPath);

        File.WriteAllText(markdownPath, FormatMarkdownTable(report), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, JsonOptions), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static void EnsureParentDir(string path)
    {
        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }
    }

    private sealed class LiteralsOnlyLz77Parser : ILz77Parser
    {
        private readonly Lz77Parser _decoder = new();

        public IReadOnlyList<Lz77Token> Parse(ReadOnlySpan<byte> input, int windowSize = 32768)
        {
            var tokens = new List<Lz77Token>(input.Length);
            for (int i = 0; i < input.Length; i++)
            {
                tokens.Add(new Lz77Token(Lz77TokenType.Literal, input[i], 0, 0));
            }

            return tokens;
        }

        public byte[] Decompress(IReadOnlyList<Lz77Token> tokens, int expectedLength) =>
            _decoder.Decompress(tokens, expectedLength);
    }

    private sealed class NoCompressionBlockCompressor : IBlockCompressor
    {
        private readonly BlockCompressor _inner = new();

        public byte[] Compress(
            ReadOnlySpan<byte> blockData,
            out byte blockFlags,
            bool allowCompression = true,
            int windowSize = 32768,
            int minMatchLength = 3,
            bool useLazyMatching = false) =>
            _inner.Compress(blockData, out blockFlags, allowCompression: false, windowSize, minMatchLength, useLazyMatching);

        public byte[] Decompress(ReadOnlySpan<byte> codedData, byte blockFlags, int expectedRawLength) =>
            _inner.Decompress(codedData, blockFlags, expectedRawLength);
    }

    private sealed class GreedyOnlyKnapsackPacker(IKnapsackPacker inner) : IKnapsackPacker
    {
        public PackingResult PackVolumeDp(int capacity, IReadOnlyList<BlockCandidate> candidates) =>
            inner.PackVolumeGreedy(capacity, candidates);

        public PackingResult PackVolumeGreedy(int capacity, IReadOnlyList<BlockCandidate> candidates) =>
            inner.PackVolumeGreedy(capacity, candidates);
    }
}
