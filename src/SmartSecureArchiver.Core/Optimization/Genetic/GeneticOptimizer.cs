using System.Diagnostics;
using System.Text.Json;
using SmartSecureArchiver.Core.Analysis;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Packing;

namespace SmartSecureArchiver.Core.Optimization;

/// <summary>
/// Реалізація Генетичного алгоритму (Issue #35) та Random Search baseline (Issue #36)
/// власноруч з нуля без сторонніх бібліотек оптимізації.
/// Хромосома містить 3 гени: [window_size, min_match, no_comp_threshold].
/// Оператори: турнірна селекція, одноточковий кросовер, випадкова мутація, елітизм.
/// </summary>
public sealed class GeneticOptimizer : IGeneticOptimizer
{
    public const int MinWindowSize = 1024;
    public const int MaxWindowSize = Lz77Parser.DefaultWindowSize; // 32768
    public const int WindowStep = 256;

    public const int MinMatchLower = Lz77Parser.MinMatchLength; // 3
    public const int MinMatchUpper = 12;

    public const double MinEntropyThreshold = 6.0;
    public const double MaxEntropyThreshold = 8.0;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _password;
    private readonly int _maxVolumeBytes;
    private readonly int _blockSize;
    private readonly double _alpha;
    private readonly double _beta;
    private readonly double _referenceSeconds;
    private readonly int _seed;
    private readonly double _crossoverRate;
    private readonly double _mutationRate;
    private readonly int _tournamentSize;
    private readonly string? _evolutionLogPath;
    private readonly Func<GeneticParameters, IReadOnlyList<string>, QualityMetricResult>? _customEvaluator;

    public GeneticOptimizer(
        string password = "algo2026",
        int maxVolumeBytes = 65536,
        int blockSize = ArchiveOrchestrator.DefaultBlockSize,
        double alpha = QualityMetricCalculator.DefaultAlpha,
        double beta = QualityMetricCalculator.DefaultBeta,
        double referenceSeconds = QualityMetricCalculator.DefaultReferenceSeconds,
        int seed = 2001,
        double crossoverRate = 0.8,
        double mutationRate = 0.25,
        int tournamentSize = 3,
        string? evolutionLogPath = null,
        Func<GeneticParameters, IReadOnlyList<string>, QualityMetricResult>? customEvaluator = null)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (crossoverRate is < 0.0 or > 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(crossoverRate), "Crossover rate must be in [0, 1].");
        }

        if (mutationRate is < 0.0 or > 1.0)
        {
            throw new ArgumentOutOfRangeException(nameof(mutationRate), "Mutation rate must be in [0, 1].");
        }

        if (tournamentSize < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(tournamentSize), "Tournament size must be >= 1.");
        }

        _password = password;
        _maxVolumeBytes = maxVolumeBytes;
        _blockSize = blockSize;
        _alpha = alpha;
        _beta = beta;
        _referenceSeconds = referenceSeconds;
        _seed = seed;
        _crossoverRate = crossoverRate;
        _mutationRate = mutationRate;
        _tournamentSize = tournamentSize;
        _evolutionLogPath = evolutionLogPath;
        _customEvaluator = customEvaluator;
    }

    /// <inheritdoc />
    public GeneticParameters Optimize(IReadOnlyList<string> sampleFiles, int generations, int populationSize)
    {
        GaOptimizationReport report = OptimizeWithLog(sampleFiles, generations, populationSize);
        return report.BestParameters;
    }

    /// <summary>
    /// Запускає еволюцію ГА та повертає детальний журнал за поколіннями (Issue #36).
    /// Якщо в конструкторі вказано evolutionLogPath, автоматично зберігає JSON-журнал на диск.
    /// </summary>
    public GaOptimizationReport OptimizeWithLog(
        IReadOnlyList<string> sampleFiles,
        int generations,
        int populationSize)
    {
        ValidateSampleFiles(sampleFiles);

        if (generations < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(generations), "Generations must be >= 0.");
        }

        if (populationSize < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(populationSize), "Population size must be >= 2.");
        }

        var sw = Stopwatch.StartNew();
        var rng = new Random(_seed);
        var cache = new Dictionary<(int, int, int), QualityMetricResult>();
        var history = new List<GaGenerationRecord>(generations + 1);
        int evaluationCount = 0;

        // Ініціалізація популяції покоління 0
        var population = new List<Individual>(populationSize);
        for (int i = 0; i < populationSize; i++)
        {
            GeneticParameters genes = CreateRandomParameters(rng);
            QualityMetricResult metrics = EvaluateCached(genes, sampleFiles, cache, ref evaluationCount);
            population.Add(new Individual(genes, metrics));
        }

        population.Sort(CompareIndividualsDesc);
        double bestInitialQ = population[0].Metrics.TotalScoreQ;
        history.Add(BuildGenerationRecord(0, population, evaluationCount));

        int elitismCount = Math.Max(1, populationSize / 4);

        for (int gen = 1; gen <= generations; gen++)
        {
            var nextPopulation = new List<Individual>(populationSize);

            // Елітизм: найкращі особини переходять без змін (гарантія best_final >= best_initial)
            for (int e = 0; e < elitismCount; e++)
            {
                nextPopulation.Add(population[e]);
            }

            while (nextPopulation.Count < populationSize)
            {
                Individual parentA = SelectTournament(population, rng);
                Individual parentB = SelectTournament(population, rng);

                (GeneticParameters child1Genes, GeneticParameters child2Genes) =
                    rng.NextDouble() < _crossoverRate
                        ? SinglePointCrossover(parentA.Parameters, parentB.Parameters, rng)
                        : (parentA.Parameters, parentB.Parameters);

                child1Genes = Mutate(child1Genes, rng);
                QualityMetricResult child1Metrics = EvaluateCached(child1Genes, sampleFiles, cache, ref evaluationCount);
                nextPopulation.Add(new Individual(child1Genes, child1Metrics));

                if (nextPopulation.Count < populationSize)
                {
                    child2Genes = Mutate(child2Genes, rng);
                    QualityMetricResult child2Metrics = EvaluateCached(child2Genes, sampleFiles, cache, ref evaluationCount);
                    nextPopulation.Add(new Individual(child2Genes, child2Metrics));
                }
            }

            population = nextPopulation;
            population.Sort(CompareIndividualsDesc);
            history.Add(BuildGenerationRecord(gen, population, evaluationCount));
        }

        sw.Stop();

        Individual best = population[0];
        var report = new GaOptimizationReport(
            Seed: _seed,
            PopulationSize: populationSize,
            Generations: generations,
            TotalEvaluations: evaluationCount,
            BestInitialQ: bestInitialQ,
            BestFinalQ: best.Metrics.TotalScoreQ,
            BestParameters: best.Parameters,
            GenerationsHistory: history,
            ElapsedSeconds: sw.Elapsed.TotalSeconds);

        if (!string.IsNullOrWhiteSpace(_evolutionLogPath))
        {
            SaveEvolutionLog(_evolutionLogPath, report);
        }

        return report;
    }

    /// <inheritdoc />
    public GeneticParameters RunRandomSearch(IReadOnlyList<string> sampleFiles, int iterations)
    {
        RandomSearchReport report = RunRandomSearchWithLog(sampleFiles, iterations);
        return report.BestParameters;
    }

    /// <summary>
    /// Запускає Random Search із заданим бюджетом оцінок пристосованості Q та формує детальний звіт.
    /// </summary>
    public RandomSearchReport RunRandomSearchWithLog(IReadOnlyList<string> sampleFiles, int iterations)
    {
        ValidateSampleFiles(sampleFiles);

        if (iterations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be >= 1.");
        }

        var sw = Stopwatch.StartNew();
        var rng = new Random(_seed ^ 0x5F3759DF);
        var cache = new Dictionary<(int, int, int), QualityMetricResult>();
        var history = new List<RandomSearchRecord>(iterations);
        int evaluationCount = 0;

        Individual? best = null;
        double sumQ = 0.0;

        for (int iter = 1; iter <= iterations; iter++)
        {
            GeneticParameters candidate = CreateRandomParameters(rng);
            QualityMetricResult metrics = EvaluateCached(candidate, sampleFiles, cache, ref evaluationCount);

            if (best is null || metrics.TotalScoreQ > best.Metrics.TotalScoreQ)
            {
                best = new Individual(candidate, metrics);
            }

            sumQ += metrics.TotalScoreQ;
            history.Add(new RandomSearchRecord(
                Iteration: iter,
                CandidateQ: metrics.TotalScoreQ,
                BestQSoFar: best.Metrics.TotalScoreQ,
                CandidateParameters: candidate));
        }

        sw.Stop();

        return new RandomSearchReport(
            Seed: _seed,
            Iterations: iterations,
            BestQ: best!.Metrics.TotalScoreQ,
            AverageQ: sumQ / iterations,
            BestS: best.Metrics.CompressionScoreS,
            BestT: best.Metrics.SpeedScoreT,
            BestParameters: best.Parameters,
            History: history,
            ElapsedSeconds: sw.Elapsed.TotalSeconds);
    }

    /// <summary>
    /// Зберігає журнал еволюції ГА (та опціонально baseline Random Search) у JSON-файл.
    /// </summary>
    public static void SaveEvolutionLog(
        string outputPath,
        GaOptimizationReport gaReport,
        RandomSearchReport? randomSearchReport = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentNullException.ThrowIfNull(gaReport);

        string? directory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        object payload = randomSearchReport is null
            ? new
            {
                generated_at_utc = DateTime.UtcNow.ToString("O"),
                genetic_algorithm = gaReport
            }
            : new
            {
                generated_at_utc = DateTime.UtcNow.ToString("O"),
                genetic_algorithm = gaReport,
                random_search = randomSearchReport
            };

        string json = JsonSerializer.Serialize(payload, JsonOptions);
        File.WriteAllText(outputPath, json);
    }

    /// <summary>
    /// Оцінює якість фіксованої комбінації параметрів на заданій вибірці файлів через повний конвеєр SARC v1.
    /// </summary>
    public QualityMetricResult EvaluateParameters(GeneticParameters parameters, IReadOnlyList<string> sampleFiles)
    {
        ValidateSampleFiles(sampleFiles);
        ArgumentNullException.ThrowIfNull(parameters);

        if (_customEvaluator is not null)
        {
            return _customEvaluator(parameters, sampleFiles);
        }

        IFileClassifier baseClassifier = MlpClassifier.CreateDefault();
        var orchestrator = new ArchiveOrchestrator(
            blockCompressor: new ParameterizedBlockCompressor(
                new BlockCompressor(),
                windowSize: parameters.WindowSize,
                minMatchLength: parameters.MinMatchLength,
                useLazyMatching: false),
            featureExtractor: new FeatureExtractor(),
            fileClassifier: new ParameterizedFileClassifier(baseClassifier, parameters.NoCompressionEntropyThreshold),
            knapsackPacker: new KnapsackPacker(),
            blockSize: _blockSize);

        return QualityMetricCalculator.EvaluateRoundTrip(
            orchestrator,
            sampleFiles,
            password: _password,
            maxVolumeBytes: _maxVolumeBytes,
            alpha: _alpha,
            beta: _beta,
            referenceSeconds: _referenceSeconds);
    }

    private QualityMetricResult EvaluateCached(
        GeneticParameters parameters,
        IReadOnlyList<string> sampleFiles,
        Dictionary<(int, int, int), QualityMetricResult> cache,
        ref int evaluationCount)
    {
        evaluationCount++;
        var key = (
            parameters.WindowSize,
            parameters.MinMatchLength,
            (int)Math.Round(parameters.NoCompressionEntropyThreshold * 100.0));

        if (cache.TryGetValue(key, out QualityMetricResult? cached))
        {
            return cached;
        }

        QualityMetricResult computed = EvaluateParameters(parameters, sampleFiles);
        cache[key] = computed;
        return computed;
    }

    private Individual SelectTournament(List<Individual> population, Random rng)
    {
        int count = Math.Min(_tournamentSize, population.Count);
        Individual best = population[rng.Next(population.Count)];

        for (int i = 1; i < count; i++)
        {
            Individual challenger = population[rng.Next(population.Count)];
            if (challenger.Metrics.TotalScoreQ > best.Metrics.TotalScoreQ)
            {
                best = challenger;
            }
        }

        return best;
    }

    private static (GeneticParameters Child1, GeneticParameters Child2) SinglePointCrossover(
        GeneticParameters parentA,
        GeneticParameters parentB,
        Random rng)
    {
        int cutPoint = rng.Next(1, 3); // 1 або 2 для хромосоми з 3 генів
        return cutPoint switch
        {
            1 => (
                new GeneticParameters(parentA.WindowSize, parentB.MinMatchLength, parentB.NoCompressionEntropyThreshold),
                new GeneticParameters(parentB.WindowSize, parentA.MinMatchLength, parentA.NoCompressionEntropyThreshold)),
            _ => (
                new GeneticParameters(parentA.WindowSize, parentA.MinMatchLength, parentB.NoCompressionEntropyThreshold),
                new GeneticParameters(parentB.WindowSize, parentB.MinMatchLength, parentA.NoCompressionEntropyThreshold))
        };
    }

    private GeneticParameters Mutate(GeneticParameters genes, Random rng)
    {
        int windowSize = genes.WindowSize;
        int minMatch = genes.MinMatchLength;
        double threshold = genes.NoCompressionEntropyThreshold;

        if (rng.NextDouble() < _mutationRate)
        {
            int deltaSteps = rng.Next(-16, 17);
            windowSize = QuantizeWindowSize(windowSize + deltaSteps * WindowStep);
        }

        if (rng.NextDouble() < _mutationRate)
        {
            int delta = rng.Next(-2, 3);
            minMatch = Math.Clamp(minMatch + delta, MinMatchLower, MinMatchUpper);
        }

        if (rng.NextDouble() < _mutationRate)
        {
            double delta = (rng.NextDouble() * 0.8) - 0.4;
            threshold = QuantizeThreshold(threshold + delta);
        }

        return new GeneticParameters(windowSize, minMatch, threshold);
    }

    private static GeneticParameters CreateRandomParameters(Random rng)
    {
        int totalSteps = (MaxWindowSize - MinWindowSize) / WindowStep;
        int windowSize = MinWindowSize + rng.Next(0, totalSteps + 1) * WindowStep;
        int minMatch = rng.Next(MinMatchLower, MinMatchUpper + 1);
        double threshold = QuantizeThreshold(MinEntropyThreshold + rng.NextDouble() * (MaxEntropyThreshold - MinEntropyThreshold));

        return new GeneticParameters(windowSize, minMatch, threshold);
    }

    private static int QuantizeWindowSize(int value)
    {
        int clamped = Math.Clamp(value, MinWindowSize, MaxWindowSize);
        int offset = clamped - MinWindowSize;
        int rounded = MinWindowSize + ((offset + WindowStep / 2) / WindowStep) * WindowStep;
        return Math.Clamp(rounded, MinWindowSize, MaxWindowSize);
    }

    private static double QuantizeThreshold(double value)
    {
        double clamped = Math.Clamp(value, MinEntropyThreshold, MaxEntropyThreshold);
        return Math.Round(clamped, 2);
    }

    private static GaGenerationRecord BuildGenerationRecord(int generation, List<Individual> sortedPopulation, int evaluationsSoFar)
    {
        double bestQ = sortedPopulation[0].Metrics.TotalScoreQ;
        double worstQ = sortedPopulation[^1].Metrics.TotalScoreQ;
        double avgQ = sortedPopulation.Average(ind => ind.Metrics.TotalScoreQ);

        return new GaGenerationRecord(
            Generation: generation,
            BestQ: bestQ,
            AverageQ: avgQ,
            WorstQ: worstQ,
            BestS: sortedPopulation[0].Metrics.CompressionScoreS,
            BestT: sortedPopulation[0].Metrics.SpeedScoreT,
            BestParameters: sortedPopulation[0].Parameters,
            EvaluationsSoFar: evaluationsSoFar);
    }

    private static int CompareIndividualsDesc(Individual a, Individual b)
    {
        int cmp = b.Metrics.TotalScoreQ.CompareTo(a.Metrics.TotalScoreQ);
        if (cmp != 0)
        {
            return cmp;
        }

        return b.Metrics.CompressionScoreS.CompareTo(a.Metrics.CompressionScoreS);
    }

    private static void ValidateSampleFiles(IReadOnlyList<string> sampleFiles)
    {
        ArgumentNullException.ThrowIfNull(sampleFiles);
        if (sampleFiles.Count == 0)
        {
            throw new ArgumentException("Sample files list cannot be empty.", nameof(sampleFiles));
        }
    }

    private sealed record Individual(GeneticParameters Parameters, QualityMetricResult Metrics);
}
