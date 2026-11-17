using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Optimization;
using SmartSecureArchiver.Core.Packing;
using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Benchmarks;

/// <summary>
/// Генерує Таблицю №2 (Issue #47, Ablation Study) та Таблицю №3 звіту (Issue #27, ДП-рюкзак 0/1 проти жадібного)
/// на реальному корпусі team/corpus (відкривається лише для читання).
/// </summary>
public static class Program
{
    private const int BlockSize = 16384;
    private const int MaxVolumeBytes = 65536;

    // Пріоритети типів із team_config.json: 0,1 -> 3; 2,3,4 -> 2; 5,6 -> 1.
    private static readonly int[] Priorities = [3, 3, 2, 2, 2, 1, 1];

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        string repositoryRoot = FindRepositoryRoot();
        string corpusDirectory = Path.Combine(repositoryRoot, "team", "corpus");
        string labelsPath = Path.Combine(corpusDirectory, "labels.csv");
        string reportsDir = Path.Combine(repositoryRoot, "reports");
        Directory.CreateDirectory(reportsDir);

        if (!File.Exists(labelsPath))
        {
            Console.Error.WriteLine($"Labels file not found: {labelsPath}");
            return 1;
        }

        Dictionary<string, byte> labels = ReadLabels(labelsPath);
        var files = new List<ArchiveFileInfo>();
        var corpusPaths = new List<string>();
        var candidates = new List<BlockCandidate>();
        var compressor = new BlockCompressor();
        var crypto = new CryptoEngine();
        int blockId = 0;

        foreach ((string fileName, byte fileType) in labels)
        {
            string path = Path.Combine(corpusDirectory, fileName);
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"Skipping missing corpus file: {path}");
                continue;
            }

            corpusPaths.Add(path);
            byte[] data = File.ReadAllBytes(path);
            var fileIndex = (ushort)files.Count;
            files.Add(new ArchiveFileInfo(fileName, (uint)data.Length, crypto.ComputeCrc32(data), fileType));

            bool allowCompression = fileType != 5;
            uint blockSeq = 0;

            for (int offset = 0; offset < data.Length; offset += BlockSize)
            {
                ReadOnlySpan<byte> block = data.AsSpan(offset, Math.Min(BlockSize, data.Length - offset));
                byte[] coded = compressor.Compress(block, out byte blockFlags, allowCompression);
                candidates.Add(new BlockCandidate(
                    BlockId: ++blockId,
                    Weight: coded.Length + 15,
                    Value: Priorities[fileType],
                    Data: coded,
                    FileIndex: fileIndex,
                    BlockSeq: blockSeq++,
                    RawLength: (uint)block.Length,
                    BlockFlags: blockFlags));
            }
        }

        if (candidates.Count == 0)
        {
            Console.Error.WriteLine("No block candidates were produced.");
            return 1;
        }

        var planner = new VolumeCapacityCalculator();
        VolumeCapacityPlan plan = planner.Plan(MaxVolumeBytes, files, candidates);
        var packer = new KnapsackPacker();

        (PackingResult dp, double dpMs) = Measure(() => packer.PackVolumeDp(plan.UsableBlockCapacity, candidates));
        (PackingResult greedy, double greedyMs) = Measure(() => packer.PackVolumeGreedy(plan.UsableBlockCapacity, candidates));

        var table3Sb = new StringBuilder();
        table3Sb.AppendLine("# Таблиця №3 — ДП-рюкзак 0/1 проти жадібного алгоритму (перший том)");
        table3Sb.AppendLine();
        table3Sb.AppendLine($"- Файлів у корпусі: {files.Count}");
        table3Sb.AppendLine($"- Блоків-кандидатів: {candidates.Count}");
        table3Sb.AppendLine($"- Розмір тому: {MaxVolumeBytes} байт");
        table3Sb.AppendLine($"- Таблиця файлів: {plan.FileTableSize} байт");
        table3Sb.AppendLine($"- Чиста місткість W: {plan.UsableBlockCapacity} байт");
        table3Sb.AppendLine();
        table3Sb.AppendLine("| Показник | ДП 0/1 | Жадібний |");
        table3Sb.AppendLine("|---|---:|---:|");
        table3Sb.AppendLine($"| Сумарна цінність | {dp.TotalValue} | {greedy.TotalValue} |");
        table3Sb.AppendLine($"| Сумарна вага, байт | {dp.TotalWeight} | {greedy.TotalWeight} |");
        table3Sb.AppendLine($"| Кількість блоків | {dp.SelectedBlocks.Count} | {greedy.SelectedBlocks.Count} |");
        table3Sb.AppendLine($"| Час, мс (мінімум із 3 прогонів) | {dpMs.ToString("F3", CultureInfo.InvariantCulture)} | {greedyMs.ToString("F3", CultureInfo.InvariantCulture)} |");
        table3Sb.AppendLine($"| Різниця цінності (ДП − greedy) | {dp.TotalValue - greedy.TotalValue} | — |");
        table3Sb.AppendLine($"| Різниця ваги (ДП − greedy), байт | {dp.TotalWeight - greedy.TotalWeight} | — |");

        string table3Content = table3Sb.ToString();
        string table3Path = Path.Combine(reportsDir, "table3_knapsack.md");
        File.WriteAllText(table3Path, table3Content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        Console.WriteLine(table3Content);
        Console.WriteLine($"-> Збережено {table3Path}");
        Console.WriteLine();

        // Генерація Таблиці №2 (Ablation Study, Issue #47)
        corpusPaths.Sort(StringComparer.Ordinal);
        GeneticParameters? gaParams = TryLoadBestGaParameters(Path.Combine(reportsDir, "ga_evolution_log.json"));
        AblationStudyReport ablationReport = AblationStudyRunner.Run(
            corpusPaths,
            password: "algo2026",
            maxVolumeBytes: MaxVolumeBytes,
            blockSize: BlockSize,
            alpha: QualityMetricCalculator.DefaultAlpha,
            beta: QualityMetricCalculator.DefaultBeta,
            referenceSeconds: QualityMetricCalculator.DefaultReferenceSeconds,
            runsPerVariant: 3,
            gaOptimizedParameters: gaParams);

        string table2Path = Path.Combine(reportsDir, "table2_ablation.md");
        string table2JsonPath = Path.Combine(reportsDir, "ablation_results.json");
        AblationStudyRunner.SaveReport(table2Path, table2JsonPath, ablationReport);
        Console.WriteLine(AblationStudyRunner.FormatMarkdownTable(ablationReport));
        Console.WriteLine($"-> Збережено {table2Path} та {table2JsonPath}");

        return ablationReport.Variants.All(v => v.IsByteExact) ? 0 : 1;
    }

    private static GeneticParameters? TryLoadBestGaParameters(string gaLogPath)
    {
        if (!File.Exists(gaLogPath))
        {
            return null;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(gaLogPath));
            if (!doc.RootElement.TryGetProperty("genetic_algorithm", out JsonElement gaEl) ||
                !gaEl.TryGetProperty("BestParameters", out JsonElement bestEl))
            {
                return null;
            }

            int windowSize = bestEl.GetProperty("WindowSize").GetInt32();
            int minMatch = bestEl.GetProperty("MinMatchLength").GetInt32();
            double threshold = bestEl.GetProperty("NoCompressionEntropyThreshold").GetDouble();
            return new GeneticParameters(windowSize, minMatch, threshold);
        }
        catch
        {
            return null;
        }
    }

    private static (PackingResult Result, double Milliseconds) Measure(Func<PackingResult> action)
    {
        _ = action();

        PackingResult result = null!;
        double bestMilliseconds = double.MaxValue;

        for (int run = 0; run < 3; run++)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            result = action();
            stopwatch.Stop();
            bestMilliseconds = Math.Min(bestMilliseconds, stopwatch.Elapsed.TotalMilliseconds);
        }

        return (result, bestMilliseconds);
    }

    private static Dictionary<string, byte> ReadLabels(string labelsPath)
    {
        var labels = new Dictionary<string, byte>(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(labelsPath).Skip(1))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            string[] parts = line.Split(',');
            if (parts.Length < 2 || !byte.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out byte fileType))
            {
                throw new InvalidDataException($"Malformed labels line: {line}");
            }

            labels[parts[0]] = fileType;
        }

        return labels;
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
}
