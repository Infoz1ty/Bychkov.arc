using System.Diagnostics;
using System.Globalization;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Packing;
using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Benchmarks;

/// <summary>
/// Генерує Таблицю №3 звіту (Issue #27): порівняння ДП-рюкзака 0/1 та жадібного алгоритму
/// на першому томі, зібраному з реальних блоків team/corpus.
/// team/ відкривається лише для читання.
/// </summary>
public static class Program
{
    private const int BlockSize = 16384;
    private const int MaxVolumeBytes = 65536;

    // Пріоритети типів із team_config.json: 0,1 -> 3; 2,3,4 -> 2; 5,6 -> 1.
    private static readonly int[] Priorities = [3, 3, 2, 2, 2, 1, 1];

    public static int Main(string[] args)
    {
        string repositoryRoot = FindRepositoryRoot();
        string corpusDirectory = Path.Combine(repositoryRoot, "team", "corpus");
        string labelsPath = Path.Combine(corpusDirectory, "labels.csv");

        if (!File.Exists(labelsPath))
        {
            Console.Error.WriteLine($"Labels file not found: {labelsPath}");
            return 1;
        }

        Dictionary<string, byte> labels = ReadLabels(labelsPath);
        var files = new List<ArchiveFileInfo>();
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

        Console.WriteLine("# Таблиця №3 — ДП-рюкзак 0/1 проти жадібного алгоритму (перший том)");
        Console.WriteLine();
        Console.WriteLine($"- Файлів у корпусі: {files.Count}");
        Console.WriteLine($"- Блоків-кандидатів: {candidates.Count}");
        Console.WriteLine($"- Розмір тому: {MaxVolumeBytes} байт");
        Console.WriteLine($"- Таблиця файлів: {plan.FileTableSize} байт");
        Console.WriteLine($"- Чиста місткість W: {plan.UsableBlockCapacity} байт");
        Console.WriteLine();
        Console.WriteLine("| Показник | ДП 0/1 | Жадібний |");
        Console.WriteLine("|---|---:|---:|");
        Console.WriteLine($"| Сумарна цінність | {dp.TotalValue} | {greedy.TotalValue} |");
        Console.WriteLine($"| Сумарна вага, байт | {dp.TotalWeight} | {greedy.TotalWeight} |");
        Console.WriteLine($"| Кількість блоків | {dp.SelectedBlocks.Count} | {greedy.SelectedBlocks.Count} |");
        Console.WriteLine($"| Час, мс (мінімум із 3 прогонів) | {dpMs.ToString("F3", CultureInfo.InvariantCulture)} | {greedyMs.ToString("F3", CultureInfo.InvariantCulture)} |");
        Console.WriteLine($"| Різниця цінності (ДП − greedy) | {dp.TotalValue - greedy.TotalValue} | — |");
        Console.WriteLine($"| Різниця ваги (ДП − greedy), байт | {dp.TotalWeight - greedy.TotalWeight} | — |");
        Console.WriteLine();

        return 0;
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
