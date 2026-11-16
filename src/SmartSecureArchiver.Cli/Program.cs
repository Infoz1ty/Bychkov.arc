using System.Diagnostics;
using System.Text;
using System.Text.Json;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Cli;

public static class Program
{
    public const int DefaultMaxVolumeBytes = 65536;
    public const int DefaultBlockSize = 16384;

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;

        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return 0;
        }

        string command = args[0].ToLowerInvariant();
        var inputTargets = new List<string>();
        var archiveVolumes = new List<string>();
        string? output = null;
        string? password = null;
        string? configPath = null;
        int? maxVolumeOverride = null;
        int? blockSizeOverride = null;

        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "-i":
                case "--input":
                    while (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                    {
                        inputTargets.Add(args[++i]);
                    }
                    break;

                case "-a":
                case "--archive":
                    while (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                    {
                        archiveVolumes.Add(args[++i]);
                    }
                    break;

                case "-o":
                case "--output":
                    if (i + 1 < args.Length)
                    {
                        output = args[++i];
                    }
                    break;

                case "-p":
                case "--password":
                    if (i + 1 < args.Length)
                    {
                        password = args[++i];
                    }
                    break;

                case "-c":
                case "--config":
                    if (i + 1 < args.Length)
                    {
                        configPath = args[++i];
                    }
                    break;

                case "-m":
                case "--max-volume":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int parsedMax))
                    {
                        maxVolumeOverride = parsedMax;
                    }
                    break;

                case "-b":
                case "--block-size":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int parsedBlock))
                    {
                        blockSizeOverride = parsedBlock;
                    }
                    break;

                default:
                    Console.Error.WriteLine($"Невідомий параметр: '{arg}'.");
                    PrintUsage();
                    return 2;
            }
        }

        CliTeamConfig config = LoadTeamConfig(configPath);
        int maxVolumeBytes = maxVolumeOverride ?? config.MaxVolumeBytes;
        int blockSize = blockSizeOverride ?? config.BlockSize;

        var orchestrator = ArchiveOrchestratorFactory.CreateDefault(blockSize: blockSize);

        try
        {
            switch (command)
            {
                case "archive":
                {
                    if (inputTargets.Count == 0 || string.IsNullOrWhiteSpace(output) || password is null)
                    {
                        Console.Error.WriteLine("Помилка: для команди 'archive' обов'язкові параметри -i, -o та -p.");
                        PrintUsage();
                        return 2;
                    }

                    List<string> resolvedFiles = ResolveInputFiles(inputTargets);
                    var sw = Stopwatch.StartNew();
                    IReadOnlyList<string> volumes = orchestrator.CreateArchive(resolvedFiles, output, password, maxVolumeBytes);
                    sw.Stop();

                    long origBytes = resolvedFiles.Sum(f => new FileInfo(f).Length);
                    long arcBytes = volumes.Sum(v => new FileInfo(v).Length);

                    Console.WriteLine($"[OK] Архів успішно створено за {sw.Elapsed.TotalSeconds:F3} с.");
                    Console.WriteLine($"  Файлів: {resolvedFiles.Count} ({origBytes} байтів)");
                    Console.WriteLine($"  Томів:  {volumes.Count} ({arcBytes} байтів, ліміт тому: {maxVolumeBytes} байтів)");
                    foreach (string vol in volumes)
                    {
                        Console.WriteLine($"  -> {vol}");
                    }

                    return 0;
                }

                case "extract":
                {
                    if (archiveVolumes.Count == 0 || string.IsNullOrWhiteSpace(output) || password is null)
                    {
                        Console.Error.WriteLine("Помилка: для команди 'extract' обов'язкові параметри -a, -o та -p.");
                        PrintUsage();
                        return 2;
                    }

                    var sw = Stopwatch.StartNew();
                    if (archiveVolumes.Count == 1)
                    {
                        orchestrator.ExtractArchive(archiveVolumes[0], output, password);
                    }
                    else
                    {
                        orchestrator.ExtractArchive(archiveVolumes, output, password);
                    }
                    sw.Stop();

                    Console.WriteLine($"[OK] Архів успішно розпаковано у '{output}' за {sw.Elapsed.TotalSeconds:F3} с.");
                    return 0;
                }

                case "benchmark":
                {
                    if (inputTargets.Count == 0)
                    {
                        Console.Error.WriteLine("Помилка: для команди 'benchmark' вкажіть файли або каталог через -i.");
                        PrintUsage();
                        return 2;
                    }

                    string benchPassword = password ?? config.DefaultPassword;
                    List<string> resolvedFiles = ResolveInputFiles(inputTargets);

                    QualityMetricResult result = QualityMetricCalculator.EvaluateRoundTrip(
                        orchestrator,
                        resolvedFiles,
                        password: benchPassword,
                        maxVolumeBytes: maxVolumeBytes,
                        alpha: config.Alpha,
                        beta: config.Beta,
                        referenceSeconds: config.ReferenceSeconds);

                    Console.WriteLine("=== Результати вимірювання метрики якості Q (SARC v1) ===");
                    Console.WriteLine($"  Файлів у вибірці:       {resolvedFiles.Count}");
                    Console.WriteLine($"  Побайтовий збіг:        {(result.IsByteExact ? "ТАК (original == restored)" : "НІ (Q = 0)")}");
                    Console.WriteLine($"  Сирий розмір B_orig:    {result.OriginalBytes} байтів");
                    Console.WriteLine($"  Розмір архіву B_arc:    {result.ArchiveBytes} байтів");
                    Console.WriteLine($"  Час виконання t:        {result.ElapsedSeconds:F4} с");
                    Console.WriteLine($"  Компонента стиснення S: {result.CompressionScoreS:F4}");
                    Console.WriteLine($"  Компонента швидкодії T: {result.SpeedScoreT:F4}");
                    Console.WriteLine($"  Підсумкова метрика Q:   {result.TotalScoreQ:F4}");

                    return result.IsByteExact ? 0 : 1;
                }

                default:
                    Console.Error.WriteLine($"Невідома команда: '{command}'.");
                    PrintUsage();
                    return 2;
            }
        }
        catch (SarcException ex)
        {
            Console.Error.WriteLine(ex.ErrorCode.ToString());
            Console.Error.WriteLine(ex.Message);
            return (int)ex.ErrorCode;
        }
        catch (FileNotFoundException ex)
        {
            Console.Error.WriteLine($"E_FILE_NOT_FOUND: {ex.Message}");
            return 3;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"E_ACCESS_DENIED: {ex.Message}");
            return 4;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"E_INTERNAL: {ex.Message}");
            return 1;
        }
    }

    private static List<string> ResolveInputFiles(List<string> inputTargets)
    {
        var files = new List<string>();
        foreach (string target in inputTargets)
        {
            if (Directory.Exists(target))
            {
                string[] dirFiles = Directory.GetFiles(target, "*", SearchOption.TopDirectoryOnly)
                    .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                files.AddRange(dirFiles);
            }
            else
            {
                files.Add(target);
            }
        }

        if (files.Count == 0)
        {
            throw new FileNotFoundException("Жодного вхідного файлу не знайдено.");
        }

        return files;
    }

    private static CliTeamConfig LoadTeamConfig(string? explicitPath)
    {
        string? path = explicitPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            DirectoryInfo? dir = new(Directory.GetCurrentDirectory());
            while (dir is not null)
            {
                string candidate = Path.Combine(dir.FullName, "team", "team_config.json");
                if (File.Exists(candidate))
                {
                    path = candidate;
                    break;
                }

                dir = dir.Parent;
            }
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new CliTeamConfig(DefaultMaxVolumeBytes, DefaultBlockSize, "algo2026", 0.7, 0.3, 30.0);
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
            JsonElement root = doc.RootElement;

            string defaultPass = root.TryGetProperty("пароль_сеансу", out JsonElement passEl)
                ? passEl.GetString() ?? "algo2026"
                : "algo2026";

            int maxVol = DefaultMaxVolumeBytes;
            int blockSize = DefaultBlockSize;
            if (root.TryGetProperty("пакування", out JsonElement packEl))
            {
                if (packEl.TryGetProperty("max_volume_bytes", out JsonElement mvEl))
                {
                    maxVol = mvEl.GetInt32();
                }

                if (packEl.TryGetProperty("block_size", out JsonElement bsEl))
                {
                    blockSize = bsEl.GetInt32();
                }
            }

            double alpha = 0.7;
            double beta = 0.3;
            double tRef = 30.0;
            if (root.TryGetProperty("метрика_Q", out JsonElement qEl))
            {
                if (qEl.TryGetProperty("alpha", out JsonElement aEl))
                {
                    alpha = aEl.GetDouble();
                }

                if (qEl.TryGetProperty("beta", out JsonElement bEl))
                {
                    beta = bEl.GetDouble();
                }

                if (qEl.TryGetProperty("t_ref_секунд", out JsonElement tEl))
                {
                    tRef = tEl.GetDouble();
                }
            }

            return new CliTeamConfig(maxVol, blockSize, defaultPass, alpha, beta, tRef);
        }
        catch
        {
            return new CliTeamConfig(DefaultMaxVolumeBytes, DefaultBlockSize, "algo2026", 0.7, 0.3, 30.0);
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("SmartSecureArchiver — Консольний архіватор SARC v1");
        Console.WriteLine("Використання:");
        Console.WriteLine("  1. Архівування файлів:");
        Console.WriteLine("     archive -i <files_or_dir...> -o <output.arc> -p <password> [-m <max_volume_bytes>] [-b <block_size>] [-c <team_config.json>]");
        Console.WriteLine("  2. Розархівування томів (у будь-якому порядку):");
        Console.WriteLine("     extract -a <volumes...> -o <output_dir> -p <password>");
        Console.WriteLine("  3. Оцінка метрики якості Q = a*S + b*T:");
        Console.WriteLine("     benchmark -i <files_or_dir...> [-p <password>] [-m <max_volume_bytes>] [-c <team_config.json>]");
    }

    private sealed record CliTeamConfig(
        int MaxVolumeBytes,
        int BlockSize,
        string DefaultPassword,
        double Alpha,
        double Beta,
        double ReferenceSeconds
    );
}
