using System.Globalization;
using System.Text;
using SmartSecureArchiver.Core.Optimization;
using SmartSecureArchiver.Core.Security;
using SmartSecureArchiver.Core.Security.Attack;

namespace SmartSecureArchiver.Zone3Runner;

/// <summary>
/// Генератор експериментальних звітів і журналу еволюції ГА для Зони 3 (Учасник 3: Залєвський Володимир):
/// - Таблиця №4 (Issue #37): Стиснути перед шифруванням vs Зашифрувати перед стисненням
/// - Таблиця №5 + ga_evolution_log.json (Issues #35, #36, D1 #17): ГА vs Random Search
/// - Модуль базової атаки (Issue #38): криптоаналіз слабких шифрів ГА + перевірка цілісності архіву
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        string repoRoot = FindRepositoryRoot();
        string corpusDir = Path.Combine(repoRoot, "team", "corpus");
        string reportsDir = Path.Combine(repoRoot, "reports");
        Directory.CreateDirectory(reportsDir);

        List<string> corpusFiles = Directory.GetFiles(corpusDir)
            .Where(f => !f.EndsWith("labels.csv", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Console.WriteLine($"[Zone3] Corpus files: {corpusFiles.Count}");

        // 1. Issue #37 — Таблиця №4: Стиснути перед шифруванням vs Зашифрувати перед стисненням
        Console.WriteLine("[Zone3] Running Issue #37 (Compress-then-Encrypt vs Encrypt-then-Compress)...");
        var compressionOrderExp = new CompressionOrderExperiment();
        CompressionOrderReport table4Report = compressionOrderExp.Run(corpusFiles, password: "algo2026");
        string table4Md = CompressionOrderExperiment.FormatMarkdownTable(table4Report);
        string table4Path = Path.Combine(reportsDir, "table4_encrypt_vs_compress.md");
        File.WriteAllText(table4Path, table4Md, Encoding.UTF8);
        Console.WriteLine($"  -> Saved {table4Path}");

        // 2. Issues #35, #36 — ГА vs Random Search + журнал еволюції ГА + Таблиця №5
        Console.WriteLine("[Zone3] Running Issues #35-#36 (Genetic Algorithm vs Random Search on full corpus)...");
        var optimizer = new GeneticOptimizer(password: "algo2026", seed: 2001);
        GaOptimizationReport gaReport = optimizer.OptimizeWithLog(corpusFiles, generations: 6, populationSize: 10);
        RandomSearchReport rsReport = optimizer.RunRandomSearchWithLog(corpusFiles, iterations: gaReport.TotalEvaluations);

        string gaLogPath = Path.Combine(reportsDir, "ga_evolution_log.json");
        GeneticOptimizer.SaveEvolutionLog(gaLogPath, gaReport, rsReport);
        Console.WriteLine($"  -> Saved {gaLogPath}");

        string table5Md = FormatTable5Markdown(gaReport, rsReport);
        string table5Path = Path.Combine(reportsDir, "table5_ga_vs_random.md");
        File.WriteAllText(table5Path, table5Md, Encoding.UTF8);
        Console.WriteLine($"  -> Saved {table5Path}");

        // 3. Issue #38 — Базовий модуль атаки (Віженер, підстановка, XOR) + модифікація байтів архіву
        Console.WriteLine("[Zone3] Running Issue #38 (Weak cipher GA attacks & SARC tamper audit)...");
        string attackReportMd = RunIssue38AndFormatReport(repoRoot, corpusDir);
        string attackPath = Path.Combine(reportsDir, "attack_and_tamper_report.md");
        File.WriteAllText(attackPath, attackReportMd, Encoding.UTF8);
        Console.WriteLine($"  -> Saved {attackPath}");

        Console.WriteLine("[Zone3] Done.");
        return 0;
    }

    private static string FormatTable5Markdown(GaOptimizationReport ga, RandomSearchReport rs)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Таблиця №5 — Порівняння Генетичного алгоритму (ГА) проти Random Search (Issues #35, #36)");
        sb.AppendLine();
        sb.AppendLine($"- Seed: `{ga.Seed}`");
        sb.AppendLine($"- Бюджет обчислень метрики $Q$: **{ga.TotalEvaluations}** оцінок (ГА: `pop={ga.PopulationSize}`, `gen={ga.Generations}`; Random Search: `iterations={rs.Iterations}`)");
        sb.AppendLine($"- Перевірка кейсу **D1 №17** (`best_final >= best_initial`): **{ga.BestFinalQ.ToString("F6", CultureInfo.InvariantCulture)} >= {ga.BestInitialQ.ToString("F6", CultureInfo.InvariantCulture)}** — **{(ga.BestFinalQ >= ga.BestInitialQ ? "ПРОЙДЕНО" : "ПРОВАЛЕНО")}**");
        sb.AppendLine();
        sb.AppendLine("## 1. Зведена таблиця порівняння (ГА vs Random Search)");
        sb.AppendLine();
        sb.AppendLine("| Метод | Бюджет оцінок Q | Найкраще Q | Середнє Q | Компонента S | Компонента T | Знайдені параметри `[window_size, min_match, no_comp_threshold]` | Час пошуку (с) |");
        sb.AppendLine("|---|---:|---:|---:|---:|---:|---|---:|");

        GaGenerationRecord lastGen = ga.GenerationsHistory[^1];
        string gaParams = $"`[{ga.BestParameters.WindowSize}, {ga.BestParameters.MinMatchLength}, {ga.BestParameters.NoCompressionEntropyThreshold.ToString("F2", CultureInfo.InvariantCulture)}]`";
        string rsParams = $"`[{rs.BestParameters.WindowSize}, {rs.BestParameters.MinMatchLength}, {rs.BestParameters.NoCompressionEntropyThreshold.ToString("F2", CultureInfo.InvariantCulture)}]`";

        sb.AppendLine($"| **Генетичний алгоритм (елітизм)** | {ga.TotalEvaluations} | **{ga.BestFinalQ.ToString("F6", CultureInfo.InvariantCulture)}** | {lastGen.AverageQ.ToString("F6", CultureInfo.InvariantCulture)} | {lastGen.BestS.ToString("F4", CultureInfo.InvariantCulture)} | {lastGen.BestT.ToString("F4", CultureInfo.InvariantCulture)} | {gaParams} | {ga.ElapsedSeconds.ToString("F3", CultureInfo.InvariantCulture)} |");
        sb.AppendLine($"| Random Search (baseline) | {rs.Iterations} | {rs.BestQ.ToString("F6", CultureInfo.InvariantCulture)} | {rs.AverageQ.ToString("F6", CultureInfo.InvariantCulture)} | {rs.BestS.ToString("F4", CultureInfo.InvariantCulture)} | {rs.BestT.ToString("F4", CultureInfo.InvariantCulture)} | {rsParams} | {rs.ElapsedSeconds.ToString("F3", CultureInfo.InvariantCulture)} |");
        sb.AppendLine();
        sb.AppendLine("## 2. Журнал еволюції ГА за поколіннями");
        sb.AppendLine();
        sb.AppendLine("| Покоління | Найкраще Q | Середнє Q | Найгірше Q | Best S | Best T | Найкращі параметри | Оцінок Q |");
        sb.AppendLine("|---:|---:|---:|---:|---:|---:|---|---:|");

        foreach (GaGenerationRecord rec in ga.GenerationsHistory)
        {
            string pStr = $"`[{rec.BestParameters.WindowSize}, {rec.BestParameters.MinMatchLength}, {rec.BestParameters.NoCompressionEntropyThreshold.ToString("F2", CultureInfo.InvariantCulture)}]`";
            sb.AppendLine($"| {rec.Generation} | {rec.BestQ.ToString("F6", CultureInfo.InvariantCulture)} | {rec.AverageQ.ToString("F6", CultureInfo.InvariantCulture)} | {rec.WorstQ.ToString("F6", CultureInfo.InvariantCulture)} | {rec.BestS.ToString("F4", CultureInfo.InvariantCulture)} | {rec.BestT.ToString("F4", CultureInfo.InvariantCulture)} | {pStr} | {rec.EvaluationsSoFar} |");
        }

        return sb.ToString();
    }

    private static string RunIssue38AndFormatReport(string repoRoot, string corpusDir)
    {
        const string sampleEnglish =
            "The smart secure archiver combines Lempel Ziv compression with canonical Huffman coding " +
            "and authenticated encryption using AES counter mode with HMAC SHA256 verification. " +
            "When data is compressed before encryption, statistical redundancy is removed effectively, " +
            "which improves storage efficiency and makes cryptanalysis significantly harder than classical ciphers.";

        var attackerEn = new WeakCipherGeneticAttacker(NgramFrequencyScorer.CreateDefaultEnglish(), seed: 2001);

        string vigCipher = WeakCiphers.EncryptVigenere(sampleEnglish, "KEY");
        CipherAttackResult vigRes = attackerEn.AttackVigenere(vigCipher, maxKeyLength: 8, populationSize: 50, generations: 60);

        string subAlphabet = "QWERTYUIOPASDFGHJKLZXCVBNM";
        string subCipher = WeakCiphers.EncryptSubstitution(sampleEnglish, subAlphabet);
        CipherAttackResult subRes = attackerEn.AttackSubstitution(subCipher, populationSize: 60, generations: 80);

        byte[] xorCipher = WeakCiphers.ApplyRepeatingXor(Encoding.ASCII.GetBytes(sampleEnglish), "SARC"u8);
        XorAttackResult xorRes = attackerEn.AttackRepeatingXor(xorCipher, maxKeyLength: 8, populationSize: 50, generations: 50);

        string ukrTrain = File.ReadAllText(Path.Combine(corpusDir, "f0014.txt"), Encoding.UTF8);
        string ukrTarget = File.ReadAllText(Path.Combine(corpusDir, "f0000.txt"), Encoding.UTF8)[..600];
        var attackerUkr = new WeakCipherGeneticAttacker(NgramFrequencyScorer.TrainFromText(ukrTrain), seed: 2001);
        string ukrVigCipher = WeakCiphers.EncryptVigenere(ukrTarget, "КЛЮЧ", WeakCiphers.UkrainianAlphabet);
        CipherAttackResult ukrVigRes = attackerUkr.AttackVigenere(
            ukrVigCipher,
            alphabet: WeakCiphers.UkrainianAlphabet,
            maxKeyLength: 8,
            populationSize: 50,
            generations: 60);

        int subMatches = sampleEnglish.Zip(subRes.RecoveredPlaintext, (a, b) => a == b ? 1 : 0).Sum();
        double subAccuracy = (double)subMatches / sampleEnglish.Length * 100.0;

        string refArc = Path.Combine(repoRoot, "team", "reference", "ref_01_single_file.arc");
        IReadOnlyList<TamperProbeResult> tamperResults = ArchiveTamperTool.RunTamperAudit(refArc, "algo2026");

        var sb = new StringBuilder();
        sb.AppendLine("# Звіт Issue #38 — Базовий модуль атаки та перевірка цілісності архіву");
        sb.AppendLine();
        sb.AppendLine("## 1. Криптоаналіз слабких шифрів генетичним алгоритмом за частотами n-грам");
        sb.AppendLine();
        sb.AppendLine("| Шифр | Справжній ключ | Відновлений ключ | Точність відновлення тексту |");
        sb.AppendLine("|---|---|---|---:|");
        sb.AppendLine($"| Віженер (EN) | `KEY` | `{vigRes.RecoveredKey}` | {(vigRes.RecoveredPlaintext == sampleEnglish ? "100.0%" : "Частково")} |");
        sb.AppendLine($"| Віженер (UA, корпус) | `КЛЮЧ` | `{ukrVigRes.RecoveredKey}` | {(ukrVigRes.RecoveredPlaintext == ukrTarget ? "100.0%" : "Частково")} |");
        sb.AppendLine($"| Підстановка (EN) | `{subAlphabet}` | `{subRes.RecoveredKey}` | {subAccuracy.ToString("F1", CultureInfo.InvariantCulture)}% |");
        sb.AppendLine($"| Короткий XOR (EN) | `SARC` | `{xorRes.RecoveredKeyAscii}` (`0x{xorRes.RecoveredKeyHex}`) | {(xorRes.RecoveredPlaintextBytes.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes(sampleEnglish)) ? "100.0%" : "Частково")} |");
        sb.AppendLine();
        sb.AppendLine("## 2. Аудит цілісності чужого архіву (`team/reference/ref_01_single_file.arc`)");
        sb.AppendLine();
        sb.AppendLine("| Модифікація байтів | Очікуваний код | Отриманий код | Чистий каталог виводу | Статус |");
        sb.AppendLine("|---|---|---|---|---|");
        foreach (TamperProbeResult probe in tamperResults)
        {
            sb.AppendLine($"| {probe.AttackName} | `{probe.ExpectedCode}` | `{probe.ActualCode}` | {(probe.OutputDirectoryUntouched ? "ТАК" : "НІ")} | {(probe.RejectedCleanly ? "OK" : "FAIL")} |");
        }

        return sb.ToString();
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "team", "team_config.json")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root with team/team_config.json.");
    }
}
