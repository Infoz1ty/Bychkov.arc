using System.Diagnostics;

namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Результат обчислення єдиної метрики якості Q (Issue #47, team_config.json).
/// </summary>
public sealed record QualityMetricResult(
    bool IsByteExact,
    long OriginalBytes,
    long ArchiveBytes,
    double ElapsedSeconds,
    double CompressionScoreS,
    double SpeedScoreT,
    double TotalScoreQ
);

/// <summary>
/// Калькулятор єдиної метрики якості системи SARC v1 (Issue #47):
/// Q = alpha * S + beta * T, де S = B_orig / (B_orig + B_arc), T = t_ref / (t_ref + t).
/// Якщо хоча б один файл не відновлено побайтово (original != restored), Q = 0.
/// </summary>
public static class QualityMetricCalculator
{
    public const double DefaultAlpha = 0.7;
    public const double DefaultBeta = 0.3;
    public const double DefaultReferenceSeconds = 30.0;

    /// <summary>
    /// Обчислює компоненти S, T та підсумкову метрику Q за відомими розмірами і часом.
    /// </summary>
    public static QualityMetricResult Compute(
        long originalBytes,
        long archiveBytes,
        double elapsedSeconds,
        bool isByteExact = true,
        double alpha = DefaultAlpha,
        double beta = DefaultBeta,
        double referenceSeconds = DefaultReferenceSeconds)
    {
        if (!isByteExact || originalBytes < 0 || archiveBytes <= 0 || elapsedSeconds < 0)
        {
            return new QualityMetricResult(
                IsByteExact: false,
                OriginalBytes: Math.Max(0, originalBytes),
                ArchiveBytes: Math.Max(0, archiveBytes),
                ElapsedSeconds: Math.Max(0, elapsedSeconds),
                CompressionScoreS: 0.0,
                SpeedScoreT: 0.0,
                TotalScoreQ: 0.0);
        }

        double s = originalBytes == 0
            ? 0.0
            : (double)originalBytes / (originalBytes + archiveBytes);

        double t = referenceSeconds / (referenceSeconds + elapsedSeconds);
        double q = alpha * s + beta * t;

        return new QualityMetricResult(
            IsByteExact: true,
            OriginalBytes: originalBytes,
            ArchiveBytes: archiveBytes,
            ElapsedSeconds: elapsedSeconds,
            CompressionScoreS: s,
            SpeedScoreT: t,
            TotalScoreQ: q);
    }

    /// <summary>
    /// Проводить повний цикл архівування -> розархівування -> побайтової звірки всіх файлів
    /// та повертає метрику якості Q (для ГА та Ablation Study — Таблиця №2 звіту).
    /// </summary>
    public static QualityMetricResult EvaluateRoundTrip(
        IArchiveOrchestrator orchestrator,
        IReadOnlyList<string> inputFiles,
        string password = "algo2026",
        int maxVolumeBytes = 65536,
        double alpha = DefaultAlpha,
        double beta = DefaultBeta,
        double referenceSeconds = DefaultReferenceSeconds)
    {
        ArgumentNullException.ThrowIfNull(orchestrator);
        ArgumentNullException.ThrowIfNull(inputFiles);

        string tempWorkDir = Path.Combine(Path.GetTempPath(), $"sarc_eval_{Guid.NewGuid():N}");
        string archiveOutDir = Path.Combine(tempWorkDir, "arc");
        string extractOutDir = Path.Combine(tempWorkDir, "ext");

        Directory.CreateDirectory(archiveOutDir);
        Directory.CreateDirectory(extractOutDir);

        try
        {
            long originalBytes = 0;
            foreach (string file in inputFiles)
            {
                originalBytes += new FileInfo(file).Length;
            }

            string baseArchivePath = Path.Combine(archiveOutDir, "eval.arc");

            var sw = Stopwatch.StartNew();
            IReadOnlyList<string> volumePaths = orchestrator.CreateArchive(inputFiles, baseArchivePath, password, maxVolumeBytes);
            orchestrator.ExtractArchive(volumePaths, extractOutDir, password);
            sw.Stop();

            long archiveBytes = 0;
            foreach (string volPath in volumePaths)
            {
                archiveBytes += new FileInfo(volPath).Length;
            }

            bool allExact = VerifyFilesByteIdentical(inputFiles, extractOutDir);
            return Compute(originalBytes, archiveBytes, sw.Elapsed.TotalSeconds, allExact, alpha, beta, referenceSeconds);
        }
        catch
        {
            return new QualityMetricResult(false, 0, 0, 0, 0, 0, 0);
        }
        finally
        {
            if (Directory.Exists(tempWorkDir))
            {
                try
                {
                    Directory.Delete(tempWorkDir, recursive: true);
                }
                catch
                {
                    // Ігноруємо помилки видалення тимчасової папки
                }
            }
        }
    }

    /// <summary>
    /// Перевіряє побайтову ідентичність усіх вихідних та відновлених файлів (original == restored).
    /// </summary>
    public static bool VerifyFilesByteIdentical(IEnumerable<string> originalFiles, string restoredDirectory)
    {
        foreach (string origPath in originalFiles)
        {
            if (!File.Exists(origPath))
            {
                return false;
            }

            string fileName = Path.GetFileName(origPath);
            string restoredPath = Path.Combine(restoredDirectory, fileName);
            if (!File.Exists(restoredPath))
            {
                return false;
            }

            byte[] origBytes = File.ReadAllBytes(origPath);
            byte[] restoredBytes = File.ReadAllBytes(restoredPath);

            if (!origBytes.AsSpan().SequenceEqual(restoredBytes))
            {
                return false;
            }
        }

        return true;
    }
}
