using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Tests.Security;

public class CompressionOrderExperimentTests
{
    [Fact]
    public void CompressThenEncrypt_AchievesSubstantiallyBetterRatioThanEncryptThenCompress()
    {
        string corpusDir = FindRepoDirectory(Path.Combine("team", "corpus"));
        List<string> corpusFiles = Directory.GetFiles(corpusDir)
            .Where(f => !f.EndsWith("labels.csv", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        var experiment = new CompressionOrderExperiment();
        CompressionOrderReport report = experiment.Run(corpusFiles, password: "algo2026");

        Assert.Equal(corpusFiles.Count, report.Files.Count);
        Assert.All(report.Files, f => Assert.True(f.RoundTripVerified));

        // «Стиснути перед шифруванням» дає реальне стиснення (> 2.0x на корпусі)
        Assert.True(
            report.TotalCompressThenEncryptRatio > 2.0,
            $"Expected Compress-then-Encrypt ratio > 2.0, got {report.TotalCompressThenEncryptRatio:F3}.");

        // «Зашифрувати перед стисненням» не стискається (коефіцієнт ~1.00)
        Assert.InRange(report.TotalEncryptThenCompressRatio, 0.99, 1.02);
        Assert.True(report.TotalCompressThenEncryptBytes < report.TotalEncryptThenCompressBytes);

        string markdown = CompressionOrderExperiment.FormatMarkdownTable(report);
        Assert.Contains("Таблиця №4", markdown);
        Assert.Contains("УСЬОГО", markdown);
    }

    private static string FindRepoDirectory(string relativePath)
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, relativePath);
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException($"Could not locate '{relativePath}'.");
    }
}
