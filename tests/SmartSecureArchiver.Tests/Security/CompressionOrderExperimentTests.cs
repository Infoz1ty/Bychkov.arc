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

        // «Стиснути перед шифруванням» дає суттєво краще стиснення за антипатерн.
        Assert.True(
            report.TotalCompressThenEncryptRatio > 1.5
                && report.TotalCompressThenEncryptRatio > report.TotalEncryptThenCompressRatio * 1.5,
            $"Expected Compress-then-Encrypt to provide a substantial improvement, got {report.TotalCompressThenEncryptRatio:F3}x vs {report.TotalEncryptThenCompressRatio:F3}x.");

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
