using System.Text.Json;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Optimization;

namespace SmartSecureArchiver.Tests.Optimization;

public class GeneticOptimizerTests
{
    [Fact]
    public void OptimizeWithLog_RealPipeline_BestFinalIsNeverWorseThanBestInitial_CaseD1_17()
    {
        IReadOnlyList<string> sampleFiles = GetSubsetOfCorpusFiles();
        string tempLogPath = Path.Combine(Path.GetTempPath(), $"ga_log_{Guid.NewGuid():N}.json");

        try
        {
            var optimizer = new GeneticOptimizer(
                seed: 2001,
                evolutionLogPath: tempLogPath);

            GaOptimizationReport gaReport = optimizer.OptimizeWithLog(
                sampleFiles,
                generations: 3,
                populationSize: 4);

            // Кейс D1 №17: найкращий результат останнього покоління не гірший за покоління 0
            Assert.True(
                gaReport.BestFinalQ >= gaReport.BestInitialQ,
                $"Expected BestFinalQ ({gaReport.BestFinalQ}) >= BestInitialQ ({gaReport.BestInitialQ}).");
            Assert.True(gaReport.BestFinalQ > 0.0);
            Assert.Equal(4, gaReport.GenerationsHistory.Count);

            // Перевірка монотонності елітизму за поколіннями
            for (int i = 1; i < gaReport.GenerationsHistory.Count; i++)
            {
                Assert.True(
                    gaReport.GenerationsHistory[i].BestQ >= gaReport.GenerationsHistory[i - 1].BestQ,
                    $"Elitism violated at generation {i}.");
            }

            // Перевірка меж генів знайденого рішення
            Assert.InRange(gaReport.BestParameters.WindowSize, GeneticOptimizer.MinWindowSize, GeneticOptimizer.MaxWindowSize);
            Assert.InRange(gaReport.BestParameters.MinMatchLength, GeneticOptimizer.MinMatchLower, GeneticOptimizer.MinMatchUpper);
            Assert.InRange(gaReport.BestParameters.NoCompressionEntropyThreshold, GeneticOptimizer.MinEntropyThreshold, GeneticOptimizer.MaxEntropyThreshold);

            // Перевірка автоматичного збереження журналу еволюції ГА
            Assert.True(File.Exists(tempLogPath));
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(tempLogPath));
            Assert.True(doc.RootElement.TryGetProperty("genetic_algorithm", out _));
        }
        finally
        {
            if (File.Exists(tempLogPath))
            {
                File.Delete(tempLogPath);
            }
        }
    }

    [Fact]
    public void RunRandomSearchWithLog_UsesExactEvaluationBudgetAndMatchesInterfaceContract()
    {
        IReadOnlyList<string> sampleFiles = GetSubsetOfCorpusFiles();
        var optimizer = new GeneticOptimizer(seed: 2001);

        GaOptimizationReport gaReport = optimizer.OptimizeWithLog(sampleFiles, generations: 2, populationSize: 4);
        RandomSearchReport randomReport = optimizer.RunRandomSearchWithLog(sampleFiles, iterations: gaReport.TotalEvaluations);

        Assert.Equal(gaReport.TotalEvaluations, randomReport.Iterations);
        Assert.Equal(gaReport.TotalEvaluations, randomReport.History.Count);
        Assert.True(randomReport.BestQ > 0.0);

        GeneticParameters interfaceResult = optimizer.RunRandomSearch(sampleFiles, iterations: 3);
        Assert.InRange(interfaceResult.WindowSize, GeneticOptimizer.MinWindowSize, GeneticOptimizer.MaxWindowSize);
    }

    [Fact]
    public void Optimize_WithDeterministicEvaluator_IsReproducibleForFixedSeed()
    {
        IReadOnlyList<string> sampleFiles = GetSubsetOfCorpusFiles();
        static QualityMetricResult SyntheticFitness(GeneticParameters p, IReadOnlyList<string> _)
        {
            double wScore = 1.0 - Math.Abs(p.WindowSize - 16384) / 32768.0;
            double mScore = 1.0 - Math.Abs(p.MinMatchLength - 4) / 10.0;
            double eScore = 1.0 - Math.Abs(p.NoCompressionEntropyThreshold - 7.5) / 2.0;
            double q = 0.4 * wScore + 0.3 * mScore + 0.3 * eScore;
            return new QualityMetricResult(true, 1000, 500, 0.1, q, 0.99, q);
        }

        var opt1 = new GeneticOptimizer(seed: 2001, customEvaluator: SyntheticFitness);
        var opt2 = new GeneticOptimizer(seed: 2001, customEvaluator: SyntheticFitness);

        GaOptimizationReport r1 = opt1.OptimizeWithLog(sampleFiles, generations: 10, populationSize: 12);
        GaOptimizationReport r2 = opt2.OptimizeWithLog(sampleFiles, generations: 10, populationSize: 12);

        Assert.Equal(r1.BestParameters, r2.BestParameters);
        Assert.Equal(r1.BestFinalQ, r2.BestFinalQ, precision: 10);
        Assert.True(r1.BestFinalQ >= r1.BestInitialQ);
    }

    private static IReadOnlyList<string> GetSubsetOfCorpusFiles()
    {
        string corpusDir = FindRepoDirectory(Path.Combine("team", "corpus"));
        return
        [
            Path.Combine(corpusDir, "f0000.txt"),
            Path.Combine(corpusDir, "f0001.py"),
            Path.Combine(corpusDir, "f0005.z")
        ];
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
