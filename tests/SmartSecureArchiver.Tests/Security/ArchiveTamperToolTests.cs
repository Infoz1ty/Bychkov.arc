using SmartSecureArchiver.Core.Security.Attack;

namespace SmartSecureArchiver.Tests.Security;

public class ArchiveTamperToolTests
{
    [Fact]
    public void RunTamperAudit_OnReferenceArchive_DetectsAllTamperingFailClosed()
    {
        string refArchive = FindRepoFile(Path.Combine("team", "reference", "ref_01_single_file.arc"));

        IReadOnlyList<TamperProbeResult> results = ArchiveTamperTool.RunTamperAudit(refArchive, password: "algo2026");

        Assert.NotEmpty(results);
        Assert.All(results, probe =>
        {
            Assert.True(probe.RejectedCleanly, $"{probe.AttackName}: expected {probe.ExpectedCode}, got {probe.ActualCode}.");
            Assert.True(probe.OutputDirectoryUntouched, $"{probe.AttackName}: output directory was not empty after rejection.");
        });
    }

    private static string FindRepoFile(string relativePath)
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException($"Could not locate '{relativePath}'.");
    }
}
