using SmartSecureArchiver.Core.Analysis;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Packing;

namespace SmartSecureArchiver.Tests.Integration;

public class MlpPipelineIntegrationTests
{
    [Fact]
    public void CreateDefault_LoadsEmbeddedModelWithExpectedArchitecture()
    {
        MlpClassifier classifier = MlpClassifier.CreateDefault();

        Assert.Equal(FeatureVectorizer.Size, classifier.Network.InputSize);
        Assert.Equal(7, classifier.Network.OutputSize);
        Assert.False(classifier.ShouldCompress(MlpClassifier.AlreadyCompressedClass, CreateFeatures(entropy: 4)));
        Assert.False(classifier.ShouldCompress(fileClass: 0, CreateFeatures(entropy: 8)));
    }

    [Fact]
    public void Factory_CreatesArchiveThatRoundTripsThroughMlpPipeline()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"sarc-integration-{Guid.NewGuid():N}");
        string inputDirectory = Path.Combine(tempRoot, "input");
        string outputDirectory = Path.Combine(tempRoot, "output");
        Directory.CreateDirectory(inputDirectory);

        var files = new Dictionary<string, byte[]>
        {
            ["text.txt"] = System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("SARC MLP integration test line.\n", 400))),
            ["empty.dat"] = [],
            ["random.bin"] = CreateDeterministicBytes(20_000, seed: 1234)
        };

        try
        {
            var inputPaths = new List<string>();
            foreach ((string name, byte[] content) in files)
            {
                string path = Path.Combine(inputDirectory, name);
                File.WriteAllBytes(path, content);
                inputPaths.Add(path);
            }

            ArchiveOrchestrator orchestrator = ArchiveOrchestratorFactory.CreateDefault();
            IReadOnlyList<string> volumes = orchestrator.CreateArchive(
                inputPaths,
                Path.Combine(tempRoot, "archive.arc"),
                password: "integration-pass",
                maxVolumeBytes: 65536);

            Assert.NotEmpty(volumes);
            orchestrator.ExtractArchive(volumes, outputDirectory, password: "integration-pass");

            foreach ((string name, byte[] expected) in files)
            {
                string restoredPath = Path.Combine(outputDirectory, name);
                Assert.True(File.Exists(restoredPath), $"Restored file not found: {restoredPath}");
                Assert.Equal(expected, File.ReadAllBytes(restoredPath));
            }
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void Classifier_IsDeterministicOnCorpusFiles()
    {
        string corpusDirectory = FindRepoDirectory(Path.Combine("team", "corpus"));
        var extractor = new FeatureExtractor();
        MlpClassifier first = MlpClassifier.CreateDefault();
        MlpClassifier second = MlpClassifier.CreateDefault();

        foreach (string path in Directory.EnumerateFiles(corpusDirectory).OrderBy(path => path, StringComparer.Ordinal))
        {
            byte[] data = File.ReadAllBytes(path);
            FileFeatures features = extractor.Extract(data);

            byte firstClass = first.Classify(features);
            byte secondClass = second.Classify(features);

            Assert.Equal(firstClass, secondClass);
            Assert.InRange(firstClass, (byte)0, (byte)6);
            Assert.Equal(first.ShouldCompress(firstClass, features), second.ShouldCompress(secondClass, features));
        }
    }

    [Fact]
    public void Packer_IsDeterministicOnCorpusBlocks()
    {
        string corpusDirectory = FindRepoDirectory(Path.Combine("team", "corpus"));
        var compressor = new BlockCompressor();
        var candidates = new List<BlockCandidate>();
        int blockId = 0;

        foreach (string path in Directory.EnumerateFiles(corpusDirectory)
                     .Where(path => !path.EndsWith("labels.csv", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(path => path, StringComparer.Ordinal))
        {
            byte[] data = File.ReadAllBytes(path);
            uint blockSeq = 0;

            for (int offset = 0; offset < data.Length; offset += ArchiveOrchestrator.DefaultBlockSize)
            {
                ReadOnlySpan<byte> block = data.AsSpan(
                    offset,
                    Math.Min(ArchiveOrchestrator.DefaultBlockSize, data.Length - offset));
                byte[] coded = compressor.Compress(block, out byte blockFlags);
                candidates.Add(new BlockCandidate(
                    BlockId: ++blockId,
                    Weight: coded.Length + FileBlock.HeaderSize,
                    Value: 1,
                    Data: coded,
                    BlockSeq: blockSeq++,
                    RawLength: (uint)block.Length,
                    BlockFlags: blockFlags));
            }
        }

        var packer = new KnapsackPacker();
        PackingResult first = packer.PackVolumeDp(capacity: 65025, candidates);
        PackingResult second = packer.PackVolumeDp(capacity: 65025, candidates);

        Assert.Equal(
            first.SelectedBlocks.Select(block => block.BlockId),
            second.SelectedBlocks.Select(block => block.BlockId));
        Assert.Equal(first.TotalWeight, second.TotalWeight);
        Assert.Equal(first.TotalValue, second.TotalValue);
    }

    private static FileFeatures CreateFeatures(double entropy) =>
        new(
            Entropy: entropy,
            Histogram32: Enumerable.Repeat(1.0 / 32, 32).ToArray(),
            AsciiRatio: 0.5,
            NewlineDistanceAvg: 20,
            Autocorrelation16: new double[16],
            BigramEntropy: 5);

    private static byte[] CreateDeterministicBytes(int length, int seed)
    {
        var random = new Random(seed);
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }

    private static string FindRepoDirectory(string relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, relativePath);
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"Could not locate '{relativePath}' in repository tree.");
    }
}
