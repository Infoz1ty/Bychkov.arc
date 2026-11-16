using SmartSecureArchiver.Core.Analysis;
using SmartSecureArchiver.Core.Packing;

namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Типова збірка конвеєра архіватора з навченою MLP-моделлю (інтеграція Среза 3).
/// Використовує вбудовані ваги models/mlp_weights.bin, FeatureExtractor та ДП-рюкзак.
/// </summary>
public static class ArchiveOrchestratorFactory
{
    public static ArchiveOrchestrator CreateDefault(int blockSize = ArchiveOrchestrator.DefaultBlockSize)
    {
        return new ArchiveOrchestrator(
            featureExtractor: new FeatureExtractor(),
            fileClassifier: MlpClassifier.CreateDefault(),
            knapsackPacker: new KnapsackPacker(),
            blockSize: blockSize);
    }
}
