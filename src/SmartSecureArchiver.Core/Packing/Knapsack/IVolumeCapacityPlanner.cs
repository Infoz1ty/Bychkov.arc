using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Packing;

/// <summary>
/// Фіксація складу файлів-кандидатів і розрахунок чистої місткості тому перед запуском рюкзака 0/1 (Issue #28).
/// </summary>
public interface IVolumeCapacityPlanner
{
    /// <summary>
    /// Фіксує файли, яким належать блоки-кандидати, та обчислює доступну місткість під ці блоки.
    /// </summary>
    /// <exception cref="SarcException">
    /// E_CAPACITY, якщо таблиця файлів або хоча б один блок не вміщується в порожній том.
    /// </exception>
    VolumeCapacityPlan Plan(
        int maxVolumeBytes,
        IReadOnlyList<ArchiveFileInfo> allFiles,
        IReadOnlyList<BlockCandidate> candidates);
}
