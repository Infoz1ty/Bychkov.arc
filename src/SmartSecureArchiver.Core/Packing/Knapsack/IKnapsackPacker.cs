namespace SmartSecureArchiver.Core.Packing;

public interface IKnapsackPacker
{
    /// <summary>
    /// Розв'язує задачу рюкзака 0/1 методом динамічного програмування (DP).
    /// </summary>
    PackingResult PackVolumeDp(int capacity, IReadOnlyList<BlockCandidate> candidates);

    /// <summary>
    /// Жадібний алгоритм пакування (сортування за value/weight) для експериментального порівняння з DP.
    /// </summary>
    PackingResult PackVolumeGreedy(int capacity, IReadOnlyList<BlockCandidate> candidates);
}
