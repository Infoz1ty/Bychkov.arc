namespace SmartSecureArchiver.Core.Packing;

public interface IKnapsackPacker
{
    /// <summary>
    /// Розв'язує задачу рюкзака 0/1 методом динамічного програмування (DP).
    /// Якщо всі блоки вміщуються в том, повертає точний розв'язок без ДП.
    /// Якщо ємність тому перевищує бюджет ДП (<see cref="KnapsackPacker.MaxExactDpCapacity"/>
    /// або <see cref="KnapsackPacker.MaxExactDpCells"/>), повертає greedy-апроксимацію.
    /// </summary>
    PackingResult PackVolumeDp(int capacity, IReadOnlyList<BlockCandidate> candidates);

    /// <summary>
    /// Жадібний алгоритм пакування (сортування за value/weight) для експериментального порівняння з DP.
    /// </summary>
    PackingResult PackVolumeGreedy(int capacity, IReadOnlyList<BlockCandidate> candidates);
}
