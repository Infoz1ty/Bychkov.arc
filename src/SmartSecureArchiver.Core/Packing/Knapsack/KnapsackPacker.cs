namespace SmartSecureArchiver.Core.Packing;

/// <summary>
/// Пакування блоків у том задачі про рюкзак 0/1 (Issues #26, #27).
/// DP — точний алгоритм O(n * W) із відновленням вибраної множини.
/// Greedy — евристика сортуванням за спаданням v/w для порівняння у звіті.
/// Обидва алгоритми детерміновані: при рівній цінності перевага надається ранішому блоку.
/// </summary>
public sealed class KnapsackPacker : IKnapsackPacker
{
    /// <inheritdoc />
    public PackingResult PackVolumeDp(int capacity, IReadOnlyList<BlockCandidate> candidates)
    {
        ValidateInputs(capacity, candidates);

        int itemCount = candidates.Count;
        bool[] selected = new bool[itemCount];

        if (itemCount == 0 || capacity == 0)
        {
            // Блоки нульової ваги з додатною цінністю все одно беруться.
            SelectZeroWeightItems(candidates, selected);
            return BuildResult(candidates, selected, capacity);
        }

        int wordsPerRow = ((capacity + 1) + 63) / 64;
        ulong[]?[] decisions = new ulong[]?[itemCount];
        long[] previous = new long[capacity + 1];
        long[] current = new long[capacity + 1];

        for (int i = 0; i < itemCount; i++)
        {
            BlockCandidate item = candidates[i];

            if (item.Weight > capacity)
            {
                continue;
            }

            ulong[] row = new ulong[wordsPerRow];
            int weight = item.Weight;
            int value = item.Value;

            for (int w = 0; w <= capacity; w++)
            {
                long bestWithoutItem = previous[w];
                if (w >= weight)
                {
                    long bestWithItem = previous[w - weight] + value;
                    if (bestWithItem > bestWithoutItem)
                    {
                        current[w] = bestWithItem;
                        row[w >> 6] |= 1UL << (w & 63);
                        continue;
                    }
                }

                current[w] = bestWithoutItem;
            }

            decisions[i] = row;
            (previous, current) = (current, previous);
        }

        int remainingCapacity = capacity;
        for (int i = itemCount - 1; i >= 0; i--)
        {
            ulong[]? row = decisions[i];
            if (row is null)
            {
                continue;
            }

            if ((row[remainingCapacity >> 6] & (1UL << (remainingCapacity & 63))) == 0)
            {
                continue;
            }

            selected[i] = true;
            remainingCapacity -= candidates[i].Weight;
        }

        return BuildResult(candidates, selected, capacity);
    }

    /// <inheritdoc />
    public PackingResult PackVolumeGreedy(int capacity, IReadOnlyList<BlockCandidate> candidates)
    {
        ValidateInputs(capacity, candidates);

        int itemCount = candidates.Count;
        int[] order = new int[itemCount];
        for (int i = 0; i < itemCount; i++)
        {
            order[i] = i;
        }

        BlockCandidate[] items = candidates.ToArray();
        Array.Sort(order, (left, right) => CompareByValuePerWeight(items[left], items[right], left, right));

        bool[] selected = new bool[itemCount];
        int usedWeight = 0;

        foreach (int index in order)
        {
            BlockCandidate item = candidates[index];

            if (item.Weight == 0)
            {
                selected[index] = item.Value > 0;
                continue;
            }

            if (usedWeight + item.Weight <= capacity)
            {
                selected[index] = true;
                usedWeight += item.Weight;
            }
        }

        return BuildResult(candidates, selected, capacity);
    }

    private static void ValidateInputs(int capacity, IReadOnlyList<BlockCandidate> candidates)
    {
        ArgumentNullException.ThrowIfNull(candidates);

        if (capacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(capacity), capacity, "Knapsack capacity cannot be negative.");
        }

        for (int i = 0; i < candidates.Count; i++)
        {
            BlockCandidate candidate = candidates[i];
            if (candidate.Weight < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(candidates),
                    candidate.Weight,
                    $"Block {candidate.BlockId} has negative weight.");
            }
        }
    }

    private static void SelectZeroWeightItems(IReadOnlyList<BlockCandidate> candidates, bool[] selected)
    {
        for (int i = 0; i < candidates.Count; i++)
        {
            if (candidates[i].Weight == 0 && candidates[i].Value > 0)
            {
                selected[i] = true;
            }
        }
    }

    private static PackingResult BuildResult(
        IReadOnlyList<BlockCandidate> candidates,
        bool[] selected,
        int capacity)
    {
        List<BlockCandidate> selectedBlocks = new(selected.Count(item => item));
        List<BlockCandidate> remainingBlocks = new();
        long totalWeight = 0;
        long totalValue = 0;

        for (int i = 0; i < candidates.Count; i++)
        {
            BlockCandidate candidate = candidates[i];
            if (selected[i])
            {
                selectedBlocks.Add(candidate);
                totalWeight += candidate.Weight;
                totalValue += candidate.Value;
            }
            else
            {
                remainingBlocks.Add(candidate);
            }
        }

        if (totalWeight > capacity)
        {
            throw new InvalidOperationException(
                $"Packer selected {totalWeight} bytes, exceeding capacity {capacity}.");
        }

        return new PackingResult(
            selectedBlocks,
            remainingBlocks,
            (int)totalWeight,
            totalValue > int.MaxValue ? int.MaxValue : (int)totalValue);
    }

    /// <summary>
    /// Порівняння за спаданням v/w без ділення з плаваючою комою.
    /// Блоки нульової ваги йдуть першими; при рівності — більша цінність, потім менший індекс.
    /// </summary>
    private static int CompareByValuePerWeight(BlockCandidate left, BlockCandidate right, int leftIndex, int rightIndex)
    {
        if (left.Weight == 0 || right.Weight == 0)
        {
            if (left.Weight == 0 && right.Weight == 0)
            {
                int byValue = right.Value.CompareTo(left.Value);
                return byValue != 0 ? byValue : leftIndex.CompareTo(rightIndex);
            }

            return left.Weight == 0 ? -1 : 1;
        }

        long leftScaled = (long)left.Value * right.Weight;
        long rightScaled = (long)right.Value * left.Weight;
        if (leftScaled != rightScaled)
        {
            return rightScaled.CompareTo(leftScaled);
        }

        int valueComparison = right.Value.CompareTo(left.Value);
        return valueComparison != 0 ? valueComparison : leftIndex.CompareTo(rightIndex);
    }
}
