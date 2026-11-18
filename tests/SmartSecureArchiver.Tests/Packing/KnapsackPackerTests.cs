using SmartSecureArchiver.Core.Packing;

namespace SmartSecureArchiver.Tests.Packing;

public class KnapsackPackerTests
{
    private readonly KnapsackPacker _packer = new();

    [Fact]
    public void Dp_PicksOptimalSubset()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 6, value: 10),
            Candidate(2, weight: 5, value: 7),
            Candidate(3, weight: 4, value: 4)
        ];

        PackingResult result = _packer.PackVolumeDp(capacity: 10, items);

        Assert.Equal([1, 3], Ids(result.SelectedBlocks));
        Assert.Equal(14, result.TotalValue);
        Assert.Equal(10, result.TotalWeight);
    }

    [Fact]
    public void Dp_DoesNotReuseSameBlockTwice()
    {
        BlockCandidate[] items = [Candidate(1, weight: 5, value: 10)];

        PackingResult result = _packer.PackVolumeDp(capacity: 10, items);

        Assert.Single(result.SelectedBlocks);
        Assert.Equal(10, result.TotalValue);
        Assert.Equal(5, result.TotalWeight);
    }

    [Fact]
    public void Dp_TooHeavyBlockGoesToRemaining()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 6, value: 100),
            Candidate(2, weight: 5, value: 10)
        ];

        PackingResult result = _packer.PackVolumeDp(capacity: 5, items);

        Assert.Equal([2], Ids(result.SelectedBlocks));
        Assert.Equal([1], Ids(result.RemainingBlocks));
        Assert.Equal(10, result.TotalValue);
    }

    [Fact]
    public void Dp_ZeroWeightPositiveValueBlockIsAlwaysSelected()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 0, value: 5),
            Candidate(2, weight: 3, value: 4),
            Candidate(3, weight: 3, value: 4)
        ];

        PackingResult result = _packer.PackVolumeDp(capacity: 3, items);

        Assert.Equal([1, 2], Ids(result.SelectedBlocks));
        Assert.Equal(9, result.TotalValue);
        Assert.Equal(3, result.TotalWeight);
    }

    [Fact]
    public void Dp_ZeroCapacity_KeepsOnlyZeroWeightValuableBlocks()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 0, value: 2),
            Candidate(2, weight: 1, value: 5)
        ];

        PackingResult result = _packer.PackVolumeDp(capacity: 0, items);

        Assert.Equal([1], Ids(result.SelectedBlocks));
        Assert.Equal([2], Ids(result.RemainingBlocks));
    }

    [Fact]
    public void Dp_EmptyCandidates_ReturnsEmptyResult()
    {
        PackingResult result = _packer.PackVolumeDp(100, []);

        Assert.Empty(result.SelectedBlocks);
        Assert.Empty(result.RemainingBlocks);
        Assert.Equal(0, result.TotalWeight);
        Assert.Equal(0, result.TotalValue);
    }

    [Fact]
    public void Dp_TieOnEqualValuePrefersEarlierBlockDeterministically()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 5, value: 10),
            Candidate(2, weight: 5, value: 10)
        ];

        PackingResult first = _packer.PackVolumeDp(5, items);
        PackingResult second = _packer.PackVolumeDp(5, items);

        Assert.Equal([1], Ids(first.SelectedBlocks));
        Assert.Equal(Ids(first.SelectedBlocks), Ids(second.SelectedBlocks));
    }

    [Fact]
    public void Dp_PartitionsInputIntoSelectedAndRemaining()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 4, value: 4),
            Candidate(2, weight: 8, value: 8),
            Candidate(3, weight: 2, value: 3)
        ];

        PackingResult result = _packer.PackVolumeDp(capacity: 7, items);

        Assert.Equal(items.Length, result.SelectedBlocks.Count + result.RemainingBlocks.Count);
        Assert.Equal(result.TotalWeight, result.SelectedBlocks.Sum(item => item.Weight));
        Assert.Equal(result.TotalValue, result.SelectedBlocks.Sum(item => item.Value));
        Assert.True(result.TotalWeight <= 7);
    }

    [Fact]
    public void Greedy_CanLoseToDp()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 6, value: 6),
            Candidate(2, weight: 5, value: 5),
            Candidate(3, weight: 5, value: 5)
        ];

        PackingResult greedy = _packer.PackVolumeGreedy(capacity: 10, items);
        PackingResult dp = _packer.PackVolumeDp(capacity: 10, items);

        Assert.Equal(6, greedy.TotalValue);
        Assert.Equal(10, dp.TotalValue);
    }

    [Fact]
    public void Greedy_ZeroWeightPositiveValueBlockIsSelectedFirst()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 4, value: 4),
            Candidate(2, weight: 0, value: 1),
            Candidate(3, weight: 3, value: 3)
        ];

        PackingResult result = _packer.PackVolumeGreedy(capacity: 4, items);

        Assert.Contains(2, Ids(result.SelectedBlocks));
        Assert.True(result.TotalWeight <= 4);
    }

    [Fact]
    public void Knapsack_DpVsGreedy_DpValueIsNeverLess()
    {
        var random = new Random(2026);

        for (int iteration = 0; iteration < 300; iteration++)
        {
            int capacity = random.Next(0, 60);
            int count = random.Next(0, 25);
            BlockCandidate[] items = new BlockCandidate[count];

            for (int i = 0; i < count; i++)
            {
                items[i] = Candidate(i + 1, weight: random.Next(0, 25), value: random.Next(1, 15));
            }

            PackingResult dp = _packer.PackVolumeDp(capacity, items);
            PackingResult greedy = _packer.PackVolumeGreedy(capacity, items);

            Assert.True(
                dp.TotalValue >= greedy.TotalValue,
                $"Iteration {iteration}: DP value {dp.TotalValue} < greedy value {greedy.TotalValue}.");
            Assert.True(dp.TotalWeight <= capacity);
            Assert.True(greedy.TotalWeight <= capacity);
            Assert.Equal(items.Length, dp.SelectedBlocks.Count + dp.RemainingBlocks.Count);
            Assert.Equal(items.Length, greedy.SelectedBlocks.Count + greedy.RemainingBlocks.Count);
        }
    }

    [Fact]
    public void Dp_IsDeterministic()
    {
        var random = new Random(777);
        BlockCandidate[] items = Enumerable.Range(1, 40)
            .Select(i => Candidate(i, random.Next(0, 20), random.Next(1, 10)))
            .ToArray();

        PackingResult first = _packer.PackVolumeDp(capacity: 100, items);
        PackingResult second = _packer.PackVolumeDp(capacity: 100, items);

        Assert.Equal(Ids(first.SelectedBlocks), Ids(second.SelectedBlocks));
        Assert.Equal(first.TotalWeight, second.TotalWeight);
        Assert.Equal(first.TotalValue, second.TotalValue);
    }

    [Fact]
    public void Greedy_IsDeterministic()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 4, value: 8),
            Candidate(2, weight: 2, value: 4),
            Candidate(3, weight: 3, value: 6)
        ];

        PackingResult first = _packer.PackVolumeGreedy(6, items);
        PackingResult second = _packer.PackVolumeGreedy(6, items);

        Assert.Equal(Ids(first.SelectedBlocks), Ids(second.SelectedBlocks));
    }

    [Fact]
    public void NegativeCapacityOrWeight_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _packer.PackVolumeDp(-1, []));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _packer.PackVolumeGreedy(-1, []));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _packer.PackVolumeDp(10, [Candidate(1, weight: -1, value: 5)]));
    }

    [Fact]
    public void Dp_WhenAllBlocksFitTheVolume_SelectsAllPositiveValueBlocksWithoutDp()
    {
        BlockCandidate[] items =
        [
            Candidate(1, weight: 1_000_000, value: 3),
            Candidate(2, weight: 2_000_000, value: 2),
            Candidate(3, weight: 500_000, value: 0)
        ];

        PackingResult result = _packer.PackVolumeDp(capacity: 50_000_000, items);

        Assert.Equal([1, 2], Ids(result.SelectedBlocks));
        Assert.Equal([3], Ids(result.RemainingBlocks));
        Assert.Equal(3_000_000, result.TotalWeight);
        Assert.Equal(5, result.TotalValue);
    }

    [Fact]
    public void Dp_WhenCapacityExceedsExactBudget_FallsBackToGreedyWithinCapacity()
    {
        int capacity = KnapsackPacker.MaxExactDpCapacity + 1;
        BlockCandidate[] items =
        [
            Candidate(1, weight: 600_000, value: 6),
            Candidate(2, weight: 600_000, value: 5)
        ];

        PackingResult result = _packer.PackVolumeDp(capacity, items);
        PackingResult greedy = _packer.PackVolumeGreedy(capacity, items);

        Assert.Equal(Ids(greedy.SelectedBlocks), Ids(result.SelectedBlocks));
        Assert.Equal(greedy.TotalValue, result.TotalValue);
        Assert.True(result.TotalWeight <= capacity);
    }

    [Fact]
    public void Dp_WhenCellBudgetExceeded_FallsBackToGreedyWithinCapacity()
    {
        const int capacity = 200_000;
        BlockCandidate[] items = Enumerable.Range(1, 250)
            .Select(i => Candidate(i, weight: 1_000, value: 1))
            .ToArray();

        Assert.True((long)items.Length * (capacity + 1) > KnapsackPacker.MaxExactDpCells);

        PackingResult result = _packer.PackVolumeDp(capacity, items);
        PackingResult greedy = _packer.PackVolumeGreedy(capacity, items);

        Assert.Equal(Ids(greedy.SelectedBlocks), Ids(result.SelectedBlocks));
        Assert.Equal(items.Length, result.SelectedBlocks.Count + result.RemainingBlocks.Count);
        Assert.True(result.TotalWeight <= capacity);
    }

    private static BlockCandidate Candidate(int id, int weight, int value) =>
        new(BlockId: id, Weight: weight, Value: value);

    private static int[] Ids(IReadOnlyList<BlockCandidate> blocks) =>
        blocks.Select(block => block.BlockId).ToArray();
}
