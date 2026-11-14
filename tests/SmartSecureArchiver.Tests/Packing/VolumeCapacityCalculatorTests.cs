using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Packing;

namespace SmartSecureArchiver.Tests.Packing;

public class VolumeCapacityCalculatorTests
{
    private readonly VolumeCapacityCalculator _calculator = new();

    [Fact]
    public void Calculator_WorksThroughIVolumeCapacityPlannerInterface()
    {
        IVolumeCapacityPlanner planner = new VolumeCapacityCalculator();
        ArchiveFileInfo[] files = [new("a.txt", 10, 0)];
        BlockCandidate[] candidates = [new(BlockId: 1, Weight: 10, Value: 3, FileIndex: 0)];

        VolumeCapacityPlan plan = planner.Plan(65536, files, candidates);

        Assert.Equal(65440, plan.UsableBlockCapacity);
    }

    [Fact]
    public void CalculateFileTableSize_CountsUtf8NameBytesAndFixedFields()
    {
        ArchiveFileInfo[] files =
        [
            new("a.txt", 10, 0),
            new("тест.txt", 20, 0)
        ];

        // "a.txt" = 5 байтів -> 12 + 5 = 17; "тест.txt" = 12 байтів UTF-8 -> 12 + 12 = 24.
        Assert.Equal(17, VolumeCapacityCalculator.GetFileTableEntrySize(files[0]));
        Assert.Equal(24, VolumeCapacityCalculator.GetFileTableEntrySize(files[1]));
        Assert.Equal(41, VolumeCapacityCalculator.CalculateFileTableSize(files));
    }

    [Fact]
    public void Plan_ComputesCapacityFromHeaderHmacFixedFieldsAndFileTable()
    {
        ArchiveFileInfo[] files = [new("a.txt", 10, 0)];
        BlockCandidate[] candidates = [new(BlockId: 1, Weight: 100, Value: 3, FileIndex: 0)];

        VolumeCapacityPlan plan = _calculator.Plan(65536, files, candidates);

        // 65536 - 41 - 32 - 6 - 17 = 65440.
        Assert.Equal(17, plan.FileTableSize);
        Assert.Equal(65440, plan.UsableBlockCapacity);
        Assert.Equal(65536, plan.MaxVolumeBytes);
    }

    [Fact]
    public void Plan_FixesOnlyFilesOwnedByCandidatesInOriginalOrder()
    {
        ArchiveFileInfo[] files =
        [
            new("a.txt", 1, 0),
            new("b.bin", 2, 0),
            new("c.dat", 3, 0)
        ];

        BlockCandidate[] candidates =
        [
            new(BlockId: 1, Weight: 10, Value: 1, FileIndex: 2),
            new(BlockId: 2, Weight: 10, Value: 1, FileIndex: 0),
            new(BlockId: 3, Weight: 10, Value: 1, FileIndex: 2)
        ];

        VolumeCapacityPlan plan = _calculator.Plan(65536, files, candidates);

        Assert.Equal(["a.txt", "c.dat"], plan.FixedFiles.Select(file => file.FileName));
        Assert.Equal(17 + 17, plan.FileTableSize);
    }

    [Fact]
    public void Plan_EmptyCandidates_UsesFullCapacityWithoutFileTable()
    {
        VolumeCapacityPlan plan = _calculator.Plan(65536, [new("a.txt", 1, 0)], []);

        Assert.Empty(plan.FixedFiles);
        Assert.Equal(0, plan.FileTableSize);
        Assert.Equal(65536 - 79, plan.UsableBlockCapacity);
    }

    [Fact]
    public void Plan_BlockWeightEqualsCapacity_IsAccepted()
    {
        ArchiveFileInfo[] files = [new("a.txt", 10, 0)];
        int capacity = 65536 - 79 - 17;
        BlockCandidate[] candidates = [new(BlockId: 1, Weight: capacity, Value: 3, FileIndex: 0)];

        VolumeCapacityPlan plan = _calculator.Plan(65536, files, candidates);

        Assert.Equal(capacity, plan.UsableBlockCapacity);
    }

    [Fact]
    public void Plan_BlockHeavierThanCapacity_ThrowsE_CAPACITY()
    {
        ArchiveFileInfo[] files = [new("a.txt", 10, 0)];
        int capacity = 65536 - 79 - 17;
        BlockCandidate[] candidates = [new(BlockId: 7, Weight: capacity + 1, Value: 3, FileIndex: 0)];

        var exception = Assert.Throws<SarcException>(() => _calculator.Plan(65536, files, candidates));

        Assert.Equal(SarcErrorCode.E_CAPACITY, exception.ErrorCode);
    }

    [Fact]
    public void Plan_FileTableDoesNotFitEmptyVolume_ThrowsE_CAPACITY()
    {
        ArchiveFileInfo[] files = [new("a.txt", 10, 0)];
        BlockCandidate[] candidates = [new(BlockId: 1, Weight: 10, Value: 3, FileIndex: 0)];

        // 89 - 79 - 17 = -7 байтів під блоки.
        var exception = Assert.Throws<SarcException>(() => _calculator.Plan(89, files, candidates));

        Assert.Equal(SarcErrorCode.E_CAPACITY, exception.ErrorCode);
    }

    [Fact]
    public void Plan_DoesNotSubtractBlockTableTwice_BecauseWeightAlreadyContains15Bytes()
    {
        ArchiveFileInfo[] files = [new("a.txt", 10, 0)];
        int capacity = 1000 - 79 - 17;
        BlockCandidate[] candidates = [new(BlockId: 1, Weight: capacity, Value: 3, FileIndex: 0)];

        VolumeCapacityPlan plan = _calculator.Plan(1000, files, candidates);

        Assert.Equal(904, plan.UsableBlockCapacity);
        Assert.Equal(15, VolumeCapacityCalculator.BlockTableEntrySize);
    }

    [Fact]
    public void Plan_CandidateReferencesUnknownFile_ThrowsArgumentOutOfRange()
    {
        BlockCandidate[] candidates = [new(BlockId: 1, Weight: 10, Value: 3, FileIndex: 5)];

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _calculator.Plan(65536, [new("a.txt", 1, 0)], candidates));
    }

    [Fact]
    public void Plan_NegativeBlockWeight_ThrowsArgumentOutOfRange()
    {
        BlockCandidate[] candidates = [new(BlockId: 1, Weight: -1, Value: 3, FileIndex: 0)];

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            _calculator.Plan(65536, [new("a.txt", 1, 0)], candidates));
    }
}
