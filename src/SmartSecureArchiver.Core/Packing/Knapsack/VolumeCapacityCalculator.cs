using System.Text;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Packing;

/// <summary>
/// Зафіксований перед запуском рюкзака план місткості одного тому (Issue #28).
/// FixedFiles — саме той склад таблиці файлів, який потім потрапить у Payload і не може змінюватися
/// після вибору блоків (розділ 7 FORMAT_SPEC_P2.md, ADR-05).
/// </summary>
public sealed record VolumeCapacityPlan(
    int MaxVolumeBytes,
    int FileTableSize,
    int UsableBlockCapacity,
    IReadOnlyList<ArchiveFileInfo> FixedFiles
);

/// <summary>
/// Розраховує чисту місткість тому під дані блоків (Issue #28).
/// Формула: W = max_volume_bytes - 41 (заголовок) - 32 (HMAC) - 6 (file_count, flags, reserved, block_count)
/// - розмір таблиці файлів.
/// Вага блока вже включає 15 байтів його запису в таблиці блоків, тому 15 * block_count тут НЕ віднімається.
/// </summary>
public sealed class VolumeCapacityCalculator : IVolumeCapacityPlanner
{
    public const int VolumeHeaderSize = 41;
    public const int HmacTagSize = 32;
    public const int PayloadFixedBytes = 6;
    public const int FileTableEntryFixedBytes = 12;
    public const int BlockTableEntrySize = 15;

    /// <summary>
    /// Фіксує файли, яким належать блоки-кандидати, та обчислює доступну місткість під ці блоки.
    /// </summary>
    /// <exception cref="SarcException">
    /// E_CAPACITY, якщо таблиця файлів або хоча б один блок не вміщується в порожній том.
    /// </exception>
    public VolumeCapacityPlan Plan(
        int maxVolumeBytes,
        IReadOnlyList<ArchiveFileInfo> allFiles,
        IReadOnlyList<BlockCandidate> candidates)
    {
        ArgumentNullException.ThrowIfNull(allFiles);
        ArgumentNullException.ThrowIfNull(candidates);

        if (maxVolumeBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxVolumeBytes), maxVolumeBytes, "Volume size must be positive.");
        }

        List<ArchiveFileInfo> fixedFiles = FixCandidateFiles(allFiles, candidates);
        int fileTableSize = CalculateFileTableSize(fixedFiles);

        int capacity = maxVolumeBytes
            - VolumeHeaderSize
            - HmacTagSize
            - PayloadFixedBytes
            - fileTableSize;

        if (capacity < 0)
        {
            throw new SarcException(
                SarcErrorCode.E_CAPACITY,
                $"File table ({fileTableSize} bytes) does not fit into volume of {maxVolumeBytes} bytes.");
        }

        foreach (BlockCandidate candidate in candidates)
        {
            if (candidate.Weight < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(candidates), candidate.Weight, "Block weight cannot be negative.");
            }

            if (candidate.Weight > capacity)
            {
                throw new SarcException(
                    SarcErrorCode.E_CAPACITY,
                    $"Block {candidate.BlockId} of weight {candidate.Weight} bytes does not fit into usable capacity {capacity} bytes.");
            }
        }

        return new VolumeCapacityPlan(maxVolumeBytes, fileTableSize, capacity, fixedFiles);
    }

    /// <summary>
    /// Розмір запису таблиці файлів: name_len (2) + name (UTF-8) + orig_size (4) + crc32 (4)
    /// + file_type (1) + strategy (1).
    /// </summary>
    public static int GetFileTableEntrySize(ArchiveFileInfo file)
    {
        ArgumentNullException.ThrowIfNull(file);
        return FileTableEntryFixedBytes + Encoding.UTF8.GetByteCount(file.FileName);
    }

    /// <summary>
    /// Повний розмір таблиці файлів у байтах.
    /// </summary>
    public static int CalculateFileTableSize(IReadOnlyList<ArchiveFileInfo> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        int size = 0;
        foreach (ArchiveFileInfo file in files)
        {
            size += GetFileTableEntrySize(file);
        }

        return size;
    }

    /// <summary>
    /// Відбирає файли, на які посилаються блоки-кандидати, зберігаючи вихідний порядок allFiles.
    /// </summary>
    private static List<ArchiveFileInfo> FixCandidateFiles(
        IReadOnlyList<ArchiveFileInfo> allFiles,
        IReadOnlyList<BlockCandidate> candidates)
    {
        bool[] isCandidateFile = new bool[allFiles.Count];

        foreach (BlockCandidate candidate in candidates)
        {
            if (candidate.FileIndex >= allFiles.Count)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(candidates),
                    candidate.FileIndex,
                    $"Block {candidate.BlockId} references file index outside the file list.");
            }

            isCandidateFile[candidate.FileIndex] = true;
        }

        List<ArchiveFileInfo> fixedFiles = new(isCandidateFile.Count(item => item));
        for (int i = 0; i < allFiles.Count; i++)
        {
            if (isCandidateFile[i])
            {
                fixedFiles.Add(allFiles[i]);
            }
        }

        return fixedFiles;
    }
}
