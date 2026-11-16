using SmartSecureArchiver.Core.Analysis;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Packing;
using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Наскрізний оркестратор створення та розархівування томів SARC v1 (Issues #43, #45, #46).
/// Реалізує повний конвеєр за розділами 1, 2, 4 та 7 FORMAT_SPEC_P2_2.md і рішеннями ADR-04, ADR-05.
/// </summary>
public sealed class ArchiveOrchestrator : IArchiveOrchestrator
{
    public const int DefaultBlockSize = 16384; // згідно з team_config.json

    private readonly ISarcFormatHandler _formatHandler;
    private readonly CryptoEngine _cryptoEngine;
    private readonly IBlockCompressor _blockCompressor;
    private readonly IFeatureExtractor? _featureExtractor;
    private readonly IFileClassifier? _fileClassifier;
    private readonly IKnapsackPacker? _knapsackPacker;
    private readonly int _blockSize;

    public ArchiveOrchestrator(
        ISarcFormatHandler? formatHandler = null,
        CryptoEngine? cryptoEngine = null,
        IBlockCompressor? blockCompressor = null,
        IFeatureExtractor? featureExtractor = null,
        IFileClassifier? fileClassifier = null,
        IKnapsackPacker? knapsackPacker = null,
        int blockSize = DefaultBlockSize)
    {
        if (blockSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be positive.");
        }

        _formatHandler = formatHandler ?? new SarcFormatHandler();
        _cryptoEngine = cryptoEngine ?? new CryptoEngine();
        _blockCompressor = blockCompressor ?? new BlockCompressor();
        _featureExtractor = featureExtractor;
        _fileClassifier = fileClassifier;
        _knapsackPacker = knapsackPacker;
        _blockSize = blockSize;
    }

    /// <inheritdoc />
    public IReadOnlyList<string> CreateArchive(
        IEnumerable<string> filePaths,
        string outputArchivePath,
        string password,
        int maxVolumeBytes)
    {
        ArgumentNullException.ThrowIfNull(filePaths);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputArchivePath);
        ArgumentNullException.ThrowIfNull(password);

        // Критерій C2.4: мінімальний розмір тому має вміщувати хоча б 41B заголовок + 6B порожнього Payload + 32B HMAC
        if (maxVolumeBytes < VolumeHeader.MinVolumeSize + VolumeHeader.PayloadFixedOverhead)
        {
            throw new SarcException(
                SarcErrorCode.E_CAPACITY,
                $"maxVolumeBytes ({maxVolumeBytes}) is smaller than minimum possible volume size ({VolumeHeader.MinVolumeSize + VolumeHeader.PayloadFixedOverhead}).");
        }

        List<string> inputPathList = filePaths.ToList();
        var globalFiles = new List<ArchiveFileInfo>(inputPathList.Count);
        var allCandidates = new List<BlockCandidate>();
        var seenFileNames = new HashSet<string>(StringComparer.Ordinal);
        int nextBlockId = 0;

        for (int fileIdx = 0; fileIdx < inputPathList.Count; fileIdx++)
        {
            string path = inputPathList[fileIdx];
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                throw new FileNotFoundException($"Input file not found: '{path}'.", path);
            }

            string simpleName = Path.GetFileName(path);
            FileNameValidator.ValidateOrThrow(simpleName);

            if (!seenFileNames.Add(simpleName))
            {
                throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Duplicate file name in archive: '{simpleName}'.");
            }

            byte[] fileBytes = File.ReadAllBytes(path);
            uint crc32 = _cryptoEngine.ComputeCrc32(fileBytes);

            byte fileType = 0;
            bool allowCompression = true;

            if (_featureExtractor is not null && _fileClassifier is not null)
            {
                FileFeatures features = _featureExtractor.Extract(fileBytes);
                fileType = _fileClassifier.Classify(features);
                allowCompression = _fileClassifier.ShouldCompress(fileType, features);
            }

            byte strategy = allowCompression ? (byte)1 : (byte)0;
            int priorityValue = GetPriorityForFileType(fileType);

            globalFiles.Add(new ArchiveFileInfo(
                FileName: simpleName,
                OriginalSize: checked((uint)fileBytes.Length),
                Crc32: crc32,
                FileType: fileType,
                Strategy: strategy));

            // Нарізання на блоки (Issue #43):
            // Порожній файл (0 байтів) представлений рівно 1 блоком з raw_len=0, coded_len=0, NO_COMPRESSION (як у ref_02_empty_file.arc)
            if (fileBytes.Length == 0)
            {
                allCandidates.Add(new BlockCandidate(
                    BlockId: nextBlockId++,
                    Weight: FileBlock.HeaderSize,
                    Value: priorityValue,
                    Data: [],
                    FileIndex: (ushort)fileIdx,
                    BlockSeq: 0u,
                    RawLength: 0u,
                    BlockFlags: FileBlock.NoCompressionFlag));
                continue;
            }

            uint blockSeq = 0;
            int offset = 0;
            while (offset < fileBytes.Length)
            {
                int chunkLen = Math.Min(_blockSize, fileBytes.Length - offset);
                ReadOnlySpan<byte> rawChunk = fileBytes.AsSpan(offset, chunkLen);

                byte[] codedChunk = _blockCompressor.Compress(
                    rawChunk,
                    out byte blockFlags,
                    allowCompression: allowCompression);

                int weight = checked(codedChunk.Length + FileBlock.HeaderSize);

                allCandidates.Add(new BlockCandidate(
                    BlockId: nextBlockId++,
                    Weight: weight,
                    Value: priorityValue,
                    Data: codedChunk,
                    FileIndex: (ushort)fileIdx,
                    BlockSeq: blockSeq,
                    RawLength: (uint)chunkLen,
                    BlockFlags: blockFlags));

                offset += chunkLen;
                blockSeq++;
            }
        }

        // Формування томів із попередньою фіксацією таблиці файлів-кандидатів (ADR-05, розділ 7 FORMAT_SPEC_P2_2.md)
        var volumePayloads = new List<byte[]>();

        if (allCandidates.Count == 0)
        {
            // Порожній архів (Критерій C2.2: file_count = 0, block_count = 0)
            volumePayloads.Add(_formatHandler.BuildPayload([], [], flags: 0));
        }
        else
        {
            IReadOnlyList<BlockCandidate> remaining = allCandidates;

            while (remaining.Count > 0)
            {
                // 1. Фіксуємо множину всіх файлів, яким належать блоки-кандидати поточного тому (у порядку зростання індексу)
                var candidateGlobalFileIndices = remaining
                    .Select(b => b.FileIndex)
                    .Distinct()
                    .OrderBy(idx => idx)
                    .ToList();

                var volumeFiles = new List<ArchiveFileInfo>(candidateGlobalFileIndices.Count);
                var globalToLocalFileIndex = new Dictionary<ushort, ushort>(candidateGlobalFileIndices.Count);
                int fileTableBytes = 0;

                for (int i = 0; i < candidateGlobalFileIndices.Count; i++)
                {
                    ushort globalIdx = candidateGlobalFileIndices[i];
                    ArchiveFileInfo fileInfo = globalFiles[globalIdx];
                    volumeFiles.Add(fileInfo);
                    globalToLocalFileIndex[globalIdx] = (ushort)i;
                    fileTableBytes += fileInfo.GetSerializedSize();
                }

                // 2. Обчислюємо чисту місткість W для блоків у поточному томі:
                // W = max_volume_bytes - 41 - 32 - 6 - (розмір таблиці файлів тому)
                int capacityW = maxVolumeBytes
                    - VolumeHeader.Size
                    - VolumeHeader.HmacSize
                    - VolumeHeader.PayloadFixedOverhead
                    - fileTableBytes;

                if (capacityW <= 0)
                {
                    throw new SarcException(
                        SarcErrorCode.E_CAPACITY,
                        $"Available volume capacity W ({capacityW}) is non-positive after reserving file table ({fileTableBytes} bytes).");
                }

                // Перевіряємо, що кожен блок-кандидат здатен поміститися хоча б у порожній том із цією таблицею файлів
                foreach (BlockCandidate candidate in remaining)
                {
                    if (candidate.Weight > capacityW)
                    {
                        throw new SarcException(
                            SarcErrorCode.E_CAPACITY,
                            $"Block {candidate.BlockId} weight ({candidate.Weight} bytes) exceeds volume capacity W ({capacityW} bytes).");
                    }
                }

                // 3. Відбираємо блоки для поточного тому (через IKnapsackPacker або послідовний пакувальник)
                PackingResult packingResult = _knapsackPacker is not null
                    ? _knapsackPacker.PackVolumeDp(capacityW, remaining)
                    : PackVolumeSequentialFallback(capacityW, remaining);

                if (packingResult.SelectedBlocks.Count == 0)
                {
                    throw new SarcException(
                        SarcErrorCode.E_CAPACITY,
                        $"No blocks could be packed into volume with capacity W = {capacityW} bytes.");
                }

                // 4. Формуємо записи таблиці блоків із локальними індексами файлів цього тому
                var volumeBlocks = packingResult.SelectedBlocks
                    .OrderBy(b => b.BlockId)
                    .Select(b => new FileBlock(
                        FileIndex: globalToLocalFileIndex[b.FileIndex],
                        BlockSeq: b.BlockSeq,
                        RawLength: b.RawLength,
                        CodedLength: checked((uint)(b.Data?.Length ?? 0)),
                        BlockFlags: b.BlockFlags,
                        Data: b.Data ?? []))
                    .ToList();

                // Важливо (розділ 7 FORMAT_SPEC_P2_2.md): таблиця файлів volumeFiles НЕ змінюється після вибору блоків!
                byte[] payload = _formatHandler.BuildPayload(volumeFiles, volumeBlocks, flags: 0);
                volumePayloads.Add(payload);

                remaining = packingResult.RemainingBlocks;
            }
        }

        // Криптографічне оформлення томів (ADR-04: PBKDF2 виконується ОДИН раз на весь архів)
        byte[] salt = _cryptoEngine.GenerateSalt();
        byte[] noncePrefix = _cryptoEngine.GenerateNoncePrefix();
        DerivedKeys keys = _cryptoEngine.DeriveKeys(password, salt);

        ushort volumeCount = checked((ushort)volumePayloads.Count);
        var createdVolumePaths = new List<string>(volumeCount);

        string? outDir = Path.GetDirectoryName(Path.GetFullPath(outputArchivePath));
        if (!string.IsNullOrEmpty(outDir))
        {
            Directory.CreateDirectory(outDir);
        }

        for (ushort volIdx = 0; volIdx < volumeCount; volIdx++)
        {
            byte[] payload = volumePayloads[volIdx];
            byte[] nonce = _cryptoEngine.CreateVolumeNonce(noncePrefix, volIdx);

            byte[] headerBytes = new byte[VolumeHeader.Size];
            _formatHandler.WriteVolumeHeader(
                headerBytes,
                volumeIndex: volIdx,
                volumeCount: volumeCount,
                salt: salt,
                nonce: nonce,
                ciphertextLen: (uint)payload.Length);

            (byte[] ciphertext, byte[] hmacTag) = _cryptoEngine.EncryptVolumePayload(
                payload: payload,
                volumeHeader: headerBytes,
                keys: keys,
                nonce: nonce);

            byte[] fullVolume = new byte[VolumeHeader.Size + ciphertext.Length + VolumeHeader.HmacSize];
            headerBytes.CopyTo(fullVolume.AsSpan(0, VolumeHeader.Size));
            ciphertext.CopyTo(fullVolume.AsSpan(VolumeHeader.Size, ciphertext.Length));
            hmacTag.CopyTo(fullVolume.AsSpan(VolumeHeader.Size + ciphertext.Length, VolumeHeader.HmacSize));

            string volumeFilePath = GetVolumeFilePath(outputArchivePath, volIdx, volumeCount);
            File.WriteAllBytes(volumeFilePath, fullVolume);
            createdVolumePaths.Add(volumeFilePath);
        }

        return createdVolumePaths;
    }

    /// <inheritdoc />
    public void ExtractArchive(string archivePath, string outputDirectory, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        IReadOnlyList<string> volumePaths = ResolveArchiveVolumes(archivePath);
        ExtractArchive(volumePaths, outputDirectory, password);
    }

    /// <inheritdoc />
    public void ExtractArchive(IEnumerable<string> volumePaths, string outputDirectory, string password)
    {
        ArgumentNullException.ThrowIfNull(volumePaths);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentNullException.ThrowIfNull(password);

        List<string> paths = volumePaths.ToList();
        if (paths.Count == 0)
        {
            throw new SarcException(SarcErrorCode.E_VOLUMES, "No volume paths provided for extraction.");
        }

        // Крок 1–3 (розділ 4.3 FORMAT_SPEC_P2_2.md): Зчитати томи та перевірити 41B заголовки ДО розшифрування
        var parsedVolumes = new List<(VolumeHeader Header, byte[] RawBytes)>(paths.Count);

        foreach (string path in paths)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                throw new FileNotFoundException($"Archive volume file not found: '{path}'.", path);
            }

            byte[] rawBytes = File.ReadAllBytes(path);
            SarcErrorCode headerStatus = _formatHandler.TryParseVolumeHeader(
                rawBytes,
                out ushort volIndex,
                out ushort volCount,
                out byte[] volSalt,
                out byte[] volNonce,
                out uint ciphertextLen);

            if (headerStatus != SarcErrorCode.Ok)
            {
                throw new SarcException(headerStatus, $"Header validation failed for volume '{path}': {headerStatus}.");
            }

            parsedVolumes.Add((new VolumeHeader(volIndex, volCount, volSalt, volNonce, ciphertextLen), rawBytes));
        }

        // Перевірка повноти і несуперечливості набору томів (розділ 4.3 FORMAT_SPEC_P2_2.md -> E_VOLUMES)
        ushort expectedVolumeCount = parsedVolumes[0].Header.VolumeCount;
        byte[] archiveSalt = parsedVolumes[0].Header.Salt;

        if (expectedVolumeCount == 0 || parsedVolumes.Count != expectedVolumeCount)
        {
            throw new SarcException(
                SarcErrorCode.E_VOLUMES,
                $"Volume count mismatch: expected {expectedVolumeCount} volumes, but received {parsedVolumes.Count}.");
        }

        var seenIndices = new HashSet<ushort>();
        var seenNonces = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (header, _) in parsedVolumes)
        {
            if (header.VolumeCount != expectedVolumeCount)
            {
                throw new SarcException(
                    SarcErrorCode.E_VOLUMES,
                    $"Inconsistent volume_count across volumes ({header.VolumeCount} vs {expectedVolumeCount}).");
            }

            if (header.VolumeIndex >= expectedVolumeCount)
            {
                throw new SarcException(
                    SarcErrorCode.E_VOLUMES,
                    $"volume_index ({header.VolumeIndex}) is out of range for volume_count ({expectedVolumeCount}).");
            }

            if (!seenIndices.Add(header.VolumeIndex))
            {
                throw new SarcException(
                    SarcErrorCode.E_VOLUMES,
                    $"Duplicate volume_index {header.VolumeIndex} detected.");
            }

            if (!header.Salt.AsSpan().SequenceEqual(archiveSalt))
            {
                throw new SarcException(
                    SarcErrorCode.E_VOLUMES,
                    "Volumes have different KDF salts and belong to different archives.");
            }

            if (!seenNonces.Add(Convert.ToHexString(header.Nonce)))
            {
                throw new SarcException(
                    SarcErrorCode.E_VOLUMES,
                    "Duplicate CTR nonce detected across volumes of the same archive.");
            }
        }

        // Упорядкування томів за volume_index (0 .. volume_count - 1) незалежно від порядку подання
        parsedVolumes.Sort((a, b) => a.Header.VolumeIndex.CompareTo(b.Header.VolumeIndex));

        // Крок 4–6 (розділ 4.1 та 4.3): PBKDF2 виконується ОДИН раз на архів;
        // для кожного тому спочатку перевіряється HMAC у постійний час, і лише потім виконується розшифрування
        DerivedKeys keys = _cryptoEngine.DeriveKeys(password, archiveSalt);
        var decryptedPayloads = new List<byte[]>(expectedVolumeCount);

        foreach (var (header, rawBytes) in parsedVolumes)
        {
            int cipherLen = checked((int)header.CiphertextLength);
            ReadOnlySpan<byte> headerSpan = rawBytes.AsSpan(0, VolumeHeader.Size);
            ReadOnlySpan<byte> ciphertextSpan = rawBytes.AsSpan(VolumeHeader.Size, cipherLen);
            ReadOnlySpan<byte> expectedTagSpan = rawBytes.AsSpan(VolumeHeader.Size + cipherLen, VolumeHeader.HmacSize);

            byte[] payload = _cryptoEngine.DecryptVolumePayload(
                volumeHeader: headerSpan,
                ciphertext: ciphertextSpan,
                expectedTag: expectedTagSpan,
                keys: keys,
                nonce: header.Nonce);

            decryptedPayloads.Add(payload);
        }

        // Крок 7–8: Парсинг Payload кожного тому та декомпресія блоків
        var fileMetadataByName = new Dictionary<string, ArchiveFileInfo>(StringComparer.Ordinal);
        var fileOrder = new List<string>();
        var blocksByFileName = new Dictionary<string, List<(uint BlockSeq, byte[] RawData)>>(StringComparer.Ordinal);

        for (int volIdx = 0; volIdx < decryptedPayloads.Count; volIdx++)
        {
            _formatHandler.ParsePayload(
                decryptedPayloads[volIdx],
                out List<ArchiveFileInfo> volFiles,
                out List<FileBlock> volBlocks,
                out _);

            foreach (ArchiveFileInfo fileInfo in volFiles)
            {
                if (!fileMetadataByName.TryGetValue(fileInfo.FileName, out ArchiveFileInfo? existing))
                {
                    fileMetadataByName[fileInfo.FileName] = fileInfo;
                    fileOrder.Add(fileInfo.FileName);
                    blocksByFileName[fileInfo.FileName] = [];
                }
                else if (existing.OriginalSize != fileInfo.OriginalSize || existing.Crc32 != fileInfo.Crc32)
                {
                    throw new SarcException(
                        SarcErrorCode.E_PAYLOAD,
                        $"Inconsistent file metadata across volumes for '{fileInfo.FileName}'.");
                }
            }

            foreach (FileBlock block in volBlocks)
            {
                ArchiveFileInfo ownerFile = volFiles[block.FileIndex];
                byte[] decompressedBlock = _blockCompressor.Decompress(
                    block.Data,
                    block.BlockFlags,
                    checked((int)block.RawLength));

                blocksByFileName[ownerFile.FileName].Add((block.BlockSeq, decompressedBlock));
            }
        }

        // Крок 9–10: Перевірка суцільності ряду block_seq (0, 1, 2, ...), склеювання файлів і перевірка CRC32 (E_CRC)
        var verifiedFiles = new List<(string FileName, byte[] Content)>(fileOrder.Count);

        foreach (string fileName in fileOrder)
        {
            ArchiveFileInfo meta = fileMetadataByName[fileName];
            List<(uint BlockSeq, byte[] RawData)> blocks = blocksByFileName[fileName];

            // Якщо файл не мав жодного блоку (допустимо лише для порожнього файлу orig_size == 0)
            if (blocks.Count == 0)
            {
                if (meta.OriginalSize != 0)
                {
                    throw new SarcException(
                        SarcErrorCode.E_PAYLOAD,
                        $"File '{fileName}' has OriginalSize = {meta.OriginalSize}, but 0 blocks were found.");
                }

                _cryptoEngine.VerifyCrc32OrThrow([], meta.Crc32);
                verifiedFiles.Add((fileName, []));
                continue;
            }

            blocks.Sort((a, b) => a.BlockSeq.CompareTo(b.BlockSeq));

            long totalRestoredSize = 0;
            for (int i = 0; i < blocks.Count; i++)
            {
                if (blocks[i].BlockSeq != (uint)i)
                {
                    throw new SarcException(
                        SarcErrorCode.E_PAYLOAD,
                        $"File '{fileName}' has non-contiguous or duplicate block_seq: expected {i}, got {blocks[i].BlockSeq}.");
                }

                totalRestoredSize += blocks[i].RawData.Length;
            }

            if (totalRestoredSize != meta.OriginalSize)
            {
                throw new SarcException(
                    SarcErrorCode.E_CRC,
                    $"Restored size ({totalRestoredSize}) for file '{fileName}' does not match orig_size ({meta.OriginalSize}).");
            }

            byte[] restoredBytes = new byte[(int)totalRestoredSize];
            int writeOffset = 0;
            foreach (var (_, rawData) in blocks)
            {
                if (rawData.Length > 0)
                {
                    rawData.CopyTo(restoredBytes.AsSpan(writeOffset, rawData.Length));
                    writeOffset += rawData.Length;
                }
            }

            _cryptoEngine.VerifyCrc32OrThrow(restoredBytes, meta.Crc32);
            verifiedFiles.Add((fileName, restoredBytes));
        }

        // Крок 11 (Issue #46, Критерій C5.4): Атомарний запис на диск через тимчасові файли .tmp
        // Запис починається ЛИШЕ після того, як УСІ файли архіву успішно пройшли перевірку CRC32
        Directory.CreateDirectory(outputDirectory);
        string fullOutputDir = Path.GetFullPath(outputDirectory);
        var tempFiles = new List<(string TempPath, string FinalPath)>(verifiedFiles.Count);

        try
        {
            foreach (var (fileName, content) in verifiedFiles)
            {
                FileNameValidator.ValidateOrThrow(fileName);
                string finalPath = Path.GetFullPath(Path.Combine(fullOutputDir, fileName));

                // Додатковий захист: перевіряємо, що канонічний шлях лежить всередині цільового каталогу
                if (!Path.GetDirectoryName(finalPath)!.Equals(
                        fullOutputDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Resolved path escapes output directory: '{fileName}'.");
                }

                string tempPath = Path.Combine(fullOutputDir, $".{fileName}.{Guid.NewGuid():N}.tmp");
                File.WriteAllBytes(tempPath, content);
                tempFiles.Add((tempPath, finalPath));
            }

            foreach (var (tempPath, finalPath) in tempFiles)
            {
                File.Move(tempPath, finalPath, overwrite: true);
            }
        }
        finally
        {
            foreach (var (tempPath, _) in tempFiles)
            {
                if (File.Exists(tempPath))
                {
                    try
                    {
                        File.Delete(tempPath);
                    }
                    catch
                    {
                        // Ігноруємо помилки прибирання тимчасового файла у finally
                    }
                }
            }
        }
    }

    public static int GetPriorityForFileType(byte fileType) => fileType switch
    {
        0 => 3, // природний текст
        1 => 3, // вихідний код
        2 => 2, // структуровані дані
        3 => 2, // растр без стиснення
        4 => 2, // виконуваний файл
        5 => 1, // вже стиснуте
        6 => 1, // штучні дані
        _ => 1
    };

    private static PackingResult PackVolumeSequentialFallback(int capacity, IReadOnlyList<BlockCandidate> candidates)
    {
        var selected = new List<BlockCandidate>();
        var remaining = new List<BlockCandidate>();
        int totalWeight = 0;
        int totalValue = 0;

        foreach (BlockCandidate candidate in candidates)
        {
            if (totalWeight + candidate.Weight <= capacity)
            {
                selected.Add(candidate);
                totalWeight += candidate.Weight;
                totalValue += candidate.Value;
            }
            else
            {
                remaining.Add(candidate);
            }
        }

        return new PackingResult(selected, remaining, totalWeight, totalValue);
    }

    private static string GetVolumeFilePath(string outputArchivePath, ushort volumeIndex, ushort volumeCount)
    {
        if (volumeCount <= 1)
        {
            return outputArchivePath;
        }

        string dir = Path.GetDirectoryName(outputArchivePath) ?? string.Empty;
        string ext = Path.GetExtension(outputArchivePath);
        if (string.IsNullOrEmpty(ext))
        {
            ext = ".arc";
        }

        string stem = Path.GetFileNameWithoutExtension(outputArchivePath);
        if (stem.EndsWith(".part0", StringComparison.OrdinalIgnoreCase))
        {
            stem = stem[..^".part0".Length];
        }

        string fileName = $"{stem}.part{volumeIndex}{ext}";
        return string.IsNullOrEmpty(dir) ? fileName : Path.Combine(dir, fileName);
    }

    private static IReadOnlyList<string> ResolveArchiveVolumes(string archivePath)
    {
        if (File.Exists(archivePath))
        {
            // Якщо передано один із томів серії *.partN.arc, автоматично знаходимо всі сусідні томи цієї серії
            string fileName = Path.GetFileName(archivePath);
            int partIdx = fileName.LastIndexOf(".part", StringComparison.OrdinalIgnoreCase);
            if (partIdx > 0)
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(archivePath)) ?? Directory.GetCurrentDirectory();
                string prefix = fileName[..(partIdx + ".part".Length)];
                string ext = Path.GetExtension(fileName);

                var matched = Directory.GetFiles(dir, $"{prefix}*{ext}")
                    .Where(p =>
                    {
                        string name = Path.GetFileName(p);
                        if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                            !name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        {
                            return false;
                        }

                        string numberPart = name.Substring(prefix.Length, name.Length - prefix.Length - ext.Length);
                        return ushort.TryParse(numberPart, out _);
                    })
                    .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (matched.Count > 0)
                {
                    return matched;
                }
            }

            return [archivePath];
        }

        // Якщо передано базове ім'я archive.arc, а на диску лежать archive.part0.arc, archive.part1.arc...
        string parentDir = Path.GetDirectoryName(Path.GetFullPath(archivePath)) ?? Directory.GetCurrentDirectory();
        string baseStem = Path.GetFileNameWithoutExtension(archivePath);
        string archiveExt = Path.GetExtension(archivePath);
        if (string.IsNullOrEmpty(archiveExt))
        {
            archiveExt = ".arc";
        }

        if (Directory.Exists(parentDir))
        {
            string searchPrefix = $"{baseStem}.part";
            var siblingParts = Directory.GetFiles(parentDir, $"{searchPrefix}*{archiveExt}")
                .Where(p =>
                {
                    string name = Path.GetFileName(p);
                    string numberPart = name.Substring(searchPrefix.Length, name.Length - searchPrefix.Length - archiveExt.Length);
                    return ushort.TryParse(numberPart, out _);
                })
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (siblingParts.Count > 0)
            {
                return siblingParts;
            }
        }

        return [archivePath];
    }
}
