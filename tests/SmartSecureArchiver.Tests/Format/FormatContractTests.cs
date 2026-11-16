using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Tests.Format;

public class FormatContractTests
{
    private readonly SarcFormatHandler _handler = new();
    private readonly CryptoEngine _crypto = new();

    [Fact]
    public void SarcErrorCodes_ContainAllSpecRequiredCodes()
    {
        var defined = Enum.GetNames<SarcErrorCode>();
        Assert.Contains("E_SHORT", defined);
        Assert.Contains("E_MAGIC", defined);
        Assert.Contains("E_LENGTH", defined);
        Assert.Contains("E_HMAC", defined);
        Assert.Contains("E_PAYLOAD", defined);
        Assert.Contains("E_CODE", defined);
        Assert.Contains("E_CRC", defined);
        Assert.Contains("E_VOLUMES", defined);
        Assert.Contains("E_CAPACITY", defined);
    }

    [Fact]
    public void FileBlock_Matches15ByteHeaderFieldTypes()
    {
        var block = new FileBlock(
            FileIndex: 0,
            BlockSeq: 0u,
            RawLength: 480u,
            CodedLength: 57u,
            BlockFlags: 0,
            Data: new byte[57]);

        Assert.Equal((ushort)0, block.FileIndex);
        Assert.Equal(0u, block.BlockSeq);
        Assert.Equal(480u, block.RawLength);
        Assert.Equal(57u, block.CodedLength);
        Assert.Equal((byte)0, block.BlockFlags);
        Assert.False(block.IsNoCompression);
        Assert.Equal(72, block.KnapsackWeight);
    }

    [Fact]
    public void HuffmanCodeTables_StoresThreeSeparateTreeLengths()
    {
        var tables = new HuffmanCodeTables(
            LitLengths: new byte[257],
            LenLengths: new byte[256],
            DistLengths: new byte[16]);

        Assert.Equal(257, tables.LitLengths.Length);
        Assert.Equal(256, tables.LenLengths.Length);
        Assert.Equal(16, tables.DistLengths.Length);
    }

    [Fact]
    public void VolumeHeader_SerializationRoundTrip_Success()
    {
        byte[] salt = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] nonce = Convert.FromHexString("010203040506070800000000");
        uint ciphertextLen = 99u;

        byte[] fullVolume = new byte[VolumeHeader.Size + ciphertextLen + VolumeHeader.HmacSize];
        _handler.WriteVolumeHeader(fullVolume, volumeIndex: 0, volumeCount: 1, salt, nonce, ciphertextLen);

        SarcErrorCode code = _handler.TryParseVolumeHeader(
            fullVolume,
            out ushort volIndex,
            out ushort volCount,
            out byte[] parsedSalt,
            out byte[] parsedNonce,
            out uint parsedCipherLen);

        Assert.Equal(SarcErrorCode.Ok, code);
        Assert.Equal((ushort)0, volIndex);
        Assert.Equal((ushort)1, volCount);
        Assert.Equal(salt, parsedSalt);
        Assert.Equal(nonce, parsedNonce);
        Assert.Equal(99u, parsedCipherLen);
    }

    [Fact]
    public void TryParseVolumeHeader_RejectsShortMagicAndLength()
    {
        // 1. Менше 73 байтів -> E_SHORT
        byte[] shortVolume = new byte[72];
        Assert.Equal(
            SarcErrorCode.E_SHORT,
            _handler.TryParseVolumeHeader(shortVolume, out _, out _, out _, out _, out _));

        // 2. Невірний magic або версія -> E_MAGIC
        byte[] badMagic = new byte[73];
        "XXXX"u8.CopyTo(badMagic.AsSpan(0, 4));
        badMagic[4] = 1;
        Assert.Equal(
            SarcErrorCode.E_MAGIC,
            _handler.TryParseVolumeHeader(badMagic, out _, out _, out _, out _, out _));

        byte[] badVersion = new byte[73];
        "SARC"u8.CopyTo(badVersion.AsSpan(0, 4));
        badVersion[4] = 2;
        Assert.Equal(
            SarcErrorCode.E_MAGIC,
            _handler.TryParseVolumeHeader(badVersion, out _, out _, out _, out _, out _));

        // 3. Невідповідність фізичної довжини -> E_LENGTH
        byte[] badLen = new byte[80];
        "SARC"u8.CopyTo(badLen.AsSpan(0, 4));
        badLen[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(badLen.AsSpan(5, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(badLen.AsSpan(7, 2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(badLen.AsSpan(37, 4), 50u); // 41 + 50 + 32 = 123 != 80
        Assert.Equal(
            SarcErrorCode.E_LENGTH,
            _handler.TryParseVolumeHeader(badLen, out _, out _, out _, out _, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("../secret.txt")]
    [InlineData("..\\secret.txt")]
    [InlineData("folder/file.txt")]
    [InlineData("folder\\file.txt")]
    [InlineData("C:file.txt")]
    [InlineData("/etc/passwd")]
    [InlineData("file\0name.txt")]
    public void FileNameValidator_RejectsUnsafeNamesWithE_PAYLOAD(string unsafeName)
    {
        Assert.False(FileNameValidator.IsSafeArchiveFileName(unsafeName));
        var ex = Assert.Throws<SarcException>(() => FileNameValidator.ValidateOrThrow(unsafeName));
        Assert.Equal(SarcErrorCode.E_PAYLOAD, ex.ErrorCode);
    }

    [Fact]
    public void FileNameValidator_RejectsOverlyLongNameAndAcceptsSimpleUtf8Names()
    {
        string tooLong = new string('a', 256) + ".txt";
        Assert.False(FileNameValidator.IsSafeArchiveFileName(tooLong));

        Assert.True(FileNameValidator.IsSafeArchiveFileName("hello.txt"));
        Assert.True(FileNameValidator.IsSafeArchiveFileName("звіт_2026.csv"));
    }

    [Fact]
    public void Payload_BuildAndParse_RoundTripMatchesSpecControlExample()
    {
        // Контрольний приклад із розділу 8 FORMAT_SPEC_P2_2.md (ref_01_single_file.arc):
        // hello.txt, orig_size=480, crc32=0x70208846, file_type=0, strategy=1, 1 блок coded_len=57
        var files = new List<ArchiveFileInfo>
        {
            new("hello.txt", OriginalSize: 480u, Crc32: 0x70208846u, FileType: 0, Strategy: 1)
        };

        byte[] dummyCodedBlock = new byte[57];
        var blocks = new List<FileBlock>
        {
            new(FileIndex: 0, BlockSeq: 0u, RawLength: 480u, CodedLength: 57u, BlockFlags: 0, Data: dummyCodedBlock)
        };

        byte[] payload = _handler.BuildPayload(files, blocks, flags: 0);

        // За розділом 8 специфікації: довжина навантаження має бути рівно 99 байтів!
        Assert.Equal(99, payload.Length);

        // Перевіряємо перші 42 байти (до даних блоку) побайтово за розділом 8 FORMAT_SPEC_P2_2.md
        string expectedPrefixHex =
            "0001" +                 // file_count = 1
            "00" +                   // flags = 0
            "00" +                   // reserved = 0
            "0009" +                 // name_len = 9
            "68656C6C6F2E747874" +   // "hello.txt"
            "000001E0" +             // orig_size = 480
            "70208846" +             // crc32
            "00" +                   // file_type = 0
            "01" +                   // strategy = 1
            "0001" +                 // block_count = 1
            "000000000000000001E00000003900"; // file_index=0, block_seq=0, raw_len=480, coded_len=57, flags=0

        Assert.Equal(expectedPrefixHex, Convert.ToHexString(payload.AsSpan(0, 42)));

        _handler.ParsePayload(payload, out var parsedFiles, out var parsedBlocks, out byte parsedFlags);
        Assert.Equal((byte)0, parsedFlags);
        Assert.Single(parsedFiles);
        Assert.Equal(files[0], parsedFiles[0]);
        Assert.Single(parsedBlocks);
        Assert.Equal((ushort)0, parsedBlocks[0].FileIndex);
        Assert.Equal(0u, parsedBlocks[0].BlockSeq);
        Assert.Equal(480u, parsedBlocks[0].RawLength);
        Assert.Equal(57u, parsedBlocks[0].CodedLength);
        Assert.Equal((byte)0, parsedBlocks[0].BlockFlags);
    }

    [Fact]
    public void ParsePayload_RejectsInvalidFlagsReservedFileTypeAndTrailingBytes()
    {
        var files = new List<ArchiveFileInfo>
        {
            new("test.txt", 4u, 0x12345678u, FileType: 0, Strategy: 0)
        };
        var blocks = new List<FileBlock>
        {
            new(0, 0u, 4u, 4u, FileBlock.NoCompressionFlag, [1, 2, 3, 4])
        };

        byte[] validPayload = _handler.BuildPayload(files, blocks);

        // 1. reserved != 0 -> E_PAYLOAD
        byte[] badReserved = (byte[])validPayload.Clone();
        badReserved[3] = 1;
        var exRes = Assert.Throws<SarcException>(() => _handler.ParsePayload(badReserved, out _, out _, out _));
        Assert.Equal(SarcErrorCode.E_PAYLOAD, exRes.ErrorCode);

        // 2. flags != 0 -> E_PAYLOAD
        byte[] badFlags = (byte[])validPayload.Clone();
        badFlags[2] = 0x01;
        var exFlags = Assert.Throws<SarcException>(() => _handler.ParsePayload(badFlags, out _, out _, out _));
        Assert.Equal(SarcErrorCode.E_PAYLOAD, exFlags.ErrorCode);

        // 3. file_type > 6 -> E_PAYLOAD
        byte[] badType = (byte[])validPayload.Clone();
        badType[4 + 2 + 8 + 8] = 7; // file_type offset
        var exType = Assert.Throws<SarcException>(() => _handler.ParsePayload(badType, out _, out _, out _));
        Assert.Equal(SarcErrorCode.E_PAYLOAD, exType.ErrorCode);

        // 4. Зайвий байт у кінці Payload -> E_PAYLOAD
        byte[] extraBytePayload = [.. validPayload, 0xFF];
        var exExtra = Assert.Throws<SarcException>(() => _handler.ParsePayload(extraBytePayload, out _, out _, out _));
        Assert.Equal(SarcErrorCode.E_PAYLOAD, exExtra.ErrorCode);
    }

    [Fact]
    public void ReferenceArchive01_ControlExample_ParsesHeaderPayloadAndHuffmanTablesExact()
    {
        string path = FindRepoFile(Path.Combine("team", "reference", "ref_01_single_file.arc"));
        byte[] volumeBytes = File.ReadAllBytes(path);
        Assert.Equal(172, volumeBytes.Length);

        VolumeHeader header = _handler.ParseVolumeHeaderOrThrow(volumeBytes);
        Assert.Equal((ushort)0, header.VolumeIndex);
        Assert.Equal((ushort)1, header.VolumeCount);
        Assert.Equal(99u, header.CiphertextLength);

        DerivedKeys keys = _crypto.DeriveKeys("algo2026", header.Salt);
        byte[] payload = _crypto.DecryptVolumePayload(
            volumeBytes.AsSpan(0, VolumeHeader.Size),
            volumeBytes.AsSpan(VolumeHeader.Size, (int)header.CiphertextLength),
            volumeBytes.AsSpan(VolumeHeader.Size + (int)header.CiphertextLength, VolumeHeader.HmacSize),
            keys,
            header.Nonce);

        _handler.ParsePayload(payload, out var files, out var blocks, out byte flags);
        Assert.Equal(0, flags);
        Assert.Single(files);
        Assert.Equal("hello.txt", files[0].FileName);
        Assert.Equal(480u, files[0].OriginalSize);
        Assert.Equal(0x70208846u, files[0].Crc32);

        Assert.Single(blocks);
        Assert.Equal(57u, blocks[0].CodedLength);

        // Перевіряємо таблиці Гаффмана LIT, LEN, DIST та потік 7 байтів (розділ 8 FORMAT_SPEC_P2_2.md)
        ReadOnlySpan<byte> codedBlock = blocks[0].Data;
        int offset = 0;
        byte[] litLengths = BlockCompressor.ReadAndValidateCodeTable(codedBlock, ref offset, BlockCompressor.MaxLitSymbol, "LIT");
        byte[] lenLengths = BlockCompressor.ReadAndValidateCodeTable(codedBlock, ref offset, BlockCompressor.MaxLenSymbol, "LEN");
        byte[] distLengths = BlockCompressor.ReadAndValidateCodeTable(codedBlock, ref offset, BlockCompressor.MaxDistSymbol, "DIST");

        Assert.Equal(2, litLengths['l']);
        Assert.Equal(3, litLengths[' ']);
        Assert.Equal(3, litLengths['o']);
        Assert.Equal(3, litLengths['w']);
        Assert.Equal(3, litLengths[256]);
        Assert.Equal(4, litLengths['d']);
        Assert.Equal(4, litLengths['e']);
        Assert.Equal(4, litLengths['h']);
        Assert.Equal(4, litLengths['r']);

        Assert.Equal(1, lenLengths[207]);
        Assert.Equal(1, lenLengths[255]);
        Assert.Equal(1, distLengths[4]);

        uint tokenCount = BinaryPrimitives.ReadUInt32BigEndian(codedBlock.Slice(offset, 4));
        uint streamLen = BinaryPrimitives.ReadUInt32BigEndian(codedBlock.Slice(offset + 4, 4));
        offset += 8;

        Assert.Equal(14u, tokenCount);
        Assert.Equal(7u, streamLen);
        Assert.Equal("ED06A3F3159D18", Convert.ToHexString(codedBlock.Slice(offset, (int)streamLen)));
    }

    [Theory]
    [InlineData("ref_02_empty_file.arc", "empty.dat", 0u, 0x00000000u)]
    [InlineData("ref_05_no_compression.arc", "packed.z", 12000u, 0x369BB1DDu)]
    public void ReferenceArchives_EmptyAndNoCompression_ExtractEndToEndWithExactCrc32(
        string archiveName,
        string expectedFileName,
        uint expectedSize,
        uint expectedCrc32)
    {
        string archivePath = FindRepoFile(Path.Combine("team", "reference", archiveName));
        string tempOutDir = Path.Combine(Path.GetTempPath(), $"sarc_ref_test_{Guid.NewGuid():N}");

        try
        {
            var orchestrator = new ArchiveOrchestrator();
            orchestrator.ExtractArchive(archivePath, tempOutDir, "algo2026");

            string restoredFilePath = Path.Combine(tempOutDir, expectedFileName);
            Assert.True(File.Exists(restoredFilePath));

            byte[] restoredBytes = File.ReadAllBytes(restoredFilePath);
            Assert.Equal((int)expectedSize, restoredBytes.Length);
            Assert.Equal(expectedCrc32, _crypto.ComputeCrc32(restoredBytes));
        }
        finally
        {
            if (Directory.Exists(tempOutDir))
            {
                Directory.Delete(tempOutDir, recursive: true);
            }
        }
    }

    [Fact]
    public void ReferenceBadArchives_AllReturnExpectedFailureCodesFromJson()
    {
        string jsonPath = FindRepoFile(Path.Combine("team", "reference", "expected_failures.json"));
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(jsonPath));

        var orchestrator = new ArchiveOrchestrator(blockCompressor: new ControlExampleBlockCompressorStub());
        string tempOutDir = Path.Combine(Path.GetTempPath(), $"sarc_bad_test_{Guid.NewGuid():N}");

        try
        {
            foreach (JsonProperty prop in doc.RootElement.EnumerateObject())
            {
                string badFileName = prop.Name;
                string expectedCodeStr = prop.Value.GetProperty("очікуваний_код").GetString()!;
                SarcErrorCode expectedCode = Enum.Parse<SarcErrorCode>(expectedCodeStr);

                string badArchivePath = FindRepoFile(Path.Combine("team", "reference", badFileName));

                var ex = Assert.Throws<SarcException>(() =>
                    orchestrator.ExtractArchive([badArchivePath], tempOutDir, "algo2026"));

                Assert.Equal(expectedCode, ex.ErrorCode);
            }
        }
        finally
        {
            if (Directory.Exists(tempOutDir))
            {
                Directory.Delete(tempOutDir, recursive: true);
            }
        }
    }

    [Fact]
    public void ArchiveOrchestrator_MultiVolumeRoundTrip_RestoresInAnyOrderAndDetectsVolumeErrors()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"sarc_multivol_{Guid.NewGuid():N}");
        string inDir = Path.Combine(tempDir, "in");
        string arcDir = Path.Combine(tempDir, "arc");
        string outDir = Path.Combine(tempDir, "out");
        Directory.CreateDirectory(inDir);
        Directory.CreateDirectory(arcDir);

        try
        {
            string f0 = Path.Combine(inDir, "empty.bin");
            string f1 = Path.Combine(inDir, "one_byte.bin");
            string f2 = Path.Combine(inDir, "large_data.bin");

            byte[] data0 = [];
            byte[] data1 = [0x42];
            byte[] data2 = new byte[40_000];
            new Random(2001).NextBytes(data2);

            File.WriteAllBytes(f0, data0);
            File.WriteAllBytes(f1, data1);
            File.WriteAllBytes(f2, data2);

            var orchestrator = new ArchiveOrchestrator(blockSize: 16384);
            string baseArcPath = Path.Combine(arcDir, "multi.arc");

            // Ліміт тому 32768 байтів змусить розбити 40 КБ даних на кілька томів
            IReadOnlyList<string> volumes = orchestrator.CreateArchive([f0, f1, f2], baseArcPath, "algo2026", maxVolumeBytes: 32768);
            Assert.True(volumes.Count >= 2);

            // Подаємо томи у ЗВОРОТНОМУ порядку -> має успішно зібрати всі файли
            IReadOnlyList<string> reversedVolumes = volumes.Reverse().ToList();
            orchestrator.ExtractArchive(reversedVolumes, outDir, "algo2026");

            Assert.Equal(data0, File.ReadAllBytes(Path.Combine(outDir, "empty.bin")));
            Assert.Equal(data1, File.ReadAllBytes(Path.Combine(outDir, "one_byte.bin")));
            Assert.Equal(data2, File.ReadAllBytes(Path.Combine(outDir, "large_data.bin")));

            // Перевірка відсутності тому -> E_VOLUMES
            var missingOne = volumes.Take(volumes.Count - 1).ToList();
            var exMissing = Assert.Throws<SarcException>(() =>
                orchestrator.ExtractArchive(missingOne, outDir, "algo2026"));
            Assert.Equal(SarcErrorCode.E_VOLUMES, exMissing.ErrorCode);

            // Перевірка дубльованого тому -> E_VOLUMES
            var duplicateVol = new List<string>(volumes) { volumes[0] };
            duplicateVol.RemoveAt(volumes.Count - 1);
            var exDup = Assert.Throws<SarcException>(() =>
                orchestrator.ExtractArchive(duplicateVol, outDir, "algo2026"));
            Assert.Equal(SarcErrorCode.E_VOLUMES, exDup.ErrorCode);

            // Перевірка метрики якості Q > 0 на створеному архіві
            QualityMetricResult qResult = QualityMetricCalculator.EvaluateRoundTrip(
                orchestrator,
                [f0, f1, f2],
                password: "algo2026",
                maxVolumeBytes: 32768);
            Assert.True(qResult.IsByteExact);
            Assert.True(qResult.TotalScoreQ > 0.0);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void ArchiveOrchestrator_AtomicExtraction_DoesNotOverwriteExistingFileOnFailure()
    {
        string tempOutDir = Path.Combine(Path.GetTempPath(), $"sarc_atomic_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempOutDir);

        try
        {
            // У bad_06_bad_crc.arc міститься файл hello.txt із пошкодженим CRC32
            string existingFilePath = Path.Combine(tempOutDir, "hello.txt");
            byte[] originalSafeContent = Encoding.UTF8.GetBytes("ORIGINAL_SAFE_USER_FILE_CONTENT");
            File.WriteAllBytes(existingFilePath, originalSafeContent);

            string badCrcArchive = FindRepoFile(Path.Combine("team", "reference", "bad_06_bad_crc.arc"));
            var orchestrator = new ArchiveOrchestrator(blockCompressor: new ControlExampleBlockCompressorStub());

            var ex = Assert.Throws<SarcException>(() =>
                orchestrator.ExtractArchive([badCrcArchive], tempOutDir, "algo2026"));
            Assert.Equal(SarcErrorCode.E_CRC, ex.ErrorCode);

            // Наявний файл користувача не повинен бути перезаписаний або видалений, і .tmp файлів не має залишитись
            Assert.Equal(originalSafeContent, File.ReadAllBytes(existingFilePath));
            Assert.Empty(Directory.GetFiles(tempOutDir, "*.tmp"));
        }
        finally
        {
            if (Directory.Exists(tempOutDir))
            {
                Directory.Delete(tempOutDir, recursive: true);
            }
        }
    }

    [Fact]
    public void ArchiveOrchestrator_TooSmallMaxVolumeBytes_ThrowsE_CAPACITY()
    {
        var orchestrator = new ArchiveOrchestrator();
        var ex = Assert.Throws<SarcException>(() =>
            orchestrator.CreateArchive([], "dummy.arc", "algo2026", maxVolumeBytes: 50));
        Assert.Equal(SarcErrorCode.E_CAPACITY, ex.ErrorCode);
    }

    /// <summary>
    /// Тестова заглушка IBlockCompressor для перевірки E_CRC на контрольному прикладі (480B "hello world " * 40),
    /// поки Учасник 1 не підключив свої класи IHuffmanCodec та ILz77Parser.
    /// </summary>
    private sealed class ControlExampleBlockCompressorStub : IBlockCompressor
    {
        private readonly BlockCompressor _inner = new();

        public byte[] Compress(
            ReadOnlySpan<byte> blockData,
            out byte blockFlags,
            bool allowCompression = true,
            int windowSize = 32768,
            int minMatchLength = 3,
            bool useLazyMatching = false) =>
            _inner.Compress(blockData, out blockFlags, allowCompression, windowSize, minMatchLength, useLazyMatching);

        public byte[] Decompress(ReadOnlySpan<byte> codedData, byte blockFlags, int expectedRawLength)
        {
            if ((blockFlags & FileBlock.NoCompressionFlag) != 0)
            {
                return _inner.Decompress(codedData, blockFlags, expectedRawLength);
            }

            return new byte[expectedRawLength];
        }
    }

    private static string FindRepoFile(string relativePath)
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException($"Could not locate '{relativePath}' in repository tree.");
    }
}
