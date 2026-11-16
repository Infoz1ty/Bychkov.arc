using System.Globalization;
using System.Text;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Tests.Compression;

/// <summary>
/// Інтеграційні та перевірочні тести Зрізу 3 та Зрізу 4 для Зони 1 (Учасник 1 — Стиснення):
/// 1) Round-trip стиснення та декомпресії на всіх 21 файлах (7 груп типів) корпусу team/corpus/
///    як цілими файлами, так і блоками по 16 КБ у режимах allowCompression=true/false, Greedy та Lazy Greedy.
/// 2) Перевірка автоматичного переходу в NO_COMPRESSION (0x01) при coded_len >= raw_len (група 5, випадковий шум).
/// 3) Крайові випадки C2 (0 байтів, 1 байт, 2 байти < MIN_MATCH, вироджений алфавіт, межа вікна 32768).
/// 4) Negative та Fuzz-тести на пошкоджених потоках і таблицях із гарантією викидання SarcException(E_CODE)
///    без жодних необроблених системних винятків.
/// </summary>
public class Slice3CorpusRoundTripTests
{
    private const int CorpusBlockSize = 16384;

    private readonly BlockCompressor _compressor = new();
    private readonly HuffmanCodec _huffman = new();
    private readonly Lz77Parser _lz77 = new();

    [Fact]
    public void CorpusAll21Files_FullAndChunkedRoundTrip_GreedyAndLazyAndNoCompression_Succeeds()
    {
        IReadOnlyList<(string FileName, byte GroupId, byte[] Data)> corpus = LoadAllCorpusFiles();
        Assert.Equal(21, corpus.Count);
        Assert.Equal(7, corpus.Select(c => c.GroupId).Distinct().Count());

        foreach ((string fileName, byte groupId, byte[] data) in corpus)
        {
            // 1. Примусовий режим без стиснення (allowCompression = false)
            byte[] rawCoded = _compressor.Compress(data, out byte rawFlags, allowCompression: false);
            Assert.Equal(BlockCompressor.FlagNoCompression, rawFlags);
            Assert.Equal(data.Length, rawCoded.Length);
            byte[] rawRestored = _compressor.Decompress(rawCoded, rawFlags, data.Length);
            Assert.Equal(data, rawRestored);

            // 2. Цілий файл у режимах Greedy та Lazy Greedy (allowCompression = true)
            foreach (bool useLazy in new[] { false, true })
            {
                byte[] coded = _compressor.Compress(
                    data,
                    out byte flags,
                    allowCompression: true,
                    windowSize: Lz77Parser.DefaultWindowSize,
                    minMatchLength: Lz77Parser.MinMatchLength,
                    useLazyMatching: useLazy);

                Assert.True(coded.Length <= data.Length, $"File {fileName} expanded: {coded.Length} > {data.Length}");

                if (flags == BlockCompressor.FlagNoCompression)
                {
                    Assert.Equal(data.Length, coded.Length);
                }
                else
                {
                    Assert.Equal(BlockCompressor.FlagCompressed, flags);
                    Assert.True(coded.Length < data.Length);
                }

                // Для групи 5 ("вже стиснуте", .z) перевіряємо, що блок автоматично перейшов у NO_COMPRESSION
                if (groupId == 5)
                {
                    Assert.Equal(BlockCompressor.FlagNoCompression, flags);
                    Assert.Equal(data.Length, coded.Length);
                }

                byte[] restored = _compressor.Decompress(coded, flags, data.Length);
                Assert.Equal(data, restored);
            }

            // 3. Поблочний round-trip (block_size = 16384 з team_config.json)
            using var reassembled = new MemoryStream(data.Length);
            for (int offset = 0; offset < data.Length; offset += CorpusBlockSize)
            {
                int chunkLen = Math.Min(CorpusBlockSize, data.Length - offset);
                ReadOnlySpan<byte> chunk = data.AsSpan(offset, chunkLen);

                byte[] codedChunk = _compressor.Compress(chunk, out byte chunkFlags, allowCompression: true, useLazyMatching: true);
                Assert.True(codedChunk.Length <= chunkLen);

                byte[] restoredChunk = _compressor.Decompress(codedChunk, chunkFlags, chunkLen);
                Assert.Equal(chunk.ToArray(), restoredChunk);
                reassembled.Write(restoredChunk, 0, restoredChunk.Length);
            }

            Assert.Equal(data, reassembled.ToArray());
        }
    }

    [Fact]
    public void EdgeCases_C2_EmptySingleTwoByteDegenerateAndMaxWindow_RoundTripCorrectly()
    {
        // 0 байтів, 1 байт, 2 байти (< MIN_MATCH = 3), 3 байти (== MIN_MATCH)
        byte[][] smallInputs =
        [
            [],
            [0x42],
            [0x42, 0x42],
            [0x42, 0x42, 0x42],
            Encoding.ASCII.GetBytes("AAAAAAAAAA")
        ];

        foreach (byte[] input in smallInputs)
        {
            byte[] coded = _compressor.Compress(input, out byte flags, allowCompression: true);
            Assert.True(coded.Length <= input.Length);
            byte[] restored = _compressor.Decompress(coded, flags, input.Length);
            Assert.Equal(input, restored);
        }

        // Перевірка збігу рівно на максимальній відстані вікна 32768 байтів
        byte[] windowBoundary = new byte[32768 + 64];
        var rng = new Random(42);
        rng.NextBytes(windowBoundary);
        // Копіюємо перші 64 байти у кінець на відстані рівно 32768
        Array.Copy(windowBoundary, 0, windowBoundary, 32768, 64);

        IReadOnlyList<Lz77Token> tokens = _lz77.Parse(windowBoundary, windowSize: 32768);
        Assert.Contains(tokens, t => t.Type == Lz77TokenType.Match && t.Distance == 32768);

        byte[] encoded = _huffman.Encode(tokens, out HuffmanCodeTables tables);
        IReadOnlyList<Lz77Token> decodedTokens = _huffman.Decode(encoded, tables, tokens.Count);
        byte[] decompressed = _lz77.Decompress(decodedTokens, windowBoundary.Length);
        Assert.Equal(windowBoundary, decompressed);
    }

    [Fact]
    public void NegativeTests_CorruptedHeadersTablesAndBitstreams_AlwaysThrowSarcExceptionWithE_CODE()
    {
        byte[] original = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("Valid compressible payload for negative E_CODE testing! ", 40)));
        byte[] validCoded = _compressor.Compress(original, out byte flags);
        Assert.Equal(BlockCompressor.FlagCompressed, flags);

        // 1. Порожній буфер стисненого блоку -> E_CODE
        AssertThrowsECode(() => _compressor.Decompress([], BlockCompressor.FlagCompressed, original.Length));

        // 2. Обрізаний стиснений блок на кожній можливій довжині префікса -> E_CODE
        for (int len = 1; len < validCoded.Length; len++)
        {
            byte[] truncated = validCoded[..len];
            AssertThrowsECode(() => _compressor.Decompress(truncated, BlockCompressor.FlagCompressed, original.Length));
        }

        // 3. Доданий зайвий байт у кінець стисненого блоку (stream_len не збігається із залишком) -> E_CODE
        byte[] extraByteBlock = [.. validCoded, 0x00];
        AssertThrowsECode(() => _compressor.Decompress(extraByteBlock, BlockCompressor.FlagCompressed, original.Length));

        // 4. Невідповідність expectedRawLength (менший або більший за фактичний) -> E_CODE
        AssertThrowsECode(() => _compressor.Decompress(validCoded, BlockCompressor.FlagCompressed, original.Length - 1));
        AssertThrowsECode(() => _compressor.Decompress(validCoded, BlockCompressor.FlagCompressed, original.Length + 1));

        // 5. Негативний expectedRawLength -> E_CODE
        AssertThrowsECode(() => _compressor.Decompress(validCoded, BlockCompressor.FlagCompressed, -1));

        // 6. NO_COMPRESSION із розбіжністю довжини coded_len != raw_len -> E_CODE
        AssertThrowsECode(() => _compressor.Decompress(original[..10], BlockCompressor.FlagNoCompression, original.Length));

        // 7. Невідомі біти у blockFlags (біти 1..7 != 0) -> E_PAYLOAD
        var exPayload = Assert.Throws<SarcException>(() =>
            _compressor.Decompress(original, blockFlags: 0x02, original.Length));
        Assert.Equal(SarcErrorCode.E_PAYLOAD, exPayload.ErrorCode);

        // 8. Таблиця LIT із nsym > 257 (наприклад, 300) -> E_CODE
        byte[] badNsym = (byte[])validCoded.Clone();
        badNsym[0] = 0x01;
        badNsym[1] = 0x2C; // 300 > 257
        AssertThrowsECode(() => _compressor.Decompress(badNsym, BlockCompressor.FlagCompressed, original.Length));

        // 9. Таблиця LIT із довжиною коду 0 або 16 (> 15) у першому записі -> E_CODE
        byte[] badLenZero = (byte[])validCoded.Clone();
        badLenZero[4] = 0;
        AssertThrowsECode(() => _compressor.Decompress(badLenZero, BlockCompressor.FlagCompressed, original.Length));

        byte[] badLen16 = (byte[])validCoded.Clone();
        badLen16[4] = 16;
        AssertThrowsECode(() => _compressor.Decompress(badLen16, BlockCompressor.FlagCompressed, original.Length));

        // 10. Порушення порядку символів у таблиці Гаффмана (другий символ <= першого) -> E_CODE
        byte[] unsortedSymbols = (byte[])validCoded.Clone();
        unsortedSymbols[5] = unsortedSymbols[2];
        unsortedSymbols[6] = unsortedSymbols[3];
        AssertThrowsECode(() => _compressor.Decompress(unsortedSymbols, BlockCompressor.FlagCompressed, original.Length));

        // 11. Спроба декодувати токени при порожній таблиці LIT (nsym = 0, token_count = 1) -> E_CODE
        byte[] emptyTablesWithToken =
        [
            0x00, 0x00, // LIT nsym = 0
            0x00, 0x00, // LEN nsym = 0
            0x00, 0x00, // DIST nsym = 0
            0x00, 0x00, 0x00, 0x01, // token_count = 1
            0x00, 0x00, 0x00, 0x01, // stream_len = 1
            0x00 // stream
        ];
        AssertThrowsECode(() => _compressor.Decompress(emptyTablesWithToken, BlockCompressor.FlagCompressed, 1));

        // 12. Вироджена таблиця LIT (nsym = 1, symbol = 'A', length = 1), але в потоці біт '1' замість '0' -> E_CODE
        byte[] degenerateBadBit =
        [
            0x00, 0x01, 0x00, (byte)'A', 0x01, // LIT: nsym = 1, symbol = 'A', length = 1
            0x00, 0x00, // LEN: nsym = 0
            0x00, 0x00, // DIST: nsym = 0
            0x00, 0x00, 0x00, 0x01, // token_count = 1
            0x00, 0x00, 0x00, 0x01, // stream_len = 1
            0x80 // Перший біт = 1 (невалідний для виродженого дерева, де єдиний код = 0)
        ];
        AssertThrowsECode(() => _compressor.Decompress(degenerateBadBit, BlockCompressor.FlagCompressed, 1));
    }

    [Fact]
    public void FuzzTests_RandomMutationsAndGarbageStreams_NeverThrowUnhandledExceptions()
    {
        byte[] sample = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("Fuzzing SARC v1 Huffman and LZ77 decoder resilience against bit flips. ", 30)));
        byte[] validCoded = _compressor.Compress(sample, out byte flags);
        Assert.Equal(BlockCompressor.FlagCompressed, flags);

        var rng = new Random(20261116);

        // 1. 300 випадкових мутацій валідного стисненого блоку
        for (int trial = 0; trial < 300; trial++)
        {
            byte[] mutated = (byte[])validCoded.Clone();
            int mutationsCount = rng.Next(1, 6);
            for (int m = 0; m < mutationsCount; m++)
            {
                int pos = rng.Next(0, mutated.Length);
                mutated[pos] ^= (byte)(1 << rng.Next(0, 8));
            }

            try
            {
                byte[] output = _compressor.Decompress(mutated, BlockCompressor.FlagCompressed, sample.Length);
                Assert.Equal(sample.Length, output.Length);
            }
            catch (SarcException ex)
            {
                Assert.Equal(SarcErrorCode.E_CODE, ex.ErrorCode);
            }
        }

        // 2. 200 повністю випадкових байтових буферів різної довжини
        for (int trial = 0; trial < 200; trial++)
        {
            byte[] garbage = new byte[rng.Next(0, 256)];
            rng.NextBytes(garbage);
            int expectedLen = rng.Next(0, 512);

            try
            {
                _ = _compressor.Decompress(garbage, BlockCompressor.FlagCompressed, expectedLen);
            }
            catch (SarcException ex)
            {
                Assert.Equal(SarcErrorCode.E_CODE, ex.ErrorCode);
            }
        }
    }

    private static void AssertThrowsECode(Action action)
    {
        var ex = Assert.Throws<SarcException>(action);
        Assert.Equal(SarcErrorCode.E_CODE, ex.ErrorCode);
    }

    private static IReadOnlyList<(string FileName, byte GroupId, byte[] Data)> LoadAllCorpusFiles()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string corpusDir = Path.Combine(dir.FullName, "team", "corpus");
            string labelsPath = Path.Combine(corpusDir, "labels.csv");
            if (Directory.Exists(corpusDir) && File.Exists(labelsPath))
            {
                var result = new List<(string FileName, byte GroupId, byte[] Data)>();
                foreach (string line in File.ReadLines(labelsPath).Skip(1))
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    string[] parts = line.Split(',');
                    string fileName = parts[0].Trim();
                    byte groupId = byte.Parse(parts[1].Trim(), CultureInfo.InvariantCulture);
                    string path = Path.Combine(corpusDir, fileName);
                    result.Add((fileName, groupId, File.ReadAllBytes(path)));
                }

                return result;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate team/corpus/ directory.");
    }
}
