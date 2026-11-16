using System.Buffers.Binary;
using System.Text;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Tests.Compression;

public class HuffmanAndBlockCompressorTests
{
    private readonly HuffmanCodec _huffman = new();
    private readonly Lz77Parser _lz77 = new();
    private readonly BlockCompressor _compressor = new();
    private readonly CryptoEngine _crypto = new();

    [Fact]
    public void Huffman_DegenerateAlphabet_EncodesSingleSymbolCorrectly()
    {
        // 1. Одиночний символ (nsym == 1) у потоці токенів -> length = 1, code = 0 (Кейси C1 №2, №8)
        var singleTokenList = new List<Lz77Token>
        {
            new(Lz77TokenType.Literal, (byte)'A', 0, 0),
            new(Lz77TokenType.Literal, (byte)'A', 0, 0),
            new(Lz77TokenType.Literal, (byte)'A', 0, 0)
        };

        byte[] bitstream = _huffman.Encode(singleTokenList, out HuffmanCodeTables tables);

        Assert.Equal(1, tables.LitLengths['A']);
        Assert.Equal(1, tables.LitLengths.Count(len => len > 0));
        Assert.Single(bitstream);
        Assert.Equal(0x00, bitstream[0]); // Три коди '0' + п'ять бітів нульового доповнення

        IReadOnlyList<Lz77Token> decodedTokens = _huffman.Decode(bitstream, tables, singleTokenList.Count);
        byte[] restored = _lz77.Decompress(decodedTokens, 3);
        Assert.Equal("AAA"u8.ToArray(), restored);

        // 2. Блок з 1 байта та блок з 5000 однакових байтів ('A') через BlockCompressor
        byte[] oneByte = [(byte)'Z'];
        byte[] compressedOne = _compressor.Compress(oneByte, out byte flagsOne);
        byte[] decompressedOne = _compressor.Decompress(compressedOne, flagsOne, oneByte.Length);
        Assert.Equal(oneByte, decompressedOne);

        byte[] repeated5000 = Enumerable.Repeat((byte)'A', 5000).ToArray();
        byte[] compressed5000 = _compressor.Compress(repeated5000, out byte flags5000);
        Assert.Equal(BlockCompressor.FlagCompressed, flags5000);
        Assert.True(compressed5000.Length < 150);

        byte[] decompressed5000 = _compressor.Decompress(compressed5000, flags5000, repeated5000.Length);
        Assert.Equal(repeated5000, decompressed5000);
    }

    [Fact]
    public void MinHeap_MaintainsCorrectOrderingAndDeterministicTieBreaking()
    {
        var heap = new MinHeap<HuffmanNode>();
        heap.Push(new HuffmanNode(symbol: 10, frequency: 5));
        heap.Push(new HuffmanNode(symbol: 2, frequency: 5));
        heap.Push(new HuffmanNode(symbol: 7, frequency: 1));
        heap.Push(new HuffmanNode(symbol: 4, frequency: 3));

        Assert.Equal(4, heap.Count);
        Assert.Equal(7, heap.Pop().Symbol);
        Assert.Equal(4, heap.Pop().Symbol);
        Assert.Equal(2, heap.Pop().Symbol);
        Assert.Equal(10, heap.Pop().Symbol);
        Assert.Equal(0, heap.Count);
    }

    [Fact]
    public void BitWriterAndBitReader_PackMsbFirstAndRejectNonZeroPadding()
    {
        var writer = new BitWriter();
        // Записуємо 5 бітів: 1, 0, 1, 1, 0 -> має дати байт 10110_000 = 0xB0
        writer.WriteBit(1);
        writer.WriteBit(0);
        writer.WriteBits(0b110u, 3);

        byte[] bytes = writer.ToArray();
        Assert.Single(bytes);
        Assert.Equal(0xB0, bytes[0]);

        var reader = new BitReader(bytes);
        Assert.Equal(1, reader.ReadBit());
        Assert.Equal(0, reader.ReadBit());
        Assert.Equal(0b110u, reader.ReadBits(3));
        reader.VerifyZeroPaddingAndEndOrThrow();

        // Якщо молодші біти доповнення ненульові -> E_CODE
        byte[] badPadding = [0xB1];
        var ex = Assert.Throws<SarcException>(() =>
        {
            var badReader = new BitReader(badPadding);
            _ = badReader.ReadBits(5);
            badReader.VerifyZeroPaddingAndEndOrThrow();
        });
        Assert.Equal(SarcErrorCode.E_CODE, ex.ErrorCode);
    }

    [Fact]
    public void CanonicalHuffman_SkewedFibonacciFrequencies_EnforcesMax15BitsAndKraftEquality()
    {
        // Частоти Фібоначчі для 22 символів без обмеження дають глибину дерева 21 (> 15)
        int[] freq = new int[257];
        int a = 1, b = 1;
        for (int i = 0; i < 22; i++)
        {
            freq[i] = a;
            int next = a + b;
            a = b;
            b = next;
        }

        byte[] lengths = CanonicalHuffman.BuildCodeLengths(freq);
        Assert.All(lengths, len => Assert.InRange(len, 0, CanonicalHuffman.MaxCodeLength));

        int nsym = CanonicalHuffman.ValidateLengthsOrThrow(lengths, FrequencyTable.LitAlphabetSize);
        Assert.Equal(22, nsym);

        int kraftSum = lengths.Where(l => l > 0).Sum(l => 1 << (CanonicalHuffman.MaxCodeLength - l));
        Assert.Equal(CanonicalHuffman.KraftTargetSum, kraftSum);
    }

    [Fact]
    public void CanonicalHuffman_InvalidKraftOrLengthOver15_ThrowsE_CODE()
    {
        // Неповне дерево (два символи з довжиною 2: 2^-2 + 2^-2 = 0.5 != 1)
        byte[] incomplete = new byte[16];
        incomplete[0] = 2;
        incomplete[1] = 2;
        var exIncomplete = Assert.Throws<SarcException>(() =>
            CanonicalHuffman.ValidateLengthsOrThrow(incomplete, 16));
        Assert.Equal(SarcErrorCode.E_CODE, exIncomplete.ErrorCode);

        // Переповнене дерево (три символи з довжиною 1: 3 * 2^-1 = 1.5 != 1)
        byte[] oversubscribed = new byte[16];
        oversubscribed[0] = 1;
        oversubscribed[1] = 1;
        oversubscribed[2] = 1;
        var exOver = Assert.Throws<SarcException>(() =>
            CanonicalHuffman.ValidateLengthsOrThrow(oversubscribed, 16));
        Assert.Equal(SarcErrorCode.E_CODE, exOver.ErrorCode);

        // Довжина > 15
        byte[] tooLong = new byte[16];
        tooLong[0] = 16;
        var exTooLong = Assert.Throws<SarcException>(() =>
            CanonicalHuffman.ValidateLengthsOrThrow(tooLong, 16));
        Assert.Equal(SarcErrorCode.E_CODE, exTooLong.ErrorCode);
    }

    [Fact]
    public void Lz77Parser_HandlesOverlapAndRejectsOutOfBoundsMatchesWithE_CODE()
    {
        // Перекриття: distance = 1, length = 10 повторює попередній байт 10 разів
        var overlapTokens = new List<Lz77Token>
        {
            new(Lz77TokenType.Literal, (byte)'X', 0, 0),
            new(Lz77TokenType.Match, 0, Distance: 1, Length: 10)
        };

        byte[] restored = _lz77.Decompress(overlapTokens, 11);
        Assert.Equal(Encoding.ASCII.GetBytes("XXXXXXXXXXX"), restored);

        // Посилання за межі початку блоку (distance > writePos) -> E_CODE
        var badDistTokens = new List<Lz77Token>
        {
            new(Lz77TokenType.Literal, (byte)'X', 0, 0),
            new(Lz77TokenType.Match, 0, Distance: 2, Length: 3)
        };

        var ex = Assert.Throws<SarcException>(() => _lz77.Decompress(badDistTokens, 4));
        Assert.Equal(SarcErrorCode.E_CODE, ex.ErrorCode);
    }

    [Fact]
    public void BlockCompressor_EmptyAndHighEntropyAndTextBlocks_RoundTripCorrectly()
    {
        // 1. Порожній масив (0 байт)
        byte[] empty = [];
        byte[] codedEmpty = _compressor.Compress(empty, out byte flagsEmpty);
        Assert.Empty(codedEmpty);
        Assert.Equal(BlockCompressor.FlagNoCompression, flagsEmpty);
        Assert.Empty(_compressor.Decompress(codedEmpty, flagsEmpty, 0));

        // 2. Природний текст (Greedy та Lazy)
        byte[] text = Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("SARC v1 canonical Huffman and LZ77 compression test line.\n", 20)));
        byte[] codedGreedy = _compressor.Compress(text, out byte flagsGreedy, useLazyMatching: false);
        byte[] codedLazy = _compressor.Compress(text, out byte flagsLazy, useLazyMatching: true);

        Assert.Equal(BlockCompressor.FlagCompressed, flagsGreedy);
        Assert.Equal(BlockCompressor.FlagCompressed, flagsLazy);
        Assert.True(codedGreedy.Length < text.Length);
        Assert.Equal(text, _compressor.Decompress(codedGreedy, flagsGreedy, text.Length));
        Assert.Equal(text, _compressor.Decompress(codedLazy, flagsLazy, text.Length));

        // 3. Випадковий шум -> автоматичний NO_COMPRESSION (coded_len >= raw_len)
        var rng = new Random(2001);
        byte[] randomNoise = new byte[1024];
        rng.NextBytes(randomNoise);

        byte[] codedNoise = _compressor.Compress(randomNoise, out byte flagsNoise);
        Assert.Equal(BlockCompressor.FlagNoCompression, flagsNoise);
        Assert.Equal(randomNoise.Length, codedNoise.Length);
        Assert.Equal(randomNoise, _compressor.Decompress(codedNoise, flagsNoise, randomNoise.Length));
    }

    [Theory]
    [InlineData("ref_01_single_file.arc")]
    [InlineData("ref_02_empty_file.arc")]
    [InlineData("ref_03_degenerate.arc")]
    [InlineData("ref_04_seven_groups.arc")]
    [InlineData("ref_05_no_compression.arc")]
    public void ReferenceSingleVolumeArchives_DecompressAllBlocksAndMatchCrc32(string archiveFileName)
    {
        string path = FindRepoFile(Path.Combine("team", "reference", archiveFileName));
        byte[] volumeBytes = File.ReadAllBytes(path);
        byte[] payload = DecryptReferenceVolume(volumeBytes);

        VerifyPayloadBlocksDecompressAndMatchCrc32([payload]);
    }

    [Fact]
    public void ReferenceMultiVolumeArchive_DecompressesAllBlocksAcrossVolumesAndMatchesCrc32()
    {
        byte[][] payloads =
        [
            DecryptReferenceVolume(File.ReadAllBytes(FindRepoFile(Path.Combine("team", "reference", "ref_06_two_volumes.part0.arc")))),
            DecryptReferenceVolume(File.ReadAllBytes(FindRepoFile(Path.Combine("team", "reference", "ref_06_two_volumes.part1.arc")))),
            DecryptReferenceVolume(File.ReadAllBytes(FindRepoFile(Path.Combine("team", "reference", "ref_06_two_volumes.part2.arc"))))
        ];

        VerifyPayloadBlocksDecompressAndMatchCrc32(payloads);
    }

    private byte[] DecryptReferenceVolume(byte[] volumeBytes)
    {
        ReadOnlySpan<byte> header = volumeBytes.AsSpan(0, CryptoEngine.VolumeHeaderSize);
        ReadOnlySpan<byte> salt = header.Slice(9, CryptoEngine.SaltSize);
        ReadOnlySpan<byte> nonce = header.Slice(25, CryptoEngine.NonceSize);
        uint ciphertextLen = BinaryPrimitives.ReadUInt32BigEndian(header.Slice(37, 4));
        ReadOnlySpan<byte> ciphertext = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize, (int)ciphertextLen);
        ReadOnlySpan<byte> tag = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize + (int)ciphertextLen, CryptoEngine.HmacTagSize);

        DerivedKeys keys = _crypto.DeriveKeys("algo2026", salt);
        return _crypto.DecryptVolumePayload(header, ciphertext, tag, keys, nonce);
    }

    private void VerifyPayloadBlocksDecompressAndMatchCrc32(IReadOnlyList<byte[]> volumePayloads)
    {
        var filesMeta = new Dictionary<string, (uint OrigSize, uint Crc32)>(StringComparer.Ordinal);
        var fileBlocks = new Dictionary<string, SortedDictionary<uint, byte[]>>(StringComparer.Ordinal);

        foreach (byte[] payload in volumePayloads)
        {
            ReadOnlySpan<byte> span = payload;
            int offset = 0;

            ushort fileCount = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset, 2));
            offset += 4; // file_count (2) + flags (1) + reserved (1)

            string[] volumeFileNames = new string[fileCount];
            for (int f = 0; f < fileCount; f++)
            {
                ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset, 2));
                offset += 2;
                string name = Encoding.UTF8.GetString(span.Slice(offset, nameLen));
                offset += nameLen;
                uint origSize = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(offset, 4));
                uint crc32 = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(offset + 4, 4));
                offset += 10; // orig_size (4) + crc32 (4) + file_type (1) + strategy (1)

                volumeFileNames[f] = name;
                filesMeta[name] = (origSize, crc32);
                if (!fileBlocks.ContainsKey(name))
                {
                    fileBlocks[name] = new SortedDictionary<uint, byte[]>();
                }
            }

            ushort blockCount = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset, 2));
            offset += 2;

            var descriptors = new (ushort FileIndex, uint BlockSeq, uint RawLen, uint CodedLen, byte Flags)[blockCount];
            for (int b = 0; b < blockCount; b++)
            {
                ushort fileIndex = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(offset, 2));
                uint blockSeq = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(offset + 2, 4));
                uint rawLen = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(offset + 6, 4));
                uint codedLen = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(offset + 10, 4));
                byte blockFlags = span[offset + 14];
                offset += 15;

                descriptors[b] = (fileIndex, blockSeq, rawLen, codedLen, blockFlags);
            }

            for (int b = 0; b < blockCount; b++)
            {
                var desc = descriptors[b];
                ReadOnlySpan<byte> codedBlock = span.Slice(offset, (int)desc.CodedLen);
                offset += (int)desc.CodedLen;

                byte[] decompressedBlock = _compressor.Decompress(codedBlock, desc.Flags, (int)desc.RawLen);
                Assert.Equal((int)desc.RawLen, decompressedBlock.Length);

                string fileName = volumeFileNames[desc.FileIndex];
                fileBlocks[fileName][desc.BlockSeq] = decompressedBlock;
            }

            Assert.Equal(span.Length, offset);
        }

        foreach ((string fileName, (uint origSize, uint expectedCrc)) in filesMeta)
        {
            using var ms = new MemoryStream((int)origSize);
            foreach (byte[] blockBytes in fileBlocks[fileName].Values)
            {
                ms.Write(blockBytes, 0, blockBytes.Length);
            }

            byte[] fullFile = ms.ToArray();
            Assert.Equal((int)origSize, fullFile.Length);
            Assert.Equal(expectedCrc, _crypto.ComputeCrc32(fullFile));
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
