using System.Buffers.Binary;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Реалізація стиснення та декомпресії блоків SARC v1 (LZ77 + Канонічний Гаффман)
/// згідно з розділом 3 FORMAT_SPEC_P2.md (Зріз 1, Issues #14–#19).
/// Автоматично встановлює NO_COMPRESSION (0x01), якщо allowCompression == false або coded_len >= raw_len.
/// </summary>
public sealed class BlockCompressor : IBlockCompressor
{
    public const byte FlagCompressed = 0x00;
    public const byte FlagNoCompression = 0x01;

    private readonly ILz77Parser _lz77Parser;
    private readonly IHuffmanCodec _huffmanCodec;

    public BlockCompressor()
        : this(new Lz77Parser(), new HuffmanCodec())
    {
    }

    public BlockCompressor(ILz77Parser lz77Parser, IHuffmanCodec huffmanCodec)
    {
        ArgumentNullException.ThrowIfNull(lz77Parser);
        ArgumentNullException.ThrowIfNull(huffmanCodec);

        _lz77Parser = lz77Parser;
        _huffmanCodec = huffmanCodec;
    }

    /// <inheritdoc />
    public byte[] Compress(
        ReadOnlySpan<byte> blockData,
        out byte blockFlags,
        bool allowCompression = true,
        int windowSize = 32768,
        int minMatchLength = 3,
        bool useLazyMatching = false)
    {
        if (!allowCompression || blockData.IsEmpty)
        {
            blockFlags = FlagNoCompression;
            return blockData.ToArray();
        }

        IReadOnlyList<Lz77Token> tokens = _lz77Parser is Lz77Parser concreteParser
            ? concreteParser.Parse(blockData, windowSize, minMatchLength, useLazyMatching)
            : _lz77Parser.Parse(blockData, windowSize);

        byte[] stream = _huffmanCodec.Encode(tokens, out HuffmanCodeTables tables);
        byte[] codedBlock = SerializeCompressedBlock(tables, (uint)tokens.Count, stream);

        if (codedBlock.Length >= blockData.Length)
        {
            blockFlags = FlagNoCompression;
            return blockData.ToArray();
        }

        blockFlags = FlagCompressed;
        return codedBlock;
    }

    /// <inheritdoc />
    public byte[] Decompress(ReadOnlySpan<byte> codedData, byte blockFlags, int expectedRawLength)
    {
        if (expectedRawLength < 0)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Invalid negative expectedRawLength: {expectedRawLength}.");
        }

        if ((blockFlags & ~FlagNoCompression) != 0)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Invalid unknown bits in block_flags: 0x{blockFlags:X2}.");
        }

        if ((blockFlags & FlagNoCompression) != 0)
        {
            if (codedData.Length != expectedRawLength)
            {
                throw new SarcException(
                    SarcErrorCode.E_CODE,
                    $"NO_COMPRESSION block coded_len ({codedData.Length}) does not match raw_len ({expectedRawLength}).");
            }

            return codedData.ToArray();
        }

        int offset = 0;
        byte[] litLengths = CanonicalHuffman.ReadTable(codedData, ref offset, FrequencyTable.LitAlphabetSize);
        byte[] lenLengths = CanonicalHuffman.ReadTable(codedData, ref offset, FrequencyTable.LenAlphabetSize);
        byte[] distLengths = CanonicalHuffman.ReadTable(codedData, ref offset, FrequencyTable.DistAlphabetSize);

        if (offset + 8 > codedData.Length)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Unexpected end of compressed block before token_count and stream_len.");
        }

        uint tokenCount = BinaryPrimitives.ReadUInt32BigEndian(codedData.Slice(offset, 4));
        uint streamLen = BinaryPrimitives.ReadUInt32BigEndian(codedData.Slice(offset + 4, 4));
        offset += 8;

        if ((long)offset + streamLen != codedData.Length)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                $"Compressed block stream_len ({streamLen}) does not match remaining block bytes ({codedData.Length - offset}).");
        }

        if (tokenCount > (uint)expectedRawLength && expectedRawLength >= 0)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Compressed block token_count ({tokenCount}) exceeds raw_len ({expectedRawLength}).");
        }

        var tables = new HuffmanCodeTables(litLengths, lenLengths, distLengths);
        ReadOnlySpan<byte> bitstream = codedData.Slice(offset, (int)streamLen);
        IReadOnlyList<Lz77Token> tokens = _huffmanCodec.Decode(bitstream, tables, (int)tokenCount);

        return _lz77Parser.Decompress(tokens, expectedRawLength);
    }

    /// <summary>
    /// Серіалізує стиснений блок за розділом 3.1 FORMAT_SPEC_P2.md:
    /// [Таблиця LIT] + [Таблиця LEN] + [Таблиця DIST] + [token_count: uint32 BE] + [stream_len: uint32 BE] + [stream].
    /// </summary>
    public static byte[] SerializeCompressedBlock(HuffmanCodeTables tables, uint tokenCount, ReadOnlySpan<byte> stream)
    {
        ArgumentNullException.ThrowIfNull(tables);

        var output = new List<byte>(64 + stream.Length);
        CanonicalHuffman.WriteTable(tables.LitLengths, output);
        CanonicalHuffman.WriteTable(tables.LenLengths, output);
        CanonicalHuffman.WriteTable(tables.DistLengths, output);

        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(header[..4], tokenCount);
        BinaryPrimitives.WriteUInt32BigEndian(header.Slice(4, 4), (uint)stream.Length);

        for (int i = 0; i < 8; i++)
        {
            output.Add(header[i]);
        }

        for (int i = 0; i < stream.Length; i++)
        {
            output.Add(stream[i]);
        }

        return output.ToArray();
    }
}
