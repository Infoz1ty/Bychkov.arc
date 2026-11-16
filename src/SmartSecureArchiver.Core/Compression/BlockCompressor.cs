using System.Buffers.Binary;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Реалізація компресора та декомпресора блоків SARC v1 (Issue #43, розділ 3 FORMAT_SPEC_P2_2.md).
/// Підтримує базовий режим NO_COMPRESSION (Зріз 1) та повний конвеєр LZ77 + Канонічний Гаффман,
/// коли передані реалізації ILz77Parser та IHuffmanCodec.
/// </summary>
public sealed class BlockCompressor : IBlockCompressor
{
    public const int MaxLitSymbol = 256;
    public const int MaxLenSymbol = 255;
    public const int MaxDistSymbol = 15;
    public const int MaxCodeLength = 15;
    private const int KraftTargetSum = 1 << MaxCodeLength; // 32768

    private readonly ILz77Parser? _lz77Parser;
    private readonly IHuffmanCodec? _huffmanCodec;

    public BlockCompressor(ILz77Parser? lz77Parser = null, IHuffmanCodec? huffmanCodec = null)
    {
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
        // Порожні блоки, вимкнене стиснення або відсутність підключених кодеків -> NO_COMPRESSION
        if (!allowCompression || blockData.IsEmpty || _lz77Parser is null || _huffmanCodec is null)
        {
            blockFlags = FileBlock.NoCompressionFlag;
            return blockData.ToArray();
        }

        IReadOnlyList<Lz77Token> tokens = _lz77Parser.Parse(blockData, windowSize);
        byte[] bitStream = _huffmanCodec.Encode(tokens, out HuffmanCodeTables tables);
        byte[] serializedCompressed = SerializeCompressedBlock(tables, (uint)tokens.Count, bitStream);

        // Якщо стиснутий блок не коротший за сирий (coded_len >= raw_len) -> NO_COMPRESSION (п. 2.4 FORMAT_SPEC_P2_2.md)
        if (serializedCompressed.Length >= blockData.Length)
        {
            blockFlags = FileBlock.NoCompressionFlag;
            return blockData.ToArray();
        }

        blockFlags = 0x00;
        return serializedCompressed;
    }

    /// <inheritdoc />
    public byte[] Decompress(ReadOnlySpan<byte> codedData, byte blockFlags, int expectedRawLength)
    {
        if (expectedRawLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedRawLength));
        }

        if ((blockFlags & FileBlock.ReservedFlagsMask) != 0)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Invalid reserved bits in block_flags: 0x{blockFlags:X2}.");
        }

        // Режим NO_COMPRESSION (біт 0 = 1)
        if ((blockFlags & FileBlock.NoCompressionFlag) != 0)
        {
            if (codedData.Length != expectedRawLength)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"NO_COMPRESSION block length ({codedData.Length}) does not match raw_len ({expectedRawLength}).");
            }

            return codedData.ToArray();
        }

        // Режим зі стисненням (біт 0 = 0): розбір 3 таблиць (LIT, LEN, DIST), token_count, stream_len, stream
        int offset = 0;
        byte[] litLengths = ReadAndValidateCodeTable(codedData, ref offset, MaxLitSymbol, "LIT");
        byte[] lenLengths = ReadAndValidateCodeTable(codedData, ref offset, MaxLenSymbol, "LEN");
        byte[] distLengths = ReadAndValidateCodeTable(codedData, ref offset, MaxDistSymbol, "DIST");

        if (codedData.Length - offset < 8)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Compressed block is truncated before token_count and stream_len.");
        }

        uint tokenCount = BinaryPrimitives.ReadUInt32BigEndian(codedData.Slice(offset, 4));
        uint streamLen = BinaryPrimitives.ReadUInt32BigEndian(codedData.Slice(offset + 4, 4));
        offset += 8;

        // Розархіватор зупиняється, прочитавши рівно token_count елементів. Байти після потоку неприпустимі (п. 3.1)
        if (codedData.Length - offset != streamLen)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                $"Compressed block stream_len ({streamLen}) does not match remaining bytes ({codedData.Length - offset}).");
        }

        if (expectedRawLength == 0 && tokenCount == 0 && streamLen == 0)
        {
            return [];
        }

        if (_huffmanCodec is null || _lz77Parser is null)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                "Compressed block encountered, but Huffman/LZ77 decoders are not configured.");
        }

        var tables = new HuffmanCodeTables(litLengths, lenLengths, distLengths);
        ReadOnlySpan<byte> bitstream = codedData.Slice(offset, (int)streamLen);

        IReadOnlyList<Lz77Token> tokens = _huffmanCodec.Decode(bitstream, tables, checked((int)tokenCount));
        byte[] rawBytes = _lz77Parser.Decompress(tokens, expectedRawLength);

        if (rawBytes.Length != expectedRawLength)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                $"Decompressed block size ({rawBytes.Length}) does not match expected raw_len ({expectedRawLength}).");
        }

        return rawBytes;
    }

    /// <summary>
    /// Серіалізує стиснутий блок згідно з п. 3.1 та п. 3.3 FORMAT_SPEC_P2_2.md:
    /// таблиця LIT -> таблиця LEN -> таблиця DIST -> token_count (uint32_BE) -> stream_len (uint32_BE) -> stream.
    /// </summary>
    public static byte[] SerializeCompressedBlock(HuffmanCodeTables tables, uint tokenCount, ReadOnlySpan<byte> bitStream)
    {
        ArgumentNullException.ThrowIfNull(tables);

        int litSymCount = CountNonZeroAndValidateTable(tables.LitLengths, MaxLitSymbol, "LIT");
        int lenSymCount = CountNonZeroAndValidateTable(tables.LenLengths, MaxLenSymbol, "LEN");
        int distSymCount = CountNonZeroAndValidateTable(tables.DistLengths, MaxDistSymbol, "DIST");

        int totalSize =
            (2 + litSymCount * 3) +
            (2 + lenSymCount * 3) +
            (2 + distSymCount * 3) +
            4 + 4 + bitStream.Length;

        byte[] buffer = new byte[totalSize];
        Span<byte> span = buffer.AsSpan();
        int offset = 0;

        WriteCodeTable(span, ref offset, tables.LitLengths, (ushort)litSymCount);
        WriteCodeTable(span, ref offset, tables.LenLengths, (ushort)lenSymCount);
        WriteCodeTable(span, ref offset, tables.DistLengths, (ushort)distSymCount);

        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), tokenCount);
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset + 4, 4), (uint)bitStream.Length);
        offset += 8;

        bitStream.CopyTo(span.Slice(offset, bitStream.Length));
        return buffer;
    }

    /// <summary>
    /// Зчитує та валідує одну таблицю кодів Гаффмана (п. 3.2–3.3 FORMAT_SPEC_P2_2.md, ADR-03).
    /// Перевіряє межі алфавіту, зростання символів, довжину 1..15, вироджений випадок (nsym == 1) та рівність Крафта.
    /// </summary>
    public static byte[] ReadAndValidateCodeTable(ReadOnlySpan<byte> buffer, ref int offset, int maxSymbol, string tableName)
    {
        if (buffer.Length - offset < 2)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Truncated {tableName} Huffman table header.");
        }

        ushort nsym = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset, 2));
        offset += 2;

        if (nsym > maxSymbol + 1)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                $"Table {tableName} has too many symbols ({nsym} > {maxSymbol + 1}).");
        }

        long tableBytes = (long)nsym * 3;
        if (buffer.Length - offset < tableBytes)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Truncated {tableName} Huffman table entries.");
        }

        byte[] lengths = new byte[maxSymbol + 1];
        int prevSymbol = -1;
        int kraftSum = 0;

        for (int i = 0; i < nsym; i++)
        {
            ushort symbol = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset, 2));
            byte length = buffer[offset + 2];
            offset += 3;

            if (symbol > maxSymbol)
            {
                throw new SarcException(
                    SarcErrorCode.E_CODE,
                    $"Symbol {symbol} in {tableName} exceeds maximum allowed symbol {maxSymbol}.");
            }

            if (symbol <= prevSymbol)
            {
                throw new SarcException(
                    SarcErrorCode.E_CODE,
                    $"Symbols in {tableName} table are not in strictly ascending order ({symbol} after {prevSymbol}).");
            }

            if (length is 0 or > MaxCodeLength)
            {
                throw new SarcException(
                    SarcErrorCode.E_CODE,
                    $"Invalid Huffman code length {length} for symbol {symbol} in {tableName} (must be 1..{MaxCodeLength}).");
            }

            lengths[symbol] = length;
            prevSymbol = symbol;
            kraftSum += 1 << (MaxCodeLength - length);
        }

        // Перевірка повноти коду за розділом 3.3 FORMAT_SPEC_P2_2.md та ADR-03:
        // - При nsym == 1 довжина єдиного символу має дорівнювати 1 (kraftSum == 16384)
        // - При nsym > 1 сума Σ 2^(15 - L_i) має точно дорівнювати 32768 (Σ 2^(-L_i) == 1)
        if (nsym == 1)
        {
            if (kraftSum != (1 << (MaxCodeLength - 1)))
            {
                throw new SarcException(
                    SarcErrorCode.E_CODE,
                    $"Degenerate single-symbol table {tableName} must have code length 1.");
            }
        }
        else if (nsym > 1)
        {
            if (kraftSum != KraftTargetSum)
            {
                throw new SarcException(
                    SarcErrorCode.E_CODE,
                    $"Kraft equality violated in {tableName} table (sum = {kraftSum}, expected {KraftTargetSum}).");
            }
        }

        return lengths;
    }

    private static int CountNonZeroAndValidateTable(byte[] lengths, int maxSymbol, string tableName)
    {
        if (lengths is null || lengths.Length != maxSymbol + 1)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                $"Table {tableName} lengths array must have size {maxSymbol + 1}.");
        }

        int count = 0;
        int kraftSum = 0;

        for (int s = 0; s <= maxSymbol; s++)
        {
            byte len = lengths[s];
            if (len == 0)
            {
                continue;
            }

            if (len > MaxCodeLength)
            {
                throw new SarcException(
                    SarcErrorCode.E_CODE,
                    $"Symbol {s} in {tableName} has code length {len} > {MaxCodeLength}.");
            }

            count++;
            kraftSum += 1 << (MaxCodeLength - len);
        }

        if (count == 1 && kraftSum != (1 << (MaxCodeLength - 1)))
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Single symbol in {tableName} must have length 1.");
        }

        if (count > 1 && kraftSum != KraftTargetSum)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Kraft equality violated in {tableName} when serializing.");
        }

        return count;
    }

    private static void WriteCodeTable(Span<byte> destination, ref int offset, byte[] lengths, ushort nsym)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), nsym);
        offset += 2;

        for (ushort symbol = 0; symbol < lengths.Length; symbol++)
        {
            byte len = lengths[symbol];
            if (len > 0)
            {
                BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(offset, 2), symbol);
                destination[offset + 2] = len;
                offset += 3;
            }
        }
    }
}
