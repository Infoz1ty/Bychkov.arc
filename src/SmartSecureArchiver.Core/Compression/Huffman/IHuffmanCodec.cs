namespace SmartSecureArchiver.Core.Compression;

public interface IHuffmanCodec
{
    /// <summary>
    /// Будує канонічні коди за частотами, обмежує глибину до 15 біт і кодує токени в потік MSB-first.
    /// </summary>
    byte[] Encode(IReadOnlyList<Lz77Token> tokens, out HuffmanCodeTables tables);

    /// <summary>
    /// Зчитує бітовий потік за трьома таблицями довжин і відновлює токени LZ77.
    /// </summary>
    IReadOnlyList<Lz77Token> Decode(ReadOnlySpan<byte> bitstream, HuffmanCodeTables tables, int tokenCount);
}
