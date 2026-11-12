namespace SmartSecureArchiver.Core.Compression;

public interface IBlockCompressor
{
    /// <summary>
    /// Стискає блок даних (LZ77 + канонічний Гаффман за розділом 3 FORMAT_SPEC_P2.md) або зберігає сирі байти.
    /// Якщо allowCompression == false або стиснутий блок не коротший за сирий (coded_len >= raw_len),
    /// автоматично встановлює blockFlags = 0x01 (NO_COMPRESSION) і повертає сирі байти блоку.
    /// </summary>
    byte[] Compress(
        ReadOnlySpan<byte> blockData,
        out byte blockFlags,
        bool allowCompression = true,
        int windowSize = 32768,
        int minMatchLength = 3,
        bool useLazyMatching = false);

    /// <summary>
    /// Декодує блок даних. Якщо (blockFlags &amp; 0x01) != 0, повертає сирі байти.
    /// Інакше читає таблиці LIT, LEN, DIST, token_count, stream_len і декодує потік.
    /// При порушенні формату кодування або меж буфера кидає SarcException(E_CODE).
    /// </summary>
    byte[] Decompress(ReadOnlySpan<byte> codedData, byte blockFlags, int expectedRawLength);
}
