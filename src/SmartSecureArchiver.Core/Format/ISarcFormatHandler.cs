namespace SmartSecureArchiver.Core.Format;

public interface ISarcFormatHandler
{
    /// <summary>
    /// Збирає та серіалізує незашифрований Payload тому за розділом 2 FORMAT_SPEC_P2.md:
    /// file_count (uint16) -> flags (uint8) -> reserved=0 (uint8) -> таблиця файлів ->
    /// block_count (uint16) -> таблиця блоків (15B * block_count) -> дані блоків.
    /// </summary>
    byte[] BuildPayload(IReadOnlyList<ArchiveFileInfo> files, IReadOnlyList<FileBlock> blocks, byte flags = 0);

    /// <summary>
    /// Парсить розшифрований Payload, перевіряє reserved == 0, flags, file_type &lt;= 6,
    /// безпечність імен файлів (Path Traversal) та узгодженість довжин секцій.
    /// У разі порушення кидає SarcException(E_PAYLOAD).
    /// </summary>
    void ParsePayload(ReadOnlySpan<byte> payload, out List<ArchiveFileInfo> files, out List<FileBlock> blocks, out byte flags);

    /// <summary>
    /// Записує 41-байтний заголовок тому у форматі Big-Endian через BinaryPrimitives (розділ 1.1 FORMAT_SPEC_P2.md).
    /// </summary>
    void WriteVolumeHeader(Span<byte> destination, ushort volumeIndex, ushort volumeCount,
                           ReadOnlySpan<byte> salt, ReadOnlySpan<byte> nonce, uint ciphertextLen);

    /// <summary>
    /// Валідує та парсить 41-байтний відкритий заголовок тому до розшифрування (кроки 1–3 розділу 4.3 FORMAT_SPEC_P2.md).
    /// Повертає SarcErrorCode.Ok або код відмови (E_SHORT, E_MAGIC, E_LENGTH).
    /// </summary>
    SarcErrorCode TryParseVolumeHeader(ReadOnlySpan<byte> volumeBytes, out ushort volumeIndex, out ushort volumeCount,
                                       out byte[] salt, out byte[] nonce, out uint ciphertextLen);
}
