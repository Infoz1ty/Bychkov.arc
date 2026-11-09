namespace SmartSecureArchiver.Core.Format;

public interface ISarcFormatHandler
{
    /// <summary>
    /// Збирає та серіалізує незашифрований Payload (таблиця файлів + блоки) у бінарний потік.
    /// </summary>
    byte[] BuildPayload(IReadOnlyList<ArchiveFileInfo> files, IReadOnlyList<FileBlock> blocks);

    /// <summary>
    /// Парсить розшифрований Payload і перевіряє шляхи файлів на вразливість Path Traversal.
    /// </summary>
    void ParsePayload(ReadOnlySpan<byte> payload, out List<ArchiveFileInfo> files, out List<FileBlock> blocks);

    /// <summary>
    /// Записує 41-байтний заголовок тому у форматі Big-Endian через BinaryPrimitives.
    /// </summary>
    void WriteVolumeHeader(Span<byte> destination, ushort volumeIndex, ushort volumeCount, 
                           ReadOnlySpan<byte> salt, ReadOnlySpan<byte> nonce, uint ciphertextLen);

    /// <summary>
    /// Валідує та парсить 41-байтний заголовок тому.
    /// </summary>
    bool TryParseVolumeHeader(ReadOnlySpan<byte> source, out ushort volumeIndex, out ushort volumeCount, 
                             out byte[] salt, out byte[] nonce, out uint ciphertextLen);
}
