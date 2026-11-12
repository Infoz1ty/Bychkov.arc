namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Запис у таблиці файлів тому згідно з розділом 2.2 FORMAT_SPEC_P2.md.
/// Оригінальний розмір і CRC32 стосуються цілого файла (після склеювання блоків з усіх томів).
/// Ім'я файла — просте ім'я UTF-8 без шляху (без '/', '\', ':', NUL, '.' або '..').
/// </summary>
public sealed record ArchiveFileInfo(
    string FileName,
    uint OriginalSize,
    uint Crc32,
    byte FileType = 0,
    byte Strategy = 0
);
