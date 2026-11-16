using System.Text;

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
)
{
    /// <summary>
    /// Фіксована частина запису таблиці файлів без байтів імені:
    /// name_len (2B) + orig_size (4B) + crc32 (4B) + file_type (1B) + strategy (1B) = 12 байтів.
    /// </summary>
    public const int FixedFieldsSize = 12;

    /// <summary>Максимальне допустиме значення поля file_type (0..6).</summary>
    public const byte MaxFileType = 6;

    /// <summary>Обчислює точний розмір запису в байтах при серіалізації в таблицю файлів тому.</summary>
    public int GetSerializedSize() => FixedFieldsSize + Encoding.UTF8.GetByteCount(FileName ?? string.Empty);
}
