namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Запис блоку (15 байтів у таблиці блоків + закодовані дані) згідно з розділами 2.3–2.4 FORMAT_SPEC_P2.md.
/// Порядок полів у 15-байтному заголовку:
/// file_index (uint16, 2B) | block_seq (uint32, 4B) | raw_len (uint32, 4B) | coded_len (uint32, 4B) | block_flags (uint8, 1B).
/// Біт 0 у BlockFlags (0x01) означає NO_COMPRESSION (при цьому CodedLength == RawLength).
/// </summary>
public sealed record FileBlock(
    ushort FileIndex,
    uint BlockSeq,
    uint RawLength,
    uint CodedLength,
    byte BlockFlags,
    byte[] Data
)
{
    /// <summary>Фіксований розмір заголовка одного запису в таблиці блоків (15 байтів).</summary>
    public const int HeaderSize = 15;

    /// <summary>Маска біта 0 (NO_COMPRESSION).</summary>
    public const byte NoCompressionFlag = 0x01;

    /// <summary>Маска зарезервованих бітів 1..7 у block_flags (мають дорівнювати 0).</summary>
    public const byte ReservedFlagsMask = 0xFE;

    /// <summary>Чи збережено блок у режимі без стиснення (NO_COMPRESSION = 1).</summary>
    public bool IsNoCompression => (BlockFlags & NoCompressionFlag) != 0;

    /// <summary>Повна вага блоку для задачі про рюкзак 0/1: w = coded_len + 15 байтів.</summary>
    public int KnapsackWeight => checked((int)CodedLength + HeaderSize);
}
