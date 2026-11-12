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
);
