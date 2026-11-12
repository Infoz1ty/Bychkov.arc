namespace SmartSecureArchiver.Core.Packing;

/// <summary>
/// Блок-кандидат для задачі про рюкзак 0/1 (розділ 7 FORMAT_SPEC_P2.md).
/// Weight = CodedLength + 15 байтів (15 байтів — запис у таблиці блоків).
/// Value визначається пріоритетом типу файлу з team_config.json.
/// </summary>
public sealed record BlockCandidate(
    int BlockId,
    int Weight,
    int Value,
    byte[]? Data = null,
    ushort FileIndex = 0,
    uint BlockSeq = 0,
    uint RawLength = 0,
    byte BlockFlags = 0
);
