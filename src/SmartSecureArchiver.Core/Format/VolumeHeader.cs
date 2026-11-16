namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Відкритий 41-байтний заголовок тому SARC v1 згідно з розділом 1.1 FORMAT_SPEC_P2_2.md:
/// [0..3]   magic          = ASCII "SARC" (53 41 52 43)
/// [4]      version        = 1 (uint8)
/// [5..6]   volume_index   = номер тому від 0 (uint16_BE)
/// [7..8]   volume_count   = загальна кількість томів (uint16_BE)
/// [9..24]  salt           = сіль KDF, 16 байтів (однакова для всіх томів архіву)
/// [25..36] nonce          = nonce CTR, 12 байтів (різний для кожного тому)
/// [37..40] ciphertext_len = довжина шифротексту (uint32_BE)
/// </summary>
public sealed record VolumeHeader(
    ushort VolumeIndex,
    ushort VolumeCount,
    byte[] Salt,
    byte[] Nonce,
    uint CiphertextLength
)
{
    /// <summary>Фіксований розмір відкритого заголовка тому (41 байт).</summary>
    public const int Size = 41;

    /// <summary>Фіксований розмір тегу HMAC-SHA256 у кінці тому (32 байти).</summary>
    public const int HmacSize = 32;

    /// <summary>Мінімальна припустима довжина файлу тому: 41 + 0 + 32 = 73 байти.</summary>
    public const int MinVolumeSize = Size + HmacSize;

    /// <summary>Підтримувана версія специфікації SARC.</summary>
    public const byte CurrentVersion = 1;

    /// <summary>Розмір солі PBKDF2 у байтах.</summary>
    public const int SaltSize = 16;

    /// <summary>Розмір nonce AES-256-CTR у байтах.</summary>
    public const int NonceSize = 12;

    /// <summary>Розмір одного запису в таблиці блоків (15 байтів).</summary>
    public const int BlockEntrySize = 15;

    /// <summary>
    /// Фіксовані накладні витрати Payload без таблиць:
    /// file_count (2B) + flags (1B) + reserved (1B) + block_count (2B) = 6 байтів.
    /// </summary>
    public const int PayloadFixedOverhead = 6;

    /// <summary>Магічні байти формату "SARC" (0x53, 0x41, 0x52, 0x43).</summary>
    public static ReadOnlySpan<byte> MagicBytes => "SARC"u8;

    /// <summary>Очікувана повна фізична довжина файлу тому в байтах.</summary>
    public long ExpectedTotalVolumeLength => (long)Size + CiphertextLength + HmacSize;
}
