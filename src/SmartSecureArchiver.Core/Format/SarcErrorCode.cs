namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Стандартизовані коди відмови розархіватора згідно з розділом 5 FORMAT_SPEC_P2.md.
/// </summary>
public enum SarcErrorCode
{
    Ok = 0,

    /// <summary>Том коротший за 73 байти (41 + 0 + 32).</summary>
    E_SHORT,

    /// <summary>Невірний magic ("SARC") або version (1).</summary>
    E_MAGIC,

    /// <summary>Фізична довжина тому не дорівнює 41 + ciphertext_len + 32.</summary>
    E_LENGTH,

    /// <summary>HMAC не збігається: зіпсовані дані, зіпсований тег або невірний пароль.</summary>
    E_HMAC,

    /// <summary>Ненульове reserved, невідомі біти flags, file_type > 6, небезпечне ім'я файла, порушений ряд block_seq або неузгоджені довжини секцій.</summary>
    E_PAYLOAD,

    /// <summary>Довжина коду Гаффмана > 15, порушена рівність Крафта, символ поза таблицею, посилання LZ77 за межі буфера або ненульове доповнення.</summary>
    E_CODE,

    /// <summary>CRC32 або розмір склеєного файла не збігається із записаним у таблиці файлів.</summary>
    E_CRC,

    /// <summary>Набір томів неповний, містить дублікати volume_index або томи з різних архівів.</summary>
    E_VOLUMES,

    /// <summary>Таблиця файлів або один блок перевищує доступну місткість тому (помилка конфігурації при пакуванні).</summary>
    E_CAPACITY
}

/// <summary>
/// Контрольований виняток формату SARC із фіксованим кодом відмови.
/// </summary>
public sealed class SarcException : Exception
{
    public SarcErrorCode ErrorCode { get; }

    public SarcException(SarcErrorCode errorCode, string message)
        : base($"{errorCode}: {message}")
    {
        ErrorCode = errorCode;
    }
}
