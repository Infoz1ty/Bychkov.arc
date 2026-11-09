namespace SmartSecureArchiver.Core.Security;

public interface ICryptoEngine
{
    /// <summary>
    /// Генерує роздільні 32-байтні ключі K_enc та K_mac за 100 000 ітерацій PBKDF2-HMAC-SHA256.
    /// </summary>
    DerivedKeys DeriveKeys(string password, ReadOnlySpan<byte> salt);

    /// <summary>
    /// Шифрує/розшифровує дані за алгоритмом AES-256-CTR з нумерацією блоків лічильника починаючи з 1.
    /// </summary>
    byte[] TransformAesCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce);

    /// <summary>
    /// Обчислює код автентичності HMAC-SHA256 над VolumeHeader + Ciphertext.
    /// </summary>
    byte[] ComputeHmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> macKey);

    /// <summary>
    /// Перевіряє HMAC у постійний час (constant-time). Кидає виняток за невідповідності до розшифрування.
    /// </summary>
    bool VerifyHmacConstantTime(ReadOnlySpan<byte> expectedTag, ReadOnlySpan<byte> actualTag);

    /// <summary>
    /// Обчислює контрольну суму CRC32 для перевірки цілісності вихідного файлу цілком.
    /// </summary>
    uint ComputeCrc32(ReadOnlySpan<byte> data);
}
