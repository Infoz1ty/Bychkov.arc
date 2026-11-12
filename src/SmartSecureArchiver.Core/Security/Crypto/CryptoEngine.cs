using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Security;

/// <summary>
/// Реалізація криптографічного ядра SARC v1 (Зріз 1: Issues #31–#34):
/// - KDF: PBKDF2-HMAC-SHA256 (100 000 ітерацій, 16B salt -> 32B K_enc + 32B K_mac)
/// - Шифрування: AES-256-CTR (16B блок лічильника = nonce(12B) || uint32_BE(i), i = 1, 2, ...)
/// - Унікальний nonce тому: 8B префікс архіву || uint32_BE(volume_index)
/// - Автентифікація Encrypt-then-MAC: HMAC-SHA256 над [VolumeHeader (41B) || Ciphertext] у постійний час
/// - Контроль цілісності файлів: CRC32 (IEEE 802.3, поліном 0xEDB88320)
/// </summary>
public sealed class CryptoEngine : ICryptoEngine
{
    public const int SaltSize = 16;
    public const int NonceSize = 12;
    public const int NoncePrefixSize = 8;
    public const int KeySize = 32;
    public const int DerivedMaterialSize = 64;
    public const int HmacTagSize = 32;
    public const int VolumeHeaderSize = 41;
    public const int Pbkdf2Iterations = 100_000;
    private const int AesBlockSize = 16;

    private static readonly uint[] Crc32Table = BuildCrc32Table();

    /// <inheritdoc />
    public DerivedKeys DeriveKeys(string password, ReadOnlySpan<byte> salt)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (salt.Length != SaltSize)
        {
            throw new ArgumentException($"Salt must be {SaltSize} bytes.", nameof(salt));
        }

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        Span<byte> derived = stackalloc byte[DerivedMaterialSize];

        try
        {
            Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                derived,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256);

            byte[] encKey = derived[..KeySize].ToArray();
            byte[] macKey = derived.Slice(KeySize, KeySize).ToArray();
            return new DerivedKeys(encKey, macKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    /// <inheritdoc />
    public byte[] TransformAesCtr(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"AES-256 key must be {KeySize} bytes.", nameof(key));
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException($"AES-CTR nonce must be {NonceSize} bytes.", nameof(nonce));
        }

        if (input.IsEmpty)
        {
            return [];
        }

        byte[] output = new byte[input.Length];
        byte[] keyArray = key.ToArray();
        Span<byte> counterBlock = stackalloc byte[AesBlockSize];
        Span<byte> keystreamBlock = stackalloc byte[AesBlockSize];

        nonce.CopyTo(counterBlock[..NonceSize]);

        try
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = keyArray;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            uint blockIndex = 1;
            int offset = 0;

            while (offset < input.Length)
            {
                BinaryPrimitives.WriteUInt32BigEndian(counterBlock.Slice(NonceSize, sizeof(uint)), blockIndex);
                aes.EncryptEcb(counterBlock, keystreamBlock, PaddingMode.None);

                int chunkLength = Math.Min(AesBlockSize, input.Length - offset);
                for (int i = 0; i < chunkLength; i++)
                {
                    output[offset + i] = (byte)(input[offset + i] ^ keystreamBlock[i]);
                }

                offset += chunkLength;
                blockIndex++;
            }

            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyArray);
            CryptographicOperations.ZeroMemory(counterBlock);
            CryptographicOperations.ZeroMemory(keystreamBlock);
        }
    }

    /// <inheritdoc />
    public byte[] ComputeHmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> macKey)
    {
        if (macKey.Length != KeySize)
        {
            throw new ArgumentException($"HMAC key must be {KeySize} bytes.", nameof(macKey));
        }

        return HMACSHA256.HashData(macKey, data);
    }

    /// <inheritdoc />
    public bool VerifyHmacConstantTime(ReadOnlySpan<byte> expectedTag, ReadOnlySpan<byte> actualTag)
    {
        if (expectedTag.Length != HmacTagSize || actualTag.Length != HmacTagSize)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(expectedTag, actualTag);
    }

    /// <inheritdoc />
    public uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        for (int i = 0; i < data.Length; i++)
        {
            byte index = (byte)((crc ^ data[i]) & 0xFF);
            crc = (crc >> 8) ^ Crc32Table[index];
        }

        return ~crc;
    }

    /// <summary>
    /// Генерує криптографічно стійку 16-байтну сіль для сесії архівування (однакова для всіх томів архіву).
    /// </summary>
    public byte[] GenerateSalt()
    {
        byte[] salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }

    /// <summary>
    /// Генерує криптографічно стійкий 8-байтний префікс nonce для архіву (ADR-04, Issue #33).
    /// </summary>
    public byte[] GenerateNoncePrefix()
    {
        byte[] prefix = new byte[NoncePrefixSize];
        RandomNumberGenerator.Fill(prefix);
        return prefix;
    }

    /// <summary>
    /// Формує унікальний 12-байтний nonce для конкретного тому за схемою:
    /// 8B random prefix || uint32_BE(volume_index) (ADR-04, Issue #33).
    /// </summary>
    public byte[] CreateVolumeNonce(ReadOnlySpan<byte> archiveNoncePrefix, uint volumeIndex)
    {
        if (archiveNoncePrefix.Length != NoncePrefixSize)
        {
            throw new ArgumentException($"Nonce prefix must be {NoncePrefixSize} bytes.", nameof(archiveNoncePrefix));
        }

        byte[] nonce = new byte[NonceSize];
        archiveNoncePrefix.CopyTo(nonce.AsSpan(0, NoncePrefixSize));
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(NoncePrefixSize, sizeof(uint)), volumeIndex);
        return nonce;
    }

    /// <summary>
    /// Обчислює 32-байтний тег HMAC-SHA256 над конкатенацією [VolumeHeader (41B) || Ciphertext] (Issue #34).
    /// </summary>
    public byte[] ComputeVolumeHmac(ReadOnlySpan<byte> volumeHeader, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> macKey)
    {
        if (volumeHeader.Length != VolumeHeaderSize)
        {
            throw new ArgumentException($"Volume header must be {VolumeHeaderSize} bytes.", nameof(volumeHeader));
        }

        if (macKey.Length != KeySize)
        {
            throw new ArgumentException($"HMAC key must be {KeySize} bytes.", nameof(macKey));
        }

        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, macKey);
        hmac.AppendData(volumeHeader);
        hmac.AppendData(ciphertext);
        return hmac.GetHashAndReset();
    }

    /// <summary>
    /// Перевіряє тег HMAC-SHA256 у постійний час і кидає SarcException(E_HMAC) при невідповідності (Fail-closed).
    /// </summary>
    public void VerifyHmacOrThrow(ReadOnlySpan<byte> expectedTag, ReadOnlySpan<byte> actualTag)
    {
        if (!VerifyHmacConstantTime(expectedTag, actualTag))
        {
            throw new SarcException(SarcErrorCode.E_HMAC, "HMAC authentication failed: invalid password or corrupted volume.");
        }
    }

    /// <summary>
    /// Виконує повний цикл Encrypt-then-MAC для тому:
    /// 1) шифрує payload за допомогою AES-256-CTR;
    /// 2) обчислює HMAC-SHA256 над [volumeHeader (41B) || ciphertext].
    /// </summary>
    public (byte[] Ciphertext, byte[] HmacTag) EncryptVolumePayload(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> volumeHeader,
        DerivedKeys keys,
        ReadOnlySpan<byte> nonce)
    {
        if (volumeHeader.Length != VolumeHeaderSize)
        {
            throw new ArgumentException($"Volume header must be {VolumeHeaderSize} bytes.", nameof(volumeHeader));
        }

        byte[] ciphertext = TransformAesCtr(payload, keys.EncKey, nonce);
        byte[] hmacTag = ComputeVolumeHmac(volumeHeader, ciphertext, keys.MacKey);
        return (ciphertext, hmacTag);
    }

    /// <summary>
    /// Виконує перевірку автентичності та розшифрування тому за принципом Fail-closed (Issue #34):
    /// 1) обчислює та звіряє HMAC-SHA256 у постійний час СУВОРО ДО початку розшифрування;
    /// 2) у разі незбігу негайно кидає SarcException(E_HMAC);
    /// 3) лише після підтвердження автентичності розшифровує ciphertext через AES-256-CTR.
    /// </summary>
    public byte[] DecryptVolumePayload(
        ReadOnlySpan<byte> volumeHeader,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> expectedTag,
        DerivedKeys keys,
        ReadOnlySpan<byte> nonce)
    {
        byte[] actualTag = ComputeVolumeHmac(volumeHeader, ciphertext, keys.MacKey);
        VerifyHmacOrThrow(expectedTag, actualTag);
        return TransformAesCtr(ciphertext, keys.EncKey, nonce);
    }

    /// <summary>
    /// Перевіряє контрольну суму CRC32 відновленого файлу та кидає SarcException(E_CRC) у разі невідповідності.
    /// </summary>
    public void VerifyCrc32OrThrow(ReadOnlySpan<byte> data, uint expectedCrc32)
    {
        uint actualCrc32 = ComputeCrc32(data);
        if (actualCrc32 != expectedCrc32)
        {
            throw new SarcException(SarcErrorCode.E_CRC, $"CRC32 mismatch: expected 0x{expectedCrc32:X8}, got 0x{actualCrc32:X8}.");
        }
    }

    private static uint[] BuildCrc32Table()
    {
        const uint polynomial = 0xEDB88320u;
        uint[] table = new uint[256];

        for (uint i = 0; i < table.Length; i++)
        {
            uint crc = i;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1u) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
            }

            table[i] = crc;
        }

        return table;
    }
}
