using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Tests.Security;

public class CryptoEngineTests
{
    private readonly CryptoEngine _crypto = new();

    [Fact]
    public void Crypto_TamperedCiphertextOrHeader_ReturnsE_HMAC()
    {
        byte[] salt = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] prefix = Convert.FromHexString("0102030405060708");
        byte[] nonce = _crypto.CreateVolumeNonce(prefix, volumeIndex: 0);
        DerivedKeys keys = _crypto.DeriveKeys("algo2026", salt);

        byte[] payload = Encoding.UTF8.GetBytes("SARC v1 test payload data");
        byte[] header = new byte[CryptoEngine.VolumeHeaderSize];
        "SARC"u8.CopyTo(header.AsSpan(0, 4));
        header[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(5, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(7, 2), 1);
        salt.CopyTo(header.AsSpan(9, 16));
        nonce.CopyTo(header.AsSpan(25, 12));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(37, 4), (uint)payload.Length);

        (byte[] ciphertext, byte[] tag) = _crypto.EncryptVolumePayload(payload, header, keys, nonce);

        // 1. Зміна 1 байта у шифротексті -> E_HMAC
        byte[] tamperedCiphertext = (byte[])ciphertext.Clone();
        tamperedCiphertext[0] ^= 0x01;
        var exCipher = Assert.Throws<SarcException>(() =>
            _crypto.DecryptVolumePayload(header, tamperedCiphertext, tag, keys, nonce));
        Assert.Equal(SarcErrorCode.E_HMAC, exCipher.ErrorCode);

        // 2. Зміна 1 байта у 41B VolumeHeader -> E_HMAC
        byte[] tamperedHeader = (byte[])header.Clone();
        tamperedHeader[6] ^= 0x01;
        var exHeader = Assert.Throws<SarcException>(() =>
            _crypto.DecryptVolumePayload(tamperedHeader, ciphertext, tag, keys, nonce));
        Assert.Equal(SarcErrorCode.E_HMAC, exHeader.ErrorCode);

        // 3. Зміна 1 байта у тегу HMAC -> E_HMAC
        byte[] tamperedTag = (byte[])tag.Clone();
        tamperedTag[^1] ^= 0x80;
        var exTag = Assert.Throws<SarcException>(() =>
            _crypto.DecryptVolumePayload(header, ciphertext, tamperedTag, keys, nonce));
        Assert.Equal(SarcErrorCode.E_HMAC, exTag.ErrorCode);

        // 4. Невірний пароль -> E_HMAC
        DerivedKeys wrongKeys = _crypto.DeriveKeys("wrong_password", salt);
        var exWrongPass = Assert.Throws<SarcException>(() =>
            _crypto.DecryptVolumePayload(header, ciphertext, tag, wrongKeys, nonce));
        Assert.Equal(SarcErrorCode.E_HMAC, exWrongPass.ErrorCode);
    }

    [Fact]
    public void Crypto_TamperedCiphertext_ThrowsHmacException()
    {
        Crypto_TamperedCiphertextOrHeader_ReturnsE_HMAC();
    }

    [Fact]
    public void DeriveKeys_ProducesDeterministicDistinct32ByteKeys()
    {
        byte[] salt = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

        DerivedKeys keys1 = _crypto.DeriveKeys("algo2026", salt);
        DerivedKeys keys2 = _crypto.DeriveKeys("algo2026", salt);

        Assert.Equal(32, keys1.EncKey.Length);
        Assert.Equal(32, keys1.MacKey.Length);
        Assert.Equal(keys1.EncKey, keys2.EncKey);
        Assert.Equal(keys1.MacKey, keys2.MacKey);
        Assert.NotEqual(keys1.EncKey, keys1.MacKey);
    }

    [Fact]
    public void TransformAesCtr_CounterStartsAtOneAndRoundTripsUnalignedData()
    {
        byte[] key = new byte[32];
        byte[] nonce = Convert.FromHexString("010203040506070800000000");

        // Перевірка, що блок лічильника починається строго з i = 1: nonce(12B) || uint32_BE(1)
        byte[] zeros16 = new byte[16];
        byte[] actualFirstKeystream = _crypto.TransformAesCtr(zeros16, key, nonce);

        byte[] expectedCounterBlock1 = new byte[16];
        nonce.CopyTo(expectedCounterBlock1.AsSpan(0, 12));
        BinaryPrimitives.WriteUInt32BigEndian(expectedCounterBlock1.AsSpan(12, 4), 1u);

        using var aes = Aes.Create();
        aes.Key = key;
        byte[] expectedFirstKeystream = aes.EncryptEcb(expectedCounterBlock1, PaddingMode.None);
        Assert.Equal(expectedFirstKeystream, actualFirstKeystream);

        // Перевірка round-trip на некратній довжині (73 байти)
        byte[] original = Encoding.UTF8.GetBytes("Test message of non-multiple-of-16 length for AES-256-CTR stream cipher!!");
        byte[] encrypted = _crypto.TransformAesCtr(original, key, nonce);
        Assert.NotEqual(original, encrypted);

        byte[] decrypted = _crypto.TransformAesCtr(encrypted, key, nonce);
        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void CreateVolumeNonce_GeneratesUniqueNoncesMatchingSpecFormat()
    {
        byte[] prefix = Convert.FromHexString("0102030405060708");

        byte[] nonce0 = _crypto.CreateVolumeNonce(prefix, 0);
        byte[] nonce1 = _crypto.CreateVolumeNonce(prefix, 1);
        byte[] nonce2 = _crypto.CreateVolumeNonce(prefix, 2);

        Assert.Equal("010203040506070800000000", Convert.ToHexString(nonce0));
        Assert.Equal("010203040506070800000001", Convert.ToHexString(nonce1));
        Assert.Equal("010203040506070800000002", Convert.ToHexString(nonce2));
    }

    [Fact]
    public void ComputeCrc32_MatchesStandardIeee8023Vectors()
    {
        Assert.Equal(0x00000000u, _crypto.ComputeCrc32([]));
        Assert.Equal(0xCBF43926u, _crypto.ComputeCrc32("123456789"u8));

        var ex = Assert.Throws<SarcException>(() => _crypto.VerifyCrc32OrThrow("123456789"u8, 0xDEADBEEFu));
        Assert.Equal(SarcErrorCode.E_CRC, ex.ErrorCode);
    }

    [Theory]
    [InlineData("ref_01_single_file.arc")]
    [InlineData("ref_02_empty_file.arc")]
    [InlineData("ref_03_degenerate.arc")]
    [InlineData("ref_04_seven_groups.arc")]
    [InlineData("ref_05_no_compression.arc")]
    [InlineData("ref_06_two_volumes.part0.arc")]
    [InlineData("ref_06_two_volumes.part1.arc")]
    [InlineData("ref_06_two_volumes.part2.arc")]
    public void ReferenceArchives_PassHmacAndDecryptValidPayloadHeader(string archiveFileName)
    {
        string path = FindRepoFile(Path.Combine("team", "reference", archiveFileName));
        byte[] volumeBytes = File.ReadAllBytes(path);

        ReadOnlySpan<byte> header = volumeBytes.AsSpan(0, CryptoEngine.VolumeHeaderSize);
        ReadOnlySpan<byte> salt = header.Slice(9, CryptoEngine.SaltSize);
        ReadOnlySpan<byte> nonce = header.Slice(25, CryptoEngine.NonceSize);
        uint ciphertextLen = BinaryPrimitives.ReadUInt32BigEndian(header.Slice(37, 4));

        Assert.Equal(CryptoEngine.VolumeHeaderSize + (int)ciphertextLen + CryptoEngine.HmacTagSize, volumeBytes.Length);

        ReadOnlySpan<byte> ciphertext = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize, (int)ciphertextLen);
        ReadOnlySpan<byte> expectedTag = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize + (int)ciphertextLen, CryptoEngine.HmacTagSize);

        DerivedKeys keys = _crypto.DeriveKeys("algo2026", salt);
        byte[] payload = _crypto.DecryptVolumePayload(header, ciphertext, expectedTag, keys, nonce);

        // У розшифрованому Payload перші 4 байти: file_count (uint16_BE) >= 1, flags == 0, reserved == 0
        ushort fileCount = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(0, 2));
        byte flags = payload[2];
        byte reserved = payload[3];

        Assert.True(fileCount >= 1);
        Assert.Equal(0, flags);
        Assert.Equal(0, reserved);
    }

    [Fact]
    public void ReferenceArchive_NoCompression_DecryptsAndMatchesExactFileCrc32()
    {
        string path = FindRepoFile(Path.Combine("team", "reference", "ref_05_no_compression.arc"));
        byte[] volumeBytes = File.ReadAllBytes(path);

        ReadOnlySpan<byte> header = volumeBytes.AsSpan(0, CryptoEngine.VolumeHeaderSize);
        ReadOnlySpan<byte> salt = header.Slice(9, CryptoEngine.SaltSize);
        ReadOnlySpan<byte> nonce = header.Slice(25, CryptoEngine.NonceSize);
        uint ciphertextLen = BinaryPrimitives.ReadUInt32BigEndian(header.Slice(37, 4));
        ReadOnlySpan<byte> ciphertext = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize, (int)ciphertextLen);
        ReadOnlySpan<byte> tag = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize + (int)ciphertextLen, CryptoEngine.HmacTagSize);

        DerivedKeys keys = _crypto.DeriveKeys("algo2026", salt);
        byte[] payload = _crypto.DecryptVolumePayload(header, ciphertext, tag, keys, nonce);

        // Останні 12000 байтів payload — сирі дані файлу packed.z (CRC32 = 0x369BB1DD за ref_05_no_compression.json)
        ReadOnlySpan<byte> rawFileBytes = payload.AsSpan(payload.Length - 12000, 12000);
        uint crc32 = _crypto.ComputeCrc32(rawFileBytes);
        Assert.Equal(0x369BB1DDu, crc32);
    }

    [Theory]
    [InlineData("bad_01_tampered_byte.arc")]
    [InlineData("bad_02_tampered_tag.arc")]
    public void ReferenceBadArchives_TamperedByteOrTag_ThrowsE_HMAC(string badFileName)
    {
        string path = FindRepoFile(Path.Combine("team", "reference", badFileName));
        byte[] volumeBytes = File.ReadAllBytes(path);

        byte[] header = volumeBytes[..CryptoEngine.VolumeHeaderSize];
        byte[] salt = header[9..(9 + CryptoEngine.SaltSize)];
        byte[] nonce = header[25..(25 + CryptoEngine.NonceSize)];
        uint ciphertextLen = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(37, 4));
        byte[] ciphertext = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize, (int)ciphertextLen).ToArray();
        byte[] tag = volumeBytes.AsSpan(CryptoEngine.VolumeHeaderSize + (int)ciphertextLen, CryptoEngine.HmacTagSize).ToArray();

        DerivedKeys keys = _crypto.DeriveKeys("algo2026", salt);
        var ex = Assert.Throws<SarcException>(() =>
            _crypto.DecryptVolumePayload(header, ciphertext, tag, keys, nonce));

        Assert.Equal(SarcErrorCode.E_HMAC, ex.ErrorCode);
    }

    private static string FindRepoFile(string relativePath)
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException($"Could not locate '{relativePath}' in repository tree.");
    }
}
