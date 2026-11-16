using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Security.Attack;

/// <summary>
/// Результат однієї спроби модифікації байтів архіву SARC v1 (Issue #38, п. 3.7 п. 3 ТЗ).
/// </summary>
public sealed record TamperProbeResult(
    string AttackName,
    SarcErrorCode ExpectedCode,
    SarcErrorCode ActualCode,
    bool RejectedCleanly,
    bool OutputDirectoryUntouched
);

/// <summary>
/// Скрипт/інструмент модифікації байтів для перевірки цілісності чужого або власного архіву SARC v1
/// (Issue #38): змінює байти в заголовку, шифротексті, тегу HMAC або обрізає файл та підтверджує
/// контрольовану відмову Fail-closed (E_HMAC / E_LENGTH / E_SHORT / E_MAGIC) без запису на диск.
/// </summary>
public static class ArchiveTamperTool
{
    public static byte[] FlipByteInVolumeHeader(ReadOnlySpan<byte> archiveBytes, int headerOffset = 25, byte mask = 0x01)
    {
        if (archiveBytes.Length < VolumeHeader.MinVolumeSize)
        {
            throw new ArgumentException("Archive is shorter than minimum SARC v1 volume size.", nameof(archiveBytes));
        }

        if ((uint)headerOffset >= VolumeHeader.Size)
        {
            throw new ArgumentOutOfRangeException(nameof(headerOffset));
        }

        byte[] tampered = archiveBytes.ToArray();
        tampered[headerOffset] ^= mask;
        return tampered;
    }

    public static byte[] FlipByteInCiphertext(ReadOnlySpan<byte> archiveBytes, int ciphertextOffset = 0, byte mask = 0x01)
    {
        if (archiveBytes.Length <= VolumeHeader.MinVolumeSize)
        {
            throw new ArgumentException("Archive ciphertext is empty.", nameof(archiveBytes));
        }

        int ciphertextLen = archiveBytes.Length - VolumeHeader.Size - VolumeHeader.HmacSize;
        if ((uint)ciphertextOffset >= (uint)ciphertextLen)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertextOffset));
        }

        byte[] tampered = archiveBytes.ToArray();
        tampered[VolumeHeader.Size + ciphertextOffset] ^= mask;
        return tampered;
    }

    public static byte[] FlipByteInHmacTag(ReadOnlySpan<byte> archiveBytes, int tagOffset = 0, byte mask = 0x01)
    {
        if (archiveBytes.Length < VolumeHeader.MinVolumeSize)
        {
            throw new ArgumentException("Archive is shorter than minimum SARC v1 volume size.", nameof(archiveBytes));
        }

        if ((uint)tagOffset >= VolumeHeader.HmacSize)
        {
            throw new ArgumentOutOfRangeException(nameof(tagOffset));
        }

        byte[] tampered = archiveBytes.ToArray();
        tampered[archiveBytes.Length - VolumeHeader.HmacSize + tagOffset] ^= mask;
        return tampered;
    }

    public static byte[] TruncateArchive(ReadOnlySpan<byte> archiveBytes, int bytesToRemove)
    {
        if (bytesToRemove <= 0 || bytesToRemove >= archiveBytes.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(bytesToRemove));
        }

        return archiveBytes[..^bytesToRemove].ToArray();
    }

    public static byte[] CorruptMagic(ReadOnlySpan<byte> archiveBytes)
    {
        if (archiveBytes.Length < VolumeHeader.MinVolumeSize)
        {
            throw new ArgumentException("Archive is shorter than minimum SARC v1 volume size.", nameof(archiveBytes));
        }

        byte[] tampered = archiveBytes.ToArray();
        tampered[0] = (byte)'X';
        return tampered;
    }

    /// <summary>
    /// Запускає серію модифікацій над копією цільового .arc файлу (оригінальний файл не змінюється!)
    /// і перевіряє, що розархіватор відхиляє кожну підробку з очікуваним кодом відмови.
    /// </summary>
    public static IReadOnlyList<TamperProbeResult> RunTamperAudit(
        string sourceArchivePath,
        string password,
        IArchiveOrchestrator? orchestrator = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceArchivePath);
        ArgumentNullException.ThrowIfNull(password);

        if (!File.Exists(sourceArchivePath))
        {
            throw new FileNotFoundException($"Archive file not found: '{sourceArchivePath}'.", sourceArchivePath);
        }

        IArchiveOrchestrator runner = orchestrator ?? ArchiveOrchestratorFactory.CreateDefault();
        byte[] originalBytes = File.ReadAllBytes(sourceArchivePath);

        var probes = new List<(string Name, SarcErrorCode Expected, byte[] Bytes)>
        {
            ("Flip byte in VolumeHeader nonce (offset 25)", SarcErrorCode.E_HMAC, FlipByteInVolumeHeader(originalBytes, headerOffset: 25)),
            ("Flip byte in Ciphertext (offset 0)", SarcErrorCode.E_HMAC, FlipByteInCiphertext(originalBytes, ciphertextOffset: 0)),
            ("Flip byte in HMAC-SHA256 tag (last byte)", SarcErrorCode.E_HMAC, FlipByteInHmacTag(originalBytes, tagOffset: VolumeHeader.HmacSize - 1)),
            ("Truncate archive by 5 bytes", SarcErrorCode.E_LENGTH, TruncateArchive(originalBytes, bytesToRemove: 5)),
            ("Truncate archive below 73 bytes", SarcErrorCode.E_SHORT, TruncateArchive(originalBytes, bytesToRemove: originalBytes.Length - 40)),
            ("Corrupt MAGIC header", SarcErrorCode.E_MAGIC, CorruptMagic(originalBytes))
        };

        string tempDir = Path.Combine(Path.GetTempPath(), $"sarc_tamper_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var results = new List<TamperProbeResult>(probes.Count);

        try
        {
            for (int i = 0; i < probes.Count; i++)
            {
                (string name, SarcErrorCode expected, byte[] bytes) = probes[i];
                string tamperedArcPath = Path.Combine(tempDir, $"tampered_{i}.arc");
                string extractOutDir = Path.Combine(tempDir, $"out_{i}");
                Directory.CreateDirectory(extractOutDir);

                File.WriteAllBytes(tamperedArcPath, bytes);

                SarcErrorCode actualCode = SarcErrorCode.Ok;
                try
                {
                    runner.ExtractArchive(tamperedArcPath, extractOutDir, password);
                }
                catch (SarcException ex)
                {
                    actualCode = ex.ErrorCode;
                }

                bool untouched = Directory.GetFiles(extractOutDir, "*", SearchOption.AllDirectories).Length == 0;
                results.Add(new TamperProbeResult(
                    AttackName: name,
                    ExpectedCode: expected,
                    ActualCode: actualCode,
                    RejectedCleanly: actualCode == expected,
                    OutputDirectoryUntouched: untouched));
            }

            return results;
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try
                {
                    Directory.Delete(tempDir, recursive: true);
                }
                catch
                {
                    // Ігноруємо помилки прибирання тимчасової теки
                }
            }
        }
    }
}
