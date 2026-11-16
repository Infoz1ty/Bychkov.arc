using System.Text;

namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Безпекова валідація імен файлів згідно з розділом 2.2 FORMAT_SPEC_P2_2.md (Issue #44, Критерій C5 п. 5).
/// Дозволені лише прості імена файлів без шляху.
/// </summary>
public static class FileNameValidator
{
    /// <summary>Максимальна безпечна довжина простого імені файла у байтах UTF-8 (Критерій C2.1).</summary>
    public const int MaxSafeUtf8NameBytes = 255;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Перевіряє, чи є ім'я файла безпечним згідно з розділом 2.2 FORMAT_SPEC_P2_2.md:
    /// відхиляє порожні імена, ".", "..", імена з '/', '\', ':', '\0', абсолютні шляхи та надто довгі імена.
    /// </summary>
    public static bool IsSafeArchiveFileName(string? fileName)
    {
        if (string.IsNullOrEmpty(fileName))
        {
            return false;
        }

        if (fileName is "." or "..")
        {
            return false;
        }

        if (fileName.IndexOfAny(['/', '\\', ':', '\0']) >= 0)
        {
            return false;
        }

        if (Path.IsPathRooted(fileName))
        {
            return false;
        }

        try
        {
            int byteCount = StrictUtf8.GetByteCount(fileName);
            if (byteCount is <= 0 or > MaxSafeUtf8NameBytes)
            {
                return false;
            }
        }
        catch (EncoderFallbackException)
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Валідує ім'я файла та кидає SarcException(E_PAYLOAD) у разі небезпечного або некоректного імені.
    /// </summary>
    public static void ValidateOrThrow(string? fileName)
    {
        if (!IsSafeArchiveFileName(fileName))
        {
            throw new SarcException(
                SarcErrorCode.E_PAYLOAD,
                $"Unsafe or invalid archive file name: '{fileName}'.");
        }
    }
}
