using System.Diagnostics;
using System.Globalization;
using System.Text;
using SmartSecureArchiver.Core.Analysis;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Security;

/// <summary>
/// Результат порівняння порядку операцій для одного файлу (Issue #37, Таблиця №4 звіту).
/// </summary>
public sealed record CompressionOrderFileResult(
    string FileName,
    byte FileType,
    long OriginalBytes,
    long CompressThenEncryptBytes,
    double CompressThenEncryptRatio,
    double CompressThenEncryptMs,
    long EncryptThenCompressBytes,
    double EncryptThenCompressRatio,
    double EncryptThenCompressMs,
    bool RoundTripVerified
);

/// <summary>
/// Зведений результат експерименту «Стиснути перед шифруванням» vs «Зашифрувати перед стисненням».
/// </summary>
public sealed record CompressionOrderReport(
    long TotalOriginalBytes,
    long TotalCompressThenEncryptBytes,
    double TotalCompressThenEncryptRatio,
    double TotalCompressThenEncryptMs,
    long TotalEncryptThenCompressBytes,
    double TotalEncryptThenCompressRatio,
    double TotalEncryptThenCompressMs,
    IReadOnlyList<CompressionOrderFileResult> Files
);

/// <summary>
/// Експеримент п. 3.5 ТЗ (Issue #37, Таблиця №4 звіту):
/// доводить, що шифрування перед стисненням знищує статистичну надлишковість
/// (ентропія шифротексту AES-256-CTR ~8 біт/байт) і унеможливлює стиснення (коефіцієнт ~1.00x).
/// </summary>
public sealed class CompressionOrderExperiment
{
    private readonly CryptoEngine _cryptoEngine;
    private readonly IBlockCompressor _blockCompressor;
    private readonly IFeatureExtractor _featureExtractor;
    private readonly IFileClassifier _fileClassifier;
    private readonly int _blockSize;

    public CompressionOrderExperiment(
        CryptoEngine? cryptoEngine = null,
        IBlockCompressor? blockCompressor = null,
        IFeatureExtractor? featureExtractor = null,
        IFileClassifier? fileClassifier = null,
        int blockSize = ArchiveOrchestrator.DefaultBlockSize)
    {
        if (blockSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be positive.");
        }

        _cryptoEngine = cryptoEngine ?? new CryptoEngine();
        _blockCompressor = blockCompressor ?? new BlockCompressor();
        _featureExtractor = featureExtractor ?? new FeatureExtractor();
        _fileClassifier = fileClassifier ?? MlpClassifier.CreateDefault();
        _blockSize = blockSize;
    }

    /// <summary>
    /// Виконує порівняльний експеримент на списку файлів (наприклад, team/corpus).
    /// </summary>
    public CompressionOrderReport Run(IReadOnlyList<string> filePaths, string password = "algo2026")
    {
        ArgumentNullException.ThrowIfNull(filePaths);
        ArgumentNullException.ThrowIfNull(password);

        if (filePaths.Count == 0)
        {
            throw new ArgumentException("File list cannot be empty.", nameof(filePaths));
        }

        byte[] salt = _cryptoEngine.GenerateSalt();
        DerivedKeys keys = _cryptoEngine.DeriveKeys(password, salt);
        byte[] noncePrefix = _cryptoEngine.GenerateNoncePrefix();

        var results = new List<CompressionOrderFileResult>(filePaths.Count);
        long totalOrig = 0;
        long totalCte = 0;
        long totalEtc = 0;
        double totalCteMs = 0;
        double totalEtcMs = 0;

        for (int idx = 0; idx < filePaths.Count; idx++)
        {
            string path = filePaths[idx];
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"Corpus file not found: '{path}'.", path);
            }

            byte[] rawBytes = File.ReadAllBytes(path);
            FileFeatures features = _featureExtractor.Extract(rawBytes);
            byte fileType = _fileClassifier.Classify(features);
            bool allowCompression = _fileClassifier.ShouldCompress(fileType, features);

            byte[] nonceCte = _cryptoEngine.CreateVolumeNonce(noncePrefix, (uint)(idx * 2));
            byte[] nonceEtc = _cryptoEngine.CreateVolumeNonce(noncePrefix, (uint)(idx * 2 + 1));

            // 1. Стиснути перед шифруванням (правильний конвеєр SARC v1)
            var swCte = Stopwatch.StartNew();
            (long cteCodedBytes, bool cteOk) = RunCompressThenEncrypt(rawBytes, allowCompression, keys, nonceCte);
            swCte.Stop();

            // 2. Зашифрувати перед стисненням (антипатерн)
            var swEtc = Stopwatch.StartNew();
            (long etcCodedBytes, bool etcOk) = RunEncryptThenCompress(rawBytes, keys, nonceEtc);
            swEtc.Stop();

            double cteRatio = cteCodedBytes > 0 ? (double)rawBytes.Length / cteCodedBytes : 1.0;
            double etcRatio = etcCodedBytes > 0 ? (double)rawBytes.Length / etcCodedBytes : 1.0;

            results.Add(new CompressionOrderFileResult(
                FileName: Path.GetFileName(path),
                FileType: fileType,
                OriginalBytes: rawBytes.Length,
                CompressThenEncryptBytes: cteCodedBytes,
                CompressThenEncryptRatio: cteRatio,
                CompressThenEncryptMs: swCte.Elapsed.TotalMilliseconds,
                EncryptThenCompressBytes: etcCodedBytes,
                EncryptThenCompressRatio: etcRatio,
                EncryptThenCompressMs: swEtc.Elapsed.TotalMilliseconds,
                RoundTripVerified: cteOk && etcOk));

            totalOrig += rawBytes.Length;
            totalCte += cteCodedBytes;
            totalEtc += etcCodedBytes;
            totalCteMs += swCte.Elapsed.TotalMilliseconds;
            totalEtcMs += swEtc.Elapsed.TotalMilliseconds;
        }

        double totalCteRatio = totalCte > 0 ? (double)totalOrig / totalCte : 1.0;
        double totalEtcRatio = totalEtc > 0 ? (double)totalOrig / totalEtc : 1.0;

        return new CompressionOrderReport(
            TotalOriginalBytes: totalOrig,
            TotalCompressThenEncryptBytes: totalCte,
            TotalCompressThenEncryptRatio: totalCteRatio,
            TotalCompressThenEncryptMs: totalCteMs,
            TotalEncryptThenCompressBytes: totalEtc,
            TotalEncryptThenCompressRatio: totalEtcRatio,
            TotalEncryptThenCompressMs: totalEtcMs,
            Files: results);
    }

    /// <summary>
    /// Генерує Markdown-звіт Таблиці №4 для документації та захисту.
    /// </summary>
    public static string FormatMarkdownTable(CompressionOrderReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var sb = new StringBuilder();
        sb.AppendLine("# Таблиця №4 — Експеримент «Стиснути перед шифруванням» проти «Зашифрувати перед стисненням» (Issue #37)");
        sb.AppendLine();
        sb.AppendLine($"- Файлів у вибірці: {report.Files.Count}");
        sb.AppendLine($"- Загальний сирий розмір: {report.TotalOriginalBytes} байт");
        sb.AppendLine($"- Стиснути перед шифруванням (AES-256-CTR): **{report.TotalCompressThenEncryptBytes}** байт (коефіцієнт **{report.TotalCompressThenEncryptRatio.ToString("F3", CultureInfo.InvariantCulture)}x**)");
        sb.AppendLine($"- Зашифрувати перед стисненням (антипатерн): **{report.TotalEncryptThenCompressBytes}** байт (коефіцієнт **{report.TotalEncryptThenCompressRatio.ToString("F3", CultureInfo.InvariantCulture)}x**)");
        sb.AppendLine();
        sb.AppendLine("| Файл | Тип | Сирий розмір (Б) | Стиснути -> Шифрувати (Б / коеф.) | Шифрувати -> Стиснути (Б / коеф.) | Round-trip |");
        sb.AppendLine("|---|---:|---:|---:|---:|:---:|");

        foreach (CompressionOrderFileResult f in report.Files)
        {
            string cteStr = $"{f.CompressThenEncryptBytes} ({f.CompressThenEncryptRatio.ToString("F2", CultureInfo.InvariantCulture)}x)";
            string etcStr = $"{f.EncryptThenCompressBytes} ({f.EncryptThenCompressRatio.ToString("F2", CultureInfo.InvariantCulture)}x)";
            sb.AppendLine($"| `{f.FileName}` | {f.FileType} | {f.OriginalBytes} | {cteStr} | {etcStr} | {(f.RoundTripVerified ? "OK" : "FAIL")} |");
        }

        sb.AppendLine($"| **УСЬОГО** | — | **{report.TotalOriginalBytes}** | **{report.TotalCompressThenEncryptBytes} ({report.TotalCompressThenEncryptRatio.ToString("F3", CultureInfo.InvariantCulture)}x)** | **{report.TotalEncryptThenCompressBytes} ({report.TotalEncryptThenCompressRatio.ToString("F3", CultureInfo.InvariantCulture)}x)** | **{(report.Files.All(x => x.RoundTripVerified) ? "OK" : "FAIL")}** |");
        sb.AppendLine();
        sb.AppendLine("## Висновок");
        sb.AppendLine("1. Шифрування `AES-256-CTR` перетворює будь-який структурований або текстовий потік на псевдовипадковий шум із ентропією близькою до 8 біт/байт, через що `LZ77 + Гаффман` не знаходить повторів (`coded_len >= raw_len`), і `BlockCompressor` переходить у `NO_COMPRESSION` (коефіцієнт ≈ `1.000x`).");
        sb.AppendLine("2. Пайплайн `SARC v1` («Стиснути перед шифруванням») зберігає повну ефективність стиснення і забезпечує конфіденційність та цілісність через `AES-256-CTR` + `HMAC-SHA256` (Encrypt-then-MAC).");

        return sb.ToString();
    }

    private (long CodedPayloadBytes, bool Verified) RunCompressThenEncrypt(
        byte[] rawBytes,
        bool allowCompression,
        DerivedKeys keys,
        byte[] nonce)
    {
        if (rawBytes.Length == 0)
        {
            byte[] emptyCipher = _cryptoEngine.TransformAesCtr([], keys.EncKey, nonce);
            byte[] emptyPlain = _cryptoEngine.TransformAesCtr(emptyCipher, keys.EncKey, nonce);
            return (0, emptyPlain.Length == 0);
        }

        var blocks = new List<(byte[] Data, byte Flags, int RawLen)>();
        int totalCoded = 0;

        for (int offset = 0; offset < rawBytes.Length; offset += _blockSize)
        {
            int len = Math.Min(_blockSize, rawBytes.Length - offset);
            byte[] coded = _blockCompressor.Compress(rawBytes.AsSpan(offset, len), out byte flags, allowCompression);
            blocks.Add((coded, flags, len));
            totalCoded += coded.Length;
        }

        byte[] packed = ConcatBlocks(blocks, totalCoded);
        byte[] ciphertext = _cryptoEngine.TransformAesCtr(packed, keys.EncKey, nonce);
        byte[] decrypted = _cryptoEngine.TransformAesCtr(ciphertext, keys.EncKey, nonce);

        byte[] restored = new byte[rawBytes.Length];
        int readPos = 0;
        int writePos = 0;
        foreach (var (data, flags, rawLen) in blocks)
        {
            byte[] decoded = _blockCompressor.Decompress(decrypted.AsSpan(readPos, data.Length), flags, rawLen);
            decoded.CopyTo(restored.AsSpan(writePos));
            readPos += data.Length;
            writePos += rawLen;
        }

        return (ciphertext.Length, restored.AsSpan().SequenceEqual(rawBytes));
    }

    private (long CodedPayloadBytes, bool Verified) RunEncryptThenCompress(
        byte[] rawBytes,
        DerivedKeys keys,
        byte[] nonce)
    {
        if (rawBytes.Length == 0)
        {
            return (0, true);
        }

        byte[] ciphertext = _cryptoEngine.TransformAesCtr(rawBytes, keys.EncKey, nonce);

        var blocks = new List<(byte[] Data, byte Flags, int RawLen)>();
        int totalCoded = 0;

        for (int offset = 0; offset < ciphertext.Length; offset += _blockSize)
        {
            int len = Math.Min(_blockSize, ciphertext.Length - offset);
            byte[] coded = _blockCompressor.Compress(ciphertext.AsSpan(offset, len), out byte flags, allowCompression: true);
            blocks.Add((coded, flags, len));
            totalCoded += coded.Length;
        }

        byte[] restoredCiphertext = new byte[ciphertext.Length];
        int writePos = 0;
        foreach (var (data, flags, rawLen) in blocks)
        {
            byte[] decoded = _blockCompressor.Decompress(data, flags, rawLen);
            decoded.CopyTo(restoredCiphertext.AsSpan(writePos));
            writePos += rawLen;
        }

        byte[] restoredRaw = _cryptoEngine.TransformAesCtr(restoredCiphertext, keys.EncKey, nonce);
        return (totalCoded, restoredRaw.AsSpan().SequenceEqual(rawBytes));
    }

    private static byte[] ConcatBlocks(List<(byte[] Data, byte Flags, int RawLen)> blocks, int totalLength)
    {
        byte[] buffer = new byte[totalLength];
        int offset = 0;
        foreach (var (data, _, _) in blocks)
        {
            data.CopyTo(buffer.AsSpan(offset));
            offset += data.Length;
        }

        return buffer;
    }
}
