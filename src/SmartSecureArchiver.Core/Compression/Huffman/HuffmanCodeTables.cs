namespace SmartSecureArchiver.Core.Compression;

public sealed record HuffmanCodeTables(
    byte[] LitLengths,    // Алфавіт 0..256
    byte[] LenLengths,    // Алфавіт 0..255
    byte[] DistLengths    // Алфавіт 0..15
);
