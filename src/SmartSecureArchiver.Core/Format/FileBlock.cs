namespace SmartSecureArchiver.Core.Format;

public sealed record FileBlock(
    int FileIndex,
    ushort BlockSeq,
    byte CompressionMethod,
    uint RawLength,
    uint CodedLength,
    byte[] Data
);
