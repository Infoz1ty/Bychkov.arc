namespace SmartSecureArchiver.Core.Compression;

public enum Lz77TokenType
{
    Literal,
    Match
}

public readonly record struct Lz77Token(Lz77TokenType Type, byte Literal, ushort Distance, ushort Length);
