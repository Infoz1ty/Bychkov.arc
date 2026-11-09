namespace SmartSecureArchiver.Core.Compression;

public interface IBlockCompressor
{
    byte[] Compress(ReadOnlySpan<byte> blockData, out byte compressionMethod);
    byte[] Decompress(ReadOnlySpan<byte> compressedData, byte compressionMethod, int originalLength);
}
