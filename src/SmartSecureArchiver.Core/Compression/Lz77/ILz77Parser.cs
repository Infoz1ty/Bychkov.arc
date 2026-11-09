namespace SmartSecureArchiver.Core.Compression;

public interface ILz77Parser
{
    /// <summary>
    /// Розбирає потік байтів на токени (літерали та посилання).
    /// Підтримує режими Greedy та Lazy Greedy.
    /// </summary>
    IReadOnlyList<Lz77Token> Parse(ReadOnlySpan<byte> input, int windowSize = 32768);
    
    /// <summary>
    /// Відновлює сирі байти з токенів LZ77 з обов'язковою підтримкою перекриття (overlap).
    /// </summary>
    byte[] Decompress(IReadOnlyList<Lz77Token> tokens, int expectedLength);
}
