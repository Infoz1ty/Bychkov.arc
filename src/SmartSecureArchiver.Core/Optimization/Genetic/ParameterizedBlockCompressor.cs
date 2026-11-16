using SmartSecureArchiver.Core.Compression;

namespace SmartSecureArchiver.Core.Optimization;

/// <summary>
/// Адаптер IBlockCompressor, що застосовує параметри оптимізації ГА
/// (WindowSize та MinMatchLength) без зміни існуючих контрактів ядра.
/// </summary>
public sealed class ParameterizedBlockCompressor : IBlockCompressor
{
    private readonly IBlockCompressor _inner;
    private readonly int _windowSize;
    private readonly int _minMatchLength;
    private readonly bool _useLazyMatching;

    public ParameterizedBlockCompressor(
        IBlockCompressor inner,
        int windowSize,
        int minMatchLength,
        bool useLazyMatching = false)
    {
        ArgumentNullException.ThrowIfNull(inner);

        if (windowSize is < 1 or > Lz77Parser.DefaultWindowSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(windowSize),
                $"WindowSize must be in range 1..{Lz77Parser.DefaultWindowSize}.");
        }

        if (minMatchLength is < Lz77Parser.MinMatchLength or > Lz77Parser.MaxMatchLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minMatchLength),
                $"MinMatchLength must be in range {Lz77Parser.MinMatchLength}..{Lz77Parser.MaxMatchLength}.");
        }

        _inner = inner;
        _windowSize = windowSize;
        _minMatchLength = minMatchLength;
        _useLazyMatching = useLazyMatching;
    }

    public int WindowSize => _windowSize;

    public int MinMatchLength => _minMatchLength;

    /// <inheritdoc />
    public byte[] Compress(
        ReadOnlySpan<byte> blockData,
        out byte blockFlags,
        bool allowCompression = true,
        int windowSize = Lz77Parser.DefaultWindowSize,
        int minMatchLength = Lz77Parser.MinMatchLength,
        bool useLazyMatching = false)
    {
        return _inner.Compress(
            blockData,
            out blockFlags,
            allowCompression: allowCompression,
            windowSize: _windowSize,
            minMatchLength: _minMatchLength,
            useLazyMatching: _useLazyMatching);
    }

    /// <inheritdoc />
    public byte[] Decompress(ReadOnlySpan<byte> codedData, byte blockFlags, int expectedRawLength)
    {
        return _inner.Decompress(codedData, blockFlags, expectedRawLength);
    }
}
