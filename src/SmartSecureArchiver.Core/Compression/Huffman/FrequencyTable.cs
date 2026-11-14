namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Підрахунок частот символів для побудови дерев канонічного Гаффмана (Зріз 1, Issue #15).
/// Підтримує як підрахунок частот сирих байтів (0..255), так і підрахунок частот
/// трьох окремих алфавітів SARC v1 (LIT 0..256, LEN 0..255, DIST 0..15).
/// </summary>
public static class FrequencyTable
{
    public const int LitAlphabetSize = 257;
    public const int LenAlphabetSize = 256;
    public const int DistAlphabetSize = 16;
    public const ushort MatchMarkerSymbol = 256;

    /// <summary>
    /// Підраховує частоти байтів (0..255) для довільного зрізу даних.
    /// </summary>
    public static int[] CountByteFrequencies(ReadOnlySpan<byte> data)
    {
        int[] frequencies = new int[256];
        for (int i = 0; i < data.Length; i++)
        {
            frequencies[data[i]]++;
        }

        return frequencies;
    }

    /// <summary>
    /// Підраховує частоти символів для трьох окремих дерев Гаффмана (LIT, LEN, DIST)
    /// за послідовністю токенів LZ77 згідно з розділом 3.2 FORMAT_SPEC_P2.md.
    /// </summary>
    public static (int[] LitFreq, int[] LenFreq, int[] DistFreq) CountTokenFrequencies(IReadOnlyList<Lz77Token> tokens)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        int[] litFreq = new int[LitAlphabetSize];
        int[] lenFreq = new int[LenAlphabetSize];
        int[] distFreq = new int[DistAlphabetSize];

        for (int i = 0; i < tokens.Count; i++)
        {
            Lz77Token token = tokens[i];
            if (token.Type == Lz77TokenType.Literal)
            {
                litFreq[token.Literal]++;
            }
            else
            {
                litFreq[MatchMarkerSymbol]++;

                int lenSymbol = token.Length - 3;
                if (lenSymbol is < 0 or >= LenAlphabetSize)
                {
                    throw new ArgumentOutOfRangeException(nameof(tokens), $"Invalid LZ77 match length {token.Length} (expected 3..258).");
                }

                lenFreq[lenSymbol]++;

                DecomposeDistance(token.Distance, out int distCode, out _, out _);
                distFreq[distCode]++;
            }
        }

        return (litFreq, lenFreq, distFreq);
    }

    /// <summary>
    /// Розкладає відстань LZ77 (1..32768) на код Гаффмана DIST (0..15) та додаткові біти
    /// згідно з п. 3.2 FORMAT_SPEC_P2.md:
    /// d = dist - 1, code = bit_length(d) (0 при d = 0), extra = max(0, code - 1).
    /// </summary>
    public static void DecomposeDistance(ushort distance, out int distCode, out int extraBitsCount, out uint extraBitsValue)
    {
        if (distance is < 1 or > 32768)
        {
            throw new ArgumentOutOfRangeException(nameof(distance), $"LZ77 distance must be in range 1..32768, got {distance}.");
        }

        uint d = (uint)(distance - 1);
        if (d == 0)
        {
            distCode = 0;
            extraBitsCount = 0;
            extraBitsValue = 0;
            return;
        }

        // bit_length(d) для d > 0: позиція старшого одиничного біта + 1 (1..15)
        int bitLength = 0;
        uint temp = d;
        while (temp > 0)
        {
            bitLength++;
            temp >>= 1;
        }

        distCode = bitLength;
        extraBitsCount = Math.Max(0, distCode - 1);
        uint mask = (1u << extraBitsCount) - 1u;
        extraBitsValue = d & mask;
    }
}
