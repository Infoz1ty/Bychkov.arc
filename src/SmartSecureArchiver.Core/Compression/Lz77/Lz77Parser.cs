using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Розбір потоку байтів та побайтовий декодер LZ77 згідно з розділом 3.2 FORMAT_SPEC_P2.md (Зріз 1, Issue #14; Зріз 2, Issues #11–#13).
/// Параметри формату: MIN_MATCH = 3, MAX_MATCH = 258, MAX_WINDOW = 32768.
/// </summary>
public sealed class Lz77Parser : ILz77Parser
{
    public const int DefaultWindowSize = 32768;
    public const int MinMatchLength = 3;
    public const int MaxMatchLength = 258;
    private const int HashBits = 15;
    private const int HashSize = 1 << HashBits;
    private const int HashMask = HashSize - 1;
    private const int MaxChainChecks = 128;

    /// <inheritdoc />
    public IReadOnlyList<Lz77Token> Parse(ReadOnlySpan<byte> input, int windowSize = DefaultWindowSize)
    {
        return Parse(input, windowSize, MinMatchLength, useLazyMatching: false);
    }

    /// <summary>
    /// Розбирає вхідний буфер на токени LZ77 із заданим розміром вікна (1..32768),
    /// мінімальною довжиною збігу (3..258) та вибором режиму (Greedy або Lazy Greedy).
    /// </summary>
    public IReadOnlyList<Lz77Token> Parse(
        ReadOnlySpan<byte> input,
        int windowSize,
        int minMatchLength,
        bool useLazyMatching)
    {
        if (windowSize is < 1 or > DefaultWindowSize)
        {
            throw new ArgumentOutOfRangeException(nameof(windowSize), $"windowSize must be in range 1..{DefaultWindowSize}.");
        }

        if (minMatchLength is < MinMatchLength or > MaxMatchLength)
        {
            throw new ArgumentOutOfRangeException(nameof(minMatchLength), $"minMatchLength must be in range {MinMatchLength}..{MaxMatchLength}.");
        }

        if (input.IsEmpty)
        {
            return [];
        }

        var tokens = new List<Lz77Token>(input.Length / 2 + 1);
        if (input.Length < minMatchLength)
        {
            for (int i = 0; i < input.Length; i++)
            {
                tokens.Add(new Lz77Token(Lz77TokenType.Literal, input[i], 0, 0));
            }

            return tokens;
        }

        int[] head = new int[HashSize];
        Array.Fill(head, -1);
        int[] prev = new int[input.Length];
        Array.Fill(prev, -1);

        int pos = 0;
        while (pos < input.Length)
        {
            FindBestMatch(input, pos, windowSize, minMatchLength, head, prev, out int bestDist, out int bestLen);

            if (bestLen >= minMatchLength)
            {
                if (useLazyMatching && pos + 1 < input.Length && bestLen < MaxMatchLength)
                {
                    InsertHash(input, pos, head, prev);
                    FindBestMatch(input, pos + 1, windowSize, minMatchLength, head, prev, out int nextDist, out int nextLen);

                    if (nextLen > bestLen)
                    {
                        tokens.Add(new Lz77Token(Lz77TokenType.Literal, input[pos], 0, 0));
                        pos++;
                        tokens.Add(new Lz77Token(Lz77TokenType.Match, 0, (ushort)nextDist, (ushort)nextLen));
                        for (int k = 0; k < nextLen; k++)
                        {
                            InsertHash(input, pos + k, head, prev);
                        }

                        pos += nextLen;
                        continue;
                    }

                    tokens.Add(new Lz77Token(Lz77TokenType.Match, 0, (ushort)bestDist, (ushort)bestLen));
                    for (int k = 1; k < bestLen; k++)
                    {
                        InsertHash(input, pos + k, head, prev);
                    }

                    pos += bestLen;
                    continue;
                }

                tokens.Add(new Lz77Token(Lz77TokenType.Match, 0, (ushort)bestDist, (ushort)bestLen));
                for (int k = 0; k < bestLen; k++)
                {
                    InsertHash(input, pos + k, head, prev);
                }

                pos += bestLen;
            }
            else
            {
                InsertHash(input, pos, head, prev);
                tokens.Add(new Lz77Token(Lz77TokenType.Literal, input[pos], 0, 0));
                pos++;
            }
        }

        return tokens;
    }

    /// <inheritdoc />
    public byte[] Decompress(IReadOnlyList<Lz77Token> tokens, int expectedLength)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        if (expectedLength < 0)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Invalid negative expectedLength: {expectedLength}.");
        }

        byte[] output = new byte[expectedLength];
        int writePos = 0;

        for (int i = 0; i < tokens.Count; i++)
        {
            Lz77Token token = tokens[i];
            if (token.Type == Lz77TokenType.Literal)
            {
                if (writePos >= expectedLength)
                {
                    throw new SarcException(SarcErrorCode.E_CODE, "LZ77 literal exceeds expected raw_len.");
                }

                output[writePos++] = token.Literal;
            }
            else
            {
                if (token.Distance is < 1 or > DefaultWindowSize)
                {
                    throw new SarcException(SarcErrorCode.E_CODE, $"LZ77 distance {token.Distance} is out of valid range 1..{DefaultWindowSize}.");
                }

                if (token.Length is < MinMatchLength or > MaxMatchLength)
                {
                    throw new SarcException(SarcErrorCode.E_CODE, $"LZ77 match length {token.Length} is out of valid range {MinMatchLength}..{MaxMatchLength}.");
                }

                if (token.Distance > writePos)
                {
                    throw new SarcException(SarcErrorCode.E_CODE, $"LZ77 match distance ({token.Distance}) references before start of block (pos={writePos}).");
                }

                if (writePos + token.Length > expectedLength)
                {
                    throw new SarcException(SarcErrorCode.E_CODE, "LZ77 match exceeds expected raw_len.");
                }

                // Побайтове копіювання для коректної підтримки перекриття (distance < length)
                int srcPos = writePos - token.Distance;
                for (int k = 0; k < token.Length; k++)
                {
                    output[writePos++] = output[srcPos++];
                }
            }
        }

        if (writePos != expectedLength)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                $"Decoded LZ77 block size ({writePos}) does not match expected raw_len ({expectedLength}).");
        }

        return output;
    }

    private static int ComputeHash(ReadOnlySpan<byte> input, int pos)
    {
        return (((input[pos] << 10) ^ (input[pos + 1] << 5) ^ input[pos + 2]) & HashMask);
    }

    private static void InsertHash(ReadOnlySpan<byte> input, int pos, int[] head, int[] prev)
    {
        if (pos + 2 >= input.Length)
        {
            return;
        }

        int h = ComputeHash(input, pos);
        prev[pos] = head[h];
        head[h] = pos;
    }

    private static void FindBestMatch(
        ReadOnlySpan<byte> input,
        int pos,
        int windowSize,
        int minMatchLength,
        int[] head,
        int[] prev,
        out int bestDistance,
        out int bestLength)
    {
        bestDistance = 0;
        bestLength = 0;

        if (pos + minMatchLength > input.Length)
        {
            return;
        }

        int maxAllowedLength = Math.Min(MaxMatchLength, input.Length - pos);
        if (maxAllowedLength < minMatchLength)
        {
            return;
        }

        int minCandidatePos = Math.Max(0, pos - windowSize);
        int h = ComputeHash(input, pos);
        int candidate = head[h];
        int checks = 0;

        while (candidate >= minCandidatePos && checks < MaxChainChecks)
        {
            checks++;

            if (input[candidate + bestLength] == input[pos + bestLength])
            {
                int len = 0;
                while (len < maxAllowedLength && input[candidate + len] == input[pos + len])
                {
                    len++;
                }

                if (len >= minMatchLength && len > bestLength)
                {
                    bestLength = len;
                    bestDistance = pos - candidate;
                    if (bestLength == maxAllowedLength)
                    {
                        break;
                    }
                }
            }

            candidate = prev[candidate];
        }
    }
}
