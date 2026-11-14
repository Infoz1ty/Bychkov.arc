using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Реалізація канонічного кодека Гаффмана для трьох окремих дерев SARC v1:
/// LIT (0..256), LEN (0..255), DIST (0..15) згідно з розділом 3 FORMAT_SPEC_P2.md (Зріз 1, Issues #15–#19).
/// </summary>
public sealed class HuffmanCodec : IHuffmanCodec
{
    /// <inheritdoc />
    public byte[] Encode(IReadOnlyList<Lz77Token> tokens, out HuffmanCodeTables tables)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        (int[] litFreq, int[] lenFreq, int[] distFreq) = FrequencyTable.CountTokenFrequencies(tokens);

        byte[] litLengths = CanonicalHuffman.BuildCodeLengths(litFreq);
        byte[] lenLengths = CanonicalHuffman.BuildCodeLengths(lenFreq);
        byte[] distLengths = CanonicalHuffman.BuildCodeLengths(distFreq);

        tables = new HuffmanCodeTables(litLengths, lenLengths, distLengths);

        if (tokens.Count == 0)
        {
            return [];
        }

        uint[] litCodes = CanonicalHuffman.BuildCanonicalCodes(litLengths);
        uint[] lenCodes = CanonicalHuffman.BuildCanonicalCodes(lenLengths);
        uint[] distCodes = CanonicalHuffman.BuildCanonicalCodes(distLengths);

        var writer = new BitWriter(Math.Max(64, tokens.Count));

        for (int i = 0; i < tokens.Count; i++)
        {
            Lz77Token token = tokens[i];
            if (token.Type == Lz77TokenType.Literal)
            {
                byte sym = token.Literal;
                writer.WriteBits(litCodes[sym], litLengths[sym]);
            }
            else
            {
                writer.WriteBits(litCodes[FrequencyTable.MatchMarkerSymbol], litLengths[FrequencyTable.MatchMarkerSymbol]);

                int lenSym = token.Length - 3;
                writer.WriteBits(lenCodes[lenSym], lenLengths[lenSym]);

                FrequencyTable.DecomposeDistance(token.Distance, out int distCode, out int extraBitsCount, out uint extraBitsValue);
                writer.WriteBits(distCodes[distCode], distLengths[distCode]);

                if (extraBitsCount > 0)
                {
                    writer.WriteBits(extraBitsValue, extraBitsCount);
                }
            }
        }

        return writer.ToArray();
    }

    /// <inheritdoc />
    public IReadOnlyList<Lz77Token> Decode(ReadOnlySpan<byte> bitstream, HuffmanCodeTables tables, int tokenCount)
    {
        ArgumentNullException.ThrowIfNull(tables);

        if (tokenCount < 0)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Invalid negative token_count: {tokenCount}.");
        }

        if (tables.LitLengths is null || tables.LitLengths.Length != FrequencyTable.LitAlphabetSize ||
            tables.LenLengths is null || tables.LenLengths.Length != FrequencyTable.LenAlphabetSize ||
            tables.DistLengths is null || tables.DistLengths.Length != FrequencyTable.DistAlphabetSize)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Invalid HuffmanCodeTables dimensions.");
        }

        var litDecoder = new CanonicalHuffmanDecoder(tables.LitLengths, FrequencyTable.LitAlphabetSize);
        var lenDecoder = new CanonicalHuffmanDecoder(tables.LenLengths, FrequencyTable.LenAlphabetSize);
        var distDecoder = new CanonicalHuffmanDecoder(tables.DistLengths, FrequencyTable.DistAlphabetSize);

        var reader = new BitReader(bitstream);
        var tokens = new List<Lz77Token>(Math.Min(tokenCount, 65536));

        for (int i = 0; i < tokenCount; i++)
        {
            ushort litSym = litDecoder.DecodeSymbol(ref reader);
            if (litSym < FrequencyTable.MatchMarkerSymbol)
            {
                tokens.Add(new Lz77Token(Lz77TokenType.Literal, (byte)litSym, 0, 0));
            }
            else
            {
                ushort lenSym = lenDecoder.DecodeSymbol(ref reader);
                ushort length = (ushort)(lenSym + 3);

                ushort distCode = distDecoder.DecodeSymbol(ref reader);
                if (distCode >= FrequencyTable.DistAlphabetSize)
                {
                    throw new SarcException(SarcErrorCode.E_CODE, $"Invalid DIST code {distCode}.");
                }

                ushort distance;
                if (distCode == 0)
                {
                    distance = 1;
                }
                else if (distCode == 1)
                {
                    distance = 2;
                }
                else
                {
                    int extraBitsCount = distCode - 1;
                    uint extraBits = reader.ReadBits(extraBitsCount);
                    uint d = (1u << extraBitsCount) | extraBits;
                    distance = (ushort)(d + 1u);
                }

                tokens.Add(new Lz77Token(Lz77TokenType.Match, 0, distance, length));
            }
        }

        reader.VerifyZeroPaddingAndEndOrThrow();
        return tokens;
    }
}
