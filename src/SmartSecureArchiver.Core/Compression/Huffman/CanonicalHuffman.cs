using System.Buffers.Binary;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Побудова довжин кодів, генерація канонічних кодів Гаффмана (до 15 біт),
/// перевірка точної рівності Крафта та декодування потоку виключно з довжин кодів
/// згідно з розділом 3 FORMAT_SPEC_P2.md та ADR-03 (Зріз 1, Issues #16, #17, #18).
/// </summary>
public static class CanonicalHuffman
{
    public const int MaxCodeLength = 15;
    public const int KraftTargetSum = 1 << MaxCodeLength; // 32768

    /// <summary>
    /// Будує масив бітових довжин кодів (0..MaxCodeLength) за частотами символів:
    /// - якщо активних символів немає (nsym == 0) -> усі довжини 0;
    /// - якщо активний лише один символ (nsym == 1) -> length = 1 (вироджений алфавіт);
    /// - якщо nsym > 1 -> будує дерево через MinHeap&lt;HuffmanNode&gt; і за потреби обмежує
    ///   максимальну глибину до 15 біт із збереженням точної рівності Крафта (ADR-03).
    /// </summary>
    public static byte[] BuildCodeLengths(ReadOnlySpan<int> frequencies, int maxBits = MaxCodeLength)
    {
        if (maxBits is < 1 or > MaxCodeLength)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBits), $"maxBits must be in range 1..{MaxCodeLength}.");
        }

        byte[] lengths = new byte[frequencies.Length];
        int activeCount = 0;
        int singleSymbol = -1;

        for (int s = 0; s < frequencies.Length; s++)
        {
            if (frequencies[s] < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(frequencies), "Symbol frequency cannot be negative.");
            }

            if (frequencies[s] > 0)
            {
                activeCount++;
                singleSymbol = s;
            }
        }

        if (activeCount == 0)
        {
            return lengths;
        }

        // Вироджений випадок (nsym == 1): length = 1, code = 0 (п. 3.4 FORMAT_SPEC_P2.md)
        if (activeCount == 1)
        {
            lengths[singleSymbol] = 1;
            return lengths;
        }

        if (activeCount > (1 << maxBits))
        {
            throw new ArgumentException($"Active symbol count ({activeCount}) exceeds capacity for maxBits={maxBits}.");
        }

        var heap = new MinHeap<HuffmanNode>(activeCount);
        for (int s = 0; s < frequencies.Length; s++)
        {
            if (frequencies[s] > 0)
            {
                heap.Push(new HuffmanNode(s, frequencies[s]));
            }
        }

        while (heap.Count > 1)
        {
            HuffmanNode left = heap.Pop();
            HuffmanNode right = heap.Pop();
            heap.Push(new HuffmanNode(left, right));
        }

        HuffmanNode root = heap.Pop();
        int[] rawDepths = new int[frequencies.Length];
        int maxDepth = 0;
        ComputeDepths(root, 0, rawDepths, ref maxDepth);

        if (maxDepth <= maxBits)
        {
            for (int s = 0; s < frequencies.Length; s++)
            {
                lengths[s] = (byte)rawDepths[s];
            }

            return lengths;
        }

        // Двофазне обмеження довжини до maxBits із збереженням точної рівності Крафта (ADR-03)
        EnforceMaxBitsWithKraftEquality(frequencies, rawDepths, lengths, activeCount, maxBits);
        return lengths;
    }

    /// <summary>
    /// Перевіряє коректність масиву довжин кодів за правилами п. 3.3–3.4 FORMAT_SPEC_P2.md:
    /// - довжина кожного активного символу в межах 1..maxBits;
    /// - при nsym == 1 довжина єдиного символу дорівнює 1;
    /// - при nsym > 1 виконується точна рівність Крафта: sum(2^(maxBits - L_i)) == 2^maxBits.
    /// При будь-якому порушенні кидає SarcException(E_CODE).
    /// </summary>
    public static int ValidateLengthsOrThrow(ReadOnlySpan<byte> lengths, int maxSymbols, int maxBits = MaxCodeLength)
    {
        if (lengths.Length > maxSymbols)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Huffman table size {lengths.Length} exceeds max symbols {maxSymbols}.");
        }

        int nsym = 0;
        int singleLen = 0;
        int kraftSum = 0;

        for (int s = 0; s < lengths.Length; s++)
        {
            byte len = lengths[s];
            if (len == 0)
            {
                continue;
            }

            if (len > maxBits)
            {
                throw new SarcException(SarcErrorCode.E_CODE, $"Huffman code length {len} exceeds maximum allowed {maxBits} bits.");
            }

            nsym++;
            singleLen = len;
            kraftSum += 1 << (maxBits - len);
        }

        if (nsym == 0)
        {
            return 0;
        }

        if (nsym == 1)
        {
            if (singleLen != 1)
            {
                throw new SarcException(SarcErrorCode.E_CODE, $"Degenerate single-symbol Huffman table must have code length 1, got {singleLen}.");
            }

            return 1;
        }

        int targetKraft = 1 << maxBits;
        if (kraftSum != targetKraft)
        {
            throw new SarcException(
                SarcErrorCode.E_CODE,
                $"Kraft equality violated for Huffman table (nsym={nsym}): sum={kraftSum}, expected={targetKraft}.");
        }

        return nsym;
    }

    /// <summary>
    /// Генерує канонічні коди Гаффмана виключно з масиву бітових довжин:
    /// символи впорядковуються за зростанням довжини коду (1..15), а при рівній довжині — за зростанням символу.
    /// При nsym == 1 єдиний символ отримує length = 1, code = 0.
    /// </summary>
    public static uint[] BuildCanonicalCodes(ReadOnlySpan<byte> lengths, int maxBits = MaxCodeLength)
    {
        ValidateLengthsOrThrow(lengths, lengths.Length, maxBits);

        uint[] codes = new uint[lengths.Length];
        Span<int> blCount = stackalloc int[maxBits + 1];

        for (int s = 0; s < lengths.Length; s++)
        {
            byte len = lengths[s];
            if (len > 0)
            {
                blCount[len]++;
            }
        }

        Span<uint> nextCode = stackalloc uint[maxBits + 1];
        uint code = 0;
        for (int bits = 1; bits <= maxBits; bits++)
        {
            code = (code + (uint)blCount[bits - 1]) << 1;
            nextCode[bits] = code;
        }

        for (int s = 0; s < lengths.Length; s++)
        {
            byte len = lengths[s];
            if (len > 0)
            {
                codes[s] = nextCode[len]++;
            }
        }

        return codes;
    }

    /// <summary>
    /// Серіалізує таблицю довжин кодів у бінарний буфер згідно з п. 3.1 FORMAT_SPEC_P2.md:
    /// [nsym: uint16 BE] + nsym записів по 3 байти [symbol: uint16 BE, length: uint8] за зростанням symbol.
    /// </summary>
    public static void WriteTable(ReadOnlySpan<byte> lengths, List<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int nsym = ValidateLengthsOrThrow(lengths, lengths.Length);

        Span<byte> temp = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(temp, (ushort)nsym);
        output.Add(temp[0]);
        output.Add(temp[1]);

        for (int symbol = 0; symbol < lengths.Length; symbol++)
        {
            byte len = lengths[symbol];
            if (len > 0)
            {
                BinaryPrimitives.WriteUInt16BigEndian(temp, (ushort)symbol);
                output.Add(temp[0]);
                output.Add(temp[1]);
                output.Add(len);
            }
        }
    }

    /// <summary>
    /// Десеріалізує таблицю довжин кодів із бінарного буфера згідно з п. 3.1 FORMAT_SPEC_P2.md
    /// та перевіряє впорядкованість символів, межі алфавіту і рівність Крафта (E_CODE).
    /// </summary>
    public static byte[] ReadTable(ReadOnlySpan<byte> data, ref int offset, int alphabetSize)
    {
        if (offset + 2 > data.Length)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Unexpected end of data while reading Huffman table nsym.");
        }

        ushort nsym = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
        offset += 2;

        if (nsym > alphabetSize)
        {
            throw new SarcException(SarcErrorCode.E_CODE, $"Huffman table nsym ({nsym}) exceeds alphabet size ({alphabetSize}).");
        }

        int tableBytes = nsym * 3;
        if (offset + tableBytes > data.Length)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Unexpected end of data while reading Huffman table entries.");
        }

        byte[] lengths = new byte[alphabetSize];
        int prevSymbol = -1;

        for (int i = 0; i < nsym; i++)
        {
            ushort symbol = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
            byte length = data[offset + 2];
            offset += 3;

            if (symbol >= alphabetSize)
            {
                throw new SarcException(SarcErrorCode.E_CODE, $"Huffman symbol {symbol} is out of range for alphabet size {alphabetSize}.");
            }

            if (symbol <= prevSymbol)
            {
                throw new SarcException(SarcErrorCode.E_CODE, "Huffman table symbols must be in strictly ascending order.");
            }

            if (length is < 1 or > MaxCodeLength)
            {
                throw new SarcException(SarcErrorCode.E_CODE, $"Invalid Huffman code length {length} for symbol {symbol}.");
            }

            lengths[symbol] = length;
            prevSymbol = symbol;
        }

        ValidateLengthsOrThrow(lengths, alphabetSize);
        return lengths;
    }

    private static void ComputeDepths(HuffmanNode node, int currentDepth, int[] depths, ref int maxDepth)
    {
        if (node.IsLeaf)
        {
            depths[node.Symbol] = currentDepth;
            if (currentDepth > maxDepth)
            {
                maxDepth = currentDepth;
            }

            return;
        }

        if (node.Left is not null)
        {
            ComputeDepths(node.Left, currentDepth + 1, depths, ref maxDepth);
        }

        if (node.Right is not null)
        {
            ComputeDepths(node.Right, currentDepth + 1, depths, ref maxDepth);
        }
    }

    private static void EnforceMaxBitsWithKraftEquality(
        ReadOnlySpan<int> frequencies,
        int[] rawDepths,
        byte[] outputLengths,
        int activeCount,
        int maxBits)
    {
        int[] activeSymbols = new int[activeCount];
        long[] sortKeys = new long[activeCount];
        int idx = 0;
        for (int s = 0; s < frequencies.Length; s++)
        {
            if (frequencies[s] > 0)
            {
                activeSymbols[idx] = s;
                // Сортування за спаданням частоти, а при рівності — за зростанням символу
                sortKeys[idx] = (-((long)frequencies[s]) << 32) | (uint)s;
                idx++;
            }
        }

        Array.Sort(sortKeys, activeSymbols);

        int[] workingLengths = new int[activeCount];
        for (int i = 0; i < activeCount; i++)
        {
            int s = activeSymbols[i];
            workingLengths[i] = Math.Clamp(rawDepths[s], 1, maxBits);
        }

        Array.Sort(workingLengths);

        int targetKraft = 1 << maxBits;
        int kraftSum = 0;
        for (int i = 0; i < activeCount; i++)
        {
            kraftSum += 1 << (maxBits - workingLengths[i]);
        }

        // Фаза 1: якщо сума Крафта перевищує 2^maxBits, подовжуємо коди найменш частих символів (з L < maxBits)
        while (kraftSum > targetKraft)
        {
            for (int i = activeCount - 1; i >= 0; i--)
            {
                if (workingLengths[i] < maxBits)
                {
                    workingLengths[i]++;
                    kraftSum -= 1 << (maxBits - workingLengths[i]);
                    break;
                }
            }
        }

        // Фаза 2: якщо після Фази 1 сума Крафта менша за 2^maxBits, скорочуємо коди найбільш частих символів
        while (kraftSum < targetKraft)
        {
            int deficit = targetKraft - kraftSum;
            for (int i = 0; i < activeCount; i++)
            {
                if (workingLengths[i] > 1)
                {
                    int delta = 1 << (maxBits - workingLengths[i]);
                    if (delta <= deficit)
                    {
                        workingLengths[i]--;
                        kraftSum += delta;
                        break;
                    }
                }
            }
        }

        Array.Sort(workingLengths);
        for (int i = 0; i < activeCount; i++)
        {
            outputLengths[activeSymbols[i]] = (byte)workingLengths[i];
        }
    }
}

/// <summary>
/// Декодер канонічного дерева Гаффмана, побудований виключно з масиву довжин кодів (Issue #18).
/// </summary>
public sealed class CanonicalHuffmanDecoder
{
    private readonly int _symbolCount;
    private readonly int _maxBits;
    private readonly int[] _blCount;
    private readonly ushort[] _sortedSymbols;

    public int SymbolCount => _symbolCount;

    public CanonicalHuffmanDecoder(ReadOnlySpan<byte> lengths, int maxSymbols, int maxBits = CanonicalHuffman.MaxCodeLength)
    {
        _maxBits = maxBits;
        _symbolCount = CanonicalHuffman.ValidateLengthsOrThrow(lengths, maxSymbols, maxBits);
        _blCount = new int[maxBits + 1];
        _sortedSymbols = new ushort[_symbolCount];

        if (_symbolCount == 0)
        {
            return;
        }

        for (int s = 0; s < lengths.Length; s++)
        {
            byte len = lengths[s];
            if (len > 0)
            {
                _blCount[len]++;
            }
        }

        Span<int> offsets = stackalloc int[maxBits + 1];
        int currentOffset = 0;
        for (int bits = 1; bits <= maxBits; bits++)
        {
            offsets[bits] = currentOffset;
            currentOffset += _blCount[bits];
        }

        for (int s = 0; s < lengths.Length; s++)
        {
            byte len = lengths[s];
            if (len > 0)
            {
                _sortedSymbols[offsets[len]++] = (ushort)s;
            }
        }
    }

    /// <summary>
    /// Декодує один символ із побітового потоку MSB-first.
    /// При невалідному коді або спробі читання з порожньої таблиці кидає SarcException(E_CODE).
    /// </summary>
    public ushort DecodeSymbol(ref BitReader reader)
    {
        if (_symbolCount == 0)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Cannot decode symbol from an empty Huffman table.");
        }

        // Вироджений алфавіт (nsym == 1): єдиний допустимий 1-бітний код дорівнює 0
        if (_symbolCount == 1)
        {
            int bit = reader.ReadBit();
            if (bit != 0)
            {
                throw new SarcException(SarcErrorCode.E_CODE, "Invalid non-zero bit encountered for degenerate single-symbol Huffman table.");
            }

            return _sortedSymbols[0];
        }

        int code = 0;
        int first = 0;
        int index = 0;

        for (int len = 1; len <= _maxBits; len++)
        {
            code = (code << 1) | reader.ReadBit();
            int count = _blCount[len];
            if (code - first < count)
            {
                return _sortedSymbols[index + (code - first)];
            }

            index += count;
            first = (first + count) << 1;
        }

        throw new SarcException(SarcErrorCode.E_CODE, "Invalid Huffman code encountered in bitstream.");
    }
}
