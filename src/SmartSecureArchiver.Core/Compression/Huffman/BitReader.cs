using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Побітовий зчитувач у порядку MSB-first (старший біт 0x80 читається першим)
/// згідно з розділом 0 та розділом 3 FORMAT_SPEC_P2.md (Зріз 1, Issue #19).
/// Контролює межі бітового потоку та нульове доповнення останнього байта (E_CODE).
/// </summary>
public ref struct BitReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _byteIndex;
    private int _bitIndex; // 0..7, де 0 відповідає старшому біту (0x80)
    private readonly int _maxBits;
    private int _bitsRead;

    public int BitsRead => _bitsRead;
    public int TotalAvailableBits => _maxBits;
    public bool IsAtEnd => _bitsRead >= _maxBits;

    public BitReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _byteIndex = 0;
        _bitIndex = 0;
        _maxBits = data.Length * 8;
        _bitsRead = 0;
    }

    public BitReader(ReadOnlySpan<byte> data, int exactBitCount)
    {
        if (exactBitCount < 0 || exactBitCount > data.Length * 8)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Invalid bit count for bitstream.");
        }

        _data = data;
        _byteIndex = 0;
        _bitIndex = 0;
        _maxBits = exactBitCount;
        _bitsRead = 0;
    }

    /// <summary>
    /// Зчитує один біт (0 або 1) у порядку MSB-first.
    /// Якщо потік вичерпано, кидає SarcException(E_CODE).
    /// </summary>
    public int ReadBit()
    {
        if (_bitsRead >= _maxBits || _byteIndex >= _data.Length)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Unexpected end of Huffman bitstream.");
        }

        int bit = (_data[_byteIndex] >> (7 - _bitIndex)) & 1;
        _bitIndex++;
        _bitsRead++;

        if (_bitIndex == 8)
        {
            _bitIndex = 0;
            _byteIndex++;
        }

        return bit;
    }

    /// <summary>
    /// Зчитує count бітів (0..32) старшим бітом уперед (MSB-first).
    /// </summary>
    public uint ReadBits(int count)
    {
        if (count is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Bit count must be in range 0..32.");
        }

        uint value = 0;
        for (int i = 0; i < count; i++)
        {
            value = (value << 1) | (uint)ReadBit();
        }

        return value;
    }

    /// <summary>
    /// Перевіряє після завершення декодування всіх токенів блоку:
    /// 1) що всі біти доповнення в поточному останньому байті дорівнюють 0;
    /// 2) що після останнього байта немає зайвих непрочитаних байтів у stream.
    /// При порушенні кидає SarcException(E_CODE) згідно з п. 0.2 та п. 3.1 FORMAT_SPEC_P2.md.
    /// </summary>
    public void VerifyZeroPaddingAndEndOrThrow()
    {
        if (_bitIndex > 0)
        {
            int remainingBits = 8 - _bitIndex;
            byte paddingMask = (byte)((1 << remainingBits) - 1);
            if ((_data[_byteIndex] & paddingMask) != 0)
            {
                throw new SarcException(SarcErrorCode.E_CODE, "Non-zero padding bits in the last byte of compressed bitstream.");
            }

            if (_byteIndex + 1 != _data.Length)
            {
                throw new SarcException(SarcErrorCode.E_CODE, "Trailing unconsumed bytes found after compressed bitstream.");
            }
        }
        else if (_byteIndex != _data.Length)
        {
            throw new SarcException(SarcErrorCode.E_CODE, "Trailing unconsumed bytes found after compressed bitstream.");
        }
    }
}
