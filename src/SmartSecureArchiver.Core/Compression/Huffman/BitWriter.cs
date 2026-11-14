namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Побітовий записувач у порядку MSB-first (старший біт іде в 0x80 першого байта)
/// згідно з розділом 0 та розділом 3 FORMAT_SPEC_P2.md (Зріз 1, Issue #19).
/// Останній неповний байт доповнюється нульовими бітами до межі байта.
/// </summary>
public sealed class BitWriter
{
    private byte[] _buffer;
    private int _byteLength;
    private byte _currentByte;
    private int _bitsInCurrentByte;
    private int _totalBitsWritten;

    public int TotalBitsWritten => _totalBitsWritten;

    public int ByteLength => _bitsInCurrentByte > 0 ? _byteLength + 1 : _byteLength;

    public BitWriter(int initialCapacityBytes = 256)
    {
        if (initialCapacityBytes < 16)
        {
            initialCapacityBytes = 16;
        }

        _buffer = new byte[initialCapacityBytes];
    }

    /// <summary>
    /// Записує один біт (0 або 1) у позицію (7 - _bitsInCurrentByte) поточного байта.
    /// </summary>
    public void WriteBit(int bit)
    {
        if ((bit & 1) != 0)
        {
            _currentByte |= (byte)(1 << (7 - _bitsInCurrentByte));
        }

        _bitsInCurrentByte++;
        _totalBitsWritten++;

        if (_bitsInCurrentByte == 8)
        {
            FlushCurrentByte();
        }
    }

    /// <summary>
    /// Записує count молодших бітів значення value старшим бітом уперед (MSB-first).
    /// </summary>
    public void WriteBits(uint value, int count)
    {
        if (count is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Bit count must be in range 0..32.");
        }

        for (int shift = count - 1; shift >= 0; shift--)
        {
            int bit = (int)((value >> shift) & 1u);
            WriteBit(bit);
        }
    }

    /// <summary>
    /// Завершує поточний неповний байт (доповнюючи молодші біти нулями) і повертає сформований масив байтів.
    /// </summary>
    public byte[] ToArray()
    {
        int finalLength = ByteLength;
        byte[] result = new byte[finalLength];
        Array.Copy(_buffer, 0, result, 0, _byteLength);

        if (_bitsInCurrentByte > 0)
        {
            result[_byteLength] = _currentByte;
        }

        return result;
    }

    private void FlushCurrentByte()
    {
        if (_byteLength == _buffer.Length)
        {
            Array.Resize(ref _buffer, _buffer.Length * 2);
        }

        _buffer[_byteLength++] = _currentByte;
        _currentByte = 0;
        _bitsInCurrentByte = 0;
    }
}
