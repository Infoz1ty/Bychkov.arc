namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Вузол бінарного дерева Гаффмана (Зріз 1, Issue #15).
/// Забезпечує детерміноване порівняння за частотою, а при рівності частот — за найменшим символом піддерева.
/// </summary>
public sealed class HuffmanNode : IComparable<HuffmanNode>
{
    public int Symbol { get; }
    public int Frequency { get; }
    public int MinSymbol { get; }
    public HuffmanNode? Left { get; }
    public HuffmanNode? Right { get; }

    public bool IsLeaf => Left is null && Right is null;

    /// <summary>
    /// Створює листовий вузол дерева Гаффмана.
    /// </summary>
    public HuffmanNode(int symbol, int frequency)
    {
        Symbol = symbol;
        Frequency = frequency;
        MinSymbol = symbol;
    }

    /// <summary>
    /// Створює внутрішній вузол дерева Гаффмана з двох дочірніх піддерев.
    /// </summary>
    public HuffmanNode(HuffmanNode left, HuffmanNode right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        Symbol = -1;
        Frequency = left.Frequency + right.Frequency;
        MinSymbol = Math.Min(left.MinSymbol, right.MinSymbol);
        Left = left;
        Right = right;
    }

    public int CompareTo(HuffmanNode? other)
    {
        if (other is null)
        {
            return 1;
        }

        int freqComparison = Frequency.CompareTo(other.Frequency);
        return freqComparison != 0
            ? freqComparison
            : MinSymbol.CompareTo(other.MinSymbol);
    }
}
