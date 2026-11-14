namespace SmartSecureArchiver.Core.Compression;

/// <summary>
/// Власна реалізація бінарної мінімальної купи (Priority Queue) для побудови дерев Гаффмана (Зріз 1, Issue #15).
/// Усі операції вставки (Push) та вилучення мінімуму (Pop) виконуються за O(log n).
/// </summary>
public sealed class MinHeap<T> where T : IComparable<T>
{
    private T[] _items;
    private int _count;

    public int Count => _count;

    public MinHeap(int capacity = 16)
    {
        if (capacity < 1)
        {
            capacity = 16;
        }

        _items = new T[capacity];
    }

    public void Push(T item)
    {
        if (_count == _items.Length)
        {
            Array.Resize(ref _items, _items.Length * 2);
        }

        _items[_count] = item;
        SiftUp(_count);
        _count++;
    }

    public T Peek()
    {
        if (_count == 0)
        {
            throw new InvalidOperationException("MinHeap is empty.");
        }

        return _items[0];
    }

    public T Pop()
    {
        if (_count == 0)
        {
            throw new InvalidOperationException("MinHeap is empty.");
        }

        T min = _items[0];
        _count--;

        if (_count > 0)
        {
            _items[0] = _items[_count];
            _items[_count] = default!;
            SiftDown(0);
        }
        else
        {
            _items[0] = default!;
        }

        return min;
    }

    private void SiftUp(int index)
    {
        while (index > 0)
        {
            int parent = (index - 1) >> 1;
            if (_items[index].CompareTo(_items[parent]) >= 0)
            {
                break;
            }

            (_items[index], _items[parent]) = (_items[parent], _items[index]);
            index = parent;
        }
    }

    private void SiftDown(int index)
    {
        while (true)
        {
            int left = (index << 1) + 1;
            if (left >= _count)
            {
                break;
            }

            int right = left + 1;
            int smallest = (right < _count && _items[right].CompareTo(_items[left]) < 0)
                ? right
                : left;

            if (_items[index].CompareTo(_items[smallest]) <= 0)
            {
                break;
            }

            (_items[index], _items[smallest]) = (_items[smallest], _items[index]);
            index = smallest;
        }
    }
}
