using System.Text;

namespace SmartSecureArchiver.Core.Security.Attack;

/// <summary>
/// Реалізація класичних слабких шифрів (Віженер, моноалфавітна підстановка, короткий XOR)
/// для моделювання атак у модулі криптоаналізу (Issue #38, п. 3.7 ТЗ).
/// </summary>
public static class WeakCiphers
{
    public const string EnglishAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string UkrainianAlphabet = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";

    public static string EncryptVigenere(string plaintext, string key, string alphabet = EnglishAlphabet) =>
        TransformVigenere(plaintext, key, alphabet, encrypt: true);

    public static string DecryptVigenere(string ciphertext, string key, string alphabet = EnglishAlphabet) =>
        TransformVigenere(ciphertext, key, alphabet, encrypt: false);

    public static string EncryptSubstitution(string plaintext, string substitutionAlphabet, string alphabet = EnglishAlphabet) =>
        TransformSubstitution(plaintext, substitutionAlphabet, alphabet, encrypt: true);

    public static string DecryptSubstitution(string ciphertext, string substitutionAlphabet, string alphabet = EnglishAlphabet) =>
        TransformSubstitution(ciphertext, substitutionAlphabet, alphabet, encrypt: false);

    public static byte[] ApplyRepeatingXor(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("XOR key cannot be empty.", nameof(key));
        }

        byte[] output = new byte[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (byte)(input[i] ^ key[i % key.Length]);
        }

        return output;
    }

    private static string TransformVigenere(string input, string key, string alphabet, bool encrypt)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentException.ThrowIfNullOrEmpty(alphabet);

        var indexMap = BuildIndexMap(alphabet);
        int m = alphabet.Length;
        int[] keyShifts = new int[key.Length];

        for (int i = 0; i < key.Length; i++)
        {
            char kc = char.ToUpperInvariant(key[i]);
            if (!indexMap.TryGetValue(kc, out int idx))
            {
                throw new ArgumentException($"Key character '{key[i]}' is not in the specified alphabet.", nameof(key));
            }

            keyShifts[i] = idx;
        }

        var sb = new StringBuilder(input.Length);
        int keyPos = 0;

        foreach (char ch in input)
        {
            char upper = char.ToUpperInvariant(ch);
            if (indexMap.TryGetValue(upper, out int plainIdx))
            {
                int shift = keyShifts[keyPos % keyShifts.Length];
                int outIdx = encrypt
                    ? (plainIdx + shift) % m
                    : (plainIdx - shift + m) % m;

                char mappedUpper = alphabet[outIdx];
                sb.Append(char.IsLower(ch) ? char.ToLowerInvariant(mappedUpper) : mappedUpper);
                keyPos++;
            }
            else
            {
                sb.Append(ch);
            }
        }

        return sb.ToString();
    }

    private static string TransformSubstitution(string input, string substitutionAlphabet, string alphabet, bool encrypt)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentException.ThrowIfNullOrEmpty(substitutionAlphabet);
        ArgumentException.ThrowIfNullOrEmpty(alphabet);

        if (substitutionAlphabet.Length != alphabet.Length)
        {
            throw new ArgumentException("Substitution alphabet length must match base alphabet length.", nameof(substitutionAlphabet));
        }

        var map = new Dictionary<char, char>(alphabet.Length);
        for (int i = 0; i < alphabet.Length; i++)
        {
            char a = char.ToUpperInvariant(alphabet[i]);
            char s = char.ToUpperInvariant(substitutionAlphabet[i]);
            if (encrypt)
            {
                map[a] = s;
            }
            else
            {
                map[s] = a;
            }
        }

        var sb = new StringBuilder(input.Length);
        foreach (char ch in input)
        {
            char upper = char.ToUpperInvariant(ch);
            if (map.TryGetValue(upper, out char mapped))
            {
                sb.Append(char.IsLower(ch) ? char.ToLowerInvariant(mapped) : mapped);
            }
            else
            {
                sb.Append(ch);
            }
        }

        return sb.ToString();
    }

    private static Dictionary<char, int> BuildIndexMap(string alphabet)
    {
        var map = new Dictionary<char, int>(alphabet.Length);
        for (int i = 0; i < alphabet.Length; i++)
        {
            map[char.ToUpperInvariant(alphabet[i])] = i;
        }

        return map;
    }
}
