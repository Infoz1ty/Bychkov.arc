using System.Text;

namespace SmartSecureArchiver.Core.Security.Attack;

/// <summary>
/// Частотна модель n-грам (монограми, біграми, триграми) для оцінки правдоподібності
/// відкритого тексту під час генетичного криптоаналізу слабких шифрів (Issue #38).
/// </summary>
public sealed class NgramFrequencyScorer
{
    private const double DefaultFloor = -11.5;

    private const string BuiltInEnglishCorpus =
        "In computer science and cryptography, data compression and authenticated encryption serve complementary roles. " +
        "When information is compressed before encryption, statistical patterns, repeated phrases, and structural regularities " +
        "are replaced by compact variable length codes and backward references in a sliding window. " +
        "A good compression algorithm removes predictable redundancy so that the compressed stream has high entropy. " +
        "Afterward, a modern block cipher operating in counter mode transforms the compressed payload into pseudorandom ciphertext, " +
        "while a message authentication code verifies the integrity and authenticity of both the header and the encrypted payload " +
        "in constant time before any decryption is attempted. " +
        "By contrast, classical substitution ciphers, Vigenere polyalphabetic ciphers, and short repeating key exclusive or schemes " +
        "leave statistical fingerprints of the underlying natural language directly inside the ciphertext. " +
        "Letter frequencies, common bigrams such as th, he, in, er, an, re, on, at, en, nd, ti, es, or, te, of, ed, is, it, al, ar, " +
        "st, to, nt, ng, se, ha, as, ou, io, le, ve, co, me, de, hi, ri, ro, ic, ne, ea, ra, ce, and frequent trigrams such as " +
        "the, and, ing, her, hat, his, tha, ere, for, ent, ion, ter, was, you, ith, ver, all, wit, thi, tio, allow an attacker " +
        "using a genetic algorithm or hill climbing search to score candidate plaintexts and recover the secret key automatically. " +
        "Every secure archive format must validate lengths, magic bytes, authentication tags, file names, and checksums atomically " +
        "so that partial or corrupted data never overwrites valid files on disk. " +
        "Dynamic programming for the knapsack problem, multilayer perceptrons for file classification, and genetic optimization " +
        "of compression parameters work together inside the pipeline to maximize both compression ratio and execution speed.";

    private readonly Dictionary<char, double> _monograms;
    private readonly Dictionary<(char, char), double> _bigrams;
    private readonly Dictionary<(char, char, char), double> _trigrams;
    private readonly double _monogramFloor;
    private readonly double _bigramFloor;
    private readonly double _trigramFloor;

    private NgramFrequencyScorer(
        Dictionary<char, double> monograms,
        Dictionary<(char, char), double> bigrams,
        Dictionary<(char, char, char), double> trigrams,
        double monogramFloor,
        double bigramFloor,
        double trigramFloor)
    {
        _monograms = monograms;
        _bigrams = bigrams;
        _trigrams = trigrams;
        _monogramFloor = monogramFloor;
        _bigramFloor = bigramFloor;
        _trigramFloor = trigramFloor;
    }

    /// <summary>
    /// Навчає модель частот монограм, біграм і триграм безпосередньо на текстовому корпусі.
    /// </summary>
    public static NgramFrequencyScorer TrainFromText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        string normalized = NormalizeForNgrams(text);
        var monoCounts = new Dictionary<char, long>();
        var biCounts = new Dictionary<(char, char), long>();
        var triCounts = new Dictionary<(char, char, char), long>();

        long monoTotal = 0;
        long biTotal = 0;
        long triTotal = 0;

        for (int i = 0; i < normalized.Length; i++)
        {
            char c0 = normalized[i];
            monoCounts[c0] = monoCounts.GetValueOrDefault(c0) + 1;
            monoTotal++;

            if (i + 1 < normalized.Length)
            {
                var bg = (c0, normalized[i + 1]);
                biCounts[bg] = biCounts.GetValueOrDefault(bg) + 1;
                biTotal++;
            }

            if (i + 2 < normalized.Length)
            {
                var tg = (c0, normalized[i + 1], normalized[i + 2]);
                triCounts[tg] = triCounts.GetValueOrDefault(tg) + 1;
                triTotal++;
            }
        }

        double monoFloor = Math.Log(0.05 / Math.Max(1, monoTotal));
        double biFloor = Math.Log(0.05 / Math.Max(1, biTotal));
        double triFloor = Math.Log(0.05 / Math.Max(1, triTotal));

        var monograms = monoCounts.ToDictionary(kv => kv.Key, kv => Math.Log((double)kv.Value / monoTotal));
        var bigrams = biCounts.ToDictionary(kv => kv.Key, kv => Math.Log((double)kv.Value / biTotal));
        var trigrams = triCounts.ToDictionary(kv => kv.Key, kv => Math.Log((double)kv.Value / triTotal));

        return new NgramFrequencyScorer(monograms, bigrams, trigrams, monoFloor, biFloor, triFloor);
    }

    /// <summary>
    /// Навчає модель n-грам на переліку текстових файлів (наприклад, на текстах корпусу).
    /// </summary>
    public static NgramFrequencyScorer TrainFromFiles(IEnumerable<string> filePaths)
    {
        ArgumentNullException.ThrowIfNull(filePaths);

        var sb = new StringBuilder();
        foreach (string path in filePaths)
        {
            if (File.Exists(path))
            {
                sb.AppendLine(File.ReadAllText(path, Encoding.UTF8));
            }
        }

        return sb.Length > 0 ? TrainFromText(sb.ToString()) : CreateDefaultEnglish();
    }

    /// <summary>
    /// Повертає вбудовану частотну модель для англійської мови (монограми, біграми, триграми).
    /// </summary>
    public static NgramFrequencyScorer CreateDefaultEnglish() => TrainFromText(BuiltInEnglishCorpus);

    /// <summary>
    /// Повертає вбудовану частотну модель для української мови (монограми та часті біграми/триграми).
    /// </summary>
    public static NgramFrequencyScorer CreateDefaultUkrainian()
    {
        var monoWeights = new Dictionary<char, double>
        {
            [' '] = 0.155,
            ['О'] = 0.088, ['А'] = 0.072, ['Н'] = 0.064, ['И'] = 0.057, ['І'] = 0.055,
            ['В'] = 0.049, ['Т'] = 0.048, ['Е'] = 0.045, ['Р'] = 0.043, ['С'] = 0.039,
            ['К'] = 0.033, ['М'] = 0.030, ['У'] = 0.029, ['Л'] = 0.028, ['Д'] = 0.028,
            ['П'] = 0.026, ['З'] = 0.021, ['Я'] = 0.019, ['Б'] = 0.016, ['Г'] = 0.014,
            ['Ч'] = 0.013, ['Й'] = 0.011, ['Х'] = 0.011, ['Ж'] = 0.009, ['Ю'] = 0.008,
            ['Ш'] = 0.007, ['Ц'] = 0.006, ['Ї'] = 0.006, ['Є'] = 0.005, ['Щ'] = 0.004,
            ['Ф'] = 0.003, ['Ь'] = 0.016, ['Ґ'] = 0.001
        };

        var topBigrams = new (string Pair, double Weight)[]
        {
            ("НА", 0.022), ("СТ", 0.020), ("ТА", 0.018), ("ПО", 0.017), ("РО", 0.016),
            ("ОВ", 0.016), ("ЕН", 0.015), ("НО", 0.015), ("КО", 0.014), ("АН", 0.014),
            ("ВА", 0.013), ("РА", 0.013), ("ПР", 0.013), ("ОР", 0.012), ("НИ", 0.012),
            ("ТИ", 0.012), ("ТО", 0.011), ("АТ", 0.011), ("ІВ", 0.010), ("НЯ", 0.010),
            ("О ", 0.025), ("А ", 0.022), ("И ", 0.018), (" П", 0.018), (" В", 0.016),
            (" С", 0.015), (" Н", 0.014), (" З", 0.013), ("Я ", 0.013), ("І ", 0.013)
        };

        var topTrigrams = new (string Tri, double Weight)[]
        {
            ("ННЯ", 0.014), ("ПРО", 0.010), ("СТА", 0.009), ("ОВА", 0.009), ("АТИ", 0.008),
            ("СТІ", 0.008), ("ПЕР", 0.007), ("ОГО", 0.007), ("АЛЬ", 0.007), ("НИЙ", 0.007),
            (" ПО", 0.011), (" ПР", 0.010), (" НА", 0.010), ("НЯ ", 0.010), ("ТИ ", 0.009)
        };

        var monograms = monoWeights.ToDictionary(kv => kv.Key, kv => Math.Log(kv.Value));
        var bigrams = topBigrams.ToDictionary(x => (x.Pair[0], x.Pair[1]), x => Math.Log(x.Weight));
        var trigrams = topTrigrams.ToDictionary(x => (x.Tri[0], x.Tri[1], x.Tri[2]), x => Math.Log(x.Weight));

        return new NgramFrequencyScorer(monograms, bigrams, trigrams, DefaultFloor, DefaultFloor, DefaultFloor);
    }

    /// <summary>
    /// Обчислює позитивну оцінку відповідності тексту моделі n-грам (зсунутий log-likelihood відносно порогу):
    /// чим більше відомих монограм, біграм і триграм присутні у тексті, тим вища оцінка.
    /// </summary>
    public double ScoreText(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return double.NegativeInfinity;
        }

        string norm = NormalizeForNgrams(text);
        if (norm.Length == 0)
        {
            return 0.0;
        }

        double monoScore = 0.0;
        double biScore = 0.0;
        double triScore = 0.0;

        for (int i = 0; i < norm.Length; i++)
        {
            char c0 = norm[i];
            double mLog = _monograms.GetValueOrDefault(c0, _monogramFloor);
            monoScore += Math.Max(0.0, mLog - _monogramFloor);

            if (i + 1 < norm.Length)
            {
                double bLog = _bigrams.GetValueOrDefault((c0, norm[i + 1]), _bigramFloor);
                biScore += Math.Max(0.0, bLog - _bigramFloor);
            }

            if (i + 2 < norm.Length)
            {
                double tLog = _trigrams.GetValueOrDefault((c0, norm[i + 1], norm[i + 2]), _trigramFloor);
                triScore += Math.Max(0.0, tLog - _trigramFloor);
            }
        }

        return (0.15 * monoScore) + (0.45 * biScore) + (0.40 * triScore);
    }

    /// <summary>
    /// Оцінює розшифрований потік байтів (для атаки на повторюваний XOR):
    /// штрафує керуючі та не-ASCII байти і нагороджує друкований текст із високою оцінкою n-грам.
    /// </summary>
    public double ScoreBytesForXor(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return double.NegativeInfinity;
        }

        int printableAscii = 0;
        int spaceOrLetter = 0;
        int nonPrintableOrBinary = 0;

        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            if (b is (>= 32 and <= 126) or (byte)'\n' or (byte)'\r' or (byte)'\t')
            {
                printableAscii++;
                if (b == ' ' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'))
                {
                    spaceOrLetter++;
                }
            }
            else
            {
                nonPrintableOrBinary++;
            }
        }

        string decoded = DecodeAsciiLossy(bytes);
        double ngramScore = ScoreText(decoded);
        return ngramScore + (spaceOrLetter * 2.0) + (printableAscii * 0.5) - (nonPrintableOrBinary * 30.0);
    }

    /// <summary>
    /// Повертає логарифм частоти літери алфавіту (для ініціалізації та частотного аналізу).
    /// </summary>
    public double GetMonogramLogProbability(char upperChar) =>
        _monograms.GetValueOrDefault(char.ToUpperInvariant(upperChar), _monogramFloor);

    private static string NormalizeForNgrams(string text)
    {
        var sb = new StringBuilder(text.Length);
        bool prevSpace = false;

        foreach (char ch in text)
        {
            if (char.IsLetter(ch))
            {
                sb.Append(char.ToUpperInvariant(ch));
                prevSpace = false;
            }
            else if (char.IsWhiteSpace(ch))
            {
                if (!prevSpace && sb.Length > 0)
                {
                    sb.Append(' ');
                    prevSpace = true;
                }
            }
        }

        return sb.ToString();
    }

    private static string DecodeAsciiLossy(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length);
        foreach (byte b in bytes)
        {
            if (b is (>= 32 and <= 126) or (byte)'\n' or (byte)'\r' or (byte)'\t')
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append(' ');
            }
        }

        return sb.ToString();
    }
}
