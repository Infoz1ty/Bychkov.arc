using System.Text;

namespace SmartSecureArchiver.Core.Security.Attack;

/// <summary>
/// Результат атаки генетичним алгоритмом на класичний шифр (Віженер або підстановка).
/// </summary>
public sealed record CipherAttackResult(
    string CipherName,
    string RecoveredKey,
    string RecoveredPlaintext,
    double FitnessScore,
    int GenerationsRun
);

/// <summary>
/// Результат атаки генетичним алгоритмом на шифр XOR із коротким повторюваним ключем.
/// </summary>
public sealed record XorAttackResult(
    byte[] RecoveredKeyBytes,
    string RecoveredKeyHex,
    string RecoveredKeyAscii,
    byte[] RecoveredPlaintextBytes,
    double FitnessScore,
    int GenerationsRun
);

/// <summary>
/// Генетичний криптоаналіз слабких шифрів за частотами n-грам (Issue #38, п. 3.7 п. 1 ТЗ):
/// 1) шифр Віженера (індекс збігу + ГА над ключем);
/// 2) моноалфавітна підстановка (ГА над перестановкою алфавіту з OX1-кросовером та swap-мутацією);
/// 3) XOR із коротким повторюваним ключем (оцінка періоду за відстанню Хеммінга + ГА над байтами ключа).
/// </summary>
public sealed class WeakCipherGeneticAttacker
{
    private readonly NgramFrequencyScorer _scorer;
    private readonly int _seed;

    public WeakCipherGeneticAttacker(NgramFrequencyScorer? scorer = null, int seed = 2001)
    {
        _scorer = scorer ?? NgramFrequencyScorer.CreateDefaultEnglish();
        _seed = seed;
    }

    /// <summary>
    /// Криптоаналіз шифру Віженера генетичним алгоритмом за частотами n-грам.
    /// </summary>
    public CipherAttackResult AttackVigenere(
        string ciphertext,
        string alphabet = WeakCiphers.EnglishAlphabet,
        int maxKeyLength = 12,
        int populationSize = 60,
        int generations = 80,
        int? knownKeyLength = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(ciphertext);
        ArgumentException.ThrowIfNullOrEmpty(alphabet);

        var rng = new Random(_seed);
        List<int> candidateLengths = knownKeyLength.HasValue
            ? [knownKeyLength.Value]
            : EstimateVigenereKeyLengths(ciphertext, alphabet, maxKeyLength, topK: 3);

        CipherAttackResult? globalBest = null;

        foreach (int keyLength in candidateLengths)
        {
            CipherAttackResult candidate = RunVigenereGa(
                ciphertext,
                alphabet,
                keyLength,
                populationSize,
                generations,
                rng);

            if (globalBest is null || candidate.FitnessScore > globalBest.FitnessScore)
            {
                globalBest = candidate;
            }
        }

        return globalBest!;
    }

    /// <summary>
    /// Криптоаналіз моноалфавітного шифру підстановки генетичним алгоритмом за частотами біграм/триграм.
    /// </summary>
    public CipherAttackResult AttackSubstitution(
        string ciphertext,
        string alphabet = WeakCiphers.EnglishAlphabet,
        int populationSize = 80,
        int generations = 150)
    {
        ArgumentException.ThrowIfNullOrEmpty(ciphertext);
        ArgumentException.ThrowIfNullOrEmpty(alphabet);

        var rng = new Random(_seed ^ 0x13572468);
        int n = alphabet.Length;

        // Початкова частотна підказка: впорядкувати літери шифротексту та алфавіту за частотою
        int[] freqSeedKey = BuildFrequencySeedPermutation(ciphertext, alphabet);

        var population = new List<(int[] Perm, double Score)>(populationSize);
        population.Add((freqSeedKey, ScoreSubstitution(ciphertext, freqSeedKey, alphabet)));

        for (int i = 1; i < populationSize; i++)
        {
            int[] perm = (int[])freqSeedKey.Clone();
            int swaps = i < populationSize / 2 ? rng.Next(1, 6) : n;
            for (int s = 0; s < swaps; s++)
            {
                int a = rng.Next(n);
                int b = rng.Next(n);
                (perm[a], perm[b]) = (perm[b], perm[a]);
            }

            population.Add((perm, ScoreSubstitution(ciphertext, perm, alphabet)));
        }

        population.Sort((a, b) => b.Score.CompareTo(a.Score));
        int elitismCount = Math.Max(2, populationSize / 10);

        for (int gen = 1; gen <= generations; gen++)
        {
            var next = new List<(int[] Perm, double Score)>(populationSize);
            for (int e = 0; e < elitismCount; e++)
            {
                next.Add(population[e]);
            }

            while (next.Count < populationSize)
            {
                int[] p1 = SelectTournamentPerm(population, rng);
                int[] p2 = SelectTournamentPerm(population, rng);

                int[] child = rng.NextDouble() < 0.8
                    ? OrderCrossover(p1, p2, rng)
                    : (int[])p1.Clone();

                int mutationSwaps = rng.NextDouble() < 0.7 ? 1 : 2;
                for (int m = 0; m < mutationSwaps; m++)
                {
                    int a = rng.Next(n);
                    int b = rng.Next(n);
                    (child[a], child[b]) = (child[b], child[a]);
                }

                next.Add((child, ScoreSubstitution(ciphertext, child, alphabet)));
            }

            next.Sort((a, b) => b.Score.CompareTo(a.Score));

            // Локальне 2-opt уточнення еліти (гібридний/меметичний ГА для швидкої збіжності на 26!)
            (int[] bestPerm, double bestScore) = RefineSubstitutionElite(ciphertext, next[0].Perm, next[0].Score, alphabet);
            next[0] = (bestPerm, bestScore);
            next.Sort((a, b) => b.Score.CompareTo(a.Score));

            population = next;
        }

        int[] finalPerm = population[0].Perm;
        string recoveredKey = PermutationToAlphabet(finalPerm, alphabet);
        string recoveredPlain = WeakCiphers.DecryptSubstitution(ciphertext, recoveredKey, alphabet);

        return new CipherAttackResult(
            CipherName: "Substitution",
            RecoveredKey: recoveredKey,
            RecoveredPlaintext: recoveredPlain,
            FitnessScore: population[0].Score,
            GenerationsRun: generations);
    }

    /// <summary>
    /// Криптоаналіз шифру XOR із коротким повторюваним ключем за відстанню Хеммінга та ГА за частотами n-грам.
    /// </summary>
    public XorAttackResult AttackRepeatingXor(
        ReadOnlySpan<byte> ciphertext,
        int maxKeyLength = 16,
        int populationSize = 60,
        int generations = 60,
        int? knownKeyLength = null)
    {
        if (ciphertext.IsEmpty)
        {
            throw new ArgumentException("Ciphertext cannot be empty.", nameof(ciphertext));
        }

        byte[] cipherCopy = ciphertext.ToArray();
        var rng = new Random(_seed ^ 0x24681357);

        List<int> candidateLengths = knownKeyLength.HasValue
            ? [knownKeyLength.Value]
            : EstimateXorKeyLengths(cipherCopy, maxKeyLength, topK: 3);

        XorAttackResult? globalBest = null;

        foreach (int keyLength in candidateLengths)
        {
            XorAttackResult candidate = RunXorGa(
                cipherCopy,
                keyLength,
                populationSize,
                generations,
                rng);

            if (globalBest is null || candidate.FitnessScore > globalBest.FitnessScore)
            {
                globalBest = candidate;
            }
        }

        return globalBest!;
    }

    private CipherAttackResult RunVigenereGa(
        string ciphertext,
        string alphabet,
        int keyLength,
        int populationSize,
        int generations,
        Random rng)
    {
        int m = alphabet.Length;

        // Для кожної позиції ключа формуємо топ-3 імовірні зсуви за частотами монограм
        int[][] columnTopShifts = EstimateTopVigenereColumnShifts(ciphertext, alphabet, keyLength, topCount: 3);

        var population = new List<(int[] KeyIdx, double Score)>(populationSize);

        // Перша особина — найкращі монограмні зсуви
        int[] initialSeed = new int[keyLength];
        for (int k = 0; k < keyLength; k++)
        {
            initialSeed[k] = columnTopShifts[k][0];
        }

        population.Add((initialSeed, ScoreVigenere(ciphertext, initialSeed, alphabet)));

        for (int i = 1; i < populationSize; i++)
        {
            int[] keyIdx = new int[keyLength];
            for (int k = 0; k < keyLength; k++)
            {
                keyIdx[k] = i < populationSize / 2
                    ? columnTopShifts[k][rng.Next(columnTopShifts[k].Length)]
                    : rng.Next(m);
            }

            population.Add((keyIdx, ScoreVigenere(ciphertext, keyIdx, alphabet)));
        }

        population.Sort((a, b) => b.Score.CompareTo(a.Score));
        int elitismCount = Math.Max(2, populationSize / 10);

        for (int gen = 1; gen <= generations; gen++)
        {
            var next = new List<(int[] KeyIdx, double Score)>(populationSize);
            for (int e = 0; e < elitismCount; e++)
            {
                next.Add(population[e]);
            }

            while (next.Count < populationSize)
            {
                int[] p1 = SelectTournamentInt(population, rng);
                int[] p2 = SelectTournamentInt(population, rng);

                int[] child = new int[keyLength];
                if (keyLength > 1 && rng.NextDouble() < 0.8)
                {
                    int cut = rng.Next(1, keyLength);
                    for (int k = 0; k < keyLength; k++)
                    {
                        child[k] = k < cut ? p1[k] : p2[k];
                    }
                }
                else
                {
                    p1.CopyTo(child, 0);
                }

                for (int k = 0; k < keyLength; k++)
                {
                    if (rng.NextDouble() < 0.25)
                    {
                        child[k] = rng.NextDouble() < 0.5
                            ? columnTopShifts[k][rng.Next(columnTopShifts[k].Length)]
                            : rng.Next(m);
                    }
                }

                next.Add((child, ScoreVigenere(ciphertext, child, alphabet)));
            }

            next.Sort((a, b) => b.Score.CompareTo(a.Score));
            population = next;
        }

        string bestKey = IndicesToKeyString(population[0].KeyIdx, alphabet);
        string plain = WeakCiphers.DecryptVigenere(ciphertext, bestKey, alphabet);

        return new CipherAttackResult(
            CipherName: "Vigenere",
            RecoveredKey: bestKey,
            RecoveredPlaintext: plain,
            FitnessScore: population[0].Score,
            GenerationsRun: generations);
    }

    private XorAttackResult RunXorGa(
        byte[] ciphertext,
        int keyLength,
        int populationSize,
        int generations,
        Random rng)
    {
        // Для кожної колонки ключа знаходимо топ-4 кандидати байта ключа за часткою друкованих ASCII
        byte[][] columnTopBytes = EstimateTopXorKeyBytes(ciphertext, keyLength, topCount: 4);

        var population = new List<(byte[] Key, double Score)>(populationSize);
        byte[] greedyKey = new byte[keyLength];
        for (int k = 0; k < keyLength; k++)
        {
            greedyKey[k] = columnTopBytes[k][0];
        }

        population.Add((greedyKey, ScoreXor(ciphertext, greedyKey)));

        for (int i = 1; i < populationSize; i++)
        {
            byte[] key = new byte[keyLength];
            for (int k = 0; k < keyLength; k++)
            {
                key[k] = i < (populationSize * 3) / 4
                    ? columnTopBytes[k][rng.Next(columnTopBytes[k].Length)]
                    : (byte)rng.Next(256);
            }

            population.Add((key, ScoreXor(ciphertext, key)));
        }

        population.Sort((a, b) => b.Score.CompareTo(a.Score));
        int elitismCount = Math.Max(2, populationSize / 10);

        for (int gen = 1; gen <= generations; gen++)
        {
            var next = new List<(byte[] Key, double Score)>(populationSize);
            for (int e = 0; e < elitismCount; e++)
            {
                next.Add(population[e]);
            }

            while (next.Count < populationSize)
            {
                byte[] p1 = SelectTournamentByte(population, rng);
                byte[] p2 = SelectTournamentByte(population, rng);

                byte[] child = new byte[keyLength];
                if (keyLength > 1 && rng.NextDouble() < 0.8)
                {
                    int cut = rng.Next(1, keyLength);
                    for (int k = 0; k < keyLength; k++)
                    {
                        child[k] = k < cut ? p1[k] : p2[k];
                    }
                }
                else
                {
                    p1.CopyTo(child, 0);
                }

                for (int k = 0; k < keyLength; k++)
                {
                    if (rng.NextDouble() < 0.25)
                    {
                        child[k] = rng.NextDouble() < 0.65
                            ? columnTopBytes[k][rng.Next(columnTopBytes[k].Length)]
                            : (byte)rng.Next(256);
                    }
                }

                next.Add((child, ScoreXor(ciphertext, child)));
            }

            next.Sort((a, b) => b.Score.CompareTo(a.Score));
            population = next;
        }

        byte[] bestKey = population[0].Key;
        byte[] plainBytes = WeakCiphers.ApplyRepeatingXor(ciphertext, bestKey);
        string asciiKey = new(bestKey.Select(b => b is >= 32 and <= 126 ? (char)b : '.').ToArray());

        return new XorAttackResult(
            RecoveredKeyBytes: bestKey,
            RecoveredKeyHex: Convert.ToHexString(bestKey),
            RecoveredKeyAscii: asciiKey,
            RecoveredPlaintextBytes: plainBytes,
            FitnessScore: population[0].Score,
            GenerationsRun: generations);
    }

    private double ScoreVigenere(string ciphertext, int[] keyIdx, string alphabet)
    {
        string key = IndicesToKeyString(keyIdx, alphabet);
        string candidate = WeakCiphers.DecryptVigenere(ciphertext, key, alphabet);
        return _scorer.ScoreText(candidate);
    }

    private double ScoreSubstitution(string ciphertext, int[] perm, string alphabet)
    {
        string subAlphabet = PermutationToAlphabet(perm, alphabet);
        string candidate = WeakCiphers.DecryptSubstitution(ciphertext, subAlphabet, alphabet);
        return _scorer.ScoreText(candidate);
    }

    private double ScoreXor(byte[] ciphertext, byte[] key)
    {
        byte[] plain = WeakCiphers.ApplyRepeatingXor(ciphertext, key);
        return _scorer.ScoreBytesForXor(plain);
    }

    private (int[] BestPerm, double BestScore) RefineSubstitutionElite(
        string ciphertext,
        int[] elitePerm,
        double eliteScore,
        string alphabet)
    {
        int[] current = (int[])elitePerm.Clone();
        double currentScore = eliteScore;
        int n = current.Length;

        for (int i = 0; i < n - 1; i++)
        {
            for (int j = i + 1; j < n; j++)
            {
                (current[i], current[j]) = (current[j], current[i]);
                double score = ScoreSubstitution(ciphertext, current, alphabet);
                if (score > currentScore)
                {
                    currentScore = score;
                }
                else
                {
                    (current[i], current[j]) = (current[j], current[i]);
                }
            }
        }

        return (current, currentScore);
    }

    private int[] BuildFrequencySeedPermutation(string ciphertext, string alphabet)
    {
        var cipherCounts = new Dictionary<char, int>(alphabet.Length);
        foreach (char c in alphabet)
        {
            cipherCounts[c] = 0;
        }

        foreach (char ch in ciphertext)
        {
            char u = char.ToUpperInvariant(ch);
            if (cipherCounts.ContainsKey(u))
            {
                cipherCounts[u]++;
            }
        }

        char[] cipherByFreq = cipherCounts
            .OrderByDescending(kv => kv.Value)
            .Select(kv => kv.Key)
            .ToArray();

        char[] alphabetByFreq = alphabet
            .OrderByDescending(c => _scorer.GetMonogramLogProbability(c))
            .ToArray();

        var indexMap = new Dictionary<char, int>(alphabet.Length);
        for (int i = 0; i < alphabet.Length; i++)
        {
            indexMap[alphabet[i]] = i;
        }

        // permutation[plainIndex] = cipherIndex
        int[] perm = new int[alphabet.Length];
        for (int rank = 0; rank < alphabet.Length; rank++)
        {
            int plainIdx = indexMap[alphabetByFreq[rank]];
            int cipherIdx = indexMap[cipherByFreq[rank]];
            perm[plainIdx] = cipherIdx;
        }

        return perm;
    }

    private static List<int> EstimateVigenereKeyLengths(string ciphertext, string alphabet, int maxKeyLength, int topK)
    {
        var validLetters = new List<char>(ciphertext.Length);
        var validSet = new HashSet<char>(alphabet);
        foreach (char ch in ciphertext)
        {
            char u = char.ToUpperInvariant(ch);
            if (validSet.Contains(u))
            {
                validLetters.Add(u);
            }
        }

        int cap = Math.Min(maxKeyLength, Math.Max(1, validLetters.Count / 2));
        var scoredLengths = new List<(int Length, double Ioc)>(cap);

        for (int len = 1; len <= cap; len++)
        {
            double sumIoc = 0.0;
            for (int col = 0; col < len; col++)
            {
                var counts = new Dictionary<char, int>();
                int colN = 0;
                for (int i = col; i < validLetters.Count; i += len)
                {
                    char c = validLetters[i];
                    counts[c] = counts.GetValueOrDefault(c) + 1;
                    colN++;
                }

                if (colN > 1)
                {
                    long num = 0;
                    foreach (int count in counts.Values)
                    {
                        num += (long)count * (count - 1);
                    }

                    sumIoc += (double)num / ((double)colN * (colN - 1));
                }
            }

            double avgIoc = sumIoc / len;
            // Легкий пріоритет меншим періодам, щоб уникнути кратних 2L/3L при однаковому IoC
            double penalizedScore = avgIoc - (len * 0.0005);
            scoredLengths.Add((len, penalizedScore));
        }

        return scoredLengths
            .OrderByDescending(x => x.Ioc)
            .Take(topK)
            .Select(x => x.Length)
            .ToList();
    }

    private int[][] EstimateTopVigenereColumnShifts(string ciphertext, string alphabet, int keyLength, int topCount)
    {
        var indexMap = new Dictionary<char, int>(alphabet.Length);
        for (int i = 0; i < alphabet.Length; i++)
        {
            indexMap[alphabet[i]] = i;
        }

        var lettersOnly = new List<int>(ciphertext.Length);
        foreach (char ch in ciphertext)
        {
            if (indexMap.TryGetValue(char.ToUpperInvariant(ch), out int idx))
            {
                lettersOnly.Add(idx);
            }
        }

        int m = alphabet.Length;
        var result = new int[keyLength][];

        for (int col = 0; col < keyLength; col++)
        {
            var shiftScores = new List<(int Shift, double Score)>(m);
            for (int shift = 0; shift < m; shift++)
            {
                double score = 0.0;
                for (int i = col; i < lettersOnly.Count; i += keyLength)
                {
                    int plainIdx = (lettersOnly[i] - shift + m) % m;
                    score += _scorer.GetMonogramLogProbability(alphabet[plainIdx]);
                }

                shiftScores.Add((shift, score));
            }

            result[col] = shiftScores
                .OrderByDescending(x => x.Score)
                .Take(Math.Min(topCount, m))
                .Select(x => x.Shift)
                .ToArray();
        }

        return result;
    }

    private static List<int> EstimateXorKeyLengths(byte[] ciphertext, int maxKeyLength, int topK)
    {
        int cap = Math.Min(maxKeyLength, Math.Max(1, ciphertext.Length / 4));
        var scores = new List<(int Length, double NormalizedHamming)>(cap);

        for (int len = 1; len <= cap; len++)
        {
            int blocks = Math.Min(6, ciphertext.Length / len);
            if (blocks < 2)
            {
                continue;
            }

            double totalDist = 0.0;
            int pairs = 0;
            for (int b = 0; b < blocks - 1; b++)
            {
                int dist = 0;
                int offsetA = b * len;
                int offsetB = (b + 1) * len;
                for (int i = 0; i < len; i++)
                {
                    dist += int.PopCount(ciphertext[offsetA + i] ^ ciphertext[offsetB + i]);
                }

                totalDist += (double)dist / len;
                pairs++;
            }

            if (pairs > 0)
            {
                scores.Add((len, totalDist / pairs));
            }
        }

        if (scores.Count == 0)
        {
            return [1];
        }

        return scores
            .OrderBy(x => x.NormalizedHamming)
            .Take(topK)
            .Select(x => x.Length)
            .ToList();
    }

    private byte[][] EstimateTopXorKeyBytes(byte[] ciphertext, int keyLength, int topCount)
    {
        var result = new byte[keyLength][];

        for (int col = 0; col < keyLength; col++)
        {
            var candidates = new List<(byte KeyByte, double Score)>(256);
            for (int k = 0; k < 256; k++)
            {
                double score = 0.0;
                for (int i = col; i < ciphertext.Length; i += keyLength)
                {
                    byte plain = (byte)(ciphertext[i] ^ k);
                    if (plain is (>= (byte)'a' and <= (byte)'z') or (>= (byte)'A' and <= (byte)'Z'))
                    {
                        score += 3.0 + (_scorer.GetMonogramLogProbability((char)plain) * 0.25);
                    }
                    else if (plain == (byte)' ')
                    {
                        score += 3.5;
                    }
                    else if (plain is (>= 32 and <= 126) or (byte)'\n' or (byte)'\r' or (byte)'\t')
                    {
                        score += 1.0;
                    }
                    else
                    {
                        score -= 20.0;
                    }
                }

                candidates.Add(((byte)k, score));
            }

            result[col] = candidates
                .OrderByDescending(x => x.Score)
                .Take(topCount)
                .Select(x => x.KeyByte)
                .ToArray();
        }

        return result;
    }

    private static int[] OrderCrossover(int[] parentA, int[] parentB, Random rng)
    {
        int n = parentA.Length;
        int cut1 = rng.Next(n);
        int cut2 = rng.Next(n);
        if (cut1 > cut2)
        {
            (cut1, cut2) = (cut2, cut1);
        }

        int[] child = new int[n];
        Array.Fill(child, -1);
        var used = new bool[n];

        for (int i = cut1; i <= cut2; i++)
        {
            child[i] = parentA[i];
            used[parentA[i]] = true;
        }

        int bPos = 0;
        for (int i = 0; i < n; i++)
        {
            if (child[i] != -1)
            {
                continue;
            }

            while (used[parentB[bPos]])
            {
                bPos++;
            }

            child[i] = parentB[bPos];
            used[parentB[bPos]] = true;
        }

        return child;
    }

    private static int[] SelectTournamentInt(List<(int[] KeyIdx, double Score)> pop, Random rng)
    {
        int best = rng.Next(pop.Count);
        for (int i = 0; i < 2; i++)
        {
            int idx = rng.Next(pop.Count);
            if (pop[idx].Score > pop[best].Score)
            {
                best = idx;
            }
        }

        return pop[best].KeyIdx;
    }

    private static int[] SelectTournamentPerm(List<(int[] Perm, double Score)> pop, Random rng)
    {
        int best = rng.Next(pop.Count);
        for (int i = 0; i < 2; i++)
        {
            int idx = rng.Next(pop.Count);
            if (pop[idx].Score > pop[best].Score)
            {
                best = idx;
            }
        }

        return pop[best].Perm;
    }

    private static byte[] SelectTournamentByte(List<(byte[] Key, double Score)> pop, Random rng)
    {
        int best = rng.Next(pop.Count);
        for (int i = 0; i < 2; i++)
        {
            int idx = rng.Next(pop.Count);
            if (pop[idx].Score > pop[best].Score)
            {
                best = idx;
            }
        }

        return pop[best].Key;
    }

    private static string IndicesToKeyString(int[] indices, string alphabet)
    {
        var sb = new StringBuilder(indices.Length);
        foreach (int idx in indices)
        {
            sb.Append(alphabet[idx]);
        }

        return sb.ToString();
    }

    private static string PermutationToAlphabet(int[] perm, string alphabet)
    {
        var sb = new StringBuilder(perm.Length);
        foreach (int idx in perm)
        {
            sb.Append(alphabet[idx]);
        }

        return sb.ToString();
    }
}
