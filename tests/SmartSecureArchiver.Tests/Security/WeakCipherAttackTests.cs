using System.Text;
using SmartSecureArchiver.Core.Security.Attack;

namespace SmartSecureArchiver.Tests.Security;

public class WeakCipherAttackTests
{
    private const string EnglishSampleText =
        "The smart secure archiver combines Lempel Ziv compression with canonical Huffman coding " +
        "and authenticated encryption using AES counter mode with HMAC SHA256 verification. " +
        "When data is compressed before encryption, statistical redundancy is removed effectively, " +
        "which improves storage efficiency and makes cryptanalysis significantly harder than classical ciphers. " +
        "In contrast, weak classical schemes preserve language frequency patterns across n-grams and can be broken.";

    [Fact]
    public void AttackVigenere_RecoversKeyAndPlaintextFromNgramFrequencies()
    {
        const string secretKey = "KEY";
        string ciphertext = WeakCiphers.EncryptVigenere(EnglishSampleText, secretKey);

        var attacker = new WeakCipherGeneticAttacker(NgramFrequencyScorer.CreateDefaultEnglish(), seed: 2001);
        CipherAttackResult result = attacker.AttackVigenere(ciphertext, maxKeyLength: 8, populationSize: 50, generations: 60);

        Assert.Equal(secretKey, result.RecoveredKey);
        Assert.Equal(EnglishSampleText, result.RecoveredPlaintext);
    }

    [Fact]
    public void AttackVigenere_UkrainianCorpusText_RecoversKeyAndPlaintext()
    {
        string corpusDir = FindRepoDirectory(Path.Combine("team", "corpus"));
        string ukrTrainingText = File.ReadAllText(Path.Combine(corpusDir, "f0014.txt"), Encoding.UTF8);
        string ukrTarget = File.ReadAllText(Path.Combine(corpusDir, "f0000.txt"), Encoding.UTF8)[..600];

        const string secretKey = "КЛЮЧ";
        string ciphertext = WeakCiphers.EncryptVigenere(ukrTarget, secretKey, WeakCiphers.UkrainianAlphabet);

        var scorer = NgramFrequencyScorer.TrainFromText(ukrTrainingText);
        var attacker = new WeakCipherGeneticAttacker(scorer, seed: 2001);
        CipherAttackResult result = attacker.AttackVigenere(
            ciphertext,
            alphabet: WeakCiphers.UkrainianAlphabet,
            maxKeyLength: 8,
            populationSize: 50,
            generations: 60);

        Assert.Equal(secretKey, result.RecoveredKey);
        Assert.Equal(ukrTarget, result.RecoveredPlaintext);
    }

    [Fact]
    public void AttackSubstitution_RecoversHighAccuracyPlaintextViaGaAndNgrams()
    {
        const string subAlphabet = "QWERTYUIOPASDFGHJKLZXCVBNM";
        string ciphertext = WeakCiphers.EncryptSubstitution(EnglishSampleText, subAlphabet);

        var attacker = new WeakCipherGeneticAttacker(NgramFrequencyScorer.CreateDefaultEnglish(), seed: 2001);
        CipherAttackResult result = attacker.AttackSubstitution(ciphertext, populationSize: 60, generations: 80);

        Assert.Equal(26, result.RecoveredKey.Length);
        Assert.Equal(26, result.RecoveredKey.Distinct().Count());

        int matchingChars = 0;
        for (int i = 0; i < EnglishSampleText.Length; i++)
        {
            if (result.RecoveredPlaintext[i] == EnglishSampleText[i])
            {
                matchingChars++;
            }
        }

        double accuracy = (double)matchingChars / EnglishSampleText.Length;
        Assert.True(accuracy >= 0.90, $"Expected >= 90% character recovery accuracy, got {accuracy:P2}.");
    }

    [Fact]
    public void AttackRepeatingXor_RecoversShortKeyAndPlaintext()
    {
        byte[] plainBytes = Encoding.ASCII.GetBytes(EnglishSampleText);
        byte[] keyBytes = Encoding.ASCII.GetBytes("SARC");
        byte[] ciphertext = WeakCiphers.ApplyRepeatingXor(plainBytes, keyBytes);

        var attacker = new WeakCipherGeneticAttacker(NgramFrequencyScorer.CreateDefaultEnglish(), seed: 2001);
        XorAttackResult result = attacker.AttackRepeatingXor(ciphertext, maxKeyLength: 8, populationSize: 50, generations: 50);

        Assert.Equal(keyBytes, result.RecoveredKeyBytes);
        Assert.Equal(plainBytes, result.RecoveredPlaintextBytes);
    }

    private static string FindRepoDirectory(string relativePath)
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, relativePath);
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException($"Could not locate '{relativePath}'.");
    }
}
