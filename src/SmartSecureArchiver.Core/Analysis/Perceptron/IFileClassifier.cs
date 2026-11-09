namespace SmartSecureArchiver.Core.Analysis;

public interface IFileClassifier
{
    /// <summary>
    /// Класифікує файл на один із 7 типів за вектором ознак за допомогою MLP.
    /// Повертає рекомендовану стратегію: стискати чи пропустити.
    /// </summary>
    int Classify(FileFeatures features);
    bool ShouldCompress(int fileClass);
}
