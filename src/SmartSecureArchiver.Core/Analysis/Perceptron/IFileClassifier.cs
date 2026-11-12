namespace SmartSecureArchiver.Core.Analysis;

public interface IFileClassifier
{
    /// <summary>
    /// Класифікує файл на один із 7 типів (0..6) за вектором ознак за допомогою багатошарового перцептрона (MLP).
    /// </summary>
    byte Classify(FileFeatures features);

    /// <summary>
    /// Визначає, чи доцільно стискати файл (повертає false для класу 5 «вже стиснуте»
    /// або при перевищенні порогу ентропії noCompressionEntropyThreshold для випадкового шуму).
    /// </summary>
    bool ShouldCompress(byte fileClass, FileFeatures features, double noCompressionEntropyThreshold = 7.95);
}
