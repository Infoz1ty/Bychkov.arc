namespace SmartSecureArchiver.Core.Analysis;

public interface IFeatureExtractor
{
    /// <summary>
    /// Обчислює вектор із 6 статистичних ознак для вхідного файлу.
    /// </summary>
    FileFeatures Extract(ReadOnlySpan<byte> fileData);
}
