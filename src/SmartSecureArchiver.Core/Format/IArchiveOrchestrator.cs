namespace SmartSecureArchiver.Core.Format;

public interface IArchiveOrchestrator
{
    /// <summary>
    /// Наскрізне створення архіву: аналіз -> пакування -> стиснення -> шифрування -> запис томів.
    /// </summary>
    void CreateArchive(IEnumerable<string> filePaths, string outputArchivePath, string password, int maxVolumeBytes);

    /// <summary>
    /// Наскрізне розархівування: збір томів -> HMAC check -> розшифрування -> декомпресія -> перевірка CRC32.
    /// </summary>
    void ExtractArchive(string archivePath, string outputDirectory, string password);
}
