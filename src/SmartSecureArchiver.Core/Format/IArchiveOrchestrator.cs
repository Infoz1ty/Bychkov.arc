namespace SmartSecureArchiver.Core.Format;

public interface IArchiveOrchestrator
{
    /// <summary>
    /// Наскрізне створення архіву: аналіз -> розбиття на блоки -> стиснення -> пакування в томи -> шифрування -> HMAC -> запис томів.
    /// </summary>
    IReadOnlyList<string> CreateArchive(IEnumerable<string> filePaths, string outputArchivePath, string password, int maxVolumeBytes);

    /// <summary>
    /// Наскрізне розархівування одного тому або серії томів за базовим шляхом.
    /// </summary>
    void ExtractArchive(string archivePath, string outputDirectory, string password);

    /// <summary>
    /// Наскрізне розархівування набору томів (поданих у довільному порядку):
    /// перевірка заголовків -> перевірка HMAC (до розшифрування) -> перевірка повноти набору томів (E_VOLUMES) ->
    /// розшифрування -> декомпресія -> склеювання за (FileName, BlockSeq) -> перевірка CRC32 (E_CRC) -> атомарний запис.
    /// </summary>
    void ExtractArchive(IEnumerable<string> volumePaths, string outputDirectory, string password);
}
