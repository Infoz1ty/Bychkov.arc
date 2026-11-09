namespace SmartSecureArchiver.Core.Format;

public sealed record ArchiveFileInfo(string RelativePath, long OriginalSize, uint Crc32);
