using System.Buffers.Binary;
using System.Text;

namespace SmartSecureArchiver.Core.Format;

/// <summary>
/// Реалізація бінарного серіалізатора та парсера формату SARC v1 (Зріз 1: Issues #41, #42, #44).
/// Усі багатобайтові цілі числа кодуються у форматі Big-Endian через BinaryPrimitives (ADR-02).
/// </summary>
public sealed class SarcFormatHandler : ISarcFormatHandler
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <inheritdoc />
    public void WriteVolumeHeader(
        Span<byte> destination,
        ushort volumeIndex,
        ushort volumeCount,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> nonce,
        uint ciphertextLen)
    {
        if (destination.Length < VolumeHeader.Size)
        {
            throw new ArgumentException($"Destination buffer must be at least {VolumeHeader.Size} bytes.", nameof(destination));
        }

        if (salt.Length != VolumeHeader.SaltSize)
        {
            throw new ArgumentException($"Salt must be exactly {VolumeHeader.SaltSize} bytes.", nameof(salt));
        }

        if (nonce.Length != VolumeHeader.NonceSize)
        {
            throw new ArgumentException($"Nonce must be exactly {VolumeHeader.NonceSize} bytes.", nameof(nonce));
        }

        if (volumeCount == 0 || volumeIndex >= volumeCount)
        {
            throw new ArgumentOutOfRangeException(nameof(volumeIndex), "VolumeIndex must be less than VolumeCount (and VolumeCount >= 1).");
        }

        VolumeHeader.MagicBytes.CopyTo(destination[..4]);
        destination[4] = VolumeHeader.CurrentVersion;
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(5, 2), volumeIndex);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(7, 2), volumeCount);
        salt.CopyTo(destination.Slice(9, VolumeHeader.SaltSize));
        nonce.CopyTo(destination.Slice(25, VolumeHeader.NonceSize));
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(37, 4), ciphertextLen);
    }

    /// <summary>
    /// Створює новий 41-байтний масив заголовка тому у форматі Big-Endian.
    /// </summary>
    public byte[] BuildVolumeHeader(
        ushort volumeIndex,
        ushort volumeCount,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> nonce,
        uint ciphertextLen)
    {
        byte[] header = new byte[VolumeHeader.Size];
        WriteVolumeHeader(header, volumeIndex, volumeCount, salt, nonce, ciphertextLen);
        return header;
    }

    /// <inheritdoc />
    public SarcErrorCode TryParseVolumeHeader(
        ReadOnlySpan<byte> volumeBytes,
        out ushort volumeIndex,
        out ushort volumeCount,
        out byte[] salt,
        out byte[] nonce,
        out uint ciphertextLen)
    {
        volumeIndex = 0;
        volumeCount = 0;
        salt = [];
        nonce = [];
        ciphertextLen = 0;

        // Крок 1 (розділ 4.3 FORMAT_SPEC_P2_2.md): Перевірити довжину тому >= 73 байти (41 + 0 + 32)
        if (volumeBytes.Length < VolumeHeader.MinVolumeSize)
        {
            return SarcErrorCode.E_SHORT;
        }

        // Крок 2: Перевірити magic == "SARC" і version == 1
        if (!volumeBytes[..4].SequenceEqual(VolumeHeader.MagicBytes) ||
            volumeBytes[4] != VolumeHeader.CurrentVersion)
        {
            return SarcErrorCode.E_MAGIC;
        }

        // Крок 3: Прочитати поля заголовка та перевірити точну відповідність фізичної довжини тому
        volumeIndex = BinaryPrimitives.ReadUInt16BigEndian(volumeBytes.Slice(5, 2));
        volumeCount = BinaryPrimitives.ReadUInt16BigEndian(volumeBytes.Slice(7, 2));
        salt = volumeBytes.Slice(9, VolumeHeader.SaltSize).ToArray();
        nonce = volumeBytes.Slice(25, VolumeHeader.NonceSize).ToArray();
        ciphertextLen = BinaryPrimitives.ReadUInt32BigEndian(volumeBytes.Slice(37, 4));

        long expectedTotalLength = (long)VolumeHeader.Size + ciphertextLen + VolumeHeader.HmacSize;
        if (volumeBytes.Length != expectedTotalLength)
        {
            return SarcErrorCode.E_LENGTH;
        }

        return SarcErrorCode.Ok;
    }

    /// <summary>
    /// Валідує та парсить відкритий 41-байтний заголовок тому або кидає SarcException (E_SHORT, E_MAGIC, E_LENGTH).
    /// </summary>
    public VolumeHeader ParseVolumeHeaderOrThrow(ReadOnlySpan<byte> volumeBytes)
    {
        SarcErrorCode code = TryParseVolumeHeader(
            volumeBytes,
            out ushort volumeIndex,
            out ushort volumeCount,
            out byte[] salt,
            out byte[] nonce,
            out uint ciphertextLen);

        if (code != SarcErrorCode.Ok)
        {
            throw new SarcException(code, $"Volume header validation failed with {code}.");
        }

        return new VolumeHeader(volumeIndex, volumeCount, salt, nonce, ciphertextLen);
    }

    /// <inheritdoc />
    public byte[] BuildPayload(IReadOnlyList<ArchiveFileInfo> files, IReadOnlyList<FileBlock> blocks, byte flags = 0)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(blocks);

        // У базовому форматі SARC v1 біт PREDICTION (0x01) та біти 1..7 мають дорівнювати 0
        if (flags != 0)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Unsupported payload flags: 0x{flags:X2}.");
        }

        if (files.Count > ushort.MaxValue)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Too many files in volume: {files.Count}.");
        }

        if (blocks.Count > ushort.MaxValue)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Too many blocks in volume: {blocks.Count}.");
        }

        byte[][] encodedNames = new byte[files.Count][];
        long totalLength = VolumeHeader.PayloadFixedOverhead;

        for (int i = 0; i < files.Count; i++)
        {
            ArchiveFileInfo file = files[i] ?? throw new ArgumentNullException(nameof(files), $"File entry at index {i} is null.");
            FileNameValidator.ValidateOrThrow(file.FileName);

            if (file.FileType > ArchiveFileInfo.MaxFileType)
            {
                throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Invalid file_type {file.FileType} for file '{file.FileName}'.");
            }

            byte[] nameBytes = StrictUtf8.GetBytes(file.FileName);
            encodedNames[i] = nameBytes;
            totalLength += ArchiveFileInfo.FixedFieldsSize + nameBytes.Length;
        }

        totalLength += (long)blocks.Count * FileBlock.HeaderSize;

        for (int i = 0; i < blocks.Count; i++)
        {
            FileBlock block = blocks[i] ?? throw new ArgumentNullException(nameof(blocks), $"Block entry at index {i} is null.");
            if (block.Data is null)
            {
                throw new ArgumentException($"Block data at index {i} is null.", nameof(blocks));
            }

            if (block.FileIndex >= files.Count)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Block {i} references out-of-range file_index {block.FileIndex} (file_count = {files.Count}).");
            }

            if ((block.BlockFlags & FileBlock.ReservedFlagsMask) != 0)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Block {i} has non-zero reserved bits in block_flags: 0x{block.BlockFlags:X2}.");
            }

            if (block.Data.Length != block.CodedLength)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Block {i} Data.Length ({block.Data.Length}) does not match CodedLength ({block.CodedLength}).");
            }

            if (block.IsNoCompression && block.CodedLength != block.RawLength)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Block {i} has NO_COMPRESSION flag set, but CodedLength ({block.CodedLength}) != RawLength ({block.RawLength}).");
            }

            totalLength += block.CodedLength;
        }

        if (totalLength > int.MaxValue)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, "Payload exceeds maximum supported array size.");
        }

        byte[] payload = new byte[(int)totalLength];
        Span<byte> span = payload.AsSpan();
        int offset = 0;

        // 1. Заголовок Payload: file_count (uint16), flags (uint8), reserved = 0 (uint8)
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset, 2), (ushort)files.Count);
        span[offset + 2] = flags;
        span[offset + 3] = 0; // reserved = 0
        offset += 4;

        // 2. Таблиця файлів
        for (int i = 0; i < files.Count; i++)
        {
            ArchiveFileInfo file = files[i];
            byte[] nameBytes = encodedNames[i];

            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset, 2), (ushort)nameBytes.Length);
            offset += 2;

            nameBytes.CopyTo(span.Slice(offset, nameBytes.Length));
            offset += nameBytes.Length;

            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), file.OriginalSize);
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset + 4, 4), file.Crc32);
            span[offset + 8] = file.FileType;
            span[offset + 9] = file.Strategy;
            offset += 10;
        }

        // 3. Кількість блоків: block_count (uint16)
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset, 2), (ushort)blocks.Count);
        offset += 2;

        // 4. Таблиця блоків (15 * block_count байтів)
        for (int i = 0; i < blocks.Count; i++)
        {
            FileBlock block = blocks[i];
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset, 2), block.FileIndex);
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset + 2, 4), block.BlockSeq);
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset + 6, 4), block.RawLength);
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset + 10, 4), block.CodedLength);
            span[offset + 14] = block.BlockFlags;
            offset += FileBlock.HeaderSize;
        }

        // 5. Дані блоків (склеєні підряд)
        for (int i = 0; i < blocks.Count; i++)
        {
            byte[] data = blocks[i].Data;
            if (data.Length > 0)
            {
                data.CopyTo(span.Slice(offset, data.Length));
                offset += data.Length;
            }
        }

        return payload;
    }

    /// <inheritdoc />
    public void ParsePayload(
        ReadOnlySpan<byte> payload,
        out List<ArchiveFileInfo> files,
        out List<FileBlock> blocks,
        out byte flags)
    {
        if (payload.Length < VolumeHeader.PayloadFixedOverhead)
        {
            throw new SarcException(
                SarcErrorCode.E_PAYLOAD,
                $"Payload is too short ({payload.Length} bytes); minimum is {VolumeHeader.PayloadFixedOverhead} bytes.");
        }

        ushort fileCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(0, 2));
        flags = payload[2];
        byte reserved = payload[3];

        // Перевірка reserved == 0 (п. 0.5 та п. 2 FORMAT_SPEC_P2_2.md)
        if (reserved != 0)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Non-zero reserved field in payload: 0x{reserved:X2}.");
        }

        // Перевірка flags (п. 2.1 та п. 2.5 FORMAT_SPEC_P2_2.md: невідомі біти або розширення -> E_PAYLOAD)
        if (flags != 0)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Unsupported or non-zero flags in payload: 0x{flags:X2}.");
        }

        files = new List<ArchiveFileInfo>(fileCount);
        int offset = 4;

        for (int i = 0; i < fileCount; i++)
        {
            if (payload.Length - offset < ArchiveFileInfo.FixedFieldsSize)
            {
                throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Unexpected end of payload while reading file table entry {i}.");
            }

            ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
            offset += 2;

            if (payload.Length - offset < nameLen + 10)
            {
                throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Unexpected end of payload while reading file name {i}.");
            }

            string fileName;
            try
            {
                fileName = StrictUtf8.GetString(payload.Slice(offset, nameLen));
            }
            catch (DecoderFallbackException ex)
            {
                throw new SarcException(SarcErrorCode.E_PAYLOAD, $"Invalid UTF-8 file name at entry {i}: {ex.Message}");
            }

            offset += nameLen;

            // Безпекова перевірка імені файла до будь-якого запису на диск (Issue #44)
            FileNameValidator.ValidateOrThrow(fileName);

            uint origSize = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset, 4));
            uint crc32 = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset + 4, 4));
            byte fileType = payload[offset + 8];
            byte strategy = payload[offset + 9];
            offset += 10;

            if (fileType > ArchiveFileInfo.MaxFileType)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Invalid file_type {fileType} (must be 0..{ArchiveFileInfo.MaxFileType}) for file '{fileName}'.");
            }

            files.Add(new ArchiveFileInfo(fileName, origSize, crc32, fileType, strategy));
        }

        if (payload.Length - offset < 2)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, "Unexpected end of payload before block_count.");
        }

        ushort blockCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        offset += 2;

        long blockTableBytes = (long)blockCount * FileBlock.HeaderSize;
        if (payload.Length - offset < blockTableBytes)
        {
            throw new SarcException(SarcErrorCode.E_PAYLOAD, "Unexpected end of payload inside block table.");
        }

        var headerEntries = new (ushort FileIndex, uint BlockSeq, uint RawLen, uint CodedLen, byte BlockFlags)[blockCount];
        long totalCodedLength = 0;

        for (int i = 0; i < blockCount; i++)
        {
            ushort fileIndex = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
            uint blockSeq = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset + 2, 4));
            uint rawLen = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset + 6, 4));
            uint codedLen = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset + 10, 4));
            byte blockFlags = payload[offset + 14];
            offset += FileBlock.HeaderSize;

            if (fileIndex >= fileCount)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Block {i} has file_index {fileIndex}, which is out of bounds for file_count {fileCount}.");
            }

            if ((blockFlags & FileBlock.ReservedFlagsMask) != 0)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Block {i} has non-zero reserved bits in block_flags: 0x{blockFlags:X2}.");
            }

            bool isNoCompression = (blockFlags & FileBlock.NoCompressionFlag) != 0;
            if (isNoCompression && codedLen != rawLen)
            {
                throw new SarcException(
                    SarcErrorCode.E_PAYLOAD,
                    $"Block {i} is marked NO_COMPRESSION, but coded_len ({codedLen}) != raw_len ({rawLen}).");
            }

            headerEntries[i] = (fileIndex, blockSeq, rawLen, codedLen, blockFlags);
            totalCodedLength += codedLen;
        }

        // Залишок байтів у payload має точно збігатися із сумою coded_len усіх блоків (без зайвих або відсутніх байтів)
        if (payload.Length - offset != totalCodedLength)
        {
            throw new SarcException(
                SarcErrorCode.E_PAYLOAD,
                $"Remaining payload bytes ({payload.Length - offset}) do not match sum of block coded_len ({totalCodedLength}).");
        }

        blocks = new List<FileBlock>(blockCount);
        for (int i = 0; i < blockCount; i++)
        {
            var entry = headerEntries[i];
            int len = checked((int)entry.CodedLen);
            byte[] blockData = len == 0 ? [] : payload.Slice(offset, len).ToArray();
            offset += len;

            blocks.Add(new FileBlock(
                entry.FileIndex,
                entry.BlockSeq,
                entry.RawLen,
                entry.CodedLen,
                entry.BlockFlags,
                blockData));
        }
    }
}
