using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;

namespace SmartSecureArchiver.Tests.Format;

public class FormatContractTests
{
    [Fact]
    public void SarcErrorCodes_ContainAllSpecRequiredCodes()
    {
        var defined = Enum.GetNames<SarcErrorCode>();
        Assert.Contains("E_SHORT", defined);
        Assert.Contains("E_MAGIC", defined);
        Assert.Contains("E_LENGTH", defined);
        Assert.Contains("E_HMAC", defined);
        Assert.Contains("E_PAYLOAD", defined);
        Assert.Contains("E_CODE", defined);
        Assert.Contains("E_CRC", defined);
        Assert.Contains("E_VOLUMES", defined);
    }

    [Fact]
    public void FileBlock_Matches15ByteHeaderFieldTypes()
    {
        var block = new FileBlock(
            FileIndex: 0,
            BlockSeq: 0u,
            RawLength: 480u,
            CodedLength: 57u,
            BlockFlags: 0,
            Data: new byte[57]);

        Assert.Equal((ushort)0, block.FileIndex);
        Assert.Equal(0u, block.BlockSeq);
        Assert.Equal(480u, block.RawLength);
        Assert.Equal(57u, block.CodedLength);
        Assert.Equal((byte)0, block.BlockFlags);
    }

    [Fact]
    public void HuffmanCodeTables_StoresThreeSeparateTreeLengths()
    {
        var tables = new HuffmanCodeTables(
            LitLengths: new byte[257],
            LenLengths: new byte[256],
            DistLengths: new byte[16]);

        Assert.Equal(257, tables.LitLengths.Length);
        Assert.Equal(256, tables.LenLengths.Length);
        Assert.Equal(16, tables.DistLengths.Length);
    }
}
