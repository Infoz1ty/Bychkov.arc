namespace SmartSecureArchiver.Core.Analysis;

/// <summary>
/// Бінарний формат збереження навченої моделі MLP (внутрішній формат проєкту, не частина SARC).
/// Файл містить архітектуру, z-score статистики та всі ваги/зміщення.
/// </summary>
public static class MlpModelSerializer
{
    private const int Magic = 0x4D4C5031; // "MLP1"
    private const int Version = 1;

    public static void Save(string path, MlpNetwork network, FeatureNormalizer normalizer)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(normalizer);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (normalizer.Mean.Length != network.InputSize)
        {
            throw new ArgumentException("Normalizer dimension does not match network input size.", nameof(normalizer));
        }

        string? directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        Save(stream, network, normalizer, leaveOpen: false);
    }

    public static void Save(Stream stream, MlpNetwork network, FeatureNormalizer normalizer, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(normalizer);

        if (normalizer.Mean.Length != network.InputSize)
        {
            throw new ArgumentException("Normalizer dimension does not match network input size.", nameof(normalizer));
        }

        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen);

        writer.Write(Magic);
        writer.Write(Version);
        writer.Write(network.InputSize);
        writer.Write(network.HiddenSize);
        writer.Write(network.OutputSize);

        WriteArray(writer, normalizer.Mean);
        WriteArray(writer, normalizer.StandardDeviation);

        WriteMatrix(writer, network.HiddenWeights);
        WriteArray(writer, network.HiddenBiases);
        WriteMatrix(writer, network.OutputWeights);
        WriteArray(writer, network.OutputBiases);
    }

    public static (MlpNetwork Network, FeatureNormalizer Normalizer) Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Load(stream, leaveOpen: false);
    }

    public static (MlpNetwork Network, FeatureNormalizer Normalizer) Load(Stream stream, bool leaveOpen = true)
    {
        ArgumentNullException.ThrowIfNull(stream);

        using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen);

        if (reader.ReadInt32() != Magic)
        {
            throw new InvalidDataException("Invalid MLP model magic.");
        }

        int version = reader.ReadInt32();
        if (version != Version)
        {
            throw new InvalidDataException($"Unsupported MLP model version {version}.");
        }

        int inputSize = reader.ReadInt32();
        int hiddenSize = reader.ReadInt32();
        int outputSize = reader.ReadInt32();
        var network = new MlpNetwork(inputSize, hiddenSize, outputSize);

        double[] mean = ReadArray(reader, inputSize);
        double[] standardDeviation = ReadArray(reader, inputSize);
        var normalizer = new FeatureNormalizer(mean, standardDeviation);

        ReadMatrix(reader, network.HiddenWeights);
        ReadArrayInto(reader, network.HiddenBiases);
        ReadMatrix(reader, network.OutputWeights);
        ReadArrayInto(reader, network.OutputBiases);

        return (network, normalizer);
    }

    private static void WriteArray(BinaryWriter writer, double[] values)
    {
        foreach (double value in values)
        {
            writer.Write(value);
        }
    }

    private static void WriteMatrix(BinaryWriter writer, double[,] values)
    {
        int rows = values.GetLength(0);
        int columns = values.GetLength(1);
        for (int row = 0; row < rows; row++)
        {
            for (int column = 0; column < columns; column++)
            {
                writer.Write(values[row, column]);
            }
        }
    }

    private static double[] ReadArray(BinaryReader reader, int length)
    {
        double[] values = new double[length];
        ReadArrayInto(reader, values);
        return values;
    }

    private static void ReadArrayInto(BinaryReader reader, double[] values)
    {
        for (int i = 0; i < values.Length; i++)
        {
            values[i] = reader.ReadDouble();
        }
    }

    private static void ReadMatrix(BinaryReader reader, double[,] values)
    {
        int rows = values.GetLength(0);
        int columns = values.GetLength(1);
        for (int row = 0; row < rows; row++)
        {
            for (int column = 0; column < columns; column++)
            {
                values[row, column] = reader.ReadDouble();
            }
        }
    }
}
