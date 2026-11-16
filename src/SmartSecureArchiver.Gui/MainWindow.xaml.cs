using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using SmartSecureArchiver.Core.Analysis;
using SmartSecureArchiver.Core.Compression;
using SmartSecureArchiver.Core.Format;
using SmartSecureArchiver.Core.Packing;
using SmartSecureArchiver.Core.Security;

namespace SmartSecureArchiver.Gui;

public sealed class GuiFileItem
{
    public string FullPath { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string FullTooltip { get; init; } = string.Empty;
    public ImageSource IconSource { get; init; } = null!;
    public bool IsArchiveFile { get; init; }
}

public partial class MainWindow : Window
{
    private static readonly string[] FileTypeDescriptions =
    [
        "0 (Природний текст)",
        "1 (Вихідний код)",
        "2 (Структуровані дані)",
        "3 (Растр без стиснення)",
        "4 (Виконуваний файл)",
        "5 (Вже стиснуте)",
        "6 (Штучні дані)"
    ];

    private readonly ObservableCollection<GuiFileItem> _fileItems = [];
    private bool _isPasswordVisible = true;
    private bool _isCompressionEnabled = true;
    private bool _syncingPassword;
    private bool _isBusy;
    private string? _selectedOutputArchivePath;

    public MainWindow()
    {
        InitializeComponent();
        FilesItemsControl.ItemsSource = _fileItems;
        SecretPasswordBox.Password = VisiblePasswordTextBox.Text;

        AppendLog("SARC v1 GUI готовий. Додайте файли ('+ ФАЙЛИ') або оберіть архів ('ОГЛЯД...').");
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        // Якщо у списку вже є звичайні файли для архівування — обираємо куди зберегти вихідний .arc
        bool hasRegularFiles = _fileItems.Any(i => !i.IsArchiveFile);
        if (hasRegularFiles)
        {
            var saveDialog = new SaveFileDialog
            {
                Title = "Оберіть шлях для збереження архіву SARC v1 (.arc)",
                Filter = "Архів SARC v1 (*.arc)|*.arc",
                DefaultExt = ".arc",
                FileName = string.IsNullOrWhiteSpace(_selectedOutputArchivePath)
                    ? "archive.arc"
                    : Path.GetFileName(_selectedOutputArchivePath)
            };

            if (saveDialog.ShowDialog(this) == true)
            {
                _selectedOutputArchivePath = saveDialog.FileName;
                TargetPathTextBlock.Text = Path.GetFileName(_selectedOutputArchivePath);
                TargetPathTextBlock.ToolTip = _selectedOutputArchivePath;
                AppendLog($"КУДИ: обрано цільовий архів '{_selectedOutputArchivePath}'.");
            }

            return;
        }

        // Інакше дозволяємо обрати існуючий .arc (для розпакування) або вказати новий .arc файл
        var openDialog = new OpenFileDialog
        {
            Title = "Оберіть архів SARC v1 (.arc) для розпакування або новий шлях .arc",
            Filter = "Архів SARC v1 (*.arc)|*.arc|Усі файли (*.*)|*.*",
            CheckFileExists = false,
            Multiselect = true
        };

        if (openDialog.ShowDialog(this) == true)
        {
            foreach (string path in openDialog.FileNames)
            {
                if (File.Exists(path))
                {
                    AddFileToList(path);
                }
                else if (path.EndsWith(".arc", StringComparison.OrdinalIgnoreCase))
                {
                    _selectedOutputArchivePath = path;
                    TargetPathTextBlock.Text = Path.GetFileName(path);
                    TargetPathTextBlock.ToolTip = path;
                    AppendLog($"КУДИ: встановлено шлях нового архіву '{path}'.");
                }
            }
        }
    }

    private void AddFilesButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Оберіть файли для додавання в архів (або томи .arc для розпакування)",
            Filter = "Усі файли (*.*)|*.*|Архіви SARC v1 (*.arc)|*.arc",
            Multiselect = true
        };

        if (dialog.ShowDialog(this) == true)
        {
            int added = 0;
            foreach (string file in dialog.FileNames)
            {
                if (AddFileToList(file))
                {
                    added++;
                }
            }

            if (added > 0)
            {
                AppendLog($"Додано файлів до списку: {added} (усього у списку: {_fileItems.Count}).");
            }
        }
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        _fileItems.Clear();
        _selectedOutputArchivePath = null;
        EmptyFilesHintTextBlock.Visibility = Visibility.Visible;
        TargetPathTextBlock.Text = "archive.arc (авто)";
        TargetPathTextBlock.ToolTip = "Цільовий шлях архіву або теки (змінюється кнопкою ОГЛЯД...)";
        SetProgressBarFrame(0);
        AppendLog("Список файлів очищено.");
    }

    private void EyeToggleButton_Click(object sender, RoutedEventArgs e)
    {
        _isPasswordVisible = !_isPasswordVisible;

        if (_isPasswordVisible)
        {
            VisiblePasswordTextBox.Text = SecretPasswordBox.Password;
            VisiblePasswordTextBox.Visibility = Visibility.Visible;
            SecretPasswordBox.Visibility = Visibility.Collapsed;
            EyeIconImage.Source = LoadAssetImage("icon_eye_open.png");
        }
        else
        {
            SecretPasswordBox.Password = VisiblePasswordTextBox.Text;
            SecretPasswordBox.Visibility = Visibility.Visible;
            VisiblePasswordTextBox.Visibility = Visibility.Collapsed;
            EyeIconImage.Source = LoadAssetImage("icon_eye_closed.png");
        }
    }

    private void SecretPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingPassword)
        {
            return;
        }

        _syncingPassword = true;
        VisiblePasswordTextBox.Text = SecretPasswordBox.Password;
        UpdateLockStateIcon(SecretPasswordBox.Password);
        _syncingPassword = false;
    }

    private void VisiblePasswordTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (_syncingPassword || SecretPasswordBox is null)
        {
            return;
        }

        _syncingPassword = true;
        SecretPasswordBox.Password = VisiblePasswordTextBox.Text;
        UpdateLockStateIcon(VisiblePasswordTextBox.Text);
        _syncingPassword = false;
    }

    private void CompressionCheckButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        _isCompressionEnabled = !_isCompressionEnabled;

        if (_isCompressionEnabled)
        {
            CheckMarkImage.Visibility = Visibility.Visible;
            CrossMarkImage.Visibility = Visibility.Collapsed;
            CompressionStateHintText.Text = "MLP + LZ77 + HUFF";
            CompressionStateHintText.Foreground = new SolidColorBrush(Color.FromRgb(0x8C, 0xFF, 0x98));
            AppendLog("СТИСНЕННЯ: УВІМКНЕНО (класифікатор MLP + LZ77 + Канонічний Гаффман).");
        }
        else
        {
            CheckMarkImage.Visibility = Visibility.Collapsed;
            CrossMarkImage.Visibility = Visibility.Visible;
            CompressionStateHintText.Text = "NO_COMPRESSION";
            CompressionStateHintText.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x7A, 0x7A));
            AppendLog("СТИСНЕННЯ: ВИМКНЕНО (примусовий режим NO_COMPRESSION).");
        }
    }

    private async void ArchiveButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        List<string> inputFiles = _fileItems
            .Where(i => !i.IsArchiveFile && File.Exists(i.FullPath))
            .Select(i => i.FullPath)
            .ToList();

        if (inputFiles.Count == 0)
        {
            var pickFilesDialog = new OpenFileDialog
            {
                Title = "Оберіть файли для створення архіву SARC v1",
                Filter = "Усі файли (*.*)|*.*",
                Multiselect = true
            };

            if (pickFilesDialog.ShowDialog(this) != true || pickFilesDialog.FileNames.Length == 0)
            {
                return;
            }

            foreach (string path in pickFilesDialog.FileNames)
            {
                AddFileToList(path);
            }

            inputFiles = pickFilesDialog.FileNames.ToList();
        }

        string password = GetCurrentPassword();
        if (string.IsNullOrEmpty(password))
        {
            AppendLog("[ПОМИЛКА] Введіть непорожній пароль для генерації ключів PBKDF2-HMAC-SHA256.");
            return;
        }

        string? outputArchivePath = _selectedOutputArchivePath;
        if (string.IsNullOrWhiteSpace(outputArchivePath))
        {
            var saveDialog = new SaveFileDialog
            {
                Title = "Зберегти захищений архів SARC v1 (.arc)",
                Filter = "Архів SARC v1 (*.arc)|*.arc",
                DefaultExt = ".arc",
                FileName = inputFiles.Count == 1
                    ? Path.GetFileNameWithoutExtension(inputFiles[0]) + ".arc"
                    : "archive.arc"
            };

            if (saveDialog.ShowDialog(this) != true)
            {
                return;
            }

            outputArchivePath = saveDialog.FileName;
            _selectedOutputArchivePath = outputArchivePath;
            TargetPathTextBlock.Text = Path.GetFileName(outputArchivePath);
            TargetPathTextBlock.ToolTip = outputArchivePath;
        }

        if (!TryParseVolumeSizeBytes(inputFiles, out int maxVolumeBytes, out bool isMultiVolumeMode))
        {
            return;
        }

        bool useCompression = _isCompressionEnabled;
        SetBusyState(true);
        SetProgressBarFrame(1);

        try
        {
            AppendLog($"--- Старт архівування ({inputFiles.Count} файл(ів)) -> '{Path.GetFileName(outputArchivePath)}' ---");

            var sw = Stopwatch.StartNew();
            (IReadOnlyList<string> createdVolumes, List<string> details, long rawTotalBytes, long archiveTotalBytes) =
                await Task.Run(() =>
                {
                    var logLines = new List<string>();
                    var extractor = new FeatureExtractor();
                    var mlp = MlpClassifier.CreateDefault();
                    var crypto = new CryptoEngine();
                    long origSum = 0;

                    for (int idx = 0; idx < inputFiles.Count; idx++)
                    {
                        string fPath = inputFiles[idx];
                        byte[] bytes = File.ReadAllBytes(fPath);
                        origSum += bytes.Length;
                        uint crc = crypto.ComputeCrc32(bytes);

                        FileFeatures features = extractor.Extract(bytes);
                        byte predictedType = mlp.Classify(features);
                        bool mlpWantsCompress = useCompression && mlp.ShouldCompress(predictedType, features);
                        string typeDesc = predictedType < FileTypeDescriptions.Length
                            ? FileTypeDescriptions[predictedType]
                            : predictedType.ToString(CultureInfo.InvariantCulture);
                        string strategyText = mlpWantsCompress ? "COMPRESS (LZ77+Huffman)" : "NO_COMPRESSION";

                        logLines.Add($"  • {Path.GetFileName(fPath)} ({bytes.Length} Б, CRC32=0x{crc:X8}) -> Тип {typeDesc}, Стратегія: {strategyText}");

                        int progressStep = 2 + (int)Math.Round(3.0 * (idx + 1) / inputFiles.Count);
                        Dispatcher.Invoke(() => SetProgressBarFrame(Math.Clamp(progressStep, 2, 5)));
                    }

                    Dispatcher.Invoke(() => SetProgressBarFrame(6));

                    IFileClassifier classifier = useCompression
                        ? mlp
                        : new ForcedNoCompressionClassifier(mlp);

                    IKnapsackPacker? packer = (isMultiVolumeMode || maxVolumeBytes <= 262_144)
                        ? new KnapsackPacker()
                        : null;

                    var orchestrator = new ArchiveOrchestrator(
                        formatHandler: new SarcFormatHandler(),
                        cryptoEngine: crypto,
                        blockCompressor: new BlockCompressor(),
                        featureExtractor: extractor,
                        fileClassifier: classifier,
                        knapsackPacker: packer);

                    Dispatcher.Invoke(() => SetProgressBarFrame(8));
                    IReadOnlyList<string> volumes = orchestrator.CreateArchive(
                        inputFiles,
                        outputArchivePath,
                        password,
                        maxVolumeBytes);

                    long arcSum = volumes.Sum(v => new FileInfo(v).Length);
                    return (volumes, logLines, origSum, arcSum);
                });

            sw.Stop();
            foreach (string line in details)
            {
                AppendLog(line);
            }

            SetProgressBarFrame(10);

            double ratio = archiveTotalBytes > 0 ? (double)rawTotalBytes / archiveTotalBytes : 1.0;
            AppendLog(string.Format(
                CultureInfo.InvariantCulture,
                "[УСПІХ] Створено томів: {0} за {1:F1} мс. Сирий розмір: {2} Б -> Архів: {3} Б (коефіцієнт: {4:F2}x).",
                createdVolumes.Count,
                sw.Elapsed.TotalMilliseconds,
                rawTotalBytes,
                archiveTotalBytes,
                ratio));

            foreach (string vol in createdVolumes)
            {
                AppendLog($"  -> Том: {Path.GetFileName(vol)} ({new FileInfo(vol).Length} Б)");
                AddFileToList(vol);
            }
        }
        catch (SarcException sarcEx)
        {
            SetProgressBarFrame(0);
            AppendLog($"[ВІДМОВА SARC: {sarcEx.ErrorCode}] {DescribeSarcError(sarcEx.ErrorCode)} ({sarcEx.Message})");
        }
        catch (Exception ex)
        {
            SetProgressBarFrame(0);
            AppendLog($"[ПОМИЛКА] {ex.Message}");
        }
        finally
        {
            SetBusyState(false);
        }
    }

    private async void ExtractButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        List<string> archiveVolumes = _fileItems
            .Where(i => i.IsArchiveFile && File.Exists(i.FullPath))
            .Select(i => i.FullPath)
            .ToList();

        if (archiveVolumes.Count == 0 && !string.IsNullOrWhiteSpace(_selectedOutputArchivePath) && File.Exists(_selectedOutputArchivePath))
        {
            archiveVolumes.Add(_selectedOutputArchivePath);
        }

        if (archiveVolumes.Count == 0)
        {
            var openArchiveDialog = new OpenFileDialog
            {
                Title = "Оберіть том(и) архіву SARC v1 (*.arc) для розпакування",
                Filter = "Архів SARC v1 (*.arc)|*.arc|Усі файли (*.*)|*.*",
                Multiselect = true
            };

            if (openArchiveDialog.ShowDialog(this) != true || openArchiveDialog.FileNames.Length == 0)
            {
                return;
            }

            foreach (string path in openArchiveDialog.FileNames)
            {
                AddFileToList(path);
                archiveVolumes.Add(path);
            }
        }

        string password = GetCurrentPassword();
        if (string.IsNullOrEmpty(password))
        {
            AppendLog("[ПОМИЛКА] Введіть пароль для перевірки HMAC-SHA256 та розшифрування архіву.");
            return;
        }

        var folderDialog = new OpenFolderDialog
        {
            Title = "Оберіть цільову теку для розпакування файлів SARC v1"
        };

        if (folderDialog.ShowDialog(this) != true || string.IsNullOrWhiteSpace(folderDialog.FolderName))
        {
            return;
        }

        string outputDir = folderDialog.FolderName;
        TargetPathTextBlock.Text = Path.GetFileName(outputDir);
        TargetPathTextBlock.ToolTip = outputDir;

        SetBusyState(true);
        SetProgressBarFrame(2);

        try
        {
            AppendLog($"--- Старт розархівування у '{outputDir}' ---");
            var sw = Stopwatch.StartNew();

            await Task.Run(() =>
            {
                Dispatcher.Invoke(() => SetProgressBarFrame(5));
                ArchiveOrchestrator orchestrator = ArchiveOrchestratorFactory.CreateDefault();

                if (archiveVolumes.Count == 1)
                {
                    // Автоматичний пошук усіх частин багатотомного архіву (.part0.arc, .part1.arc, ...)
                    orchestrator.ExtractArchive(archiveVolumes[0], outputDir, password);
                }
                else
                {
                    orchestrator.ExtractArchive(archiveVolumes, outputDir, password);
                }

                Dispatcher.Invoke(() => SetProgressBarFrame(9));
            });

            sw.Stop();
            SetProgressBarFrame(10);

            AppendLog(string.Format(
                CultureInfo.InvariantCulture,
                "[УСПІХ] Архів успішно перевірено (HMAC-SHA256 OK, CRC32 OK) та атомарно розпаковано за {0:F1} мс у '{1}'.",
                sw.Elapsed.TotalMilliseconds,
                outputDir));
        }
        catch (SarcException sarcEx)
        {
            SetProgressBarFrame(0);
            AppendLog($"[ВІДМОВА SARC: {sarcEx.ErrorCode}] {DescribeSarcError(sarcEx.ErrorCode)} ({sarcEx.Message})");
        }
        catch (Exception ex)
        {
            SetProgressBarFrame(0);
            AppendLog($"[ПОМИЛКА] {ex.Message}");
        }
        finally
        {
            SetBusyState(false);
        }
    }

    private bool AddFileToList(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return false;
        }

        string fullPath = Path.GetFullPath(path);
        if (_fileItems.Any(i => string.Equals(i.FullPath, fullPath, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        bool isArchive = fullPath.EndsWith(".arc", StringComparison.OrdinalIgnoreCase);
        long size = new FileInfo(fullPath).Length;
        string name = Path.GetFileName(fullPath);

        _fileItems.Add(new GuiFileItem
        {
            FullPath = fullPath,
            DisplayName = name,
            FullTooltip = $"{name} ({size} байт)\n{fullPath}",
            IconSource = LoadAssetImage(isArchive ? "icon_folder_locked.png" : "icon_folder.png"),
            IsArchiveFile = isArchive
        });

        EmptyFilesHintTextBlock.Visibility = Visibility.Collapsed;
        return true;
    }

    private bool TryParseVolumeSizeBytes(IReadOnlyList<string> inputFiles, out int maxVolumeBytes, out bool isMultiVolumeMode)
    {
        string rawText = VolumeSizeKbTextBox.Text.Trim();
        if (string.IsNullOrEmpty(rawText) || rawText == "0")
        {
            long sumBytes = inputFiles.Sum(f => new FileInfo(f).Length);
            long singleVolCapacity = Math.Max(65_536L, sumBytes + 65_536L + inputFiles.Count * 512L);
            maxVolumeBytes = (int)Math.Min(int.MaxValue / 2, singleVolCapacity);
            isMultiVolumeMode = false;
            return true;
        }

        if (!int.TryParse(rawText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int volumeKb) || volumeKb < 0)
        {
            AppendLog("[ПОМИЛКА] Поле 'РОЗМІР ТОМУ' має містити ціле невід'ємне число у КБ (наприклад, 64 або 0).");
            maxVolumeBytes = 0;
            isMultiVolumeMode = false;
            return false;
        }

        maxVolumeBytes = checked(volumeKb * 1024);
        isMultiVolumeMode = true;
        return true;
    }

    private string GetCurrentPassword()
    {
        return _isPasswordVisible ? VisiblePasswordTextBox.Text : SecretPasswordBox.Password;
    }

    private void UpdateLockStateIcon(string password)
    {
        if (LockStateImage is null)
        {
            return;
        }

        LockStateImage.Source = LoadAssetImage(
            string.IsNullOrEmpty(password) ? "icon_lock_open.png" : "icon_lock_closed.png");
    }

    private void SetProgressBarFrame(int frameIndex)
    {
        int clamped = Math.Clamp(frameIndex, 0, 10);
        ProgressBarImage.Source = LoadAssetImage($"bar_{clamped:D2}.png");
    }

    private void SetBusyState(bool busy)
    {
        _isBusy = busy;
        ArchiveButton.IsEnabled = !busy;
        ExtractButton.IsEnabled = !busy;
        BrowseButton.IsEnabled = !busy;
        AddFilesButton.IsEnabled = !busy;
        ClearButton.IsEnabled = !busy;
        CompressionCheckButton.IsEnabled = !busy;
    }

    private void AppendLog(string message)
    {
        string timestamp = DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        LogTextBox.AppendText($"[{timestamp}] {message}{Environment.NewLine}");
        LogTextBox.ScrollToEnd();
    }

    private static BitmapImage LoadAssetImage(string assetFileName)
    {
        var uri = new Uri($"pack://application:,,,/Assets/{assetFileName}", UriKind.Absolute);
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.UriSource = uri;
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.EndInit();
        bitmap.Freeze();
        return bitmap;
    }

    private static string DescribeSarcError(SarcErrorCode code) => code switch
    {
        SarcErrorCode.E_SHORT => "Файл тому коротший за мінімальні 73 байти (41B заголовок + 32B HMAC).",
        SarcErrorCode.E_MAGIC => "Невірна сигнатура MAGIC ('SARC') або непідтримувана версія формату.",
        SarcErrorCode.E_LENGTH => "Фізичний розмір тому не збігається з 41 + ciphertext_len + 32 (архів обрізаний або пошкоджений).",
        SarcErrorCode.E_HMAC => "Перевірка HMAC-SHA256 не пройдена: невірний пароль або порушена цілісність даних.",
        SarcErrorCode.E_PAYLOAD => "Пошкоджена внутрішня структура Payload або небезпечне ім'я файла.",
        SarcErrorCode.E_CODE => "Помилка декодування стисненого потоку Гаффмана або LZ77.",
        SarcErrorCode.E_CRC => "Контрольна сума CRC32 або розмір відновленого файла не збігається з оригіналом.",
        SarcErrorCode.E_VOLUMES => "Неповний набір томів, дублікати індексів або томи з різних архівів.",
        SarcErrorCode.E_CAPACITY => "Обраний розмір тому замалий для розміщення таблиці файлів або блоку даних.",
        _ => "Невідома помилка формату SARC."
    };

    private sealed class ForcedNoCompressionClassifier(IFileClassifier inner) : IFileClassifier
    {
        public byte Classify(FileFeatures features) => inner.Classify(features);

        public bool ShouldCompress(byte fileType, FileFeatures features, double entropyThreshold = 7.95) => false;
    }
}
