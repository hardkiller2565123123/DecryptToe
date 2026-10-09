using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using DecryptToe.Models;
using DecryptToe.Services;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace DecryptToe;
public partial class MainWindow : Window
{
    void TitleBar_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) { ToggleMaximize(); return; }
        if (e.LeftButton == System.Windows.Input.MouseButtonState.Pressed) DragMove();
    }
    void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    void CloseWindow_Click(object sender, RoutedEventArgs e) => Close();
    Process? _process;
    CancellationTokenSource? _cts;
    bool _busy;
    readonly string _root, _logPath;
    List<ModuleItem> _modules = new();
    CancellationTokenSource? _inspectCts;

    public MainWindow()
    {
        InitializeComponent();
        _root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "DecryptToe");
        Directory.CreateDirectory(Path.Combine(_root, "Logs"));
        OutputBox.Text = Path.Combine(_root, "Dumps");
        _logPath = Path.Combine(_root, "Logs", $"session_{DateTime.Now:yyyyMMdd_HHmmss}.log");
        Log("Ready");
    }
    void Log(string message)
    {
        Dispatcher.Invoke(() =>
        {
            string line = $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
            LogBox.AppendText(line);
            LogBox.ScrollToEnd();
            try { File.AppendAllText(_logPath, line); } catch { }
        });
    }
    void Failure(Exception e) { Log("ERROR: " + e.Message); StatusText.Text = "Error: " + e.Message; }
    void SetBusy(bool busy)
    {
        _busy = busy;
        StartButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
        DumpButton.IsEnabled = !busy;
    }
    async Task RunJob(Func<CancellationToken, Task> job)
    {
        if (_busy) return;
        _cts = new CancellationTokenSource(); SetBusy(true); Progress.Value = 0;
        try { await job(_cts.Token); StatusText.Text = "Completed"; Progress.Value = 100; }
        catch (OperationCanceledException) { StatusText.Text = "Canceled"; Log("Operation canceled"); }
        catch (Exception ex) { Failure(ex); }
        finally { SetBusy(false); _cts.Dispose(); _cts = null; }
    }
    Process GetTarget() => _process is { HasExited: false } p ? p : throw new InvalidOperationException("No live target selected.");
    void Attach(int pid)
    {
        if (pid <= 0) throw new ArgumentOutOfRangeException(nameof(pid));
        var p = Process.GetProcessById(pid);
        if (p.HasExited) throw new InvalidOperationException("Process has exited.");
        _process?.Dispose(); _process = p;
        try { if (p.MainModule?.FileName is string file && File.Exists(file)) ShowExecutableInfo(file); } catch { }
        SummaryBox.Text = $"Attached: {p.ProcessName} (PID {pid})";
        Log($"Attached to {p.ProcessName}, PID {pid}");
    }
    async Task LoadModulesAsync()
    {
        var pid = GetTarget().Id;
        _modules = await Task.Run(() => MemoryDumper.EnumerateModules(Process.GetProcessById(pid)));
        ModuleList.ItemsSource = _modules;
        Log($"Enumerated {_modules.Count} loaded modules");
    }
    async Task DumpModuleAsync(ModuleItem module, CancellationToken ct)
    {
        int pid = GetTarget().Id;
        Log($"Capturing module: {module.Name} at 0x{module.BaseAddress:X}");
        var reporter = new Progress<double>(v => Progress.Value = v * 100);
        string path = await MemoryDumper.DumpAsync(pid, module, OutputBox.Text, reporter, Log, ct);
        SummaryBox.Text = $"Last module capture:\n{path}\n\nReconstructed PE is best-effort and may require manual import repair.";
    }
    void ExePath_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (GameNameText == null) return;
        string path = ExePath.Text.Trim().Trim('"');
        ShowExecutableInfo(path);
        ScheduleInspection(path);
    }
    void ShowExecutableInfo(string path)
    {
        GameNameText.Text = "Select a game EXE";
        GamePublisherText.Text = GameVersionText.Text = ExeSizeText.Text = ExeModifiedText.Text = "";
        ExeNameText.Text = "No executable selected";
        try
        {
            if (!File.Exists(path)) return;
            var file = new FileInfo(path);
            var version = FileVersionInfo.GetVersionInfo(path);
            GameNameText.Text = string.IsNullOrWhiteSpace(version.ProductName) ? Path.GetFileNameWithoutExtension(path) : version.ProductName;
            GamePublisherText.Text = version.CompanyName ?? "";
            GameVersionText.Text = string.IsNullOrWhiteSpace(version.ProductVersion) ? "" : $"Version: {version.ProductVersion}";
            ExeNameText.Text = file.Name;
            ExeNameText.ToolTip = file.FullName;
            ExeSizeText.Text = $"Size: {file.Length / 1048576d:N2} MB";
            ExeModifiedText.Text = $"Modified: {file.LastWriteTime:yyyy-MM-dd HH:mm}";
        }
        catch (Exception) { ExeNameText.Text = "Cannot read executable details"; }
    }
    async void ScheduleInspection(string path)
    {
        _inspectCts?.Cancel();
        var cts = new CancellationTokenSource();
        _inspectCts = cts;
        if (!File.Exists(path)) { SummaryBox.Text = ""; return; }
        SummaryBox.Text = "Inspecting executable...";
        try
        {
            await Task.Delay(250, cts.Token);
            var report = await Task.Run(() => PeInspector.Inspect(path), cts.Token);
            if (!cts.IsCancellationRequested && ReferenceEquals(cts, _inspectCts))
                SummaryBox.Text = report;
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!cts.IsCancellationRequested && ReferenceEquals(cts, _inspectCts))
                SummaryBox.Text = "Executable inspection unavailable: " + ex.Message;
        }
    }
    void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Filter = "Windows Executable (*.exe)|*.exe|All files|*.*" };
        if (dlg.ShowDialog() == true) ExePath.Text = dlg.FileName;
    }
    void Output_Click(object sender, RoutedEventArgs e)
    {
        using var dlg = new Forms.FolderBrowserDialog { SelectedPath = OutputBox.Text, Description = "Choose dump output folder" };
        if (dlg.ShowDialog() == Forms.DialogResult.OK) OutputBox.Text = dlg.SelectedPath;
    }
    void OpenFolder_Click(object sender, RoutedEventArgs e) => OpenFolder(OutputBox.Text);
    void OpenLogs_Click(object sender, RoutedEventArgs e) => OpenFolder(Path.Combine(_root, "Logs"));
    void OpenFolder(string path)
    {
        try { Directory.CreateDirectory(path); Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true }); }
        catch (Exception ex) { Failure(ex); }
    }
    async void Start_Click(object sender, RoutedEventArgs e)
    {
        await RunJob(async ct =>
        {
            if (!int.TryParse(WaitBox.Text, out int delay) || delay is < 0 or > 3600) throw new InvalidOperationException("Wait must be 0–3600 seconds.");
            string path = ExePath.Text.Trim().Trim('"');
            if (!File.Exists(path)) throw new FileNotFoundException("Choose an existing executable", path);
            var process = Process.Start(new ProcessStartInfo(path) { WorkingDirectory = Path.GetDirectoryName(path)!, UseShellExecute = false });
            if (process == null) throw new InvalidOperationException("Launch failed.");
            int pid = process.Id; process.Dispose(); Attach(pid);
            for (int remaining = delay; remaining > 0; remaining--)
            {
                ct.ThrowIfCancellationRequested();
                if (GetTarget().HasExited) throw new InvalidOperationException("Target exited during wait.");
                StatusText.Text = $"Waiting: {remaining} seconds";
                Progress.Value = (delay - remaining) * 100d / Math.Max(1, delay);
                await Task.Delay(1000, ct);
            }
            await LoadModulesAsync();
            var main = GetTarget().MainModule ?? throw new InvalidOperationException("Cannot access main module.");
            await DumpModuleAsync(new ModuleItem(main.ModuleName, main.FileName, main.BaseAddress.ToInt64(), main.ModuleMemorySize), ct);
        });
    }
    async void RefreshAll_Click(object sender, RoutedEventArgs e)
    {
        await RunJob(async ct => { ct.ThrowIfCancellationRequested(); await LoadModulesAsync(); });
    }
    async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        try { await LoadModulesAsync(); } catch (Exception ex) { Failure(ex); }
    }
    async void DumpMain_Click(object sender, RoutedEventArgs e)
    {
        await RunJob(async ct =>
        {
            var main = GetTarget().MainModule ?? throw new InvalidOperationException("Cannot inspect main module");
            await DumpModuleAsync(new ModuleItem(main.ModuleName, main.FileName, main.BaseAddress.ToInt64(), main.ModuleMemorySize), ct);
        });
    }
    async void Dump_Click(object sender, RoutedEventArgs e)
    {
        if (ModuleList.SelectedItem is ModuleItem module) await RunJob(ct => DumpModuleAsync(module, ct));
    }
    void ExportModules_Click(object sender, RoutedEventArgs e) => ExportCsv("modules", "Name,BaseAddress,Size,Path", _modules.Select(m => $"{Csv(m.Name)},{Csv(m.Address)},{m.Size},{Csv(m.Path)}"));
    static string Csv(string? text) => "\"" + (text ?? "").Replace("\"", "\"\"") + "\"";
    void ExportCsv(string name, string header, IEnumerable<string> rows)
    {
        try
        {
            Directory.CreateDirectory(OutputBox.Text);
            string path = Path.Combine(OutputBox.Text, $"{name}_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
            File.WriteAllLines(path, new[] { header }.Concat(rows), Encoding.UTF8);
            Log("Saved CSV: " + path);
        }
        catch (Exception ex) { Failure(ex); }
    }
    void CopyReport_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(SummaryBox.Text))
        {
            System.Windows.Clipboard.SetText(SummaryBox.Text);
        }
    }
    void ClearLog_Click(object sender, RoutedEventArgs e) => LogBox.Clear();
    void Cancel_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();
    protected override void OnClosed(EventArgs e) { _inspectCts?.Cancel(); _cts?.Cancel(); _process?.Dispose(); base.OnClosed(e); }
}
