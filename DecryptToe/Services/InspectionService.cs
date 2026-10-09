using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DecryptToe.Services;

public sealed record ProcessItem(int Pid, string Name, string Title)
{
    public string Display => $"{Name}   •   PID {Pid}   {Title}";
}
public sealed record RegionItem(long BaseAddress, long Size, uint State, uint Protect, uint Type)
{
    public string Address => $"0x{BaseAddress:X16}";
    public string End => $"0x{BaseAddress + Size:X16}";
    public string SizeText => $"{Size / 1024.0 / 1024:0.00} MB";
    public string Protection => Protect switch
    {
        0x01 => "NOACCESS", 0x02 => "R", 0x04 => "RW", 0x08 => "WC", 0x10 => "X",
        0x20 => "RX", 0x40 => "RWX", 0x80 => "XWC", _ => $"0x{Protect:X}"
    };
    public string StateText => State == 0x1000 ? "COMMIT" : State == 0x2000 ? "RESERVE" : "FREE";
    public string TypeText => Type == 0x1000000 ? "IMAGE" : Type == 0x40000 ? "MAPPED" : Type == 0x20000 ? "PRIVATE" : "—";
    public bool Readable => State == 0x1000 && (Protect & 0x100) == 0 && (Protect & 0xFF) is 0x02 or 0x04 or 0x08 or 0x20 or 0x40 or 0x80;
}

public static class InspectionService
{
    const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;
    const int Chunk = 64 * 1024;
    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State, Protect, Type;
    }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint desiredAccess, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern nuint VirtualQueryEx(IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION info, nuint length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr handle, IntPtr address, [Out] byte[] buffer, nuint size, out nuint bytesRead);

    public static List<ProcessItem> Processes() => Process.GetProcesses().Select(p =>
    {
        try { return new ProcessItem(p.Id, p.ProcessName, p.MainWindowTitle); }
        catch { return null; }
        finally { p.Dispose(); }
    }).Where(x => x != null).Cast<ProcessItem>().OrderBy(x => x.Name).ThenBy(x => x.Pid).ToList();

    public static List<RegionItem> Regions(int pid, CancellationToken ct)
    {
        var handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot query process memory");
        try
        {
            var regions = new List<RegionItem>();
            ulong address = 0;
            for (int i = 0; i < 500000 && address < 0x00007FFFFFFF0000UL; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (VirtualQueryEx(handle, (IntPtr)unchecked((long)address), out var info, (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == 0) break;
                ulong start = unchecked((ulong)info.BaseAddress.ToInt64());
                ulong size = (ulong)info.RegionSize;
                if (size == 0 || start + size <= address) break;
                if (info.State == 0x1000) regions.Add(new RegionItem((long)start, (long)size, info.State, info.Protect, info.Type));
                address = start + size;
            }
            return regions;
        }
        finally { CloseHandle(handle); }
    }
    public static byte[] Read(int pid, long address, int count)
    {
        if (count < 1 || count > 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(count), "Preview limit: 1 MB");
        var handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var bytes = new byte[count];
            if (!ReadProcessMemory(handle, new IntPtr(address), bytes, (nuint)count, out var read) || (ulong)read != (ulong)count)
                throw new IOException($"Read failed or incomplete (read {read} of {count} bytes). Select a readable committed region.");
            return bytes;
        }
        finally { CloseHandle(handle); }
    }
    public static async Task<string> DumpRegionAsync(int pid, RegionItem region, string folder, IProgress<double>? progress, CancellationToken ct)
    {
        if (!region.Readable) throw new InvalidOperationException("The region is not readable.");
        if (region.Size <= 0 || region.Size > 512L * 1024 * 1024) throw new InvalidOperationException("Single-region export is limited to 512 MB.");
        Directory.CreateDirectory(folder);
        string stem = $"region_{pid}_{region.BaseAddress:X}_{DateTime.Now:yyyyMMdd_HHmmss}";
        string path = Path.Combine(folder, stem + ".bin");
        await Task.Run(() =>
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (h == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                byte[] block = new byte[Chunk];
                for (long offset = 0; offset < region.Size; offset += Chunk)
                {
                    ct.ThrowIfCancellationRequested();
                    int length = (int)Math.Min(Chunk, region.Size - offset);
                    Array.Clear(block);
                    ReadProcessMemory(h, new IntPtr(region.BaseAddress + offset), block, (nuint)length, out var got);
                    // Zero-filled missing bytes; metadata identifies this as a best-effort capture.
                    file.Write(block, 0, length);
                    progress?.Report((offset + length) / (double)region.Size);
                }
            }
            finally { CloseHandle(h); }
        }, ct);
        await File.WriteAllTextAsync(Path.Combine(folder, stem + ".json"), JsonSerializer.Serialize(new
        {
            Pid = pid, region.BaseAddress, region.Size, region.Protection, region.TypeText,
            Captured = DateTimeOffset.Now, Note = "Raw best-effort region dump; unreadable bytes are zero-filled."
        }, new JsonSerializerOptions { WriteIndented = true }), ct);
        return path;
    }
    public static string Hex(byte[] data, long baseAddress = 0)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append($"{baseAddress + i:X16}  ");
            for (int j = 0; j < 16; j++) sb.Append(i + j < data.Length ? $"{data[i + j]:X2} " : "   ");
            sb.Append(" | ");
            for (int j = i; j < Math.Min(i + 16, data.Length); j++) sb.Append(data[j] is >= 32 and <= 126 ? (char)data[j] : '.');
            sb.AppendLine();
        }
        return sb.ToString();
    }
    public static async Task<string> AnalyzeFileAsync(string input, string folder, int minLength, CancellationToken ct)
    {
        if (!File.Exists(input)) throw new FileNotFoundException("Select a dump file", input);
        if (minLength < 4 || minLength > 64) throw new ArgumentOutOfRangeException(nameof(minLength));
        Directory.CreateDirectory(folder);
        var info = new FileInfo(input);
        string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string stem = Path.Combine(folder, Path.GetFileName(input) + "_" + stamp);
        string stringsPath = stem + ".strings.txt", reportPath = stem + ".analysis.json";
        await Task.Run(() =>
        {
            using var stream = File.OpenRead(input);
            using var strings = new StreamWriter(stringsPath, false, Encoding.UTF8);
            using var sha = SHA256.Create();
            byte[] buffer = new byte[Chunk];
            var ascii = new StringBuilder();
            long start = 0, offset = 0;
            long[] counts = new long[256];
            long emitted = 0;
            void Flush()
            {
                if (ascii.Length >= minLength && emitted < 200000)
                {
                    strings.WriteLine($"0x{start:X12}  {ascii}"); emitted++;
                }
                ascii.Clear();
            }
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                int n = stream.Read(buffer, 0, buffer.Length);
                if (n == 0) break;
                sha.TransformBlock(buffer, 0, n, buffer, 0);
                for (int i = 0; i < n; i++)
                {
                    byte b = buffer[i]; counts[b]++;
                    if (b is >= 32 and <= 126 || b == 9)
                    {
                        if (ascii.Length == 0) start = offset;
                        if (ascii.Length < 4096) ascii.Append((char)b);
                    }
                    else Flush();
                    offset++;
                }
            }
            Flush();
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            double entropy = 0;
            foreach (long c in counts) if (c != 0) { double p = c / (double)offset; entropy -= p * Math.Log2(p); }
            File.WriteAllText(reportPath, JsonSerializer.Serialize(new
            {
                File = info.FullName, info.Length, SHA256 = Convert.ToHexString(sha.Hash!), ShannonEntropy = entropy,
                StringsExtracted = emitted, StringMinimum = minLength, StringsFile = stringsPath,
                AnalyzedAt = DateTimeOffset.Now
            }, new JsonSerializerOptions { WriteIndented = true }));
        }, ct);
        return reportPath;
    }
}
