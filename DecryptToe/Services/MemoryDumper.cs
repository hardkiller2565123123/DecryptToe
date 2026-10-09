using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using DecryptToe.Models;

namespace DecryptToe.Services;

public static class MemoryDumper
{
    const uint PROCESS_VM_READ = 0x0010;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const int ChunkSize = 64 * 1024;
    const int PageSize = 4096;
    const int MaxModuleSize = 1024 * 1024 * 1024;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [Out] byte[] buffer, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);

    public static List<ModuleItem> EnumerateModules(Process process)
    {
        process.Refresh();
        var result = new List<ModuleItem>();
        foreach (ProcessModule module in process.Modules)
            result.Add(new ModuleItem(module.ModuleName, module.FileName, module.BaseAddress.ToInt64(), module.ModuleMemorySize));
        return result.OrderBy(m => m.BaseAddress).ToList();
    }

    public static async Task<string> DumpAsync(int pid, ModuleItem module, string outputDirectory,
        IProgress<double>? progress, Action<string>? log, CancellationToken token)
    {
        if (module.Size <= 0 || module.Size > MaxModuleSize)
            throw new InvalidOperationException("Module size is invalid or over the 1 GB safety limit.");

        Directory.CreateDirectory(outputDirectory);
        var handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read this process. Check permissions and whether it is protected.");
        try
        {
            var image = new byte[module.Size];
            int missingPages = 0;
            await Task.Run(() =>
            {
                for (int offset = 0; offset < module.Size; offset += ChunkSize)
                {
                    token.ThrowIfCancellationRequested();
                    int count = Math.Min(ChunkSize, module.Size - offset);
                    if (!TryRead(handle, module.BaseAddress + offset, image, offset, count))
                    {
                        // A partially unreadable region should not discard the whole module.
                        for (int p = 0; p < count; p += PageSize)
                        {
                            int len = Math.Min(PageSize, count - p);
                            if (!TryRead(handle, module.BaseAddress + offset + p, image, offset + p, len))
                                missingPages++;
                        }
                    }
                    progress?.Report((double)(offset + count) / module.Size);
                }
            }, token);

            string baseName = string.Concat(module.Name.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));
            string stem = $"{Path.GetFileNameWithoutExtension(baseName)}_{pid}_{DateTime.Now:yyyyMMdd_HHmmss}";
            string rawPath = Path.Combine(outputDirectory, stem + ".memory.bin");
            string pePath = Path.Combine(outputDirectory, stem + ".reconstructed.exe");
            string infoPath = Path.Combine(outputDirectory, stem + ".json");
            await File.WriteAllBytesAsync(rawPath, image, token);
            bool peOk = TryBuildReconstructedPe(image, out var reconstructed, out var peMessage);
            if (peOk) await File.WriteAllBytesAsync(pePath, reconstructed!, token);
            var info = new
            {
                ProcessId = pid,
                module.Name,
                module.Path,
                BaseAddress = $"0x{module.BaseAddress:X}",
                ImageSize = module.Size,
                MissingPages = missingPages,
                RawDump = rawPath,
                ReconstructedPe = peOk ? pePath : null,
                ReconstructionStatus = peMessage,
                CapturedAt = DateTimeOffset.Now,
                Note = "Memory snapshot; reconstructed PE is best-effort, not a runnable executable. No encryption keys or protected-process bypasses are provided."
            };
            await File.WriteAllTextAsync(infoPath, JsonSerializer.Serialize(info, new JsonSerializerOptions { WriteIndented = true }), token);
            log?.Invoke($"Saved raw memory: {rawPath}");
            log?.Invoke(peOk ? $"Saved analysis PE: {pePath}" : $"Reconstruction skipped: {peMessage}");
            log?.Invoke($"Unreadable 4KB pages: {missingPages}; report: {infoPath}");
            return rawPath;
        }
        finally { CloseHandle(handle); }
    }

    static bool TryRead(IntPtr handle, long address, byte[] destination, int destinationOffset, int size)
    {
        var block = new byte[size];
        bool success = ReadProcessMemory(handle, new IntPtr(address), block, new IntPtr(size), out var count);
        if (count.ToInt64() > 0)
            Buffer.BlockCopy(block, 0, destination, destinationOffset, (int)Math.Min(count.ToInt64(), size));
        return success && count.ToInt64() == size;
    }

    // Transform in-memory RVAs to file offsets so IDA/Ghidra can open the image.
    // The image includes relocations already applied by the Windows loader.
    static bool TryBuildReconstructedPe(byte[] memory, out byte[]? output, out string status)
    {
        output = null;
        status = "Unrecognized image";
        try
        {
            if (memory.Length < 0x100 || BitConverter.ToUInt16(memory, 0) != 0x5A4D) return false;
            int pe = BitConverter.ToInt32(memory, 0x3C);
            if (pe < 0 || pe > memory.Length - 0x200 || BitConverter.ToUInt32(memory, pe) != 0x00004550) return false;
            int sectionCount = BitConverter.ToUInt16(memory, pe + 6);
            int optionalSize = BitConverter.ToUInt16(memory, pe + 20);
            int sectionTable = checked(pe + 24 + optionalSize);
            if (sectionCount < 1 || sectionCount > 96 || sectionTable > memory.Length - sectionCount * 40) return false;
            int magic = BitConverter.ToUInt16(memory, pe + 24);
            if (magic != 0x20B && magic != 0x10B) { status = "Unsupported PE optional header"; return false; }
            output = (byte[])memory.Clone();
            uint fileAlignment = BitConverter.ToUInt32(memory, pe + 24 + 36);
            if (fileAlignment is < 1 or > 65536 || (fileAlignment & (fileAlignment - 1)) != 0) fileAlignment = 512;
            for (int s = 0; s < sectionCount; s++)
            {
                int at = sectionTable + s * 40;
                uint virtualSize = BitConverter.ToUInt32(memory, at + 8);
                uint rva = BitConverter.ToUInt32(memory, at + 12);
                uint originalRawSize = BitConverter.ToUInt32(memory, at + 16);
                if (rva >= memory.Length) continue;
                uint available = (uint)(memory.Length - rva);
                uint wanted = Math.Max(virtualSize, originalRawSize);
                uint rawSize = Math.Min(available, (wanted + fileAlignment - 1) / fileAlignment * fileAlignment);
                BitConverter.GetBytes(rawSize).CopyTo(output, at + 16);
                BitConverter.GetBytes(rva).CopyTo(output, at + 20);
            }
            status = "Best-effort PE reconstructed using memory-layout section offsets";
            return true;
        }
        catch (Exception ex) { output = null; status = ex.Message; return false; }
    }
}
