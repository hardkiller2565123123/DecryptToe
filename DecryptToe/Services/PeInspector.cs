using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DecryptToe.Services;

/// <summary>Read-only analysis of on-disk Windows PE metadata; never changes the executable.</summary>
public static class PeInspector
{
    public static string Inspect(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var br = new BinaryReader(fs, Encoding.ASCII, leaveOpen: true);
        long length = fs.Length;
        if (length < 64 || br.ReadUInt16() != 0x5A4D) return "Not a valid MZ executable.";
        fs.Position = 0x3C;
        uint peOffset = br.ReadUInt32();
        if (peOffset < 64 || peOffset > length - 24 || peOffset > 16 * 1024 * 1024) return "Invalid PE header offset.";
        fs.Position = peOffset;
        if (br.ReadUInt32() != 0x00004550) return "PE signature not found.";
        ushort machine = br.ReadUInt16();
        ushort sectionCount = br.ReadUInt16();
        uint timeStamp = br.ReadUInt32();
        br.ReadUInt32(); br.ReadUInt32();
        ushort optionalSize = br.ReadUInt16();
        ushort characteristics = br.ReadUInt16();
        if (sectionCount > 96 || optionalSize < 96 || fs.Position + optionalSize + sectionCount * 40L > length)
            return "PE headers appear truncated or malformed.";
        long opt = fs.Position;
        ushort magic = br.ReadUInt16();
        if (magic != 0x10B && magic != 0x20B) return "Unknown PE optional-header format.";
        bool is64 = magic == 0x20B;
        fs.Position = opt + 16; uint entry = br.ReadUInt32();
        fs.Position = opt + (is64 ? 24 : 28);
        ulong imageBase = is64 ? br.ReadUInt64() : br.ReadUInt32();
        fs.Position = opt + 56; uint imageSize = br.ReadUInt32();
        fs.Position = opt + 60; uint headerSize = br.ReadUInt32();
        fs.Position = opt + 68; ushort subsystem = br.ReadUInt16();
        fs.Position = opt + (is64 ? 108 : 92);
        uint dirCount = br.ReadUInt32();
        uint importRva = 0, importSize = 0;
        if (dirCount > 1 && optionalSize >= (is64 ? 128 : 112))
        {
            fs.Position = opt + (is64 ? 120 : 104);
            importRva = br.ReadUInt32(); importSize = br.ReadUInt32();
        }
        fs.Position = opt + optionalSize;
        var sections = new List<Section>();
        for (int i = 0; i < sectionCount; i++)
        {
            string name = Encoding.ASCII.GetString(br.ReadBytes(8)).TrimEnd('\0');
            uint vSize = br.ReadUInt32(), vAddr = br.ReadUInt32(), rawSize = br.ReadUInt32(), rawPtr = br.ReadUInt32();
            br.ReadUInt32(); br.ReadUInt32(); br.ReadUInt16(); br.ReadUInt16();
            uint flags = br.ReadUInt32();
            sections.Add(new Section(name, vAddr, vSize, rawPtr, rawSize, flags));
        }
        var sb = new StringBuilder();
        sb.AppendLine("PORTABLE EXECUTABLE  /  STATIC ANALYSIS");
        sb.AppendLine($"Architecture     {MachineName(machine)}  ({(is64 ? "PE32+" : "PE32")})");
        sb.AppendLine($"Entry point      RVA 0x{entry:X8}   VA 0x{imageBase + entry:X}");
        sb.AppendLine($"Image base       0x{imageBase:X}");
        sb.AppendLine($"Image size       {imageSize / 1048576d:N2} MiB    Header size  {headerSize:N0} bytes");
        sb.AppendLine($"Subsystem        {SubsystemName(subsystem)}");
        sb.AppendLine($"Build timestamp  {FormatStamp(timeStamp)} (PE header; may be modified)");
        sb.AppendLine($"Characteristics  0x{characteristics:X4}");
        return sb.ToString();
    }
    static string MachineName(ushort value) => value switch { 0x8664 => "x64 / AMD64", 0x14C => "x86 / i386", 0xAA64 => "ARM64", 0x1C0 => "ARM", _ => $"0x{value:X4}" };
    static string SubsystemName(ushort value) => value switch { 2 => "Windows GUI", 3 => "Windows Console", 1 => "Native", 10 => "EFI application", _ => value.ToString() };
    static string FormatStamp(uint stamp) { try { return DateTimeOffset.FromUnixTimeSeconds(stamp).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'"); } catch { return $"0x{stamp:X8}"; } }
    static string Flags(uint flags) => $"{((flags & 0x20000000) != 0 ? "X" : "-")}{((flags & 0x40000000) != 0 ? "R" : "-")}{((flags & 0x80000000) != 0 ? "W" : "-")}";
    static long? RvaOffset(uint rva, List<Section> sections, uint headerSize, long fileSize)
    {
        if (rva < headerSize && rva < fileSize) return rva;
        foreach (var s in sections)
        {
            if ((ulong)rva >= s.VirtualAddress && (ulong)rva < (ulong)s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize))
            {
                long off = (long)s.RawPointer + (rva - s.VirtualAddress);
                if (off >= 0 && off < fileSize && (rva - s.VirtualAddress) < s.RawSize) return off;
            }
        }
        return null;
    }
    static string ReadAscii(FileStream fs, long offset, int max)
    {
        fs.Position = offset;
        var bytes = new List<byte>();
        for (int i = 0; i < max && fs.Position < fs.Length; i++)
        {
            int b = fs.ReadByte(); if (b <= 0) break;
            if (b < 32 || b > 126) break;
            bytes.Add((byte)b);
        }
        return Encoding.ASCII.GetString(bytes.ToArray());
    }
    static double? Entropy(FileStream fs, uint rawPointer, uint rawSize, long length)
    {
        if (rawSize == 0 || rawPointer >= length) return null;
        long remaining = Math.Min((long)rawSize, length - rawPointer);
        // Sample at most 8 MiB per section; avoids reading multi-gigabyte game assets.
        remaining = Math.Min(remaining, 8 * 1024 * 1024);
        fs.Position = rawPointer;
        var counts = new long[256]; var buffer = new byte[65536]; long total = 0;
        while (remaining > 0)
        {
            int n = fs.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (n <= 0) break;
            for (int i = 0; i < n; i++) counts[buffer[i]]++;
            total += n; remaining -= n;
        }
        if (total == 0) return null;
        double value = 0;
        foreach (long count in counts) if (count > 0) { double p = count / (double)total; value -= p * Math.Log2(p); }
        return value;
    }
    readonly record struct Section(string Name, uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize, uint Flags);
}
