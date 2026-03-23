using System.IO;
using GuardianConfigManager.Models;

namespace GuardianConfigManager.Services;

public static class AuthListService
{
    public static List<AuthEntry> Load(string path)
    {
        var entries = new List<AuthEntry>();
        if (!File.Exists(path)) return entries;

        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#'))
                continue;

            var parts = line.Split(',', 3);
            entries.Add(new AuthEntry
            {
                Ip = parts.Length > 0 ? parts[0].Trim() : "",
                Mac = parts.Length > 1 ? parts[1].Trim() : "",
                Description = parts.Length > 2 ? parts[2].Trim() : ""
            });
        }
        return entries;
    }

    public static void Save(string path, IEnumerable<AuthEntry> entries)
    {
        var lines = new List<string>
        {
            "# GuardianShield 授权清单",
            "# 格式: IP地址,MAC地址,备注",
            "# 支持通配符: IP 或 MAC 可设为 * 表示任意匹配"
        };

        foreach (var e in entries)
        {
            if (string.IsNullOrWhiteSpace(e.Ip)) continue;
            lines.Add($"{e.Ip},{e.Mac},{e.Description}");
        }

        File.WriteAllLines(path, lines);
    }

    public static string GetDefaultAuthPath()
    {
        var found = YamlConfigService.FindConfigFileUpward("auth.list");
        if (!string.IsNullOrEmpty(found)) return found;

        var pd = @"C:\ProgramData\GuardianShield\config\auth.list";
        return File.Exists(pd) ? pd : "";
    }
}
