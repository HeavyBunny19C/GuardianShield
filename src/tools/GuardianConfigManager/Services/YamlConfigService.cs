using System.IO;
using GuardianConfigManager.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace GuardianConfigManager.Services;

public static class YamlConfigService
{
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static readonly ISerializer Serializer = new SerializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.Preserve)
        .Build();

    public static GuardianConfig Load(string path)
    {
        var yaml = File.ReadAllText(path);
        return Deserializer.Deserialize<GuardianConfig>(yaml) ?? new GuardianConfig();
    }

    public static void Save(string path, GuardianConfig config)
    {
        var header =
            "# ================================================================\r\n" +
            "# GuardianShield 统一配置文件 (guardian_config.yaml)\r\n" +
            "# ================================================================\r\n" +
            "# 由 GuardianConfigManager 生成\r\n" +
            "#\r\n" +
            "# 【留空规则】(阈值字段)\r\n" +
            "#   - 填写正整数: 按该阈值检测\r\n" +
            "#   - 留空或设为 0: 不限制该类行为（跳过该项检测）\r\n" +
            "#   - 删除该行或注释掉: 使用系统内置默认值\r\n" +
            "# ================================================================\r\n\r\n";
        var yaml = Serializer.Serialize(config);
        File.WriteAllText(path, header + yaml);
    }

    public static string GetDefaultConfigPath()
    {
        var found = FindConfigFileUpward("guardian_config.yaml");
        if (!string.IsNullOrEmpty(found)) return found;

        var pd = @"C:\ProgramData\GuardianShield\config\guardian_config.yaml";
        return File.Exists(pd) ? pd : "";
    }

    internal static string FindConfigFileUpward(string fileName)
    {
        var dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            var candidate = Path.Combine(dir, "config", fileName);
            if (File.Exists(candidate)) return candidate;
            dir = Directory.GetParent(dir)?.FullName;
        }
        return "";
    }

    internal static string? FindConfigDirUpward()
    {
        var dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            var candidate = Path.Combine(dir, "config");
            if (Directory.Exists(candidate)) return candidate;
            dir = Directory.GetParent(dir)?.FullName;
        }
        return null;
    }
}
