using YamlDotNet.Serialization;

namespace GuardianConfigManager.Models;

public class GuardianConfig
{
    [YamlMember(Alias = "system")]
    public SystemConfig System { get; set; } = new();

    [YamlMember(Alias = "detection")]
    public DetectionConfig Detection { get; set; } = new();

    [YamlMember(Alias = "protection")]
    public ProtectionConfig Protection { get; set; } = new();

    [YamlMember(Alias = "authorization")]
    public AuthorizationConfig Authorization { get; set; } = new();

    [YamlMember(Alias = "logging")]
    public LoggingConfig Logging { get; set; } = new();

    [YamlMember(Alias = "admin")]
    public AdminConfig Admin { get; set; } = new();

    [YamlMember(Alias = "whitelist")]
    public WhitelistConfig Whitelist { get; set; } = new();

    [YamlMember(Alias = "emergency")]
    public EmergencyConfig Emergency { get; set; } = new();

    [YamlMember(Alias = "communication")]
    public CommunicationConfig Communication { get; set; } = new();

    [YamlMember(Alias = "keys")]
    public KeysConfig Keys { get; set; } = new();
}

// ---- system ----
public class SystemConfig
{
    [YamlMember(Alias = "version")]
    public string Version { get; set; } = "2.0.0";

    [YamlMember(Alias = "config_version")]
    public int ConfigVersion { get; set; } = 1;

    [YamlMember(Alias = "log_level")]
    public string LogLevel { get; set; } = "INFO";

    [YamlMember(Alias = "log_path")]
    public string LogPath { get; set; } = @"C:\ProgramData\GuardianShield\logs";
}

// ---- detection ----
public class DetectionConfig
{
    [YamlMember(Alias = "rules")]
    public List<DetectionRule> Rules { get; set; } = new();

    [YamlMember(Alias = "alert_timeout_seconds")]
    public int AlertTimeoutSeconds { get; set; } = 30;

    [YamlMember(Alias = "thresholds")]
    public ThresholdsConfig Thresholds { get; set; } = new();
}

public class DetectionRule
{
    [YamlMember(Alias = "id")]
    public string Id { get; set; } = "";

    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; } = true;

    [YamlMember(Alias = "action")]
    public string Action { get; set; } = "LOG";
}

public class ThresholdsConfig
{
    [YamlMember(Alias = "tier1")]
    public TierThresholds Tier1 { get; set; } = new();

    [YamlMember(Alias = "tier2")]
    public TierThresholds Tier2 { get; set; } = new TierThresholds
    {
        FileWriteCount = 50, FileWriteWindowSeconds = 10,
        FileCompressCount = 250, FileCompressWindowSeconds = 10,
        FileDeleteCount = 20, FileDeleteWindowSeconds = 10,
        FileNetworkTransferCount = 40, FileNetworkTransferWindowSeconds = 10,
        DataTransferMb = 10, ProcessTerminationCount = 6
    };
}

public class TierThresholds
{
    [YamlMember(Alias = "file_write_count")]
    public int? FileWriteCount { get; set; } = 10;

    [YamlMember(Alias = "file_write_window_seconds")]
    public int? FileWriteWindowSeconds { get; set; } = 5;

    [YamlMember(Alias = "file_compress_count")]
    public int? FileCompressCount { get; set; } = 50;

    [YamlMember(Alias = "file_compress_window_seconds")]
    public int? FileCompressWindowSeconds { get; set; } = 5;

    [YamlMember(Alias = "file_delete_count")]
    public int? FileDeleteCount { get; set; } = 5;

    [YamlMember(Alias = "file_delete_window_seconds")]
    public int? FileDeleteWindowSeconds { get; set; } = 5;

    [YamlMember(Alias = "file_network_transfer_count")]
    public int? FileNetworkTransferCount { get; set; } = 10;

    [YamlMember(Alias = "file_network_transfer_window_seconds")]
    public int? FileNetworkTransferWindowSeconds { get; set; } = 5;

    [YamlMember(Alias = "data_transfer_mb")]
    public int? DataTransferMb { get; set; } = 1;

    [YamlMember(Alias = "process_termination_count")]
    public int? ProcessTerminationCount { get; set; } = 2;
}

// ---- protection ----
public class ProtectionConfig
{
    [YamlMember(Alias = "directories")]
    public List<ProtectedDirectory> Directories { get; set; } = new();

    [YamlMember(Alias = "file_types")]
    public FileTypesConfig FileTypes { get; set; } = new();
}

public class ProtectedDirectory
{
    [YamlMember(Alias = "path")]
    public string Path { get; set; } = "";

    [YamlMember(Alias = "recursive")]
    public bool Recursive { get; set; } = true;

    [YamlMember(Alias = "priority")]
    public string Priority { get; set; } = "HIGH";
}

public class FileTypesConfig
{
    [YamlMember(Alias = "include")]
    public List<string> Include { get; set; } = new();

    [YamlMember(Alias = "exclude")]
    public List<string> Exclude { get; set; } = new();
}

// ---- authorization ----
public class AuthorizationConfig
{
    [YamlMember(Alias = "list_path")]
    public string ListPath { get; set; } = @"C:\ProgramData\GuardianShield\config\auth.list";

    [YamlMember(Alias = "check_on_boot")]
    public bool CheckOnBoot { get; set; } = true;

    [YamlMember(Alias = "strict_mode")]
    public bool StrictMode { get; set; } = true;
}

// ---- logging ----
public class LoggingConfig
{
    [YamlMember(Alias = "path")]
    public string Path { get; set; } = @"C:\ProgramData\GuardianShield\logs";

    [YamlMember(Alias = "format")]
    public string Format { get; set; } = "json";

    [YamlMember(Alias = "retention_days")]
    public int RetentionDays { get; set; } = 7;

    [YamlMember(Alias = "daily_rotation")]
    public bool DailyRotation { get; set; } = true;
}

// ---- admin ----
public class AdminConfig
{
    [YamlMember(Alias = "password_hash")]
    public string PasswordHash { get; set; } = "";

    [YamlMember(Alias = "install_key_hash")]
    public string InstallKeyHash { get; set; } = "";

    [YamlMember(Alias = "unlock_timeout_seconds")]
    public int UnlockTimeoutSeconds { get; set; } = 30;
}

// ---- whitelist ----
public class WhitelistConfig
{
    [YamlMember(Alias = "processes")]
    public List<WhitelistProcess> Processes { get; set; } = new();
}

public class WhitelistProcess
{
    [YamlMember(Alias = "name")]
    public string Name { get; set; } = "";

    [YamlMember(Alias = "description")]
    public string Description { get; set; } = "";

    [YamlMember(Alias = "permissions")]
    public List<string> Permissions { get; set; } = new();

    [YamlMember(Alias = "conditions")]
    public List<WhitelistCondition>? Conditions { get; set; }
}

public class WhitelistCondition
{
    [YamlMember(Alias = "user")]
    public string User { get; set; } = "";
}

// ---- emergency ----
public class EmergencyConfig
{
    [YamlMember(Alias = "encrypt_timeout_seconds")]
    public int EncryptTimeoutSeconds { get; set; } = 30;

    [YamlMember(Alias = "recovery_wait_seconds")]
    public int RecoveryWaitSeconds { get; set; } = 30;

    [YamlMember(Alias = "wipe_method")]
    public string WipeMethod { get; set; } = "DOD_5220";

    [YamlMember(Alias = "notifications")]
    public List<NotificationChannel> Notifications { get; set; } = new();
}

public class NotificationChannel
{
    [YamlMember(Alias = "type")]
    public string Type { get; set; } = "EMAIL";

    [YamlMember(Alias = "recipients")]
    public List<string>? Recipients { get; set; }

    [YamlMember(Alias = "url")]
    public string? Url { get; set; }
}

// ---- communication ----
public class CommunicationConfig
{
    [YamlMember(Alias = "named_pipe")]
    public NamedPipeConfig NamedPipe { get; set; } = new();

    [YamlMember(Alias = "shared_memory")]
    public SharedMemoryConfig SharedMemory { get; set; } = new();

    [YamlMember(Alias = "tcp")]
    public TcpConfig Tcp { get; set; } = new();
}

public class NamedPipeConfig
{
    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; } = true;

    [YamlMember(Alias = "timeout_ms")]
    public int TimeoutMs { get; set; } = 5000;
}

public class SharedMemoryConfig
{
    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; } = true;

    [YamlMember(Alias = "size_kb")]
    public int SizeKb { get; set; } = 4;
}

public class TcpConfig
{
    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; } = true;

    [YamlMember(Alias = "port_base")]
    public int PortBase { get; set; } = 17500;

    [YamlMember(Alias = "tls")]
    public bool Tls { get; set; } = true;
}

// ---- keys ----
public class KeysConfig
{
    [YamlMember(Alias = "tpm")]
    public TpmConfig Tpm { get; set; } = new();

    [YamlMember(Alias = "encryption")]
    public EncryptionConfig Encryption { get; set; } = new();
}

public class TpmConfig
{
    [YamlMember(Alias = "enabled")]
    public bool Enabled { get; set; } = true;

    [YamlMember(Alias = "pcr_indices")]
    public List<int> PcrIndices { get; set; } = new() { 0, 1, 2, 3, 4, 5, 6, 7 };
}

public class EncryptionConfig
{
    [YamlMember(Alias = "algorithm")]
    public string Algorithm { get; set; } = "AES-256-GCM";

    [YamlMember(Alias = "key_rotation_days")]
    public int KeyRotationDays { get; set; } = 30;
}
