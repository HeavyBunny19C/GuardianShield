/**
 * @file config.h
 * @brief 配置管理模块 - 支持配置缓存机制
 * 
 * 版本: 2.0
 * 更新日期: 2026-03-02
 * 
 * 缓存机制：
 * - 配置文件读取成功 → 保存到缓存
 * - 配置文件读取失败 → 从缓存恢复上一次成功读取的配置
 * - 缓存也失败 → 使用默认配置
 */

#pragma once

#include "common_types.h"
#include <string>
#include <memory>
#include <functional>

#ifdef HAS_YAML_CPP
#include <yaml-cpp/yaml.h>
#endif

namespace Guardian {

/**
 * @brief Configuration change callback type
 */
using ConfigChangeCallback = std::function<void(const std::string& key)>;

/**
 * @brief 配置来源
 */
enum class ConfigSource {
    FILE,       // 从配置文件读取
    CACHE,      // 从缓存恢复
    DEFAULT     // 使用默认值
};

/**
 * @brief Configuration Manager
 * 
 * Manages system configuration loaded from YAML files.
 * Provides validation and type-safe access to settings.
 */
class Config {
public:
    /**
     * @brief Construct configuration from file
     * @param configPath Path to YAML configuration file
     */
    explicit Config(const std::wstring& configPath);
    ~Config();
    
    // Non-copyable
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    
    /**
     * @brief Load configuration from file
     * @return true if successful
     */
    bool Load();

    /**
     * @brief 在 auth 加载完成后，统一保存缓存并删除源文件
     */
    bool SecureDeleteSources();

    /**
     * @brief Reload configuration from file
     * @return true if successful
     */
    bool Reload();
    
    /**
     * @brief Validate configuration
     * @return true if configuration is valid
     * @note Detection thresholds (file_write_count, file_delete_count, etc.) allow 0:
     *       0 = no restriction (that batch check is disabled). Negative values are invalid.
     */
    bool Validate() const;
    
    /**
     * @brief Get configuration file path
     */
    const std::wstring& GetConfigPath() const { return m_configPath; }
    
    /**
     * @brief 获取配置来源
     */
    ConfigSource GetConfigSource() const { return m_source; }
    
    /**
     * @brief 获取缓存文件路径
     */
    std::wstring GetCachePath() const;
    
    /**
     * @brief 清除缓存
     */
    bool ClearCache();
    // ========================================
    // System Settings
    // ========================================
    
    std::string GetVersion() const;
    std::string GetLogLevel() const;
    std::wstring GetLogPath() const;
    
    // ========================================
    // Protection Settings
    // ========================================
    
    /**
     * @brief Get list of protected directories
     */
    std::vector<ProtectedDirectory> GetProtectedDirectories() const;
    
    /**
     * @brief Check if path is protected
     */
    bool IsPathProtected(const std::wstring& path) const;
    
    // ========================================
    // Whitelist Settings
    // ========================================
    
    /**
     * @brief Get process whitelist
     */
    std::vector<WhitelistProcess> GetProcessWhitelist() const;
    
    /**
     * @brief Check if process is whitelisted
     * @param processName Process name (e.g., "devenv.exe")
     * @param permission Required permission (optional)
     * @param fullPath Full process image path for path_prefix verification (optional)
     */
    bool IsProcessWhitelisted(const std::wstring& processName, 
                              const std::wstring& permission = L"",
                              const std::wstring& fullPath = L"") const;
    
    /**
     * @brief Check if file type is monitored based on include/exclude lists
     * @param filePath Full file path to check extension of
     * @return true if monitored (include list empty = all monitored)
     */
    bool IsFileTypeMonitored(const std::wstring& filePath) const;
    
    // ========================================
    // Detection Settings
    // ========================================
    
    /**
     * @brief Get detection rules
     */
    std::vector<DetectionRule> GetDetectionRules() const;
    
    /**
     * @brief Get rule by ID
     */
    bool GetRule(const std::string& id, DetectionRule& rule) const;
    
    /**
     * @brief Get configured response action bitmask for a single event type
     */
    ResponseAction GetEventResponse(DriverEventType eventType) const;
    
    /**
     * @brief Get Tier-1 detection thresholds (protection protocol)
     */
    int GetFileWriteThreshold() const;
    int GetFileWriteWindowSeconds() const;
    int GetFileCompressThreshold() const;
    int GetFileCompressWindowSeconds() const;
    int GetFileDeleteThreshold() const;
    int GetFileDeleteWindowSeconds() const;
    int GetFileNetworkTransferThreshold() const;
    int GetFileNetworkTransferWindowSeconds() const;
    int GetDataTransferThresholdMB() const;
    int GetProcessTerminationCount() const;
    int GetProcessTerminationWindowSeconds() const;
    
    /**
     * @brief Get Tier-2 detection thresholds (emergency protocol)
     */
    int GetTier2FileWriteThreshold() const;
    int GetTier2FileWriteWindowSeconds() const;
    int GetTier2FileCompressThreshold() const;
    int GetTier2FileCompressWindowSeconds() const;
    int GetTier2FileDeleteThreshold() const;
    int GetTier2FileDeleteWindowSeconds() const;
    int GetTier2FileNetworkTransferThreshold() const;
    int GetTier2FileNetworkTransferWindowSeconds() const;
    int GetTier2DataTransferThresholdMB() const;
    int GetTier2ProcessTerminationCount() const;
    int GetTier2ProcessTerminationWindowSeconds() const;
    
    int GetFileCreateThreshold() const;
    int GetFileCreateWindowSeconds() const;
    int GetTier2FileCreateThreshold() const;
    int GetTier2FileCreateWindowSeconds() const;
    
    int GetFileRenameThreshold() const;
    int GetFileRenameWindowSeconds() const;
    int GetFileMoveThreshold() const;
    int GetFileMoveWindowSeconds() const;
    int GetTier2FileRenameThreshold() const;
    int GetTier2FileRenameWindowSeconds() const;
    int GetTier2FileMoveThreshold() const;
    int GetTier2FileMoveWindowSeconds() const;
    
    /**
     * @brief Get admin settings
     */
    std::string GetAdminPasswordHash() const;
    std::string GetInstallKeyHash() const;
    int GetUnlockTimeoutSeconds() const;
    int GetAlertTimeoutSeconds() const;
    
    /**
     * @brief Get log settings
     */
    int GetLogRetentionDays() const;
    bool GetLogDailyRotation() const;
    std::string GetLogFormat() const;
    
    /**
     * @brief Get authorization list path
     */
    std::wstring GetAuthorizationListPath() const;
    
    struct CachedAuthEntry {
        std::string ip;
        std::string mac;
        std::string description;
    };
    void SetCachedAuthEntries(const std::vector<CachedAuthEntry>& entries);
    std::vector<CachedAuthEntry> GetCachedAuthEntries() const;
    bool HasCachedAuthEntries() const;
    // ========================================
    // Emergency Settings
    // ========================================
    
    int GetEncryptTimeoutSeconds() const;
    int GetRecoveryWaitSeconds() const;
    std::string GetWipeMethod() const;
    
    // ========================================
    // Communication Settings
    // ========================================
    
    uint16_t GetTcpPortBase() const;
    bool IsTlsEnabled() const;
    
    // ========================================
    // Change Notification
    // ========================================
    
    /**
     * @brief Register callback for configuration changes
     */
    void RegisterChangeCallback(ConfigChangeCallback callback);
    
    /**
     * @brief Start watching configuration file for changes
     */
    void StartWatching();
    
    /**
     * @brief Stop watching configuration file
     */
    void StopWatching();
    
    // ========================================
    // System Configuration
    // ========================================
    
    /**
     * @brief Get complete system configuration
     */
    SystemConfig GetSystemConfig() const;
    
    /**
     * @brief Update system configuration
     */
    bool UpdateSystemConfig(const SystemConfig& config);
    
    /**
     * @brief Save configuration to file
     */
    bool Save();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    std::wstring m_configPath;
    
    // 缓存相关方法
    bool LoadFromCache();
    bool SaveToCache();
    
    // 读取成功后删除原始 YAML（"钥匙"回收）
    void DeleteConfigFile();
    
    // 设置缓存文件 ACL，仅 SYSTEM + Administrators 可访问
    void SetCacheFilePermissions(const std::wstring& path);
    
    // 配置来源
    ConfigSource m_source = ConfigSource::DEFAULT;
    
    // Fallback simple parser
    bool LoadSimple();

#ifdef HAS_YAML_CPP
    bool LoadYaml();
#endif
};

/**
 * @brief Global configuration instance
 */
extern std::shared_ptr<Config> g_config;

/**
 * @brief Initialize global configuration
 */
inline void InitializeConfig(const std::wstring& configPath) {
    g_config = std::make_shared<Config>(configPath);
}

/**
 * @brief Get global configuration
 */
inline std::shared_ptr<Config> GetConfig() {
    return g_config;
}

} // namespace Guardian
