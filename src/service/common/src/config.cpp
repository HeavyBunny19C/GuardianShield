/**
 * @file config.cpp
 * @brief 配置管理实现 - 支持配置缓存机制
 * 
 * 版本: 3.2
 * 更新日期: 2026-03-17
 * 
 * 缓存机制说明：
 * - 配置文件读取成功 → 保存到缓存，更新当前配置
 * - 配置文件读取失败 → 从缓存恢复上一次成功的配置
 * - 缓存也失败 → 使用默认配置
 */

#include "config.h"
#include "logger.h"
#include "../include/string_utils.h"
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <thread>
#include <atomic>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#include <sddl.h>
#include <aclapi.h>
#pragma comment(lib, "Advapi32.lib")
#endif

#ifdef HAS_YAML_CPP
#include <yaml-cpp/yaml.h>
#endif

namespace Guardian {

class Config::Impl {
public:
    SystemConfig config;
    std::vector<ConfigChangeCallback> callbacks;
    
    // Tier 1 detection thresholds (protection protocol: encrypt + lock)
    int fileWriteThreshold = 10;
    int fileWriteWindowSeconds = 5;
    int fileCompressThreshold = 50;
    int fileCompressWindowSeconds = 5;
    int fileDeleteThreshold = 5;
    int fileDeleteWindowSeconds = 5;
    int fileCreateThreshold = 15;
    int fileCreateWindowSeconds = 5;
    int fileRenameThreshold = 10;
    int fileRenameWindowSeconds = 5;
    int fileMoveThreshold = 10;
    int fileMoveWindowSeconds = 5;
    int fileNetworkTransferThreshold = 10;
    int fileNetworkTransferWindowSeconds = 5;
    int dataTransferMB = 1;
    int processTerminationCount = 2;
    int processTerminationWindowSeconds = 5;
    
    // Tier 2 detection thresholds (emergency protocol: encrypt + wipe + delete)
    int tier2FileWriteThreshold = 50;
    int tier2FileWriteWindowSeconds = 10;
    int tier2FileCompressThreshold = 250;
    int tier2FileCompressWindowSeconds = 10;
    int tier2FileDeleteThreshold = 20;
    int tier2FileDeleteWindowSeconds = 10;
    int tier2FileCreateThreshold = 50;
    int tier2FileCreateWindowSeconds = 10;
    int tier2FileRenameThreshold = 50;
    int tier2FileRenameWindowSeconds = 10;
    int tier2FileMoveThreshold = 50;
    int tier2FileMoveWindowSeconds = 10;
    int tier2FileNetworkTransferThreshold = 40;
    int tier2FileNetworkTransferWindowSeconds = 10;
    int tier2DataTransferMB = 10;
    int tier2ProcessTerminationCount = 6;
    int tier2ProcessTerminationWindowSeconds = 5;
    
    // 管理员密码
    std::string adminPasswordHash;
    std::string installKey;
    int unlockTimeoutSeconds = 30;
    int alertTimeoutSeconds = 30;
    
    // 授权条目缓存
    struct AuthEntry {
        std::string ip;
        std::string mac;
        std::string description;
    };
    std::vector<AuthEntry> cachedAuthEntries;
    
    // File type include/exclude lists (from protection.file_types)
    std::vector<std::wstring> includeFileTypes;
    std::vector<std::wstring> excludeFileTypes;
    
    // 日志设置
    std::wstring logPath = L"C:\\ProgramData\\GuardianShield\\logs";
    int logRetentionDays = 7;
    bool logDailyRotation = true;
    std::string logFormat = "json";
    
    // 授权清单路径
    std::wstring authorizationListPath;
    
    // Event response configuration
    std::unordered_map<uint32_t, ResponseAction> eventResponses;
    
    // 文件监视
    std::thread watcherThread;
    std::atomic<bool> watcherRunning{false};
};

Config::Config(const std::wstring& configPath) 
    : m_impl(std::make_unique<Impl>()), m_configPath(configPath), m_source(ConfigSource::DEFAULT) {
    m_impl->config.log_path = m_impl->logPath;
}

Config::~Config() = default;

std::wstring Config::GetCachePath() const {
    // 缓存文件存放在固定的系统目录
    return L"C:\\ProgramData\\GuardianShield\\config_cache.bin";
}

bool Config::ClearCache() {
    std::wstring cachePath = GetCachePath();
    if (std::filesystem::exists(cachePath)) {
        return std::filesystem::remove(cachePath);
    }
    return true;
}

bool Config::Load() {
    // FIX-04: 跨进程互斥锁，防止两个服务同时读YAML→写缓存→删文件
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"Global\\GuardianShieldConfigMutex");
    if (hMutex) WaitForSingleObject(hMutex, 10000);

    bool result = false;
#ifdef HAS_YAML_CPP
    if (LoadYaml()) {
        m_source = ConfigSource::FILE;
        result = true;
        if (g_logger) g_logger->Info("Config loaded from YAML file");
        if (!SaveToCache()) {
            std::cerr << "[配置] YAML 加载成功但缓存写入失败" << std::endl;
        }
    }
#else
    if (!result && LoadSimple()) {
        m_source = ConfigSource::FILE;
        result = true;
        if (g_logger) g_logger->Info("Config loaded from simple config file");
        if (!SaveToCache()) {
            std::cerr << "[配置] 简单配置加载成功但缓存写入失败" << std::endl;
        }
    }
#endif

    if (!result && LoadFromCache()) {
        m_source = ConfigSource::CACHE;
        std::cerr << "[配置] 沿用缓存策略(v10)" << std::endl;
        if (g_logger) g_logger->Warn("Config loaded from CACHE (YAML source file not found)");
        result = true;
    }

    if (!result) {
        std::cerr << "[配置] 首次运行，使用默认配置" << std::endl;
        m_source = ConfigSource::DEFAULT;
        if (g_logger) g_logger->Warn("Config loaded from DEFAULT (no YAML, no cache)");
        result = true;
    }

    if (m_impl->alertTimeoutSeconds <= 0) {
        if (g_logger) g_logger->Warn("alert_timeout_seconds=%d invalid, using default 30",
                                      m_impl->alertTimeoutSeconds);
        m_impl->alertTimeoutSeconds = 30;
    }

    if (!Validate()) {
        if (g_logger) g_logger->Warn("Config validation failed after load, continuing with current values");
    }

    if (g_logger) g_logger->Info("Config alert_timeout_seconds=%d", m_impl->alertTimeoutSeconds);

    // Diagnostic: log file type filter state for troubleshooting
    std::cerr << "[配置诊断] excludeFileTypes count: "
              << m_impl->excludeFileTypes.size() << std::endl;
    if (g_logger) g_logger->Info("Config loaded: excludeFileTypes count=%zu, includeFileTypes count=%zu",
                                  m_impl->excludeFileTypes.size(), m_impl->includeFileTypes.size());
    for (size_t i = 0; i < m_impl->excludeFileTypes.size(); ++i) {
        std::string s = WideToUtf8(m_impl->excludeFileTypes[i]);
        std::cerr << "[配置诊断]   exclude[" << i << "]: " << s << std::endl;
        if (g_logger) g_logger->Info("  excludeFileTypes[%zu]: %s", i, s.c_str());
    }
    std::cerr << "[配置诊断] includeFileTypes count: "
              << m_impl->includeFileTypes.size() << std::endl;
    if (g_logger) g_logger->Info("Config loaded: whitelist process count=%zu",
                                  m_impl->config.whitelist.size());
    for (size_t i = 0; i < m_impl->config.whitelist.size(); ++i) {
        std::string name = WideToUtf8(m_impl->config.whitelist[i].name);
        if (g_logger) g_logger->Info("  whitelist[%zu]: %s (perms=%zu)",
                                      i, name.c_str(),
                                      m_impl->config.whitelist[i].permissions.size());
    }

    if (hMutex) { ReleaseMutex(hMutex); CloseHandle(hMutex); }
    return result;
}

bool Config::SecureDeleteSources() {
    if (m_source != ConfigSource::FILE) return true;
    if (!SaveToCache()) {
        std::cerr << "[错误] 无法保存缓存, 保留源文件" << std::endl;
        return false;
    }
    DeleteConfigFile();
    // auth.list 由调用方在 InitializeEnvironmentValidator 中处理
    return true;
}

bool Config::LoadFromCache() {
    std::wstring cachePath = GetCachePath();

    std::ifstream file(cachePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    try {
        uint32_t version = 0;
        file.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != 11) {
            file.close();
            std::cerr << "[配置] 缓存版本不匹配(got " << version << ", want 11), 需要重建" << std::endl;
            return false;
        }

        // Tier 1 thresholds (12 ints)
        file.read(reinterpret_cast<char*>(&m_impl->fileWriteThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileWriteWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileCompressThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileCompressWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileDeleteThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileDeleteWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileCreateThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileCreateWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileRenameThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileRenameWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileMoveThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileMoveWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileNetworkTransferThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->fileNetworkTransferWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->dataTransferMB), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->processTerminationCount), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->processTerminationWindowSeconds), sizeof(int));

        // Tier 2 thresholds (13 ints)
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileWriteThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileWriteWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileCompressThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileCompressWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileDeleteThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileDeleteWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileCreateThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileCreateWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileRenameThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileRenameWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileMoveThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileMoveWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileNetworkTransferThreshold), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2FileNetworkTransferWindowSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2DataTransferMB), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2ProcessTerminationCount), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->tier2ProcessTerminationWindowSeconds), sizeof(int));

        file.read(reinterpret_cast<char*>(&m_impl->logRetentionDays), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->logDailyRotation), sizeof(bool));

        auto readString = [&](size_t maxLen = 32768) -> std::string {
            uint32_t len = 0;
            file.read(reinterpret_cast<char*>(&len), sizeof(uint32_t));
            if (len > maxLen) throw std::runtime_error("string length exceeds limit");
            std::string s(len, '\0');
            if (len > 0) file.read(&s[0], len);
            return s;
        };

        m_impl->logPath = Utf8ToWide(readString());
        m_impl->logFormat = readString(256);
        m_impl->adminPasswordHash = readString(1024);
        m_impl->installKey = readString(1024);

        // v6: alertTimeoutSeconds, unlockTimeoutSeconds
        file.read(reinterpret_cast<char*>(&m_impl->alertTimeoutSeconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->unlockTimeoutSeconds), sizeof(int));

        // v6: authorizationListPath
        m_impl->authorizationListPath = Utf8ToWide(readString());

        // Protected directories
        uint32_t dirCount = 0;
        file.read(reinterpret_cast<char*>(&dirCount), sizeof(uint32_t));
        if (dirCount > 10000) return false;
        m_impl->config.protected_dirs.clear();
        for (uint32_t i = 0; i < dirCount; ++i) {
            ProtectedDirectory pd;
            pd.path = Utf8ToWide(readString());
            file.read(reinterpret_cast<char*>(&pd.recursive), sizeof(bool));
            file.read(reinterpret_cast<char*>(&pd.priority), sizeof(int));
            m_impl->config.protected_dirs.push_back(pd);
        }

        // v6: includeFileTypes
        uint32_t incCount = 0;
        file.read(reinterpret_cast<char*>(&incCount), sizeof(uint32_t));
        if (incCount > 10000) return false;
        m_impl->includeFileTypes.clear();
        for (uint32_t i = 0; i < incCount; ++i)
            m_impl->includeFileTypes.push_back(Utf8ToWide(readString()));

        // v6: excludeFileTypes
        uint32_t excCount = 0;
        file.read(reinterpret_cast<char*>(&excCount), sizeof(uint32_t));
        if (excCount > 10000) return false;
        m_impl->excludeFileTypes.clear();
        for (uint32_t i = 0; i < excCount; ++i)
            m_impl->excludeFileTypes.push_back(Utf8ToWide(readString()));

        // Auth entries
        uint32_t authCount = 0;
        file.read(reinterpret_cast<char*>(&authCount), sizeof(uint32_t));
        if (authCount > 100000) return false;
        m_impl->cachedAuthEntries.clear();
        for (uint32_t i = 0; i < authCount; ++i) {
            Impl::AuthEntry entry;
            entry.ip = readString(256);
            entry.mac = readString(256);
            entry.description = readString(4096);
            m_impl->cachedAuthEntries.push_back(entry);
        }

        // v7: whitelist processes
        uint32_t wlCount = 0;
        file.read(reinterpret_cast<char*>(&wlCount), sizeof(uint32_t));
        if (wlCount > 10000) return false;
        m_impl->config.whitelist.clear();
        for (uint32_t i = 0; i < wlCount; ++i) {
            WhitelistProcess wp;
            wp.name = Utf8ToWide(readString());
            wp.description = Utf8ToWide(readString());
            uint32_t permCount = 0;
            file.read(reinterpret_cast<char*>(&permCount), sizeof(uint32_t));
            if (permCount > 1000) return false;
            for (uint32_t j = 0; j < permCount; ++j)
                wp.permissions.push_back(Utf8ToWide(readString()));
            wp.path_prefix = Utf8ToWide(readString());
            m_impl->config.whitelist.push_back(wp);
        }

        // v7: emergency settings
        file.read(reinterpret_cast<char*>(&m_impl->config.encrypt_timeout_seconds), sizeof(int));
        file.read(reinterpret_cast<char*>(&m_impl->config.recovery_wait_seconds), sizeof(int));
        m_impl->config.wipe_method = readString(256);

        // v7: system metadata
        m_impl->config.version = readString(256);
        m_impl->config.log_level = readString(256);

        // v8: event responses
        uint32_t erCount = 0;
        file.read(reinterpret_cast<char*>(&erCount), sizeof(uint32_t));
        if (erCount > 1000) return false;
        m_impl->eventResponses.clear();
        for (uint32_t i = 0; i < erCount; ++i) {
            uint32_t evtType = 0;
            uint8_t actionMask = 0;
            file.read(reinterpret_cast<char*>(&evtType), sizeof(uint32_t));
            file.read(reinterpret_cast<char*>(&actionMask), sizeof(uint8_t));
            m_impl->eventResponses[evtType] = static_cast<ResponseAction>(actionMask);
        }

        uint32_t magic = 0;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        if (magic != 0x47534843) {
            file.close();
            std::cerr << "[配置] 缓存 magic 校验失败" << std::endl;
            return false;
        }

        file.close();
        m_impl->config.log_path = m_impl->logPath;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[错误] 缓存读取失败: " << e.what() << std::endl;
        file.close();
        return false;
    }
}

bool Config::SaveToCache() {
    std::wstring cachePath = GetCachePath();
    std::wstring tmpPath = cachePath + L".tmp";

    std::filesystem::path p(cachePath);
    if (p.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
    }

    std::ofstream file(tmpPath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "[错误] 无法创建缓存临时文件" << std::endl;
        return false;
    }

    try {
        uint32_t version = 11;
        file.write(reinterpret_cast<const char*>(&version), sizeof(version));

        // Tier 1 thresholds (12 ints)
        file.write(reinterpret_cast<const char*>(&m_impl->fileWriteThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileWriteWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileCompressThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileCompressWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileDeleteThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileDeleteWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileCreateThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileCreateWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileRenameThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileRenameWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileMoveThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileMoveWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileNetworkTransferThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->fileNetworkTransferWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->dataTransferMB), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->processTerminationCount), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->processTerminationWindowSeconds), sizeof(int));

        // Tier 2 thresholds (13 ints)
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileWriteThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileWriteWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileCompressThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileCompressWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileDeleteThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileDeleteWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileCreateThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileCreateWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileRenameThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileRenameWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileMoveThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileMoveWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileNetworkTransferThreshold), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2FileNetworkTransferWindowSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2DataTransferMB), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2ProcessTerminationCount), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->tier2ProcessTerminationWindowSeconds), sizeof(int));

        file.write(reinterpret_cast<const char*>(&m_impl->logRetentionDays), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->logDailyRotation), sizeof(bool));

        auto writeString = [&](const std::string& s) {
            uint32_t len = static_cast<uint32_t>(s.size());
            file.write(reinterpret_cast<const char*>(&len), sizeof(uint32_t));
            if (len > 0) file.write(s.data(), len);
        };

        writeString(WideToUtf8(m_impl->logPath));
        writeString(m_impl->logFormat);
        writeString(m_impl->adminPasswordHash);
        writeString(m_impl->installKey);

        // v6: alertTimeoutSeconds, unlockTimeoutSeconds
        file.write(reinterpret_cast<const char*>(&m_impl->alertTimeoutSeconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->unlockTimeoutSeconds), sizeof(int));

        // v6: authorizationListPath
        writeString(WideToUtf8(m_impl->authorizationListPath));

        // Protected directories
        uint32_t dirCount = static_cast<uint32_t>(m_impl->config.protected_dirs.size());
        file.write(reinterpret_cast<const char*>(&dirCount), sizeof(uint32_t));
        for (const auto& dir : m_impl->config.protected_dirs) {
            writeString(WideToUtf8(dir.path));
            file.write(reinterpret_cast<const char*>(&dir.recursive), sizeof(bool));
            file.write(reinterpret_cast<const char*>(&dir.priority), sizeof(int));
        }

        // v6: includeFileTypes
        uint32_t incCount = static_cast<uint32_t>(m_impl->includeFileTypes.size());
        file.write(reinterpret_cast<const char*>(&incCount), sizeof(uint32_t));
        for (const auto& ft : m_impl->includeFileTypes) writeString(WideToUtf8(ft));

        // v6: excludeFileTypes
        uint32_t excCount = static_cast<uint32_t>(m_impl->excludeFileTypes.size());
        file.write(reinterpret_cast<const char*>(&excCount), sizeof(uint32_t));
        for (const auto& ft : m_impl->excludeFileTypes) writeString(WideToUtf8(ft));

        // Auth entries
        uint32_t authCount = static_cast<uint32_t>(m_impl->cachedAuthEntries.size());
        file.write(reinterpret_cast<const char*>(&authCount), sizeof(uint32_t));
        for (const auto& entry : m_impl->cachedAuthEntries) {
            writeString(entry.ip);
            writeString(entry.mac);
            writeString(entry.description);
        }

        // v7: whitelist processes
        uint32_t wlCount = static_cast<uint32_t>(m_impl->config.whitelist.size());
        file.write(reinterpret_cast<const char*>(&wlCount), sizeof(uint32_t));
        for (const auto& wp : m_impl->config.whitelist) {
            writeString(WideToUtf8(wp.name));
            writeString(WideToUtf8(wp.description));
            uint32_t permCount = static_cast<uint32_t>(wp.permissions.size());
            file.write(reinterpret_cast<const char*>(&permCount), sizeof(uint32_t));
            for (const auto& perm : wp.permissions)
                writeString(WideToUtf8(perm));
            writeString(WideToUtf8(wp.path_prefix));
        }

        // v7: emergency settings
        file.write(reinterpret_cast<const char*>(&m_impl->config.encrypt_timeout_seconds), sizeof(int));
        file.write(reinterpret_cast<const char*>(&m_impl->config.recovery_wait_seconds), sizeof(int));
        writeString(m_impl->config.wipe_method);

        // v7: system metadata
        writeString(m_impl->config.version);
        writeString(m_impl->config.log_level);

        // v8: event responses
        uint32_t erCount = static_cast<uint32_t>(m_impl->eventResponses.size());
        file.write(reinterpret_cast<const char*>(&erCount), sizeof(uint32_t));
        for (const auto& [evtType, action] : m_impl->eventResponses) {
            file.write(reinterpret_cast<const char*>(&evtType), sizeof(uint32_t));
            uint8_t actionMask = static_cast<uint8_t>(action);
            file.write(reinterpret_cast<const char*>(&actionMask), sizeof(uint8_t));
        }

        uint32_t magic = 0x47534843;
        file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));

        file.close();

        // FIX-02: atomic rename — tmp → final
        if (!MoveFileExW(tmpPath.c_str(), cachePath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            DeleteFileW(tmpPath.c_str());
            std::cerr << "[错误] 缓存原子替换失败" << std::endl;
            return false;
        }

        SetCacheFilePermissions(cachePath);
        std::cerr << "[配置] 已保存到缓存(v9): " << WideToUtf8(cachePath) << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[错误] 缓存保存失败: " << e.what() << std::endl;
        file.close();
        DeleteFileW(tmpPath.c_str());
        return false;
    }
}

#ifdef HAS_YAML_CPP
bool Config::LoadYaml() {
    try {
        // 转换路径
        std::string narrowPath = WideToUtf8(m_configPath);
        
        YAML::Node root = YAML::LoadFile(narrowPath);
        
        // 系统基础配置
        if (root["system"]) {
            auto sys = root["system"];
            if (sys["version"])
                m_impl->config.version = sys["version"].as<std::string>();
            if (sys["log_level"])
                m_impl->config.log_level = sys["log_level"].as<std::string>();
            if (sys["log_path"]) {
                std::string lp = sys["log_path"].as<std::string>();
                m_impl->logPath = Utf8ToWide(lp);
            }
        }
        
        // 检测阈值
        if (root["detection"]) {
            auto detection = root["detection"];
            
            if (detection["alert_timeout_seconds"] && !detection["alert_timeout_seconds"].IsNull()) {
                m_impl->alertTimeoutSeconds = detection["alert_timeout_seconds"].as<int>();
            }

            if (detection["event_responses"] && detection["event_responses"].IsMap()) {
                auto er = detection["event_responses"];
                auto parseEventType = [](const std::string& name) -> int {
                    if (name == "FILE_CREATE") return static_cast<int>(DriverEventType::FILE_CREATE);
                    if (name == "FILE_WRITE") return static_cast<int>(DriverEventType::FILE_WRITE);
                    if (name == "FILE_DELETE") return static_cast<int>(DriverEventType::FILE_DELETE);
                    if (name == "FILE_RENAME") return static_cast<int>(DriverEventType::FILE_RENAME);
                    if (name == "FILE_MOVE") return static_cast<int>(DriverEventType::FILE_MOVE);
                    if (name == "FILE_COMPRESS") return static_cast<int>(DriverEventType::FILE_COMPRESS);
                    if (name == "FILE_NETWORK_TRANSFER") return static_cast<int>(DriverEventType::FILE_NETWORK_TRANSFER);
                    if (name == "PROCESS_CREATE") return static_cast<int>(DriverEventType::PROCESS_CREATE);
                    if (name == "PROC_TERMINATE") return static_cast<int>(DriverEventType::PROC_TERMINATE);
                    if (name == "DRIVER_LOAD") return static_cast<int>(DriverEventType::DRIVER_LOAD);
                    if (name == "DRIVER_UNLOAD") return static_cast<int>(DriverEventType::DRIVER_UNLOAD);
                    return -1;
                };
                auto parseAction = [](const std::string& name) -> int {
                    if (name == "LOG") return static_cast<int>(ResponseAction::LOG);
                    if (name == "ALERT_USER") return static_cast<int>(ResponseAction::ALERT_USER);
                    if (name == "TERMINATE") return static_cast<int>(ResponseAction::TERMINATE);
                    if (name == "BLOCK") return static_cast<int>(ResponseAction::BLOCK);
                    if (name == "ENCRYPT") return static_cast<int>(ResponseAction::ENCRYPT);
                    if (name == "WIPE") return -2;
                    if (name == "LOCKDOWN") return -2;
                    return -1;
                };
                for (auto it = er.begin(); it != er.end(); ++it) {
                    std::string eventName = it->first.as<std::string>();
                    int eventId = parseEventType(eventName);
                    if (eventId < 0) {
                        std::cerr << "[配置] 未知事件类型，已忽略: " << eventName << std::endl;
                        continue;
                    }
                    uint8_t bitmask = 0;
                    if (it->second.IsSequence()) {
                        for (const auto& actNode : it->second) {
                            std::string actName = actNode.as<std::string>();
                            int actVal = parseAction(actName);
                            if (actVal == -2) {
                                std::cerr << "[配置] " << actName << " 不可用于单事件响应，已过滤" << std::endl;
                            } else if (actVal < 0) {
                                std::cerr << "[配置] 未知响应动作，已忽略: " << actName << std::endl;
                            } else {
                                bitmask |= static_cast<uint8_t>(actVal);
                            }
                        }
                    }
                    m_impl->eventResponses[static_cast<uint32_t>(eventId)] =
                        static_cast<ResponseAction>(bitmask);
                }
            }

            if (detection["thresholds"]) {
                auto thresh = detection["thresholds"];

                // Helper: read a key, falling back to an alias (file_copy_* → file_write_*)
                // Returns: -1 = key absent (keep default), 0 = key present but null/empty (no restriction)
                auto readInt = [](const YAML::Node& node, const char* key, const char* alias) -> int {
                    if (node[key]) {
                        if (node[key].IsNull()) return 0;
                        return node[key].as<int>();
                    }
                    if (alias && node[alias]) {
                        if (node[alias].IsNull()) return 0;
                        return node[alias].as<int>();
                    }
                    return -1;
                };

                // Helper: read a simple int key; null/empty → 0 (no restriction)
                auto safeInt = [](const YAML::Node& node, const char* key) -> int {
                    if (!node[key]) return -1;
                    if (node[key].IsNull()) return 0;
                    return node[key].as<int>();
                };

                // ---- Tier 1 ----
                if (thresh["tier1"]) {
                    auto t1 = thresh["tier1"];
                    int v;
                    v = readInt(t1, "file_write_count", "file_copy_count");
                    if (v >= 0) m_impl->fileWriteThreshold = v;
                    v = readInt(t1, "file_write_window_seconds", "file_copy_window_seconds");
                    if (v >= 0) m_impl->fileWriteWindowSeconds = v;
                    v = safeInt(t1, "file_compress_count");
                    if (v >= 0) m_impl->fileCompressThreshold = v;
                    v = safeInt(t1, "file_compress_window_seconds");
                    if (v >= 0) m_impl->fileCompressWindowSeconds = v;
                    v = safeInt(t1, "file_delete_count");
                    if (v >= 0) m_impl->fileDeleteThreshold = v;
                    v = safeInt(t1, "file_delete_window_seconds");
                    if (v >= 0) m_impl->fileDeleteWindowSeconds = v;
                    v = safeInt(t1, "file_network_transfer_count");
                    if (v >= 0) m_impl->fileNetworkTransferThreshold = v;
                    v = safeInt(t1, "file_network_transfer_window_seconds");
                    if (v >= 0) m_impl->fileNetworkTransferWindowSeconds = v;
                    v = safeInt(t1, "data_transfer_mb");
                    if (v >= 0) m_impl->dataTransferMB = v;
                    v = safeInt(t1, "file_create_count");
                    if (v >= 0) m_impl->fileCreateThreshold = v;
                    v = safeInt(t1, "file_create_window_seconds");
                    if (v >= 0) m_impl->fileCreateWindowSeconds = v;
                    v = safeInt(t1, "file_rename_count");
                    if (v >= 0) m_impl->fileRenameThreshold = v;
                    v = safeInt(t1, "file_rename_window_seconds");
                    if (v >= 0) m_impl->fileRenameWindowSeconds = v;
                    v = safeInt(t1, "file_move_count");
                    if (v >= 0) m_impl->fileMoveThreshold = v;
                    v = safeInt(t1, "file_move_window_seconds");
                    if (v >= 0) m_impl->fileMoveWindowSeconds = v;
                    v = safeInt(t1, "process_termination_count");
                    if (v >= 0) m_impl->processTerminationCount = v;
                    v = safeInt(t1, "process_termination_window_seconds");
                    if (v >= 0) m_impl->processTerminationWindowSeconds = v;
                }

                // ---- Tier 2 ----
                if (thresh["tier2"]) {
                    auto t2 = thresh["tier2"];
                    int v;
                    v = readInt(t2, "file_write_count", "file_copy_count");
                    if (v >= 0) m_impl->tier2FileWriteThreshold = v;
                    v = readInt(t2, "file_write_window_seconds", "file_copy_window_seconds");
                    if (v >= 0) m_impl->tier2FileWriteWindowSeconds = v;
                    v = safeInt(t2, "file_compress_count");
                    if (v >= 0) m_impl->tier2FileCompressThreshold = v;
                    v = safeInt(t2, "file_compress_window_seconds");
                    if (v >= 0) m_impl->tier2FileCompressWindowSeconds = v;
                    v = safeInt(t2, "file_delete_count");
                    if (v >= 0) m_impl->tier2FileDeleteThreshold = v;
                    v = safeInt(t2, "file_delete_window_seconds");
                    if (v >= 0) m_impl->tier2FileDeleteWindowSeconds = v;
                    v = safeInt(t2, "file_network_transfer_count");
                    if (v >= 0) m_impl->tier2FileNetworkTransferThreshold = v;
                    v = safeInt(t2, "file_network_transfer_window_seconds");
                    if (v >= 0) m_impl->tier2FileNetworkTransferWindowSeconds = v;
                    v = safeInt(t2, "data_transfer_mb");
                    if (v >= 0) m_impl->tier2DataTransferMB = v;
                    v = safeInt(t2, "file_create_count");
                    if (v >= 0) m_impl->tier2FileCreateThreshold = v;
                    v = safeInt(t2, "file_create_window_seconds");
                    if (v >= 0) m_impl->tier2FileCreateWindowSeconds = v;
                    v = safeInt(t2, "file_rename_count");
                    if (v >= 0) m_impl->tier2FileRenameThreshold = v;
                    v = safeInt(t2, "file_rename_window_seconds");
                    if (v >= 0) m_impl->tier2FileRenameWindowSeconds = v;
                    v = safeInt(t2, "file_move_count");
                    if (v >= 0) m_impl->tier2FileMoveThreshold = v;
                    v = safeInt(t2, "file_move_window_seconds");
                    if (v >= 0) m_impl->tier2FileMoveWindowSeconds = v;
                    v = safeInt(t2, "process_termination_count");
                    if (v >= 0) m_impl->tier2ProcessTerminationCount = v;
                    v = safeInt(t2, "process_termination_window_seconds");
                    if (v >= 0) m_impl->tier2ProcessTerminationWindowSeconds = v;
                }

                // Legacy flat format (no tier1/tier2 sub-nodes)
                if (!thresh["tier1"] && !thresh["tier2"]) {
                    int v;
                    v = readInt(thresh, "file_write_count", "file_copy_count");
                    if (v >= 0) m_impl->fileWriteThreshold = v;
                    v = readInt(thresh, "file_write_window_seconds", "file_copy_window_seconds");
                    if (v >= 0) m_impl->fileWriteWindowSeconds = v;
                    v = safeInt(thresh, "file_compress_count");
                    if (v >= 0) m_impl->fileCompressThreshold = v;
                    v = safeInt(thresh, "file_compress_window_seconds");
                    if (v >= 0) m_impl->fileCompressWindowSeconds = v;
                    v = safeInt(thresh, "file_delete_count");
                    if (v >= 0) m_impl->fileDeleteThreshold = v;
                    v = safeInt(thresh, "file_delete_window_seconds");
                    if (v >= 0) m_impl->fileDeleteWindowSeconds = v;
                    v = safeInt(thresh, "file_network_transfer_count");
                    if (v >= 0) m_impl->fileNetworkTransferThreshold = v;
                    v = safeInt(thresh, "file_network_transfer_window_seconds");
                    if (v >= 0) m_impl->fileNetworkTransferWindowSeconds = v;
                    v = safeInt(thresh, "data_transfer_mb");
                    if (v >= 0) m_impl->dataTransferMB = v;
                    v = safeInt(thresh, "process_termination_count");
                    if (v >= 0) m_impl->processTerminationCount = v;
                    v = safeInt(thresh, "process_termination_window_seconds");
                    if (v >= 0) m_impl->processTerminationWindowSeconds = v;
                }
            }
        }
        
        // 管理员设置
        if (root["admin"]) {
            auto admin = root["admin"];
            if (admin["password_hash"]) {
                m_impl->adminPasswordHash = admin["password_hash"].as<std::string>();
            }
            if (admin["install_key"]) {
                m_impl->installKey = admin["install_key"].as<std::string>();
            }
            if (admin["unlock_timeout_seconds"]) {
                m_impl->unlockTimeoutSeconds = admin["unlock_timeout_seconds"].as<int>();
            }
        }
        
        // 日志设置
        if (root["logging"]) {
            auto logging = root["logging"];
            if (logging["path"]) {
                std::string path = logging["path"].as<std::string>();
                m_impl->logPath = Utf8ToWide(path);
            }
            if (logging["format"]) {
                m_impl->logFormat = logging["format"].as<std::string>();
            }
            if (logging["retention_days"]) {
                m_impl->logRetentionDays = logging["retention_days"].as<int>();
            }
            if (logging["daily_rotation"]) {
                m_impl->logDailyRotation = logging["daily_rotation"].as<bool>();
            }
        }
        
        // 授权清单
        if (root["authorization"] && root["authorization"]["list_path"]) {
            std::string path = root["authorization"]["list_path"].as<std::string>();
            m_impl->authorizationListPath = Utf8ToWide(path);
        }
        
        // 保护目录
        if (root["protection"] && root["protection"]["directories"]) {
            m_impl->config.protected_dirs.clear();
            for (const auto& dir : root["protection"]["directories"]) {
                ProtectedDirectory pd;
                if (dir["path"]) {
                    std::string path = dir["path"].as<std::string>();
                    pd.path = Utf8ToWide(path);
                }
                if (dir["recursive"]) {
                    pd.recursive = dir["recursive"].as<bool>();
                }
                if (dir["priority"]) {
                    std::string priority = dir["priority"].as<std::string>();
                    if (priority == "HIGH") pd.priority = 10;
                    else if (priority == "MEDIUM") pd.priority = 5;
                    else if (priority == "LOW") pd.priority = 1;
                    else pd.priority = dir["priority"].as<int>();
                }
                m_impl->config.protected_dirs.push_back(pd);
            }
        }
        
        if (root["protection"] && root["protection"]["file_types"]) {
            auto ft = root["protection"]["file_types"];
            try {
            if (ft["include"]) {
                m_impl->includeFileTypes.clear();
                for (const auto& inc : ft["include"]) {
                    std::string s = inc.as<std::string>();
                    m_impl->includeFileTypes.push_back(Utf8ToWide(s));
                }
            }
            } catch (const std::exception& e) {
                std::cerr << "[错误] file_types.include 解析失败: " << e.what() << std::endl;
            }
            try {
            if (ft["exclude"]) {
                m_impl->excludeFileTypes.clear();
                for (const auto& exc : ft["exclude"]) {
                    std::string s = exc.as<std::string>();
                    m_impl->excludeFileTypes.push_back(Utf8ToWide(s));
                }
            }
            } catch (const std::exception& e) {
                std::cerr << "[错误] file_types.exclude 解析失败: " << e.what() << std::endl;
            }
        }
        
        // 白名单进程
        if (root["whitelist"] && root["whitelist"]["processes"]) {
            m_impl->config.whitelist.clear();
            for (const auto& proc : root["whitelist"]["processes"]) {
                WhitelistProcess wp;
                if (proc["name"]) {
                    std::string name = proc["name"].as<std::string>();
                    wp.name = Utf8ToWide(name);
                }
                if (proc["description"]) {
                    std::string desc = proc["description"].as<std::string>();
                    wp.description = Utf8ToWide(desc);
                }
                if (proc["permissions"]) {
                    for (const auto& perm : proc["permissions"]) {
                        std::string p = perm.as<std::string>();
                        wp.permissions.push_back(Utf8ToWide(p));
                    }
                }
                if (proc["path_prefix"]) {
                    std::string pp = proc["path_prefix"].as<std::string>();
                    wp.path_prefix = Utf8ToWide(pp);
                }
                m_impl->config.whitelist.push_back(wp);
            }
        }
        
        // 紧急协议配置
        if (root["emergency"]) {
            auto emergency = root["emergency"];
            if (emergency["encrypt_timeout_seconds"])
                m_impl->config.encrypt_timeout_seconds = emergency["encrypt_timeout_seconds"].as<int>();
            if (emergency["recovery_wait_seconds"])
                m_impl->config.recovery_wait_seconds = emergency["recovery_wait_seconds"].as<int>();
            if (emergency["wipe_method"])
                m_impl->config.wipe_method = emergency["wipe_method"].as<std::string>();
        }
        
        // 更新日志路径
        m_impl->config.log_path = m_impl->logPath;
        
        std::cerr << "[配置] 已从文件加载: " << WideToUtf8(m_configPath) << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[错误] 配置加载失败: " << e.what() << std::endl;
        return false;
    }
}
#endif

bool Config::LoadSimple() {
    std::ifstream file(m_configPath);
    if (!file.is_open()) {
        std::cerr << "[Config] File not found: " << WideToUtf8(m_configPath) << std::endl;
        return false;
    }

    std::string line;
    std::vector<std::string> sectionStack;
    bool inDirectoriesArray = false;
    bool inExcludeArray = false;
    bool inIncludeArray = false;
    bool inWhitelistArray = false;
    ProtectedDirectory currentDir;
    bool hasDirEntry = false;
    WhitelistProcess currentWl;
    bool hasWlEntry = false;

    auto getIndentLevel = [](const std::string& s) -> int {
        int n = 0;
        for (char c : s) {
            if (c == ' ') ++n;
            else if (c == '\t') n += 2;
            else break;
        }
        return n / 2;
    };

    auto stripQuotes = [](std::string s) -> std::string {
        if (s.size() >= 2 &&
            ((s.front() == '"' && s.back() == '"') ||
             (s.front() == '\'' && s.back() == '\''))) {
            s = s.substr(1, s.size() - 2);
        }
        return s;
    };

    auto unescapeBackslash = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '\\') {
                out += '\\';
                ++i;
            } else {
                out += s[i];
            }
        }
        return out;
    };

    auto toWide = [](const std::string& s) -> std::wstring {
        return Utf8ToWide(s);
    };

    while (std::getline(file, line)) {
        std::string raw = line;
        size_t commentPos = std::string::npos;
        bool inQuote = false;
        for (size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '"' || raw[i] == '\'') inQuote = !inQuote;
            if (raw[i] == '#' && !inQuote) { commentPos = i; break; }
        }
        if (commentPos != std::string::npos) raw = raw.substr(0, commentPos);

        std::string trimmed = raw;
        trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
        trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);
        if (trimmed.empty()) continue;

        int indent = getIndentLevel(raw);

        while ((int)sectionStack.size() > indent) {
            sectionStack.pop_back();
        }

        if (trimmed.front() == '-' && trimmed.size() > 1) {
            std::string item = trimmed.substr(1);
            item.erase(0, item.find_first_not_of(" \t"));

            if (inDirectoriesArray) {
                size_t colonPos = item.find(':');
                if (colonPos != std::string::npos) {
                    std::string k = item.substr(0, colonPos);
                    std::string v = item.substr(colonPos + 1);
                    k.erase(k.find_last_not_of(" \t") + 1);
                    v.erase(0, v.find_first_not_of(" \t"));
                    v = stripQuotes(v);
                    v = unescapeBackslash(v);

                    if (hasDirEntry) {
                        m_impl->config.protected_dirs.push_back(currentDir);
                        currentDir = ProtectedDirectory();
                    }
                    hasDirEntry = true;

                    if (k == "path") currentDir.path = toWide(v);
                    else if (k == "recursive") currentDir.recursive = (v == "true");
                    else if (k == "priority") {
                        if (v == "HIGH") currentDir.priority = 10;
                        else if (v == "MEDIUM") currentDir.priority = 5;
                        else if (v == "LOW") currentDir.priority = 1;
                    }
                }
            } else if (inExcludeArray) {
                std::string val = stripQuotes(item);
                m_impl->excludeFileTypes.push_back(toWide(val));
            } else if (inIncludeArray) {
                std::string val = stripQuotes(item);
                m_impl->includeFileTypes.push_back(toWide(val));
            } else if (inWhitelistArray) {
                size_t colonPos = item.find(':');
                if (colonPos != std::string::npos) {
                    std::string k = item.substr(0, colonPos);
                    std::string v = item.substr(colonPos + 1);
                    k.erase(k.find_last_not_of(" \t") + 1);
                    v.erase(0, v.find_first_not_of(" \t"));
                    v = stripQuotes(v);

                    if (k == "name") {
                        if (hasWlEntry) {
                            m_impl->config.whitelist.push_back(currentWl);
                            currentWl = WhitelistProcess();
                        }
                        hasWlEntry = true;
                        currentWl.name = toWide(v);
                    } else if (k == "description") {
                        currentWl.description = toWide(v);
                    } else if (k == "permissions") {
                        v.erase(std::remove(v.begin(), v.end(), '['), v.end());
                        v.erase(std::remove(v.begin(), v.end(), ']'), v.end());
                        std::istringstream ss(v);
                        std::string perm;
                        while (std::getline(ss, perm, ',')) {
                            perm.erase(0, perm.find_first_not_of(" \t"));
                            perm.erase(perm.find_last_not_of(" \t") + 1);
                            if (!perm.empty()) currentWl.permissions.push_back(toWide(perm));
                        }
                    }
                }
            }
            continue;
        }

        size_t colonPos = trimmed.find(':');
        if (colonPos == std::string::npos) continue;

        std::string key = trimmed.substr(0, colonPos);
        std::string value = trimmed.substr(colonPos + 1);
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));

        if (value.empty()) {
            if (inDirectoriesArray && hasDirEntry) {
                m_impl->config.protected_dirs.push_back(currentDir);
                currentDir = ProtectedDirectory();
                hasDirEntry = false;
            }
            if (inWhitelistArray && hasWlEntry) {
                m_impl->config.whitelist.push_back(currentWl);
                currentWl = WhitelistProcess();
                hasWlEntry = false;
            }
            inDirectoriesArray = false;
            inExcludeArray = false;
            inIncludeArray = false;
            inWhitelistArray = false;

            sectionStack.resize(indent);
            sectionStack.push_back(key);

            std::string fullKey;
            for (const auto& s : sectionStack) {
                if (!fullKey.empty()) fullKey += ".";
                fullKey += s;
            }
            if (fullKey == "protection.directories") {
                inDirectoriesArray = true;
            } else if (fullKey == "protection.file_types.exclude") {
                inExcludeArray = true;
            } else if (fullKey == "protection.file_types.include") {
                inIncludeArray = true;
            } else if (fullKey == "whitelist.processes") {
                inWhitelistArray = true;
            }
            continue;
        }

        if (inDirectoriesArray && hasDirEntry) {
            std::string vClean = stripQuotes(value);
            vClean = unescapeBackslash(vClean);
            if (key == "recursive") currentDir.recursive = (vClean == "true");
            else if (key == "priority") {
                if (vClean == "HIGH") currentDir.priority = 10;
                else if (vClean == "MEDIUM") currentDir.priority = 5;
                else if (vClean == "LOW") currentDir.priority = 1;
            }
            continue;
        }

        value = stripQuotes(value);
        value = unescapeBackslash(value);

        std::string fullKey;
        for (const auto& s : sectionStack) {
            fullKey += s + ".";
        }
        fullKey += key;

        // event_responses entries: fullKey = "detection.event_responses.FILE_DELETE" etc.
        if (fullKey.find("detection.event_responses.") == 0) {
            std::string eventName = fullKey.substr(strlen("detection.event_responses."));
            auto parseEvt = [](const std::string& name) -> int {
                if (name == "FILE_CREATE") return static_cast<int>(DriverEventType::FILE_CREATE);
                if (name == "FILE_WRITE") return static_cast<int>(DriverEventType::FILE_WRITE);
                if (name == "FILE_DELETE") return static_cast<int>(DriverEventType::FILE_DELETE);
                if (name == "FILE_RENAME") return static_cast<int>(DriverEventType::FILE_RENAME);
                if (name == "FILE_MOVE") return static_cast<int>(DriverEventType::FILE_MOVE);
                if (name == "FILE_COMPRESS") return static_cast<int>(DriverEventType::FILE_COMPRESS);
                if (name == "FILE_NETWORK_TRANSFER") return static_cast<int>(DriverEventType::FILE_NETWORK_TRANSFER);
                if (name == "PROCESS_CREATE") return static_cast<int>(DriverEventType::PROCESS_CREATE);
                if (name == "PROC_TERMINATE") return static_cast<int>(DriverEventType::PROC_TERMINATE);
                if (name == "DRIVER_LOAD") return static_cast<int>(DriverEventType::DRIVER_LOAD);
                if (name == "DRIVER_UNLOAD") return static_cast<int>(DriverEventType::DRIVER_UNLOAD);
                return -1;
            };
            auto parseAct = [](const std::string& name) -> int {
                if (name == "LOG") return static_cast<int>(ResponseAction::LOG);
                if (name == "ALERT_USER") return static_cast<int>(ResponseAction::ALERT_USER);
                if (name == "TERMINATE") return static_cast<int>(ResponseAction::TERMINATE);
                if (name == "BLOCK") return static_cast<int>(ResponseAction::BLOCK);
                if (name == "ENCRYPT") return static_cast<int>(ResponseAction::ENCRYPT);
                return -1;
            };
            int evtId = parseEvt(eventName);
            if (evtId >= 0) {
                std::string v = value;
                v.erase(std::remove(v.begin(), v.end(), '['), v.end());
                v.erase(std::remove(v.begin(), v.end(), ']'), v.end());
                uint8_t bitmask = 0;
                std::istringstream ss(v);
                std::string token;
                while (std::getline(ss, token, ',')) {
                    token.erase(0, token.find_first_not_of(" \t"));
                    token.erase(token.find_last_not_of(" \t") + 1);
                    int a = parseAct(token);
                    if (a > 0) bitmask |= static_cast<uint8_t>(a);
                }
                m_impl->eventResponses[static_cast<uint32_t>(evtId)] =
                    static_cast<ResponseAction>(bitmask);
            }
            continue;
        }

        if (fullKey == "system.log_level") m_impl->config.log_level = value;
        else if (fullKey == "system.log_path") {
            m_impl->logPath = toWide(value);
        }
        else if (fullKey == "system.version") m_impl->config.version = value;
        else if (fullKey == "authorization.list_path") {
            m_impl->authorizationListPath = toWide(value);
        }
        // Tier 1 thresholds (accept both file_write_* and legacy file_copy_*)
        else if (fullKey == "detection.thresholds.tier1.file_write_count" ||
                 fullKey == "detection.thresholds.tier1.file_copy_count" ||
                 fullKey == "detection.thresholds.file_copy_count")
            m_impl->fileWriteThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_write_window_seconds" ||
                 fullKey == "detection.thresholds.tier1.file_copy_window_seconds" ||
                 fullKey == "detection.thresholds.file_copy_window_seconds")
            m_impl->fileWriteWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_compress_count" ||
                 fullKey == "detection.thresholds.file_compress_count")
            m_impl->fileCompressThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_compress_window_seconds" ||
                 fullKey == "detection.thresholds.file_compress_window_seconds")
            m_impl->fileCompressWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_delete_count")
            m_impl->fileDeleteThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_delete_window_seconds")
            m_impl->fileDeleteWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_create_count")
            m_impl->fileCreateThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_create_window_seconds")
            m_impl->fileCreateWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_rename_count")
            m_impl->fileRenameThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_rename_window_seconds")
            m_impl->fileRenameWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_move_count")
            m_impl->fileMoveThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_move_window_seconds")
            m_impl->fileMoveWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_network_transfer_count" ||
                 fullKey == "detection.thresholds.file_network_transfer_count")
            m_impl->fileNetworkTransferThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.file_network_transfer_window_seconds" ||
                 fullKey == "detection.thresholds.file_network_transfer_window_seconds")
            m_impl->fileNetworkTransferWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.data_transfer_mb" ||
                 fullKey == "detection.thresholds.data_transfer_mb")
            m_impl->dataTransferMB = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.process_termination_count" ||
                 fullKey == "detection.thresholds.process_termination_count")
            m_impl->processTerminationCount = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier1.process_termination_window_seconds" ||
                 fullKey == "detection.thresholds.process_termination_window_seconds")
            m_impl->processTerminationWindowSeconds = std::stoi(value);
        // Tier 2 thresholds
        else if (fullKey == "detection.thresholds.tier2.file_write_count" ||
                 fullKey == "detection.thresholds.tier2.file_copy_count")
            m_impl->tier2FileWriteThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_write_window_seconds" ||
                 fullKey == "detection.thresholds.tier2.file_copy_window_seconds")
            m_impl->tier2FileWriteWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_compress_count")
            m_impl->tier2FileCompressThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_compress_window_seconds")
            m_impl->tier2FileCompressWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_delete_count")
            m_impl->tier2FileDeleteThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_delete_window_seconds")
            m_impl->tier2FileDeleteWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_create_count")
            m_impl->tier2FileCreateThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_create_window_seconds")
            m_impl->tier2FileCreateWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_rename_count")
            m_impl->tier2FileRenameThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_rename_window_seconds")
            m_impl->tier2FileRenameWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_move_count")
            m_impl->tier2FileMoveThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_move_window_seconds")
            m_impl->tier2FileMoveWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_network_transfer_count")
            m_impl->tier2FileNetworkTransferThreshold = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.file_network_transfer_window_seconds")
            m_impl->tier2FileNetworkTransferWindowSeconds = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.data_transfer_mb")
            m_impl->tier2DataTransferMB = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.process_termination_count")
            m_impl->tier2ProcessTerminationCount = std::stoi(value);
        else if (fullKey == "detection.thresholds.tier2.process_termination_window_seconds")
            m_impl->tier2ProcessTerminationWindowSeconds = std::stoi(value);
        else if (fullKey == "emergency.encrypt_timeout_seconds")
            m_impl->config.encrypt_timeout_seconds = std::stoi(value);
        else if (fullKey == "emergency.recovery_wait_seconds")
            m_impl->config.recovery_wait_seconds = std::stoi(value);
        else if (fullKey == "emergency.wipe_method")
            m_impl->config.wipe_method = value;
        else if (fullKey == "detection.alert_timeout_seconds")
            m_impl->alertTimeoutSeconds = std::stoi(value);
        else if (fullKey == "admin.password_hash")
            m_impl->adminPasswordHash = value;
        else if (fullKey == "admin.install_key")
            m_impl->installKey = value;
        else if (fullKey == "admin.unlock_timeout_seconds")
            m_impl->unlockTimeoutSeconds = std::stoi(value);
        else if (fullKey == "communication.tcp.port_base")
            m_impl->config.tcp_port_base = static_cast<uint16_t>(std::stoi(value));
    }

    if (inDirectoriesArray && hasDirEntry) {
        m_impl->config.protected_dirs.push_back(currentDir);
    }
    if (inWhitelistArray && hasWlEntry) {
        m_impl->config.whitelist.push_back(currentWl);
    }

    m_impl->config.log_path = m_impl->logPath;

    std::cerr << "[Config] Loaded (simple mode): "
              << m_impl->config.protected_dirs.size() << " protected dirs, "
              << "log=" << WideToUtf8(m_impl->logPath) << ", "
              << "auth=" << WideToUtf8(m_impl->authorizationListPath)
              << std::endl;
    return true;
}

bool Config::Reload() {
    return Load();
}

bool Config::Validate() const {
    if (m_impl->fileWriteWindowSeconds < 0 || m_impl->fileWriteWindowSeconds > 3600) {
        if (g_logger) g_logger->Warn("fileWriteWindowSeconds out of range [0,3600]: %d", m_impl->fileWriteWindowSeconds);
        return false;
    }
    if (m_impl->logRetentionDays < 0 || m_impl->logRetentionDays > 365) {
        if (g_logger) g_logger->Warn("logRetentionDays out of range [0,365]: %d", m_impl->logRetentionDays);
        return false;
    }
    if (m_impl->alertTimeoutSeconds <= 0 || m_impl->alertTimeoutSeconds > 600) {
        if (g_logger) g_logger->Warn("alertTimeoutSeconds out of range (0,600]: %d", m_impl->alertTimeoutSeconds);
        return false;
    }
    if (m_impl->config.encrypt_timeout_seconds <= 0 || m_impl->config.encrypt_timeout_seconds > 600) {
        if (g_logger) g_logger->Warn("encrypt_timeout_seconds out of range (0,600]: %d", m_impl->config.encrypt_timeout_seconds);
        return false;
    }
    if (m_impl->fileWriteThreshold < 0 || m_impl->fileWriteThreshold > 100000) {
        if (g_logger) g_logger->Warn("fileWriteThreshold out of range [0,100000]: %d", m_impl->fileWriteThreshold);
        return false;
    }
    if (m_impl->fileDeleteThreshold < 0 || m_impl->fileDeleteThreshold > 100000) {
        if (g_logger) g_logger->Warn("fileDeleteThreshold out of range [0,100000]: %d", m_impl->fileDeleteThreshold);
        return false;
    }
    if (m_impl->fileCompressThreshold < 0 || m_impl->fileCompressThreshold > 100000) {
        if (g_logger) g_logger->Warn("fileCompressThreshold out of range [0,100000]: %d", m_impl->fileCompressThreshold);
        return false;
    }
    if (m_impl->config.protected_dirs.empty()) {
        if (g_logger) g_logger->Warn("No protected directories configured");
        return false;
    }
    if (m_impl->logPath.empty()) {
        if (g_logger) g_logger->Warn("logPath is empty");
        return false;
    }
    return true;
}

std::string Config::GetVersion() const {
    return m_impl->config.version;
}

std::string Config::GetLogLevel() const {
    return m_impl->config.log_level;
}

std::wstring Config::GetLogPath() const {
    return m_impl->logPath;
}

std::vector<ProtectedDirectory> Config::GetProtectedDirectories() const {
    return m_impl->config.protected_dirs;
}

bool Config::IsPathProtected(const std::wstring& path) const {
    std::wstring lowerPath(path);
    while (!lowerPath.empty() && lowerPath.back() == L'\\') lowerPath.pop_back();
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    for (const auto& dir : m_impl->config.protected_dirs) {
        std::wstring lowerDir(dir.path);
        while (!lowerDir.empty() && lowerDir.back() == L'\\') lowerDir.pop_back();
        std::transform(lowerDir.begin(), lowerDir.end(), lowerDir.begin(), ::towlower);
        if (lowerPath.find(lowerDir) == 0 &&
            (lowerPath.length() == lowerDir.length() || lowerPath[lowerDir.length()] == L'\\')) {
            return true;
        }
    }
    return false;
}

std::vector<WhitelistProcess> Config::GetProcessWhitelist() const {
    return m_impl->config.whitelist;
}

bool Config::IsProcessWhitelisted(const std::wstring& processName, 
                                   const std::wstring& permission,
                                   const std::wstring& fullPath) const {
    for (const auto& proc : m_impl->config.whitelist) {
        if (_wcsicmp(proc.name.c_str(), processName.c_str()) == 0) {
            if (!proc.path_prefix.empty() && !fullPath.empty()) {
                if (fullPath.size() < proc.path_prefix.size())
                    continue;
                if (_wcsnicmp(fullPath.c_str(), proc.path_prefix.c_str(),
                              proc.path_prefix.size()) != 0)
                    continue;
                wchar_t boundary = fullPath[proc.path_prefix.size()];
                if (boundary != L'\0' && boundary != L'\\')
                    continue;
            }
            if (permission.empty()) return true;
            for (const auto& perm : proc.permissions) {
                if (_wcsicmp(perm.c_str(), permission.c_str()) == 0) return true;
            }
        }
    }
    return false;
}

std::vector<DetectionRule> Config::GetDetectionRules() const {
    return m_impl->config.rules;
}

bool Config::GetRule(const std::string& id, DetectionRule& rule) const {
    for (const auto& r : m_impl->config.rules) {
        if (r.id == id) {
            rule = r;
            return true;
        }
    }
    return false;
}

// Tier 1 getters
int Config::GetFileWriteThreshold() const { return m_impl->fileWriteThreshold; }
int Config::GetFileWriteWindowSeconds() const { return m_impl->fileWriteWindowSeconds; }
int Config::GetFileCompressThreshold() const { return m_impl->fileCompressThreshold; }
int Config::GetFileCompressWindowSeconds() const { return m_impl->fileCompressWindowSeconds; }
int Config::GetFileDeleteThreshold() const { return m_impl->fileDeleteThreshold; }
int Config::GetFileDeleteWindowSeconds() const { return m_impl->fileDeleteWindowSeconds; }
int Config::GetFileNetworkTransferThreshold() const { return m_impl->fileNetworkTransferThreshold; }
int Config::GetFileNetworkTransferWindowSeconds() const { return m_impl->fileNetworkTransferWindowSeconds; }
int Config::GetDataTransferThresholdMB() const { return m_impl->dataTransferMB; }
int Config::GetProcessTerminationCount() const { return m_impl->processTerminationCount; }
int Config::GetProcessTerminationWindowSeconds() const { return m_impl->processTerminationWindowSeconds; }

// Tier 2 getters
int Config::GetTier2FileWriteThreshold() const { return m_impl->tier2FileWriteThreshold; }
int Config::GetTier2FileWriteWindowSeconds() const { return m_impl->tier2FileWriteWindowSeconds; }
int Config::GetTier2FileCompressThreshold() const { return m_impl->tier2FileCompressThreshold; }
int Config::GetTier2FileCompressWindowSeconds() const { return m_impl->tier2FileCompressWindowSeconds; }
int Config::GetTier2FileDeleteThreshold() const { return m_impl->tier2FileDeleteThreshold; }
int Config::GetTier2FileDeleteWindowSeconds() const { return m_impl->tier2FileDeleteWindowSeconds; }
int Config::GetTier2FileNetworkTransferThreshold() const { return m_impl->tier2FileNetworkTransferThreshold; }
int Config::GetTier2FileNetworkTransferWindowSeconds() const { return m_impl->tier2FileNetworkTransferWindowSeconds; }
int Config::GetTier2DataTransferThresholdMB() const { return m_impl->tier2DataTransferMB; }
int Config::GetTier2ProcessTerminationCount() const { return m_impl->tier2ProcessTerminationCount; }
int Config::GetTier2ProcessTerminationWindowSeconds() const { return m_impl->tier2ProcessTerminationWindowSeconds; }

int Config::GetFileCreateThreshold() const { return m_impl->fileCreateThreshold; }
int Config::GetFileCreateWindowSeconds() const { return m_impl->fileCreateWindowSeconds; }
int Config::GetTier2FileCreateThreshold() const { return m_impl->tier2FileCreateThreshold; }
int Config::GetTier2FileCreateWindowSeconds() const { return m_impl->tier2FileCreateWindowSeconds; }

int Config::GetFileRenameThreshold() const { return m_impl->fileRenameThreshold; }
int Config::GetFileRenameWindowSeconds() const { return m_impl->fileRenameWindowSeconds; }
int Config::GetFileMoveThreshold() const { return m_impl->fileMoveThreshold; }
int Config::GetFileMoveWindowSeconds() const { return m_impl->fileMoveWindowSeconds; }
int Config::GetTier2FileRenameThreshold() const { return m_impl->tier2FileRenameThreshold; }
int Config::GetTier2FileRenameWindowSeconds() const { return m_impl->tier2FileRenameWindowSeconds; }
int Config::GetTier2FileMoveThreshold() const { return m_impl->tier2FileMoveThreshold; }
int Config::GetTier2FileMoveWindowSeconds() const { return m_impl->tier2FileMoveWindowSeconds; }

bool Config::IsFileTypeMonitored(const std::wstring& filePath) const {
    auto dot = filePath.rfind(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = filePath.substr(dot);
    
    // Check exclude list first
    for (const auto& dir : m_impl->config.protected_dirs) {
        for (const auto& ft : dir.file_types) {
            if (ft.size() > 1 && ft[0] == L'-') {
                std::wstring pattern = ft.substr(1);
                auto pDot = pattern.rfind(L'.');
                if (pDot != std::wstring::npos) {
                    if (_wcsicmp(ext.c_str(), pattern.substr(pDot).c_str()) == 0) return false;
                }
            }
        }
    }
    
    // Global exclude list (protection.file_types.exclude from YAML)
    for (const auto& exc : m_impl->excludeFileTypes) {
        auto eDot = exc.rfind(L'.');
        if (eDot != std::wstring::npos) {
            if (_wcsicmp(ext.c_str(), exc.substr(eDot).c_str()) == 0) return false;
        }
    }

    // Global include list — if non-empty, only listed types are monitored
    if (!m_impl->includeFileTypes.empty()) {
        for (const auto& inc : m_impl->includeFileTypes) {
            auto iDot = inc.rfind(L'.');
            if (iDot != std::wstring::npos) {
                if (_wcsicmp(ext.c_str(), inc.substr(iDot).c_str()) == 0) return true;
            }
        }
        return false;
    }
    
    return true;
}

static ResponseAction GetDefaultEventResponse(DriverEventType eventType) {
    switch (eventType) {
        case DriverEventType::FILE_CREATE:
        case DriverEventType::PROCESS_CREATE:
        case DriverEventType::PROC_TERMINATE:
        case DriverEventType::DRIVER_LOAD:
        case DriverEventType::DRIVER_UNLOAD:
            return ResponseAction::LOG;
        case DriverEventType::FILE_WRITE:
        case DriverEventType::FILE_RENAME:
        case DriverEventType::FILE_DELETE:
        case DriverEventType::FILE_MOVE:
        case DriverEventType::FILE_COMPRESS:
        case DriverEventType::FILE_NETWORK_TRANSFER:
            return ResponseAction::LOG | ResponseAction::ALERT_USER;
        default:
            return ResponseAction::LOG;
    }
}

ResponseAction Config::GetEventResponse(DriverEventType eventType) const {
    auto it = m_impl->eventResponses.find(static_cast<uint32_t>(eventType));
    if (it != m_impl->eventResponses.end()) {
        return it->second;
    }
    return GetDefaultEventResponse(eventType);
}

std::string Config::GetAdminPasswordHash() const { return m_impl->adminPasswordHash; }
std::string Config::GetInstallKey() const { return m_impl->installKey; }
int Config::GetUnlockTimeoutSeconds() const { return m_impl->unlockTimeoutSeconds; }
int Config::GetAlertTimeoutSeconds() const { return m_impl->alertTimeoutSeconds; }

int Config::GetLogRetentionDays() const { return m_impl->logRetentionDays; }
bool Config::GetLogDailyRotation() const { return m_impl->logDailyRotation; }
std::string Config::GetLogFormat() const { return m_impl->logFormat; }

std::wstring Config::GetAuthorizationListPath() const { return m_impl->authorizationListPath; }

void Config::SetCachedAuthEntries(const std::vector<CachedAuthEntry>& entries) {
    m_impl->cachedAuthEntries.clear();
    for (const auto& e : entries) {
        m_impl->cachedAuthEntries.push_back({e.ip, e.mac, e.description});
    }
}

std::vector<Config::CachedAuthEntry> Config::GetCachedAuthEntries() const {
    std::vector<CachedAuthEntry> result;
    for (const auto& e : m_impl->cachedAuthEntries) {
        result.push_back({e.ip, e.mac, e.description});
    }
    return result;
}

bool Config::HasCachedAuthEntries() const {
    return !m_impl->cachedAuthEntries.empty();
}

int Config::GetEncryptTimeoutSeconds() const {
    return m_impl->config.encrypt_timeout_seconds;
}

int Config::GetRecoveryWaitSeconds() const {
    return m_impl->config.recovery_wait_seconds;
}

std::string Config::GetWipeMethod() const {
    return m_impl->config.wipe_method;
}

uint16_t Config::GetTcpPortBase() const {
    return m_impl->config.tcp_port_base;
}

bool Config::IsTlsEnabled() const {
    return m_impl->config.tls_enabled;
}

void Config::RegisterChangeCallback(ConfigChangeCallback callback) {
    m_impl->callbacks.push_back(std::move(callback));
}

void Config::StartWatching() {
    if (m_impl->watcherRunning) return;
    m_impl->watcherRunning = true;
    m_impl->watcherThread = std::thread([this]() {
        std::wstring dir = L"C:\\ProgramData\\GuardianShield\\config";
        HANDLE hChange = FindFirstChangeNotificationW(
            dir.c_str(), FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE);
        if (hChange == INVALID_HANDLE_VALUE) return;
        while (m_impl->watcherRunning) {
            DWORD wait = WaitForSingleObject(hChange, 1000);
            if (wait == WAIT_OBJECT_0) {
                Load();
                for (const auto& cb : m_impl->callbacks) {
                    if (cb) cb("config");
                }
                FindNextChangeNotification(hChange);
            }
        }
        FindCloseChangeNotification(hChange);
    });
}

void Config::StopWatching() {
    m_impl->watcherRunning = false;
    if (m_impl->watcherThread.joinable()) {
        m_impl->watcherThread.join();
    }
}

SystemConfig Config::GetSystemConfig() const {
    return m_impl->config;
}

bool Config::UpdateSystemConfig(const SystemConfig& config) {
    m_impl->config = config;
    return true;
}

bool Config::Save() {
    std::wstring tempPath = L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml.tmp";
    std::wstring finalPath = L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml";
    
    std::ofstream file(tempPath);
    if (!file.is_open()) {
        SaveToCache();
        return false;
    }
    
    auto ws2s = [](const std::wstring& ws) -> std::string { return WideToUtf8(ws); };
    
    file << "system:\n";
    file << "  version: \"" << m_impl->config.version << "\"\n";
    file << "  log_level: \"" << m_impl->config.log_level << "\"\n";
    file << "  log_path: \"" << ws2s(m_impl->logPath) << "\"\n";
    
    file << "\ndetection:\n";
    file << "  alert_timeout_seconds: " << m_impl->alertTimeoutSeconds << "\n";
    file << "  thresholds:\n";
    file << "    tier1:\n";
    file << "      file_write_count: " << m_impl->fileWriteThreshold << "\n";
    file << "      file_write_window_seconds: " << m_impl->fileWriteWindowSeconds << "\n";
    file << "      file_compress_count: " << m_impl->fileCompressThreshold << "\n";
    file << "      file_compress_window_seconds: " << m_impl->fileCompressWindowSeconds << "\n";
    file << "      file_delete_count: " << m_impl->fileDeleteThreshold << "\n";
    file << "      file_delete_window_seconds: " << m_impl->fileDeleteWindowSeconds << "\n";
    file << "      file_create_count: " << m_impl->fileCreateThreshold << "\n";
    file << "      file_create_window_seconds: " << m_impl->fileCreateWindowSeconds << "\n";
    file << "      file_rename_count: " << m_impl->fileRenameThreshold << "\n";
    file << "      file_rename_window_seconds: " << m_impl->fileRenameWindowSeconds << "\n";
    file << "      file_move_count: " << m_impl->fileMoveThreshold << "\n";
    file << "      file_move_window_seconds: " << m_impl->fileMoveWindowSeconds << "\n";
    file << "      file_network_transfer_count: " << m_impl->fileNetworkTransferThreshold << "\n";
    file << "      file_network_transfer_window_seconds: " << m_impl->fileNetworkTransferWindowSeconds << "\n";
    file << "      data_transfer_mb: " << m_impl->dataTransferMB << "\n";
    file << "      process_termination_count: " << m_impl->processTerminationCount << "\n";
    file << "      process_termination_window_seconds: " << m_impl->processTerminationWindowSeconds << "\n";
    file << "    tier2:\n";
    file << "      file_write_count: " << m_impl->tier2FileWriteThreshold << "\n";
    file << "      file_write_window_seconds: " << m_impl->tier2FileWriteWindowSeconds << "\n";
    file << "      file_compress_count: " << m_impl->tier2FileCompressThreshold << "\n";
    file << "      file_compress_window_seconds: " << m_impl->tier2FileCompressWindowSeconds << "\n";
    file << "      file_delete_count: " << m_impl->tier2FileDeleteThreshold << "\n";
    file << "      file_delete_window_seconds: " << m_impl->tier2FileDeleteWindowSeconds << "\n";
    file << "      file_create_count: " << m_impl->tier2FileCreateThreshold << "\n";
    file << "      file_create_window_seconds: " << m_impl->tier2FileCreateWindowSeconds << "\n";
    file << "      file_rename_count: " << m_impl->tier2FileRenameThreshold << "\n";
    file << "      file_rename_window_seconds: " << m_impl->tier2FileRenameWindowSeconds << "\n";
    file << "      file_move_count: " << m_impl->tier2FileMoveThreshold << "\n";
    file << "      file_move_window_seconds: " << m_impl->tier2FileMoveWindowSeconds << "\n";
    file << "      file_network_transfer_count: " << m_impl->tier2FileNetworkTransferThreshold << "\n";
    file << "      file_network_transfer_window_seconds: " << m_impl->tier2FileNetworkTransferWindowSeconds << "\n";
    file << "      data_transfer_mb: " << m_impl->tier2DataTransferMB << "\n";
    file << "      process_termination_count: " << m_impl->tier2ProcessTerminationCount << "\n";
    file << "      process_termination_window_seconds: " << m_impl->tier2ProcessTerminationWindowSeconds << "\n";
    
    file << "\nprotection:\n";
    file << "  directories:\n";
    for (const auto& dir : m_impl->config.protected_dirs) {
        file << "    - path: \"" << ws2s(dir.path) << "\"\n";
        file << "      recursive: " << (dir.recursive ? "true" : "false") << "\n";
        const char* prio = (dir.priority >= 10) ? "HIGH" 
                         : (dir.priority >= 5)  ? "MEDIUM" : "LOW";
        file << "      priority: " << prio << "\n";
    }
    file << "  file_types:\n";
    file << "    include:\n";
    for (const auto& ft : m_impl->includeFileTypes)
        file << "      - \"" << ws2s(ft) << "\"\n";
    file << "    exclude:\n";
    for (const auto& ft : m_impl->excludeFileTypes)
        file << "      - \"" << ws2s(ft) << "\"\n";
    
    file << "\nwhitelist:\n";
    file << "  processes:\n";
    for (const auto& wp : m_impl->config.whitelist) {
        file << "    - name: \"" << ws2s(wp.name) << "\"\n";
        if (!wp.description.empty())
            file << "      description: \"" << ws2s(wp.description) << "\"\n";
        if (!wp.permissions.empty()) {
            file << "      permissions: [";
            for (size_t i = 0; i < wp.permissions.size(); ++i) {
                if (i > 0) file << ", ";
                file << "\"" << ws2s(wp.permissions[i]) << "\"";
            }
            file << "]\n";
        }
    }
    
    file << "\nauthorization:\n";
    file << "  list_path: \"" << ws2s(m_impl->authorizationListPath) << "\"\n";
    
    file << "\nlogging:\n";
    file << "  path: \"" << ws2s(m_impl->logPath) << "\"\n";
    file << "  format: \"" << m_impl->logFormat << "\"\n";
    file << "  retention_days: " << m_impl->logRetentionDays << "\n";
    file << "  daily_rotation: " << (m_impl->logDailyRotation ? "true" : "false") << "\n";
    
    file << "\nadmin:\n";
    if (!m_impl->adminPasswordHash.empty())
        file << "  password_hash: \"" << m_impl->adminPasswordHash << "\"\n";
    if (!m_impl->installKey.empty())
        file << "  install_key: \"" << m_impl->installKey << "\"\n";
    file << "  unlock_timeout_seconds: " << m_impl->unlockTimeoutSeconds << "\n";
    
    file << "\nemergency:\n";
    file << "  encrypt_timeout_seconds: " << m_impl->config.encrypt_timeout_seconds << "\n";
    file << "  recovery_wait_seconds: " << m_impl->config.recovery_wait_seconds << "\n";
    file << "  wipe_method: \"" << m_impl->config.wipe_method << "\"\n";
    
    file.close();
    
    if (!MoveFileExW(tempPath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(tempPath.c_str());
        SaveToCache();
        return false;
    }
    
    SaveToCache();
    return true;
}

void Config::DeleteConfigFile() {
    std::error_code ec;
    if (std::filesystem::exists(m_configPath, ec)) {
        if (std::filesystem::remove(m_configPath, ec)) {
            std::cerr << "[配置] 已删除原始配置文件（钥匙已回收）" << std::endl;
        }
    }
}

void Config::SetCacheFilePermissions(const std::wstring& path) {
#ifdef _WIN32
    PSECURITY_DESCRIPTOR pSD = nullptr;
    // SYSTEM 和 Administrators 完全访问，其他用户无权限
    LPCWSTR sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, nullptr)) {
        SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION, pSD);
        LocalFree(pSD);
    }
#else
    (void)path;
#endif
}

// 全局配置实例
std::shared_ptr<Config> g_config;

} // namespace Guardian
