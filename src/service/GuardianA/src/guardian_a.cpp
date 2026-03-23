/**
 * @file guardian_a.cpp
 * @brief GuardianA service implementation
 */

#include "guardian_a.h"
#include "../../../driver/shared/guardian_ioctl.h"
#include "../../common/include/string_utils.h"
#include "../../common/include/emergency_state_machine.h"
#include <iostream>
#include <functional>
#include <algorithm>
#include <shlobj.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <wincrypt.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Psapi.lib")

namespace Guardian {

// ============================================
// ETW — Microsoft-Windows-Kernel-File (manifest-based)
// ============================================

// NT device path -> DOS drive letter conversion
static std::unordered_map<std::wstring, std::wstring> s_deviceToDosMap;
static std::once_flag s_deviceMapOnce;

static void BuildDeviceToDosMap() {
    s_deviceToDosMap.clear();
    wchar_t drives[512] = {};
    if (!GetLogicalDriveStringsW(511, drives)) return;
    for (wchar_t* d = drives; *d; d += wcslen(d) + 1) {
        wchar_t letter[3] = { d[0], L':', 0 };
        wchar_t device[MAX_PATH] = {};
        if (QueryDosDeviceW(letter, device, MAX_PATH) > 0) {
            s_deviceToDosMap[device] = letter;
        }
    }
}

static void ConvertDevicePathToDos(wchar_t* path, size_t pathChars) {
    std::call_once(s_deviceMapOnce, BuildDeviceToDosMap);
    if (path[0] != L'\\') return;
    for (const auto& [dev, dos] : s_deviceToDosMap) {
        size_t devLen = dev.size();
        if (_wcsnicmp(path, dev.c_str(), devLen) == 0 &&
            (path[devLen] == L'\\' || path[devLen] == L'\0')) {
            std::wstring result = dos + (path + devLen);
            wcsncpy(path, result.c_str(), pathChars - 1);
            path[pathChars - 1] = L'\0';
            return;
        }
    }
}

// FileObject -> Path LRU/TTL cache
struct FileObjectCacheEntry {
    std::wstring path;
    uint64_t lastAccessMs;
};

static std::unordered_map<uint64_t, FileObjectCacheEntry> s_fileObjectCache;
static std::mutex s_fileObjectCacheMutex;
static constexpr size_t FILE_OBJECT_CACHE_MAX = 50000;
static constexpr uint64_t FILE_OBJECT_CACHE_TTL_MS = 120000;

// FILE_MOVE correlation: cross-volume moves appear as CREATE+DELETE from the same process.
// Track recent FILE_CREATE events; when a FILE_DELETE arrives with the same
// base filename from the same PID within the time window, reclassify as FILE_MOVE.
struct MoveCreateCandidate {
    DWORD processId;
    std::wstring baseNameLower;
    std::wstring fullPath;
    uint64_t timestampMs;
};
static std::vector<MoveCreateCandidate> s_moveCandidates;
static std::mutex s_moveCandidateMutex;
static constexpr size_t MOVE_CANDIDATES_MAX = 2048;
static constexpr uint64_t MOVE_CORRELATION_WINDOW_MS = 5000; // 5 seconds

static uint64_t GetCurrentTimeMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

static void EvictStaleCacheEntries() {
    uint64_t now = GetCurrentTimeMs();
    for (auto it = s_fileObjectCache.begin(); it != s_fileObjectCache.end(); ) {
        if (now - it->second.lastAccessMs > FILE_OBJECT_CACHE_TTL_MS) {
            it = s_fileObjectCache.erase(it);
        } else {
            ++it;
        }
    }
}

// Event deduplication cache
static std::unordered_map<size_t, uint64_t> s_recentEvents;
static std::mutex s_deduplicationMutex;
static constexpr uint64_t DEDUP_WINDOW_MS = 500;

// Microsoft-Windows-Kernel-File provider GUID (manifest-based)
static const GUID FileProviderGuid =
    { 0xEDD08927, 0x9CC4, 0x4E65,
      { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };

// Microsoft-Windows-Kernel-Process provider GUID (manifest-based)
static const GUID ProcessProviderGuid =
    { 0x22FB2CD6, 0x0E7B, 0x422B,
      { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

// Static instance for ETW callback
std::atomic<GuardianA*> GuardianA::s_instance{nullptr};

// ResponseAction combined bitmask -> highest-priority string
static const char* ResponseActionCombinedToString(ResponseAction action) {
    uint8_t v = static_cast<uint8_t>(action);
    if (v & static_cast<uint8_t>(ResponseAction::BLOCK)) return "BLOCK";
    if (v & static_cast<uint8_t>(ResponseAction::TERMINATE)) return "TERMINATE";
    if (v & static_cast<uint8_t>(ResponseAction::ENCRYPT)) return "ENCRYPT";
    if (v & static_cast<uint8_t>(ResponseAction::ALERT_USER)) return "ALERT_USER";
    return "LOG";
}

// ============================================
// Constructor / Destructor
// ============================================

GuardianA::GuardianA() 
    : WindowsService(L"WinDefenderCore", L"Windows Defender Core Service", 
                   SERVICE_AUTO_START, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
    , m_hFilterDriver(INVALID_HANDLE_VALUE)
    , m_hMonitorDriver(INVALID_HANDLE_VALUE)
    , m_traceSession(0)
    , m_traceHandle(INVALID_PROCESSTRACE_HANDLE)
    , m_etwRunning(false)
    , m_running(false)
    , m_emergencyMode(false)
    , m_emergencyLevel(0)
    , m_cancelRequested(false)
    , m_emergencyState(EmergencyState::NORMAL)
    , m_sequence(0)
    , m_eventsProcessed(0)
    , m_threatsDetected(0)
{
    memset(m_lastHeartbeat, 0, sizeof(m_lastHeartbeat));
    memset(m_missedHeartbeats, 0, sizeof(m_missedHeartbeats));
    s_instance = this;
}

GuardianA::~GuardianA() {
    StopWorkerThreads();
    ShutdownEtw();
    if (m_hFilterDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFilterDriver);
    }
    if (m_hMonitorDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hMonitorDriver);
    }
    s_instance = nullptr;
}

void GuardianA::OnStart(DWORD argc, LPWSTR* argv) {
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianA starting...");

    m_leaderMutex = CreateMutexW(NULL, TRUE, L"Global\\GuardianShield-Leader");
    if (!m_leaderMutex) {
        LogEvent(EVENTLOG_WARNING_TYPE,
                 L"Failed to create leader election mutex; continuing without split-brain lock");
    }
    
    if (!Initialize()) {
        LogEvent(EVENTLOG_ERROR_TYPE, L"GuardianA initialization failed");
        ReportStatus(State::Stopped, 1);
        return;
    }
    
    // FIX-05: 区分"无授权数据"(良性) vs "设备未授权"(恶意)
    if (!ValidateEnvironment()) {
        if (m_envValidator && !m_envValidator->HasAuthorizationList()) {
            LogEvent(EVENTLOG_ERROR_TYPE,
                     L"No authorization data - entering SAFE MODE (monitoring only)");
            m_safeMode = true;
        } else {
            LogEvent(EVENTLOG_ERROR_TYPE,
                     L"UNAUTHORIZED DEVICE - triggering emergency protocol!");
            TriggerEmergencyProtocol(true);
            return;
        }
    }
    
    StartWorkerThreads();
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianA started successfully");
}

void GuardianA::OnStop() {
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianA stopping...");
    m_running = false;
    StopWorkerThreads();

    if (m_leaderMutex) {
        ReleaseMutex(m_leaderMutex);
        CloseHandle(m_leaderMutex);
        m_leaderMutex = NULL;
    }

    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianA stopped");
}

void GuardianA::OnShutdown() {
    OnStop();
}

bool GuardianA::Initialize() {
    if (!LoadConfiguration()) {
        return false;
    }
    
    // Initialize logger
    if (!InitializeLogger()) {
        LogEvent(EVENTLOG_WARNING_TYPE, L"Failed to initialize logger");
        // Continue without logger
    }
    
    if (!InitializeIPC()) {
        return false;
    }

    // Register IPC message handler to receive DRIVER_EVENTs from GuardianC
    if (m_ipcManager) {
        m_ipcManager->SetMessageHandler(
            [this](const MessageHeader& hdr, const uint8_t* payload, size_t len) {
                if (static_cast<MessageType>(hdr.type) == MessageType::DRIVER_EVENT
                    && len >= sizeof(DriverEvent)) {
                    DriverEvent event;
                    memcpy(&event, payload, sizeof(DriverEvent));
                    size_t dedupKey = std::hash<std::wstring>{}(
                        std::wstring(event.file_path)) ^
                        (std::hash<uint32_t>{}(event.event_type) << 1) ^
                        (std::hash<uint32_t>{}(event.process_id) << 2);
                    {
                        std::lock_guard<std::mutex> dlock(s_deduplicationMutex);
                        uint64_t now = GetCurrentTimeMs();
                        auto it = s_recentEvents.find(dedupKey);
                        if (it != s_recentEvents.end() &&
                            (now - it->second) < DEDUP_WINDOW_MS) {
                            return;
                        }
                        s_recentEvents[dedupKey] = now;
                    }
                    QueueEvent(event);
                } else {
                    HandleGuardianMessage(hdr, payload, len);
                }
            });
    }

    if (!InitializeEnvironmentValidator()) {
        LogEvent(EVENTLOG_WARNING_TYPE,
                 L"Environment validator init returned false - no auth data");
    }
    if (!InitializeKeys()) {
        // Non-fatal: continue without TPM
    }
    
    m_fileEncryptor = std::make_unique<FileEncryptor>();
    m_fileWiper = std::make_unique<FileWiper>();

    // Initialize ThreatEvaluator with two-tier thresholds from config
    m_threatEvaluator = std::make_unique<ThreatEvaluator>();
    {
        DetectionThresholds tier1, tier2;
        
        tier1.file_write_count = m_config->GetFileWriteThreshold();
        tier1.file_write_window_seconds = m_config->GetFileWriteWindowSeconds();
        tier1.file_compress_count = m_config->GetFileCompressThreshold();
        tier1.file_compress_window_seconds = m_config->GetFileCompressWindowSeconds();
        tier1.file_delete_count = m_config->GetFileDeleteThreshold();
        tier1.file_delete_window_seconds = m_config->GetFileDeleteWindowSeconds();
        tier1.file_network_transfer_count = m_config->GetFileNetworkTransferThreshold();
        tier1.file_network_transfer_window_seconds = m_config->GetFileNetworkTransferWindowSeconds();
        tier1.file_create_count = m_config->GetFileCreateThreshold();
        tier1.file_create_window_seconds = m_config->GetFileCreateWindowSeconds();
        tier1.file_rename_count = m_config->GetFileRenameThreshold();
        tier1.file_rename_window_seconds = m_config->GetFileRenameWindowSeconds();
        tier1.file_move_count = m_config->GetFileMoveThreshold();
        tier1.file_move_window_seconds = m_config->GetFileMoveWindowSeconds();
        tier1.data_transfer_mb = m_config->GetDataTransferThresholdMB();
        tier1.process_termination_count = m_config->GetProcessTerminationCount();
        tier1.process_termination_window_seconds = m_config->GetProcessTerminationWindowSeconds();

        tier2.file_write_count = m_config->GetTier2FileWriteThreshold();
        tier2.file_write_window_seconds = m_config->GetTier2FileWriteWindowSeconds();
        tier2.file_compress_count = m_config->GetTier2FileCompressThreshold();
        tier2.file_compress_window_seconds = m_config->GetTier2FileCompressWindowSeconds();
        tier2.file_delete_count = m_config->GetTier2FileDeleteThreshold();
        tier2.file_delete_window_seconds = m_config->GetTier2FileDeleteWindowSeconds();
        tier2.file_network_transfer_count = m_config->GetTier2FileNetworkTransferThreshold();
        tier2.file_network_transfer_window_seconds = m_config->GetTier2FileNetworkTransferWindowSeconds();
        tier2.file_create_count = m_config->GetTier2FileCreateThreshold();
        tier2.file_create_window_seconds = m_config->GetTier2FileCreateWindowSeconds();
        tier2.file_rename_count = m_config->GetTier2FileRenameThreshold();
        tier2.file_rename_window_seconds = m_config->GetTier2FileRenameWindowSeconds();
        tier2.file_move_count = m_config->GetTier2FileMoveThreshold();
        tier2.file_move_window_seconds = m_config->GetTier2FileMoveWindowSeconds();
        tier2.data_transfer_mb = m_config->GetTier2DataTransferThresholdMB();
        tier2.process_termination_count = m_config->GetTier2ProcessTerminationCount();
        tier2.process_termination_window_seconds = m_config->GetTier2ProcessTerminationWindowSeconds();

        m_threatEvaluator->SetTieredThresholds(tier1, tier2);
    }

    LoadProtectedPaths();
    
    if (!ConnectDrivers()) {
        LogEvent(EVENTLOG_WARNING_TYPE, L"Driver connection failed - running without kernel driver");
    }
    
    if (!InitializeEtw()) {
        if (g_logger) g_logger->Warn("ETW initialization failed - relying on minifilter only");
    }
    
    return true;
}

bool GuardianA::InitializeLogger() {
    try {
        std::wstring logDir = m_config->GetLogPath();
        if (logDir.empty()) {
            logDir = L"C:\\ProgramData\\GuardianShield\\logs";
        }
        std::wstring logPath = logDir + L"\\guardian_a";
        
        int retentionDays = m_config->GetLogRetentionDays();
        if (retentionDays == 0) {
            retentionDays = 7; // Default to 7 days
        }
        
        LogFormat format = LogFormat::JSON;
        std::string logFormat = m_config->GetLogFormat();
        if (logFormat == "text") {
            format = LogFormat::TEXT;
        }
        
        g_logger = std::make_shared<Logger>(logPath, LogLevel::INFO, format, retentionDays);
        g_logger->SetConsoleOutput(false); // No console output for service
        return true;
    } catch (const std::exception& e) {
        LogEvent(EVENTLOG_ERROR_TYPE, (L"Logger initialization failed: " + Utf8ToWide(std::string(e.what()))).c_str());
        return false;
    }
}

bool GuardianA::InitializeEnvironmentValidator() {
    m_envValidator = std::make_unique<EnvironmentValidator>();

    std::wstring authListPath = m_config->GetAuthorizationListPath();
    bool loaded = false;
    if (!authListPath.empty()) {
        loaded = m_envValidator->LoadAuthorizationList(authListPath);
    }

    if (loaded) {
        // FIX-03: 回写到配置缓存，确保重启后可恢复
        const auto& auths = m_envValidator->GetAuthorizations();
        std::vector<Config::CachedAuthEntry> entries;
        for (const auto& a : auths) {
            entries.push_back({a.ip_address, a.mac_address, a.description});
        }
        m_config->SetCachedAuthEntries(entries);

        // FIX-03: 统一缓存 + 删除源文件（YAML 和 auth.list）
        m_config->SecureDeleteSources();
        m_envValidator->DeleteAuthorizationFile(authListPath);

        LogEvent(EVENTLOG_INFORMATION_TYPE,
                 L"Authorization list loaded from file and cached");
    } else if (m_config->HasCachedAuthEntries()) {
        auto cached = m_config->GetCachedAuthEntries();
        for (const auto& e : cached) {
            AuthorizationEntry entry;
            entry.ip_address = e.ip;
            entry.mac_address = e.mac;
            entry.description = e.description;
            m_envValidator->AddAuthorization(entry);
        }
        LogEvent(EVENTLOG_INFORMATION_TYPE,
                 L"Authorization list restored from cache");
    } else {
        // FIX-10: 升级为 ERROR 级别
        LogEvent(EVENTLOG_ERROR_TYPE,
                 L"CRITICAL: No authorization data available (file or cache)!");
        return false;
    }

    return true;
}

bool GuardianA::ValidateEnvironment() {
    if (!m_envValidator) return true;
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (m_envValidator->ValidateEnvironment()) return true;
        auto ifaces = m_envValidator->GetAllNetworkInterfaces();
        bool hasRealIP = false;
        for (const auto& iface : ifaces) {
            if (iface.first != "0.0.0.0") { hasRealIP = true; break; }
        }
        if (hasRealIP) return false;
        Sleep(3000);
    }
    return false;
}

bool GuardianA::LoadConfiguration() {
    m_config = std::make_shared<Config>(L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml");
    return m_config->Load();
}

bool GuardianA::InitializeIPC() {
    m_ipcManager = std::make_unique<IpcManager>(NodeId::GUARDIAN_A);
    if (!m_ipcManager->Initialize()) {
        LogEvent(EVENTLOG_WARNING_TYPE, L"IPC initialization failed - running in standalone mode");
        // IPC is optional - don't fail initialization
    }
    return true;  // Always succeed, IPC is optional
}

bool GuardianA::ConnectDrivers() {
    m_driverClient = std::make_unique<DriverClient>();
    if (m_driverClient->Connect(GUARDFILTER_PORT_NAME)) {
        if (g_logger) g_logger->Info("Connected to GuardFilter via FilterPort");
    } else {
        if (g_logger) g_logger->Warn("Failed to connect to GuardFilter port, running without driver");
    }

    // Connect to GuardMonitor (legacy driver — uses CreateFile/DeviceIoControl)
    m_hMonitorDriver = CreateFileW(
        GUARDMONITOR_USERMODE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_hMonitorDriver != INVALID_HANDLE_VALUE) {
        if (g_logger) g_logger->Info("Connected to GuardMonitor driver");
        DWORD pids[3] = { GetCurrentProcessId(), 0, 0 };
        DWORD br = 0;
        DeviceIoControl(m_hMonitorDriver, IOCTL_GUARDIAN_SET_PROTECTED_PIDS,
                        pids, sizeof(pids), nullptr, 0, &br, nullptr);
    } else {
        if (g_logger) g_logger->Warn("Failed to connect to GuardMonitor: error %lu", GetLastError());
    }

    SyncDriverWhitelist();
    SendBlockPolicy();

    return m_driverClient->IsConnected() || m_hMonitorDriver != INVALID_HANDLE_VALUE;
}

void GuardianA::SyncDriverWhitelist() {
    if (!m_driverClient || !m_driverClient->IsConnected()) return;

    m_driverClient->AddWhitelistProcess(L"svchost_core.exe", 7);
    m_driverClient->AddWhitelistProcess(L"svchost_helper.exe", 7);
    m_driverClient->AddWhitelistProcess(L"winmon.exe", 1);

    if (m_config) {
        for (const auto& wp : m_config->GetProcessWhitelist()) {
            uint32_t driverPerm = 0;
            for (const auto& p : wp.permissions) {
                if (p == L"READ") driverPerm |= 1;
                else if (p == L"WRITE") driverPerm |= 6;
                else if (p == L"DELETE") driverPerm |= 4;
            }
            if (driverPerm == 0) driverPerm = 1;
            m_driverClient->AddWhitelistProcess(wp.name, driverPerm);
        }
    }

    if (g_logger) g_logger->Info("GuardianA: synced whitelist to driver");
}

void GuardianA::SendBlockPolicy() {
    if (!m_config) return;

    uint32_t policy = 0;
    bool hasBlock = false;

    auto check = [&](DriverEventType et, uint32_t flag) {
        ResponseAction ra = m_config->GetEventResponse(et);
        if (HasAction(ra, ResponseAction::BLOCK)) {
            policy |= flag;
            hasBlock = true;
        }
    };
    check(DriverEventType::FILE_CREATE, BLOCK_FLAG_CREATE);
    check(DriverEventType::FILE_WRITE, BLOCK_FLAG_WRITE);
    check(DriverEventType::FILE_DELETE, BLOCK_FLAG_DELETE);
    check(DriverEventType::FILE_RENAME, BLOCK_FLAG_RENAME);

    if (!hasBlock) return;

    if (!m_driverClient || !m_driverClient->IsConnected()) {
        if (g_logger) g_logger->Warn("BLOCK actions configured but driver not connected - BLOCK will be skipped at runtime");
        LogEvent(EVENTLOG_WARNING_TYPE, L"BLOCK actions configured but GuardFilter driver not loaded — BLOCK will be skipped");
        if (m_ipcManager) {
            AlertNotification alert = {};
            alert.level = static_cast<uint8_t>(ThreatLevel::LEVEL_1);
            strncpy_s(alert.message, "BLOCK skipped - kernel driver not loaded", sizeof(alert.message) - 1);
            m_ipcManager->SendToNode(NodeId::GUARDIAN_C, MessageType::ALERT_NOTIFICATION, &alert, sizeof(alert));
        }
        return;
    }

    m_driverClient->SetBlockPolicy(policy);
    if (g_logger) g_logger->Info("GuardianA: block policy sent to driver (flags=0x%02X)", policy);
}

bool GuardianA::InitializeKeys() {
    DATA_BLOB dataIn, dataOut;
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\GuardianShield\\Keys", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        DWORD dataSize = 0;
        result = RegQueryValueExW(hKey, L"MasterKey", nullptr, nullptr, nullptr, &dataSize);
        if (result == ERROR_SUCCESS && dataSize > 0) {
            RegCloseKey(hKey);
            return true;
        }
        RegCloseKey(hKey);
    }

    uint8_t rawKey[32];
    NTSTATUS status = BCryptGenRandom(nullptr, rawKey, sizeof(rawKey),
                                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        SecureZeroMemory(rawKey, sizeof(rawKey));
        return false;
    }

    dataIn.pbData = rawKey;
    dataIn.cbData = sizeof(rawKey);

    BOOL ok = CryptProtectData(&dataIn, L"GuardianShield Master Key",
                                nullptr, nullptr, nullptr,
                                CRYPTPROTECT_LOCAL_MACHINE, &dataOut);
    SecureZeroMemory(rawKey, sizeof(rawKey));

    if (!ok) return false;

    result = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\GuardianShield\\Keys", 0, nullptr, 0,
        KEY_WRITE, nullptr, &hKey, nullptr);
    if (result == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"MasterKey", 0, REG_BINARY,
                       dataOut.pbData, dataOut.cbData);
        RegCloseKey(hKey);
    }

    LocalFree(dataOut.pbData);
    return result == ERROR_SUCCESS;
}

void GuardianA::StartWorkerThreads() {
    m_running = true;
    m_heartbeatThread = std::thread(&GuardianA::HeartbeatThread, this);
    m_eventThread = std::thread(&GuardianA::EventProcessingThread, this);
    m_driverThread = std::thread(&GuardianA::DriverReadThread, this);
}

void GuardianA::StopWorkerThreads() {
    m_running = false;
    m_cancelRequested = true;
    m_emergencyMode = false;
    m_eventCV.notify_all();
    ShutdownEtw();
    if (m_heartbeatThread.joinable()) m_heartbeatThread.join();
    if (m_eventThread.joinable()) m_eventThread.join();
    if (m_driverThread.joinable()) m_driverThread.join();
    if (m_protocolThread.joinable()) m_protocolThread.join();
    if (m_decryptThread.joinable()) m_decryptThread.join();
}

// ============================================
// ETW Event Collection (migrated from GuardianC)
// ============================================

bool GuardianA::InitializeEtw() {
    ShutdownEtw();

    size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
                        (wcslen(ETW_SESSION_NAME) + 1) * sizeof(wchar_t);
    std::vector<BYTE> buffer(bufferSize, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());

    props->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ControlTraceW(0, ETW_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    memset(buffer.data(), 0, bufferSize);
    props->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->BufferSize = 256;
    props->MinimumBuffers = 16;
    props->MaximumBuffers = 64;

    ULONG status = StartTraceW(&m_traceSession, ETW_SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        if (g_logger) g_logger->Error("ETW StartTrace failed: error %lu", status);
        LogEvent(EVENTLOG_ERROR_TYPE, L"ETW StartTrace failed — file I/O monitoring via ETW is unavailable");
        FILE* df = _wfopen(L"C:\\ProgramData\\GuardianShield\\logs\\etw_init.txt", L"a");
        if (df) { fprintf(df, "StartTrace failed: %lu\n", status); fflush(df); fclose(df); }
        if (m_ipcManager) {
            AlertNotification alert = {};
            alert.level = static_cast<uint8_t>(ThreatLevel::LEVEL_1);
            strncpy_s(alert.message, "ETW initialization failed - monitoring degraded", sizeof(alert.message) - 1);
            m_ipcManager->SendToNode(NodeId::GUARDIAN_C, MessageType::ALERT_NOTIFICATION, &alert, sizeof(alert));
        }
        return false;
    }

    // Enable Microsoft-Windows-Kernel-File provider (manifest-based, captures all file I/O)
    ULONG fileStatus = EnableTraceEx2(
        m_traceSession, &FileProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0xFFFFFFFFFFFFFFFF, 0, 0, nullptr);
    {
        FILE* df = _wfopen(L"C:\\ProgramData\\GuardianShield\\logs\\etw_init.txt", L"a");
        if (df) {
            fprintf(df, "EnableTraceEx2(Kernel-File): status=%lu\n", fileStatus);
            fflush(df); fclose(df);
        }
    }

    // Enable Microsoft-Windows-Kernel-Process provider
    ULONG procStatus = EnableTraceEx2(
        m_traceSession, &ProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0xFFFFFFFFFFFFFFFF, 0, 0, nullptr);
    {
        FILE* df = _wfopen(L"C:\\ProgramData\\GuardianShield\\logs\\etw_init.txt", L"a");
        if (df) {
            fprintf(df, "EnableTraceEx2(Kernel-Process): status=%lu\n", procStatus);
            fflush(df); fclose(df);
        }
    }

    if (fileStatus != ERROR_SUCCESS && procStatus != ERROR_SUCCESS) {
        LogEvent(EVENTLOG_ERROR_TYPE, L"ETW: Both providers failed to enable");
        m_etwRunning = false;
        return false;
    }

    m_etwRunning = true;
    m_etwThread = std::thread(&GuardianA::EtwCollectionThread, this);

    if (g_logger) g_logger->Info("ETW session started with Kernel-File and Kernel-Process providers");
    return true;
}

void GuardianA::ShutdownEtw() {
    m_etwRunning = false;

    TRACEHANDLE h = m_traceHandle.load();
    if (h != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(h);
        m_traceHandle.store(INVALID_PROCESSTRACE_HANDLE);
    }

    if (m_traceSession != 0) {
        size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
        std::vector<BYTE> buffer(bufferSize, 0);
        auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
        props->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ControlTraceW(m_traceSession, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        m_traceSession = 0;
    }

    if (m_etwThread.joinable()) {
        m_etwThread.join();
    }
}

void GuardianA::EtwCollectionThread() {
    {
        FILE* df = _wfopen(L"C:\\ProgramData\\GuardianShield\\logs\\etw_thread.txt", L"a");
        if (df) { fprintf(df, "EtwCollectionThread started, session=0x%llx\n", (unsigned long long)m_traceSession); fflush(df); fclose(df); }
    }

    while (m_etwRunning) {
        EVENT_TRACE_LOGFILEW logFile = {};
        logFile.LoggerName = const_cast<LPWSTR>(ETW_SESSION_NAME);
        logFile.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = EtwEventCallback;

        TRACEHANDLE handle = OpenTraceW(&logFile);
        m_traceHandle.store(handle);
        {
            DWORD err = GetLastError();
            FILE* df = _wfopen(L"C:\\ProgramData\\GuardianShield\\logs\\etw_thread.txt", L"a");
            if (df) {
                fprintf(df, "OpenTraceW returned 0x%llx (INVALID=%d) err=%lu\n",
                    (unsigned long long)handle,
                    (int)(handle == INVALID_PROCESSTRACE_HANDLE), err);
                fflush(df); fclose(df);
            }
        }
        if (handle == INVALID_PROCESSTRACE_HANDLE) {
            if (g_logger) g_logger->Warn("OpenTraceW failed, retrying in 5s");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        ULONG status = ProcessTrace(&handle, 1, nullptr, nullptr);
        {
            FILE* df = _wfopen(L"C:\\ProgramData\\GuardianShield\\logs\\etw_thread.txt", L"a");
            if (df) { fprintf(df, "ProcessTrace returned %lu\n", status); fflush(df); fclose(df); }
        }
        if (g_logger) g_logger->Warn("ProcessTrace returned %lu, will restart", status);

        CloseTrace(handle);
        m_traceHandle.store(INVALID_PROCESSTRACE_HANDLE);

        if (!m_etwRunning) break;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void WINAPI GuardianA::EtwEventCallback(PEVENT_RECORD eventRecord) {
    auto inst = s_instance.load();
    if (!inst || !inst->m_running) return;

    bool isFileEvent =
        IsEqualGUID(eventRecord->EventHeader.ProviderId, FileProviderGuid);
    bool isProcessEvent =
        IsEqualGUID(eventRecord->EventHeader.ProviderId, ProcessProviderGuid);

    if (!isFileEvent && !isProcessEvent) return;

    static DWORD s_selfPid = GetCurrentProcessId();
    if (eventRecord->EventHeader.ProcessId == s_selfPid) return;

    DriverEvent driverEvent = {};
    driverEvent.process_id = eventRecord->EventHeader.ProcessId;
    driverEvent.timestamp = eventRecord->EventHeader.TimeStamp.QuadPart;

    if (isFileEvent) {
        USHORT eventId = eventRecord->EventHeader.EventDescriptor.Id;
        auto* ud = static_cast<const uint8_t*>(eventRecord->UserData);
        USHORT udLen = eventRecord->UserDataLength;

        // TDH-based FileName extraction (primary method)
        auto extractFileNameTDH = [&](const wchar_t* propName, wchar_t* dest, size_t destChars) -> bool {
            PROPERTY_DATA_DESCRIPTOR desc = {};
            desc.PropertyName = reinterpret_cast<ULONGLONG>(propName);
            desc.ArrayIndex = ULONG_MAX;
            DWORD propSize = 0;
            ULONG st = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &desc, &propSize);
            if (st != ERROR_SUCCESS || propSize == 0 || propSize > 65536) return false;
            std::vector<BYTE> propBuf(propSize);
            st = TdhGetProperty(eventRecord, 0, nullptr, 1, &desc, propSize, propBuf.data());
            if (st != ERROR_SUCCESS) return false;
            const wchar_t* str = reinterpret_cast<const wchar_t*>(propBuf.data());
            size_t maxChars = propSize / sizeof(wchar_t);
            if (maxChars > 0 && str[0] != L'\0') {
                size_t cc = std::min(maxChars, destChars - 1);
                wcsncpy(dest, str, cc);
                dest[cc] = L'\0';
                return true;
            }
            return false;
        };

        // Microsoft-Windows-Kernel-File event IDs:
        // 10=NameCreate, 11=NameDelete, 12=Create, 14=Write, 15=Read,
        // 17=DeletePath, 19=RenamePath, 23=Close, 26=Cleanup

        uint64_t fileObject = 0;
        uint64_t fileKey = 0;

        // Diagnostic: track event ID distribution (written periodically)
        static std::atomic<uint64_t> s_diagCounts[64] = {};
        static std::atomic<uint64_t> s_diagDropped{0};
        static std::atomic<uint64_t> s_diagDroppedById[64] = {};
        static std::atomic<uint64_t> s_diagTotal{0};
        static std::atomic<uint64_t> s_diagLastDump{0};
        if (eventId < 64) s_diagCounts[eventId].fetch_add(1, std::memory_order_relaxed);
        uint64_t total = s_diagTotal.fetch_add(1, std::memory_order_relaxed);
        if (total > 0 && (total % 10000) == 0) {
            uint64_t now = GetCurrentTimeMs();
            uint64_t last = s_diagLastDump.load(std::memory_order_relaxed);
            if (now - last > 30000) {
                s_diagLastDump.store(now, std::memory_order_relaxed);
                FILE* df = nullptr;
                _wfopen_s(&df, L"C:\\ProgramData\\GuardianShield\\logs\\etw_diag.txt", L"w");
                if (df) {
                    fprintf(df, "total=%llu dropped=%llu\n",
                            (unsigned long long)total,
                            (unsigned long long)s_diagDropped.load(std::memory_order_relaxed));
                    for (int i = 0; i < 64; i++) {
                        uint64_t c = s_diagCounts[i].load(std::memory_order_relaxed);
                        uint64_t d = s_diagDroppedById[i].load(std::memory_order_relaxed);
                        if (c > 0 || d > 0)
                            fprintf(df, "eventId=%d count=%llu dropped=%llu\n",
                                    i, (unsigned long long)c, (unsigned long long)d);
                    }
                    std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
                    fprintf(df, "cache_size=%zu\n", s_fileObjectCache.size());
                    fclose(df);
                }
            }
        }

        // Helper: extract path from NameCreate/NameDelete layout (FileObject(8) + FileName(wchar[]))
        auto extractNameEventPath = [&](wchar_t* dest, size_t destChars, uint64_t& outFo) -> bool {
            if (!ud || udLen <= sizeof(uint64_t)) return false;
            outFo = *reinterpret_cast<const uint64_t*>(ud);
            const wchar_t* namePtr = reinterpret_cast<const wchar_t*>(ud + sizeof(uint64_t));
            size_t nameChars = (udLen - sizeof(uint64_t)) / sizeof(wchar_t);
            if (nameChars > 0 && namePtr[0] != L'\0') {
                size_t cc = std::min(nameChars, destChars - 1);
                wcsncpy(dest, namePtr, cc);
                dest[cc] = L'\0';
                if (wcslen(dest) > 0) {
                    ConvertDevicePathToDos(dest, (DWORD)destChars);
                    if (outFo != 0) {
                        std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
                        s_fileObjectCache[outFo] = { dest, GetCurrentTimeMs() };
                        if (s_fileObjectCache.size() > FILE_OBJECT_CACHE_MAX)
                            EvictStaleCacheEntries();
                    }
                    return true;
                }
            }
            return false;
        };

        switch (eventId) {
            case 10: // NameCreate — cache-only, no security event
            {
                uint64_t fo = 0;
                wchar_t pathBuf[MAX_PATH_LENGTH] = {};
                extractNameEventPath(pathBuf, MAX_PATH_LENGTH, fo);
                return;
            }

            case 11: // NameDelete — NTFS namespace removal (metadata-level).
            {
                // EventId 11 fires for routine NTFS journal/MFT operations (PID 4 "System"),
                // but also for user-initiated deletions from cmd.exe (BUG-11 fix).
                // For system PIDs (<=4), only evict cache. For user PIDs, also
                // generate a FILE_DELETE event so cmd.exe deletions are not missed.
                uint64_t fo = 0;
                wchar_t pathBuf[MAX_PATH_LENGTH] = {};
                bool pathOk = extractNameEventPath(pathBuf, MAX_PATH_LENGTH, fo);
                if (fo != 0) {
                    std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
                    s_fileObjectCache.erase(fo);
                }
                if (driverEvent.process_id > 4 && pathOk && pathBuf[0] != L'\0') {
                    driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_DELETE);
                    wcsncpy(driverEvent.file_path, pathBuf, MAX_PATH_LENGTH - 1);
                    break; // proceed to path resolution, dedup, and QueueEvent
                }
                return;
            }

            case 12: // Create (IRP_MJ_CREATE)
            {
                driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_CREATE);

                // Layout: IrpPtr(8) + FileObject(8) + TTID(4) + CreateOptions(4) + CreateAttributes(4) + ShareAccess(4) + FileName(wchar[])
                uint64_t createFileObject = 0;
                if (ud && udLen >= 16) {
                    createFileObject = *reinterpret_cast<const uint64_t*>(ud + 8);
                }

                bool tdhOk = extractFileNameTDH(L"FileName", driverEvent.file_path, MAX_PATH_LENGTH);
                if (!tdhOk) {
                    if (ud && udLen > 32 + sizeof(wchar_t)) {
                        const wchar_t* p = reinterpret_cast<const wchar_t*>(ud + 32);
                        size_t chars = (udLen - 32) / sizeof(wchar_t);
                        if (chars > 0 && p[0] == L'\\') {
                            size_t cc = std::min(chars, (size_t)(MAX_PATH_LENGTH - 1));
                            wcsncpy(driverEvent.file_path, p, cc);
                            driverEvent.file_path[cc] = L'\0';
                        }
                    }
                }
                if (driverEvent.file_path[0] != L'\0') {
                    ConvertDevicePathToDos(driverEvent.file_path, MAX_PATH_LENGTH);

                    if (createFileObject != 0) {
                        std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
                        s_fileObjectCache[createFileObject] = { driverEvent.file_path, GetCurrentTimeMs() };
                        if (s_fileObjectCache.size() > FILE_OBJECT_CACHE_MAX)
                            EvictStaleCacheEntries();
                    }
                }
                break;
            }

            case 13: // FileCleanup — no security event
            case 15: // FileRead — no security event
                return;

            case 14: // FileClose — update cache, no security event
            {
                if (ud && udLen >= 16) {
                    uint64_t fo = *reinterpret_cast<const uint64_t*>(ud + 8);
                    if (fo != 0) {
                        std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
                        auto it = s_fileObjectCache.find(fo);
                        if (it != s_fileObjectCache.end())
                            it->second.lastAccessMs = GetCurrentTimeMs();
                    }
                }
                return;
            }

            case 16: // FileWrite — the actual write event
            {
                driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_WRITE);
                if (ud && udLen >= 24) {
                    fileObject = *reinterpret_cast<const uint64_t*>(ud + 8);
                    fileKey = *reinterpret_cast<const uint64_t*>(ud + 16);
                }

                // Extract I/O size via TDH for data_transfer_mb tracking
                {
                    PROPERTY_DATA_DESCRIPTOR ioDesc = {};
                    ioDesc.PropertyName = reinterpret_cast<ULONGLONG>(L"IoSize");
                    ioDesc.ArrayIndex = ULONG_MAX;
                    DWORD ioSz = 0;
                    ULONG ioSt = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &ioDesc, &ioSz);
                    if (ioSt == ERROR_SUCCESS && ioSz >= sizeof(ULONG)) {
                        ULONG val = 0;
                        if (TdhGetProperty(eventRecord, 0, nullptr, 1, &ioDesc,
                                           sizeof(val), reinterpret_cast<PBYTE>(&val)) == ERROR_SUCCESS) {
                            driverEvent.data_size = val;
                        }
                    } else if (ud && udLen >= 24) {
                        // Fallback: IoSize typically at offset 20 (after IrpPtr+FileObject+TTID)
                        driverEvent.data_size = *reinterpret_cast<const uint32_t*>(ud + 20);
                    }
                }

                extractFileNameTDH(L"FileName", driverEvent.file_path, MAX_PATH_LENGTH);
                if (driverEvent.file_path[0] != L'\0')
                    ConvertDevicePathToDos(driverEvent.file_path, MAX_PATH_LENGTH);
                break;
            }

            case 17: // DeletePath
            case 18: // SetDelete (some manifests use 18)
            {
                driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_DELETE);
                if (ud && udLen >= 24) {
                    fileObject = *reinterpret_cast<const uint64_t*>(ud + 8);
                    fileKey = *reinterpret_cast<const uint64_t*>(ud + 16);
                }
                extractFileNameTDH(L"FileName", driverEvent.file_path, MAX_PATH_LENGTH);
                if (driverEvent.file_path[0] != L'\0')
                    ConvertDevicePathToDos(driverEvent.file_path, MAX_PATH_LENGTH);
                break;
            }

            case 19: // RenamePath
            {
                driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_RENAME);
                if (ud && udLen >= 24) {
                    fileObject = *reinterpret_cast<const uint64_t*>(ud + 8);
                    fileKey = *reinterpret_cast<const uint64_t*>(ud + 16);
                }
                extractFileNameTDH(L"FileName", driverEvent.file_path, MAX_PATH_LENGTH);
                if (driverEvent.file_path[0] != L'\0')
                    ConvertDevicePathToDos(driverEvent.file_path, MAX_PATH_LENGTH);
                break;
            }

            case 23: // Close — update cache timestamp
            {
                if (ud && udLen >= 16) {
                    uint64_t fo = *reinterpret_cast<const uint64_t*>(ud + 8);
                    if (fo != 0) {
                        std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
                        auto it = s_fileObjectCache.find(fo);
                        if (it != s_fileObjectCache.end())
                            it->second.lastAccessMs = GetCurrentTimeMs();
                    }
                }
                return;
            }

            case 26: // Cleanup
                return;

            default:
                return;
        }

        // Resolve path from FileObject cache
        if (driverEvent.file_path[0] == L'\0' && fileObject != 0) {
            std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
            auto it = s_fileObjectCache.find(fileObject);
            if (it != s_fileObjectCache.end()) {
                wcsncpy(driverEvent.file_path, it->second.path.c_str(), MAX_PATH_LENGTH - 1);
                it->second.lastAccessMs = GetCurrentTimeMs();
            }
        }

        // Fallback: try FileKey as secondary lookup
        if (driverEvent.file_path[0] == L'\0' && fileKey != 0) {
            std::lock_guard<std::mutex> lock(s_fileObjectCacheMutex);
            for (auto& kv : s_fileObjectCache) {
                if (kv.first == fileKey) {
                    wcsncpy(driverEvent.file_path, kv.second.path.c_str(), MAX_PATH_LENGTH - 1);
                    kv.second.lastAccessMs = GetCurrentTimeMs();
                    break;
                }
            }
        }

        // Skip events with unresolved paths
        if (driverEvent.file_path[0] == L'\0') {
            s_diagDropped.fetch_add(1, std::memory_order_relaxed);
            if (eventId < 64) s_diagDroppedById[eventId].fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Filter directory-level events (path ends with \ or is just a drive root)
        {
            size_t pathLen = wcslen(driverEvent.file_path);
            if (pathLen > 0 && driverEvent.file_path[pathLen - 1] == L'\\') return;
            if (pathLen <= 3) return; // e.g., "C:\"
        }

        // Resolve process name with Session 0 fallbacks
        wchar_t procName[MAX_PATH] = {};
        if (driverEvent.process_id == 0) {
            wcscpy(procName, L"System Idle Process");
        } else if (driverEvent.process_id == 4) {
            wcscpy(procName, L"System");
        } else {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                       driverEvent.process_id);
            if (hProc) {
                DWORD sz = MAX_PATH;
                if (!QueryFullProcessImageNameW(hProc, 0, procName, &sz) || procName[0] == L'\0') {
                    // Fallback: GetProcessImageFileNameW returns NT device path
                    wchar_t ntPath[MAX_PATH] = {};
                    if (GetProcessImageFileNameW(hProc, ntPath, MAX_PATH) > 0) {
                        ConvertDevicePathToDos(ntPath, MAX_PATH);
                        wcscpy(procName, ntPath);
                    }
                }
                CloseHandle(hProc);
            }
        }
        wcsncpy(driverEvent.process_name, procName,
                 sizeof(driverEvent.process_name) / sizeof(wchar_t) - 1);

        // FIX-09: 精确匹配可执行文件名（旧代码用 find() 子串匹配全路径，
        //         导致 "tar" 匹配 "StartMenuExperienceHost" 等误报）
        std::wstring pn(procName);
        auto slashPos = pn.rfind(L'\\');
        std::wstring exeNameLower = (slashPos != std::wstring::npos) ? pn.substr(slashPos + 1) : pn;
        std::transform(exeNameLower.begin(), exeNameLower.end(), exeNameLower.begin(), ::towlower);

        static const wchar_t* kCompressExes[] = {
            L"7z.exe", L"7zfm.exe", L"7zg.exe",
            L"winrar.exe", L"rar.exe", L"unrar.exe",
            L"zip.exe", L"unzip.exe", L"tar.exe",
            L"peazip.exe", L"bandizip.exe",
        };
        for (const auto& ce : kCompressExes) {
            if (exeNameLower == ce) {
                driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_COMPRESS);
                break;
            }
        }

        static const wchar_t* kNetworkExes[] = {
            L"scp.exe", L"sftp.exe", L"pscp.exe",
            L"curl.exe", L"wget.exe", L"rclone.exe",
            L"onedrive.exe", L"dropbox.exe",
        };
        for (const auto& ne : kNetworkExes) {
            if (exeNameLower == ne) {
                driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_NETWORK_TRANSFER);
                break;
            }
        }

        // FILE_MOVE correlation: cross-volume move = CREATE at destination + DELETE at source.
        // Track FILE_CREATE events; when FILE_DELETE arrives with matching PID+filename,
        // reclassify the DELETE as FILE_MOVE.
        {
            DriverEventType curType = static_cast<DriverEventType>(driverEvent.event_type);
            if (curType == DriverEventType::FILE_CREATE || curType == DriverEventType::FILE_DELETE) {
                std::wstring fp(driverEvent.file_path);
                auto sep = fp.rfind(L'\\');
                std::wstring baseName = (sep != std::wstring::npos) ? fp.substr(sep + 1) : fp;
                std::transform(baseName.begin(), baseName.end(), baseName.begin(), ::towlower);

                uint64_t nowMs = GetCurrentTimeMs();
                std::lock_guard<std::mutex> mlock(s_moveCandidateMutex);

                // purge expired candidates
                s_moveCandidates.erase(
                    std::remove_if(s_moveCandidates.begin(), s_moveCandidates.end(),
                        [nowMs](const MoveCreateCandidate& c) {
                            return (nowMs - c.timestampMs) > MOVE_CORRELATION_WINDOW_MS;
                        }),
                    s_moveCandidates.end());

                if (curType == DriverEventType::FILE_DELETE) {
                    // Look for a matching CREATE from the same process
                    for (auto it = s_moveCandidates.begin(); it != s_moveCandidates.end(); ++it) {
                        if (it->processId == driverEvent.process_id &&
                            it->baseNameLower == baseName &&
                            _wcsicmp(it->fullPath.c_str(), fp.c_str()) != 0) {
                            driverEvent.event_type = static_cast<uint32_t>(DriverEventType::FILE_MOVE);
                            s_moveCandidates.erase(it);
                            break;
                        }
                    }
                } else {
                    // FILE_CREATE: store for future correlation
                    if (s_moveCandidates.size() < MOVE_CANDIDATES_MAX) {
                        s_moveCandidates.push_back({driverEvent.process_id, baseName, fp, nowMs});
                    }
                }
            }
        }

    } else if (isProcessEvent) {
        USHORT procEventId = eventRecord->EventHeader.EventDescriptor.Id;
        UCHAR procOpcode = eventRecord->EventHeader.EventDescriptor.Opcode;

        // Microsoft-Windows-Kernel-Process: EventId 1=Start, 2=Stop; also check Opcode
        if (procEventId == 1 || procOpcode == 1) {
            driverEvent.event_type =
                static_cast<uint32_t>(DriverEventType::PROCESS_CREATE);
        } else if (procEventId == 2 || procOpcode == 2) {
            driverEvent.event_type =
                static_cast<uint32_t>(DriverEventType::PROC_TERMINATE);
        } else {
            return;
        }

        // Extract process image name via TDH
        PROPERTY_DATA_DESCRIPTOR desc = {};
        desc.PropertyName = reinterpret_cast<ULONGLONG>(L"ImageName");
        desc.ArrayIndex = ULONG_MAX;
        DWORD propSize = 0;
        ULONG st = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &desc, &propSize);
        if (st == ERROR_SUCCESS && propSize > 0 && propSize < 65536) {
            std::vector<BYTE> buf(propSize);
            st = TdhGetProperty(eventRecord, 0, nullptr, 1, &desc, propSize, buf.data());
            if (st == ERROR_SUCCESS) {
                const wchar_t* imgName = reinterpret_cast<const wchar_t*>(buf.data());
                wcsncpy(driverEvent.process_name, imgName,
                         sizeof(driverEvent.process_name) / sizeof(wchar_t) - 1);
            }
        }

        // Use PID as the "path" for dedup differentiation
        swprintf(driverEvent.file_path, MAX_PATH_LENGTH, L"PID:%lu",
                 eventRecord->EventHeader.ProcessId);
    } else {
        return;
    }

    {
        size_t dedupKey = std::hash<std::wstring>{}(
            std::wstring(driverEvent.file_path)) ^
            (std::hash<uint32_t>{}(driverEvent.event_type) << 1) ^
            (std::hash<uint32_t>{}(driverEvent.process_id) << 2);
        std::lock_guard<std::mutex> lock(s_deduplicationMutex);
        uint64_t now = GetCurrentTimeMs();
        auto it = s_recentEvents.find(dedupKey);
        if (it != s_recentEvents.end() && (now - it->second) < DEDUP_WINDOW_MS) {
            return;
        }
        s_recentEvents[dedupKey] = now;
        if (s_recentEvents.size() > 2000) {
            int cleaned = 0;
            for (auto jt = s_recentEvents.begin(); jt != s_recentEvents.end() && cleaned < 500; ) {
                if (now - jt->second > DEDUP_WINDOW_MS * 2) {
                    jt = s_recentEvents.erase(jt);
                    ++cleaned;
                } else {
                    ++jt;
                }
            }
        }
    }

    inst->QueueEvent(driverEvent);
}

void GuardianA::DriverReadThread() {
    constexpr int RECONNECT_INTERVAL_MS = 10000;
    int reconnectTimer = 0;

    while (m_running) {
        if (!m_driverClient || !m_driverClient->IsConnected()) {
            reconnectTimer += 500;
            if (reconnectTimer >= RECONNECT_INTERVAL_MS) {
                reconnectTimer = 0;
                if (g_logger) g_logger->Info("DriverReadThread: attempting driver reconnect...");
                if (!m_driverClient) {
                    m_driverClient = std::make_unique<DriverClient>();
                }
                if (m_driverClient->Connect(GUARDFILTER_PORT_NAME)) {
                    if (g_logger) g_logger->Info("DriverReadThread: reconnected to GuardFilter");
                    LoadProtectedPaths();
                    SyncDriverWhitelist();
                    SendBlockPolicy();
                } else {
                    if (g_logger) g_logger->Warn("DriverReadThread: reconnect failed, will retry in %ds",
                        RECONNECT_INTERVAL_MS / 1000);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        DriverEvent event;
        if (m_driverClient->GetNextEvent(event, 500)) {
            QueueEvent(event);
        }
    }
}

void GuardianA::HeartbeatThread() {
    if (g_logger) g_logger->Info("HeartbeatThread started (tid=%u)", GetCurrentThreadId());
    uint64_t lastEventCount = 0;
    int etwStallTicks = 0;
    int totalTicks = 0;
    constexpr int kEtwStallThreshold = 120; // 120 * 500ms = 60 seconds

    while (m_running) {
        totalTicks++;
        SendHeartbeat();
        CheckHeartbeats();

        uint64_t current = m_eventsProcessed.load();
        if (current == lastEventCount) {
            etwStallTicks++;
            if (etwStallTicks >= kEtwStallThreshold && m_etwRunning) {
                if (g_logger) g_logger->Warn("ETW stall detected (%d sec idle), restarting session",
                                              etwStallTicks / 2);
                ShutdownEtw();
                InitializeEtw();
                etwStallTicks = 0;
            }
        } else {
            etwStallTicks = 0;
            lastEventCount = current;
        }

        if (totalTicks > 0 && (totalTicks % 120) == 0) {
            if (g_logger) g_logger->Info("HeartbeatThread alive: ticks=%d events=%llu stallTicks=%d",
                                          totalTicks, (unsigned long long)current, etwStallTicks);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void GuardianA::SendHeartbeat() {
    if (!m_ipcManager) return;
    HeartbeatPayload hb = {};
    hb.process_id = GetCurrentProcessId();
    hb.status = static_cast<uint8_t>(m_emergencyState.load());
    hb.nonce = m_sequence++;
    m_ipcManager->SendToNode(NodeId::GUARDIAN_C, MessageType::HEARTBEAT, &hb, sizeof(hb));
    m_ipcManager->SendToNode(NodeId::GUARDIAN_B, MessageType::HEARTBEAT, &hb, sizeof(hb));
    m_ipcManager->UpdateHeartbeat(hb);
    {
        std::lock_guard<std::mutex> lock(m_hbMutex);
        m_lastHeartbeat[0] = std::chrono::steady_clock::now();
    }
}

void GuardianA::CheckHeartbeats() {
    auto now = std::chrono::steady_clock::now();
    constexpr int HEARTBEAT_TIMEOUT_MS = 5000;
    constexpr int MAX_MISSED = 6;

    std::lock_guard<std::mutex> lock(m_hbMutex);
    for (int i = 1; i <= 2; i++) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_lastHeartbeat[i]).count();
        if (elapsed > HEARTBEAT_TIMEOUT_MS) {
            m_missedHeartbeats[i]++;
            if (m_missedHeartbeats[i] >= MAX_MISSED) {
                OnNodeTimeout(static_cast<NodeId>(i));
            }
        } else {
            m_missedHeartbeats[i] = 0;
        }
    }
}

void GuardianA::OnNodeTimeout(NodeId node) {
    std::string nodeName(NodeIdToString(node));
    std::wstring wNodeName(Utf8ToWide(nodeName));
    LogEvent(EVENTLOG_WARNING_TYPE, L"Node timeout: " + wNodeName);

    if (node == NodeId::GUARDIAN_C) {
        // Check if GuardianC IPC pipe already exists (another instance is running)
        HANDLE hProbe = CreateFileW(L"\\\\.\\pipe\\GuardianIPC_C",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hProbe != INVALID_HANDLE_VALUE) {
            CloseHandle(hProbe);
            if (g_logger) g_logger->Info("GuardianIPC_C pipe exists, skip winmon restart");
            return;
        }

        wchar_t modulePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
        std::wstring installDir(modulePath);
        auto lastSlash = installDir.rfind(L'\\');
        if (lastSlash != std::wstring::npos) {
            installDir = installDir.substr(0, lastSlash + 1);
        }
        std::wstring winmonPath = installDir + L"winmon.exe";

        if (GetFileAttributesW(winmonPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            if (g_logger) g_logger->Warn("winmon.exe not found at %s", WideToUtf8(winmonPath).c_str());
            return;
        }

        std::wstring cmdLine = L"\"" + winmonPath + L"\" --silent";

        // Spawn winmon in the active user session so it has desktop access
        DWORD sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId != 0 && sessionId != 0xFFFFFFFF) {
            HANDLE hToken = nullptr;
            if (WTSQueryUserToken(sessionId, &hToken)) {
                LPVOID pEnv = nullptr;
                CreateEnvironmentBlock(&pEnv, hToken, FALSE);

                STARTUPINFOW si = { sizeof(si) };
                si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
                PROCESS_INFORMATION pi = {};

                BOOL ok = CreateProcessAsUserW(hToken, nullptr, &cmdLine[0],
                    nullptr, nullptr, FALSE,
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    pEnv, nullptr, &si, &pi);

                if (ok) {
                    if (g_logger) g_logger->Info(
                        "Restarted GuardianC in user session %lu, PID=%lu",
                        sessionId, pi.dwProcessId);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    if (g_logger) g_logger->Warn(
                        "CreateProcessAsUserW failed for winmon (err=%lu), falling back",
                        GetLastError());
                }

                if (pEnv) DestroyEnvironmentBlock(pEnv);
                CloseHandle(hToken);

                if (ok) return;
            } else {
                if (g_logger) g_logger->Warn(
                    "WTSQueryUserToken(session=%lu) failed (err=%lu)",
                    sessionId, GetLastError());
            }
        } else {
            if (g_logger) g_logger->Info(
                "No active user session (id=%lu), skip winmon restart",
                sessionId);
            return;
        }

        // Fallback: CreateProcessW (may land in Session 0 — last resort)
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        if (CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            if (g_logger) g_logger->Warn(
                "Restarted GuardianC via CreateProcessW fallback (Session 0), PID=%lu",
                pi.dwProcessId);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            if (g_logger) g_logger->Warn("Failed to restart GuardianC (err=%lu)", GetLastError());
        }
    }
}

void GuardianA::EventProcessingThread() {
    while (m_running) {
        std::unique_lock<std::mutex> lock(m_eventMutex);
        m_eventCV.wait_for(lock, std::chrono::milliseconds(100), 
            [this] { return !m_eventQueue.empty() || !m_running; });
        
        while (!m_eventQueue.empty() && m_running) {
            DriverEvent event = m_eventQueue.front();
            m_eventQueue.pop();
            lock.unlock();
            
            if (m_ipcManager) {
                m_ipcManager->SendToNode(
                    NodeId::GUARDIAN_B, MessageType::DRIVER_EVENT,
                    &event, sizeof(event));
            }
            HandleDriverEvent(event);
            m_eventsProcessed++;
            
            lock.lock();
        }
    }
}

void GuardianA::HandleDriverEvent(const DriverEvent& event) {
    // FIX-08: 协议执行期间暂停事件处理，防止级联
    if (m_protocolActive) return;

    // FIX-07: 排除自身进程的操作
    static DWORD s_selfPid = GetCurrentProcessId();
    if (event.process_id == s_selfPid) return;

    // System/System Idle Process file operations are NTFS internal (journal, MFT)
    if (event.process_id <= 4) return;

    if (event.event_type >= static_cast<uint32_t>(DriverEventType::MAX_TYPE)) return;

    DriverEventType evType = static_cast<DriverEventType>(event.event_type);
    bool isProcessEvent = (evType == DriverEventType::PROCESS_CREATE ||
                           evType == DriverEventType::PROC_TERMINATE);

    if (!isProcessEvent && !IsInProtectedPath(event.file_path)) return;

    std::wstring filePath(event.file_path);
    if (!isProcessEvent && filePath.empty()) return;

    if (!isProcessEvent) {
        // Filter directory-level events (path equals a protected directory itself)
        for (const auto& protPath : m_protectedPaths) {
            if (filePath == protPath || filePath == protPath + L"\\") return;
        }

        // File type filter
        if (m_config && !m_config->IsFileTypeMonitored(filePath)) return;

        // Skip OS metadata files that are never user data
        {
            auto lastSep = filePath.rfind(L'\\');
            std::wstring baseName = (lastSep != std::wstring::npos)
                ? filePath.substr(lastSep + 1) : filePath;
            if (_wcsicmp(baseName.c_str(), L"desktop.ini") == 0 ||
                _wcsicmp(baseName.c_str(), L"Thumbs.db") == 0) {
                return;
            }
        }

        // System-level whitelist: OS background processes whose file I/O is noise
        {
            std::wstring pn(event.process_name);
            auto pos = pn.rfind(L'\\');
            std::wstring exeName = (pos != std::wstring::npos) ? pn.substr(pos + 1) : pn;
            static const wchar_t* kSystemWhitelist[] = {
                L"SearchProtocolHost.exe",
                L"SearchIndexer.exe",
                L"SearchFilterHost.exe",
                L"TrustedInstaller.exe",
                L"TiWorker.exe",
                L"MsMpEng.exe",
                L"svchost_core.exe",
                L"svchost_helper.exe",
            };
            for (const auto& sys : kSystemWhitelist) {
                if (_wcsicmp(exeName.c_str(), sys) == 0) return;
            }
        }

        // User-configurable whitelist
        if (m_config) {
            std::wstring pn(event.process_name);
            std::wstring fullProcessPath = pn;
            auto pos = pn.rfind(L'\\');
            std::wstring exeName = (pos != std::wstring::npos) ? pn.substr(pos + 1) : pn;

            // UWP fallback: if the extracted name has no .exe suffix (UWP package dir),
            // query the real image name from the PID.
            if (exeName.size() > 0 && exeName.find(L".exe") == std::wstring::npos &&
                event.process_id > 4) {
                HANDLE hTmp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                          event.process_id);
                if (hTmp) {
                    wchar_t imgBuf[MAX_PATH] = {};
                    DWORD imgSz = MAX_PATH;
                    if (QueryFullProcessImageNameW(hTmp, 0, imgBuf, &imgSz) && imgBuf[0]) {
                        std::wstring imgPath(imgBuf);
                        fullProcessPath = imgPath;
                        auto ls = imgPath.rfind(L'\\');
                        if (ls != std::wstring::npos)
                            exeName = imgPath.substr(ls + 1);
                    }
                    CloseHandle(hTmp);
                }
            }

            std::wstring requiredPerm = L"WRITE";

            if (m_config->IsProcessWhitelisted(exeName, requiredPerm, fullProcessPath)) return;
        }
    }

    // Single-event threat assessment (always runs, always logged)
    ThreatAssessment assessment = AssessThreat(event);

    // Two-tier batch threshold check — file events only.
    // Process events (PROCESS_CREATE/PROC_TERMINATE) are system-wide ETW events
    // and must NOT participate in file-protection batch thresholds.
    BatchThreatTier batchTier = BatchThreatTier::NONE;
    if (m_threatEvaluator && !isProcessEvent) {
        batchTier = m_threatEvaluator->CheckBatchThresholds(event);
        if (batchTier == BatchThreatTier::TIER_2) {
            assessment.level = ThreatLevel::LEVEL_3;
            assessment.action = static_cast<ResponseAction>(
                static_cast<uint8_t>(ResponseAction::LOG) |
                static_cast<uint8_t>(ResponseAction::ALERT_USER));
            assessment.description = "\xe7\xb4\xa7\xe6\x80\xa5\xef\xbc\x9a\xe6\xa3\x80\xe6\xb5\x8b\xe5\x88\xb0\xe5\xa4\xa7\xe8\xa7\x84\xe6\xa8\xa1\xe6\x93\x8d\xe4\xbd\x9c";
        } else if (batchTier == BatchThreatTier::TIER_1) {
            if (assessment.level < ThreatLevel::LEVEL_2)
                assessment.level = ThreatLevel::LEVEL_2;
            assessment.action = static_cast<ResponseAction>(
                static_cast<uint8_t>(assessment.action) |
                static_cast<uint8_t>(ResponseAction::ALERT_USER));
            assessment.description = "\xe8\xad\xa6\xe5\x91\x8a\xef\xbc\x9a\xe6\xa3\x80\xe6\xb5\x8b\xe5\x88\xb0\xe6\x89\xb9\xe9\x87\x8f\xe6\x93\x8d\xe4\xbd\x9c";
        }
    }

    if (g_logger) {
        std::wstring processName(event.process_name);
        g_logger->LogEvent(
            DriverEventTypeToString(static_cast<DriverEventType>(event.event_type)),
            ThreatLevelToString(assessment.level),
            ResponseActionCombinedToString(assessment.action),
            filePath, processName, event.process_id,
            assessment.description);
    }

    if (assessment.level != ThreatLevel::LEVEL_0) {
        m_threatsDetected++;
        ExecuteResponse(assessment, event);
    }

    if (batchTier == BatchThreatTier::TIER_2) {
        // Targeted termination: only kill the process that contributed the most events
        if (m_threatEvaluator) {
            uint32_t targetPid = m_threatEvaluator->GetTopContributorPid();
            if (targetPid > 4) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                           FALSE, targetPid);
                if (hProc) {
                    wchar_t imgName[MAX_PATH] = {};
                    DWORD sz = MAX_PATH;
                    QueryFullProcessImageNameW(hProc, 0, imgName, &sz);
                    std::wstring procLower(imgName);
                    std::transform(procLower.begin(), procLower.end(), procLower.begin(), ::towlower);
                    auto ls = procLower.rfind(L'\\');
                    std::wstring fn = (ls != std::wstring::npos) ? procLower.substr(ls + 1) : procLower;
                    static const std::wstring safe[] = {
                        L"explorer.exe", L"dwm.exe", L"csrss.exe", L"lsass.exe",
                        L"svchost.exe", L"winlogon.exe", L"services.exe",
                        L"svchost_core.exe", L"svchost_helper.exe", L"winmon.exe",
                    };
                    bool isSafe = false;
                    for (const auto& s : safe) { if (fn == s) { isSafe = true; break; } }
                    if (!isSafe) {
                        LogEvent(EVENTLOG_WARNING_TYPE, L"Targeted termination of top-contributor process");
                        if (!TerminateProcess(hProc, 1)) {
                            if (g_logger) g_logger->Warn("Targeted TerminateProcess failed for PID %u (err=%lu)",
                                targetPid, GetLastError());
                        } else {
                            WaitForSingleObject(hProc, 3000);
                        }
                    }
                    CloseHandle(hProc);
                }
            }
        }
        TriggerEmergencyProtocol();
    } else if (batchTier == BatchThreatTier::TIER_1) {
        TriggerProtectionProtocol();
    }
}

static bool SecureCompare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
    }
    return result == 0;
}

void GuardianA::HandleGuardianMessage(const MessageHeader& header, 
                                       const uint8_t* payload, 
                                       size_t payloadSize) {
    MessageType type = static_cast<MessageType>(header.type);

    switch (type) {
        case MessageType::HEARTBEAT:
            if (payloadSize >= sizeof(HeartbeatPayload)) {
                NodeId source = static_cast<NodeId>(header.source);
                int idx = static_cast<int>(source);
                if (idx >= 1 && idx <= 2) {
                    std::lock_guard<std::mutex> hbLock(m_hbMutex);
                    m_lastHeartbeat[idx] = std::chrono::steady_clock::now();
                    m_missedHeartbeats[idx] = 0;
                }
            }
            break;

        case MessageType::UNLOCK_RESPONSE:
            if (m_emergencyState == EmergencyState::LOCKED) {
                LogEvent(EVENTLOG_INFORMATION_TYPE,
                         L"System unlocked by administrator via lock screen");
                CancelEmergency();
            }
            break;

        case MessageType::DECRYPT_REQUEST:
        {
            if (payloadSize < sizeof(DecryptRequestPayload)) break;
            auto* req = reinterpret_cast<const DecryptRequestPayload*>(payload);

            DecryptResponsePayload resp = {};
            NodeId requester = static_cast<NodeId>(header.source);

            if (m_emergencyState != EmergencyState::LOCKED &&
                m_emergencyState != EmergencyState::NORMAL) {
                resp.success = 0;
                wcscpy_s(resp.error_message, L"\x5F53\x524D\x72B6\x6001\x4E0D\x5141\x8BB8\x89E3\x5BC6\x64CD\x4F5C");
                if (m_ipcManager)
                    m_ipcManager->SendToNode(requester, MessageType::DECRYPT_RESPONSE,
                        &resp, sizeof(resp));
                break;
            }

            if (m_decryptInProgress.exchange(true)) {
                resp.success = 2;
                wcscpy_s(resp.error_message, L"\x89E3\x5BC6\x64CD\x4F5C\x6B63\x5728\x8FDB\x884C\x4E2D");
                if (m_ipcManager)
                    m_ipcManager->SendToNode(requester, MessageType::DECRYPT_RESPONSE,
                        &resp, sizeof(resp));
                break;
            }

            std::string inputHash(req->password_hash);
            std::string adminHash = m_config ? m_config->GetAdminPasswordHash() : "";
            if (adminHash.empty() || !SecureCompare(inputHash, adminHash)) {
                resp.success = 0;
                wcscpy_s(resp.error_message, L"\x5BC6\x7801\x9A8C\x8BC1\x5931\x8D25");
                m_decryptInProgress = false;
                if (m_ipcManager)
                    m_ipcManager->SendToNode(requester, MessageType::DECRYPT_RESPONSE,
                        &resp, sizeof(resp));
                break;
            }

            if (m_decryptThread.joinable()) {
                m_decryptThread.join();
            }

            m_decryptThread = std::thread([this, adminHash, requester]() {
                struct ProtocolGuard {
                    std::atomic<bool>& flag;
                    ProtocolGuard(std::atomic<bool>& f) : flag(f) { flag = true; }
                    ~ProtocolGuard() { flag = false; }
                } guard(m_protocolActive);

                DecryptResponsePayload resp = {};

                if (m_ipcManager) {
                    m_ipcManager->Broadcast(MessageType::UNLOCK_RESPONSE, nullptr, 0);
                }

                std::this_thread::sleep_for(std::chrono::seconds(1));

                if (m_fileEncryptor && m_config) {
                    auto dirs = m_config->GetProtectedDirectories();
                    for (const auto& dir : dirs) {
                        resp.decrypted_count += static_cast<uint32_t>(
                            m_fileEncryptor->DecryptDirectory(
                                dir.path, adminHash, dir.recursive));
                    }
                }

                if (m_emergencyState != EmergencyState::NORMAL) {
                    CancelEmergency();
                }

                resp.success = 1;
                if (resp.decrypted_count == 0) {
                    wcscpy_s(resp.error_message,
                        L"\x6CA1\x6709\x627E\x5230\x9700\x8981\x89E3\x9501\x7684\x6587\x4EF6");
                } else {
                    swprintf_s(resp.error_message,
                        L"\x89E3\x5BC6 %u \x4E2A\x6587\x4EF6",
                        resp.decrypted_count);
                }

                if (m_ipcManager) {
                    m_ipcManager->SendToNode(requester, MessageType::DECRYPT_RESPONSE,
                        &resp, sizeof(resp));
                }

                m_decryptInProgress = false;
            });

            break;
        }

        default:
            break;
    }
}

void GuardianA::QueueEvent(const DriverEvent& event) {
    std::lock_guard<std::mutex> lock(m_eventMutex);
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    if (m_eventQueue.size() >= MAX_QUEUE_SIZE) {
        m_eventQueue.pop();
        static std::atomic<uint64_t> s_dropCount{0};
        if (++s_dropCount % 1000 == 1) {
            LogEvent(EVENTLOG_WARNING_TYPE,
                     L"Event queue overflow: dropping oldest events");
        }
    }
    m_eventQueue.push(event);
    m_eventCV.notify_one();
}

ThreatAssessment GuardianA::AssessThreat(const DriverEvent& event) {
    auto se = BuildEventResponse(*m_config,
        static_cast<DriverEventType>(event.event_type));
    ThreatAssessment assessment;
    assessment.level = se.level;
    assessment.action = se.action;
    assessment.confidence = se.confidence;
    assessment.description = se.description;
    return assessment;
}

void GuardianA::ExecuteResponse(const ThreatAssessment& assessment, 
                                 const DriverEvent& event) {
    uint8_t act = static_cast<uint8_t>(assessment.action);

    // NOTE: event already logged by HandleDriverEvent via g_logger->LogEvent.
    // LOG action only writes to Windows Event Log (no duplicate file log).
    if (act & static_cast<uint8_t>(ResponseAction::LOG)) {
        LogEvent(EVENTLOG_WARNING_TYPE,
                 Utf8ToWide(assessment.description).c_str());
    }
    
    if (act & static_cast<uint8_t>(ResponseAction::ALERT_USER)) {
        // Send IPC alert to GuardianC without duplicate file logging
        if (m_ipcManager) {
            AlertNotification notif = {};
            notif.level = static_cast<uint8_t>(assessment.level);
            notif.process_id = event.process_id;
            strncpy(notif.message, assessment.description.c_str(), sizeof(notif.message) - 1);
            wcsncpy(notif.file_path, event.file_path,
                     sizeof(notif.file_path) / sizeof(wchar_t) - 1);
            bool sent = m_ipcManager->SendToNode(NodeId::GUARDIAN_C,
                                     MessageType::ALERT_NOTIFICATION,
                                     &notif, sizeof(notif));
            if (g_logger) {
                if (sent)
                    g_logger->Info("ALERT_NOTIFICATION sent to GuardianC for PID %u",
                                   event.process_id);
                else
                    g_logger->Warn("ALERT_NOTIFICATION FAILED to GuardianC for PID %u",
                                   event.process_id);
            }
        }
    }

    if (act & static_cast<uint8_t>(ResponseAction::BLOCK)) {
        if (m_driverClient && m_driverClient->IsConnected()) {
            if (g_logger) g_logger->Info("BLOCK: operation already denied by driver for PID %u", event.process_id);
        } else {
            if (g_logger) g_logger->Warn("BLOCK: driver not connected, BLOCK skipped for PID %u (no degradation to TERMINATE)", event.process_id);
        }
    }
    
    if (act & static_cast<uint8_t>(ResponseAction::TERMINATE)) {
        if (event.process_id > 4) {
            std::wstring procName(event.process_name);
            std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
            auto lastSlash = procName.rfind(L'\\');
            std::wstring fileName = (lastSlash != std::wstring::npos)
                ? procName.substr(lastSlash + 1) : procName;
            static const std::wstring protectedProcs[] = {
                L"system", L"csrss.exe", L"smss.exe", L"wininit.exe",
                L"services.exe", L"lsass.exe", L"svchost.exe", L"winlogon.exe",
                L"explorer.exe", L"dwm.exe", L"sihost.exe", L"fontdrvhost.exe",
                L"runtimebroker.exe", L"shellexperiencehost.exe",
                L"startmenuexperiencehost.exe", L"searchhost.exe",
                L"taskhostw.exe", L"ctfmon.exe",
                L"svchost_core.exe", L"svchost_helper.exe", L"winmon.exe",
            };
            bool isProtected = false;
            for (const auto& pp : protectedProcs) {
                if (fileName == pp) { isProtected = true; break; }
            }
            if (!isProtected) {
                LogEvent(EVENTLOG_WARNING_TYPE, L"Terminating suspicious process");
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, event.process_id);
                if (hProc) {
                    if (!TerminateProcess(hProc, 1)) {
                        if (g_logger) g_logger->Warn("TerminateProcess failed for PID %u (err=%lu)",
                            event.process_id, GetLastError());
                    } else {
                        WaitForSingleObject(hProc, 3000);
                    }
                    CloseHandle(hProc);
                } else {
                    if (g_logger) g_logger->Warn("OpenProcess(TERMINATE) failed for PID %u (err=%lu)",
                        event.process_id, GetLastError());
                }
            } else {
                LogEvent(EVENTLOG_WARNING_TYPE, L"Skipped termination of protected system process");
            }
        }
    }
    
    if (act & static_cast<uint8_t>(ResponseAction::ENCRYPT)) {
        if (event.file_path[0] != L'\0') {
            std::wstring fp(event.file_path);
            if (fp.size() <= 3 || fp.substr(fp.size() - 3) != L".gs") {
                if (m_emergencyState == EmergencyState::NORMAL) {
                    std::string pwd = m_config ? m_config->GetAdminPasswordHash() : "";
                    if (!pwd.empty() && m_fileEncryptor) {
                        auto result = m_fileEncryptor->EncryptFile(fp, pwd);
                        if (g_logger) {
                            if (result.success)
                                g_logger->Info("Single-file encrypted: %s",
                                    WideToUtf8(fp).c_str());
                            else
                                g_logger->Warn("Single-file encrypt failed: %s - %s",
                                    WideToUtf8(fp).c_str(),
                                    result.error_message.c_str());
                        }
                    }
                }
            }
        }
    }
}

void GuardianA::TriggerProtectionProtocol() {
    int currentLevel = m_emergencyLevel.load();
    if (currentLevel >= 1) return;
    int expected = 0;
    if (!m_emergencyLevel.compare_exchange_strong(expected, 1)) return;
    m_emergencyMode = true;
    m_cancelRequested = false;
    EmergencyStateMachine stateMachine;
    if (stateMachine.TryTransition(EmergencyState::ALERT)) {
        SetEmergencyState(EmergencyState::ALERT);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Protection protocol (Tier 1) triggered");
    SendAlert(ThreatLevel::LEVEL_2, "\xe4\xbf\x9d\xe6\x8a\xa4\xe5\x8d\x8f\xe8\xae\xae\xe5\xb7\xb2\xe8\xa7\xa6\xe5\x8f\x91 - \xe6\x96\x87\xe4\xbb\xb6\xe5\xb0\x86\xe8\xa2\xab\xe5\x8a\xa0\xe5\xaf\x86\xe5\xb9\xb6\xe9\x94\x81\xe5\xae\x9a", nullptr);

    if (m_protocolThread.joinable()) m_protocolThread.join();
    m_protocolActive = true;
    try {
        m_protocolThread = std::thread([this]() {
            StartProtectionCountdown();
        });
    } catch (const std::exception& e) {
        if (g_logger) g_logger->Error("Failed to create protection thread: %s", e.what());
        m_protocolActive = false;
        m_emergencyLevel = 0;
        m_emergencyMode = false;
        SetEmergencyState(EmergencyState::NORMAL);
    }
}

void GuardianA::StartProtectionCountdown() {
    EmergencyStateMachine stateMachine;
    (void)stateMachine.TryTransition(EmergencyState::ALERT);

    uint32_t alertSeconds = m_config ? m_config->GetAlertTimeoutSeconds() : 30;
    if (g_logger) g_logger->Warn("ALERT countdown started: %u seconds (level=%d)",
                                  alertSeconds, m_emergencyLevel.load());
    for (uint32_t i = 0; i < alertSeconds; ++i) {
        if (!m_emergencyMode || m_cancelRequested) {
            LogEvent(EVENTLOG_INFORMATION_TYPE, L"Protection protocol cancelled");
            if (g_logger) g_logger->Info("ALERT countdown cancelled at %u/%u seconds", i, alertSeconds);
            if (stateMachine.Cancel()) {
                SetEmergencyState(EmergencyState::NORMAL);
            }
            if (m_ipcManager) {
                EmergencyState normalState = EmergencyState::NORMAL;
                m_ipcManager->Broadcast(MessageType::STATE_SYNC,
                    &normalState, sizeof(normalState));
            }
            m_emergencyLevel = 0;
            m_emergencyMode = false;
            m_protocolActive = false;
            return;
        }
        if (i == 0 || i % 10 == 0) {
            if (g_logger) g_logger->Warn("ALERT countdown: %u/%u seconds (level=%d)",
                                          i, alertSeconds, m_emergencyLevel.load());
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (stateMachine.TryTransition(EmergencyState::ENCRYPTING)) {
        SetEmergencyState(EmergencyState::ENCRYPTING);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Protection: encrypting protected files");
    EncryptProtectedFiles();

    if (stateMachine.TryTransition(EmergencyState::LOCKED)) {
        SetEmergencyState(EmergencyState::LOCKED);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Protection: locking all protected files");
    LockdownSystem();

    m_protocolActive = false;
}

void GuardianA::TriggerEmergencyProtocol(bool skipAlert) {
    int currentLevel = m_emergencyLevel.load();
    if (currentLevel >= 2) return;
    // Tier-2 can override Tier-1: cancel running Tier-1 first
    if (currentLevel == 1) {
        m_cancelRequested = true;
        if (m_protocolThread.joinable()) m_protocolThread.join();
        m_cancelRequested = false;
    }
    m_emergencyLevel = 2;
    m_emergencyMode = true;
    EmergencyStateMachine stateMachine;
    if (stateMachine.TryTransition(EmergencyState::ALERT)) {
        SetEmergencyState(EmergencyState::ALERT);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Emergency protocol (Tier 2) triggered - IRRECOVERABLE");

    if (!skipAlert) {
        SendAlert(ThreatLevel::LEVEL_3,
                  "\xe7\xb4\xa7\xe6\x80\xa5\xe5\x8d\x8f\xe8\xae\xae\xe5\xb7\xb2\xe8\xa7\xa6\xe5\x8f\x91 - \xe6\x96\x87\xe4\xbb\xb6\xe5\xb0\x86\xe8\xa2\xab\xe5\x8a\xa0\xe5\xaf\x86\xe3\x80\x81\xe6\x93\xa6\xe9\x99\xa4\xe5\xb9\xb6\xe5\x88\xa0\xe9\x99\xa4", nullptr);
    }

    if (m_protocolThread.joinable()) m_protocolThread.join();
    m_protocolActive = true;
    try {
        m_protocolThread = std::thread([this, skipAlert]() {
            StartEmergencyCountdown(skipAlert);
        });
    } catch (const std::exception& e) {
        if (g_logger) g_logger->Error("Failed to create emergency thread: %s", e.what());
        m_protocolActive = false;
        m_emergencyLevel = 0;
        m_emergencyMode = false;
        SetEmergencyState(EmergencyState::NORMAL);
    }
}

void GuardianA::StartEmergencyCountdown(bool skipAlert) {
    EmergencyStateMachine stateMachine;
    (void)stateMachine.TryTransition(EmergencyState::ALERT);

    if (!skipAlert) {
        uint32_t alertSeconds = m_config ? m_config->GetAlertTimeoutSeconds() : 30;
        if (g_logger) g_logger->Warn("EMERGENCY countdown started: %u seconds (level=%d)",
                                      alertSeconds, m_emergencyLevel.load());
        for (uint32_t i = 0; i < alertSeconds; ++i) {
            if (!m_emergencyMode || m_cancelRequested) {
                LogEvent(EVENTLOG_INFORMATION_TYPE, L"Emergency protocol cancelled by admin");
                if (g_logger) g_logger->Info("EMERGENCY countdown cancelled at %u/%u seconds", i, alertSeconds);
                if (stateMachine.Cancel()) {
                    SetEmergencyState(EmergencyState::NORMAL);
                }
                m_emergencyLevel = 0;
                m_emergencyMode = false;
                m_protocolActive = false;
                return;
            }
            if (i == 0 || i % 10 == 0) {
                if (g_logger) g_logger->Warn("EMERGENCY countdown: %u/%u seconds (level=%d)",
                                              i, alertSeconds, m_emergencyLevel.load());
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    if (stateMachine.TryTransition(EmergencyState::ENCRYPTING)) {
        SetEmergencyState(EmergencyState::ENCRYPTING);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Emergency: encrypting protected files");
    EncryptProtectedFiles(false);

    if (stateMachine.TryTransition(EmergencyState::WIPING)) {
        SetEmergencyState(EmergencyState::WIPING);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Emergency: secure wiping originals (DOD 5220.22-M)");
    WipeProtectedFiles();

    if (stateMachine.TryTransition(EmergencyState::DELETING)) {
        SetEmergencyState(EmergencyState::DELETING);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Emergency: cleaning system traces");
    CleanSystemTraces();

    if (stateMachine.TryTransition(EmergencyState::LOCKED)) {
        SetEmergencyState(EmergencyState::LOCKED);
    }
    LogEvent(EVENTLOG_WARNING_TYPE, L"Emergency: system locked");
    LockdownSystem();

    m_protocolActive = false;
}

void GuardianA::CancelEmergency() {
    m_cancelRequested = true;
    m_emergencyMode = false;
    m_emergencyLevel = 0;
    SetEmergencyState(EmergencyState::NORMAL);
    if (m_ipcManager) {
        EmergencyState normalState = EmergencyState::NORMAL;
        m_ipcManager->Broadcast(MessageType::STATE_SYNC,
            &normalState, sizeof(normalState));
    }
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"Emergency protocol cancelled");
}

void GuardianA::EncryptProtectedFiles(bool deleteSource) {
    if (!m_fileEncryptor) return;

    std::string password = m_config->GetAdminPasswordHash();
    if (password.empty()) {
        LogEvent(EVENTLOG_ERROR_TYPE, L"Cannot encrypt: no admin password configured");
        return;
    }

    auto protectedDirs = m_config->GetProtectedDirectories();
    for (const auto& dir : protectedDirs) {
        if (m_cancelRequested) break;

        LogEvent(EVENTLOG_INFORMATION_TYPE, (L"Encrypting files in: " + dir.path).c_str());

        auto progressCb = [this](size_t current, size_t total, const std::wstring& fp) {
            if (g_logger) {
                std::string p(WideToUtf8(fp));
                g_logger->Info("Encrypting [%zu/%zu]: %s", current, total, p.c_str());
            }
        };

        auto cancelCb = [this]() -> bool { return m_cancelRequested.load(); };
        size_t count = m_fileEncryptor->EncryptDirectory(
            dir.path, password, dir.recursive, progressCb, deleteSource, cancelCb);

        LogEvent(EVENTLOG_INFORMATION_TYPE,
            (L"Encrypted " + std::to_wstring(count) + L" files in: " + dir.path).c_str());
    }
}

void GuardianA::WipeProtectedFiles() {
    if (!m_fileWiper) return;

    auto protectedDirs = m_config->GetProtectedDirectories();
    for (const auto& dir : protectedDirs) {
        LogEvent(EVENTLOG_INFORMATION_TYPE, (L"Secure wiping files in: " + dir.path).c_str());

        auto progressCb = [this](size_t pass, size_t total, size_t bytes) {
            if (g_logger) {
                g_logger->Info("Wipe pass %zu/%zu, %zu bytes processed", pass, total, bytes);
            }
        };

        size_t count = m_fileWiper->WipeDirectory(dir.path, dir.recursive, progressCb, L".gs");

        LogEvent(EVENTLOG_INFORMATION_TYPE,
            (L"Wiped " + std::to_wstring(count) + L" files in: " + dir.path).c_str());
    }
}

void GuardianA::CleanSystemTraces() {
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"Cleaning system traces");

    // 1. Clear clipboard
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
    }

    // 2. Clear recent documents list
    SHAddToRecentDocs(SHARD_PATHA, nullptr);

    // 3. Clean GuardianShield temp files (recursive)
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        std::wstring gsTemp = std::wstring(tempPath) + L"GuardianShield";
        std::function<void(const std::wstring&)> cleanDir =
            [&](const std::wstring& dir) {
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &fd);
            if (hFind == INVALID_HANDLE_VALUE) return;
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                    continue;
                std::wstring fullPath = dir + L"\\" + fd.cFileName;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    cleanDir(fullPath);
                    RemoveDirectoryW(fullPath.c_str());
                } else {
                    DeleteFileW(fullPath.c_str());
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        };
        cleanDir(gsTemp);
        RemoveDirectoryW(gsTemp.c_str());
    }

    LogEvent(EVENTLOG_INFORMATION_TYPE, L"System traces cleaned");
}

void GuardianA::LockdownSystem() {
    LogEvent(EVENTLOG_WARNING_TYPE, L"System lockdown initiated");

    if (m_ipcManager) {
        m_ipcManager->SendToNode(NodeId::GUARDIAN_C,
                                 MessageType::EMERGENCY_TRIGGER, nullptr, 0);
    }

    constexpr int LOCKDOWN_TIMEOUT_SECONDS = 3600;
    int elapsed = 0;
    while (m_running && m_emergencyState == EmergencyState::LOCKED) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        elapsed += 2;
        if (elapsed >= LOCKDOWN_TIMEOUT_SECONDS) {
            if (g_logger) g_logger->Warn("Lockdown timeout after %d seconds, releasing protocolActive", elapsed);
            LogEvent(EVENTLOG_WARNING_TYPE, L"Lockdown timed out — resuming event processing");
            m_protocolActive = false;
            break;
        }
    }

    LogEvent(EVENTLOG_INFORMATION_TYPE, L"Lockdown procedure completed");
}

bool GuardianA::OpenDriverHandle(const std::wstring& deviceName) {
    HANDLE h = CreateFileW(deviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (g_logger) {
            std::string dn(WideToUtf8(deviceName));
            g_logger->Warn("OpenDriverHandle failed for %s: error %lu", dn.c_str(), GetLastError());
        }
        return false;
    }
    if (deviceName.find(L"GuardFilter") != std::wstring::npos) {
        m_hFilterDriver = h;
    } else {
        m_hMonitorDriver = h;
    }
    return true;
}

bool GuardianA::ReadDriverEvent(DriverEvent& event) {
    if (m_driverClient && m_driverClient->IsConnected()) {
        return m_driverClient->GetNextEvent(event, 100);
    }
    return false;
}

bool GuardianA::SendDriverCommand(uint32_t ioctlCode, const void* input, size_t inputSize,
                                   void* output, size_t outputSize) {
    HANDLE h = m_hFilterDriver;
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD bytesReturned = 0;
    return DeviceIoControl(h, ioctlCode,
        const_cast<void*>(input), static_cast<DWORD>(inputSize),
        output, static_cast<DWORD>(outputSize),
        &bytesReturned, nullptr) != FALSE;
}

bool GuardianA::AddProtectedPath(const std::wstring& path) {
    if (m_driverClient && m_driverClient->IsConnected()) {
        return m_driverClient->AddProtectedPath(path);
    }
    return false;
}

bool GuardianA::RemoveProtectedPath(const std::wstring& path) {
    if (m_driverClient && m_driverClient->IsConnected()) {
        return m_driverClient->RemoveProtectedPath(path);
    }
    return false;
}

void GuardianA::UpdateSharedState() {
    if (!m_ipcManager) return;
    HeartbeatPayload hb = {};
    hb.process_id = GetCurrentProcessId();
    hb.status = static_cast<uint8_t>(m_emergencyState.load());
    hb.nonce = m_sequence++;
    m_ipcManager->UpdateHeartbeat(hb);
}

void GuardianA::SetEmergencyState(EmergencyState state) {
    m_emergencyState = state;
    if (m_ipcManager) {
        m_ipcManager->SendToNode(NodeId::GUARDIAN_C,
            MessageType::STATE_SYNC, &state, sizeof(state));
    }
}

void GuardianA::LoadProtectedPaths() {
    m_protectedPaths.clear();
    auto protectedDirs = m_config->GetProtectedDirectories();
    if (protectedDirs.empty()) {
        if (g_logger) {
            g_logger->Info("No protected paths configured");
        }
        return;
    }
    
    if (g_logger) {
        g_logger->Info("Loading %zu protected paths", protectedDirs.size());
    }
    
    for (const auto& dir : protectedDirs) {
        std::wstring path = dir.path;
        
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string pathStr(WideToUtf8(path));
            if (g_logger) g_logger->Error("Protected path does NOT exist or is not a directory: %s — files under this path will NOT be protected!", pathStr.c_str());
            if (m_ipcManager) {
                AlertNotification alert = {};
                alert.level = static_cast<uint8_t>(ThreatLevel::LEVEL_2);
                std::string msg = "Protected directory missing: " + pathStr;
                strncpy_s(alert.message, msg.c_str(), sizeof(alert.message) - 1);
                m_ipcManager->SendToNode(NodeId::GUARDIAN_C, MessageType::ALERT_NOTIFICATION, &alert, sizeof(alert));
            }
        }

        m_protectedPaths.push_back(path);
        
        if (g_logger) {
            std::string pathStr(WideToUtf8(path));
            g_logger->Info("Adding protected path: %s", pathStr.c_str());
        }
        
        if (m_driverClient && m_driverClient->IsConnected()) {
            m_driverClient->AddProtectedPath(dir.path);
        }
    }
}

bool GuardianA::IsInProtectedPath(const wchar_t* filePath) {
    if (m_protectedPaths.empty()) {
        return false;
    }
    
    std::wstring file(filePath);
    while (!file.empty() && file.back() == L'\\') file.pop_back();
    std::transform(file.begin(), file.end(), file.begin(), ::towlower);
    for (const auto& path : m_protectedPaths) {
        std::wstring lowerPath(path);
        while (!lowerPath.empty() && lowerPath.back() == L'\\') lowerPath.pop_back();
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
        if (file.find(lowerPath) == 0 && 
            (file.length() == lowerPath.length() || file[lowerPath.length()] == L'\\')) {
            return true;
        }
    }
    return false;
}

void GuardianA::LogSecurityEvent(ThreatLevel level, const std::string& message, const DriverEvent* event) {
    // Write to Windows event log
    LogEvent(EVENTLOG_WARNING_TYPE, 
             Utf8ToWide(message).c_str());
    
    // Write to GuardianShield log file
    if (g_logger) {
        if (event) {
            std::wstring filePath(event->file_path);
            std::wstring processName(event->process_name);
            
            g_logger->LogEvent(
                DriverEventTypeToString(static_cast<DriverEventType>(event->event_type)),
                ThreatLevelToString(level),
                "LOG",
                filePath,
                processName,
                event->process_id,
                message
            );
        } else {
            g_logger->Log(LogLevel::INFO, message.c_str());
        }
    }
}

void GuardianA::SendAlert(ThreatLevel level, const std::string& message,
                           const DriverEvent* event) {
    LogSecurityEvent(level, message, event);
    
    // Send ALERT_NOTIFICATION via IPC to GuardianC (runs in user session)
    if (m_ipcManager) {
        AlertNotification notif = {};
        notif.level = static_cast<uint8_t>(level);
        notif.process_id = event ? event->process_id : 0;
        strncpy(notif.message, message.c_str(), sizeof(notif.message) - 1);
        if (event) {
            wcsncpy(notif.file_path, event->file_path,
                     sizeof(notif.file_path) / sizeof(wchar_t) - 1);
        }
        bool sent = m_ipcManager->SendToNode(NodeId::GUARDIAN_C,
                                 MessageType::ALERT_NOTIFICATION,
                                 &notif, sizeof(notif));
        if (!sent && g_logger) {
            static std::atomic<int> s_ipcFailCount{0};
            int fc = ++s_ipcFailCount;
            if (fc == 1 || fc == 10 || fc == 100 || (fc % 500 == 0))
                g_logger->Warn("IPC ALERT_NOTIFICATION send failure (total=%d)", fc);
        }
    }
}

} // namespace Guardian
