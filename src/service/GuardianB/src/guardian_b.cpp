/**
 * @file guardian_b.cpp
 * @brief GuardianB service implementation - Backup Controller
 */

#include "guardian_b.h"
#include "../../../driver/shared/guardian_ioctl.h"
#include "../../common/include/string_utils.h"
#include <iostream>
#include <functional>
#include <algorithm>
#include <unordered_map>
#include <chrono>
#include <shlobj.h>
#include <wtsapi32.h>
#include <psapi.h>

#pragma comment(lib, "Wtsapi32.lib")

namespace Guardian {

static uint64_t GetCurrentTimeMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

static std::unordered_map<size_t, uint64_t> s_recentEventsB;
static std::mutex s_deduplicationMutexB;
static constexpr uint64_t DEDUP_WINDOW_MS = 500;

static const char* ResponseActionCombinedToString(ResponseAction action) {
    uint8_t v = static_cast<uint8_t>(action);
    if (v & static_cast<uint8_t>(ResponseAction::BLOCK)) return "BLOCK";
    if (v & static_cast<uint8_t>(ResponseAction::TERMINATE)) return "TERMINATE";
    if (v & static_cast<uint8_t>(ResponseAction::ENCRYPT)) return "ENCRYPT";
    if (v & static_cast<uint8_t>(ResponseAction::ALERT_USER)) return "ALERT_USER";
    return "LOG";
}

GuardianB::GuardianB()
    : WindowsService(L"WinDefenderHelper", L"Windows Defender Helper Service",
                     SERVICE_AUTO_START, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
    , m_running(false)
    , m_isPrimary(false)
    , m_emergencyMode(false)
    , m_emergencyLevel(0)
    , m_cancelRequested(false)
    , m_emergencyState(EmergencyState::NORMAL)
    , m_guardianAMissedBeats(0)
    , m_sequence(0)
    , m_eventsProcessed(0)
    , m_threatsDetected(0)
{
    m_lastGuardianAHeartbeat = std::chrono::steady_clock::now();
}

GuardianB::~GuardianB() {
    StopWorkerThreads();
}

// ============================================
// Service Lifecycle
// ============================================

void GuardianB::OnStart(DWORD argc, LPWSTR* argv) {
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB starting...");

    m_leaderMutex = CreateMutexW(NULL, FALSE, L"Global\\GuardianShield-Leader");
    if (!m_leaderMutex) {
        LogEvent(EVENTLOG_WARNING_TYPE,
                 L"Failed to create leader election mutex; failover election lock disabled");
    }

    if (!Initialize()) {
        LogEvent(EVENTLOG_ERROR_TYPE, L"GuardianB initialization failed");
        ReportStatus(State::Stopped, 1);
        return;
    }

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
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB started successfully");
}

void GuardianB::OnStop() {
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB stopping...");
    m_running = false;
    StopWorkerThreads();

    if (m_isPrimary && m_leaderMutex) {
        ReleaseMutex(m_leaderMutex);
    }
    if (m_leaderMutex) {
        CloseHandle(m_leaderMutex);
        m_leaderMutex = NULL;
    }

    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB stopped");
}

void GuardianB::OnShutdown() {
    OnStop();
}

// ============================================
// Initialization
// ============================================

bool GuardianB::Initialize() {
    if (!LoadConfiguration()) {
        return false;
    }

    if (!InitializeLogger()) {
        LogEvent(EVENTLOG_WARNING_TYPE, L"Failed to initialize logger");
    }

    if (!InitializeIPC()) {
        return false;
    }

    if (!InitializeEnvironmentValidator()) {
        // Non-fatal
    }

    m_fileEncryptor = std::make_unique<FileEncryptor>();
    m_fileWiper = std::make_unique<FileWiper>();

    // Initialize ThreatEvaluator with same two-tier thresholds as GuardianA
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
        tier1.data_transfer_mb = m_config->GetDataTransferThresholdMB();
        tier1.process_termination_count = m_config->GetProcessTerminationCount();
        tier1.process_termination_window_seconds = m_config->GetProcessTerminationWindowSeconds();
        tier1.file_create_count = m_config->GetFileCreateThreshold();
        tier1.file_create_window_seconds = m_config->GetFileCreateWindowSeconds();
        tier1.file_rename_count = m_config->GetFileRenameThreshold();
        tier1.file_rename_window_seconds = m_config->GetFileRenameWindowSeconds();
        tier1.file_move_count = m_config->GetFileMoveThreshold();
        tier1.file_move_window_seconds = m_config->GetFileMoveWindowSeconds();

        tier2.file_write_count = m_config->GetTier2FileWriteThreshold();
        tier2.file_write_window_seconds = m_config->GetTier2FileWriteWindowSeconds();
        tier2.file_compress_count = m_config->GetTier2FileCompressThreshold();
        tier2.file_compress_window_seconds = m_config->GetTier2FileCompressWindowSeconds();
        tier2.file_delete_count = m_config->GetTier2FileDeleteThreshold();
        tier2.file_delete_window_seconds = m_config->GetTier2FileDeleteWindowSeconds();
        tier2.file_network_transfer_count = m_config->GetTier2FileNetworkTransferThreshold();
        tier2.file_network_transfer_window_seconds = m_config->GetTier2FileNetworkTransferWindowSeconds();
        tier2.data_transfer_mb = m_config->GetTier2DataTransferThresholdMB();
        tier2.process_termination_count = m_config->GetTier2ProcessTerminationCount();
        tier2.process_termination_window_seconds = m_config->GetTier2ProcessTerminationWindowSeconds();
        tier2.file_create_count = m_config->GetTier2FileCreateThreshold();
        tier2.file_create_window_seconds = m_config->GetTier2FileCreateWindowSeconds();
        tier2.file_rename_count = m_config->GetTier2FileRenameThreshold();
        tier2.file_rename_window_seconds = m_config->GetTier2FileRenameWindowSeconds();
        tier2.file_move_count = m_config->GetTier2FileMoveThreshold();
        tier2.file_move_window_seconds = m_config->GetTier2FileMoveWindowSeconds();

        m_threatEvaluator->SetTieredThresholds(tier1, tier2);
    }

    LoadProtectedPaths();
    if (!ConnectDrivers()) {
        LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: Driver connection failed - running without kernel driver");
    }

    return true;
}

bool GuardianB::LoadConfiguration() {
    m_config = std::make_shared<Config>(
        L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml");
    return m_config->Load();
}

bool GuardianB::InitializeIPC() {
    m_ipcManager = std::make_unique<IpcManager>(NodeId::GUARDIAN_B);
    bool ok = m_ipcManager->Initialize();
    if (!ok) {
        LogEvent(EVENTLOG_WARNING_TYPE,
                 L"IPC initialization failed - running in standalone mode");
    }

    if (ok) {
        m_ipcManager->SetMessageHandler(
            [this](const MessageHeader& header, const uint8_t* payload, size_t size) {
                HandleGuardianMessage(header, payload, size);
            });
    }

    return true;
}

bool GuardianB::InitializeLogger() {
    try {
        std::wstring logDir = m_config->GetLogPath();
        if (logDir.empty()) {
            logDir = L"C:\\ProgramData\\GuardianShield\\logs";
        }
        std::wstring logPath = logDir + L"\\guardian_b";

        int retentionDays = m_config->GetLogRetentionDays();
        if (retentionDays == 0) retentionDays = 7;

        LogFormat format = LogFormat::JSON;
        std::string logFormat = m_config->GetLogFormat();
        if (logFormat == "text") format = LogFormat::TEXT;

        g_logger = std::make_shared<Logger>(logPath, LogLevel::INFO,
                                             format, retentionDays);
        g_logger->SetConsoleOutput(false);

        std::wstring backupLogPath = logDir + L"\\backup_events";
        m_backupEventLogger = std::make_shared<Logger>(
            backupLogPath, LogLevel::INFO, LogFormat::JSON, retentionDays);
        m_backupEventLogger->SetConsoleOutput(false);

        return true;
    } catch (const std::exception& e) {
        LogEvent(EVENTLOG_ERROR_TYPE,
                 (L"Logger init failed: " +
                  Utf8ToWide(std::string(e.what()))).c_str());
        return false;
    }
}

bool GuardianB::InitializeEnvironmentValidator() {
    m_envValidator = std::make_unique<EnvironmentValidator>();

    std::wstring authListPath = m_config->GetAuthorizationListPath();
    bool loaded = false;
    if (!authListPath.empty()) {
        loaded = m_envValidator->LoadAuthorizationList(authListPath);
    }

    if (loaded) {
        const auto& auths = m_envValidator->GetAuthorizations();
        std::vector<Config::CachedAuthEntry> entries;
        for (const auto& a : auths) {
            entries.push_back({a.ip_address, a.mac_address, a.description});
        }
        m_config->SetCachedAuthEntries(entries);
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
        LogEvent(EVENTLOG_ERROR_TYPE,
                 L"CRITICAL: No authorization data available (file or cache)!");
        return false;
    }

    return true;
}

bool GuardianB::ValidateEnvironment() {
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

bool GuardianB::ConnectDrivers() {
    m_driverClient = std::make_unique<DriverClient>();
    bool connected = m_driverClient->Connect(GUARDFILTER_PORT_NAME);
    if (connected) {
        SyncDriverWhitelist();
    }
    return connected;
}

void GuardianB::SyncDriverWhitelist() {
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

    if (g_logger) g_logger->Info("GuardianB: synced whitelist to driver");
}

void GuardianB::SendBlockPolicy() {
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
        if (g_logger) g_logger->Warn("GuardianB: BLOCK configured but driver not connected - BLOCK will be skipped");
        LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: BLOCK skipped — driver not loaded");
        return;
    }

    m_driverClient->SetBlockPolicy(policy);
    if (g_logger) g_logger->Info("GuardianB: block policy sent to driver (flags=0x%02X)", policy);
}

void GuardianB::LoadProtectedPaths() {
    m_protectedPaths.clear();
    auto protectedDirs = m_config->GetProtectedDirectories();
    for (const auto& dir : protectedDirs) {
        DWORD attrs = GetFileAttributesW(dir.path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string pathStr(WideToUtf8(dir.path));
            if (g_logger) g_logger->Error("GuardianB: Protected path does NOT exist: %s", pathStr.c_str());
        }
        m_protectedPaths.push_back(dir.path);
        if (m_driverClient && m_driverClient->IsConnected()) {
            m_driverClient->AddProtectedPath(dir.path);
        }
        if (g_logger) {
            std::string pathStr(WideToUtf8(dir.path));
            g_logger->Info("GuardianB: protected path: %s", pathStr.c_str());
        }
    }
}

// ============================================
// Worker Threads
// ============================================

void GuardianB::StartWorkerThreads() {
    m_running = true;
    m_heartbeatThread = std::thread(&GuardianB::HeartbeatThread, this);
    m_monitorThread = std::thread(&GuardianB::MonitorGuardianAThread, this);
    m_eventThread = std::thread(&GuardianB::EventProcessingThread, this);
}

void GuardianB::StopWorkerThreads() {
    m_running = false;
    m_cancelRequested = true;
    m_emergencyMode = false;
    m_eventCV.notify_all();
    if (m_heartbeatThread.joinable()) m_heartbeatThread.join();
    if (m_monitorThread.joinable()) m_monitorThread.join();
    if (m_eventThread.joinable()) m_eventThread.join();
    if (m_driverReadThread.joinable()) m_driverReadThread.join();
    if (m_protocolThread.joinable()) m_protocolThread.join();
    if (m_decryptThread.joinable()) m_decryptThread.join();
}

// ============================================
// Heartbeat
// ============================================

void GuardianB::HeartbeatThread() {
    while (m_running) {
        SendHeartbeat();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));
    }
}

void GuardianB::SendHeartbeat() {
    if (!m_ipcManager) return;

    HeartbeatPayload payload = {};
    payload.process_id = GetCurrentProcessId();
    payload.uptime = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    payload.status = static_cast<uint8_t>(m_emergencyState.load());
    payload.nonce = m_sequence++;

    PROCESS_MEMORY_COUNTERS pmc = {};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        payload.memory_usage = pmc.WorkingSetSize;
    }

    m_ipcManager->UpdateHeartbeat(payload);
    m_ipcManager->Broadcast(MessageType::HEARTBEAT, &payload, sizeof(payload));
}

// ============================================
// GuardianA Monitoring & Failover
// ============================================

void GuardianB::MonitorGuardianAThread() {
    while (m_running) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));

        HeartbeatPayload aHeartbeat = {};
        bool gotHeartbeat = false;

        if (m_ipcManager) {
            gotHeartbeat = m_ipcManager->GetNodeHeartbeat(
                NodeId::GUARDIAN_A, aHeartbeat);
        }

        std::lock_guard<std::mutex> lock(m_heartbeatMutex);

        if (gotHeartbeat && aHeartbeat.process_id != 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - m_lastGuardianAHeartbeat).count();

            if (elapsed < static_cast<int64_t>(HEARTBEAT_INTERVAL_MS * 3)) {
                if (m_isPrimary) {
                    DemoteToBackup();
                }
                m_guardianAMissedBeats = 0;
            }
            m_lastGuardianAHeartbeat = now;
        } else {
            m_guardianAMissedBeats++;
            if (m_guardianAMissedBeats >= MAX_MISSED_HEARTBEATS && !m_isPrimary) {
                PromoteToPrimary();
            }
        }
    }
}

void GuardianB::PromoteToPrimary() {
    if (!m_leaderMutex) {
        LogEvent(EVENTLOG_WARNING_TYPE,
                 L"Leader mutex unavailable - skipping promotion to avoid split-brain");
        return;
    }

    DWORD waitResult = WaitForSingleObject(m_leaderMutex, 0);
    if (waitResult == WAIT_TIMEOUT) {
        LogEvent(EVENTLOG_INFORMATION_TYPE,
                 L"GuardianA still holds leader mutex - staying in BACKUP mode");
        return;
    }

    if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_ABANDONED) {
        LogEvent(EVENTLOG_WARNING_TYPE,
                 L"Leader mutex wait failed - skipping promotion to avoid split-brain");
        return;
    }

    m_isPrimary = true;
    LogEvent(EVENTLOG_WARNING_TYPE,
             L"GuardianA unresponsive - GuardianB promoted to PRIMARY controller");

    if (g_logger) {
        g_logger->Log(LogLevel::WARN,
                      "GuardianB promoted to primary controller (failover)");
    }

    if (m_ipcManager) {
        m_ipcManager->Broadcast(MessageType::ALERT, nullptr, 0);
    }

    if (!m_driverReadThread.joinable()) {
        if (!m_driverClient || !m_driverClient->IsConnected()) {
            ConnectDrivers();
        }
        LoadProtectedPaths();
        SyncDriverWhitelist();
        SendBlockPolicy();
        try {
            m_driverReadThread = std::thread([this]() { DriverReadThread(); });
        } catch (const std::exception& e) {
            if (g_logger) g_logger->Error("GuardianB: Failed to start DriverReadThread: %s", e.what());
        }
    }
}

void GuardianB::DemoteToBackup() {
    m_isPrimary = false;
    m_guardianAMissedBeats = 0;

    if (m_leaderMutex) {
        ReleaseMutex(m_leaderMutex);
    }

    LogEvent(EVENTLOG_INFORMATION_TYPE,
             L"GuardianA recovered - GuardianB demoted back to BACKUP");

    if (g_logger) {
        g_logger->Log(LogLevel::INFO,
                      "GuardianB demoted back to backup (GuardianA recovered)");
    }

    if (m_driverReadThread.joinable()) {
        m_driverReadThread.join();
    }
}

// ============================================
// Event Processing
// ============================================

void GuardianB::EventProcessingThread() {
    while (m_running) {
        std::unique_lock<std::mutex> lock(m_eventMutex);
        m_eventCV.wait_for(lock, std::chrono::milliseconds(100),
                           [this] { return !m_eventQueue.empty() || !m_running; });

        while (!m_eventQueue.empty() && m_running) {
            DriverEvent event = m_eventQueue.front();
            m_eventQueue.pop();
            lock.unlock();

            if (m_isPrimary) {
                HandleDriverEvent(event);
            } else if (m_backupEventLogger) {
                auto eventTypeStr = DriverEventTypeToString(
                    static_cast<DriverEventType>(event.event_type));
                m_backupEventLogger->LogEvent(
                    eventTypeStr, "LEVEL_0", "LOG",
                    event.file_path, event.process_name, event.process_id,
                    "non-primary backup capture");
            }
            m_eventsProcessed++;
            lock.lock();
        }
    }
}

void GuardianB::DriverReadThread() {
    if (g_logger) g_logger->Info("GuardianB DriverReadThread started");

    while (m_running && m_isPrimary) {
        if (!m_driverClient || !m_driverClient->IsConnected()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (g_logger) g_logger->Info("GuardianB DriverReadThread: attempting driver reconnect...");
            if (!m_driverClient) {
                m_driverClient = std::make_unique<DriverClient>();
            }
            if (!m_driverClient->Connect(GUARDFILTER_PORT_NAME)) {
                continue;
            }
            if (g_logger) g_logger->Info("GuardianB DriverReadThread: reconnected");
            LoadProtectedPaths();
            SyncDriverWhitelist();
            SendBlockPolicy();
        }

        DriverEvent event;
        if (m_driverClient->GetNextEvent(event, 500)) {
            QueueEvent(event);
        }
    }

    if (g_logger) g_logger->Info("GuardianB DriverReadThread stopped");
}

void GuardianB::HandleDriverEvent(const DriverEvent& event) {
    if (m_protocolActive) return;

    static DWORD s_selfPid = GetCurrentProcessId();
    if (event.process_id == s_selfPid) return;

    if (event.process_id <= 4) return;

    if (event.event_type >= static_cast<uint32_t>(DriverEventType::MAX_TYPE)) return;

    DriverEventType evType = static_cast<DriverEventType>(event.event_type);
    bool isProcessEvent = (evType == DriverEventType::PROCESS_CREATE ||
                           evType == DriverEventType::PROC_TERMINATE);

    if (!isProcessEvent && !IsInProtectedPath(event.file_path)) return;

    std::wstring filePath(event.file_path);
    if (!isProcessEvent && filePath.empty()) return;

    if (!isProcessEvent) {
        for (const auto& protPath : m_protectedPaths) {
            if (filePath == protPath || filePath == protPath + L"\\") return;
        }

        // Skip OS metadata files
        std::wstring fp(event.file_path);
        auto lastSep = fp.rfind(L'\\');
        std::wstring baseName = (lastSep != std::wstring::npos)
            ? fp.substr(lastSep + 1) : fp;
        if (_wcsicmp(baseName.c_str(), L"desktop.ini") == 0 ||
            _wcsicmp(baseName.c_str(), L"Thumbs.db") == 0) {
            return;
        }

        if (m_config && !m_config->IsFileTypeMonitored(fp)) return;
    }

    // System-level whitelist: OS background processes whose file I/O is noise
    if (!isProcessEvent) {
        std::wstring pn(event.process_name);
        auto pos = pn.rfind(L'\\');
        std::wstring exeName = (pos != std::wstring::npos) ? pn.substr(pos + 1) : pn;
        static const wchar_t* kSystemWhitelist[] = {
            L"SearchProtocolHost.exe", L"SearchIndexer.exe",
            L"SearchFilterHost.exe", L"TrustedInstaller.exe",
            L"TiWorker.exe", L"MsMpEng.exe",
            L"svchost_core.exe", L"svchost_helper.exe",
        };
        for (const auto& sys : kSystemWhitelist) {
            if (_wcsicmp(exeName.c_str(), sys) == 0) return;
        }

        // User-configurable whitelist (with UWP fallback)
        if (m_config) {
            std::wstring fullProcessPath(event.process_name);
            // UWP fallback: if extracted name has no .exe suffix, query real image name
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

    {
        size_t dedupKey = std::hash<std::wstring>{}(
            std::wstring(event.file_path)) ^
            (std::hash<uint32_t>{}(event.event_type) << 1) ^
            (std::hash<uint32_t>{}(event.process_id) << 2);
        std::lock_guard<std::mutex> lock(s_deduplicationMutexB);
        uint64_t now = GetCurrentTimeMs();
        auto it = s_recentEventsB.find(dedupKey);
        if (it != s_recentEventsB.end() && (now - it->second) < DEDUP_WINDOW_MS) {
            return;
        }
        s_recentEventsB[dedupKey] = now;
        if (s_recentEventsB.size() > 2000) {
            int cleaned = 0;
            for (auto jt = s_recentEventsB.begin(); jt != s_recentEventsB.end() && cleaned < 500; ) {
                if (now - jt->second > DEDUP_WINDOW_MS * 2) {
                    jt = s_recentEventsB.erase(jt);
                    ++cleaned;
                } else {
                    ++jt;
                }
            }
        }
    }

    // Single-event assessment (always runs, always logged)
    ThreatAssessmentB assessment = AssessThreat(event);

    // Two-tier batch threshold check — file events only.
    // Process events are system-wide and must not trigger file-protection protocols.
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
                        LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: Targeted termination of top-contributor process");
                        if (!TerminateProcess(hProc, 1)) {
                            if (g_logger) g_logger->Warn("GuardianB: Targeted TerminateProcess failed for PID %u (err=%lu)",
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

static bool SecureCompareB(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
    }
    return result == 0;
}

void GuardianB::HandleGuardianMessage(const MessageHeader& header,
                                       const uint8_t* payload,
                                       size_t payloadSize) {
    MessageType type = static_cast<MessageType>(header.type);

    switch (type) {
        case MessageType::HEARTBEAT:
            if (static_cast<NodeId>(header.source) == NodeId::GUARDIAN_A) {
                std::lock_guard<std::mutex> lock(m_heartbeatMutex);
                m_lastGuardianAHeartbeat = std::chrono::steady_clock::now();
                m_guardianAMissedBeats = 0;
            }
            break;

        case MessageType::DRIVER_EVENT:
            if (payloadSize >= sizeof(DriverEvent)) {
                DriverEvent event;
                memcpy(&event, payload, sizeof(DriverEvent));
                QueueEvent(event);
            }
            break;

        case MessageType::EMERGENCY_TRIGGER:
            if (!m_emergencyMode) {
                TriggerEmergencyProtocol();
            }
            break;

        case MessageType::EMERGENCY_PREPARE:
            LogEvent(EVENTLOG_WARNING_TYPE,
                     L"Emergency prepare received from GuardianA");
            break;

        case MessageType::UNLOCK_RESPONSE:
            if (m_emergencyState == EmergencyState::LOCKED) {
                LogEvent(EVENTLOG_INFORMATION_TYPE,
                         L"GuardianB: Unlocked by administrator via lock screen");
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
            if (adminHash.empty() || !SecureCompareB(inputHash, adminHash)) {
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
                resp.reserved2 = 0;

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
                        L"\x6CA1\x6709\x627E\x5230\x9700\x8981\x89E3\x5BC6\x7684\x6587\x4EF6");
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

void GuardianB::QueueEvent(const DriverEvent& event) {
    std::lock_guard<std::mutex> lock(m_eventMutex);
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    if (m_eventQueue.size() >= MAX_QUEUE_SIZE) {
        m_eventQueue.pop();
        static std::atomic<uint64_t> s_dropCount{0};
        if (++s_dropCount % 1000 == 1) {
            LogEvent(EVENTLOG_WARNING_TYPE,
                     L"GuardianB: Event queue overflow: dropping oldest events");
        }
    }
    m_eventQueue.push(event);
    m_eventCV.notify_one();
}

// ============================================
// Threat Assessment (Primary Mode)
// ============================================

ThreatAssessmentB GuardianB::AssessThreat(const DriverEvent& event) {
    auto se = BuildEventResponse(*m_config,
        static_cast<DriverEventType>(event.event_type));
    ThreatAssessmentB assessment;
    assessment.level = se.level;
    assessment.action = se.action;
    assessment.confidence = se.confidence;
    assessment.description = se.description;
    return assessment;
}

void GuardianB::ExecuteResponse(const ThreatAssessmentB& assessment,
                                 const DriverEvent& event) {
    uint8_t act = static_cast<uint8_t>(assessment.action);

    if (act & static_cast<uint8_t>(ResponseAction::LOG)) {
        LogSecurityEvent(assessment.level, assessment.description, &event);
    }

    if (act & static_cast<uint8_t>(ResponseAction::ALERT_USER)) {
        SendAlert(assessment.level, assessment.description, &event);
    }

    if (act & static_cast<uint8_t>(ResponseAction::BLOCK)) {
        if (m_driverClient && m_driverClient->IsConnected()) {
            if (g_logger) g_logger->Info("GuardianB BLOCK: operation already denied by driver for PID %u", event.process_id);
        } else {
            if (g_logger) g_logger->Warn("GuardianB BLOCK: driver not connected, BLOCK skipped for PID %u (no degradation to TERMINATE)", event.process_id);
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
                LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: Terminating process");
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, event.process_id);
                if (hProc) {
                    if (!TerminateProcess(hProc, 1)) {
                        if (g_logger) g_logger->Warn("GuardianB: TerminateProcess failed for PID %u (err=%lu)",
                            event.process_id, GetLastError());
                    } else {
                        WaitForSingleObject(hProc, 3000);
                    }
                    CloseHandle(hProc);
                } else {
                    if (g_logger) g_logger->Warn("GuardianB: OpenProcess(TERMINATE) failed for PID %u (err=%lu)",
                        event.process_id, GetLastError());
                }
            } else {
                LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: Skipped termination of protected system process");
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

// ============================================
// Emergency Protocol (Primary Mode)
// ============================================

void GuardianB::TriggerProtectionProtocol() {
    int currentLevel = m_emergencyLevel.load();
    if (currentLevel >= 1) return;
    int expected = 0;
    if (!m_emergencyLevel.compare_exchange_strong(expected, 1)) return;
    m_emergencyMode = true;
    m_cancelRequested = false;
    SetEmergencyState(EmergencyState::ALERT);
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: Protection protocol (Tier 1) triggered");
    SendAlert(ThreatLevel::LEVEL_2,
              "\xe4\xbf\x9d\xe6\x8a\xa4\xe5\x8d\x8f\xe8\xae\xae\xe5\xb7\xb2\xe8\xa7\xa6\xe5\x8f\x91 - \xe6\x96\x87\xe4\xbb\xb6\xe5\xb0\x86\xe8\xa2\xab\xe5\x8a\xa0\xe5\xaf\x86\xe5\xb9\xb6\xe9\x94\x81\xe5\xae\x9a", nullptr);

    if (m_protocolThread.joinable()) m_protocolThread.join();
    m_protocolActive = true;
    try {
        m_protocolThread = std::thread([this]() {
            StartProtectionCountdown();
        });
    } catch (const std::exception& e) {
        if (g_logger) g_logger->Error("GuardianB: Failed to create protection thread: %s", e.what());
        m_protocolActive = false;
        m_emergencyLevel = 0;
        m_emergencyMode = false;
        SetEmergencyState(EmergencyState::NORMAL);
    }
}

void GuardianB::StartProtectionCountdown() {
    uint32_t alertSeconds = m_config ? m_config->GetAlertTimeoutSeconds() : 30;
    if (g_logger) g_logger->Warn("GuardianB ALERT countdown started: %u seconds (level=%d)",
                                  alertSeconds, m_emergencyLevel.load());
    for (uint32_t i = 0; i < alertSeconds; ++i) {
        if (!m_emergencyMode || m_cancelRequested) {
            LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB: Protection protocol cancelled");
            if (g_logger) g_logger->Info("GuardianB ALERT countdown cancelled at %u/%u seconds", i, alertSeconds);
            SetEmergencyState(EmergencyState::NORMAL);
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
            if (g_logger) g_logger->Warn("GuardianB ALERT countdown: %u/%u seconds (level=%d)",
                                          i, alertSeconds, m_emergencyLevel.load());
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    SetEmergencyState(EmergencyState::ENCRYPTING);
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: Protection - encrypting protected files");
    EncryptProtectedFiles();

    SetEmergencyState(EmergencyState::LOCKED);
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: Protection - locking all protected files");
    LockdownSystem();

    m_protocolActive = false;
}

void GuardianB::TriggerEmergencyProtocol(bool skipAlert) {
    int currentLevel = m_emergencyLevel.load();
    if (currentLevel >= 2) return;
    if (currentLevel == 1) {
        m_cancelRequested = true;
        if (m_protocolThread.joinable()) m_protocolThread.join();
        m_cancelRequested = false;
    }
    m_emergencyLevel = 2;
    m_emergencyMode = true;
    SetEmergencyState(EmergencyState::ALERT);
    LogEvent(EVENTLOG_WARNING_TYPE,
             L"GuardianB emergency protocol (Tier 2) triggered - IRRECOVERABLE");

    if (!skipAlert) {
        SendAlert(ThreatLevel::LEVEL_3,
                  "\xe7\xb4\xa7\xe6\x80\xa5\xe5\x8d\x8f\xe8\xae\xae\xe5\xb7\xb2\xe8\xa7\xa6\xe5\x8f\x91 - \xe6\x96\x87\xe4\xbb\xb6\xe5\xb0\x86\xe8\xa2\xab\xe5\x8a\xa0\xe5\xaf\x86\xe3\x80\x81\xe6\x93\xa6\xe9\x99\xa4\xe5\xb9\xb6\xe5\x88\xa0\xe9\x99\xa4", nullptr);
    }

    if (m_ipcManager) {
        m_ipcManager->Broadcast(MessageType::EMERGENCY_TRIGGER, nullptr, 0);
    }

    if (m_protocolThread.joinable()) m_protocolThread.join();
    m_protocolActive = true;
    try {
        m_protocolThread = std::thread([this, skipAlert]() {
            StartEmergencyCountdown(skipAlert);
        });
    } catch (const std::exception& e) {
        if (g_logger) g_logger->Error("GuardianB: Failed to create emergency thread: %s", e.what());
        m_protocolActive = false;
        m_emergencyLevel = 0;
        m_emergencyMode = false;
        SetEmergencyState(EmergencyState::NORMAL);
    }
}

void GuardianB::StartEmergencyCountdown(bool skipAlert) {
    if (!skipAlert) {
        uint32_t alertSeconds = m_config ? m_config->GetAlertTimeoutSeconds() : 30;
        if (g_logger) g_logger->Warn("GuardianB EMERGENCY countdown started: %u seconds (level=%d)",
                                      alertSeconds, m_emergencyLevel.load());
        for (uint32_t i = 0; i < alertSeconds; ++i) {
            if (!m_emergencyMode || m_cancelRequested) {
                LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB: Emergency protocol cancelled");
                if (g_logger) g_logger->Info("GuardianB EMERGENCY countdown cancelled at %u/%u seconds", i, alertSeconds);
                SetEmergencyState(EmergencyState::NORMAL);
                m_emergencyLevel = 0;
                m_emergencyMode = false;
                m_protocolActive = false;
                return;
            }
            if (i == 0 || i % 10 == 0) {
                if (g_logger) g_logger->Warn("GuardianB EMERGENCY countdown: %u/%u seconds (level=%d)",
                                              i, alertSeconds, m_emergencyLevel.load());
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    SetEmergencyState(EmergencyState::ENCRYPTING);
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: ENCRYPTING state");
    EncryptProtectedFiles(false);

    SetEmergencyState(EmergencyState::WIPING);
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: WIPING originals (DOD 5220.22-M)");
    WipeProtectedFiles();

    SetEmergencyState(EmergencyState::DELETING);
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: DELETING state");
    CleanSystemTraces();

    SetEmergencyState(EmergencyState::LOCKED);
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB: LOCKED state");
    LockdownSystem();
}

void GuardianB::CancelEmergency() {
    m_cancelRequested = true;
    m_emergencyMode = false;
    m_emergencyLevel = 0;
    SetEmergencyState(EmergencyState::NORMAL);
    if (m_ipcManager) {
        EmergencyState normalState = EmergencyState::NORMAL;
        m_ipcManager->Broadcast(MessageType::STATE_SYNC,
            &normalState, sizeof(normalState));
    }
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB emergency cancelled");
}

void GuardianB::SetEmergencyState(EmergencyState state) {
    m_emergencyState = state;
    if (m_ipcManager) {
        m_ipcManager->SendToNode(NodeId::GUARDIAN_C,
            MessageType::STATE_SYNC, &state, sizeof(state));
    }
}

void GuardianB::EncryptProtectedFiles(bool deleteSource) {
    if (!m_fileEncryptor) return;

    std::string password = m_config->GetAdminPasswordHash();
    if (password.empty()) {
        LogEvent(EVENTLOG_ERROR_TYPE, L"GuardianB: Cannot encrypt: no admin password configured");
        return;
    }

    auto protectedDirs = m_config->GetProtectedDirectories();
    for (const auto& dir : protectedDirs) {
        if (m_cancelRequested) break;

        LogEvent(EVENTLOG_INFORMATION_TYPE,
                 (L"GuardianB encrypting: " + dir.path).c_str());

        auto cb = [this](size_t current, size_t total, const std::wstring& fp) {
            if (g_logger) {
                std::string p(WideToUtf8(fp));
                g_logger->Info("GuardianB encrypt [%zu/%zu]: %s", current, total, p.c_str());
            }
        };

        auto cancelCb = [this]() -> bool { return m_cancelRequested.load(); };
        size_t count = m_fileEncryptor->EncryptDirectory(
            dir.path, password, dir.recursive, cb, deleteSource, cancelCb);
        LogEvent(EVENTLOG_INFORMATION_TYPE,
                 (L"GuardianB encrypted " + std::to_wstring(count) +
                  L" files in: " + dir.path).c_str());
    }
}

void GuardianB::WipeProtectedFiles() {
    if (!m_fileWiper) return;

    auto protectedDirs = m_config->GetProtectedDirectories();
    for (const auto& dir : protectedDirs) {
        LogEvent(EVENTLOG_INFORMATION_TYPE,
                 (L"GuardianB wiping: " + dir.path).c_str());

        auto cb = [this](size_t pass, size_t total, size_t bytes) {
            if (g_logger) {
                g_logger->Info("GuardianB wipe %zu/%zu, %zu bytes", pass, total, bytes);
            }
        };

        size_t count = m_fileWiper->WipeDirectory(dir.path, dir.recursive, cb, L".gs");
        LogEvent(EVENTLOG_INFORMATION_TYPE,
                 (L"GuardianB wiped " + std::to_wstring(count) +
                  L" files in: " + dir.path).c_str());
    }
}

void GuardianB::CleanSystemTraces() {
    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB cleaning system traces");

    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
    }

    SHAddToRecentDocs(SHARD_PATHA, nullptr);

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
}

void GuardianB::LockdownSystem() {
    LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB system lockdown initiated");

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
            if (g_logger) g_logger->Warn("GuardianB lockdown timeout after %d seconds, releasing protocolActive", elapsed);
            LogEvent(EVENTLOG_WARNING_TYPE, L"GuardianB lockdown timed out — resuming event processing");
            m_protocolActive = false;
            break;
        }
    }

    LogEvent(EVENTLOG_INFORMATION_TYPE, L"GuardianB lockdown completed");
}

// ============================================
// Logging & Notification
// ============================================

void GuardianB::LogSecurityEvent(ThreatLevel level,
                                  const std::string& message,
                                  const DriverEvent* event) {
    LogEvent(EVENTLOG_WARNING_TYPE,
             Utf8ToWide(message).c_str());

    if (g_logger) {
        if (event) {
            std::wstring filePath(event->file_path);
            std::wstring processName(event->process_name);
            g_logger->LogEvent(
                DriverEventTypeToString(
                    static_cast<DriverEventType>(event->event_type)),
                ThreatLevelToString(level), "LOG",
                filePath, processName, event->process_id, message);
        } else {
            g_logger->Log(LogLevel::INFO, message.c_str());
        }
    }
}

void GuardianB::SendAlert(ThreatLevel level, const std::string& message,
                            const DriverEvent* event) {
    LogSecurityEvent(level, message, event);

    // Send via IPC to GuardianC for desktop notification (same as GuardianA)
    if (m_ipcManager) {
        AlertNotification notif = {};
        notif.level = static_cast<uint8_t>(level);
        notif.process_id = event ? event->process_id : 0;
        strncpy(notif.message, message.c_str(), sizeof(notif.message) - 1);
        if (event) {
            wcsncpy(notif.file_path, event->file_path,
                     sizeof(notif.file_path) / sizeof(wchar_t) - 1);
        }
        m_ipcManager->SendToNode(NodeId::GUARDIAN_C,
                                 MessageType::ALERT_NOTIFICATION,
                                 &notif, sizeof(notif));
    }
}

bool GuardianB::IsInProtectedPath(const wchar_t* filePath) {
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

} // namespace Guardian
