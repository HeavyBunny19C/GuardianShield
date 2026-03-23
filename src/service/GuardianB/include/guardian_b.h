/**
 * @file guardian_b.h
 * @brief GuardianB - Backup Controller Node
 *
 * The backup controller responsible for:
 * - Monitoring GuardianA health via heartbeat
 * - Taking over as primary when GuardianA is unavailable
 * - Forwarding events between GuardianC and GuardianA
 * - Independently executing emergency protocols when promoted
 */

#pragma once

#include "../../common/include/common_types.h"
#include "../../common/include/windows_service.h"
#include "../../common/include/ipc.h"
#include "../../common/include/config.h"
#include "../../common/include/logger.h"
#include "../../common/include/environment_validator.h"
#include "../../common/include/driver_client.h"
#include "../../common/include/file_encryptor.h"
#include "../../common/include/file_wiper.h"
#include "../../GuardianA/include/threat_evaluator.h"

#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace Guardian {

using KernelDriverEvent = DriverEvent;

struct ThreatAssessmentB {
    ThreatLevel level;
    ResponseAction action;
    std::string description;
    float confidence;
};

/**
 * @brief GuardianB - Backup Controller Service
 *
 * Runs as a Windows service with SYSTEM privileges.
 * Monitors GuardianA and assumes primary role on failure.
 */
class GuardianB : public WindowsService {
public:
    GuardianB();
    ~GuardianB() override;

    GuardianB(const GuardianB&) = delete;
    GuardianB& operator=(const GuardianB&) = delete;

protected:
    void OnStart(DWORD argc, LPWSTR* argv) override;
    void OnStop() override;
    void OnShutdown() override;

private:
    // Initialization
    bool Initialize();
    bool LoadConfiguration();
    bool InitializeIPC();
    bool InitializeLogger();
    bool InitializeEnvironmentValidator();
    bool ValidateEnvironment();
    bool ConnectDrivers();
    void SyncDriverWhitelist();
    void SendBlockPolicy();
    void StartWorkerThreads();
    void StopWorkerThreads();
    void LoadProtectedPaths();

    // Heartbeat
    void HeartbeatThread();
    void SendHeartbeat();

    // GuardianA monitoring & failover
    void MonitorGuardianAThread();
    void PromoteToPrimary();
    void DemoteToBackup();

    // Event processing (active when promoted to primary)
    void EventProcessingThread();
    void DriverReadThread();
    void HandleDriverEvent(const DriverEvent& event);
    void HandleGuardianMessage(const MessageHeader& header,
                               const uint8_t* payload,
                               size_t payloadSize);
    void QueueEvent(const DriverEvent& event);

    // Threat assessment (used only in primary mode)
    ThreatAssessmentB AssessThreat(const DriverEvent& event);
    void ExecuteResponse(const ThreatAssessmentB& assessment,
                         const DriverEvent& event);

    // Protection protocol (Tier 1 - recoverable)
    void TriggerProtectionProtocol();
    void StartProtectionCountdown();

    // Emergency protocol (Tier 2 - irrecoverable)
    void TriggerEmergencyProtocol(bool skipAlert = false);
    void StartEmergencyCountdown(bool skipAlert);
    void CancelEmergency();
    void EncryptProtectedFiles(bool deleteSource = true);
    void WipeProtectedFiles();
    void CleanSystemTraces();
    void LockdownSystem();
    void SetEmergencyState(EmergencyState state);

    // Logging
    void LogSecurityEvent(ThreatLevel level,
                          const std::string& message,
                          const DriverEvent* event = nullptr);
    void SendAlert(ThreatLevel level,
                   const std::string& message,
                   const DriverEvent* event = nullptr);

    bool IsInProtectedPath(const wchar_t* filePath);

private:
    // Configuration
    std::shared_ptr<Config> m_config;

    // Environment validation
    std::unique_ptr<EnvironmentValidator> m_envValidator;

    // IPC
    std::unique_ptr<IpcManager> m_ipcManager;

    // Driver
    std::unique_ptr<DriverClient> m_driverClient;

    // File operation components (used when promoted)
    std::unique_ptr<FileEncryptor> m_fileEncryptor;
    std::unique_ptr<FileWiper> m_fileWiper;

    // Threat evaluation (reuses same two-tier logic as GuardianA in primary mode)
    std::unique_ptr<ThreatEvaluator> m_threatEvaluator;

    // Worker threads
    std::thread m_heartbeatThread;
    std::thread m_monitorThread;
    std::thread m_eventThread;
    std::thread m_driverReadThread;

    // State
    std::atomic<bool> m_running;
    std::atomic<bool> m_isPrimary;
    std::atomic<bool> m_emergencyMode;
    std::atomic<bool> m_safeMode{false};
    std::atomic<bool> m_protocolActive{false};
    std::atomic<bool> m_decryptInProgress{false};
    std::thread m_decryptThread;
    std::atomic<int> m_emergencyLevel;  // 0=normal, 1=protection, 2=emergency
    std::atomic<bool> m_cancelRequested;
    std::atomic<EmergencyState> m_emergencyState;
    std::thread m_protocolThread;

    // Event queue
    std::mutex m_eventMutex;
    std::condition_variable m_eventCV;
    std::queue<DriverEvent> m_eventQueue;

    // GuardianA heartbeat tracking
    std::chrono::steady_clock::time_point m_lastGuardianAHeartbeat;
    uint32_t m_guardianAMissedBeats;
    std::mutex m_heartbeatMutex;
    HANDLE m_leaderMutex{NULL};

    static constexpr uint32_t HEARTBEAT_INTERVAL_MS = 500;
    static constexpr uint32_t MAX_MISSED_HEARTBEATS = 3;

    // Backup event logger (logs events when non-primary)
    std::shared_ptr<Logger> m_backupEventLogger;

    // Protected paths
    std::vector<std::wstring> m_protectedPaths;

    // Sequence & stats
    std::atomic<uint32_t> m_sequence;
    std::atomic<uint64_t> m_eventsProcessed;
    std::atomic<uint64_t> m_threatsDetected;
};

} // namespace Guardian
