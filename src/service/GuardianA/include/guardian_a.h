/**
 * @file guardian_a.h
 * @brief GuardianA - Primary Controller Node
 * 
 * The primary controller responsible for:
 * - Coordinating GuardianB and GuardianC
 * - ETW event collection (runs as SYSTEM, no UAC needed)
 * - Receiving events from kernel drivers
 * - Making threat assessment decisions
 * - Triggering emergency protocols
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
#include "threat_evaluator.h"

#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_map>

#ifdef _WIN32
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <psapi.h>
#endif

namespace Guardian {

/**
 * @brief Event from kernel driver (alias for compatibility)
 */
using KernelDriverEvent = DriverEvent;

/**
 * @brief Threat assessment result
 */
struct ThreatAssessment {
    ThreatLevel level;
    ResponseAction action;
    std::string description;
    float confidence;
};

/**
 * @brief GuardianA - Primary Controller Service
 * 
 * Runs as a Windows service with SYSTEM privileges.
 * Acts as the central coordinator for the GuardianShield system.
 */
class GuardianA : public WindowsService {
public:
    /**
     * @brief Construct GuardianA service
     */
    GuardianA();
    ~GuardianA() override;
    
    // Non-copyable
    GuardianA(const GuardianA&) = delete;
    GuardianA& operator=(const GuardianA&) = delete;

protected:
    // ========================================
    // Windows Service Event Handlers
    // ========================================
    
    void OnStart(DWORD argc, LPWSTR* argv) override;
    void OnStop() override;
    void OnShutdown() override;

private:
    // ========================================
    // Initialization
    // ========================================
    
    /**
     * @brief Initialize all components
     * @return true if successful
     */
    bool Initialize();
    
    /**
     * @brief Load configuration
     */
    bool LoadConfiguration();
    
    /**
     * @brief Initialize IPC communication
     */
    bool InitializeIPC();
    
    /**
     * @brief Connect to kernel drivers
     */
    bool ConnectDrivers();
    void SyncDriverWhitelist();
    void SendBlockPolicy();
    
    /**
     * @brief Initialize encryption keys
     */
    bool InitializeKeys();
    
    /**
     * @brief Initialize environment validator
     */
    bool InitializeEnvironmentValidator();
    
    /**
     * @brief Validate environment (IP/MAC address)
     */
    bool ValidateEnvironment();
    
    /**
     * @brief Initialize logger
     */
    bool InitializeLogger();
    
    /**
     * @brief Initialize ETW event collection
     */
    bool InitializeEtw();
    
    /**
     * @brief Shut down ETW session and consumer thread
     */
    void ShutdownEtw();
    
    /**
     * @brief ETW consumer thread function
     */
    void EtwCollectionThread();
    
    /**
     * @brief Static ETW event callback (dispatches to s_instance)
     */
    static void WINAPI EtwEventCallback(PEVENT_RECORD eventRecord);
    
    /**
     * @brief Start worker threads
     */
    void StartWorkerThreads();
    
    /**
     * @brief Stop all worker threads
     */
    void StopWorkerThreads();

    // ========================================
    // Heartbeat Management
    // ========================================
    
    /**
     * @brief Heartbeat thread function
     */
    void HeartbeatThread();
    
    /**
     * @brief Send heartbeat to other nodes
     */
    void SendHeartbeat();
    
    /**
     * @brief Check for node heartbeat timeouts
     */
    void CheckHeartbeats();
    
    /**
     * @brief Handle node heartbeat timeout
     */
    void OnNodeTimeout(NodeId node);

    // ========================================
    // Event Processing
    // ========================================
    
    /**
     * @brief Event processing thread function
     */
    void EventProcessingThread();
    
    /**
     * @brief Handle driver event
     */
    void HandleDriverEvent(const DriverEvent& event);
    
    /**
     * @brief Handle message from other guardian
     */
    void HandleGuardianMessage(const MessageHeader& header, 
                               const uint8_t* payload, 
                               size_t payloadSize);
    
    /**
     * @brief Queue event for processing
     */
    void QueueEvent(const DriverEvent& event);

    // ========================================
    // Threat Assessment
    // ========================================
    
    /**
     * @brief Assess threat level of an event
     */
    ThreatAssessment AssessThreat(const DriverEvent& event);
    
    /**
     * @brief Execute response action
     */
    void ExecuteResponse(const ThreatAssessment& assessment, 
                        const DriverEvent& event);

    // ========================================
    // Emergency Protocol
    // ========================================
    
    /**
     * @brief Trigger protection protocol (Tier 1: encrypt + lock, recoverable)
     */
    void TriggerProtectionProtocol();

    /**
     * @brief Trigger emergency protocol (Tier 2: encrypt + wipe + delete, irrecoverable)
     * @param skipAlert If true, skip ALERT phase (for unauthorized device boot)
     */
    void TriggerEmergencyProtocol(bool skipAlert = false);
    
    /**
     * @brief Start emergency countdown (internal)
     */
    void StartEmergencyCountdown(bool skipAlert);

    /**
     * @brief Start protection countdown (internal, Tier 1)
     */
    void StartProtectionCountdown();

    /**
     * @brief Driver event read thread function
     */
    void DriverReadThread();
    
    /**
     * @brief Cancel emergency countdown
     */
    void CancelEmergency();
    
    /**
     * @brief Encrypt protected files
     */
    void EncryptProtectedFiles(bool deleteSource = true);
    
    /**
     * @brief Wipe protected files
     */
    void WipeProtectedFiles();
    
    /**
     * @brief Clean system traces
     */
    void CleanSystemTraces();
    
    /**
     * @brief Lock down system
     */
    void LockdownSystem();

    // ========================================
    // Driver Communication
    // ========================================
    
    /**
     * @brief Open driver device handle
     */
    bool OpenDriverHandle(const std::wstring& deviceName);
    
    /**
     * @brief Read events from driver
     */
    bool ReadDriverEvent(DriverEvent& event);
    
    /**
     * @brief Send command to driver
     */
    bool SendDriverCommand(uint32_t ioctlCode, 
                          const void* input, 
                          size_t inputSize,
                          void* output = nullptr,
                          size_t outputSize = 0);
    
    /**
     * @brief Add protected path to driver
     */
    bool AddProtectedPath(const std::wstring& path);
    
    /**
     * @brief Remove protected path from driver
     */
    bool RemoveProtectedPath(const std::wstring& path);

    // ========================================
    // State Management
    // ========================================
    
    /**
     * @brief Update shared state
     */
    void UpdateSharedState();
    
    /**
     * @brief Get current emergency state
     */
    EmergencyState GetEmergencyState() const { return m_emergencyState; }
    
    /**
     * @brief Set emergency state
     */
    void SetEmergencyState(EmergencyState state);
    
    /**
     * @brief Load protected paths from configuration
     */
    void LoadProtectedPaths();

    // ========================================
    // Logging and Notification
    // ========================================
    
    /**
     * @brief Log security event
     */
    void LogSecurityEvent(ThreatLevel level, 
                         const std::string& message,
                         const DriverEvent* event = nullptr);
    
    /**
     * @brief Send alert notification
     */
    void SendAlert(ThreatLevel level, 
                  const std::string& message,
                  const DriverEvent* event = nullptr);
    
private:
    // Configuration
    std::shared_ptr<Config> m_config;
    
    // Environment validation
    std::unique_ptr<EnvironmentValidator> m_envValidator;
    
    // IPC components
    std::unique_ptr<IpcManager> m_ipcManager;
    std::unique_ptr<SharedMemory> m_sharedMemory;
    
    // Driver handles
    HANDLE m_hFilterDriver;
    HANDLE m_hMonitorDriver;
    HANDLE m_leaderMutex{NULL};
    
    // File monitoring components
    std::unique_ptr<DriverClient> m_driverClient;

    std::unique_ptr<FileEncryptor> m_fileEncryptor;
    std::unique_ptr<FileWiper> m_fileWiper;
    
    // Threat evaluation (two-tier batch detection)
    std::unique_ptr<ThreatEvaluator> m_threatEvaluator;
    
    // ETW
    TRACEHANDLE m_traceSession;
    std::atomic<TRACEHANDLE> m_traceHandle;
    std::thread m_etwThread;
    std::atomic<bool> m_etwRunning;
    static constexpr wchar_t ETW_SESSION_NAME[] = L"GuardianShieldETW";
    static std::atomic<GuardianA*> s_instance;
    
    // Worker threads
    std::thread m_heartbeatThread;
    std::thread m_eventThread;
    std::thread m_driverThread;
    
    // Synchronization
    std::atomic<bool> m_running;
    std::atomic<bool> m_emergencyMode;
    std::atomic<bool> m_safeMode{false};
    std::atomic<bool> m_protocolActive{false};
    std::atomic<bool> m_decryptInProgress{false};
    std::thread m_decryptThread;
    std::atomic<int> m_emergencyLevel;  // 0=normal, 1=protection, 2=emergency
    std::atomic<bool> m_cancelRequested;
    std::atomic<EmergencyState> m_emergencyState;
    std::thread m_protocolThread;
    
    std::mutex m_eventMutex;
    std::condition_variable m_eventCV;
    std::queue<DriverEvent> m_eventQueue;
    
    // Heartbeat tracking (guarded by m_hbMutex)
    std::mutex m_hbMutex;
    std::chrono::steady_clock::time_point m_lastHeartbeat[3];
    uint32_t m_missedHeartbeats[3];
    
    // Sequence counters
    std::atomic<uint32_t> m_sequence;
    
    // Statistics
    std::atomic<uint64_t> m_eventsProcessed;
    std::atomic<uint64_t> m_threatsDetected;
    
    // Protected paths
    std::vector<std::wstring> m_protectedPaths;
    
    bool IsInProtectedPath(const wchar_t* filePath);
};

} // namespace Guardian
