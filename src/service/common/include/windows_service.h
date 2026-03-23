/**
 * @file windows_service.h
 * @brief Windows Service base class for GuardianShield
 * 
 * Provides a framework for implementing Windows services.
 * Handles service control requests and lifecycle management.
 */

#pragma once

#ifdef _WIN32
#include <Windows.h>
#endif

#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace Guardian {

/**
 * @brief Windows Service base class
 * 
 * Inherit from this class to implement a Windows service.
 * Override OnStart(), OnStop(), etc. to handle service events.
 * 
 * Usage:
 * @code
 * class MyService : public WindowsService {
 * public:
 *     void OnStart(DWORD argc, LPWSTR* argv) override {
 *         // Service start logic
 *     }
 *     void OnStop() override {
 *         // Service stop logic
 *     }
 * };
 * 
 * // In main():
 * MyService service(L"MyService", L"My Service Display Name", 
 *                   SERVICE_AUTO_START, SERVICE_ACCEPT_STOP);
 * return service.Run(argc, argv);
 * @endcode
 */
class WindowsService {
public:
    /**
     * @brief Service state enumeration
     */
    enum class State {
        Stopped = SERVICE_STOPPED,
        StartPending = SERVICE_START_PENDING,
        StopPending = SERVICE_STOP_PENDING,
        Running = SERVICE_RUNNING,
        ContinuePending = SERVICE_CONTINUE_PENDING,
        PausePending = SERVICE_PAUSE_PENDING,
        Paused = SERVICE_PAUSED
    };
    
    /**
     * @brief Construct a new Windows Service
     * @param serviceName Service name (internal identifier)
     * @param displayName Display name (shown in services.msc)
     * @param startType Service start type (SERVICE_AUTO_START, etc.)
     * @param acceptedControls Accepted control codes
     */
    WindowsService(
        const std::wstring& serviceName,
        const std::wstring& displayName,
        DWORD startType = SERVICE_AUTO_START,
        DWORD acceptedControls = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    );
    
    virtual ~WindowsService();
    
    // Non-copyable
    WindowsService(const WindowsService&) = delete;
    WindowsService& operator=(const WindowsService&) = delete;
    
    /**
     * @brief Run the service
     * 
     * This method should be called from main().
     * It handles service registration and dispatching.
     * 
     * @param argc Argument count
     * @param argv Argument values
     * @return Service exit code
     */
    int Run(int argc, wchar_t* argv[]);
    
    /**
     * @brief Install the service
     * @return true if successful
     */
    bool Install();
    
    /**
     * @brief Uninstall the service
     * @return true if successful
     */
    bool Uninstall();
    
    /**
     * @brief Start the service
     * @return true if successful
     */
    bool Start();
    
    /**
     * @brief Stop the service
     * @return true if successful
     */
    bool Stop();
    
    /**
     * @brief Get service name
     */
    const std::wstring& GetName() const { return m_serviceName; }
    
    /**
     * @brief Get current state
     */
    State GetState() const { return m_state; }
    
    /**
     * @brief Check if service is running
     */
    bool IsRunning() const { return m_state == State::Running; }

protected:
    // ========================================
    // Virtual event handlers (override these)
    // ========================================
    
    /**
     * @brief Called when service starts
     * @param argc Argument count
     * @param argv Argument values
     */
    virtual void OnStart(DWORD argc, LPWSTR* argv);
    
    /**
     * @brief Called when service stops
     */
    virtual void OnStop();
    
    /**
     * @brief Called when service pauses
     */
    virtual void OnPause();
    
    /**
     * @brief Called when service continues from pause
     */
    virtual void OnContinue();
    
    /**
     * @brief Called when system is shutting down
     */
    virtual void OnShutdown();
    
    /**
     * @brief Called for custom control codes
     * @param controlCode Control code (128-255 for user-defined)
     */
    virtual void OnCustomControl(DWORD controlCode);
    
    // ========================================
    // Service control methods
    // ========================================
    
    /**
     * @brief Report status to SCM
     */
    void ReportStatus(State state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0);
    
    /**
     * @brief Set service status
     */
    void SetStatus(State state);
    
    /**
     * @brief Log message to Windows event log
     */
    void LogEvent(WORD eventType, const std::wstring& message);
    
    /**
     * @brief Get service handle
     */
    SERVICE_STATUS_HANDLE GetStatusHandle() const { return m_statusHandle; }

private:
    // Static callback for SCM
    static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    static void WINAPI ServiceControlHandler(DWORD controlCode);
    
    // Internal initialization
    void InitServiceControlHandler();
    void ServiceMainImpl(DWORD argc, LPWSTR* argv);
    
    // Singleton instance for callbacks
    static WindowsService* s_instance;
    static std::mutex s_instanceMutex;
    
    std::wstring m_serviceName;
    std::wstring m_displayName;
    DWORD m_startType;
    DWORD m_acceptedControls;
    
    SERVICE_STATUS_HANDLE m_statusHandle;
    SERVICE_STATUS m_status;
    State m_state;
    
    std::atomic<bool> m_stopping;
    std::mutex m_mutex;
    std::condition_variable m_stopCondition;
    
    HANDLE m_stopEvent;
    HANDLE m_pauseEvent;
};

// ============================================
// Service Installer Utilities
// ============================================

/**
 * @brief Service installation utilities
 */
class ServiceInstaller {
public:
    /**
     * @brief Install a service
     * @param serviceName Service name
     * @param displayName Display name
     * @param binaryPath Path to service executable
     * @param startType Start type
     * @param dependencies Dependencies (semicolon-separated)
     * @param account Account name (NULL for LocalSystem)
     * @param password Account password
     * @return true if successful
     */
    static bool Install(
        const std::wstring& serviceName,
        const std::wstring& displayName,
        const std::wstring& binaryPath,
        DWORD startType = SERVICE_AUTO_START,
        const std::wstring& dependencies = L"",
        const std::wstring& account = L"",
        const std::wstring& password = L""
    );
    
    /**
     * @brief Uninstall a service
     * @param serviceName Service name
     * @return true if successful
     */
    static bool Uninstall(const std::wstring& serviceName);
    
    /**
     * @brief Check if service is installed
     */
    static bool IsInstalled(const std::wstring& serviceName);
    
    /**
     * @brief Check if service is running
     */
    static bool IsRunning(const std::wstring& serviceName);
    
    /**
     * @brief Start a service
     */
    static bool Start(const std::wstring& serviceName);
    
    /**
     * @brief Stop a service
     */
    static bool Stop(const std::wstring& serviceName);
};

} // namespace Guardian
