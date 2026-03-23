/**
 * @file guardian_c.h
 * @brief GuardianC - User-Mode UI Node
 *
 * The user-mode UI process responsible for:
 * - System tray icon with status display
 * - Desktop balloon notifications for security events
 * - Monitoring GuardianA and GuardianB heartbeat health
 * - Lock screen display on emergency protocol
 * - Auto-start via registry Run key
 *
 * NOTE: ETW event collection has been moved to GuardianA (SYSTEM service).
 */

#pragma once

#include "../../common/include/common_types.h"
#include "../../common/include/ipc.h"
#include "../../common/include/config.h"
#include "../../common/include/logger.h"

#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>
#include <queue>
#include <mutex>

#ifdef _WIN32
#include <Windows.h>
#include <shellapi.h>
#include <commctrl.h>
#endif

namespace Guardian {

/**
 * @brief System tray status indicator
 */
enum class TrayStatus {
    NORMAL,
    ALERT,
    LOCKED,
    DISCONNECTED
};

/**
 * @brief Queued notification for display
 */
struct PendingNotification {
    std::wstring title;
    std::wstring message;
    DWORD infoFlags;   // NIIF_INFO / NIIF_WARNING / NIIF_ERROR
};

/**
 * @brief GuardianC - User-Mode Monitor Application
 *
 * Runs as a background user-mode process (not a service).
 * Provides user interface via system tray and collects ETW events.
 */
class GuardianC {
public:
    GuardianC();
    ~GuardianC();

    GuardianC(const GuardianC&) = delete;
    GuardianC& operator=(const GuardianC&) = delete;

    /**
     * @brief Main application run loop (message pump)
     * @return Exit code
     */
    int Run();

    /**
     * @brief Install auto-start registry entry
     * @return true if successful
     */
    static bool InstallAutoStart();

    /**
     * @brief Remove auto-start registry entry
     * @return true if successful
     */
    static bool UninstallAutoStart();

    /**
     * @brief Check if auto-start is configured
     */
    static bool IsAutoStartInstalled();

private:
    // Initialization
    bool Initialize();
    bool LoadConfiguration();
    bool InitializeIPC();
    bool InitializeLogger();

    // System tray
    bool InitializeSystemTray();
    void CleanupSystemTray();
    void UpdateTrayIcon(TrayStatus status);
    void ShowBalloonNotification(const std::wstring& title,
                                 const std::wstring& message,
                                 DWORD flags = NIIF_INFO);
    void ShowContextMenu();

    // Window message handling
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg,
                                        WPARAM wParam, LPARAM lParam);
    void HandleTrayMessage(WPARAM wParam, LPARAM lParam);

    // Heartbeat & service monitoring
    void HeartbeatThread();
    void SendHeartbeat();
    void CheckServiceHealth();

    // IPC message handling
    void HandleGuardianMessage(const MessageHeader& header,
                               const uint8_t* payload,
                               size_t payloadSize);

    // Lock screen (fullscreen, topmost, unclosable, password-protected)
    bool ShowLockScreen();
    void HideLockScreen();
    bool VerifyUnlockPassword(const std::wstring& password);
    static LRESULT CALLBACK LockWindowProc(HWND hwnd, UINT msg,
                                            WPARAM wParam, LPARAM lParam);

    // File manager panel
    void ShowFileManager();
    void PopulateFileList();
    void RequestDecryptAll();
    NodeId GetActivePrimaryNode() const;
    std::string ComputePasswordHash(const std::wstring& password);
    static LRESULT CALLBACK FileManagerProc(HWND hwnd, UINT msg,
                                             WPARAM wParam, LPARAM lParam);
    void HandleDecryptResponse(const DecryptResponsePayload* resp);

    // Notification processing (dequeued on main thread)
    void ProcessPendingNotifications();
    void QueueNotification(const std::wstring& title,
                           const std::wstring& message,
                           DWORD flags);

private:
    // Win32 window & tray
    HWND m_hWnd;
    HWND m_hLockWnd;      // Lock screen window handle
    HWND m_hLockPwdEdit;  // Password edit control inside lock window
    HWND m_hLockBtn;      // Unlock button inside lock window
    HINSTANCE m_hInstance;
    NOTIFYICONDATAW m_nid;
    bool m_trayInitialized;
    std::atomic<bool> m_lockScreenActive;

    // Configuration & logging
    std::shared_ptr<Config> m_config;

    // IPC
    std::unique_ptr<IpcManager> m_ipcManager;

    // Worker threads
    std::thread m_heartbeatThread;
    std::atomic<bool> m_running;

    // Service health tracking
    std::atomic<bool> m_guardianAAlive;
    std::atomic<bool> m_guardianBAlive;
    std::chrono::steady_clock::time_point m_lastGuardianABeat;
    std::chrono::steady_clock::time_point m_lastGuardianBBeat;
    uint32_t m_lastSeenNonceA = 0;
    uint32_t m_lastSeenNonceB = 0;
    std::mutex m_healthMutex;

    // Notification queue (thread-safe, consumed on message thread)
    std::mutex m_notifyMutex;
    std::queue<PendingNotification> m_notifyQueue;

    // Sequence
    std::atomic<uint32_t> m_sequence;

    // Tray status
    TrayStatus m_currentStatus;
    std::atomic<int64_t> m_lastAlertTimeMs{0};

    // Single-instance mutex
    HANDLE m_singleInstanceMutex = nullptr;

    // Custom window messages
    static constexpr UINT WM_TRAYICON = WM_USER + 1;
    static constexpr UINT WM_PROCESS_NOTIFICATIONS = WM_USER + 2;
    static constexpr UINT WM_SHOW_LOCKSCREEN = WM_USER + 3;
    static constexpr UINT WM_UPDATE_TRAYSTATUS = WM_USER + 4;
    static constexpr UINT WM_UPDATE_TRAYICON = WM_USER + 200;

    // Lock screen control IDs
    static constexpr int IDC_LOCK_PASSWORD = 2001;
    static constexpr int IDC_LOCK_UNLOCK_BTN = 2002;

    // Context menu IDs
    static constexpr UINT IDM_STATUS = 1001;
    static constexpr UINT IDM_VIEWLOG = 1002;
    static constexpr UINT IDM_EXIT = 1003;
    static constexpr UINT IDM_FILEMANAGER = 1004;

    // File manager panel
    HWND m_hFileManagerWnd = nullptr;
    HWND m_hFileListView = nullptr;
    HWND m_hUnlockBtn = nullptr;
    HWND m_hRefreshBtn = nullptr;
    HWND m_hFileCountLabel = nullptr;

    static constexpr int IDC_FILE_LISTVIEW = 3001;
    static constexpr int IDC_UNLOCK_ALL_BTN = 3002;
    static constexpr int IDC_FILE_COUNT_LABEL = 3003;
    static constexpr int IDC_REFRESH_BTN = 3004;

    static constexpr UINT WM_HIDE_LOCKSCREEN = WM_USER + 6;
    static constexpr UINT WM_DECRYPT_RESULT = WM_USER + 5;
    static constexpr DWORD DECRYPT_TIMEOUT_MS = 150000;
    static constexpr UINT TIMER_DECRYPT_TIMEOUT = 5001;

    // GDI resources for lock screen
    HFONT m_lockFont = nullptr;
    HBRUSH m_lockBrush = nullptr;

    // Keyboard hook for lock screen
    static HHOOK s_keyboardHook;
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

};

} // namespace Guardian
