/**
 * @file guardian_c.cpp
 * @brief GuardianC implementation - User-Mode UI Node
 *
 * Provides system tray, notifications, and lock screen.
 * ETW collection has been moved to GuardianA (SYSTEM service).
 */

#include "guardian_c.h"
#include <cstring>
#include <fstream>
#include <vector>
#include <functional>
#include <psapi.h>
#include <bcrypt.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Comctl32.lib")

namespace Guardian {

HHOOK GuardianC::s_keyboardHook = nullptr;

// ============================================
// Constructor / Destructor
// ============================================

GuardianC::GuardianC()
    : m_hWnd(nullptr)
    , m_hLockWnd(nullptr)
    , m_hLockPwdEdit(nullptr)
    , m_hLockBtn(nullptr)
    , m_hInstance(GetModuleHandle(nullptr))
    , m_trayInitialized(false)
    , m_lockScreenActive(false)
    , m_running(false)
    , m_guardianAAlive(false)
    , m_guardianBAlive(false)
    , m_sequence(0)
    , m_currentStatus(TrayStatus::DISCONNECTED)
{
    memset(&m_nid, 0, sizeof(m_nid));
    m_lastGuardianABeat = std::chrono::steady_clock::now();
    m_lastGuardianBBeat = std::chrono::steady_clock::now();
}

GuardianC::~GuardianC() {
    m_running = false;
    CleanupSystemTray();

    if (m_singleInstanceMutex) {
        ReleaseMutex(m_singleInstanceMutex);
        CloseHandle(m_singleInstanceMutex);
        m_singleInstanceMutex = nullptr;
    }

    if (m_heartbeatThread.joinable()) m_heartbeatThread.join();

    HideLockScreen();

    if (m_hWnd) {
        DestroyWindow(m_hWnd);
        m_hWnd = nullptr;
    }
}

// ============================================
// Auto-Start Management
// ============================================

bool GuardianC::InstallAutoStart() {
    // MSI installer writes HKLM\...\Run\WindowsMonitor; this manual path
    // uses HKCU for non-elevated hand-installs. Both are cleaned on uninstall.
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);

    if (result != ERROR_SUCCESS) return false;

    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    std::wstring value = std::wstring(L"\"") + exePath + L"\" --silent";

    result = RegSetValueExW(
        hKey, L"GuardianC", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

bool GuardianC::UninstallAutoStart() {
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);

    if (result != ERROR_SUCCESS) return false;

    result = RegDeleteValueW(hKey, L"GuardianC");
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

bool GuardianC::IsAutoStartInstalled() {
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_QUERY_VALUE, &hKey);

    if (result != ERROR_SUCCESS) return false;

    result = RegQueryValueExW(hKey, L"GuardianC", nullptr, nullptr, nullptr, nullptr);
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

// ============================================
// Main Run Loop
// ============================================

int GuardianC::Run() {
    m_singleInstanceMutex = CreateMutexW(nullptr, TRUE,
                                          L"Global\\GuardianC_SingleInstance");
    if (m_singleInstanceMutex == nullptr || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (m_singleInstanceMutex) {
            CloseHandle(m_singleInstanceMutex);
            m_singleInstanceMutex = nullptr;
        }
        return 0;
    }

    if (!Initialize()) {
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_PROCESS_NOTIFICATIONS) {
            ProcessPendingNotifications();
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    m_running = false;
    return static_cast<int>(msg.wParam);
}

// ============================================
// Initialization
// ============================================

bool GuardianC::Initialize() {
    if (!LoadConfiguration()) {
        return false;
    }

    InitializeLogger();

    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = L"GuardianCWindowClass";
    if (!RegisterClassExW(&wc)) {
        return false;
    }

    // Create hidden message-only window
    m_hWnd = CreateWindowExW(
        0, L"GuardianCWindowClass", L"GuardianC",
        0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, m_hInstance, nullptr);

    if (!m_hWnd) {
        return false;
    }

    SetWindowLongPtrW(m_hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

    InitializeSystemTray();

    if (!InitializeIPC()) {
        // IPC failure is non-fatal; run in degraded mode
    }

    m_running = true;
    m_heartbeatThread = std::thread(&GuardianC::HeartbeatThread, this);

    UpdateTrayIcon(TrayStatus::NORMAL);

    if (g_logger) {
        g_logger->Log(LogLevel::INFO, "GuardianC initialized successfully");
    }

    return true;
}

bool GuardianC::LoadConfiguration() {
    m_config = std::make_shared<Config>(
        L"C:\\ProgramData\\GuardianShield\\config\\guardian_config.yaml");
    return m_config->Load();
}

bool GuardianC::InitializeIPC() {
    m_ipcManager = std::make_unique<IpcManager>(NodeId::GUARDIAN_C);
    if (!m_ipcManager->Initialize()) {
        return false;
    }

    m_ipcManager->SetMessageHandler(
        [this](const MessageHeader& header, const uint8_t* payload, size_t size) {
            HandleGuardianMessage(header, payload, size);
        });

    return true;
}

bool GuardianC::InitializeLogger() {
    try {
        std::wstring logDir = m_config->GetLogPath();
        if (logDir.empty()) {
            logDir = L"C:\\ProgramData\\GuardianShield\\logs";
        }
        std::wstring logPath = logDir + L"\\guardian_c";

        int retentionDays = m_config->GetLogRetentionDays();
        if (retentionDays == 0) retentionDays = 7;

        LogFormat format = LogFormat::JSON;
        std::string logFormat = m_config->GetLogFormat();
        if (logFormat == "text") format = LogFormat::TEXT;

        g_logger = std::make_shared<Logger>(logPath, LogLevel::INFO,
                                            format, retentionDays);
        g_logger->SetConsoleOutput(false);
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================
// System Tray
// ============================================

bool GuardianC::InitializeSystemTray() {
    memset(&m_nid, 0, sizeof(m_nid));
    m_nid.cbSize = sizeof(NOTIFYICONDATAW);
    m_nid.hWnd = m_hWnd;
    m_nid.uID = 1;
    m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    m_nid.uCallbackMessage = WM_TRAYICON;
    m_nid.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    wcscpy_s(m_nid.szTip, L"\x7CFB\x7EDF\x9632\x62A4 - \x8FD0\x884C\x4E2D");
    m_trayInitialized = Shell_NotifyIconW(NIM_ADD, &m_nid) != FALSE;
    if (m_trayInitialized) {
        m_nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &m_nid);
    }
    return m_trayInitialized;
}

void GuardianC::CleanupSystemTray() {
    if (m_trayInitialized) {
        Shell_NotifyIconW(NIM_DELETE, &m_nid);
        m_trayInitialized = false;
    }
}

void GuardianC::UpdateTrayIcon(TrayStatus status) {
    m_currentStatus = status;
    if (status == TrayStatus::ALERT) {
        auto now = std::chrono::steady_clock::now();
        m_lastAlertTimeMs.store(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count(),
            std::memory_order_relaxed);
    }
    if (!m_trayInitialized) return;
    m_nid.uFlags = NIF_TIP | NIF_ICON;
    switch (status) {
        case TrayStatus::NORMAL:
            wcscpy_s(m_nid.szTip, L"\x7CFB\x7EDF\x9632\x62A4 - \x5DF2\x4FDD\x62A4");
            m_nid.hIcon = LoadIconW(nullptr, IDI_SHIELD);
            break;
        case TrayStatus::ALERT:
            wcscpy_s(m_nid.szTip, L"\x7CFB\x7EDF\x9632\x62A4 - \x8B66\x62A5");
            m_nid.hIcon = LoadIconW(nullptr, IDI_WARNING);
            break;
        case TrayStatus::LOCKED:
            wcscpy_s(m_nid.szTip, L"\x7CFB\x7EDF\x9632\x62A4 - \x5DF2\x9501\x5B9A");
            m_nid.hIcon = LoadIconW(nullptr, IDI_ERROR);
            break;
        default:
            wcscpy_s(m_nid.szTip, L"\x7CFB\x7EDF\x9632\x62A4 - \x8FD0\x884C\x4E2D");
            m_nid.hIcon = LoadIconW(nullptr, IDI_SHIELD);
            break;
    }
    Shell_NotifyIconW(NIM_MODIFY, &m_nid);
}

void GuardianC::ShowBalloonNotification(const std::wstring& title,
                                         const std::wstring& message,
                                         DWORD flags) {
    if (!m_trayInitialized) {
        if (g_logger) g_logger->Warn("ShowBalloonNotification skipped: tray not initialized (Session 0?)");
        return;
    }
    m_nid.uFlags = NIF_INFO;
    m_nid.dwInfoFlags = flags;
    wcsncpy_s(m_nid.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(m_nid.szInfo, message.c_str(), _TRUNCATE);
    BOOL ok = Shell_NotifyIconW(NIM_MODIFY, &m_nid);
    if (g_logger) {
        int len = WideCharToMultiByte(CP_UTF8, 0, title.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string narrowTitle(len > 0 ? len - 1 : 0, '\0');
        if (len > 0) WideCharToMultiByte(CP_UTF8, 0, title.c_str(), -1, &narrowTitle[0], len, nullptr, nullptr);
        g_logger->Info("ShowBalloonNotification: result=%s title=[%s]",
                       ok ? "OK" : "FAIL", narrowTitle.c_str());
    }
    if (flags != NIIF_INFO) {
        MessageBeep(flags == NIIF_ERROR ? MB_ICONERROR : MB_ICONWARNING);
    }
}

void GuardianC::ShowContextMenu() {
    if (!m_hWnd) return;
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu) return;
    AppendMenuW(hMenu, MF_STRING, IDM_STATUS, L"\x72B6\x6001: \x8FD0\x884C\x4E2D");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, IDM_FILEMANAGER, L"\x6587\x4EF6\x7BA1\x7406");
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(m_hWnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, m_hWnd, nullptr);
    DestroyMenu(hMenu);
}

// ============================================
// Window Procedure
// ============================================

LRESULT CALLBACK GuardianC::WindowProc(HWND hwnd, UINT msg,
                                        WPARAM wParam, LPARAM lParam) {
    GuardianC* self = reinterpret_cast<GuardianC*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {
        case WM_TRAYICON:
            if (self) {
                self->HandleTrayMessage(wParam, lParam);
            }
            return 0;

        case WM_COMMAND:
        {
            switch (LOWORD(wParam)) {
                case IDM_STATUS:
                    self->QueueNotification(L"\x7CFB\x7EDF\x72B6\x6001",
                        self->m_guardianAAlive && self->m_guardianBAlive ?
                            L"\x6240\x6709\x670D\x52A1\x8FD0\x884C\x6B63\x5E38" : L"\x670D\x52A1\x72B6\x6001\x5F02\x5E38",
                        NIIF_INFO);
                    break;
                case IDM_EXIT:
                    PostQuitMessage(0);
                    break;
                case IDM_FILEMANAGER:
                    if (self) self->ShowFileManager();
                    break;
            }
            return 0;
        }

        case WM_DECRYPT_RESULT:
        {
            auto* resp = reinterpret_cast<DecryptResponsePayload*>(wParam);
            if (self && resp) self->HandleDecryptResponse(resp);
            delete resp;
            return 0;
        }

        case WM_PROCESS_NOTIFICATIONS:
            if (self) {
                self->ProcessPendingNotifications();
            }
            return 0;

        case WM_SHOW_LOCKSCREEN:
            if (self) {
                self->ShowLockScreen();
            }
            return 0;

        case WM_HIDE_LOCKSCREEN:
            if (self) {
                self->HideLockScreen();
            }
            return 0;

        case WM_UPDATE_TRAYSTATUS:
            if (self) {
                self->UpdateTrayIcon(static_cast<TrayStatus>(wParam));
            }
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void GuardianC::HandleTrayMessage(WPARAM wParam, LPARAM lParam) {
    switch (LOWORD(lParam)) {
        case WM_LBUTTONDBLCLK:
            QueueNotification(L"\x7CFB\x7EDF\x72B6\x6001",
                m_guardianAAlive && m_guardianBAlive ? 
                    L"\x6240\x6709\x670D\x52A1\x8FD0\x884C\x6B63\x5E38" : L"\x670D\x52A1\x72B6\x6001\x5F02\x5E38\xFF0C\x8BF7\x68C0\x67E5\x65E5\x5FD7",
                NIIF_INFO);
            break;
        case WM_RBUTTONUP:
            ShowContextMenu();
            break;
    }
}

// ============================================
// Heartbeat & Service Monitoring
// ============================================

void GuardianC::HeartbeatThread() {
    while (m_running) {
        SendHeartbeat();
        CheckServiceHealth();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void GuardianC::SendHeartbeat() {
    if (!m_ipcManager) return;

    HeartbeatPayload payload = {};
    payload.process_id = GetCurrentProcessId();
    payload.uptime = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    payload.status = 0;
    payload.nonce = m_sequence++;

    PROCESS_MEMORY_COUNTERS pmc = {};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        payload.memory_usage = pmc.WorkingSetSize;
    }

    m_ipcManager->UpdateHeartbeat(payload);
    m_ipcManager->Broadcast(MessageType::HEARTBEAT, &payload, sizeof(payload));
}

void GuardianC::CheckServiceHealth() {
    if (!m_ipcManager) return;

    auto now = std::chrono::steady_clock::now();

    // Check GuardianA — nonce must be non-zero AND changed since last check
    HeartbeatPayload aPayload = {};
    if (m_ipcManager->GetNodeHeartbeat(NodeId::GUARDIAN_A, aPayload) &&
        aPayload.nonce != 0 && aPayload.nonce != m_lastSeenNonceA) {
        m_lastSeenNonceA = aPayload.nonce;
        m_lastGuardianABeat = now;
        m_guardianAAlive = true;
    } else {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_lastGuardianABeat).count();
        if (elapsed > 2000) {
            if (m_guardianAAlive) {
                m_guardianAAlive = false;
                QueueNotification(
                    L"\x5B89\x5168\x8B66\x544A",
                    L"\x4E3B\x63A7\x670D\x52A1\x65E0\x54CD\x5E94\xFF01",
                    NIIF_WARNING);
            }
        }
    }

    // Check GuardianB — nonce must be non-zero AND changed since last check
    HeartbeatPayload bPayload = {};
    if (m_ipcManager->GetNodeHeartbeat(NodeId::GUARDIAN_B, bPayload) &&
        bPayload.nonce != 0 && bPayload.nonce != m_lastSeenNonceB) {
        m_lastSeenNonceB = bPayload.nonce;
        m_lastGuardianBBeat = now;
        m_guardianBAlive = true;
    } else {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_lastGuardianBBeat).count();
        if (elapsed > 2000) {
            if (m_guardianBAlive) {
                m_guardianBAlive = false;
                QueueNotification(
                    L"\x5B89\x5168\x8B66\x544A",
                    L"\x5907\x4EFD\x670D\x52A1\x65E0\x54CD\x5E94\xFF01",
                    NIIF_WARNING);
            }
        }
    }

    // Update tray icon based on health (via PostMessage for thread safety)
    if (!m_guardianAAlive && !m_guardianBAlive) {
        if (m_currentStatus != TrayStatus::DISCONNECTED) {
            PostMessage(m_hWnd, WM_UPDATE_TRAYSTATUS, 
                        static_cast<WPARAM>(TrayStatus::DISCONNECTED), 0);
        }
    } else if (m_currentStatus == TrayStatus::DISCONNECTED) {
        PostMessage(m_hWnd, WM_UPDATE_TRAYSTATUS,
                    static_cast<WPARAM>(TrayStatus::NORMAL), 0);
    }

    if (m_currentStatus == TrayStatus::ALERT &&
        m_guardianAAlive && m_guardianBAlive) {
        int64_t lastMs = m_lastAlertTimeMs.load(std::memory_order_relaxed);
        if (lastMs > 0) {
            auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();
            if (nowMs - lastMs > 120000) {
                PostMessage(m_hWnd, WM_UPDATE_TRAYSTATUS,
                            static_cast<WPARAM>(TrayStatus::NORMAL), 0);
                m_lastAlertTimeMs.store(0, std::memory_order_relaxed);
            }
        }
    }
}

// ============================================
// IPC Message Handling
// ============================================

void GuardianC::HandleGuardianMessage(const MessageHeader& header,
                                       const uint8_t* payload,
                                       size_t payloadSize) {
    MessageType type = static_cast<MessageType>(header.type);

    switch (type) {
        case MessageType::HEARTBEAT:
            if (static_cast<NodeId>(header.source) == NodeId::GUARDIAN_A) {
                if (!m_guardianAAlive && g_logger) {
                    g_logger->Info("First heartbeat received from GuardianA");
                }
                m_lastGuardianABeat = std::chrono::steady_clock::now();
                m_guardianAAlive = true;
            } else if (static_cast<NodeId>(header.source) == NodeId::GUARDIAN_B) {
                if (!m_guardianBAlive && g_logger) {
                    g_logger->Info("First heartbeat received from GuardianB");
                }
                m_lastGuardianBBeat = std::chrono::steady_clock::now();
                m_guardianBAlive = true;
            }
            break;

        case MessageType::ALERT:
            if (payloadSize >= sizeof(AlertPayload)) {
                auto* alert = reinterpret_cast<const AlertPayload*>(payload);
                ThreatLevel level = static_cast<ThreatLevel>(alert->level);

                DWORD flags = NIIF_INFO;
                if (level == ThreatLevel::LEVEL_2) flags = NIIF_WARNING;
                if (level == ThreatLevel::LEVEL_3) flags = NIIF_ERROR;

                std::wstring msg =
                    L"\x5A01\x80C1\x7B49\x7EA7: " +
                    std::wstring(
                        ThreatLevelToString(level),
                        ThreatLevelToString(level) + strlen(ThreatLevelToString(level)));

                QueueNotification(L"\x5B89\x5168\x8B66\x62A5", msg, flags);

                if (level >= ThreatLevel::LEVEL_2) {
                    UpdateTrayIcon(TrayStatus::ALERT);
                }
            } else {
                QueueNotification(
                    L"\x5B89\x5168\x8B66\x62A5",
                    L"\x6536\x5230\x5B89\x5168\x670D\x52A1\x544A\x8B66\x3002",
                    NIIF_WARNING);
                UpdateTrayIcon(TrayStatus::ALERT);
            }
            break;

        case MessageType::EMERGENCY_PREPARE:
            QueueNotification(
                L"\x7D27\x6025\x8B66\x62A5",
                L"\x7D27\x6025\x534F\x8BAE\x51C6\x5907\x4E2D\xFF0C\x8BF7\x7B49\x5F85\x3002",
                NIIF_ERROR);
            UpdateTrayIcon(TrayStatus::ALERT);
            break;

        case MessageType::EMERGENCY_TRIGGER:
            UpdateTrayIcon(TrayStatus::LOCKED);
            if (m_hWnd) {
                PostMessage(m_hWnd, WM_SHOW_LOCKSCREEN, 0, 0);
            }
            break;

        case MessageType::ALERT_NOTIFICATION:
            if (payloadSize >= sizeof(AlertNotification)) {
                auto* notif = reinterpret_cast<const AlertNotification*>(payload);
                ThreatLevel tl = static_cast<ThreatLevel>(notif->level);

                if (g_logger) {
                    g_logger->Info("ALERT_NOTIFICATION received: level=%d PID=%u msg=[%.64s]",
                                   notif->level, notif->process_id, notif->message);
                }

                DWORD nFlags = NIIF_INFO;
                if (tl >= ThreatLevel::LEVEL_2) nFlags = NIIF_WARNING;
                if (tl >= ThreatLevel::LEVEL_3) nFlags = NIIF_ERROR;

                int msgLen = (int)strnlen(notif->message, sizeof(notif->message));
                int wMsgLen = MultiByteToWideChar(CP_UTF8, 0, notif->message, msgLen, nullptr, 0);
                std::wstring wMsg(wMsgLen, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, notif->message, msgLen, &wMsg[0], wMsgLen);

                if (notif->file_path[0] != L'\0') {
                    const wchar_t* slash = wcsrchr(notif->file_path, L'\\');
                    wMsg += L"\n";
                    wMsg += slash ? (slash + 1) : notif->file_path;
                }

                wMsg += L"\n\x2192 \x53F3\x952E\x6258\x76D8 \x2192 \x6587\x4EF6\x7BA1\x7406";
                QueueNotification(L"\x5B89\x5168\x8B66\x62A5", wMsg, nFlags);

                if (tl >= ThreatLevel::LEVEL_2) {
                    UpdateTrayIcon(TrayStatus::ALERT);
                }
            }
            break;

        case MessageType::COMMAND:
            if (payloadSize > 0) {
                uint8_t cmd = payload[0];
                if (cmd == 0x01) { // Lock command
                    PostMessage(m_hWnd, WM_SHOW_LOCKSCREEN, 0, 0);
                } else if (cmd == 0x02) { // Unlock command
                    PostMessage(m_hWnd, WM_HIDE_LOCKSCREEN, 0, 0);
                }
            }
            break;

        case MessageType::STATE_SYNC:
            if (payloadSize >= sizeof(EmergencyState)) {
                EmergencyState state = *reinterpret_cast<const EmergencyState*>(payload);
                if (state == EmergencyState::LOCKED || state == EmergencyState::ENCRYPTING) {
                    if (!m_lockScreenActive) {
                        PostMessage(m_hWnd, WM_SHOW_LOCKSCREEN, 0, 0);
                    }
                } else if (state == EmergencyState::NORMAL) {
                    if (m_currentStatus == TrayStatus::ALERT) {
                        PostMessage(m_hWnd, WM_UPDATE_TRAYSTATUS,
                            static_cast<WPARAM>(TrayStatus::NORMAL), 0);
                    }
                }
            }
            break;

        case MessageType::DECRYPT_RESPONSE:
            if (payloadSize >= sizeof(DecryptResponsePayload)) {
                auto* resp = reinterpret_cast<const DecryptResponsePayload*>(payload);
                auto* copy = new DecryptResponsePayload(*resp);
                if (m_hWnd) {
                    PostMessage(m_hWnd, WM_DECRYPT_RESULT,
                                reinterpret_cast<WPARAM>(copy), 0);
                } else {
                    delete copy;
                }
            }
            break;

        default:
            break;
    }
}

// ============================================
// Notification Queue
// ============================================

void GuardianC::QueueNotification(const std::wstring& title,
                                   const std::wstring& message,
                                   DWORD flags) {
    {
        std::lock_guard<std::mutex> lock(m_notifyMutex);
        if (m_notifyQueue.size() >= 100) return;
        m_notifyQueue.push({title, message, flags});
    }

    if (m_hWnd) {
        PostMessage(m_hWnd, WM_PROCESS_NOTIFICATIONS, 0, 0);
    }
}

void GuardianC::ProcessPendingNotifications() {
    std::lock_guard<std::mutex> lock(m_notifyMutex);
    while (!m_notifyQueue.empty()) {
        auto& notif = m_notifyQueue.front();
        ShowBalloonNotification(notif.title, notif.message, notif.infoFlags);
        m_notifyQueue.pop();
    }
}

// ============================================
// Lock Screen Implementation
// ============================================

static HFONT CreateLockFont(int height, bool bold = false)
{
    return CreateFontW(
        height, 0, 0, 0,
        bold ? FW_BOLD : FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Microsoft YaHei");
}

LRESULT CALLBACK GuardianC::LockWindowProc(HWND hwnd, UINT msg,
                                            WPARAM wParam, LPARAM lParam)
{
    GuardianC* self = reinterpret_cast<GuardianC*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {
        case WM_CREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            SetTimer(hwnd, 1, 500, nullptr);
            return 0;
        }

        case WM_TIMER:
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            SetForegroundWindow(hwnd);
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            RECT rc;
            GetClientRect(hwnd, &rc);

            HBRUSH bgBrush = CreateSolidBrush(RGB(20, 20, 40));
            FillRect(hdc, &rc, bgBrush);
            DeleteObject(bgBrush);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(220, 50, 50));

            HFONT hTitleFont = CreateLockFont(72, true);
            HFONT hOld = (HFONT)SelectObject(hdc, hTitleFont);

            RECT titleRc = { rc.left, rc.top + rc.bottom / 6,
                             rc.right, rc.top + rc.bottom / 6 + 100 };
            DrawTextW(hdc, L"\x26A0 \u7CFB\u7EDF\u5DF2\u9501\u5B9A", -1,
                      &titleRc, DT_CENTER | DT_SINGLELINE);
            SelectObject(hdc, hOld);
            DeleteObject(hTitleFont);

            SetTextColor(hdc, RGB(200, 200, 200));
            HFONT hMsgFont = CreateLockFont(28);
            hOld = (HFONT)SelectObject(hdc, hMsgFont);

            RECT msgRc = { rc.left + 100, titleRc.bottom + 30,
                           rc.right - 100, titleRc.bottom + 200 };
            DrawTextW(hdc,
                L"\u68C0\u6D4B\u5230\u5B89\u5168\u5A01\u80C1\uFF0C\u7CFB\u7EDF\u5DF2\u8FDB\u5165\u4FDD\u62A4\u6A21\u5F0F\u3002\r\n"
                L"\u6240\u6709\u53D7\u4FDD\u62A4\u6587\u4EF6\u5DF2\u88AB\u9501\u5B9A\u3002\r\n"
                L"\u8BF7\u8F93\u5165\u7BA1\u7406\u5458\u5BC6\u7801\u4EE5\u89E3\u9501\u7CFB\u7EDF\u3002",
                -1, &msgRc, DT_CENTER | DT_WORDBREAK);

            SelectObject(hdc, hOld);
            DeleteObject(hMsgFont);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_COMMAND:
            if (self && LOWORD(wParam) == IDC_LOCK_UNLOCK_BTN) {
                wchar_t pwd[256] = {};
                GetWindowTextW(self->m_hLockPwdEdit, pwd, 255);
                if (self->VerifyUnlockPassword(pwd)) {
                    self->HideLockScreen();
                } else {
                    SetWindowTextW(self->m_hLockPwdEdit, L"");
                    MessageBeep(MB_ICONERROR);
                }
                SecureZeroMemory(pwd, sizeof(pwd));
            }
            return 0;

        case WM_CLOSE:
            return 0;

        case WM_SYSCOMMAND:
            return 0;  // Block all system commands on lock screen

        case WM_SYSKEYDOWN:
            return 0;  // Block all Alt+key combinations

        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE || wParam == VK_F4)
                return 0;
            break;

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GuardianC::LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* kbd = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        if (kbd->vkCode == VK_TAB && (kbd->flags & LLKHF_ALTDOWN))
            return 1;
        if (kbd->vkCode == VK_ESCAPE && (kbd->flags & LLKHF_ALTDOWN))
            return 1;
        if (kbd->vkCode == VK_LWIN || kbd->vkCode == VK_RWIN)
            return 1;
        if (kbd->vkCode == VK_ESCAPE && (GetAsyncKeyState(VK_CONTROL) & 0x8000))
            return 1;
        if (kbd->vkCode == VK_F4 && (kbd->flags & LLKHF_ALTDOWN))
            return 1;
        if (kbd->vkCode == VK_DELETE && (GetAsyncKeyState(VK_CONTROL) & 0x8000) 
            && (GetAsyncKeyState(VK_MENU) & 0x8000))
            return 1;
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

bool GuardianC::ShowLockScreen()
{
    if (m_lockScreenActive)
        return true;

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = LockWindowProc;
    wc.hInstance = m_hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(20, 20, 40));
    wc.lpszClassName = L"GuardianLockWindowClass";
    RegisterClassExW(&wc);

    int screenW = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int screenH = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int screenX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int screenY = GetSystemMetrics(SM_YVIRTUALSCREEN);

    m_hLockWnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"GuardianLockWindowClass",
        L"\x7CFB\x7EDF\x9632\x62A4 - \x7CFB\x7EDF\x5DF2\x9501\x5B9A",
        WS_POPUP | WS_VISIBLE,
        screenX, screenY, screenW, screenH,
        nullptr, nullptr, m_hInstance, this);

    if (!m_hLockWnd)
        return false;

    int cx = screenW / 2;
    int cy = screenH / 2 + 80;

    HFONT hFont = CreateLockFont(22);

    HWND hLabel = CreateWindowExW(0, L"STATIC",
        L"\u8BF7\u8F93\u5165\u7BA1\u7406\u5458\u5BC6\u7801\uFF1A",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        cx - 200, cy, 400, 30,
        m_hLockWnd, nullptr, m_hInstance, nullptr);
    SendMessage(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);

    m_hLockPwdEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_CENTER | ES_AUTOHSCROLL,
        cx - 180, cy + 40, 360, 36,
        m_hLockWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOCK_PASSWORD)),
        m_hInstance, nullptr);
    SendMessage(m_hLockPwdEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    m_hLockBtn = CreateWindowExW(0, L"BUTTON",
        L"\u89E3  \u9501",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_CENTER,
        cx - 80, cy + 90, 160, 40,
        m_hLockWnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LOCK_UNLOCK_BTN)),
        m_hInstance, nullptr);
    SendMessage(m_hLockBtn, WM_SETFONT, (WPARAM)hFont, TRUE);

    SetWindowPos(m_hLockWnd, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE);
    SetForegroundWindow(m_hLockWnd);
    SetFocus(m_hLockPwdEdit);

    s_keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(nullptr), 0);

    m_lockScreenActive = true;
    return true;
}

void GuardianC::HideLockScreen()
{
    if (s_keyboardHook) {
        UnhookWindowsHookEx(s_keyboardHook);
        s_keyboardHook = nullptr;
    }

    if (!m_lockScreenActive || !m_hLockWnd)
        return;

    DestroyWindow(m_hLockWnd);
    m_hLockWnd = nullptr;
    m_hLockPwdEdit = nullptr;
    m_hLockBtn = nullptr;
    m_lockScreenActive = false;

    UnregisterClassW(L"GuardianLockWindowClass", m_hInstance);

    UpdateTrayIcon(TrayStatus::NORMAL);
}

static bool SecureCompare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
    }
    return result == 0;
}

bool GuardianC::VerifyUnlockPassword(const std::wstring& password)
{
    if (password.empty())
        return false;

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string passwordA(sizeNeeded - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, &passwordA[0], sizeNeeded, nullptr, nullptr);

    std::string adminHash;
    if (m_config) {
        adminHash = m_config->GetAdminPasswordHash();
    }

    // Compute SHA-256 of input
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                   nullptr, 0) != 0)
        return false;

    DWORD hashLen = 0, dataLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hashLen),
                      sizeof(hashLen), &dataLen, 0);

    std::vector<BYTE> hashValue(hashLen);
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCryptHashData(hHash,
                   reinterpret_cast<PUCHAR>(const_cast<char*>(passwordA.data())),
                   static_cast<ULONG>(passwordA.size()), 0);
    BCryptFinishHash(hHash, hashValue.data(), hashLen, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    static const char hex[] = "0123456789abcdef";
    std::string computed;
    computed.reserve(hashLen * 2);
    for (DWORD i = 0; i < hashLen; ++i) {
        computed += hex[(hashValue[i] >> 4) & 0xF];
        computed += hex[hashValue[i] & 0xF];
    }

    bool match = false;
    if (!adminHash.empty()) {
        match = (computed.size() == adminHash.size()) &&
                (SecureCompare(computed, adminHash));
    } else {
        match = false;  // No admin password configured - reject all attempts
    }

    if (match && m_ipcManager) {
        m_ipcManager->Broadcast(MessageType::UNLOCK_RESPONSE, nullptr, 0);
    }

    SecureZeroMemory(&passwordA[0], passwordA.size());
    return match;
}

// ============================================
// File Manager Panel
// ============================================

std::string GuardianC::ComputePasswordHash(const std::wstring& password) {
    if (password.empty()) return "";

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string passwordA(sizeNeeded - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, password.c_str(), -1, &passwordA[0], sizeNeeded, nullptr, nullptr);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return "";

    DWORD hashLen = 0, dataLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hashLen),
                      sizeof(hashLen), &dataLen, 0);

    std::vector<BYTE> hashValue(hashLen);
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptHashData(hHash,
                   reinterpret_cast<PUCHAR>(const_cast<char*>(passwordA.data())),
                   static_cast<ULONG>(passwordA.size()), 0);
    BCryptFinishHash(hHash, hashValue.data(), hashLen, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    static const char hex[] = "0123456789abcdef";
    result.reserve(hashLen * 2);
    for (DWORD i = 0; i < hashLen; ++i) {
        result += hex[(hashValue[i] >> 4) & 0xF];
        result += hex[hashValue[i] & 0xF];
    }

    SecureZeroMemory(&passwordA[0], passwordA.size());
    return result;
}

NodeId GuardianC::GetActivePrimaryNode() const {
    if (m_guardianAAlive) return NodeId::GUARDIAN_A;
    if (m_guardianBAlive) return NodeId::GUARDIAN_B;
    return NodeId::UNKNOWN;
}

LRESULT CALLBACK GuardianC::FileManagerProc(HWND hwnd, UINT msg,
                                             WPARAM wParam, LPARAM lParam) {
    GuardianC* self = reinterpret_cast<GuardianC*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (msg) {
        case WM_CREATE:
        {
            auto* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
            self = reinterpret_cast<GuardianC*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));

            self->m_hFileCountLabel = CreateWindowExW(0, L"STATIC",
                L"\x4FDD\x62A4\x76EE\x5F55\x4E2D\x7684\x52A0\x5BC6\x6587\x4EF6 (*.gs):",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                10, 10, 680, 20, hwnd, (HMENU)(LONG_PTR)IDC_FILE_COUNT_LABEL,
                cs->hInstance, nullptr);

            self->m_hFileListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                10, 35, 680, 380, hwnd, (HMENU)(LONG_PTR)IDC_FILE_LISTVIEW,
                cs->hInstance, nullptr);

            ListView_SetExtendedListViewStyle(self->m_hFileListView,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMNW col = {};
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

            col.cx = 200; col.pszText = const_cast<LPWSTR>(L"\x6587\x4EF6\x540D");
            col.iSubItem = 0;
            ListView_InsertColumn(self->m_hFileListView, 0, &col);

            col.cx = 300; col.pszText = const_cast<LPWSTR>(L"\x539F\x59CB\x8DEF\x5F84");
            col.iSubItem = 1;
            ListView_InsertColumn(self->m_hFileListView, 1, &col);

            col.cx = 80; col.pszText = const_cast<LPWSTR>(L"\x6587\x4EF6\x5927\x5C0F");
            col.iSubItem = 2;
            ListView_InsertColumn(self->m_hFileListView, 2, &col);

            col.cx = 90; col.pszText = const_cast<LPWSTR>(L"\x72B6\x6001");
            col.iSubItem = 3;
            ListView_InsertColumn(self->m_hFileListView, 3, &col);

            self->m_hRefreshBtn = CreateWindowExW(0, L"BUTTON",
                L"\x5237\x65B0",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 425, 80, 30, hwnd, (HMENU)(LONG_PTR)IDC_REFRESH_BTN,
                cs->hInstance, nullptr);

            self->m_hUnlockBtn = CreateWindowExW(0, L"BUTTON",
                L"\x4E00\x952E\x89E3\x5BC6",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                100, 425, 120, 30, hwnd, (HMENU)(LONG_PTR)IDC_UNLOCK_ALL_BTN,
                cs->hInstance, nullptr);

            self->PopulateFileList();
            return 0;
        }

        case WM_COMMAND:
            if (self) {
                if (LOWORD(wParam) == IDC_UNLOCK_ALL_BTN)
                    self->RequestDecryptAll();
                else if (LOWORD(wParam) == IDC_REFRESH_BTN)
                    self->PopulateFileList();
            }
            return 0;

        case WM_SIZE:
        {
            if (self && self->m_hFileListView) {
                RECT rc;
                GetClientRect(hwnd, &rc);
                MoveWindow(self->m_hFileListView, 10, 35,
                           rc.right - 20, rc.bottom - 80, TRUE);
                MoveWindow(self->m_hRefreshBtn, 10, rc.bottom - 40, 80, 30, TRUE);
                MoveWindow(self->m_hUnlockBtn, 100, rc.bottom - 40, 120, 30, TRUE);
            }
            return 0;
        }

        case WM_TIMER:
            if (wParam == TIMER_DECRYPT_TIMEOUT && self) {
                KillTimer(hwnd, TIMER_DECRYPT_TIMEOUT);
                if (self->m_hUnlockBtn) {
                    SetWindowTextW(self->m_hUnlockBtn, L"\x4E00\x952E\x89E3\x9501");
                    EnableWindow(self->m_hUnlockBtn, TRUE);
                }
                MessageBoxW(hwnd,
                    L"\x89E3\x5BC6\x64CD\x4F5C\x8D85\x65F6\xFF0C\x8BF7\x68C0\x67E5\x670D\x52A1\x72B6\x6001",
                    L"\x7CFB\x7EDF\x9632\x62A4", MB_OK | MB_ICONWARNING);
            }
            return 0;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            if (self) {
                self->m_hFileManagerWnd = nullptr;
                self->m_hFileListView = nullptr;
                self->m_hUnlockBtn = nullptr;
                self->m_hRefreshBtn = nullptr;
                self->m_hFileCountLabel = nullptr;
            }
            return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void GuardianC::ShowFileManager() {
    if (m_hFileManagerWnd && IsWindow(m_hFileManagerWnd)) {
        SetForegroundWindow(m_hFileManagerWnd);
        PopulateFileList();
        return;
    }

    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    if (!GetClassInfoExW(m_hInstance, L"GuardianFileManagerClass", &wc)) {
        wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = FileManagerProc;
        wc.hInstance = m_hInstance;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"GuardianFileManagerClass";
        wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
        RegisterClassExW(&wc);
    }

    m_hFileManagerWnd = CreateWindowExW(
        0, L"GuardianFileManagerClass",
        L"\x7CFB\x7EDF\x9632\x62A4 \x2014 \x6587\x4EF6\x7BA1\x7406",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 720, 500,
        nullptr, nullptr, m_hInstance, this);

    if (m_hFileManagerWnd) {
        ShowWindow(m_hFileManagerWnd, SW_SHOW);
        UpdateWindow(m_hFileManagerWnd);
    }
}

void GuardianC::PopulateFileList() {
    if (!m_hFileListView) return;

    ListView_DeleteAllItems(m_hFileListView);

    if (!m_config) return;

    auto dirs = m_config->GetProtectedDirectories();
    int itemIndex = 0;
    int encryptedCount = 0;

    for (const auto& dir : dirs) {
        if (GetFileAttributesW(dir.path.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;

        std::function<void(const std::wstring&)> scanDir = [&](const std::wstring& path) {
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW((path + L"\\*").c_str(), &fd);
            if (hFind == INVALID_HANDLE_VALUE) return;

            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                    continue;

                std::wstring fullPath = path + L"\\" + fd.cFileName;

                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (dir.recursive) scanDir(fullPath);
                } else {
                    size_t len = wcslen(fd.cFileName);
                    bool isGsFile = (len > 3 && std::wstring(fd.cFileName + len - 3) == L".gs");

                    if (isGsFile) {
                        LVITEMW item = {};
                        item.mask = LVIF_TEXT;
                        item.iItem = itemIndex;
                        item.iSubItem = 0;
                        item.pszText = fd.cFileName;
                        ListView_InsertItem(m_hFileListView, &item);

                        std::wstring origPath = fullPath.substr(0, fullPath.size() - 3);
                        ListView_SetItemText(m_hFileListView, itemIndex, 1,
                            const_cast<LPWSTR>(origPath.c_str()));

                        ULARGE_INTEGER fileSize;
                        fileSize.LowPart = fd.nFileSizeLow;
                        fileSize.HighPart = fd.nFileSizeHigh;
                        wchar_t sizeBuf[32];
                        if (fileSize.QuadPart >= 1048576)
                            swprintf_s(sizeBuf, L"%.1f MB",
                                fileSize.QuadPart / 1048576.0);
                        else
                            swprintf_s(sizeBuf, L"%.1f KB",
                                fileSize.QuadPart / 1024.0);
                        ListView_SetItemText(m_hFileListView, itemIndex, 2, sizeBuf);

                        ListView_SetItemText(m_hFileListView, itemIndex, 3,
                            const_cast<LPWSTR>(L"\x5DF2\x52A0\x5BC6"));

                        itemIndex++;
                        encryptedCount++;
                    }
                }
            } while (FindNextFileW(hFind, &fd));

            FindClose(hFind);
        };

        scanDir(dir.path);
    }

    if (m_hFileCountLabel) {
        wchar_t buf[128];
        swprintf_s(buf, L"\x52A0\x5BC6\x6587\x4EF6: %d \x4E2A",
            encryptedCount);
        SetWindowTextW(m_hFileCountLabel, buf);
    }
}

static INT_PTR CALLBACK PasswordDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG:
        {
            SetWindowLongPtrW(hDlg, DWLP_USER, lParam);
            SetWindowTextW(hDlg, L"\x7CFB\x7EDF\x9632\x62A4");

            CreateWindowExW(0, L"STATIC",
                L"\x8BF7\x8F93\x5165\x7BA1\x7406\x5458\x5BC6\x7801\xFF1A",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                15, 15, 310, 20, hDlg, nullptr,
                reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hDlg, GWLP_HINSTANCE)), nullptr);

            HWND hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP,
                15, 40, 310, 25, hDlg, (HMENU)101,
                reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hDlg, GWLP_HINSTANCE)), nullptr);

            CreateWindowExW(0, L"BUTTON", L"\x786E\x5B9A",
                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
                145, 80, 80, 28, hDlg, (HMENU)IDOK,
                reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hDlg, GWLP_HINSTANCE)), nullptr);

            CreateWindowExW(0, L"BUTTON", L"\x53D6\x6D88",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
                240, 80, 80, 28, hDlg, (HMENU)IDCANCEL,
                reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(hDlg, GWLP_HINSTANCE)), nullptr);

            SetFocus(hEdit);
            return FALSE;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                wchar_t* buf = reinterpret_cast<wchar_t*>(GetWindowLongPtrW(hDlg, DWLP_USER));
                if (buf) GetDlgItemTextW(hDlg, 101, buf, 256);
                EndDialog(hDlg, IDOK);
                return TRUE;
            }
            if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            break;
        case WM_CLOSE:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

static INT_PTR CreatePasswordDialog(HINSTANCE hInst, HWND hParent, wchar_t* pwdBuf) {
    alignas(4) BYTE buf[256] = {};
    DLGTEMPLATE* pDlg = reinterpret_cast<DLGTEMPLATE*>(buf);
    pDlg->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    pDlg->cdit = 0;
    pDlg->cx = 230;
    pDlg->cy = 80;

    WORD* p = reinterpret_cast<WORD*>(pDlg + 1);
    *p++ = 0; // menu
    *p++ = 0; // class
    const wchar_t* title = L"\x7CFB\x7EDF\x9632\x62A4";
    while (*title) *p++ = *title++;
    *p++ = 0;

    return DialogBoxIndirectParamW(hInst, pDlg, hParent,
                                   PasswordDlgProc, reinterpret_cast<LPARAM>(pwdBuf));
}

void GuardianC::RequestDecryptAll() {
    NodeId primary = GetActivePrimaryNode();
    if (primary == NodeId::UNKNOWN) {
        MessageBoxW(m_hFileManagerWnd,
            L"\x670D\x52A1\x4E0D\x53EF\x7528\xFF0C\x4E3B\x63A7\x670D\x52A1\x548C\x5907\x4EFD\x670D\x52A1\x5747\x672A\x54CD\x5E94",
            L"\x7CFB\x7EDF\x9632\x62A4", MB_OK | MB_ICONERROR);
        return;
    }

    wchar_t pwdBuf[256] = {};
    CreatePasswordDialog(m_hInstance, m_hFileManagerWnd, pwdBuf);

    if (wcslen(pwdBuf) == 0) {
        SecureZeroMemory(pwdBuf, sizeof(pwdBuf));
        return;
    }

    std::wstring password(pwdBuf);
    SecureZeroMemory(pwdBuf, sizeof(pwdBuf));

    std::string hash = ComputePasswordHash(password);
    SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));

    if (hash.empty()) {
        MessageBoxW(m_hFileManagerWnd,
            L"\x5BC6\x7801\x54C8\x5E0C\x8BA1\x7B97\x5931\x8D25",
            L"\x7CFB\x7EDF\x9632\x62A4", MB_OK | MB_ICONERROR);
        return;
    }

    std::string adminHash = m_config ? m_config->GetAdminPasswordHash() : "";
    if (adminHash.empty() || hash.size() != adminHash.size() ||
        !SecureCompare(hash, adminHash)) {
        MessageBoxW(m_hFileManagerWnd,
            L"\x5BC6\x7801\x9519\x8BEF",
            L"\x7CFB\x7EDF\x9632\x62A4", MB_OK | MB_ICONERROR);
        return;
    }

    DecryptRequestPayload req = {};
    strncpy_s(req.password_hash, hash.c_str(), sizeof(req.password_hash) - 1);

    if (m_ipcManager) {
        m_ipcManager->SendToNode(primary, MessageType::DECRYPT_REQUEST,
                                  &req, sizeof(req));
    }

    if (m_hUnlockBtn) {
        SetWindowTextW(m_hUnlockBtn, L"\x89E3\x9501\x4E2D...");
        EnableWindow(m_hUnlockBtn, FALSE);
    }

    if (m_hFileManagerWnd) {
        SetTimer(m_hFileManagerWnd, TIMER_DECRYPT_TIMEOUT, DECRYPT_TIMEOUT_MS, nullptr);
    }
}

void GuardianC::HandleDecryptResponse(const DecryptResponsePayload* resp) {
    if (!resp) return;

    if (m_hFileManagerWnd) {
        KillTimer(m_hFileManagerWnd, TIMER_DECRYPT_TIMEOUT);
    }

    if (m_hUnlockBtn) {
        SetWindowTextW(m_hUnlockBtn, L"\x4E00\x952E\x89E3\x9501");
        EnableWindow(m_hUnlockBtn, TRUE);
    }

    UINT mbType = MB_OK;
    if (resp->success == 1)
        mbType |= MB_ICONINFORMATION;
    else if (resp->success == 2)
        mbType |= MB_ICONWARNING;
    else
        mbType |= MB_ICONERROR;

    MessageBoxW(m_hFileManagerWnd, resp->error_message,
                L"\x7CFB\x7EDF\x9632\x62A4", mbType);

    PopulateFileList();
}

} // namespace Guardian
