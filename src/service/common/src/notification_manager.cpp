/**
 * @file notification_manager.cpp
 * @brief Notification manager implementation
 */

#include "notification_manager.h"
#include "../include/string_utils.h"
#include <Windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

namespace Guardian {

/**
 * @brief System tray warning item
 */
struct SystemTrayWarning {
    std::wstring title;
    std::wstring message;
};

/**
 * @brief System tray warnings
 */
static std::vector<SystemTrayWarning> g_systemTrayWarnings;

NotificationManager::NotificationManager() 
    : m_notificationsEnabled(true),
      m_systemTrayInitialized(false),
      m_hIcon(nullptr) {
    // Initialize NOTIFYICONDATA
    memset(&m_nid, 0, sizeof(m_nid));
    m_nid.cbSize = sizeof(m_nid);
    m_nid.hWnd = nullptr;
    m_nid.uID = 1;
    m_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    m_nid.uCallbackMessage = WM_USER + 1;
    wcscpy_s(m_nid.szTip, L"GuardianShield");
}

NotificationManager::~NotificationManager() {
    // Clean up system tray icon
    if (m_systemTrayInitialized) {
        Shell_NotifyIcon(NIM_DELETE, &m_nid);
    }
    
    // Clean up icon
    if (m_hIcon) {
        DestroyIcon(m_hIcon);
    }
}

bool NotificationManager::Initialize() {
    // Initialize system tray
    if (!InitializeSystemTray()) {
        return false;
    }
    
    return true;
}

bool NotificationManager::ShowDesktopNotification(const std::string& title, 
                                               const std::string& message, 
                                               const std::string& details, 
                                               NotificationType type) {
    if (!m_notificationsEnabled) {
        return false;
    }
    
    // Convert strings to wide strings
    std::wstring wTitle = Utf8ToWide(title);
    std::wstring wMessage = Utf8ToWide(message);
    std::wstring wDetails = Utf8ToWide(details);
    
    return ShowToastNotification(wTitle, wMessage, wDetails, type);
}

bool NotificationManager::AddSystemTrayWarning(const std::string& title, const std::string& message) {
    if (!m_notificationsEnabled) {
        return false;
    }
    
    // Convert strings to wide strings
    std::wstring wTitle = Utf8ToWide(title);
    std::wstring wMessage = Utf8ToWide(message);
    
    // Add warning to list
    SystemTrayWarning warning;
    warning.title = wTitle;
    warning.message = wMessage;
    g_systemTrayWarnings.push_back(warning);
    
    // Update system tray
    return UpdateSystemTray();
}

bool NotificationManager::ClearSystemTrayWarnings() {
    g_systemTrayWarnings.clear();
    return UpdateSystemTray();
}

bool NotificationManager::NotifyThreat(ThreatLevel level, const std::string& message, const DriverEvent* event) {
    if (!m_notificationsEnabled) {
        return false;
    }
    
    // Determine notification type based on threat level
    NotificationType type;
    std::string title;
    
    switch (level) {
    case ThreatLevel::LEVEL_0:
        type = NotificationType::INFO;
        title = "GuardianShield - Information";
        break;
    case ThreatLevel::LEVEL_1:
        type = NotificationType::WARNING;
        title = "GuardianShield - Warning";
        break;
    case ThreatLevel::LEVEL_2:
        type = NotificationType::ERROR_TYPE;
        title = "GuardianShield - Alert";
        break;
    case ThreatLevel::LEVEL_3:
        type = NotificationType::ERROR_TYPE;
        title = "GuardianShield - Critical Alert";
        break;
    default:
        type = NotificationType::INFO;
        title = "GuardianShield";
        break;
    }
    
    // Build details message
    std::string details = message;
    if (event) {
        std::wstring filePath(event->file_path);
        std::wstring processName(event->process_name);
        details += "\nFile: " + WideToUtf8(filePath);
        details += "\nProcess: " + WideToUtf8(processName);
        details += "\nProcess ID: " + std::to_string(event->process_id);
    }
    
    // Show desktop notification
    if (!ShowDesktopNotification(title, message, details, type)) {
        return false;
    }
    
    // Add to system tray if warning or error
    if (level >= ThreatLevel::LEVEL_1) {
        return AddSystemTrayWarning(title, message);
    }
    
    return true;
}

bool NotificationManager::EnableNotifications(bool enable) {
    m_notificationsEnabled = enable;
    return true;
}

bool NotificationManager::IsNotificationsEnabled() const {
    return m_notificationsEnabled;
}

bool NotificationManager::ShowToastNotification(const std::wstring& title, 
                                             const std::wstring& message, 
                                             const std::wstring& details, 
                                             NotificationType type) {
    // Use Windows toast notification API
    // Note: This is a simplified implementation
    // In a real implementation, you would use the Windows Notification Framework
    
    // For demonstration purposes, we'll use the older balloon notification
    if (m_systemTrayInitialized) {
        // Update the notification data
        NOTIFYICONDATA nid = m_nid;
        nid.uFlags |= NIF_INFO;
        
        // Set notification title and message
        wcscpy_s(nid.szInfoTitle, title.c_str());
        wcscpy_s(nid.szInfo, message.c_str());
        
        // Set notification icon based on type
        switch (type) {
        case NotificationType::INFO:
            nid.dwInfoFlags = NIIF_INFO;
            break;
        case NotificationType::WARNING:
            nid.dwInfoFlags = NIIF_WARNING;
            break;
        case NotificationType::ERROR_TYPE:
            nid.dwInfoFlags = NIIF_ERROR;
            break;
        }
        
        // Show the notification
        return Shell_NotifyIcon(NIM_MODIFY, &nid) != FALSE;
    }
    
    return false;
}

bool NotificationManager::InitializeSystemTray() {
    // Create a simple icon for the system tray
    // In a real implementation, you would use a proper icon
    m_hIcon = LoadIcon(nullptr, IDI_SHIELD);
    if (!m_hIcon) {
        return false;
    }
    
    // Set the icon
    m_nid.hIcon = m_hIcon;
    
    // Get a window handle (we'll use the desktop window for simplicity)
    m_nid.hWnd = GetDesktopWindow();
    if (!m_nid.hWnd) {
        return false;
    }
    
    // Add the icon to the system tray
    if (Shell_NotifyIcon(NIM_ADD, &m_nid) == FALSE) {
        return false;
    }
    
    m_systemTrayInitialized = true;
    return true;
}

bool NotificationManager::UpdateSystemTray() {
    if (!m_systemTrayInitialized) {
        return false;
    }
    
    // Update the tooltip with warning count
    std::wstring tooltip = L"GuardianShield";
    if (!g_systemTrayWarnings.empty()) {
        tooltip += L" - " + std::to_wstring(g_systemTrayWarnings.size()) + L" warning(s)";
    }
    
    wcscpy_s(m_nid.szTip, tooltip.c_str());
    
    // Update the system tray icon
    return Shell_NotifyIcon(NIM_MODIFY, &m_nid) != FALSE;
}

} // namespace Guardian
