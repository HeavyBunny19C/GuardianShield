/**
 * @file notification_manager.h
 * @brief Notification manager for GuardianShield
 * 
 * Provides Windows desktop notifications and system tray warnings
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "common_types.h"
#include <Windows.h>
#include <shellapi.h>

namespace Guardian {

/**
 * @brief Notification type
 */
enum class NotificationType {
    INFO,    // Information notification
    WARNING, // Warning notification
    ERROR_TYPE    // Error notification
};

/**
 * @brief Notification manager
 * 
 * Manages Windows desktop notifications and system tray warnings
 */
class NotificationManager {
public:
    /**
     * @brief Constructor
     */
    NotificationManager();

    /**
     * @brief Destructor
     */
    ~NotificationManager();

    /**
     * @brief Initialize the notification manager
     * @return true if successful
     */
    bool Initialize();

    /**
     * @brief Show a desktop notification
     * @param title Notification title
     * @param message Notification message
     * @param details Detailed message
     * @param type Notification type
     * @return true if successful
     */
    bool ShowDesktopNotification(const std::string& title, 
                                const std::string& message, 
                                const std::string& details, 
                                NotificationType type);

    /**
     * @brief Add a warning to the system tray
     * @param title Warning title
     * @param message Warning message
     * @return true if successful
     */
    bool AddSystemTrayWarning(const std::string& title, const std::string& message);

    /**
     * @brief Clear all system tray warnings
     * @return true if successful
     */
    bool ClearSystemTrayWarnings();

    /**
     * @brief Notify about a threat
     * @param level Threat level
     * @param message Threat message
     * @param event Optional driver event
     * @return true if successful
     */
    bool NotifyThreat(ThreatLevel level, const std::string& message, const DriverEvent* event = nullptr);

    /**
     * @brief Enable or disable notifications
     * @param enable Enable flag
     * @return true if successful
     */
    bool EnableNotifications(bool enable);

    /**
     * @brief Check if notifications are enabled
     * @return true if notifications are enabled
     */
    bool IsNotificationsEnabled() const;

private:
    /**
     * @brief Show a Windows toast notification
     * @param title Notification title
     * @param message Notification message
     * @param details Detailed message
     * @param type Notification type
     * @return true if successful
     */
    bool ShowToastNotification(const std::wstring& title, 
                              const std::wstring& message, 
                              const std::wstring& details, 
                              NotificationType type);

    /**
     * @brief Initialize the system tray icon
     * @return true if successful
     */
    bool InitializeSystemTray();

    /**
     * @brief Update the system tray icon
     * @return true if successful
     */
    bool UpdateSystemTray();

private:
    bool m_notificationsEnabled;  // Whether notifications are enabled
    bool m_systemTrayInitialized; // Whether system tray is initialized
    HICON m_hIcon;                // System tray icon handle
    NOTIFYICONDATA m_nid;         // System tray icon data
};

} // namespace Guardian
