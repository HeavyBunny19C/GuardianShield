/**
 * @file common_types.h
 * @brief Common type definitions for GuardianShield
 * 
 * This file defines all shared data structures, enumerations, and constants
 * used across the GuardianShield system components.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace Guardian {

// ============================================
// Constants
// ============================================

/// Magic number for message validation: "GUAR" in hex
constexpr uint32_t MESSAGE_MAGIC = 0x47554152;

/// Protocol version
constexpr uint8_t PROTOCOL_VERSION = 1;

/// Message header size in bytes
constexpr size_t MESSAGE_HEADER_SIZE = 32;

/// Maximum file path length
constexpr size_t MAX_PATH_LENGTH = 260;

/// Maximum process name length
constexpr size_t MAX_PROCESS_NAME = 64;

/// HMAC-SHA256 truncated to 12 bytes for message checksum
constexpr size_t CHECKSUM_SIZE = 12;
// ============================================
// Enumerations
// ============================================

/**
 * @brief Node identifier in the guardian triangle
 */
enum class NodeId : uint8_t {
    GUARDIAN_A = 0,     ///< Primary controller (SYSTEM service)
    GUARDIAN_B = 1,     ///< Backup controller (SYSTEM service)
    GUARDIAN_C = 2,     ///< Monitor node (User process)
    UNKNOWN    = 0xFF   ///< Unknown node
};

/**
 * @brief Message types for inter-process communication
 */
enum class MessageType : uint8_t {
    // Heartbeat messages (0x01-0x0F)
    HEARTBEAT           = 0x01,     ///< Heartbeat ping
    HEARTBEAT_ACK       = 0x02,     ///< Heartbeat acknowledgment
    
    // Alert messages (0x10-0x1F)
    ALERT               = 0x10,     ///< Security alert
    ALERT_ACK           = 0x11,     ///< Alert acknowledgment
    
    // Command messages (0x20-0x2F)
    COMMAND             = 0x20,     ///< Control command
    COMMAND_RESPONSE    = 0x21,     ///< Command response
    
    // State messages (0x30-0x3F)
    STATE_SYNC          = 0x30,     ///< State synchronization
    STATE_REQUEST       = 0x31,     ///< Request state
    
    // Driver messages (0x40-0x4F)
    DRIVER_EVENT        = 0x40,     ///< Event from kernel driver
    DRIVER_RESPONSE     = 0x41,     ///< Response to driver
    
    // Notification messages (0x50-0x5F)
    ALERT_NOTIFICATION  = 0x50,     ///< Alert notification for desktop display

    // Emergency messages (0xF0-0xFF)
    EMERGENCY_PREPARE   = 0xF0,     ///< Prepare emergency mode
    DECRYPT_REQUEST     = 0xFC,     ///< Request file decryption
    DECRYPT_RESPONSE    = 0xFD,     ///< Decryption result response
    UNLOCK_RESPONSE     = 0xFE,     ///< System unlocked by administrator
    EMERGENCY_TRIGGER   = 0xFF      ///< Trigger emergency protocol
};

/**
 * @brief Threat level classification
 */
enum class ThreatLevel : uint8_t {
    LEVEL_0 = 0,     ///< Normal operation
    LEVEL_1 = 1,     ///< Suspicious activity
    LEVEL_2 = 2,     ///< Dangerous activity
    LEVEL_3 = 3      ///< Critical emergency
};

/**
 * @brief Event types from kernel driver
 */
enum class DriverEventType : uint8_t {
    // File operations — IMPLEMENTED: produced by minifilter/ETW
    FILE_CREATE     = 0x01,
    FILE_WRITE      = 0x03,
    FILE_DELETE     = 0x04,
    FILE_RENAME     = 0x05,

    FILE_MOVE       = 0x07,     // cross-volume move: correlated from CREATE+DELETE
    FILE_COMPRESS   = 0x08,     // heuristic only (process name list)
    FILE_NETWORK_TRANSFER = 0x09,  // heuristic only (process name list)

    // Process operations — IMPLEMENTED: produced by GuardMonitor driver
    PROCESS_CREATE  = 0x10,
    PROC_TERMINATE  = 0x11,

    // --- RESERVED: not implemented in current version (no event source) ---
    // FILE_READ       = 0x02,  // needs smart filtering (ETW EventId 15 too noisy)
    // FILE_SET_INFO   = 0x06,  // needs minifilter IRP_MJ_SET_INFORMATION
    // PROCESS_INJECT  = 0x12,  // needs GuardMonitor kernel driver
    // PROCESS_DEBUG   = 0x13,  // needs GuardMonitor kernel driver
    // NETWORK_CONNECT = 0x20,  // needs WFP / ETW network provider
    // NETWORK_SEND    = 0x21,  // needs WFP driver
    // NETWORK_RECV    = 0x22,  // needs WFP driver

    // Driver operations — IMPLEMENTED: produced by GuardMonitor
    DRIVER_LOAD     = 0x30,
    DRIVER_UNLOAD   = 0x31,

    MAX_TYPE        = 0x32      // sentinel for range validation
};

/**
 * @brief Emergency state machine states
 */
enum class EmergencyState : uint8_t {
    NORMAL      = 0,    ///< Normal operation
    ALERT       = 1,    ///< Alert mode (enhanced monitoring)
    ENCRYPTING  = 2,    ///< Encrypting files
    WIPING      = 3,    ///< Secure wiping files
    DELETING    = 4,    ///< Deleting files
    LOCKED      = 5     ///< System locked
};

/**
 * @brief Response actions for threat mitigation
 */
enum class ResponseAction : uint8_t {
    NONE            = 0x00,
    LOG             = 0x01,     ///< Log the event
    ALERT_USER      = 0x02,     ///< Alert user
    TERMINATE       = 0x08,     ///< Terminate process
    BLOCK           = 0x10,     ///< Kernel-level I/O block (requires GuardFilter driver)
    ENCRYPT         = 0x20,     ///< Encrypt file
    WIPE            = 0x40,     ///< Secure wipe
    LOCKDOWN        = 0x80      ///< System lockdown
};

// Bitwise operators for ResponseAction
inline ResponseAction operator|(ResponseAction a, ResponseAction b) {
    return static_cast<ResponseAction>(
        static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

inline ResponseAction operator&(ResponseAction a, ResponseAction b) {
    return static_cast<ResponseAction>(
        static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}

inline bool HasAction(ResponseAction actions, ResponseAction flag) {
    return (static_cast<uint8_t>(actions) & static_cast<uint8_t>(flag)) != 0;
}

// ============================================
// Message Structures
// ============================================

#pragma pack(push, 1)

/**
 * @brief Message header (32 bytes fixed)
 * 
 * All messages between guardian processes start with this header.
 * Provides routing, sequencing, and integrity checking.
 */
struct MessageHeader {
    uint32_t    magic;          ///< Magic number (MESSAGE_MAGIC)
    uint8_t     version;        ///< Protocol version
    uint8_t     type;           ///< MessageType enum value
    uint8_t     source;         ///< Source NodeId
    uint8_t     dest;           ///< Destination NodeId
    uint32_t    sequence;       ///< Sequence number (incrementing)
    uint32_t    timestamp;      ///< Unix timestamp in milliseconds
    uint32_t    payload_len;    ///< Length of payload following header
    uint8_t     checksum[12];   ///< HMAC-SHA256 truncated
};

static_assert(sizeof(MessageHeader) == MESSAGE_HEADER_SIZE,
    "MessageHeader must be exactly 32 bytes");

/**
 * @brief Heartbeat message payload
 * 
 * Sent every 500ms between guardian processes to monitor health.
 */
struct HeartbeatPayload {
    uint32_t    process_id;         ///< Process ID of sender
    uint32_t    thread_count;       ///< Number of threads
    uint64_t    memory_usage;       ///< Memory usage in bytes
    uint32_t    cpu_usage;          ///< CPU usage (0.01% units, 10000 = 100%)
    uint32_t    uptime;             ///< Uptime in seconds
    uint8_t     status;             ///< EmergencyState value
    uint8_t     reserved[3];        ///< Reserved for alignment
    uint32_t    nonce;              ///< Incrementing nonce (anti-replay)
};

/**
 * @brief Alert message payload
 * 
 * Used to communicate security events between processes.
 */
struct AlertPayload {
    uint8_t     level;              ///< ThreatLevel
    uint8_t     source_type;        ///< 0=driver, 1=process, 2=ETW
    uint8_t     event_type;         ///< DriverEventType
    uint8_t     reserved;
    uint32_t    process_id;         ///< Related process ID
    uint32_t    timestamp;          ///< Event timestamp
    wchar_t     file_path[260];     ///< Related file path
    wchar_t     process_name[64];   ///< Process name
    uint8_t     extra_data[128];    ///< Extended data (context-specific)
};

/**
 * @brief Alert notification payload (GuardianA → GuardianC for desktop display)
 */
struct AlertNotification {
    uint8_t     level;              ///< ThreatLevel
    uint8_t     reserved[3];
    uint32_t    process_id;
    char        message[256];       ///< Alert message (UTF-8)
    wchar_t     file_path[MAX_PATH_LENGTH];
};

/**
 * @brief File event from driver
 */
struct FileEvent {
    uint32_t    process_id;
    uint32_t    event_type;
    uint32_t    access_mask;
    uint64_t    timestamp;
    wchar_t     file_path[MAX_PATH_LENGTH];
};

/**
 * @brief Process event from driver
 */
struct ProcessEvent {
    uint32_t    process_id;
    uint32_t    parent_pid;
    uint32_t    event_type;
    uint64_t    timestamp;
    wchar_t     process_name[MAX_PROCESS_NAME];
    wchar_t     command_line[512];
};

/**
 * @brief Driver event structure (unified)
 */
struct DriverEvent {
    uint32_t    process_id;
    uint32_t    event_type;      ///< DriverEventType value
    uint64_t    timestamp;
    uint32_t    access_mask;
    uint32_t    data_size;
    wchar_t     file_path[MAX_PATH_LENGTH];
    wchar_t     process_name[MAX_PROCESS_NAME];
    uint8_t     extra_data[256];
};

/**
 * @brief Decrypt request payload (GuardianC -> primary controller)
 */
struct DecryptRequestPayload {
    char        password_hash[65];  ///< SHA-256 hex string + null
};

/**
 * @brief Decrypt response payload (primary controller -> GuardianC)
 */
struct DecryptResponsePayload {
    uint8_t     success;            ///< 0=failed, 1=success, 2=in_progress
    uint8_t     reserved[3];
    uint32_t    reserved2;          ///< Reserved (was acl_restored_count)
    uint32_t    decrypted_count;    ///< Number of files successfully decrypted
    uint32_t    failed_count;       ///< Number of files that failed to decrypt
    wchar_t     error_message[256]; ///< Result/error description
};

#pragma pack(pop)

// ============================================
// Configuration Structures
// ============================================

/**
 * @brief Protected directory configuration
 */
struct ProtectedDirectory {
    std::wstring path;          ///< Directory path
    bool recursive = true;      ///< Include subdirectories
    int priority = 0;           ///< Protection priority (higher = more important)
    std::vector<std::wstring> file_types;  ///< File type filters
};

/**
 * @brief Whitelist process entry
 */
struct WhitelistProcess {
    std::wstring name;          ///< Process name (e.g., "devenv.exe")
    std::wstring description;   ///< Human-readable description
    std::vector<std::wstring> permissions;  ///< "READ", "WRITE", etc.
    std::wstring path_prefix;   ///< Optional path prefix for security (e.g., "C:\\Windows\\")
};

/**
 * @brief Detection rule configuration
 */
struct DetectionRule {
    std::string id;             ///< Rule ID (e.g., "F1", "P1")
    bool enabled = true;        ///< Is rule active
    std::string action;         ///< Response action
    int threshold = 0;          ///< Triggering threshold
};

/**
 * @brief System configuration
 */
struct SystemConfig {
    std::string version = "1.0.0";
    std::string log_level = "INFO";
    std::wstring log_path;
    
    std::vector<ProtectedDirectory> protected_dirs;
    std::vector<WhitelistProcess> whitelist;
    std::vector<DetectionRule> rules;
    
    // Emergency settings
    int encrypt_timeout_seconds = 30;
    int recovery_wait_seconds = 30;
    std::string wipe_method = "DOD_5220";
    
    // Communication settings
    uint16_t tcp_port_base = 17500;
    bool tls_enabled = true;
};

// ============================================
// Utility Functions
// ============================================

/**
 * @brief Get current timestamp in milliseconds
 */
inline uint64_t GetCurrentTimestamp() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()
    ).count();
}

/**
 * @brief Convert NodeId to string
 */
inline const char* NodeIdToString(NodeId id) {
    switch (id) {
        case NodeId::GUARDIAN_A: return "GuardianA";
        case NodeId::GUARDIAN_B: return "GuardianB";
        case NodeId::GUARDIAN_C: return "GuardianC";
        default: return "Unknown";
    }
}

/**
 * @brief Convert ThreatLevel to string
 */
inline const char* ThreatLevelToString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::LEVEL_0: return "Normal";
        case ThreatLevel::LEVEL_1: return "Suspicious";
        case ThreatLevel::LEVEL_2: return "Dangerous";
        case ThreatLevel::LEVEL_3: return "Critical";
        default: return "Unknown";
    }
}

/**
 * @brief Convert EmergencyState to string
 */
inline const char* EmergencyStateToString(EmergencyState state) {
    switch (state) {
        case EmergencyState::NORMAL: return "Normal";
        case EmergencyState::ALERT: return "Alert";
        case EmergencyState::ENCRYPTING: return "Encrypting";
        case EmergencyState::WIPING: return "Wiping";
        case EmergencyState::DELETING: return "Deleting";
        case EmergencyState::LOCKED: return "Locked";
        default: return "Unknown";
    }
}

/**
 * @brief Convert DriverEventType to string
 */
inline const char* DriverEventTypeToString(DriverEventType type) {
    switch (type) {
        case DriverEventType::FILE_CREATE: return "FILE_CREATE";
        case DriverEventType::FILE_WRITE: return "FILE_WRITE";
        case DriverEventType::FILE_DELETE: return "FILE_DELETE";
        case DriverEventType::FILE_RENAME: return "FILE_RENAME";
        case DriverEventType::FILE_MOVE: return "FILE_MOVE";
        case DriverEventType::FILE_COMPRESS: return "FILE_COMPRESS";
        case DriverEventType::FILE_NETWORK_TRANSFER: return "FILE_NETWORK_TRANSFER";
        case DriverEventType::PROCESS_CREATE: return "PROCESS_CREATE";
        case DriverEventType::PROC_TERMINATE: return "PROCESS_TERMINATE";
        case DriverEventType::DRIVER_LOAD: return "DRIVER_LOAD";
        case DriverEventType::DRIVER_UNLOAD: return "DRIVER_UNLOAD";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Convert ResponseAction to string
 */
inline const char* ResponseActionToString(ResponseAction action) {
    switch (action) {
        case ResponseAction::NONE: return "NONE";
        case ResponseAction::LOG: return "LOG";
        case ResponseAction::ALERT_USER: return "ALERT_USER";
        case ResponseAction::TERMINATE: return "TERMINATE";
        case ResponseAction::BLOCK: return "BLOCK";
        case ResponseAction::ENCRYPT: return "ENCRYPT";
        case ResponseAction::WIPE: return "WIPE";
        case ResponseAction::LOCKDOWN: return "LOCKDOWN";
        default: return "UNKNOWN";
    }
}


} // namespace Guardian
