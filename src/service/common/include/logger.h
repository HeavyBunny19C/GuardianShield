/**
 * @file logger.h
 * @brief Thread-safe logging system for GuardianShield
 * 
 * Provides multi-level logging with daily rotation and retention policy.
 * Thread-safe implementation using lock-free techniques where possible.
 */

#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <memory>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace Guardian {

/**
 * @brief Log severity levels
 */
enum class LogLevel : uint8_t {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    LOG_ERROR = 4,
    CRITICAL = 5,
    OFF = 255
};

/**
 * @brief Log format type
 */
enum class LogFormat : uint8_t {
    TEXT = 0,   // Plain text format
    JSON = 1    // JSON format
};

/**
 * @brief Convert LogLevel to string
 */
inline const char* LogLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE:    return "TRACE";
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARN:     return "WARN";
        case LogLevel::LOG_ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default:                 return "UNKNOWN";
    }
}

/**
 * @brief Thread-safe logger with daily rotation and retention
 * 
 * Features:
 * - Multi-level logging (TRACE to CRITICAL)
 * - Daily file rotation (new file each day)
 * - Retention policy (delete logs older than N days)
 * - JSON format support
 * - Thread-safe operation
 * - Console output option
 * - Timestamp with millisecond precision
 * 
 * File naming: guardian_YYYY-MM-DD.json (or .log for text)
 * 
 * Usage:
 * @code
 * Logger logger(L"C:\\ProgramData\\GuardianShield\\logs\\guardian", 
 *               LogLevel::INFO, LogFormat::JSON, 7);
 * logger.Info("System started");
 * logger.LogEvent("FILE_DELETE", ThreatLevel::LEVEL_0, "LOG", 
 *                 L"D:\\test.txt", L"explorer.exe", 1234);
 * @endcode
 */
class Logger {
public:
    /**
     * @brief Construct a new Logger with daily rotation
     * @param basePath Base path for log files (without extension)
     *                 Files will be named: basePath_YYYY-MM-DD.json
     * @param level Minimum log level to record
     * @param format Log format (TEXT or JSON)
     * @param retentionDays Number of days to keep log files (0 = unlimited)
     */
    Logger(const std::wstring& basePath,
           LogLevel level = LogLevel::INFO,
           LogFormat format = LogFormat::JSON,
           uint32_t retentionDays = 7);
    
    /**
     * @brief Destructor - flushes and closes log file
     */
    ~Logger();
    
    // Delete copy constructor and assignment
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    /**
     * @brief Set minimum log level
     */
    void SetLevel(LogLevel level) { m_level = level; }
    
    /**
     * @brief Get current log level
     */
    LogLevel GetLevel() const { return m_level.load(); }
    
    /**
     * @brief Set log format
     */
    void SetFormat(LogFormat format) { m_format = format; }
    
    /**
     * @brief Get log format
     */
    LogFormat GetFormat() const { return m_format; }
    
    /**
     * @brief Enable/disable console output
     */
    void SetConsoleOutput(bool enabled) { m_consoleOutput = enabled; }
    
    /**
     * @brief Log a trace message
     */
    template<typename... Args>
    void Trace(const char* format, Args... args) {
        Log(LogLevel::TRACE, format, args...);
    }
    
    /**
     * @brief Log a debug message
     */
    template<typename... Args>
    void Debug(const char* format, Args... args) {
        Log(LogLevel::DEBUG, format, args...);
    }
    
    /**
     * @brief Log an info message
     */
    template<typename... Args>
    void Info(const char* format, Args... args) {
        Log(LogLevel::INFO, format, args...);
    }
    
    /**
     * @brief Log a warning message
     */
    template<typename... Args>
    void Warn(const char* format, Args... args) {
        Log(LogLevel::WARN, format, args...);
    }
    
    /**
     * @brief Log an error message
     */
    template<typename... Args>
    void Error(const char* format, Args... args) {
        Log(LogLevel::LOG_ERROR, format, args...);
    }
    
    /**
     * @brief Log a critical message
     */
    template<typename... Args>
    void Critical(const char* format, Args... args) {
        Log(LogLevel::CRITICAL, format, args...);
    }
    
    /**
     * @brief Log with explicit level
     */
    template<typename... Args>
    void Log(LogLevel level, const char* format, Args... args) {
        if (level < m_level.load()) return;
        
        // Format the message
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), format, args...);
        
        WriteLog(level, buffer);
    }
    
    /**
     * @brief Log structured event (JSON format)
     * @param eventType Event type string (e.g., "FILE_DELETE")
     * @param threatLevel Threat level string (e.g., "LEVEL_0")
     * @param responseAction Response action string (e.g., "LOG")
     * @param filePath Related file path (optional)
     * @param processName Process name (optional)
     * @param processId Process ID (optional)
     * @param details Additional details (optional)
     */
    void LogEvent(
        const std::string& eventType,
        const std::string& threatLevel,
        const std::string& responseAction,
        const std::wstring& filePath = L"",
        const std::wstring& processName = L"",
        uint32_t processId = 0,
        const std::string& details = ""
    );
    
    /**
     * @brief Flush log buffer to disk
     */
    void Flush();
    
    /**
     * @brief Get current log file path
     */
    const std::wstring& GetCurrentFilePath() const { return m_currentFilePath; }

private:
    /**
     * @brief Write formatted log entry
     */
    void WriteLog(LogLevel level, const std::string& message);
    
    /**
     * @brief Write JSON log entry
     */
    void WriteJsonLog(LogLevel level, const std::string& message);
    
    /**
     * @brief Get current timestamp string
     */
    std::string GetTimestamp() const;
    
    /**
     * @brief Get ISO 8601 timestamp string
     */
    std::string GetIsoTimestamp() const;
    
    /**
     * @brief Get current date string (YYYY-MM-DD)
     */
    std::string GetCurrentDateString() const;
    
    /**
     * @brief Check if daily rotation is needed
     */
    bool NeedsDailyRotation() const;
    
    /**
     * @brief Perform daily rotation - open new file for today
     */
    void RotateDaily();
    
    /**
     * @brief Clean up old log files based on retention policy
     */
    void CleanupOldLogs();
    
    /**
     * @brief Generate log filename for a date
     */
    std::wstring GetLogFilename(const std::string& date) const;

    std::wstring m_basePath;            ///< Base path for log files
    std::wstring m_currentFilePath;     ///< Current log file path
    std::atomic<LogLevel> m_level;      ///< Minimum log level
    LogFormat m_format;                 ///< Log format (TEXT/JSON)
    uint32_t m_retentionDays;           ///< Days to keep log files
    std::atomic<bool> m_consoleOutput;  ///< Console output enabled
    std::mutex m_mutex;                 ///< Thread safety mutex
    std::ofstream m_file;               ///< Output file stream
    std::string m_currentDate;          ///< Current date string (YYYY-MM-DD)
};

/**
 * @brief Global logger instance
 * 
 * Initialize with InitializeGlobalLogger() before use.
 */
extern std::shared_ptr<Logger> g_logger;

/**
 * @brief Initialize the global logger
 */
inline void InitializeGlobalLogger(
    const std::wstring& basePath,
    LogLevel level = LogLevel::INFO,
    LogFormat format = LogFormat::JSON,
    uint32_t retentionDays = 7
) {
    g_logger = std::make_shared<Logger>(basePath, level, format, retentionDays);
}

/**
 * @brief Get the global logger
 */
inline std::shared_ptr<Logger> GetLogger() {
    return g_logger;
}

// Convenience macros for global logger access
#define LOG_TRACE(...)   Guardian::g_logger->Trace(__VA_ARGS__)
#define LOG_DEBUG(...)   Guardian::g_logger->Debug(__VA_ARGS__)
#define LOG_INFO(...)    Guardian::g_logger->Info(__VA_ARGS__)
#define LOG_WARN(...)    Guardian::g_logger->Warn(__VA_ARGS__)
#define LOG_ERROR(...)   Guardian::g_logger->Error(__VA_ARGS__)
#define LOG_CRITICAL(...) Guardian::g_logger->Critical(__VA_ARGS__)

} // namespace Guardian
