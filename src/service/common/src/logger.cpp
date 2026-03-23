/**
 * @file logger.cpp
 * @brief Implementation of thread-safe logging system with daily rotation
 */

#include "logger.h"
#include "../include/string_utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>

#ifdef _WIN32
#include <Windows.h>
#include <sddl.h>
#pragma comment(lib, "Advapi32.lib")
#endif

namespace Guardian {

// Global logger instance
std::shared_ptr<Logger> g_logger = nullptr;

Logger::Logger(const std::wstring& basePath,
               LogLevel level,
               LogFormat format,
               uint32_t retentionDays)
    : m_basePath(basePath)
    , m_level(level)
    , m_format(format)
    , m_retentionDays(retentionDays)
    , m_consoleOutput(false)
{
    // Create directory if it doesn't exist
    std::filesystem::path path(basePath);
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    
    // Initialize with today's date
    m_currentDate = GetCurrentDateString();
    
    // Open today's log file
    RotateDaily();
    
    // Clean up old log files
    CleanupOldLogs();
}

Logger::~Logger() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.flush();
        m_file.close();
    }
}

std::string Logger::GetTimestamp() const {
    using namespace std::chrono;
    
    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);
    auto now_ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    
    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &now_time_t);
#else
    localtime_r(&now_time_t, &tm_buf);
#endif
    
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << now_ms.count();
    
    return oss.str();
}

std::string Logger::GetIsoTimestamp() const {
    using namespace std::chrono;
    
    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);
    auto now_ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    
    std::tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &now_time_t);
#else
    gmtime_r(&now_time_t, &tm_buf);
#endif
    
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << now_ms.count()
        << "Z";
    
    return oss.str();
}

std::string Logger::GetCurrentDateString() const {
    using namespace std::chrono;
    
    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);
    
    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &now_time_t);
#else
    localtime_r(&now_time_t, &tm_buf);
#endif
    
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d");
    return oss.str();
}

std::wstring Logger::GetLogFilename(const std::string& date) const {
    std::filesystem::path basePath(m_basePath);
    std::wstring extension = (m_format == LogFormat::JSON) ? L".json" : L".log";
    
    // Get the base filename from the path
    std::wstring filename = basePath.filename().wstring();
    
    // Construct: directory/filename_YYYY-MM-DD.json
    return basePath.parent_path().wstring() + L"\\" + filename + L"_" 
           + Utf8ToWide(date) + extension;
}

bool Logger::NeedsDailyRotation() const {
    std::string today = GetCurrentDateString();
    return today != m_currentDate;
}

void Logger::RotateDaily() {
    // Close current file if open
    if (m_file.is_open()) {
        m_file.flush();
        m_file.close();
    }
    
    // Update current date
    m_currentDate = GetCurrentDateString();
    
    // Generate new filename
    m_currentFilePath = GetLogFilename(m_currentDate);
    
    // Open new file for appending
    m_file.open(m_currentFilePath, std::ios::app | std::ios::binary);
    
#ifdef _WIN32
    if (m_file.is_open()) {
        PSECURITY_DESCRIPTOR psd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;FA;;;SY)(A;;FA;;;BA)",
                SDDL_REVISION_1, &psd, nullptr)) {
            SetFileSecurityW(m_currentFilePath.c_str(), DACL_SECURITY_INFORMATION, psd);
            LocalFree(psd);
        }
    }
#endif
    
    // Clean up old log files
    CleanupOldLogs();
}

void Logger::CleanupOldLogs() {
    if (m_retentionDays == 0) return;  // No cleanup if retention is unlimited
    
    using namespace std::chrono;
    
    std::filesystem::path basePath(m_basePath);
    std::wstring baseFilename = basePath.filename().wstring();
    std::filesystem::path logDir = basePath.parent_path();
    
    if (!std::filesystem::exists(logDir)) return;
    
    // Calculate cutoff date
    auto now = system_clock::now();
    auto cutoffTime = now - hours(24 * m_retentionDays);
    
    // Iterate through log files
    for (const auto& entry : std::filesystem::directory_iterator(logDir)) {
        if (!entry.is_regular_file()) continue;
        
        std::wstring filename = entry.path().filename().wstring();
        
        // Check if it's a log file matching our pattern
        std::wstring prefix = baseFilename + L"_";
        if (filename.find(prefix) != 0) continue;
        
        // Check file extension
        std::wstring ext = (m_format == LogFormat::JSON) ? L".json" : L".log";
        if (filename.substr(filename.length() - ext.length()) != ext) continue;
        
        // Get file modification time
        auto ftime = std::filesystem::last_write_time(entry);
        auto sctp = time_point_cast<system_clock::duration>(
            ftime - std::filesystem::file_time_type::clock::now() + system_clock::now()
        );
        
        // Delete if older than retention period
        if (sctp < cutoffTime) {
            std::filesystem::remove(entry);
        }
    }
}

void Logger::WriteLog(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check if daily rotation is needed
    if (NeedsDailyRotation()) {
        RotateDaily();
    }
    
    if (m_format == LogFormat::JSON) {
        WriteJsonLog(level, message);
    } else {
        // Text format
        std::ostringstream oss;
        oss << "[" << GetTimestamp() << "] "
            << "[" << LogLevelToString(level) << "] "
            << message << "\n";
        
        std::string entry = oss.str();
        
        if (m_file.is_open()) {
            m_file.write(entry.c_str(), entry.size());
            m_file.flush();
            if (m_file.fail()) {
                m_file.clear();
#ifdef _WIN32
                HANDLE hEventLog = RegisterEventSourceW(nullptr, L"GuardianShield");
                if (hEventLog) {
                    const wchar_t* msg = L"GuardianShield: Log file write failed — disk full or I/O error";
                    ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, 0, 0, nullptr, 1, 0, &msg, nullptr);
                    DeregisterEventSource(hEventLog);
                }
#endif
            }
        }
    }
    
    // Write to console if enabled
    if (m_consoleOutput) {
#ifdef _WIN32
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        
        WORD color = csbi.wAttributes;
        switch (level) {
            case LogLevel::WARN:
                color = 14; // Yellow
                break;
            case LogLevel::LOG_ERROR:
                color = 12; // Red
                break;
            case LogLevel::CRITICAL:
                color = 12 | FOREGROUND_INTENSITY; // Bright Red
                break;
            default:
                break;
        }
        
        SetConsoleTextAttribute(hConsole, color);
        std::cout << "[" << LogLevelToString(level) << "] " << message << std::endl;
        SetConsoleTextAttribute(hConsole, csbi.wAttributes);
#else
        std::cout << "[" << LogLevelToString(level) << "] " << message << std::endl;
#endif
    }
}

void Logger::WriteJsonLog(LogLevel level, const std::string& message) {
    if (!m_file.is_open()) return;
    
    // Escape special characters in message for JSON
    std::string escapedMsg;
    for (char c : message) {
        switch (c) {
            case '"': escapedMsg += "\\\""; break;
            case '\\': escapedMsg += "\\\\"; break;
            case '\n': escapedMsg += "\\n"; break;
            case '\r': escapedMsg += "\\r"; break;
            case '\t': escapedMsg += "\\t"; break;
            default: escapedMsg += c; break;
        }
    }
    
    std::ostringstream oss;
    oss << "{"
        << "\"timestamp\":\"" << GetIsoTimestamp() << "\","
        << "\"level\":\"" << LogLevelToString(level) << "\","
        << "\"message\":\"" << escapedMsg << "\""
        << "}\n";
    
    std::string entry = oss.str();
    m_file.write(entry.c_str(), entry.size());
    m_file.flush();
    if (m_file.fail()) {
        m_file.clear();
#ifdef _WIN32
        HANDLE hEventLog = RegisterEventSourceW(nullptr, L"GuardianShield");
        if (hEventLog) {
            const wchar_t* msg = L"GuardianShield: JSON log write failed";
            ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, 0, 0, nullptr, 1, 0, &msg, nullptr);
            DeregisterEventSource(hEventLog);
        }
#endif
    }
}

void Logger::LogEvent(
    const std::string& eventType,
    const std::string& threatLevel,
    const std::string& responseAction,
    const std::wstring& filePath,
    const std::wstring& processName,
    uint32_t processId,
    const std::string& details
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check if daily rotation is needed
    if (NeedsDailyRotation()) {
        RotateDaily();
    }
    
    if (!m_file.is_open()) return;
    
    // Escape string for JSON
    auto escapeJson = [](const std::string& str) -> std::string {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    };
    
    std::ostringstream oss;
    oss << "{"
        << "\"timestamp\":\"" << GetIsoTimestamp() << "\","
        << "\"event_type\":\"" << eventType << "\","
        << "\"threat_level\":\"" << threatLevel << "\","
        << "\"response_action\":\"" << responseAction << "\","
        << "\"file_path\":\"" << escapeJson(WideToUtf8(filePath)) << "\","
        << "\"process_name\":\"" << escapeJson(WideToUtf8(processName)) << "\","
        << "\"process_id\":" << processId << ","
        << "\"details\":\"" << escapeJson(details) << "\""
        << "}\n";
    
    std::string entry = oss.str();
    m_file.write(entry.c_str(), entry.size());
    m_file.flush();
    if (m_file.fail()) {
        m_file.clear();
#ifdef _WIN32
        HANDLE hEventLog = RegisterEventSourceW(nullptr, L"GuardianShield");
        if (hEventLog) {
            const wchar_t* msg = L"GuardianShield: Event log write failed";
            ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE, 0, 0, nullptr, 1, 0, &msg, nullptr);
            DeregisterEventSource(hEventLog);
        }
#endif
    }
    
    // Write to console if enabled
    if (m_consoleOutput) {
        std::cout << "[" << eventType << "] " 
                  << threatLevel << " - " 
                  << WideToUtf8(filePath) << std::endl;
    }
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) {
        m_file.flush();
    }
}

} // namespace Guardian
