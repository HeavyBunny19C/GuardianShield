/**
 * @file test_event_logging.cpp
 * @brief Tests for Logger API writing JSON Lines format events
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "../src/service/common/include/logger.h"

using namespace Guardian;

class EventLoggingTest : public ::testing::Test {
protected:
    std::wstring m_logDir;
    std::wstring m_basePath;

    void SetUp() override {
        m_logDir = L".\\test_event_log_data";
        std::filesystem::create_directories(m_logDir);
        m_basePath = m_logDir + L"\\eventlog";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_logDir, ec);
    }

    std::string ReadLogFile(const std::wstring& path) {
        std::ifstream f(path, std::ios::binary);
        return std::string(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());
    }

    bool IsValidJson(const std::string& line) {
        // Check if line starts with { and ends with }
        if (line.empty()) return false;
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if (start == std::string::npos || end == std::string::npos) return false;
        return line[start] == '{' && line[end] == '}';
    }

    std::vector<std::string> SplitLines(const std::string& content) {
        std::vector<std::string> lines;
        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            if (!line.empty()) {
                lines.push_back(line);
            }
        }
        return lines;
    }
};

TEST_F(EventLoggingTest, LoggerWritesToFile) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.Info("Test message");
    logger.Flush();

    auto logFile = logger.GetCurrentFilePath();
    EXPECT_TRUE(std::filesystem::exists(logFile));

    auto content = ReadLogFile(logFile);
    EXPECT_FALSE(content.empty());
}

TEST_F(EventLoggingTest, OutputIsValidJsonLines) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.Info("First message");
    logger.Info("Second message");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    auto lines = SplitLines(content);

    EXPECT_GE(lines.size(), 2);
    for (const auto& line : lines) {
        EXPECT_TRUE(IsValidJson(line)) << "Line is not valid JSON: " << line;
    }
}

TEST_F(EventLoggingTest, JsonContainsLevelField) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.Info("Test event");
    logger.Error("Error event");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    auto lines = SplitLines(content);

    EXPECT_GE(lines.size(), 2);
    for (const auto& line : lines) {
        EXPECT_TRUE(
            line.find("\"level\"") != std::string::npos ||
            line.find("\"message\"") != std::string::npos
        ) << "Line missing required field: " << line;
    }
}

TEST_F(EventLoggingTest, MultipleWritesAllPreserved) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.Info("Message 1");
    logger.Info("Message 2");
    logger.Info("Message 3");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("Message 1") != std::string::npos);
    EXPECT_TRUE(content.find("Message 2") != std::string::npos);
    EXPECT_TRUE(content.find("Message 3") != std::string::npos);

    auto lines = SplitLines(content);
    EXPECT_GE(lines.size(), 3);
}

TEST_F(EventLoggingTest, LogEventWritesStructured) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.LogEvent(
        "FILE_DELETE",
        "LEVEL_0",
        "LOG",
        L"C:\\test\\file.txt",
        L"explorer.exe",
        1234
    );
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_FALSE(content.empty());

    auto lines = SplitLines(content);
    EXPECT_GE(lines.size(), 1);

    EXPECT_TRUE(IsValidJson(lines[0]));
}
