/**
 * @file test_system_logger.cpp
 * @brief Tests for system runtime logging
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "../src/service/common/include/logger.h"

using namespace Guardian;

class SystemLoggerTest : public ::testing::Test {
protected:
    std::wstring m_logDir;
    std::wstring m_basePath;

    void SetUp() override {
        m_logDir = L".\\test_logs_system";
        std::filesystem::create_directories(m_logDir);
        m_basePath = m_logDir + L"\\syslog";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_logDir, ec);
    }

    std::string ReadLogFile(const std::wstring& path) {
        std::ifstream f(path);
        return std::string(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());
    }
};

TEST_F(SystemLoggerTest, CreateLoggerAndWrite) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.Info("System starting");
    logger.Info("System started successfully");
    logger.Flush();

    auto logFile = logger.GetCurrentFilePath();
    EXPECT_TRUE(std::filesystem::exists(logFile));

    auto content = ReadLogFile(logFile);
    EXPECT_TRUE(content.find("System starting") != std::string::npos);
    EXPECT_TRUE(content.find("System started successfully") != std::string::npos);
}

TEST_F(SystemLoggerTest, LogLevelFiltering) {
    Logger logger(m_basePath, LogLevel::WARN, LogFormat::TEXT, 1);

    logger.Debug("debug msg");
    logger.Info("info msg");
    logger.Warn("warn msg");
    logger.Error("error msg");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("debug msg") == std::string::npos);
    EXPECT_TRUE(content.find("info msg") == std::string::npos);
    EXPECT_TRUE(content.find("warn msg") != std::string::npos);
    EXPECT_TRUE(content.find("error msg") != std::string::npos);
}

TEST_F(SystemLoggerTest, LogLevelChange) {
    Logger logger(m_basePath, LogLevel::INFO, LogFormat::TEXT, 1);

    EXPECT_EQ(logger.GetLevel(), LogLevel::INFO);
    logger.SetLevel(LogLevel::CRITICAL);
    EXPECT_EQ(logger.GetLevel(), LogLevel::CRITICAL);
}

TEST_F(SystemLoggerTest, ErrorAndCriticalLogging) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.Error("Failed to connect: %s", "timeout");
    logger.Critical("System integrity compromised");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("Failed to connect") != std::string::npos);
    EXPECT_TRUE(content.find("System integrity compromised") != std::string::npos);
}

TEST_F(SystemLoggerTest, LogFilePath) {
    Logger logger(m_basePath, LogLevel::INFO, LogFormat::JSON, 1);
    logger.Info("test");
    logger.Flush();

    auto path = logger.GetCurrentFilePath();
    EXPECT_FALSE(path.empty());
    EXPECT_TRUE(path.find(L"syslog") != std::wstring::npos);
}