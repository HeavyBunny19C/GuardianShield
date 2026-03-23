/**
 * @file test_monitor_logger.cpp
 * @brief Tests for protection path monitoring event logging
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "../src/service/common/include/logger.h"

using namespace Guardian;

class MonitorLoggerTest : public ::testing::Test {
protected:
    std::wstring m_logDir;
    std::wstring m_basePath;

    void SetUp() override {
        m_logDir = L".\\test_logs_monitor";
        std::filesystem::create_directories(m_logDir);
        m_basePath = m_logDir + L"\\monlog";
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

TEST_F(MonitorLoggerTest, LogFileCreationEvent) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.LogEvent("FILE_CREATE", "LEVEL_0", "LOG",
                    L"D:\\test\\new_file.txt", L"explorer.exe", 1234,
                    "New file created in protected path");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("FILE_CREATE") != std::string::npos);
    EXPECT_TRUE(content.find("LEVEL_0") != std::string::npos);
    EXPECT_TRUE(content.find("new_file.txt") != std::string::npos);
    EXPECT_TRUE(content.find("explorer.exe") != std::string::npos);
}

TEST_F(MonitorLoggerTest, LogFileDeletionEvent) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.LogEvent("FILE_DELETE", "LEVEL_1", "LOG",
                    L"D:\\test\\delete_file.txt", L"cmd.exe", 5678,
                    "File deleted from protected path");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("FILE_DELETE") != std::string::npos);
    EXPECT_TRUE(content.find("LEVEL_1") != std::string::npos);
}

TEST_F(MonitorLoggerTest, LogBatchOperationEvent) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.LogEvent("BATCH_OPERATION", "LEVEL_2", "LOCK",
                    L"D:\\test\\", L"powershell.exe", 7890,
                    "Batch file creation detected (10 files)");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("BATCH_OPERATION") != std::string::npos);
    EXPECT_TRUE(content.find("LEVEL_2") != std::string::npos);
    EXPECT_TRUE(content.find("LOCK") != std::string::npos);
}

TEST_F(MonitorLoggerTest, LogEncryptEvent) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.LogEvent("FILE_ENCRYPT", "LEVEL_3", "ENCRYPT",
                    L"D:\\test\\sensitive.txt", L"guardiana.exe", 2468,
                    "File encrypted due to suspicious activity");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("FILE_ENCRYPT") != std::string::npos);
    EXPECT_TRUE(content.find("LEVEL_3") != std::string::npos);
    EXPECT_TRUE(content.find("ENCRYPT") != std::string::npos);
}

TEST_F(MonitorLoggerTest, LogMinimalEvent) {
    Logger logger(m_basePath, LogLevel::DEBUG, LogFormat::JSON, 1);

    logger.LogEvent("TEST_EVENT", "LEVEL_0", "LOG");
    logger.Flush();

    auto content = ReadLogFile(logger.GetCurrentFilePath());
    EXPECT_TRUE(content.find("TEST_EVENT") != std::string::npos);
    EXPECT_TRUE(content.find("LEVEL_0") != std::string::npos);
}