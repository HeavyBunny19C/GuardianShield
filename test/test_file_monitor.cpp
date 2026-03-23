/**
 * @file test_file_monitor.cpp
 * @brief Integration tests for file monitoring event flow
 */

#include <gtest/gtest.h>
#include <string>
#include <filesystem>
#include <fstream>

#include "../src/service/common/include/common_types.h"
#include "../src/service/common/include/driver_client.h"

#include "../src/service/common/include/file_encryptor.h"
#include "../src/service/common/include/file_wiper.h"

using namespace Guardian;

class FileMonitorIntegrationTest : public ::testing::Test {
protected:
    std::wstring m_testDir;

    void SetUp() override {
        m_testDir = L".\\test_monitor_data";
        std::filesystem::create_directories(m_testDir);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
    }

    std::wstring CreateTestFile(const std::wstring& name, const std::string& content) {
        std::wstring path = m_testDir + L"\\" + name;
        std::ofstream f(path);
        f << content;
        f.close();
        return path;
    }
};

TEST_F(FileMonitorIntegrationTest, DriverEventStructureLayout) {
    DriverEvent event = {};
    event.event_type = static_cast<uint32_t>(DriverEventType::FILE_CREATE);
    event.process_id = 1234;
    event.timestamp = GetCurrentTimestamp();
    wcscpy_s(event.file_path, L"C:\\Test\\file.txt");
    wcscpy_s(event.process_name, L"test.exe");

    EXPECT_EQ(event.event_type, static_cast<uint32_t>(DriverEventType::FILE_CREATE));
    EXPECT_EQ(event.process_id, 1234u);
    EXPECT_GT(event.timestamp, 0u);
    EXPECT_STREQ(event.file_path, L"C:\\Test\\file.txt");
    EXPECT_STREQ(event.process_name, L"test.exe");
}

TEST_F(FileMonitorIntegrationTest, DriverClientDisconnectedState) {
    DriverClient client;
    EXPECT_FALSE(client.IsConnected());
    EXPECT_EQ(client.GetTotalOperations(), 0u);
    EXPECT_EQ(client.GetBlockedOperations(), 0u);
    EXPECT_EQ(client.GetPendingEventCount(), 0u);

    DriverEvent event;
    EXPECT_FALSE(client.GetNextEvent(event));
    EXPECT_FALSE(client.AddProtectedPath(L"C:\\test"));
    EXPECT_FALSE(client.EnableMonitoring());
}

TEST_F(FileMonitorIntegrationTest, FileEncryptorEncryptDecrypt) {
    auto path = CreateTestFile(L"enctest.txt", "Secret data here");
    FileEncryptor encryptor;
    std::string password = "test_password_123";

    EncryptResult encResult = encryptor.EncryptFile(path, password);
    EXPECT_TRUE(encResult.success);
    EXPECT_GT(encResult.encrypted_size, 0u);

    std::wstring encPath = path + L".gs";
    EXPECT_TRUE(std::filesystem::exists(encPath));
    EXPECT_TRUE(encryptor.IsEncrypted(encPath));

    EncryptResult decResult = encryptor.DecryptFile(encPath, password);
    EXPECT_TRUE(decResult.success);

    std::ifstream f(path);
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "Secret data here");
}

TEST_F(FileMonitorIntegrationTest, FileWiperSecureDelete) {
    auto path = CreateTestFile(L"wipeme.txt", "Sensitive information");
    FileWiper wiper;

    EXPECT_TRUE(std::filesystem::exists(path));

    WipeResult result = wiper.WipeAndDelete(path);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(result.passes_completed, 7u);
}

TEST_F(FileMonitorIntegrationTest, DriverEventTypeEnumCoverage) {
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::FILE_CREATE), 0x01);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::FILE_WRITE), 0x03);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::FILE_DELETE), 0x04);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::FILE_RENAME), 0x05);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::FILE_MOVE), 0x07);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::FILE_COMPRESS), 0x08);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::FILE_NETWORK_TRANSFER), 0x09);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::PROCESS_CREATE), 0x10);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::PROC_TERMINATE), 0x11);
    EXPECT_EQ(static_cast<uint8_t>(DriverEventType::DRIVER_LOAD), 0x30);
}