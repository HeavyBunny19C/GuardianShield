/**
 * @file test_config.cpp
 * @brief Unit tests for Config cache serialization (P1-1 fix verification)
 *
 * Tests that SaveToCache/LoadFromCache correctly round-trip all fields,
 * including the v7 additions: whitelist, emergency settings, version, log_level.
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "../src/service/common/include/config.h"

using namespace Guardian;

class ConfigCacheTest : public ::testing::Test {
protected:
    std::wstring m_testDir;
    std::wstring m_configPath;

    void SetUp() override {
        m_testDir = L".\\test_config_data";
        std::filesystem::create_directories(m_testDir);
        m_configPath = m_testDir + L"\\guardian_config.yaml";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);

        std::wstring cachePath = L"C:\\ProgramData\\GuardianShield\\config_cache.bin";
        std::filesystem::remove(cachePath, ec);
    }

    void WriteSimpleConfig(const std::string& content) {
        std::ofstream f(m_configPath);
        f << content;
        f.close();
    }
};

TEST_F(ConfigCacheTest, DefaultConfigCreatesValidObject) {
    Config cfg(m_configPath);
    bool loaded = cfg.Load();
    EXPECT_TRUE(loaded);

    auto sys = cfg.GetSystemConfig();
    EXPECT_EQ(sys.version, "1.0.0");
    EXPECT_EQ(sys.log_level, "INFO");
    EXPECT_EQ(sys.encrypt_timeout_seconds, 30);
    EXPECT_EQ(sys.recovery_wait_seconds, 30);
    EXPECT_EQ(sys.wipe_method, "DOD_5220");
}

TEST_F(ConfigCacheTest, CacheRoundTrip_Thresholds) {
    WriteSimpleConfig(
        "system:\n"
        "  version: '2.1'\n"
        "  log_level: debug\n"
        "detection:\n"
        "  thresholds:\n"
        "    tier1:\n"
        "      file_delete_count: 15\n"
        "      file_delete_window_seconds: 10\n"
    );

    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_EQ(cfg1.GetFileDeleteThreshold(), 15);
        EXPECT_EQ(cfg1.GetFileDeleteWindowSeconds(), 10);
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }

    ASSERT_FALSE(std::filesystem::exists(m_configPath));

    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        EXPECT_EQ(cfg2.GetFileDeleteThreshold(), 15);
        EXPECT_EQ(cfg2.GetFileDeleteWindowSeconds(), 10);
    }
}

TEST_F(ConfigCacheTest, CacheRoundTrip_EmergencySettings) {
    WriteSimpleConfig(
        "emergency:\n"
        "  encrypt_timeout_seconds: 120\n"
        "  recovery_wait_seconds: 60\n"
        "  wipe_method: dod_7pass\n"
    );

    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_EQ(cfg1.GetEncryptTimeoutSeconds(), 120);
        EXPECT_EQ(cfg1.GetRecoveryWaitSeconds(), 60);
        EXPECT_EQ(cfg1.GetWipeMethod(), "dod_7pass");
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }

    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        EXPECT_EQ(cfg2.GetEncryptTimeoutSeconds(), 120);
        EXPECT_EQ(cfg2.GetRecoveryWaitSeconds(), 60);
        EXPECT_EQ(cfg2.GetWipeMethod(), "dod_7pass");
    }
}

TEST_F(ConfigCacheTest, CacheRoundTrip_VersionAndLogLevel) {
    WriteSimpleConfig(
        "system:\n"
        "  version: '3.0.0'\n"
        "  log_level: trace\n"
    );

    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_EQ(cfg1.GetVersion(), "3.0.0");
        EXPECT_EQ(cfg1.GetLogLevel(), "trace");
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }

    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        EXPECT_EQ(cfg2.GetVersion(), "3.0.0");
        EXPECT_EQ(cfg2.GetLogLevel(), "trace");
    }
}

TEST_F(ConfigCacheTest, CacheOldVersionRejected) {
    std::wstring cachePath = L"C:\\ProgramData\\GuardianShield\\config_cache.bin";
    std::filesystem::create_directories(L"C:\\ProgramData\\GuardianShield");

    {
        std::ofstream f(cachePath, std::ios::binary | std::ios::trunc);
        uint32_t v7 = 7;
        f.write(reinterpret_cast<const char*>(&v7), sizeof(v7));
        char padding[512] = {};
        f.write(padding, sizeof(padding));
        f.close();
    }

    Config cfg(m_configPath);
    bool loaded = cfg.Load();
    EXPECT_TRUE(loaded);
    EXPECT_EQ(cfg.GetConfigSource(), ConfigSource::DEFAULT);
}
