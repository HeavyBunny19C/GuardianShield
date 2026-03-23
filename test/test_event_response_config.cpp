/**
 * @file test_event_response_config.cpp
 * @brief Unit tests for configurable event response mapping
 *
 * Tests Config::GetEventResponse() YAML parsing, defaults, safety filtering,
 * and BuildEventResponse() shared function.
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "../src/service/common/include/config.h"
#include "../src/service/GuardianA/include/threat_evaluator.h"

using namespace Guardian;

class EventResponseConfigTest : public ::testing::Test {
protected:
    std::wstring m_testDir;
    std::wstring m_configPath;

    void SetUp() override {
        m_testDir = L".\\test_evtresp_data";
        std::filesystem::create_directories(m_testDir);
        m_configPath = m_testDir + L"\\guardian_config.yaml";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
        std::wstring cachePath = L"C:\\ProgramData\\GuardianShield\\config_cache.bin";
        std::filesystem::remove(cachePath, ec);
    }

    void WriteConfig(const std::string& content) {
        std::ofstream f(m_configPath);
        f << content;
        f.close();
    }
};

TEST_F(EventResponseConfigTest, DefaultConfig_ReturnsHardcodedDefaults) {
    WriteConfig("system:\n  version: '1.0'\n");
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    EXPECT_FALSE(HasAction(action, ResponseAction::ENCRYPT));
    EXPECT_FALSE(HasAction(action, ResponseAction::WIPE));
    EXPECT_FALSE(HasAction(action, ResponseAction::LOCKDOWN));
}

TEST_F(EventResponseConfigTest, DefaultConfig_FileCreateIsLogOnly) {
    WriteConfig("system:\n  version: '1.0'\n");
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_CREATE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(action, ResponseAction::ALERT_USER));
}

TEST_F(EventResponseConfigTest, DefaultConfig_FileMoveHasAlert) {
    WriteConfig("system:\n  version: '1.0'\n");
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_MOVE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
}

TEST_F(EventResponseConfigTest, CustomConfig_OverridesDefault) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, ALERT_USER, ENCRYPT]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    EXPECT_TRUE(HasAction(action, ResponseAction::ENCRYPT));
}

TEST_F(EventResponseConfigTest, UnknownAction_Ignored) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, FOOBAR, ALERT_USER]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    EXPECT_EQ(static_cast<uint8_t>(action),
              static_cast<uint8_t>(ResponseAction::LOG) |
              static_cast<uint8_t>(ResponseAction::ALERT_USER));
}

TEST_F(EventResponseConfigTest, UnknownEvent_UsesDefault) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_QUANTUM: [LOG, ENCRYPT]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    EXPECT_FALSE(HasAction(action, ResponseAction::ENCRYPT));
}

TEST_F(EventResponseConfigTest, WipeLockdownOnSingleEvent_Rejected) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, WIPE, LOCKDOWN, ALERT_USER]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    EXPECT_FALSE(HasAction(action, ResponseAction::WIPE));
    EXPECT_FALSE(HasAction(action, ResponseAction::LOCKDOWN));
}

TEST_F(EventResponseConfigTest, EncryptOnSingleEvent_AllowedByConfig) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_WRITE: [LOG, ALERT_USER, ENCRYPT]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_WRITE);
    EXPECT_TRUE(HasAction(action, ResponseAction::ENCRYPT));
}

TEST_F(EventResponseConfigTest, EmptyEventResponses_UsesDefaults) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
}

TEST_F(EventResponseConfigTest, CacheRoundTrip_EventResponses) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, ALERT_USER, ENCRYPT]\n"
        "    FILE_MOVE: [LOG, ALERT_USER]\n"
    );
    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_TRUE(HasAction(cfg1.GetEventResponse(DriverEventType::FILE_DELETE),
                              ResponseAction::ENCRYPT));
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }
    ASSERT_FALSE(std::filesystem::exists(m_configPath));
    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        auto action = cfg2.GetEventResponse(DriverEventType::FILE_DELETE);
        EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
        EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
        EXPECT_TRUE(HasAction(action, ResponseAction::ENCRYPT));
    }
}

TEST_F(EventResponseConfigTest, BuildEventResponse_LogOnlyIsLevel0) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_CREATE: [LOG]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto assessment = BuildEventResponse(cfg, DriverEventType::FILE_CREATE);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_0);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::LOG));
}

TEST_F(EventResponseConfigTest, BuildEventResponse_AlertIsLevel1) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_WRITE: [LOG, ALERT_USER]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto assessment = BuildEventResponse(cfg, DriverEventType::FILE_WRITE);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_1);
}

TEST_F(EventResponseConfigTest, BuildEventResponse_EncryptIsLevel2) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, ALERT_USER, ENCRYPT]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto assessment = BuildEventResponse(cfg, DriverEventType::FILE_DELETE);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_2);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ENCRYPT));
}

TEST_F(EventResponseConfigTest, BuildEventResponse_TerminateIsLevel2) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, ALERT_USER, TERMINATE]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto assessment = BuildEventResponse(cfg, DriverEventType::FILE_DELETE);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_2);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::TERMINATE));
}

TEST_F(EventResponseConfigTest, BlockParsing_YamlRecognizesBlock) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_RENAME: [LOG, ALERT_USER, BLOCK]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_RENAME);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    EXPECT_TRUE(HasAction(action, ResponseAction::BLOCK));
}

TEST_F(EventResponseConfigTest, BlockIsLevel2) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_RENAME: [LOG, BLOCK]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto assessment = BuildEventResponse(cfg, DriverEventType::FILE_RENAME);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_2);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::BLOCK));
}

TEST_F(EventResponseConfigTest, BlockPlusTerminate_DegradesToBlock) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_RENAME: [LOG, ALERT_USER, BLOCK, TERMINATE]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto assessment = BuildEventResponse(cfg, DriverEventType::FILE_RENAME);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_2);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::BLOCK));
    EXPECT_FALSE(HasAction(assessment.action, ResponseAction::TERMINATE));
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ALERT_USER));
}

TEST_F(EventResponseConfigTest, BlockCacheRoundTrip) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_RENAME: [LOG, ALERT_USER, BLOCK]\n"
    );
    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_TRUE(HasAction(cfg1.GetEventResponse(DriverEventType::FILE_RENAME),
                              ResponseAction::BLOCK));
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }
    ASSERT_FALSE(std::filesystem::exists(m_configPath));
    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        auto action = cfg2.GetEventResponse(DriverEventType::FILE_RENAME);
        EXPECT_TRUE(HasAction(action, ResponseAction::BLOCK));
        EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    }
}

TEST_F(EventResponseConfigTest, WipeLockdownBlock_FilterConsistency) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, WIPE, LOCKDOWN, BLOCK, ALERT_USER]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    EXPECT_TRUE(HasAction(action, ResponseAction::BLOCK));
    EXPECT_FALSE(HasAction(action, ResponseAction::WIPE));
    EXPECT_FALSE(HasAction(action, ResponseAction::LOCKDOWN));
}

TEST_F(EventResponseConfigTest, CacheV11RoundTrip_RenameThresholds) {
    WriteConfig(
        "detection:\n"
        "  thresholds:\n"
        "    tier1:\n"
        "      file_rename_count: 20\n"
        "      file_rename_window_seconds: 8\n"
        "    tier2:\n"
        "      file_rename_count: 80\n"
        "      file_rename_window_seconds: 15\n"
    );
    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_EQ(cfg1.GetFileRenameThreshold(), 20);
        EXPECT_EQ(cfg1.GetFileRenameWindowSeconds(), 8);
        EXPECT_EQ(cfg1.GetTier2FileRenameThreshold(), 80);
        EXPECT_EQ(cfg1.GetTier2FileRenameWindowSeconds(), 15);
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }
    ASSERT_FALSE(std::filesystem::exists(m_configPath));
    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        EXPECT_EQ(cfg2.GetFileRenameThreshold(), 20);
        EXPECT_EQ(cfg2.GetFileRenameWindowSeconds(), 8);
        EXPECT_EQ(cfg2.GetTier2FileRenameThreshold(), 80);
        EXPECT_EQ(cfg2.GetTier2FileRenameWindowSeconds(), 15);
    }
}

// ================================================================
// ACTION AVAILABILITY AUDIT TESTS
// Verifies each ResponseAction's real implementation status
// ================================================================

TEST_F(EventResponseConfigTest, ActionAudit_LOG_ParsedAndAccepted) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_CREATE: [LOG]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto action = cfg.GetEventResponse(DriverEventType::FILE_CREATE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    auto assess = BuildEventResponse(cfg, DriverEventType::FILE_CREATE);
    EXPECT_EQ(assess.level, ThreatLevel::LEVEL_0);
}

TEST_F(EventResponseConfigTest, ActionAudit_ALERT_USER_ParsedAndAccepted) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_WRITE: [LOG, ALERT_USER]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto action = cfg.GetEventResponse(DriverEventType::FILE_WRITE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(action, ResponseAction::ALERT_USER));
    auto assess = BuildEventResponse(cfg, DriverEventType::FILE_WRITE);
    EXPECT_EQ(assess.level, ThreatLevel::LEVEL_1);
}

TEST_F(EventResponseConfigTest, ActionAudit_TERMINATE_ParsedAndAccepted) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, ALERT_USER, TERMINATE]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::TERMINATE));
    auto assess = BuildEventResponse(cfg, DriverEventType::FILE_DELETE);
    EXPECT_EQ(assess.level, ThreatLevel::LEVEL_2);
}

TEST_F(EventResponseConfigTest, ActionAudit_BLOCK_ParsedAndAccepted) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_RENAME: [LOG, ALERT_USER, BLOCK]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto action = cfg.GetEventResponse(DriverEventType::FILE_RENAME);
    EXPECT_TRUE(HasAction(action, ResponseAction::BLOCK));
    auto assess = BuildEventResponse(cfg, DriverEventType::FILE_RENAME);
    EXPECT_EQ(assess.level, ThreatLevel::LEVEL_2);
}

TEST_F(EventResponseConfigTest, ActionAudit_ENCRYPT_ParsedAndAccepted) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, ENCRYPT]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::ENCRYPT));
    auto assess = BuildEventResponse(cfg, DriverEventType::FILE_DELETE);
    EXPECT_EQ(assess.level, ThreatLevel::LEVEL_2);
}

TEST_F(EventResponseConfigTest, ActionAudit_WIPE_RejectedFromSingleEvent) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, WIPE]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(action, ResponseAction::WIPE))
        << "WIPE must be filtered from single-event responses";
}

TEST_F(EventResponseConfigTest, ActionAudit_LOCKDOWN_RejectedFromSingleEvent) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, LOCKDOWN]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto action = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(action, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(action, ResponseAction::LOCKDOWN))
        << "LOCKDOWN must be filtered from single-event responses";
}

TEST_F(EventResponseConfigTest, ActionAudit_BLOCK_TERMINATE_MutualExclusion) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_WRITE: [LOG, ALERT_USER, BLOCK, TERMINATE]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto assess = BuildEventResponse(cfg, DriverEventType::FILE_WRITE);
    EXPECT_TRUE(HasAction(assess.action, ResponseAction::BLOCK))
        << "BLOCK should be preserved when BLOCK+TERMINATE conflict";
    EXPECT_FALSE(HasAction(assess.action, ResponseAction::TERMINATE))
        << "TERMINATE should be stripped when BLOCK is also present";
}

TEST_F(EventResponseConfigTest, ActionAudit_AllValidActions_InOneConfig) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_DELETE: [LOG, ALERT_USER, TERMINATE, ENCRYPT, BLOCK, WIPE, LOCKDOWN]\n"
    );
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto raw = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(raw, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(raw, ResponseAction::ALERT_USER));
    EXPECT_TRUE(HasAction(raw, ResponseAction::TERMINATE));
    EXPECT_TRUE(HasAction(raw, ResponseAction::ENCRYPT));
    EXPECT_TRUE(HasAction(raw, ResponseAction::BLOCK));
    EXPECT_FALSE(HasAction(raw, ResponseAction::WIPE))
        << "WIPE filtered at parse time";
    EXPECT_FALSE(HasAction(raw, ResponseAction::LOCKDOWN))
        << "LOCKDOWN filtered at parse time";

    auto assess = BuildEventResponse(cfg, DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(assess.action, ResponseAction::BLOCK));
    EXPECT_FALSE(HasAction(assess.action, ResponseAction::TERMINATE))
        << "TERMINATE stripped by BLOCK mutual exclusion";
}

TEST_F(EventResponseConfigTest, ActionAudit_CacheRoundTrip_AllActions) {
    WriteConfig(
        "detection:\n"
        "  event_responses:\n"
        "    FILE_RENAME: [LOG, ALERT_USER, BLOCK]\n"
        "    FILE_DELETE: [LOG, ALERT_USER, ENCRYPT]\n"
        "    FILE_WRITE: [LOG, ALERT_USER, TERMINATE]\n"
    );
    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_TRUE(HasAction(cfg1.GetEventResponse(DriverEventType::FILE_RENAME),
                              ResponseAction::BLOCK));
        EXPECT_TRUE(HasAction(cfg1.GetEventResponse(DriverEventType::FILE_DELETE),
                              ResponseAction::ENCRYPT));
        EXPECT_TRUE(HasAction(cfg1.GetEventResponse(DriverEventType::FILE_WRITE),
                              ResponseAction::TERMINATE));
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }
    ASSERT_FALSE(std::filesystem::exists(m_configPath));
    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        EXPECT_TRUE(HasAction(cfg2.GetEventResponse(DriverEventType::FILE_RENAME),
                              ResponseAction::BLOCK));
        EXPECT_TRUE(HasAction(cfg2.GetEventResponse(DriverEventType::FILE_DELETE),
                              ResponseAction::ENCRYPT));
        EXPECT_TRUE(HasAction(cfg2.GetEventResponse(DriverEventType::FILE_WRITE),
                              ResponseAction::TERMINATE));
    }
}

TEST_F(EventResponseConfigTest, ActionAudit_FileMoveThresholds_CacheRoundTrip) {
    WriteConfig(
        "detection:\n"
        "  thresholds:\n"
        "    tier1:\n"
        "      file_move_count: 15\n"
        "      file_move_window_seconds: 7\n"
        "    tier2:\n"
        "      file_move_count: 60\n"
        "      file_move_window_seconds: 12\n"
    );
    {
        Config cfg1(m_configPath);
        ASSERT_TRUE(cfg1.Load());
        EXPECT_EQ(cfg1.GetFileMoveThreshold(), 15);
        EXPECT_EQ(cfg1.GetFileMoveWindowSeconds(), 7);
        EXPECT_EQ(cfg1.GetTier2FileMoveThreshold(), 60);
        EXPECT_EQ(cfg1.GetTier2FileMoveWindowSeconds(), 12);
        ASSERT_TRUE(cfg1.SecureDeleteSources());
    }
    ASSERT_FALSE(std::filesystem::exists(m_configPath));
    {
        Config cfg2(m_configPath);
        ASSERT_TRUE(cfg2.Load());
        EXPECT_EQ(cfg2.GetConfigSource(), ConfigSource::CACHE);
        EXPECT_EQ(cfg2.GetFileMoveThreshold(), 15);
        EXPECT_EQ(cfg2.GetFileMoveWindowSeconds(), 7);
        EXPECT_EQ(cfg2.GetTier2FileMoveThreshold(), 60);
        EXPECT_EQ(cfg2.GetTier2FileMoveWindowSeconds(), 12);
    }
}

TEST_F(EventResponseConfigTest, ActionAudit_DefaultActions_EveryImplementedType) {
    WriteConfig("system:\n  version: '1.0'\n");
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());

    auto fileCreate = cfg.GetEventResponse(DriverEventType::FILE_CREATE);
    EXPECT_TRUE(HasAction(fileCreate, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(fileCreate, ResponseAction::ALERT_USER));

    auto fileWrite = cfg.GetEventResponse(DriverEventType::FILE_WRITE);
    EXPECT_TRUE(HasAction(fileWrite, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(fileWrite, ResponseAction::ALERT_USER));

    auto fileDelete = cfg.GetEventResponse(DriverEventType::FILE_DELETE);
    EXPECT_TRUE(HasAction(fileDelete, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(fileDelete, ResponseAction::ALERT_USER));

    auto fileRename = cfg.GetEventResponse(DriverEventType::FILE_RENAME);
    EXPECT_TRUE(HasAction(fileRename, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(fileRename, ResponseAction::ALERT_USER));

    auto fileMove = cfg.GetEventResponse(DriverEventType::FILE_MOVE);
    EXPECT_TRUE(HasAction(fileMove, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(fileMove, ResponseAction::ALERT_USER));

    auto fileCompress = cfg.GetEventResponse(DriverEventType::FILE_COMPRESS);
    EXPECT_TRUE(HasAction(fileCompress, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(fileCompress, ResponseAction::ALERT_USER));

    auto fileNetXfer = cfg.GetEventResponse(DriverEventType::FILE_NETWORK_TRANSFER);
    EXPECT_TRUE(HasAction(fileNetXfer, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(fileNetXfer, ResponseAction::ALERT_USER));

    auto procCreate = cfg.GetEventResponse(DriverEventType::PROCESS_CREATE);
    EXPECT_TRUE(HasAction(procCreate, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(procCreate, ResponseAction::ALERT_USER));

    auto procTerm = cfg.GetEventResponse(DriverEventType::PROC_TERMINATE);
    EXPECT_TRUE(HasAction(procTerm, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(procTerm, ResponseAction::ALERT_USER));

    auto drvLoad = cfg.GetEventResponse(DriverEventType::DRIVER_LOAD);
    EXPECT_TRUE(HasAction(drvLoad, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(drvLoad, ResponseAction::ALERT_USER));
}
