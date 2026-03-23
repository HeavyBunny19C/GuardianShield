/**
 * @file test_threat_evaluator.cpp
 * @brief Unit tests for ThreatEvaluator batch detection and event classification
 *
 * Tests the REAL ThreatEvaluator class and verifies that event classification
 * matches the actual GuardianA::AssessThreat logic.
 */

#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <string>
#include <filesystem>
#include <fstream>

#include "../src/service/common/include/common_types.h"
#include "../src/service/common/include/config.h"
#include "../src/service/GuardianA/include/threat_evaluator.h"

using namespace Guardian;

static DriverEvent MakeEvent(DriverEventType type, const wchar_t* path = L"C:\\test") {
    DriverEvent ev = {};
    ev.event_type = static_cast<uint32_t>(type);
    ev.process_id = 1234;
    ev.timestamp = 0;
    if (path) wcsncpy(ev.file_path, path, MAX_PATH_LENGTH - 1);
    return ev;
}

class ThreatEvaluatorBatchTest : public ::testing::Test {
protected:
    ThreatEvaluator evaluator;

    void SetUp() override {
        DetectionThresholds tier1, tier2;
        tier1.file_write_count = 10;
        tier1.file_write_window_seconds = 5;
        tier1.file_compress_count = 50;
        tier1.file_compress_window_seconds = 5;
        tier1.file_delete_count = 5;
        tier1.file_delete_window_seconds = 5;
        tier1.file_network_transfer_count = 10;
        tier1.file_network_transfer_window_seconds = 5;
        tier1.file_create_count = 15;
        tier1.file_create_window_seconds = 5;
        tier1.file_rename_count = 10;
        tier1.file_rename_window_seconds = 5;
        tier1.data_transfer_mb = 1;
        tier1.process_termination_count = 50;

        tier2.file_write_count = 50;
        tier2.file_write_window_seconds = 10;
        tier2.file_compress_count = 250;
        tier2.file_compress_window_seconds = 10;
        tier2.file_delete_count = 20;
        tier2.file_delete_window_seconds = 10;
        tier2.file_create_count = 50;
        tier2.file_create_window_seconds = 10;
        tier2.file_network_transfer_count = 40;
        tier2.file_network_transfer_window_seconds = 10;
        tier2.file_rename_count = 50;
        tier2.file_rename_window_seconds = 10;
        tier2.data_transfer_mb = 10;
        tier2.process_termination_count = 200;

        evaluator.SetTieredThresholds(tier1, tier2);
    }
};

/* ============================================
 * ThreatLevel / ResponseAction enum tests
 * ============================================ */

TEST(ThreatEnumTest, ThreatLevelValues) {
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::LEVEL_0), 0);
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::LEVEL_1), 1);
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::LEVEL_2), 2);
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::LEVEL_3), 3);
}

TEST(ThreatEnumTest, ThreatLevelStrings) {
    EXPECT_STREQ(ThreatLevelToString(ThreatLevel::LEVEL_0), "Normal");
    EXPECT_STREQ(ThreatLevelToString(ThreatLevel::LEVEL_1), "Suspicious");
    EXPECT_STREQ(ThreatLevelToString(ThreatLevel::LEVEL_2), "Dangerous");
    EXPECT_STREQ(ThreatLevelToString(ThreatLevel::LEVEL_3), "Critical");
}

TEST(ThreatEnumTest, ResponseActionBitwiseOr) {
    auto combined = ResponseAction::LOG | ResponseAction::ALERT_USER;
    EXPECT_TRUE(HasAction(combined, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(combined, ResponseAction::ALERT_USER));
    EXPECT_FALSE(HasAction(combined, ResponseAction::TERMINATE));
}

TEST(ThreatEnumTest, DriverEventTypeStrings) {
    EXPECT_STREQ(DriverEventTypeToString(DriverEventType::FILE_CREATE), "FILE_CREATE");
    EXPECT_STREQ(DriverEventTypeToString(DriverEventType::FILE_DELETE), "FILE_DELETE");
    EXPECT_STREQ(DriverEventTypeToString(DriverEventType::FILE_NETWORK_TRANSFER), "FILE_NETWORK_TRANSFER");
}

/* ============================================
 * Event classification (matching GuardianA::AssessThreat)
 *
 * Mapping from BuildEventResponse (config-driven):
 *   FILE_CREATE/PROCESS_CREATE        ? LEVEL_0 (LOG)
 *   FILE_WRITE/RENAME/DELETE/MOVE     ? LEVEL_1 (LOG + ALERT_USER)
 *   FILE_COMPRESS                     ? LEVEL_1 (LOG + ALERT_USER)
 *   FILE_NETWORK_TRANSFER             ? LEVEL_1 (LOG + ALERT_USER)
 *   PROC_TERMINATE/DRIVER_LOAD/UNLOAD ? LEVEL_0 (LOG)
 *   [预留] FILE_READ, FILE_SET_INFO, PROCESS_INJECT, PROCESS_DEBUG,
 *          NETWORK_CONNECT, NETWORK_SEND, NETWORK_RECV
 * ============================================ */

class EventClassificationTestFixture : public ::testing::Test {
protected:
    std::wstring m_testDir;
    std::wstring m_configPath;

    void SetUp() override {
        m_testDir = L".\\test_evtclass_data";
        std::filesystem::create_directories(m_testDir);
        m_configPath = m_testDir + L"\\guardian_config.yaml";
        std::ofstream f(m_configPath);
        f << "system:\n  version: '1.0'\n";
        f.close();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
        std::wstring cachePath = L"C:\\ProgramData\\GuardianShield\\config_cache.bin";
        std::filesystem::remove(cachePath, ec);
    }
};

TEST_F(EventClassificationTestFixture, FileCreateIsLevel0) {
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto a = BuildEventResponse(cfg, DriverEventType::FILE_CREATE);
    EXPECT_EQ(a.level, ThreatLevel::LEVEL_0);
    EXPECT_TRUE(HasAction(a.action, ResponseAction::LOG));
    EXPECT_FALSE(HasAction(a.action, ResponseAction::ALERT_USER));
}

TEST_F(EventClassificationTestFixture, FileDeleteIsLevel1) {
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto a = BuildEventResponse(cfg, DriverEventType::FILE_DELETE);
    EXPECT_EQ(a.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(a.action, ResponseAction::LOG));
    EXPECT_TRUE(HasAction(a.action, ResponseAction::ALERT_USER));
    EXPECT_FALSE(HasAction(a.action, ResponseAction::ENCRYPT));
}

TEST_F(EventClassificationTestFixture, FileCompressIsLevel1) {
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto a = BuildEventResponse(cfg, DriverEventType::FILE_COMPRESS);
    EXPECT_EQ(a.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(a.action, ResponseAction::ALERT_USER));
}

TEST_F(EventClassificationTestFixture, NetworkTransferIsLevel1NotLevel3) {
    Config cfg(m_configPath);
    ASSERT_TRUE(cfg.Load());
    auto a = BuildEventResponse(cfg, DriverEventType::FILE_NETWORK_TRANSFER);
    EXPECT_TRUE(a.level <= ThreatLevel::LEVEL_2);
    EXPECT_FALSE(HasAction(a.action, ResponseAction::ENCRYPT));
    EXPECT_FALSE(HasAction(a.action, ResponseAction::WIPE));
    EXPECT_FALSE(HasAction(a.action, ResponseAction::LOCKDOWN));
}

/* ============================================
 * Real ThreatEvaluator batch threshold tests
 * ============================================ */

TEST_F(ThreatEvaluatorBatchTest, BelowThresholdReturnsNone) {
    for (int i = 0; i < 5; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_WRITE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
}

TEST_F(ThreatEvaluatorBatchTest, Tier1FileWriteTriggersAtThreshold) {
    for (int i = 0; i < 9; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_WRITE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::FILE_WRITE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, Tier1DeleteTriggersAt5) {
    for (int i = 0; i < 4; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_DELETE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::FILE_DELETE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, Tier2FileWriteTriggersAt50) {
    for (int i = 0; i < 49; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_WRITE);
        evaluator.CheckBatchThresholds(ev);
    }
    auto ev = MakeEvent(DriverEventType::FILE_WRITE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_2);
}

TEST_F(ThreatEvaluatorBatchTest, Tier2DeleteTriggersAt20) {
    for (int i = 0; i < 19; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_DELETE);
        evaluator.CheckBatchThresholds(ev);
    }
    auto ev = MakeEvent(DriverEventType::FILE_DELETE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_2);
}

TEST_F(ThreatEvaluatorBatchTest, ZeroThresholdMeansUnlimited) {
    DetectionThresholds t1, t2;
    t1.file_write_count = 0;
    t1.file_write_window_seconds = 5;
    t2.file_write_count = 0;
    t2.file_write_window_seconds = 10;
    evaluator.SetTieredThresholds(t1, t2);

    for (int i = 0; i < 200; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_WRITE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
}

TEST_F(ThreatEvaluatorBatchTest, ProcessTerminationTier1At50) {
    for (int i = 0; i < 49; ++i) {
        auto ev = MakeEvent(DriverEventType::PROC_TERMINATE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::PROC_TERMINATE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, ProcessTerminationTier2At200) {
    for (int i = 0; i < 199; ++i) {
        auto ev = MakeEvent(DriverEventType::PROC_TERMINATE);
        evaluator.CheckBatchThresholds(ev);
    }
    auto ev = MakeEvent(DriverEventType::PROC_TERMINATE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_2);
}

TEST_F(ThreatEvaluatorBatchTest, MixedEventsIndependent) {
    for (int i = 0; i < 8; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_WRITE));
    }
    for (int i = 0; i < 3; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_DELETE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::FILE_WRITE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    ev = MakeEvent(DriverEventType::FILE_WRITE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, StatisticsCounter) {
    for (int i = 0; i < 5; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_WRITE));
    }
    EXPECT_EQ(evaluator.GetEvaluationsCount(), 5u);
}

/* ============================================
 * FILE_RENAME batch threshold tests
 * ============================================ */

TEST_F(ThreatEvaluatorBatchTest, Tier1RenameTriggersAtThreshold) {
    for (int i = 0; i < 9; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_RENAME);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::FILE_RENAME);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, Tier2RenameTriggersAt50) {
    for (int i = 0; i < 49; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_RENAME);
        evaluator.CheckBatchThresholds(ev);
    }
    auto ev = MakeEvent(DriverEventType::FILE_RENAME);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_2);
}

TEST_F(ThreatEvaluatorBatchTest, RenameZeroThreshold_Unlimited) {
    DetectionThresholds t1, t2;
    t1.file_rename_count = 0;
    t1.file_rename_window_seconds = 5;
    t2.file_rename_count = 0;
    t2.file_rename_window_seconds = 10;
    evaluator.SetTieredThresholds(t1, t2);

    for (int i = 0; i < 200; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_RENAME);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
}

TEST_F(ThreatEvaluatorBatchTest, RenameIndependentOfDelete) {
    for (int i = 0; i < 8; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_RENAME));
    }
    for (int i = 0; i < 4; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_DELETE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::FILE_RENAME);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    ev = MakeEvent(DriverEventType::FILE_RENAME);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, RenameTier1ThenContinueTier2) {
    for (int i = 0; i < 10; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_RENAME));
    }
    for (int i = 10; i < 49; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_RENAME);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
    }
    auto ev = MakeEvent(DriverEventType::FILE_RENAME);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_2);
}

/* ============================================
 * DetectionRule / DetectionThresholds defaults
 * ============================================ */

TEST(DetectionRuleTest, DetectionRuleDefaults) {
    DetectionRule rule;
    EXPECT_TRUE(rule.enabled);
    EXPECT_EQ(rule.threshold, 0);
    EXPECT_TRUE(rule.id.empty());
}

TEST(DetectionThresholdsTest, DefaultValues) {
    DetectionThresholds t;
    EXPECT_EQ(t.file_write_count, 10u);
    EXPECT_EQ(t.file_write_window_seconds, 5u);
    EXPECT_EQ(t.file_delete_count, 5u);
    EXPECT_EQ(t.process_termination_count, 50u);
}

TEST(DetectionThresholdsTest, DefaultValues_RenameIs10) {
    DetectionThresholds t;
    EXPECT_EQ(t.file_rename_count, 10u);
    EXPECT_EQ(t.file_rename_window_seconds, 5u);
}

TEST(DetectionThresholdsTest, DefaultValues_FileCreateIs15) {
    DetectionThresholds t;
    EXPECT_EQ(t.file_create_count, 15u);
    EXPECT_EQ(t.file_create_window_seconds, 5u);
}

/* ============================================
 * FILE_CREATE batch threshold tests (Gate 3)
 * ============================================ */

TEST_F(ThreatEvaluatorBatchTest, Tier1FileCreateTriggersAt15) {
    for (int i = 0; i < 14; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_CREATE);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::FILE_CREATE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, Tier2FileCreateTriggersAt50) {
    for (int i = 0; i < 49; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_CREATE));
    }
    auto ev = MakeEvent(DriverEventType::FILE_CREATE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_2);
}

/* ============================================
 * FILE_COMPRESS batch threshold tests (Gate 3)
 * ============================================ */

TEST_F(ThreatEvaluatorBatchTest, Tier1FileCompressTriggersAt50) {
    for (int i = 0; i < 49; ++i) {
        auto ev = MakeEvent(DriverEventType::FILE_COMPRESS);
        EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    }
    auto ev = MakeEvent(DriverEventType::FILE_COMPRESS);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}

TEST_F(ThreatEvaluatorBatchTest, Tier2FileCompressTriggersAt250) {
    for (int i = 0; i < 249; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_COMPRESS));
    }
    auto ev = MakeEvent(DriverEventType::FILE_COMPRESS);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_2);
}

/* ============================================
 * Cross-type independence (Gate 4)
 * ============================================ */

TEST_F(ThreatEvaluatorBatchTest, CreateWriteIndependent) {
    for (int i = 0; i < 8; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_CREATE));
    }
    for (int i = 0; i < 8; ++i) {
        evaluator.CheckBatchThresholds(MakeEvent(DriverEventType::FILE_WRITE));
    }
    auto ev = MakeEvent(DriverEventType::FILE_CREATE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    ev = MakeEvent(DriverEventType::FILE_WRITE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::NONE);
    ev = MakeEvent(DriverEventType::FILE_WRITE);
    EXPECT_EQ(evaluator.CheckBatchThresholds(ev), BatchThreatTier::TIER_1);
}