#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "../src/service/common/include/common_types.h"
#include "../src/service/common/include/config.h"
#include "../src/service/GuardianA/include/threat_evaluator.h"

using namespace Guardian;

namespace {

DriverEvent MakeDriverEvent(
    DriverEventType eventType,
    const wchar_t* filePath = L"C:\\test\\sample.txt",
    const wchar_t* processName = L"explorer.exe",
    uint32_t processId = 1234)
{
    DriverEvent ev = {};
    ev.event_type = static_cast<uint32_t>(eventType);
    ev.process_id = processId;
    ev.timestamp = 0;
    if (filePath) {
        wcsncpy(ev.file_path, filePath, MAX_PATH_LENGTH - 1);
    }
    if (processName) {
        wcsncpy(ev.process_name, processName, MAX_PROCESS_NAME - 1);
    }
    return ev;
}

}

class ETWPipelineTest : public ::testing::Test {
protected:
    ThreatEvaluator evaluator;
    std::wstring testDir;
    std::wstring configPath;

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
        tier1.file_move_count = 10;
        tier1.file_move_window_seconds = 5;
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
        tier2.file_move_count = 50;
        tier2.file_move_window_seconds = 10;
        tier2.data_transfer_mb = 10;
        tier2.process_termination_count = 200;

        evaluator.SetTieredThresholds(tier1, tier2);

        testDir = L".\\test_etw_pipeline_data";
        std::filesystem::create_directories(testDir);
        configPath = testDir + L"\\guardian_config.yaml";
        std::ofstream f(configPath);
        f << "system:\n  version: '1.0'\n";
        f.close();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(testDir, ec);
        std::filesystem::remove(L"C:\\ProgramData\\GuardianShield\\config_cache.bin", ec);
    }

    SingleEventAssessment Classify(const DriverEvent& event) const {
        Config cfg(configPath);
        EXPECT_TRUE(cfg.Load());
        return BuildEventResponse(cfg, static_cast<DriverEventType>(event.event_type));
    }
};

TEST_F(ETWPipelineTest, FileCreateEventIsClassifiedAsNormalOrSuspicious) {
    auto event = MakeDriverEvent(DriverEventType::FILE_CREATE);
    const auto assessment = Classify(event);
    EXPECT_LE(assessment.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::LOG));
}

TEST_F(ETWPipelineTest, FileWriteEventIsClassified) {
    auto event = MakeDriverEvent(DriverEventType::FILE_WRITE);
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ALERT_USER));
}

TEST_F(ETWPipelineTest, FileDeleteEventIsClassified) {
    auto event = MakeDriverEvent(DriverEventType::FILE_DELETE);
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ALERT_USER));
}

TEST_F(ETWPipelineTest, FileRenameEventIsClassified) {
    auto event = MakeDriverEvent(DriverEventType::FILE_RENAME);
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ALERT_USER));
}

TEST_F(ETWPipelineTest, FileCompressFrom7zIsClassifiedAsSuspicious) {
    auto event = MakeDriverEvent(
        DriverEventType::FILE_COMPRESS,
        L"C:\\docs\\archive.7z",
        L"7z.exe");
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ALERT_USER));
}

TEST_F(ETWPipelineTest, NetworkTransferFromCurlIsClassifiedAsSuspicious) {
    auto event = MakeDriverEvent(
        DriverEventType::FILE_NETWORK_TRANSFER,
        L"C:\\docs\\payload.bin",
        L"curl.exe");
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ALERT_USER));
}

TEST_F(ETWPipelineTest, FileMoveCorrelatedFromCreateDeleteIsClassified) {
    auto event = MakeDriverEvent(DriverEventType::FILE_MOVE, L"C:\\target\\moved.txt");
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_1);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::ALERT_USER));
}

TEST_F(ETWPipelineTest, ProcessCreateEventIsClassified) {
    auto event = MakeDriverEvent(DriverEventType::PROCESS_CREATE, nullptr, L"powershell.exe");
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_0);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::LOG));
}

TEST_F(ETWPipelineTest, ProcessTerminateEventIsClassified) {
    auto event = MakeDriverEvent(DriverEventType::PROC_TERMINATE, nullptr, L"notepad.exe");
    const auto assessment = Classify(event);
    EXPECT_EQ(assessment.level, ThreatLevel::LEVEL_0);
    EXPECT_TRUE(HasAction(assessment.action, ResponseAction::LOG));
}

TEST_F(ETWPipelineTest, BatchThresholdElevenFileWritesExceedsTier1) {
    BatchThreatTier tier = BatchThreatTier::NONE;
    for (int i = 0; i < 11; ++i) {
        auto event = MakeDriverEvent(DriverEventType::FILE_WRITE, L"C:\\test\\burst.txt", L"app.exe");
        tier = evaluator.CheckBatchThresholds(event);
    }

    EXPECT_EQ(tier, BatchThreatTier::TIER_1);
}

TEST_F(ETWPipelineTest, BatchThresholdFiftyOneFileWritesExceedsTier2) {
    BatchThreatTier tier = BatchThreatTier::NONE;
    for (int i = 0; i < 51; ++i) {
        auto event = MakeDriverEvent(DriverEventType::FILE_WRITE, L"C:\\test\\flood.txt", L"app.exe");
        tier = evaluator.CheckBatchThresholds(event);
    }

    EXPECT_EQ(tier, BatchThreatTier::TIER_2);
}
