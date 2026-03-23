/**
 * @file test_common.cpp
 * @brief Unit tests for GuardianShield common library
 */

#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>
#include <filesystem>

// Mock Windows types for non-Windows testing
#ifdef _WIN32
#include <Windows.h>
#else
typedef unsigned long DWORD;
#define GetCurrentProcessId() 0
#endif

// Include headers
#include "../src/service/common/include/common_types.h"

// ============================================
// Common Types Tests
// ============================================

class CommonTypesTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(CommonTypesTest, MessageHeaderSize) {
    EXPECT_EQ(sizeof(Guardian::MessageHeader), Guardian::MESSAGE_HEADER_SIZE);
}

TEST_F(CommonTypesTest, MessageMagic) {
    EXPECT_EQ(Guardian::MESSAGE_MAGIC, 0x47554152U); // "GUAR"
}

TEST_F(CommonTypesTest, NodeIdEnumValues) {
    EXPECT_EQ(static_cast<uint8_t>(Guardian::NodeId::GUARDIAN_A), 0);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::NodeId::GUARDIAN_B), 1);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::NodeId::GUARDIAN_C), 2);
}

TEST_F(CommonTypesTest, MessageTypeEnumValues) {
    EXPECT_EQ(static_cast<uint8_t>(Guardian::MessageType::HEARTBEAT), 0x01);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::MessageType::HEARTBEAT_ACK), 0x02);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::MessageType::ALERT), 0x10);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::MessageType::COMMAND), 0x20);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::MessageType::EMERGENCY_TRIGGER), 0xFF);
}

TEST_F(CommonTypesTest, ThreatLevelEnumValues) {
    EXPECT_EQ(static_cast<uint8_t>(Guardian::ThreatLevel::LEVEL_0), 0);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::ThreatLevel::LEVEL_1), 1);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::ThreatLevel::LEVEL_2), 2);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::ThreatLevel::LEVEL_3), 3);
}

TEST_F(CommonTypesTest, EmergencyStateEnumValues) {
    EXPECT_EQ(static_cast<uint8_t>(Guardian::EmergencyState::NORMAL), 0);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::EmergencyState::ALERT), 1);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::EmergencyState::ENCRYPTING), 2);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::EmergencyState::WIPING), 3);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::EmergencyState::DELETING), 4);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::EmergencyState::LOCKED), 5);
}

TEST_F(CommonTypesTest, GetCurrentTimestamp) {
    uint64_t ts = Guardian::GetCurrentTimestamp();
    EXPECT_GT(ts, 0);
    EXPECT_LT(ts, 2000000000000ULL); // Before year 2033
}

TEST_F(CommonTypesTest, NodeIdToString) {
    EXPECT_STREQ(Guardian::NodeIdToString(Guardian::NodeId::GUARDIAN_A), "GuardianA");
    EXPECT_STREQ(Guardian::NodeIdToString(Guardian::NodeId::GUARDIAN_B), "GuardianB");
    EXPECT_STREQ(Guardian::NodeIdToString(Guardian::NodeId::GUARDIAN_C), "GuardianC");
}

TEST_F(CommonTypesTest, ThreatLevelToString) {
    EXPECT_STREQ(Guardian::ThreatLevelToString(Guardian::ThreatLevel::LEVEL_0), "Normal");
    EXPECT_STREQ(Guardian::ThreatLevelToString(Guardian::ThreatLevel::LEVEL_1), "Suspicious");
    EXPECT_STREQ(Guardian::ThreatLevelToString(Guardian::ThreatLevel::LEVEL_2), "Dangerous");
    EXPECT_STREQ(Guardian::ThreatLevelToString(Guardian::ThreatLevel::LEVEL_3), "Critical");
}

TEST_F(CommonTypesTest, EmergencyStateToString) {
    EXPECT_STREQ(Guardian::EmergencyStateToString(Guardian::EmergencyState::NORMAL), "Normal");
    EXPECT_STREQ(Guardian::EmergencyStateToString(Guardian::EmergencyState::ALERT), "Alert");
    EXPECT_STREQ(Guardian::EmergencyStateToString(Guardian::EmergencyState::ENCRYPTING), "Encrypting");
    EXPECT_STREQ(Guardian::EmergencyStateToString(Guardian::EmergencyState::WIPING), "Wiping");
    EXPECT_STREQ(Guardian::EmergencyStateToString(Guardian::EmergencyState::LOCKED), "Locked");
}

TEST_F(CommonTypesTest, HeartbeatPayloadSize) {
    // Just verify it can be instantiated
    Guardian::HeartbeatPayload payload;
    payload.process_id = GetCurrentProcessId();
    payload.thread_count = 1;
    payload.memory_usage = 1024 * 1024;
    payload.cpu_usage = 5000;
    payload.uptime = 3600;
    payload.status = 0;
    payload.nonce = 1;
    
    EXPECT_EQ(payload.process_id, GetCurrentProcessId());
    EXPECT_EQ(payload.thread_count, 1);
}

TEST_F(CommonTypesTest, AlertPayloadFields) {
    Guardian::AlertPayload alert;
    alert.level = static_cast<uint8_t>(Guardian::ThreatLevel::LEVEL_2);
    alert.source_type = 0;
    alert.event_type = static_cast<uint8_t>(Guardian::DriverEventType::FILE_MOVE);
    alert.process_id = 1234;
    alert.timestamp = Guardian::GetCurrentTimestamp();
    
    EXPECT_EQ(alert.level, 2);
    EXPECT_EQ(alert.process_id, 1234);
}

TEST_F(CommonTypesTest, ProtectedDirectoryDefaults) {
    Guardian::ProtectedDirectory dir;
    EXPECT_TRUE(dir.recursive);
    EXPECT_EQ(dir.priority, 0);
}

TEST_F(CommonTypesTest, DetectionRuleDefaults) {
    Guardian::DetectionRule rule;
    EXPECT_TRUE(rule.enabled);
    EXPECT_EQ(rule.threshold, 0);
}

TEST_F(CommonTypesTest, SystemConfigDefaults) {
    Guardian::SystemConfig config;
    EXPECT_EQ(config.version, "1.0.0");
    EXPECT_EQ(config.log_level, "INFO");
    EXPECT_EQ(config.encrypt_timeout_seconds, 30);
    EXPECT_EQ(config.recovery_wait_seconds, 30);
    EXPECT_EQ(config.wipe_method, "DOD_5220");
    EXPECT_EQ(config.tcp_port_base, 17500);
    EXPECT_TRUE(config.tls_enabled);
}

// ============================================
// ResponseAction Tests
// ============================================

TEST_F(CommonTypesTest, ResponseActionFlags) {
    uint8_t actions = static_cast<uint8_t>(Guardian::ResponseAction::LOG) |
                     static_cast<uint8_t>(Guardian::ResponseAction::ALERT_USER);
    
    EXPECT_TRUE(actions & static_cast<uint8_t>(Guardian::ResponseAction::LOG));
    EXPECT_TRUE(actions & static_cast<uint8_t>(Guardian::ResponseAction::ALERT_USER));
    EXPECT_FALSE(actions & static_cast<uint8_t>(Guardian::ResponseAction::TERMINATE));
}

// ============================================
// DriverEventType Tests
// ============================================

TEST_F(CommonTypesTest, DriverEventTypeValues) {
    EXPECT_EQ(static_cast<uint8_t>(Guardian::DriverEventType::FILE_CREATE), 0x01);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::DriverEventType::FILE_WRITE), 0x03);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::DriverEventType::FILE_DELETE), 0x04);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::DriverEventType::FILE_MOVE), 0x07);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::DriverEventType::PROCESS_CREATE), 0x10);
    EXPECT_EQ(static_cast<uint8_t>(Guardian::DriverEventType::DRIVER_LOAD), 0x30);
}

// ============================================
// Multi-threaded Tests
// ============================================

TEST_F(CommonTypesTest, ThreadSafeTimestamp) {
    std::vector<uint64_t> timestamps;
    std::vector<std::thread> threads;
    std::mutex mtx;
    
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&timestamps, &mtx]() {
            for (int j = 0; j < 100; j++) {
                uint64_t ts = Guardian::GetCurrentTimestamp();
                std::lock_guard<std::mutex> lock(mtx);
                timestamps.push_back(ts);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(timestamps.size(), 1000);
    
    // All timestamps should be unique (with 1ms sleep)
    std::sort(timestamps.begin(), timestamps.end());
    auto last = std::unique(timestamps.begin(), timestamps.end());
    EXPECT_GT(std::distance(timestamps.begin(), last), 500); // At least 50% unique
}

// ============================================
// Main
// ============================================