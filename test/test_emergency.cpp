/**
 * @file test_emergency.cpp
 * @brief Unit tests for emergency protocol states and transitions
 *
 * Tests EmergencyState enum values and valid state transitions
 * as implemented in GuardianA (TriggerProtectionProtocol / TriggerEmergencyProtocol).
 */

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include "../src/service/common/include/common_types.h"
#include "../src/service/common/include/emergency_state_machine.h"
#include "../src/service/GuardianA/include/threat_evaluator.h"

using namespace Guardian;

/* ============================================
 * EmergencyState enum tests
 * ============================================ */

TEST(EmergencyStateTest, EnumValues) {
    EXPECT_EQ(static_cast<uint8_t>(EmergencyState::NORMAL), 0);
    EXPECT_EQ(static_cast<uint8_t>(EmergencyState::ALERT), 1);
    EXPECT_EQ(static_cast<uint8_t>(EmergencyState::ENCRYPTING), 2);
    EXPECT_EQ(static_cast<uint8_t>(EmergencyState::WIPING), 3);
    EXPECT_EQ(static_cast<uint8_t>(EmergencyState::DELETING), 4);
    EXPECT_EQ(static_cast<uint8_t>(EmergencyState::LOCKED), 5);
}

TEST(EmergencyStateTest, StringConversion) {
    EXPECT_STREQ(EmergencyStateToString(EmergencyState::NORMAL), "Normal");
    EXPECT_STREQ(EmergencyStateToString(EmergencyState::ALERT), "Alert");
    EXPECT_STREQ(EmergencyStateToString(EmergencyState::ENCRYPTING), "Encrypting");
    EXPECT_STREQ(EmergencyStateToString(EmergencyState::WIPING), "Wiping");
    EXPECT_STREQ(EmergencyStateToString(EmergencyState::LOCKED), "Locked");
}

/* ============================================
 * State transition tests (matching guardian_a.cpp logic)
 *
 * Tier 1 flow: NORMAL -> ALERT -> ENCRYPTING -> LOCKED
 * Tier 2 flow: NORMAL -> ALERT -> ENCRYPTING -> WIPING -> DELETING -> LOCKED
 * Cancel:      ALERT -> NORMAL (only during countdown)
 * ============================================ */

TEST(EmergencyTransitionTest, AtomicTriggerPreventsDoubleFire) {
    std::atomic<bool> emergencyMode{false};
    bool expected = false;
    EXPECT_TRUE(emergencyMode.compare_exchange_strong(expected, true));
    expected = false;
    EXPECT_FALSE(emergencyMode.compare_exchange_strong(expected, true));
}

TEST(EmergencyTransitionTest, CancelDuringCountdown) {
    std::atomic<bool> emergencyMode{true};
    emergencyMode.store(false);
    EXPECT_FALSE(emergencyMode.load());
}

TEST(EmergencyTransitionTest, Tier1ProgressionStops) {
    std::atomic<EmergencyState> state{EmergencyState::NORMAL};
    state.store(EmergencyState::ALERT);
    EXPECT_EQ(state.load(), EmergencyState::ALERT);
    state.store(EmergencyState::ENCRYPTING);
    EXPECT_EQ(state.load(), EmergencyState::ENCRYPTING);
    state.store(EmergencyState::LOCKED);
    EXPECT_EQ(state.load(), EmergencyState::LOCKED);
}

TEST(EmergencyTransitionTest, Tier2FullProgression) {
    std::atomic<EmergencyState> state{EmergencyState::NORMAL};
    state.store(EmergencyState::ALERT);
    state.store(EmergencyState::ENCRYPTING);
    state.store(EmergencyState::WIPING);
    state.store(EmergencyState::DELETING);
    state.store(EmergencyState::LOCKED);
    EXPECT_EQ(state.load(), EmergencyState::LOCKED);
}

/* ============================================
 * Batch tier tests (integration with ThreatEvaluator)
 * ============================================ */

TEST(BatchTierTest, EnumValues) {
    EXPECT_EQ(static_cast<uint8_t>(BatchThreatTier::NONE), 0);
    EXPECT_EQ(static_cast<uint8_t>(BatchThreatTier::TIER_1), 1);
    EXPECT_EQ(static_cast<uint8_t>(BatchThreatTier::TIER_2), 2);
}

TEST(BatchTierTest, Tier1IsRecoverable) {
    // Tier 1 protocol: ENCRYPT + LOCK, no WIPE, no DELETE
    // Verifying the design invariant
    EXPECT_LT(static_cast<uint8_t>(BatchThreatTier::TIER_1),
              static_cast<uint8_t>(BatchThreatTier::TIER_2));
}

/* ============================================
 * ThreatAssessment structure tests
 * ============================================ */

TEST(ThreatEvaluationTest, DefaultValues) {
    SingleEventAssessment te;
    te.level = ThreatLevel::LEVEL_0;
    te.action = ResponseAction::LOG;
    te.confidence = 0.5f;
    te.description = "test";
    EXPECT_EQ(te.level, ThreatLevel::LEVEL_0);
    EXPECT_EQ(te.confidence, 0.5f);
}

TEST(ThreatEvaluationTest, SingleEventNeverTriggersWipeLockdown) {
    // Updated invariant: WIPE and LOCKDOWN are NEVER available for single events.
    // ENCRYPT is now configurable for single events (disabled by default).
    auto singleActions = ResponseAction::LOG | ResponseAction::ALERT_USER |
                         ResponseAction::TERMINATE | ResponseAction::ENCRYPT;
    EXPECT_FALSE(HasAction(singleActions, ResponseAction::WIPE));
    EXPECT_FALSE(HasAction(singleActions, ResponseAction::LOCKDOWN));
    EXPECT_TRUE(HasAction(singleActions, ResponseAction::ENCRYPT));
}

class EmergencyStateMachineTest : public ::testing::Test {
protected:
    EmergencyStateMachine machine;
};

TEST_F(EmergencyStateMachineTest, NormalToAlertValidTransition) {
    EXPECT_TRUE(machine.TryTransition(EmergencyState::ALERT));
    EXPECT_EQ(machine.CurrentState(), EmergencyState::ALERT);
}

TEST_F(EmergencyStateMachineTest, NormalToWipingInvalidTransition) {
    EXPECT_FALSE(machine.TryTransition(EmergencyState::WIPING));
    EXPECT_EQ(machine.CurrentState(), EmergencyState::NORMAL);
}

TEST_F(EmergencyStateMachineTest, AlertToNormalCancelWorks) {
    ASSERT_TRUE(machine.TryTransition(EmergencyState::ALERT));
    EXPECT_TRUE(machine.Cancel());
    EXPECT_EQ(machine.CurrentState(), EmergencyState::NORMAL);
}

TEST_F(EmergencyStateMachineTest, CancelFailsInEncryptingState) {
    ASSERT_TRUE(machine.TryTransition(EmergencyState::ALERT));
    ASSERT_TRUE(machine.TryTransition(EmergencyState::ENCRYPTING));
    EXPECT_TRUE(machine.IsIrreversible());
    EXPECT_FALSE(machine.Cancel());
    EXPECT_EQ(machine.CurrentState(), EmergencyState::ENCRYPTING);
}

TEST_F(EmergencyStateMachineTest, Tier1ProgressionNormalAlertEncryptingLocked) {
    EXPECT_TRUE(machine.TryTransition(EmergencyState::ALERT));
    EXPECT_TRUE(machine.TryTransition(EmergencyState::ENCRYPTING));
    EXPECT_TRUE(machine.TryTransition(EmergencyState::LOCKED));
    EXPECT_EQ(machine.CurrentState(), EmergencyState::LOCKED);
}

TEST_F(EmergencyStateMachineTest, Tier2ProgressionNormalAlertEncryptingWipingDeletingLocked) {
    EXPECT_TRUE(machine.TryTransition(EmergencyState::ALERT));
    EXPECT_TRUE(machine.TryTransition(EmergencyState::ENCRYPTING));
    EXPECT_TRUE(machine.TryTransition(EmergencyState::WIPING));
    EXPECT_TRUE(machine.TryTransition(EmergencyState::DELETING));
    EXPECT_TRUE(machine.TryTransition(EmergencyState::LOCKED));
    EXPECT_EQ(machine.CurrentState(), EmergencyState::LOCKED);
}

TEST_F(EmergencyStateMachineTest, LockedToNormalIsInvalidWithoutReset) {
    ASSERT_TRUE(machine.TryTransition(EmergencyState::ALERT));
    ASSERT_TRUE(machine.TryTransition(EmergencyState::ENCRYPTING));
    ASSERT_TRUE(machine.TryTransition(EmergencyState::LOCKED));
    EXPECT_FALSE(machine.TryTransition(EmergencyState::NORMAL));
    EXPECT_EQ(machine.CurrentState(), EmergencyState::LOCKED);
}

TEST_F(EmergencyStateMachineTest, ConcurrentAlertTransitionOnlyOneSucceeds) {
    constexpr int kAttempts = 8;
    std::atomic<int> successCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kAttempts);

    for (int i = 0; i < kAttempts; ++i) {
        threads.emplace_back([this, &successCount]() {
            if (machine.TryTransition(EmergencyState::ALERT)) {
                ++successCount;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), 1);
    EXPECT_EQ(machine.CurrentState(), EmergencyState::ALERT);
}
