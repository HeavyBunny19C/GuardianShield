/**
 * @file test_state_sync.cpp
 * @brief Unit tests for state synchronization (P1-3 + P2-3 fix verification)
 *
 * Verifies:
 * - SharedMemory emergency state transitions
 * - State round-trip through shared memory
 * - NORMAL state correctly restorable (CancelEmergency path)
 */

#include <gtest/gtest.h>
#include "../src/service/common/include/ipc.h"
#include "../src/service/common/include/common_types.h"

#if defined(_WIN32) && __has_include(<Windows.h>)
#include <Windows.h>
#include <chrono>
#include <future>
#include <thread>
#define GUARDIAN_TEST_WINDOWS_MUTEX_API 1
#endif

using namespace Guardian;

class StateSyncTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(StateSyncTest, SharedMemoryEmergencyStateRoundTrip) {
    SharedMemory shm(L"Local\\GuardianTestStateSync", sizeof(SharedStateBlock), true);
    ASSERT_TRUE(shm.IsValid());

    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::NORMAL);

    shm.SetEmergencyState(EmergencyState::ALERT);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::ALERT);

    shm.SetEmergencyState(EmergencyState::ENCRYPTING);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::ENCRYPTING);

    shm.SetEmergencyState(EmergencyState::WIPING);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::WIPING);

    shm.SetEmergencyState(EmergencyState::LOCKED);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::LOCKED);
}

TEST_F(StateSyncTest, CancelRestoresNormal) {
    SharedMemory shm(L"Local\\GuardianTestCancel", sizeof(SharedStateBlock), true);
    ASSERT_TRUE(shm.IsValid());

    shm.SetEmergencyState(EmergencyState::ALERT);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::ALERT);

    shm.SetEmergencyState(EmergencyState::NORMAL);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::NORMAL);
}

TEST_F(StateSyncTest, StateVisibleAcrossInstances) {
    SharedMemory writer(L"Local\\GuardianTestCrossSync", sizeof(SharedStateBlock), true);
    ASSERT_TRUE(writer.IsValid());

    writer.SetEmergencyState(EmergencyState::ENCRYPTING);

    SharedMemory reader(L"Local\\GuardianTestCrossSync", sizeof(SharedStateBlock), false);
    ASSERT_TRUE(reader.IsValid());

    EXPECT_EQ(reader.GetEmergencyState(), EmergencyState::ENCRYPTING);

    writer.SetEmergencyState(EmergencyState::NORMAL);
    EXPECT_EQ(reader.GetEmergencyState(), EmergencyState::NORMAL);
}

TEST_F(StateSyncTest, Tier1Progression) {
    SharedMemory shm(L"Local\\GuardianTestTier1Prog", sizeof(SharedStateBlock), true);
    ASSERT_TRUE(shm.IsValid());

    shm.SetEmergencyState(EmergencyState::ALERT);
    shm.SetEmergencyState(EmergencyState::ENCRYPTING);
    shm.SetEmergencyState(EmergencyState::LOCKED);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::LOCKED);
}

TEST_F(StateSyncTest, Tier2FullProgression) {
    SharedMemory shm(L"Local\\GuardianTestTier2Prog", sizeof(SharedStateBlock), true);
    ASSERT_TRUE(shm.IsValid());

    shm.SetEmergencyState(EmergencyState::ALERT);
    shm.SetEmergencyState(EmergencyState::ENCRYPTING);
    shm.SetEmergencyState(EmergencyState::WIPING);
    shm.SetEmergencyState(EmergencyState::DELETING);
    shm.SetEmergencyState(EmergencyState::LOCKED);
    EXPECT_EQ(shm.GetEmergencyState(), EmergencyState::LOCKED);
}

#ifdef GUARDIAN_TEST_WINDOWS_MUTEX_API
class FailoverTest : public ::testing::Test {
protected:
    static constexpr wchar_t kLeaderMutexName[] = L"Global\\GuardianShield-Leader";
    static constexpr uint32_t kHeartbeatIntervalMs = 500;
    static constexpr uint32_t kMaxMissedHeartbeats = 3;

    static bool IsHeartbeatStale(uint32_t previousNonce,
                                 uint32_t currentNonce,
                                 uint32_t missedBeats) {
        return (previousNonce == currentNonce) && (missedBeats >= kMaxMissedHeartbeats);
    }
};

TEST_F(FailoverTest, AcquireLeaderMutexSucceedsWhenUnheld) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, kLeaderMutexName);
    ASSERT_NE(hMutex, nullptr);

    DWORD waitResult = WaitForSingleObject(hMutex, 0);
    EXPECT_EQ(waitResult, WAIT_OBJECT_0);

    if (waitResult == WAIT_OBJECT_0 || waitResult == WAIT_ABANDONED) {
        EXPECT_TRUE(ReleaseMutex(hMutex));
    }
    EXPECT_TRUE(CloseHandle(hMutex));
}

TEST_F(FailoverTest, SecondPromotionAttemptTimesOutWhileLeaderHeld) {
    HANDLE hLeaderA = CreateMutexW(NULL, FALSE, kLeaderMutexName);
    HANDLE hLeaderB = CreateMutexW(NULL, FALSE, kLeaderMutexName);
    ASSERT_NE(hLeaderA, nullptr);
    ASSERT_NE(hLeaderB, nullptr);

    ASSERT_EQ(WaitForSingleObject(hLeaderA, 0), WAIT_OBJECT_0);

    std::promise<DWORD> secondAttemptPromise;
    auto secondAttempt = secondAttemptPromise.get_future();
    std::thread contender([&]() {
        secondAttemptPromise.set_value(WaitForSingleObject(hLeaderB, 0));
    });

    EXPECT_EQ(secondAttempt.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_EQ(secondAttempt.get(), WAIT_TIMEOUT);

    EXPECT_TRUE(ReleaseMutex(hLeaderA));
    contender.join();
    EXPECT_TRUE(CloseHandle(hLeaderB));
    EXPECT_TRUE(CloseHandle(hLeaderA));
}

TEST_F(FailoverTest, ReleasedLeaderMutexCanBeReacquired) {
    HANDLE hLeaderA = CreateMutexW(NULL, FALSE, kLeaderMutexName);
    HANDLE hLeaderB = CreateMutexW(NULL, FALSE, kLeaderMutexName);
    ASSERT_NE(hLeaderA, nullptr);
    ASSERT_NE(hLeaderB, nullptr);

    ASSERT_EQ(WaitForSingleObject(hLeaderA, 0), WAIT_OBJECT_0);
    EXPECT_EQ(WaitForSingleObject(hLeaderB, 0), WAIT_TIMEOUT);

    EXPECT_TRUE(ReleaseMutex(hLeaderA));
    DWORD takeoverResult = WaitForSingleObject(hLeaderB, 0);
    EXPECT_EQ(takeoverResult, WAIT_OBJECT_0);

    if (takeoverResult == WAIT_OBJECT_0 || takeoverResult == WAIT_ABANDONED) {
        EXPECT_TRUE(ReleaseMutex(hLeaderB));
    }
    EXPECT_TRUE(CloseHandle(hLeaderB));
    EXPECT_TRUE(CloseHandle(hLeaderA));
}

TEST_F(FailoverTest, AbandonedLeaderMutexCanBeAcquiredForFailover) {
    HANDLE hObserver = CreateMutexW(NULL, FALSE, kLeaderMutexName);
    ASSERT_NE(hObserver, nullptr);

    std::promise<void> ownerAcquired;
    auto ownerReady = ownerAcquired.get_future();

    std::thread crashedOwner([&]() {
        HANDLE hOwner = CreateMutexW(NULL, FALSE, kLeaderMutexName);
        if (!hOwner) {
            ownerAcquired.set_value();
            return;
        }

        DWORD waitResult = WaitForSingleObject(hOwner, 0);
        if (waitResult == WAIT_OBJECT_0) {
            ownerAcquired.set_value();
            CloseHandle(hOwner);
            return;
        }

        ownerAcquired.set_value();
        CloseHandle(hOwner);
    });

    ASSERT_EQ(ownerReady.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    crashedOwner.join();

    DWORD takeoverResult = WaitForSingleObject(hObserver, 0);
    EXPECT_EQ(takeoverResult, WAIT_ABANDONED);

    if (takeoverResult == WAIT_OBJECT_0 || takeoverResult == WAIT_ABANDONED) {
        EXPECT_TRUE(ReleaseMutex(hObserver));
    }
    EXPECT_TRUE(CloseHandle(hObserver));
}

TEST_F(FailoverTest, HeartbeatNonceStallTriggersMissedBeatThreshold) {
    SharedMemory shm(L"Local\\GuardianFailoverHeartbeat", sizeof(SharedStateBlock), true);
    ASSERT_TRUE(shm.IsValid());

    SharedStateBlock* state = shm.GetStateBlock();
    ASSERT_NE(state, nullptr);

    state->heartbeats[0].nonce = 42;
    uint32_t observedNonce = state->heartbeats[0].nonce;
    uint32_t missedBeats = 0;

    for (uint32_t i = 0; i < kMaxMissedHeartbeats; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(kHeartbeatIntervalMs));

        uint32_t currentNonce = state->heartbeats[0].nonce;
        if (currentNonce == observedNonce) {
            ++missedBeats;
        } else {
            observedNonce = currentNonce;
            missedBeats = 0;
        }
    }

    EXPECT_TRUE(IsHeartbeatStale(observedNonce, state->heartbeats[0].nonce, missedBeats));
    EXPECT_GE(missedBeats, kMaxMissedHeartbeats);
}
#endif
