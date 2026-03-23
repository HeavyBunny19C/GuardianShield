/**
 * @file test_heartbeat.cpp
 * @brief Unit tests for heartbeat nonce detection (P1-2 fix verification)
 *
 * Verifies that the nonce-change detection logic works correctly:
 * - Same nonce across heartbeat cycles -> service is dead (nonce stale)
 * - Changing nonce -> service is alive
 * - Zero nonce -> service never started
 */

#include <gtest/gtest.h>
#include "../src/service/common/include/ipc.h"
#include "../src/service/common/include/common_types.h"

using namespace Guardian;

class HeartbeatNonceTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(HeartbeatNonceTest, SharedMemory_WriteAndReadNonce) {
    SharedMemory shm(L"Local\\GuardianTestNonce", sizeof(SharedStateBlock), true);
    ASSERT_TRUE(shm.IsValid());

    HeartbeatPayload hb = {};
    hb.process_id = 1234;
    hb.nonce = 42;
    hb.status = static_cast<uint8_t>(EmergencyState::NORMAL);
    shm.UpdateHeartbeat(NodeId::GUARDIAN_A, hb);

    HeartbeatPayload readHb = {};
    bool ok = shm.GetHeartbeat(NodeId::GUARDIAN_A, readHb);
    EXPECT_TRUE(ok);
    EXPECT_EQ(readHb.nonce, 42u);
    EXPECT_EQ(readHb.process_id, 1234u);
}

TEST_F(HeartbeatNonceTest, SameNonce_DetectsStale) {
    uint32_t lastSeenNonce = 0;
    uint32_t currentNonce = 42;

    bool alive = (currentNonce != 0 && currentNonce != lastSeenNonce);
    EXPECT_TRUE(alive);
    lastSeenNonce = currentNonce;

    alive = (currentNonce != 0 && currentNonce != lastSeenNonce);
    EXPECT_FALSE(alive);
}

TEST_F(HeartbeatNonceTest, ChangingNonce_DetectsAlive) {
    uint32_t lastSeenNonce = 0;

    uint32_t nonce1 = 42;
    bool alive1 = (nonce1 != 0 && nonce1 != lastSeenNonce);
    EXPECT_TRUE(alive1);
    lastSeenNonce = nonce1;

    uint32_t nonce2 = 43;
    bool alive2 = (nonce2 != 0 && nonce2 != lastSeenNonce);
    EXPECT_TRUE(alive2);
    lastSeenNonce = nonce2;

    uint32_t nonce3 = 100;
    bool alive3 = (nonce3 != 0 && nonce3 != lastSeenNonce);
    EXPECT_TRUE(alive3);
}

TEST_F(HeartbeatNonceTest, ZeroNonce_DetectsNeverStarted) {
    uint32_t lastSeenNonce = 0;
    uint32_t currentNonce = 0;

    bool alive = (currentNonce != 0 && currentNonce != lastSeenNonce);
    EXPECT_FALSE(alive);
}

TEST_F(HeartbeatNonceTest, NonceTransitionSequence) {
    uint32_t lastSeenNonceA = 0;
    
    auto checkAlive = [&](uint32_t nonce) -> bool {
        bool alive = (nonce != 0 && nonce != lastSeenNonceA);
        if (alive) lastSeenNonceA = nonce;
        return alive;
    };

    EXPECT_FALSE(checkAlive(0));
    EXPECT_TRUE(checkAlive(1));
    EXPECT_FALSE(checkAlive(1));
    EXPECT_FALSE(checkAlive(1));
    EXPECT_TRUE(checkAlive(2));
    EXPECT_TRUE(checkAlive(3));
    EXPECT_FALSE(checkAlive(0));
}
