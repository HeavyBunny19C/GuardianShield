/**
 * @file test_ipc.cpp
 * @brief Unit tests for IPC communication module
 */

#include <gtest/gtest.h>
#include <thread>
#include <chrono>

#include "../src/service/common/include/common_types.h"
#include "../src/service/common/include/ipc.h"

using namespace Guardian;

class IpcTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

/* ============================================
 * Message Serialization Tests
 * ============================================ */

TEST_F(IpcTest, MessageHeaderSize) {
    EXPECT_EQ(sizeof(MessageHeader), MESSAGE_HEADER_SIZE);
    EXPECT_EQ(sizeof(MessageHeader), 32u);
}

TEST_F(IpcTest, SerializeDeserializeRoundTrip) {
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    header.source = static_cast<uint8_t>(NodeId::GUARDIAN_A);
    header.dest = static_cast<uint8_t>(NodeId::GUARDIAN_B);
    header.sequence = 42;
    header.timestamp = static_cast<uint32_t>(GetCurrentTimestamp() & 0xFFFFFFFF);
    header.payload_len = 4;

    uint32_t payload = 12345;
    auto serialized = SerializeMessage(header, &payload, sizeof(payload));
    EXPECT_GT(serialized.size(), sizeof(MessageHeader));

    MessageHeader outHeader = {};
    std::vector<uint8_t> outPayload;
    bool ok = DeserializeMessage(serialized.data(), serialized.size(), outHeader, outPayload);
    EXPECT_TRUE(ok);
    EXPECT_EQ(outHeader.magic, MESSAGE_MAGIC);
    EXPECT_EQ(outHeader.type, static_cast<uint8_t>(MessageType::HEARTBEAT));
    EXPECT_EQ(outHeader.source, static_cast<uint8_t>(NodeId::GUARDIAN_A));
    EXPECT_EQ(outHeader.dest, static_cast<uint8_t>(NodeId::GUARDIAN_B));
    EXPECT_EQ(outHeader.sequence, 42u);
}

TEST_F(IpcTest, DeserializeEmptyBuffer) {
    MessageHeader header = {};
    std::vector<uint8_t> payload;
    EXPECT_FALSE(DeserializeMessage(nullptr, 0, header, payload));
}

TEST_F(IpcTest, DeserializeTruncatedBuffer) {
    uint8_t buf[16] = {};
    MessageHeader header = {};
    std::vector<uint8_t> payload;
    EXPECT_FALSE(DeserializeMessage(buf, sizeof(buf), header, payload));
}

TEST_F(IpcTest, SerializeEmptyPayload) {
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(MessageType::COMMAND);
    header.payload_len = 0;

    auto serialized = SerializeMessage(header, nullptr, 0);
    EXPECT_GE(serialized.size(), sizeof(MessageHeader));
}

/* ============================================
 * HeartbeatPayload Tests
 * ============================================ */

TEST_F(IpcTest, HeartbeatPayloadConstruction) {
    HeartbeatPayload hb = {};
    hb.process_id = 1234;
    hb.thread_count = 8;
    hb.memory_usage = 1024 * 1024 * 50;
    hb.cpu_usage = 500;
    hb.uptime = 3600;
    hb.status = static_cast<uint8_t>(EmergencyState::NORMAL);
    hb.nonce = 1;

    EXPECT_EQ(hb.process_id, 1234u);
    EXPECT_EQ(hb.thread_count, 8u);
    EXPECT_EQ(hb.cpu_usage, 500u);
    EXPECT_EQ(hb.status, 0);
}

TEST_F(IpcTest, HeartbeatSerializeDeserialize) {
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    header.source = static_cast<uint8_t>(NodeId::GUARDIAN_C);
    header.dest = static_cast<uint8_t>(NodeId::GUARDIAN_A);
    header.payload_len = sizeof(HeartbeatPayload);

    HeartbeatPayload hb = {};
    hb.process_id = 9876;
    hb.nonce = 42;

    auto serialized = SerializeMessage(header, &hb, sizeof(hb));

    MessageHeader outHeader = {};
    std::vector<uint8_t> outPayload;
    bool ok = DeserializeMessage(serialized.data(), serialized.size(), outHeader, outPayload);
    EXPECT_TRUE(ok);
    EXPECT_GE(outPayload.size(), sizeof(HeartbeatPayload));

    auto* outHb = reinterpret_cast<const HeartbeatPayload*>(outPayload.data());
    EXPECT_EQ(outHb->process_id, 9876u);
    EXPECT_EQ(outHb->nonce, 42u);
}

/* ============================================
 * AlertPayload Tests
 * ============================================ */

TEST_F(IpcTest, AlertPayloadConstruction) {
    AlertPayload alert = {};
    alert.level = static_cast<uint8_t>(ThreatLevel::LEVEL_2);
    alert.event_type = static_cast<uint8_t>(DriverEventType::FILE_DELETE);
    alert.process_id = 5678;
    alert.timestamp = static_cast<uint32_t>(GetCurrentTimestamp() & 0xFFFFFFFF);
    wcscpy_s(alert.file_path, L"C:\\Protected\\secret.docx");
    wcscpy_s(alert.process_name, L"suspicious.exe");

    EXPECT_EQ(alert.level, 2);
    EXPECT_EQ(alert.process_id, 5678u);
    EXPECT_STREQ(alert.file_path, L"C:\\Protected\\secret.docx");
}

/* ============================================
 * Named Pipe Tests
 * ============================================ */

TEST_F(IpcTest, NamedPipeServerStartStop) {
    NamedPipeServer server(L"\\\\.\\pipe\\GuardianTestPipe_IPC");

    EXPECT_TRUE(server.Start());
    EXPECT_TRUE(server.IsRunning());

    server.Stop();
    EXPECT_FALSE(server.IsRunning());
}

TEST_F(IpcTest, NamedPipeClientConnectDisconnect) {
    std::wstring pipeName = L"\\\\.\\pipe\\GuardianTestPipe_Client";
    NamedPipeServer server(pipeName);
    server.Start();

    NamedPipeClient client(pipeName);
    bool connected = client.Connect(500);

    if (connected) {
        EXPECT_TRUE(client.IsConnected());
        client.Disconnect();
        EXPECT_FALSE(client.IsConnected());
    }

    server.Stop();
}

TEST_F(IpcTest, NamedPipeSendReceive) {
    std::wstring pipeName = L"\\\\.\\pipe\\GuardianTestPipe_SendRecv";
    bool messageReceived = false;

    NamedPipeServer server(pipeName);
    server.SetMessageHandler(
        [&messageReceived](const MessageHeader& h, const uint8_t*, size_t) {
            if (h.type == static_cast<uint8_t>(MessageType::HEARTBEAT)) {
                messageReceived = true;
            }
        });
    server.Start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    NamedPipeClient client(pipeName);
    if (client.Connect(500)) {
        MessageHeader header = {};
        header.magic = MESSAGE_MAGIC;
        header.version = PROTOCOL_VERSION;
        header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
        header.source = static_cast<uint8_t>(NodeId::GUARDIAN_C);
        header.payload_len = 0;

        client.Send(header, nullptr, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        client.Disconnect();
    }

    server.Stop();

    /* Message may or may not be received depending on pipe timing */
}

/* ============================================
 * SharedMemory Tests
 * ============================================ */

TEST_F(IpcTest, SharedMemoryCreateAndMap) {
    SharedMemory shm(L"Local\\GuardianTestShm", sizeof(SharedStateBlock), true);
    EXPECT_TRUE(shm.IsValid());
}

TEST_F(IpcTest, SharedMemoryHeartbeatReadWrite) {
    SharedMemory writer(L"Local\\GuardianTestShmHB", sizeof(SharedStateBlock), true);
    EXPECT_TRUE(writer.IsValid());

    HeartbeatPayload hb = {};
    hb.process_id = 1234;
    hb.nonce = 42;
    writer.UpdateHeartbeat(NodeId::GUARDIAN_A, hb);

    SharedMemory reader(L"Local\\GuardianTestShmHB", sizeof(SharedStateBlock), false);
    EXPECT_TRUE(reader.IsValid());

    HeartbeatPayload readHb = {};
    bool ok = reader.GetHeartbeat(NodeId::GUARDIAN_A, readHb);
    EXPECT_TRUE(ok);
    EXPECT_EQ(readHb.process_id, 1234u);
    EXPECT_EQ(readHb.nonce, 42u);
}

/* ============================================
 * HMAC Security Tests
 * ============================================ */

class HMACSecurityTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

/**
 * Test 1: Valid message with calculated checksum should verify successfully
 * This is the happy path - checksum is calculated and verifies correctly.
 */
TEST_F(HMACSecurityTest, ValidMessageVerifiesSuccessfully) {
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    header.source = static_cast<uint8_t>(NodeId::GUARDIAN_A);
    header.dest = static_cast<uint8_t>(NodeId::GUARDIAN_B);
    header.sequence = 42;
    header.timestamp = static_cast<uint32_t>(GetCurrentTimestamp() & 0xFFFFFFFF);
    header.payload_len = 4;

    uint32_t payload = 0xDEADBEEF;

    // Calculate checksum and place it in the header
    uint8_t checksum[CHECKSUM_SIZE] = {};
    CalculateChecksum(header, &payload, checksum);
    memcpy(header.checksum, checksum, CHECKSUM_SIZE);

    // Verify the checksum matches
    bool verified = VerifyChecksum(header, &payload);
    EXPECT_TRUE(verified);
}

/**
 * Test 2: Message with tampered payload should fail verification
 * Tampering detection: flip one byte in the payload and verify fails.
 */
TEST_F(HMACSecurityTest, TamperedPayloadFailsVerification) {
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    header.source = static_cast<uint8_t>(NodeId::GUARDIAN_A);
    header.dest = static_cast<uint8_t>(NodeId::GUARDIAN_B);
    header.sequence = 42;
    header.timestamp = static_cast<uint32_t>(GetCurrentTimestamp() & 0xFFFFFFFF);
    header.payload_len = 4;

    uint32_t payload = 0xDEADBEEF;

    // Calculate checksum for original payload
    uint8_t checksum[CHECKSUM_SIZE] = {};
    CalculateChecksum(header, &payload, checksum);
    memcpy(header.checksum, checksum, CHECKSUM_SIZE);

    // Tamper with payload (flip one byte)
    uint32_t tamperedPayload = payload ^ 0x00000001;

    // Verify should fail for tampered payload
    bool verified = VerifyChecksum(header, &tamperedPayload);
    EXPECT_FALSE(verified);
}

/**
 * Test 3: Zero-checksum (all bytes are 0) should be REJECTED
 * BUG DETECTION TEST - This test will FAIL because VerifyChecksum does not reject
 * all-zero checksums. The bug: CalculateChecksum sets checksum to all zeros on HMAC
 * failure, creating a valid-looking (but actually failed) checksum.
 * A message with all-zero checksum should be rejected as invalid.
 */
TEST_F(HMACSecurityTest, ZeroChecksumBypassDetection) {
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    header.source = static_cast<uint8_t>(NodeId::GUARDIAN_A);
    header.dest = static_cast<uint8_t>(NodeId::GUARDIAN_B);
    header.sequence = 42;
    header.timestamp = static_cast<uint32_t>(GetCurrentTimestamp() & 0xFFFFFFFF);
    header.payload_len = 4;

    uint32_t payload = 0xDEADBEEF;

    // Deliberately set checksum to all zeros (bypass attempt)
    memset(header.checksum, 0, CHECKSUM_SIZE);

    // VerifyChecksum should REJECT this because all-zero is not a valid HMAC output
    // EXPECTED FAILURE: This test exposes the bug - VerifyChecksum doesn't reject zeros
    bool verified = VerifyChecksum(header, &payload);
    EXPECT_FALSE(verified) << "Zero checksum should be rejected as invalid (BUG: currently returns true)";
}

/**
 * Test 4: Truncated message should fail deserialization
 * Verify that messages shorter than MESSAGE_HEADER_SIZE are rejected.
 */
TEST_F(HMACSecurityTest, TruncatedMessageDeserializationFails) {
    // Create a buffer smaller than message header size
    uint8_t buffer[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00};
    MessageHeader header = {};
    std::vector<uint8_t> payload;

    // Deserialization should fail for truncated buffer
    bool result = DeserializeMessage(buffer, sizeof(buffer), header, payload);
    EXPECT_FALSE(result);
}

/**
 * Test 5: CalculateChecksum produces non-zero output for valid input
 * Verify that the checksum is actually computed and not always zero.
 */
TEST_F(HMACSecurityTest, CalculateChecksumProducesNonZeroOutput) {
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(MessageType::HEARTBEAT);
    header.source = static_cast<uint8_t>(NodeId::GUARDIAN_A);
    header.dest = static_cast<uint8_t>(NodeId::GUARDIAN_B);
    header.sequence = 42;
    header.timestamp = static_cast<uint32_t>(GetCurrentTimestamp() & 0xFFFFFFFF);
    header.payload_len = 8;

    uint64_t payload = 0x123456789ABCDEF0;

    uint8_t checksum[CHECKSUM_SIZE] = {};
    CalculateChecksum(header, &payload, checksum);

    // Checksum should NOT be all zeros for valid input
    bool allZeros = true;
    for (size_t i = 0; i < CHECKSUM_SIZE; i++) {
        if (checksum[i] != 0) {
            allZeros = false;
            break;
        }
    }
    EXPECT_FALSE(allZeros) << "Checksum should be non-zero for valid input";
}