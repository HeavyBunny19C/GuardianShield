/**
 * @file test_driver_client.cpp
 * @brief Unit tests for DriverClient
 *
 * Tests the user-mode driver client interface. Since the actual kernel driver
 * may not be loaded during testing, these tests primarily verify the client's
 * state management and error handling for disconnected state.
 */

#include <gtest/gtest.h>
#include "../src/service/common/include/common_types.h"
#include "../src/service/common/include/driver_client.h"

using namespace Guardian;

class DriverClientTest : public ::testing::Test {
protected:
    DriverClient m_client;
};

TEST_F(DriverClientTest, InitialState) {
    EXPECT_FALSE(m_client.IsConnected());
    EXPECT_EQ(m_client.GetTotalOperations(), 0u);
    EXPECT_EQ(m_client.GetBlockedOperations(), 0u);
}

TEST_F(DriverClientTest, ConnectToInvalidDevice) {
    EXPECT_FALSE(m_client.Connect(L"\\\\.\\NonExistentDevice12345"));
    EXPECT_FALSE(m_client.IsConnected());
}

TEST_F(DriverClientTest, DisconnectWhileNotConnected) {
    m_client.Disconnect();
    EXPECT_FALSE(m_client.IsConnected());
}

TEST_F(DriverClientTest, DoubleDisconnect) {
    m_client.Disconnect();
    m_client.Disconnect();
    EXPECT_FALSE(m_client.IsConnected());
}

TEST_F(DriverClientTest, AddProtectedPathWhileDisconnected) {
    EXPECT_FALSE(m_client.AddProtectedPath(L"C:\\Protected", true, 0));
    EXPECT_FALSE(m_client.AddProtectedPath(L"D:\\Data", false, 5));
}

TEST_F(DriverClientTest, RemoveProtectedPathWhileDisconnected) {
    EXPECT_FALSE(m_client.RemoveProtectedPath(L"C:\\Protected"));
}

TEST_F(DriverClientTest, ClearProtectedPathsWhileDisconnected) {
    EXPECT_FALSE(m_client.ClearProtectedPaths());
}

TEST_F(DriverClientTest, AddWhitelistWhileDisconnected) {
    EXPECT_FALSE(m_client.AddWhitelistProcess(L"explorer.exe", 7));
}

TEST_F(DriverClientTest, RemoveWhitelistWhileDisconnected) {
    EXPECT_FALSE(m_client.RemoveWhitelistProcess(L"explorer.exe"));
}

TEST_F(DriverClientTest, ClearWhitelistWhileDisconnected) {
    EXPECT_FALSE(m_client.ClearWhitelist());
}

TEST_F(DriverClientTest, GetNextEventWhileDisconnected) {
    DriverEvent event = {};
    EXPECT_FALSE(m_client.GetNextEvent(event, 100));
}

TEST_F(DriverClientTest, GetPendingEventCountWhileDisconnected) {
    EXPECT_EQ(m_client.GetPendingEventCount(), 0u);
}

TEST_F(DriverClientTest, EnableMonitoringWhileDisconnected) {
    EXPECT_FALSE(m_client.EnableMonitoring());
}

TEST_F(DriverClientTest, DisableMonitoringWhileDisconnected) {
    EXPECT_FALSE(m_client.DisableMonitoring());
}

TEST_F(DriverClientTest, TriggerEmergencyWhileDisconnected) {
    EXPECT_FALSE(m_client.TriggerEmergency());
}

TEST_F(DriverClientTest, CancelEmergencyWhileDisconnected) {
    EXPECT_FALSE(m_client.CancelEmergency());
}

TEST_F(DriverClientTest, StatisticsAfterFailedOps) {
    m_client.AddProtectedPath(L"C:\\test");
    m_client.EnableMonitoring();
    EXPECT_EQ(m_client.GetTotalOperations(), 0u);
    EXPECT_EQ(m_client.GetBlockedOperations(), 0u);
}

TEST_F(DriverClientTest, ConnectToGuardFilterPath) {
    bool result = m_client.Connect(L"\\\\.\\GuardFilter");
    /* Driver likely not installed, but we test the attempt doesn't crash */
    if (!result) {
        EXPECT_FALSE(m_client.IsConnected());
    }
}

TEST_F(DriverClientTest, ConnectToGuardMonitorPath) {
    bool result = m_client.Connect(L"\\\\.\\GuardMonitor");
    if (!result) {
        EXPECT_FALSE(m_client.IsConnected());
    }
}