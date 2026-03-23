/**
 * @file driver_client.h
 * @brief Driver communication client for GuardianA
 */

#pragma once

#include "../../common/include/common_types.h"
#include <string>
#include <vector>
#include <memory>

#ifdef _WIN32
#include <Windows.h>
#include <fltUser.h>
#pragma comment(lib, "fltlib.lib")
#endif

namespace Guardian {

class DriverClient {
public:
    DriverClient();
    ~DriverClient();
    
    bool Connect(const std::wstring& portName);
    void Disconnect();
    bool IsConnected() const;
    
    bool AddProtectedPath(const std::wstring& path, bool recursive = true, uint32_t priority = 0);
    bool RemoveProtectedPath(const std::wstring& path);
    bool ClearProtectedPaths();
    
    bool AddWhitelistProcess(const std::wstring& processName, uint32_t permissions);
    bool RemoveWhitelistProcess(const std::wstring& processName);
    bool ClearWhitelist();
    
    bool GetNextEvent(DriverEvent& event, uint32_t timeoutMs = 1000);
    size_t GetPendingEventCount() const;
    
    bool EnableMonitoring();
    bool DisableMonitoring();
    bool TriggerEmergency();
    bool CancelEmergency();

    bool SetBlockPolicy(uint32_t flags);
    uint32_t GetBlockPolicy() const;
    
    uint64_t GetTotalOperations() const;
    uint64_t GetBlockedOperations() const;
    
private:
    bool SendCommand(ULONG command, const void* data, ULONG dataSize,
                     void* outBuf = nullptr, ULONG outBufSize = 0,
                     ULONG* bytesReturned = nullptr) const;

    HANDLE m_hPort;
    std::wstring m_portName;
    uint64_t m_totalOps;
    uint64_t m_blockedOps;
};

} // namespace Guardian
