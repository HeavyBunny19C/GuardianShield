/**
 * @file driver_client.cpp
 * @brief Driver client using FilterConnectCommunicationPort for minifilter communication
 */

#include "../include/driver_client.h"
#include "../../../driver/shared/guardian_ioctl.h"
#include <Windows.h>
#include <fltUser.h>
#include <vector>

#pragma comment(lib, "fltlib.lib")

namespace Guardian {

DriverClient::DriverClient()
    : m_hPort(INVALID_HANDLE_VALUE)
    , m_totalOps(0)
    , m_blockedOps(0)
{
}

DriverClient::~DriverClient() {
    Disconnect();
}

bool DriverClient::Connect(const std::wstring& portName) {
    if (m_hPort != INVALID_HANDLE_VALUE) {
        Disconnect();
    }
    m_portName = portName;

    HRESULT hr = FilterConnectCommunicationPort(
        portName.c_str(),
        0,
        nullptr, 0,
        nullptr,
        &m_hPort);

    return SUCCEEDED(hr);
}

void DriverClient::Disconnect() {
    if (m_hPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPort);
        m_hPort = INVALID_HANDLE_VALUE;
    }
    m_portName.clear();
}

bool DriverClient::IsConnected() const {
    return (m_hPort != INVALID_HANDLE_VALUE);
}

bool DriverClient::SendCommand(ULONG command, const void* data, ULONG dataSize,
                                void* outBuf, ULONG outBufSize,
                                ULONG* bytesReturned) const {
    if (m_hPort == INVALID_HANDLE_VALUE) return false;

    ULONG msgSize = offsetof(GUARDIAN_COMMAND_MESSAGE, Data) + dataSize;
    std::vector<BYTE> buf(msgSize, 0);
    auto* msg = reinterpret_cast<GUARDIAN_COMMAND_MESSAGE*>(buf.data());
    msg->Command  = command;
    msg->DataSize = dataSize;
    if (data && dataSize > 0) {
        memcpy(msg->Data, data, dataSize);
    }

    DWORD returned = 0;
    HRESULT hr = FilterSendMessage(
        m_hPort,
        msg, msgSize,
        outBuf, outBufSize,
        &returned);

    if (bytesReturned) *bytesReturned = returned;
    return SUCCEEDED(hr);
}

bool DriverClient::AddProtectedPath(const std::wstring& path, bool recursive, uint32_t priority) {
    GUARDIAN_PATH_ENTRY entry = {};
    wcsncpy_s(entry.Path, GUARDIAN_MAX_PATH, path.c_str(), _TRUNCATE);
    entry.Recursive = recursive ? 1 : 0;
    entry.Priority = priority;

    bool ok = SendCommand(IOCTL_GUARDIAN_ADD_PROTECTED_PATH, &entry, sizeof(entry));
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::RemoveProtectedPath(const std::wstring& path) {
    ULONG sz = static_cast<ULONG>((path.size() + 1) * sizeof(wchar_t));
    bool ok = SendCommand(IOCTL_GUARDIAN_REMOVE_PROTECTED_PATH, path.c_str(), sz);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::ClearProtectedPaths() {
    bool ok = SendCommand(IOCTL_GUARDIAN_CLEAR_PROTECTED_PATHS, nullptr, 0);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::AddWhitelistProcess(const std::wstring& processName, uint32_t permissions) {
    GUARDIAN_WHITELIST_ENTRY entry = {};
    wcsncpy_s(entry.ProcessName, GUARDIAN_MAX_PROC_NAME, processName.c_str(), _TRUNCATE);
    entry.Permissions = permissions;

    bool ok = SendCommand(IOCTL_GUARDIAN_ADD_WHITELIST_PROCESS, &entry, sizeof(entry));
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::RemoveWhitelistProcess(const std::wstring& processName) {
    ULONG sz = static_cast<ULONG>((processName.size() + 1) * sizeof(wchar_t));
    bool ok = SendCommand(IOCTL_GUARDIAN_REMOVE_WHITELIST_PROCESS, processName.c_str(), sz);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::ClearWhitelist() {
    bool ok = SendCommand(IOCTL_GUARDIAN_CLEAR_WHITELIST, nullptr, 0);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::GetNextEvent(DriverEvent& event, uint32_t timeoutMs) {
    GUARDIAN_EVENT_OUTPUT rawEvent = {};
    ULONG returned = 0;

    bool ok = SendCommand(IOCTL_GUARDIAN_GET_EVENT,
                          &timeoutMs, sizeof(timeoutMs),
                          &rawEvent, sizeof(rawEvent), &returned);

    if (!ok || returned < sizeof(GUARDIAN_EVENT_OUTPUT)) return false;

    event.event_type   = rawEvent.EventType;
    event.process_id   = rawEvent.ProcessId;
    event.timestamp    = rawEvent.Timestamp;
    event.access_mask  = rawEvent.AccessMask;
    event.data_size    = rawEvent.DataSize;
    wcscpy_s(event.file_path, rawEvent.FilePath);
    wcscpy_s(event.process_name, rawEvent.ProcessName);

    m_totalOps++;
    return true;
}

size_t DriverClient::GetPendingEventCount() const {
    LONG count = 0;
    ULONG returned = 0;
    bool ok = SendCommand(IOCTL_GUARDIAN_GET_PENDING_COUNT, nullptr, 0,
                          &count, sizeof(count), &returned);
    return ok ? static_cast<size_t>(count) : 0;
}

bool DriverClient::EnableMonitoring() {
    bool ok = SendCommand(IOCTL_GUARDIAN_ENABLE_MONITORING, nullptr, 0);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::DisableMonitoring() {
    bool ok = SendCommand(IOCTL_GUARDIAN_DISABLE_MONITORING, nullptr, 0);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::TriggerEmergency() {
    bool ok = SendCommand(IOCTL_GUARDIAN_TRIGGER_EMERGENCY, nullptr, 0);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::CancelEmergency() {
    bool ok = SendCommand(IOCTL_GUARDIAN_CANCEL_EMERGENCY, nullptr, 0);
    if (ok) m_totalOps++;
    return ok;
}

bool DriverClient::SetBlockPolicy(uint32_t flags) {
    GUARDIAN_BLOCK_POLICY bp = {};
    bp.Flags = flags;
    bool ok = SendCommand(IOCTL_GUARDIAN_SET_BLOCK_POLICY, &bp, sizeof(bp));
    if (ok) m_totalOps++;
    return ok;
}

uint32_t DriverClient::GetBlockPolicy() const {
    GUARDIAN_BLOCK_POLICY bp = {};
    ULONG returned = 0;
    bool ok = SendCommand(IOCTL_GUARDIAN_GET_BLOCK_POLICY, nullptr, 0,
                          &bp, sizeof(bp), &returned);
    return ok ? bp.Flags : 0;
}

uint64_t DriverClient::GetTotalOperations() const {
    if (m_hPort == INVALID_HANDLE_VALUE) return m_totalOps;

    GUARDIAN_STATISTICS stats = {};
    ULONG returned = 0;
    bool ok = SendCommand(IOCTL_GUARDIAN_GET_STATISTICS, nullptr, 0,
                          &stats, sizeof(stats), &returned);
    return ok ? stats.TotalOperations : m_totalOps;
}

uint64_t DriverClient::GetBlockedOperations() const {
    if (m_hPort == INVALID_HANDLE_VALUE) return m_blockedOps;

    GUARDIAN_STATISTICS stats = {};
    ULONG returned = 0;
    bool ok = SendCommand(IOCTL_GUARDIAN_GET_STATISTICS, nullptr, 0,
                          &stats, sizeof(stats), &returned);
    return ok ? stats.BlockedOperations : m_blockedOps;
}

} // namespace Guardian
