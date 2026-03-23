/**
 * @file process_notify.c
 * @brief GuardMonitor - Process creation/termination notification callback
 */

#include "../include/guard_monitor.h"

VOID GmonProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    GUARDIAN_EVENT_OUTPUT event = { 0 };
    LARGE_INTEGER timestamp;
    PCHAR imageName;

    if (!InterlockedCompareExchange(&g_MonitorData.MonitoringEnabled, 0, 0)) {
        return;
    }

    event.ProcessId = (ULONG)(ULONG_PTR)ProcessId;

    KeQuerySystemTimePrecise(&timestamp);
    event.Timestamp = (ULONG64)timestamp.QuadPart;

    /* Get process image name */
    imageName = (PCHAR)PsGetProcessImageFileName(Process);
    if (imageName) {
        ANSI_STRING ansi;
        UNICODE_STRING uni;
        RtlInitAnsiString(&ansi, imageName);
        uni.Buffer = event.ProcessName;
        uni.Length = 0;
        uni.MaximumLength = sizeof(event.ProcessName);
        RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
    }

    if (CreateInfo) {
        /* Process creation */
        event.EventType = GUARDIAN_EVENT_PROCESS_CREATE;

        /* Store the image file name in FilePath */
        if (CreateInfo->ImageFileName) {
            SIZE_T copyLen = min(
                CreateInfo->ImageFileName->Length,
                sizeof(event.FilePath) - sizeof(WCHAR));
            RtlCopyMemory(event.FilePath, CreateInfo->ImageFileName->Buffer, copyLen);
            event.FilePath[copyLen / sizeof(WCHAR)] = L'\0';
        }

        /* Check whitelist */
        if (event.ProcessName[0] != L'\0') {
            UNICODE_STRING procName;
            RtlInitUnicodeString(&procName, event.ProcessName);
            if (GmonIsProcessWhitelisted(&procName)) {
                return;
            }
        }

        /* In emergency mode, deny non-whitelisted process creation */
        if (InterlockedCompareExchange(&g_MonitorData.EmergencyActive, 0, 0)) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            InterlockedIncrement64((volatile LONG64*)&g_MonitorData.BlockedOperations);
        }
    } else {
        /* Process termination */
        event.EventType = GUARDIAN_EVENT_PROCESS_TERMINATE;
    }

    InterlockedIncrement64((volatile LONG64*)&g_MonitorData.TotalOperations);
    GmonPushEvent(&event);
}
