/**
 * @file image_notify.c
 * @brief GuardMonitor - Image/DLL/Driver load notification callback
 */

#include "../include/guard_monitor.h"

VOID GmonImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    GUARDIAN_EVENT_OUTPUT event = { 0 };
    LARGE_INTEGER timestamp;

    if (!InterlockedCompareExchange(&g_MonitorData.MonitoringEnabled, 0, 0)) {
        return;
    }

    event.ProcessId = (ULONG)(ULONG_PTR)ProcessId;

    KeQuerySystemTimePrecise(&timestamp);
    event.Timestamp = (ULONG64)timestamp.QuadPart;

    if (ImageInfo->SystemModeImage) {
        event.EventType = GUARDIAN_EVENT_DRIVER_LOAD;
    } else {
        /* User-mode image load - only track if PID == 0 (kernel) or for monitored processes */
        if (ProcessId == 0) {
            event.EventType = GUARDIAN_EVENT_DRIVER_LOAD;
        } else {
            return;
        }
    }

    /* Store image path */
    if (FullImageName && FullImageName->Buffer) {
        SIZE_T copyLen = min(
            FullImageName->Length,
            sizeof(event.FilePath) - sizeof(WCHAR));
        RtlCopyMemory(event.FilePath, FullImageName->Buffer, copyLen);
        event.FilePath[copyLen / sizeof(WCHAR)] = L'\0';
    }

    /* Get process name if available */
    if (ProcessId != 0) {
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
        if (NT_SUCCESS(status) && process) {
            PCHAR imageName = (PCHAR)PsGetProcessImageFileName(process);
            if (imageName) {
                ANSI_STRING ansi;
                UNICODE_STRING uni;
                RtlInitAnsiString(&ansi, imageName);
                uni.Buffer = event.ProcessName;
                uni.Length = 0;
                uni.MaximumLength = sizeof(event.ProcessName);
                RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
            }
            ObDereferenceObject(process);
        }
    }

    InterlockedIncrement64((volatile LONG64*)&g_MonitorData.TotalOperations);
    GmonPushEvent(&event);
}
