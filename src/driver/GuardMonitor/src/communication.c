/**
 * @file communication.c
 * @brief GuardMonitor - DeviceIoControl dispatch handler
 */

#include "../include/guard_monitor.h"

NTSTATUS GmonDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputLength;
    ULONG outputLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {

    /* ----- Whitelist Management ----- */
    case IOCTL_GUARDIAN_ADD_WHITELIST_PROCESS:
    {
        PGUARDIAN_WHITELIST_ENTRY entry;
        PMONITOR_WHITELIST_NODE node;
        UNICODE_STRING nameStr;
        SIZE_T nameLen;

        if (!inputBuffer || inputLength < sizeof(GUARDIAN_WHITELIST_ENTRY)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        entry = (PGUARDIAN_WHITELIST_ENTRY)inputBuffer;
        RtlInitUnicodeString(&nameStr, entry->ProcessName);
        nameLen = nameStr.Length;

        node = (PMONITOR_WHITELIST_NODE)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(MONITOR_WHITELIST_NODE), GMON_TAG);
        if (!node) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        node->ProcessName.Buffer = (PWCH)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, nameLen + sizeof(WCHAR), GMON_TAG);
        if (!node->ProcessName.Buffer) {
            ExFreePoolWithTag(node, GMON_TAG);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlCopyMemory(node->ProcessName.Buffer, entry->ProcessName, nameLen);
        node->ProcessName.Buffer[nameLen / sizeof(WCHAR)] = L'\0';
        node->ProcessName.Length = (USHORT)nameLen;
        node->ProcessName.MaximumLength = (USHORT)(nameLen + sizeof(WCHAR));
        node->Permissions = entry->Permissions;

        if (KeGetCurrentIrql() > APC_LEVEL) { status = STATUS_UNSUCCESSFUL; break; }
        ExAcquireResourceExclusiveLite(&g_MonitorData.WhitelistLock, TRUE);
        InsertTailList(&g_MonitorData.WhitelistEntries, &node->ListEntry);
        g_MonitorData.WhitelistCount++;
        ExReleaseResourceLite(&g_MonitorData.WhitelistLock);
        break;
    }

    case IOCTL_GUARDIAN_REMOVE_WHITELIST_PROCESS:
    {
        UNICODE_STRING searchName;
        PLIST_ENTRY listEntry;

        if (!inputBuffer || inputLength < sizeof(WCHAR)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlInitUnicodeString(&searchName, (PCWSTR)inputBuffer);

        if (KeGetCurrentIrql() > APC_LEVEL) { status = STATUS_UNSUCCESSFUL; break; }
        ExAcquireResourceExclusiveLite(&g_MonitorData.WhitelistLock, TRUE);
        for (listEntry = g_MonitorData.WhitelistEntries.Flink;
             listEntry != &g_MonitorData.WhitelistEntries;
             listEntry = listEntry->Flink) {
            PMONITOR_WHITELIST_NODE node = CONTAINING_RECORD(
                listEntry, MONITOR_WHITELIST_NODE, ListEntry);
            if (RtlEqualUnicodeString(&node->ProcessName, &searchName, TRUE)) {
                RemoveEntryList(listEntry);
                g_MonitorData.WhitelistCount--;
                ExReleaseResourceLite(&g_MonitorData.WhitelistLock);
                if (node->ProcessName.Buffer) {
                    ExFreePoolWithTag(node->ProcessName.Buffer, GMON_TAG);
                }
                ExFreePoolWithTag(node, GMON_TAG);
                goto Done;
            }
        }
        ExReleaseResourceLite(&g_MonitorData.WhitelistLock);
        status = STATUS_NOT_FOUND;
        break;
    }

    case IOCTL_GUARDIAN_CLEAR_WHITELIST:
    {
        PLIST_ENTRY listEntry;
        if (KeGetCurrentIrql() > APC_LEVEL) { status = STATUS_UNSUCCESSFUL; break; }
        ExAcquireResourceExclusiveLite(&g_MonitorData.WhitelistLock, TRUE);
        while (!IsListEmpty(&g_MonitorData.WhitelistEntries)) {
            listEntry = RemoveHeadList(&g_MonitorData.WhitelistEntries);
            PMONITOR_WHITELIST_NODE node = CONTAINING_RECORD(
                listEntry, MONITOR_WHITELIST_NODE, ListEntry);
            if (node->ProcessName.Buffer) {
                ExFreePoolWithTag(node->ProcessName.Buffer, GMON_TAG);
            }
            ExFreePoolWithTag(node, GMON_TAG);
        }
        g_MonitorData.WhitelistCount = 0;
        ExReleaseResourceLite(&g_MonitorData.WhitelistLock);
        break;
    }

    /* ----- Event Retrieval ----- */
    case IOCTL_GUARDIAN_GET_EVENT:
        if (!outputBuffer || outputLength < sizeof(GUARDIAN_EVENT_OUTPUT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (GmonPopEvent((PGUARDIAN_EVENT_OUTPUT)outputBuffer)) {
            bytesReturned = sizeof(GUARDIAN_EVENT_OUTPUT);
        } else {
            status = STATUS_NO_MORE_ENTRIES;
        }
        break;

    case IOCTL_GUARDIAN_GET_PENDING_COUNT:
        if (!outputBuffer || outputLength < sizeof(LONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        *(PLONG)outputBuffer = g_MonitorData.EventRing.Count;
        bytesReturned = sizeof(LONG);
        break;

    /* ----- Monitoring Control ----- */
    case IOCTL_GUARDIAN_ENABLE_MONITORING:
        InterlockedExchange(&g_MonitorData.MonitoringEnabled, TRUE);
        break;

    case IOCTL_GUARDIAN_DISABLE_MONITORING:
        InterlockedExchange(&g_MonitorData.MonitoringEnabled, FALSE);
        break;

    /* ----- Emergency ----- */
    case IOCTL_GUARDIAN_TRIGGER_EMERGENCY:
        InterlockedExchange(&g_MonitorData.EmergencyActive, TRUE);
        InterlockedExchange(&g_MonitorData.MonitoringEnabled, TRUE);
        break;

    case IOCTL_GUARDIAN_CANCEL_EMERGENCY:
        InterlockedExchange(&g_MonitorData.EmergencyActive, FALSE);
        break;

    /* ----- Statistics ----- */
    case IOCTL_GUARDIAN_GET_STATISTICS:
        if (!outputBuffer || outputLength < sizeof(GUARDIAN_STATISTICS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            PGUARDIAN_STATISTICS stats = (PGUARDIAN_STATISTICS)outputBuffer;
            stats->TotalOperations = g_MonitorData.TotalOperations;
            stats->BlockedOperations = g_MonitorData.BlockedOperations;
            stats->EventsGenerated = g_MonitorData.TotalOperations;
            stats->EventsDropped = (ULONG64)g_MonitorData.EventRing.DroppedCount;
            stats->MonitoringEnabled = (ULONG)g_MonitorData.MonitoringEnabled;
            stats->EmergencyActive = (ULONG)g_MonitorData.EmergencyActive;
            stats->ProtectedPathCount = 0;
            stats->WhitelistCount = g_MonitorData.WhitelistCount;
            bytesReturned = sizeof(GUARDIAN_STATISTICS);
        }
        break;

    /* ----- Process Protection (ObRegisterCallbacks) ----- */
    case IOCTL_GUARDIAN_SET_PROTECTED_PIDS:
    {
        ULONG count;
        ULONG i;
        HANDLE *pids;

        if (!inputBuffer || inputLength < sizeof(HANDLE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        pids = (HANDLE *)inputBuffer;
        count = inputLength / sizeof(HANDLE);
        if (count > GUARDIAN_MAX_PROTECTED_PIDS)
            count = GUARDIAN_MAX_PROTECTED_PIDS;

        for (i = 0; i < count; i++) {
            g_MonitorData.ProtectedPids[i] = pids[i];
        }
        InterlockedExchange(&g_MonitorData.ProtectedPidCount, (LONG)count);
        break;
    }

    case IOCTL_GUARDIAN_CLEAR_PROTECTED_PIDS:
        InterlockedExchange(&g_MonitorData.ProtectedPidCount, 0);
        RtlZeroMemory(g_MonitorData.ProtectedPids, sizeof(g_MonitorData.ProtectedPids));
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Done:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
