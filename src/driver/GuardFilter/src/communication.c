/**
 * @file communication.c
 * @brief GuardFilter communication port handler
 */

#include "../include/guard_filter.h"

/* ============================================
 * Port Connect / Disconnect
 * ============================================ */

NTSTATUS GfltPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    g_FilterData.ClientPort = ClientPort;
    *ConnectionCookie = NULL;

    return STATUS_SUCCESS;
}

VOID GfltPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(g_FilterData.Filter, &g_FilterData.ClientPort);
    g_FilterData.ClientPort = NULL;
}

/* ============================================
 * Port Message Handler
 * ============================================ */

NTSTATUS GfltPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    PGUARDIAN_COMMAND_MESSAGE cmd;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;

    if (!InputBuffer || InputBufferLength < sizeof(GUARDIAN_COMMAND_MESSAGE)) {
        return STATUS_INVALID_PARAMETER;
    }

    cmd = (PGUARDIAN_COMMAND_MESSAGE)InputBuffer;

    switch (cmd->Command) {

    /* ----- Protected Path Management ----- */
    case IOCTL_GUARDIAN_ADD_PROTECTED_PATH:
        if (cmd->DataSize >= sizeof(GUARDIAN_PATH_ENTRY)) {
            status = GfltAddProtectedPath((PGUARDIAN_PATH_ENTRY)cmd->Data);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARDIAN_REMOVE_PROTECTED_PATH:
        if (cmd->DataSize >= sizeof(WCHAR)) {
            status = GfltRemoveProtectedPath((PCWSTR)cmd->Data);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARDIAN_CLEAR_PROTECTED_PATHS:
    {
        PLIST_ENTRY entry;
        if (KeGetCurrentIrql() > APC_LEVEL) { status = STATUS_UNSUCCESSFUL; break; }
        ExAcquireResourceExclusiveLite(&g_FilterData.PathListLock, TRUE);
        while (!IsListEmpty(&g_FilterData.ProtectedPaths)) {
            entry = RemoveHeadList(&g_FilterData.ProtectedPaths);
            PPROTECTED_PATH_NODE node = CONTAINING_RECORD(entry, PROTECTED_PATH_NODE, ListEntry);
            if (node->Path.Buffer) ExFreePoolWithTag(node->Path.Buffer, GFLT_TAG);
            ExFreePoolWithTag(node, GFLT_TAG);
        }
        g_FilterData.PathCount = 0;
        ExReleaseResourceLite(&g_FilterData.PathListLock);
        break;
    }

    /* ----- Whitelist Management ----- */
    case IOCTL_GUARDIAN_ADD_WHITELIST_PROCESS:
        if (cmd->DataSize >= sizeof(GUARDIAN_WHITELIST_ENTRY)) {
            status = GfltAddWhitelistEntry((PGUARDIAN_WHITELIST_ENTRY)cmd->Data);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARDIAN_CLEAR_WHITELIST:
    {
        PLIST_ENTRY entry;
        if (KeGetCurrentIrql() > APC_LEVEL) { status = STATUS_UNSUCCESSFUL; break; }
        ExAcquireResourceExclusiveLite(&g_FilterData.WhitelistLock, TRUE);
        while (!IsListEmpty(&g_FilterData.WhitelistEntries)) {
            entry = RemoveHeadList(&g_FilterData.WhitelistEntries);
            PWHITELIST_NODE node = CONTAINING_RECORD(entry, WHITELIST_NODE, ListEntry);
            if (node->ProcessName.Buffer) ExFreePoolWithTag(node->ProcessName.Buffer, GFLT_TAG);
            ExFreePoolWithTag(node, GFLT_TAG);
        }
        g_FilterData.WhitelistCount = 0;
        ExReleaseResourceLite(&g_FilterData.WhitelistLock);
        break;
    }

    /* ----- Event Retrieval ----- */
    case IOCTL_GUARDIAN_GET_EVENT:
        if (OutputBuffer && OutputBufferLength >= sizeof(GUARDIAN_EVENT_OUTPUT)) {
            if (GfltPopEvent((PGUARDIAN_EVENT_OUTPUT)OutputBuffer)) {
                *ReturnOutputBufferLength = sizeof(GUARDIAN_EVENT_OUTPUT);
            } else {
                status = STATUS_NO_MORE_ENTRIES;
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARDIAN_GET_PENDING_COUNT:
        if (OutputBuffer && OutputBufferLength >= sizeof(LONG)) {
            *(PLONG)OutputBuffer = g_FilterData.EventRing.Count;
            *ReturnOutputBufferLength = sizeof(LONG);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ----- Monitoring Control ----- */
    case IOCTL_GUARDIAN_ENABLE_MONITORING:
        InterlockedExchange(&g_FilterData.MonitoringEnabled, TRUE);
        break;

    case IOCTL_GUARDIAN_DISABLE_MONITORING:
        InterlockedExchange(&g_FilterData.MonitoringEnabled, FALSE);
        break;

    /* ----- Emergency ----- */
    case IOCTL_GUARDIAN_TRIGGER_EMERGENCY:
        InterlockedExchange(&g_FilterData.EmergencyActive, TRUE);
        InterlockedExchange(&g_FilterData.MonitoringEnabled, TRUE);
        break;

    case IOCTL_GUARDIAN_CANCEL_EMERGENCY:
        InterlockedExchange(&g_FilterData.EmergencyActive, FALSE);
        break;

    /* ----- Statistics ----- */
    case IOCTL_GUARDIAN_GET_STATISTICS:
        if (OutputBuffer && OutputBufferLength >= sizeof(GUARDIAN_STATISTICS)) {
            PGUARDIAN_STATISTICS stats = (PGUARDIAN_STATISTICS)OutputBuffer;
            stats->TotalOperations = g_FilterData.TotalOperations;
            stats->BlockedOperations = g_FilterData.BlockedOperations;
            stats->EventsGenerated = g_FilterData.TotalOperations;
            stats->EventsDropped = (ULONG64)g_FilterData.EventRing.DroppedCount;
            stats->MonitoringEnabled = (ULONG)g_FilterData.MonitoringEnabled;
            stats->EmergencyActive = (ULONG)g_FilterData.EmergencyActive;
            stats->ProtectedPathCount = g_FilterData.PathCount;
            stats->WhitelistCount = g_FilterData.WhitelistCount;
            *ReturnOutputBufferLength = sizeof(GUARDIAN_STATISTICS);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ----- Block Policy ----- */
    case IOCTL_GUARDIAN_SET_BLOCK_POLICY:
        if (cmd->DataSize >= sizeof(GUARDIAN_BLOCK_POLICY)) {
            PGUARDIAN_BLOCK_POLICY bp = (PGUARDIAN_BLOCK_POLICY)cmd->Data;
            InterlockedExchange(&g_FilterData.BlockPolicy, (LONG)bp->Flags);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARDIAN_GET_BLOCK_POLICY:
        if (OutputBuffer && OutputBufferLength >= sizeof(GUARDIAN_BLOCK_POLICY)) {
            PGUARDIAN_BLOCK_POLICY bp = (PGUARDIAN_BLOCK_POLICY)OutputBuffer;
            bp->Flags = (ULONG)InterlockedCompareExchange(&g_FilterData.BlockPolicy, 0, 0);
            *ReturnOutputBufferLength = sizeof(GUARDIAN_BLOCK_POLICY);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}
