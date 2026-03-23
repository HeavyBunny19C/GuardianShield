/**
 * @file guard_filter.c
 * @brief GuardFilter minifilter - DriverEntry, instance setup, unload
 */

#include "../include/guard_filter.h"

GUARD_FILTER_DATA g_FilterData = { 0 };

/* Callback registration structure */
static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,         0, GfltPreCreate,         NULL },
    { IRP_MJ_WRITE,          0, GfltPreWrite,          NULL },
    { IRP_MJ_SET_INFORMATION, 0, GfltPreSetInformation, NULL },
    { IRP_MJ_CLEANUP,        0, GfltPreCleanup,        NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                          /* Flags */
    NULL,                       /* Context registration */
    g_Callbacks,
    GfltUnload,
    GfltInstanceSetup,
    NULL,                       /* InstanceQueryTeardown */
    NULL,                       /* InstanceTeardownStart */
    NULL,                       /* InstanceTeardownComplete */
    NULL, NULL, NULL            /* Unused callbacks */
};

/* ============================================
 * DriverEntry
 * ============================================ */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Initialize global data */
    RtlZeroMemory(&g_FilterData, sizeof(g_FilterData));
    InitializeListHead(&g_FilterData.ProtectedPaths);
    InitializeListHead(&g_FilterData.WhitelistEntries);
    ExInitializeResourceLite(&g_FilterData.PathListLock);
    ExInitializeResourceLite(&g_FilterData.WhitelistLock);
    KeInitializeSpinLock(&g_FilterData.EventRing.Lock);
    g_FilterData.MonitoringEnabled = FALSE;
    g_FilterData.EmergencyActive = FALSE;

    /* Register minifilter */
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterData.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Create communication port */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterData.Filter);
        return status;
    }

    RtlInitUnicodeString(&portName, GUARDFILTER_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

    status = FltCreateCommunicationPort(
        g_FilterData.Filter,
        &g_FilterData.ServerPort,
        &oa,
        NULL,
        GfltPortConnect,
        GfltPortDisconnect,
        GfltPortMessageNotify,
        1                       /* MaxConnections */
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterData.Filter);
        return status;
    }

    /* Start filtering */
    status = FltStartFiltering(g_FilterData.Filter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(g_FilterData.ServerPort);
        FltUnregisterFilter(g_FilterData.Filter);
        return status;
    }

    return STATUS_SUCCESS;
}

/* ============================================
 * Unload
 * ============================================ */

NTSTATUS GfltUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    PLIST_ENTRY entry;
    UNREFERENCED_PARAMETER(Flags);

    if (g_FilterData.ServerPort) {
        FltCloseCommunicationPort(g_FilterData.ServerPort);
    }
    if (g_FilterData.Filter) {
        FltUnregisterFilter(g_FilterData.Filter);
    }

    /* Free protected path list */
    while (!IsListEmpty(&g_FilterData.ProtectedPaths)) {
        entry = RemoveHeadList(&g_FilterData.ProtectedPaths);
        PPROTECTED_PATH_NODE node = CONTAINING_RECORD(entry, PROTECTED_PATH_NODE, ListEntry);
        if (node->Path.Buffer) {
            ExFreePoolWithTag(node->Path.Buffer, GFLT_TAG);
        }
        ExFreePoolWithTag(node, GFLT_TAG);
    }

    /* Free whitelist */
    while (!IsListEmpty(&g_FilterData.WhitelistEntries)) {
        entry = RemoveHeadList(&g_FilterData.WhitelistEntries);
        PWHITELIST_NODE node = CONTAINING_RECORD(entry, WHITELIST_NODE, ListEntry);
        if (node->ProcessName.Buffer) {
            ExFreePoolWithTag(node->ProcessName.Buffer, GFLT_TAG);
        }
        ExFreePoolWithTag(node, GFLT_TAG);
    }

    ExDeleteResourceLite(&g_FilterData.PathListLock);
    ExDeleteResourceLite(&g_FilterData.WhitelistLock);

    return STATUS_SUCCESS;
}

/* ============================================
 * Instance Setup
 * ============================================ */

NTSTATUS GfltInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    /* Only attach to disk-based NTFS/ReFS volumes */
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

/* ============================================
 * Path & Whitelist Helpers
 * ============================================ */

NTSTATUS GfltAddProtectedPath(_In_ PGUARDIAN_PATH_ENTRY PathEntry)
{
    PPROTECTED_PATH_NODE node;
    UNICODE_STRING pathStr;
    SIZE_T pathLen;

    RtlInitUnicodeString(&pathStr, PathEntry->Path);
    pathLen = pathStr.Length;

    node = (PPROTECTED_PATH_NODE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(PROTECTED_PATH_NODE), GFLT_TAG);
    if (!node) return STATUS_INSUFFICIENT_RESOURCES;

    node->Path.Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, pathLen + sizeof(WCHAR), GFLT_TAG);
    if (!node->Path.Buffer) {
        ExFreePoolWithTag(node, GFLT_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(node->Path.Buffer, PathEntry->Path, pathLen);
    node->Path.Buffer[pathLen / sizeof(WCHAR)] = L'\0';
    node->Path.Length = (USHORT)pathLen;
    node->Path.MaximumLength = (USHORT)(pathLen + sizeof(WCHAR));
    node->Recursive = PathEntry->Recursive;
    node->Priority = PathEntry->Priority;

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;
    ExAcquireResourceExclusiveLite(&g_FilterData.PathListLock, TRUE);
    InsertTailList(&g_FilterData.ProtectedPaths, &node->ListEntry);
    g_FilterData.PathCount++;
    ExReleaseResourceLite(&g_FilterData.PathListLock);

    return STATUS_SUCCESS;
}

NTSTATUS GfltRemoveProtectedPath(_In_ PCWSTR Path)
{
    UNICODE_STRING searchPath;
    PLIST_ENTRY entry;

    RtlInitUnicodeString(&searchPath, Path);

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;
    ExAcquireResourceExclusiveLite(&g_FilterData.PathListLock, TRUE);

    for (entry = g_FilterData.ProtectedPaths.Flink;
         entry != &g_FilterData.ProtectedPaths;
         entry = entry->Flink) {
        PPROTECTED_PATH_NODE node = CONTAINING_RECORD(entry, PROTECTED_PATH_NODE, ListEntry);
        if (RtlEqualUnicodeString(&node->Path, &searchPath, TRUE)) {
            RemoveEntryList(entry);
            g_FilterData.PathCount--;
            ExReleaseResourceLite(&g_FilterData.PathListLock);

            if (node->Path.Buffer) {
                ExFreePoolWithTag(node->Path.Buffer, GFLT_TAG);
            }
            ExFreePoolWithTag(node, GFLT_TAG);
            return STATUS_SUCCESS;
        }
    }

    ExReleaseResourceLite(&g_FilterData.PathListLock);
    return STATUS_NOT_FOUND;
}

NTSTATUS GfltAddWhitelistEntry(_In_ PGUARDIAN_WHITELIST_ENTRY Entry)
{
    PWHITELIST_NODE node;
    UNICODE_STRING nameStr;
    SIZE_T nameLen;

    RtlInitUnicodeString(&nameStr, Entry->ProcessName);
    nameLen = nameStr.Length;

    node = (PWHITELIST_NODE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WHITELIST_NODE), GFLT_TAG);
    if (!node) return STATUS_INSUFFICIENT_RESOURCES;

    node->ProcessName.Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, nameLen + sizeof(WCHAR), GFLT_TAG);
    if (!node->ProcessName.Buffer) {
        ExFreePoolWithTag(node, GFLT_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(node->ProcessName.Buffer, Entry->ProcessName, nameLen);
    node->ProcessName.Buffer[nameLen / sizeof(WCHAR)] = L'\0';
    node->ProcessName.Length = (USHORT)nameLen;
    node->ProcessName.MaximumLength = (USHORT)(nameLen + sizeof(WCHAR));
    node->Permissions = Entry->Permissions;

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_UNSUCCESSFUL;
    ExAcquireResourceExclusiveLite(&g_FilterData.WhitelistLock, TRUE);
    InsertTailList(&g_FilterData.WhitelistEntries, &node->ListEntry);
    g_FilterData.WhitelistCount++;
    ExReleaseResourceLite(&g_FilterData.WhitelistLock);

    return STATUS_SUCCESS;
}

BOOLEAN GfltIsPathProtected(_In_ PUNICODE_STRING FilePath)
{
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;

    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    ExAcquireResourceSharedLite(&g_FilterData.PathListLock, TRUE);

    for (entry = g_FilterData.ProtectedPaths.Flink;
         entry != &g_FilterData.ProtectedPaths;
         entry = entry->Flink) {
        PPROTECTED_PATH_NODE node = CONTAINING_RECORD(entry, PROTECTED_PATH_NODE, ListEntry);

        if (node->Recursive) {
            /* Prefix match for recursive protection */
            if (FilePath->Length >= node->Path.Length &&
                RtlPrefixUnicodeString(&node->Path, FilePath, TRUE)) {
                found = TRUE;
                break;
            }
        } else {
            if (RtlEqualUnicodeString(&node->Path, FilePath, TRUE)) {
                found = TRUE;
                break;
            }
        }
    }

    ExReleaseResourceLite(&g_FilterData.PathListLock);
    return found;
}

BOOLEAN GfltIsProcessWhitelisted(
    _In_ PUNICODE_STRING ProcessName,
    _In_ ULONG RequiredPermission)
{
    PLIST_ENTRY entry;
    BOOLEAN whitelisted = FALSE;

    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    ExAcquireResourceSharedLite(&g_FilterData.WhitelistLock, TRUE);

    for (entry = g_FilterData.WhitelistEntries.Flink;
         entry != &g_FilterData.WhitelistEntries;
         entry = entry->Flink) {
        PWHITELIST_NODE node = CONTAINING_RECORD(entry, WHITELIST_NODE, ListEntry);
        if (RtlEqualUnicodeString(&node->ProcessName, ProcessName, TRUE)) {
            if (node->Permissions & RequiredPermission) {
                whitelisted = TRUE;
            }
            break;
        }
    }

    ExReleaseResourceLite(&g_FilterData.WhitelistLock);
    return whitelisted;
}

/* ============================================
 * Ring Buffer Operations
 * ============================================ */

VOID GfltPushEvent(_In_ PGUARDIAN_EVENT_OUTPUT Event)
{
    KIRQL oldIrql;
    LONG nextHead;

    KeAcquireSpinLock(&g_FilterData.EventRing.Lock, &oldIrql);

    nextHead = (g_FilterData.EventRing.Head + 1) % GUARDIAN_EVENT_RING_SIZE;
    if (g_FilterData.EventRing.Count >= GUARDIAN_EVENT_RING_SIZE) {
        /* Ring full, drop oldest */
        g_FilterData.EventRing.Tail = (g_FilterData.EventRing.Tail + 1) % GUARDIAN_EVENT_RING_SIZE;
        InterlockedIncrement(&g_FilterData.EventRing.DroppedCount);
    } else {
        InterlockedIncrement(&g_FilterData.EventRing.Count);
    }

    RtlCopyMemory(
        &g_FilterData.EventRing.Events[g_FilterData.EventRing.Head],
        Event,
        sizeof(GUARDIAN_EVENT_OUTPUT));
    g_FilterData.EventRing.Head = nextHead;

    KeReleaseSpinLock(&g_FilterData.EventRing.Lock, oldIrql);
}

BOOLEAN GfltPopEvent(_Out_ PGUARDIAN_EVENT_OUTPUT Event)
{
    KIRQL oldIrql;
    BOOLEAN hasEvent = FALSE;

    KeAcquireSpinLock(&g_FilterData.EventRing.Lock, &oldIrql);

    if (g_FilterData.EventRing.Count > 0) {
        RtlCopyMemory(
            Event,
            &g_FilterData.EventRing.Events[g_FilterData.EventRing.Tail],
            sizeof(GUARDIAN_EVENT_OUTPUT));
        g_FilterData.EventRing.Tail = (g_FilterData.EventRing.Tail + 1) % GUARDIAN_EVENT_RING_SIZE;
        InterlockedDecrement(&g_FilterData.EventRing.Count);
        hasEvent = TRUE;
    }

    KeReleaseSpinLock(&g_FilterData.EventRing.Lock, oldIrql);
    return hasEvent;
}
