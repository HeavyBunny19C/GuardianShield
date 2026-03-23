/**
 * @file guard_monitor.c
 * @brief GuardMonitor driver - DriverEntry, device creation, unload
 */

#include "../include/guard_monitor.h"

GUARD_MONITOR_DATA g_MonitorData = { 0 };

/* ============================================
 * DriverEntry
 * ============================================ */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Initialize global data */
    RtlZeroMemory(&g_MonitorData, sizeof(g_MonitorData));
    InitializeListHead(&g_MonitorData.WhitelistEntries);
    ExInitializeResourceLite(&g_MonitorData.WhitelistLock);
    KeInitializeSpinLock(&g_MonitorData.EventRing.Lock);
    g_MonitorData.MonitoringEnabled = FALSE;
    g_MonitorData.EmergencyActive = FALSE;

    /* Create device object */
    RtlInitUnicodeString(&g_MonitorData.DeviceName, GUARDMONITOR_DEVICE_NAME);
    RtlInitUnicodeString(&g_MonitorData.SymlinkName, GUARDMONITOR_SYMLINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_MonitorData.DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_MonitorData.DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Create symbolic link for user-mode access */
    status = IoCreateSymbolicLink(&g_MonitorData.SymlinkName, &g_MonitorData.DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_MonitorData.DeviceObject);
        return status;
    }

    /* Register dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = GmonDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = GmonDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = GmonDispatchDeviceControl;
    DriverObject->DriverUnload = GmonUnload;

    /* Register process creation/termination notification */
    status = PsSetCreateProcessNotifyRoutineEx(GmonProcessNotifyCallback, FALSE);
    if (NT_SUCCESS(status)) {
        g_MonitorData.ProcessNotifyRegistered = TRUE;
    }

    /* Register image load notification */
    status = PsSetLoadImageNotifyRoutine(GmonImageNotifyCallback);
    if (NT_SUCCESS(status)) {
        g_MonitorData.ImageNotifyRegistered = TRUE;
    }

    /* Register ObCallbacks for process protection */
    GmonRegisterObCallbacks();

    /* Don't fail DriverEntry if notifications fail - degrade gracefully */
    return STATUS_SUCCESS;
}

/* ============================================
 * Unload
 * ============================================ */

VOID GmonUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    PLIST_ENTRY entry;
    UNREFERENCED_PARAMETER(DriverObject);

    /* Unregister notifications */
    if (g_MonitorData.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(GmonProcessNotifyCallback, TRUE);
        g_MonitorData.ProcessNotifyRegistered = FALSE;
    }
    if (g_MonitorData.ImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(GmonImageNotifyCallback);
        g_MonitorData.ImageNotifyRegistered = FALSE;
    }

    /* Unregister ObCallbacks */
    GmonUnregisterObCallbacks();

    /* Delete symbolic link and device */
    IoDeleteSymbolicLink(&g_MonitorData.SymlinkName);
    if (g_MonitorData.DeviceObject) {
        IoDeleteDevice(g_MonitorData.DeviceObject);
    }

    /* Free whitelist */
    while (!IsListEmpty(&g_MonitorData.WhitelistEntries)) {
        entry = RemoveHeadList(&g_MonitorData.WhitelistEntries);
        PMONITOR_WHITELIST_NODE node = CONTAINING_RECORD(entry, MONITOR_WHITELIST_NODE, ListEntry);
        if (node->ProcessName.Buffer) {
            ExFreePoolWithTag(node->ProcessName.Buffer, GMON_TAG);
        }
        ExFreePoolWithTag(node, GMON_TAG);
    }

    ExDeleteResourceLite(&g_MonitorData.WhitelistLock);
}

/* ============================================
 * IRP_MJ_CREATE / IRP_MJ_CLOSE
 * ============================================ */

NTSTATUS GmonDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ============================================
 * Whitelist Helper
 * ============================================ */

BOOLEAN GmonIsProcessWhitelisted(_In_ PUNICODE_STRING ProcessName)
{
    PLIST_ENTRY entry;
    BOOLEAN whitelisted = FALSE;

    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    ExAcquireResourceSharedLite(&g_MonitorData.WhitelistLock, TRUE);

    for (entry = g_MonitorData.WhitelistEntries.Flink;
         entry != &g_MonitorData.WhitelistEntries;
         entry = entry->Flink) {
        PMONITOR_WHITELIST_NODE node = CONTAINING_RECORD(entry, MONITOR_WHITELIST_NODE, ListEntry);
        if (RtlEqualUnicodeString(&node->ProcessName, ProcessName, TRUE)) {
            whitelisted = TRUE;
            break;
        }
    }

    ExReleaseResourceLite(&g_MonitorData.WhitelistLock);
    return whitelisted;
}

/* ============================================
 * Ring Buffer Operations
 * ============================================ */

VOID GmonPushEvent(_In_ PGUARDIAN_EVENT_OUTPUT Event)
{
    KIRQL oldIrql;
    LONG nextHead;

    KeAcquireSpinLock(&g_MonitorData.EventRing.Lock, &oldIrql);

    nextHead = (g_MonitorData.EventRing.Head + 1) % GUARDIAN_EVENT_RING_SIZE;
    if (g_MonitorData.EventRing.Count >= GUARDIAN_EVENT_RING_SIZE) {
        g_MonitorData.EventRing.Tail = (g_MonitorData.EventRing.Tail + 1) % GUARDIAN_EVENT_RING_SIZE;
        InterlockedIncrement(&g_MonitorData.EventRing.DroppedCount);
    } else {
        InterlockedIncrement(&g_MonitorData.EventRing.Count);
    }

    RtlCopyMemory(
        &g_MonitorData.EventRing.Events[g_MonitorData.EventRing.Head],
        Event,
        sizeof(GUARDIAN_EVENT_OUTPUT));
    g_MonitorData.EventRing.Head = nextHead;

    KeReleaseSpinLock(&g_MonitorData.EventRing.Lock, oldIrql);
}

BOOLEAN GmonPopEvent(_Out_ PGUARDIAN_EVENT_OUTPUT Event)
{
    KIRQL oldIrql;
    BOOLEAN hasEvent = FALSE;

    KeAcquireSpinLock(&g_MonitorData.EventRing.Lock, &oldIrql);

    if (g_MonitorData.EventRing.Count > 0) {
        RtlCopyMemory(
            Event,
            &g_MonitorData.EventRing.Events[g_MonitorData.EventRing.Tail],
            sizeof(GUARDIAN_EVENT_OUTPUT));
        g_MonitorData.EventRing.Tail = (g_MonitorData.EventRing.Tail + 1) % GUARDIAN_EVENT_RING_SIZE;
        InterlockedDecrement(&g_MonitorData.EventRing.Count);
        hasEvent = TRUE;
    }

    KeReleaseSpinLock(&g_MonitorData.EventRing.Lock, oldIrql);
    return hasEvent;
}

/* ============================================
 * ObRegisterCallbacks - Process Protection
 * ============================================ */

BOOLEAN GmonIsProtectedPid(_In_ HANDLE Pid)
{
    LONG count = InterlockedCompareExchange(&g_MonitorData.ProtectedPidCount, 0, 0);
    LONG i;
    for (i = 0; i < count && i < GUARDIAN_MAX_PROTECTED_PIDS; i++) {
        if (g_MonitorData.ProtectedPids[i] == Pid) {
            return TRUE;
        }
    }
    return FALSE;
}

OB_PREOP_CALLBACK_STATUS GmonPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInfo->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInfo->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);

    if (!GmonIsProtectedPid(targetPid)) {
        return OB_PREOP_SUCCESS;
    }

    /* Don't restrict the process itself */
    if (PsGetCurrentProcessId() == targetPid) {
        return OB_PREOP_SUCCESS;
    }

    /* Strip PROCESS_TERMINATE and PROCESS_SUSPEND_RESUME from non-guardian callers */
    if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME);
    } else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME);
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS GmonRegisterObCallbacks(VOID)
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION cbReg;
    OB_OPERATION_REGISTRATION opReg;

    RtlZeroMemory(&cbReg, sizeof(cbReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = GmonPreOperationCallback;
    opReg.PostOperation = NULL;

    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&cbReg.Altitude, L"321000");
    cbReg.OperationRegistration = &opReg;

    status = ObRegisterCallbacks(&cbReg, &g_MonitorData.ObCallbackHandle);
    if (!NT_SUCCESS(status)) {
        g_MonitorData.ObCallbackHandle = NULL;
    }

    return status;
}

VOID GmonUnregisterObCallbacks(VOID)
{
    if (g_MonitorData.ObCallbackHandle != NULL) {
        ObUnRegisterCallbacks(g_MonitorData.ObCallbackHandle);
        g_MonitorData.ObCallbackHandle = NULL;
    }
}
