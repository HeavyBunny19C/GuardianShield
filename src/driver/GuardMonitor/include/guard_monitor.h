/**
 * @file guard_monitor.h
 * @brief GuardMonitor process/image monitoring driver header
 */

#ifndef GUARD_MONITOR_H
#define GUARD_MONITOR_H

#include <ntddk.h>
#include <ntstrsafe.h>

#include "../../shared/guardian_ioctl.h"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           0x0001
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME      0x0800
#endif
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

/* ============================================
 * Driver Tag
 * ============================================ */

#define GMON_TAG  'noMG'

/* ============================================
 * Whitelist
 * ============================================ */

typedef struct _MONITOR_WHITELIST_NODE {
    LIST_ENTRY      ListEntry;
    UNICODE_STRING  ProcessName;
    ULONG           Permissions;
} MONITOR_WHITELIST_NODE, *PMONITOR_WHITELIST_NODE;

/* ============================================
 * Event Ring Buffer (same pattern as GuardFilter)
 * ============================================ */

typedef struct _MONITOR_EVENT_RING {
    GUARDIAN_EVENT_OUTPUT  Events[GUARDIAN_EVENT_RING_SIZE];
    volatile LONG   Head;
    volatile LONG   Tail;
    volatile LONG   Count;
    volatile LONG   DroppedCount;
    KSPIN_LOCK      Lock;
} MONITOR_EVENT_RING, *PMONITOR_EVENT_RING;

/* ============================================
 * Global Driver Data
 * ============================================ */

typedef struct _GUARD_MONITOR_DATA {
    PDEVICE_OBJECT      DeviceObject;
    UNICODE_STRING      DeviceName;
    UNICODE_STRING      SymlinkName;

    LIST_ENTRY          WhitelistEntries;
    ERESOURCE           WhitelistLock;
    ULONG               WhitelistCount;

    MONITOR_EVENT_RING  EventRing;

    volatile LONG       MonitoringEnabled;
    volatile LONG       EmergencyActive;
    BOOLEAN             ProcessNotifyRegistered;
    BOOLEAN             ImageNotifyRegistered;

    /* ObRegisterCallbacks process protection */
    PVOID               ObCallbackHandle;
    HANDLE              ProtectedPids[8];
    volatile LONG       ProtectedPidCount;

    ULONG64             TotalOperations;
    ULONG64             BlockedOperations;
} GUARD_MONITOR_DATA, *PGUARD_MONITOR_DATA;

extern GUARD_MONITOR_DATA g_MonitorData;

/* ============================================
 * DriverEntry & Unload
 * ============================================ */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

VOID GmonUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

/* ============================================
 * IRP Dispatch
 * ============================================ */

NTSTATUS GmonDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS GmonDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

/* ============================================
 * Process/Image Notification Callbacks
 * ============================================ */

VOID GmonProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID GmonImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

/* ============================================
 * ObRegisterCallbacks Process Protection
 * ============================================ */

NTSTATUS GmonRegisterObCallbacks(VOID);
VOID GmonUnregisterObCallbacks(VOID);
BOOLEAN GmonIsProtectedPid(_In_ HANDLE Pid);

OB_PREOP_CALLBACK_STATUS GmonPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInfo
);

/* ============================================
 * Helpers
 * ============================================ */

BOOLEAN GmonIsProcessWhitelisted(
    _In_ PUNICODE_STRING ProcessName
);

VOID GmonPushEvent(
    _In_ PGUARDIAN_EVENT_OUTPUT Event
);

BOOLEAN GmonPopEvent(
    _Out_ PGUARDIAN_EVENT_OUTPUT Event
);

#endif /* GUARD_MONITOR_H */
