/**
 * @file guard_filter.h
 * @brief GuardFilter minifilter driver header
 */

#ifndef GUARD_FILTER_H
#define GUARD_FILTER_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "../../shared/guardian_ioctl.h"

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

/* ============================================
 * Driver Tag
 * ============================================ */

#define GFLT_TAG  'tlfG'

/* ============================================
 * Protected Path List
 * ============================================ */

#define MAX_PROTECTED_PATHS   256
#define MAX_WHITELIST_ENTRIES  128

typedef struct _PROTECTED_PATH_NODE {
    LIST_ENTRY  ListEntry;
    UNICODE_STRING Path;
    ULONG       Recursive;
    ULONG       Priority;
} PROTECTED_PATH_NODE, *PPROTECTED_PATH_NODE;

typedef struct _WHITELIST_NODE {
    LIST_ENTRY  ListEntry;
    UNICODE_STRING ProcessName;
    ULONG       Permissions;
} WHITELIST_NODE, *PWHITELIST_NODE;

/* ============================================
 * Event Ring Buffer
 * ============================================ */

typedef struct _EVENT_RING_BUFFER {
    GUARDIAN_EVENT_OUTPUT  Events[GUARDIAN_EVENT_RING_SIZE];
    volatile LONG   Head;
    volatile LONG   Tail;
    volatile LONG   Count;
    volatile LONG   DroppedCount;
    KSPIN_LOCK      Lock;
} EVENT_RING_BUFFER, *PEVENT_RING_BUFFER;

/* ============================================
 * Global Driver Data
 * ============================================ */

typedef struct _GUARD_FILTER_DATA {
    PFLT_FILTER         Filter;
    PFLT_PORT           ServerPort;
    PFLT_PORT           ClientPort;

    LIST_ENTRY          ProtectedPaths;
    ERESOURCE           PathListLock;
    ULONG               PathCount;

    LIST_ENTRY          WhitelistEntries;
    ERESOURCE           WhitelistLock;
    ULONG               WhitelistCount;

    EVENT_RING_BUFFER   EventRing;

    volatile LONG       MonitoringEnabled;
    volatile LONG       EmergencyActive;
    volatile LONG       BlockPolicy;

    ULONG64             TotalOperations;
    ULONG64             BlockedOperations;
} GUARD_FILTER_DATA, *PGUARD_FILTER_DATA;

extern GUARD_FILTER_DATA g_FilterData;

/* ============================================
 * DriverEntry & Unload
 * ============================================ */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS GfltUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS GfltInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

/* ============================================
 * Minifilter Callbacks
 * ============================================ */

FLT_PREOP_CALLBACK_STATUS GfltPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS GfltPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS GfltPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS GfltPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

/* ============================================
 * Communication Port
 * ============================================ */

NTSTATUS GfltPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID GfltPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS GfltPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

/* ============================================
 * Helper Functions
 * ============================================ */

BOOLEAN GfltIsPathProtected(
    _In_ PUNICODE_STRING FilePath
);

BOOLEAN GfltIsProcessWhitelisted(
    _In_ PUNICODE_STRING ProcessName,
    _In_ ULONG RequiredPermission
);

NTSTATUS GfltAddProtectedPath(
    _In_ PGUARDIAN_PATH_ENTRY PathEntry
);

NTSTATUS GfltRemoveProtectedPath(
    _In_ PCWSTR Path
);

NTSTATUS GfltAddWhitelistEntry(
    _In_ PGUARDIAN_WHITELIST_ENTRY Entry
);

VOID GfltPushEvent(
    _In_ PGUARDIAN_EVENT_OUTPUT Event
);

BOOLEAN GfltPopEvent(
    _Out_ PGUARDIAN_EVENT_OUTPUT Event
);

#endif /* GUARD_FILTER_H */
