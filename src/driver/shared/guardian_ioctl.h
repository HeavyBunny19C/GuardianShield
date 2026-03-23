/**
 * @file guardian_ioctl.h
 * @brief Shared IOCTL definitions between kernel drivers and user-mode clients
 *
 * This header is included by both kernel-mode drivers (GuardFilter, GuardMonitor)
 * and user-mode services (DriverClient). It defines the communication protocol.
 */

#ifndef GUARDIAN_IOCTL_H
#define GUARDIAN_IOCTL_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#endif

/* ============================================
 * Device Names
 * ============================================ */

#define GUARDFILTER_DEVICE_NAME     L"\\Device\\GuardFilter"
#define GUARDFILTER_SYMLINK_NAME    L"\\DosDevices\\GuardFilter"
#define GUARDFILTER_USERMODE_PATH   L"\\\\.\\GuardFilter"
#define GUARDFILTER_PORT_NAME       L"\\GuardFilterPort"

#define GUARDMONITOR_DEVICE_NAME    L"\\Device\\GuardMonitor"
#define GUARDMONITOR_SYMLINK_NAME   L"\\DosDevices\\GuardMonitor"
#define GUARDMONITOR_USERMODE_PATH  L"\\\\.\\GuardMonitor"

/* ============================================
 * IOCTL Codes
 * ============================================
 * FILE_DEVICE_UNKNOWN = 0x22
 * METHOD_BUFFERED     = 0
 * FILE_ANY_ACCESS     = 0
 */

#define GUARDIAN_DEVICE_TYPE  0x8000

/* GuardFilter IOCTLs (0x800 - 0x8FF) */
#define IOCTL_GUARDIAN_ADD_PROTECTED_PATH \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_REMOVE_PROTECTED_PATH \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_CLEAR_PROTECTED_PATHS \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_ADD_WHITELIST_PROCESS \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_REMOVE_WHITELIST_PROCESS \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_CLEAR_WHITELIST \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Event retrieval */
#define IOCTL_GUARDIAN_GET_EVENT \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_GET_PENDING_COUNT \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Monitoring control */
#define IOCTL_GUARDIAN_ENABLE_MONITORING \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_DISABLE_MONITORING \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Emergency */
#define IOCTL_GUARDIAN_TRIGGER_EMERGENCY \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_CANCEL_EMERGENCY \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Statistics */
#define IOCTL_GUARDIAN_GET_STATISTICS \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Process protection (ObRegisterCallbacks) */
#define IOCTL_GUARDIAN_SET_PROTECTED_PIDS \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_CLEAR_PROTECTED_PIDS \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define GUARDIAN_MAX_PROTECTED_PIDS  8

/* Block policy (kernel-level I/O blocking) */
#define IOCTL_GUARDIAN_SET_BLOCK_POLICY \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x860, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GUARDIAN_GET_BLOCK_POLICY \
    CTL_CODE(GUARDIAN_DEVICE_TYPE, 0x861, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BLOCK_FLAG_CREATE   0x01
#define BLOCK_FLAG_WRITE    0x02
#define BLOCK_FLAG_DELETE   0x04
#define BLOCK_FLAG_RENAME   0x08

/* ============================================
 * Shared Structures
 * ============================================ */

#define GUARDIAN_MAX_PATH       260
#define GUARDIAN_MAX_PROC_NAME  64
#define GUARDIAN_EVENT_EXTRA    256

#pragma pack(push, 1)

/**
 * @brief Protected path entry for IOCTL_GUARDIAN_ADD_PROTECTED_PATH
 */
typedef struct _GUARDIAN_PATH_ENTRY {
    WCHAR   Path[GUARDIAN_MAX_PATH];
    ULONG   Recursive;          /* 1 = include subdirectories */
    ULONG   Priority;           /* 0 = normal, higher = more important */
} GUARDIAN_PATH_ENTRY, *PGUARDIAN_PATH_ENTRY;

/**
 * @brief Whitelist process entry for IOCTL_GUARDIAN_ADD_WHITELIST_PROCESS
 */
typedef struct _GUARDIAN_WHITELIST_ENTRY {
    WCHAR   ProcessName[GUARDIAN_MAX_PROC_NAME];
    ULONG   Permissions;        /* Bitmask: 1=READ, 2=WRITE, 4=DELETE */
} GUARDIAN_WHITELIST_ENTRY, *PGUARDIAN_WHITELIST_ENTRY;

/**
 * @brief Event types matching user-mode DriverEventType
 */
#define GUARDIAN_EVENT_FILE_CREATE           0x01
#define GUARDIAN_EVENT_FILE_WRITE            0x03
#define GUARDIAN_EVENT_FILE_DELETE           0x04
#define GUARDIAN_EVENT_FILE_RENAME           0x05
#define GUARDIAN_EVENT_FILE_MOVE             0x07
#define GUARDIAN_EVENT_FILE_COMPRESS         0x08
#define GUARDIAN_EVENT_FILE_NETWORK_TRANSFER 0x09
#define GUARDIAN_EVENT_PROCESS_CREATE        0x10
#define GUARDIAN_EVENT_PROCESS_TERMINATE     0x11
#define GUARDIAN_EVENT_DRIVER_LOAD           0x30
#define GUARDIAN_EVENT_DRIVER_UNLOAD         0x31
// RESERVED (not implemented in current version):
// #define GUARDIAN_EVENT_FILE_READ          0x02
// #define GUARDIAN_EVENT_FILE_SET_INFO      0x06
// #define GUARDIAN_EVENT_PROCESS_INJECT     0x12
// #define GUARDIAN_EVENT_PROCESS_DEBUG      0x13
// #define GUARDIAN_EVENT_NETWORK_CONNECT    0x20
// #define GUARDIAN_EVENT_NETWORK_SEND       0x21
// #define GUARDIAN_EVENT_NETWORK_RECV       0x22

/**
 * @brief Event output structure for IOCTL_GUARDIAN_GET_EVENT
 * Layout matches user-mode DriverEvent for zero-copy deserialization.
 */
typedef struct _GUARDIAN_EVENT_OUTPUT {
    ULONG   ProcessId;
    ULONG   EventType;          /* GUARDIAN_EVENT_* values */
    ULONG64 Timestamp;
    ULONG   AccessMask;
    ULONG   DataSize;
    WCHAR   FilePath[GUARDIAN_MAX_PATH];
    WCHAR   ProcessName[GUARDIAN_MAX_PROC_NAME];
    UCHAR   ExtraData[GUARDIAN_EVENT_EXTRA];
} GUARDIAN_EVENT_OUTPUT, *PGUARDIAN_EVENT_OUTPUT;

/**
 * @brief Block policy for IOCTL_GUARDIAN_SET/GET_BLOCK_POLICY
 */
typedef struct _GUARDIAN_BLOCK_POLICY {
    ULONG   Flags;              /* Bitmask of BLOCK_FLAG_* */
} GUARDIAN_BLOCK_POLICY, *PGUARDIAN_BLOCK_POLICY;

/**
 * @brief Statistics output for IOCTL_GUARDIAN_GET_STATISTICS
 */
typedef struct _GUARDIAN_STATISTICS {
    ULONG64 TotalOperations;
    ULONG64 BlockedOperations;
    ULONG64 EventsGenerated;
    ULONG64 EventsDropped;
    ULONG   MonitoringEnabled;
    ULONG   EmergencyActive;
    ULONG   ProtectedPathCount;
    ULONG   WhitelistCount;
} GUARDIAN_STATISTICS, *PGUARDIAN_STATISTICS;

#pragma pack(pop)

/* ============================================
 * Ring Buffer Constants
 * ============================================ */

#define GUARDIAN_EVENT_RING_SIZE  1024

/* ============================================
 * Minifilter Communication Port Messages
 * ============================================ */

typedef struct _GUARDIAN_COMMAND_MESSAGE {
    ULONG   Command;            /* IOCTL code */
    ULONG   DataSize;
    UCHAR   Data[1];            /* Variable-length payload */
} GUARDIAN_COMMAND_MESSAGE, *PGUARDIAN_COMMAND_MESSAGE;

typedef struct _GUARDIAN_REPLY_MESSAGE {
    NTSTATUS Status;
    ULONG    DataSize;
    UCHAR    Data[1];
} GUARDIAN_REPLY_MESSAGE, *PGUARDIAN_REPLY_MESSAGE;

#endif /* GUARDIAN_IOCTL_H */
