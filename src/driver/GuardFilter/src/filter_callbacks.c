/**
 * @file filter_callbacks.c
 * @brief GuardFilter minifilter pre-operation callbacks
 */

#include "../include/guard_filter.h"

/**
 * @brief Get the current process image name (short name only)
 */
static VOID GfltGetProcessName(
    _Out_writes_(BufferLen) PWCHAR Buffer,
    _In_ ULONG BufferLen)
{
    PEPROCESS process = PsGetCurrentProcess();
    PCHAR imageName;

    RtlZeroMemory(Buffer, BufferLen * sizeof(WCHAR));

    if (!process) return;

    imageName = (PCHAR)PsGetProcessImageFileName(process);
    if (imageName) {
        ANSI_STRING ansi;
        UNICODE_STRING uni;
        RtlInitAnsiString(&ansi, imageName);
        uni.Buffer = Buffer;
        uni.Length = 0;
        uni.MaximumLength = (USHORT)(BufferLen * sizeof(WCHAR));
        RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
    }
}

/**
 * @brief Build and push an event into the ring buffer
 */
static VOID GfltRecordEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG EventType)
{
    GUARDIAN_EVENT_OUTPUT event = { 0 };
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    LARGE_INTEGER timestamp;

    UNREFERENCED_PARAMETER(FltObjects);

    event.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event.EventType = EventType;

    KeQuerySystemTimePrecise(&timestamp);
    event.Timestamp = (ULONG64)timestamp.QuadPart;

    event.AccessMask = Data->Iopb->Parameters.Create.SecurityContext
        ? Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess
        : 0;

    /* File path */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        SIZE_T copyLen = min(nameInfo->Name.Length, sizeof(event.FilePath) - sizeof(WCHAR));
        RtlCopyMemory(event.FilePath, nameInfo->Name.Buffer, copyLen);
        event.FilePath[copyLen / sizeof(WCHAR)] = L'\0';
        FltReleaseFileNameInformation(nameInfo);
    }

    /* Process name */
    GfltGetProcessName(event.ProcessName, GUARDIAN_MAX_PROC_NAME);

    InterlockedIncrement64((volatile LONG64*)&g_FilterData.TotalOperations);
    GfltPushEvent(&event);
}

/* ============================================
 * PreCreate Callback
 * ============================================ */

FLT_PREOP_CALLBACK_STATUS GfltPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    UNICODE_STRING processName;
    WCHAR procBuf[GUARDIAN_MAX_PROC_NAME];

    *CompletionContext = NULL;

    if (!InterlockedCompareExchange(&g_FilterData.MonitoringEnabled, 0, 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Get file name to check protection */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    if (!GfltIsPathProtected(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Check process whitelist */
    GfltGetProcessName(procBuf, GUARDIAN_MAX_PROC_NAME);
    RtlInitUnicodeString(&processName, procBuf);
    if (GfltIsProcessWhitelisted(&processName, 1 /* READ */)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltReleaseFileNameInformation(nameInfo);

    /* Record event */
    GfltRecordEvent(Data, FltObjects, GUARDIAN_EVENT_FILE_CREATE);

    /* In emergency mode, block all non-whitelisted access */
    if (InterlockedCompareExchange(&g_FilterData.EmergencyActive, 0, 0)) {
        InterlockedIncrement64((volatile LONG64*)&g_FilterData.BlockedOperations);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* Block policy: block create if BLOCK_FLAG_CREATE is set */
    if (InterlockedCompareExchange(&g_FilterData.BlockPolicy, 0, 0) & BLOCK_FLAG_CREATE) {
        InterlockedIncrement64((volatile LONG64*)&g_FilterData.BlockedOperations);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================
 * PreWrite Callback
 * ============================================ */

FLT_PREOP_CALLBACK_STATUS GfltPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    UNICODE_STRING processName;
    WCHAR procBuf[GUARDIAN_MAX_PROC_NAME];

    *CompletionContext = NULL;

    if (!InterlockedCompareExchange(&g_FilterData.MonitoringEnabled, 0, 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    if (!GfltIsPathProtected(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    GfltGetProcessName(procBuf, GUARDIAN_MAX_PROC_NAME);
    RtlInitUnicodeString(&processName, procBuf);
    if (GfltIsProcessWhitelisted(&processName, 2 /* WRITE */)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltReleaseFileNameInformation(nameInfo);

    GfltRecordEvent(Data, FltObjects, GUARDIAN_EVENT_FILE_WRITE);

    if (InterlockedCompareExchange(&g_FilterData.EmergencyActive, 0, 0)) {
        InterlockedIncrement64((volatile LONG64*)&g_FilterData.BlockedOperations);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* Block policy: block write if BLOCK_FLAG_WRITE is set */
    if (InterlockedCompareExchange(&g_FilterData.BlockPolicy, 0, 0) & BLOCK_FLAG_WRITE) {
        InterlockedIncrement64((volatile LONG64*)&g_FilterData.BlockedOperations);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================
 * PreSetInformation Callback (Rename/Delete)
 * ============================================ */

FLT_PREOP_CALLBACK_STATUS GfltPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    FILE_INFORMATION_CLASS infoClass;
    ULONG eventType;
    UNICODE_STRING processName;
    WCHAR procBuf[GUARDIAN_MAX_PROC_NAME];

    *CompletionContext = NULL;

    if (!InterlockedCompareExchange(&g_FilterData.MonitoringEnabled, 0, 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        eventType = GUARDIAN_EVENT_FILE_RENAME;
    } else if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx) {
        eventType = GUARDIAN_EVENT_FILE_DELETE;
    } else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    if (!GfltIsPathProtected(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    GfltGetProcessName(procBuf, GUARDIAN_MAX_PROC_NAME);
    RtlInitUnicodeString(&processName, procBuf);
    if (GfltIsProcessWhitelisted(&processName, 4 /* DELETE */)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltReleaseFileNameInformation(nameInfo);

    GfltRecordEvent(Data, FltObjects, eventType);

    /* Block rename/delete of protected files in emergency */
    if (InterlockedCompareExchange(&g_FilterData.EmergencyActive, 0, 0)) {
        InterlockedIncrement64((volatile LONG64*)&g_FilterData.BlockedOperations);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* Block policy: check RENAME or DELETE flag */
    {
        LONG bp = InterlockedCompareExchange(&g_FilterData.BlockPolicy, 0, 0);
        ULONG flag = (eventType == GUARDIAN_EVENT_FILE_RENAME) ? BLOCK_FLAG_RENAME : BLOCK_FLAG_DELETE;
        if (bp & flag) {
            InterlockedIncrement64((volatile LONG64*)&g_FilterData.BlockedOperations);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ============================================
 * PreCleanup Callback
 * ============================================ */

FLT_PREOP_CALLBACK_STATUS GfltPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    /* Cleanup tracking - placeholder for future stream context cleanup */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
