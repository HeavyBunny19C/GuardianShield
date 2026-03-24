/**
 * @file guardian_ca.cpp
 * @brief WiX Custom Action DLL for GuardianShield MSI Installer
 *
 * Exported functions:
 *   ValidateInstallKey  - Verifies the user-provided key using plaintext comparison
 *   CopyConfigFiles     - Copies auth.list and guardian_config.yaml to runtime dir
 */

#include <Windows.h>
#include <msi.h>
#include <msiquery.h>
#include <shlwapi.h>
#include <sddl.h>
#include <commdlg.h>
#include <string>
#include <vector>

#pragma comment(lib, "msi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")

// Default plaintext install key (plaintext comparison, no SHA256 per user requirement)
static const char* DEFAULT_INSTALL_KEY = "GuardianShield2024";

static constexpr const wchar_t* RUNTIME_CONFIG_DIR =
    L"C:\\ProgramData\\GuardianShield\\config";

// ---------------------------------------------------------------------------
// Read an MSI property into a wide string
// ---------------------------------------------------------------------------
static std::wstring GetMsiProperty(MSIHANDLE hInstall, const wchar_t* name)
{
    DWORD size = 0;
    MsiGetPropertyW(hInstall, name, L"", &size);
    if (size == 0)
        return L"";

    ++size; // null terminator
    std::wstring value(size, L'\0');
    MsiGetPropertyW(hInstall, name, &value[0], &size);
    value.resize(size);
    return value;
}

// ---------------------------------------------------------------------------
// Show a message box through the MSI UI
// ---------------------------------------------------------------------------
static void MsiMessageBox(MSIHANDLE hInstall, const wchar_t* text)
{
    PMSIHANDLE hRec = MsiCreateRecord(0);
    MsiRecordSetStringW(hRec, 0, text);
    MsiProcessMessage(hInstall, INSTALLMESSAGE_ERROR, hRec);
}

// ---------------------------------------------------------------------------
// Ensure directory exists (recursive)
// ---------------------------------------------------------------------------
static bool EnsureDirectoryExists(const std::wstring& path)
{
    if (PathFileExistsW(path.c_str()))
        return true;

    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        EnsureDirectoryExists(path.substr(0, pos));
    }
    return CreateDirectoryW(path.c_str(), nullptr) ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

// ---------------------------------------------------------------------------
// Set restrictive ACL: SYSTEM and Administrators only
// ---------------------------------------------------------------------------
static bool SetRestrictiveAcl(const wchar_t* path)
{
    PSECURITY_DESCRIPTOR pSD = nullptr;
    const wchar_t* sddl =
        L"D:P"
        L"(A;OICI;FA;;;SY)"     // SYSTEM full access
        L"(A;OICI;FA;;;BA)";    // Administrators full access

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, nullptr))
        return false;

    BOOL ok = SetFileSecurityW(path, DACL_SECURITY_INFORMATION, pSD);
    LocalFree(pSD);
    return ok != FALSE;
}

// ---------------------------------------------------------------------------
// Constant-time string comparison to prevent timing attacks
// ---------------------------------------------------------------------------
static bool ConstantTimeStringCompare(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
    }
    return diff == 0;
}

// ---------------------------------------------------------------------------
// Exported: ValidateInstallKey (immediate CA)
//
// Reads INSTALL_KEY property and compares to expected key using plaintext
// comparison (no SHA256 hashing per user requirement).
// Returns ERROR_SUCCESS on match, ERROR_INSTALL_FAILURE on mismatch.
// ---------------------------------------------------------------------------
extern "C" UINT __stdcall ValidateInstallKey(MSIHANDLE hInstall)
{
    std::wstring keyW = GetMsiProperty(hInstall, L"INSTALL_KEY");
    if (keyW.empty()) {
        MsiMessageBox(hInstall,
            L"[GuardianShield] \u8bf7\u8f93\u5165\u5b89\u88c5\u5bc6\u94a5\u3002");
        return ERROR_INSTALL_FAILURE;
    }

    int cbNeeded = WideCharToMultiByte(CP_UTF8, 0, keyW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string keyA(cbNeeded - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, keyW.c_str(), -1, &keyA[0], cbNeeded, nullptr, nullptr);

    // Plaintext comparison (no SHA256 per user requirement)
    if (!ConstantTimeStringCompare(keyA, DEFAULT_INSTALL_KEY)) {
        MsiMessageBox(hInstall,
            L"[GuardianShield] \u5b89\u88c5\u5bc6\u94a5\u9a8c\u8bc1\u5931\u8d25\uff0c\u8bf7\u786e\u8ba4\u5bc6\u94a5\u662f\u5426\u6b63\u786e\u3002");
        return ERROR_INSTALL_FAILURE;
    }

    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Exported: CopyConfigFiles (deferred CA, runs elevated)
//
// CustomActionData format: "AUTH_LIST_PATH|CONFIG_YAML_PATH"
// Copies both files to C:\ProgramData\GuardianShield\config\
// ---------------------------------------------------------------------------
extern "C" UINT __stdcall CopyConfigFiles(MSIHANDLE hInstall)
{
    std::wstring customData = GetMsiProperty(hInstall, L"CustomActionData");
    if (customData.empty()) {
        MsiMessageBox(hInstall,
            L"[GuardianShield] \u672a\u63d0\u4f9b\u914d\u7f6e\u6587\u4ef6\u8def\u5f84\u3002");
        return ERROR_INSTALL_FAILURE;
    }

    size_t sep = customData.find(L'|');
    if (sep == std::wstring::npos) {
        MsiMessageBox(hInstall,
            L"[GuardianShield] CustomActionData \u683c\u5f0f\u9519\u8bef\u3002");
        return ERROR_INSTALL_FAILURE;
    }

    std::wstring authListPath = customData.substr(0, sep);
    std::wstring configYamlPath = customData.substr(sep + 1);

    if (!EnsureDirectoryExists(RUNTIME_CONFIG_DIR)) {
        MsiMessageBox(hInstall,
            L"[GuardianShield] \u65e0\u6cd5\u521b\u5efa\u914d\u7f6e\u76ee\u5f55\u3002");
        return ERROR_INSTALL_FAILURE;
    }

    SetRestrictiveAcl(RUNTIME_CONFIG_DIR);

    std::wstring destAuth = std::wstring(RUNTIME_CONFIG_DIR) + L"\\auth.list";
    std::wstring destYaml = std::wstring(RUNTIME_CONFIG_DIR) + L"\\guardian_config.yaml";

    if (!authListPath.empty() && PathFileExistsW(authListPath.c_str())) {
        if (!CopyFileW(authListPath.c_str(), destAuth.c_str(), FALSE)) {
            MsiMessageBox(hInstall,
                L"[GuardianShield] \u590d\u5236 auth.list \u5931\u8d25\u3002");
            return ERROR_INSTALL_FAILURE;
        }
    }

    if (!configYamlPath.empty() && PathFileExistsW(configYamlPath.c_str())) {
        if (!CopyFileW(configYamlPath.c_str(), destYaml.c_str(), FALSE)) {
            MsiMessageBox(hInstall,
                L"[GuardianShield] \u590d\u5236 guardian_config.yaml \u5931\u8d25\u3002");
            return ERROR_INSTALL_FAILURE;
        }
    }

    SetRestrictiveAcl(destAuth.c_str());
    SetRestrictiveAcl(destYaml.c_str());

    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Helper: Set an MSI property
// ---------------------------------------------------------------------------
static void SetMsiProperty(MSIHANDLE hInstall, const wchar_t* name, const wchar_t* value)
{
    MsiSetPropertyW(hInstall, name, value);
}

// ---------------------------------------------------------------------------
// Helper: Get directory containing the MSI package
// ---------------------------------------------------------------------------
static std::wstring GetMsiSourceDir(MSIHANDLE hInstall)
{
    std::wstring db = GetMsiProperty(hInstall, L"OriginalDatabase");
    if (db.empty())
        db = GetMsiProperty(hInstall, L"SOURCEDIR");
    if (db.empty())
        return L"";
    size_t pos = db.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        return db.substr(0, pos + 1);
    return L"";
}

// ---------------------------------------------------------------------------
// Exported: LocateConfigFiles (immediate CA)
//
// Auto-detect auth.list / guardian_config.yaml next to the MSI package,
// in the project config/ subfolder, or in the existing ProgramData dir.
// Sets AUTH_LIST_PATH / CONFIG_YAML_PATH if found.
// ---------------------------------------------------------------------------
extern "C" UINT __stdcall LocateConfigFiles(MSIHANDLE hInstall)
{
    std::wstring msiDir = GetMsiSourceDir(hInstall);
    std::wstring msiConfigDir;
    if (!msiDir.empty())
        msiConfigDir = msiDir + L"config\\";

    const wchar_t* candidates[] = {
        msiDir.c_str(),
        msiConfigDir.c_str(),
        L"C:\\ProgramData\\GuardianShield\\config\\"
    };

    auto tryFind = [&](const wchar_t* filename, const wchar_t* propName) {
        for (const wchar_t* dir : candidates) {
            if (!dir || !dir[0]) continue;
            std::wstring full = std::wstring(dir) + filename;
            if (PathFileExistsW(full.c_str())) {
                SetMsiProperty(hInstall, propName, full.c_str());
                return;
            }
        }
    };

    tryFind(L"auth.list", L"AUTH_LIST_PATH");
    tryFind(L"guardian_config.yaml", L"CONFIG_YAML_PATH");

    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Helper: Show a file-open dialog and return the selected path
// ---------------------------------------------------------------------------
static std::wstring BrowseForFile(const wchar_t* title, const wchar_t* filter)
{
    wchar_t filePath[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn))
        return filePath;
    return L"";
}

// ---------------------------------------------------------------------------
// Exported: BrowseAuthList (immediate CA)
// ---------------------------------------------------------------------------
extern "C" UINT __stdcall BrowseAuthList(MSIHANDLE hInstall)
{
    std::wstring path = BrowseForFile(
        L"\u9009\u62e9\u6388\u6743\u6e05\u5355 (auth.list)",
        L"Auth List (*.list)\0*.list\0All Files (*.*)\0*.*\0");
    if (!path.empty())
        SetMsiProperty(hInstall, L"AUTH_LIST_PATH", path.c_str());
    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Exported: BrowseConfigYaml (immediate CA)
// ---------------------------------------------------------------------------
extern "C" UINT __stdcall BrowseConfigYaml(MSIHANDLE hInstall)
{
    std::wstring path = BrowseForFile(
        L"\u9009\u62e9\u914d\u7f6e\u6587\u4ef6 (guardian_config.yaml)",
        L"YAML Config (*.yaml;*.yml)\0*.yaml;*.yml\0All Files (*.*)\0*.*\0");
    if (!path.empty())
        SetMsiProperty(hInstall, L"CONFIG_YAML_PATH", path.c_str());
    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Exported: BackupConfigCache (deferred CA, runs elevated)
//
// Copies config_cache.bin to a temp location before MajorUpgrade destroys it.
// ---------------------------------------------------------------------------
static constexpr const wchar_t* CACHE_FILE =
    L"C:\\ProgramData\\GuardianShield\\config_cache.bin";
static constexpr const wchar_t* CACHE_BACKUP =
    L"C:\\ProgramData\\GuardianShield\\config_cache.bin.upgrade_backup";

extern "C" UINT __stdcall BackupConfigCache(MSIHANDLE hInstall)
{
    (void)hInstall;
    if (PathFileExistsW(CACHE_FILE)) {
        CopyFileW(CACHE_FILE, CACHE_BACKUP, FALSE);
    }
    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Exported: RestoreConfigCache (deferred CA, runs elevated)
//
// Restores config_cache.bin from backup after RemoveExistingProducts.
// Only restores if the cache was destroyed by the old product's uninstall.
// ---------------------------------------------------------------------------
extern "C" UINT __stdcall RestoreConfigCache(MSIHANDLE hInstall)
{
    (void)hInstall;
    if (!PathFileExistsW(CACHE_FILE) && PathFileExistsW(CACHE_BACKUP)) {
        EnsureDirectoryExists(L"C:\\ProgramData\\GuardianShield");
        CopyFileW(CACHE_BACKUP, CACHE_FILE, FALSE);
        SetRestrictiveAcl(CACHE_FILE);
    }
    DeleteFileW(CACHE_BACKUP);
    return ERROR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
