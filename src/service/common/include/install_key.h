/**
 * @file install_key.h
 * @brief Install/Uninstall key verification using plaintext comparison
 * 
 * The key must come from the configuration cache. No built-in fallback key is
 * shipped with the repository.
 * 
 * NOTE: This is plaintext comparison (no SHA256 hashing) per user requirement.
 */

#pragma once

#include <string>
#include "string_utils.h"
#include <Windows.h>

namespace Guardian {

/**
 * Get the install key from command line arguments or environment variable.
 * Returns empty string if not found.
 */
inline std::wstring GetInstallKeyFromArgs(int argc, wchar_t** argv) {
    std::wstring keyW;

    for (int i = 1; i < argc - 1; ++i) {
        if (wcscmp(argv[i], L"-key") == 0 || wcscmp(argv[i], L"--key") == 0) {
            keyW = argv[i + 1];
            break;
        }
    }

    if (keyW.empty()) {
        const wchar_t* envKey = _wgetenv(L"GUARDIAN_INSTALL_KEY");
        if (envKey) {
            keyW = envKey;
        }
    }

    return keyW;
}

/**
 * Show a message box prompting for the install key.
 */
inline void ShowKeyRequiredMessage() {
    MessageBoxW(nullptr,
        L"请通过 -key <密钥> 参数提供安装密钥。\n"
        L"示例: svchost_core.exe -install -key YourKey",
        L"GuardianShield - 需要安装密钥",
        MB_OK | MB_ICONINFORMATION);
}

/**
 * Verify install key against expected key using plaintext comparison.
 * Uses constant-time comparison to prevent timing attacks.
 */
inline bool VerifyInstallKeyAgainstExpected(int argc, wchar_t** argv, const std::string& expectedKey) {
    std::wstring keyW = GetInstallKeyFromArgs(argc, argv);

    if (keyW.empty()) {
        ShowKeyRequiredMessage();
        return false;
    }

    std::string keyA = WideToUtf8(keyW);
    
    // Constant-time comparison to prevent timing attacks
    if (keyA.size() != expectedKey.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < keyA.size(); ++i) {
        diff |= static_cast<uint8_t>(keyA[i]) ^ static_cast<uint8_t>(expectedKey[i]);
    }
    return diff == 0;
}

/**
 * Verify install key. An explicit configured key is required.
 */
inline bool VerifyInstallKey(int argc, wchar_t** argv, const std::string& configKey = "") {
    if (configKey.empty()) return false;
    return VerifyInstallKeyAgainstExpected(argc, argv, configKey);
}

} // namespace Guardian
