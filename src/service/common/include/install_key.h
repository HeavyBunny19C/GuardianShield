/**
 * @file install_key.h
 * @brief Install/Uninstall key verification using SHA-256
 * 
 * Supports two modes:
 * 1. Config-backed: reads install_key_hash from Config cache (set in guardian_config.yaml)
 * 2. Hardcoded fallback: uses built-in default hash for first-time installation
 */

#pragma once

#include <string>
#include "string_utils.h"
#include <vector>
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace Guardian {

static constexpr const char* DEFAULT_INSTALL_KEY_HASH =
    "9fa5a1127819b0ec6ab6bfdacbc62ffe2a9cd3d1faf7f2db7df7fcc369e5d3df";

inline std::string ComputeSHA256(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return "";

    DWORD hashLen = 0, dataLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &dataLen, 0);

    std::vector<BYTE> hashValue(hashLen);

    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.size(), 0);
    BCryptFinishHash(hHash, hashValue.data(), hashLen, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    static const char hex[] = "0123456789abcdef";
    result.reserve(hashLen * 2);
    for (DWORD i = 0; i < hashLen; ++i) {
        result += hex[(hashValue[i] >> 4) & 0xF];
        result += hex[hashValue[i] & 0xF];
    }
    return result;
}

inline bool VerifyInstallKeyAgainstHash(int argc, wchar_t** argv, const std::string& expectedHash) {
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
        } else {
            MessageBoxW(nullptr,
                L"请通过 -key <密钥> 参数提供安装密钥。\n"
                L"示例: svchost_core.exe -install -key YourKey",
                L"GuardianShield - 需要安装密钥",
                MB_OK | MB_ICONINFORMATION);
            return false;
        }
    }

    std::string keyA = WideToUtf8(keyW);
    std::string hash = ComputeSHA256(keyA);
    if (hash.size() != expectedHash.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < hash.size(); ++i) {
        diff |= static_cast<uint8_t>(hash[i]) ^ static_cast<uint8_t>(expectedHash[i]);
    }
    return diff == 0;
}

/**
 * Verify install key. If configHash is non-empty, use it; otherwise fall back to default.
 */
inline bool VerifyInstallKey(int argc, wchar_t** argv, const std::string& configHash = "") {
    std::string expected = configHash.empty() ? std::string(DEFAULT_INSTALL_KEY_HASH) : configHash;
    if (expected.empty()) return false;
    return VerifyInstallKeyAgainstHash(argc, argv, expected);
}

} // namespace Guardian
