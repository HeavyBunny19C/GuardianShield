/**
 * @file security.cpp
 * @brief Security utilities implementation
 */

#include "security.h"
#include <chrono>

#ifdef _WIN32
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace Guardian {

// AntiDebug Implementation
bool AntiDebug::IsDebuggerPresent() {
#ifdef _WIN32
    return ::IsDebuggerPresent() != FALSE;
#else
    return false;
#endif
}

bool AntiDebug::CheckPEBDebugPort() {
    return false;
}

bool AntiDebug::CheckNtGlobalFlag() {
    return false;
}

bool AntiDebug::CheckHardwareBreakpoints() {
    return false;
}

bool AntiDebug::CheckTimingAnomaly() {
    auto start = std::chrono::high_resolution_clock::now();
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x++;
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    return duration.count() > 10000;
}

bool AntiDebug::HasRemoteThread() {
    return false;
}

bool AntiDebug::HasUnknownModule() {
    return false;
}

bool AntiDebug::HasMemoryModification() {
    return false;
}

bool AntiDebug::IsInjected() {
    return false;
}

bool AntiDebug::RunAllChecks() {
    return IsDebuggerPresent() || CheckTimingAnomaly();
}

#ifdef _WIN64
void* AntiDebug::GetPEB() {
    return nullptr;
}
#else
void* AntiDebug::GetPEB() {
    return nullptr;
}
#endif

// Hash Implementation
bool Hash::SHA256(const void* data, size_t size, uint8_t hash[32]) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashSize = 32;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return false;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)size, 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    if (BCryptFinishHash(hHash, hash, 32, 0) != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
#else
    return false;
#endif
}

bool Hash::SHA256File(const std::wstring& filePath, uint8_t hash[32]) {
#ifdef _WIN32
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
        CloseHandle(hFile);
        return false;
    }
    
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return false;
    }
    
    const size_t CHUNK_SIZE = 65536; // 64KB
    uint8_t buffer[CHUNK_SIZE];
    DWORD bytesRead = 0;
    bool success = true;
    
    while (ReadFile(hFile, buffer, CHUNK_SIZE, &bytesRead, NULL) && bytesRead > 0) {
        if (BCryptHashData(hHash, buffer, bytesRead, 0) != 0) {
            success = false;
            break;
        }
    }
    
    SecureZeroMemory(buffer, sizeof(buffer));
    
    if (success && BCryptFinishHash(hHash, hash, 32, 0) != 0) {
        success = false;
    }
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    
    return success;
#else
    return false;
#endif
}

bool Hash::HMAC_SHA256(const void* key, size_t keySize,
                        const void* data, size_t dataSize,
                        uint8_t hmac[32]) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptCreateHash(
        hAlg, &hHash, nullptr, 0,
        (PUCHAR)key, (ULONG)keySize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptFinishHash(hHash, hmac, 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status);
#else
    return false;
#endif
}

std::string Hash::ToHexString(const uint8_t* hash, size_t size) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for (size_t i = 0; i < size; i++) {
        result.push_back(hex[hash[i] >> 4]);
        result.push_back(hex[hash[i] & 0xf]);
    }
    return result;
}

// ProcessIntegrity Implementation
bool ProcessIntegrity::VerifyHash(const std::wstring& processPath, const uint8_t expectedHash[32]) {
    return false;
}

bool ProcessIntegrity::IsElevated() {
#ifdef _WIN32
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return elevated != FALSE;
#else
    return false;
#endif
}

std::wstring ProcessIntegrity::GetIntegrityLevel() {
    return L"Medium";
}

bool ProcessIntegrity::IsRunningAsUser(const std::wstring& username) {
    return false;
}

} // namespace Guardian
