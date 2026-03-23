/**
 * @file file_wiper.cpp
 * @brief File secure wiping implementation (DOD 5220.22-M standard, 7-pass)
 *
 * Pass order: 0x00, 0xFF, random, 0x00, 0xFF, random, 0x00
 * Uses BCryptGenRandom for cryptographically secure random data.
 */

#include "../include/file_wiper.h"
#include "../include/string_utils.h"
#include <iostream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace Guardian {

FileWiper::FileWiper() {
}

FileWiper::~FileWiper() {
}

WipeResult FileWiper::WipeFile(const std::wstring& filePath, WipeProgressCallback callback) {
    WipeResult result;
    result.success = false;
    result.file_path = filePath;
    result.original_size = 0;
    result.passes_completed = 0;

    DWORD attrs = GetFileAttributesW(filePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        result.error_message = "File does not exist";
        return result;
    }

    // Remove read-only attribute if set
    if (attrs & FILE_ATTRIBUTE_READONLY) {
        SetFileAttributesW(filePath.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
    }

    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        result.error_message = "Failed to get file information";
        return result;
    }

    LARGE_INTEGER fileSize;
    fileSize.HighPart = fileInfo.nFileSizeHigh;
    fileSize.LowPart = fileInfo.nFileSizeLow;
    result.original_size = static_cast<size_t>(fileSize.QuadPart);

    if (fileSize.QuadPart == 0) {
        result.success = true;
        result.passes_completed = m_passes;
        return result;
    }

    // DOD 5220.22-M 7-pass pattern
    // Pass 1: 0x00, Pass 2: 0xFF, Pass 3: random
    // Pass 4: 0x00, Pass 5: 0xFF, Pass 6: random, Pass 7: 0x00
    for (size_t i = 0; i < m_passes; i++) {
        if (callback) {
            callback(i + 1, m_passes, result.original_size * i);
        }

        bool ok = false;
        switch (i % 3) {
            case 0: ok = OverwriteFile(filePath, 0x00); break;
            case 1: ok = OverwriteFile(filePath, 0xFF); break;
            case 2: ok = OverwriteRandom(filePath);      break;
        }

        if (!ok) {
            result.error_message = "Failed during pass " + std::to_string(i + 1);
            return result;
        }
        result.passes_completed++;
    }

    if (callback) {
        callback(m_passes, m_passes, result.original_size * m_passes);
    }

    result.success = true;
    m_wipedCount++;
    m_wipedBytes += result.original_size;
    return result;
}

WipeResult FileWiper::WipeAndDelete(const std::wstring& filePath, WipeProgressCallback callback) {
    WipeResult result = WipeFile(filePath, callback);

    if (result.success) {
        if (!SecureDeleteFile(filePath)) {
            result.success = false;
            result.error_message = "Failed to delete file after wiping";
        }
    }

    return result;
}

size_t FileWiper::WipeDirectory(const std::wstring& dirPath, bool recursive,
                                WipeProgressCallback callback, const std::wstring& skipExtension) {
    size_t wipedCount = 0;

    WIN32_FIND_DATAW findData;
    std::wstring searchPath = dirPath + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = dirPath + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recursive) {
                wipedCount += WipeDirectory(fullPath, recursive, callback, skipExtension);
            }
        } else {
            if (!skipExtension.empty()) {
                std::wstring name(findData.cFileName);
                if (name.size() >= skipExtension.size() &&
                    name.substr(name.size() - skipExtension.size()) == skipExtension) {
                    continue;
                }
            }
            WipeResult result = WipeAndDelete(fullPath, callback);
            if (result.success) {
                wipedCount++;
            } else {
                std::string errPath = WideToUtf8(fullPath);
                std::cerr << "[WipeDirectory] FAILED: " << errPath
                          << " - " << result.error_message << std::endl;
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return wipedCount;
}

bool FileWiper::OverwriteFile(const std::wstring& filePath, uint8_t pattern) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Get file size via handle
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return false;
    }

    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

    const size_t bufferSize = 1024 * 1024; // 1 MB
    std::vector<uint8_t> buffer(bufferSize, pattern);

    LONGLONG bytesWritten = 0;
    while (bytesWritten < fileSize.QuadPart) {
        DWORD chunkSize = static_cast<DWORD>(
            (std::min)(static_cast<LONGLONG>(bufferSize), fileSize.QuadPart - bytesWritten));
        DWORD written = 0;

        if (!WriteFile(hFile, buffer.data(), chunkSize, &written, nullptr)) {
            CloseHandle(hFile);
            return false;
        }
        bytesWritten += written;
    }

    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    return true;
}

bool FileWiper::OverwriteRandom(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return false;
    }

    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

    const size_t bufferSize = 1024 * 1024; // 1 MB

    LONGLONG bytesWritten = 0;
    while (bytesWritten < fileSize.QuadPart) {
        DWORD chunkSize = static_cast<DWORD>(
            (std::min)(static_cast<LONGLONG>(bufferSize), fileSize.QuadPart - bytesWritten));

        std::vector<uint8_t> buffer = GenerateRandomData(chunkSize);
        DWORD written = 0;

        if (!WriteFile(hFile, buffer.data(), chunkSize, &written, nullptr)) {
            CloseHandle(hFile);
            return false;
        }
        bytesWritten += written;
    }

    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    return true;
}

bool FileWiper::SecureDeleteFile(const std::wstring& filePath) {
    return ::DeleteFileW(filePath.c_str()) != FALSE;
}

std::vector<uint8_t> FileWiper::GenerateRandomData(size_t size) {
    std::vector<uint8_t> data(size);
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        data.data(),
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!NT_SUCCESS(status)) {
        // Fallback: fill with pseudo-random as last resort
        for (size_t i = 0; i < size; i++) {
            data[i] = static_cast<uint8_t>(GetTickCount64() ^ (i * 2654435761ULL));
        }
    }
    return data;
}

} // namespace Guardian
