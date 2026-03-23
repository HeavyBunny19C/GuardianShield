/**
 * @file string_utils.h
 * @brief Safe Unicode string conversion utilities
 */

#pragma once

#include <string>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace Guardian {

inline std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), 
                                    static_cast<int>(str.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), 
                         static_cast<int>(str.size()), &result[0], size);
    return result;
}

inline std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), 
                                    static_cast<int>(wstr.size()), 
                                    nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), 
                         static_cast<int>(wstr.size()), 
                         &result[0], size, nullptr, nullptr);
    return result;
}

} // namespace Guardian
