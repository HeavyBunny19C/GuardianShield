/**
 * @file environment_validator.cpp
 * @brief 环境校验实现 - IP/MAC地址验证
 * 
 * 版本: 1.0
 * 日期: 2026-03-02
 */

#include "environment_validator.h"
#include "../include/string_utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

namespace Guardian {

EnvironmentValidator::EnvironmentValidator()
    : m_validated(false)
    , m_hasList(false)
    , m_lastValidationTime(0)
{
}

EnvironmentValidator::~EnvironmentValidator() = default;

// =====================================================
// 核心方法
// =====================================================

bool EnvironmentValidator::ValidateEnvironment() {
    m_lastValidationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    if (!m_hasList || m_authorizationList.empty()) {
        m_validated = false;
        if (m_callback) {
            m_callback(false, "No authorization list - access denied (fail-safe)");
        }
        return false;
    }
    
    // Check ALL network interfaces against the authorization list
    auto interfaces = GetAllNetworkInterfaces();
    
    for (const auto& iface : interfaces) {
        if (IsAuthorized(iface.first, iface.second)) {
            m_validated = true;
            if (m_callback) {
                m_callback(true, "Authorized: IP=" + iface.first + ", MAC=" + iface.second);
            }
            return true;
        }
    }
    
    // Fallback: also try the primary IP/MAC detection
    std::string currentIP = GetCurrentIPAddress();
    std::string currentMAC = GetCurrentMACAddress();
    m_validated = IsAuthorized(currentIP, currentMAC);
    
    if (m_callback) {
        if (m_validated) {
            m_callback(true, "Authorized: IP=" + currentIP + ", MAC=" + currentMAC);
        } else {
            std::string allIfaces;
            for (const auto& iface : interfaces) {
                allIfaces += " [" + iface.first + "/" + iface.second + "]";
            }
            m_callback(false, "Validation failed. Interfaces:" + allIfaces);
        }
    }
    
    return m_validated;
}

bool EnvironmentValidator::LoadAuthorizationList(const std::wstring& listPath) {
    m_authorizationList.clear();

    bool result = ParseAuthorizationFile(listPath);
    m_hasList = result;
    // FIX-03: 不再立即删除文件，由调用方在缓存完成后统一删除
    return result;
}

void EnvironmentValidator::DeleteAuthorizationFile(const std::wstring& listPath) {
    if (!listPath.empty()) {
#ifdef _WIN32
        DeleteFileW(listPath.c_str());
#else
        std::error_code ec;
        std::filesystem::remove(std::filesystem::path(listPath), ec);
#endif
    }
}

bool EnvironmentValidator::SaveAuthorizationList(const std::wstring& listPath) {
    std::wofstream file(listPath);
    if (!file.is_open()) {
        return false;
    }
    
    file << L"# GuardianShield 授权清单\n";
    file << L"# 格式: IP地址,MAC地址,备注\n";
    
    for (const auto& entry : m_authorizationList) {
        file << Utf8ToWide(entry.ip_address) << L","
             << Utf8ToWide(entry.mac_address) << L","
             << Utf8ToWide(entry.description) << L"\n";
    }
    
    file.close();
    return true;
}

void EnvironmentValidator::SetValidationCallback(EnvironmentValidationCallback callback) {
    m_callback = std::move(callback);
}

// =====================================================
// 网络信息获取
// =====================================================

std::string EnvironmentValidator::GetCurrentIPAddress() {
#ifdef _WIN32
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "0.0.0.0";
    }
    
    char hostName[256] = {0};
    if (gethostname(hostName, sizeof(hostName)) != 0) {
        WSACleanup();
        return "0.0.0.0";
    }
    
    struct addrinfo hints, *info = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostName, nullptr, &hints, &info) != 0) {
        WSACleanup();
        return "0.0.0.0";
    }
    
    std::string ipAddress;
    for (struct addrinfo* p = info; p != nullptr; p = p->ai_next) {
        struct sockaddr_in* addr = (struct sockaddr_in*)p->ai_addr;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr->sin_addr), ipStr, INET_ADDRSTRLEN);
        
        // 跳过127.0.0.1
        if (strcmp(ipStr, "127.0.0.1") != 0) {
            ipAddress = ipStr;
            break;
        }
    }
    
    freeaddrinfo(info);
    WSACleanup();
    
    return ipAddress.empty() ? "0.0.0.0" : ipAddress;
#else
    return "0.0.0.0";
#endif
}

std::string EnvironmentValidator::GetCurrentMACAddress() {
#ifdef _WIN32
    PIP_ADAPTER_INFO adapterInfo = nullptr;
    ULONG size = 0;
    
    // 获取所需缓冲区大小
    if (GetAdaptersInfo(adapterInfo, &size) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (PIP_ADAPTER_INFO)malloc(size);
        if (adapterInfo == nullptr) {
            return "00:00:00:00:00:00";
        }
    }
    
    if (GetAdaptersInfo(adapterInfo, &size) != NO_ERROR) {
        if (adapterInfo) free(adapterInfo);
        return "00:00:00:00:00:00";
    }
    
    std::string macAddress;
    PIP_ADAPTER_INFO adapter = adapterInfo;
    
    // 找到第一个有效的、非虚拟的适配器
    while (adapter) {
        // 跳过虚拟适配器和回环
        if (adapter->Type != MIB_IF_TYPE_LOOPBACK && 
            strstr(adapter->Description, "Virtual") == nullptr &&
            strstr(adapter->Description, "VMware") == nullptr &&
            strstr(adapter->Description, "VirtualBox") == nullptr &&
            strstr(adapter->Description, "Hyper-V") == nullptr) {
            
            macAddress = FormatMACAddress(adapter->Address, adapter->AddressLength);
            break;
        }
        adapter = adapter->Next;
    }
    
    // 如果没找到物理适配器，使用第一个可用的
    if (macAddress.empty() && adapterInfo) {
        macAddress = FormatMACAddress(adapterInfo->Address, adapterInfo->AddressLength);
    }
    
    if (adapterInfo) free(adapterInfo);
    
    return macAddress.empty() ? "00:00:00:00:00:00" : macAddress;
#else
    return "00:00:00:00:00:00";
#endif
}

std::vector<std::pair<std::string, std::string>> EnvironmentValidator::GetAllNetworkInterfaces() {
    std::vector<std::pair<std::string, std::string>> interfaces;
    
#ifdef _WIN32
    PIP_ADAPTER_INFO adapterInfo = nullptr;
    ULONG size = 0;
    
    if (GetAdaptersInfo(adapterInfo, &size) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (PIP_ADAPTER_INFO)malloc(size);
        if (adapterInfo == nullptr) {
            return interfaces;
        }
    }
    
    if (GetAdaptersInfo(adapterInfo, &size) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            std::string mac = FormatMACAddress(adapter->Address, adapter->AddressLength);
            std::string ip = adapter->IpAddressList.IpAddress.String;
            
            interfaces.push_back(std::make_pair(ip, mac));
            
            adapter = adapter->Next;
        }
    }
    
    if (adapterInfo) free(adapterInfo);
#endif
    
    return interfaces;
}

// =====================================================
// 授权管理
// =====================================================

bool EnvironmentValidator::IsAuthorized(const std::string& ip, const std::string& mac) {
    for (const auto& entry : m_authorizationList) {
        // IP匹配（支持通配符 *，DHCP未完成时IP为0.0.0.0视为通配）
        bool ipMatch = false;
        if (entry.ip_address == "*" || entry.ip_address == ip || ip == "0.0.0.0") {
            ipMatch = true;
        }
        
        // MAC匹配（支持通配符 *，忽略格式差异）
        bool macMatch = false;
        if (entry.mac_address == "*") {
            macMatch = true;
        } else {
            macMatch = CompareMACAddress(entry.mac_address, mac);
        }
        
        // IP和MAC都匹配才授权
        if (ipMatch && macMatch) {
            return true;
        }
    }
    
    return false;
}

void EnvironmentValidator::AddAuthorization(const AuthorizationEntry& entry) {
    m_authorizationList.push_back(entry);
    m_hasList = true;
}

void EnvironmentValidator::RemoveAuthorization(const std::string& ip) {
    m_authorizationList.erase(
        std::remove_if(m_authorizationList.begin(), m_authorizationList.end(),
            [&ip](const AuthorizationEntry& entry) {
                return entry.ip_address == ip;
            }),
        m_authorizationList.end()
    );
}

const std::vector<AuthorizationEntry>& EnvironmentValidator::GetAuthorizations() const {
    return m_authorizationList;
}

void EnvironmentValidator::ClearAuthorizations() {
    m_authorizationList.clear();
    m_hasList = false;
}

// =====================================================
// 状态查询
// =====================================================

bool EnvironmentValidator::GetLastValidationResult() const {
    return m_validated;
}

uint64_t EnvironmentValidator::GetLastValidationTime() const {
    return m_lastValidationTime;
}

bool EnvironmentValidator::HasAuthorizationList() const {
    return m_hasList;
}

// =====================================================
// 私有方法
// =====================================================

bool EnvironmentValidator::ParseAuthorizationFile(const std::wstring& path) {
#ifdef _WIN32
    std::wifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    std::wstring line;
    while (std::getline(file, line)) {
        // 跳过空行和注释
        if (line.empty() || line[0] == L'#') {
            continue;
        }
        
        // 解析 CSV 格式: IP,MAC,备注
        std::wistringstream iss(line);
        std::wstring token;
        AuthorizationEntry entry;
        
        // IP
        if (std::getline(iss, token, L',')) {
            entry.ip_address = WideToUtf8(token);
        }
        // MAC
        if (std::getline(iss, token, L',')) {
            entry.mac_address = WideToUtf8(token);
        }
        // 备注
        if (std::getline(iss, token)) {
            entry.description = WideToUtf8(token);
        }
        
        auto trim = [](std::string& s) {
            size_t start = s.find_first_not_of(" \t\r\n");
            size_t end = s.find_last_not_of(" \t\r\n");
            if (start != std::string::npos) {
                s = s.substr(start, end - start + 1);
            }
        };
        
        trim(entry.ip_address);
        trim(entry.mac_address);
        trim(entry.description);
        
        if (!entry.ip_address.empty()) {
            m_authorizationList.push_back(entry);
        }
    }
    
    file.close();
    return true;
#else
    return false;
#endif
}

std::string EnvironmentValidator::FormatMACAddress(const uint8_t* mac, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') 
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

bool EnvironmentValidator::CompareMACAddress(const std::string& mac1, const std::string& mac2) {
    // 移除所有分隔符，转大写
    auto normalize = [](std::string mac) {
        std::string result;
        for (char c : mac) {
            if (std::isxdigit(c)) {
                result += std::toupper(c);
            }
        }
        return result;
    };
    
    return normalize(mac1) == normalize(mac2);
}

} // namespace Guardian
