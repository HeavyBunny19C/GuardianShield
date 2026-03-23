/**
 * @file environment_validator.h
 * @brief 环境校验模块 - IP/MAC地址验证
 * 
 * 功能说明：
 * - 开机启动时校验运行环境
 * - 检查IP地址与MAC地址是否在授权清单中
 * - 未授权环境触发最高等级处置流程
 * 
 * 版本: 1.0
 * 日期: 2026-03-02
 */

#pragma once

#include <string>
#include <vector>
#include <functional>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

namespace Guardian {

/**
 * @brief 授权条目
 */
struct AuthorizationEntry {
    std::string ip_address;     // IP地址
    std::string mac_address;    // MAC地址 (格式: AA:BB:CC:DD:EE:FF)
    std::string description;    // 备注
};

/**
 * @brief 环境校验回调
 * @param authorized 是否授权
 * @param message 消息
 */
using EnvironmentValidationCallback = std::function<void(bool authorized, const std::string& message)>;

/**
 * @brief 环境校验器
 * 
 * 负责验证当前运行环境是否被授权：
 * 1. 获取本机IP地址和MAC地址
 * 2. 加载授权清单
 * 3. 比对是否在清单中
 * 4. 未授权则触发最高等级处置
 */
class EnvironmentValidator {
public:
    EnvironmentValidator();
    ~EnvironmentValidator();
    
    // =====================================================
    // 核心方法
    // =====================================================
    
    /**
     * @brief 校验当前环境
     * @return true=已授权, false=未授权
     */
    bool ValidateEnvironment();
    
    /**
     * @brief 加载授权清单
     * @param listPath 清单文件路径
     * @return true=加载成功
     */
    bool LoadAuthorizationList(const std::wstring& listPath);
    void DeleteAuthorizationFile(const std::wstring& listPath);

    /**
     * @brief 保存授权清单
     * @param listPath 清单文件路径
     * @return true=保存成功
     */
    bool SaveAuthorizationList(const std::wstring& listPath);
    
    /**
     * @brief 设置校验回调
     */
    void SetValidationCallback(EnvironmentValidationCallback callback);
    
    // =====================================================
    // 网络信息获取
    // =====================================================
    
    /**
     * @brief 获取本机主要IP地址
     * @return IP地址字符串
     */
    std::string GetCurrentIPAddress();
    
    /**
     * @brief 获取本机主要MAC地址
     * @return MAC地址字符串 (格式: AA:BB:CC:DD:EE:FF)
     */
    std::string GetCurrentMACAddress();
    
    /**
     * @brief 获取所有网络接口信息
     */
    std::vector<std::pair<std::string, std::string>> GetAllNetworkInterfaces();
    
    // =====================================================
    // 授权管理
    // =====================================================
    
    /**
     * @brief 检查是否授权
     * @param ip IP地址
     * @param mac MAC地址
     * @return true=已授权
     */
    bool IsAuthorized(const std::string& ip, const std::string& mac);
    
    /**
     * @brief 添加授权条目
     */
    void AddAuthorization(const AuthorizationEntry& entry);
    
    /**
     * @brief 删除授权条目
     */
    void RemoveAuthorization(const std::string& ip);
    
    /**
     * @brief 获取所有授权条目
     */
    const std::vector<AuthorizationEntry>& GetAuthorizations() const;
    
    /**
     * @brief 清空授权清单
     */
    void ClearAuthorizations();
    
    // =====================================================
    // 状态查询
    // =====================================================
    
    /**
     * @brief 获取上次校验结果
     */
    bool GetLastValidationResult() const;
    
    /**
     * @brief 获取上次校验时间
     */
    uint64_t GetLastValidationTime() const;
    
    /**
     * @brief 是否已加载授权清单
     */
    bool HasAuthorizationList() const;

private:
    /**
     * @brief 解析授权清单文件
     */
    bool ParseAuthorizationFile(const std::wstring& path);
    
    /**
     * @brief 格式化MAC地址
     */
    std::string FormatMACAddress(const uint8_t* mac, size_t len);
    
    /**
     * @brief MAC地址比较（忽略大小写和分隔符）
     */
    bool CompareMACAddress(const std::string& mac1, const std::string& mac2);
    
    // 授权清单
    std::vector<AuthorizationEntry> m_authorizationList;
    
    // 状态
    bool m_validated;
    bool m_hasList;
    uint64_t m_lastValidationTime;
    
    // 回调
    EnvironmentValidationCallback m_callback;
};

} // namespace Guardian
