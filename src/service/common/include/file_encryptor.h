/**
 * @file file_encryptor.h
 * @brief 文件加密模块
 * 
 * 功能说明：
 * - 使用 AES-256-GCM 加密文件
 * - 密码由管理员设置
 * - 支持批量加密目录
 * 
 * 版本: 1.0
 * 日期: 2026-03-02
 */

#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <functional>

#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#undef EncryptFile
#undef DecryptFile
#endif

namespace Guardian {

/**
 * @brief 加密进度回调
 * @param current 当前处理的文件索引
 * @param total 总文件数
 * @param filePath 当前文件路径
 */
using EncryptProgressCallback = std::function<void(size_t current, size_t total, const std::wstring& filePath)>;
using CancelCallback = std::function<bool()>;

/**
 * @brief 加密结果
 */
struct EncryptResult {
    bool success;              // 是否成功
    std::wstring file_path;    // 文件路径
    std::string error_message; // 错误信息
    size_t original_size;      // 原始大小
    size_t encrypted_size;     // 加密后大小
};

/**
 * @brief 文件加密器
 * 
 * 使用 Windows CNG (Cryptography Next Generation) API
 * 实现 AES-256-GCM 加密算法
 */
class FileEncryptor {
public:
    FileEncryptor();
    ~FileEncryptor();
    
    // =====================================================
    // 加密/解密操作
    // =====================================================
    
    /**
     * @brief 加密单个文件
     * @param filePath 文件路径
     * @param password 加密密码
     * @return 加密结果
     */
    EncryptResult EncryptFile(const std::wstring& filePath, const std::string& password,
                              bool deleteSource = true);
    
    /**
     * @brief 解密单个文件
     * @param filePath 文件路径
     * @param password 解密密码
     * @param deleteSource 解密后是否删除 .gs 源文件
     * @return 加密结果
     */
    EncryptResult DecryptFile(const std::wstring& filePath, const std::string& password,
                              bool deleteSource = true);
    
    /**
     * @brief 加密目录下所有文件
     * @param dirPath 目录路径
     * @param password 加密密码
     * @param recursive 是否递归子目录
     * @param callback 进度回调
     * @param deleteSource 加密后是否删除原文件
     * @return 成功加密的文件数
     */
    size_t EncryptDirectory(
        const std::wstring& dirPath, 
        const std::string& password,
        bool recursive = true,
        EncryptProgressCallback callback = nullptr,
        bool deleteSource = true,
        CancelCallback cancelCheck = nullptr
    );

    /**
     * @brief 解密目录下所有 .gs 文件
     * @param dirPath 目录路径
     * @param password 解密密码 (admin password hash)
     * @param recursive 是否递归子目录
     * @param callback 进度回调
     * @param deleteSource 解密后是否删除 .gs 源文件
     * @return 成功解密的文件数
     */
    size_t DecryptDirectory(
        const std::wstring& dirPath,
        const std::string& password,
        bool recursive = true,
        EncryptProgressCallback callback = nullptr,
        bool deleteSource = true
    );

    /**
     * @brief 检查文件是否已加密
     * @param filePath 文件路径
     * @return true=已加密
     */
    bool IsEncrypted(const std::wstring& filePath) const;
    
    // =====================================================
    // 统计信息
    // =====================================================
    
    /**
     * @brief 获取已加密文件数
     */
    size_t GetEncryptedFileCount() const;
    
    /**
     * @brief 获取加密文件列表
     */
    const std::vector<std::wstring>& GetEncryptedFiles() const;

private:
    // =====================================================
    // 加密算法实现
    // =====================================================
    
#ifdef _WIN32
    /**
     * @brief 初始化加密算法
     */
    bool InitializeCrypto();
    
    /**
     * @brief 生成随机盐值
     */
    bool GenerateRandomBytes(std::vector<uint8_t>& buffer, size_t size);
    
    /**
     * @brief 派生密钥 (PBKDF2)
     */
    bool DeriveKey(
        const std::string& password,
        const std::vector<uint8_t>& salt,
        std::vector<uint8_t>& key
    );
    
    /**
     * @brief AES-GCM 加密数据
     */
    bool EncryptData(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& iv,
        std::vector<uint8_t>& tag
    );
    
    /**
     * @brief AES-GCM 解密数据
     */
    bool DecryptData(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& tag,
        std::vector<uint8_t>& plaintext
    );
#endif
    
    // 加密文件列表 (guarded by m_filesMutex)
    mutable std::mutex m_filesMutex;
    std::vector<std::wstring> m_encryptedFiles;
    
    // 常量
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t IV_SIZE = 12;         // GCM nonce
    static constexpr size_t TAG_SIZE = 16;        // GCM auth tag
    static constexpr size_t KEY_SIZE = 32;        // AES-256
    static constexpr size_t ITERATIONS = 100000;
    static constexpr size_t CBC_IV_SIZE = 16;     // AES block size for CBC
    static constexpr size_t HMAC_SIZE = 32;       // SHA-256 output
    static constexpr size_t STREAM_THRESHOLD = 100ULL * 1024 * 1024;  // 100 MB
    static constexpr size_t STREAM_CHUNK_SIZE = 1ULL * 1024 * 1024;   // 1 MB

    static const char ENCRYPTION_MAGIC[8];        // "GSENCR01" for GCM
    static const char STREAM_MAGIC[8];            // "GSENCR02" for CBC stream

#ifdef _WIN32
    EncryptResult StreamEncryptFile(const std::wstring& filePath, const std::string& password, bool deleteSource);
    EncryptResult StreamDecryptFile(const std::wstring& filePath, const std::string& password, bool deleteSource);
#endif
};

} // namespace Guardian
