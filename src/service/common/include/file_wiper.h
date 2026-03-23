/**
 * @file file_wiper.h
 * @brief 文件安全擦除模块
 * 
 * 功能说明：
 * - 使用 DOD_5220 标准进行安全擦除（7次覆写）
 * - 文件内容被覆盖且不能复原
 * 
 * 版本: 1.0
 * 日期: 2026-03-02
 */

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace Guardian {

/**
 * @brief 擦除进度回调
 * @param current 当前遍次
 * @param total 总遍次
 * @param bytesProcessed 已处理字节数
 */
using WipeProgressCallback = std::function<void(size_t current, size_t total, size_t bytesProcessed)>;

/**
 * @brief 擦除结果
 */
struct WipeResult {
    bool success;              // 是否成功
    std::wstring file_path;    // 文件路径
    std::string error_message; // 错误信息
    size_t original_size;      // 原始大小
    size_t passes_completed;   // 完成的遍次
};

/**
 * @brief 文件安全擦除器
 * 
 * DOD_5220 标准实现（7次覆写）：
 * 1. 写入 0x00
 * 2. 写入 0xFF
 * 3. 写入随机数据
 * 4. 写入 0x00
 * 5. 写入 0xFF
 * 6. 写入随机数据
 * 7. 写入 0x00 并删除
 */
class FileWiper {
public:
    FileWiper();
    ~FileWiper();
    
    // =====================================================
    // 擦除操作
    // =====================================================
    
    /**
     * @brief 安全擦除文件
     * @param filePath 文件路径
     * @param callback 进度回调
     * @return 擦除结果
     */
    WipeResult WipeFile(const std::wstring& filePath, WipeProgressCallback callback = nullptr);
    
    /**
     * @brief 擦除并删除文件
     * @param filePath 文件路径
     * @param callback 进度回调
     * @return 擦除结果
     */
    WipeResult WipeAndDelete(const std::wstring& filePath, WipeProgressCallback callback = nullptr);
    
    /**
     * @brief 擦除目录下所有文件
     * @param dirPath 目录路径
     * @param recursive 是否递归子目录
     * @param callback 进度回调
     * @param skipExtension 跳过指定扩展名的文件 (如 L".gs")
     * @return 成功擦除的文件数
     */
    size_t WipeDirectory(
        const std::wstring& dirPath,
        bool recursive = true,
        WipeProgressCallback callback = nullptr,
        const std::wstring& skipExtension = L""
    );
    
    // =====================================================
    // 配置
    // =====================================================
    
    /**
     * @brief 设置擦除遍次
     * @param passes 遍次数（默认7次）
     */
    void SetPasses(size_t passes) { m_passes = passes; }
    
    /**
     * @brief 获取擦除遍次
     */
    size_t GetPasses() const { return m_passes; }
    
    // =====================================================
    // 统计信息
    // =====================================================
    
    /**
     * @brief 获取已擦除文件数
     */
    size_t GetWipedFileCount() const { return m_wipedCount; }
    
    /**
     * @brief 获取已擦除总字节数
     */
    uint64_t GetWipedBytes() const { return m_wipedBytes; }

private:
    /**
     * @brief 单次覆写
     * @param filePath 文件路径
     * @param pattern 覆写模式
     * @return 是否成功
     */
    bool OverwriteFile(const std::wstring& filePath, uint8_t pattern);
    
    /**
     * @brief 随机覆写
     */
    bool OverwriteRandom(const std::wstring& filePath);
    
    /**
     * @brief 删除文件
     */
    bool SecureDeleteFile(const std::wstring& filePath);
    
    /**
     * @brief 生成随机数据
     */
    std::vector<uint8_t> GenerateRandomData(size_t size);
    
    // 配置
    size_t m_passes = 7;  // DOD_5220 标准
    
    // 统计
    size_t m_wipedCount = 0;
    uint64_t m_wipedBytes = 0;
};

} // namespace Guardian
