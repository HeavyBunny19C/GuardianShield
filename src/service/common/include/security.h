/**
 * @file security.h
 * @brief Security utilities for GuardianShield
 * 
 * Provides anti-debugging, anti-injection, and secure memory utilities.
 */

#pragma once

#include <vector>
#include <cstdint>
#include <string>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace Guardian {

// ============================================
// Anti-Debug Utilities
// ============================================

/**
 * @brief Anti-debugging detection utilities
 * 
 * Provides multiple methods to detect if the process is being debugged
 * or if there are injection attempts.
 */
class AntiDebug {
public:
    /**
     * @brief Check if debugger is present using multiple methods
     * @return true if debugger detected
     */
    static bool IsDebuggerPresent();
    
    /**
     * @brief Check for debugger via PEB
     * @return true if debugger detected
     */
    static bool CheckPEBDebugPort();
    
    /**
     * @brief Check for NtGlobalFlag modification
     * @return true if debugger detected
     */
    static bool CheckNtGlobalFlag();
    
    /**
     * @brief Check for hardware breakpoints
     * @return true if hardware breakpoints detected
     */
    static bool CheckHardwareBreakpoints();
    
    /**
     * @brief Check for timing anomalies (debugger slowdown)
     * @return true if timing anomaly detected
     */
    static bool CheckTimingAnomaly();
    
    /**
     * @brief Check if process has remote thread (injection)
     * @return true if remote thread detected
     */
    static bool HasRemoteThread();
    
    /**
     * @brief Check for unknown/foreign modules
     * @return true if suspicious module detected
     */
    static bool HasUnknownModule();
    
    /**
     * @brief Check for memory modification
     * @return true if memory modification detected
     */
    static bool HasMemoryModification();
    
    /**
     * @brief Check if process is being injected
     * @return true if injection detected
     */
    static bool IsInjected();
    
    /**
     * @brief Run all security checks
     * @return true if any security threat detected
     */
    static bool RunAllChecks();

private:
#ifdef _WIN64
    static void* GetPEB();
#else
    static void* GetPEB();
#endif
};

// ============================================
// Secure Buffer
// ============================================

/**
 * @brief Secure memory buffer that wipes on destruction
 * 
 * Automatically zeroizes memory when destroyed.
 * Useful for storing sensitive data like encryption keys.
 * 
 * @tparam T Element type
 * @tparam N Buffer size in elements
 */
template<typename T, size_t N>
class SecureBuffer {
public:
    SecureBuffer() {
        ZeroMemory(m_data, sizeof(m_data));
    }
    
    ~SecureBuffer() {
        Clear();
    }
    
    // Non-copyable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Movable
    SecureBuffer(SecureBuffer&& other) noexcept {
        memcpy(m_data, other.m_data, sizeof(m_data));
        other.Clear();
    }
    
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            memcpy(m_data, other.m_data, sizeof(m_data));
            other.Clear();
        }
        return *this;
    }
    
    /**
     * @brief Get pointer to data
     */
    T* Data() { return m_data; }
    const T* Data() const { return m_data; }
    
    /**
     * @brief Get buffer size in elements
     */
    constexpr size_t Size() const { return N; }
    
    /**
     * @brief Get buffer size in bytes
     */
    constexpr size_t SizeBytes() const { return sizeof(m_data); }
    
    /**
     * @brief Access element
     */
    T& operator[](size_t index) { return m_data[index]; }
    const T& operator[](size_t index) const { return m_data[index]; }
    
    /**
     * @brief Clear buffer securely
     */
    void Clear() {
        SecureZeroMemory(m_data, sizeof(m_data));
    }
    
    /**
     * @brief Fill buffer with random data
     */
    void Randomize() {
#ifdef _WIN32
        BCryptGenRandom(NULL, reinterpret_cast<PUCHAR>(m_data), 
                        sizeof(m_data), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#endif
    }

private:
    T m_data[N];
};

// ============================================
// Hash Utilities
// ============================================

/**
 * @brief Cryptographic hash utilities
 */
class Hash {
public:
    /**
     * @brief Compute SHA-256 hash
     * @param data Input data
     * @param size Data size
     * @param hash Output hash (32 bytes)
     * @return true if successful
     */
    static bool SHA256(const void* data, size_t size, uint8_t hash[32]);
    
    /**
     * @brief Compute SHA-256 hash of file
     * @param filePath File path
     * @param hash Output hash (32 bytes)
     * @return true if successful
     */
    static bool SHA256File(const std::wstring& filePath, uint8_t hash[32]);
    
    /**
     * @brief Compute HMAC-SHA256
     * @param key HMAC key
     * @param keySize Key size
     * @param data Input data
     * @param dataSize Data size
     * @param hmac Output HMAC (32 bytes)
     * @return true if successful
     */
    static bool HMAC_SHA256(
        const void* key, size_t keySize,
        const void* data, size_t dataSize,
        uint8_t hmac[32]
    );
    
    /**
     * @brief Convert hash to hex string
     */
    static std::string ToHexString(const uint8_t* hash, size_t size);
};

// ============================================
// Process Integrity
// ============================================

/**
 * @brief Process integrity utilities
 */
class ProcessIntegrity {
public:
    /**
     * @brief Verify process integrity by checking hash
     * @param processPath Path to process executable
     * @param expectedHash Expected SHA-256 hash
     * @return true if integrity verified
     */
    static bool VerifyHash(const std::wstring& processPath, const uint8_t expectedHash[32]);
    
    /**
     * @brief Check if process is running with elevated privileges
     */
    static bool IsElevated();
    
    /**
     * @brief Get process integrity level
     */
    static std::wstring GetIntegrityLevel();
    
    /**
     * @brief Check if process is running under specific account
     */
    static bool IsRunningAsUser(const std::wstring& username);
};

} // namespace Guardian
