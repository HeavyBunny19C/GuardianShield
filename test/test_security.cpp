/**
 * @file test_security.cpp
 * @brief Unit tests for security utilities (SHA256File, VerifyHash)
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <cstring>

#include "../src/service/common/include/security.h"

using namespace Guardian;

class SecurityHashTest : public ::testing::Test {
protected:
    std::wstring m_testDir;

    void SetUp() override {
        m_testDir = L".\\test_security_data";
        std::filesystem::create_directories(m_testDir);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
    }

    std::wstring MakeFile(const std::wstring& name, const std::string& content) {
        std::wstring path = m_testDir + L"\\" + name;
        std::ofstream f(path, std::ios::binary);
        f << content;
        f.close();
        return path;
    }

    std::wstring MakeEmptyFile(const std::wstring& name) {
        std::wstring path = m_testDir + L"\\" + name;
        std::ofstream f(path, std::ios::binary);
        f.close();
        return path;
    }

    // Helper to convert hex string to uint8_t array
    void HexStringToBytes(const std::string& hexStr, uint8_t* bytes, size_t size) {
        for (size_t i = 0; i < size; i++) {
            std::string byteStr = hexStr.substr(i * 2, 2);
            bytes[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
        }
    }

    // Helper to compare hash arrays
    bool HashesEqual(const uint8_t* hash1, const uint8_t* hash2, size_t size) {
        return std::memcmp(hash1, hash2, size) == 0;
    }
};

// ============================================
// SHA256File Tests
// ============================================

TEST_F(SecurityHashTest, SHA256FileWithNISTTestVector_abc) {
    // NIST test vector: "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    auto path = MakeFile(L"test_abc.txt", "abc");
    
    uint8_t hash[32];
    bool result = Hash::SHA256File(path, hash);
    
    EXPECT_TRUE(result);
    
    uint8_t expectedHash[32];
    HexStringToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 
                     expectedHash, 32);
    
    EXPECT_TRUE(HashesEqual(hash, expectedHash, 32));
}

TEST_F(SecurityHashTest, SHA256FileWithEmptyFile) {
    // NIST test vector: "" (empty) -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    auto path = MakeEmptyFile(L"test_empty.txt");
    
    uint8_t hash[32];
    bool result = Hash::SHA256File(path, hash);
    
    EXPECT_TRUE(result);
    
    uint8_t expectedHash[32];
    HexStringToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 
                     expectedHash, 32);
    
    EXPECT_TRUE(HashesEqual(hash, expectedHash, 32));
}

TEST_F(SecurityHashTest, SHA256FileWithNonexistentPath) {
    // Non-existent file should return false without crashing
    std::wstring nonexistentPath = m_testDir + L"\\nonexistent_file_12345.txt";
    
    uint8_t hash[32];
    bool result = Hash::SHA256File(nonexistentPath, hash);
    
    EXPECT_FALSE(result);
}

TEST_F(SecurityHashTest, SHA256FileWithLargeFile) {
    // Test with larger content
    std::string largeContent(10000, 'A');
    auto path = MakeFile(L"test_large.bin", largeContent);
    
    uint8_t hash[32];
    bool result = Hash::SHA256File(path, hash);
    
    EXPECT_TRUE(result);
    // Just verify it returns a hash (non-zero)
    bool hasNonZero = false;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != 0) {
            hasNonZero = true;
            break;
        }
    }
    EXPECT_TRUE(hasNonZero);
}

// ============================================
// VerifyHash Tests
// ============================================

TEST_F(SecurityHashTest, VerifyHashWithCorrectHash) {
    // Create a file and verify with correct hash
    auto path = MakeFile(L"test_verify.txt", "abc");
    
    uint8_t expectedHash[32];
    HexStringToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 
                     expectedHash, 32);
    
    bool result = ProcessIntegrity::VerifyHash(path, expectedHash);
    
    EXPECT_TRUE(result);
}

TEST_F(SecurityHashTest, VerifyHashWithWrongHash) {
    // Create a file and verify with incorrect hash
    auto path = MakeFile(L"test_wrong.txt", "abc");
    
    uint8_t wrongHash[32];
    // Use a different hash (all zeros)
    std::memset(wrongHash, 0, 32);
    
    bool result = ProcessIntegrity::VerifyHash(path, wrongHash);
    
    EXPECT_FALSE(result);
}

TEST_F(SecurityHashTest, VerifyHashWithNonexistentPath) {
    // Non-existent file should return false
    std::wstring nonexistentPath = m_testDir + L"\\nonexistent_verify_12345.txt";
    
    uint8_t hash[32];
    std::memset(hash, 0, 32);
    
    bool result = ProcessIntegrity::VerifyHash(nonexistentPath, hash);
    
    EXPECT_FALSE(result);
}
