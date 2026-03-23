/**
 * @file test_file_encryptor.cpp
 * @brief Unit tests for FileEncryptor module (AES-256-CBC via Windows CNG)
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include <atomic>

#include "../src/service/common/include/file_encryptor.h"

using namespace Guardian;

class FileEncryptorTest : public ::testing::Test {
protected:
    std::wstring m_testDir;
    FileEncryptor m_encryptor;
    std::string m_password = "TestPassword@2026!";

    void SetUp() override {
        m_testDir = L".\\test_encryptor_data";
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

    std::string ReadFile(const std::wstring& path) {
        std::ifstream f(path, std::ios::binary);
        return std::string(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());
    }
};

TEST_F(FileEncryptorTest, InitialState) {
    EXPECT_EQ(m_encryptor.GetEncryptedFileCount(), 0u);
    EXPECT_TRUE(m_encryptor.GetEncryptedFiles().empty());
}

TEST_F(FileEncryptorTest, EncryptSingleFile) {
    auto path = MakeFile(L"enc1.txt", "Hello World");

    EncryptResult result = m_encryptor.EncryptFile(path, m_password);
    EXPECT_TRUE(result.success);
    EXPECT_GT(result.encrypted_size, 0u);
    EXPECT_EQ(result.original_size, 11u);

    std::wstring encPath = path + L".gs";
    EXPECT_TRUE(std::filesystem::exists(encPath));
}

TEST_F(FileEncryptorTest, DecryptSingleFile) {
    auto path = MakeFile(L"dec1.txt", "Decrypt me please");

    m_encryptor.EncryptFile(path, m_password);
    std::wstring encPath = path + L".gs";

    EncryptResult result = m_encryptor.DecryptFile(encPath, m_password);
    EXPECT_TRUE(result.success);

    auto content = ReadFile(path);
    EXPECT_EQ(content, "Decrypt me please");
}

TEST_F(FileEncryptorTest, RoundTripPreservesContent) {
    std::string original = "This is a test of the encryption system.\n"
                           "It should preserve all data perfectly.\n"
                           "Including special chars: \t\r\n\x01\xff";
    auto path = MakeFile(L"roundtrip.bin", original);

    m_encryptor.EncryptFile(path, m_password);
    m_encryptor.DecryptFile(path + L".gs", m_password);

    auto restored = ReadFile(path);
    EXPECT_EQ(restored, original);
}

TEST_F(FileEncryptorTest, WrongPasswordFails) {
    auto path = MakeFile(L"wrongpw.txt", "Secret data");

    m_encryptor.EncryptFile(path, m_password);
    std::wstring encPath = path + L".gs";

    EncryptResult result = m_encryptor.DecryptFile(encPath, "wrong_password");
    EXPECT_FALSE(result.success);
}

TEST_F(FileEncryptorTest, IsEncryptedDetectsMagic) {
    auto path = MakeFile(L"magic.txt", "normal file");
    EXPECT_FALSE(m_encryptor.IsEncrypted(path));

    m_encryptor.EncryptFile(path, m_password);
    EXPECT_TRUE(m_encryptor.IsEncrypted(path + L".gs"));
}

TEST_F(FileEncryptorTest, IsEncryptedNonExistentFile) {
    EXPECT_FALSE(m_encryptor.IsEncrypted(L"C:\\__nonexistent__.gs"));
}

TEST_F(FileEncryptorTest, EncryptEmptyFile) {
    auto path = MakeFile(L"empty.txt", "");

    EncryptResult result = m_encryptor.EncryptFile(path, m_password);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.original_size, 0u);
}

TEST_F(FileEncryptorTest, EncryptLargeFile) {
    std::string large(1024 * 100, 'A');
    auto path = MakeFile(L"large.bin", large);

    EncryptResult encResult = m_encryptor.EncryptFile(path, m_password);
    EXPECT_TRUE(encResult.success);

    EncryptResult decResult = m_encryptor.DecryptFile(path + L".gs", m_password);
    EXPECT_TRUE(decResult.success);

    auto restored = ReadFile(path);
    EXPECT_EQ(restored.size(), large.size());
    EXPECT_EQ(restored, large);
}

TEST_F(FileEncryptorTest, EncryptNonExistentFile) {
    EncryptResult result = m_encryptor.EncryptFile(
        L"C:\\__absolutely_nonexistent_file__.txt", m_password);
    EXPECT_FALSE(result.success);
}

TEST_F(FileEncryptorTest, EncryptDirectory) {
    MakeFile(L"dir_enc1.txt", "file 1");
    MakeFile(L"dir_enc2.txt", "file 2");
    MakeFile(L"dir_enc3.txt", "file 3");

    size_t count = m_encryptor.EncryptDirectory(m_testDir, m_password, false);
    EXPECT_GE(count, 3u);
}

TEST_F(FileEncryptorTest, EncryptedFileFormatHeader) {
    auto path = MakeFile(L"format.txt", "check header");

    m_encryptor.EncryptFile(path, m_password);
    std::wstring encPath = path + L".gs";

    std::ifstream f(encPath, std::ios::binary);
    char magic[8];
    f.read(magic, 8);

    EXPECT_EQ(std::string(magic, 8), "GSENCR01");
}

TEST_F(FileEncryptorTest, DifferentPasswordsDifferentCiphertext) {
    auto path1 = MakeFile(L"diffpw1.txt", "same content");
    auto path2 = MakeFile(L"diffpw2.txt", "same content");

    m_encryptor.EncryptFile(path1, "password_A");
    m_encryptor.EncryptFile(path2, "password_B");

    auto enc1 = ReadFile(path1 + L".gs");
    auto enc2 = ReadFile(path2 + L".gs");

    /* Different passwords and random salt/IV should produce different ciphertext */
    EXPECT_NE(enc1, enc2);
}

TEST_F(FileEncryptorTest, EncryptedFileCount) {
    MakeFile(L"cnt1.txt", "a");
    MakeFile(L"cnt2.txt", "b");

    m_encryptor.EncryptFile(m_testDir + L"\\cnt1.txt", m_password);
    EXPECT_EQ(m_encryptor.GetEncryptedFileCount(), 1u);

    m_encryptor.EncryptFile(m_testDir + L"\\cnt2.txt", m_password);
    EXPECT_EQ(m_encryptor.GetEncryptedFileCount(), 2u);
}

// ========== P0 Fix Tests: deleteSource parameter ==========

TEST_F(FileEncryptorTest, EncryptFile_KeepOriginal) {
    auto path = MakeFile(L"keep_orig.txt", "keep me alive");
    EncryptResult result = m_encryptor.EncryptFile(path, m_password, false);
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_TRUE(std::filesystem::exists(path + L".gs"));
    auto content = ReadFile(path);
    EXPECT_EQ(content, "keep me alive");
}

TEST_F(FileEncryptorTest, EncryptFile_DeleteOriginal_Default) {
    auto path = MakeFile(L"del_default.txt", "delete me");
    m_encryptor.EncryptFile(path, m_password);
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_TRUE(std::filesystem::exists(path + L".gs"));
}

TEST_F(FileEncryptorTest, DecryptFile_KeepEncrypted) {
    auto path = MakeFile(L"keep_enc.txt", "preserve gs");
    m_encryptor.EncryptFile(path, m_password);
    auto encPath = path + L".gs";

    EncryptResult result = m_encryptor.DecryptFile(encPath, m_password, false);
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(std::filesystem::exists(encPath));
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_EQ(ReadFile(path), "preserve gs");
}

TEST_F(FileEncryptorTest, DecryptFile_DeleteEncrypted_Default) {
    auto path = MakeFile(L"del_enc.txt", "remove gs");
    m_encryptor.EncryptFile(path, m_password);
    auto encPath = path + L".gs";

    m_encryptor.DecryptFile(encPath, m_password);
    EXPECT_FALSE(std::filesystem::exists(encPath));
    EXPECT_TRUE(std::filesystem::exists(path));
}

TEST_F(FileEncryptorTest, EncryptDirectory_KeepOriginals) {
    MakeFile(L"dir_keep1.txt", "file 1");
    MakeFile(L"dir_keep2.txt", "file 2");

    size_t count = m_encryptor.EncryptDirectory(m_testDir, m_password, false, nullptr, false);
    EXPECT_EQ(count, 2u);

    EXPECT_TRUE(std::filesystem::exists(m_testDir + L"\\dir_keep1.txt"));
    EXPECT_TRUE(std::filesystem::exists(m_testDir + L"\\dir_keep1.txt.gs"));
    EXPECT_TRUE(std::filesystem::exists(m_testDir + L"\\dir_keep2.txt"));
    EXPECT_TRUE(std::filesystem::exists(m_testDir + L"\\dir_keep2.txt.gs"));
}

TEST_F(FileEncryptorTest, DecryptDirectory_SkipsWhenOriginalExists) {
    auto path = MakeFile(L"skip_exists.txt", "original content");
    m_encryptor.EncryptFile(path, m_password, false);

    size_t count = m_encryptor.DecryptDirectory(m_testDir, m_password, false);
    EXPECT_EQ(count, 0u);
    EXPECT_TRUE(std::filesystem::exists(path + L".gs"));
    EXPECT_EQ(ReadFile(path), "original content");
}

// ========== P0 Fix Test: Tier-2 Pipeline Simulation ==========

TEST_F(FileEncryptorTest, Tier2Pipeline_EncryptKeepThenWipeOriginals) {
    MakeFile(L"secret1.doc", "classified");
    MakeFile(L"secret2.doc", "top secret");

    size_t enc = m_encryptor.EncryptDirectory(m_testDir, m_password, false, nullptr, false);
    EXPECT_EQ(enc, 2u);

    size_t totalFiles = 0;
    size_t gsFiles = 0;
    for (auto& entry : std::filesystem::directory_iterator(m_testDir)) {
        totalFiles++;
        if (entry.path().extension() == ".gs") gsFiles++;
    }
    EXPECT_EQ(totalFiles, 4u);
    EXPECT_EQ(gsFiles, 2u);

    size_t dec = m_encryptor.DecryptDirectory(m_testDir, m_password, false);
    EXPECT_EQ(dec, 0u);

    FileEncryptor fresh;
    size_t freshDec = fresh.DecryptDirectory(m_testDir, m_password, false, nullptr, false);
    EXPECT_EQ(freshDec, 0u);

    for (auto& entry : std::filesystem::directory_iterator(m_testDir)) {
        if (entry.path().extension() != ".gs") {
            std::filesystem::remove(entry.path());
        }
    }

    size_t decAfterRemove = fresh.DecryptDirectory(m_testDir, m_password, false);
    EXPECT_EQ(decAfterRemove, 2u);
    EXPECT_EQ(ReadFile(m_testDir + L"\\secret1.doc"), "classified");
    EXPECT_EQ(ReadFile(m_testDir + L"\\secret2.doc"), "top secret");
}

TEST_F(FileEncryptorTest, ConcurrentEncryptFileListSafe) {
    constexpr int kThreads = 4;
    constexpr int kFilesPerThread = 10;

    for (int t = 0; t < kThreads; ++t) {
        for (int f = 0; f < kFilesPerThread; ++f) {
            std::wstring name = m_testDir + L"\\t" + std::to_wstring(t)
                              + L"_f" + std::to_wstring(f) + L".txt";
            std::ofstream ofs(name);
            ofs << "thread " << t << " file " << f;
        }
    }

    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t]() {
            for (int f = 0; f < kFilesPerThread; ++f) {
                std::wstring name = m_testDir + L"\\t" + std::to_wstring(t)
                                  + L"_f" + std::to_wstring(f) + L".txt";
                auto result = m_encryptor.EncryptFile(name, m_password, false);
                if (!result.success) failures++;
            }
        });
    }
    for (auto& th : threads) th.join();

    EXPECT_EQ(failures.load(), 0);
    EXPECT_EQ(m_encryptor.GetEncryptedFileCount(),
              static_cast<size_t>(kThreads * kFilesPerThread));
}