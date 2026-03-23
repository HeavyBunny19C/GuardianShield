/**
 * @file test_file_wiper.cpp
 * @brief Unit tests for FileWiper module (DOD 5220.22-M secure wipe)
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>

#include "../src/service/common/include/file_wiper.h"

using namespace Guardian;

class FileWiperTest : public ::testing::Test {
protected:
    std::wstring m_testDir;
    FileWiper m_wiper;

    void SetUp() override {
        m_testDir = L".\\test_wiper_data";
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

    std::wstring MakeFile(const std::wstring& name, size_t size) {
        std::wstring path = m_testDir + L"\\" + name;
        std::ofstream f(path, std::ios::binary);
        std::string data(size, 'X');
        f << data;
        f.close();
        return path;
    }
};

TEST_F(FileWiperTest, InitialState) {
    EXPECT_EQ(m_wiper.GetWipedFileCount(), 0u);
    EXPECT_EQ(m_wiper.GetWipedBytes(), 0u);
    EXPECT_EQ(m_wiper.GetPasses(), 7u);
}

TEST_F(FileWiperTest, WipeSingleFile) {
    auto path = MakeFile(L"wipe1.txt", "Sensitive data");

    WipeResult result = m_wiper.WipeFile(path);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.passes_completed, 7u);
    EXPECT_GT(result.original_size, 0u);
}

TEST_F(FileWiperTest, WipeAndDeleteFile) {
    auto path = MakeFile(L"wipedel.txt", "Delete after wipe");
    EXPECT_TRUE(std::filesystem::exists(path));

    WipeResult result = m_wiper.WipeAndDelete(path);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST_F(FileWiperTest, WipeNonExistentFile) {
    WipeResult result = m_wiper.WipeFile(L"C:\\__nonexistent_wipe_file__.txt");
    EXPECT_FALSE(result.success);
}

TEST_F(FileWiperTest, WipeEmptyFile) {
    auto path = MakeFile(L"empty_wipe.txt", "");

    WipeResult result = m_wiper.WipeAndDelete(path);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST_F(FileWiperTest, WipeLargeFile) {
    auto path = MakeFile(L"large_wipe.bin", (size_t)(64 * 1024));

    WipeResult result = m_wiper.WipeFile(path);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.original_size, 64u * 1024u);
}

TEST_F(FileWiperTest, WipeDirectory) {
    MakeFile(L"dirwipe1.txt", "file 1");
    MakeFile(L"dirwipe2.txt", "file 2");
    MakeFile(L"dirwipe3.txt", "file 3");

    size_t count = m_wiper.WipeDirectory(m_testDir, false);
    EXPECT_GE(count, 3u);
}

TEST_F(FileWiperTest, WipeDirectoryRecursive) {
    std::filesystem::create_directories(m_testDir + L"\\subdir");
    MakeFile(L"root.txt", "root file");

    std::wstring subPath = m_testDir + L"\\subdir\\sub.txt";
    std::ofstream sf(subPath);
    sf << "sub file";
    sf.close();

    size_t count = m_wiper.WipeDirectory(m_testDir, true);
    EXPECT_GE(count, 2u);
}

TEST_F(FileWiperTest, SetPasses) {
    m_wiper.SetPasses(3);
    EXPECT_EQ(m_wiper.GetPasses(), 3u);

    auto path = MakeFile(L"passes.txt", "quick wipe");
    WipeResult result = m_wiper.WipeFile(path);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.passes_completed, 3u);
}

TEST_F(FileWiperTest, WipedCountIncrementsAfterDelete) {
    auto p1 = MakeFile(L"stat1.txt", "a");
    auto p2 = MakeFile(L"stat2.txt", "b");

    m_wiper.WipeAndDelete(p1);
    EXPECT_EQ(m_wiper.GetWipedFileCount(), 1u);

    m_wiper.WipeAndDelete(p2);
    EXPECT_EQ(m_wiper.GetWipedFileCount(), 2u);
}

TEST_F(FileWiperTest, WipedBytesAccumulates) {
    auto path = MakeFile(L"bytes.txt", std::string(1000, 'Z'));
    m_wiper.WipeAndDelete(path);
    EXPECT_GE(m_wiper.GetWipedBytes(), 1000u);
}

TEST_F(FileWiperTest, ProgressCallback) {
    auto path = MakeFile(L"progress.txt", "callback test");
    int callbackCount = 0;

    WipeResult result = m_wiper.WipeFile(path,
        [&callbackCount](size_t current, size_t total, size_t bytes) {
            callbackCount++;
            EXPECT_LE(current, total);
            (void)bytes;
        });

    EXPECT_TRUE(result.success);
    EXPECT_GT(callbackCount, 0);
}

TEST_F(FileWiperTest, ContentOverwrittenAfterWipe) {
    std::string sentinel = "UNIQUE_SENTINEL_STRING_12345";
    auto path = MakeFile(L"overwrite.txt", sentinel);

    m_wiper.WipeFile(path);

    /* After wipe, file content should NOT contain the original sentinel */
    std::ifstream f(path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    EXPECT_TRUE(content.find(sentinel) == std::string::npos);
}

// ========== P0 Fix Tests: skipExtension parameter ==========

TEST_F(FileWiperTest, WipeDirectory_SkipsGsExtension) {
    MakeFile(L"plain.txt", "wipe me");
    MakeFile(L"plain2.doc", "wipe me too");

    std::wstring gsPath = m_testDir + L"\\encrypted.doc.gs";
    std::ofstream gsFile(gsPath, std::ios::binary);
    gsFile << "precious encrypted data";
    gsFile.close();

    size_t count = m_wiper.WipeDirectory(m_testDir, false, nullptr, L".gs");
    EXPECT_EQ(count, 2u);

    EXPECT_FALSE(std::filesystem::exists(m_testDir + L"\\plain.txt"));
    EXPECT_FALSE(std::filesystem::exists(m_testDir + L"\\plain2.doc"));
    EXPECT_TRUE(std::filesystem::exists(gsPath));

    std::ifstream check(gsPath, std::ios::binary);
    std::string preserved((std::istreambuf_iterator<char>(check)),
                           std::istreambuf_iterator<char>());
    EXPECT_EQ(preserved, "precious encrypted data");
}

TEST_F(FileWiperTest, WipeDirectory_NoFilter_WipesEverything) {
    MakeFile(L"all1.txt", "gone");
    MakeFile(L"all2.gs", "also gone");

    size_t count = m_wiper.WipeDirectory(m_testDir, false);
    EXPECT_EQ(count, 2u);
    EXPECT_FALSE(std::filesystem::exists(m_testDir + L"\\all1.txt"));
    EXPECT_FALSE(std::filesystem::exists(m_testDir + L"\\all2.gs"));
}

TEST_F(FileWiperTest, WipeDirectory_SkipRecursive) {
    std::filesystem::create_directories(m_testDir + L"\\sub");
    MakeFile(L"root.txt", "wipe");

    std::wstring subGs = m_testDir + L"\\sub\\backup.gs";
    std::ofstream sf(subGs, std::ios::binary);
    sf << "sub backup";
    sf.close();

    std::wstring subTxt = m_testDir + L"\\sub\\data.txt";
    std::ofstream df(subTxt, std::ios::binary);
    df << "sub data";
    df.close();

    size_t count = m_wiper.WipeDirectory(m_testDir, true, nullptr, L".gs");
    EXPECT_EQ(count, 2u);
    EXPECT_FALSE(std::filesystem::exists(m_testDir + L"\\root.txt"));
    EXPECT_FALSE(std::filesystem::exists(subTxt));
    EXPECT_TRUE(std::filesystem::exists(subGs));
}