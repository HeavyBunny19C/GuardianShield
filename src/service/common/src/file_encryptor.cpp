/**
 * @file file_encryptor.cpp
 * @brief File encryption using Windows CNG (BCrypt) — dual-mode AES-256
 *
 * Small files (≤100MB):  AES-256-GCM   [GSENCR01 8B][SALT 16B][IV 12B][TAG 16B][Encrypted Data]
 * Large files (>100MB):  AES-256-CBC + HMAC-SHA256 (stream)  [GSENCR02 8B][SALT 16B][IV 16B][HMAC 32B][Encrypted Data]
 * Key derivation: PBKDF2-SHA256 (100000 iterations) → 32-byte AES key
 */

#include "../include/file_encryptor.h"
#include "../include/string_utils.h"

#include <fstream>
#include <algorithm>
#include <iostream>

#ifdef _WIN32
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#endif

namespace Guardian {

const char FileEncryptor::ENCRYPTION_MAGIC[8] = { 'G','S','E','N','C','R','0','1' };
const char FileEncryptor::STREAM_MAGIC[8]     = { 'G','S','E','N','C','R','0','2' };

static constexpr size_t AES_BLOCK_SIZE = 16;

FileEncryptor::FileEncryptor() {
}

FileEncryptor::~FileEncryptor() {
}

#ifdef _WIN32

bool FileEncryptor::InitializeCrypto() {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status >= 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return true;
    }
    return false;
}

bool FileEncryptor::GenerateRandomBytes(std::vector<uint8_t>& buffer, size_t size) {
    buffer.resize(size);
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer.data(),
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return NT_SUCCESS(status);
}

bool FileEncryptor::DeriveKey(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    std::vector<uint8_t>& key)
{
    BCRYPT_ALG_HANDLE hPrf = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hPrf, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return false;

    key.resize(KEY_SIZE);
    status = BCryptDeriveKeyPBKDF2(
        hPrf,
        (PUCHAR)password.data(), (ULONG)password.size(),
        (PUCHAR)salt.data(), (ULONG)salt.size(),
        ITERATIONS,
        key.data(), (ULONG)key.size(), 0);
    BCryptCloseAlgorithmProvider(hPrf, 0);
    return NT_SUCCESS(status);
}

bool FileEncryptor::EncryptData(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& iv,
    std::vector<uint8_t>& tag)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool success = false;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    DWORD keyObjLen = 0;
    DWORD cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjLen, sizeof(keyObjLen), &cbData, 0);

    std::vector<uint8_t> keyObj(keyObjLen);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    if (!GenerateRandomBytes(iv, IV_SIZE)) goto cleanup;

    {
        tag.resize(TAG_SIZE);
        ciphertext.resize(plaintext.size());

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = iv.data();
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag = tag.data();
        authInfo.cbTag = static_cast<ULONG>(tag.size());

        DWORD cipherLen = 0;
        status = BCryptEncrypt(hKey,
            (PUCHAR)plaintext.data(), static_cast<ULONG>(plaintext.size()),
            &authInfo,
            nullptr, 0,
            ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cipherLen,
            0);
        if (!NT_SUCCESS(status)) goto cleanup;

        ciphertext.resize(cipherLen);
        success = true;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

bool FileEncryptor::DecryptData(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    std::vector<uint8_t>& plaintext)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool success = false;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    DWORD keyObjLen = 0;
    DWORD cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjLen, sizeof(keyObjLen), &cbData, 0);

    std::vector<uint8_t> keyObj(keyObjLen);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = (PUCHAR)iv.data();
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag = (PUCHAR)tag.data();
        authInfo.cbTag = static_cast<ULONG>(tag.size());

        plaintext.resize(ciphertext.size());
        DWORD plainLen = 0;
        status = BCryptDecrypt(hKey,
            (PUCHAR)ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
            &authInfo,
            nullptr, 0,
            plaintext.data(), static_cast<ULONG>(plaintext.size()), &plainLen,
            0);
        if (!NT_SUCCESS(status)) goto cleanup;

        plaintext.resize(plainLen);
        success = true;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return success;
}

EncryptResult FileEncryptor::StreamEncryptFile(const std::wstring& filePath, const std::string& password, bool deleteSource) {
    EncryptResult result;
    result.success = false;
    result.file_path = filePath;
    result.original_size = 0;
    result.encrypted_size = 0;

    HANDLE hIn = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) {
        result.error_message = "Failed to open source file";
        return result;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hIn, &liSize)) {
        CloseHandle(hIn);
        result.error_message = "Failed to get file size";
        return result;
    }
    result.original_size = static_cast<size_t>(liSize.QuadPart);

    std::vector<uint8_t> salt, key;
    if (!GenerateRandomBytes(salt, SALT_SIZE)) {
        CloseHandle(hIn);
        result.error_message = "Failed to generate salt";
        return result;
    }
    if (!DeriveKey(password, salt, key)) {
        CloseHandle(hIn);
        result.error_message = "Failed to derive key";
        return result;
    }

    std::vector<uint8_t> iv;
    if (!GenerateRandomBytes(iv, CBC_IV_SIZE)) {
        CloseHandle(hIn);
        result.error_message = "Failed to generate IV";
        return result;
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    BCRYPT_HASH_HANDLE hHmac = nullptr;
    BCRYPT_ALG_HANDLE hHmacAlg = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) { CloseHandle(hIn); result.error_message = "AES provider failed"; return result; }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hIn); result.error_message = "CBC mode failed"; return result; }

    DWORD keyObjLen = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjLen, sizeof(keyObjLen), &cbData, 0);
    std::vector<uint8_t> keyObj(keyObjLen);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hIn); result.error_message = "Key gen failed"; return result; }

    status = BCryptOpenAlgorithmProvider(&hHmacAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hIn); result.error_message = "HMAC provider failed"; return result; }

    DWORD hmacObjLen = 0;
    BCryptGetProperty(hHmacAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hmacObjLen, sizeof(hmacObjLen), &cbData, 0);
    std::vector<uint8_t> hmacObj(hmacObjLen);
    status = BCryptCreateHash(hHmacAlg, &hHmac, hmacObj.data(), hmacObjLen,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptCloseAlgorithmProvider(hHmacAlg, 0); CloseHandle(hIn);
        result.error_message = "HMAC create failed"; return result;
    }

    std::wstring encPath = filePath + L".gs";
    std::wstring tmpPath = encPath + L".tmp";
    HANDLE hOut = CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        BCryptDestroyHash(hHmac); BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0); BCryptCloseAlgorithmProvider(hHmacAlg, 0);
        CloseHandle(hIn); result.error_message = "Failed to create output file"; return result;
    }

    auto writeAll = [&](const void* data, DWORD len) -> bool {
        DWORD written;
        return WriteFile(hOut, data, len, &written, nullptr) && written == len;
    };

    bool ok = true;
    uint64_t origSize = static_cast<uint64_t>(result.original_size);
    ok = ok && writeAll(STREAM_MAGIC, sizeof(STREAM_MAGIC));
    ok = ok && writeAll(salt.data(), static_cast<DWORD>(salt.size()));
    ok = ok && writeAll(iv.data(), static_cast<DWORD>(iv.size()));
    ok = ok && writeAll(&origSize, sizeof(origSize));

    BCryptHashData(hHmac, (PUCHAR)salt.data(), static_cast<ULONG>(salt.size()), 0);
    BCryptHashData(hHmac, iv.data(), static_cast<ULONG>(iv.size()), 0);
    BCryptHashData(hHmac, (PUCHAR)&origSize, sizeof(origSize), 0);

    std::vector<uint8_t> cbcIv(iv);
    std::vector<uint8_t> inBuf(STREAM_CHUNK_SIZE);
    std::vector<uint8_t> outBuf(STREAM_CHUNK_SIZE + AES_BLOCK_SIZE);
    size_t totalWritten = sizeof(STREAM_MAGIC) + salt.size() + iv.size() + sizeof(origSize);
    uint64_t remaining = origSize;

    while (ok && remaining > 0) {
        DWORD toRead = static_cast<DWORD>((std::min)(static_cast<uint64_t>(STREAM_CHUNK_SIZE), remaining));
        DWORD bytesRead = 0;
        if (!ReadFile(hIn, inBuf.data(), toRead, &bytesRead, nullptr) || bytesRead == 0) {
            ok = false; break;
        }
        remaining -= bytesRead;
        bool isFinal = (remaining == 0);
        DWORD encLen = 0;
        std::vector<uint8_t> ivCopy(cbcIv);
        status = BCryptEncrypt(hKey, inBuf.data(), bytesRead,
            nullptr, ivCopy.data(), static_cast<ULONG>(ivCopy.size()),
            outBuf.data(), static_cast<ULONG>(outBuf.size()), &encLen,
            isFinal ? BCRYPT_BLOCK_PADDING : 0);
        if (!NT_SUCCESS(status)) { ok = false; break; }

        if (encLen >= AES_BLOCK_SIZE) {
            cbcIv.assign(outBuf.data() + encLen - AES_BLOCK_SIZE, outBuf.data() + encLen);
        }

        BCryptHashData(hHmac, outBuf.data(), encLen, 0);
        ok = ok && writeAll(outBuf.data(), encLen);
        totalWritten += encLen;
    }

    std::vector<uint8_t> hmacTag(HMAC_SIZE);
    if (ok) {
        BCryptFinishHash(hHmac, hmacTag.data(), static_cast<ULONG>(hmacTag.size()), 0);
        ok = ok && writeAll(hmacTag.data(), static_cast<DWORD>(hmacTag.size()));
        totalWritten += hmacTag.size();
    }

    SecureZeroMemory(key.data(), key.size());
    BCryptDestroyHash(hHmac);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    BCryptCloseAlgorithmProvider(hHmacAlg, 0);
    CloseHandle(hIn);
    CloseHandle(hOut);

    if (!ok) {
        DeleteFileW(tmpPath.c_str());
        result.error_message = "Stream encryption failed";
        return result;
    }

    if (!MoveFileExW(tmpPath.c_str(), encPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(tmpPath.c_str());
        result.error_message = "Failed to finalize encrypted file (rename)";
        return result;
    }

    result.encrypted_size = totalWritten;

    if (deleteSource) {
        if (!DeleteFileW(filePath.c_str())) {
            result.error_message = "Encrypted but failed to delete original";
            result.success = false;
            return result;
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_filesMutex);
        m_encryptedFiles.push_back(encPath);
    }
    result.success = true;
    return result;
}

EncryptResult FileEncryptor::StreamDecryptFile(const std::wstring& filePath, const std::string& password, bool deleteSource) {
    EncryptResult result;
    result.success = false;
    result.file_path = filePath;
    result.original_size = 0;
    result.encrypted_size = 0;

    HANDLE hIn = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hIn == INVALID_HANDLE_VALUE) {
        result.error_message = "Failed to open encrypted file";
        return result;
    }

    LARGE_INTEGER liSize;
    GetFileSizeEx(hIn, &liSize);
    result.encrypted_size = static_cast<size_t>(liSize.QuadPart);

    auto readAll = [&](void* buf, DWORD len) -> bool {
        DWORD rd;
        return ReadFile(hIn, buf, len, &rd, nullptr) && rd == len;
    };

    char magic[8];
    if (!readAll(magic, sizeof(magic)) || memcmp(magic, STREAM_MAGIC, sizeof(STREAM_MAGIC)) != 0) {
        CloseHandle(hIn);
        result.error_message = "Invalid stream magic";
        return result;
    }

    std::vector<uint8_t> salt(SALT_SIZE), iv(CBC_IV_SIZE);
    uint64_t origSize = 0;
    if (!readAll(salt.data(), static_cast<DWORD>(SALT_SIZE)) ||
        !readAll(iv.data(), static_cast<DWORD>(CBC_IV_SIZE)) ||
        !readAll(&origSize, sizeof(origSize))) {
        CloseHandle(hIn);
        result.error_message = "Failed to read header";
        return result;
    }
    result.original_size = static_cast<size_t>(origSize);

    size_t headerSize = sizeof(STREAM_MAGIC) + SALT_SIZE + CBC_IV_SIZE + sizeof(origSize);
    size_t ciphertextSize = result.encrypted_size - headerSize - HMAC_SIZE;

    std::vector<uint8_t> key;
    if (!DeriveKey(password, salt, key)) {
        CloseHandle(hIn);
        result.error_message = "Failed to derive key";
        return result;
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr, hHmacAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    BCRYPT_HASH_HANDLE hHmac = nullptr;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    DWORD keyObjLen = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&keyObjLen, sizeof(keyObjLen), &cbData, 0);
    std::vector<uint8_t> keyObj(keyObjLen);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);

    BCryptOpenAlgorithmProvider(&hHmacAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    DWORD hmacObjLen = 0;
    BCryptGetProperty(hHmacAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hmacObjLen, sizeof(hmacObjLen), &cbData, 0);
    std::vector<uint8_t> hmacObj(hmacObjLen);
    BCryptCreateHash(hHmacAlg, &hHmac, hmacObj.data(), hmacObjLen,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);

    BCryptHashData(hHmac, salt.data(), static_cast<ULONG>(SALT_SIZE), 0);
    BCryptHashData(hHmac, iv.data(), static_cast<ULONG>(CBC_IV_SIZE), 0);
    BCryptHashData(hHmac, (PUCHAR)&origSize, sizeof(origSize), 0);

    std::wstring outPath = filePath.substr(0, filePath.length() - 3);
    HANDLE hOut = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        BCryptDestroyHash(hHmac); BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0); BCryptCloseAlgorithmProvider(hHmacAlg, 0);
        CloseHandle(hIn);
        result.error_message = "Failed to create output file";
        return result;
    }

    std::vector<uint8_t> cbcIv(iv);
    std::vector<uint8_t> inBuf(STREAM_CHUNK_SIZE + AES_BLOCK_SIZE);
    std::vector<uint8_t> outBuf(STREAM_CHUNK_SIZE + AES_BLOCK_SIZE);
    bool ok = true;
    uint64_t cipherRemaining = ciphertextSize;

    while (ok && cipherRemaining > 0) {
        DWORD toRead = static_cast<DWORD>((std::min)(static_cast<uint64_t>(STREAM_CHUNK_SIZE + AES_BLOCK_SIZE), cipherRemaining));
        DWORD bytesRead = 0;
        if (!ReadFile(hIn, inBuf.data(), toRead, &bytesRead, nullptr) || bytesRead == 0) {
            ok = false; break;
        }
        cipherRemaining -= bytesRead;

        BCryptHashData(hHmac, inBuf.data(), bytesRead, 0);

        bool isFinal = (cipherRemaining == 0);
        DWORD decLen = 0;
        std::vector<uint8_t> ivCopy(cbcIv);
        NTSTATUS st = BCryptDecrypt(hKey, inBuf.data(), bytesRead,
            nullptr, ivCopy.data(), static_cast<ULONG>(ivCopy.size()),
            outBuf.data(), static_cast<ULONG>(outBuf.size()), &decLen,
            isFinal ? BCRYPT_BLOCK_PADDING : 0);
        if (!NT_SUCCESS(st)) { ok = false; break; }

        if (bytesRead >= AES_BLOCK_SIZE) {
            cbcIv.assign(inBuf.data() + bytesRead - AES_BLOCK_SIZE, inBuf.data() + bytesRead);
        }

        DWORD written;
        if (!WriteFile(hOut, outBuf.data(), decLen, &written, nullptr) || written != decLen) {
            ok = false; break;
        }
    }

    std::vector<uint8_t> computedHmac(HMAC_SIZE);
    BCryptFinishHash(hHmac, computedHmac.data(), static_cast<ULONG>(HMAC_SIZE), 0);

    std::vector<uint8_t> storedHmac(HMAC_SIZE);
    DWORD rd;
    if (!ReadFile(hIn, storedHmac.data(), static_cast<DWORD>(HMAC_SIZE), &rd, nullptr) || rd != HMAC_SIZE) {
        ok = false;
    }
    if (ok && memcmp(computedHmac.data(), storedHmac.data(), HMAC_SIZE) != 0) {
        ok = false;
        result.error_message = "HMAC verification failed — data corrupted";
    }

    SecureZeroMemory(key.data(), key.size());
    BCryptDestroyHash(hHmac);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    BCryptCloseAlgorithmProvider(hHmacAlg, 0);
    CloseHandle(hIn);
    CloseHandle(hOut);

    if (!ok) {
        DeleteFileW(outPath.c_str());
        if (result.error_message.empty()) result.error_message = "Stream decryption failed";
        return result;
    }

    if (deleteSource) {
        if (!DeleteFileW(filePath.c_str())) {
            result.error_message = "Decrypted but failed to delete source .gs file";
            result.success = false;
            return result;
        }
    }

    result.success = true;
    return result;
}

#endif // _WIN32

EncryptResult FileEncryptor::EncryptFile(const std::wstring& filePath, const std::string& password, bool deleteSource) {
    EncryptResult result;
    result.success = false;
    result.file_path = filePath;
    result.original_size = 0;
    result.encrypted_size = 0;

#ifdef _WIN32
    // Check file size to decide GCM (small) vs CBC stream (large)
    std::ifstream inFile(filePath, std::ios::binary | std::ios::ate);
    if (!inFile) {
        result.error_message = "Failed to open source file";
        return result;
    }
    auto fileSize = inFile.tellg();
    inFile.close();
    if (static_cast<uint64_t>(fileSize) > STREAM_THRESHOLD) {
        return StreamEncryptFile(filePath, password, deleteSource);
    }

    inFile.open(filePath, std::ios::binary | std::ios::ate);
    if (!inFile) {
        result.error_message = "Failed to open source file";
        return result;
    }

    fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    result.original_size = static_cast<size_t>(fileSize);

    std::vector<uint8_t> plaintext(static_cast<size_t>(fileSize));
    if (fileSize > 0) {
        inFile.read(reinterpret_cast<char*>(plaintext.data()), fileSize);
    }
    inFile.close();

    // Generate salt and derive key
    std::vector<uint8_t> salt;
    if (!GenerateRandomBytes(salt, SALT_SIZE)) {
        result.error_message = "Failed to generate salt";
        return result;
    }

    std::vector<uint8_t> key;
    if (!DeriveKey(password, salt, key)) {
        result.error_message = "Failed to derive encryption key";
        return result;
    }

    // Encrypt
    std::vector<uint8_t> ciphertext, iv, tag;
    if (!EncryptData(plaintext, key, ciphertext, iv, tag)) {
        result.error_message = "Encryption failed";
        return result;
    }

    // Atomic write: write to .gs.tmp first, then rename to .gs
    std::wstring encPath = filePath + L".gs";
    std::wstring tmpPath = encPath + L".tmp";
    std::ofstream outFile(tmpPath, std::ios::binary);
    if (!outFile) {
        result.error_message = "Failed to create encrypted file";
        return result;
    }

    outFile.write(ENCRYPTION_MAGIC, sizeof(ENCRYPTION_MAGIC));
    outFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    outFile.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    outFile.close();

    if (!outFile.good()) {
        result.error_message = "Failed to write encrypted file";
        DeleteFileW(tmpPath.c_str());
        return result;
    }

    if (!MoveFileExW(tmpPath.c_str(), encPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        result.error_message = "Failed to finalize encrypted file (rename)";
        DeleteFileW(tmpPath.c_str());
        return result;
    }

    result.encrypted_size = sizeof(ENCRYPTION_MAGIC) + salt.size() + iv.size() + tag.size() + ciphertext.size();

    if (deleteSource) {
        if (!DeleteFileW(filePath.c_str())) {
            result.error_message = "Encrypted but failed to delete original";
            result.success = false;
            SecureZeroMemory(key.data(), key.size());
            SecureZeroMemory(plaintext.data(), plaintext.size());
            return result;
        }
    }

    // Clear sensitive data
    SecureZeroMemory(key.data(), key.size());
    SecureZeroMemory(plaintext.data(), plaintext.size());

    {
        std::lock_guard<std::mutex> lock(m_filesMutex);
        m_encryptedFiles.push_back(encPath);
    }
    result.success = true;
#else
    result.error_message = "Encryption not supported on this platform";
#endif

    return result;
}

EncryptResult FileEncryptor::DecryptFile(const std::wstring& filePath, const std::string& password, bool deleteSource) {
    EncryptResult result;
    result.success = false;
    result.file_path = filePath;
    result.original_size = 0;
    result.encrypted_size = 0;

#ifdef _WIN32
    std::ifstream inFile(filePath, std::ios::binary | std::ios::ate);
    if (!inFile) {
        result.error_message = "Failed to open encrypted file";
        return result;
    }

    auto fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    result.encrypted_size = static_cast<size_t>(fileSize);

    const size_t headerSize = sizeof(ENCRYPTION_MAGIC) + SALT_SIZE + IV_SIZE + TAG_SIZE;
    if (static_cast<size_t>(fileSize) < headerSize) {
        result.error_message = "File too small to be encrypted";
        return result;
    }

    char magic[8];
    inFile.read(magic, sizeof(magic));
    if (memcmp(magic, STREAM_MAGIC, sizeof(STREAM_MAGIC)) == 0) {
        inFile.close();
        return StreamDecryptFile(filePath, password, deleteSource);
    }
    if (memcmp(magic, ENCRYPTION_MAGIC, sizeof(ENCRYPTION_MAGIC)) != 0) {
        result.error_message = "Invalid encryption magic — not a GuardianShield encrypted file";
        return result;
    }

    // Read salt, IV, and auth tag
    std::vector<uint8_t> salt(SALT_SIZE);
    inFile.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);

    std::vector<uint8_t> iv(IV_SIZE);
    inFile.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);

    std::vector<uint8_t> tag(TAG_SIZE);
    inFile.read(reinterpret_cast<char*>(tag.data()), TAG_SIZE);

    // Read ciphertext
    size_t cipherLen = static_cast<size_t>(fileSize) - headerSize;
    std::vector<uint8_t> ciphertext(cipherLen);
    if (cipherLen > 0) {
        inFile.read(reinterpret_cast<char*>(ciphertext.data()), cipherLen);
    }
    inFile.close();

    // Derive key
    std::vector<uint8_t> key;
    if (!DeriveKey(password, salt, key)) {
        result.error_message = "Failed to derive decryption key";
        return result;
    }

    // Decrypt
    std::vector<uint8_t> plaintext;
    if (!DecryptData(ciphertext, key, iv, tag, plaintext)) {
        result.error_message = "Decryption failed — wrong password or corrupted file";
        SecureZeroMemory(key.data(), key.size());
        return result;
    }

    result.original_size = plaintext.size();

    // Determine output path: strip .gs extension
    std::wstring outPath = filePath;
    if (outPath.size() > 3 && outPath.substr(outPath.size() - 3) == L".gs") {
        outPath = outPath.substr(0, outPath.size() - 3);
    } else {
        outPath += L".dec";
    }

    std::ofstream outFile(outPath, std::ios::binary);
    if (!outFile) {
        result.error_message = "Failed to create decrypted file";
        SecureZeroMemory(key.data(), key.size());
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return result;
    }

    if (!plaintext.empty()) {
        outFile.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    }
    outFile.close();

    if (!outFile.good()) {
        result.error_message = "Failed to write decrypted file";
        DeleteFileW(outPath.c_str());
        SecureZeroMemory(key.data(), key.size());
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return result;
    }

    if (deleteSource) {
        if (!DeleteFileW(filePath.c_str())) {
            result.error_message = "Decrypted but failed to delete source .gs file";
            result.success = false;
            SecureZeroMemory(key.data(), key.size());
            SecureZeroMemory(plaintext.data(), plaintext.size());
            return result;
        }
    }

    SecureZeroMemory(key.data(), key.size());
    SecureZeroMemory(plaintext.data(), plaintext.size());

    result.file_path = outPath;
    result.success = true;
#else
    result.error_message = "Decryption not supported on this platform";
#endif

    return result;
}

size_t FileEncryptor::EncryptDirectory(
    const std::wstring& dirPath,
    const std::string& password,
    bool recursive,
    EncryptProgressCallback callback,
    bool deleteSource,
    CancelCallback cancelCheck)
{
    size_t encryptedCount = 0;

#ifdef _WIN32
    std::vector<std::wstring> files;

    std::function<void(const std::wstring&)> collectFiles = [&](const std::wstring& dir) {
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
                continue;

            std::wstring fullPath = dir + L"\\" + findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (recursive) {
                    collectFiles(fullPath);
                }
            } else {
                size_t len = wcslen(findData.cFileName);
                if (len > 3) {
                    std::wstring ext(findData.cFileName + len - 3);
                    if (ext == L".gs") continue;
                }
                files.push_back(fullPath);
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    };

    collectFiles(dirPath);

    for (size_t i = 0; i < files.size(); ++i) {
        if (cancelCheck && cancelCheck()) break;

        if (callback) {
            callback(i + 1, files.size(), files[i]);
        }

        EncryptResult result = EncryptFile(files[i], password, deleteSource);
        if (result.success) {
            encryptedCount++;
        } else {
            std::string errPath = WideToUtf8(files[i]);
            std::cerr << "[EncryptDirectory] FAILED: " << errPath
                      << " - " << result.error_message << std::endl;
        }
    }

    if (encryptedCount < files.size()) {
        std::cerr << "[EncryptDirectory] " << encryptedCount << "/" << files.size()
                  << " files encrypted successfully" << std::endl;
    }
#endif

    return encryptedCount;
}

size_t FileEncryptor::DecryptDirectory(
    const std::wstring& dirPath,
    const std::string& password,
    bool recursive,
    EncryptProgressCallback callback,
    bool deleteSource)
{
    size_t decryptedCount = 0;

#ifdef _WIN32
    if (GetFileAttributesW(dirPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        return 0;

    std::vector<std::wstring> gsFiles;

    std::function<void(const std::wstring&)> collectFiles = [&](const std::wstring& dir) {
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
                continue;

            std::wstring fullPath = dir + L"\\" + findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (recursive) {
                    collectFiles(fullPath);
                }
            } else {
                size_t len = wcslen(findData.cFileName);
                if (len > 3) {
                    std::wstring ext(findData.cFileName + len - 3);
                    if (ext == L".gs") {
                        gsFiles.push_back(fullPath);
                    }
                }
            }
        } while (FindNextFileW(hFind, &findData));

        FindClose(hFind);
    };

    collectFiles(dirPath);

    for (size_t i = 0; i < gsFiles.size(); ++i) {
        if (callback) {
            callback(i + 1, gsFiles.size(), gsFiles[i]);
        }

        std::wstring originalPath = gsFiles[i].substr(0, gsFiles[i].size() - 3);
        if (GetFileAttributesW(originalPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            continue;
        }

        EncryptResult result = DecryptFile(gsFiles[i], password, deleteSource);
        if (result.success) {
            decryptedCount++;
        }
    }
#endif

    return decryptedCount;
}

bool FileEncryptor::IsEncrypted(const std::wstring& filePath) const {
#ifdef _WIN32
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return false;

    char magic[8];
    inFile.read(magic, sizeof(magic));
    if (inFile.gcount() != sizeof(magic)) return false;

    return memcmp(magic, ENCRYPTION_MAGIC, sizeof(ENCRYPTION_MAGIC)) == 0
        || memcmp(magic, STREAM_MAGIC, sizeof(STREAM_MAGIC)) == 0;
#else
    return false;
#endif
}

size_t FileEncryptor::GetEncryptedFileCount() const {
    std::lock_guard<std::mutex> lock(m_filesMutex);
    return m_encryptedFiles.size();
}

const std::vector<std::wstring>& FileEncryptor::GetEncryptedFiles() const {
    std::lock_guard<std::mutex> lock(m_filesMutex);
    return m_encryptedFiles;
}

} // namespace Guardian
