#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

static const uint32_t MESSAGE_MAGIC = 0x47554152;
static const size_t MESSAGE_HEADER_SIZE = 32;
static const size_t CHECKSUM_SIZE = 12;
static const uint8_t IPC_HMAC_KEY[] = "GuardianShield_IPC_v2";
static const size_t IPC_HMAC_KEY_LEN = sizeof(IPC_HMAC_KEY) - 1;

#pragma pack(push, 1)
struct MessageHeader {
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
    uint8_t  source;
    uint8_t  dest;
    uint32_t sequence;
    uint32_t timestamp;
    uint32_t payload_len;
    uint8_t  checksum[12];
};

struct DecryptRequestPayload {
    char password_hash[65];
};
#pragma pack(pop)

static_assert(sizeof(MessageHeader) == 32, "Header must be 32 bytes");

bool HMAC_SHA256(const uint8_t* key, size_t keyLen,
                 const uint8_t* data, size_t dataLen,
                 uint8_t* out32) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbHash = 0, cbResult = 0;
    
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return false;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbResult, 0);
    
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, (PUCHAR)key, (ULONG)keyLen, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0);
    BCryptFinishHash(hHash, out32, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

void CalculateChecksum(MessageHeader& hdr, const void* payload, uint8_t* out12) {
    MessageHeader copy = hdr;
    memset(copy.checksum, 0, CHECKSUM_SIZE);
    
    size_t totalLen = MESSAGE_HEADER_SIZE + hdr.payload_len;
    std::vector<uint8_t> buf(totalLen);
    memcpy(buf.data(), &copy, MESSAGE_HEADER_SIZE);
    if (payload && hdr.payload_len > 0)
        memcpy(buf.data() + MESSAGE_HEADER_SIZE, payload, hdr.payload_len);
    
    uint8_t full[32] = {};
    HMAC_SHA256(IPC_HMAC_KEY, IPC_HMAC_KEY_LEN, buf.data(), totalLen, full);
    memcpy(out12, full, CHECKSUM_SIZE);
}

int main(int argc, char* argv[]) {
    const char* pipeName = "\\\\.\\pipe\\GuardianIPC_A";
    const char* passwordHash = "9fa5a1127819b0ec6ab6bfdacbc62ffe2a9cd3d1faf7f2db7df7fcc369e5d3df";
    uint8_t msgType = 0xFC; // DECRYPT_REQUEST
    
    if (argc > 1) passwordHash = argv[1];
    if (argc > 2) {
        if (strcmp(argv[2], "unlock") == 0) msgType = 0x60; // UNLOCK_FILES_REQUEST
    }
    
    printf("Connecting to %s...\n", pipeName);
    printf("Message type: 0x%02X (%s)\n", msgType,
           msgType == 0xFC ? "DECRYPT_REQUEST" : "UNLOCK_FILES_REQUEST");
    
    HANDLE hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("ERROR: Cannot connect to pipe (err=%lu)\n", GetLastError());
        return 1;
    }
    
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);
    
    DecryptRequestPayload payload = {};
    strncpy_s(payload.password_hash, passwordHash, 64);
    
    MessageHeader hdr = {};
    hdr.magic = MESSAGE_MAGIC;
    hdr.version = 1;
    hdr.type = msgType;
    hdr.source = 2; // GUARDIAN_C
    hdr.dest = 0;   // GUARDIAN_A
    hdr.sequence = 1;
    hdr.timestamp = (uint32_t)(GetTickCount64() & 0xFFFFFFFF);
    hdr.payload_len = sizeof(DecryptRequestPayload);
    
    CalculateChecksum(hdr, &payload, hdr.checksum);
    
    uint8_t message[sizeof(MessageHeader) + sizeof(DecryptRequestPayload)];
    memcpy(message, &hdr, sizeof(MessageHeader));
    memcpy(message + sizeof(MessageHeader), &payload, sizeof(DecryptRequestPayload));
    
    DWORD written = 0;
    if (!WriteFile(hPipe, message, sizeof(message), &written, nullptr)) {
        printf("ERROR: WriteFile failed (err=%lu)\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    
    printf("Sent %lu bytes. Message delivered.\n", written);
    
    printf("Header: magic=%08X ver=%d type=0x%02X src=%d dst=%d seq=%u ts=%u plen=%u\n",
           hdr.magic, hdr.version, hdr.type, hdr.source, hdr.dest,
           hdr.sequence, hdr.timestamp, hdr.payload_len);
    printf("Checksum: ");
    for (int i = 0; i < 12; i++) printf("%02X", hdr.checksum[i]);
    printf("\n");
    
    Sleep(2000);
    FlushFileBuffers(hPipe);
    CloseHandle(hPipe);
    printf("Done.\n");
    return 0;
}
