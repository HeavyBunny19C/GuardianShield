/**
 * @file ipc.cpp
 * @brief Implementation of inter-process communication
 */

#include "ipc.h"
#include "logger.h"
#include "security.h"
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sddl.h>
#include <aclapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

namespace Guardian {

// Forward declarations
bool CalculateChecksum(const MessageHeader& header, const void* payload, uint8_t* checksumOut);
bool VerifyChecksum(const MessageHeader& header, const void* payload);

// ============================================
// Message Serialization
// ============================================

std::vector<uint8_t> SerializeMessage(const MessageHeader& header, 
                                       const void* payload, 
                                       size_t payloadSize) {
    MessageHeader hdr = header;
    memset(hdr.checksum, 0, CHECKSUM_SIZE);
    if (!CalculateChecksum(hdr, payload, hdr.checksum)) {
        return {};
    }
    
    std::vector<uint8_t> buffer(MESSAGE_HEADER_SIZE + payloadSize);
    memcpy(buffer.data(), &hdr, MESSAGE_HEADER_SIZE);
    
    if (payload && payloadSize > 0) {
        memcpy(buffer.data() + MESSAGE_HEADER_SIZE, payload, payloadSize);
    }
    
    return buffer;
}

bool DeserializeMessage(const uint8_t* data, size_t size,
                        MessageHeader& header,
                        std::vector<uint8_t>& payload) {
    if (size < MESSAGE_HEADER_SIZE) {
        return false;
    }
    
    // Copy header
    memcpy(&header, data, MESSAGE_HEADER_SIZE);
    
    // Validate magic number
    if (header.magic != MESSAGE_MAGIC) {
        return false;
    }
    
    // Validate version
    if (header.version != PROTOCOL_VERSION) {
        return false;
    }
    
    // Extract payload
    if (header.payload_len > 0 && size >= MESSAGE_HEADER_SIZE + header.payload_len) {
        payload.resize(header.payload_len);
        memcpy(payload.data(), data + MESSAGE_HEADER_SIZE, header.payload_len);
    }
    
    // Verify HMAC checksum
    const void* payloadPtr = payload.empty() ? nullptr : payload.data();
    if (!VerifyChecksum(header, payloadPtr)) {
        return false;
    }
    
    return true;
}

static bool GetMachineKey(std::vector<uint8_t>& keyOut) {
#ifdef _WIN32
    static const wchar_t* kSalt = L"GuardianShield-IPC-Key-v3";

    auto deriveFromSid = [](std::wstring& identityOut) -> bool {
        wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD nameLen = MAX_COMPUTERNAME_LENGTH + 1;
        if (!GetComputerNameW(computerName, &nameLen)) {
            return false;
        }

        std::wstring machineAccount(computerName, nameLen);
        machineAccount.push_back(L'$');

        DWORD sidSize = 0;
        DWORD domainSize = 0;
        SID_NAME_USE sidUse = SidTypeUnknown;
        LookupAccountNameW(nullptr, machineAccount.c_str(), nullptr, &sidSize, nullptr, &domainSize, &sidUse);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sidSize == 0) {
            return false;
        }

        std::vector<uint8_t> sidBuffer(sidSize);
        std::vector<wchar_t> domainBuffer(domainSize > 0 ? domainSize : 1);
        if (!LookupAccountNameW(
                nullptr,
                machineAccount.c_str(),
                sidBuffer.data(),
                &sidSize,
                domainBuffer.data(),
                &domainSize,
                &sidUse)) {
            return false;
        }

        LPWSTR sidString = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuffer.data()), &sidString)) {
            return false;
        }

        identityOut.assign(sidString);
        LocalFree(sidString);
        return true;
    };

    auto deriveFromMachineGuid = [](std::wstring& identityOut) -> bool {
        wchar_t machineGuid[128] = {};
        DWORD machineGuidBytes = sizeof(machineGuid);
        LONG regStatus = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid",
            RRF_RT_REG_SZ,
            nullptr,
            machineGuid,
            &machineGuidBytes);
        if (regStatus != ERROR_SUCCESS || machineGuid[0] == L'\0') {
            return false;
        }

        identityOut.assign(machineGuid);
        return true;
    };

    static std::once_flag keyInitOnce;
    static std::vector<uint8_t> cachedKey;
    static bool keyReady = false;
    std::call_once(keyInitOnce, [&]() {
        std::wstring machineIdentity;
        if (!deriveFromSid(machineIdentity) && !deriveFromMachineGuid(machineIdentity)) {
            keyReady = false;
            return;
        }

        machineIdentity.append(L"|");
        machineIdentity.append(kSalt);

        uint8_t digest[32] = {};
        if (!Hash::SHA256(
                machineIdentity.data(),
                machineIdentity.size() * sizeof(wchar_t),
                digest)) {
            SecureZeroMemory(digest, sizeof(digest));
            keyReady = false;
            return;
        }

        cachedKey.assign(digest, digest + sizeof(digest));
        SecureZeroMemory(digest, sizeof(digest));
        keyReady = true;
    });

    if (!keyReady || cachedKey.empty()) {
        return false;
    }

    keyOut = cachedKey;
    return true;
#else
    (void)keyOut;
    return false;
#endif
}

bool CalculateChecksum(const MessageHeader& header,
                       const void* payload,
                       uint8_t* checksumOut) {
    if (checksumOut == nullptr) {
        return false;
    }
    if (header.payload_len > 0 && payload == nullptr) {
        return false;
    }

    // Build buffer: header fields (excluding checksum) + payload
    MessageHeader hdrCopy = header;
    memset(hdrCopy.checksum, 0, CHECKSUM_SIZE);

    size_t totalLen = MESSAGE_HEADER_SIZE + header.payload_len;
    std::vector<uint8_t> buf(totalLen);
    memcpy(buf.data(), &hdrCopy, MESSAGE_HEADER_SIZE);
    if (payload && header.payload_len > 0) {
        memcpy(buf.data() + MESSAGE_HEADER_SIZE, payload, header.payload_len);
    }

    std::vector<uint8_t> machineKey;
    if (!GetMachineKey(machineKey)) {
        return false;
    }

    uint8_t fullHmac[32] = {};
    if (!Hash::HMAC_SHA256(machineKey.data(), machineKey.size(), buf.data(), totalLen, fullHmac)) {
        return false;
    }

    memcpy(checksumOut, fullHmac, CHECKSUM_SIZE);
    return true;
}

bool VerifyChecksum(const MessageHeader& header, const void* payload) {
    bool allZeroChecksum = true;
    for (size_t i = 0; i < CHECKSUM_SIZE; i++) {
        if (header.checksum[i] != 0) {
            allZeroChecksum = false;
            break;
        }
    }
    if (allZeroChecksum) {
        return false;
    }

    uint8_t expected[CHECKSUM_SIZE] = {};
    if (!CalculateChecksum(header, payload, expected)) {
        return false;
    }

    // Constant-time comparison to prevent timing side-channel attacks
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < CHECKSUM_SIZE; i++) {
        diff |= expected[i] ^ header.checksum[i];
    }
    return diff == 0;
}

// ============================================
// Named Pipe Server
// ============================================

NamedPipeServer::NamedPipeServer(const std::wstring& pipeName, size_t bufferSize)
    : m_pipeName(pipeName)
    , m_bufferSize(bufferSize)
    , m_running(false)
    , m_hPipe(INVALID_HANDLE_VALUE)
{
}

NamedPipeServer::~NamedPipeServer() {
    Stop();
}

bool NamedPipeServer::Start() {
    if (m_running) return true;
    
    m_running = true;
    m_acceptThread = std::thread(&NamedPipeServer::AcceptLoop, this);
    
    return true;
}

void NamedPipeServer::Stop() {
    if (!m_running) return;
    
    m_running = false;
    
    // Close pipe to unblock accept thread
    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
    
    if (m_acceptThread.joinable()) {
        m_acceptThread.join();
    }
}

void NamedPipeServer::AcceptLoop() {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    // SY=SYSTEM, BA=Administrators, IU=Interactive Users (non-elevated GuardianC)
    BOOL sdOk = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
        SDDL_REVISION_1, &pSD, nullptr);
    if (sdOk) sa.lpSecurityDescriptor = pSD;

    int consecutiveFailures = 0;
    const int kMaxConsecutiveFailures = 50;

    while (m_running) {
        m_hPipe = CreateNamedPipeW(
            m_pipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            static_cast<DWORD>(m_bufferSize),
            static_cast<DWORD>(m_bufferSize),
            0,
            sdOk ? &sa : nullptr
        );
        
        if (m_hPipe == INVALID_HANDLE_VALUE) {
            consecutiveFailures++;
            DWORD err = GetLastError();
            if (consecutiveFailures == 1 || consecutiveFailures == 10 || consecutiveFailures == kMaxConsecutiveFailures)
                std::cerr << "[IPC] CreateNamedPipeW failed: err=" << err << " (attempt " << consecutiveFailures << ")" << std::endl;
            if (consecutiveFailures >= kMaxConsecutiveFailures) {
                std::cerr << "[IPC] CreateNamedPipeW: giving up after " << kMaxConsecutiveFailures << " failures" << std::endl;
                break;
            }
            Sleep(100);
            continue;
        }
        consecutiveFailures = 0;
        
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        
        BOOL connected = ConnectNamedPipe(m_hPipe, &overlapped);
        DWORD connectErr = GetLastError();

        if (connected || connectErr == ERROR_IO_PENDING) {
            WaitForSingleObject(overlapped.hEvent, INFINITE);
            
            if (m_running) {
                HANDLE hClientPipe = m_hPipe;
                std::thread clientThread(&NamedPipeServer::HandleClient, this, hClientPipe);
                clientThread.detach();
            }
        } else if (connectErr == ERROR_PIPE_CONNECTED) {
            // Client connected before ConnectNamedPipe was called
            if (m_running) {
                HANDLE hClientPipe = m_hPipe;
                std::thread clientThread(&NamedPipeServer::HandleClient, this, hClientPipe);
                clientThread.detach();
            }
        } else {
            CloseHandle(m_hPipe);
            m_hPipe = INVALID_HANDLE_VALUE;
        }
        
        CloseHandle(overlapped.hEvent);
    }
    if (pSD) LocalFree(pSD);
}

void NamedPipeServer::HandleClient(HANDLE hPipe) {
    std::vector<uint8_t> buffer(m_bufferSize);
    
    while (m_running) {
        DWORD bytesRead = 0;
        BOOL success = ReadFile(hPipe, buffer.data(), 
                                static_cast<DWORD>(buffer.size()), 
                                &bytesRead, nullptr);
        
        if (!success || bytesRead == 0) {
            break;
        }
        
        // Parse message
        MessageHeader header;
        std::vector<uint8_t> payload;
        
        if (DeserializeMessage(buffer.data(), bytesRead, header, payload)) {
            if (m_handler) {
                m_handler(header, payload.data(), payload.size());
            }
        }
    }
    
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

bool NamedPipeServer::SendResponse(HANDLE hClientPipe,
                                    const MessageHeader& header,
                                    const void* payload, size_t payloadSize) {
    if (hClientPipe == INVALID_HANDLE_VALUE) return false;

    auto buffer = SerializeMessage(header, payload, payloadSize);
    
    DWORD bytesWritten = 0;
    return WriteFile(hClientPipe, buffer.data(), 
                     static_cast<DWORD>(buffer.size()), 
                     &bytesWritten, nullptr) != FALSE;
}

// ============================================
// Named Pipe Client
// ============================================

NamedPipeClient::NamedPipeClient(const std::wstring& pipeName)
    : m_pipeName(pipeName)
    , m_hPipe(INVALID_HANDLE_VALUE)
    , m_connected(false)
{
}

NamedPipeClient::~NamedPipeClient() {
    Disconnect();
}

bool NamedPipeClient::Connect(uint32_t timeoutMs) {
    if (m_connected) return true;
    
    // Wait for pipe to be available
    if (!WaitNamedPipeW(m_pipeName.c_str(), timeoutMs)) {
        return false;
    }
    
    // Open pipe
    m_hPipe = CreateFileW(
        m_pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );
    
    if (m_hPipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    m_connected = true;
    return true;
}

void NamedPipeClient::Disconnect() {
    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
    m_connected = false;
}

bool NamedPipeClient::Send(const MessageHeader& header,
                            const void* payload, size_t payloadSize) {
    if (!m_connected) return false;
    
    auto buffer = SerializeMessage(header, payload, payloadSize);
    
    DWORD bytesWritten = 0;
    return WriteFile(m_hPipe, buffer.data(), 
                     static_cast<DWORD>(buffer.size()), 
                     &bytesWritten, nullptr) != FALSE;
}

bool NamedPipeClient::SendAndWait(const MessageHeader& header,
                                   const void* payload, size_t payloadSize,
                                   MessageHeader& responseHeader,
                                   std::vector<uint8_t>& responseData,
                                   uint32_t timeoutMs) {
    if (!Send(header, payload, payloadSize)) {
        return false;
    }
    
    // Read response
    std::vector<uint8_t> buffer(65536);
    DWORD bytesRead = 0;
    
    BOOL success = ReadFile(m_hPipe, buffer.data(), 
                            static_cast<DWORD>(buffer.size()), 
                            &bytesRead, nullptr);
    
    if (!success || bytesRead == 0) {
        return false;
    }
    
    return DeserializeMessage(buffer.data(), bytesRead, 
                              responseHeader, responseData);
}

// ============================================
// Shared Memory
// ============================================

SharedMemory::SharedMemory(const std::wstring& name, size_t size, bool create)
    : m_name(name)
    , m_hMapFile(nullptr)
    , m_data(nullptr)
    , m_stateBlock(nullptr)
    , m_hMutex(nullptr)
    , m_size(size)
{
    if (create) {
        PSECURITY_DESCRIPTOR psd = nullptr;
        SECURITY_ATTRIBUTES sa = {};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        // IU allows non-elevated GuardianC in user session to access shared memory
        BOOL sdOk = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
            SDDL_REVISION_1, &psd, nullptr);
        if (sdOk) sa.lpSecurityDescriptor = psd;

        m_hMapFile = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            sdOk ? &sa : nullptr,
            PAGE_READWRITE,
            0,
            static_cast<DWORD>(size),
            name.c_str()
        );
        if (psd) LocalFree(psd);
    } else {
        // Open existing shared memory
        m_hMapFile = OpenFileMappingW(
            FILE_MAP_ALL_ACCESS,
            FALSE,
            name.c_str()
        );
    }
    
    if (m_hMapFile) {
        m_data = MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (m_data) {
            m_stateBlock = static_cast<SharedStateBlock*>(m_data);
            
            // Create/open mutex for synchronization
            std::wstring mutexName = name + L"_Mutex";
            m_hMutex = CreateMutexW(nullptr, FALSE, mutexName.c_str());
            
            if (create) {
                memset(m_data, 0, size);
            }
        }
    }
}

SharedMemory::~SharedMemory() {
    if (m_data) {
        UnmapViewOfFile(m_data);
    }
    if (m_hMapFile) {
        CloseHandle(m_hMapFile);
    }
    if (m_hMutex) {
        CloseHandle(m_hMutex);
    }
}

void SharedMemory::UpdateHeartbeat(NodeId nodeId, const HeartbeatPayload& heartbeat) {
    Lock();
    if (m_stateBlock && nodeId != NodeId::UNKNOWN) {
        int idx = static_cast<int>(nodeId);
        m_stateBlock->heartbeats[idx] = heartbeat;
        InterlockedExchange64((LONGLONG*)&m_stateBlock->last_update, (LONGLONG)GetCurrentTimestamp());
        m_stateBlock->sequence++;
    }
    Unlock();
}

bool SharedMemory::GetHeartbeat(NodeId nodeId, HeartbeatPayload& heartbeat) const {
    if (!m_stateBlock || nodeId == NodeId::UNKNOWN) {
        return false;
    }
    
    int idx = static_cast<int>(nodeId);
    heartbeat = m_stateBlock->heartbeats[idx];
    return true;
}

void SharedMemory::SetEmergencyState(EmergencyState state) {
    Lock();
    if (m_stateBlock) {
        m_stateBlock->emergency_state = static_cast<uint8_t>(state);
        InterlockedExchange64((LONGLONG*)&m_stateBlock->last_update, (LONGLONG)GetCurrentTimestamp());
    }
    Unlock();
}

EmergencyState SharedMemory::GetEmergencyState() const {
    if (!m_stateBlock) {
        return EmergencyState::NORMAL;
    }
    return static_cast<EmergencyState>(m_stateBlock->emergency_state);
}

void SharedMemory::Lock() {
    if (m_hMutex) {
        WaitForSingleObject(m_hMutex, INFINITE);
    }
}

void SharedMemory::Unlock() {
    if (m_hMutex) {
        ReleaseMutex(m_hMutex);
    }
}

// ============================================
// TCP Server (Backup Channel)
// ============================================

TcpServer::TcpServer(uint16_t port, bool useTLS)
    : m_port(port)
    , m_useTLS(useTLS)
    , m_running(false)
    , m_listenSocket(INVALID_SOCKET)
{
}

TcpServer::~TcpServer() {
    Stop();
}

bool TcpServer::Start() {
    if (m_running) return true;

    if (m_useTLS) {
         if (g_logger)
             g_logger->Log(LogLevel::WARN,
                 "TcpServer: TLS deferred to V2. Plaintext loopback active with peer validation. "
                 "Phase 2.8 will add full TLS support.");
        m_useTLS = false;
    }
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    // Create socket
    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    // Bind to port
    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serverAddr.sin_port = htons(m_port);
    
    if (bind(m_listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        WSACleanup();
        return false;
    }
    
    // Listen
    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        WSACleanup();
        return false;
    }
    
    m_running = true;
    m_acceptThread = std::thread(&TcpServer::AcceptLoop, this);
    
    return true;
}

void TcpServer::Stop() {
    if (!m_running) return;
    
    m_running = false;
    
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }
    
    if (m_acceptThread.joinable()) {
        m_acceptThread.join();
    }
    
    WSACleanup();
}

void TcpServer::AcceptLoop() {
     while (m_running) {
         sockaddr_in clientAddr = {};
         int clientAddrSize = sizeof(clientAddr);
         
         SOCKET clientSocket = accept(m_listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);
         if (clientSocket == INVALID_SOCKET) {
             continue;
         }
         
         // Validate peer connection is from loopback (127.0.0.1)
         sockaddr_in peerAddr{};
         int peerLen = sizeof(peerAddr);
         if (getpeername(clientSocket, (sockaddr*)&peerAddr, &peerLen) == SOCKET_ERROR ||
             peerAddr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
             closesocket(clientSocket);
             continue;
         }
         
         if (m_running) {
             std::thread clientThread(&TcpServer::HandleClient, this, clientSocket);
             clientThread.detach();
         } else {
             closesocket(clientSocket);
         }
     }
 }

void TcpServer::HandleClient(SOCKET clientSocket) {
    std::vector<uint8_t> buffer(65536);
    
    while (m_running) {
        int bytesRead = recv(clientSocket, (char*)buffer.data(), (int)buffer.size(), 0);
        
        if (bytesRead <= 0) {
            break;
        }
        
        // Parse message
        MessageHeader header;
        std::vector<uint8_t> payload;
        
        if (DeserializeMessage(buffer.data(), bytesRead, header, payload)) {
            if (m_handler) {
                m_handler(header, payload.data(), payload.size());
            }
        }
    }
    
    closesocket(clientSocket);
}

// ============================================
// TCP Client (Backup Channel)
// ============================================

TcpClient::TcpClient(const std::string& host, uint16_t port, bool useTLS)
    : m_host(host)
    , m_port(port)
    , m_useTLS(useTLS)
    , m_socket(INVALID_SOCKET)
    , m_connected(false)
{
}

TcpClient::~TcpClient() {
    Disconnect();
}

bool TcpClient::Connect(uint32_t timeoutMs) {
    if (m_connected) return true;

    if (m_useTLS) {
        if (g_logger)
            g_logger->Log(LogLevel::WARN,
                "TcpClient: TLS requested but SChannel negotiation is not yet implemented. "
                "Falling back to plaintext loopback. Phase 2.8 will add full TLS support.");
        m_useTLS = false;
    }
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    // Create socket
    m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    
    // Set timeout
    DWORD timeout = timeoutMs;
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Connect to server
    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(m_host.c_str());
    serverAddr.sin_port = htons(m_port);
    
    if (connect(m_socket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
        WSACleanup();
        return false;
    }
    
    m_connected = true;
    return true;
}

void TcpClient::Disconnect() {
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    m_connected = false;
    WSACleanup();
}

bool TcpClient::IsConnected() const {
    return m_connected;
}

bool TcpClient::Send(const MessageHeader& header, const void* payload, size_t payloadSize) {
    if (!m_connected) return false;
    
    auto buffer = SerializeMessage(header, payload, payloadSize);
    
    int bytesSent = send(m_socket, (char*)buffer.data(), (int)buffer.size(), 0);
    return bytesSent == static_cast<int>(buffer.size());
}

bool TcpClient::Receive(MessageHeader& header, std::vector<uint8_t>& data, uint32_t timeoutMs) {
    if (!m_connected) return false;
    
    std::vector<uint8_t> buffer(65536);
    int bytesRead = recv(m_socket, (char*)buffer.data(), (int)buffer.size(), 0);
    
    if (bytesRead <= 0) {
        return false;
    }
    
    return DeserializeMessage(buffer.data(), bytesRead, header, data);
}

// ============================================
// IpcManager Implementation
// ============================================

IpcManager::IpcManager(NodeId nodeId)
    : m_nodeId(nodeId)
    , m_sequence(0)
{
}

IpcManager::~IpcManager() {
    Shutdown();
}

bool IpcManager::Initialize() {
    // Create pipe server for this node
    std::wstring pipeName = L"\\\\.\\pipe\\GuardianIPC_";
    switch (m_nodeId) {
        case NodeId::GUARDIAN_A:
            pipeName += L"A";
            break;
        case NodeId::GUARDIAN_B:
            pipeName += L"B";
            break;
        case NodeId::GUARDIAN_C:
            pipeName += L"C";
            break;
        default:
            return false;
    }
    
    m_pipeServer = std::make_unique<NamedPipeServer>(pipeName);
    if (!m_pipeServer->Start()) {
        return false;
    }
    
    // Global namespace for cross-session access (Session 0 services <-> user session GuardianC).
    // SYSTEM has SeCreateGlobalPrivilege by default.
    bool isCreator = (m_nodeId == NodeId::GUARDIAN_A);
    m_sharedMemory = std::make_unique<SharedMemory>(
        L"Global\\GuardianState", 
        sizeof(SharedStateBlock), 
        isCreator
    );
    
    // Shared memory creation may fail, but it's not critical for basic operation
    // Pipe server is the primary IPC mechanism, shared memory is secondary
    
    return true;
}

void IpcManager::Shutdown() {
    if (m_pipeServer) {
        m_pipeServer->Stop();
        m_pipeServer.reset();
    }
    
    if (m_sharedMemory) {
        m_sharedMemory.reset();
    }
    
    // Close client connections
    for (int i = 0; i < 3; i++) {
        if (m_pipeClients[i]) {
            m_pipeClients[i]->Disconnect();
            m_pipeClients[i].reset();
        }
    }
}

bool IpcManager::SendToNode(NodeId dest, MessageType type, 
                            const void* payload, size_t payloadSize) {
    int idx = static_cast<int>(dest);
    if (idx < 0 || idx >= 3) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_sendMutex[idx]);
    
    // Ensure client connection exists
    if (!m_pipeClients[idx]) {
        std::wstring pipeName = L"\\\\.\\pipe\\GuardianIPC_";
        switch (dest) {
            case NodeId::GUARDIAN_A: pipeName += L"A"; break;
            case NodeId::GUARDIAN_B: pipeName += L"B"; break;
            case NodeId::GUARDIAN_C: pipeName += L"C"; break;
            default: return false;
        }
        m_pipeClients[idx] = std::make_unique<NamedPipeClient>(pipeName);
    }
    
    auto tryConnect = [&]() -> bool {
        if (m_pipeClients[idx]->IsConnected()) return true;
        if (m_pipeClients[idx]->Connect(300)) return true;
        return false;
    };

    if (!tryConnect()) {
        // Suppress repeated warnings (log at most once per 30s per node)
        static uint64_t s_lastWarn[3] = {};
        uint64_t now = static_cast<uint64_t>(GetCurrentTimestamp());
        if (now - s_lastWarn[idx] > 30) {
            s_lastWarn[idx] = now;
            if (g_logger)
                g_logger->Log(LogLevel::WARN,
                    "IPC: cannot reach node %d (will keep retrying)", idx);
        }
        return false;
    }
    
    MessageHeader header = {};
    header.magic = MESSAGE_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(type);
    header.source = static_cast<uint8_t>(m_nodeId);
    header.dest = static_cast<uint8_t>(dest);
    header.sequence = m_sequence++;
    header.timestamp = static_cast<uint32_t>(GetCurrentTimestamp());
    header.payload_len = static_cast<uint32_t>(payloadSize);
    memset(header.checksum, 0, CHECKSUM_SIZE);
    if (!CalculateChecksum(header, payload, header.checksum)) {
        return false;
    }
    
    bool sent = m_pipeClients[idx]->Send(header, payload, payloadSize);
    if (!sent) {
        // Connection broken — reset for next attempt
        m_pipeClients[idx]->Disconnect();
    }
    return sent;
}

bool IpcManager::Broadcast(MessageType type, 
                           const void* payload, size_t payloadSize) {
    bool success = true;
    
    for (int i = 0; i < 3; i++) {
        NodeId dest = static_cast<NodeId>(i);
        if (dest != m_nodeId) {
            if (!SendToNode(dest, type, payload, payloadSize)) {
                success = false;
            }
        }
    }
    
    return success;
}

void IpcManager::UpdateHeartbeat(const HeartbeatPayload& heartbeat) {
    if (m_sharedMemory) {
        m_sharedMemory->UpdateHeartbeat(m_nodeId, heartbeat);
    }
}

bool IpcManager::GetNodeHeartbeat(NodeId nodeId, HeartbeatPayload& heartbeat) const {
    if (m_sharedMemory) {
        return m_sharedMemory->GetHeartbeat(nodeId, heartbeat);
    }
    return false;
}

void IpcManager::SetMessageHandler(NamedPipeServer::MessageHandler handler) {
    if (m_pipeServer) {
        m_pipeServer->SetMessageHandler(std::move(handler));
    }
}

} // namespace Guardian
