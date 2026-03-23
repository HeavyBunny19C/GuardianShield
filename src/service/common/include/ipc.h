/**
 * @file ipc.h
 * @brief Inter-Process Communication for GuardianShield
 * 
 * Implements three communication channels:
 * 1. Named Pipe - Primary high-priority message channel
 * 2. Shared Memory - Fast heartbeat/state synchronization
 * 3. TCP Loopback - Backup channel for redundancy
 */

#pragma once

#include "common_types.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

#ifdef _WIN32
#include <winsock2.h>
#include <Windows.h>
#endif

namespace Guardian {

// ============================================
// Message Serialization
// ============================================

/**
 * @brief Serialize message header to byte buffer
 */
std::vector<uint8_t> SerializeMessage(const MessageHeader& header, const void* payload, size_t payloadSize);

/**
 * @brief Deserialize message header from byte buffer
 */
bool DeserializeMessage(const uint8_t* data, size_t size, MessageHeader& header, std::vector<uint8_t>& payload);

/**
 * @brief Calculate message checksum (HMAC-SHA256 truncated)
 */
bool CalculateChecksum(const MessageHeader& header, const void* payload, uint8_t* checksumOut);
bool VerifyChecksum(const MessageHeader& header, const void* payload);

// ============================================
// Named Pipe Communication
// ============================================

/**
 * @brief Named Pipe Server
 * 
 * Server side of named pipe communication.
 * Used by GuardianA and GuardianB for receiving messages.
 */
class NamedPipeServer {
public:
    using MessageHandler = std::function<void(const MessageHeader&, const uint8_t*, size_t)>;
    
    /**
     * @brief Construct a new Named Pipe Server
     * @param pipeName Pipe name (e.g., "\\\\.\\pipe\\GuardianIPC_A")
     * @param bufferSize Size of pipe buffer (default 64KB)
     */
    NamedPipeServer(const std::wstring& pipeName, size_t bufferSize = 65536);
    ~NamedPipeServer();
    
    // Non-copyable
    NamedPipeServer(const NamedPipeServer&) = delete;
    NamedPipeServer& operator=(const NamedPipeServer&) = delete;
    
    /**
     * @brief Start the pipe server
     * @return true if successful
     */
    bool Start();
    
    /**
     * @brief Stop the pipe server
     */
    void Stop();
    
    /**
     * @brief Set message handler
     */
    void SetMessageHandler(MessageHandler handler) { m_handler = std::move(handler); }
    
    /**
     * @brief Check if server is running
     */
    bool IsRunning() const { return m_running.load(); }
    
    /**
     * @brief Send response to a specific client pipe
     * @param hClientPipe Handle to the client's pipe (avoids using shared m_hPipe)
     */
    bool SendResponse(HANDLE hClientPipe, const MessageHeader& header, const void* payload, size_t payloadSize);

private:
    void AcceptLoop();
    void HandleClient(HANDLE hPipe);
    
    std::wstring m_pipeName;
    size_t m_bufferSize;
    std::atomic<bool> m_running;
    HANDLE m_hPipe;
    std::thread m_acceptThread;
    MessageHandler m_handler;
    std::mutex m_mutex;
};

/**
 * @brief Named Pipe Client
 * 
 * Client side of named pipe communication.
 * Used for sending messages between guardian processes.
 */
class NamedPipeClient {
public:
    /**
     * @brief Construct a new Named Pipe Client
     * @param pipeName Pipe name to connect to
     */
    explicit NamedPipeClient(const std::wstring& pipeName);
    ~NamedPipeClient();
    
    // Non-copyable
    NamedPipeClient(const NamedPipeClient&) = delete;
    NamedPipeClient& operator=(const NamedPipeClient&) = delete;
    
    /**
     * @brief Connect to pipe server
     * @param timeoutMs Connection timeout in milliseconds
     * @return true if connected successfully
     */
    bool Connect(uint32_t timeoutMs = 5000);
    
    /**
     * @brief Disconnect from pipe server
     */
    void Disconnect();
    
    /**
     * @brief Check if connected
     */
    bool IsConnected() const { return m_connected; }
    
    /**
     * @brief Send message and wait for response
     * @param header Message header
     * @param payload Payload data
     * @param payloadSize Size of payload
     * @param responseHeader Response header (output)
     * @param responseData Response payload data (output)
     * @param timeoutMs Response timeout
     * @return true if response received
     */
    bool SendAndWait(
        const MessageHeader& header,
        const void* payload,
        size_t payloadSize,
        MessageHeader& responseHeader,
        std::vector<uint8_t>& responseData,
        uint32_t timeoutMs = 5000
    );
    
    /**
     * @brief Send message without waiting for response
     */
    bool Send(const MessageHeader& header, const void* payload, size_t payloadSize);

private:
    std::wstring m_pipeName;
    HANDLE m_hPipe;
    bool m_connected;
    std::mutex m_mutex;
};

// ============================================
// Shared Memory Communication
// ============================================

/**
 * @brief Shared Memory State Block
 * 
 * Fixed-size structure for inter-process state sharing.
 */
struct SharedStateBlock {
    uint64_t last_update;           ///< Timestamp of last update
    uint8_t node_status[3];         ///< Status of each node (A, B, C)
    uint8_t emergency_state;        ///< Current emergency state
    uint32_t sequence;              ///< Update sequence number
    uint8_t reserved[48];           ///< Reserved for future use
    HeartbeatPayload heartbeats[3]; ///< Latest heartbeat from each node
};

/**
 * @brief Shared Memory Manager
 * 
 * Manages shared memory region for fast state synchronization.
 */
class SharedMemory {
public:
    /**
     * @brief Construct a new Shared Memory Manager
     * @param name Shared memory name (e.g., "Global\\GuardianState")
     * @param size Size of shared memory region
     * @param create If true, create new; if false, open existing
     */
    SharedMemory(const std::wstring& name, size_t size = sizeof(SharedStateBlock), bool create = true);
    ~SharedMemory();
    
    // Non-copyable
    SharedMemory(const SharedMemory&) = delete;
    SharedMemory& operator=(const SharedMemory&) = delete;
    
    /**
     * @brief Check if shared memory is valid
     */
    bool IsValid() const { return m_data != nullptr; }
    
    /**
     * @brief Get pointer to shared state block
     */
    SharedStateBlock* GetStateBlock() { return m_stateBlock; }
    const SharedStateBlock* GetStateBlock() const { return m_stateBlock; }
    
    /**
     * @brief Update heartbeat for a node
     * @param nodeId Node to update
     * @param heartbeat Heartbeat data
     */
    void UpdateHeartbeat(NodeId nodeId, const HeartbeatPayload& heartbeat);
    
    /**
     * @brief Get heartbeat from a node
     */
    bool GetHeartbeat(NodeId nodeId, HeartbeatPayload& heartbeat) const;
    
    /**
     * @brief Update emergency state
     */
    void SetEmergencyState(EmergencyState state);
    
    /**
     * @brief Get current emergency state
     */
    EmergencyState GetEmergencyState() const;
    
    /**
     * @brief Lock the shared memory for exclusive access
     */
    void Lock();
    
    /**
     * @brief Unlock the shared memory
     */
    void Unlock();

private:
    std::wstring m_name;
    HANDLE m_hMapFile;
    void* m_data;
    SharedStateBlock* m_stateBlock;
    HANDLE m_hMutex;
    size_t m_size;
};

// ============================================
// TCP Loopback Communication (Backup Channel)
// ============================================

/**
 * @brief TCP Server for backup communication
 */
class TcpServer {
public:
    using MessageHandler = std::function<void(const MessageHeader&, const uint8_t*, size_t)>;
    
    // TODO(Phase 2.8): Full SChannel TLS will be integrated here.
    // m_useTLS controls whether TLS is attempted; currently defaults to false
    // until SChannel negotiation is fully implemented.
    TcpServer(uint16_t port, bool useTLS = false);
    ~TcpServer();
    
    bool Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    void SetMessageHandler(MessageHandler handler) { m_handler = std::move(handler); }
    
private:
    void AcceptLoop();
    void HandleClient(SOCKET clientSocket);
    
    uint16_t m_port;
    bool m_useTLS;
    std::atomic<bool> m_running;
    SOCKET m_listenSocket;
    std::thread m_acceptThread;
    MessageHandler m_handler;
};

/**
 * @brief TCP Client for backup communication
 */
class TcpClient {
public:
    // TODO(Phase 2.8): Full SChannel TLS will be integrated here.
    TcpClient(const std::string& host, uint16_t port, bool useTLS = false);
    ~TcpClient();
    
    bool Connect(uint32_t timeoutMs = 5000);
    void Disconnect();
    bool IsConnected() const;
    
    bool Send(const MessageHeader& header, const void* payload, size_t payloadSize);
    bool Receive(MessageHeader& header, std::vector<uint8_t>& data, uint32_t timeoutMs = 5000);

private:
    std::string m_host;
    uint16_t m_port;
    bool m_useTLS;
    SOCKET m_socket;
    bool m_connected;
};

// ============================================
// IPC Manager - Unified Communication Interface
// ============================================

/**
 * @brief IPC Manager
 * 
 * Manages all three communication channels for a guardian process.
 */
class IpcManager {
public:
    /**
     * @brief Construct IPC Manager for a node
     * @param nodeId This node's ID
     */
    explicit IpcManager(NodeId nodeId);
    ~IpcManager();
    
    /**
     * @brief Initialize all communication channels
     */
    bool Initialize();
    
    /**
     * @brief Shutdown all communication channels
     */
    void Shutdown();
    
    /**
     * @brief Send message to specific node
     */
    bool SendToNode(NodeId dest, MessageType type, const void* payload, size_t payloadSize);
    
    /**
     * @brief Broadcast message to all other nodes
     */
    bool Broadcast(MessageType type, const void* payload, size_t payloadSize);
    
    /**
     * @brief Update local heartbeat in shared memory
     */
    void UpdateHeartbeat(const HeartbeatPayload& heartbeat);
    
    /**
     * @brief Get heartbeat from another node
     */
    bool GetNodeHeartbeat(NodeId nodeId, HeartbeatPayload& heartbeat) const;
    
    /**
     * @brief Set message handler for incoming messages
     */
    void SetMessageHandler(NamedPipeServer::MessageHandler handler);

private:
    NodeId m_nodeId;
    std::unique_ptr<NamedPipeServer> m_pipeServer;
    std::unique_ptr<SharedMemory> m_sharedMemory;
    std::unique_ptr<TcpServer> m_tcpServer;
    
    // Client connections to other nodes
    std::unique_ptr<NamedPipeClient> m_pipeClients[3];
    std::unique_ptr<TcpClient> m_tcpClients[3];
    
    std::mutex m_sendMutex[3];
    std::atomic<uint32_t> m_sequence;
};

} // namespace Guardian
