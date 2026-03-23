/**
 * @file threat_evaluator.h
 * @brief Threat evaluation for GuardianA
 */

#pragma once

#include "../../common/include/common_types.h"
#include "../../common/include/config.h"
#include <string>
#include <vector>
#include <memory>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace Guardian {

/**
 * @brief Batch threat tier (result of two-tier threshold check)
 */
enum class BatchThreatTier : uint8_t {
    NONE   = 0,   ///< Below all thresholds
    TIER_1 = 1,   ///< Exceeded tier-1 → encrypt + lock (recoverable)
    TIER_2 = 2    ///< Exceeded tier-2 → emergency protocol (irrecoverable)
};

/**
 * @brief Threshold configuration for batch detection
 *
 * NOTE: file_write tracks FILE_WRITE events (there is no FILE_COPY event type).
 * YAML config keys use "file_write_count" / "file_write_window_seconds".
 * Legacy "file_copy_*" keys are accepted as aliases for backward compatibility.
 */
struct DetectionThresholds {
    uint32_t file_write_count = 10;
    uint32_t file_write_window_seconds = 5;
    
    uint32_t file_compress_count = 50;
    uint32_t file_compress_window_seconds = 5;
    
    uint32_t file_delete_count = 5;
    uint32_t file_delete_window_seconds = 5;
    
    uint32_t file_create_count = 15;
    uint32_t file_create_window_seconds = 5;
    
    uint32_t file_rename_count = 10;
    uint32_t file_rename_window_seconds = 5;
    
    uint32_t file_move_count = 10;
    uint32_t file_move_window_seconds = 5;
    
    uint32_t file_network_transfer_count = 10;
    uint32_t file_network_transfer_window_seconds = 5;
    
    uint32_t data_transfer_mb = 1;
    
    uint32_t process_termination_count = 50;
    uint32_t process_termination_window_seconds = 5;
};

/**
 * @brief Event timestamp record for batch detection
 */
struct EventRecord {
    uint64_t timestamp;
    DriverEventType event_type;
    uint32_t process_id;
    std::wstring file_path;
    size_t data_size;
};

/**
 * @brief Threat evaluator -- batch threshold detection only
 *
 * Single-event threat assessment is handled by GuardianA::AssessThreat()
 * (or GuardianB::AssessThreat() in failover).  This class is responsible
 * for recording events and checking two-tier batch thresholds.
 */
class ThreatEvaluator {
public:
    ThreatEvaluator();
    ~ThreatEvaluator();
    
    // Two-tier threshold check (returns TIER_2, TIER_1, or NONE)
    BatchThreatTier CheckBatchThresholds(const DriverEvent& event);
    
    // Configuration
    void SetThresholds(const DetectionThresholds& thresholds);
    void SetTieredThresholds(const DetectionThresholds& tier1, const DetectionThresholds& tier2);
    
    // Statistics
    uint64_t GetEvaluationsCount() const;
    uint64_t GetThreatsDetected() const;
    
    // Returns the PID that contributed the most file events in the recent window.
    // Used for targeted termination instead of blanket TERMINATE on every event.
    uint32_t GetTopContributorPid() const;

    void RecordEvent(const DriverEvent& event);
    void CleanOldRecords();

    // test-only: individual batch checks, production uses CheckBatchThresholds()
    bool CheckBatchFileWrite();
    bool CheckBatchFileCompress();
    bool CheckBatchFileDelete();
    bool CheckBatchFileCreate();
    bool CheckBatchFileMove();
    bool CheckBatchNetworkTransfer();
    bool CheckProcessTerminationAnomaly();
    bool CheckDataTransferAnomaly();
    
private:
    // Two-tier thresholds
    DetectionThresholds m_thresholds;      // used as single-tier fallback
    DetectionThresholds m_tier1Thresholds;  // encrypt + lock
    DetectionThresholds m_tier2Thresholds;  // emergency protocol
    
    // Statistics
    std::atomic<uint64_t> m_evalCount;
    std::atomic<uint64_t> m_threatsDetected;
    
    // Batch detection event records
    mutable std::mutex m_recordsMutex;
    std::deque<EventRecord> m_fileWriteRecords;
    std::deque<EventRecord> m_fileCompressRecords;
    std::deque<EventRecord> m_fileDeleteRecords;
    std::deque<EventRecord> m_fileRenameRecords;
    std::deque<EventRecord> m_fileMoveRecords;
    std::deque<EventRecord> m_fileCreateRecords;
    std::deque<EventRecord> m_networkTransferRecords;
    std::deque<EventRecord> m_processTerminateRecords;
    
    // Helper methods
    uint64_t GetCurrentTimeMs() const;
    void RemoveOldRecords(std::deque<EventRecord>& records, uint32_t windowSeconds);
    size_t CountRecordsInWindow(std::deque<EventRecord>& records, uint32_t windowSeconds);
    size_t CalculateDataTransferSize(std::deque<EventRecord>& records, uint32_t windowSeconds);
};

struct SingleEventAssessment {
    ThreatLevel level;
    ResponseAction action;
    float confidence;
    std::string description;
};

SingleEventAssessment BuildEventResponse(
    const Config& config,
    DriverEventType eventType);

} // namespace Guardian
