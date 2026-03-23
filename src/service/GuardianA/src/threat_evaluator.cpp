/**
 * @file threat_evaluator.cpp
 * @brief Batch threshold detection -- two-tier system
 *
 * Single-event assessment lives in GuardianA::AssessThreat() /
 * GuardianB::AssessThreat().  This file only handles recording events
 * and checking whether batch thresholds (Tier 1 / Tier 2) have been
 * exceeded.
 */

#include "threat_evaluator.h"
#include <algorithm>
#include <chrono>

namespace Guardian {

ThreatEvaluator::ThreatEvaluator()
    : m_evalCount(0)
    , m_threatsDetected(0)
{
}

ThreatEvaluator::~ThreatEvaluator() = default;

uint64_t ThreatEvaluator::GetCurrentTimeMs() const {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()
    ).count();
}

void ThreatEvaluator::RemoveOldRecords(std::deque<EventRecord>& records, uint32_t windowSeconds) {
    uint64_t cutoff = GetCurrentTimeMs() - (windowSeconds * 1000);
    while (!records.empty() && records.front().timestamp < cutoff) {
        records.pop_front();
    }
}

size_t ThreatEvaluator::CountRecordsInWindow(std::deque<EventRecord>& records, uint32_t windowSeconds) {
    RemoveOldRecords(records, windowSeconds);
    return records.size();
}

size_t ThreatEvaluator::CalculateDataTransferSize(std::deque<EventRecord>& records, uint32_t windowSeconds) {
    RemoveOldRecords(records, windowSeconds);
    size_t totalSize = 0;
    for (const auto& record : records) {
        totalSize += record.data_size;
    }
    return totalSize;
}

void ThreatEvaluator::RecordEvent(const DriverEvent& event) {
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    
    EventRecord record;
    record.timestamp = GetCurrentTimeMs();
    record.event_type = static_cast<DriverEventType>(event.event_type);
    record.process_id = event.process_id;
    record.file_path = event.file_path;
    record.data_size = event.data_size;
    
    switch (record.event_type) {
        case DriverEventType::FILE_WRITE:
            m_fileWriteRecords.push_back(record);
            break;
            
        case DriverEventType::FILE_COMPRESS:
            m_fileCompressRecords.push_back(record);
            break;
            
        case DriverEventType::FILE_NETWORK_TRANSFER:
            m_networkTransferRecords.push_back(record);
            break;
            
        case DriverEventType::PROC_TERMINATE:
            m_processTerminateRecords.push_back(record);
            break;

        case DriverEventType::FILE_DELETE:
            m_fileDeleteRecords.push_back(record);
            break;

        case DriverEventType::FILE_RENAME:
            m_fileRenameRecords.push_back(record);
            break;

        case DriverEventType::FILE_MOVE:
            m_fileMoveRecords.push_back(record);
            break;
        
        case DriverEventType::FILE_CREATE:
            m_fileCreateRecords.push_back(record);
            break;
            
        default:
            break;
    }
}

bool ThreatEvaluator::CheckBatchFileWrite() {
    if (m_thresholds.file_write_count == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t count = CountRecordsInWindow(m_fileWriteRecords, m_thresholds.file_write_window_seconds);
    return count >= m_thresholds.file_write_count;
}

bool ThreatEvaluator::CheckBatchFileCompress() {
    if (m_thresholds.file_compress_count == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t count = CountRecordsInWindow(m_fileCompressRecords, m_thresholds.file_compress_window_seconds);
    return count >= m_thresholds.file_compress_count;
}

bool ThreatEvaluator::CheckBatchNetworkTransfer() {
    if (m_thresholds.file_network_transfer_count == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t count = CountRecordsInWindow(m_networkTransferRecords, m_thresholds.file_network_transfer_window_seconds);
    return count >= m_thresholds.file_network_transfer_count;
}

bool ThreatEvaluator::CheckProcessTerminationAnomaly() {
    if (m_thresholds.process_termination_count == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t count = CountRecordsInWindow(m_processTerminateRecords,
                                         m_thresholds.process_termination_window_seconds);
    return count >= m_thresholds.process_termination_count;
}

bool ThreatEvaluator::CheckDataTransferAnomaly() {
    if (m_thresholds.data_transfer_mb == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t totalMB = CalculateDataTransferSize(m_networkTransferRecords,
                                                m_thresholds.file_network_transfer_window_seconds) / (1024 * 1024);
    return totalMB >= m_thresholds.data_transfer_mb;
}

void ThreatEvaluator::CleanOldRecords() {
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    uint32_t maxWindow = std::max({
        m_tier2Thresholds.file_write_window_seconds,
        m_tier2Thresholds.file_compress_window_seconds,
        m_tier2Thresholds.file_delete_window_seconds,
        m_tier2Thresholds.file_create_window_seconds,
        m_tier2Thresholds.file_rename_window_seconds,
        m_tier2Thresholds.file_move_window_seconds,
        m_tier2Thresholds.file_network_transfer_window_seconds,
        m_tier2Thresholds.process_termination_window_seconds,
        m_tier1Thresholds.file_write_window_seconds,
        m_tier1Thresholds.file_compress_window_seconds,
        m_tier1Thresholds.file_delete_window_seconds,
        m_tier1Thresholds.file_create_window_seconds,
        m_tier1Thresholds.file_rename_window_seconds,
        m_tier1Thresholds.file_move_window_seconds,
        m_tier1Thresholds.file_network_transfer_window_seconds,
        m_tier1Thresholds.process_termination_window_seconds,
        uint32_t(60)
    });
    RemoveOldRecords(m_fileWriteRecords, maxWindow);
    RemoveOldRecords(m_fileCompressRecords, maxWindow);
    RemoveOldRecords(m_networkTransferRecords, maxWindow);
    RemoveOldRecords(m_processTerminateRecords, maxWindow);
    RemoveOldRecords(m_fileDeleteRecords, maxWindow);
    RemoveOldRecords(m_fileRenameRecords, maxWindow);
    RemoveOldRecords(m_fileMoveRecords, maxWindow);
    RemoveOldRecords(m_fileCreateRecords, maxWindow);
}

void ThreatEvaluator::SetThresholds(const DetectionThresholds& thresholds) {
    m_thresholds = thresholds;
}

void ThreatEvaluator::SetTieredThresholds(const DetectionThresholds& tier1,
                                            const DetectionThresholds& tier2) {
    m_tier1Thresholds = tier1;
    m_tier2Thresholds = tier2;
    m_thresholds = tier1;
}

BatchThreatTier ThreatEvaluator::CheckBatchThresholds(const DriverEvent& event) {
    RecordEvent(event);
    uint64_t count = m_evalCount.fetch_add(1, std::memory_order_relaxed) + 1;

    if (count % 100 == 0) {
        CleanOldRecords();
    }

    // Single lock scope for both tiers to prevent inter-tier race conditions
    std::lock_guard<std::mutex> lock(m_recordsMutex);

    // Tier 2 check first (higher severity); threshold == 0 means unrestricted (skip)
    if (m_tier2Thresholds.file_write_count > 0 &&
        CountRecordsInWindow(m_fileWriteRecords, m_tier2Thresholds.file_write_window_seconds)
            >= m_tier2Thresholds.file_write_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }
    if (m_tier2Thresholds.file_compress_count > 0 &&
        CountRecordsInWindow(m_fileCompressRecords, m_tier2Thresholds.file_compress_window_seconds)
            >= m_tier2Thresholds.file_compress_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }
    if (m_tier2Thresholds.file_network_transfer_count > 0 &&
        CountRecordsInWindow(m_networkTransferRecords, m_tier2Thresholds.file_network_transfer_window_seconds)
            >= m_tier2Thresholds.file_network_transfer_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }
    if (m_tier2Thresholds.file_delete_count > 0 &&
        CountRecordsInWindow(m_fileDeleteRecords, m_tier2Thresholds.file_delete_window_seconds)
            >= m_tier2Thresholds.file_delete_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }
    if (m_tier2Thresholds.file_create_count > 0 &&
        CountRecordsInWindow(m_fileCreateRecords, m_tier2Thresholds.file_create_window_seconds)
            >= m_tier2Thresholds.file_create_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }
    if (m_tier2Thresholds.file_rename_count > 0 &&
        CountRecordsInWindow(m_fileRenameRecords, m_tier2Thresholds.file_rename_window_seconds)
            >= m_tier2Thresholds.file_rename_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }
    if (m_tier2Thresholds.file_move_count > 0 &&
        CountRecordsInWindow(m_fileMoveRecords, m_tier2Thresholds.file_move_window_seconds)
            >= m_tier2Thresholds.file_move_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }
    if (m_tier2Thresholds.data_transfer_mb > 0) {
        size_t xferMB = CalculateDataTransferSize(m_networkTransferRecords,
                            m_tier2Thresholds.file_network_transfer_window_seconds) / (1024 * 1024);
        if (xferMB >= m_tier2Thresholds.data_transfer_mb) {
            m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
            return BatchThreatTier::TIER_2;
        }
    }
    if (m_tier2Thresholds.process_termination_count > 0 &&
        CountRecordsInWindow(m_processTerminateRecords,
                              m_tier2Thresholds.process_termination_window_seconds)
            >= m_tier2Thresholds.process_termination_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_2;
    }

    // Tier 1 check; threshold == 0 means unrestricted (skip)
    if (m_tier1Thresholds.file_write_count > 0 &&
        CountRecordsInWindow(m_fileWriteRecords, m_tier1Thresholds.file_write_window_seconds)
            >= m_tier1Thresholds.file_write_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }
    if (m_tier1Thresholds.file_compress_count > 0 &&
        CountRecordsInWindow(m_fileCompressRecords, m_tier1Thresholds.file_compress_window_seconds)
            >= m_tier1Thresholds.file_compress_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }
    if (m_tier1Thresholds.file_network_transfer_count > 0 &&
        CountRecordsInWindow(m_networkTransferRecords, m_tier1Thresholds.file_network_transfer_window_seconds)
            >= m_tier1Thresholds.file_network_transfer_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }
    if (m_tier1Thresholds.file_delete_count > 0 &&
        CountRecordsInWindow(m_fileDeleteRecords, m_tier1Thresholds.file_delete_window_seconds)
            >= m_tier1Thresholds.file_delete_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }
    if (m_tier1Thresholds.file_create_count > 0 &&
        CountRecordsInWindow(m_fileCreateRecords, m_tier1Thresholds.file_create_window_seconds)
            >= m_tier1Thresholds.file_create_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }
    if (m_tier1Thresholds.file_rename_count > 0 &&
        CountRecordsInWindow(m_fileRenameRecords, m_tier1Thresholds.file_rename_window_seconds)
            >= m_tier1Thresholds.file_rename_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }
    if (m_tier1Thresholds.file_move_count > 0 &&
        CountRecordsInWindow(m_fileMoveRecords, m_tier1Thresholds.file_move_window_seconds)
            >= m_tier1Thresholds.file_move_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }
    if (m_tier1Thresholds.data_transfer_mb > 0) {
        size_t xferMB = CalculateDataTransferSize(m_networkTransferRecords,
                            m_tier1Thresholds.file_network_transfer_window_seconds) / (1024 * 1024);
        if (xferMB >= m_tier1Thresholds.data_transfer_mb) {
            m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
            return BatchThreatTier::TIER_1;
        }
    }
    if (m_tier1Thresholds.process_termination_count > 0 &&
        CountRecordsInWindow(m_processTerminateRecords,
                              m_tier1Thresholds.process_termination_window_seconds)
            >= m_tier1Thresholds.process_termination_count) {
        m_threatsDetected.fetch_add(1, std::memory_order_relaxed);
        return BatchThreatTier::TIER_1;
    }

    return BatchThreatTier::NONE;
}

bool ThreatEvaluator::CheckBatchFileDelete() {
    if (m_thresholds.file_delete_count == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t count = CountRecordsInWindow(m_fileDeleteRecords, m_thresholds.file_delete_window_seconds);
    return count >= m_thresholds.file_delete_count;
}

bool ThreatEvaluator::CheckBatchFileCreate() {
    if (m_thresholds.file_create_count == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t count = CountRecordsInWindow(m_fileCreateRecords, m_thresholds.file_create_window_seconds);
    return count >= m_thresholds.file_create_count;
}

bool ThreatEvaluator::CheckBatchFileMove() {
    if (m_thresholds.file_move_count == 0) return false;
    std::lock_guard<std::mutex> lock(m_recordsMutex);
    size_t count = CountRecordsInWindow(m_fileMoveRecords, m_thresholds.file_move_window_seconds);
    return count >= m_thresholds.file_move_count;
}

uint64_t ThreatEvaluator::GetEvaluationsCount() const {
    return m_evalCount.load(std::memory_order_relaxed);
}

uint64_t ThreatEvaluator::GetThreatsDetected() const {
    return m_threatsDetected.load(std::memory_order_relaxed);
}

uint32_t ThreatEvaluator::GetTopContributorPid() const {
    std::lock_guard<std::mutex> lock(m_recordsMutex);

    std::unordered_map<uint32_t, size_t> pidCounts;
    auto tally = [&](const std::deque<EventRecord>& records) {
        for (const auto& r : records) {
            pidCounts[r.process_id]++;
        }
    };
    tally(m_fileWriteRecords);
    tally(m_fileDeleteRecords);
    tally(m_fileRenameRecords);
    tally(m_fileCreateRecords);
    tally(m_fileCompressRecords);
    tally(m_networkTransferRecords);

    uint32_t topPid = 0;
    size_t topCount = 0;
    for (const auto& kv : pidCounts) {
        if (kv.second > topCount) {
            topCount = kv.second;
            topPid = kv.first;
        }
    }
    return topPid;
}

static bool IsEventTypeImplemented(DriverEventType t) {
    switch (t) {
        case DriverEventType::FILE_CREATE:
        case DriverEventType::FILE_WRITE:
        case DriverEventType::FILE_DELETE:
        case DriverEventType::FILE_RENAME:
        case DriverEventType::FILE_COMPRESS:         // heuristic: process name match
        case DriverEventType::FILE_NETWORK_TRANSFER: // heuristic: process name match
        case DriverEventType::PROCESS_CREATE:
        case DriverEventType::PROC_TERMINATE:
        case DriverEventType::DRIVER_LOAD:
        case DriverEventType::DRIVER_UNLOAD:
            return true;

        case DriverEventType::FILE_MOVE:
            return true;

        default:
            return false;
    }
}

SingleEventAssessment BuildEventResponse(
    const Config& config,
    DriverEventType eventType)
{
    SingleEventAssessment result;

    if (!IsEventTypeImplemented(eventType)) {
        result.level = ThreatLevel::LEVEL_0;
        result.action = ResponseAction::LOG;
        result.confidence = 0.0f;
        result.description = std::string(DriverEventTypeToString(eventType)) + " [NOT_IMPLEMENTED]";
        return result;
    }

    result.action = config.GetEventResponse(eventType);
    result.confidence = 0.5f;

    uint8_t act = static_cast<uint8_t>(result.action);
    if (act & static_cast<uint8_t>(ResponseAction::TERMINATE) ||
        act & static_cast<uint8_t>(ResponseAction::ENCRYPT) ||
        act & static_cast<uint8_t>(ResponseAction::BLOCK)) {
        result.level = ThreatLevel::LEVEL_2;
        result.confidence = 0.8f;
    } else if (act & static_cast<uint8_t>(ResponseAction::ALERT_USER)) {
        result.level = ThreatLevel::LEVEL_1;
        result.confidence = 0.6f;
    } else {
        result.level = ThreatLevel::LEVEL_0;
    }

    if (HasAction(result.action, ResponseAction::BLOCK) &&
        HasAction(result.action, ResponseAction::TERMINATE)) {
        result.action = static_cast<ResponseAction>(
            static_cast<uint8_t>(result.action) &
            ~static_cast<uint8_t>(ResponseAction::TERMINATE));
    }

    result.description = DriverEventTypeToString(eventType);
    return result;
}

} // namespace Guardian
