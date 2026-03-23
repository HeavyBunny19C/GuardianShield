#include "../include/emergency_state_machine.h"

namespace Guardian {

EmergencyStateMachine::EmergencyStateMachine()
    : m_state(EmergencyState::NORMAL) {}

bool EmergencyStateMachine::IsValidTransition(EmergencyState from, EmergencyState to) const {
    switch (from) {
        case EmergencyState::NORMAL:
            return to == EmergencyState::ALERT;
        case EmergencyState::ALERT:
            return to == EmergencyState::ENCRYPTING || to == EmergencyState::NORMAL;
        case EmergencyState::ENCRYPTING:
            return to == EmergencyState::WIPING || to == EmergencyState::LOCKED;
        case EmergencyState::WIPING:
            return to == EmergencyState::DELETING;
        case EmergencyState::DELETING:
            return to == EmergencyState::LOCKED;
        case EmergencyState::LOCKED:
            return false;
        default:
            return false;
    }
}

bool EmergencyStateMachine::TryTransition(EmergencyState to) {
    EmergencyState from = m_state.load();
    if (!IsValidTransition(from, to)) {
        return false;
    }
    return m_state.compare_exchange_strong(from, to);
}

EmergencyState EmergencyStateMachine::CurrentState() const {
    return m_state.load();
}

bool EmergencyStateMachine::IsIrreversible() const {
    return static_cast<uint8_t>(CurrentState()) >= static_cast<uint8_t>(EmergencyState::ENCRYPTING);
}

void EmergencyStateMachine::Reset() {
    EmergencyState expected = EmergencyState::NORMAL;
    m_state.compare_exchange_strong(expected, EmergencyState::NORMAL);
}

bool EmergencyStateMachine::Cancel() {
    EmergencyState expected = EmergencyState::ALERT;
    return m_state.compare_exchange_strong(expected, EmergencyState::NORMAL);
}

}
