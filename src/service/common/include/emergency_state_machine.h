#pragma once

#include <atomic>

#include "common_types.h"

namespace Guardian {

class EmergencyStateMachine {
public:
    EmergencyStateMachine();

    bool IsValidTransition(EmergencyState from, EmergencyState to) const;
    bool TryTransition(EmergencyState to);
    EmergencyState CurrentState() const;
    bool IsIrreversible() const;
    void Reset();
    bool Cancel();

private:
    std::atomic<EmergencyState> m_state{EmergencyState::NORMAL};
};

}
