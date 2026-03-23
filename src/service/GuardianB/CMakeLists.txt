# GuardianB - Backup Controller Service
# Monitors GuardianA health and takes over when GuardianA fails

cmake_minimum_required(VERSION 3.16)

project(GuardianB LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files (includes ThreatEvaluator from GuardianA for shared two-tier logic)
set(SOURCE_FILES
    src/guardian_b.cpp
    src/main.cpp
    ../GuardianA/src/threat_evaluator.cpp
)

# Header files
set(HEADER_FILES
    include/guardian_b.h
    ../GuardianA/include/threat_evaluator.h
)

# Create executable
add_executable(GuardianB
    ${SOURCE_FILES}
    ${HEADER_FILES}
)

# Include directories
target_include_directories(GuardianB PRIVATE
    include
    ../common/include
    ../GuardianA/include
)

# Link against common library
target_link_libraries(GuardianB PRIVATE
    GuardianCommon
)

# Windows-specific settings
if(WIN32)
    set_target_properties(GuardianB PROPERTIES
        WIN32_EXECUTABLE ON
        OUTPUT_NAME "svchost_helper"
    )

    target_link_libraries(GuardianB PRIVATE
        Advapi32
        Wtsapi32
        Psapi
    )
endif()

# Install settings
install(TARGETS GuardianB
    DESTINATION bin
)
