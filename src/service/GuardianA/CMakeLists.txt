# GuardianA - Primary Controller Service
# The main service responsible for coordinating the GuardianShield system

cmake_minimum_required(VERSION 3.16)

project(GuardianA LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files
set(SOURCE_FILES
    src/guardian_a.cpp
    src/main.cpp
    src/threat_evaluator.cpp
)

# Header files
set(HEADER_FILES
    include/guardian_a.h
    include/threat_evaluator.h
)

# Create executable
add_executable(GuardianA
    ${SOURCE_FILES}
    ${HEADER_FILES}
)

# Include directories
target_include_directories(GuardianA PRIVATE
    include
    ../common/include
)

# Link against common library
target_link_libraries(GuardianA PRIVATE
    GuardianCommon
)

# Windows-specific settings
if(WIN32)
    set_target_properties(GuardianA PROPERTIES
        WIN32_EXECUTABLE ON
        OUTPUT_NAME "svchost_core"
    )
    
    target_link_libraries(GuardianA PRIVATE
        Advapi32
        Wtsapi32
        Userenv
        Tdh
        Psapi
    )
endif()

# Install settings
install(TARGETS GuardianA
    DESTINATION bin
)
