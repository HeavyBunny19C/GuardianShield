# GuardianShield Common Library
# Contains shared components used by all Guardian services

cmake_minimum_required(VERSION 3.16)

project(GuardianCommon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files
set(SOURCE_FILES
    src/common_types.cpp
    src/config.cpp
    src/driver_client.cpp
    src/emergency_state_machine.cpp
    src/environment_validator.cpp
    src/file_encryptor.cpp

    src/file_wiper.cpp
    src/ipc.cpp
    src/logger.cpp
    src/notification_manager.cpp
    src/security.cpp
    src/windows_service.cpp
)

# Header files
set(HEADER_FILES
    include/common_types.h
    include/config.h
    include/driver_client.h
    include/emergency_state_machine.h
    include/environment_validator.h
    include/file_encryptor.h

    include/file_wiper.h
    include/ipc.h
    include/logger.h
    include/notification_manager.h
    include/security.h
    include/windows_service.h
)

# Create library
add_library(GuardianCommon STATIC
    ${SOURCE_FILES}
    ${HEADER_FILES}
)

# Include directories
target_include_directories(GuardianCommon PUBLIC
    include
)

# Windows-specific settings
if(WIN32)
    target_link_libraries(GuardianCommon PUBLIC
        Advapi32
        Bcrypt
        User32
        Shell32
        Ws2_32
    )
    
    # Add Windows-specific defines
    target_compile_definitions(GuardianCommon PUBLIC
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
    )
endif()
