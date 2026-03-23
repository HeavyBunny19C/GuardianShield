# GuardianC - User-Mode Monitor Node
# Background process with system tray, ETW collection, and heartbeat monitoring

cmake_minimum_required(VERSION 3.16)

project(GuardianC LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files
set(SOURCE_FILES
    src/guardian_c.cpp
    src/main.cpp
)

# Header files
set(HEADER_FILES
    include/guardian_c.h
)

# Create executable
add_executable(GuardianC
    ${SOURCE_FILES}
    ${HEADER_FILES}
)

# Include directories
target_include_directories(GuardianC PRIVATE
    include
    ../common/include
)

# Link against common library
target_link_libraries(GuardianC PRIVATE
    GuardianCommon
)

# Windows-specific settings
if(WIN32)
    set_target_properties(GuardianC PROPERTIES
        WIN32_EXECUTABLE ON
        OUTPUT_NAME "winmon"
    )

    target_link_libraries(GuardianC PRIVATE
        Advapi32
        Shell32
        Ole32
        Psapi
        Comctl32
    )
endif()

# Install settings
install(TARGETS GuardianC
    DESTINATION bin
)
