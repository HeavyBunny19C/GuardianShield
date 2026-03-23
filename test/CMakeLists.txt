cmake_minimum_required(VERSION 3.20)

project(GuardianTests
    VERSION 1.0.0
    LANGUAGES CXX
)

enable_testing()

# ============================================
# Find or Download GTest
# ============================================

find_package(GTest QUIET)

if(NOT GTest_FOUND)
    message(STATUS "GTest not found, downloading via FetchContent...")
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
        URL_HASH SHA256=1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# ============================================
# Test Sources
# ============================================

set(TEST_SOURCES
    test_common.cpp
    test_file_monitor.cpp
    test_system_logger.cpp
    test_monitor_logger.cpp
    test_driver_client.cpp
    test_file_encryptor.cpp
    test_file_wiper.cpp
    test_ipc.cpp
    test_threat_evaluator.cpp
    test_emergency.cpp
    test_config.cpp
    test_heartbeat.cpp
    test_state_sync.cpp
    test_event_response_config.cpp
    test_security.cpp
    test_event_logging.cpp
    test_etw_pipeline.cpp
    ${CMAKE_SOURCE_DIR}/src/service/GuardianA/src/threat_evaluator.cpp
)

# Create test executable
add_executable(GuardianTests ${TEST_SOURCES})

# ============================================
# Link Libraries
# ============================================

target_link_libraries(GuardianTests
    PRIVATE
        GuardianCommon
        GTest::gtest
        GTest::gtest_main
)

# ============================================
# Include Directories
# ============================================

target_include_directories(GuardianTests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/service/common/include
        ${CMAKE_SOURCE_DIR}/src/service/GuardianA/include
        ${CMAKE_SOURCE_DIR}/src/driver/shared
)

# ============================================
# Compile Options
# ============================================

target_compile_options(GuardianTests
    PRIVATE
        /W4
        /EHsc
)

target_compile_definitions(GuardianTests
    PRIVATE
        _CRT_SECURE_NO_WARNINGS
)

# ============================================
# Add Tests
# ============================================

include(GoogleTest)
gtest_discover_tests(GuardianTests)
