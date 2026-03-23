# Guardian Shield - Source Code Protection System
# CMake Build Configuration
# 
# Requirements:
# - Visual Studio 2022
# - Windows SDK 10.0.19041.0 or later
# - CMake 3.20+
# - (Optional) Windows Driver Kit (WDK) 11 for kernel drivers

cmake_minimum_required(VERSION 3.20)

project(GuardianShield
    VERSION 3.3.0
    DESCRIPTION "Source Code Protection System"
    LANGUAGES CXX C
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ============================================
# Global Settings
# ============================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Windows specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    add_definitions(-DUNICODE -D_UNICODE)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    
    # Force UTF-8 source and execution charset for MSVC
    add_compile_options(/utf-8)
    
    # Link Windows libraries
    set(WIN_LIBS 
        bcrypt
        ws2_32
        advapi32
        ole32
        shell32
        version
        netapi32
        secur32
        crypt32
    )
endif()

# ============================================
# Build Options
# ============================================

option(BUILD_DRIVERS "Build kernel drivers (requires WDK)" OFF)
option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_TOOLS "Build utility tools" ON)
option(ENABLE_DEBUG_OUTPUT "Enable debug output" ON)

if(ENABLE_DEBUG_OUTPUT)
    add_definitions(-DDEBUG_OUTPUT)
endif()

# ============================================
# Dependencies
# ============================================

# yaml-cpp for configuration
find_package(yaml-cpp QUIET)
if(NOT yaml-cpp_FOUND)
    message(STATUS "yaml-cpp not found, will use bundled version")
    # Optionally fetch yaml-cpp
endif()

# ============================================
# Subdirectories
# ============================================

# Common shared library (always build)
if(EXISTS "${CMAKE_SOURCE_DIR}/src/service/common/CMakeLists.txt")
    add_subdirectory(src/service/common)
else()
    message(STATUS "Skipping common library - CMakeLists.txt not found")
endif()

# User-mode services
if(EXISTS "${CMAKE_SOURCE_DIR}/src/service/GuardianA/CMakeLists.txt")
    add_subdirectory(src/service/GuardianA)
else()
    message(STATUS "Skipping GuardianA - CMakeLists.txt not found")
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/src/service/GuardianB/CMakeLists.txt")
    add_subdirectory(src/service/GuardianB)
else()
    message(STATUS "Skipping GuardianB - directory not found")
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/src/service/GuardianC/CMakeLists.txt")
    add_subdirectory(src/service/GuardianC)
else()
    message(STATUS "Skipping GuardianC - directory not found")
endif()

# Kernel drivers (requires WDK)
if(BUILD_DRIVERS)
    find_package(WDK)
    if(WDK_FOUND)
        message(STATUS "Building kernel drivers with WDK ${WDK_VERSION}")
        if(EXISTS "${CMAKE_SOURCE_DIR}/src/driver/GuardFilter/CMakeLists.txt")
            add_subdirectory(src/driver/GuardFilter)
        endif()
        if(EXISTS "${CMAKE_SOURCE_DIR}/src/driver/GuardMonitor/CMakeLists.txt")
            add_subdirectory(src/driver/GuardMonitor)
        endif()
    else()
        message(WARNING "BUILD_DRIVERS=ON but WDK not found - skipping drivers")
    endif()
else()
    message(STATUS "Skipping kernel drivers - set BUILD_DRIVERS=ON to enable")
endif()

# Installer
if(EXISTS "${CMAKE_SOURCE_DIR}/src/installer/CMakeLists.txt")
    add_subdirectory(src/installer)
else()
    message(STATUS "Skipping installer - directory not found")
endif()

# Tools
if(BUILD_TOOLS)
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/tools/CMakeLists.txt")
        add_subdirectory(src/tools)
    else()
        message(STATUS "Skipping tools - directory not found")
    endif()
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

# ============================================
# Install Configuration
# ============================================

# Core executables
if(TARGET GuardianA)
    install(TARGETS GuardianA RUNTIME DESTINATION bin)
endif()
if(TARGET GuardianB)
    install(TARGETS GuardianB RUNTIME DESTINATION bin)
endif()
if(TARGET GuardianC)
    install(TARGETS GuardianC RUNTIME DESTINATION bin)
endif()

# Configuration templates
install(DIRECTORY config/
    DESTINATION config
    FILES_MATCHING PATTERN "*.yaml" PATTERN "*.yml" PATTERN "*.list"
)

# Documentation
install(FILES 
    ${CMAKE_SOURCE_DIR}/README.md
    DESTINATION docs
    OPTIONAL
)
if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
    install(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION docs)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/docs/FUNCTIONAL_SPEC.md")
    install(FILES ${CMAKE_SOURCE_DIR}/docs/FUNCTIONAL_SPEC.md DESTINATION docs)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/docs/USER_MANUAL.md")
    install(FILES ${CMAKE_SOURCE_DIR}/docs/USER_MANUAL.md DESTINATION docs)
endif()

# Deployment scripts
if(EXISTS "${CMAKE_SOURCE_DIR}/scripts/deploy_services.bat")
    install(FILES ${CMAKE_SOURCE_DIR}/scripts/deploy_services.bat DESTINATION scripts)
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/scripts/uninstall.bat")
    install(FILES ${CMAKE_SOURCE_DIR}/scripts/uninstall.bat DESTINATION scripts)
endif()

# ============================================
# Package Configuration (CPack)
# ============================================

set(CPACK_PACKAGE_NAME "GuardianShield")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "GuardianShield 源代码保护系统")
set(CPACK_PACKAGE_VENDOR "GuardianShield")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "GuardianShield")
set(CPACK_PACKAGE_EXECUTABLES "svchost_core;GuardianA" "svchost_helper;GuardianB" "winmon;GuardianC")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
endif()

include(CPack)

# ============================================
# MSI Build (standalone WiX, bypasses CPack to avoid duplicate Product conflict)
# ============================================
if(WIN32)
    find_program(WIX_CANDLE_EXECUTABLE candle
        PATHS "C:/Program Files (x86)/WiX Toolset v3.14/bin"
              "C:/Program Files (x86)/WiX Toolset v3.11/bin"
              "C:/Program Files/WiX Toolset v3.14/bin")
    find_program(WIX_LIGHT_EXECUTABLE light
        PATHS "C:/Program Files (x86)/WiX Toolset v3.14/bin"
              "C:/Program Files (x86)/WiX Toolset v3.11/bin"
              "C:/Program Files/WiX Toolset v3.14/bin")

    if(WIX_CANDLE_EXECUTABLE AND WIX_LIGHT_EXECUTABLE)
        set(MSI_STAGING_DIR "${CMAKE_BINARY_DIR}/msi_staging")
        set(MSI_OUTPUT "${CMAKE_BINARY_DIR}/GuardianShield-${PROJECT_VERSION}-win64.msi")
        set(WXS_MAIN "${CMAKE_SOURCE_DIR}/src/installer/GuardianShield.wxs")
        set(WXS_UI "${CMAKE_SOURCE_DIR}/src/installer/InstallDlg.wxs")

        add_custom_target(build_msi
            COMMENT "Building GuardianShield MSI installer..."
            COMMAND ${CMAKE_COMMAND} -E make_directory "${MSI_STAGING_DIR}"
            COMMAND ${CMAKE_COMMAND} -E copy
                "$<TARGET_FILE:GuardianA>" "${MSI_STAGING_DIR}/svchost_core.exe"
            COMMAND ${CMAKE_COMMAND} -E copy
                "$<TARGET_FILE:GuardianB>" "${MSI_STAGING_DIR}/svchost_helper.exe"
            COMMAND ${CMAKE_COMMAND} -E copy
                "$<TARGET_FILE:GuardianC>" "${MSI_STAGING_DIR}/winmon.exe"
            COMMAND ${CMAKE_COMMAND} -E copy
                "$<TARGET_FILE:guardian_ca>" "${MSI_STAGING_DIR}/guardian_ca.dll"
            COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_SOURCE_DIR}/config/guardian_config.yaml"
                "${MSI_STAGING_DIR}/guardian_config.yaml"
            COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_SOURCE_DIR}/config/auth.list"
                "${MSI_STAGING_DIR}/auth.list"
            COMMAND "${WIX_CANDLE_EXECUTABLE}" -nologo -arch x64
                -dBuildOutputDir="${MSI_STAGING_DIR}"
                -out "${CMAKE_BINARY_DIR}/GuardianShield.wixobj"
                -ext WixUtilExtension
                "${WXS_MAIN}"
            COMMAND "${WIX_CANDLE_EXECUTABLE}" -nologo -arch x64
                -dBuildOutputDir="${MSI_STAGING_DIR}"
                -out "${CMAKE_BINARY_DIR}/InstallDlg.wixobj"
                -ext WixUtilExtension
                "${WXS_UI}"
            COMMAND "${WIX_LIGHT_EXECUTABLE}" -nologo
                -out "${MSI_OUTPUT}"
                -ext WixUIExtension -ext WixUtilExtension
                -cultures:zh-CN
                "${CMAKE_BINARY_DIR}/GuardianShield.wixobj"
                "${CMAKE_BINARY_DIR}/InstallDlg.wixobj"
            DEPENDS GuardianA GuardianB GuardianC guardian_ca
            VERBATIM
        )
        message(STATUS "WiX found: MSI target 'build_msi' available")
        message(STATUS "  candle: ${WIX_CANDLE_EXECUTABLE}")
        message(STATUS "  light:  ${WIX_LIGHT_EXECUTABLE}")
    else()
        message(STATUS "WiX not found: MSI target 'build_msi' not available")
    endif()
endif()

# ============================================
# Print Build Summary
# ============================================

message(STATUS "")
message(STATUS "========================================")
message(STATUS "Guardian Shield Build Configuration")
message(STATUS "========================================")
message(STATUS "Version:        ${PROJECT_VERSION}")
message(STATUS "Build Type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard:   ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Drivers:  ${BUILD_DRIVERS}")
message(STATUS "Build Tests:    ${BUILD_TESTS}")
message(STATUS "Build Tools:    ${BUILD_TOOLS}")
message(STATUS "Debug Output:   ${ENABLE_DEBUG_OUTPUT}")
message(STATUS "========================================")
message(STATUS "")
