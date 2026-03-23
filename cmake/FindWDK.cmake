# FindWDK.cmake - Locate the Windows Driver Kit (WDK)
#
# This module searches standard installation paths for WDK 10/11 and provides
# a wdk_add_driver() macro for building kernel-mode drivers.
#
# Output variables:
#   WDK_FOUND          - TRUE if WDK was found
#   WDK_ROOT           - Root path of the WDK installation
#   WDK_VERSION        - WDK version string (e.g. "10.0.22621.0")
#   WDK_INCLUDE_DIRS   - Include directories for kernel-mode compilation
#   WDK_LIB_DIRS       - Library directories
#
# Provided macros:
#   wdk_add_driver(<name> [KMDF|WDM] WINVER <hex> SOURCES <files...>)

if(WDK_FOUND)
    return()
endif()

set(WDK_SEARCH_PATHS
    "C:/Program Files (x86)/Windows Kits/10"
    "C:/Program Files/Windows Kits/10"
    "$ENV{WDKContentRoot}"
)

set(WDK_FOUND FALSE)

foreach(_wdk_path ${WDK_SEARCH_PATHS})
    if(EXISTS "${_wdk_path}/Include")
        file(GLOB _wdk_versions RELATIVE "${_wdk_path}/Include" "${_wdk_path}/Include/10.*")
        if(_wdk_versions)
            list(SORT _wdk_versions)
            list(GET _wdk_versions -1 WDK_VERSION)
            set(WDK_ROOT "${_wdk_path}")
            set(WDK_FOUND TRUE)
            break()
        endif()
    endif()
endforeach()

if(NOT WDK_FOUND)
    if(WDK_FIND_REQUIRED)
        message(FATAL_ERROR "Could not find Windows Driver Kit (WDK). "
            "Install WDK from https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk")
    else()
        message(STATUS "WDK not found - kernel driver targets will be skipped")
        return()
    endif()
endif()

message(STATUS "Found WDK ${WDK_VERSION} at ${WDK_ROOT}")

set(WDK_INCLUDE_DIRS
    "${WDK_ROOT}/Include/${WDK_VERSION}/km"
    "${WDK_ROOT}/Include/${WDK_VERSION}/km/crt"
    "${WDK_ROOT}/Include/${WDK_VERSION}/shared"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_wdk_arch "x64")
else()
    set(_wdk_arch "x86")
endif()

set(WDK_LIB_DIRS
    "${WDK_ROOT}/Lib/${WDK_VERSION}/km/${_wdk_arch}"
)

# Macro to add a kernel-mode driver target
macro(wdk_add_driver _target)
    cmake_parse_arguments(_WDK "KMDF;WDM" "WINVER" "SOURCES" ${ARGN})

    if(NOT _WDK_WINVER)
        set(_WDK_WINVER "0x0A00")
    endif()

    add_library(${_target} SHARED ${_WDK_SOURCES})

    target_include_directories(${_target} PRIVATE ${WDK_INCLUDE_DIRS})

    target_compile_definitions(${_target} PRIVATE
        _KERNEL_MODE
        _AMD64_
        NTDDI_VERSION=0x0A000000
        _WIN32_WINNT=${_WDK_WINVER}
    )

    target_compile_options(${_target} PRIVATE
        /kernel
        /GS-
        /W4
        /Gz
        /Oi
    )

    target_link_directories(${_target} PRIVATE ${WDK_LIB_DIRS})

    target_link_libraries(${_target} PRIVATE
        ntoskrnl.lib
        hal.lib
        wmilib.lib
    )

    if(_WDK_KMDF)
        file(GLOB _kmdf_versions RELATIVE "${WDK_ROOT}/Include/wdf/kmdf" "${WDK_ROOT}/Include/wdf/kmdf/*")
        if(_kmdf_versions)
            list(SORT _kmdf_versions)
            list(GET _kmdf_versions -1 _kmdf_ver)
            message(STATUS "KMDF version ${_kmdf_ver} for ${_target}")
            target_include_directories(${_target} PRIVATE
                "${WDK_ROOT}/Include/wdf/kmdf/${_kmdf_ver}")
            target_link_directories(${_target} PRIVATE
                "${WDK_ROOT}/Lib/wdf/kmdf/${_wdk_arch}/${_kmdf_ver}")
            target_link_libraries(${_target} PRIVATE wdfldr.lib WdfDriverEntry.lib)
        else()
            message(WARNING "KMDF headers not found under ${WDK_ROOT}/Include/wdf/kmdf")
        endif()
    endif()

    set_target_properties(${_target} PROPERTIES
        SUFFIX ".sys"
        OUTPUT_NAME "${_target}"
    )

    target_link_options(${_target} PRIVATE
        /DRIVER
        /SUBSYSTEM:NATIVE
        /ENTRY:DriverEntry
        /MERGE:.rdata=.text
        /INTEGRITYCHECK
        /NODEFAULTLIB
        /MANIFEST:NO
    )
endmacro()
