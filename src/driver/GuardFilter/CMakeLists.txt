cmake_minimum_required(VERSION 3.20)
project(GuardFilter C)

if(WDK_FOUND)
    wdk_add_driver(GuardFilter
        WDM
        WINVER 0x0A00
        SOURCES
            src/guard_filter.c
            src/filter_callbacks.c
            src/communication.c
    )

    target_include_directories(GuardFilter PRIVATE
        include
        ../shared
    )

    target_compile_definitions(GuardFilter PRIVATE
        POOL_NX_OPTIN=1
    )

    target_link_libraries(GuardFilter PRIVATE fltMgr.lib)

else()
    message(STATUS "WDK not available - GuardFilter as INTERFACE target (IDE only)")

    add_library(GuardFilter INTERFACE)
    target_include_directories(GuardFilter INTERFACE include ../shared)

    set(GUARDFILTER_SOURCES
        src/guard_filter.c
        src/filter_callbacks.c
        src/communication.c
        include/guard_filter.h
        ../shared/guardian_ioctl.h
    )
    add_custom_target(GuardFilter_Sources SOURCES ${GUARDFILTER_SOURCES})
endif()
